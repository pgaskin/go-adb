// Package aproto implements the lower level transport protocol used by ADB.
package aproto

import (
	"crypto/tls"
	"crypto/x509"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"time"
)

// Packet payload sizes (adb.h).
const (
	MaxPayloadSizeV1 = 4 * 1024
	MaxPayloadSize   = 1024 * 1024
)

// When delayed acks are supported, the initial number of unacknowledged bytes
// we're willing to receive on a socket before the other side should block
// (adb.h).
const InitialDelayedAckBytes = 32 * 1024 * 1024

// ADB protocol version (adb.h).
const (
	VersionMin          uint32 = 0x01000000 // original
	VersionSkipChecksum uint32 = 0x01000001 // skip checksum (Dec 2017)
	VersionMax                 = VersionSkipChecksum
)

// Stream-based TLS protocol version (adb.h).
const (
	STLSVersionMin uint32 = 0x01000000
)

// note: I didn't include ADB_SERVER_VERSION since I'm trying to keep this
// package relatively version-independent

type Command uint32

// Message commands (types.h).
const (
	A_SYNC Command = 0x434e5953
	A_CNXN Command = 0x4e584e43
	A_OPEN Command = 0x4e45504f
	A_OKAY Command = 0x59414b4f
	A_CLSE Command = 0x45534c43
	A_WRTE Command = 0x45545257
	A_AUTH Command = 0x48545541
	A_STLS Command = 0x534C5453
)

func (c Command) String() string {
	return string(binary.LittleEndian.AppendUint32(nil, uint32(c)))
}

// AUTH packets first argument.
const (
	AuthToken        uint32 = 1
	AuthSignature    uint32 = 2
	AuthRSAPublicKey uint32 = 3
)

const AuthTokenSize = 20

const MessageSize = 6 * 4

// Message is an amessage (types.h)
type Message struct {
	Command    Command // command identifier constant
	Arg0       uint32  // first argument
	Arg1       uint32  // second argument
	DataLength uint32  // length of payload (0 is allowed)
	DataCheck  uint32  // checksum of data payload
	Magic      uint32  // command ^ 0xffffffff
}

// Packet is an apacket (types.h).
type Packet struct {
	Message
	Payload []byte
}

var (
	_ encoding.BinaryUnmarshaler = (*Message)(nil)
	_ encoding.BinaryAppender    = Message{}
	_ encoding.BinaryMarshaler   = Message{}
)

// Checksum computes the checksum of an apacket payload.
func Checksum(payload []byte) uint32 {
	var sum uint32
	for _, b := range payload {
		sum += uint32(b)
	}
	return sum
}

// UnmarshalBinary decodes an amessage.
func (k *Message) UnmarshalBinary(buf []byte) error {
	if len(buf) != MessageSize {
		return fmt.Errorf("incorrect amessage size")
	}
	*k = Message{
		Command:    Command(binary.LittleEndian.Uint32(buf[0:4])),
		Arg0:       binary.LittleEndian.Uint32(buf[4:8]),
		Arg1:       binary.LittleEndian.Uint32(buf[8:12]),
		DataLength: binary.LittleEndian.Uint32(buf[12:16]),
		DataCheck:  binary.LittleEndian.Uint32(buf[16:20]),
		Magic:      binary.LittleEndian.Uint32(buf[20:24]),
	}
	return nil
}

// AppendBinary encodes an amessage.
func (k Message) AppendBinary(b []byte) ([]byte, error) {
	b = slices.Grow(b, MessageSize)
	b = binary.LittleEndian.AppendUint32(b, uint32(k.Command))
	b = binary.LittleEndian.AppendUint32(b, k.Arg0)
	b = binary.LittleEndian.AppendUint32(b, k.Arg1)
	b = binary.LittleEndian.AppendUint32(b, k.DataLength)
	b = binary.LittleEndian.AppendUint32(b, k.DataCheck)
	b = binary.LittleEndian.AppendUint32(b, k.Magic)
	return b, nil
}

// MarshalBinary is like AppendBinary.
func (k Message) MarshalBinary() ([]byte, error) {
	return k.AppendBinary(nil)
}

// IsMagicValid checks whether the magic is valid.
func (k Message) IsMagicValid() bool {
	return k.Command^0xFFFFFFFF == Command(k.Magic)
}

// IsChecksumValid checks whether the checksum is valid.
func (k Packet) IsChecksumValid() bool {
	if k.DataCheck == 0 || k.DataLength == 0 {
		return true
	}
	return Checksum(k.Payload) == k.DataCheck
}

// AppendBinary encodes an amessage.
func (k Packet) AppendBinary(b []byte) ([]byte, error) {
	var err error
	b = slices.Grow(b, MessageSize+len(k.Payload))
	b, err = k.Message.AppendBinary(b)
	if err != nil {
		return nil, err
	}
	b = append(b, k.Payload...)
	return b, nil
}

// MarshalBinary is like AppendBinary.
func (k Packet) MarshalBinary() ([]byte, error) {
	return k.AppendBinary(nil)
}

// ConnectionProps is the list of properties which should be sent in the A_CNXN
// banner.
var ConnectionProps = []string{
	"ro.product.name",
	"ro.product.model",
	"ro.product.device",
}

// Conn is a low-level aproto connection. It does not handle connection state,
// but it does parse A_CNXN.
type Conn struct {
	rw io.ReadWriter

	// connection state (populated by CNXN)
	cmu  sync.Mutex
	cmps uint32
	cver uint32

	// read buffers
	rmsg [MessageSize]byte
	rbuf []byte

	// write buffers
	wmsg [MessageSize]byte

	// error state
	errm sync.Mutex
	err  error
}

// New creates a new conn reading and writing to rw. It buffers its own input
// and output.
//
// The transport should be kicked by closing its underlying connection if any
// methods return an error.
func New(rw io.ReadWriter) *Conn {
	return &Conn{
		rw: rw,

		cmps: MaxPayloadSizeV1, // legacy v1 payload size until we know how much the remote can accept
		cver: VersionMin,       // min protocol version to support
	}
}

func (c *Conn) MaxPayloadSize() uint32 {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	return c.cmps
}

func (c *Conn) ProtocolVersion() uint32 {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	return c.cver
}

// Read reads the next packet, blocking until it is received or an error occurs.
// If an error occurs, false is returned and all future operations on c will
// fail. Read must not be called concurrently with other calls to Read, and the
// returned buffer will be changed on the next call to Read.
func (c *Conn) Read() (Message, []byte, bool) {
	var pkt Packet
	if c.Error() != nil {
		return pkt.Message, pkt.Payload, false
	}
	if n := int(c.MaxPayloadSize()); len(c.rbuf) != n {
		c.rbuf = slices.Grow(c.rbuf[:0], n)[:n] // resize the buffer, but reuse the memory if possible
	}
	if _, err := io.ReadFull(c.rw, c.rmsg[:]); err != nil {
		if err == io.EOF {
			c.setError(errors.New("client kicked transport"))
		} else {
			c.setError(fmt.Errorf("read: %w", err))
		}
		return pkt.Message, pkt.Payload, false
	}
	if err := pkt.Message.UnmarshalBinary(c.rmsg[:]); err != nil {
		c.setError(fmt.Errorf("read: %w", err))
		return pkt.Message, pkt.Payload, false
	}
	if !pkt.Message.IsMagicValid() {
		c.setError(fmt.Errorf("read: invalid magic (cmd=0x%08X magic=0x%08X)", pkt.Message.Command, pkt.Message.Magic))
		return pkt.Message, pkt.Payload, false
	}
	if pkt.DataLength != 0 {
		if pkt.DataLength > uint32(len(c.rbuf)) {
			c.setError(fmt.Errorf("read: payload too large (len=%d max=%d)", pkt.DataLength, len(c.rbuf)))
			return pkt.Message, pkt.Payload, false
		}
		if _, err := io.ReadFull(c.rw, c.rbuf[:pkt.DataLength]); err != nil {
			if err == io.EOF {
				c.setError(errors.New("client kicked transport"))
			} else {
				c.setError(fmt.Errorf("read: %w", err))
			}
			return pkt.Message, pkt.Payload, false
		}
	}
	if pkt.Payload = c.rbuf[:pkt.DataLength]; !pkt.IsChecksumValid() {
		c.setError(fmt.Errorf("read: invalid checksum (cmd=%s)", pkt.Command))
		return pkt.Message, pkt.Payload, false
	}
	if pkt.Command == A_CNXN {
		c.cmu.Lock()
		defer c.cmu.Unlock()

		if c.cver = min(pkt.Arg0, VersionMax); c.cver < VersionMin {
			c.setError(errors.New("client version negotiation failed"))
			return pkt.Message, pkt.Payload, false
		}

		if c.cmps = min(pkt.Arg1, MaxPayloadSize); c.cmps < MaxPayloadSizeV1 {
			c.setError(errors.New("client max payload size negotiation failed"))
			return pkt.Message, pkt.Payload, false
		}
	}
	return pkt.Message, pkt.Payload, true
}

// Write writes packets to the connection, splitting the data if required. It
// blocks until all packets have been written or an error occurs. If an error
// occurs, false is returned and all future operations on c will fail. Write
// must not be called concurrently with other calls to Write.
func (c *Conn) Write(cmd Command, arg0, arg1 uint32, data []byte) bool {
	if c.Error() != nil {
		return false
	}
	pkt := Packet{
		Message: Message{
			Command: cmd,
			Arg0:    arg0,
			Arg1:    arg1,
			Magic:   uint32(cmd) ^ 0xFFFFFFFF,
		},
		Payload: data,
	}
	if len(data) == 0 {
		if buf, err := pkt.Message.AppendBinary(c.wmsg[:]); err != nil {
			c.setError(fmt.Errorf("write: %w", err))
			return false
		} else if _, err := c.rw.Write(buf); err != nil {
			c.setError(fmt.Errorf("write: %w", err))
			return false
		}
	} else {
		for chunk := range slices.Chunk(data, int(c.MaxPayloadSize())) {
			pkt.Payload = chunk
			if c.ProtocolVersion() < VersionSkipChecksum {
				pkt.DataCheck = Checksum(pkt.Payload)
			}
			if buf, err := pkt.Message.AppendBinary(c.wmsg[:]); err != nil {
				c.setError(fmt.Errorf("write: %w", err))
				return false
			} else if _, err := c.rw.Write(buf); err != nil {
				c.setError(fmt.Errorf("write: %w", err))
				return false
			}
			if _, err := c.rw.Write(pkt.Payload); err != nil {
				c.setError(fmt.Errorf("write: %w", err))
				return false
			}
		}
	}
	return true
}

// Handshake performs a TLS handshake. It should be called in response to an
// A_STLS packet. Like with A_AUTH authentication, a A_CNXN packet needs to be
// sent back after the handshake completes if authentication was successful.
// Read and Write must not be called concurrently.
func (c *Conn) Handshake(serverCert *tls.Certificate, verify func(peerCert *x509.Certificate)) bool {
	if c.Error() != nil {
		return false
	}
	tlsconn := tls.Server(&fakeNetConn{c.rw}, &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return serverCert, nil
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/daemon/auth.cpp;l=301-356;drc=61197364367c9e404c7da6900658f1b16c42d0da
			for _, rawCert := range rawCerts {
				if cert, err := x509.ParseCertificate(rawCert); err == nil {
					if verify != nil {
						verify(cert)
					}
				}
			}
			return nil
		},
		ClientAuth: tls.RequestClientCert,
	})
	if err := tlsconn.Handshake(); err != nil {
		c.setError(fmt.Errorf("tls: %w", err))
		return false
	}
	c.rw = tlsconn
	return true
}

// Error gets the error, if any. It can safely be called concurrently.
func (c *Conn) Error() error {
	c.errm.Lock()
	defer c.errm.Unlock()
	return c.err
}

// setError sets the sticky error, if not already set.
func (c *Conn) setError(err error) {
	c.errm.Lock()
	defer c.errm.Unlock()
	if c.err == nil {
		c.err = err
	}
}

type fakeNetConn struct {
	rw io.ReadWriter
}

func (c *fakeNetConn) Read(b []byte) (n int, err error) {
	return c.rw.Read(b)
}

func (c *fakeNetConn) Write(b []byte) (n int, err error) {
	return c.rw.Write(b)
}

func (c *fakeNetConn) Close() error {
	return errors.ErrUnsupported
}

func (c *fakeNetConn) LocalAddr() net.Addr {
	return nil
}

func (c *fakeNetConn) RemoteAddr() net.Addr {
	return nil
}

func (c *fakeNetConn) SetDeadline(t time.Time) error {
	return errors.ErrUnsupported
}

func (c *fakeNetConn) SetReadDeadline(t time.Time) error {
	return errors.ErrUnsupported
}

func (c *fakeNetConn) SetWriteDeadline(t time.Time) error {
	return errors.ErrUnsupported
}
