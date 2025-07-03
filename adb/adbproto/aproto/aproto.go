// Package aproto implements the lower level transport protocol used by ADB.
package aproto

import (
	"encoding"
	"encoding/binary"
	"fmt"
	"slices"
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
