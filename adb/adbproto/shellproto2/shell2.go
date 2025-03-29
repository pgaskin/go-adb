// Package shellproto2 implements the shell v2 protocol.
package shellproto2

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"sync"
)

// PacketID is a shell v2 packet ID.
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/shell_protocol.h;drc=90228a63bb6a59e8195165fbb7c332be27459696
type PacketID uint8

const (
	PacketStdin  PacketID = 0
	PacketStdout PacketID = 1
	PacketStderr PacketID = 2
	PacketExit   PacketID = 3

	// Close subprocess stdin if possible.
	PacketCloseStdin PacketID = 4

	// Window size change (an ASCII version of struct winsize).
	PacketWindowSizeChange PacketID = 5

	// Indicates an invalid or unknown packet.
	PacketInvalid PacketID = 255
)

const (
	// It's OK if MAX_PAYLOAD doesn't match on the sending and receiving
	// end, reading will split larger packets into multiple smaller ones.
	MaxPayload = 1024 * 1024
	BufferSize = MaxPayload

	// Header is 1 byte ID + 4 bytes length.
	HeaderSize = 1 + 4
)

type WinSize struct {
	Row    int
	Col    int
	XPixel int
	YPixel int
}

func (s WinSize) AppendBinary(b []byte) []byte {
	return fmt.Appendf(b, "%dx%d,%dx%d", s.Row, s.Col, s.XPixel, s.YPixel)
}

// Conn is a low-level shell v2 connection.
type Conn struct {
	rw   io.ReadWriter
	rrem int
	rcnt int
	rbuf [BufferSize]byte
	wbuf [BufferSize]byte
	errm sync.Mutex
	err  error
}

// New creates a new conn reading and writing to rw. It buffers its own input
// and output.
func New(rw io.ReadWriteCloser) *Conn {
	return &Conn{rw: rw}
}

// Read reads the next packet, blocking until it is received or an error occurs.
// If an error occurs, false is returned and all future operations on c will
// fail. Read must not be called concurrently with other calls to Read, and the
// returned buffer will be changed on the next call to Read.
func (c *Conn) Read() (PacketID, []byte, bool) {
	if c.Error() != nil {
		return PacketInvalid, nil, false
	}
	if c.rrem == 0 {
		if _, err := io.ReadFull(c.rw, c.rbuf[:HeaderSize]); err != nil {
			c.setError(fmt.Errorf("read header: %w", err))
			return PacketInvalid, nil, false
		}
		c.rrem = int(binary.LittleEndian.Uint32(c.rbuf[1:HeaderSize]))
		c.rcnt = 0
	}
	n := min(c.rrem, BufferSize-HeaderSize-c.rcnt)
	if n != 0 {
		if _, err := io.ReadFull(c.rw, c.rbuf[HeaderSize:HeaderSize+n]); err != nil {
			c.setError(fmt.Errorf("read data: %w", err))
			return 0, nil, false
		}
	}
	c.rrem -= n
	c.rcnt = n
	return PacketID(c.rbuf[0]), c.rbuf[HeaderSize : HeaderSize+c.rcnt : HeaderSize+c.rcnt], true
}

// Write writes packets to the connection, splitting the data if required. It
// blocks until all packets have been written or an error occurs. If an error
// occurs, false is returned and all future operations on c will fail. Write
// must not be called concurrently with other calls to Write.
func (c *Conn) Write(id PacketID, data []byte) bool {
	for c.Error() == nil {
		n := copy(c.wbuf[HeaderSize:], data)
		c.wbuf[0] = uint8(id)
		binary.LittleEndian.PutUint32(c.wbuf[1:HeaderSize], uint32(n))
		data = data[n:]

		if _, err := c.rw.Write(c.wbuf[:HeaderSize+n]); err != nil {
			c.setError(fmt.Errorf("write: %w", err))
			return false
		}

		if len(data) == 0 {
			return true
		}
	}
	return false
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
		c.err = fmt.Errorf("write: %w", err)
	}
}

// ServiceBuilder builds a service name for shell v2.
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/daemon/services.cpp;l=86-123;drc=9c843a66d11d85e1f69e944f1b37314d3e47aab1
type ServiceBuilder struct {
	term string
	raw  bool
	pty  bool
	cmd  string
}

// Raw disables pty allocation.
func (s *ServiceBuilder) Raw() {
	s.pty = false
	s.raw = true
}

// PTY enables pty allocation.
func (s *ServiceBuilder) PTY() {
	s.pty = true
	s.raw = false
}

// Term sets the TERM environment variable. If invalid, it is not set, and false
// is returned.
func (s *ServiceBuilder) Term(term string) bool {
	ok := !strings.ContainsAny(term, ",:")
	if ok {
		s.term = term
	}
	return ok
}

// Command sets the command to execute. If not set, an interactive shell is
// started.
func (s *ServiceBuilder) Command(cmd string) {
	s.cmd = cmd
}

// String builds the service name.
func (s *ServiceBuilder) String() string {
	var b strings.Builder
	b.WriteString("shell,v2")
	if s.term != "" {
		b.WriteString(",TERM=" + s.term)
	}
	if s.pty {
		b.WriteString(",pty")
	}
	if s.raw {
		b.WriteString(",raw")
	}
	b.WriteString(":")
	b.WriteString(s.cmd)
	return b.String()
}
