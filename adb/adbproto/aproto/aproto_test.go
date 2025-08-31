package aproto

import (
	"bytes"
	"errors"
	"io"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestConn(t *testing.T) {
	t.Run("ReadWrite", func(t *testing.T) {
		pr1, pw1, err := os.Pipe()
		if err != nil {
			panic(err)
		}
		defer pr1.Close()
		defer pw1.Close()

		pr2, pw2, err := os.Pipe()
		if err != nil {
			panic(err)
		}
		defer pr2.Close()
		defer pw2.Close()

		type splitReadWriter struct {
			io.Reader
			io.Writer
		}
		c1 := New(splitReadWriter{pr1, pw2})
		c2 := New(splitReadWriter{pr2, pw1})

		var (
			depth  = 0
			deeper = func(o *int) func() {
				depth++
				_, _, line, _ := runtime.Caller(depth + 1)
				*o = line
				return func() { depth-- }
			}
			// recv ensures that a read works correctly
			recv = func(c *Conn, cmd Command, arg0, arg1, dataLength, dataCheck uint32, data []byte) {
				var line int
				defer deeper(&line)()
				select {
				case <-time.After(time.Millisecond * 50):
					t.Fatalf("%d: read did not complete", line)
				case res := <-background(func() (Packet, bool) {
					msg, data, ok := c.Read()
					return Packet{msg, data}, ok
				}):
					if !res.B {
						t.Fatalf("%d: unexpected connection error: %v", line, c.Error())
					}
					if uint32(res.A.Command)^0xFFFFFFFF != res.A.Magic {
						t.Fatalf("%d: invalid magic received: %v", line, res.A)
					}
					if act, exp := res.A.Command, cmd; act != exp {
						t.Fatalf("%d: incorrect command received: expected %08X, got %08X", line, exp, act)
					}
					if act, exp := res.A.Arg0, arg0; act != exp {
						t.Fatalf("%d: incorrect arg0 received: expected %08X, got %08X", line, exp, act)
					}
					if act, exp := res.A.Arg1, arg1; act != exp {
						t.Fatalf("%d: incorrect arg1 received: expected %08X, got %08X", line, exp, act)
					}
					if act, exp := res.A.DataLength, dataLength; act != exp {
						t.Fatalf("%d: incorrect dataLength received: expected %08X, got %08X", line, exp, act)
					}
					if act, exp := res.A.DataCheck, dataCheck; act != exp {
						t.Fatalf("%d: incorrect dataCheck received: expected %08X, got %08X", line, exp, act)
					}
					if act, exp := res.A.Payload, data; !bytes.Equal(act, exp) {
						t.Fatalf("%d: incorrect data received:\n\texp %x\n\tact %x", line, exp, act)
					}
				}
			}
			// sendRecv ensures a write/read round-trip works
			sendRecv = func(w, r *Conn, cmd Command, arg0 uint32, arg1 uint32, data []byte, recvChecksum bool) {
				var line int
				defer deeper(&line)()
				if !w.Write(cmd, arg0, arg1, data) {
					t.Fatalf("%d: unexpected connection error: %v", line, w.Error())
				}
				var cksum uint32
				if recvChecksum {
					cksum = Checksum(data)
				}
				recv(r, cmd, arg0, arg1, uint32(len(data)), cksum, data)
			}
			// sendRaw sends a raw message header and data
			sendRaw = func(c *Conn, msg Message, data []byte) {
				var line int
				defer deeper(&line)()
				buf, _ := msg.AppendBinary(nil)
				buf = append(buf, data...)
				if _, err := c.rw.Write(buf); err != nil {
					t.Fatalf("%d: unexpected error: %v", line, err)
				}
			}
			// nothing ensures there's nothing left to read (c will no longer be usabe)
			nothing = func(c *Conn) {
				var line int
				defer deeper(&line)()
				select {
				case res := <-background(func() (Packet, bool) {
					msg, data, ok := c.Read()
					return Packet{msg, data}, ok
				}):
					if !res.B {
						t.Fatalf("%d: unexpected connection error: %v", line, c.Error())
					}
					t.Fatalf("%d: unexpected packet: %#v", line, res.A)
				case <-time.After(time.Millisecond * 50):
					c.setError(errors.New("unusable"))
				}
			}
		)

		_ = sendRaw
		sendRecv(c1, c2, A_AUTH, 0, 0, nil, false)
		// TODO: more

		nothing(c1)
		nothing(c2)
	})
	// TODO: test handshake
	// TODO: test error cases
}

func background[T, U any](fn func() (T, U)) <-chan struct {
	A T
	B U
} {
	ch := make(chan struct {
		A T
		B U
	}, 1)
	go func() {
		a, b := fn()
		ch <- struct {
			A T
			B U
		}{a, b}
	}()
	return ch
}
