package adbexec

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/pgaskin/go-adb/adb/adbproto/shellproto2"
)

// Process represents an established shell v2 connection.
//
// It is designed to be similar to [os.Process].
type Process struct {
	netconn net.Conn
	conn    *shellproto2.Conn

	mu          sync.Mutex // for writing to the conn
	stdinClosed bool

	exited atomic.Bool
	state  *ProcessState
	done   chan struct{}
}

// ProcessState represents the status of a finished shell v2 connection.
//
// It is designed to be similar to [os.ProcessState].
type ProcessState struct {
	neterr error // network error which caused a disconnection (e.g., timeout, network failure), nil if exited normally
	status int   // exit status, or -1 if invalid
}

// NewProcess creates a new wrapper around an established shell v2 connection.
// The provided connection should no longer be used after being passed to this
// function.
//
// It reads stdin and sends it to the standard input, closing stdin if it
// returns an error while reading.
//
// It receives output and writes to stdout and stderr, ignoring any write
// errors.
//
// Note that slow stdout/stderr writes will block the connection, including
// waiting for the process to exit!
func NewProcess(conn net.Conn, stdin io.Reader, stdout, stderr io.Writer) *Process {
	proc := &Process{
		netconn: conn,
		conn:    shellproto2.New(conn),
		done:    make(chan struct{}),
	}

	go func() {
		for {
			id, data, ok := proc.conn.Read()
			if !ok {
				break
			}
			switch id {
			case shellproto2.PacketExit:
				status := -1
				if len(data) == 1 {
					status = int(data[0])
				}
				proc.disconnect(&ProcessState{
					status: status,
				})

			case shellproto2.PacketStdout:
				if stdout != nil {
					stdout.Write(data)
				}

			case shellproto2.PacketStderr:
				if stderr != nil {
					stderr.Write(data)
				}
			}
		}
	}()

	go func() {
		if stdin == nil {
			proc.CloseStdin()
			return
		}
		buf := make([]byte, shellproto2.MaxPayload-shellproto2.HeaderSize)
		for {
			n, err := stdin.Read(buf)
			if err != nil {
				proc.CloseStdin()
				break
			}
			if proc.writeStdin(buf[:n]) != nil {
				break
			}
		}
	}()

	return proc
}

// disconnect signals the end of the process and closes the connection. The
// first one which calls it wins, future ones are ignored.
func (p *Process) disconnect(state *ProcessState) {
	if p.exited.CompareAndSwap(false, true) { // if we're the first one
		// defer the send so it always happens even if the netconn.Close panics
		defer func() {
			p.state = state
			close(p.done) // wake up all current and future waiters
		}()
		p.netconn.Close() // close the connection if we haven't already
	}
}

// disconnectWithConnError handles the error from the conn.
func (p *Process) disconnectWithConnError() error {
	err := p.conn.Error()
	if err == nil {
		// this should never happen unless either:
		//	- there's a bug in this code which calls handleConnError when it shouldn't
		//	- there's a bug in Conn which returns false without calling setError
		//	- the atomic CompareAndSwap in Conn isn't behaving according to Go's memory model (i.e., no read/write memory barrier before and after), resulting in err not being set when the bool is true
		panic("handleConnError called without a conn error")
	}
	p.disconnect(&ProcessState{
		neterr: fmt.Errorf("connection error: %w", err),
	})
	return err
}

var errManuallyDisconnected = errors.New("client disconnected")

// Disconnect immediately disconnects the socket, which causes adbd to send a
// SIGHUP to the process (see Subprocess::PassDataStreams).
func (p *Process) Disconnect() {
	p.disconnect(&ProcessState{
		neterr: errManuallyDisconnected,
	})
}

// Resize tells adbd to update the process window size using TIOCSWINSZ, which
// sends a SIGWINCH to the process group. It only works if the process is using
// a PTY. It waits until the packet is sent, but the actual resize is
// asynchronous.
func (p *Process) Resize(row, col, xpixel, ypixel int) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	s := shellproto2.WinSize{
		Row:    row,
		Col:    col,
		XPixel: xpixel,
		YPixel: ypixel,
	}
	if !p.conn.Write(shellproto2.PacketWindowSizeChange, s.AppendBinary(nil)) {
		return p.disconnectWithConnError()
	}
	return nil
}

// CloseStdin tells adbd to close stdin. It waits until the packet is sent, but
// the actual close is asynchronous. This has no effect if the process is using
// a PTY.
func (p *Process) CloseStdin() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.stdinClosed {
		return nil
	}

	if !p.conn.Write(shellproto2.PacketCloseStdin, nil) {
		return p.disconnectWithConnError()
	}
	p.stdinClosed = true

	return nil
}

// writeStdin writes to stdin.
func (p *Process) writeStdin(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.stdinClosed {
		return nil
	}

	if !p.conn.Write(shellproto2.PacketStdin, b) {
		return p.disconnectWithConnError()
	}
	return nil
}

// Wait waits for the process to exit or a network error to occur, waits for the
// underlying connection to close, then returns a [ProcessState] describing its
// status.
//
// Unlike [os.Process.Wait], this will never return an error and can be called
// multiple times, even after the process exits.
func (p *Process) Wait() *ProcessState {
	<-p.done
	if p.state == nil {
		panic("done close without setting state")
	}
	return p.state
}

// ProcessConn gets the underlying ADB [net.Conn] for the process. Do not use
// this unless you know what you are doing.
func ProcessConn(p *Process) net.Conn {
	return p.netconn
}

// String returns a string describing the process exit status.
func (s *ProcessState) String() string {
	if s == nil {
		return "<nil>"
	}
	if err := s.neterr; err != nil {
		if err == errManuallyDisconnected {
			return "client disconnected, SIGHUP sent"
		}
		if errors.Is(err, net.ErrClosed) {
			return "connection closed"
		}
		return "connection error (" + err.Error() + ")"
	}
	if s.status == -1 {
		return "exit status unknown"
	}
	return "exit status " + strconv.Itoa(s.status)
}

// Success returns true if the process exited with a zero status.
func (s *ProcessState) Success() bool {
	return s != nil && s.neterr == nil && s.status == 0
}

// Exited returns true if the process exited (as opposed to a connection error).
func (s *ProcessState) Exited() bool {
	return s != nil && s.neterr == nil
}
