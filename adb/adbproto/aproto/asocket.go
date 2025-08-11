package aproto

import (
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// TODO: actually test delayed acks

// LocalSocket is a stream which reads from the aproto client (i.e., receives
// A_WRTE/A_CLSE packets and sends A_OKAY ones). It is safe for concurrent use.
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/sockets.cpp;drc=bef3d190db435c27fa76b9ed1b8d732de769ee1b
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/docs/dev/asocket.md;drc=2cbf5915385eb975e1cb07eb4605cd9a4f56f3c7
type LocalSocket struct {
	Local  uint32
	Remote uint32

	MaxPayload uint32                                                         // required
	DelayedAck uint32                                                         // required, zero if delayed ack disabled
	Send       func(cmd Command, arg0 uint32, arg1 uint32, data []byte) error // must be safe to be called concurrently

	deadline deadline
	closer   closer

	mu         sync.Mutex
	buf        []byte
	off        int // start of data
	len        int // length of data (wraps)
	eof        bool
	notifyData chan struct{}
	notifyRead chan struct{}
}

var _ io.ReadCloser = (*LocalSocket)(nil)

func (r *LocalSocket) initLocked() {
	if r.Local == 0 || r.Remote == 0 || r.MaxPayload == 0 || r.Send == nil {
		panic("local socket missing required fields")
	}
	if r.buf == nil {
		r.buf = make([]byte, cmp.Or(r.DelayedAck, r.MaxPayload))
		r.notifyData = make(chan struct{})
		r.notifyRead = make(chan struct{})
	}
}

// Handle handles a packet. It does not keep references to the packet payload
// after returning. It must not be called concurrently (if you are trying to,
// you are doing something wrong since an Conn's Read can't be used concurrently
// either). It will block if it receives more A_WRTE packets than allowed given
// the A_OKAY acks sent and the max payload size.
func (r *LocalSocket) Handle(pkt Packet) {
	if pkt.Command != A_WRTE && pkt.Command != A_CLSE {
		return
	}
	if r.Local != pkt.Arg1 || r.Remote != pkt.Arg0 {
		return
	}

	// check if closed
	if r.closer.IsClosed() {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.initLocked()

	if pkt.Command == A_CLSE {
		if !r.eof {
			r.eof = true
			close(r.notifyData) // wake up all pending and future readers
		}
		return
	}

	b := pkt.Payload
	for len(b) != 0 {
		// if delayed ack, wait for any amount of room to be available
		// if not delayed ack, wait for the buffer to be drained
		for ((r.DelayedAck != 0 && len(r.buf)-r.len == 0) || (r.DelayedAck == 0 && r.len != 0)) && !r.eof {
			r.mu.Unlock()
			select {
			case <-r.closer.Closed():
				r.mu.Lock()
				return
			case <-r.notifyRead:
			}
			r.mu.Lock()
		}

		// handle eof (it could have changed while we were waiting)
		if r.eof {
			return
		}

		// copy data to the ring buffer
		n := min(len(r.buf)-r.len, len(b))
		o := r.off + r.len
		if o > len(r.buf) {
			o -= len(r.buf)
		}
		x := copy(r.buf[o:], b[:n])
		if x < n {
			copy(r.buf, b[x:n])
		}
		r.len += n
		b = b[n:]

		// wake up another pending reader, if any (the !r.eof check is critical,
		// otherwise we may double-close the channel for a partial read after
		// eof)
		select {
		case r.notifyData <- struct{}{}:
		default:
		}
	}
}

// Read reads data from the stream up to len(b), returning the number of bytes
// read (n > 0). On EOF, it returns (0, io.EOF).
func (r *LocalSocket) Read(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.initLocked()

	// check if closed
	if r.closer.IsClosed() {
		return 0, net.ErrClosed
	}

	if len(b) == 0 {
		return 0, nil
	}

	// wait for data to be available
	for r.len == 0 && !r.eof {
		r.mu.Unlock()
		select {
		case <-r.deadline.Done():
			r.mu.Lock()
			return 0, os.ErrDeadlineExceeded
		case <-r.closer.Closed():
			r.mu.Lock()
			return 0, net.ErrClosed
		case <-r.notifyData:
		}
		r.mu.Lock()
	}

	// handle eof
	if r.len == 0 && r.eof {
		return 0, io.EOF
	}

	// copy data from the ring buffer (and ack it)
	n := min(r.len, len(b))
	x := copy(b[:n], r.buf[r.off:])
	if x < n {
		copy(b[x:n], r.buf)
	}
	if r.DelayedAck == 0 {
		// if not delayed ack, send an okay
		if err := r.Send(A_OKAY, uint32(r.Local), uint32(r.Remote), nil); err != nil {
			return 0, fmt.Errorf("failed to ack data: %w", err)
		}
	} else {
		// if delayed ack, send an okay with the amount we read
		if err := r.Send(A_OKAY, uint32(r.Local), uint32(r.Remote), binary.BigEndian.AppendUint32(nil, uint32(n))); err != nil {
			return 0, fmt.Errorf("failed to ack data: %w", err)
		}
	}
	r.len -= n
	r.off += n
	if r.off > len(b) {
		r.off -= len(b)
	}

	// wake up a blocked handle, if any
	select {
	case r.notifyRead <- struct{}{}:
	default:
	}

	// wake up another pending reader, if any (the !r.eof check is critical,
	// otherwise we may double-close the channel for a partial read after eof)
	if r.len != 0 && !r.eof {
		select {
		case r.notifyData <- struct{}{}:
		default:
		}
	}

	return n, nil
}

// SetDeadline sets the deadline for future and pending Read calls. A zero value
// for t means Read will not time out.
//
// The deadline does not propagate to sending the ACKs; it only affects the time
// to wait for the data to arrive.
func (r *LocalSocket) SetDeadline(t time.Time) {
	r.deadline.Set(t)
}

// Close prevents future calls to Read and interrupts any pending ones, causing
// them to return [net.ErrClosed]. It does not have any effect on the peer. It
// wil never fail.
//
// It is simlar to a TCP shutdown(SHUT_RD).
func (r *LocalSocket) Close() error {
	return r.closer.Close(func() error {
		return nil
	})
}

// RemoteSocket is a stream which writes to the aproto client (i.e., sends
// A_WRTE/A_CLSE packets and receives A_OKAY onces). It is safe for concurrent
// use.
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/sockets.cpp;drc=bef3d190db435c27fa76b9ed1b8d732de769ee1b
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/docs/dev/asocket.md;drc=2cbf5915385eb975e1cb07eb4605cd9a4f56f3c7
type RemoteSocket struct {
	Local  uint32
	Remote uint32

	MaxPayload uint32                                                         // required
	DelayedAck uint32                                                         // required, zero if delayed ack disabled
	Send       func(cmd Command, arg0 uint32, arg1 uint32, data []byte) error // must be safe to be called concurrently

	deadline deadline
	closer   closer

	mu     sync.Mutex
	notify chan struct{}
	asb    int32
	pkt    int
}

var _ io.WriteCloser = (*RemoteSocket)(nil)

func (w *RemoteSocket) initLocked() {
	if w.Local == 0 || w.Remote == 0 || w.MaxPayload == 0 || w.Send == nil {
		panic("remote socket missing required fields")
	}
	if w.notify == nil {
		w.notify = make(chan struct{})
		if w.DelayedAck != 0 {
			w.asb = int32(w.DelayedAck)
		} else {
			w.pkt = 1
		}
	}
}

// Handle handles a packet. It does not keep references to the packet payload
// after returning. It must not be called concurrently (if you are trying to,
// you are doing something wrong since an Conn's Read can't be used concurrently
// either).
func (w *RemoteSocket) Handle(pkt Packet) {
	if pkt.Command != A_OKAY {
		return
	}
	if w.Local != pkt.Arg1 || w.Remote != pkt.Arg0 {
		return
	}

	var acked int32
	if len(pkt.Payload) != 0 {
		if len(pkt.Payload) != 4 {
			return
		}
		acked = int32(binary.LittleEndian.Uint32(pkt.Payload)) // yes, it can be negative for backpressure (it isn't currently used, but it can be)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.initLocked()

	if w.DelayedAck != 0 {
		w.asb += acked
		if w.asb <= 0 {
			return
		}
	} else {
		w.pkt++
		if w.pkt <= 0 {
			return
		}
	}

	select {
	case w.notify <- struct{}{}:
	default:
	}
}

// Write writes data to the stream. It returns the number of bytes written to
// the stream. If err is nil, n == len(b).
func (w *RemoteSocket) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.initLocked()

	if w.closer.IsClosed() {
		return 0, net.ErrClosed
	}

	var total int
	for len(b) != 0 {
		for {
			if w.DelayedAck != 0 {
				if w.asb > 0 {
					break
				}
			} else {
				if w.pkt > 0 {
					break
				}
			}
			w.mu.Unlock()
			select {
			case <-w.deadline.Done():
				w.mu.Lock()
				return 0, os.ErrDeadlineExceeded
			case <-w.closer.Closed():
				w.mu.Lock()
				return 0, net.ErrClosed
			case <-w.notify:
			}
			w.mu.Lock()
		}

		n := len(b)
		if w.DelayedAck != 0 {
			n = min(n, int(w.asb)) // note: Send will split it into multiple WRTE packets for us if it's greater than MaxPayload
		} else {
			n = min(n, int(w.MaxPayload))
		}
		if err := w.Send(A_WRTE, uint32(w.Local), uint32(w.Remote), b[:n]); err != nil {
			return total, fmt.Errorf("failed to write data: %w", err)
		}
		if w.DelayedAck != 0 {
			w.asb -= int32(n)
		} else {
			w.pkt--
		}
		b = b[n:]

		total += n
	}

	return total, nil
}

// Close closes the stream. This preempts any writes which have not started yet
// and causes them to return [net.ErrClosed]. It blocks until the A_CLOSE is
// sent (it does not follow the write deadline). It causes the peer to detect an
// EOF, after which the peer will send an A_CLSE back to close our local socket.
//
// It is simlar to a TCP shutdown(SHUT_WR).
func (w *RemoteSocket) Close() error {
	return w.closer.Close(func() error {
		return w.Send(A_CLSE, uint32(w.Local), uint32(w.Remote), nil)
	})
}

// SetDeadline sets the deadline for future and pending Write calls. Even if
// write times out, it may return n > 0, indicating that some of the data was
// successfully written. A zero value for t means Write will not time out.
//
// The deadline does not propagate to sending the data; it only affects the time
// to wait for the peer to ack the previous data to make room.
func (w *RemoteSocket) SetDeadline(t time.Time) {
	w.deadline.Set(t)
}

// LocalServiceSocket runs the loop connecting a local service socket to a
// socket pair, then closes both sockets.
func LocalServiceSocket(ls *LocalSocket, rs *RemoteSocket, lss io.ReadWriteCloser) error {
	var (
		readCh     = make(chan error, 1)
		writeCh    = make(chan error, 1)
		lssCloseCh = make(chan error, 1)
		lsCloseCh  = make(chan error, 1)
		rsCloseCh  = make(chan error, 1)
	)
	go func() {
		defer func() {
			// this doesn't do anything unless the user is doing weird stuff,
			// but let's just call it for completeness
			err := ls.Close()
			if err != nil {
				err = fmt.Errorf("close local socket: %w", err)
			}
			lsCloseCh <- err
		}()
		defer func() {
			// the client told us to go away, so tell our local service to go
			// away as well
			err := lss.Close()
			if err != nil {
				err = fmt.Errorf("close local service socket: %w", err)
			}
			lssCloseCh <- err
		}()
		b := make([]byte, cmp.Or(ls.DelayedAck, ls.MaxPayload))
		for {
			nr, err := ls.Read(b)
			if err == io.EOF {
				// we received a CLSE from the client since they want us to go
				// away or we closed RS and they finished reading it
				readCh <- nil
				return
			}
			if err != nil {
				readCh <- fmt.Errorf("read local socket: %w", err)
				return
			}
			nw, err := lss.Write(b[:nr])
			if err != nil {
				readCh <- fmt.Errorf("write local service socket: %w", err)
				return
			}
			if nr != nw {
				readCh <- fmt.Errorf("write local service socket: %w", io.ErrShortWrite)
				return
			}
		}
	}()
	go func() {
		defer func() {
			// tell the client we have no more data for it, so it will finish
			// reading, then send us a CLSE (which will make the LS EOF once we
			// finish reading it)
			err := rs.Close()
			if err != nil {
				err = fmt.Errorf("close remote socket: %q", err)
			}
			rsCloseCh <- err
		}()
		b := make([]byte, cmp.Or(rs.DelayedAck, rs.MaxPayload))
		for {
			nr, err := lss.Read(b)
			if err == io.EOF {
				writeCh <- nil
				return
			}
			if err != nil {
				writeCh <- fmt.Errorf("read local service socket: %w", err)
				return
			}
			nw, err := rs.Write(b[:nr])
			if err != nil {
				writeCh <- fmt.Errorf("write remote socket: %w", err)
				return
			}
			if nr != nw {
				writeCh <- fmt.Errorf("write remote socket: %w", io.ErrShortWrite)
				return
			}
		}
	}()
	var (
		readErr     = <-readCh
		writeErr    = <-writeCh
		lssCloseErr = <-lssCloseCh
		lsCloseErr  = <-lsCloseCh
		rsCloseErr  = <-rsCloseCh
	)
	return errors.Join(readErr, writeErr, rsCloseErr, lsCloseErr, lssCloseErr)
}

// deadline implements stuff needed for deadlines on connection implementations.
// It is safe for concurrent use.
//
// TODO: optimize this
type deadline struct {
	mu      sync.Mutex
	timer   *time.Timer
	notify  chan struct{}
	cancel  chan struct{}
	elapsed bool
}

// Done returns a channel which is closed when the deadline is exceeded.
func (d *deadline) Done() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.notify != nil {
		return d.notify
	}
	return d.setLocked(-1) // initialize with an infinite deadline
}

// Set sets the deadline to t. If t is in the past, the deadline is immediate.
// If t iz zero, the deadline is disabled.
func (d *deadline) Set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if t.IsZero() {
		d.setLocked(-1)
	} else {
		d.setLocked(max(0, time.Until(t)))
	}
}

// SetTimeout sets the deadline to occur after t. If t is negative, the deadline
// is disabled.
func (d *deadline) SetTimeout(t time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.setLocked(t)
}

// setLocked sets the deadline to t. If t is negative, there is no deadline. The
// mutex must be held while calling this.
func (d *deadline) setLocked(t time.Duration) <-chan struct{} {
	if d.timer == nil {
		d.timer = time.NewTimer(math.MaxInt64)
	}
	d.timer.Stop()
	if d.notify == nil || d.elapsed {
		if d.cancel != nil {
			close(d.cancel)
		}
		c := make(chan struct{})
		x := make(chan struct{})
		go func() {
			select {
			case <-x:
				return
			case <-d.timer.C:
			}
			d.mu.Lock()
			defer d.mu.Unlock()
			d.elapsed = true
			close(c)
		}()
		d.notify = c
		d.cancel = x
		d.elapsed = false
	}
	if t >= 0 {
		d.timer.Reset(t)
	}
	return d.notify
}

// closer implements stuff needed for closing connection implementations.
type closer struct {
	mu  sync.Mutex
	ch  atomic.Value
	ok  atomic.Bool
	err error
}

// IsClosed returns true if Close has been called.
func (c *closer) IsClosed() bool {
	if c.ok.Load() {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ok.Load()
}

// Close calls fn if it hasn't already been called, then saves and returns the
// error.
func (c *closer) Close(fn func() error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ok.Load() {
		return c.err // this isn't racy since we hold the mutex
	}
	x := c.ch.Load()
	if x == nil {
		x = make(chan struct{})
		c.ch.Store(x)
	}
	c.ok.Store(true)
	close(x.(chan struct{}))
	if fn != nil {
		c.err = fn()
	}
	return c.err
}

// Closed returns a channel which is closed when Close is called (just before
// the actual close logic is executed).
func (c *closer) Closed() <-chan struct{} {
	x := c.ch.Load()
	if x != nil { // fast path (this is only safe since we only ever set ch once)
		return x.(chan struct{})
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	x = c.ch.Load()
	if x == nil { // check again (we could have missed it before the mutex)
		x = make(chan struct{})
		c.ch.Store(x)
	}
	return x.(chan struct{})
}
