package aproto

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pgaskin/go-adb/internal/util"
)

var globalSocketAddr atomic.Uint32 // we could do it per-mux, but this is nicer for debugging

// SessionConfig configures a [Session]. All fields are optional.
type SessionConfig struct {
	// Open opens services requested by the peer. You probably want to use an
	// adb.Dialer's DialADB here. If nil, A_OPEN is rejected.
	Open func(ctx context.Context, svc string) (io.ReadWriteCloser, error)

	// OpenContext optionally derives the context used for a service dial from
	// the base context (the one passed to Serve).
	OpenContext func(ctx context.Context, svc string) context.Context

	// LazyOpen, if enabled, dials services requested by the peer in a new
	// goroutine instead of blocking the read loop. This improves performance
	// and reliability when re-exposing a remote ADB server.
	//
	// This is non-standard behaviour.
	LazyOpen bool

	// DelayedAck enables delayed acks (if also supported by the peer). If
	// the peer is the official adbd, ADB_BURST_MODE must be set.
	DelayedAck bool

	// LocalDelayedAck, if nonzero and DelayedAck is enabled, is the delayed ack
	// window for our half of a socket pair.
	//
	// Currently, ADB hardcodes this to 33554432 bytes, but it should
	// theoretically support anything. However, making this smaller than the
	// maximum payload size is counterproductive.
	//
	// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=543-544;drc=9f298fb1f3317371b49439efb20a598b3a881bf3
	LocalDelayedAck uint32

	// SupportsDelayedAck should return true if the peer supports delayed acks.
	// If nil, delayed acks are treated as unsupported.
	SupportsDelayedAck func() bool

	// MaxQueuedPackets, if nonzero, is the maximum number of packets which can
	// be waiting to be written before the connection is kicked.
	//
	// For a well-behaved peer, the number of queued packets is bounded by the
	// flow control (roughly one data packet per stream, plus a few control
	// packets), so this only comes into play if the peer makes us generate
	// packets (e.g., acks, or the A_CLSE replies to A_OKAY packets for unknown
	// streams) faster than it reads them.
	//
	// Setting this to 16384 works fine for most situations.
	//
	// This is non-standard behaviour.
	MaxQueuedPackets int

	// WriteTimeout, if nonzero, is the maximum time a single packet may take to
	// be written to the underlying connection before the connection is kicked.
	// This protects against a peer which stops reading (e.g., a buggy or
	// malicious one), which would otherwise leave the session (and anything
	// blocked on writing to it) stuck forever.
	//
	// It should be set relatively high, since some transports may be slow and
	// packets may be large.
	//
	// This is non-standard behaviour.
	WriteTimeout time.Duration

	// MaxStreams, if nonzero, is the maximum number of streams which may be
	// open at once (including ones being opened, and ones we opened). Streams
	// opened by the peer past this are rejected. This bounds the memory and
	// goroutines a peer can make us use.
	//
	// Setting this to around a hundred works fine for typical usage.
	//
	// This is non-standard behaviour.
	MaxStreams int

	// KickWriteTimeout is how long [Session.Kick] waits for a packet which is
	// currently being written to finish before closing the underlying
	// connection anyway. If zero or negative, it doesn't wait.
	//
	// This should be set for transports which can't tell the peer that the
	// connection was interrupted (e.g., USB), since the peer would otherwise
	// wait forever for the rest of a partial packet (and then misinterpret the
	// start of the next connection as the rest of it). Setting this to a few
	// seconds is more than enough for USB.
	//
	// It isn't needed for transports like TCP, where the peer sees the
	// connection close.
	//
	// This is non-standard behaviour.
	KickWriteTimeout time.Duration
}

// SessionTrace is a set of hooks to run at various points in the lifecycle of a [Session].
// Any particular hook may be nil. Functions may be called concurrently from
// different goroutines and at arbitrary times. They should avoid blocking for
// extended periods of time.
//
// These hooks should not be used for important logic. They are intended for
// debugging and metrics.
type SessionTrace struct {
	// PacketSent is called when a packet is queued to be sent (it won't have
	// the checksum, and may not be split yet).
	PacketSent func(cmd Command, arg0, arg1 uint32, data []byte)

	// PacketReceived is called when a packet is received.
	PacketReceived func(pkt Packet)

	// PacketUnknown is called when an unknown packet is ignored.
	PacketUnknown func(pkt Packet)

	// PacketIgnored is called when a packet is ignored.
	PacketIgnored func(pkt Packet)

	// PacketSocketUnknown is called when a packet references an unknown socket
	// and is ignored.
	PacketSocketUnknown func(pkt Packet)

	// LocalServiceOpen is called when the a service is opened for the peer.
	LocalServiceOpen func(local, remote uint32, svc string)

	// LocalServiceFail is called when the service cannot be opened.
	LocalServiceFail func(local, remote uint32, err error)

	// LocalServiceSuccess is called when the service is opened.
	LocalServiceSuccess func(local, remote uint32)

	// LocalServiceDelayedAck is called if and when delayed acks are configured
	// for a local service.
	LocalServiceDelayedAck func(local, remote, localDelayedAck, remoteDelayedAck uint32)

	// LocalServiceClose is called when the service is fully closed.
	LocalServiceClose func(local, remote uint32)
}

type sessionTraceKey struct{}

func sessionTrace(ctx context.Context) *SessionTrace {
	if t := ctx.Value(sessionTraceKey{}); t != nil {
		return t.(*SessionTrace)
	}
	return nil
}

// WithSessionTrace returns a new context based on the provided parent ctx. When
// the returned context is used with a [Session], the provided trace hooks will
// be used, in addition to any previous hooks registered with ctx. Any hooks
// defined in the provided trace will be called first.
func WithSessionTrace(ctx context.Context, trace *SessionTrace) context.Context {
	if trace == nil {
		panic("nil trace")
	}
	if old := ctx.Value(sessionTraceKey{}); old != nil {
		util.ComposeHooks(trace, old.(*SessionTrace))
	}
	return context.WithValue(ctx, sessionTraceKey{}, trace)
}

// Session is the socket-multiplexing layer for one connection. It routes
// A_OPEN/A_OKAY/A_CLSE/A_WRTE packets, tracks the local/remote socket pairs,
// opens services for/on the peer.
//
// It does not handle the connection handshake (A_CNXN/A_AUTH/A_STLS), which
// must be done in the [Session.Serve] callback.
type Session struct {
	conn *Conn
	cfg  SessionConfig

	// set by Serve before the loop starts
	trace   atomic.Pointer[SessionTrace]
	dialCtx context.Context // only used by the loop

	// connection lifecycle
	stateMu       sync.Mutex
	connected     chan struct{}
	authenticated chan struct{}
	kicked        chan struct{}
	kickErr       error

	// outgoing packets (see Send)
	writeMu     sync.Mutex // held while writing to conn (by the writer, or by a TLS handshake)
	queueMu     sync.Mutex
	queue       []*sessionPacket
	queueReady  chan struct{} // poked (non-blocking) when a packet is queued
	queueClosed bool          // set when the writer exits
	queueErr    error
	writerOnce  sync.Once

	mu             sync.Mutex
	streams        map[uint32]*sessionStream        // by local socket id
	pendingStreams map[uint32]*sessionPendingStream // by local socket id
	pendingOpens   int                              // streams being opened by the peer (counted against MaxStreams)
}

// NewSession creates a Session with the provided config. It takes ownership of
// conn, which must not be used directly for I/O afterwards (i.e., read, write,
// close).
func NewSession(conn *Conn, cfg SessionConfig) *Session {
	return &Session{
		conn:          conn,
		cfg:           cfg,
		connected:     make(chan struct{}),
		authenticated: make(chan struct{}),
		kicked:        make(chan struct{}),
		queueReady:    make(chan struct{}, 1),
	}
}

// Connected returns a channel which is closed once the connection is negotiated
// (see [Session.SetConnected]).
func (s *Session) Connected() <-chan struct{} { return s.connected }

// Authenticated returns a channel which is closed once the peer is
// authenticated (see [Session.SetAuthenticated]).
func (s *Session) Authenticated() <-chan struct{} { return s.authenticated }

// Kicked returns a channel which is closed when the connection is kicked (see
// [Session.Kick]).
func (s *Session) Kicked() <-chan struct{} { return s.kicked }

// Err returns the reason the connection was kicked, or nil if it has not been
// kicked.
func (s *Session) Err() error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.kickErr
}

// SetConnected marks the connection as negotiated, allowing A_OPEN packets to
// be processed. It is idempotent and safe to call concurrently.
func (s *Session) SetConnected() {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	select {
	case <-s.connected:
	default:
		close(s.connected)
	}
}

// SetAuthenticated marks the peer as authenticated, allowing A_OKAY/A_CLSE/
// A_WRTE packets to be processed and unblocking DialADB. It is idempotent and
// safe to call concurrently.
func (s *Session) SetAuthenticated() {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	select {
	case <-s.authenticated:
	default:
		close(s.authenticated)
	}
}

// Kick kicks the connection with the specified error (or a generic one if nil)
// if it has not been kicked yet. It closes the underlying connection (which
// interrupts [Session.Serve]) and all open streams. It is idempotent and safe
// to call concurrently.
//
// It explicitly does not wait for queued packets (e.g., acks or A_CLSE packets
// from closing streams) to be written first, since it is also used when the
// connection is already broken. This is harmless for the peer (it closes all
// of the connection's streams when it disconnects), but if it matters, call
// [Session.Flush] first.
//
// If [SessionConfig.KickWriteTimeout] is set, it does wait (up to that long)
// for a packet which is currently being written to finish, so the peer never
// receives a partial packet.
func (s *Session) Kick(err error) {
	s.stateMu.Lock()
	select {
	case <-s.kicked:
		s.stateMu.Unlock()
		return
	default:
	}
	if err == nil {
		err = errors.New("kicked")
	}
	s.kickErr = err
	close(s.kicked)
	s.stateMu.Unlock()

	// close the connection at a packet boundary if enabled (see above), but
	// don't wait forever since the write might be stuck because the peer isn't
	// reading (in which case the only way to unblock it is to close the
	// connection)
	if s.cfg.KickWriteTimeout > 0 {
		closed := make(chan struct{})
		go func() {
			s.writeMu.Lock()
			defer s.writeMu.Unlock()
			s.conn.Close()
			close(closed)
		}()
		select {
		case <-closed:
		case <-time.After(s.cfg.KickWriteTimeout):
			s.conn.Close()
		}
	} else {
		s.conn.Close()
	}

	// close streams in a new goroutine, just in case anything is misbehaving
	// (the local service conns come from user-provided implementations)
	go s.CloseStreams()
}

// MaxPayloadSize returns the negotiated maximum payload size. It is the same as
// [Conn.MaxPayloadSize].
func (s *Session) MaxPayloadSize() uint32 { return s.conn.MaxPayloadSize() }

// ProtocolVersion returns the negotiated protocol version. It is the same as
// [Conn.ProtocolVersion].
func (s *Session) ProtocolVersion() uint32 { return s.conn.ProtocolVersion() }

// sessionPacket is a packet waiting to be written by the writer.
type sessionPacket struct {
	cmd        Command
	arg0, arg1 uint32
	data       []byte
	done       chan error // receives the result (nil if nobody is waiting)
	flush      bool       // if true, this isn't a real packet (see Flush)
}

// ErrSendCancelled is returned by [Session.Send] if the send is cancelled before
// the packet has started being written.
var ErrSendCancelled = errors.New("send cancelled")

// errQueueOverflow is the error the connection is kicked with if the write
// queue overflows.
var errQueueOverflow = errors.New("too many queued packets (peer isn't reading)")

// Write sends a packet, splitting the data if required, blocking until it has
// been written to the underlying connection (or the connection is kicked). It
// is safe to call concurrently. It is equivalent to Send with a nil cancel.
func (s *Session) Write(cmd Command, arg0, arg1 uint32, data []byte) error {
	return s.Send(cmd, arg0, arg1, data, nil)
}

// Send sends a packet, splitting the data if required, blocking until it has
// been written to the underlying connection, the connection is kicked, or
// cancel is closed. If cancel is closed before the packet has started being
// written, it is dropped and [ErrSendCancelled] is returned. Otherwise, it
// blocks until the write finishes (a partially written packet can't be
// interrupted without corrupting the stream). Data is not retained after it
// returns. It is safe to call concurrently.
//
// Packets are written in the order they are sent, by a separate goroutine.
// Since it blocks on the underlying connection, it must not be called from the
// read loop (i.e., a [SessionConfig.Open] or [SessionTrace] callback), or while
// holding a lock which the read loop needs, since that could deadlock if the
// peer is also blocked writing to us (this doesn't currently happen with stock
// ADB as of 2026-09-09, but could in other implementations, e.g., if the peer
// is another go-adb Session and the underlying connection's buffers are full in
// both directions). Use SendAsync for those instead. The Serve handshake
// callback is the exception, since nothing else is happening at that point (and
// the handshake packets are small enough to be buffered).
func (s *Session) Send(cmd Command, arg0, arg1 uint32, data []byte, cancel <-chan struct{}) error {
	p := &sessionPacket{cmd: cmd, arg0: arg0, arg1: arg1, data: data, done: make(chan error, 1)}
	if err := s.enqueue(p); err != nil {
		return err
	}
	select {
	case err := <-p.done:
		return err
	case <-cancel:
	}
	if s.dequeue(p) {
		return ErrSendCancelled
	}
	return <-p.done // it's already being written
}

// SendAsync queues a packet to be written in the background. It never blocks,
// and copies data, so it is safe to call from the read loop or while holding
// locks. Errors are not reported (they will kick the connection).
func (s *Session) SendAsync(cmd Command, arg0, arg1 uint32, data []byte) {
	s.enqueue(&sessionPacket{cmd: cmd, arg0: arg0, arg1: arg1, data: slices.Clone(data)})
}

// Flush blocks until all packets queued before it was called have been written
// to the underlying connection, ctx is done, or the connection is kicked. Like
// Send, it must not be called from the read loop.
//
// This is useful before kicking the connection to ensure the peer receives the
// A_CLSE for any streams which were just closed (see [Session.Kick]).
func (s *Session) Flush(ctx context.Context) error {
	p := &sessionPacket{flush: true, done: make(chan error, 1)}
	if err := s.enqueue(p); err != nil {
		return err
	}
	select {
	case err := <-p.done:
		return err
	case <-ctx.Done():
		s.dequeue(p) // it doesn't matter if this fails
		return ctx.Err()
	}
}

// enqueue adds a packet to the write queue, starting the writer if necessary.
func (s *Session) enqueue(p *sessionPacket) error {
	if trace := s.trace.Load(); !p.flush && trace != nil && trace.PacketSent != nil {
		trace.PacketSent(p.cmd, p.arg0, p.arg1, p.data)
	}
	s.queueMu.Lock()
	if s.queueClosed {
		s.queueMu.Unlock()
		return s.queueErr
	}
	if s.cfg.MaxQueuedPackets > 0 && len(s.queue) >= s.cfg.MaxQueuedPackets {
		s.queueMu.Unlock()
		s.Kick(errQueueOverflow) // note: this is safe to call from anywhere enqueue is
		return errQueueOverflow
	}
	s.queue = append(s.queue, p)
	s.queueMu.Unlock()
	s.writerOnce.Do(func() {
		go s.writer()
	})
	select {
	case s.queueReady <- struct{}{}:
	default:
	}
	return nil
}

// dequeue removes a packet from the write queue, returning false if it is not
// there anymore (i.e., it is being or has been written, or the writer exited).
func (s *Session) dequeue(p *sessionPacket) bool {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	i := slices.Index(s.queue, p)
	if i == -1 {
		return false
	}
	s.queue = slices.Delete(s.queue, i, i+1)
	return true
}

// writer writes queued packets until the connection is kicked or a write
// fails, then fails any remaining and future packets.
func (s *Session) writer() {
	var err error
	for {
		s.queueMu.Lock()
		if len(s.queue) == 0 {
			s.queueMu.Unlock()
			select {
			case <-s.queueReady:
				continue
			case <-s.kicked:
				err = s.err()
			}
			break
		}
		p := s.queue[0]
		s.queue = slices.Delete(s.queue, 0, 1)
		s.queueMu.Unlock()

		if p.flush {
			p.done <- nil // everything before it has been written
			continue
		}

		// kick the connection if the write takes too long (see WriteTimeout),
		// which unblocks it
		var timeout *time.Timer
		if s.cfg.WriteTimeout > 0 {
			timeout = time.AfterFunc(s.cfg.WriteTimeout, func() {
				s.Kick(fmt.Errorf("write timed out after %s (peer isn't reading)", s.cfg.WriteTimeout))
			})
		}

		s.writeMu.Lock()
		ok := s.conn.Write(p.cmd, p.arg0, p.arg1, p.data)
		s.writeMu.Unlock()

		if timeout != nil {
			timeout.Stop()
		}
		if !ok {
			err = s.conn.Error()
			if p.done != nil {
				p.done <- err
			}
			s.Kick(err)
			break
		}
		if p.done != nil {
			p.done <- nil
		}
	}

	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	s.queueClosed = true
	s.queueErr = err
	for _, p := range s.queue {
		if p.done != nil {
			p.done <- err
		}
	}
	s.queue = nil
}

// Handshake performs a TLS server handshake, holding the write lock so it does
// not interleave with any packet write. It should be called from the Serve
// handshake callback in response to an A_STLS packet (after any packets sent
// with Write have been written, which is always the case if they were sent from
// the handshake callback).
func (s *Session) Handshake(serverCert *tls.Certificate, verify func(peerCert *x509.Certificate)) bool {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.conn.Handshake(serverCert, verify)
}

// HandshakeClient performs a TLS client handshake, holding the write lock so it
// does not interleave with any packet write. It should be called from the Serve
// handshake callback after sending an A_STLS packet with Write.
func (s *Session) HandshakeClient(config *tls.Config) bool {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.conn.HandshakeClient(config)
}

func (s *Session) supportsDelayedAck() bool {
	return s.cfg.SupportsDelayedAck != nil && s.cfg.SupportsDelayedAck()
}

func (s *Session) err() error {
	if err := s.Err(); err != nil {
		return err
	}
	return errors.New("kicked")
}

func isClosed(ch <-chan struct{}) bool {
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// Serve runs the read loop until the connection is kicked, then returns. Socket
// packets (A_OPEN/A_OKAY/A_CLSE/A_WRTE) are handled internally. Control packets
// (A_CNXN/A_AUTH/A_STLS) are passed to handshake for authentication (which can
// use [Session.Write]).
//
// The context is the base context for service dials and can be used with
// [WithSessionTrace].
//
// It must be called at most once. If the loop needs to kick the connection, it
// returns. The caller should call kick in a deferred call.
func (s *Session) Serve(ctx context.Context, handshake func(msg Message, data []byte)) {
	s.trace.Store(sessionTrace(ctx))
	s.dialCtx = ctx
	for {
		msg, data, ok := s.conn.Read()
		if !ok {
			return
		}
		trace := s.trace.Load()
		if trace != nil && trace.PacketReceived != nil {
			trace.PacketReceived(Packet{Message: msg, Payload: data})
		}
		switch msg.Command {
		case A_CNXN, A_AUTH, A_STLS:
			// the handshake handles its own state gating and tracing
			handshake(msg, data)

		case A_SYNC:
			goto ignore // never valid

		case A_OPEN:
			if !isClosed(s.connected) {
				goto ignore // not connected yet
			}
			if msg.Arg0 == 0 {
				goto ignore
			}
			s.handleOpen(msg, data)

		case A_OKAY:
			if !isClosed(s.authenticated) {
				goto ignore // not authenticated yet
			}
			if msg.Arg0 == 0 || msg.Arg1 == 0 {
				goto ignore
			}
			s.handleOkay(msg, data)

		case A_CLSE:
			if !isClosed(s.authenticated) {
				goto ignore // not authenticated yet
			}
			if msg.Arg1 == 0 {
				goto ignore
			}
			s.handleClose(msg, data)

		case A_WRTE:
			if !isClosed(s.authenticated) {
				goto ignore // not authenticated yet
			}
			if msg.Arg0 == 0 || msg.Arg1 == 0 {
				return // kick
			}
			s.handleWrite(msg, data)

		default:
			if trace != nil && trace.PacketUnknown != nil {
				trace.PacketUnknown(Packet{Message: msg, Payload: data})
			}
		}
		continue
	ignore:
		if trace != nil && trace.PacketIgnored != nil {
			trace.PacketIgnored(Packet{Message: msg, Payload: data})
		}
	}
}

// DialADB opens a connection to svc on the peer. It blocks until the connection
// is authenticated, ctx is done, or the connection is kicked.
func (s *Session) DialADB(ctx context.Context, svc string) (net.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.kicked:
		return nil, fmt.Errorf("kicked: %w", s.err())
	case <-s.authenticated:
	}

	local := globalSocketAddr.Add(1)

	ls := &LocalSocket{
		Local:      local,
		Remote:     0,
		MaxPayload: s.conn.MaxPayloadSize(),
		Send:       s.Send,
		SendAsync:  s.SendAsync,
	}
	if s.supportsDelayedAck() {
		ls.DelayedAck = s.cfg.LocalDelayedAck
	}

	ch, remove := s.registerPendingStream(ls)
	defer remove() // this only does something if it's still pending

	if err := s.Send(A_OPEN, local, ls.DelayedAck, []byte(svc+"\x00"), ctx.Done()); err != nil {
		if errors.Is(err, ErrSendCancelled) {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("send open: %w", err)
	}

	var pair *SocketPair
	select {
	case <-ctx.Done():
	case pair = <-ch:
	case <-s.kicked:
	}
	if pair == nil && !remove() {
		// the read loop connected or rejected the stream while we were giving
		// up, so consume the result (this won't block since the result is sent
		// while holding the lock which remove also takes)
		pair = <-ch
	}
	if err := ctx.Err(); err != nil {
		if pair != nil {
			pair.Close() // tell the peer to go away
		}
		return nil, err
	}
	if pair == nil {
		if isClosed(s.kicked) {
			return nil, fmt.Errorf("kicked: %w", s.err())
		}
		return nil, fmt.Errorf("connection rejected by device")
	}
	return pair, nil
}

func (s *Session) handleOpen(msg Message, data []byte) {
	trace := s.trace.Load()

	for len(data) > 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-1]
	}
	svc := string(data)

	// check the stream limit (the pending open is counted until the stream is
	// registered or fails)
	if s.cfg.MaxStreams > 0 {
		s.mu.Lock()
		if len(s.streams)+s.pendingOpens >= s.cfg.MaxStreams {
			s.mu.Unlock()
			if trace != nil && trace.LocalServiceFail != nil {
				trace.LocalServiceFail(0, msg.Arg0, fmt.Errorf("too many streams (max %d)", s.cfg.MaxStreams))
			}
			s.SendAsync(A_CLSE, 0, msg.Arg0, nil)
			return
		}
		s.pendingOpens++
		s.mu.Unlock()
	}

	fn := func() {
		var (
			local  = globalSocketAddr.Add(1)
			remote = msg.Arg0
		)

		if s.cfg.MaxStreams > 0 {
			defer func() {
				s.mu.Lock()
				s.pendingOpens--
				s.mu.Unlock()
			}()
		}

		sctx := s.dialCtx
		if s.cfg.OpenContext != nil {
			sctx = s.cfg.OpenContext(sctx, svc)
			if sctx == nil {
				panic("OpenContext returned nil")
			}
		}

		if s.cfg.DelayedAck {
			if delayedAckRequested := msg.Arg1 != 0; delayedAckRequested && !s.supportsDelayedAck() {
				if trace != nil && trace.LocalServiceFail != nil {
					trace.LocalServiceFail(local, remote, errors.New("client requested delayed acks but didn't declare support for it"))
				}
				s.SendAsync(A_CLSE, 0, msg.Arg0, nil)
				return
			}
		}

		if s.cfg.Open == nil {
			s.SendAsync(A_CLSE, 0, msg.Arg0, nil)
			return
		}

		if trace != nil && trace.LocalServiceOpen != nil {
			trace.LocalServiceOpen(local, remote, svc)
		}
		lss, err := s.cfg.Open(sctx, svc)
		if err != nil {
			if trace != nil && trace.LocalServiceFail != nil {
				trace.LocalServiceFail(local, remote, err)
			}
			s.SendAsync(A_CLSE, 0, msg.Arg0, nil)
			return
		}
		if trace != nil && trace.LocalServiceSuccess != nil {
			trace.LocalServiceSuccess(local, remote)
		}

		ls := &LocalSocket{
			Local:      local,
			Remote:     remote,
			MaxPayload: s.conn.MaxPayloadSize(),
			Send:       s.Send,
			SendAsync:  s.SendAsync,
		}
		rs := &RemoteSocket{
			Local:      local,
			Remote:     remote,
			MaxPayload: s.conn.MaxPayloadSize(),
			Send:       s.Send,
			SendAsync:  s.SendAsync,
		}
		if s.cfg.DelayedAck && s.supportsDelayedAck() {
			ls.DelayedAck = s.cfg.LocalDelayedAck
			rs.DelayedAck = msg.Arg1 // the client's delayed ack (note: for the adb host daemon, ADB_BURST_MODE=1 is required to enable this)
			if trace != nil && trace.LocalServiceDelayedAck != nil {
				trace.LocalServiceDelayedAck(local, remote, ls.DelayedAck, rs.DelayedAck)
			}
		}
		unregister := s.registerSocket(ls, rs, lss)

		if ls.DelayedAck != 0 {
			s.SendAsync(A_OKAY, local, remote, binary.LittleEndian.AppendUint32(nil, ls.DelayedAck))
		} else {
			s.SendAsync(A_OKAY, local, remote, nil)
		}

		go func() {
			defer func() {
				unregister()
				if trace != nil && trace.LocalServiceClose != nil {
					trace.LocalServiceClose(local, remote)
				}
			}()

			LocalServiceSocket(ls, rs, lss)
		}()
	}
	if s.cfg.LazyOpen {
		go fn()
	} else {
		fn()
	}
}

func (s *Session) handleOkay(msg Message, data []byte) {
	trace := s.trace.Load()

	pair := s.findSocket(msg.Arg1, 0)
	if pair == nil {
		// first OKAY, connect the pending stream (this must be done before we
		// read the next packet since the peer can send A_WRTE/A_CLSE for the
		// new stream immediately)
		var delayedAck uint32
		if s.supportsDelayedAck() && len(data) == 4 {
			delayedAck = binary.LittleEndian.Uint32(data)
		}
		if !s.connectPendingStream(msg.Arg1, msg.Arg0, delayedAck) {
			// no matching connected or pending socket, so tell the peer to
			// close it in case it's for a stream for which we timed out before
			// the peer accepted it
			if trace != nil && trace.PacketSocketUnknown != nil {
				trace.PacketSocketUnknown(Packet{Message: msg, Payload: data})
			}
			s.SendAsync(A_CLSE, msg.Arg1, msg.Arg0, nil)
		}
		return
	}

	pair.rs.Handle(Packet{Message: msg, Payload: data})
}

func (s *Session) handleClose(msg Message, data []byte) {
	trace := s.trace.Load()

	pair := s.findSocket(msg.Arg1, msg.Arg0)
	if pair == nil {
		if !s.rejectPendingStream(msg.Arg1) {
			// no matching connected or pending socket
			if trace != nil && trace.PacketSocketUnknown != nil {
				trace.PacketSocketUnknown(Packet{Message: msg, Payload: data})
			}
		}
		return
	}

	// closes both directions (the peer won't ack anything we write anymore)
	pair.ls.Handle(Packet{Message: msg, Payload: data}) // never fails for A_CLSE
	pair.rs.Handle(Packet{Message: msg, Payload: data})
}

func (s *Session) handleWrite(msg Message, data []byte) {
	trace := s.trace.Load()

	pair := s.findSocket(msg.Arg1, msg.Arg0)
	if pair == nil {
		if trace != nil && trace.PacketSocketUnknown != nil {
			trace.PacketSocketUnknown(Packet{Message: msg, Payload: data})
		}
		return
	}

	if err := pair.ls.Handle(Packet{Message: msg, Payload: data}); err != nil {
		// the peer sent more than it was allowed to, so the stream is broken
		// (the reader will get the error once it consumes what was buffered),
		// but the rest of the session is fine, so just close the stream
		if trace != nil && trace.LocalServiceFail != nil {
			trace.LocalServiceFail(pair.local, pair.remote, err)
		}
		pair.rs.Close() // sends the A_CLSE and fails pending writes
		s.mu.Lock()
		delete(s.streams, pair.local)
		s.mu.Unlock()
	}
}

// Idle returns true if the mux does not have any open streams.
func (s *Session) Idle() bool {
	s.mu.Lock()
	n := len(s.streams)
	s.mu.Unlock()
	return n == 0
}

// CloseStreams closes all open streams. It is intended to be called when the
// connection is kicked.
func (s *Session) CloseStreams() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for local, stream := range s.streams {
		if stream.ls != nil {
			stream.ls.Close()
		}
		if stream.rs != nil {
			stream.rs.Close()
		}
		if stream.lss != nil {
			stream.lss.Close()
		}
		delete(s.streams, local)
	}
}

type sessionStream struct {
	local  uint32
	remote uint32
	ls     *LocalSocket
	rs     *RemoteSocket
	lss    io.ReadWriteCloser
}

func (s *Session) findSocket(local, remote uint32) *sessionStream {
	s.mu.Lock()
	defer s.mu.Unlock()
	if stream, ok := s.streams[local]; ok && (remote == 0 || stream.remote == remote) {
		return stream
	}
	return nil
}

// sessionPendingStream is a stream opened by DialADB which is waiting for the
// peer to accept or reject it.
type sessionPendingStream struct {
	ls *LocalSocket
	ch chan *SocketPair // buffered, receives exactly one value (nil if rejected)
}

// connectPendingStream registers a socket pair for the pending stream with the
// specified local id (if any) and passes it to DialADB. The stream is
// registered atomically so packets for it are routed correctly even if DialADB
// hasn't returned yet.
func (s *Session) connectPendingStream(local, remote, delayedAck uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	pending, ok := s.pendingStreams[local]
	if !ok {
		return false
	}
	delete(s.pendingStreams, local)

	ls := pending.ls
	ls.Remote = remote

	rs := &RemoteSocket{
		Local:      local,
		Remote:     remote,
		MaxPayload: s.conn.MaxPayloadSize(),
		DelayedAck: delayedAck,
		Send:       s.Send,
		SendAsync:  s.SendAsync,
	}

	pending.ch <- &SocketPair{
		LS:      ls,
		RS:      rs,
		OnClose: s.registerSocketLocked(ls, rs, nil),
	}
	return true
}

// rejectPendingStream tells DialADB that the pending stream with the specified
// local id (if any) was rejected by the peer.
func (s *Session) rejectPendingStream(local uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	pending, ok := s.pendingStreams[local]
	if !ok {
		return false
	}
	delete(s.pendingStreams, local)

	pending.ch <- nil
	return true
}

func (s *Session) registerSocket(ls *LocalSocket, rs *RemoteSocket, lss io.ReadWriteCloser) (unregister func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.registerSocketLocked(ls, rs, lss)
}

func (s *Session) registerSocketLocked(ls *LocalSocket, rs *RemoteSocket, lss io.ReadWriteCloser) (unregister func()) {
	if s.streams == nil {
		s.streams = make(map[uint32]*sessionStream)
	}

	stream := &sessionStream{
		local:  ls.Local,
		remote: ls.Remote,
		ls:     ls,
		rs:     rs,
		lss:    lss,
	}
	s.streams[stream.local] = stream

	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()

		if s.streams[stream.local] == stream {
			delete(s.streams, stream.local)
		}
	}
}

// registerPendingStream registers ls as waiting for the peer to accept or
// reject it. The result is sent on the returned channel. The returned remove
// function removes the stream if it is still pending, returning true if so.
func (s *Session) registerPendingStream(ls *LocalSocket) (result <-chan *SocketPair, remove func() bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pendingStreams == nil {
		s.pendingStreams = make(map[uint32]*sessionPendingStream)
	}

	ch := make(chan *SocketPair, 1)
	s.pendingStreams[ls.Local] = &sessionPendingStream{ls: ls, ch: ch}

	return ch, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()

		if _, ok := s.pendingStreams[ls.Local]; !ok {
			return false
		}
		delete(s.pendingStreams, ls.Local)
		return true
	}
}
