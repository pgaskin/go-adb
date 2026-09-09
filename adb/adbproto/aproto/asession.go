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
	"sync"
	"sync/atomic"

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
}

// SessionTrace is a set of hooks to run at various points in the lifecycle of a [Session].
// Any particular hook may be nil. Functions may be called concurrently from
// different goroutines and at arbitrary times. They should avoid blocking for
// extended periods of time.
//
// These hooks should not be used for important logic. They are intended for
// debugging and metrics.
type SessionTrace struct {
	// PacketSent is called when a packet is about to be sent (it won't have the
	// checksum, and may not be split yet).
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

	// set once by Serve before the loop starts (only read afterwards)
	trace   *SessionTrace
	dialCtx context.Context

	// connection lifecycle
	stateMu       sync.Mutex
	connected     chan struct{}
	authenticated chan struct{}
	kicked        chan struct{}
	kickErr       error

	writeMu sync.Mutex // held while writing to conn (reading is single-threaded in Serve)

	mu             sync.Mutex
	streams        map[*sessionStream]struct{}
	pendingStreams map[uint32]*sessionPendingStream // by local socket id
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

	s.conn.Close()

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

// Write sends a packet, splitting the data if required. It holds the write lock
// and is safe to call concurrently.
func (s *Session) Write(cmd Command, arg0, arg1 uint32, data []byte) error {
	if s.trace != nil && s.trace.PacketSent != nil {
		s.trace.PacketSent(cmd, arg0, arg1, data)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if !s.conn.Write(cmd, arg0, arg1, data) {
		return s.conn.Error()
	}
	return nil
}

// Handshake performs a TLS server handshake, holding the write lock so it does
// not interleave with any packet write. It should be called from the Serve
// handshake callback in response to an A_STLS packet.
func (s *Session) Handshake(serverCert *tls.Certificate, verify func(peerCert *x509.Certificate)) bool {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.conn.Handshake(serverCert, verify)
}

// HandshakeClient performs a TLS client handshake, holding the write lock so it
// does not interleave with any packet write. It should be called from the Serve
// handshake callback after sending an A_STLS packet.
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
	s.trace = sessionTrace(ctx)
	s.dialCtx = ctx
	for {
		msg, data, ok := s.conn.Read()
		if !ok {
			return
		}
		if s.trace != nil && s.trace.PacketReceived != nil {
			s.trace.PacketReceived(Packet{Message: msg, Payload: data})
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
			if s.trace != nil && s.trace.PacketUnknown != nil {
				s.trace.PacketUnknown(Packet{Message: msg, Payload: data})
			}
		}
		continue
	ignore:
		if s.trace != nil && s.trace.PacketIgnored != nil {
			s.trace.PacketIgnored(Packet{Message: msg, Payload: data})
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
		Send:       s.Write,
	}
	if s.supportsDelayedAck() {
		ls.DelayedAck = s.cfg.LocalDelayedAck
	}

	ch, remove := s.registerPendingStream(ls)
	defer remove() // this only does something if it's still pending

	if err := s.Write(A_OPEN, local, ls.DelayedAck, []byte(svc+"\x00")); err != nil {
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
	trace := s.trace

	for len(data) > 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-1]
	}
	svc := string(data)

	fn := func() {
		var (
			local  = globalSocketAddr.Add(1)
			remote = msg.Arg0
		)

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
				s.Write(A_CLSE, 0, msg.Arg0, nil)
				return
			}
		}

		if s.cfg.Open == nil {
			s.Write(A_CLSE, 0, msg.Arg0, nil)
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
			s.Write(A_CLSE, 0, msg.Arg0, nil)
			return
		}
		if trace != nil && trace.LocalServiceSuccess != nil {
			trace.LocalServiceSuccess(local, remote)
		}

		ls := &LocalSocket{
			Local:      local,
			Remote:     remote,
			MaxPayload: s.conn.MaxPayloadSize(),
			Send:       s.Write,
		}
		rs := &RemoteSocket{
			Local:      local,
			Remote:     remote,
			MaxPayload: s.conn.MaxPayloadSize(),
			Send:       s.Write,
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
			s.Write(A_OKAY, local, remote, binary.LittleEndian.AppendUint32(nil, ls.DelayedAck))
		} else {
			s.Write(A_OKAY, local, remote, nil)
		}

		go func() {
			if trace != nil && trace.LocalServiceClose != nil {
				trace.LocalServiceSuccess(local, remote)
			}
			defer unregister()

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
	trace := s.trace

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
			s.Write(A_CLSE, msg.Arg1, msg.Arg0, nil)
		}
		return
	}

	pair.rs.Handle(Packet{Message: msg, Payload: data})
}

func (s *Session) handleClose(msg Message, data []byte) {
	trace := s.trace

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
	pair.ls.Handle(Packet{Message: msg, Payload: data})
	pair.rs.Handle(Packet{Message: msg, Payload: data})
}

func (s *Session) handleWrite(msg Message, data []byte) {
	trace := s.trace

	pair := s.findSocket(msg.Arg1, msg.Arg0)
	if pair == nil {
		if trace != nil && trace.PacketSocketUnknown != nil {
			trace.PacketSocketUnknown(Packet{Message: msg, Payload: data})
		}
		return
	}

	pair.ls.Handle(Packet{Message: msg, Payload: data})
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

	for stream := range s.streams {
		if stream.ls != nil {
			stream.ls.Close()
		}
		if stream.rs != nil {
			stream.rs.Close()
		}
		if stream.lss != nil {
			stream.lss.Close()
		}
		delete(s.streams, stream)
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
	for s := range s.streams {
		if (remote == 0 || s.remote == remote) && s.local == local {
			return s
		}
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
		Send:       s.Write,
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
		s.streams = make(map[*sessionStream]struct{})
	}

	stream := &sessionStream{
		local:  ls.Local,
		remote: ls.Remote,
		ls:     ls,
		rs:     rs,
		lss:    lss,
	}
	s.streams[stream] = struct{}{}

	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()

		delete(s.streams, stream)
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
