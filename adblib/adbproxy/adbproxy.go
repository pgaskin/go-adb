// Package adbproxy implements ADB-over-TCP/IP for an existing ADB server.
package adbproxy

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	mrand "math/rand/v2"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pgaskin/go-adb/adb"
	"github.com/pgaskin/go-adb/adb/adbproto"
	"github.com/pgaskin/go-adb/adb/adbproto/aproto"
)

var globalSocketAddr atomic.Uint32 // we could do it per-transport, but this is nicer for debugging

var ErrServerClosed = errors.New("server closed")

type (
	serverContextKey    struct{}
	transportContextKey struct{}
)

// ContextServer gets the Server ctx originated from.
func ContextServer(ctx context.Context) *Server {
	if v := ctx.Value(serverContextKey{}); v != nil {
		return v.(*Server)
	}
	return nil
}

// ContextTransport gets the Transport ctx originated from.
func ContextTransport(ctx context.Context) *Transport {
	if v := ctx.Value(transportContextKey{}); v != nil {
		return v.(*Transport)
	}
	return nil
}

type Server struct {
	// Addr is the TCP address to listen on.
	Addr string

	// Dialer is the upstream dialer to use. If it implements [adb.Features],
	// known features will be exposed.
	Dialer adb.Dialer

	// Banner is the banner to use. Unsupported features will be filtered out
	// before it is sent. If nil, [DeviceBanner] is called with the provided
	// Dialer at startup.
	Banner *aproto.Banner

	// TLS enables TLS.
	TLS bool

	// TLSKey is the TLS private key to use for the server certificate. If
	// nil, [aproto.GenerateKey] is called at startup.
	TLSKey *rsa.PrivateKey

	// TLSFallback, if true, uses a hacky method of detecting if the client
	// supports TLS, and if not, falls back to legacy auth.
	//
	// This is non-standard behaviour.
	TLSFallback bool

	// NoAuthRetry disables retries for failed A_AUTH token authentication by
	// not requesting a retry after the first round of signatures have been
	// retried.
	//
	// This is non-standard behaviour.
	NoAuthRetry bool

	// RetryAuthWithFirstSignature immediately retries authentication with the
	// first signature presented by the client after receiving the public key
	// instead of waiting for the next round of retries.
	//
	// It is intended to be combined with NoAuthRetry for cases where the list
	// of allowed adbkeys is static. Note that the client will display an
	// "failed to authenticate" message, then succeed anyways.
	//
	// This is non-standard behaviour.
	RetryAuthWithFirstSignature bool

	// If true, the listener will not wait for adb services to finish dialing
	// before continuing to process packets. This improves performance and
	// reliability when re-exposing a remote ADB server.
	//
	// This is non-standard behaviour.
	LazyOpen bool

	// If true, delayed ack will be supported by the proxy. This must also be
	// supported by the ADB client connecting to adbproxy (if backed by adbd,
	// ADB_BURST_MODE must be set).
	DelayedAck bool

	// If DelayedAck is true and this is nonzero, delayed ack will be supported
	// for our half of the socket pairs with the specified size.
	//
	// Currently, ADB hardcodes this to 33554432 bytes, but it should
	// theoretically support anything. However, making this smaller than the
	// maximum payload size is counterproductive.
	//
	// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=543-544;drc=9f298fb1f3317371b49439efb20a598b3a881bf3
	LocalDelayedAck int

	// BaseContext optionally specifies a function that returns the base context
	// for incoming requests on this server. The provided Listener is the
	// specific Listener that's about to start accepting requests. If
	// BaseContext is nil, the default is context.Background(). If non-nil, it
	// must return a non-nil context. The context can be used with
	// [ContextServer].
	BaseContext func(net.Listener) context.Context

	// ConnContext optionally specifies a function that modifies the context
	// used for a new connection c. The provided ctx is derived from the base
	// context. The context can be used with [ContextServer] and
	// [ContextTransport].
	ConnContext func(ctx context.Context, c net.Conn) context.Context

	// OpenContext optionally specifies a function that modifies the context
	// used for a new service connection c. The provided ctx is derived from the
	// connection context. The context can be used with [ContextServer] and
	// [ContextTransport].
	OpenContext func(ctx context.Context, svc string) context.Context

	// Auth gets an authenticator for authenticating clients. Each transport get
	// its own one, with ctx being the connection context. Since the auth
	// function is called while blocking the main loop, it may include sleeps
	// for throttling (note: the official adb server currently throttles for one
	// second for each failed auth after 256). If nil, authentication is not
	// required.
	Auth func(ctx context.Context) Authenticator

	bannerOnce sync.Once
	bannerErr  error
	banner     string

	certOnce sync.Once
	certErr  error
	cert     *tls.Certificate

	shuttingDown  atomic.Bool
	listenerGroup sync.WaitGroup

	mu         sync.Mutex
	listeners  map[*net.Listener]struct{}
	transports map[*Transport]struct{}
}

// loadBanner generates the device banner. Only the first call will take effect;
// other calls will wait and return the error from the first. It will be
// automatically called by [Server.ListenAndServe] or [Server.Serve] with the
// listener's context (see [Server.BaseContext]). To use a custom timeout or
// check the error, it should be called directly before starting the server.
func (s *Server) loadBanner(ctx context.Context) error {
	if s.shuttingDown.Load() {
		return ErrServerClosed
	}
	s.bannerOnce.Do(func() {
		s.banner, s.bannerErr = func() (string, error) {
			var err error
			banner := s.Banner.Clone()
			if banner == nil {
				banner, err = DeviceBanner(ctx, s.Dialer)
				if err != nil {
					return "", err
				}
			}
			for f := range banner.Features {
				if !slices.Contains(protocolFeatures, adbproto.Feature(f)) {
					delete(banner.Features, f)
				}
			}
			if s.DelayedAck && s.LocalDelayedAck != 0 {
				banner.Features[adbproto.FeatureDelayedAck] = struct{}{}
			}
			return banner.Encode(), nil
		}()
	})
	return s.bannerErr
}

// loadCertificate generates the TLS certificate (and a private key if
// necessary). Only the first call will take effect; other calls will wait and
// return the error from the first. It will be automatically called by
// [Server.ListenAndServe] or [Server.Serve] with the listener's context (see
// [Server.BaseContext]).
func (s *Server) loadCertificate() error {
	if s.shuttingDown.Load() {
		return ErrServerClosed
	}
	s.certOnce.Do(func() {
		s.cert, s.certErr = func() (*tls.Certificate, error) {
			var err error
			key := s.TLSKey
			if key == nil {
				key, err = aproto.GenerateKey(rand.Reader)
				if err != nil {
					return nil, err
				}
			}
			raw, err := aproto.GenerateCertificate(key)
			if err != nil {
				return nil, err
			}
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return nil, err
			}
			return &tls.Certificate{
				Certificate: [][]byte{raw},
				PrivateKey:  key,
				Leaf:        cert,
			}, nil
		}()
	})
	return s.certErr
}

// note: Go already sets NODELAY on TCP sockets

// ListenAndServe listens on the TCP network address s.Addr and then calls
// [Serve] to handle requests on incoming connections.
func (s *Server) ListenAndServe() error {
	if s.shuttingDown.Load() {
		return ErrServerClosed
	}

	l, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	defer l.Close()

	return s.Serve(l)
}

// Serve accepts incoming connections on the Listener l, creating a new service
// goroutine for each.
func (s *Server) Serve(l net.Listener) error {
	if s.LocalDelayedAck < 0 || s.LocalDelayedAck > 0xFFFFFFFF {
		return fmt.Errorf("delayed ack bytes out of range")
	}

	lorig := l
	l = &onceCloseListener{Listener: lorig}

	if !s.trackListener(&l, true) {
		return ErrServerClosed
	}
	defer s.trackListener(&l, false)

	ctx := context.Background()

	lctx := context.WithValue(ctx, serverContextKey{}, s)
	if s.BaseContext != nil {
		lctx = s.BaseContext(lorig)
		if lctx == nil {
			panic("BaseContext returned a nil context")
		}
	}
	trace := contextServerTrace(ctx)

	if err := s.loadBanner(lctx); err != nil {
		return fmt.Errorf("load banner: %w", err)
	}
	if trace != nil && trace.BannerGenerated != nil {
		trace.BannerGenerated(s.banner)
	}

	if s.TLS {
		if err := s.loadCertificate(); err != nil {
			return fmt.Errorf("generate tls certificate: %w", err)
		}
		if trace != nil && trace.CertificateGenerated != nil {
			trace.CertificateGenerated(s.cert)
		}
	}

	var delay time.Duration
	for {
		c, err := l.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				delay = min(1*time.Second, cmp.Or(delay*2, 5*time.Millisecond))
				time.Sleep(delay)
				continue
			}
			if s.shuttingDown.Load() {
				return ErrServerClosed
			}
			return err
		}
		delay = 0

		t := s.newTransport(c)

		cctx := context.WithValue(lctx, transportContextKey{}, t)
		if s.ConnContext != nil {
			cctx = s.ConnContext(cctx, c)
			if cctx == nil {
				panic("ConnContext returned nil")
			}
		}

		go func() {
			s.trackTransport(t, true)
			defer s.trackTransport(t, false)
			t.serve(cctx)
		}()
	}
}

func (s *Server) closeListeners() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	for l := range s.listeners {
		if err := (*l).Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *Server) closeIdleConns() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	var active bool
	for t := range s.transports {
		if !t.Idle() {
			active = true
			continue
		}
		t.Kick(ErrServerClosed)
		delete(s.transports, t)
	}
	return !active
}

// Close immediately closes the listener and all connections, returning the
// errors from calling Close on all listeners.
func (s *Server) Close() error {
	s.shuttingDown.Store(true)
	clerr := s.closeListeners()
	s.listenerGroup.Wait()

	s.mu.Lock()
	defer s.mu.Unlock()
	for t := range s.transports {
		t.Kick(ErrServerClosed)
		delete(s.transports, t)
	}
	return clerr
}

// Shutdown stops accepting new connections and waits for all connections to
// close, then returns the error from calling close on all listeners. If the
// context expires before shutdown is complete, it returns that error instead.
func (s *Server) Shutdown(ctx context.Context) error {
	const shutdownPollIntervalMax = 500 * time.Millisecond

	s.shuttingDown.Store(true)
	clerr := s.closeListeners()
	s.listenerGroup.Wait()

	// see net/http.Server.Shutdown logic for why this is done
	pollIntervalBase := time.Millisecond
	nextPollInterval := func() time.Duration {
		interval := pollIntervalBase + time.Duration(mrand.IntN(int(pollIntervalBase/10)))
		pollIntervalBase = min(pollIntervalBase*2, shutdownPollIntervalMax)
		return interval
	}

	timer := time.NewTimer(nextPollInterval())
	defer timer.Stop()
	for {
		if s.closeIdleConns() {
			return clerr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			timer.Reset(nextPollInterval())
		}
	}
}

func (s *Server) trackListener(ln *net.Listener, add bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listeners == nil {
		s.listeners = make(map[*net.Listener]struct{})
	}
	if add {
		if s.shuttingDown.Load() {
			return false
		}
		s.listeners[ln] = struct{}{}
		s.listenerGroup.Add(1)
	} else {
		delete(s.listeners, ln)
		s.listenerGroup.Done()
	}
	return true
}

func (s *Server) trackTransport(c *Transport, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.transports == nil {
		s.transports = make(map[*Transport]struct{})
	}
	if add {
		s.transports[c] = struct{}{}
	} else {
		delete(s.transports, c)
	}
}

type Transport struct {
	server *Server // only for getting config

	writeMu sync.Mutex // must be held while writing (reading is single-threaded)
	conn    net.Conn
	aproto  *aproto.Conn

	stateMu       sync.Mutex     // must be held while reading/writing (except for reading the chans) (should not be held during io)
	banner        *aproto.Banner // never write to it; always swap it
	connected     chan struct{}
	authenticated chan struct{}

	kickMu  sync.Mutex // must be held while reading/writing (except for reading the chan)
	kickErr error
	kicked  chan struct{}

	streamsMu      sync.Mutex
	streams        map[*stream]struct{}
	pendingStreams map[*aproto.LocalSocket]chan *aproto.RemoteSocket

	// must only be used within the main loop
	useTLS  bool
	token   [aproto.AuthTokenSize]byte
	sig     []byte // first auth signature
	adbkey  []byte // presented adbkey during legacy auth (not necessairly the one used for auth) (note: we only need to keep one since adb only sends the primary adbkey, not vendorkeys)
	adbkeyp *aproto.PublicKey

	traceWrite func(cmd aproto.Command, arg0 uint32, arg1 uint32, data []byte)
}

func (s *Server) newTransport(conn net.Conn) *Transport {
	return &Transport{
		server:        s,
		conn:          conn,
		aproto:        aproto.New(conn),
		connected:     make(chan struct{}),
		authenticated: make(chan struct{}),
		kicked:        make(chan struct{}),
	}
}

// LocalAddr returns the local network address.
func (t *Transport) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (t *Transport) RemoteAddr() net.Addr {
	return t.conn.RemoteAddr()
}

// Idle returns true if the transport does not have any open streams.
func (t *Transport) Idle() bool {
	t.streamsMu.Lock()
	n := len(t.streams)
	t.stateMu.Unlock()
	return n == 0
}

// Connected returns a channel which gets closed once the peer connection is
// negotiated.
func (t *Transport) Connected() <-chan struct{} {
	return t.connected
}

// Authenticated returns a channel which gets closed once the peer has
// authenticated successfully. An Authenticated channel is always already
// Connected.
func (t *Transport) Authenticated() <-chan struct{} {
	return t.authenticated
}

// Kicked returns a channel which gets closed when the transport is kicked by
// either side. The reason can be found by calling Error.
func (t *Transport) Kicked() <-chan struct{} {
	return t.kicked
}

// Error returns the reason why the transport was kicked, or nil otherwise.
func (t *Transport) Error() error {
	t.kickMu.Lock()
	err := t.kickErr
	t.kickMu.Unlock()
	return err
}

// Kick kicks the transport with the specified error (or a generic one if nil)
// if the transport has not been kicked yet. This closes the TCP connection.
func (t *Transport) Kick(err error) {
	t.kickMu.Lock()
	if t.kickErr != nil {
		t.kickMu.Unlock()
		return
	}
	if err == nil {
		err = errors.New("server kicked transport")
	}
	t.kickErr = err
	close(t.kicked)
	t.kickMu.Unlock()

	t.conn.Close()

	// close streams (just in case they're stuck on IO -- especially the local
	// service sockets -- and are still lingering)
	//
	// do it in a new goroutine just in case anything is misbehaving (since the
	// net.Conn objects come from user-provided implementations)
	go func() {
		t.streamsMu.Lock()
		defer t.streamsMu.Unlock()

		for stream := range t.streams {
			if stream.ls != nil {
				stream.ls.Close()
			}
			if stream.rs != nil {
				stream.rs.Close()
			}
			if stream.lss != nil {
				stream.lss.Close()
			}
			delete(t.streams, stream)
		}
	}()
}

var (
	_ adb.Dialer   = (*Transport)(nil)
	_ adb.Features = (*Transport)(nil)
)

// DialADB connects to a service on the client.
func (t *Transport) DialADB(ctx context.Context, svc string) (net.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.Kicked():
		return nil, fmt.Errorf("kicked: %w", t.Error())
	case <-t.Authenticated(): // authenticated implies connected
	}

	local := globalSocketAddr.Add(1)

	ls := &aproto.LocalSocket{
		Local:      local,
		Remote:     0,
		MaxPayload: t.aproto.MaxPayloadSize(),
		Send:       t.send,
	}
	if t.SupportsFeature(adbproto.FeatureDelayedAck) {
		ls.DelayedAck = uint32(t.server.LocalDelayedAck)
	}

	ch, remove := t.registerPendingStream(ls)
	defer remove() // this only does something if it's still pending

	if err := t.send(aproto.A_OPEN, local, ls.DelayedAck, []byte(svc+"\x00")); err != nil {
		return nil, fmt.Errorf("send open: %w", err)
	}

	var rs *aproto.RemoteSocket
	select {
	case <-ctx.Done():
	case remote := <-ch:
		rs = remote
	case <-t.Kicked():
		// avoid a race condition by checking for remote again specifically
		select {
		default:
			return nil, fmt.Errorf("kicked: %w", t.Error())
		case remote := <-ch:
			rs = remote
		}
	}
	if rs == nil {
		return nil, fmt.Errorf("connection rejected by device")
	}
	ls.Remote = rs.Remote

	unregister := t.registerSocket(ls, rs, nil)

	pair := &socketPair{
		LS:     ls,
		RS:     rs,
		closed: unregister,
	}
	return pair, nil
}

// SupportsFeature checks whether a feature is supported by the client.It
// returns false for everything until Connected.
func (t *Transport) SupportsFeature(f adbproto.Feature) bool {
	t.stateMu.Lock()
	var ok bool
	if t.banner != nil {
		_, ok = t.banner.Features[string(f)]
	}
	t.stateMu.Unlock()
	return ok
}

// Features returns an iterator of all features supported by the client.
func (t *Transport) Features() iter.Seq[adbproto.Feature] {
	t.stateMu.Lock()
	banner := t.banner
	t.stateMu.Unlock()
	return func(yield func(adbproto.Feature) bool) {
		if banner != nil {
			for f := range banner.Features {
				if !yield(adbproto.Feature(f)) {
					return
				}
			}
		}
	}
}

// serve runs the main loop for the connection. It blocks until the transport
// has been kicked.
func (t *Transport) serve(ctx context.Context) {
	trace := contextServerTrace(ctx)
	if trace != nil && trace.Accepted != nil {
		trace.Accepted()
	}
	if trace != nil && trace.Kicked != nil {
		defer func() { trace.Kicked(t.Error()) }()
	}
	if trace != nil && trace.PacketSent != nil {
		t.traceWrite = trace.PacketSent
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() { t.Kick(nil) }()
	var authenticator Authenticator
	if t.server.Auth != nil {
		authenticator = t.server.Auth(ctx)
	}
	for {
		msg, data, ok := t.aproto.Read()
		if !ok {
			return
		}
		if trace != nil && trace.PacketReceived != nil {
			trace.PacketReceived(aproto.Packet{
				Message: msg,
				Payload: data,
			})
		}
		switch msg.Command {
		case aproto.A_CNXN: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=407-433;drc=61197364367c9e404c7da6900658f1b16c42d0da
			select {
			case <-t.Connected():
				// note: for generic transports, adb would reset the transport
				// and auth again, but we don't need to support that for tcp,
				// which makes things much simpler
				goto ignore // already connected
			default:
			}

			func() {
				t.stateMu.Lock()
				defer t.stateMu.Unlock()

				banner := new(aproto.Banner)
				banner.Decode(string(data))
				t.banner = banner
			}()

			t.useTLS = t.server.TLS

			// HACK: disable tls unless a feature introduced since then is there
			if t.useTLS && t.server.TLSFallback {
				t.useTLS = false
				for _, feat := range tlsFeatures {
					if _, t.useTLS = t.banner.Features[string(feat)]; t.useTLS {
						break
					}
				}
			}

			if trace != nil && trace.Connected != nil {
				trace.Connected(string(data), t.useTLS)
			}
			close(t.connected)

			switch {
			case t.useTLS:
				// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=318-325;drc=61197364367c9e404c7da6900658f1b16c42d0da
				if !t.write(aproto.A_STLS, aproto.STLSVersionMin, 0, nil) {
					return
				}
			case authenticator == nil:
				if trace != nil && trace.Authenticated != nil {
					trace.Authenticated()
				}
				close(t.authenticated)

				if !t.write(aproto.A_CNXN, t.aproto.ProtocolVersion(), t.aproto.MaxPayloadSize(), []byte(t.server.banner)) {
					return
				}
			default:
				if _, err := rand.Read(t.token[:]); err != nil {
					t.Kick(fmt.Errorf("auth: failed to generate token: %w", err))
					return
				}
				if !t.write(aproto.A_AUTH, aproto.AuthToken, 0, t.token[:]) {
					return
				}
			}

		case aproto.A_AUTH: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=458-498;drc=61197364367c9e404c7da6900658f1b16c42d0da;bpv=1;bpt=1
			select {
			default:
				goto ignore // not connected yet
			case <-t.Authenticated():
				goto ignore // already authenticated
			case <-t.Connected():
			}
			if t.useTLS {
				goto ignore // ignore all auth packets when using tls
			}

			// note: when the adb host daemon has vendor keys loaded, it will
			// send initial A_AUTH packets for each of them, but if rejected, it
			// will only send the public key for the primary adbkey rather than
			// all vendor keys

			switch msg.Arg0 {
			case aproto.AuthSignature:
				if t.sig == nil {
					t.sig = slices.Clone(data)
				}
				auth := &AuthSignature{
					Token:     t.token,
					Signature: slices.Clone(data),
				}
				if t.adbkeyp != nil {
					if auth.verifyInternal(t.adbkeyp) {
						auth.AdbKey = t.adbkey
					}
				}
				if !authenticator.Auth(auth) {
					// ask for another key
					if !t.write(aproto.A_AUTH, aproto.AuthToken, 0, t.token[:]) {
						return
					}
					continue
				}

				if trace != nil && trace.Authenticated != nil {
					trace.Authenticated()
				}
				close(t.authenticated)

				if !t.write(aproto.A_CNXN, t.aproto.ProtocolVersion(), t.aproto.MaxPayloadSize(), []byte(t.server.banner)) {
					return
				}

			case aproto.AuthRSAPublicKey:
				raw := stripTrailingNulls(data)
				key, _, err := aproto.ParsePublicKey(raw)
				if err != nil {
					continue
				}

				t.adbkey = slices.Clone(raw)
				t.adbkeyp = key

				// HACK
				if t.server.RetryAuthWithFirstSignature && t.sig != nil {
					auth := &AuthSignature{
						AdbKey:    t.adbkey,
						Token:     t.token,
						Signature: slices.Clone(t.sig),
					}
					if auth.verifyInternal(t.adbkeyp) {
						if authenticator.Auth(auth) {
							if trace != nil && trace.Authenticated != nil {
								trace.Authenticated()
							}
							close(t.authenticated)

							if !t.write(aproto.A_CNXN, t.aproto.ProtocolVersion(), t.aproto.MaxPayloadSize(), []byte(t.server.banner)) {
								return
							}
							continue
						}
					}
				}

				// HACK
				if t.server.NoAuthRetry {
					continue
				}

				if _, err := rand.Read(t.token[:]); err != nil {
					t.Kick(fmt.Errorf("auth: failed to generate token: %w", err))
					return
				}
				if !t.write(aproto.A_AUTH, aproto.AuthToken, 0, t.token[:]) {
					return
				}

			default:
				if trace != nil && trace.PacketUnknown != nil {
					trace.PacketUnknown(aproto.Packet{
						Message: msg,
						Payload: data,
					})
				}
			}

		case aproto.A_STLS: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/daemon/auth.cpp;l=358-383;drc=61197364367c9e404c7da6900658f1b16c42d0da;bpv=1;bpt=1
			select {
			default:
				goto ignore // not connected yet
			case <-t.Authenticated():
				goto ignore // already authenticated
			case <-t.Connected():
			}
			if !t.useTLS {
				goto ignore // ignore all stls packets when not using tls
			}

			if t.server.cert == nil {
				panic("adbproxy: server cert is nil") // it should have been generated at startup
			}

			verified := authenticator == nil
			if !t.handshake(t.server.cert, func(peerCert *x509.Certificate) {
				auth := &AuthCertificate{
					Raw: peerCert.Raw,
				}
				if !verified && authenticator != nil {
					verified = authenticator.Auth(auth)
				}
			}) {
				return
			}
			if !verified {
				t.Kick(errors.New("tls authentication failed")) // can't try again
				return
			}

			if trace != nil && trace.Authenticated != nil {
				trace.Authenticated()
			}
			close(t.authenticated)

			if !t.write(aproto.A_CNXN, t.aproto.ProtocolVersion(), t.aproto.MaxPayloadSize(), []byte(t.server.banner)) {
				return
			}

		case aproto.A_SYNC: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/docs/dev/protocol.md;l=191-207;drc=593dc053eb97047637ff813081d9c2de55e17a46
			goto ignore // never valid

		case aproto.A_OPEN: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=500-552;drc=9f298fb1f3317371b49439efb20a598b3a881bf3
			select {
			default:
				goto ignore // not connected yet
			case <-t.Connected():
			}
			if msg.Arg0 == 0 {
				goto ignore
			}

			svc := string(stripTrailingNulls(data))

			fn := func() {
				var (
					local  = globalSocketAddr.Add(1)
					remote = msg.Arg0
				)

				sctx := ctx
				if t.server.OpenContext != nil {
					sctx = t.server.OpenContext(sctx, svc)
					if sctx == nil {
						panic("OpenContext returned nil")
					}
				}

				if t.server.DelayedAck {
					if delayedAckRequested := msg.Arg1 != 0; delayedAckRequested && !t.SupportsFeature(adbproto.FeatureDelayedAck) {
						if trace != nil && trace.LocalServiceFail != nil {
							trace.LocalServiceFail(local, remote, errors.New("client requested delayed acks but didn't declare support for it"))
						}
						t.write(aproto.A_CLSE, 0, msg.Arg0, nil)
						return
					}
				}

				if trace != nil && trace.LocalServiceDial != nil {
					trace.LocalServiceDial(local, remote, svc)
				}
				lss, err := t.server.Dialer.DialADB(sctx, svc)
				if err != nil {
					if trace != nil && trace.LocalServiceFail != nil {
						trace.LocalServiceFail(local, remote, err)
					}
					t.write(aproto.A_CLSE, 0, msg.Arg0, nil)
					return
				}
				if trace != nil && trace.LocalServiceSuccess != nil {
					trace.LocalServiceSuccess(local, remote)
				}

				ls := &aproto.LocalSocket{
					Local:      local,
					Remote:     remote,
					MaxPayload: t.aproto.MaxPayloadSize(),
					Send:       t.send,
				}
				rs := &aproto.RemoteSocket{
					Local:      local,
					Remote:     remote,
					MaxPayload: t.aproto.MaxPayloadSize(),
					Send:       t.send,
				}
				if t.server.DelayedAck && t.SupportsFeature(adbproto.FeatureDelayedAck) {
					ls.DelayedAck = uint32(t.server.LocalDelayedAck)
					rs.DelayedAck = msg.Arg1 // the client's delayed ack (note: for the adb host daemon, ADB_BURST_MODE=1 is required to enable this)
					if trace != nil && trace.LocalServiceDelayedAck != nil {
						trace.LocalServiceDelayedAck(local, remote, ls.DelayedAck, rs.DelayedAck)
					}
				}
				unregister := t.registerSocket(ls, rs, lss)

				if ls.DelayedAck != 0 {
					t.write(aproto.A_OKAY, uint32(local), uint32(remote), binary.LittleEndian.AppendUint32(nil, ls.DelayedAck))
				} else {
					t.write(aproto.A_OKAY, uint32(local), uint32(remote), nil)
				}

				go func() {
					if trace != nil && trace.LocalServiceClose != nil {
						trace.LocalServiceSuccess(local, remote)
					}
					defer unregister()

					aproto.LocalServiceSocket(ls, rs, lss)
				}()
			}
			if t.server.LazyOpen {
				go fn()
			} else {
				fn()
			}

		case aproto.A_OKAY: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=554-592;drc=9f298fb1f3317371b49439efb20a598b3a881bf3
			select {
			default:
				goto ignore // not connected yet
			case <-t.Authenticated():
			}
			if msg.Arg0 == 0 || msg.Arg1 == 0 {
				goto ignore
			}

			pair := t.findSocket(msg.Arg1, 0)
			if pair == nil {
				if ch := t.findPendingSocket(msg.Arg1); ch != nil {
					// first OKAY, create the connection
					var delayedAck uint32
					if t.SupportsFeature(adbproto.FeatureDelayedAck) && len(data) == 4 {
						delayedAck = binary.LittleEndian.Uint32(data)
					}
					rs := &aproto.RemoteSocket{
						Local:      msg.Arg1,
						Remote:     msg.Arg0,
						MaxPayload: t.aproto.MaxPayloadSize(),
						DelayedAck: delayedAck,
						Send:       t.send,
					}
					select {
					case ch <- rs:
					default:
						// DialADB isn't waiting anymore, close it immediately
						rs.Close()
					}
				} else {
					// no matching connected or pending socket
					if trace != nil && trace.PacketSocketUnknown != nil {
						trace.PacketSocketUnknown(aproto.Packet{
							Message: msg,
							Payload: data,
						})
					}
				}
				continue
			}

			pair.rs.Handle(aproto.Packet{
				Message: msg,
				Payload: data,
			})

		case aproto.A_CLSE: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=594-616;drc=9f298fb1f3317371b49439efb20a598b3a881bf3
			select {
			default:
				goto ignore // not connected yet
			case <-t.Authenticated():
			}
			if msg.Arg1 == 0 {
				goto ignore
			}

			pair := t.findSocket(msg.Arg1, msg.Arg0)
			if pair == nil {
				if ch := t.findPendingSocket(msg.Arg1); ch != nil {
					// reject
					select {
					case ch <- nil:
					default:
						// DialADB isn't waiting anymore
					}
				} else {
					// no matching connected or pending socket
					if trace != nil && trace.PacketSocketUnknown != nil {
						trace.PacketSocketUnknown(aproto.Packet{
							Message: msg,
							Payload: data,
						})
					}
				}
				continue
			}

			pair.ls.Handle(aproto.Packet{
				Message: msg,
				Payload: data,
			})

		case aproto.A_WRTE: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=618-625;drc=9f298fb1f3317371b49439efb20a598b3a881bf3
			select {
			default:
				goto ignore // not connected yet
			case <-t.Authenticated():
			}
			if msg.Arg0 == 0 || msg.Arg1 == 0 {
				return
			}

			pair := t.findSocket(msg.Arg1, msg.Arg0)
			if pair == nil {
				if trace != nil && trace.PacketSocketUnknown != nil {
					trace.PacketSocketUnknown(aproto.Packet{
						Message: msg,
						Payload: data,
					})
				}
				continue
			}

			pair.ls.Handle(aproto.Packet{
				Message: msg,
				Payload: data,
			})

		default:
			if trace != nil && trace.PacketUnknown != nil {
				trace.PacketUnknown(aproto.Packet{
					Message: msg,
					Payload: data,
				})
			}
		}
		continue
	ignore:
		if trace != nil && trace.PacketIgnored != nil {
			trace.PacketIgnored(aproto.Packet{
				Message: msg,
				Payload: data,
			})
		}
	}
}

func (t *Transport) send(cmd aproto.Command, arg0 uint32, arg1 uint32, data []byte) error {
	if !t.write(cmd, arg0, arg1, data) {
		return t.aproto.Error()
	}
	return nil
}

// write locks writeMu and sends packets.
func (t *Transport) write(cmd aproto.Command, arg0 uint32, arg1 uint32, data []byte) bool {
	if t.traceWrite != nil {
		t.traceWrite(cmd, arg0, arg1, data)
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.aproto.Write(cmd, arg0, arg1, data)
}

// handshake locks writeMu and performs a TLS server handshake.
func (t *Transport) handshake(serverCert *tls.Certificate, verify func(peerCert *x509.Certificate)) bool {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.aproto.Handshake(serverCert, verify)
}

func (t *Transport) findSocket(local, remote uint32) *stream {
	t.streamsMu.Lock()
	defer t.streamsMu.Unlock()
	for s := range t.streams {
		if (remote == 0 || s.remote == remote) && s.local == local {
			return s
		}
	}
	return nil
}

func (t *Transport) findPendingSocket(local uint32) chan<- *aproto.RemoteSocket {
	t.streamsMu.Lock()
	defer t.streamsMu.Unlock()
	for s, ch := range t.pendingStreams {
		if s.Local == local {
			delete(t.pendingStreams, s)
			return ch
		}
	}
	return nil
}

func (t *Transport) registerSocket(ls *aproto.LocalSocket, rs *aproto.RemoteSocket, lss net.Conn) (unregister func()) {
	t.streamsMu.Lock()
	defer t.streamsMu.Unlock()

	if t.streams == nil {
		t.streams = make(map[*stream]struct{})
	}

	stream := &stream{
		local:  ls.Local,
		remote: ls.Remote,
		ls:     ls,
		rs:     rs,
		lss:    lss,
	}
	t.streams[stream] = struct{}{}

	return func() {
		t.streamsMu.Lock()
		defer t.streamsMu.Unlock()

		delete(t.streams, stream)
	}
}

func (t *Transport) registerPendingStream(ls *aproto.LocalSocket) (remote <-chan *aproto.RemoteSocket, done func()) {
	t.streamsMu.Lock()
	defer t.streamsMu.Unlock()

	if t.pendingStreams == nil {
		t.pendingStreams = make(map[*aproto.LocalSocket]chan *aproto.RemoteSocket)
	}

	ch := make(chan *aproto.RemoteSocket, 1)
	t.pendingStreams[ls] = ch

	return ch, func() {
		t.streamsMu.Lock()
		defer t.streamsMu.Unlock()

		delete(t.pendingStreams, ls)
	}
}

type stream struct {
	local  uint32
	remote uint32
	ls     *aproto.LocalSocket
	rs     *aproto.RemoteSocket
	lss    net.Conn
}

// DeviceBanner creates a banner for the specified adb server. If srv implements
// [adb.Features], known protocol-level features will be added from it.
func DeviceBanner(ctx context.Context, srv adb.Dialer) (*aproto.Banner, error) {
	const sep = "._-=-_."

	var cmd strings.Builder
	cmd.WriteString("echo ")
	cmd.WriteString(sep)
	for _, prop := range aproto.ConnectionProps {
		cmd.WriteString(";getprop '")
		cmd.WriteString(prop)
		cmd.WriteString("';echo ")
		cmd.WriteString(sep)
	}

	c, err := adb.Exec(ctx, srv, cmd.String())
	if err != nil {
		return nil, fmt.Errorf("get props: %w", err)
	}

	props, err := io.ReadAll(c)
	if err != nil {
		panic(err)
	}
	defer c.Close()

	spl := strings.Split(string(props), sep)
	if len(spl) != len(aproto.ConnectionProps)+2 {
		return nil, fmt.Errorf("get props: invalid output (%q)", string(props))
	}

	b := &aproto.Banner{
		Type:     "device",
		Props:    map[string]string{},
		Features: map[string]struct{}{},
	}
	for i, prop := range aproto.ConnectionProps {
		b.Props[prop] = strings.TrimSpace(spl[i+1])
	}
	if srv, ok := srv.(adb.Features); ok {
		for _, feat := range protocolFeatures {
			if srv.SupportsFeature(feat) {
				b.Features[string(feat)] = struct{}{}
			}
		}
	}
	return b, nil
}

// tlsFeatures contains features added since the "Add A_STLS command" commit
// from oldest to newest.
//
//	git -C platform/packages/modules/adb log -pS 'const char* const kFeature' 64fab7573566c80fb3003a3b7ca9063e240e8db5..HEAD@{2025-08-08} -- transport.cpp | grep '^[+]const char[*] const kFeature' | cut -d '"' -f2 | tac
var tlsFeatures = []adbproto.Feature{
	"track_app",
	"sendrecv_v2_brotli",
	"sendrecv_v2",
	"sendrecv_v2_lz4",
	"sendrecv_v2_dry_run_send",
	"sendrecv_v2_zstd",
	"openscreen_mdns",
	"delayed_ack",
	"devicetracker_proto_format",
	"devraw",
	"app_info",
	"server_status",
}

// protocolFeatures contains known protocol-level features.
//
// note: features should be added here when added to adbproto
var protocolFeatures = []adbproto.Feature{
	adbproto.FeatureShell2,
	adbproto.FeatureCmd,
	adbproto.FeatureStat2,
	adbproto.FeatureLs2,
	adbproto.FeatureLibusb,
	adbproto.FeaturePushSync,
	adbproto.FeatureApex,
	adbproto.FeatureFixedPushMkdir,
	adbproto.FeatureAbb,
	adbproto.FeatureFixedPushSymlinkTimestamp,
	adbproto.FeatureAbbExec,
	adbproto.FeatureRemountShell,
	adbproto.FeatureTrackApp,
	adbproto.FeatureSendRecv2,
	adbproto.FeatureSendRecv2Brotli,
	adbproto.FeatureSendRecv2LZ4,
	adbproto.FeatureSendRecv2Zstd,
	adbproto.FeatureSendRecv2DryRunSend,
	// needs transport support: adbproto.FeatureDelayedAck,
	adbproto.FeatureOpenscreenMdns,
	adbproto.FeatureDeviceTrackerProtoFormat,
	adbproto.FeatureDevRaw,
	adbproto.FeatureAppInfo,
	adbproto.FeatureServerStatus,
}

type onceCloseListener struct {
	net.Listener
	once sync.Once
	err  error
}

func (oc *onceCloseListener) Close() error {
	oc.once.Do(oc.close)
	return oc.err
}

func (oc *onceCloseListener) close() {
	oc.err = oc.Listener.Close()
}

func stripTrailingNulls(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
}

type shutdownRD interface {
	CloseRead() error
}

type shutdownWR interface {
	CloseWrite() error
}

var (
	_ shutdownRD = (*net.TCPConn)(nil)
	_ shutdownWR = (*net.TCPConn)(nil)
)

// socketPair combines a LS and a RS into a [net.Conn]. It behaves similarly to
// a [net.TCPConn].
type socketPair struct {
	LS     *aproto.LocalSocket
	RS     *aproto.RemoteSocket
	closed func()
}

var (
	_ net.Conn   = (*socketPair)(nil)
	_ shutdownRD = (*socketPair)(nil)
	_ shutdownWR = (*socketPair)(nil)
)

type socketAddr uint32

func (a socketAddr) Network() string {
	return "adb"
}

func (a socketAddr) String() string {
	return strconv.FormatUint(uint64(a), 10)
}

func (d *socketPair) Read(b []byte) (n int, err error) {
	if d.LS == nil || d.RS == nil || d.LS.Local != d.RS.Local || d.LS.Remote != d.RS.Remote {
		panic("not a socket pair")
	}
	return d.LS.Read(b)
}

func (d *socketPair) Write(b []byte) (n int, err error) {
	if d.LS == nil || d.RS == nil || d.LS.Local != d.RS.Local || d.LS.Remote != d.RS.Remote {
		panic("not a socket pair")
	}
	return d.RS.Write(b)
}

func (d *socketPair) CloseRead() error {
	if err := d.LS.Close(); err != nil {
		return fmt.Errorf("local: %w", err)
	}
	return nil
}

func (d *socketPair) CloseWrite() error {
	if err := d.RS.Close(); err != nil {
		return fmt.Errorf("remote: %w", err)
	}
	return nil
}

func (d *socketPair) Close() error {
	if d.closed != nil {
		defer d.closed()
	}
	return errors.Join(
		d.CloseRead(),
		d.CloseWrite(),
	)
}

func (d *socketPair) LocalAddr() net.Addr {
	return socketAddr(d.LS.Local)
}

func (d *socketPair) RemoteAddr() net.Addr {
	return socketAddr(d.RS.Remote)
}

func (d *socketPair) SetDeadline(t time.Time) error {
	d.LS.SetDeadline(t)
	d.RS.SetDeadline(t)
	return nil
}

func (d *socketPair) SetReadDeadline(t time.Time) error {
	d.LS.SetDeadline(t)
	return nil
}

func (d *socketPair) SetWriteDeadline(t time.Time) error {
	d.RS.SetDeadline(t)
	return nil
}
