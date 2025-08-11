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
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"os"
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

// TODO: rewrite and optimize stream logic
// TODO: implement DialADB
// TODO: finish implementing and testing delayed ack

var debug *slog.Logger

func init() {
	if v, _ := strconv.ParseBool(os.Getenv("ADBPROXY_TRACE")); v {
		debug = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	} else {
		debug = slog.New(slog.DiscardHandler)
	}
}

// Trace enables debug logging to the specified logger.
func Trace(logger *slog.Logger) {
	debug = logger
}

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

	// If nonzero, delayed ack will be supported with the specified size. This
	// must also be supported by the Dialer (if backed by adbd, ADB_BURST_MODE
	// must be set).
	DelayedAck int

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
			if s.DelayedAck != 0 {
				banner.Features[adbproto.FeatureDelayedAck] = struct{}{}
			}
			if err := banner.Valid(); err != nil {
				debug.Warn("invalid banner, using anyways", "error", err, "banner", banner.Encode())
			}
			return banner.Encode(), nil
		}()
		if s.bannerErr == nil {
			debug.Debug("generated banner", "banner", s.banner)
		}
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
	if s.DelayedAck != 0 {
		panic("delayed ack not implemented") // TODO: figure out the rest of it, refactor (also see https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/docs/dev/delayed_ack.md)
	}
	if s.DelayedAck < 0 || s.DelayedAck > 0xFFFFFFFF {
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

	if err := s.loadBanner(lctx); err != nil {
		return fmt.Errorf("load banner: %w", err)
	}

	if s.TLS {
		if err := s.loadCertificate(); err != nil {
			return fmt.Errorf("generate tls certificate: %w", err)
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

		t := s.newTransport(c)

		cctx := context.WithValue(lctx, transportContextKey{}, t)
		if s.ConnContext != nil {
			cctx = s.ConnContext(lctx, c)
			if cctx == nil {
				panic("ConnContext returned nil")
			}
		}
		delay = 0

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

	streamsMu sync.Mutex
	stream    uint32
	streams   map[*stream]struct{}

	// must only be used within the main loop
	useTLS  bool
	token   [aproto.AuthTokenSize]byte
	sig     []byte // first auth signature
	adbkey  []byte // presented adbkey during legacy auth (not necessairly the one used for auth) (note: we only need to keep one since adb only sends the primary adbkey, not vendorkeys)
	adbkeyp *aproto.PublicKey
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
	return nil, errors.ErrUnsupported // TODO
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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	debug := debug.With("remote", t.RemoteAddr().String())
	defer func() { debug.Info("kick", "error", t.Error()) }()
	debug.Info("accept")
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

			debug.Info("connect", "banner", string(data), "use_tls", t.useTLS)
			close(t.connected)

			t.useTLS = t.server.TLS

			// HACK: disable tls unless a feature introduced since then is there
			if t.useTLS && t.server.TLSFallback {
				t.useTLS = false
				for _, feat := range tlsFeatures {
					if _, t.useTLS = t.banner.Features[string(feat)]; t.useTLS {
						break
					}
				}
				if !t.useTLS {
					debug.Warn("disabling tls since client seems too old")
				}
			}

			switch {
			case t.useTLS:
				// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=318-325;drc=61197364367c9e404c7da6900658f1b16c42d0da
				if !t.write(aproto.A_STLS, aproto.STLSVersionMin, 0, nil) {
					return
				}
			case authenticator == nil:
				debug.Info("authenticated")
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
				debug.Debug("got new signature")

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
					debug.Debug("auth rejected, asking for the next signature")
					if !t.write(aproto.A_AUTH, aproto.AuthToken, 0, t.token[:]) {
						return
					}
					continue
				}

				debug.Info("authenticated")
				close(t.authenticated)

				if !t.write(aproto.A_CNXN, t.aproto.ProtocolVersion(), t.aproto.MaxPayloadSize(), []byte(t.server.banner)) {
					return
				}

			case aproto.AuthRSAPublicKey:
				raw := stripTrailingNulls(data)
				key, name, err := aproto.ParsePublicKey(raw)
				if err != nil {
					debug.Warn("ignoring invalid pubkey", "err", err, "raw", string(raw))
					continue
				}

				debug.Debug("got new pubkey", "fingerprint", key.Fingerprint(), "name", name)
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
							debug.Info("authenticated")
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

				debug.Debug("doing auth again")
				if _, err := rand.Read(t.token[:]); err != nil {
					t.Kick(fmt.Errorf("auth: failed to generate token: %w", err))
					return
				}
				if !t.write(aproto.A_AUTH, aproto.AuthToken, 0, t.token[:]) {
					return
				}

			default:
				debug.Warn("unhandled packet", "cmd", msg.Command, "arg0", msg.Arg0, "arg1", msg.Arg1, "len", len(data))
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

			debug.Info("stls")

			if t.server.cert == nil {
				panic("adbproxy: server cert is nil") // it should have been generated at startup
			}

			verified := authenticator == nil
			if !t.handshake(t.server.cert, func(peerCert *x509.Certificate) {
				auth := &AuthCertificate{
					Raw: peerCert.Raw,
				}
				if pk, _ := auth.PublicKey(); pk != nil {
					debug.Debug("got cert", "alg", peerCert.PublicKeyAlgorithm, "sigalg", peerCert.SignatureAlgorithm, "subject", peerCert.Subject, "fingerprint", pk.Fingerprint())
				} else {
					debug.Warn("got malformed cert", "alg", peerCert.PublicKeyAlgorithm, "sigalg", peerCert.SignatureAlgorithm, "subject", peerCert.Subject)
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

			debug.Info("authenticated")
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

			if msg.Arg1 != uint32(t.server.DelayedAck) {
				debug.Warn("unexpected OPEN delayed acks", "exp", t.server.DelayedAck, "act", msg.Arg1)
				t.write(aproto.A_CLSE, 0, msg.Arg0, nil)
				continue
			}

			debug := debug.With("id", msg.Arg0)

			svc := string(stripTrailingNulls(data))

			fn := func() {
				sctx := ctx
				if t.server.OpenContext != nil {
					sctx = t.server.OpenContext(sctx, svc)
					if sctx == nil {
						panic("OpenContext returned nil")
					}
				}

				debug.Debug("dialing", "svc", svc)
				conn, err := t.server.Dialer.DialADB(sctx, svc)
				if err != nil {
					debug.Debug("failed to open service", "err", err)
					t.write(aproto.A_CLSE, 0, msg.Arg0, nil)
					return
				}
				debug.Debug("opened service")

				// TODO: refactor into t.newStream
				stream := func() *stream {
					t.streamsMu.Lock()
					defer t.streamsMu.Unlock()
					if t.streams == nil {
						t.streams = make(map[*stream]struct{})
					}
					t.stream++
					stream := &stream{
						local:  t.stream,
						remote: msg.Arg0,
						device: conn,
						asb:    int64(t.server.DelayedAck),
						ready:  make(chan struct{}, 1),
						wqueue: make(chan []byte, 1),
					}
					t.streams[stream] = struct{}{}
					return stream
				}()

				if t.server.DelayedAck != 0 {
					t.write(aproto.A_OKAY, stream.local, stream.remote, binary.LittleEndian.AppendUint32(nil, uint32(t.server.DelayedAck)))
				} else {
					t.write(aproto.A_OKAY, stream.local, stream.remote, nil)
				}

				// TODO: separate read and write socket pair halves (and the device is responsible for closing the one which writes to the client, then we close the other)

				go func() {
					for data := range stream.wqueue {
						if _, err := stream.device.Write(data); err != nil {
							debug.Debug("failed to write to local device socket", "err", err)
							// don't close the device here; there might be more
							// to read from it
							t.write(aproto.A_CLSE, stream.local, stream.remote, nil)
							// note: the client will send a CLSE back when it
							// wants to close its end
							return
						}
						// tell the remote we're ready for another WRTE
						// TODO: do we need to care about delayed acks here?
						t.write(aproto.A_OKAY, stream.local, stream.remote, nil)
					}
				}()

				go func() {
					buf := make([]byte, aproto.MessageSize+t.aproto.MaxPayloadSize())
					for {
						if t.server.DelayedAck == 0 || func() bool {
							stream.mu.Lock()
							defer stream.mu.Unlock()
							return stream.asb <= 0
						}() {
							<-stream.ready
						}

						payload := buf[aproto.MessageSize:]
						if t.server.DelayedAck != 0 {
							asb := func() int64 {
								stream.mu.Lock()
								defer stream.mu.Unlock()
								return stream.asb
							}()
							if asb == 0 {
								continue
							}
							if int64(len(payload)) > asb {
								payload = payload[:asb]
							}
						}

						n, err := stream.device.Read(payload)
						if err != nil {
							if err != io.EOF {
								debug.Debug("failed to read from local device socket", "err", err)
							}
							stream.device.Close()
							t.write(aproto.A_CLSE, stream.local, stream.remote, nil)
							// note: the client will send a CLSE back
							return
						}
						if n > 0 {
							t.write(aproto.A_WRTE, stream.local, stream.remote, payload[:n])
							if t.server.DelayedAck != 0 {
								func() {
									stream.mu.Lock()
									defer stream.mu.Unlock()
									stream.asb -= int64(n)
								}()
							}
						}
					}
				}()
				stream.notifyReady()
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

			var acked int32
			if len(data) != 0 {
				if len(data) != 4 {
					debug.Warn("invalid OKAY payload size", "n", len(data))
					continue
				}
				acked = int32(binary.LittleEndian.Uint32(data))
			}

			stream := t.findLocalSocket(msg.Arg1, 0)
			if stream == nil {
				// TODO: we'll need this for reverse (it'll get sent to us when we send an OPEN)
				break
			}

			func() {
				stream.mu.Lock()
				defer stream.mu.Unlock()
				if t.server.DelayedAck != 0 {
					stream.asb += int64(acked)
					if stream.asb > 0 {
						stream.notifyReady()
					}
				} else {
					stream.notifyReady()
				}
			}()

		case aproto.A_CLSE: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=594-616;drc=9f298fb1f3317371b49439efb20a598b3a881bf3
			select {
			default:
				goto ignore // not connected yet
			case <-t.Authenticated():
			}
			if msg.Arg1 == 0 {
				goto ignore
			}

			stream := t.findLocalSocket(msg.Arg1, msg.Arg0)
			if stream == nil {
				debug.Debug("cannot find stream to close, ignoring", "remote", msg.Arg0, "local", msg.Arg1)
				goto ignore
			}

			stream.device.Close()
			stream.notifyReady()
			func() {
				t.streamsMu.Lock()
				defer t.streamsMu.Unlock()
				delete(t.streams, stream)
			}()

		case aproto.A_WRTE: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=618-625;drc=9f298fb1f3317371b49439efb20a598b3a881bf3
			select {
			default:
				goto ignore // not connected yet
			case <-t.Authenticated():
			}
			if msg.Arg0 == 0 || msg.Arg1 == 0 {
				return
			}

			stream := t.findLocalSocket(msg.Arg1, msg.Arg0)
			if stream == nil {
				debug.Debug("cannot find stream to write, ignoring", "remote", msg.Arg0, "local", msg.Arg1)
				goto ignore
			}

			// if this blocks, it's because the client is misbehaving (sending
			// more than we've ack'd)
			stream.wqueue <- slices.Clone(data) // TODO: optimize this, refactor

		default:
			debug.Warn("unhandled packet", "cmd", msg.Command, "arg0", msg.Arg0, "arg1", msg.Arg1, "len", len(data))
		}
		continue
	ignore:
		debug.Warn("ignoring packet", "cmd", msg.Command, "arg0", msg.Arg0, "arg1", msg.Arg1, "len", len(data))
	}
}

// write locks writeMu and sends packets.
func (t *Transport) write(cmd aproto.Command, arg0 uint32, arg1 uint32, data []byte) bool {
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

func (t *Transport) findLocalSocket(local, remote uint32) *stream {
	t.streamsMu.Lock()
	defer t.streamsMu.Unlock()
	for s := range t.streams {
		if (remote == 0 || s.remote == remote) && s.local == local {
			return s
		}
	}
	return nil
}

type stream struct {
	local  uint32
	remote uint32
	device net.Conn
	ready  chan struct{}
	mu     sync.Mutex
	asb    int64 // available send bytes (can be negative)
	wqueue chan []byte
}

func (s *stream) notifyReady() {
	select {
	case s.ready <- struct{}{}:
		// notified
	default:
		// already have a ready queued (chan buffer is 1)
	}
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
