// Package adbproxy implements ADB-over-TCP/IP for an existing ADB server.
package adbproxy

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"iter"
	"maps"
	mrand "math/rand/v2"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pgaskin/go-adb/adb"
	"github.com/pgaskin/go-adb/adb/adbproto"
	"github.com/pgaskin/go-adb/adb/adbproto/aproto"
)

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

func (s *Server) closeIdleConns(ctx context.Context) bool {
	s.mu.Lock()
	var active bool
	var idle []*Transport
	for t := range s.transports {
		if !t.Idle() {
			active = true
			continue
		}
		idle = append(idle, t)
		delete(s.transports, t)
	}
	s.mu.Unlock()

	// give the transports a chance to send the A_CLSE for the streams which
	// were just closed (since kicking doesn't wait for queued packets), but
	// they're kicked regardless since it's harmless if they don't get through
	for _, t := range idle {
		t.Shutdown(ctx, ErrServerClosed)
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
	transports := slices.Collect(maps.Keys(s.transports))
	clear(s.transports)
	s.mu.Unlock()

	// kick them in parallel and without holding the lock since Kick may block
	// for a bit if a transport is in the middle of writing a packet
	var wg sync.WaitGroup
	for _, t := range transports {
		wg.Go(func() {
			t.Kick(ErrServerClosed)
		})
	}
	wg.Wait()
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
		if s.closeIdleConns(ctx) {
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
	conn   net.Conn

	sess *aproto.Session

	stateMu sync.Mutex     // must be held while reading/writing banner (should not be held during io)
	banner  *aproto.Banner // never write to it; always swap it

	// must only be used within the main loop
	useTLS  bool
	token   [aproto.AuthTokenSize]byte
	sig     []byte // first auth signature
	adbkey  []byte // presented adbkey during legacy auth (not necessairly the one used for auth) (note: we only need to keep one since adb only sends the primary adbkey, not vendorkeys)
	adbkeyp *aproto.PublicKey
}

func (s *Server) newTransport(conn net.Conn) *Transport {
	t := &Transport{
		server: s,
		conn:   conn,
	}
	t.sess = aproto.NewSession(aproto.New(conn), aproto.SessionConfig{
		Open: func(ctx context.Context, svc string) (io.ReadWriteCloser, error) {
			return s.Dialer.DialADB(ctx, svc)
		},
		OpenContext:        s.OpenContext,
		LazyOpen:           s.LazyOpen,
		DelayedAck:         s.DelayedAck,
		LocalDelayedAck:    uint32(s.LocalDelayedAck),
		SupportsDelayedAck: func() bool { return t.SupportsFeature(adbproto.FeatureDelayedAck) },
	})
	return t
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
	return t.sess.Idle()
}

// Connected returns a channel which gets closed once the peer connection is
// negotiated.
func (t *Transport) Connected() <-chan struct{} {
	return t.sess.Connected()
}

// Authenticated returns a channel which gets closed once the peer has
// authenticated successfully. An Authenticated channel is always already
// Connected.
func (t *Transport) Authenticated() <-chan struct{} {
	return t.sess.Authenticated()
}

// Kicked returns a channel which gets closed when the transport is kicked by
// either side. The reason can be found by calling Error.
func (t *Transport) Kicked() <-chan struct{} {
	return t.sess.Kicked()
}

// Error returns the reason why the transport was kicked, or nil otherwise.
func (t *Transport) Error() error {
	return t.sess.Err()
}

// Kick kicks the transport with the specified error (or a generic one if nil)
// if the transport has not been kicked yet. This closes the TCP connection
// without waiting for queued packets to be written (see [Transport.Flush]).
func (t *Transport) Kick(err error) {
	t.sess.Kick(err)
}

// Flush blocks until all queued packets have been written, ctx is done, or the
// transport is kicked. It is the same as [aproto.Session.Flush].
func (t *Transport) Flush(ctx context.Context) error {
	return t.sess.Flush(ctx)
}

// Shutdown gracefully kicks the transport with the specified error (or a
// generic one if nil). It closes all open streams, waits for the resulting
// A_CLSE packets (and anything else queued) to be written or for ctx to be
// done, then kicks the transport.
//
// Unlike Kick, this lets the client clean up its side of the streams right away
// rather than when it sees the connection close. It returns the error from
// waiting, if any, but the transport is kicked regardless.
func (t *Transport) Shutdown(ctx context.Context, err error) error {
	t.sess.CloseStreams()
	ferr := t.sess.Flush(ctx)
	t.Kick(err)
	return ferr
}

var (
	_ adb.Dialer   = (*Transport)(nil)
	_ adb.Features = (*Transport)(nil)
)

// DialADB connects to a service on the client.
func (t *Transport) DialADB(ctx context.Context, svc string) (net.Conn, error) {
	return t.sess.DialADB(ctx, svc)
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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() { t.Kick(nil) }()
	var authenticator Authenticator
	if t.server.Auth != nil {
		authenticator = t.server.Auth(ctx)
	}

	handshake := func(msg aproto.Message, data []byte) {
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
			t.sess.SetConnected()

			switch {
			case t.useTLS:
				// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=318-325;drc=61197364367c9e404c7da6900658f1b16c42d0da
				if err := t.sess.Write(aproto.A_STLS, aproto.STLSVersionMin, 0, nil); err != nil {
					return
				}
			case authenticator == nil:
				if trace != nil && trace.Authenticated != nil {
					trace.Authenticated()
				}
				t.sess.SetAuthenticated()

				if err := t.sess.Write(aproto.A_CNXN, t.sess.ProtocolVersion(), t.sess.MaxPayloadSize(), []byte(t.server.banner)); err != nil {
					return
				}
			default:
				if _, err := rand.Read(t.token[:]); err != nil {
					t.Kick(fmt.Errorf("auth: failed to generate token: %w", err))
					return
				}
				if err := t.sess.Write(aproto.A_AUTH, aproto.AuthToken, 0, t.token[:]); err != nil {
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
					if err := t.sess.Write(aproto.A_AUTH, aproto.AuthToken, 0, t.token[:]); err != nil {
						return
					}
					return
				}

				if trace != nil && trace.Authenticated != nil {
					trace.Authenticated()
				}
				t.sess.SetAuthenticated()

				if err := t.sess.Write(aproto.A_CNXN, t.sess.ProtocolVersion(), t.sess.MaxPayloadSize(), []byte(t.server.banner)); err != nil {
					return
				}

			case aproto.AuthRSAPublicKey:
				raw := stripTrailingNulls(data)
				key, _, err := aproto.ParsePublicKey(raw)
				if err != nil {
					return
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
							t.sess.SetAuthenticated()

							if err := t.sess.Write(aproto.A_CNXN, t.sess.ProtocolVersion(), t.sess.MaxPayloadSize(), []byte(t.server.banner)); err != nil {
								return
							}
							return
						}
					}
				}

				// HACK
				if t.server.NoAuthRetry {
					return
				}

				if _, err := rand.Read(t.token[:]); err != nil {
					t.Kick(fmt.Errorf("auth: failed to generate token: %w", err))
					return
				}
				if err := t.sess.Write(aproto.A_AUTH, aproto.AuthToken, 0, t.token[:]); err != nil {
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
			if !t.sess.Handshake(t.server.cert, func(peerCert *x509.Certificate) {
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
			t.sess.SetAuthenticated()

			if err := t.sess.Write(aproto.A_CNXN, t.sess.ProtocolVersion(), t.sess.MaxPayloadSize(), []byte(t.server.banner)); err != nil {
				return
			}
		}
		return
	ignore:
		if trace != nil && trace.PacketIgnored != nil {
			trace.PacketIgnored(aproto.Packet{
				Message: msg,
				Payload: data,
			})
		}
	}

	actx := ctx
	if trace != nil {
		actx = aproto.WithSessionTrace(ctx, &aproto.SessionTrace{
			PacketSent:             trace.PacketSent,
			PacketReceived:         trace.PacketReceived,
			PacketUnknown:          trace.PacketUnknown,
			PacketIgnored:          trace.PacketIgnored,
			PacketSocketUnknown:    trace.PacketSocketUnknown,
			LocalServiceOpen:       trace.LocalServiceDial,
			LocalServiceFail:       trace.LocalServiceFail,
			LocalServiceSuccess:    trace.LocalServiceSuccess,
			LocalServiceDelayedAck: trace.LocalServiceDelayedAck,
			LocalServiceClose:      trace.LocalServiceClose,
		})
	}
	t.sess.Serve(actx, handshake)
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
