// Package adbproxy implements a ADB TCP/IP server for an existing ADB
// connection.
package adbproxy

import (
	"cmp"
	"context"
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"iter"
	"math/big"
	"math/rand"
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

// TODO: refactor core server packet handling into adb/adbtcpip

var (
	debug, _        = strconv.ParseBool(os.Getenv("ADBPROXY_DEBUG"))
	debugPayload, _ = strconv.ParseBool(os.Getenv("ADBPROXY_DEBUG_PAYLOAD"))
)

var ErrServerClosed = errors.New("adbproxy: Server closed")

type contextKey struct {
	name string
}

var (
	ServerContextKey = &contextKey{"server"} // *Server
)

// Server serves an ADB TCP/IP server for an [adb.Dialer].
type Server struct {
	// Addr is the TCP address to listen on.
	Addr string

	// Dialer is the upstream dialer to use. If it implements [adb.Features],
	// known features will be exposed.
	Dialer adb.Dialer

	// If true, the listener will use TLS for connections (i.e., ADB-over-WiFi).
	// If false, the connection will not be encrypted (i.e., legacy
	// ADB-over-TCP/IP).
	UseTLS bool

	// If not nil and UseTLS is false, this will be called when a new key is
	// presented by the client. This function must be safe to be called
	// concurrently, but will block individual transports.
	//
	// For TLS connections, the key should be sent beforehand using the pairing
	// protocol, but for flexibility, if AllowedKeys is not nil, this will be
	// called if the presented key is not in AllowedKeys, then AllowedKeys will
	// be checked again afterwards.
	PromptKey func(ctx context.Context, name string, key *rsa.PublicKey)

	// If not nil, this will be called to get the allowed public keys. If nil,
	// all keys are allowed. This function must be safe to be called
	// concurrently.
	AllowedKeys func(ctx context.Context) iter.Seq[*rsa.PublicKey]

	// If nonzero, delayed ack will be supported with the specified size.
	// TODO: DelayedAck int

	// TODO: handle reverse stuff? might want to snoop forward: and killforward:
	// services and block them by default as we don't have a good way to open a
	// proxied port on the underlying adb server... it's probably better to do
	// this as a wrapper around the dialer instead of in Server directly to keep
	// things clean... but then we'll need to expose something to send an open
	// to a connected transport... probably need to look at it more closely to
	// ensure I understand it correctly

	// BaseContext optionally specifies a function that returns the base context
	// for incoming requests on this server. The provided Listener is the
	// specific Listener that's about to start accepting requests. If
	// BaseContext is nil, the default is context.Background(). If non-nil, it
	// must return a non-nil context.
	BaseContext func(net.Listener) context.Context

	// ConnContext optionally specifies a function that modifies the context
	// used for a new connection c. The provided ctx is derived from the base
	// context and has a ServerContextKey value.
	ConnContext func(ctx context.Context, c net.Conn) context.Context

	deviceBannerOnce sync.Once
	deviceBannerErr  error
	deviceBanner     string

	tlskeyOnce sync.Once
	tlskeyErr  error
	tlskey     *rsa.PrivateKey // so we don't waste time generating a new one on every connection

	shuttingDown  atomic.Bool
	listenerGroup sync.WaitGroup

	tid atomic.Uint64

	mu         sync.Mutex
	listeners  map[*net.Listener]struct{}
	transports map[*transport]struct{}
}

// LoadBanner generates the device banner. Only the first call will take effect;
// other calls will wait and return the error from the first. It will be
// automatically called by [Server.ListenAndServe] or [Server.Serve] with the
// listener's context (see [Server.BaseContext]). To use a custom timeout or
// check the error, it should be called directly before starting the server.
func (s *Server) LoadBanner(ctx context.Context) error {
	if s.shuttingDown.Load() {
		return ErrServerClosed
	}
	s.deviceBannerOnce.Do(sync.OnceFunc(func() {
		// TODO: add adbproto.FeatureDelayedAck once implemented
		s.deviceBanner, s.deviceBannerErr = makeDeviceBanner(ctx, s.Dialer)
	}))
	return s.deviceBannerErr
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
	lorig := l
	l = &onceCloseListener{Listener: lorig}

	if !s.trackListener(&l, true) {
		return ErrServerClosed
	}
	defer s.trackListener(&l, false)

	lctx := context.Background()
	if s.BaseContext != nil {
		lctx = s.BaseContext(lorig)
		if lctx == nil {
			panic("BaseContext returned a nil context")
		}
	}
	lctx = context.WithValue(lctx, ServerContextKey, s)

	if err := s.LoadBanner(lctx); err != nil {
		return fmt.Errorf("load banner: %w", err)
	}

	if s.UseTLS {
		s.tlskeyOnce.Do(func() {
			s.tlskey, s.tlskeyErr = rsa.GenerateKey(crand.Reader, aproto.PublicKeyModulusSize*8)
		})
		if err := s.tlskeyErr; err != nil {
			return fmt.Errorf("generate tls key: %w", err)
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

		cctx := lctx
		if s.ConnContext != nil {
			cctx = s.ConnContext(lctx, c)
			if cctx == nil {
				panic("ConnContext returned nil")
			}
		}
		delay = 0

		t := s.newTransport(c)
		go t.serve(cctx)
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
		if t.numStreams() != 0 {
			active = true
			continue
		}
		t.close()
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
		t.close()
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
		interval := pollIntervalBase + time.Duration(rand.Intn(int(pollIntervalBase/10)))
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

func (s *Server) trackTransport(c *transport, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.transports == nil {
		s.transports = make(map[*transport]struct{})
	}
	if add {
		s.transports[c] = struct{}{}
	} else {
		delete(s.transports, c)
	}
}

type transport struct {
	tid    uint64
	server *Server

	sendMu sync.Mutex
	conn   net.Conn
	rw     io.ReadWriter

	mu              sync.Mutex
	kicked          bool
	maxPayloadSize  uint32
	protocolVersion uint32
	err             error
	token           []byte
	authenticated   bool
	remoteFeatures  map[adbproto.Feature]struct{}

	// no mutex for these since only accessed from main serve goroutine
	authBuf            []byte
	failedAuthAttempts uint64
}

func (s *Server) newTransport(conn net.Conn) *transport {
	t := &transport{
		tid:             s.tid.Add(1),
		server:          s,
		conn:            conn,
		rw:              conn,
		maxPayloadSize:  aproto.MaxPayloadSizeV1, // legacy v1 payload size until we know how much the remote can accept
		protocolVersion: aproto.VersionMin,       // min protocol version for maximum compatibility
	}
	debugStatus(t, "new")
	s.trackTransport(t, true)
	return t
}

func (t *transport) close() error {
	debugStatus(t, "close")
	return t.conn.Close()
}

func (t *transport) kick(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.kickLocked(err)
}

func (t *transport) kickLocked(err error) {
	if err != nil {
		if t.err == nil {
			debugStatus(t, "error: %v", err)
			t.err = err
		}
	}
	if !t.kicked {
		debugStatus(t, "kick")
	}
	t.kicked = true
	t.server.trackTransport(t, false)
	t.close()
}

func (t *transport) error() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.err
}

func (t *transport) numStreams() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return 0 // TODO
}

func (t *transport) getToken(generate bool) []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	if generate || t.token == nil {
		token := make([]byte, aproto.AuthTokenSize)
		if _, err := crand.Read(token); err != nil {
			t.kickLocked(fmt.Errorf("failed to generate token: %w", err)) // this should never fail
			return nil
		}
		t.token = token
	}
	return t.token
}

func (t *transport) getProtocolVersion() uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.protocolVersion
}

func (t *transport) getMaxPayloadSize() uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.maxPayloadSize
}

func (t *transport) isAuthenticated() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.authenticated
}

func (t *transport) isKicked() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.kicked
}

// send sends pkt, reusing buf if possible.
func (t *transport) send(buf []byte, pkt aproto.Packet) []byte {
	debugPacket(t, false, pkt)
	if !t.isKicked() {
		if len(pkt.Payload) > int(t.getMaxPayloadSize()) {
			t.kick(fmt.Errorf("%s packet is too long for remote", pkt.Command))
			return buf
		}
		var err error
		buf, err = pkt.AppendBinary(buf[:0])
		if err != nil {
			panic(err)
		}
		t.sendMu.Lock()
		defer t.sendMu.Unlock()
		if _, err := t.rw.Write(buf); err != nil {
			t.kick(err)
			return buf
		}
	}
	return buf
}

func (t *transport) serve(ctx context.Context) {
	defer t.kick(nil)
	var (
		pkt aproto.Packet
		msg [aproto.MessageSize]byte
		buf []byte
	)
	for !t.isKicked() {
		if n := int(t.getMaxPayloadSize()); len(buf) != n {
			buf = slices.Grow(buf[:0], n)[:n]
		}
		if _, err := io.ReadFull(t.rw, msg[:]); err != nil {
			if err == io.EOF {
				t.kick(fmt.Errorf("client kicked transport"))
			} else {
				t.kick(fmt.Errorf("read message: %w", err))
			}
			return
		}
		if err := pkt.Message.UnmarshalBinary(msg[:]); err != nil {
			t.kick(fmt.Errorf("read message: %w", err))
			return
		}
		if !pkt.Message.IsMagicValid() {
			t.kick(fmt.Errorf("invalid magic (cmd=0x%08X magic=0x%08X)", pkt.Message.Command, pkt.Message.Magic))
			return
		}
		if pkt.DataLength != 0 {
			if pkt.DataLength > uint32(len(buf)) {
				t.kick(fmt.Errorf("payload too large (len=%d max=%d)", pkt.DataLength, len(buf)))
				return
			}
			if _, err := io.ReadFull(t.rw, buf[:pkt.DataLength]); err != nil {
				if err == io.EOF {
					t.kick(fmt.Errorf("client kicked transport"))
				} else {
					t.kick(fmt.Errorf("read payload: %w", err))
				}
				return
			}
		}
		if pkt.Payload = buf[:pkt.DataLength]; !pkt.IsChecksumValid() {
			t.kick(fmt.Errorf("invalid checksum (cmd=%s)", pkt.Command))
			return
		}
		debugPacket(t, true, pkt)
		var tt time.Time
		if debug {
			tt = time.Now()
		}
		if err := t.handle(ctx, pkt); err != nil {
			t.kick(fmt.Errorf("handle %s: %w", pkt.Command, err))
			return
		}
		if debug {
			if td := time.Since(tt); td > time.Millisecond*250 {
				debugStatus(t, "warning: slow handle (%s)", td)
			}
		}
	}
}

func (t *transport) handle(ctx context.Context, pkt aproto.Packet) error {
	switch pkt.Command {
	case aproto.A_CNXN: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=407-433;drc=61197364367c9e404c7da6900658f1b16c42d0da
		_, _, features := parseBanner(string(pkt.Payload))

		fmap := map[adbproto.Feature]struct{}{}
		for _, f := range features {
			fmap[f] = struct{}{}
		}
		func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			t.remoteFeatures = fmap
		}()

		if t.server.UseTLS {
			// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=318-325;drc=61197364367c9e404c7da6900658f1b16c42d0da
			t.sendAuthPacket(aproto.A_STLS, aproto.STLSVersionMin, 0, nil)
			return nil
		}

		if t.server.AllowedKeys != nil {
			t.sendAuthRequest()
			return nil
		}

		t.sendAuthConnect()
		return nil

	case aproto.A_STLS:
		if !t.server.UseTLS {
			return nil // ignore stls packets (the actual adb impl doesn't, but that code path isn't used as the adb server needs to send the stls first)
		}

		if !t.doTLSHandshake(ctx) {
			// only allow a single attempt
			t.kick(fmt.Errorf("tls handshake failed"))
			return nil
		}

		t.sendAuthConnect()
		return nil

	case aproto.A_AUTH:
		if t.server.UseTLS {
			return nil // ignore auth packets
		}
		if t.server.AllowedKeys == nil {
			return nil
		}
		if t.isAuthenticated() {
			return nil
		}

		// note: when the adb host daemon has vendor keys loaded, it will send
		// initial A_AUTH packets for each of them, but if rejected, it will
		// only send the public key for the primary adbkey rather than all
		// vendor keys

		switch pkt.Arg0 {
		case aproto.AuthSignature:
			for key := range t.server.AllowedKeys(ctx) {
				if err := rsa.VerifyPKCS1v15(key, crypto.SHA1, t.getToken(false), pkt.Payload); err != nil {
					continue
				}
				debugStatus(t, "verified signature with pubkey n=%s e=%d", key.N, key.E)
				t.failedAuthAttempts = 0
				t.sendAuthConnect()
				return nil
			}

			if t.failedAuthAttempts++; t.failedAuthAttempts > 256 {
				debugStatus(t, "reached failed auth limit, throttling")
				time.Sleep(time.Second)
			}

			t.sendAuthRequest()
			return nil

		case aproto.AuthRSAPublicKey:
			if t.server.PromptKey != nil {
				buf := stripTrailingNulls(pkt.Payload)
				key, name, err := aproto.ParsePublicKey(buf)
				if err != nil {
					debugStatus(t, "ignoring invalid pubkey %q: %v", string(buf), err)
					return nil
				}
				t.server.PromptKey(ctx, name, aproto.GoPublicKey(key))
			}
			return nil
		}

	case aproto.A_SYNC:
		// TODO

	case aproto.A_OPEN:
		// TODO

	case aproto.A_OKAY:
		// TODO

	case aproto.A_CLSE:
		// TODO

	case aproto.A_WRTE:
		// TODO
	}
	debugStatus(t, "unhandled %s packet", pkt.Command)
	return nil
}

func (t *transport) sendAuthRequest() {
	t.sendAuthPacket(aproto.A_AUTH, aproto.AuthToken, 0, t.getToken(true))
}

func (t *transport) sendAuthConnect() {
	debugStatus(t, "authenticated")
	func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		t.authenticated = true
	}()
	t.sendAuthPacket(aproto.A_CNXN, t.getProtocolVersion(), t.getMaxPayloadSize(), []byte(t.server.deviceBanner))
	debugStatus(t, "sent banner")
}

// sendAuthPacket sends a connection/auth packet.
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/transport.cpp;l=564-583;drc=61197364367c9e404c7da6900658f1b16c42d0da
func (t *transport) sendAuthPacket(command aproto.Command, arg0, arg1 uint32, data []byte) {
	pkt := aproto.Packet{
		Message: aproto.Message{
			Command:    command,
			Arg0:       arg0,
			Arg1:       arg1,
			DataLength: uint32(len(data)),
			Magic:      uint32(command) ^ 0xFFFFFFFF,
		},
		Payload: data,
	}
	if t.getProtocolVersion() < aproto.VersionSkipChecksum {
		pkt.DataCheck = aproto.Checksum(pkt.Payload)
	}
	t.authBuf = t.send(t.authBuf, pkt)
}

// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/transport.cpp;l=513-557;drc=61197364367c9e404c7da6900658f1b16c42d0da
func (t *transport) doTLSHandshake(ctx context.Context) bool {
	// we need to block the connection entirely while doing the handshake (note:
	// reading is already blocked since this is called from the packet handler)
	t.sendMu.Lock()
	defer t.sendMu.Unlock()

	cert, err := generateX509Certificate(t.server.tlskey)
	if err != nil {
		t.kick(fmt.Errorf("failed to generate tls certificate: %w", err))
		return false
	}

	parsedCert, err := x509.ParseCertificate(cert)
	if err != nil {
		t.kick(fmt.Errorf("failed to parse tls certificate: %w", err))
		return false
	}

	debugStatus(t, "starting tls handshake")
	var verified bool
	tlsconn := tls.Server(t.conn, &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &tls.Certificate{
				Certificate: [][]byte{cert},
				PrivateKey:  t.server.tlskey,
				Leaf:        parsedCert,
			}, nil
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/daemon/auth.cpp;l=301-356;drc=61197364367c9e404c7da6900658f1b16c42d0da
			for _, rawCert := range rawCerts {
				ccert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					debugStatus(t, "ignoring invalid client cert: %v", err)
					continue
				}
				debugStatus(t, "got client cert (alg=%s sigalg=%s subject=%q)", ccert.PublicKeyAlgorithm, ccert.SignatureAlgorithm, ccert.Subject)
				cpkey, ok := ccert.PublicKey.(*rsa.PublicKey)
				if !ok {
					debugStatus(t, "ignoring non-rsa %T client cert", ccert.PublicKey)
					continue
				}
				if t.server.AllowedKeys == nil {
					verified = true
					return nil
				}
				for key := range t.server.AllowedKeys(ctx) {
					if key.Equal(cpkey) {
						verified = true
						return nil
					}
				}
				if t.server.PromptKey != nil {
					t.server.PromptKey(ctx, "", cpkey)
					for key := range t.server.AllowedKeys(ctx) {
						if key.Equal(cpkey) {
							verified = true
							return nil
						}
					}
				}
				debugStatus(t, "ignoring unknown client adbkey")
			}
			return nil
		},
		ClientAuth: tls.RequestClientCert,
	})
	if err := tlsconn.HandshakeContext(ctx); err != nil {
		debugStatus(t, "tls handshake error: %v", err)
		return false
	}
	if !verified {
		return false
	}

	debugStatus(t, "tls connection established")
	t.rw = tlsconn
	return true
}

// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=351-405;drc=61197364367c9e404c7da6900658f1b16c42d0da
func parseBanner(banner string) (state string, props map[string]string, features []adbproto.Feature) {
	state, banner, _ = strings.Cut(banner, "::")
	props = map[string]string{}
	for prop := range strings.SplitSeq(banner, ";") {
		if prop == "" {
			continue
		}
		k, v, ok := strings.Cut(prop, "=")
		if !ok {
			continue
		}
		if k == "features" {
			if v != "" {
				for feat := range strings.SplitSeq(v, ",") {
					features = append(features, adbproto.Feature(feat))
				}
			}
			continue
		}
		props[k] = v
	}
	return
}

// makeDeviceBanner creates the device banner for the specified adb server. If srv
// implements [adb.Features], known protocol-level features will be added from
// it. Features which require transport support must be manually specified.
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=294-316;drc=61197364367c9e404c7da6900658f1b16c42d0da
func makeDeviceBanner(ctx context.Context, srv adb.Dialer, transportFeatures ...adbproto.Feature) (string, error) {
	const typ = "device"

	var protocolFeatures = []adbproto.Feature{
		// note: features should be added here when added to adbproto
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

	var features []adbproto.Feature
	for _, f := range protocolFeatures {
		if adb.SupportsFeature(srv, f) == nil {
			features = append(features, f)
		}
	}
	for _, f := range transportFeatures {
		if adb.SupportsFeature(srv, f) == nil && !slices.Contains(features, f) {
			features = append(features, f)
		}
	}

	var cmd strings.Builder
	cmd.WriteString("echo -n ")
	for i, prop := range aproto.ConnectionProps {
		if i != 0 {
			cmd.WriteString(`\;`)
		}
		cmd.WriteString("'")
		cmd.WriteString(prop)
		cmd.WriteString("'=`getprop ")
		cmd.WriteString(prop)
		cmd.WriteString("`")
	}

	c, err := adb.Exec(ctx, srv, cmd.String())
	if err != nil {
		return "", fmt.Errorf("get props: %w", err)
	}
	defer c.Close()

	props, err := io.ReadAll(c)
	if err != nil {
		panic(err)
	}

	var banner strings.Builder
	banner.WriteString(typ)
	banner.WriteString("::")
	banner.Write(props)
	if len(props) != 0 {
		banner.WriteByte(';')
	}
	banner.WriteString("features=")
	for i, f := range features {
		if i != 0 {
			banner.WriteByte(',')
		}
		banner.WriteString(string(f))
	}
	if legacyCompat := true; legacyCompat {
		// the property list used to be ;-terminated rather than ;-separated,
		// and newer adb versions will ignore empty items
		banner.WriteByte(';')
	}
	return banner.String(), nil
}

// TODO: move to aproto/acrypto.go?
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/crypto/x509_generator.cpp;l=34-122;drc=61197364367c9e404c7da6900658f1b16c42d0da
func generateX509Certificate(pkey *rsa.PrivateKey) ([]byte, error) {
	cert := &x509.Certificate{
		Version: 2,

		SerialNumber: big.NewInt(1),
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Now().Add(time.Second * time.Duration(10*365*24*60*60)),

		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Android"},
			CommonName:   "Adb",
		},

		BasicConstraintsValid: true,
		IsCA:                  true,

		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId: []byte("hash"),
	}
	return x509.CreateCertificate(crand.Reader, cert, cert, &pkey.PublicKey, pkey)
}

func stripTrailingNulls(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
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

func debugStatus(t *transport, format string, a ...any) {
	if debug {
		fmt.Printf("[%d] %s\n", t.tid, fmt.Sprintf(format, a...))
	}
}

func debugPacket(t *transport, recv bool, pkt aproto.Packet) {
	if debug {
		c := '>'
		if recv {
			c = '<'
		}
		pfx := fmt.Sprintf("[%d] %c", t.tid, c)
		fmt.Printf("%s %s(%d, %d, %d)\n", pfx, pkt.Command, pkt.Arg0, pkt.Arg1, pkt.DataLength)
		if debugPayload && pkt.DataLength != 0 {
			for line := range strings.Lines(hex.Dump(pkt.Payload)) {
				fmt.Printf("%*s   %s", len(pfx), "", line)
			}
		}
	}
}
