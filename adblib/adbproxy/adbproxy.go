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
	"encoding/binary"
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

// TODO: refactor asocket logic (as a wrapper around readwriteclosers) into adb/aproto since we'll probably use it for client conns too
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

const (
	protocolVersionMin = aproto.VersionMin
	protocolVersionMax = aproto.VersionSkipChecksum
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

	// If true, the listener will wait for adb services to finish dialing before
	// continuing to process packets. This makes it match the official
	// implementation, but has a significant performance and reliability
	// penalty, especially when re-exposing a remote ADB server.
	StrictOpenOrdering bool

	// If nonzero, delayed ack will be supported with the specified size. This
	// must also be supported by the Dialer (if backed by adbd, ADB_BURST_MODE
	// must be set).
	DelayedAck int

	// TODO: handle reverse stuff? might want to snoop forward: and killforward:
	// services and block them by default as we don't have a good way to open a
	// proxied port on the underlying adb server... it's probably better to do
	// this as a wrapper around the dialer instead of in Server directly to keep
	// things clean... but then we'll need to expose something to send an open
	// to a connected transport (add a helper to this package which takes a
	// context passed down from a *transport and allows doing a DialADB on the
	// client?)... probably need to look at it more closely to ensure I
	// understand it correctly

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

	// OpenContext optionally specifies a function that modifies the context
	// used for a new service connection c. The provided ctx is derived from the
	// connection context.
	OpenContext func(ctx context.Context, svc string) context.Context

	// TODO: hooks for handling common per-connection we probably want to log

	// AuthSignatureHook is called every time a signature is presented, along
	// with the current value of the token. If it returns (result, true), the
	// value of result overrides the authentication result. Note that for this
	// to be called, AllowedKeys must be non-nil, even if it doesn't return any
	// keys.
	AuthSignatureHook func(ctx context.Context, token, sig []byte) (result, override bool)

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
		var feat []adbproto.Feature
		if s.DelayedAck != 0 {
			feat = append(feat, adbproto.FeatureDelayedAck)
		}
		s.deviceBanner, s.deviceBannerErr = makeDeviceBanner(ctx, s.Dialer, feat...)
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

	streamsMu sync.Mutex
	stream    uint32
	streams   map[*stream]struct{}

	// no mutex for these since only accessed from main serve goroutine
	authBuf            []byte
	failedAuthAttempts uint64

	// no mutex for these since only modified from main serve goroutine while !authenticated
	token           []byte
	remoteFeatures  map[adbproto.Feature]struct{}
	maxPayloadSize  uint32
	protocolVersion uint32

	mu            sync.Mutex // this MUST not be held while waiting on I/O or external stuff
	kicked        bool
	err           error
	authenticated bool
	authkey       *rsa.PublicKey
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

func (s *Server) newTransport(conn net.Conn) *transport {
	t := &transport{
		tid:             s.tid.Add(1),
		server:          s,
		conn:            conn,
		rw:              conn,
		maxPayloadSize:  aproto.MaxPayloadSizeV1, // legacy v1 payload size until we know how much the remote can accept
		protocolVersion: protocolVersionMin,      // min protocol version for maximum compatibility
	}
	debugStatus(t, "new")
	s.trackTransport(t, true)
	return t
}

func (t *transport) close() error {
	debugStatus(t, "close")
	cerr := t.conn.Close()

	t.streamsMu.Lock()
	defer t.streamsMu.Unlock()
	var errs []error
	for s := range t.streams {
		// TODO: refactor?
		if err := s.device.Close(); err != nil {
			errs = append(errs, err)
		}
		delete(t.streams, s)
	}

	if serr := errors.Join(errs...); serr != nil {
		cerr = errors.Join(cerr, fmt.Errorf("close stream device conns: %w", serr))
	}
	return cerr
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
	return len(t.streams)
}

func (t *transport) getToken(generate bool) []byte {
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

func (t *transport) findLocalSocket(local, remote uint32) *stream {
	t.streamsMu.Lock()
	defer t.streamsMu.Unlock()
	for s := range t.streams {
		if (remote == 0 || s.remote == remote) && s.local == local {
			return s
		}
	}
	return nil
}

func (t *transport) write(buf []byte) {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	if _, err := t.rw.Write(buf); err != nil {
		t.kick(err)
	}
}

// send sends pkt, reusing buf if possible.
func (t *transport) send(buf []byte, pkt aproto.Packet) []byte {
	debugPacket(t, false, pkt)
	if !t.isKicked() {
		if len(pkt.Payload) > int(t.maxPayloadSize) {
			t.kick(fmt.Errorf("%s packet is too long for remote", pkt.Command))
			return buf
		}
		var err error
		buf, err = pkt.AppendBinary(buf[:0])
		if err != nil {
			panic(err)
		}
		t.write(buf)
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
		if n := int(t.maxPayloadSize); len(buf) != n {
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
		t.handle(ctx, pkt)
		if debug {
			if td := time.Since(tt); td > time.Millisecond*250 {
				debugStatus(t, "warning: slow handle (%s)", td)
			}
		}
	}
}

func (t *transport) handle(ctx context.Context, pkt aproto.Packet) {
	switch pkt.Command {
	case aproto.A_CNXN: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=407-433;drc=61197364367c9e404c7da6900658f1b16c42d0da
		func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			t.authenticated = false
			t.failedAuthAttempts = 0
		}()

		_, _, features := parseBanner(string(pkt.Payload))

		t.remoteFeatures = map[adbproto.Feature]struct{}{}
		for _, f := range features {
			t.remoteFeatures[f] = struct{}{}
		}
		if v := min(pkt.Arg0, protocolVersionMax); v != t.protocolVersion {
			t.protocolVersion = v
			debugStatus(t, "changed protocol version to 0x%08X", t.protocolVersion)
		}
		if v := min(pkt.Arg1, aproto.MaxPayloadSize); v != t.maxPayloadSize {
			t.maxPayloadSize = v
			debugStatus(t, "changed max payload size to %d", t.maxPayloadSize)
		}

		if t.server.UseTLS {
			// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=318-325;drc=61197364367c9e404c7da6900658f1b16c42d0da
			t.authBuf = t.sendPacket(t.authBuf, aproto.A_STLS, aproto.STLSVersionMin, 0, nil)
			return
		}

		if t.server.AllowedKeys != nil {
			t.sendAuthRequest()
			return
		}

		t.sendAuthConnect(nil)
		return

	case aproto.A_STLS:
		if !t.server.UseTLS {
			return // ignore stls packets (the actual adb impl doesn't, but that code path isn't used as the adb server needs to send the stls first)
		}

		authkey, ok := t.doTLSHandshake(ctx)
		if !ok {
			// only allow a single attempt
			t.kick(fmt.Errorf("tls handshake failed"))
			return
		}

		t.sendAuthConnect(authkey)
		return

	case aproto.A_AUTH:
		if t.server.UseTLS {
			return // ignore auth packets
		}
		if t.server.AllowedKeys == nil {
			return
		}
		if t.isAuthenticated() {
			return
		}

		// note: when the adb host daemon has vendor keys loaded, it will send
		// initial A_AUTH packets for each of them, but if rejected, it will
		// only send the public key for the primary adbkey rather than all
		// vendor keys

		switch pkt.Arg0 {
		case aproto.AuthSignature:
			token := t.getToken(false)

			result, override := t.server.AuthSignatureHook(ctx, token, pkt.Payload)
			if !override {
				for key := range t.server.AllowedKeys(ctx) {
					if err := rsa.VerifyPKCS1v15(key, crypto.SHA1, token, pkt.Payload); err != nil {
						continue
					}
					debugStatus(t, "verified signature with pubkey n=%s e=%d", key.N, key.E)
					t.failedAuthAttempts = 0
					t.sendAuthConnect(key)
					return
				}
			} else if result {
				debugStatus(t, "verified signature with auth hook")
				t.failedAuthAttempts = 0
				t.sendAuthConnect(nil)
				return
			}

			if t.failedAuthAttempts++; t.failedAuthAttempts > 256 {
				debugStatus(t, "reached failed auth limit, throttling")
				time.Sleep(time.Second)
			}

			t.sendAuthRequest()
			return

		case aproto.AuthRSAPublicKey:
			if t.server.PromptKey != nil {
				buf := stripTrailingNulls(pkt.Payload)
				key, name, err := aproto.ParsePublicKey(buf)
				if err != nil {
					debugStatus(t, "ignoring invalid pubkey %q: %v", string(buf), err)
					return
				}
				t.server.PromptKey(ctx, name, aproto.GoPublicKey(key))
			}
			return
		}

	case aproto.A_SYNC: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/docs/dev/protocol.md;l=191-207;drc=593dc053eb97047637ff813081d9c2de55e17a46
		debugStatus(t, "ignoring invalid SYNC packet (this is never valid on the wire)")
		return

	case aproto.A_OPEN: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=500-552;drc=9f298fb1f3317371b49439efb20a598b3a881bf3
		if !t.isAuthenticated() {
			return
		}
		if pkt.Arg0 == 0 {
			return
		}
		if pkt.Arg1 != uint32(t.server.DelayedAck) {
			debugStatus(t, "unexpected OPEN delayed acks (exp=%d act=%d)", t.server.DelayedAck, pkt.Arg1)
			t.authBuf = t.sendPacket(t.authBuf, aproto.A_CLSE, 0, pkt.Arg0, nil)
			return
		}

		svc := string(stripTrailingNulls(pkt.Payload))

		// TODO: implement tracking of streams
		// TODO: delayed ack

		fn := func() {
			sctx := ctx
			if t.server.OpenContext != nil {
				sctx = t.server.OpenContext(sctx, svc)
				if sctx == nil {
					panic("OpenContext returned nil")
				}
			}

			debugStatus(t, "[%d] dialing %q", pkt.Arg0, svc)
			conn, err := t.server.Dialer.DialADB(sctx, svc)
			if err != nil {
				debugStatus(t, "[%d] failed to open service %q: %v", pkt.Arg0, svc, err)
				t.sendPacket(nil, aproto.A_CLSE, 0, pkt.Arg0, nil)
				return
			}
			debugStatus(t, "[%d] opened %q", pkt.Arg0, svc)

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
					remote: pkt.Arg0,
					device: conn,
					asb:    int64(t.server.DelayedAck),
					ready:  make(chan struct{}, 1),
					wqueue: make(chan []byte, 1),
				}
				t.streams[stream] = struct{}{}
				return stream
			}()

			if t.server.DelayedAck != 0 {
				t.sendPacket(nil, aproto.A_OKAY, stream.local, stream.remote, binary.LittleEndian.AppendUint32(nil, uint32(t.server.DelayedAck)))
			} else {
				t.sendPacket(nil, aproto.A_OKAY, stream.local, stream.remote, nil)
			}

			go func() {
				buf := make([]byte, aproto.MessageSize+t.maxPayloadSize)
				for data := range stream.wqueue {
					if _, err := stream.device.Write(data); err != nil {
						debugStatus(t, "[%d] failed to write to local device socket: %v", stream.local, err)
						// TODO: is this the correct behaviour, or do we just ignore it?
						stream.device.Close()
						t.sendPacket(nil, aproto.A_CLSE, stream.local, stream.remote, nil)
						// note: the client will send a CLSE back
						return
					}
					// tell the remote we're ready for another WRTE
					// TODO: do we need to care about delayed acks here?
					buf = t.sendPacket(buf, aproto.A_OKAY, stream.local, stream.remote, nil)
				}
			}()

			go func() {
				buf := make([]byte, aproto.MessageSize+t.maxPayloadSize)
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
						debugStatus(t, "[%d] failed to read from local device socket: %v", stream.local, err)
						// TODO: is this the correct behaviour, or do we just ignore it?
						stream.device.Close()
						t.sendPacket(nil, aproto.A_CLSE, stream.local, stream.remote, nil)
						// note: the client will send a CLSE back
						return
					}
					if n > 0 {
						msg := aproto.Message{
							Command:    aproto.A_WRTE,
							Arg0:       stream.local,
							Arg1:       stream.remote,
							DataLength: uint32(n),
							Magic:      uint32(aproto.A_WRTE) ^ 0xFFFFFFFF,
						}
						if t.protocolVersion < aproto.VersionSkipChecksum {
							msg.DataCheck = aproto.Checksum(payload[:n])
						}
						if _, err := msg.AppendBinary(buf[:0]); err != nil {
							panic(err)
						}
						debugPacket(t, false, aproto.Packet{
							Message: msg,
							Payload: payload[:n],
						})
						t.write(buf[:aproto.MessageSize+msg.DataLength])
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
		if t.server.StrictOpenOrdering {
			fn()
		} else {
			go fn()
		}
		return

	case aproto.A_OKAY: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=554-592;drc=9f298fb1f3317371b49439efb20a598b3a881bf3
		if !t.isAuthenticated() {
			return
		}
		if pkt.Arg0 == 0 || pkt.Arg1 == 0 {
			return
		}

		var acked int32
		if len(pkt.Payload) != 0 {
			if len(pkt.Payload) != 4 {
				debugStatus(t, "invalid OKAY payload size (%d)", len(pkt.Payload))
				return
			}
			acked = int32(binary.LittleEndian.Uint32(pkt.Payload))
		}

		stream := t.findLocalSocket(pkt.Arg1, 0)
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
		return

	case aproto.A_CLSE: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=594-616;drc=9f298fb1f3317371b49439efb20a598b3a881bf3
		if !t.isAuthenticated() {
			return
		}
		if pkt.Arg1 == 0 {
			return
		}

		stream := t.findLocalSocket(pkt.Arg1, pkt.Arg0)
		if stream == nil {
			debugStatus(t, "cannot find stream to close, ignoring (remote=%d local=%d)", pkt.Arg0, pkt.Arg1)
			return
		}

		stream.device.Close()
		stream.notifyReady()
		func() {
			t.streamsMu.Lock()
			defer t.streamsMu.Unlock()
			delete(t.streams, stream)
		}()
		return

	case aproto.A_WRTE: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=618-625;drc=9f298fb1f3317371b49439efb20a598b3a881bf3
		if !t.isAuthenticated() {
			return
		}
		if pkt.Arg0 == 0 || pkt.Arg1 == 0 {
			return
		}

		stream := t.findLocalSocket(pkt.Arg1, pkt.Arg0)
		if stream == nil {
			debugStatus(t, "cannot find stream to write, ignoring (remote=%d local=%d)", pkt.Arg0, pkt.Arg1)
			break
		}

		stream.wqueue <- slices.Clone(pkt.Payload) // TODO: optimize this, refactor
		return
	}
	debugStatus(t, "unhandled %s packet", pkt.Command)
}

func (t *transport) sendAuthRequest() {
	t.authBuf = t.sendPacket(t.authBuf, aproto.A_AUTH, aproto.AuthToken, 0, t.getToken(true))
}

func (t *transport) sendAuthConnect(pubkey *rsa.PublicKey) {
	debugStatus(t, "authenticated")
	func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		t.authenticated = true
		t.authkey = pubkey
	}()
	t.authBuf = t.sendPacket(t.authBuf, aproto.A_CNXN, t.protocolVersion, t.maxPayloadSize, []byte(t.server.deviceBanner))
	debugStatus(t, "sent banner")
}

// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/transport.cpp;l=564-583;drc=61197364367c9e404c7da6900658f1b16c42d0da
// https://android-review.googlesource.com/c/platform/system/core/+/568123
func (t *transport) sendPacket(buf []byte, command aproto.Command, arg0, arg1 uint32, data []byte) []byte {
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
	if t.protocolVersion < aproto.VersionSkipChecksum {
		pkt.DataCheck = aproto.Checksum(pkt.Payload)
	}
	return t.send(buf, pkt)
}

// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/transport.cpp;l=513-557;drc=61197364367c9e404c7da6900658f1b16c42d0da
func (t *transport) doTLSHandshake(ctx context.Context) (*rsa.PublicKey, bool) {
	// we need to block the connection entirely while doing the handshake (note:
	// reading is already blocked since this is called from the packet handler)
	t.sendMu.Lock()
	defer t.sendMu.Unlock()

	cert, err := generateX509Certificate(t.server.tlskey)
	if err != nil {
		t.kick(fmt.Errorf("failed to generate tls certificate: %w", err))
		return nil, false
	}

	parsedCert, err := x509.ParseCertificate(cert)
	if err != nil {
		t.kick(fmt.Errorf("failed to parse tls certificate: %w", err))
		return nil, false
	}

	debugStatus(t, "starting tls handshake")
	var (
		verified    bool
		verifiedKey *rsa.PublicKey
	)
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
							verifiedKey = key
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
		return nil, false
	}
	if !verified {
		return nil, false
	}

	debugStatus(t, "tls connection established")
	t.rw = tlsconn
	return verifiedKey, true
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

func (s *stream) notifyReady() {
	select {
	case s.ready <- struct{}{}:
		// notified
	default:
		// already have a ready queued (chan buffer is 1)
	}
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
