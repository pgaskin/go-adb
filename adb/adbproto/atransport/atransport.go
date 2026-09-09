// Package atransport implements the host side of the ADB transport protocol,
// authenticating with and connecting to an ADB server (i.e., device) over an
// arbitrary connection.
package atransport

import (
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/pgaskin/go-adb/adb"
	"github.com/pgaskin/go-adb/adb/adbproto"
	"github.com/pgaskin/go-adb/adb/adbproto/aproto"
)

// TODO: maybe rework the API

// Config contains optional configuration for a [Transport].
type Config struct {
	// Banner is the banner to use. Unsupported features will be filtered out
	// before it is sent. If nil, [HostBanner] is used.
	Banner *aproto.Banner

	// Keys contains the keys to attempt A_AUTH authentication with, in order.
	// After all keys have been rejected, the public key of the first one is
	// sent to the device for the user to accept. For TLS, the first key (or the
	// one matching the CA list sent by the device, if any) is used for the
	// client certificate. Keys are usually RSA-2048 (see [LoadUserKey]).
	//
	// If empty, authentication will only succeed if the device does not require
	// it (i.e., ro.adb.secure=0).
	Keys []crypto.Signer

	// PublicKeyName is the name appended to the public key sent to the device
	// (and saved on it if accepted). If empty, "user@host" is used (literally),
	// like ADB.
	PublicKeyName string

	// If true, delayed acks will be used if supported by the device (i.e.,
	// ADB_BURST_MODE).
	DelayedAck bool

	// If DelayedAck is true, delayed acks will be supported for our half of
	// the socket pairs with the specified size, or
	// [aproto.InitialDelayedAckBytes] if zero.
	//
	// Currently, ADB hardcodes this to 33554432 bytes, but it should
	// theoretically support anything. However, making this smaller than the
	// maximum payload size is counterproductive.
	//
	// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=543-544;drc=9f298fb1f3317371b49439efb20a598b3a881bf3
	LocalDelayedAck int

	// Dialer, if non-nil, handles connections opened by the device (i.e.,
	// reverse forwards). If nil, they are rejected.
	Dialer adb.Dialer

	// MaxQueuedPackets, if nonzero, limits the number of packets waiting to be
	// written before the transport is kicked. See
	// [aproto.SessionConfig.MaxQueuedPackets].
	//
	// This is non-standard behaviour.
	MaxQueuedPackets int

	// WriteTimeout, if nonzero, kicks the transport if a single packet takes
	// longer than this to be written (i.e., the device stopped reading). See
	// [aproto.SessionConfig.WriteTimeout].
	//
	// This is non-standard behaviour.
	WriteTimeout time.Duration

	// MaxStreams, if nonzero, limits the number of streams open at once,
	// rejecting ones opened by the device (i.e., reverse forwards) past it.
	// See [aproto.SessionConfig.MaxStreams].
	//
	// This is non-standard behaviour.
	MaxStreams int

	// KickWriteTimeout is how long kicking the transport waits for a packet
	// which is currently being written to finish before closing the connection
	// anyway (see [aproto.SessionConfig.KickWriteTimeout]). If zero or
	// negative, it doesn't wait. This should be set for transports which can't
	// tell the device the connection was interrupted (e.g., USB).
	//
	// This is non-standard behaviour.
	KickWriteTimeout time.Duration
}

// TODO: should maybe consider getting rid of KickWriteTiemout and making the
// layer under aproto.Conn (i.e., usbfs) responsible for emsuring stuff isn't
// interrupted mid-packet, but then we'd need to fully assemble packets in
// aproto.Conn instead of writing thr header and payload separately (which would
// take additional memory for the buffer to copy the payload into)

// Transport is a connection to an ADB server (i.e., device).
type Transport struct {
	sess *aproto.Session

	keys          []crypto.Signer
	publicKeyName string
	hostBanner    *aproto.Banner
	hostBannerEnc string

	mu           sync.Mutex
	banner       *aproto.Banner
	unauthorized chan struct{}
}

// Connect starts an ADB transport on conn, sending the initial connection
// banner and processing packets in a new goroutine. It returns without waiting
// for the connection to be established (see [Transport.WaitConnected]).
//
// If conn is not created with an [io.Closer], kick will be a no-op.
//
// The transport takes ownership of conn, and will close it when the transport
// is kicked.
func Connect(conn *aproto.Conn, config *Config) (*Transport, error) {
	if config == nil {
		config = &Config{}
	}

	localDelayedAck := config.LocalDelayedAck
	if localDelayedAck < 0 || localDelayedAck > 0xFFFFFFFF {
		return nil, fmt.Errorf("delayed ack bytes out of range")
	}
	if config.DelayedAck && localDelayedAck == 0 {
		localDelayedAck = aproto.InitialDelayedAckBytes
	}

	banner := config.Banner.Clone()
	if banner == nil {
		banner = HostBanner()
	}
	for f := range banner.Features {
		if !slices.Contains(hostFeatures, adbproto.Feature(f)) {
			delete(banner.Features, f)
		}
	}
	if config.DelayedAck {
		banner.Features[string(adbproto.FeatureDelayedAck)] = struct{}{}
	} else {
		delete(banner.Features, string(adbproto.FeatureDelayedAck))
	}
	if err := banner.Valid(); err != nil {
		return nil, fmt.Errorf("invalid banner: %w", err)
	}

	enc := banner.Encode()
	if len(enc) > aproto.MaxPayloadSizeV1 {
		return nil, fmt.Errorf("banner too long (len=%d)", len(enc))
	}

	t := &Transport{
		keys:          slices.Clone(config.Keys),
		publicKeyName: config.PublicKeyName,
		hostBanner:    banner,
		hostBannerEnc: enc,
		unauthorized:  make(chan struct{}),
	}

	var dial func(ctx context.Context, svc string) (io.ReadWriteCloser, error)
	if config.Dialer != nil {
		dialer := config.Dialer
		dial = func(ctx context.Context, svc string) (io.ReadWriteCloser, error) {
			return dialer.DialADB(ctx, svc)
		}
	}

	t.sess = aproto.NewSession(conn, aproto.SessionConfig{
		Open:               dial,
		DelayedAck:         config.DelayedAck,
		LocalDelayedAck:    uint32(localDelayedAck),
		SupportsDelayedAck: func() bool { return t.SupportsFeature(adbproto.FeatureDelayedAck) },
		MaxQueuedPackets:   config.MaxQueuedPackets,
		WriteTimeout:       config.WriteTimeout,
		MaxStreams:         config.MaxStreams,
		KickWriteTimeout:   config.KickWriteTimeout,
	})
	go t.serve()
	return t, nil
}

// Idle returns true if the transport does not have any open streams.
func (t *Transport) Idle() bool {
	return t.sess.Idle()
}

// Connected returns a channel which gets closed once the device is authorized
// and has sent its connection banner.
func (t *Transport) Connected() <-chan struct{} {
	return t.sess.Connected()
}

// Unauthorized returns a channel which gets closed if all keys were rejected
// by the device and our public key was sent for the user to accept. The
// transport may still become Connected afterwards (i.e., once the user
// accepts the key).
func (t *Transport) Unauthorized() <-chan struct{} {
	return t.unauthorized
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

// WaitConnected waits until the transport is [Transport.Connected], the
// transport is kicked, or ctx is done.
func (t *Transport) WaitConnected(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.Kicked():
		return fmt.Errorf("kicked: %w", t.Error())
	case <-t.Connected():
		return nil
	}
}

// ErrTransportClosed is the error streams see after the transport is closed
// with [Transport.Close] or [Transport.Shutdown].
var ErrTransportClosed = errors.New("transport closed")

// Kick kicks the transport with the specified error (or a generic one if nil)
// if the transport has not been kicked yet. This closes the underlying
// connection without waiting for queued packets to be written (see
// [Transport.Flush] and [Transport.Shutdown]).
func (t *Transport) Kick(err error) {
	t.sess.Kick(err)
}

// Flush blocks until all queued packets have been written, ctx is done, or the
// transport is kicked. It is the same as [aproto.Session.Flush].
func (t *Transport) Flush(ctx context.Context) error {
	return t.sess.Flush(ctx)
}

// Shutdown gracefully closes the transport. It closes all open streams, waits
// for the resulting A_CLSE packets (and anything else queued) to be written or
// for ctx to be done, then kicks the transport with [ErrTransportClosed].
//
// Unlike Close, this lets the device clean up its side of the streams right
// away rather than when it sees the next connection. It returns the error from
// waiting, if any, but the transport is kicked regardless.
func (t *Transport) Shutdown(ctx context.Context) error {
	t.sess.CloseStreams()
	err := t.sess.Flush(ctx)
	t.Kick(ErrTransportClosed)
	return err
}

// Close kicks the transport with [ErrTransportClosed] immediately, without
// waiting for queued packets to be written (see [Transport.Shutdown]). It never
// returns an error.
func (t *Transport) Close() error {
	t.Kick(ErrTransportClosed)
	return nil
}

var (
	_ adb.Dialer   = (*Transport)(nil)
	_ adb.Features = (*Transport)(nil)
)

// DialADB connects to a service on the device.
func (t *Transport) DialADB(ctx context.Context, svc string) (net.Conn, error) {
	return t.sess.DialADB(ctx, svc)
}

// SupportsFeature checks whether a feature is supported by both the device
// and us. It returns false for everything until Connected.
func (t *Transport) SupportsFeature(f adbproto.Feature) bool {
	t.mu.Lock()
	banner := t.banner
	t.mu.Unlock()
	if banner == nil {
		return false
	}
	if _, ok := banner.Features[string(f)]; !ok {
		return false
	}
	if _, ok := t.hostBanner.Features[string(f)]; !ok {
		return false
	}
	return true
}

// Features returns an iterator of all features supported by both the device
// and us.
func (t *Transport) Features() iter.Seq[adbproto.Feature] {
	t.mu.Lock()
	banner := t.banner
	t.mu.Unlock()
	return func(yield func(adbproto.Feature) bool) {
		if banner != nil {
			for f := range banner.Features {
				if _, ok := t.hostBanner.Features[f]; ok {
					if !yield(adbproto.Feature(f)) {
						return
					}
				}
			}
		}
	}
}

// DeviceBanner returns a copy of the banner sent by the device, or nil if not
// Connected yet.
func (t *Transport) DeviceBanner() *aproto.Banner {
	t.mu.Lock()
	banner := t.banner
	t.mu.Unlock()
	return banner.Clone()
}

// serve runs the main loop for the connection. It blocks until the transport
// has been kicked.
func (t *Transport) serve() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer func() { t.Kick(nil) }()

	var (
		useTLS   bool
		keyIndex int
	)

	// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=327-349;drc=9f298fb1f3317371b49439efb20a598b3a881bf3
	if err := t.sess.Write(aproto.A_CNXN, aproto.VersionMax, aproto.MaxPayloadSize, []byte(t.hostBannerEnc)); err != nil {
		return
	}

	handshake := func(msg aproto.Message, data []byte) {
		switch msg.Command {
		case aproto.A_CNXN: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=407-433;drc=61197364367c9e404c7da6900658f1b16c42d0da
			select {
			case <-t.Connected():
				// note: adb would reset the connection state and all sockets,
				// but this shouldn't happen for tcp/usb transports in practice
				return // already connected
			default:
			}

			func() {
				t.mu.Lock()
				defer t.mu.Unlock()

				banner := new(aproto.Banner)
				banner.Decode(string(data))
				t.banner = banner
			}()

			// the device only sends A_CNXN once it has authenticated us, so we
			// are both connected and authenticated
			t.sess.SetConnected()
			t.sess.SetAuthenticated()

		case aproto.A_STLS: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=448-456;drc=61197364367c9e404c7da6900658f1b16c42d0da
			select {
			case <-t.Connected():
				return // already connected
			default:
			}
			if useTLS {
				return // already handshaked
			}
			useTLS = true

			if err := t.sess.Write(aproto.A_STLS, aproto.STLSVersionMin, 0, nil); err != nil {
				return
			}
			if !t.sess.HandshakeClient(t.clientTLSConfig()) {
				return
			}
			// the device will send A_CNXN once it accepts our certificate

		case aproto.A_AUTH: // https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=458-498;drc=61197364367c9e404c7da6900658f1b16c42d0da
			select {
			case <-t.Connected():
				return // already connected
			default:
			}
			if useTLS {
				return // ignore all auth packets when using tls
			}

			switch msg.Arg0 {
			case aproto.AuthToken:
				// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/client/auth.cpp;l=456-481;drc=61197364367c9e404c7da6900658f1b16c42d0da
				if i := keyIndex; i < len(t.keys) {
					keyIndex++
					sig, err := t.keys[i].Sign(rand.Reader, data, crypto.SHA1)
					if err != nil {
						t.Kick(fmt.Errorf("auth: sign token: %w", err))
						return
					}
					if err := t.sess.Write(aproto.A_AUTH, aproto.AuthSignature, 0, sig); err != nil {
						return
					}
					return
				}

				// no more keys to try, so send the public key and wait for the
				// user to accept it (the device will send A_CNXN if they do),
				// and start over with the first key if the device asks again
				keyIndex = 0

				if len(t.keys) == 0 {
					t.Kick(errors.New("auth: device requires authentication, but no keys are configured"))
					return
				}

				pub, err := encodePublicKey(t.keys[0], t.publicKeyName)
				if err != nil {
					t.Kick(fmt.Errorf("auth: encode public key: %w", err))
					return
				}
				if err := t.sess.Write(aproto.A_AUTH, aproto.AuthRSAPublicKey, 0, pub); err != nil {
					return
				}

				t.mu.Lock()
				select {
				case <-t.unauthorized:
				default:
					close(t.unauthorized)
				}
				t.mu.Unlock()

			default:
				return
			}
		}
	}

	t.sess.Serve(ctx, handshake)
}

// HostBanner returns the default banner sent to devices, containing the
// features supported by this module.
func HostBanner() *aproto.Banner {
	b := &aproto.Banner{
		Type:     "host",
		Props:    map[string]string{},
		Features: map[string]struct{}{},
	}
	for _, f := range hostFeatures {
		if f == adbproto.FeatureDelayedAck {
			continue // needs to be explicitly enabled in the config
		}
		b.Features[string(f)] = struct{}{}
	}
	return b
}

// hostFeatures contains known protocol-level features.
//
// note: features should be added here when added to adbproto
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/transport.cpp;l=1197-1240;drc=2d3e62c2af54a3e8f8803ea10492e63b8dfe709f
var hostFeatures = []adbproto.Feature{
	adbproto.FeatureShell2,
	adbproto.FeatureCmd,
	adbproto.FeatureStat2,
	adbproto.FeatureLs2,
	adbproto.FeatureFixedPushMkdir,
	adbproto.FeatureApex,
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
	adbproto.FeatureOpenscreenMdns,
	adbproto.FeatureDeviceTrackerProtoFormat,
	adbproto.FeatureDevRaw,
	adbproto.FeatureAppInfo,
	adbproto.FeatureServerStatus,
	adbproto.FeatureDelayedAck,
}
