package adbhost

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pgaskin/go-adb/adb"
	"github.com/pgaskin/go-adb/adb/adbproto"
)

// Transport selects an ADB server to connect to via a host server.
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=1293-1352;drc=9f298fb1f3317371b49439efb20a598b3a881bf3.
type Transport interface {
	hostPrefix() string
	transport() string
}

// TransportID selects a specific transport by its ID.
type TransportID uint64

func (t TransportID) String() string {
	return "TransportID(" + strconv.FormatUint(uint64(t), 10) + ")"
}

func (t TransportID) hostPrefix() string {
	return "host:transport-id:" + strconv.FormatUint(uint64(t), 10)
}

func (t TransportID) transport() string {
	return "host-transport-id:" + strconv.FormatUint(uint64(t), 10)
}

// Serial uniquely identifies devices connected to the ADB host server.
type Serial string

func (s Serial) String() string {
	if s == "" {
		return ""
	}
	return "Serial(" + string(s) + ")"
}

func (s Serial) hostPrefix() string {
	if s == "" {
		return ""
	}
	return "host-serial:" + string(s)
}

func (s Serial) transport() string {
	if s == "" {
		return ""
	}
	return "host:tport:serial:" + string(s)
}

// DefaultTransport selects the first matching device as long as there is only
// one of that kind.
type DefaultTransport string

const (
	TransportUSB   DefaultTransport = "usb"   // usb device
	TransportLocal DefaultTransport = "local" // emulator
	TransportAny   DefaultTransport = "any"   // any device
)

func (t DefaultTransport) String() string {
	return "DefaultTransport(" + string(t) + ")"
}

func (t DefaultTransport) hostPrefix() string {
	return "host:tport:" + string(t)
}

func (t DefaultTransport) transport() string {
	return "host-" + string(t)
}

// TODO: emulator

// TransportDialer is an [adb.Dialer] which dials a transport through a host
// server.
type TransportDialer struct {
	d *Dialer
	t Transport
	k atomic.Pointer[sync.Mutex] // protects t if not a TransportID
	f atomic.Pointer[map[adbproto.Feature]struct{}]
}

var _ adb.Dialer = (*TransportDialer)(nil)
var _ adb.Features = (*TransportDialer)(nil)

type serverDialerConn struct {
	net.Conn
	tid *TransportID
}

// Server returns an [adb.Dialer] for a [Transport] accessible through the host
// server.
//
// If d is nil, an empty one is used.
//
// The [TransportID] selected by the ADB host for a connection can be retrieved
// using [ServerConnTransportID] to allow the same device to be connected to
// later (e.g., after "adb root").
func Server(d *Dialer, t Transport) *TransportDialer {
	return &TransportDialer{d: d, t: t}
}

// StickyServer is like [Server], but will pin the transport id after the first
// connection.
//
// This is useful for things which may open a pool of connections to the same
// device.
//
// Note that a USB disconnection and reconnection will change the transport id.
func StickyServer(d *Dialer, t Transport) *TransportDialer {
	s := Server(d, t)
	if _, ok := t.(TransportID); !ok {
		s.k.Store(new(sync.Mutex))
	}
	return s
}

// DialADB opens a connection to svc on the transport. If the dialer was created
// with [StickyServer], this will pin the [TransportID] if supported.
func (h *TransportDialer) DialADB(ctx context.Context, svc string) (net.Conn, error) {
	var sticking bool
	if m := h.k.Load(); m != nil {
		// we're sticky, but we don't have a pinned transport id yet
		m.Lock()
		defer m.Unlock()
		sticking = true
	}
	transportSvc := h.t.transport()
	if transportSvc == "" {
		return nil, errors.New("invalid transport")
	}
	conn, err := h.d.DialADBHost(ctx, transportSvc)
	if err != nil {
		return nil, err
	}
	tid, ok := h.t.(TransportID)
	if isLegacy := !strings.HasPrefix(transportSvc, "host:tport:"); !ok && !isLegacy {
		buf := make([]byte, 8)
		if _, err := io.ReadFull(conn, buf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tport: read selected transport id: %w", err)
		}
		tid, ok = TransportID(binary.LittleEndian.Uint64(buf)), true
	}
	var tidPtr *TransportID
	if ok {
		if sticking {
			// we don't need the mutex once we have pinned the transport id
			h.k.Store(nil)
			h.t = tid
		}
		tidPtr = &tid
	}
	if err := adbService(ctx, conn, svc); err != nil {
		conn.Close()
		return nil, err
	}
	return &serverDialerConn{conn, tidPtr}, nil
}

// DialADBHostTransport opens a connection to the host svc for the transport.
// Note that this will not pin the TransportID for a [StickyServer].
func (h *TransportDialer) DialADBHostTransport(ctx context.Context, svc string) (net.Conn, error) {
	if m := h.k.Load(); m != nil {
		// we're sticky, but we don't have a pinned transport id yet
		m.Lock()
		defer m.Unlock()
	}
	t := h.t
	if tid, ok := h.t.(TransportID); ok {
		t = tid
	}
	return h.d.DialADBHost(ctx, t.hostPrefix()+":"+svc)
}

// TransportID returns the transport ID if the dialer was created with a
// TransportID or after the first [DialADB] when created with [StickyServer].
func (h *TransportDialer) TransportID() (TransportID, bool) {
	if h.k.Load() == nil {
		if tid, ok := h.t.(TransportID); ok {
			return tid, true
		}
	}
	return TransportID(0), false
}

// SupportsFeature returns true if the transport supports the provided feature.
// This is the intersection of the features supported by the transport and the
// features supported by the host server. If [TransportDialer.LoadFeatures] or
// [Dialer.LoadFeatures] have not been called, this will always return false.
func (h *TransportDialer) SupportsFeature(f adbproto.Feature) bool {
	if h.d.SupportsFeature(f) {
		if fm := h.f.Load(); fm != nil {
			_, ok := (*fm)[f]
			return ok
		}
	}
	return false
}

// LoadFeatures updates the list of supported optional features. Note that you
// also need to call [Dialer.LoadFeatures] if you haven't already done so.
func (h *TransportDialer) LoadFeatures(ctx context.Context) error {
	conn, err := h.DialADBHostTransport(ctx, "features")
	if err != nil {
		return err
	}
	defer conn.Close()

	buf, err := adbproto.ReadProtocolBytes(conn, nil)
	if err != nil {
		return err
	}

	fm := map[adbproto.Feature]struct{}{}
	for feat := range bytes.SplitSeq(buf, []byte{','}) {
		fm[adbproto.Feature(feat)] = struct{}{}
	}
	h.f.Store(&fm)

	return nil
}

// Features returns all supported features. This is the intersection of the
// features supported by the transport and the features supported by the host
// server. If [TransportDialer.LoadFeatures] or [Dialer.LoadFeatures] have not
// been called, this will always return false.
func (h *TransportDialer) Features() iter.Seq[adbproto.Feature] {
	return func(yield func(adbproto.Feature) bool) {
		if fm := h.f.Load(); fm != nil {
			for f := range *fm {
				if h.d.SupportsFeature(f) {
					if !yield(f) {
						return
					}
				}
			}
		}
	}
}

// ServerConnTransportID gets the TransportID from a conn opened via [Host] if
// known.
func ServerConnTransportID(conn net.Conn) (TransportID, bool) {
	if hc, ok := conn.(*serverDialerConn); ok && hc != nil {
		if hc.tid != nil {
			return *hc.tid, true
		}
	}
	return TransportID(0), false
}
