package adbhost

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pgaskin/go-adb/adb"
)

// Transport selects an ADB server to connect to via a host server.
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=1293-1352;drc=9f298fb1f3317371b49439efb20a598b3a881bf3.
type Transport interface {
	hostPrefix() string
}

// TransportID selects a specific transport by its ID.
type TransportID uint64

func (t TransportID) String() string {
	return "TransportID(" + strconv.FormatUint(uint64(t), 10) + ")"
}

func (t TransportID) hostPrefix() string {
	return "host:transport-id:" + strconv.FormatUint(uint64(t), 10)
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

// TODO: emulator

type serverDialer struct {
	d *Dialer
	t Transport
	k atomic.Pointer[sync.Mutex]
}

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
func Server(d *Dialer, t Transport) adb.Dialer {
	if d == nil {
		d = new(Dialer)
	}
	return &serverDialer{d: d, t: t}
}

// StickyServer is like [Server], but will pin the transport id after the first
// connection.
//
// This is useful for things which may open a pool of connections to the same
// device.
//
// Note that a USB disconnection and reconnection will change the transport id.
func StickyServer(d *Dialer, t Transport) adb.Dialer {
	s := Server(d, t).(*serverDialer)
	if _, ok := t.(TransportID); !ok {
		s.k.Store(new(sync.Mutex))
	}
	return s
}

func (h *serverDialer) DialADB(ctx context.Context, svc string) (net.Conn, error) {
	var sticking bool
	if m := h.k.Load(); m != nil {
		// we're sticky, but we don't have a pinned transport id yet
		m.Lock()
		defer m.Unlock()
		sticking = true
	}
	hostPrefix := h.t.hostPrefix()
	if hostPrefix == "" {
		return nil, errors.New("invalid transport")
	}
	conn, err := h.d.DialADBHost(ctx, hostPrefix)
	if err != nil {
		return nil, err
	}
	tid, ok := h.t.(TransportID)
	if isLegacy := !strings.HasPrefix(hostPrefix, "host:tport:"); !ok && !isLegacy {
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
