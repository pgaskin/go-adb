// Package adbtcpip authenticates with and connects to an ADB server over
// TCP/IP.
package adbtcpip

import (
	"context"
	"net"
	"strconv"

	"github.com/pgaskin/go-adb/adb/adbproto/atransport"
)

// DefaultPort is the default port for legacy ADB-over-TCP/IP.
const DefaultPort = 5555

// Dialer connects directly to ADB devices over TCP/IP (i.e., `adb tcpip` or
// wireless debugging).
//
// A nil Dialer will act the same way as a zero Dialer.
type Dialer struct {
	// DialContext is the function used to open the TCP connection. If nil, the
	// default [net.Dialer]'s DialContext is used.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// Config is the transport configuration (keys, delayed acks, etc). It may
	// be nil.
	Config *atransport.Config
}

// Connect opens a TCP connection to the device at addr (with [DefaultPort] if
// addr does not contain a port) and starts an ADB transport over it, waiting
// for the connection to be ready (see [atransport.Transport.WaitConnected]).
//
// Note that if our key isn't authorized yet, this will block until the user
// accepts it or ctx is done. To avoid waiting, use [atransport.Connect]
// directly with a [net.Conn].
func (d *Dialer) Connect(ctx context.Context, addr string) (*atransport.Transport, error) {
	var dc func(ctx context.Context, network, addr string) (net.Conn, error)
	var config *atransport.Config
	if d != nil {
		dc = d.DialContext
		config = d.Config
	}
	if dc == nil {
		dc = new(net.Dialer).DialContext
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, strconv.Itoa(DefaultPort))
	}

	// note: Go already sets NODELAY on TCP sockets

	conn, err := dc(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	t, err := atransport.Connect(conn, config)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if err := t.WaitConnected(ctx); err != nil {
		t.Kick(err)
		return nil, err
	}
	return t, nil
}

// TODO: rework api? top-level connect?

// TODO: pairing
