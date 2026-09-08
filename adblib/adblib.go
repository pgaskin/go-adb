// Package adblib provides high-level ADB functionality.
package adblib

import (
	"cmp"
	"context"
	"crypto"

	"github.com/pgaskin/go-adb/adb/adbhost"
	"github.com/pgaskin/go-adb/adb/adbproto/atransport"
	"github.com/pgaskin/go-adb/adb/adbtcpip"
)

// Connect connects to an ADB device through an ADB server. If addr is empty,
// [adbhost.DefaultAddr] is used. If dev is empty, [adbhost.TransportAny] is
// used, and the dialer will be bound to the initially selected device for
// future connections. It is equivalent to using [adbhost.Server] and calling
// LoadFeatures.
func Connect(ctx context.Context, addr, serial string) (*adbhost.TransportDialer, error) {
	dlr := &adbhost.Dialer{
		Addr: cmp.Or(addr, adbhost.DefaultAddr),
	}
	if err := dlr.LoadFeatures(ctx); err != nil {
		return nil, err
	}
	var srv *adbhost.TransportDialer
	if serial == "" {
		srv = adbhost.StickyServer(dlr, adbhost.TransportAny) // sticky so we refer to the same device and connecting more devices doesn't make it start to fail
	} else {
		srv = adbhost.Server(dlr, adbhost.Serial(serial)) // not sticky so reconnecting the device doesn't cause connections to fail
	}
	if err := srv.LoadFeatures(ctx); err != nil {
		return nil, err
	}
	return srv, nil
}

// ConnectTCP connects directly to an ADB device listening on addr over TCP/IP
// (i.e., `adb tcpip` or wireless debugging), authenticating with key (or the
// user's ADB key if key is nil; see [adbhost.LoadUserKey]). If addr does not
// contain a port, [adbtcpip.DefaultPort] is used. It waits for the connection
// to be established.
//
// Note that if the key isn't authorized yet, this blocks until the user accepts
// it on the device or ctx is done. For more control (e.g., multiple keys,
// delayed acks, no waiting), use an [adbtcpip.Dialer] directly.
func ConnectTCP(ctx context.Context, addr string, key crypto.Signer) (*atransport.Transport, error) {
	key, err := userKey(key)
	if err != nil {
		return nil, err
	}
	return (&adbtcpip.Dialer{
		Config: &atransport.Config{Keys: []crypto.Signer{key}},
	}).Connect(ctx, addr)
}

func userKey(key crypto.Signer) (crypto.Signer, error) {
	if key != nil {
		return key, nil
	}
	return adbhost.LoadUserKey()
}
