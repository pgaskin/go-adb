// Package adblib provides high-level ADB functionality.
package adblib

import (
	"cmp"
	"context"

	"github.com/pgaskin/go-adb/adb/adbhost"
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
