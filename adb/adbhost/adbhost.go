// Package adbhost connects to an ADB host server.
package adbhost

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/pgaskin/go-adb/adb/adbproto"
)

// DefaultAddr is the default address for the ADB host server.
var DefaultAddr = "localhost:5037"

// Dialer connects to an ADB host server.
//
// A nil Dialer will act the same way as an zero Dialer.
type Dialer struct {
	// DialContext is the function used to open the TCP connection. If nil,
	// the default [net.Dialer]'s DialContext is used.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// Addr is the server address. If empty, [DefaultAddr] is used.
	Addr string
}

// DialADBHost connects to the specified service on the host server. It will
// return immediately if ctx is cancelled. The context deadline applies to the
// time to establish the tcp connection and receive the OKAY completing the
// service connection.
func (c *Dialer) DialADBHost(ctx context.Context, svc string) (net.Conn, error) {
	var dc func(ctx context.Context, network, addr string) (net.Conn, error)
	if c != nil && c.DialContext != nil {
		dc = c.DialContext
	} else {
		dc = new(net.Dialer).DialContext
	}
	var addr string
	if c != nil && c.Addr != "" {
		addr = c.Addr
	} else {
		addr = DefaultAddr
	}
	conn, err := dc(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("service %q: %w", svc, err)
	}
	if err := adbService(ctx, conn, svc); err != nil {
		conn.Close()
		return nil, fmt.Errorf("service %q: %w", svc, err)
	}
	return conn, nil
}

// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/client/adb_client.cpp;l=137-156;drc=c58caa21f0c7efccf1ecbd5a5fd1570ff0c246a3
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb_io.cpp;l=68-75;drc=90228a63bb6a59e8195165fbb7c332be27459696

// adbService connects to svc, using the deadline from ctx, and returning
// immediately if ctx is cancelled.
func adbService(ctx context.Context, conn net.Conn, svc string) error {
	ch := make(chan error, 1)
	go func() (err error) {
		defer func() { ch <- err }()
		if deadline, ok := ctx.Deadline(); ok {
			conn.SetDeadline(deadline)
			defer conn.SetDeadline(time.Time{})
		}
		if err := adbproto.SendProtocolString(conn, svc); err != nil {
			return adbproto.ProtocolErrorf("send service: %w", err)
		}
		return adbproto.ReadOkayFail(conn)
	}()
	select {
	case err := <-ch:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}
