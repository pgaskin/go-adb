// Package adbhost connects to an ADB host server.
package adbhost

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"time"
)

// TODO: do I need to worry about protocol versions?

// DefaultAddr is the default address for the ADB host server.
var DefaultAddr = "localhost:5037"

// Dialer connects to an ADB host server.
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
	dc := c.DialContext
	if dc == nil {
		dc = new(net.Dialer).DialContext
	}
	conn, err := dc(ctx, "tcp", cmp.Or(c.Addr, DefaultAddr))
	if err != nil {
		return conn, nil
	}
	if err := adbService(ctx, conn, svc); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// TODO: refactor these helpers into a separate package once I figure out where to put them

// adbService connects to svc, using the deadline from ctx, and returning
// immediately if ctx is cancelled.
func adbService(ctx context.Context, conn net.Conn, svc string) error {
	ch := make(chan error, 1)
	go func() (err error) {
		defer func() { ch <- err }()
		if deadline, ok := ctx.Deadline(); ok {
			conn.SetDeadline(deadline)
		}
		if err := adbSendMsg(conn, svc); err != nil {
			return fmt.Errorf("service %q: send message: %w", svc, err)
		}
		if status, err := adbRecvStatus(conn); err != nil {
			return fmt.Errorf("service %q: recv status: %w", svc, err)
		} else if status != [4]byte{'O', 'K', 'A', 'Y'} {
			return fmt.Errorf("service %q: adb status %q", svc, status)
		}
		conn.SetDeadline(time.Time{})
		return nil
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

// TODO: refactor these and put them somewhere else (maybe go-adb/adb/protocol.go if I can make it reusable for usb stuff?)

func adbSendMsg(conn net.Conn, msg string) error {
	_, err := conn.Write(fmt.Appendf(nil, "%04x%s", len(msg), msg))
	return err
}

func adbRecvStatus(conn net.Conn) (status [4]byte, err error) {
	_, err = io.ReadFull(conn, status[:])
	return
}

func adbRecvMsg(conn net.Conn, buf []byte) ([]byte, error) {
	var length [4]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil, err
	}
	n, err := strconv.ParseUint(string(length[:]), 16, 32)
	if err != nil {
		return nil, err
	}
	if int(n) > cap(buf) {
		buf = slices.Grow(buf[:0], int(n))
	}
	buf = buf[:n]
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
