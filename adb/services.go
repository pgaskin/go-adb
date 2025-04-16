package adb

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/pgaskin/go-adb/adb/adbproto"
	"github.com/pgaskin/go-adb/adb/adbproto/shellproto2"
)

// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/daemon/services.cpp;drc=a9b3987d2a42a40de0d67fcecb50c9716639ef03

// Shell executes a command using the shell v1 protocol. This will always
// allocate a pty which will cook the input/output.
func Shell(ctx context.Context, srv Dialer, command string) (io.ReadWriteCloser, error) {
	conn, err := srv.DialADB(ctx, "shell:"+command)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Exec executes a command using the exec protocol, which enables raw mode to
// prevent the output or input from being mangled. This should be used when
// using commands which read or write binary data.
func Exec(ctx context.Context, srv Dialer, command string) (io.ReadWriteCloser, error) {
	conn, err := srv.DialADB(ctx, "shell:"+command)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// ShellConn2 wraps a [net.Conn] and [*shellproto2.Conn].
type ShellConn2 struct {
	*shellproto2.Conn
	NetConn net.Conn
}

func NewShellConn2(conn net.Conn) *ShellConn2 {
	return &ShellConn2{
		NetConn: conn,
		Conn:    shellproto2.New(conn),
	}
}

func (s *ShellConn2) Close() error {
	return s.NetConn.Close()
}

// Shell2 opens a shell v2 connection. You can use [shellproto2.ServiceBuilder]
// to build svc. The dialer must support [adbproto.FeatureShell2].
func Shell2(ctx context.Context, srv Dialer, svc string) (*ShellConn2, error) {
	if x, ok := strings.CutPrefix(svc, "shell,v2"); !ok || len(x) == 0 || !(x[0] == ',' || x[0] == ':') {
		return nil, fmt.Errorf("invalid shell v2 service %q", svc)
	}
	if err := SupportsFeature(srv, adbproto.FeatureShell2); err != nil {
		return nil, err
	}
	conn, err := srv.DialADB(ctx, svc)
	if err != nil {
		return nil, err
	}
	return NewShellConn2(conn), nil
}

// TODO: jdwp
// TODO: track-jdwp
// TODO: track-app
// TODO: sink
// TODO: source
// TODO: abb
// TODO: abb_exec
// TODO: framebuffer
// TODO: remount
// TODO: reboot
// TODO: root
// TODO: unroot
// TODO: backup
// TODO: restore
// TODO: disable-verity
// TODO: enable-verity
// TODO: tcpip
// TODO: usb
// TODO: dev
// TODO: dev-raw
// TODO: sync
// TODO: reverse
// TODO: reconnect
// TODO: spin
