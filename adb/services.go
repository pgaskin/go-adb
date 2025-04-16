package adb

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
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

// Remount calls the remount command, returning the output. If the dialer
// supports [adbproto.FeatureRemountShell], the shell v2 (if
// [adbproto.FeatureShell2]) or legacy shell protocol is used to call the
// commmand.
//
// Note that on failure, a nil error may be returned with the error message in
// the output. As such, if you care about proper error checking, you should
// check for [adbproto.FeatureRemountShell] then call remount yourself using the
// shell v2 protocol.
func Remount(ctx context.Context, srv Dialer, args string) ([]byte, error) {
	return remountOrVerity(ctx, srv, "remount", args)
}

// EnableVerity calls the enable-verity command, returning the output. If the
// dialer supports [adbproto.FeatureRemountShell], the shell v2 (if
// [adbproto.FeatureShell2]) or legacy shell protocol is used to call the
// commmand. Note that on failure, a nil error may be returned with the error
// message in the output.
//
// Note that on failure, a nil error may be returned with the error message in
// the output. As such, if you care about proper error checking, you should
// check for [adbproto.FeatureRemountShell] then call enable-verity yourself
// using the shell v2 protocol.
func EnableVerity(ctx context.Context, srv Dialer) ([]byte, error) {
	return remountOrVerity(ctx, srv, "enable-verity", "")
}

// DisableVerity calls the disable-verity command, returning the output. If the
// dialer supports [adbproto.FeatureRemountShell], the shell v2 (if
// [adbproto.FeatureShell2]) or legacy shell protocol is used to call the
// commmand.
//
// Note that on failure, a nil error may be returned with the error message in
// the output. As such, if you care about proper error checking, you should
// check for [adbproto.FeatureRemountShell] then call disable-verity yourself
// using the shell v2 protocol.
func DisableVerity(ctx context.Context, srv Dialer) ([]byte, error) {
	return remountOrVerity(ctx, srv, "disable-verity", "")
}

// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/client/commandline.cpp;l=1481-1497;drc=08a96199bf8ce0581c366fc9c725351ee127fd21
func remountOrVerity(ctx context.Context, srv Dialer, what, args string) ([]byte, error) {
	if err := SupportsFeature(srv, adbproto.FeatureRemountShell); err == nil {
		return shellRawOutputNoStdin(ctx, srv, what+" "+args)
	}

	conn, err := srv.DialADB(ctx, what+":"+args)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	context.AfterFunc(ctx, func() {
		conn.Close() // this will interrupt the output copy
	})

	buf, err := io.ReadAll(conn)
	if err != nil {
		if err := ctx.Err(); err != nil {
			return nil, err // context cancellation error first
		}
		return nil, err
	}
	return buf, ctx.Err()
}

// shellRawOutputNoStdin gets the combined stdin and stdout of executing
// command, ignoring the exit status. If [adbproto.FeatureShell2] is supported,
// shell v2 is used instead of exec.
func shellRawOutputNoStdin(ctx context.Context, srv Dialer, command string) ([]byte, error) {
	if err := SupportsFeature(srv, adbproto.FeatureShell2); err == nil {
		var b shellproto2.ServiceBuilder
		b.Raw()
		b.Command(command)

		conn, err := Shell2(ctx, srv, b.String())
		if err != nil {
			return nil, err
		}
		defer conn.Close()

		context.AfterFunc(ctx, func() {
			conn.Close() // this will interrupt the output copy
		})

		var buf bytes.Buffer
		for {
			id, pkt, ok := conn.Read()
			if !ok {
				return buf.Bytes(), conn.Error()
			}
			switch id {
			case shellproto2.PacketExit:
				// ignore the exit status for consistency with exec
				return buf.Bytes(), nil
			case shellproto2.PacketStdout:
				buf.Write(pkt)
			case shellproto2.PacketStderr:
				buf.Write(pkt)
			}
		}
	} else {
		conn, err := Exec(ctx, srv, command)
		if err != nil {
			return nil, err
		}
		defer conn.Close()

		context.AfterFunc(ctx, func() {
			conn.Close() // this will interrupt the output copy
		})

		buf, outputErr := io.ReadAll(conn)
		if err := ctx.Err(); err != nil {
			return buf, err // if the context was cancelled, that error takes precedence
		}
		if err := outputErr; err != nil {
			return buf, fmt.Errorf("read stdout: %w", err)
		}
		return buf, nil
	}
}

// RestartUSB restarts the ADB daemon in USB mode. Note that as of Android 15,
// it will restart the daemon (breaking all connections) even if already in USB mode.
func RestartUSB(ctx context.Context, srv Dialer) error {
	conn, err := srv.DialADB(ctx, "usb:")
	if err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, conn) // adb will close the connection when restarting
	return err
}

// RestartTCP restarts the ADB daemon in TCP/IP mode listening on the
// specified port. Note that as of Android 15, it will always restart the daemon
// (breaking all connections), and USB will still work on the damon listening on
// TCP/IP.
func RestartTCP(ctx context.Context, srv Dialer, port uint16) error {
	conn, err := srv.DialADB(ctx, "tcpip:"+strconv.FormatInt(int64(port), 10))
	if err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, conn) // adb will close the connection when restarting
	return err
}

// TODO: jdwp
// TODO: track-jdwp
// TODO: track-app
// TODO: sink
// TODO: source
// TODO: abb
// TODO: abb_exec
// TODO: framebuffer
// TODO: reboot
// TODO: root
// TODO: unroot
// TODO: backup
// TODO: restore
// TODO: dev
// TODO: dev-raw
// TODO: sync
// TODO: reverse
// TODO: reconnect
// TODO: spin
