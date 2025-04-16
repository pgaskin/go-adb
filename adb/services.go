package adb

import (
	"context"
	"io"
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
