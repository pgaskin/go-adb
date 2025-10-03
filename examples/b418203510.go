//go:build ignore

// Command b418203510 works around the bug in ADB causing the entire daemon to
// be blocked indefinitely by unix socket connections by proxying connections to
// unix sockets over shell v2.
//
// Also see b/372055979.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pgaskin/go-adb/adb"
	"github.com/pgaskin/go-adb/adb/adbhost"
	"github.com/pgaskin/go-adb/adb/adbproto"
	"github.com/pgaskin/go-adb/adb/adbproto/shellproto2"
	"github.com/pgaskin/go-adb/adblib/adbexec"
	"github.com/pgaskin/go-adb/adblib/adbproxy"
	"github.com/pgaskin/go-adb/adblib/adbsync"
)

var (
	Addr   = flag.String("addr", ":1234", "address to listen for 'adb connect' on")
	ADB    = flag.String("adb", adbhost.DefaultAddr, "address to connect to local adb server") // you can change this to another port running a second ADB daemon (and disable USB enumeration on the default one)
	Serial = flag.String("serial", "", "adb device serial")
	Arch   = flag.String("arch", "arm64", "goarch for android device") // we could detect this, but this is just a quick PoC
)

const src = `
package main

import (
	"fmt"
	"io"
	"net"
	"os"
)

func main() {
	conn, err := net.Dial("unix", os.Args[1])
	if err != nil {
		fmt.Printf("E%v", err)
		return
	}
	defer conn.Close()

	os.Stdout.Write([]byte{'\xFF'})

	go func() {
		defer conn.(*net.UnixConn).CloseWrite()
		io.Copy(conn, os.Stdin)
	}()

	io.Copy(os.Stdout, conn)
}
`

func main() {
	flag.Parse()

	ctx := context.Background()

	dlr := &adbhost.Dialer{
		Addr: *ADB,
	}
	if err := dlr.LoadFeatures(ctx); err != nil {
		panic(err)
	}
	slog.Info("connected to adb daemon", "addr", dlr.Addr)

	if dlr.Addr == adbhost.DefaultAddr {
		slog.Warn("you must not run chrome://inspect on the same machine unless you change the adb address for the USB device to an adb server listening on a different port")
	}

	var dev *adbhost.TransportDialer
	if *Serial != "" {
		dev = adbhost.Server(dlr, adbhost.Serial(*Serial)) // non-sticky since we're identifying it by the serial
	} else {
		dev = adbhost.StickyServer(dlr, adbhost.TransportUSB) // sticky to ensure we only connect to the same device
	}
	if err := dev.LoadFeatures(ctx); err != nil {
		panic(err)
	}

	tid, _ := dev.TransportID()
	slog.Info("connected to device", "transport_id", tid)

	banner, err := adbproxy.DeviceBanner(ctx, dev)
	if err != nil {
		panic(err)
	}
	slog.Info("generated device banner", "banner", banner.Encode())

	wrapped, err := NewSocketInterceptDialer(ctx, dev, *Arch)
	if err != nil {
		panic(err)
	}
	prx := &adbproxy.Server{
		Addr:   *Addr,
		Banner: banner,
		Dialer: wrapped,

		Auth: func(ctx context.Context) adbproxy.Authenticator {
			return adbproxy.AuthFunc(func(a adbproxy.Auth) bool {
				slog.Info("accepting connection", "auth", fmt.Sprint(a))
				return true
			})
		},

		TLS:         true,
		TLSFallback: true,

		DelayedAck:      true,
		LocalDelayedAck: 33554432,
	}
	slog.Info("listening for 'adb connect'", "addr", prx.Addr)
	panic(prx.ListenAndServe())
}

type socketInterceptDialer struct {
	bin string
	dev adb.Dialer
}

func NewSocketInterceptDialer(ctx context.Context, dev adb.Dialer, arch string) (adb.Dialer, error) {
	slog.Info("building connect helper")
	buf, err := buildConnect(ctx, arch)
	if err != nil {
		return nil, fmt.Errorf("failed to build connect helper: %w", err)
	}

	slog.Info("pushing connect helper", "size", len(buf))
	sc := adbsync.Client{Server: dev}
	defer sc.CloseIdleConnections()
	bin := "/data/local/tmp/connect_helper"
	if err := sc.WriteFile(bin, buf, 0777); err != nil {
		return nil, fmt.Errorf("failed to push connect helper: %w", err)
	}

	if err := adb.SupportsFeature(dev, adbproto.FeatureShell2); err != nil {
		return nil, err // needed since shell v1 raw mode isn't actually raw
	}
	return &socketInterceptDialer{
		bin: bin,
		dev: dev,
	}, nil
}

func buildConnect(ctx context.Context, arch string) ([]byte, error) {
	td, err := os.MkdirTemp("", "connect-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(td)

	tf := filepath.Join(td, "connect.go")
	if err := os.WriteFile(tf, []byte(src), os.ModePerm); err != nil {
		return nil, err
	}

	tb := filepath.Join(td, "connect")
	cmd := exec.CommandContext(ctx, "go", "build", "-ldflags", "-s -w", "-o", tb, tf)
	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env,
		"GOOS=linux",
		"GOARCH="+arch,
		"GOFLAGS=",
		"CGO_ENABLED=0",
	)
	if _, err := cmd.Output(); err != nil {
		return nil, fmt.Errorf("command %q failed: %w", cmd.Args, err)
	}
	return os.ReadFile(tb)
}

func (d *socketInterceptDialer) DialADB(ctx context.Context, svc string) (net.Conn, error) {
	if addr, ok := strings.CutPrefix(svc, "localabstract:"); ok {
		return d.connect(ctx, "@"+addr)
	}
	if addr, ok := strings.CutPrefix(svc, "localfilesystem:"); ok {
		return d.connect(ctx, addr)
	}
	return d.dev.DialADB(ctx, svc)
}

func (d *socketInterceptDialer) connect(ctx context.Context, addr string) (net.Conn, error) {
	slog.Info("intercepting unix socket connection", "addr", addr)

	conn, err := OpenShell2RawConn(ctx, d.dev, adbexec.Quote(d.bin, addr))
	if err != nil {
		slog.Warn("failed to start proxy", "error", err)
		return nil, fmt.Errorf("start proxy: %w", err)
	}

	tmp := make([]byte, 1)
	if _, err := io.ReadFull(conn, tmp); err != nil {
		err = fmt.Errorf("failed to read status byte: %w", err)
		slog.Warn("failed to start proxy", "error", err)
		return nil, fmt.Errorf("start proxy: %w", err)
	}
	switch tmp[0] {
	case '\xFF':
		return conn, nil
	case 'E':
		buf, _ := io.ReadAll(conn)
		err = fmt.Errorf("connect %q failed: %s", addr, string(buf))
		slog.Warn("failed to connect", "error", err)
		return nil, fmt.Errorf("start proxy: %w", err)
	default:
		err = fmt.Errorf("unexpected byte %c", tmp[0])
		slog.Warn("failed to start proxy", "error", err)
		return nil, fmt.Errorf("start proxy: %w", err)
	}
}

// shell2rawConn is a fake [net.Conn] backed by a shell v2 raw connection. It
// must not be used concurrently.
type shell2rawConn struct {
	c   *adb.ShellConn2
	b   bytes.Buffer
	eof bool
}

func OpenShell2RawConn(ctx context.Context, dev adb.Dialer, cmd string) (net.Conn, error) {
	var b shellproto2.ServiceBuilder
	b.Command(cmd)
	b.Raw()
	c, err := adb.Shell2(ctx, dev, b.String())
	if err != nil {
		return nil, err
	}
	return &shell2rawConn{c: c}, nil
}

func (c *shell2rawConn) Read(b []byte) (n int, err error) {
	for c.b.Len() == 0 {
		if c.eof {
			return 0, io.EOF
		}
		id, buf, ok := c.c.Read()
		if !ok {
			return 0, c.c.Error()
		}
		switch id {
		case shellproto2.PacketExit:
			c.eof = true
			return 0, io.EOF
		case shellproto2.PacketStdout:
			c.b.Write(buf)
		}
	}
	return c.b.Read(b)
}

func (c *shell2rawConn) Write(b []byte) (n int, err error) {
	if !c.c.Write(shellproto2.PacketStdin, b) {
		return 0, c.c.Error()
	}
	return len(b), nil
}

func (c *shell2rawConn) Close() error {
	return c.c.Close()
}

func (c *shell2rawConn) LocalAddr() net.Addr                { return nil }
func (c *shell2rawConn) RemoteAddr() net.Addr               { return nil }
func (c *shell2rawConn) SetDeadline(t time.Time) error      { return errors.ErrUnsupported }
func (c *shell2rawConn) SetReadDeadline(t time.Time) error  { return errors.ErrUnsupported }
func (c *shell2rawConn) SetWriteDeadline(t time.Time) error { return errors.ErrUnsupported }
