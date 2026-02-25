//go:build ignore

// Command adbproxyrev is an example which shows how to make `adb reverse` work
// correctly through an adbproxy instance running on a remote machine (this is
// the only thing which won't just work out-of-the-box).
//
//	$ go run ./examples/adbproxyrev.go
//
//	$ adb connect localhost:1234
//	connected to localhost:1234
//
//	$ adb -s localhost:1234 reverse --list
//	UsbFfs tcp:2222 localabstract:adbproxy,pid=184271,id=2,local=127.0.0.1:1234,remote=127.0.0.1:60463,service=tcp:22
//
//	$ adb -s localhost:1234 reverse tcp:2222 tcp:22
//
//	$ adb -s localhost:1234 reverse --list
//	UsbFfs tcp:2222 localabstract:adbproxy,pid=191081,id=1,local=127.0.0.1:1234,remote=127.0.0.1:50715,service=tcp:22
//
//	$ adb -d shell nc localhost 2222
//	SSH-2.0-OpenSSH_10.0
//	^C
//
//	$ adb disconnect
//	disconnected everything
//
//	$ adb -d reverse --list
//	UsbFfs tcp:2222 localabstract:adbproxy,pid=191081,id=1,local=127.0.0.1:1234,remote=127.0.0.1:50715,service=tcp:22
//
//	$ adb -d shell nc localhost 2222
//
//	$ adb connect localhost:1234
//	connected to localhost:1234
//
//	$ adb -s localhost:1234 reverse tcp:2222 tcp:22
//
//	$ adb -s localhost:1234 reverse --list
//	UsbFfs tcp:2222 localabstract:adbproxy,pid=191081,id=2,local=127.0.0.1:1234,remote=127.0.0.1:44271,service=tcp:22
//
//	$ adb -d shell nc localhost 2222
//	SSH-2.0-OpenSSH_10.0
//	^C
package main

import (
	"cmp"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pgaskin/go-adb/adb"
	"github.com/pgaskin/go-adb/adb/adbhost"
	"github.com/pgaskin/go-adb/adb/adbproto"
	"github.com/pgaskin/go-adb/adblib/adbproxy"
)

var (
	Addr   = flag.String("addr", ":1234", "address to listen for 'adb connect' on")
	ADB    = flag.String("adb", adbhost.DefaultAddr, "address to connect to local adb server")
	Serial = flag.String("serial", "", "adb device serial")
)

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

	// note: in a real server, you'd probably want to clean up old reverse
	// forwards left on the device which no longer point to a running adbproxy
	// (you can do this by running list-forward and parsing the socket names
	// then checking if the pid is still running, etc)

	w, close := WrapReverseForwards(dev)
	defer close()

	prx := &adbproxy.Server{
		Addr:   *Addr,
		Dialer: w,
	}
	if err := prx.ListenAndServe(); err != nil {
		panic(err)
	}
}

type reverseWrappedDialer struct {
	device    adb.Dialer
	closersMu sync.Mutex
	closers   map[io.Closer]struct{}
}

// WrapReverseForwards wraps d (passing through [adb.Features]) to tunnel
// reverse forwards from a remote client for an [adbproxy.Server] on the same
// machine as the adb host server through a local unix socket.
func WrapReverseForwards(d adb.Dialer) (w adb.Dialer, close func() error) {
	t := &reverseWrappedDialer{
		device:  d,
		closers: make(map[io.Closer]struct{}),
	}
	return t, t.closeReverseProxies
}

// closeReverseProxies immediately closes all reverse proxies currently open. It
// does not remove the reverse forwards from the device, nor does it prevent
// more from being opened by future DialADB calls.
func (d *reverseWrappedDialer) closeReverseProxies() error {
	d.closersMu.Lock()
	defer d.closersMu.Unlock()
	var errs []error
	for c := range d.closers {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
		delete(d.closers, c)
	}
	return nil
}

// SupportsFeature calls SupportsFeature on the underlying [adb.Dialer] if it
// implements [adb.Features].
func (d *reverseWrappedDialer) SupportsFeature(f adbproto.Feature) bool {
	if d, ok := d.device.(adb.Features); ok {
		return d.SupportsFeature(f)
	}
	return false
}

// DialADB calls DialADB on the underlying [adb.Dialer], intercepting
// `reverse:forward:` and rewriting it to proxy through a local abstract socket.
func (d *reverseWrappedDialer) DialADB(ctx context.Context, svc string) (net.Conn, error) {
	// note: if a reverse-forwarded port is rebound or killed, we'll leak the
	// listener unix socket until the client which created it is kicked (or we
	// exit), but that's fine (we don't really have a way of detecting if
	// another thing removed our reverse forward, and it'll all get removed
	// eventually anyways) (we also don't know if the local device port was
	// rebound between foward and killforward, so we can't do it there either)

	// see:
	//	- transport.cpp atransport::UpdateReverseConfig
	//	- adb.cpp handle_forward_request

	if tmp, ok := strings.CutPrefix(svc, "reverse:forward:"); ok {
		tmp, _ := strings.CutPrefix(tmp, "norebind:")

		local, remote, _ := strings.Cut(tmp, ";")
		if local == "" || remote == "" || strings.Contains(remote, ";") {
			return nil, fmt.Errorf("bad forward: %s", tmp)
		}

		// note: no need to verify the remote since adb doesn't do that, and all
		// we do with it is proxy it back to the transport

		transport := adbproxy.ContextTransport(ctx)
		if transport == nil {
			return nil, fmt.Errorf("missing client transport for reverse forward")
		}

		// note: in a real server, you'd probably want to cache the sockets by
		// the transport and remote so you can reuse them if there's more than
		// one reverse forward to the same remote port

		sock := proxySocketName(transport, remote)

		listener, err := net.ListenUnix("unix", &net.UnixAddr{
			Name: sock,
			Net:  "unix",
		})
		if err != nil {
			return nil, fmt.Errorf("create reverse proxy listener: %w", err)
		}

		func() {
			d.closersMu.Lock()
			defer d.closersMu.Unlock()
			d.closers[listener] = struct{}{}
		}()

		go func() {
			// close the listener when we lose the transport or listener
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				select {
				case <-ctx.Done():
				case <-transport.Kicked():
					cancel()
				}
				listener.Close()

				slog.Info("stopped listener", "sock", sock)

				d.closersMu.Lock()
				defer d.closersMu.Unlock()
				delete(d.closers, listener)
			}()
			defer cancel()

			slog.Info("listening", "sock", sock)

			var delay time.Duration
			for {
				conn, err := listener.Accept()
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Temporary() {
						delay = min(1*time.Second, cmp.Or(delay*2, 5*time.Millisecond))
						time.Sleep(delay)
						continue
					}
					return
				}

				slog.Info("proxying connection", "sock", sock)

				func() {
					d.closersMu.Lock()
					defer d.closersMu.Unlock()
					d.closers[conn] = struct{}{}
				}()

				// note: adb doesn't provide a way to signal connection errors,
				// and the native implementation just closes on error or
				// connection failure

				// note: we must not ever block on Accept or we may hang the adb
				// host server due to b/418203510 (closing the listener entirely
				// is fine though)

				go func() {
					defer func() {
						conn.Close()
						slog.Info("closed proxied conection", "sock", sock)

						d.closersMu.Lock()
						defer d.closersMu.Unlock()
						delete(d.closers, listener)
					}()

					c1, err := transport.DialADB(ctx, remote)
					if err != nil {
						return
					}
					defer c1.Close()

					go func() {
						defer conn.(*net.UnixConn).CloseWrite()
						io.Copy(conn, c1)
					}()

					io.Copy(c1, conn)
				}()
			}
		}()

		// rewrite the forward request to use the abstract socket instead of the original remote
		svc = svc[:strings.LastIndex(svc, ";")] + ";localabstract:" + sock[1:]
	}

	return d.device.DialADB(ctx, svc) // pass-through
}

var reverseID atomic.Uint64

// proxySocketName returns a unique unix socket name for proxing the specified
// service through the specified adbproxy client.
func proxySocketName(transport *adbproxy.Transport, service string) string {
	var b strings.Builder
	b.WriteByte('@') // abstract namespace
	b.WriteString("adbproxy")
	b.WriteString(",pid=")
	b.WriteString(strconv.Itoa(syscall.Getpid()))
	b.WriteString(",id=") // to deduplicate (for edge cases, e.g., if transport doesn't have a unique remote addr for some reason)
	b.WriteString(strconv.FormatUint(reverseID.Add(1), 10))

	// informational
	if laddr := transport.LocalAddr(); laddr != nil {
		b.WriteString(",local=")
		b.WriteString(laddr.String())
	}
	if raddr := transport.RemoteAddr(); raddr != nil {
		b.WriteString(",remote=")
		b.WriteString(raddr.String())
	}
	b.WriteString(",service=")
	b.WriteString(service)

	return b.String()
}
