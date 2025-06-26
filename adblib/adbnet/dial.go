package adbnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/pgaskin/go-adb/adb"
)

// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/socket_spec_test.cpp;drc=3cbf75aad9bff42f4d46fa744cf2a3547a63a1cf
// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libcutils/socket_local_client_unix.cpp;l=45;drc=9c843a66d11d85e1f69e944f1b37314d3e47aab1
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/socket_spec.cpp;l=66-76;drc=d690167dc3a1f78d80f63c532dc7a8e2bb43461c

// Dialer is like [net.Dialer].
//
// It currently supports the networks "tcp" and "unix". It also supports "tcp4"
// and "tcp6", but not if a hostname is used.
//
// Note that adbd has a tendency to hang if a unix socket misbehaves, requiring
// a reboot, so I recommend against using them unless you must (it'd be better
// to start a process which proxies to it). See [b/418203510].
//
// [b/418203510]: https://issuetracker.google.com/issues/418203510#comment9
type Dialer struct {
	// Server is the device to connect through. It must not be nil.
	Server adb.Dialer
}

// Dial calls [Dialer.Dial].
func Dial(server adb.Dialer, network, address string) (net.Conn, error) {
	d := &Dialer{
		Server: server,
	}
	return d.Dial(network, address)
}

// Dial is like [net.Dialer.Dial].
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// Dial is like [net.Dialer.DialContext].
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		panic("nil context")
	}
	if d.Server == nil {
		return nil, fmt.Errorf("no adb server specified")
	}
	svc, err := Service(network, address)
	if err != nil {
		return nil, err
	}
	return d.Server.DialADB(ctx, svc)
}

// Service returns the ADB service to use for the specified network and address.
func Service(network, address string) (string, error) {
	var svc string
	switch network {
	case "tcp", "tcp4", "tcp6":
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return "", err
		}
		if network == "tcp4" || network == "tcp6" {
			addr, err := netip.ParseAddr(host)
			if err != nil {
				return "", fmt.Errorf("adb does not support limiting connections to ipv4/ipv6")
			}
			switch {
			case network == "tcp4" && addr.Is4():
				// ok
			case network == "tcp6" && addr.Is6():
				// ok
			default:
				return "", fmt.Errorf("wrong address type for network")
			}
		}
		portnum, err := net.LookupPort(network, port)
		if err != nil {
			return "", err
		}
		if host == "localhost" {
			svc = "tcp:" + strconv.Itoa(portnum)
		} else {
			svc = "tcp:" + strconv.Itoa(portnum) + ":" + host
		}
		return svc, nil
	case "unix":
		var abstract bool
		if len(address) != 0 && address[0] == '@' {
			// this matches the stdlib behaviour
			abstract = true
			address = address[1:]
		}
		if abstract {
			svc = "localabstract:" + address
		} else {
			svc = "localfilesystem:" + address
		}
		return svc, nil
	default:
		// TODO: vsock support
		return "", fmt.Errorf("%w: adb does not support this network type", net.UnknownNetworkError(network))
	}
}
