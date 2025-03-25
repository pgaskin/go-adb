package adbhost

import (
	"context"
	"iter"

	"github.com/pgaskin/go-adb/adb/adbproto"
)

// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/services.cpp;drc=01cbbf505e3348a70cd846b26fae603bdf44b3c5
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=1275-1616;drc=9f298fb1f3317371b49439efb20a598b3a881bf3
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=1133-1242;drc=9c843a66d11d85e1f69e944f1b37314d3e47aab1

// Kill kills the ADB server. This may fail if ADB_REJECT_KILL_SERVER=1 is set
// on the server.
func Kill(ctx context.Context, srv *Dialer) error {
	conn, err := srv.DialADBHost(ctx, "host:kill")
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// Devices gets the list of devices using "host:devices" or "host:devices-l".
// Note that this uses the text format internally, which means that not all
// fields will be set and attributes will be sanitized.
func Devices(ctx context.Context, srv *Dialer, long bool) ([]*TransportInfo, error) {
	var svc string
	if long {
		svc = "host:devices-l"
	} else {
		svc = "host:devices"
	}
	conn, err := srv.DialADBHost(ctx, svc)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	buf, err := adbproto.ReadProtocolBytes(conn, nil)
	if err != nil {
		return nil, adbproto.ProtocolErrorf("read device list: %w", err)
	}
	return ParseDevices(buf)
}

// TrackDevices tracks the devices connected to the server in real-time. If long
// is false or the server does not support
// [adbproto.FeatureDeviceTrackerProtoFormat], this will use the text format
// internally, which means that not all fields will be set and attributes will
// be sanitized.
//
//	var err error
//	for info := range adbhost.TrackDevices(ctx, srv, true)(&err) {
//	    if stop {
//	        break
//	    }
//	    fmt.Println(info)
//	}
//	if err != nil {
//	    panic(err)
//	}
func TrackDevices(ctx context.Context, srv *Dialer, long bool) func(*error) iter.Seq[[]*TransportInfo] {
	return newErrIter(func(yield func([]*TransportInfo) bool) error {
		svc, parse := "", ParseDevices
		if long {
			svc = "host:track-devices-l"
		} else {
			svc = "host:track-devices"
		}
		if long && srv.SupportsFeature(adbproto.FeatureDeviceTrackerProtoFormat) {
			svc = "host:track-devices-proto-binary" // note: host:track-device-proto-text is another option
			parse = ParseDevicesProto
		}

		conn, err := srv.DialADBHost(ctx, svc)
		if err != nil {
			return err
		}
		defer conn.Close()

		var buf []byte
		for {
			buf, err = adbproto.ReadProtocolBytes(conn, buf[:0])
			if err != nil {
				return adbproto.ProtocolErrorf("read next device tracker item: %w", err)
			}
			devs, err := parse(buf)
			if err != nil {
				return adbproto.ProtocolErrorf("parse device tracker item: %w", err)
			}
			if !yield(devs) {
				return nil
			}
		}
	})
}

// host request
// TODO: server-status
// TODO: reconnect-offline
// TODO: disconnect
// TODO: version
// TODO: emulator

// host socket
// TODO: connect
// TODO: pair

// host transport
// TODO: disconnect
// TODO: get-serialno
// TODO: get-devpath
// TODO: get-state
// TODO: reconnect
// TODO: attach
// TODO: detach
// TODO: list-forward
// TODO: forward
// TODO: killforward
// TODO: mdns:check
// TODO: mdns:services

// note: reverse works by updating a whitelist on the host, and the device opens tcp:... services in reverse

func newErrIter[T any](seq func(yield func(T) bool) error) func(*error) iter.Seq[T] {
	return func(err *error) iter.Seq[T] {
		return func(yield func(T) bool) {
			*err = seq(func(v T) bool {
				return yield(v)
			})
		}
	}
}
