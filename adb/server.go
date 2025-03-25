// Package adb interacts with ADB servers.
package adb

import (
	"context"
	"net"

	"github.com/pgaskin/go-adb/adb/adbproto"
)

// Dialer connects to a service on an ADB server (i.e., device).
//
// The provided context controls the deadline and cancellation during connection
// establishment. Once the conn is returned, the context no longer affects it.
type Dialer interface {
	DialADB(ctx context.Context, svc string) (net.Conn, error)
}

// Features is an optional interface which can be implemented by a [Dialer].
type Features interface {
	SupportsFeature(f adbproto.Feature) bool
}

// SupportsFeature returns true if the dialer implements [Features] and supports
// the specified feature.
func SupportsFeature(d Dialer, f adbproto.Feature) bool {
	if df, ok := d.(Features); ok && df != nil {
		return df.SupportsFeature(f)
	}
	return false
}
