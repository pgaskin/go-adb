// Package adbserver interacts with an ADB server on a device.
package adbserver

import (
	"context"
	"net"
)

// Dialer connects to a service on an ADB server (i.e., device).
//
// The provided context controls the deadline and cancellation during connection
// establishment. Once the conn is returned, the context no longer affects it.
type Dialer interface {
	DialADB(ctx context.Context, svc string) (net.Conn, error)
}
