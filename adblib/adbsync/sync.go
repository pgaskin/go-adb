// Package adbsync wraps the sync protocol.
package adbsync

import (
	"net"
	"net/http"
	"time"

	"github.com/pgaskin/go-adb/adb"
)

type Client struct {
	Server adb.Dialer

	// ConnectTimeout, if non-zero, is the maximum amount of time to wait for a
	// new sync connection to be opened before returning an error.
	ConnectTimeout time.Duration

	// IdleConnTimeout, if non-zero, is the maximum amount of time an idle
	// connection will remain idle before closing itself.
	IdleConnTimeout time.Duration

	// MaxIdleConns, if non-zero, limits the maximum number of idle connections.
	// Connections exceeding the limit wil be closed instead of being kept for
	// later reuse.
	MaxIdleConns int

	// MaxConns, if non-zero, limits the maximum number of concurrent
	// connections in all states. Connections exceeding the limit will block.
	MaxConns int

	// CompressionConfig contains options for compression and decompression.
	CompressionConfig *CompressionConfig
}

// CloseIdleConnections closes any connections which were previously connected
// from previous requests but are now idle. It does not interrupt any
// connections currently in use.
func (c *Conn) CloseIdleConnections() {
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	// TODO
}

// TODO

type Conn struct {
	conn net.Conn
}

// TODO

func (c *Conn) Close() error {
	return nil
}
