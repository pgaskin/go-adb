// Package adbsync wraps the sync protocol.
package adbsync

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/pgaskin/go-adb/adb"
	"github.com/pierrec/lz4/v4"
)

type CompressionMethod string

const (
	CompressionMethodBrotli CompressionMethod = "brotli"
	CompressionMethodLZ4    CompressionMethod = "lz4"
	CompressionMethodZstd   CompressionMethod = "zstd"
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

	// CompressMethods, if not nil, sets the allowed compression methods in the
	// preferred order. An empty slice disables compression. A nil slice uses
	// the default value. The values will be limited to ones supported by the
	// server.
	CompressMethods []CompressionMethod

	// DecompressMethods, if not nil, sets the allowed decompression methods.
	// The device will choose which one to use. An empty slice disables
	// compression. A nil slice uses the default value. The values will be
	// limited to ones supported by the server.
	DecompressMethods []CompressionMethod

	// CompressFunc allows the compression parameters to be customized.
	CompressFunc func(method CompressionMethod, w io.Writer) (io.WriteCloser, error)

	// DecompressFunc allows the decompression parameters to be customized.
	DecompressFunc func(method CompressionMethod, r io.Reader) (io.ReadCloser, error)
}

func (c *Conn) CloseIdleConnections() {
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

var defaultMethods = []CompressionMethod{
	CompressionMethodZstd,
	CompressionMethodLZ4,
	CompressionMethodBrotli,
}

func defaultCompress(method CompressionMethod, w io.Writer) (io.WriteCloser, error) {
	switch method {
	case CompressionMethodBrotli:
		return brotli.NewWriter(w), nil
	case CompressionMethodLZ4:
		return lz4.NewWriter(w), nil
	case CompressionMethodZstd:
		return zstd.NewWriter(w)
	default:
		return nil, fmt.Errorf("%w: unsupported compression method %q", errors.ErrUnsupported, method)
	}
}

func defaultDecompress(method CompressionMethod, r io.Reader) (io.ReadCloser, error) {
	switch method {
	case CompressionMethodBrotli:
		return io.NopCloser(brotli.NewReader(r)), nil
	case CompressionMethodLZ4:
		return io.NopCloser(lz4.NewReader(r)), nil
	case CompressionMethodZstd:
		d, err := zstd.NewReader(r)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(d), nil
	default:
		return nil, fmt.Errorf("%w: unsupported decompression method %q", errors.ErrUnsupported, method)
	}
}
