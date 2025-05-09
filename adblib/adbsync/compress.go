package adbsync

import (
	"errors"
	"fmt"
	"io"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/pgaskin/go-adb/adb"
	"github.com/pgaskin/go-adb/adb/adbproto"
	"github.com/pgaskin/go-adb/adb/adbproto/syncproto"
	"github.com/pierrec/lz4/v4"
)

type CompressionMethod string

const (
	compressionMethodNone   CompressionMethod = "" // not exported intentionally
	CompressionMethodBrotli CompressionMethod = "brotli"
	CompressionMethodLZ4    CompressionMethod = "lz4"
	CompressionMethodZstd   CompressionMethod = "zstd"
)

func (m CompressionMethod) syncFlag() uint32 {
	switch m {
	case CompressionMethodBrotli:
		return syncproto.SyncFlag_Brotli
	case CompressionMethodLZ4:
		return syncproto.SyncFlag_LZ4
	case CompressionMethodZstd:
		return syncproto.SyncFlag_Zstd
	default:
		return 0
	}
}

func (m CompressionMethod) adbFeature() adbproto.Feature {
	switch m {
	case CompressionMethodBrotli:
		return syncproto.Feature_sendrecv_v2_brotli
	case CompressionMethodLZ4:
		return syncproto.Feature_sendrecv_v2_lz4
	case CompressionMethodZstd:
		return syncproto.Feature_sendrecv_v2_zstd
	default:
		return ""
	}
}

type CompressionConfig struct {
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

var DefaultCompressionConfig = &CompressionConfig{}

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

func (c *CompressionConfig) compressNegotiate(d adb.Dialer) CompressionMethod {
	if c == nil {
		c = DefaultCompressionConfig
	}
	m := c.CompressMethods
	if m == nil {
		m = defaultMethods
	}
	for _, m := range m {
		if m == compressionMethodNone || adb.SupportsFeature(d, m.adbFeature()) == nil {
			return m
		}
	}
	return compressionMethodNone
}

func (c *CompressionConfig) decompressNegotiate(d adb.Dialer) CompressionMethod {
	if c == nil {
		c = DefaultCompressionConfig
	}
	m := c.DecompressMethods
	if m == nil {
		m = defaultMethods
	}
	for _, m := range m {
		if m == compressionMethodNone || adb.SupportsFeature(d, m.adbFeature()) == nil {
			return m
		}
	}
	return compressionMethodNone
}

func (c *CompressionConfig) compress(method CompressionMethod, w io.Writer) (io.WriteCloser, error) {
	if method == compressionMethodNone {
		panic("compress called with method none")
	}
	if c == nil {
		c = DefaultCompressionConfig
	}
	fn := c.CompressFunc
	if fn == nil {
		fn = defaultCompress
	}
	return fn(method, w)
}

func (c *CompressionConfig) decompress(method CompressionMethod, r io.Reader) (io.ReadCloser, error) {
	if method == compressionMethodNone {
		panic("decompress called with method none")
	}
	if c == nil {
		c = DefaultCompressionConfig
	}
	fn := c.DecompressFunc
	if fn == nil {
		fn = defaultDecompress
	}
	return fn(method, r)
}
