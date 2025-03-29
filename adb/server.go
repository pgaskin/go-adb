// Package adb interacts with ADB servers.
package adb

import (
	"context"
	"errors"
	"fmt"
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

// ErrFeatureNotSupported is returned by [SupportsFeature].
var ErrFeatureNotSupported = errors.New("feature not supported")

// SupportsFeature returns nil if the dialer implements [Features] and supports
// the specified feature, or returns an error matching [ErrFeatureNotSupported].
func SupportsFeature(d Dialer, f adbproto.Feature) error {
	if df, ok := d.(Features); ok && df != nil {
		if df.SupportsFeature(f) {
			return nil
		}
	}
	return &featureNotSupportedError{f}
}

type featureNotSupportedError struct {
	Feature adbproto.Feature
}

func (e *featureNotSupportedError) Error() string {
	return fmt.Sprintf("feature %q not supported", e.Feature)
}

func (e *featureNotSupportedError) Is(target error) bool {
	return target == ErrFeatureNotSupported || target == errors.ErrUnsupported
}

type modifyFeatureDialer struct {
	d Dialer
	f adbproto.Feature
	p bool
}

func (m modifyFeatureDialer) DialADB(ctx context.Context, svc string) (net.Conn, error) {
	return m.d.DialADB(ctx, svc)
}

func (m modifyFeatureDialer) SupportsFeature(f adbproto.Feature) bool {
	if m.f == f {
		return m.p
	}
	if df, ok := m.d.(Features); ok && df != nil {
		return df.SupportsFeature(f)
	}
	return false
}

// WithFeature wraps d, causing [SupportsFeature] to return true for the
// specified feature. This is intended for testing.
func WithFeature(d Dialer, f adbproto.Feature) Dialer {
	return modifyFeatureDialer{d, f, true}
}

// WithoutFeature wraps d, causing [SupportsFeature] to return false for the
// specified feature. This is intended for testing or overriding the behaviour
// of high-level wrappers.
func WithoutFeature(d Dialer, f adbproto.Feature) Dialer {
	return modifyFeatureDialer{d, f, false}
}
