package adbproxy

import (
	"context"
	"crypto/tls"
	"reflect"

	"github.com/pgaskin/go-adb/adb/adbproto/aproto"
)

// ServerTrace is a set of hooks to run at various points in the lifecycle of a
// Server. Any particular hook may be nil. Functions may be called concurrently
// from different goroutines and at arbitrary times. They should avoid blocking
// for extended periods of time.
//
// For tracing authentication, wrap [Authenticator] directly.
//
// These hooks should not be used for important logic. They are intended for
// debugging and metrics.
type ServerTrace struct {
	// --- BaseContext

	// BannerGenerated is called after the initial connection banner is generated
	// for the server.
	BannerGenerated func(banner string)

	// CertificateGenerated is called after a TLS certificate is generated for
	// the server.
	CertificateGenerated func(cert *tls.Certificate)

	// --- BaseContext -> ConnContext

	// Accepted is called after a connection is accepted by the server.
	Accepted func()

	// Kicked is called after the connection is closed by the server or client.
	Kicked func(reason error)

	// Connected is called after the client sends the connection banner.
	Connected func(banner string, useTLS bool)

	// Authenticated is called after the client successfully authenticates.
	Authenticated func()

	// PacketSent is called when a packet is about to be sent (it won't have the
	// checksum, and may not be split yet)
	PacketSent func(cmd aproto.Command, arg0 uint32, arg1 uint32, data []byte)

	// PacketReceived is called when a packet is received.
	PacketReceived func(pkt aproto.Packet)

	// PacketUnknown is called when an unknown packet is ignored.
	PacketUnknown func(pkt aproto.Packet)

	// PacketIgnored is called when a packet is ignored.
	PacketIgnored func(pkt aproto.Packet)

	// PacketSocketUnknown is called when a packet references an unknown socket
	// and is ignored.
	PacketSocketUnknown func(pkt aproto.Packet)

	// --- BaseContext -> ConnContext -> OpenContext

	// LocalServiceDial is called when DialADB is called to open a service for
	// the client.
	LocalServiceDial func(local, remote uint32, svc string)

	// LocalServiceFail is called when the service cannot be opened.
	LocalServiceFail func(local, remote uint32, err error)

	// LocalServiceSuccess is called when the service is opened.
	LocalServiceSuccess func(local, remote uint32)

	// LocalServiceDelayedAck is called if and when delayed acks are configured
	// for a local service.
	LocalServiceDelayedAck func(local, remote, localDelayedAck, remoteDelayedAck uint32)

	// LocalServiceClose is called when the service is fully closed.
	LocalServiceClose func(local, remote uint32)
}

type serverTraceKey struct{}

func contextServerTrace(ctx context.Context) *ServerTrace {
	if t := ctx.Value(serverTraceKey{}); t != nil {
		return t.(*ServerTrace)
	}
	return nil
}

// WithServerTrace returns a new context based on the provided parent ctx. When
// the returned context is used with the Server, the provided trace hooks will
// be used, in addition to any previous hooks registered with ctx. Any hooks
// defined in the provided trace will be called first.
func WithServerTrace(ctx context.Context, trace *ServerTrace) context.Context {
	if trace == nil {
		panic("nil trace")
	}
	if old := ctx.Value(serverTraceKey{}); old != nil {
		composeHooks(trace, old.(*ServerTrace))
	}
	return context.WithValue(ctx, serverTraceKey{}, trace)
}

// composeHooks modifies func fields t to call the corresponding ones in next
// afterwards, if defined.
//
// inspired by net/http/httptrace
func composeHooks(t, next any) {
	tv := reflect.ValueOf(t).Elem()
	ov := reflect.ValueOf(next).Elem()
	structType := tv.Type()
	for i := 0; i < structType.NumField(); i++ {
		tf := tv.Field(i)
		hookType := tf.Type()
		if hookType.Kind() != reflect.Func {
			continue
		}
		of := ov.Field(i)
		if of.IsNil() {
			continue
		}
		if tf.IsNil() {
			tf.Set(of)
			continue
		}
		tfCopy := reflect.ValueOf(tf.Interface())
		newFunc := reflect.MakeFunc(hookType, func(args []reflect.Value) []reflect.Value {
			tfCopy.Call(args)
			return of.Call(args)
		})
		tv.Field(i).Set(newFunc)
	}
}
