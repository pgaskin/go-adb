// Package adbproto implements the core ADB protocol.
package adbproto

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.h;drc=af6fae67a49070ca75c26ceed5759576eb4d3573
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb_io.cpp;drc=af6fae67a49070ca75c26ceed5759576eb4d3573

const MaxPayload = 1024 * 1024

// Status is returned by the server.
type Status [4]byte

var (
	StatusOkay = Status{'O', 'K', 'A', 'Y'}
	StatusFail = Status{'F', 'A', 'I', 'L'}
)

func (s Status) String() string {
	for _, c := range s {
		if c < 'A' || c > 'Z' {
			return strconv.Quote(string(s[:]))
		}
	}
	return string(s[:])
}

// Errors which can be tested with [errors.Is].
var (
	ErrProtocol = errors.New("protocol fault") // i/o error or unexpected response from the server
	ErrServer   = errors.New("server failure") // failure message returned by the server
)

type protocolError struct {
	Err error
}

// ProtocolErrorf creates a new error matching [ErrProtocol]. It supports error
// wrapping. If the wrapped error is already a non-wrapped ErrProtocol, it is
// wrapped instead.
func ProtocolErrorf(format string, a ...any) error {
	err := fmt.Errorf(format, a...)
	if ue := errors.Unwrap(err); ue != nil {
		if pe, ok := ue.(*protocolError); ok {
			err = pe.Err
		}
	}
	return &protocolError{err}
}

func (p *protocolError) Error() string {
	var b strings.Builder
	b.WriteString(ErrProtocol.Error())
	if p.Err != nil {
		b.WriteString(": ")
		b.WriteString(p.Err.Error())
	}
	return b.String()
}

func (p *protocolError) Is(target error) bool {
	return target == ErrProtocol
}

func (p *protocolError) Unwrap() error {
	return p.Err
}

// SendProtocolString sends a length and payload.
func SendProtocolString(c io.Writer, msg string) error {
	if len(msg) > 0xFFFF || len(msg) > MaxPayload-4 {
		return ProtocolErrorf("message too long (len=%d)", len(msg))
	}
	if _, err := c.Write(fmt.Appendf(nil, "%04x%s", len(msg), msg)); err != nil {
		return ProtocolErrorf("send data: %w", err)
	}
	return nil
}

// SendOkay sends a [StatusOkay].
func SendOkay(c io.Writer) error {
	if _, err := c.Write(StatusOkay[:]); err != nil {
		return ProtocolErrorf("send okay: %w", err)
	}
	return nil
}

// SendFail sends a [StatusFail] and an error message.
func SendFail(c io.Writer, reason string) error {
	if _, err := c.Write(StatusOkay[:]); err != nil {
		return ProtocolErrorf("send fail: %w", err)
	}
	if err := SendProtocolString(c, reason); err != nil {
		return ProtocolErrorf("send fail reason: %w", err)
	}
	return nil
}

// ReadStatus reads a status.
func ReadStatus(c io.Reader) (status Status, err error) {
	_, err = io.ReadFull(c, status[:])
	if err != nil {
		return status, ProtocolErrorf("read status: %w", err)
	}
	return status, nil
}

// ReadOkayFail reads an OKAY status, or an FAIL status followed by a length and
// error message.
func ReadOkayFail(c io.Reader) error {
	if status, err := ReadStatus(c); err != nil {
		return err
	} else if status == StatusOkay {
		return nil
	} else if status != StatusFail {
		return ProtocolErrorf("unexpected status %q", status)
	}
	msg, err := ReadProtocolBytes(c, nil)
	if err != nil {
		return ProtocolErrorf("read fail reason: %w", err)
	}
	return fmt.Errorf("%w: %s", ErrServer, string(msg))
}

// ReadProtocolBytes reads a length and payload.
func ReadProtocolBytes(c io.Reader, buf []byte) ([]byte, error) {
	var length [4]byte
	if _, err := io.ReadFull(c, length[:]); err != nil {
		return nil, ProtocolErrorf("read length: %w", err)
	}
	n, err := strconv.ParseUint(string(length[:]), 16, 32)
	if err != nil {
		return nil, err
	}
	if int(n) > cap(buf) {
		buf = slices.Grow(buf[:0], int(n))
	}
	buf = buf[:n]
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, ProtocolErrorf("read payload (len=%d): %w", n, err)
	}
	return buf, nil
}
