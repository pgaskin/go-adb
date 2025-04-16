// Package adbexec implements a high-level interface around the legacy shell and
// exec protocols.
package adbexec

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/pgaskin/go-adb/adb"
	"github.com/pgaskin/go-adb/internal/android"
)

// Quote quotes arguments for the shell.
func Quote(args ...string) string {
	return android.QuoteShell(args...)
}

// Output returns the output of [adb.Exec] for the specified command. The
// command will be interpreted by /system/bin/sh -c, and stdout/stderr will be
// merged. Use [Quote] to escape arguments. If input is not nil, it is written
// to the command's standard input. On error, any output received so far is
// returned.
func Output(ctx context.Context, srv adb.Dialer, command string, input io.Reader) ([]byte, error) {
	conn, err := adb.Exec(ctx, srv, command)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	context.AfterFunc(ctx, func() {
		conn.Close() // this will interrupt the input/output copy
	})

	inputErrCh := make(chan error, 1)
	go func() {
		defer close(inputErrCh)
		var err error
		if input != nil {
			_, err = io.Copy(conn, input)
		}
		inputErrCh <- err
	}()

	var buf bytes.Buffer
	_, outputErr := io.Copy(&buf, conn)

	inputErr := <-inputErrCh // wait for the input copying to finish
	if err := ctx.Err(); err != nil {
		return buf.Bytes(), err // if the context was cancelled, that error takes precedence
	}
	if err := inputErr; err != nil {
		return buf.Bytes(), fmt.Errorf("write stdin: %w", err) // stdin errors first since they could be caused by the input reader failing
	}
	if err := outputErr; err != nil {
		return buf.Bytes(), fmt.Errorf("read stdout: %w", err) // output errors would only be caused by a connection close or by a network error, so check for it last
	}
	return buf.Bytes(), nil
}

// TODO: wrapper for shell v1
// TODO: streaming version of Output
