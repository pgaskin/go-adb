// Package adbexec implements a high-level interface around the shell v2
// protocol.
package adbexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/pgaskin/go-adb/adb"
	"github.com/pgaskin/go-adb/adb/adbproto/shellproto2"
)

// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/daemon/shell_service.cpp;drc=9c843a66d11d85e1f69e944f1b37314d3e47aab1;l=158

// Cmd represents a pending command.
//
// It is designed to be similar to [os/exec.Cmd].
type Cmd struct {
	// Server is the ADB server to run commands on.
	Server adb.Dialer

	// Command is the command to execute with `/system/bin/sh -c`. If empty, an
	// interactive shell is started (but note that this isn't usable without a
	// PTY).
	Command string

	// PTY causes a TTY to be allocated for the process. Note that this will
	// mean that stdin can't be closed, and stderr will be merged into stdout.
	PTY bool

	// Term sets the TERM environment variable. This defaults to "dumb" if not specified.
	Term string

	// Stdin is sent to the running command. When it returns [io.EOF] or any
	// other error, the stdin pipe on the device is closed. If nil, stdin is
	// closed from the beginning.
	Stdin io.Reader

	// Stdout, if not nil, receives the output of the running command. Errors
	// while writing to it are ignored.
	//
	// Note that if writes to it block, it also blocks receiving any other
	// packets including stderr and the exit status from the command.
	Stdout io.Writer

	// Stderr, if not nil, receives the output of the running command. Errors
	// while writing to it are ignored.
	//
	// If PTY is true, this is ignored and stderr is merged with stdout instead.
	//
	// Note that if writes to it block, it also blocks receiving any other
	// packets including stdout and the exit status from the command.
	Stderr io.Writer

	// Process contains the process, once started.
	Process *Process

	// ProcessState contains information about an exited process.
	// If the process was started successfully, Wait or Run will
	// populate its ProcessState when the command completes.
	ProcessState *ProcessState

	// TODO: WaitDelay and Cancel like os/exec.Cmd?

	// ctx is the context passed to CommandContext, if any.
	ctx         context.Context
	parentPipes []io.Closer
	childPipes  []io.Closer
	setupTTY    func() error // [Cmd.HostTTY]
	startTTY    func()       // [Cmd.HostTTY]
	cleanupTTY  func()       // [Cmd.HostTTY]
}

// Shell returns a [Cmd] to execute command on server using the default shell.
func Shell(server adb.Dialer, command string) *Cmd {
	return &Cmd{
		Server:  server,
		Command: command,
	}
}

// ShellContext is like [Shell] but includes a context.
//
// The provided context will call [Process.Disconnect] on the process if it is
// done before the command finishes normally.
func ShellContext(ctx context.Context, server adb.Dialer, command string) *Cmd {
	if ctx == nil {
		panic("nil context")
	}
	cmd := Shell(server, command)
	cmd.ctx = ctx
	return cmd
}

// Command is like [Shell], but automatically quotes arguments so it can be used
// like [os/exec.Command].
func Command(server adb.Dialer, name string, arg ...string) *Cmd {
	return Shell(server, Quote(append([]string{name}, arg...)...))
}

// CommandContext is like [Command] but includes a context like [ShellContext].
func CommandContext(ctx context.Context, server adb.Dialer, name string, arg ...string) *Cmd {
	return ShellContext(ctx, server, Quote(append([]string{name}, arg...)...))
}

// Run runs the command and waits for it to finish.
//
// Upon returning, cmd.Process and cmd.ProcessState will be set.
func (c *Cmd) Run() error {
	if err := c.Start(); err != nil {
		return err
	}
	return c.Wait()
}

// Start starts the command and returns once the connection has been
// established.
//
// Note that unlike [os/exec], this cannot check whether the command exists, as
// it is always executed in a shell. If the command does not exist, it will
// result in a non-zero exit code.
//
// Upon returning, cmd.Process will be set.
func (c *Cmd) Start() error {
	if c.Process != nil {
		return errors.New("adbexec: already started")
	}
	if c.Server == nil {
		return fmt.Errorf("adbexec: no adb server provided")
	}

	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	svc, err := c.Service()
	if err != nil {
		return err
	}
	if c.setupTTY != nil {
		if err := c.setupTTY(); err != nil {
			return fmt.Errorf("setup host tty: %w", err)
		}
	}
	conn, err := c.Server.DialADB(ctx, svc)
	if err != nil {
		return err
	}
	c.Process = NewProcess(conn, c.Stdin, c.Stdout, c.Stderr)
	go func() {
		c.Process.Wait()
		for _, p := range c.childPipes {
			p.Close()
		}
	}()
	if c.startTTY != nil {
		c.startTTY()
	}
	context.AfterFunc(ctx, func() {
		c.Process.Disconnect()
	})
	return nil
}

// Service returns the ADB service which will be run when c is started.
func (c *Cmd) Service() (string, error) {
	var b shellproto2.ServiceBuilder
	if c.Term != "" {
		if !b.Term(c.Term) {
			return "", fmt.Errorf("term contains illegal character")
		}
	}
	if c.PTY {
		b.PTY()
	} else {
		b.Raw()
	}
	if c.Command != "" {
		b.Command(c.Command)
	}
	return b.String(), nil
}

// Wait waits for the command to complete, returning an error if the command was
// not successful.
//
// Upon returning, cmd.ProcessState will be set.
func (c *Cmd) Wait() error {
	if c.Process == nil {
		return errors.New("adbexec: not started")
	}
	if c.ProcessState != nil {
		return errors.New("adbexec: Wait already called")
	}
	c.ProcessState = c.Process.Wait()
	for _, p := range c.parentPipes {
		p.Close()
	}
	if c.cleanupTTY != nil {
		c.cleanupTTY()
	}
	if !c.ProcessState.Success() {
		return &ExitError{ProcessState: c.ProcessState}
	}
	return nil
}

// StdinPipe returns a pipe that will be connected to the command's standard
// input when the command starts.
//
// [Cmd.Wait] will close the pipe after seeing the command exit, so most callers
// need not close the pipe themselves. A caller need only call Close to force
// the pipe to close sooner. For example, if the command being run will not exit
// until standard input is closed, the caller must close the pipe.
func (c *Cmd) StdinPipe() (io.WriteCloser, error) {
	if c.Stdin != nil {
		return nil, errors.New("adbexec: Stdin already set")
	}
	if c.Process != nil {
		return nil, errors.New("adbexec: StdinPipe after process started")
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	c.Stdin = pr
	c.childPipes = append(c.childPipes, pr)
	c.parentPipes = append(c.parentPipes, pw)
	return pw, nil
}

// StdoutPipe returns a pipe that will be connected to the command's standard
// output when the command starts.
//
// [Cmd.Wait] will close the pipe after seeing the command exit, so most callers
// need not close the pipe themselves. It is thus incorrect to call Wait before
// all reads from the pipe have completed. For the same reason, it is incorrect
// to call [Cmd.Run] when using StdoutPipe.
//
// See the StdoutPipe example in [os/exec].
func (c *Cmd) StdoutPipe() (io.ReadCloser, error) {
	if c.Stdout != nil {
		return nil, errors.New("adbexec: Stdout already set")
	}
	if c.Process != nil {
		return nil, errors.New("adbexec: StdoutPipe after process started")
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	c.Stdout = pw
	c.childPipes = append(c.childPipes, pw)
	c.parentPipes = append(c.parentPipes, pr)
	return pr, nil
}

// StderrPipe returns a pipe that will be connected to the command's standard
// error when the command starts.
//
// [Cmd.Wait] will close the pipe after seeing the command exit, so most callers
// need not close the pipe themselves. It is thus incorrect to call Wait before
// all reads from the pipe have completed. For the same reason, it is incorrect
// to use [Cmd.Run] when using StderrPipe.
//
// See the StderrPipe example in [os/exec].
func (c *Cmd) StderrPipe() (io.ReadCloser, error) {
	if c.Stderr != nil {
		return nil, errors.New("adbexec: Stderr already set")
	}
	if c.Process != nil {
		return nil, errors.New("adbexec: StderrPipe after process started")
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	c.Stderr = pw
	c.childPipes = append(c.childPipes, pw)
	c.parentPipes = append(c.parentPipes, pr)
	return pr, nil
}

// Output runs the command and returns its standard output.
// Any returned error will usually be of type [*ExitError].
// If c.Stderr was nil and the returned error is of type
// [*ExitError], Output populates the Stderr field of the
// returned error.
func (c *Cmd) Output() ([]byte, error) {
	if c.Stdout != nil {
		return nil, errors.New("adbexec: Stdout already set")
	}
	var stdout bytes.Buffer
	c.Stdout = &stdout

	captureErr := c.Stderr == nil
	if captureErr {
		c.Stderr = &prefixSuffixSaver{N: 32 << 10}
	}

	err := c.Run()
	if err != nil && captureErr {
		if ee, ok := err.(*ExitError); ok {
			ee.Stderr = c.Stderr.(*prefixSuffixSaver).Bytes()
		}
	}
	return stdout.Bytes(), err
}

// CombinedOutput runs the command and returns its combined standard output and
// standard error. Note that due to the way ADB buffers output, unless PTY is
// true, they may not be interleaved in the exact same way the process wrote
// them.
func (c *Cmd) CombinedOutput() ([]byte, error) {
	if c.Stdout != nil {
		return nil, errors.New("adbexec: Stdout already set")
	}
	if c.Stderr != nil {
		return nil, errors.New("adbexec: Stderr already set")
	}
	var b bytes.Buffer
	c.Stdout = &b
	c.Stderr = &b
	err := c.Run()
	return b.Bytes(), err
}

// An ExitError reports an unsuccessful exit by a command started by [Cmd].
type ExitError struct {
	*ProcessState

	// Stderr holds a subset of the standard error output from the
	// [Cmd.Output] method if standard error was not otherwise being
	// collected.
	//
	// If the error output is long, Stderr may contain only a prefix
	// and suffix of the output, with the middle replaced with
	// text about the number of omitted bytes.
	//
	// Stderr is provided for debugging, for inclusion in error messages.
	// Users with other needs should redirect Cmd.Stderr as needed.
	Stderr []byte
}

func (e *ExitError) Error() string {
	return e.ProcessState.String()
}

// prefixSuffixSaver is an io.Writer which retains the first N bytes
// and the last N bytes written to it. The Bytes() methods reconstructs
// it with a pretty error message.
//
// copied from os/exec.prefixSuffixSaver
//
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
type prefixSuffixSaver struct {
	N         int // max size of prefix or suffix
	prefix    []byte
	suffix    []byte // ring buffer once len(suffix) == N
	suffixOff int    // offset to write into suffix
	skipped   int64
}

func (w *prefixSuffixSaver) Write(p []byte) (n int, err error) {
	lenp := len(p)
	p = w.fill(&w.prefix, p)

	// Only keep the last w.N bytes of suffix data.
	if overage := len(p) - w.N; overage > 0 {
		p = p[overage:]
		w.skipped += int64(overage)
	}
	p = w.fill(&w.suffix, p)

	// w.suffix is full now if p is non-empty. Overwrite it in a circle.
	for len(p) > 0 { // 0, 1, or 2 iterations.
		n := copy(w.suffix[w.suffixOff:], p)
		p = p[n:]
		w.skipped += int64(n)
		w.suffixOff += n
		if w.suffixOff == w.N {
			w.suffixOff = 0
		}
	}
	return lenp, nil
}

// fill appends up to len(p) bytes of p to *dst, such that *dst does not
// grow larger than w.N. It returns the un-appended suffix of p.
func (w *prefixSuffixSaver) fill(dst *[]byte, p []byte) (pRemain []byte) {
	if remain := w.N - len(*dst); remain > 0 {
		add := min(len(p), remain)
		*dst = append(*dst, p[:add]...)
		p = p[add:]
	}
	return p
}

func (w *prefixSuffixSaver) Bytes() []byte {
	if w.suffix == nil {
		return w.prefix
	}
	if w.skipped == 0 {
		return append(w.prefix, w.suffix...)
	}
	var buf bytes.Buffer
	buf.Grow(len(w.prefix) + len(w.suffix) + 50)
	buf.Write(w.prefix)
	buf.WriteString("\n... omitting ")
	buf.WriteString(strconv.FormatInt(w.skipped, 10))
	buf.WriteString(" bytes ...\n")
	buf.Write(w.suffix[w.suffixOff:])
	buf.Write(w.suffix[:w.suffixOff])
	return buf.Bytes()
}
