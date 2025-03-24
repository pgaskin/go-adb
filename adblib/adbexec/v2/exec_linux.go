//go:build linux

package adbexec

import (
	"errors"
	"fmt"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

// HostTTY connects the command to [os.Stdin], which is expected to be a PTY.
// When Start or Run is called, the TTY will be put into raw mode, and when the
// command ends, it will be restored to the previous state. A signal handler
// will be added for SIGWINCH, and removed when the command ends. The TERM
// variable will be copied from the host environment.
func (c *Cmd) HostTTY() error {
	if c.setupTTY != nil || c.startTTY != nil || c.cleanupTTY != nil {
		return errors.New("adbexec: tty already set")
	}
	if c.Stdin != nil {
		return errors.New("adbexec: Stdin already set")
	}
	if c.Stdout != nil {
		return errors.New("adbexec: Stdout already set")
	}
	if c.Stderr != nil {
		return errors.New("adbexec: Stderr already set")
	}

	pty := os.Stdin
	if _, err := unix.IoctlGetTermios(int(pty.Fd()), unix.TCGETS); err != nil {
		return fmt.Errorf("not a tty: %w", err)
	}

	c.PTY = true
	c.Stdin = pty
	c.Stdout = pty
	c.Stderr = pty // not used, but we want StderrPipe to fail
	c.Term = os.Getenv("TERM")

	var (
		restore *unix.Termios
		sigs    = make(chan os.Signal, 2)
	)
	c.setupTTY = func() error {
		termios, err := unix.IoctlGetTermios(int(pty.Fd()), unix.TCGETS)
		if err != nil {
			return fmt.Errorf("get termios: %w", err)
		}
		oldTermios := *termios

		// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/client/commandline.cpp;l=277-290;drc=08a96199bf8ce0581c366fc9c725351ee127fd21
		makeRaw(termios)

		if err := unix.IoctlSetTermios(int(pty.Fd()), unix.TCSETS, termios); err != nil {
			return fmt.Errorf("set termios: %w", err)
		}
		restore = &oldTermios

		return nil
	}
	c.startTTY = func() {
		signal.Notify(sigs, unix.SIGWINCH, unix.SIGTTIN)
		go func() {
			for {
				winsize, err := unix.IoctlGetWinsize(int(pty.Fd()), unix.TIOCGWINSZ)
				if err != nil {
					continue
				}
				if err := c.Process.Resize(int(winsize.Row), int(winsize.Col), int(winsize.Xpixel), int(winsize.Ypixel)); err != nil {
					continue
				}
				for sig := range sigs {
					if sig == unix.SIGWINCH {
						break
					}
				}
			}
		}()
	}
	c.cleanupTTY = func() {
		if err := unix.IoctlSetTermios(int(pty.Fd()), unix.TCSETS, restore); err != nil {
			// ignore
		}
		signal.Stop(sigs)
		close(sigs)
	}
	return nil
}

func makeRaw(t *unix.Termios) {
	t.Iflag &^= (unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON)
	t.Oflag &^= unix.OPOST
	t.Lflag &^= (unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN)
	t.Cflag &^= (unix.CSIZE | unix.PARENB)
	t.Cflag |= unix.CS8
	t.Cc[unix.VMIN] = 1
	t.Cc[unix.VTIME] = 0
}
