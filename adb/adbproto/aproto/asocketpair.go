package aproto

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// SocketPair combines a LS and a RS into a [net.Conn]. It behaves similarly to
// a [net.TCPConn].
type SocketPair struct {
	LS *LocalSocket
	RS *RemoteSocket

	// OnClose, if non-nil, is called before Close returns.
	OnClose func()
}

var (
	_ net.Conn = (*SocketPair)(nil)
	_ interface {
		CloseRead() error
		CloseWrite() error
	} = (*SocketPair)(nil) // like (*net.TCPConn)
)

type socketAddr uint32

func (a socketAddr) Network() string {
	return "adb"
}

func (a socketAddr) String() string {
	return strconv.FormatUint(uint64(a), 10)
}

func (d *SocketPair) Read(b []byte) (n int, err error) {
	if d.LS == nil || d.RS == nil || d.LS.Local != d.RS.Local || d.LS.Remote != d.RS.Remote {
		panic("not a socket pair")
	}
	return d.LS.Read(b)
}

func (d *SocketPair) Write(b []byte) (n int, err error) {
	if d.LS == nil || d.RS == nil || d.LS.Local != d.RS.Local || d.LS.Remote != d.RS.Remote {
		panic("not a socket pair")
	}
	return d.RS.Write(b)
}

func (d *SocketPair) CloseRead() error {
	if err := d.LS.Close(); err != nil {
		return fmt.Errorf("local: %w", err)
	}
	return nil
}

func (d *SocketPair) CloseWrite() error {
	if err := d.RS.Close(); err != nil {
		return fmt.Errorf("remote: %w", err)
	}
	return nil
}

func (d *SocketPair) Close() error {
	if d.OnClose != nil {
		defer d.OnClose()
	}
	return errors.Join(
		d.CloseRead(),
		d.CloseWrite(),
	)
}

func (d *SocketPair) LocalAddr() net.Addr {
	return socketAddr(d.LS.Local)
}

func (d *SocketPair) RemoteAddr() net.Addr {
	return socketAddr(d.RS.Remote)
}

func (d *SocketPair) SetDeadline(t time.Time) error {
	d.LS.SetDeadline(t)
	d.RS.SetDeadline(t)
	return nil
}

func (d *SocketPair) SetReadDeadline(t time.Time) error {
	d.LS.SetDeadline(t)
	return nil
}

func (d *SocketPair) SetWriteDeadline(t time.Time) error {
	d.RS.SetDeadline(t)
	return nil
}
