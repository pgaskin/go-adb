// Package adbusb authenticates with and connects to an ADB device over USB.
package adbusb

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pgaskin/go-adb/adb/adbproto/aproto"
	"github.com/pgaskin/go-adb/adb/adbproto/atransport"
)

// Device selects a USB device to connect to. It must match exactly one
// connected device, or connection will fail.
type Device interface {
	match(*DeviceInfo) bool
}

// Serial selects the USB device with the specified serial number.
type Serial string

func (s Serial) match(d *DeviceInfo) bool {
	return d.Serial == string(s)
}

func (s Serial) String() string {
	if s == "" {
		return ""
	}
	return "Serial(" + string(s) + ")"
}

// VendorProduct selects the device with the specifies VID and PID.
type VendorProduct struct {
	VID uint16
	PID uint16
}

func (v VendorProduct) match(d *DeviceInfo) bool {
	return d.VID == v.VID && d.PID == v.PID
}

func (v VendorProduct) String() string {
	if v == (VendorProduct{}) {
		return ""
	}
	return fmt.Sprintf("VendorProduct(%04x:%04x)", v.VID, v.PID)
}

// Path selects the USB device with the specified OS-defined absolute device
// node path (e.g., the usbfs node /dev/bus/usb/001/002 on Linux). It does not
// work with arbitrary paths, the device must be one of the enumerated ones.
type Path string

func (p Path) match(d *DeviceInfo) bool {
	return d.Path == string(p) || filepath.Clean(d.Path) == string(p)
}

func (p Path) String() string {
	if p == "" {
		return ""
	}
	return "Path(" + string(p) + ")"
}

// Any selects the single connected ADB device, or returns an error if there is
// not exactly one.
var Any Device = anyDevice{}

type anyDevice struct{}

func (anyDevice) match(*DeviceInfo) bool {
	return true
}

func (anyDevice) String() string {
	return "Any()"
}

// DeviceInfo describes a connected USB device with an ADB interface, as
// returned by [Devices]. It also satisfies [Device], selecting itself.
type DeviceInfo struct {
	// Name is the OS-specific device ID, if known (e.g., 3-4 on Linux).
	ID string

	// Path is the OS-defined device node path (e.g., the usbfs node
	// /dev/bus/usb/001/002 on Linux). Do not depend on multiple devices not
	// having the same path.
	Path string

	// Serial is the USB serial number of the device, if known. This is supposed
	// to be unique, but isn't always so.
	Serial string

	// VID is the USB vendor ID.
	VID uint16

	// PID is the USB product ID.
	PID uint16

	// no product/model like adb since we don't connect during enumeration

	sys any

	iface     uint8
	epIn      uint8
	epOut     uint8
	maxPacket int
	zeroMask  uint32
}

// Sys returns platform-dependent device info.
func (d DeviceInfo) Sys() any {
	return d.sys
}

func (d *DeviceInfo) match(o *DeviceInfo) bool {
	panic("unhandled") // special case
}

func (d *DeviceInfo) String() string {
	var b strings.Builder
	b.WriteString(d.Path)
	b.WriteByte(' ')
	b.WriteByte('(')
	b.WriteString(fmt.Sprintf("%04x:%04x", d.VID, d.PID))
	if d.Serial != "" {
		b.WriteByte(' ')
		b.WriteString(d.Serial)
	}
	b.WriteByte(')')
	return b.String()
}

// Writes should send one bulk transfer each (with a zero-length marker if
// needed). To match ADB, the header must be written as one Write, then the
// payload, split into multiple transfers if required (each with their own
// header). The conn must implement Close. This is implemented by [aproto.Conn].
//
// Since adb 4af6e4ff (2024-09-30), ADB doesn't care about the header/payload
// being submitted as individual bulk transfers and treats it as a stream
// instead. Unfortunately, while it makes it more resilient to buggy hardware or
// adb implementations, it means it can't recover itself if a write is
// interrupted (it'll think the next CNXN was part of the packet).
var (
	enumerate func() ([]*DeviceInfo, error)
	open      func(d *DeviceInfo) (*aproto.Conn, error)
	reset     func(d *DeviceInfo) error
)

// Supported returns true if the current platform supports at least [Devices]
// and [Open].
func Supported() bool {
	return enumerate != nil && open != nil
}

// Devices enumerates connected USB devices with an ADB interface. If not
// supported on the current platform, [errors.ErrUnsupported] is returned.
// Devices which cannot be read (e.g., due to permissions) are silently skipped,
// like ADB.
func Devices() ([]*DeviceInfo, error) {
	if enumerate == nil {
		return nil, errors.ErrUnsupported
	}
	return enumerate()
}

// Reset resets the USB endpoint of the selected device. If not supported on the
// current platform, [errors.ErrUnsupported] is returned. Pass a [*DeviceInfo]
// to open it directly without enumerating all devices again.
func Reset(d Device) error {
	if reset == nil {
		return errors.ErrUnsupported
	}
	device, err := resolve(d)
	if err != nil {
		return err
	}
	return reset(device)
}

// Open opens the ADB interface of the selected device. If not supported on the
// current platform, [errors.ErrUnsupported] is returned. Pass a [*DeviceInfo]
// to open it directly without enumerating all devices again. Note that a
// running ADB daemon with USB enabled will conflict.
func Open(d Device) (*aproto.Conn, error) {
	if open == nil {
		return nil, errors.ErrUnsupported
	}
	device, err := resolve(d)
	if err != nil {
		return nil, err
	}
	return open(device)
}

func resolve(d Device) (*DeviceInfo, error) {
	if d == nil {
		return nil, fmt.Errorf("invalid device")
	}
	if d, ok := d.(*DeviceInfo); ok {
		return d, nil // already enumerated
	}
	devices, err := Devices()
	if err != nil {
		return nil, err
	}
	var match *DeviceInfo
	for _, device := range devices {
		if d.match(device) {
			if match != nil {
				return nil, fmt.Errorf("multiple matches for device %s", d)
			}
			match = device
		}
	}
	if match == nil {
		return nil, fmt.Errorf("no match for device %s", d)
	}
	return match, nil
}

// Dialer connects to ADB devices over USB.
type Dialer struct {
	// Config is the transport configuration (keys, delayed acks, etc). It may
	// be nil.
	Config *atransport.Config
}

// Connect opens a USB connection to the specified device at addr, waiting for
// the connection to be ready (see [atransport.Transport.WaitConnected]).
//
// Note that if our key isn't authorized yet, this will block until the user
// accepts it or ctx is done. To avoid waiting, use [atransport.Connect]
// directly with a [Open].
func (dl *Dialer) Connect(ctx context.Context, d Device) (*atransport.Transport, error) {
	conn, err := Open(d)
	if err != nil {
		return nil, err
	}
	var config *atransport.Config
	if dl != nil {
		config = dl.Config
	}
	t, err := atransport.Connect(conn, config)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := t.WaitConnected(ctx); err != nil {
		t.Kick(err)
		return nil, err
	}
	return t, nil
}
