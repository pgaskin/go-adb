//go:build linux

package adbusb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/pgaskin/go-adb/adb/adbproto/aproto"
	"golang.org/x/sys/unix"
)

// UsbfsPath is the path to /dev/bus/usb.
var UsbfsPath = "/dev/bus/usb"

// SysfsPath is the path to /sys. It is currently used to resolve the device
// name and read the properties (e.g., serial number) of a usbfs device node.
var SysfsPath = "/sys"

func init() {
	enumerate = func() ([]*DeviceInfo, error) {
		return usbfsEnumerate(UsbfsPath)
	}
	open = func(d *DeviceInfo) (*aproto.Conn, error) {
		c, err := usbfsOpen(d)
		if err != nil {
			return nil, err
		}
		var _ io.Closer = c // just to be sure
		conn := aproto.New(c)
		conn.Resync() // non-standard behaviour
		return conn, nil
	}
	reset = func(d *DeviceInfo) error {
		c, err := usbfsOpen(d)
		if err != nil {
			return err
		}
		defer c.Close()
		return c.reset()
	}
}

// this is heavily based on adb's usbfs implementation
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/client/usb_linux.cpp;drc=7799b4ba22bd05e1ded1c375fcadcbea2c7ee58c
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.h;l=190-200;drc=af6fae67a49070ca75c26ceed5759576eb4d3573

// linux/usbdevice_fs.h
const usbdevfsURBTypeBulk = 3

// linux/usbdevice_fs.h
type usbdevfsURB struct {
	Type         uint8
	Endpoint     uint8
	_            [2]byte
	Status       int32
	Flags        uint32
	Buffer       unsafe.Pointer
	BufferLength int32
	ActualLength int32
	StartFrame   int32
	StreamID     uint32 // union { NumberOfPackets; StreamID }
	ErrorCount   int32
	Signr        uint32
	Usercontext  unsafe.Pointer
}

// linux/usbdevice_fs.h
var (
	usbdevfsSubmitURB      = ioc(2, 'U', 10, unsafe.Sizeof(usbdevfsURB{})) // _IOR('U', 10, struct usbdevfs_urb)
	usbdevfsDiscardURB     = ioc(0, 'U', 11, 0)                            // _IO('U', 11)
	usbdevfsReapURBNDelay  = ioc(1, 'U', 13, unsafe.Sizeof(uintptr(0)))    // _IOW('U', 13, void *)
	usbdevfsClaimInterface = ioc(2, 'U', 15, 4)                            // _IOR('U', 15, unsigned int)
	usbdevfsReset          = ioc(0, 'U', 20, 0)                            // _IO('U', 20)
)

func ioc(dir, typ, nr, size uintptr) uintptr {
	return dir<<30 | size<<16 | typ<<8 | nr
}

// linux/usb/ch9.h
const (
	descTypeDevice         = 0x01 // 18 bytes
	descTypeConfig         = 0x02 // 9 bytes
	descTypeInterface      = 0x04 // 9 bytes
	descTypeEndpoint       = 0x05 // 7 bytes
	descTypeSSEndpointComp = 0x30 // 6 bytes
)

// linux/usb/ch9.h
const (
	endpointXferBulk = 0x02 // bmAttributes
	endpointDirMask  = 0x80 // bEndpointAddress
)

// usbfsEnumerate scans base for USB device nodes with an ADB interface.
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/client/usb_linux.cpp;l=131-313;drc=7799b4ba22bd05e1ded1c375fcadcbea2c7ee58c
func usbfsEnumerate(base string) ([]*DeviceInfo, error) {
	buses, err := os.ReadDir(base)
	if err != nil {
		return nil, err
	}
	var devices []*DeviceInfo
	for _, bus := range buses {
		if !allDigits(bus.Name()) {
			continue
		}
		devs, err := os.ReadDir(filepath.Join(base, bus.Name()))
		if err != nil {
			continue
		}
		for _, dev := range devs {
			if !allDigits(dev.Name()) {
				continue
			}
			if device := linuxProbe(filepath.Join(base, bus.Name(), dev.Name())); device != nil {
				devices = append(devices, device)
			}
		}
	}
	return devices, nil
}

func allDigits(s string) bool {
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

func linuxProbe(path string) *DeviceInfo {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	desc := make([]byte, 4096)
	n, err := f.Read(desc)
	if err != nil {
		return nil
	}
	desc = desc[:n]

	// should have device and configuration descriptors, and at least two endpoints
	if len(desc) < 18+9 {
		return nil
	}

	// device descriptor
	if desc[0] != 18 || desc[1] != descTypeDevice {
		return nil
	}
	var (
		vendor  = binary.LittleEndian.Uint16(desc[8:])
		product = binary.LittleEndian.Uint16(desc[10:])
	)
	buf := desc[18:]

	// config descriptor
	if buf[0] != 9 || buf[1] != descTypeConfig {
		return nil
	}
	buf = buf[9:]

	// next descriptor and potential USB 3.0 SuperSpeed Endpoint Companion descriptor
	endpoint := func() []byte {
		if len(buf) < 7 || buf[0] != 7 || buf[1] != descTypeEndpoint {
			return nil
		}
		ep := buf
		buf = buf[7:]
		if len(buf) >= 6 && buf[0] == 6 && buf[1] == descTypeSSEndpointComp {
			buf = buf[6:]
		}
		return ep
	}

	// loop through all the descriptors and look for the ADB interface
	for len(buf) >= 2 {
		length, typ := int(buf[0]), buf[1]
		if length == 0 || length > len(buf) {
			// corsair hubs may have a zero length descriptor (b/302212871)
			return nil
		}
		if typ != descTypeInterface {
			buf = buf[length:]
			continue
		}
		if length != 9 {
			return nil // interface descriptor has wrong size
		}
		iface := buf
		buf = buf[9:]

		if numEndpoints := iface[4]; numEndpoints != 2 {
			continue
		}
		if !IsADB(iface[5], iface[6], iface[7]) {
			continue
		}

		// probably adb
		ep1 := endpoint()
		ep2 := endpoint()
		if ep1 == nil || ep2 == nil {
			return nil // endpoints not found
		}

		// both endpoints should be bulk
		if ep1[3] != endpointXferBulk || ep2[3] != endpointXferBulk {
			continue
		}

		// aproto 01 needs 0 termination
		maxPacket := int(binary.LittleEndian.Uint16(ep1[4:]))
		if maxPacket == 0 {
			continue
		}

		// now we just need to figure out which is in and which is out
		epIn, epOut := ep1[2], ep2[2]
		if epIn&endpointDirMask == 0 {
			epIn, epOut = epOut, epIn
		}

		device := &DeviceInfo{
			Path:      path,
			VID:       vendor,
			PID:       product,
			iface:     iface[2],
			epIn:      epIn,
			epOut:     epOut,
			maxPacket: maxPacket,
			zeroMask:  uint32(maxPacket - 1),
		}
		device.ID, device.Serial = linuxDeviceAttr(f)
		return device
	}
	return nil
}

func linuxDeviceAttr(f *os.File) (name, serial string) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR {
		return
	}
	link, err := os.Readlink(filepath.Join(SysfsPath, fmt.Sprintf("dev/char/%d:%d", unix.Major(st.Rdev), unix.Minor(st.Rdev))))
	if err != nil {
		return
	}
	name = filepath.Base(link)

	// don't treat an unknown serial as an error (b/20883914)
	if buf, err := os.ReadFile(filepath.Join(SysfsPath, "bus/usb/devices", name, "serial")); err == nil {
		serial = strings.TrimSpace(string(buf))
	}
	return
}

type usbfsConn struct {
	f  *os.File
	rc syscall.RawConn

	epIn      uint8
	epOut     uint8
	maxPacket int
	zeroMask  uint32

	readMu  sync.Mutex // must be held while reading (and using urbIn)
	readBuf []byte
	readOff int
	readLen int
	urbIn   usbdevfsURB
	inCh    chan struct{}

	writeMu sync.Mutex // must be held while writing (and using urbOut)
	urbOut  usbdevfsURB
	outCh   chan struct{}

	deadMu  sync.Mutex
	deadErr error
	dead    chan struct{}
}

// open implements [DeviceInfo.open], claiming the ADB interface from the kernel.
func usbfsOpen(d *DeviceInfo) (*usbfsConn, error) {
	if d.maxPacket == 0 {
		return nil, errors.New("device is missing interface information")
	}

	// note: O_NONBLOCK so the runtime poller can be used to wait for urbs to reap
	f, err := os.OpenFile(d.Path, os.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}

	rc, err := f.SyscallConn()
	if err != nil {
		f.Close()
		return nil, err
	}

	c := &usbfsConn{
		f:         f,
		rc:        rc,
		epIn:      d.epIn,
		epOut:     d.epOut,
		maxPacket: d.maxPacket,
		zeroMask:  d.zeroMask,
		inCh:      make(chan struct{}, 1),
		outCh:     make(chan struct{}, 1),
		dead:      make(chan struct{}),
	}

	iface := uint32(d.iface)
	if err := c.ioctl(usbdevfsClaimInterface, unsafe.Pointer(&iface)); err != nil {
		f.Close()
		if err == syscall.EBUSY {
			return nil, fmt.Errorf("claim adb interface: %w (is another adb server running?)", err)
		}
		return nil, fmt.Errorf("claim adb interface: %w", err)
	}

	go c.reap()
	return c, nil
}

// ioctl performs an ioctl on the usbfs fd, retrying on EINTR.
func (c *usbfsConn) ioctl(req uintptr, arg unsafe.Pointer) error {
	var errno syscall.Errno
	if err := c.rc.Control(func(fd uintptr) {
		for {
			_, _, e := unix.Syscall(unix.SYS_IOCTL, fd, req, uintptr(arg))
			if e != syscall.EINTR {
				errno = e
				return
			}
		}
	}); err != nil {
		return err
	}
	if errno != 0 {
		return errno
	}
	return nil
}

// reap reaps completed urbs and dispatches them to the pending transfers, using
// the runtime poller to wait for completions (usbfs signals writability when
// completed async urbs are pending). It runs until the fd is closed or the
// device is disconnected, then marks the conn as dead and wakes up all pending
// transfers.
func (c *usbfsConn) reap() {
	var errno syscall.Errno
	err := c.rc.Write(func(fd uintptr) bool {
		for {
			var urb *usbdevfsURB
			_, _, e := unix.Syscall(unix.SYS_IOCTL, fd, usbdevfsReapURBNDelay, uintptr(unsafe.Pointer(&urb)))
			switch e {
			case 0:
			case syscall.EINTR:
				continue
			case syscall.EAGAIN:
				return false // wait for another urb to complete
			default:
				errno = e
				return true
			}
			switch urb {
			case &c.urbIn:
				select {
				case c.inCh <- struct{}{}:
				default:
				}
			case &c.urbOut:
				select {
				case c.outCh <- struct{}{}:
				default:
				}
			}
		}
	})
	if err == nil {
		if errno != 0 {
			err = fmt.Errorf("reap urb: %w", errno)
		} else {
			err = net.ErrClosed
		}
	}

	c.deadMu.Lock()
	c.deadErr = err
	close(c.dead)
	c.deadMu.Unlock()
}

// err returns the reason why the conn died, if dead.
func (c *usbfsConn) err() error {
	c.deadMu.Lock()
	defer c.deadMu.Unlock()
	if c.deadErr == nil {
		return net.ErrClosed
	}
	return c.deadErr
}

// transfer submits a bulk transfer and waits for it to complete, returning the
// number of bytes transferred.
func (c *usbfsConn) transfer(urb *usbdevfsURB, ch chan struct{}, ep uint8, buf []byte) (int, error) {
	*urb = usbdevfsURB{
		Type:     usbdevfsURBTypeBulk,
		Endpoint: ep,
	}
	if len(buf) != 0 {
		// note: the kernel accesses the buffer (and writes back to the urb when
		// it is reaped) after the submit ioctl returns, but both are kept alive
		// since the urb is referenced by us and the buffer is referenced by the
		// urb
		urb.Buffer = unsafe.Pointer(&buf[0])
		urb.BufferLength = int32(len(buf))
	}
	if err := c.ioctl(usbdevfsSubmitURB, unsafe.Pointer(urb)); err != nil {
		return 0, fmt.Errorf("submit urb: %w", err)
	}
	select {
	case <-ch:
		if urb.Status != 0 {
			return 0, fmt.Errorf("transfer failed: %w", syscall.Errno(-urb.Status))
		}
		return int(urb.ActualLength), nil
	case <-c.dead:
		return 0, c.err()
	}
}

// Read reads the next bulk transfer from the device into p, requesting up to
// len(p) rounded up to the maximum packet size, and buffering any extra data
// for the next Read (ADB sends packet headers and payloads as separate
// transfers, but we can't rely on that since some hardware is buggy).
func (c *usbfsConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}

	// leftover data from the previous transfer
	if c.readLen != 0 {
		n := copy(p, c.readBuf[c.readOff:c.readOff+c.readLen])
		c.readOff += n
		c.readLen -= n
		return n, nil
	}

	// round the transfer size up to the nearest packet size boundary (the
	// device won't send a zero packet for packet size aligned payloads, so
	// don't read any more packets than needed)
	want := (len(p) + c.maxPacket - 1) / c.maxPacket * c.maxPacket
	if want != len(c.readBuf) {
		c.readBuf = slices.Grow(c.readBuf[:0], want)[:want]
	}

	for {
		n, err := c.transfer(&c.urbIn, c.inCh, c.epIn, c.readBuf)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			continue // zero-length marker, wait for the next transfer with data
		}
		nn := copy(p, c.readBuf[:n])
		c.readOff = nn
		c.readLen = n - nn
		return nn, nil
	}
}

var zlp [1]byte // valid pointer for zero-length transfers

// Write sends p to the device as a single bulk transfer, followed by a
// zero-length marker if its length is a multiple of the packet size.
func (c *usbfsConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}

	n, err := c.transfer(&c.urbOut, c.outCh, c.epOut, p)
	if err != nil && errors.Is(err, syscall.ENOMEM) {
		// try again with the data split into chunks
		n = 0
		for chunk := range slices.Chunk(p, 16384) {
			nn, err := c.transfer(&c.urbOut, c.outCh, c.epOut, chunk)
			if n += nn; err != nil {
				return n, err
			}
			if nn != len(chunk) {
				return n, io.ErrShortWrite
			}
		}
	} else if err != nil {
		return n, err
	} else if n != len(p) {
		return n, io.ErrShortWrite
	}

	// if we need 0-markers and our transfer is an even multiple of the packet
	// size, then send a zero marker
	if c.zeroMask != 0 && uint32(len(p))&c.zeroMask == 0 {
		c.urbOut = usbdevfsURB{
			Type:     usbdevfsURBTypeBulk,
			Endpoint: c.epOut,
			Buffer:   unsafe.Pointer(&zlp),
		}
		if err := c.ioctl(usbdevfsSubmitURB, unsafe.Pointer(&c.urbOut)); err != nil {
			return len(p), fmt.Errorf("submit urb: %w", err)
		}
		select {
		case <-c.outCh:
			if c.urbOut.Status != 0 {
				return len(p), fmt.Errorf("transfer failed: %w", syscall.Errno(-c.urbOut.Status))
			}
		case <-c.dead:
			return len(p), c.err()
		}
	}

	return len(p), nil
}

// Reset resets the USB port, making the conn unusable.
func (c *usbfsConn) reset() error {
	return c.ioctl(usbdevfsReset, nil)
}

// Close cancels any pending transfers and closes the device, releasing the
// interface.
func (c *usbfsConn) Close() error {
	// unblock pending reads/writes, ignore errors (may fail if none active)
	_ = c.rc.Control(func(fd uintptr) {
		unix.Syscall(unix.SYS_IOCTL, fd, usbdevfsDiscardURB, uintptr(unsafe.Pointer(&c.urbIn)))
		unix.Syscall(unix.SYS_IOCTL, fd, usbdevfsDiscardURB, uintptr(unsafe.Pointer(&c.urbOut)))
	})
	return c.f.Close()
}
