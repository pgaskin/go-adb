package adbhost

import "strings"

// ConnectionState represents the state of a device connected to an ADB host.
//
// Note that since we don't actually deal with raw enum values anywhere (adb
// sends it as either a string or a protobuf enum), we define this as a string
// here for flexibility and compatibility.
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.h;l=105-123;drc=4af6e4ff6ff587b344236c30cb3d6765cb1de6be
type ConnectionState string

const (
	CsConnecting   ConnectionState = "connecting"     // Haven't received a response from the device yet.
	CsAuthorizing  ConnectionState = "authorizing"    // Authorizing with keys from ADB_VENDOR_KEYS.
	CsUnauthorized ConnectionState = "unauthorized"   // ADB_VENDOR_KEYS exhaustedfell back to user prompt.
	CsNoPerm       ConnectionState = "no permissions" // Insufficient permissions to communicate with the device.
	CsDetached     ConnectionState = "detached"       // USB device detached from the adb server (known but not opened/claimed).
	CsOffline      ConnectionState = "offline"        // A peer has been detected (device/host) but no comm has started yet.

	// After CNXN packet, the ConnectionState describes not a state but the type
	// of service on the other end of the transport.

	CsBootloader ConnectionState = "bootloader" // Device running fastboot OS (fastboot) or userspace fastboot (fastbootd).
	CsDevice     ConnectionState = "device"     // Device running Android OS (adbd).
	CsHost       ConnectionState = "host"       // What a device sees from its end of a Transport (adb host).
	CsRecovery   ConnectionState = "recovery"   // Device with bootloader loaded but no ROM OS loaded (adbd).
	CsSideload   ConnectionState = "sideload"   // Device running Android OS Sideload mode (minadbd sideload mode).
	CsRescue     ConnectionState = "rescue"     // Device running Android OS Rescue mode (minadbd rescue mode).
)

// ParseConnectionState attempts to parse the provided string as a connection
// state, returning true if it is a recognized value.
func ParseConnectionState(s string) (ConnectionState, bool) {
	if cs := ConnectionState(s); cs.Valid() {
		return cs, true
	}
	if strings.HasPrefix(s, string(CsNoPerm)+" (") {
		// https://cs.android.com/android/platform/superproject/main/+/main:system/core/diagnose_usb/diagnose_usb.cpp;l=83-90;drc=9c843a66d11d85e1f69e944f1b37314d3e47aab1
		return CsNoPerm, true // this is a special case since adb can add a reason afterwards
	}
	return "", false
}

// String returns the connection state as a string.
func (c ConnectionState) String() string {
	if c == "" {
		return "unknown"
	}
	return string(c)
}

// IsOnline returns true if the state is considered to be online.
func (c ConnectionState) IsOnline() bool {
	switch c {
	case CsBootloader:
	case CsDevice:
	case CsHost:
	case CsRecovery:
	case CsSideload:
	case CsRescue:
	default:
		return false
	}
	return true
}

// Valid returns true if the state is a recognized value.
func (c ConnectionState) Valid() bool {
	switch c {
	case CsConnecting:
	case CsAuthorizing:
	case CsUnauthorized:
	case CsNoPerm:
	case CsDetached:
	case CsOffline:
	case CsBootloader:
	case CsDevice:
	case CsHost:
	case CsRecovery:
	case CsSideload:
	case CsRescue:
	default:
		return false
	}
	return true
}

// TODO: device list parsing
