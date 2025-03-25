package adbhost

import (
	"fmt"
	"strconv"
	"strings"
)

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
// state. Use [ConnectionState.IsValid] to check if it is a known value.
func ParseConnectionState(s string) ConnectionState {
	if strings.HasPrefix(s, string(CsNoPerm)+" (") {
		// https://cs.android.com/android/platform/superproject/main/+/main:system/core/diagnose_usb/diagnose_usb.cpp;l=83-90;drc=9c843a66d11d85e1f69e944f1b37314d3e47aab1
		return CsNoPerm // this is a special case since adb can add a reason afterwards
	}
	return ConnectionState(s)
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

// IsValid returns true if the state is a recognized value.
func (c ConnectionState) IsValid() bool {
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

type ConnectionType string

const (
	CtUnknown = "unknown"
	CtUSB     = "usb"
	CtSocket  = "socket"
)

// ParseConnectionType attempts to parse the provided string as a connection
// type. Use [ConnectionType.IsValid] to check if it is a known value.
func ParseConnectionType(s string) ConnectionType {
	return ConnectionType(s)
}

// String returns the connection type as a string.
func (c ConnectionType) String() string {
	if c == "" {
		return "unknown"
	}
	return string(c)
}

// IsValid returns true if the state is a recognized value. Note that
// [CtUnknown] is a recognized value.
func (c ConnectionType) IsValid() bool {
	switch c {
	case CtUnknown:
	case CtUSB:
	case CtSocket:
	default:
		return false
	}
	return true
}

// TransportInfo contains the status of a device connected to the ADB host. Not
// all fields may be set.
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/transport.cpp;l=1372-1435;drc=af6fae67a49070ca75c26ceed5759576eb4d3573
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/transport.cpp;l=1341-1468;drc=af6fae67a49070ca75c26ceed5759576eb4d3573
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/transport.h;l=317-404;drc=af6fae67a49070ca75c26ceed5759576eb4d3573
type TransportInfo struct {
	Serial          string
	State           ConnectionState
	BusAddress      string
	Product         string
	Model           string
	Device          string
	NegotiatedSpeed int64
	MaxSpeed        int64
	Transport       TransportID
}

// ParseDevices parses devices info from the textual device tracker output. Note
// that the textual device tracker sanitizes non-alphanumeric values in
// attributes by replacing them with underscores.
func ParseDevices(buf []byte) ([]*TransportInfo, error) {
	var devs []*TransportInfo
	for line := range strings.FieldsFuncSeq(string(buf), func(r rune) bool { return r == '\n' }) {
		var info TransportInfo

		serial, rest, isSerialTab := strings.Cut(line, "\t") // short listings delimit the serial by a tab
		if !isSerialTab {
			var ok bool
			serial, rest, ok = strings.Cut(serial, " ")
			if !ok {
				return devs, fmt.Errorf("parse line %q: missing tab or space after serial", line)
			}
			rest = strings.TrimLeft(rest, " ") // long listings right-pad with spaces
		}
		if isUnknownSerial := serial == "(no serial number)"; isUnknownSerial {
			serial = ""
		}
		info.Serial = serial

		stateStr, rest, isLong := strings.Cut(rest, " ")
		info.State = ParseConnectionState(stateStr) // don't check IsValid for forwards compatibility

		if isLong {
			var attrs bool
			for attr := range strings.FieldsSeq(rest) {
				if !attrs {
					info.BusAddress = attr
					attrs = true
					continue
				}
				switch k, v, _ := strings.Cut(attr, ":"); k {
				case "product":
					info.Product = v
				case "model":
					info.Model = v
				case "device":
					info.Device = v
				case "transport_id":
					tid, err := strconv.ParseUint(v, 10, 64)
					if err != nil {
						return devs, fmt.Errorf("parse line %q: parse transport id: %w", line, err)
					}
					info.Transport = TransportID(tid)
				default:
					// ignore unknown attributes for forwards compatibility
				}
			}
		}

		devs = append(devs, &info)
	}
	return devs, nil
}

// TODO: ParseDevicesProto
