package adbusb

// ADB interface identifiers. ADB over gadget mode and DbC use the same ADB
// protocol.
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.h;l=194-199;drc=af6fae67a49070ca75c26ceed5759576eb4d3573
const (
	adbClass       = 0xff
	adbSubclass    = 0x42
	adbProtocol    = 0x1
	adbDbcClass    = 0xdc
	adbDbcSubclass = 0x2
)

// IsADB matches ADB interfaces.
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/client/transport_usb.cpp;l=170-177;drc=1cf2f017d312f73b3dc53bda85ef2610e35a80e9
func IsADB(class, subclass, protocol uint8) bool {
	return protocol == adbProtocol &&
		((class == adbClass && subclass == adbSubclass) ||
			(class == adbDbcClass && subclass == adbDbcSubclass))
}
