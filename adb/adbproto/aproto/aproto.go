// Package aproto implements the lower level transport protocol used by ADB.
package aproto

import "encoding/binary"

// Packet payload sizes (adb.h).
const (
	MaxPayloadSizeV1 = 4 * 1024
	MaxPayloadSize   = 1024 * 1024
)

// When delayed acks are supported, the initial number of unacknowledged bytes
// we're willing to receive on a socket before the other side should block
// (adb.h).
const InitialDelayedAckBytes = 32 * 1024 * 1024

// ADB protocol version (adb.h).
const (
	VersionMin          uint32 = 0x01000000 // original
	VersionSkipChecksum uint32 = 0x01000001 // skip checksum (Dec 2017)
)

// Stream-based TLS protocol version (adb.h).
const (
	STLSVersionMin uint32 = 0x01000000
)

// note: I didn't include ADB_SERVER_VERSION since I'm trying to keep this
// package relatively version-independent

type Command uint32

// Message commands (types.h).
const (
	A_SYNC Command = 0x434e5953
	A_CNXN Command = 0x4e584e43
	A_OPEN Command = 0x4e45504f
	A_OKAY Command = 0x59414b4f
	A_CLSE Command = 0x45534c43
	A_WRTE Command = 0x45545257
	A_AUTH Command = 0x48545541
	A_STLS Command = 0x534C5453
)

func (c Command) String() string {
	return string(binary.LittleEndian.AppendUint32(nil, uint32(c)))
}

// Message is an amessage (types.h)
type Message struct {
	Command    Command // command identifier constant
	Arg0       uint32  // first argument
	Arg1       uint32  // second argument
	DataLength uint32  // length of payload (0 is allowed)
	DataCheck  uint32  // checksum of data payload
	Magic      uint32  // command ^ 0xffffffff
}

// Packet is an apacket (types.h).
type Packet struct {
	Message
	Payload []byte
}

// TODO: PacketReader (see the shellproto2 conn stuff, and adb's apacket_reader.cpp)
