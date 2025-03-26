package syncproto

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/pgaskin/go-adb/adb/adbproto"
)

// TODO: optimize, refactor

const (
	Feature_stat_v2                  = adbproto.FeatureStat2
	Feature_ls_v2                    = adbproto.FeatureLs2
	Feature_sendrecv_v2              = adbproto.FeatureSendRecv2
	Feature_sendrecv_v2_brotli       = adbproto.FeatureSendRecv2Brotli
	Feature_sendrecv_v2_lz4          = adbproto.FeatureSendRecv2LZ4
	Feature_sendrecv_v2_zstd         = adbproto.FeatureSendRecv2Zstd
	Feature_sendrecv_v2_dry_run_send = adbproto.FeatureSendRecv2DryRunSend
)

type PacketID [4]byte

var (
	Packet_LSTAT_V1 = PacketID{'S', 'T', 'A', 'T'}
	Packet_STAT_V2  = PacketID{'S', 'T', 'A', '2'} // if stat_v2
	Packet_LSTAT_V2 = PacketID{'L', 'S', 'T', '2'} // if stat_v2
	Packet_LIST_V1  = PacketID{'L', 'I', 'S', 'T'}
	Packet_LIST_V2  = PacketID{'L', 'I', 'S', '2'} // if ls_v2
	Packet_DENT_V1  = PacketID{'D', 'E', 'N', 'T'}
	Packet_DENT_V2  = PacketID{'D', 'N', 'T', '2'} // if ls_v2
	Packet_SEND_V1  = PacketID{'S', 'E', 'N', 'D'}
	Packet_SEND_V2  = PacketID{'S', 'N', 'D', '2'} // if sendrecv_v2
	Packet_RECV_V1  = PacketID{'R', 'E', 'C', 'V'}
	Packet_RECV_V2  = PacketID{'R', 'C', 'V', '2'} // if sendrecv_v2
	Packet_DONE     = PacketID{'D', 'O', 'N', 'E'} // signals the end of an array of values
	Packet_DATA     = PacketID{'D', 'A', 'T', 'A'}
	Packet_OKAY     = PacketID{'O', 'K', 'A', 'Y'}
	Packet_FAIL     = PacketID{'F', 'A', 'I', 'L'}
	Packet_QUIT     = PacketID{'Q', 'U', 'I', 'T'}
)

func (id PacketID) String() string {
	return string(id[:])
}

type SyncFail string

func (s SyncFail) Error() string {
	return string(s)
}

const SyncDataMax = 64 * 1024

type SyncStat1 struct {
	// Packet_LSTAT_V1
	Mode  uint32
	Size  uint32
	Mtime uint32
}

type SyncStat2 struct {
	// Packet_STAT_V2, Packet_LSTAT_V2
	Error uint32
	Dev   uint64
	Ino   uint64
	Mode  uint32
	Nlink uint32
	Uid   uint32
	Gid   uint32
	Size  uint64
	Atime int64
	Mtime int64
	Ctime int64
}

type SyncDent1 struct {
	// Packet_DENT_V1
	Mode    uint32
	Size    uint32
	Mtime   uint32
	Namelen uint32
	// followed by `namelen` bytes of the name.
}

type SyncDent2 struct {
	// Packet_DENT_V2
	Error   uint32
	Dev     uint64
	Ino     uint64
	Mode    uint32
	Nlink   uint32
	Uid     uint32
	Gid     uint32
	Size    uint64
	Atime   int64
	Mtime   int64
	Ctime   int64
	Namelen uint32
	// followed by `namelen` bytes of the name.
}

const (
	SyncFlag_None   uint32 = 0
	SyncFlag_Brotli uint32 = 1          // if sendrecv_v2_brotli
	SyncFlag_LZ4    uint32 = 2          // if sendrecv_v2_lz4
	SyncFlag_Zstd   uint32 = 4          // if sendrecv_v2_zstd
	SyncFlag_DryRun uint32 = 0x80000000 // if sendrecv_v2_dry_run_send
)

// send_v1 sent the path in a buffer, followed by a comma and the mode as a string.

// send_v2 sends just the path in the first request, and then sends another with details.
type SyncSend2 struct {
	// Packet_SEND_V2
	Mode  uint32
	Flags uint32
}

// recv_v1 just sent the path without any accompanying data.

// recv_v2 sends just the path in the first request, and then sends another with details.
type SyncRecv2 struct {
	// Packet_RECV_V2
	Flags uint32
}

type SyncData struct {
	// Packet_DATA
	Size uint32
	// followed by `size` bytes of data.
}

type SyncStatus struct {
	// Packet_OKAY, Packet_FAIL, Packet_DONE
	Msglen uint32
	// followed by `msglen` bytes of error message, if id == ID_FAIL.
}

func SyncRequest(conn net.Conn, id PacketID, path string) error {
	req := make([]byte, 4+4+len(path))
	copy(req[0:4], id[:])
	binary.LittleEndian.PutUint32(req[4:8], uint32(len(path)))
	copy(req[8:], path)
	_, err := conn.Write(req)
	return err
}

func SyncResponse(conn net.Conn) error {
	b := make([]byte, 4)
	if _, err := io.ReadFull(conn, b); err != nil {
		return fmt.Errorf("read response id: %w", err)
	}
	if err := SyncResponseCheck(conn, PacketID(b)); err != nil {
		return err
	}
	if id := Packet_OKAY; PacketID(b) != id {
		return fmt.Errorf("unexpected response id %q (expected %s)", PacketID(b), id)
	}
	return nil
}

func SyncResponseObject[T any](conn net.Conn, id PacketID) (*T, error) {
	var obj T
	b := make([]byte, 4)
	if _, err := io.ReadFull(conn, b); err != nil {
		return nil, fmt.Errorf("read response id: %w", err)
	}
	if err := SyncResponseCheck(conn, PacketID(b)); err != nil {
		return nil, err
	}
	if PacketID(b) != id && PacketID(b) != Packet_DONE {
		return nil, fmt.Errorf("unexpected response id %q (expected %s)", PacketID(b), id)
	}
	if err := binary.Read(conn, binary.LittleEndian, &obj); err != nil {
		return nil, fmt.Errorf("read response %s: %w", id, err)
	}
	if PacketID(b) == Packet_DONE {
		return nil, nil
	}
	return &obj, nil
}

func SyncResponseCheck(conn net.Conn, id PacketID) error {
	switch id {
	case Packet_FAIL:
		var tmp SyncStatus
		if err := binary.Read(conn, binary.LittleEndian, &tmp); err != nil {
			return fmt.Errorf("read error response: %w", err)
		}
		tmp1 := make([]byte, tmp.Msglen)
		if _, err := io.ReadFull(conn, tmp1); err != nil {
			return fmt.Errorf("read error response: %w", err)
		}
		return SyncFail(tmp1)
	case Packet_OKAY:
		var tmp SyncStatus
		if err := binary.Read(conn, binary.LittleEndian, &tmp); err != nil {
			return fmt.Errorf("read okay response: %w", err)
		}
		if tmp.Msglen != 0 {
			return fmt.Errorf("read okay response: message length must be zero, got %d", tmp.Msglen)
		}
	}
	return nil
}
