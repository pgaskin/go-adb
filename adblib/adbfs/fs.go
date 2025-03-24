// Package adbfs provides access to files on the device.
package adbfs

import (
	"io/fs"

	"github.com/pgaskin/go-adb/adb/adbproto/syncproto"
	"github.com/pgaskin/go-adb/adblib/internal/bionic"
)

// TODO: implement io.FS
// TODO: implement some helpers like io.ReadFile, etc
// TODO: write support

// fsFileMode converts an sync file mode into an [io/fs.FileMode].
func fsFileMode(mode uint32) fs.FileMode {
	m := fs.FileMode(mode & 0777)
	switch mode & bionic.S_IFMT {
	case bionic.S_IFBLK:
		m |= fs.ModeDevice
	case bionic.S_IFCHR:
		m |= fs.ModeDevice | fs.ModeCharDevice
	case bionic.S_IFDIR:
		m |= fs.ModeDir
	case bionic.S_IFIFO:
		m |= fs.ModeNamedPipe
	case bionic.S_IFLNK:
		m |= fs.ModeSymlink
	case bionic.S_IFREG:
		// nothing to do
	case bionic.S_IFSOCK:
		m |= fs.ModeSocket
	}
	if mode&bionic.S_ISGID != 0 {
		m |= fs.ModeSetgid
	}
	if mode&bionic.S_ISUID != 0 {
		m |= fs.ModeSetuid
	}
	if mode&bionic.S_ISVTX != 0 {
		m |= fs.ModeSticky
	}
	return m
}

// fsError parses well-known errors from sync failures.
func fsError(err syncproto.SyncFail) error {
	switch _, errno, _ := bionic.FromMsgSuffix(string(err)); errno {
	case "EINVAL":
		return fs.ErrInvalid
	case "EPERM":
		return fs.ErrPermission
	case "EEXIST":
		return fs.ErrExist
	case "ENOENT":
		return fs.ErrNotExist
	}
	return nil
}
