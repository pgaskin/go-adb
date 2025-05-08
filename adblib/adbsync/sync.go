// Package adbsync wraps the sync protocol.
package adbsync

import (
	"errors"
	"io"
	"io/fs"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/pgaskin/go-adb/adb"
	"github.com/pgaskin/go-adb/adb/adbproto/syncproto"
	"github.com/pgaskin/go-adb/internal/bionic"
)

// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/daemon/file_sync_service.cpp;drc=c1bd54a6ed585e420deeafd1d55fcf9854631000
//
// if any of the do_whatever functions in the loop calling handle_sync_command
// returns false, the connection is no longer usable

type Client struct {
	Server adb.Dialer

	// ConnectTimeout, if non-zero, is the maximum amount of time to wait for a
	// new sync connection to be opened before returning an error.
	ConnectTimeout time.Duration

	// IdleConnTimeout, if non-zero, is the maximum amount of time an idle
	// connection will remain idle before closing itself.
	IdleConnTimeout time.Duration

	// MaxIdleConns, if non-zero, limits the maximum number of idle connections.
	// Connections exceeding the limit wil be closed instead of being kept for
	// later reuse.
	MaxIdleConns int

	// MaxConns, if non-zero, limits the maximum number of concurrent
	// connections in all states. Connections exceeding the limit will block.
	MaxConns int

	// CompressionConfig contains options for compression and decompression.
	CompressionConfig *CompressionConfig

	negotiateCompressOnce sync.Once
	compressFlag          uint32
	decompressFlag        uint32
}

// onceNegotiateCompression must be called by negotiateCompressOnce.
func (c *Client) onceNegotiateCompression() {
	c.compressFlag = c.CompressionConfig.compressNegotiate(c.Server)
	c.decompressFlag = c.CompressionConfig.decompressNegotiate(c.Server)
}

// CloseIdleConnections closes any connections which were previously connected
// from previous requests but are now idle and prevents future connections from
// being left idle. It does not interrupt any connections currently in use.
func (c *Client) CloseIdleConnections() {
	// TODO
}

// FileInfo describes a file. If from a stat/lstat, Sys returns a
// [*syncproto.SyncStat1] or [*syncproto.SyncStat2]. If from a readdir, Sys
// returns a [*syncproto.SyncDent1] or [*syncproto.SyncDent2].
type FileInfo = fs.FileInfo

// DirEntry is an entry read from a directory.
type DirEntry = fs.DirEntry

// FileMode represents a file's mode and permission bits.
type FileMode = fs.FileMode

var (
	ErrInvalid    = fs.ErrInvalid
	ErrPermission = fs.ErrPermission
	ErrExist      = fs.ErrExist
	ErrNotExist   = fs.ErrNotExist
	ErrClosed     = fs.ErrClosed
)

type fileInfo struct {
	name    string
	size    int64
	mode    FileMode
	modTime time.Time
	sys     any
}

func (s *fileInfo) Name() string       { return s.name }
func (s *fileInfo) Size() int64        { return s.size }
func (s *fileInfo) Mode() FileMode     { return s.mode }
func (s *fileInfo) ModTime() time.Time { return s.modTime }
func (s *fileInfo) IsDir() bool        { return s.mode.IsDir() }
func (s *fileInfo) Sys() any           { return s.sys }

func fillFileInfoStat1(dst *fileInfo, src *syncproto.SyncStat1) {
	dst.size = int64(src.Size)
	dst.mode = fsFileMode(src.Mode)
	dst.modTime = time.Unix(int64(src.Mtime), 0)
	dst.sys = src
}

func fillFileInfoStat2(dst *fileInfo, src *syncproto.SyncStat2) {
	dst.size = int64(src.Size)
	dst.mode = fsFileMode(src.Mode)
	dst.modTime = time.Unix(src.Mtime, 0)
	dst.sys = src
}

func fillFileInfoDent1(dst *fileInfo, src *syncproto.SyncDent1) {
	dst.size = int64(src.Size)
	dst.mode = fsFileMode(src.Mode)
	dst.modTime = time.Unix(int64(src.Mtime), 0)
	dst.sys = src
}

func fillFileInfoDent2(dst *fileInfo, src *syncproto.SyncDent2) {
	dst.size = int64(src.Size)
	dst.mode = fsFileMode(src.Mode)
	dst.modTime = time.Unix(src.Mtime, 0)
	dst.sys = src
}

// fsFileMode converts an sync file mode into an [io/fs.FileMode].
func fsFileMode(mode uint32) fs.FileMode {
	m := fs.FileMode(mode & 0777)
	switch mode & bionic.S_IFMT {
	case bionic.S_IFREG:
		// nothing to do
	case bionic.S_IFBLK:
		m |= fs.ModeDevice
	case bionic.S_IFCHR:
		m |= fs.ModeCharDevice
	case bionic.S_IFDIR:
		m |= fs.ModeDir
	case bionic.S_IFIFO:
		m |= fs.ModeNamedPipe
	case bionic.S_IFLNK:
		m |= fs.ModeSymlink
	case bionic.S_IFSOCK:
		m |= fs.ModeSocket
	default:
		m |= fs.ModeIrregular
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

// syncFileMode converts an [io/fs.FileMode] into a sync file mode.
func syncFileMode(mode fs.FileMode) uint32 {
	m := uint32(mode & fs.ModePerm)
	switch mode & fs.ModeType {
	case fs.ModeDevice:
		m |= bionic.S_IFBLK
	case fs.ModeCharDevice:
		m |= bionic.S_IFCHR
	case fs.ModeDir:
		m |= bionic.S_IFDIR
	case fs.ModeNamedPipe:
		m |= bionic.S_IFIFO
	case fs.ModeSymlink:
		m |= bionic.S_IFLNK
	case fs.ModeSocket:
		m |= bionic.S_IFSOCK
	case fs.ModeIrregular:
		m |= bionic.S_IFMT // we don't really have anything good to put here, so just set all the bits
	default:
		// nothing to do
	}
	if mode&fs.ModeSetgid != 0 {
		m |= bionic.S_ISGID
	}
	if mode&fs.ModeSetuid != 0 {
		m |= bionic.S_ISUID
	}
	if mode&fs.ModeSticky != 0 {
		m |= bionic.S_ISVTX
	}
	return m
}

// syncFailError parses well-known errors from sync failures or returns the
// original error.
func syncFailError(err syncproto.SyncFail) error {
	switch _, errno, _ := bionic.FromMsgSuffix(string(err)); errno {
	case "EINVAL":
		return ErrInvalid
	case "EPERM":
		return ErrPermission
	case "EEXIST":
		return ErrExist
	case "ENOENT":
		return ErrNotExist
	}
	return err
}

// syncFailError parses well-known errors from errno values or returns a generic
// error.
func errnoError(errno uint32) error {
	switch errno {
	case 22:
		return ErrInvalid
	case 1:
		return ErrPermission
	case 17:
		return ErrExist
	case 2:
		return ErrNotExist
	}
	return errors.New("error " + strconv.FormatUint(uint64(errno), 10))
}

// Stat gets information about the specified file. If the file is a symbolic
// link, it follows it.
//
// This requires [syncproto.Feature_stat_v2].
func (c *Client) Stat(name string) (FileInfo, error) {
	return nil, errors.ErrUnsupported // TODO
}

// Lstat gets information about the specified file. If the file is a symbolic
// link, it returns information about the link itself.
//
// If [syncproto.Feature_stat_v2] is not supported, only mode, size, and mtime
// will be returned.
func (c *Client) Lstat(name string) (FileInfo, error) {
	return nil, errors.ErrUnsupported // TODO
}

// TODO: OpenDir

// ReadDir lists the specified directory, returning all its directory entries
// sorted by filename.
func (c *Client) ReadDir(name string) ([]DirEntry, error) {
	return nil, errors.ErrUnsupported // TODO
}

// ReadFile reads the specified file and returns the contents.
func (c *Client) ReadFile(name string) ([]byte, error) {
	return nil, errors.ErrUnsupported // TODO
}

// WriteFile writes data to the specified file, creating it if necessary.
func (c *Client) WriteFile(name string, data []byte, mode fs.FileMode) error {
	return errors.ErrUnsupported // TODO
}

// OpenFileReader opens a reader for the specified file.
func (c *Client) OpenFileReader(name string) (io.ReadCloser, error) {
	return nil, errors.ErrUnsupported // TODO
}

// OpenFileReader opens a writer to the specified file. The error for the
// [io.Closer] must be checked to ensure the file was read successfully.
func (c *Client) OpenFileWriter(name string, mode fs.FileMode) (io.WriteCloser, error) {
	return nil, errors.ErrUnsupported // TODO
}

// TODO

// syncConn wraps a single connection to the sync service.
//
// It can usually be reused after requests, but certain kinds of errors will
// terminate the connection.
type syncConn struct {
	conn net.Conn

	compressionConfig *CompressionConfig
	compressFlag      uint32
	decompressFlag    uint32
}

// TODO

func (c *syncConn) lstat1() (*syncproto.SyncStat1, error) {
	return nil, errors.ErrUnsupported // TODO
}

func (c *syncConn) lstat2() (*syncproto.SyncStat2, error) {
	return nil, errors.ErrUnsupported // TODO
}

func (c *syncConn) stat2() (*syncproto.SyncStat2, error) {
	return nil, errors.ErrUnsupported // TODO
}

// Close closes the connection.
func (c *syncConn) Close() error {
	return c.conn.Close()
}
