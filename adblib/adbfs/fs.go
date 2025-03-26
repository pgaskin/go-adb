// Package adbfs provides access to files on the device.
package adbfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"path"
	"runtime"
	"sync"
	"time"

	"github.com/pgaskin/go-adb/adb"
	"github.com/pgaskin/go-adb/adb/adbproto/syncproto"
	"github.com/pgaskin/go-adb/internal/bionic"
)

// TODO: write support
// TODO: implement optional features
// TODO: compression: github.com/andybalholm/brotli, github.com/klauspost/compress/zstd, github.com/pierrec/lz4/v4
// TODO: network deadlines during file operations

// TODO: refactor some connection stuff and connection pooling into the syncproto package

// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/file_sync_protocol.h;drc=888a54dcbf954fdffacc8283a793290abcc589cd
// https://cs.android.com/android/_/android/platform/packages/modules/adb/+/f354ebb4a8a928e3b1e50b19ed9030431825212b:file_sync_service.h
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/daemon/file_sync_service.cpp;drc=888a54dcbf954fdffacc8283a793290abcc589cd
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/client/file_sync_client.cpp;drc=d5137445c0d4067406cb3e38aade5507ff2fcd16;bpv=0;bpt=0
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/protocol.txt;drc=ebf09dd6e6cf295df224730b1551606c521e74a9
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/SERVICES.txt;drc=ebf09dd6e6cf295df224730b1551606c521e74a9
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;drc=ebf09dd6e6cf295df224730b1551606c521e74a9
// https://gist.github.com/hfutxqd/a5b2969c485dabd512e543768a35a046
// https://github.com/cstyan/adbDocumentation
// note: sync STA2/LST2 since 2016, LIS2 since 2019

var (
	errNotDirectory = errors.New("not a directory")
	errIsDirectory  = errors.New("is a directory")
)

// FS provides access to the filesystem of an ADB device.
//
// A pool of connections is used. Additional connections will be opened for
// concurrent operations, or when other operations are done while a file is open
// for reading.
//
// In general, fs.ReadFile, fs.ReadDir, and fs.Stat should be used over the Open
// method since Open always does a stat. If Open is used (e.g., for streaming
// large files), it should be read fully and closed as soon as possible to
// prevent additional connections from being opened unnecessarily.
type FS struct {
	server    adb.Dialer
	timeout   time.Duration
	keepalive time.Duration
	connMu    sync.Mutex
	conn      map[net.Conn]func() bool // [conn]used (and call the function to stop the connection timeout)
}

var (
	_ fs.FS         = (*FS)(nil)
	_ fs.StatFS     = (*FS)(nil)
	_ fs.ReadDirFS  = (*FS)(nil)
	_ fs.ReadFileFS = (*FS)(nil)
)

type Option interface {
	apply(*FS)
}

type optionFunc func(*FS)

func (fn optionFunc) apply(fs *FS) {
	if fn != nil {
		fn(fs)
	}
}

// WithTimeout sets a timeout for connections to be established. If not set,
// file operations may block indefinitely.
func WithTimeout(t time.Duration) Option {
	return optionFunc(func(fs *FS) {
		fs.timeout = t
	})
}

// WithKeepalive keeps connections around to be reused for the specified
// duration. If not set, a new connectioni will be opened for every operation.
func WithKeepalive(t time.Duration) Option {
	return optionFunc(func(fs *FS) {
		fs.keepalive = t
	})
}

// Connect connects to the specified adb server.
func Connect(server adb.Dialer, opt ...Option) (*FS, error) {
	c := &FS{
		server: server,
		conn:   make(map[net.Conn]func() bool),
	}
	for _, opt := range opt {
		opt.apply(c)
	}

	runtime.AddCleanup(c, func(m map[net.Conn]func() bool) {
		for conn := range c.conn {
			go func() {
				defer func() {
					_ = recover()
				}()
				conn.Close()
			}()
		}
	}, c.conn)

	conn, err := c.getConn()
	if err != nil {
		return nil, fmt.Errorf("connect to sync service: %w", err)
	}
	defer c.putConn(conn)

	return c, nil
}

func (c *FS) tryGetConn() (net.Conn, error) {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if c.conn == nil {
		return nil, fs.ErrClosed
	}

	for conn, use := range c.conn {
		if use != nil && use() {
			c.conn[conn] = nil
			return conn, nil
		}
	}
	return nil, nil
}

func (c *FS) getConn() (net.Conn, error) {
	conn, err := c.tryGetConn()
	if err != nil || conn != nil {
		return conn, err
	}

	ctx := context.Background()
	if c.timeout > 0 {
		var stop context.CancelFunc
		ctx, stop = context.WithDeadline(ctx, time.Now().Add(c.timeout))
		defer stop()
	}
	conn, err = c.server.DialADB(ctx, "sync:")
	if err != nil {
		return nil, fmt.Errorf("connect to sync service: %w", err)
	}

	c.connMu.Lock()
	defer c.connMu.Unlock()

	c.conn[conn] = nil
	return conn, nil
}

func (c *FS) putConn(conn net.Conn) {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if c.keepalive > 0 {
		// if delConn hasn't been called on it, e.g., because of an error
		if _, ok := c.conn[conn]; ok {
			timer := time.NewTimer(c.keepalive)
			used := make(chan struct{}) // so we don't leak goroutines
			go func() {
				select {
				case <-time.After(c.keepalive):
					conn.Close()
					c.connMu.Lock()
					defer c.connMu.Unlock()
					delete(c.conn, conn)
				case <-used:
				}
			}()
			c.conn[conn] = func() bool {
				defer close(used)
				return timer.Stop() // true if the timer hasn't fired (thus closing the conn)
			}
			return
		}
	}

	go conn.Close()
}

func (c *FS) delConn(conn net.Conn) {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if use, ok := c.conn[conn]; ok {
		if use != nil {
			use() // so we don't leak goroutines
		}
	}
	delete(c.conn, conn)

	go conn.Close()
}

func (c *FS) Close() error {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	for conn, use := range c.conn {
		if use != nil {
			use()
		}
		delete(c.conn, conn)
		go conn.Close()
	}
	c.conn = nil

	return nil
}

func (c *FS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{
			Op:   "open",
			Path: name,
			Err:  fs.ErrInvalid,
		}
	}

	conn, err := c.getConn()
	if err != nil {
		return nil, err
	}

	stealConn := false
	defer func() {
		if !stealConn {
			c.putConn(conn)
		}
	}()

	if err := syncproto.SyncRequest(conn, syncproto.Packet_LSTAT_V1, "/"+name); err != nil {
		c.delConn(conn)
		return nil, &fs.PathError{
			Op:   "stat",
			Path: name,
			Err:  err,
		}
	}
	st, err := syncproto.SyncResponseObject[syncproto.SyncStat1](conn, syncproto.Packet_LSTAT_V1)
	if err != nil {
		return nil, &fs.PathError{
			Op:   "stat",
			Path: name,
			Err:  err,
		}
	}
	if *st == (syncproto.SyncStat1{}) {
		return nil, &fs.PathError{
			Op:   "stat",
			Path: name,
			Err:  fmt.Errorf("%w (or permission denied)", fs.ErrNotExist), // we have no way to tell from here with v1
		}
	}

	f := &fsFile{c: c, name: name, st: st}
	if !fsFileMode(st.Mode).IsDir() {
		id := syncproto.Packet_RECV_V1
		if err := syncproto.SyncRequest(conn, id, "/"+name); err != nil {
			c.delConn(conn)
			return nil, &fs.PathError{
				Op:   "open",
				Path: name,
				Err:  fmt.Errorf("do %s: %w", id, err),
			}
		}
		f.conn, stealConn = conn, true
	}
	return f, nil
}

func (c *FS) Stat(name string) (fs.FileInfo, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{
			Op:   "open",
			Path: name,
			Err:  fs.ErrInvalid,
		}
	}

	conn, err := c.getConn()
	if err != nil {
		return nil, err
	}
	defer c.putConn(conn)

	return c.fsStat(conn, name)
}

func (c *FS) fsStat(conn net.Conn, name string) (fs.FileInfo, error) {
	if err := syncproto.SyncRequest(conn, syncproto.Packet_LSTAT_V1, "/"+name); err != nil {
		c.delConn(conn)
		return nil, &fs.PathError{
			Op:   "stat",
			Path: name,
			Err:  err,
		}
	}
	st, err := syncproto.SyncResponseObject[syncproto.SyncStat1](conn, syncproto.Packet_LSTAT_V1)
	if err != nil {
		return nil, &fs.PathError{
			Op:   "stat",
			Path: name,
			Err:  err,
		}
	}
	if *st == (syncproto.SyncStat1{}) {
		return nil, &fs.PathError{
			Op:   "stat",
			Path: name,
			Err:  fmt.Errorf("%w (or permission denied)", fs.ErrNotExist), // we have no way to tell from here with v1
		}
	}
	return &fsFileInfo{name: path.Base(name), st: st}, nil
}

func (c *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{
			Op:   "open",
			Path: name,
			Err:  fs.ErrInvalid,
		}
	}

	conn, err := c.getConn()
	if err != nil {
		return nil, err
	}
	defer c.putConn(conn)

	return c.fsReadDir(conn, name)
}

func (c *FS) fsReadDir(conn net.Conn, name string) ([]fs.DirEntry, error) {
	if err := syncproto.SyncRequest(conn, syncproto.Packet_LIST_V1, "/"+name); err != nil {
		c.delConn(conn)
		return nil, &fs.PathError{
			Op:   "readdir",
			Path: name,
			Err:  err,
		}
	}

	var de []fs.DirEntry
	var seen bool
	for {
		st, err := syncproto.SyncResponseObject[syncproto.SyncDent1](conn, syncproto.Packet_DENT_V1)
		if err != nil {
			return nil, &fs.PathError{
				Op:   "readdirent",
				Path: name,
				Err:  err,
			}
		}
		if st == nil {
			if !seen {
				if st, err := c.fsStat(conn, name); err != nil {
					if err, ok := err.(*fs.PathError); ok {
						err.Op = "readdirent"
						return nil, err
					}
					return nil, err
				} else if !st.IsDir() {
					return nil, &fs.PathError{
						Op:   "readdirent",
						Path: name,
						Err:  errNotDirectory,
					}
				}
				// could be an empty directory or not found, no way to tell reliably with v1
			}
			break
		} else {
			seen = true
		}
		nb := make([]byte, st.Namelen)
		if _, err := io.ReadFull(conn, nb); err != nil {
			return nil, &fs.PathError{
				Op:   "readdirentname",
				Path: name,
				Err:  err,
			}
		}
		if string(nb) == "." || string(nb) == ".." {
			continue
		}
		de = append(de, &fsDirEntry{name: string(nb), st: st})
	}
	return de, nil
}

func (c *FS) ReadFile(name string) ([]byte, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{
			Op:   "open",
			Path: name,
			Err:  fs.ErrInvalid,
		}
	}

	conn, err := c.getConn()
	if err != nil {
		return nil, err
	}
	defer c.putConn(conn)

	if err := syncproto.SyncRequest(conn, syncproto.Packet_RECV_V1, "/"+name); err != nil {
		c.delConn(conn)
		return nil, &fs.PathError{
			Op:   "readfile",
			Path: name,
			Err:  err,
		}
	}

	var buf bytes.Buffer
	for {
		// get another chunk
		st, err := syncproto.SyncResponseObject[syncproto.SyncData](conn, syncproto.Packet_DATA)
		if err != nil {
			c.delConn(conn)
			return nil, &fs.PathError{
				Op:   "readfile",
				Path: name,
				Err:  err,
			}
		}

		// check if we don't have any chunks left
		if st == nil {
			break
		}

		// read a chunk
		buf.Grow(int(st.Size))
		if _, err := io.ReadFull(conn, buf.AvailableBuffer()[:st.Size]); err != nil {
			c.delConn(conn)
			return nil, &fs.PathError{
				Op:   "readfile",
				Path: name,
				Err:  err,
			}
		} else {
			buf.Write(buf.AvailableBuffer()[:st.Size])
		}
	}
	return buf.Bytes(), nil
}

type fsFile struct {
	c    *FS
	name string
	st   *syncproto.SyncStat1

	mu   sync.Mutex
	conn net.Conn
	buf  bytes.Buffer
	er   error
}

func (f *fsFile) Stat() (fs.FileInfo, error) {
	return &fsFileInfo{name: path.Base(f.name), st: f.st}, nil
}

func (f *fsFile) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if fsFileMode(f.st.Mode).IsDir() {
		return 0, &fs.PathError{
			Op:   "read",
			Path: f.name,
			Err:  errIsDirectory,
		}
	}
	if f.er != nil {
		return 0, f.er
	}

	if f.buf.Len() == 0 {
		// get another chunk
		st, err := syncproto.SyncResponseObject[syncproto.SyncData](f.conn, syncproto.Packet_DATA)
		if err != nil {
			f.c.delConn(f.conn)
			f.conn = nil
			f.er = &fs.PathError{
				Op:   "read",
				Path: f.name,
				Err:  err,
			}
			return 0, f.er
		}

		// check if we don't have any chunks left
		if st == nil {
			f.c.putConn(f.conn)
			f.conn = nil
			f.er = io.EOF
			return 0, f.er
		}

		// read a chunk
		f.buf.Grow(int(st.Size))
		if _, err := io.ReadFull(f.conn, f.buf.AvailableBuffer()[:st.Size]); err != nil {
			f.c.delConn(f.conn)
			f.conn = nil
			f.er = &fs.PathError{
				Op:   "read",
				Path: f.name,
				Err:  err,
			}
			return 0, f.er
		} else {
			f.buf.Write(f.buf.AvailableBuffer()[:st.Size])
		}
	}

	// read from our buffered chunk
	return f.buf.Read(p)
}

func (f *fsFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if !fsFileMode(f.st.Mode).IsDir() {
		return nil, &fs.PathError{
			Op:   "readdir",
			Path: f.name,
			Err:  errNotDirectory,
		}
	}
	return f.c.ReadDir(f.name)
}

func (f *fsFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.conn != nil {
		f.c.delConn(f.conn) // don't put a conn in a bad state back
		f.conn = nil
		f.er = fs.ErrClosed
	}
	return nil
}

type fsFileInfo struct {
	name string
	st   *syncproto.SyncStat1
}

func (f *fsFileInfo) Name() string {
	return f.name
}

func (f *fsFileInfo) Size() int64 {
	return int64(f.st.Size)
}

func (f *fsFileInfo) Mode() fs.FileMode {
	return fsFileMode(f.st.Mode)
}

func (f *fsFileInfo) ModTime() time.Time {
	return time.Unix(int64(f.st.Mtime), 0)
}

func (f *fsFileInfo) IsDir() bool {
	return f.Mode().IsDir()
}

func (f *fsFileInfo) Sys() any {
	return f.st
}

type fsDirEntry struct {
	name string
	st   *syncproto.SyncDent1
}

func (f *fsDirEntry) Name() string {
	return f.name
}

func (f *fsDirEntry) IsDir() bool {
	return f.Mode().IsDir()
}

func (f *fsDirEntry) Type() fs.FileMode {
	return fsFileMode(f.st.Mode).Type()
}

func (f *fsDirEntry) Info() (fs.FileInfo, error) {
	return f, nil
}

func (f *fsDirEntry) Size() int64 {
	return int64(f.st.Size)
}

func (f *fsDirEntry) Mode() fs.FileMode {
	return fsFileMode(f.st.Mode)
}

func (f *fsDirEntry) ModTime() time.Time {
	return time.Unix(int64(f.st.Mtime), 0)
}

func (f *fsDirEntry) Sys() any {
	return f.st
}

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
