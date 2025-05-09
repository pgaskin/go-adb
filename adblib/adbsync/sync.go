// Package adbsync wraps the sync protocol.
package adbsync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pgaskin/go-adb/adb"
	"github.com/pgaskin/go-adb/adb/adbproto"
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

	featuresOnce sync.Once
	compress     CompressionMethod
	decompress   CompressionMethod
	statv2       error
	lsv2         error
	srv2         error
}

// onceFeatures must be called by featuresOnce. It caches feature support to
// reduce allocations.
func (c *Client) onceFeatures() {
	c.compress = c.CompressionConfig.compressNegotiate(c.Server)
	c.decompress = c.CompressionConfig.decompressNegotiate(c.Server)
	c.statv2 = adb.SupportsFeature(c.Server, syncproto.Feature_stat_v2)
	c.lsv2 = adb.SupportsFeature(c.Server, syncproto.Feature_ls_v2)
	c.srv2 = adb.SupportsFeature(c.Server, syncproto.Feature_sendrecv_v2)
}

// TODO: context for requests, cancellation/timeouts

func (c *Client) getConn() (*syncConn, error) {
	c.featuresOnce.Do(c.onceFeatures)
	// TODO: connection pool
	ctx := context.Background()
	if c.ConnectTimeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, time.Now().Add(c.ConnectTimeout))
		defer cancel()
	}
	conn, err := c.Server.DialADB(ctx, "sync:")
	if err != nil {
		return nil, err
	}
	return &syncConn{
		client:            c,
		conn:              conn,
		compressionConfig: c.CompressionConfig,
		compress:          c.compress,
		decompress:        c.decompress,
	}, nil
}

func (c *Client) putConn(conn *syncConn) {
	if !conn.Usable() {
		conn.Close()
		return
	}
	conn.Close() // TODO: connection pool
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

// PathError records an error and the operation and file path that caused it.
type PathError = fs.PathError

var (
	ErrInvalid     = fs.ErrInvalid
	ErrPermission  = fs.ErrPermission
	ErrExist       = fs.ErrExist
	ErrNotExist    = fs.ErrNotExist
	ErrClosed      = fs.ErrClosed
	ErrUnsupported = errors.ErrUnsupported

	errNotDirectory = errors.New("not a directory")
	errIsDirectory  = errors.New("is a directory")
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
func (s *fileInfo) String() string     { return fs.FormatFileInfo(s) }

func dirEntry(f *fileInfo) DirEntry {
	return fs.FileInfoToDirEntry(f)
}

func fillFileInfoStat1(dst *fileInfo, src *syncproto.SyncStat1, name string) {
	dst.name = filepath.Base(name)
	dst.size = int64(src.Size)
	dst.mode = fsFileMode(src.Mode)
	dst.modTime = time.Unix(int64(src.Mtime), 0)
	dst.sys = src
}

func fillFileInfoStat2(dst *fileInfo, src *syncproto.SyncStat2, name string) {
	dst.name = filepath.Base(name)
	dst.size = int64(src.Size)
	dst.mode = fsFileMode(src.Mode)
	dst.modTime = time.Unix(src.Mtime, 0)
	dst.sys = src
}

func fillFileInfoDent1(dst *fileInfo, src *syncproto.SyncDent1, name string) {
	dst.name = filepath.Base(name)
	dst.size = int64(src.Size)
	dst.mode = fsFileMode(src.Mode)
	dst.modTime = time.Unix(int64(src.Mtime), 0)
	dst.sys = src
}

func fillFileInfoDent2(dst *fileInfo, src *syncproto.SyncDent2, name string) {
	dst.name = filepath.Base(name)
	dst.size = int64(src.Size)
	dst.mode = fsFileMode(src.Mode)
	dst.modTime = time.Unix(src.Mtime, 0)
	dst.sys = src
}

// fsFileMode converts an sync file mode into an [FileMode].
func fsFileMode(mode uint32) FileMode {
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
func syncFileMode(mode FileMode) uint32 {
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

// wrappedErr wraps an error from syncproto to match the stdlib error types.
type wrappedErr struct {
	sysErr error
	stdErr error
}

// maybeSyncFailError uses syncFailError if err is a non-wrapped SyncFail.
func maybeSyncFailError(err error) error {
	if err, ok := err.(syncproto.SyncFail); ok {
		return syncFailError(err)
	}
	return err
}

// syncFailError converts err to match stdlib errors if possible. This should be
// used where adb may use SendSyncFailErrno in file_sync_service.cpp.
func syncFailError(err syncproto.SyncFail) error {
	var stdErr error
	switch _, errno, _ := bionic.FromMsgSuffix(string(err)); errno {
	case "EINVAL":
		stdErr = ErrInvalid
	case "EPERM", "EACCES":
		stdErr = ErrPermission
	case "EEXIST":
		stdErr = ErrExist
	case "ENOENT":
		stdErr = ErrNotExist
	case "ENOSYS", "ENOTSUP", "EOPNOTSUPP":
		stdErr = ErrUnsupported
	}
	return &wrappedErr{
		stdErr: stdErr,
		sysErr: err,
	}
}

// errnoError converts errno to match stdlib errors if possible.
func errnoError(errno adbproto.Errno) error {
	if errno == 0 {
		return nil
	}
	var stdErr error
	switch errno {
	case adbproto.EINVAL:
		stdErr = ErrInvalid
	case adbproto.EPERM, adbproto.EACCES:
		stdErr = ErrPermission
	case adbproto.EEXIST:
		stdErr = ErrExist
	case adbproto.ENOENT:
		stdErr = ErrNotExist
	case 38, 95:
		stdErr = ErrUnsupported
	}
	return &wrappedErr{
		stdErr: stdErr,
		sysErr: errno,
	}
}

func (w *wrappedErr) Error() string {
	if w.stdErr == nil {
		return w.sysErr.Error()
	}
	return w.stdErr.Error() + ": " + w.sysErr.Error()
}

func (w *wrappedErr) Unwrap() error {
	return w.sysErr
}

func (w *wrappedErr) Is(target error) bool {
	if w.stdErr == nil {
		return false
	}
	if t, ok := target.(*wrappedErr); ok {
		return w.stdErr == t.stdErr
	}
	return w.stdErr == target
}

// Stat gets information about the specified file. If the file is a symbolic
// link, it follows it.
//
// This requires [syncproto.Feature_stat_v2].
func (c *Client) Stat(name string) (FileInfo, error) {
	conn, err := c.getConn()
	if err != nil {
		return nil, err
	}
	defer c.putConn(conn)

	if err := c.statv2; err != nil {
		return nil, &PathError{
			Op:   "stat",
			Path: name,
			Err:  err,
		}
	}
	return conn.Stat2(name)
}

// Lstat gets information about the specified file. If the file is a symbolic
// link, it returns information about the link itself.
//
// If [syncproto.Feature_stat_v2] is not supported, only mode, size, and mtime
// will be returned.
func (c *Client) Lstat(name string) (FileInfo, error) {
	conn, err := c.getConn()
	if err != nil {
		return nil, err
	}
	defer c.putConn(conn)

	if c.statv2 == nil {
		return conn.Lstat2(name)
	}
	return conn.Lstat1(name)
}

// ReadDir lists the specified directory, returning all its directory entries
// sorted by filename.
func (c *Client) ReadDir(name string) ([]DirEntry, error) {
	conn, err := c.getConn()
	if err != nil {
		return nil, err
	}
	defer c.putConn(conn)

	var de []DirEntry
	if c.lsv2 == nil {
		de, err = conn.List2(name)
	} else {
		de, err = conn.List1(name)
	}
	if err != nil {
		return nil, err
	}
	if len(de) == 0 {
		// DONE before any entries were seen could be an error or not found, so
		// try to stat the dir
		st, err := c.Lstat(name)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			return nil, &PathError{
				Op:   "list",
				Path: name,
				Err:  errNotDirectory,
			}
		}
	}
	slices.SortFunc(de, func(a, b DirEntry) int {
		return strings.Compare(a.Name(), b.Name())
	})
	return de, nil
}

// Open opens a reader for the specified file.
func (c *Client) Open(name string) (io.ReadCloser, error) {
	conn, err := c.getConn()
	if err != nil {
		return nil, err
	}
	if c.srv2 == nil {
		return conn.Recv2(name)
	}
	return conn.Recv1(name)
}

// Create opens a writer to the specified file. The error for the [io.Closer]
// must be checked to ensure the file was read successfully.
func (c *Client) Create(name string, mode FileMode) (io.WriteCloser, error) {
	conn, err := c.getConn()
	if err != nil {
		return nil, err
	}
	if c.srv2 == nil {
		return conn.Send1(name, mode)
	}
	return conn.Send2(name, mode)
}

// ReadFile reads the specified file and returns the contents.
func (c *Client) ReadFile(name string) ([]byte, error) {
	f, err := c.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf, err := io.ReadAll(f) // TODO: optimize for certain cases (e.g., read without compression directly into a bytes.Buffer)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// WriteFile writes data to the specified file, creating it if necessary.
func (c *Client) WriteFile(name string, data []byte, mode FileMode) error {
	f, err := c.Create(name, mode)
	if err != nil {
		return err
	}
	defer f.Close()

	// TODO: optimize for certain cases (e.g., write small single-data-message files all at once without compression)

	if _, err = f.Write(data); err != nil {
		return err
	}
	return f.Close()
}

// Symlink creates newname as a symbolic link to oldname.
func (c *Client) Symlink(oldname, newname string) error {
	if len(oldname) > syncproto.SyncDataMax {
		return fmt.Errorf("%w: name too long", ErrInvalid)
	}
	return c.WriteFile(newname, []byte(oldname), fs.ModeSymlink)
}

// syncConn wraps a single connection to the sync service.
//
// It can usually be reused after requests, but certain kinds of errors will
// terminate the connection.
type syncConn struct {
	client *Client
	conn   net.Conn
	closed error

	compressionConfig *CompressionConfig
	compress          CompressionMethod
	decompress        CompressionMethod
}

// TODO

// Close closes the connection.
func (c *syncConn) Close() error {
	if c.closed != nil {
		return c.closed
	}
	c.closed = net.ErrClosed
	return c.conn.Close()
}

// Usable returns true if the connection can be reused.
func (c *syncConn) Usable() bool {
	return c.closed == nil
}

// abort closes a connection as unusable due to reason.
func (c *syncConn) abort(err error, reason string) {
	if c.closed != nil {
		return
	}
	if errors.Is(err, net.ErrClosed) || reason == "" {
		c.closed = net.ErrClosed
	} else {
		c.closed = fmt.Errorf("%w (%s)", net.ErrClosed, reason)
	}
	c.conn.Close()
}

func (c *syncConn) Lstat1(name string) (FileInfo, error) {
	if c.closed != nil {
		return nil, c.closed
	}
	if err := syncproto.SyncRequest(c.conn, syncproto.Packet_LSTAT_V1, name); err != nil {
		c.abort(err, "lstat_v1 request protocol error")
		return nil, &PathError{
			Op:   "lstat_v1",
			Path: name,
			Err:  err,
		}
	}
	st, err := syncproto.SyncResponseObject[syncproto.SyncStat1](c.conn, syncproto.Packet_LSTAT_V1)
	if err != nil {
		c.abort(err, "lstat_v1 response protocol error")
		return nil, &PathError{
			Op:   "lstat_v1",
			Path: name,
			Err:  maybeSyncFailError(err),
		}
	}
	if *st == (syncproto.SyncStat1{}) {
		// connection is still usable; we have a response
		return nil, &PathError{
			Op:   "lstat_v1",
			Path: name,
			Err:  fmt.Errorf("%w (or permission denied)", ErrNotExist), // we have no way to tell from here with v1
		}
	}
	var fsStat fileInfo
	fillFileInfoStat1(&fsStat, st, name)
	return &fsStat, nil
}

func (c *syncConn) Lstat2(name string) (FileInfo, error) {
	if c.closed != nil {
		return nil, c.closed
	}
	if err := syncproto.SyncRequest(c.conn, syncproto.Packet_LSTAT_V2, name); err != nil {
		c.abort(err, "lstat_v2 request protocol error")
		return nil, &PathError{
			Op:   "lstat_v2",
			Path: name,
			Err:  err,
		}
	}
	st, err := syncproto.SyncResponseObject[syncproto.SyncStat2](c.conn, syncproto.Packet_LSTAT_V2)
	if err != nil {
		c.abort(err, "lstat_v2 response protocol error")
		return nil, &PathError{
			Op:   "lstat_v2",
			Path: name,
			Err:  maybeSyncFailError(err),
		}
	}
	if st.Error != 0 {
		return nil, &PathError{
			Op:   "lstat_v2",
			Path: name,
			Err:  errnoError(adbproto.Errno(st.Error)),
		}
	}
	var fsStat fileInfo
	fillFileInfoStat2(&fsStat, st, name)
	return &fsStat, nil
}

func (c *syncConn) Stat2(name string) (FileInfo, error) {
	if c.closed != nil {
		return nil, c.closed
	}
	if err := syncproto.SyncRequest(c.conn, syncproto.Packet_STAT_V2, name); err != nil {
		c.abort(err, "stat_v2 request protocol error")
		return nil, &PathError{
			Op:   "stat_v2",
			Path: name,
			Err:  err,
		}
	}
	st, err := syncproto.SyncResponseObject[syncproto.SyncStat2](c.conn, syncproto.Packet_STAT_V2)
	if err != nil {
		c.abort(err, "lstat_v2 response protocol error")
		return nil, &PathError{
			Op:   "stat_v2",
			Path: name,
			Err:  maybeSyncFailError(err),
		}
	}
	if st.Error != 0 {
		return nil, &PathError{
			Op:   "stat_v2",
			Path: name,
			Err:  errnoError(adbproto.Errno(st.Error)),
		}
	}
	var fsStat fileInfo
	fillFileInfoStat2(&fsStat, st, name)
	return &fsStat, nil
}

func (c *syncConn) List1(name string) ([]DirEntry, error) {
	if c.closed != nil {
		return nil, c.closed
	}
	if err := syncproto.SyncRequest(c.conn, syncproto.Packet_LIST_V1, name); err != nil {
		c.abort(err, "list_v1 request protocol error")
		return nil, &PathError{
			Op:   "list_v1",
			Path: name,
			Err:  err,
		}
	}
	var de []DirEntry
	for {
		st, err := syncproto.SyncResponseObject[syncproto.SyncDent1](c.conn, syncproto.Packet_DENT_V1)
		if err != nil {
			c.abort(err, "list_v1 response protocol error")
			return nil, &PathError{
				Op:   "list_v1_dent",
				Path: name,
				Err:  maybeSyncFailError(err),
			}
		}
		if st == nil {
			break
		}

		nb := make([]byte, st.Namelen)
		if _, err := io.ReadFull(c.conn, nb); err != nil {
			c.abort(err, "list_v1 response protocol error")
			return nil, &PathError{
				Op:   "list_v1_dent",
				Path: name,
				Err:  adbproto.ProtocolErrorf("read dent_v1 name: %w", err),
			}
		}
		if string(nb) == "." || string(nb) == ".." {
			continue
		}

		// note: list v1 ignores dents which fail lstat

		var fsStat fileInfo
		fillFileInfoDent1(&fsStat, st, string(nb))
		de = append(de, dirEntry(&fsStat))
	}
	if len(de) == 0 {
		// opendir error or not found
	}
	return de, nil
}

func (c *syncConn) List2(name string) ([]DirEntry, error) {
	if c.closed != nil {
		return nil, c.closed
	}
	if err := syncproto.SyncRequest(c.conn, syncproto.Packet_LIST_V2, name); err != nil {
		c.abort(err, "list_v2 request protocol error")
		return nil, &PathError{
			Op:   "list_v2",
			Path: name,
			Err:  err,
		}
	}
	var de []DirEntry
	for {
		st, err := syncproto.SyncResponseObject[syncproto.SyncDent2](c.conn, syncproto.Packet_DENT_V2)
		if err != nil {
			c.abort(err, "list_v2 response protocol error")
			return nil, &PathError{
				Op:   "list_v2_dent",
				Path: name,
				Err:  maybeSyncFailError(err),
			}
		}
		if st == nil {
			break
		}

		nb := make([]byte, st.Namelen)
		if _, err := io.ReadFull(c.conn, nb); err != nil {
			c.abort(err, "list_v2 response protocol error")
			return nil, &PathError{
				Op:   "list_v2_dent",
				Path: name,
				Err:  adbproto.ProtocolErrorf("read dent_v2 name: %w", err),
			}
		}
		if string(nb) == "." || string(nb) == ".." {
			continue
		}

		if st.Error != 0 {
			// this error comes from lstat, so it will keep returning more
			// dirents which we aren't reading since we return on the first
			// error
			//
			// to match the stdlib os.ReadDir, we'll return the error
			// immediately, unless it's due to the dent not exisitng between
			// readdir and lstat
			if adbproto.Errno(st.Error) != adbproto.ENOENT {
				c.abort(err, "list_v2 dent stat error, not continuing read")
				return nil, &PathError{
					Op:   "list_v2_dent",
					Path: string(nb),
					Err:  errnoError(adbproto.Errno(st.Error)),
				}
			}
		}

		var fsStat fileInfo
		fillFileInfoDent2(&fsStat, st, string(nb))
		de = append(de, dirEntry(&fsStat))
	}
	if len(de) == 0 {
		// opendir error or not found
	}
	return de, nil
}

func (c *syncConn) Send1(name string, mode FileMode) (io.WriteCloser, error) {
	return nil, errors.ErrUnsupported // TODO
}

func (c *syncConn) Send2(name string, mode FileMode) (io.WriteCloser, error) {
	return nil, errors.ErrUnsupported // TODO
}

func (c *syncConn) Recv1(name string) (io.ReadCloser, error) {
	if err := syncproto.SyncRequest(c.conn, syncproto.Packet_RECV_V1, name); err != nil {
		c.abort(err, "recv_v1 request protocol error")
		return nil, &PathError{
			Op:   "recv_v1",
			Path: name,
			Err:  err,
		}
	}
	return &syncConnFileReader{
		name: name,
		op:   "recv_v1",
		conn: c,
		r:    io.NopCloser(syncproto.SyncDataReader(c.conn)),
	}, nil
}

func (c *syncConn) Recv2(name string) (io.ReadCloser, error) {
	if err := syncproto.SyncRequest(c.conn, syncproto.Packet_RECV_V2, name); err != nil {
		c.abort(err, "recv_v2 request protocol error")
		return nil, &PathError{
			Op:   "recv_v2",
			Path: name,
			Err:  err,
		}
	}
	if err := syncproto.SyncRequestObject(c.conn, syncproto.Packet_RECV_V2, syncproto.SyncRecv2{
		Flags: c.decompress.syncFlag(),
	}); err != nil {
		c.abort(err, "recv_v2 request protocol error")
		return nil, &PathError{
			Op:   "recv_v2",
			Path: name,
			Err:  err,
		}
	}
	if c.decompress == compressionMethodNone {
		return &syncConnFileReader{
			name: name,
			op:   "recv_v2",
			conn: c,
			r:    io.NopCloser(syncproto.SyncDataReader(c.conn)),
		}, nil
	}
	dec, err := c.compressionConfig.decompress(c.decompress, syncproto.SyncDataReader(c.conn))
	if err != nil {
		c.abort(err, "recv_v2 decompression error")
		return nil, &PathError{
			Op:   "recv_v2",
			Path: name,
			Err:  err,
		}
	}
	return &syncConnFileReader{
		name: name,
		op:   "recv_v2_" + string(c.decompress),
		conn: c,
		r:    dec,
	}, nil
}

type syncConnFileReader struct {
	name string
	op   string
	mu   sync.Mutex
	conn *syncConn
	r    io.ReadCloser // the closer part is for decompressors which do verification/etc on close
	err  error
}

func (r *syncConnFileReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.conn == nil {
		return 0, net.ErrClosed
	}

	if r.err != nil {
		return 0, r.err
	}

	n, err := r.r.Read(p)
	if err != nil {
		// return the conn to the pool
		if err != io.EOF {
			r.conn.abort(err, "recv data protocol error")
			r.conn.client.putConn(r.conn)
			r.conn = nil
		} else {
			r.conn.client.putConn(r.conn)
			r.conn = nil
		}
		// check for decompressor errors if EOF
		if err == io.EOF {
			err = r.r.Close()
			if err == nil {
				err = io.EOF
			}
			r.r = nil
		}
		// wrap the error if not EOF
		if err != io.EOF {
			err = &PathError{
				Op:   r.op,
				Path: r.name,
				Err:  maybeSyncFailError(err),
			}
		}
		// set the sticky error
		r.err = err
	}
	return n, err
}

func (r *syncConnFileReader) Close() error {
	if r.r != nil {
		_ = r.r.Close() // ignore errors from a decompressor
	}
	if r.conn != nil {
		r.conn.abort(net.ErrClosed, "")
		r.conn.client.putConn(r.conn)
		r.conn = nil
	}
	return nil
}
