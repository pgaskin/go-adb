package adbsync

import (
	"bytes"
	"io"
	"io/fs"
)

type fsImpl struct {
	c *Client
}

var (
	_ fs.FS          = (*fsImpl)(nil)
	_ fs.StatFS      = (*fsImpl)(nil)
	_ fs.ReadDirFS   = (*fsImpl)(nil)
	_ fs.ReadFileFS  = (*fsImpl)(nil)
	_ fs.File        = (*fsFileImpl)(nil)
	_ fs.ReadDirFile = (*fsFileImpl)(nil)
)

// FS implements [io/fs.FS] for an ADB device.
func FS(c *Client) fs.FS {
	return &fsImpl{c}
}

func (f *fsImpl) transform(op, name string) (string, error) {
	if name == "." {
		return "/", nil
	}
	if !fs.ValidPath(name) {
		return "", &PathError{
			Op:   op,
			Path: name,
			Err:  ErrInvalid,
		}
	}
	return "/" + name, nil
}

func (f *fsImpl) Stat(name string) (fs.FileInfo, error) {
	name, err := f.transform("stat", name)
	if err != nil {
		return nil, err
	}
	r, err := f.c.Lstat(name)
	if err != nil {
		if err, ok := err.(*PathError); ok {
			err.Path = name
		}
	}
	return r, err
}

func (f *fsImpl) ReadDir(name string) ([]fs.DirEntry, error) {
	name, err := f.transform("open", name)
	if err != nil {
		return nil, err
	}
	r, err := f.c.ReadDir(name)
	if err != nil {
		if err, ok := err.(*PathError); ok {
			err.Path = name
		}
	}
	return r, err
}

func (f *fsImpl) ReadFile(name string) ([]byte, error) {
	name, err := f.transform("open", name)
	if err != nil {
		return nil, err
	}
	r, err := f.c.ReadFile(name)
	if err != nil {
		if err, ok := err.(*PathError); ok {
			err.Path = name
		}
	}
	return r, err
}

type fsFileImpl struct {
	name string
	fs   *fsImpl
	fi   FileInfo
	fm   FileMode
	fr   io.ReadCloser
	de   []DirEntry
}

func (f *fsImpl) Open(name string) (fs.File, error) {
	name, err := f.transform("open", name)
	if err != nil {
		return nil, err
	}
	ff := &fsFileImpl{
		name: name,
		fs:   f,
	}
	// Open follows symlinks (see golang.org/issue/45470), but only sync v2
	// supports that, so we'll just check if it's a symlink and error in that
	// case for the operations which depend on it (reading the file doesn't, so
	// we won't unnecessarily error there)
	if f.c.featuresOnce.Do(f.c.onceFeatures); f.c.statv2 == nil {
		ff.fi, err = f.c.Stat(name) // open follows symlinks (see golang.org/issue/45470)
		if err != nil {
			if err, ok := err.(*PathError); ok {
				err.Path = name
			}
			return nil, err
		}
	} else {
		ff.fi, err = f.c.Lstat(name)
		if err != nil {
			if err, ok := err.(*PathError); ok {
				err.Path = name
			}
			return nil, err
		}
	}
	ff.fm = ff.fi.Mode()
	if ff.fm&fs.ModeDir == 0 {
		ff.fr, err = f.c.Open(name)
		if err != nil && ff.fm&fs.ModeSymlink != 0 {
			//	- if we got a symlink, it's from lstat since stat_v2 wasn't supported
			//	- the symlink could point to a directory or file
			//	- adb doesn't return an error when trying to read a directory as a file
			//	- so just do this for all cases like this for consistency (we'll only hit it in the rare cases stat_v2 isn't supported AND the file is a symlink to a directory)
			ff.fr, err = io.NopCloser(bytes.NewReader(nil)), nil
		}
		if err != nil {
			if err, ok := err.(*PathError); ok {
				err.Path = name
			}
			return nil, err
		}
	}
	return ff, nil
}

func (f *fsFileImpl) Stat() (fs.FileInfo, error) {
	if f.fm&fs.ModeSymlink != 0 {
		if f.fs.c.statv2 == nil {
			panic("expected statv2 error for symlink")
		}
		return nil, &fs.PathError{
			Op:   "read",
			Path: f.name,
			Err: &wrappedErr{
				sysErr: ErrUnsupported,
				stdErr: f.fs.c.statv2,
			},
		}
	}
	return f.fi, nil
}

func (f *fsFileImpl) Read(p []byte) (n int, err error) {
	if f.fm&fs.ModeDir != 0 {
		return 0, &fs.PathError{
			Op:   "read",
			Path: f.name,
			Err:  errIsDirectory,
		}
	}
	if f.fr == nil {
		panic("expected reader for non-dir")
	}
	return f.fr.Read(p)
}

func (f *fsFileImpl) ReadDir(n int) ([]fs.DirEntry, error) {
	if f.fm&(fs.ModeDir|fs.ModeSymlink) == 0 { // see the comment in Open about the symlink case
		return nil, &fs.PathError{
			Op:   "readdir",
			Path: f.name,
			Err:  errNotDirectory,
		}
	}
	if f.de == nil {
		de, err := f.fs.c.ReadDir(f.name)
		if err != nil {
			if err, ok := err.(*PathError); ok {
				err.Path = f.name
			}
			return nil, err
		}
		if de == nil {
			de = []DirEntry{}
		}
		f.de = de
	}
	if n == 0 {
		return nil, nil
	}
	if n > 0 && len(f.de) == 0 {
		return nil, io.EOF
	}
	if n < 0 || n > len(f.de) {
		n = len(f.de)
	}
	de := f.de[:n]
	f.de = f.de[n:]
	return de, nil
}

func (f *fsFileImpl) Close() error {
	if f.fr == nil {
		return nil
	}
	return f.fr.Close()
}
