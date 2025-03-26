package adbproto

import "io/fs"

// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/sysdeps/errno.cpp;drc=af6fae67a49070ca75c26ceed5759576eb4d3573

type Errno uint32

const (
	EACCES       Errno = 13
	EEXIST       Errno = 17
	EFAULT       Errno = 14
	EFBIG        Errno = 27
	EINTR        Errno = 4
	EINVAL       Errno = 22
	EIO          Errno = 5
	EISDIR       Errno = 21
	ELOOP        Errno = 40
	EMFILE       Errno = 24
	ENAMETOOLONG Errno = 36
	ENFILE       Errno = 23
	ENOENT       Errno = 2
	ENOMEM       Errno = 12
	ENOSPC       Errno = 28
	ENOTDIR      Errno = 20
	EOVERFLOW    Errno = 75
	EPERM        Errno = 1
	EROFS        Errno = 30
	ETXTBSY      Errno = 26
)

func (e Errno) Is(target error) bool {
	switch target {
	case fs.ErrInvalid:
		return e == EINVAL
	case fs.ErrPermission:
		return e == EACCES || e == EPERM
	case fs.ErrExist:
		return e == EEXIST
	case fs.ErrNotExist:
		return e == ENOENT
	}
	return false
}
