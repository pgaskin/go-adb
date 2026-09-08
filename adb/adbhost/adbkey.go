package adbhost

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// LoadUserKey loads the user's ADB private key (i.e., ~/.android/adbkey). Note
// that unlike ADB, it will not generate a new key if it does not exist.
func LoadUserKey() (crypto.Signer, error) {
	path, err := UserKeyPath()
	if err != nil {
		return nil, err
	}
	return LoadKey(path)
}

// UserKeyPath returns the path to the user's ADB private key (i.e.,
// ~/.android/adbkey). It does not check whether it exists.
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb_utils.cpp;l=310-320;drc=61197364367c9e404c7da6900658f1b16c42d0da
func UserKeyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".android", "adbkey"), nil
}

// LoadKey reads and parses the ADB private key at path.
func LoadKey(path string) (crypto.Signer, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := ParseKey(buf)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", path, err)
	}
	return key, nil
}

// ParseKey parses a PEM-encoded ADB private key.
//
// ADB generates adbkey as an unencrypted PKCS#8 PrivateKeyInfo ("PRIVATE KEY"),
// but reads it with PEM_read_RSAPrivateKey, which also accepts the legacy
// PKCS#1 RSA format ("RSA PRIVATE KEY").
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/client/auth.cpp;l=91-136;drc=1cf2f017d312f73b3dc53bda85ef2610e35a80e9
func ParseKey(b []byte) (crypto.Signer, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no pem block found")
	}
	switch blk.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("unsupported key type %T", key)
		}
		return signer, nil
	case "RSA PRIVATE KEY": // legacy
		return x509.ParsePKCS1PrivateKey(blk.Bytes)
	default:
		return nil, fmt.Errorf("unsupported pem block %q", blk.Type)
	}
}
