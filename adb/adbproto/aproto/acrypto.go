package aproto

import (
	"crypto/md5"
	"crypto/rsa"
	"encoding"
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"
	"strings"
)

// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libcrypto_utils/android_pubkey.cpp;drc=61197364367c9e404c7da6900658f1b16c42d0da

const (
	// Size of an RSA modulus such as an encrypted block or a signature.
	PublicKeyModulusSize = 2048 / 8
	// Size of an encoded RSA key.
	PublicKeyEncodedSize = 3*4 + 2*PublicKeyModulusSize
)

// Android's custom RSA public key binary format. Public keys are stored as a
// sequence of little-endian 32 bit words.
type PublicKey struct {
	// Modulus length. This must be ANDROID_PUBKEY_MODULUS_SIZE.
	ModulusSizeWords uint32
	// Precomputed montgomery parameter: -1 / n[0] mod 2^32
	N0Inv uint32
	// RSA modulus as a little-endian array.
	Modulus [PublicKeyModulusSize]byte
	// Montgomery parameter R^2 as a little-endian array.
	RR [PublicKeyModulusSize]byte
	// RSA modulus: 3 or 65537
	Exponent uint32
}

var (
	_ encoding.BinaryUnmarshaler = (*PublicKey)(nil)
	_ encoding.BinaryAppender    = (*PublicKey)(nil)
	_ encoding.BinaryMarshaler   = (*PublicKey)(nil)
)

// NewPublicKey converts a Go RSA key into an Android pubkey, pre-computing some
// parameters.
func NewPublicKey(pub *rsa.PublicKey) (*PublicKey, error) {
	var k PublicKey

	if n := pub.Size(); n != PublicKeyModulusSize {
		return nil, fmt.Errorf("unsupported modulus size %d", n)
	}
	k.ModulusSizeWords = PublicKeyModulusSize / 4

	zero := big.NewInt(0)

	r32 := new(big.Int).SetBit(zero, 32, 1)

	n0inv := new(big.Int).Mod(pub.N, r32).ModInverse(pub.N, r32)
	k.N0Inv = uint32(n0inv.Sub(r32, n0inv).Uint64())

	mod := pub.N.Bytes()
	if len(mod) != PublicKeyModulusSize {
		panic("wtf")
	}
	slices.Reverse(mod)
	k.Modulus = [PublicKeyModulusSize]byte(mod)

	r := new(big.Int).SetBit(zero, PublicKeyModulusSize*8, 1)
	rr := new(big.Int).Mod(new(big.Int).Mul(r, r), pub.N).Bytes()
	if len(rr) != PublicKeyModulusSize {
		panic("wtf")
	}
	slices.Reverse(rr)
	k.RR = [PublicKeyModulusSize]byte(rr)

	k.Exponent = uint32(pub.E)

	return &k, nil
}

// GoPublicKey converts k to a Go RSA key. The pre-computed parameters are
// ignored.
func GoPublicKey(k *PublicKey) *rsa.PublicKey {
	m := k.Modulus
	slices.Reverse(m[:])
	return &rsa.PublicKey{
		N: big.NewInt(0).SetBytes(m[:]),
		E: int(k.Exponent),
	}
}

// UnmarshalBinary decodes an encoded pubkey. The pre-computed parameters are
// not verified. This is the inverse of MarshalBinary/AppendBinary.
func (k *PublicKey) UnmarshalBinary(buf []byte) error {
	if len(buf) != PublicKeyEncodedSize {
		return fmt.Errorf("incorrect pubkey length")
	}
	*k = PublicKey{
		ModulusSizeWords: binary.LittleEndian.Uint32(buf[0:]),
		N0Inv:            binary.LittleEndian.Uint32(buf[4:]),
		Modulus:          [PublicKeyModulusSize]byte(buf[8:]),
		RR:               [PublicKeyModulusSize]byte(buf[8+PublicKeyModulusSize:]),
		Exponent:         binary.LittleEndian.Uint32(buf[8+PublicKeyModulusSize*2:]),
	}
	return nil
}

// AppendBinary encodes a pubkey. The pre-computed parameters are not verified.
// This is the inverse of UnmarshalBinary.
func (k *PublicKey) AppendBinary(b []byte) ([]byte, error) {
	b = slices.Grow(b, PublicKeyEncodedSize)
	b = binary.LittleEndian.AppendUint32(b, k.ModulusSizeWords)
	b = binary.LittleEndian.AppendUint32(b, k.N0Inv)
	b = append(b, k.Modulus[:]...)
	b = append(b, k.RR[:]...)
	b = binary.LittleEndian.AppendUint32(b, k.Exponent)
	return b, nil
}

// MarshalBinary is like AppendBinary.
func (k *PublicKey) MarshalBinary() ([]byte, error) {
	return k.AppendBinary(nil)
}

// Fingerprint gets the MD5 fingerprint of the pubkey.
func (k *PublicKey) Fingerprint() string {
	var s strings.Builder
	s.Grow(md5.Size*3 - 1)
	b, _ := k.AppendBinary(nil)
	for i, c := range md5.Sum(b) {
		if i != 0 {
			s.WriteByte(':')
		}
		s.WriteByte("0123456789ABCDEF"[(c>>4)&0xf])
		s.WriteByte("0123456789ABCDEF"[c&0xf])
	}
	return s.String()
}
