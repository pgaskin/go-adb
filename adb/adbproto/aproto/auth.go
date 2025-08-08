package aproto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"
)

// ParsePublicKey parses an ADB public key.
func ParsePublicKey(buf []byte) (key *PublicKey, name string, err error) {
	// split on space or tab
	for i, b := range buf {
		if b == ' ' || b == '\t' {
			name = string(buf[i+1:])
			buf = buf[:i]
			break
		}
	}

	// check length
	if act, exp := len(buf), base64.StdEncoding.EncodedLen(PublicKeyEncodedSize); act != exp {
		return nil, name, fmt.Errorf("incorrect encoded pubkey length (act=%d exp=%d)", act, exp)
	}

	// decode pubkey base64
	var tmp [PublicKeyEncodedSize]byte
	if _, err := base64.StdEncoding.Decode(tmp[:], buf); err != nil {
		return nil, name, err
	}

	// decode pubkey
	key = new(PublicKey)
	if err := key.UnmarshalBinary(tmp[:]); err != nil {
		return nil, name, err
	}
	return key, name, err
}

// AppendPublicKey formats an ADB public key.
func AppendPublicKey(b []byte, key *PublicKey, name string) []byte {
	tmp, _ := key.AppendBinary(b) // will never error
	b = base64.StdEncoding.AppendEncode(b, tmp)
	if name != "" {
		b = append(b, ' ')
		b = append(b, name...)
	}
	return b
}

// GenerateCertificate generates a enw certificate for an ADB daemon.
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/crypto/x509_generator.cpp;l=34-122;drc=61197364367c9e404c7da6900658f1b16c42d0da
func GenerateCertificate(pkey *rsa.PrivateKey) ([]byte, error) {
	cert := &x509.Certificate{
		Version: 2,

		SerialNumber: big.NewInt(1),
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Now().Add(time.Second * time.Duration(10*365*24*60*60)),

		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Android"},
			CommonName:   "Adb",
		},

		BasicConstraintsValid: true,
		IsCA:                  true,

		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId: []byte("hash"),
	}
	return x509.CreateCertificate(rand.Reader, cert, cert, &pkey.PublicKey, pkey)
}
