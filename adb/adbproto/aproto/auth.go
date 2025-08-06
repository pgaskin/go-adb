package aproto

import (
	"encoding/base64"
	"fmt"
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
