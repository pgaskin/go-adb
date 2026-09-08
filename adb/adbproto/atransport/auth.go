package atransport

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"slices"
	"strings"

	"github.com/pgaskin/go-adb/adb/adbproto/aproto"
)

// encodePublicKey encodes the public half of key as an A_AUTH AuthRSAPublicKey
// payload. If name is empty, "user@host" is used.
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/crypto/rsa_2048_key.cpp;l=26-50;drc=61197364367c9e404c7da6900658f1b16c42d0da
func encodePublicKey(key crypto.Signer, name string) ([]byte, error) {
	pub, ok := key.Public().(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported key type %T", key.Public())
	}
	pkey, err := aproto.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = defaultPublicKeyName()
	}
	buf := aproto.AppendPublicKey(nil, pkey, name)
	return append(buf, 0), nil // adbd expects a null-terminated string
}

// defaultPublicKeyName returns "user@host" like ADB.
func defaultPublicKeyName() string {
	username := "unknown"
	if u, err := user.Current(); err == nil && u.Username != "" {
		username = u.Username
	}
	hostname := "unknown"
	if h, err := os.Hostname(); err == nil && h != "" {
		hostname = h
	}
	return username + "@" + hostname
}

// clientTLSConfig returns the TLS config used for the A_STLS handshake.
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/tls/tls_connection.cpp;l=209-231;drc=61197364367c9e404c7da6900658f1b16c42d0da
func (t *Transport) clientTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // self-signed

		// the device sends a CA list with the fingerprints of the authorized
		// keys... if we don't have a matching one, present the first key (like
		// adb_tls_set_certificate)
		//
		// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/client/auth.cpp;l=510-556;drc=61197364367c9e404c7da6900658f1b16c42d0da
		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if len(t.keys) == 0 {
				return &tls.Certificate{}, nil // no certificate (the device might not require auth)
			}
			key := t.keys[0]
			if match := matchCA(t.keys, cri.AcceptableCAs); match != nil {
				key = match
			}
			cert, err := aproto.GenerateCertificate(key)
			if err != nil {
				return nil, fmt.Errorf("generate client certificate: %w", err)
			}
			return &tls.Certificate{
				Certificate: [][]byte{cert},
				PrivateKey:  key,
			}, nil
		},
	}
}

// matchCA returns the first key matching an adb-encoded key fingerprint in the
// CA issuer list, if any.
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/tls/adb_ca_list.cpp;drc=61197364367c9e404c7da6900658f1b16c42d0da
func matchCA(keys []crypto.Signer, cas [][]byte) crypto.Signer {
	if len(cas) == 0 {
		return nil
	}

	fingerprints := make(map[string]crypto.Signer, len(keys))
	for _, key := range keys {
		der, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			continue
		}
		sum := sha256.Sum256(der)
		fingerprints[strings.ToUpper(hex.EncodeToString(sum[:]))] = key
	}

	for _, raw := range cas {
		var rdns pkix.RDNSequence
		if rest, err := asn1.Unmarshal(raw, &rdns); err != nil || len(rest) != 0 {
			continue
		}
		var name pkix.Name
		name.FillFromRDNSequence(&rdns)
		if !slices.Contains(name.Organization, "AdbKey-0") {
			continue
		}
		if key, ok := fingerprints[name.CommonName]; ok {
			return key
		}
	}
	return nil
}
