package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// rfc7638Modulus and rfc7638Thumbprint are the worked example from RFC 7638
// Section 3.1 (an RSA key with e=AQAB / 65537).
const (
	rfc7638Modulus    = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	rfc7638Thumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
)

func TestThumbprintRFC7638RSAExample(t *testing.T) {
	modulus, err := base64.RawURLEncoding.DecodeString(rfc7638Modulus)
	require.NoError(t, err)
	key := &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulus),
		E: 65537,
	}
	got, err := Thumbprint(key)
	require.NoError(t, err)
	require.Equal(t, rfc7638Thumbprint, got)
}

func TestThumbprintECCanonicalForm(t *testing.T) {
	// A P-256 key whose Y coordinate has a leading zero byte, exercising the
	// fixed-length padding required by RFC 7518.
	key := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(bytesOfLen(t, 0x11, 32)),
		Y:     new(big.Int).SetBytes(bytesOfLen(t, 0x22, 31)),
	}
	canonical, err := canonicalJSON(key)
	require.NoError(t, err)

	x := base64.RawURLEncoding.EncodeToString(leftPad(key.X.Bytes(), 32))
	y := base64.RawURLEncoding.EncodeToString(leftPad(key.Y.Bytes(), 32))
	want := `{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`
	require.Equal(t, want, string(canonical))
	// Padding must produce 32-byte (43 base64url char) coordinates.
	require.Len(t, leftPad(key.Y.Bytes(), 32), 32)
}

func TestThumbprintDeterministicAndDistinct(t *testing.T) {
	k1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	k2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t1a, err := Thumbprint(&k1.PublicKey)
	require.NoError(t, err)
	t1b, err := Thumbprint(&k1.PublicKey)
	require.NoError(t, err)
	t2, err := Thumbprint(&k2.PublicKey)
	require.NoError(t, err)

	require.Equal(t, t1a, t1b, "same key must produce the same thumbprint")
	require.NotEqual(t, t1a, t2, "different keys must produce different thumbprints")
}

func TestThumbprintEd25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	got, err := Thumbprint(pub)
	require.NoError(t, err)
	require.NotEmpty(t, got)
}

func TestThumbprintUnsupportedKeyType(t *testing.T) {
	_, err := Thumbprint("not a key")
	require.ErrorIs(t, err, ErrUnsupportedKeyType)
}

// bytesOfLen returns a slice of length n filled with b.
func bytesOfLen(t *testing.T, b byte, n int) []byte {
	t.Helper()
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
