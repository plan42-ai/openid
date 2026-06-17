// Package jwk provides helpers for working with JSON Web Keys (RFC 7517),
// including RFC 7638 JWK thumbprints.
package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// ErrUnsupportedKeyType is returned when a key's type or curve is not supported
// for thumbprint computation.
var ErrUnsupportedKeyType = errors.New("jwk: unsupported key type")

// Thumbprint computes the RFC 7638 JWK SHA-256 thumbprint of the given public
// key and returns it base64url-encoded without padding. This is the
// representation used for "kid" header values and the "jkt" confirmation claim.
//
// Supported key types are *ecdsa.PublicKey, *rsa.PublicKey and
// ed25519.PublicKey.
//
// See https://www.rfc-editor.org/rfc/rfc7638.
func Thumbprint(key crypto.PublicKey) (string, error) {
	canonical, err := canonicalJSON(key)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// ecThumbprint holds the required members of an EC JWK, declared in the
// lexicographic order (crv, kty, x, y) that RFC 7638 mandates for the hash input.
type ecThumbprint struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// rsaThumbprint holds the required members of an RSA JWK, declared in the
// lexicographic order (e, kty, n) that RFC 7638 mandates for the hash input.
type rsaThumbprint struct {
	E   string `json:"e"`
	Kty string `json:"kty"`
	N   string `json:"n"`
}

// okpThumbprint holds the required members of an OKP JWK, declared in the
// lexicographic order (crv, kty, x) that RFC 7638 mandates for the hash input.
type okpThumbprint struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
}

// canonicalJSON builds the RFC 7638 hash input for a key: a JSON object
// containing only the required members, with no whitespace and the member names
// in lexicographic order.
func canonicalJSON(key crypto.PublicKey) ([]byte, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		crv, err := curveName(k)
		if err != nil {
			return nil, err
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		return json.Marshal(ecThumbprint{
			Crv: crv,
			Kty: "EC",
			X:   base64.RawURLEncoding.EncodeToString(leftPad(k.X.Bytes(), size)),
			Y:   base64.RawURLEncoding.EncodeToString(leftPad(k.Y.Bytes(), size)),
		})
	case *rsa.PublicKey:
		return json.Marshal(rsaThumbprint{
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		})
	case ed25519.PublicKey:
		return json.Marshal(okpThumbprint{
			Crv: "Ed25519",
			Kty: "OKP",
			X:   base64.RawURLEncoding.EncodeToString(k),
		})
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKeyType, key)
	}
}

// curveName returns the JWK "crv" value for the key's curve (RFC 7518 6.2.1.1).
func curveName(key *ecdsa.PublicKey) (string, error) {
	// The JWK curve names match the names Go assigns to the standard curves.
	switch name := key.Curve.Params().Name; name {
	case "P-256", "P-384", "P-521":
		return name, nil
	default:
		return "", fmt.Errorf("%w: curve %q", ErrUnsupportedKeyType, name)
	}
}

// leftPad returns b left-padded with zero bytes to size. RFC 7518 requires the
// EC coordinates to be encoded at the full octet length of the curve so that the
// thumbprint is stable regardless of leading zero bytes.
func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
