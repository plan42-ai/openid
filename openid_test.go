package openid_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/plan42-ai/openid"
	"github.com/stretchr/testify/require"
)

// generateSelfSignedCert creates a test certificate for use in JWK tests.
func generateSelfSignedCert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, privateKey
}

func TestJwkMarshalUnmarshalRSA(t *testing.T) {
	// Generate RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create Jwk with RSA key
	original := openid.Jwk{
		KeyID:     "test-rsa-key",
		Use:       "sig",
		Algorithm: "RS256",
		KeyType:   "RSA",
		RSAKey:    &rsaKey.PublicKey,
	}

	// Marshal to JSON
	marshaledJSON, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back to Jwk
	var unmarshaled openid.Jwk
	err = json.Unmarshal(marshaledJSON, &unmarshaled)
	require.NoError(t, err)

	// Verify all fields match
	require.Equal(t, original.KeyID, unmarshaled.KeyID)
	require.Equal(t, original.Use, unmarshaled.Use)
	require.Equal(t, original.Algorithm, unmarshaled.Algorithm)
	require.Equal(t, original.KeyType, unmarshaled.KeyType)

	// Verify RSA key components
	require.NotNil(t, unmarshaled.RSAKey)
	require.Equal(t, original.RSAKey.N.String(), unmarshaled.RSAKey.N.String())
	require.Equal(t, original.RSAKey.E, unmarshaled.RSAKey.E)
}

func TestJwkMarshalUnmarshalECC(t *testing.T) {
	// Test with multiple ECC curves
	curves := []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()}

	for _, curve := range curves {
		t.Run(
			curve.Params().Name, func(t *testing.T) {
				// Generate ECC key
				eccKey, err := ecdsa.GenerateKey(curve, rand.Reader)
				require.NoError(t, err)

				// Create Jwk with ECC key
				original := openid.Jwk{
					KeyID:     "test-ecc-key-" + curve.Params().Name,
					Use:       "sig",
					Algorithm: "ES256",
					KeyType:   "EC",
					ECCKey:    &eccKey.PublicKey,
				}

				// Marshal to JSON
				marshaledJSON, err := json.Marshal(original)
				require.NoError(t, err)

				// Unmarshal back to Jwk
				var unmarshaled openid.Jwk
				err = json.Unmarshal(marshaledJSON, &unmarshaled)
				require.NoError(t, err)

				// Verify all fields match
				require.Equal(t, original.KeyID, unmarshaled.KeyID)
				require.Equal(t, original.Use, unmarshaled.Use)
				require.Equal(t, original.Algorithm, unmarshaled.Algorithm)
				require.Equal(t, original.KeyType, unmarshaled.KeyType)

				// Verify ECC key components
				require.NotNil(t, unmarshaled.ECCKey)
				require.Equal(t, original.ECCKey.Curve.Params().Name, unmarshaled.ECCKey.Curve.Params().Name)
				require.Equal(t, original.ECCKey.X.String(), unmarshaled.ECCKey.X.String())
				require.Equal(t, original.ECCKey.Y.String(), unmarshaled.ECCKey.Y.String())
			},
		)
	}
}

func TestJwkMarshalUnmarshalWithCertificate(t *testing.T) {
	// Generate certificate
	cert, _ := generateSelfSignedCert(t)

	// Create certificate URL
	certURL, err := url.Parse("https://example.com/cert")
	require.NoError(t, err)

	// Create Jwk with certificate
	original := openid.Jwk{
		KeyID:          "test-cert-key",
		Use:            "sig",
		Algorithm:      "RS256",
		KeyType:        "RSA",
		CertChain:      []*x509.Certificate{cert},
		CertificateURL: certURL,
	}

	// Marshal to JSON
	marshaledJSON, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back to Jwk
	var unmarshaled openid.Jwk
	err = json.Unmarshal(marshaledJSON, &unmarshaled)
	require.NoError(t, err)

	// Verify all fields match
	require.Equal(t, original.KeyID, unmarshaled.KeyID)
	require.Equal(t, original.Use, unmarshaled.Use)
	require.Equal(t, original.Algorithm, unmarshaled.Algorithm)
	require.Equal(t, original.KeyType, unmarshaled.KeyType)

	// Verify certificate chain
	require.Len(t, unmarshaled.CertChain, 1)
	require.Equal(t, cert.Subject.CommonName, unmarshaled.CertChain[0].Subject.CommonName)
	require.Equal(t, cert.SerialNumber.String(), unmarshaled.CertChain[0].SerialNumber.String())

	// Verify certificate URL
	require.NotNil(t, unmarshaled.CertificateURL)
	require.Equal(t, original.CertificateURL.String(), unmarshaled.CertificateURL.String())
}

func TestJwkMarshalUnmarshalWithCustomFields(t *testing.T) {
	// Create Jwk with custom fields
	original := openid.Jwk{
		KeyID:     "test-custom-fields",
		Use:       "sig",
		Algorithm: "RS256",
		KeyType:   "RSA",
		OtherFields: map[string]interface{}{
			"custom_field1": "custom_value1",
			"custom_field2": 12345,
			"custom_field3": true,
		},
	}

	// Marshal to JSON
	marshaledJSON, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back to Jwk
	var unmarshaled openid.Jwk
	err = json.Unmarshal(marshaledJSON, &unmarshaled)
	require.NoError(t, err)

	// Verify all fields match
	require.Equal(t, original.KeyID, unmarshaled.KeyID)
	require.Equal(t, original.Use, unmarshaled.Use)
	require.Equal(t, original.Algorithm, unmarshaled.Algorithm)
	require.Equal(t, original.KeyType, unmarshaled.KeyType)

	// Verify custom fields
	require.Contains(t, unmarshaled.OtherFields, "custom_field1")
	require.Equal(t, "custom_value1", unmarshaled.OtherFields["custom_field1"])
	require.Contains(t, unmarshaled.OtherFields, "custom_field2")
	require.Equal(t, float64(12345), unmarshaled.OtherFields["custom_field2"])
	require.Contains(t, unmarshaled.OtherFields, "custom_field3")
	require.Equal(t, true, unmarshaled.OtherFields["custom_field3"])
}

func TestJwkMarshalUnmarshalCombined(t *testing.T) {
	// Generate both RSA and ECC keys
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert, _ := generateSelfSignedCert(t)

	// Create thumbprints for testing
	sha1Thumbprint := []byte{0x01, 0x02, 0x03, 0x04}
	sha256Thumbprint := []byte{0x05, 0x06, 0x07, 0x08}

	// Create Jwk with all possible fields
	original := openid.Jwk{
		KeyID:            "test-combined-key",
		Use:              "sig",
		Algorithm:        "RS256",
		KeyType:          "RSA",
		RSAKey:           &rsaKey.PublicKey,
		CertChain:        []*x509.Certificate{cert},
		Sha1Thumbprint:   sha1Thumbprint,
		Sha256Thumbprint: sha256Thumbprint,
		OtherFields: map[string]interface{}{
			"custom_field": "custom_value",
		},
	}

	// Marshal to JSON
	marshaledJSON, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back to Jwk
	var unmarshaled openid.Jwk
	err = json.Unmarshal(marshaledJSON, &unmarshaled)
	require.NoError(t, err)

	// Verify core fields
	require.Equal(t, original.KeyID, unmarshaled.KeyID)
	require.Equal(t, original.Use, unmarshaled.Use)
	require.Equal(t, original.Algorithm, unmarshaled.Algorithm)
	require.Equal(t, original.KeyType, unmarshaled.KeyType)

	// Verify RSA key
	require.NotNil(t, unmarshaled.RSAKey)
	require.Equal(t, original.RSAKey.N.String(), unmarshaled.RSAKey.N.String())

	// Verify thumbprints
	require.Equal(t, original.Sha1Thumbprint, unmarshaled.Sha1Thumbprint)
	require.Equal(t, original.Sha256Thumbprint, unmarshaled.Sha256Thumbprint)

	// Verify certificate
	require.Len(t, unmarshaled.CertChain, 1)

	// Verify custom fields
	require.Contains(t, unmarshaled.OtherFields, "custom_field")
	require.Equal(t, "custom_value", unmarshaled.OtherFields["custom_field"])
}
