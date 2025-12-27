package jwt_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/plan42-ai/openid/internal/util"
	"github.com/plan42-ai/openid/jwt"
	"github.com/stretchr/testify/require"
)

func TestParseValidToken(t *testing.T) {
	// Create valid header
	headerMap := map[string]interface{}{
		"alg": "HS256",
		"kid": "test-key-id",
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(headerMap)
	require.NoError(t, err)
	headerBase64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Create valid payload
	now := time.Now()
	payloadMap := map[string]interface{}{
		"iss":    "https://issuer.example.com",
		"sub":    "test-subject",
		"aud":    "test-audience",
		"exp":    now.Add(time.Hour).Unix(),
		"nbf":    now.Unix(),
		"iat":    now.Unix(),
		"jti":    "test-id",
		"custom": "claim",
	}
	payloadJSON, err := json.Marshal(payloadMap)
	require.NoError(t, err)
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create signature
	signature := []byte("test-signature")
	signatureBase64 := base64.RawURLEncoding.EncodeToString(signature)

	// Combine parts
	tokenString := headerBase64 + "." + payloadBase64 + "." + signatureBase64

	// Parse token
	token, err := jwt.Parse(tokenString)
	require.NoError(t, err)
	require.NotNil(t, token)

	// Verify header
	require.Equal(t, "HS256", token.Header.Algorithm)
	require.Equal(t, "test-key-id", token.Header.KeyID)
	require.Equal(t, "JWT", token.Header.Type)

	// Verify payload
	require.Equal(t, util.Must(url.Parse("https://issuer.example.com")), token.Payload.Issuer)
	require.Equal(t, "test-subject", token.Payload.Subject)
	require.Equal(t, "test-audience", token.Payload.Audience)
	require.Equal(t, "test-id", token.Payload.ID)
	require.Equal(t, "claim", token.Payload.CustomClaims["custom"])

	// Verify signature
	require.Equal(t, signature, token.Signature)
}

func TestParseInvalidTokenFormat(t *testing.T) {
	invalidTokens := []string{
		"header.payload",                 // Missing signature
		"single",                         // Only one part
		"",                               // Empty token
		"header.payload.signature.extra", // Too many parts
	}

	for _, token := range invalidTokens {
		_, err := jwt.Parse(token)
		require.Error(t, err)
		require.ErrorIs(t, err, jwt.ErrInvalidToken)
	}
}

func TestParseInvalidBase64Encoding(t *testing.T) {
	validBase64 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	invalidBase64 := "[invalid-base64]"
	validSignature := base64.RawURLEncoding.EncodeToString([]byte("signature"))

	// Test invalid header
	_, err := jwt.Parse(invalidBase64 + "." + validBase64 + "." + validSignature)
	require.Error(t, err)
	require.ErrorIs(t, err, jwt.ErrInvalidToken)

	// Test invalid payload
	_, err = jwt.Parse(validBase64 + "." + invalidBase64 + "." + validSignature)
	require.Error(t, err)
	require.ErrorIs(t, err, jwt.ErrInvalidToken)

	// Test invalid signature
	_, err = jwt.Parse(validBase64 + "." + validBase64 + "." + invalidBase64)
	require.Error(t, err)
	require.ErrorIs(t, err, jwt.ErrInvalidToken)
}

func TestParseInvalidJSON(t *testing.T) {
	invalidJSON := base64.URLEncoding.EncodeToString([]byte(`not valid json`))
	validBase64 := base64.URLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	validSignature := base64.URLEncoding.EncodeToString([]byte("signature"))

	// Test invalid header JSON
	_, err := jwt.Parse(invalidJSON + "." + validBase64 + "." + validSignature)
	require.Error(t, err)
	require.ErrorIs(t, err, jwt.ErrInvalidToken)

	// Test invalid payload JSON
	_, err = jwt.Parse(validBase64 + "." + invalidJSON + "." + validSignature)
	require.Error(t, err)
	require.ErrorIs(t, err, jwt.ErrInvalidToken)
}

func TestHeaderMarshalJSON(t *testing.T) {
	header := jwt.Header{
		Algorithm: "HS256",
		KeyID:     "test-key-id",
		Type:      "JWT",
		OtherFields: map[string]interface{}{
			"custom": "value",
		},
	}

	jsonData, err := json.Marshal(header)
	require.NoError(t, err)

	// Unmarshal to verify structure
	var result map[string]interface{}
	err = json.Unmarshal(jsonData, &result)
	require.NoError(t, err)

	require.Equal(t, "HS256", result["alg"])
	require.Equal(t, "test-key-id", result["kid"])
	require.Equal(t, "JWT", result["typ"])
	require.Equal(t, "value", result["custom"])
}

func TestHeaderUnmarshalJSON(t *testing.T) {
	jsonData := []byte(`{"alg":"HS256","kid":"test-key-id","typ":"JWT","custom":"value"}`)

	var header jwt.Header
	err := json.Unmarshal(jsonData, &header)
	require.NoError(t, err)

	require.Equal(t, "HS256", header.Algorithm)
	require.Equal(t, "test-key-id", header.KeyID)
	require.Equal(t, "JWT", header.Type)
	require.Equal(t, "value", header.OtherFields["custom"])

	// Verify that known header fields are not present in the OtherFields map
	require.NotContains(t, header.OtherFields, "alg")
	require.NotContains(t, header.OtherFields, "kid")
	require.NotContains(t, header.OtherFields, "typ")
}

func TestPayloadMarshalJSON(t *testing.T) {
	now := time.Now().Truncate(time.Second) // Truncate to avoid sub-second precision differences

	payload := jwt.Payload{
		Issuer:     util.Must(url.Parse("https://issuer.example.com")),
		Subject:    "test-subject",
		Audience:   "test-audience",
		Expiration: now.Add(time.Hour),
		NotBefore:  now,
		IssuedAt:   now,
		ID:         "test-id",
		CustomClaims: map[string]interface{}{
			"custom": "claim",
		},
	}

	jsonData, err := json.Marshal(payload)
	require.NoError(t, err)

	// Unmarshal to verify structure
	var result map[string]interface{}
	err = json.Unmarshal(jsonData, &result)
	require.NoError(t, err)

	require.Equal(t, "https://issuer.example.com", result["iss"])
	require.Equal(t, "test-subject", result["sub"])
	require.Equal(t, "test-audience", result["aud"])
	require.Equal(t, float64(now.Add(time.Hour).Unix()), result["exp"])
	require.Equal(t, float64(now.Unix()), result["nbf"])
	require.Equal(t, float64(now.Unix()), result["iat"])
	require.Equal(t, "test-id", result["jti"])
	require.Equal(t, "claim", result["custom"])
}

func TestPayloadUnmarshalJSON(t *testing.T) {
	now := time.Now().Truncate(time.Second) // Truncate to avoid sub-second precision differences

	jsonData := []byte(fmt.Sprintf(
		`{
			"iss": "https://issuer.example.com",
			"sub": "test-subject",
			"aud": "test-audience",
			"exp": %d,
			"nbf": %d,
			"iat": %d,
			"jti": "test-id",
			"custom": "claim"
		}`,
		now.Add(time.Hour).Unix(),
		now.Unix(),
		now.Unix(),
	))

	var payload jwt.Payload
	err := json.Unmarshal(jsonData, &payload)
	require.NoError(t, err)

	require.Equal(t, util.Must(url.Parse("https://issuer.example.com")), payload.Issuer)
	require.Equal(t, "test-subject", payload.Subject)
	require.Equal(t, "test-audience", payload.Audience)
	require.Equal(t, now.Add(time.Hour).Unix(), payload.Expiration.Unix())
	require.Equal(t, now.Unix(), payload.NotBefore.Unix())
	require.Equal(t, now.Unix(), payload.IssuedAt.Unix())
	require.Equal(t, "test-id", payload.ID)
	require.Equal(t, "claim", payload.CustomClaims["custom"])

	// Verify that well-known claims are not present in the CustomClaims map
	require.NotContains(t, payload.CustomClaims, "iss")
	require.NotContains(t, payload.CustomClaims, "sub")
	require.NotContains(t, payload.CustomClaims, "aud")
	require.NotContains(t, payload.CustomClaims, "exp")
	require.NotContains(t, payload.CustomClaims, "nbf")
	require.NotContains(t, payload.CustomClaims, "iat")
	require.NotContains(t, payload.CustomClaims, "jti")
}

func TestPayloadUnmarshalJSONEmptyIssuer(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	jsonData := []byte(fmt.Sprintf(
		`{
                        "iss": "",
                        "sub": "test-subject",
                        "aud": "test-audience",
                        "exp": %d,
                        "nbf": %d,
                        "iat": %d,
                        "jti": "test-id"
               }`,
		now.Add(time.Hour).Unix(),
		now.Unix(),
		now.Unix(),
	))

	var payload jwt.Payload
	err := json.Unmarshal(jsonData, &payload)
	require.NoError(t, err)

	require.Nil(t, payload.Issuer)
	require.Equal(t, "test-subject", payload.Subject)
	require.Equal(t, "test-audience", payload.Audience)
	require.Equal(t, now.Add(time.Hour).Unix(), payload.Expiration.Unix())
	require.Equal(t, now.Unix(), payload.NotBefore.Unix())
	require.Equal(t, now.Unix(), payload.IssuedAt.Unix())
	require.Equal(t, "test-id", payload.ID)

	require.NotContains(t, payload.CustomClaims, "iss")
}
