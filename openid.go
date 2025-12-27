package openid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"

	"github.com/plan42-ai/openid/internal/util"
)

type Client struct {
	httpClient *http.Client
}

func NewClient() *Client {
	return &Client{
		httpClient: http.DefaultClient,
	}
}

func (c *Client) Discover(ctx context.Context, issuerURL *url.URL) (*DiscoveryDocument, error) {
	u := issuerURL.JoinPath(".well-known", "openid-configuration")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response code from %v: %v", u, resp.Status)
	}
	var ret DiscoveryDocument
	err = json.NewDecoder(resp.Body).Decode(&ret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode discovery document: %w", err)
	}
	return &ret, nil
}

func (c *Client) GetJwks(ctx context.Context, issuerURL *url.URL) (*Jwks, error) {
	doc, err := c.Discover(ctx, issuerURL)
	if err != nil {
		return nil, err
	}
	if doc.JwksURI == nil {
		return nil, fmt.Errorf("discovery document does not contain jwks_uri")
	}

	resp, err := c.httpClient.Get(doc.JwksURI.String())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %v: %w", doc.JwksURI, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response code from %v: %v", doc.JwksURI, resp.Status)
	}

	var jwks Jwks
	err = json.NewDecoder(resp.Body).Decode(&jwks)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}
	return &jwks, nil
}

// DiscoveryDocument represents the OpenID Connect discovery document.
// See https://openid.net/specs/openid-connect-discovery-1_0.html for the official spec.
type DiscoveryDocument struct {
	Issuer                                     *url.URL
	AuthorizationEndpoint                      *url.URL
	TokenEndpoint                              *url.URL
	UserinfoEndpoint                           *url.URL
	JwksURI                                    *url.URL
	RegistrationEndpoint                       *url.URL
	ScopesSupported                            []string
	ResponseTypesSupported                     []string
	ResponseModesSupported                     []string
	GrantTypesSupported                        []string
	AcrValuesSupported                         []string
	SubjectTypesSupported                      []string
	IDTokenSigningAlgValuesSupported           []string
	IDTokenEncryptionAlgValuesSupported        []string
	IDTokenEncryptionEncValuesSupported        []string
	UserInfoSigningAlgValuesSupported          []string
	UserInfoEncryptionAlgValuesSupported       []string
	UserInfoEncryptionEncValuesSupported       []string
	RequestObjectSigningAlgValuesSupported     []string
	TokenEndpointAuthMethodsSupported          []string
	TokenEndpointAuthSigningAlgValuesSupported []string
	DisplayValuesSupported                     []string
	ClaimTypesSupported                        []string
	ClaimsSupported                            []string
	ServiceDocumentation                       *url.URL
	ClaimsLocalesSupported                     []string
	UILocalesSupported                         []string
	ClaimsParameterSupported                   bool
	RequestParameterSupported                  bool
	RequestURIParameterSupported               bool
	RequireRequestURIRegistration              bool
	OpPolicyURI                                *url.URL
	OpTosURI                                   *url.URL
}

type discoveryDocument struct {
	Issuer                                     *string  `json:"issuer"`
	AuthorizationEndpoint                      *string  `json:"authorization_endpoint"`
	TokenEndpoint                              *string  `json:"token_endpoint,omitempty"`
	UserinfoEndpoint                           *string  `json:"userinfo_endpoint,omitempty"`
	JwksURI                                    *string  `json:"jwks_uri"`
	RegistrationEndpoint                       *string  `json:"registration_endpoint,omitempty"`
	ScopesSupported                            []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                     []string `json:"response_types_supported,omitempty"`
	ResponseModesSupported                     []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                        []string `json:"grant_types_supported,omitempty"`
	AcrValuesSupported                         []string `json:"acr_values_supported,omitempty"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	IDTokenEncryptionAlgValuesSupported        []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenEncryptionEncValuesSupported        []string `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserInfoSigningAlgValuesSupported          []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserInfoEncryptionAlgValuesSupported       []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserInfoEncryptionEncValuesSupported       []string `json:"userinfo_encryption_enc_values_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported,omitempty"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	DisplayValuesSupported                     []string `json:"display_values_supported,omitempty"`
	ClaimTypesSupported                        []string `json:"claim_types_supported,omitempty"`
	ClaimsSupported                            []string `json:"claims_supported"`
	ServiceDocumentation                       *string  `json:"service_documentation,omitempty"`
	ClaimsLocalesSupported                     []string `json:"claims_locales_supported,omitempty"`
	UILocalesSupported                         []string `json:"ui_locales_supported,omitempty"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
	RequireRequestURIRegistration              bool     `json:"require_request_uri_registration,omitempty"`
	OpPolicyURI                                *string  `json:"op_policy_uri,omitempty"`
	OpTosURI                                   *string  `json:"op_tos_uri,omitempty"`
}

func (d DiscoveryDocument) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		&discoveryDocument{
			Issuer:                                     urlToString(d.Issuer),
			AuthorizationEndpoint:                      urlToString(d.AuthorizationEndpoint),
			TokenEndpoint:                              urlToString(d.TokenEndpoint),
			UserinfoEndpoint:                           urlToString(d.UserinfoEndpoint),
			JwksURI:                                    urlToString(d.JwksURI),
			RegistrationEndpoint:                       urlToString(d.RegistrationEndpoint),
			ScopesSupported:                            d.ScopesSupported,
			ResponseTypesSupported:                     d.ResponseTypesSupported,
			ResponseModesSupported:                     d.ResponseModesSupported,
			GrantTypesSupported:                        d.GrantTypesSupported,
			AcrValuesSupported:                         d.AcrValuesSupported,
			SubjectTypesSupported:                      d.SubjectTypesSupported,
			IDTokenSigningAlgValuesSupported:           d.IDTokenSigningAlgValuesSupported,
			IDTokenEncryptionAlgValuesSupported:        d.IDTokenEncryptionAlgValuesSupported,
			IDTokenEncryptionEncValuesSupported:        d.IDTokenEncryptionEncValuesSupported,
			UserInfoSigningAlgValuesSupported:          d.UserInfoSigningAlgValuesSupported,
			UserInfoEncryptionAlgValuesSupported:       d.UserInfoEncryptionAlgValuesSupported,
			UserInfoEncryptionEncValuesSupported:       d.UserInfoEncryptionEncValuesSupported,
			RequestObjectSigningAlgValuesSupported:     d.RequestObjectSigningAlgValuesSupported,
			TokenEndpointAuthMethodsSupported:          d.TokenEndpointAuthMethodsSupported,
			TokenEndpointAuthSigningAlgValuesSupported: d.TokenEndpointAuthSigningAlgValuesSupported,
			DisplayValuesSupported:                     d.DisplayValuesSupported,
			ClaimTypesSupported:                        d.ClaimTypesSupported,
			ClaimsSupported:                            d.ClaimsSupported,
			ServiceDocumentation:                       urlToString(d.ServiceDocumentation),
			ClaimsLocalesSupported:                     d.ClaimsLocalesSupported,
			UILocalesSupported:                         d.UILocalesSupported,
			ClaimsParameterSupported:                   d.ClaimsParameterSupported,
			RequestParameterSupported:                  d.RequestParameterSupported,
			RequestURIParameterSupported:               d.RequestURIParameterSupported,
			RequireRequestURIRegistration:              d.RequireRequestURIRegistration,
			OpPolicyURI:                                urlToString(d.OpPolicyURI),
			OpTosURI:                                   urlToString(d.OpTosURI),
		},
	)
}

func (d *DiscoveryDocument) UnmarshalJSON(data []byte) error {
	var tmp1 discoveryDocument
	err := json.Unmarshal(data, &tmp1)
	if err != nil {
		return err
	}
	tmp2 := DiscoveryDocument{
		ScopesSupported:                            tmp1.ScopesSupported,
		ResponseTypesSupported:                     tmp1.ResponseTypesSupported,
		ResponseModesSupported:                     tmp1.ResponseModesSupported,
		GrantTypesSupported:                        tmp1.GrantTypesSupported,
		AcrValuesSupported:                         tmp1.AcrValuesSupported,
		SubjectTypesSupported:                      tmp1.SubjectTypesSupported,
		IDTokenSigningAlgValuesSupported:           tmp1.IDTokenSigningAlgValuesSupported,
		IDTokenEncryptionAlgValuesSupported:        tmp1.IDTokenEncryptionAlgValuesSupported,
		IDTokenEncryptionEncValuesSupported:        tmp1.IDTokenEncryptionEncValuesSupported,
		UserInfoSigningAlgValuesSupported:          tmp1.UserInfoSigningAlgValuesSupported,
		UserInfoEncryptionAlgValuesSupported:       tmp1.UserInfoEncryptionAlgValuesSupported,
		UserInfoEncryptionEncValuesSupported:       tmp1.UserInfoEncryptionEncValuesSupported,
		RequestObjectSigningAlgValuesSupported:     tmp1.RequestObjectSigningAlgValuesSupported,
		TokenEndpointAuthMethodsSupported:          tmp1.TokenEndpointAuthMethodsSupported,
		TokenEndpointAuthSigningAlgValuesSupported: tmp1.TokenEndpointAuthSigningAlgValuesSupported,
		DisplayValuesSupported:                     tmp1.DisplayValuesSupported,
		ClaimTypesSupported:                        tmp1.ClaimTypesSupported,
		ClaimsSupported:                            tmp1.ClaimsSupported,
		ClaimsLocalesSupported:                     tmp1.ClaimsLocalesSupported,
		UILocalesSupported:                         tmp1.UILocalesSupported,
		ClaimsParameterSupported:                   tmp1.ClaimsParameterSupported,
		RequestParameterSupported:                  tmp1.RequestParameterSupported,
		RequestURIParameterSupported:               tmp1.RequestURIParameterSupported,
		RequireRequestURIRegistration:              tmp1.RequireRequestURIRegistration,
	}

	err = util.Coalesce(
		stringToURL(&tmp2.Issuer, tmp1.Issuer),
		stringToURL(&tmp2.AuthorizationEndpoint, tmp1.AuthorizationEndpoint),
		stringToURL(&tmp2.TokenEndpoint, tmp1.TokenEndpoint),
		stringToURL(&tmp2.UserinfoEndpoint, tmp1.UserinfoEndpoint),
		stringToURL(&tmp2.JwksURI, tmp1.JwksURI),
		stringToURL(&tmp2.RegistrationEndpoint, tmp1.RegistrationEndpoint),
		stringToURL(&tmp2.ServiceDocumentation, tmp1.ServiceDocumentation),
		stringToURL(&tmp2.OpPolicyURI, tmp1.OpPolicyURI),
		stringToURL(&tmp2.OpTosURI, tmp1.OpTosURI),
	)

	if err != nil {
		return err
	}

	*d = tmp2
	return nil
}

func stringToURL(u **url.URL, s *string) error {
	if s == nil {
		*u = nil
		return nil
	}
	var err error
	*u, err = url.Parse(*s)
	return err
}

func urlToString(u *url.URL) *string {
	if u == nil {
		return nil
	}
	return util.Pointer(u.String())
}

type Jwk struct {
	KeyID            string
	Use              string
	Algorithm        string
	KeyType          string
	RSAKey           *rsa.PublicKey
	ECCKey           *ecdsa.PublicKey
	CertChain        []*x509.Certificate
	CertificateURL   *url.URL
	Sha1Thumbprint   []byte
	Sha256Thumbprint []byte
	OtherFields      map[string]interface{}
}

type jwk struct {
	KeyID            string         `json:"kid"`
	Use              string         `json:"use"`                // "sig" or "enc"
	Algorithm        string         `json:"alg"`                // Algorithm used for signing or encryption
	KeyType          string         `json:"kty"`                // Key type, e.g., "RSA", "EC"
	N                urlSafeBytes   `json:"n,omitempty"`        // RSA modulus (for RSA keys)
	E                urlSafeBytes   `json:"e,omitempty"`        // RSA public exponent (for RSA keys)
	Curve            string         `json:"crv,omitempty"`      // Curve name (for EC keys)
	X                urlSafeBytes   `json:"x,omitempty"`        // X coordinate (for EC keys)
	Y                urlSafeBytes   `json:"y,omitempty"`        // Y coordinate (for EC keys)
	CertChain        []urlSafeBytes `json:"x5c,omitempty"`      // X.509 certificate chain
	CertificateURL   *string        `json:"x5u,omitempty"`      // URL to the X.509 certificate
	Sha1Thumbprint   urlSafeBytes   `json:"x5t,omitempty"`      // SHA-1 thumbprint of the certificate
	Sha256Thumbprint urlSafeBytes   `json:"x5t#S256,omitempty"` // SHA-256 thumbprint of the certificate
}

type urlSafeBytes []byte

func (b *urlSafeBytes) UnmarshalJSON(data []byte) error {
	var raw string
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return fmt.Errorf("failed to unmarshal urlSafeBytes: %w", err)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return err
	}

	*b = decoded
	return nil
}

func (b urlSafeBytes) MarshalJSON() ([]byte, error) {
	encoded := base64.RawURLEncoding.EncodeToString(b)
	return json.Marshal(encoded)
}

func (j Jwk) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	for k, v := range j.OtherFields {
		m[k] = v
	}

	m["kid"] = j.KeyID
	m["use"] = j.Use
	m["alg"] = j.Algorithm
	m["kty"] = j.KeyType

	if len(j.Sha1Thumbprint) > 0 {
		m["x5t"] = urlSafeBytes(j.Sha1Thumbprint)
	}

	if len(j.Sha256Thumbprint) > 0 {
		m["x5t#S256"] = urlSafeBytes(j.Sha256Thumbprint)
	}

	if j.CertificateURL != nil {
		m["x5u"] = j.CertificateURL.String()
	}

	if len(j.CertChain) != 0 {
		var certChainRaw []urlSafeBytes
		for _, cert := range j.CertChain {
			certChainRaw = append(certChainRaw, cert.Raw)
		}
		m["x5c"] = certChainRaw
	}

	if j.RSAKey != nil {
		m["n"] = urlSafeBytes(j.RSAKey.N.Bytes())
		m["e"] = urlSafeBytes(big.NewInt(int64(j.RSAKey.E)).Bytes())
	}

	if j.ECCKey != nil {
		m["crv"] = j.ECCKey.Curve.Params().Name
		m["x"] = urlSafeBytes(j.ECCKey.X.Bytes())
		m["y"] = urlSafeBytes(j.ECCKey.Y.Bytes())
	}
	return json.Marshal(m)
}

func (j *Jwk) UnmarshalJSON(data []byte) error {
	var tmp jwk
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return fmt.Errorf("failed to unmarshal Jwk: %w", err)
	}

	var certChain []*x509.Certificate

	for _, rawCert := range tmp.CertChain {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}
		certChain = append(certChain, cert)
	}

	var certURL *url.URL

	if tmp.CertificateURL != nil {
		certURL, err = url.Parse(*tmp.CertificateURL)
		if err != nil {
			return fmt.Errorf("failed to parse certificate URL: %w", err)
		}
	}

	var otherFields map[string]interface{}
	err = json.Unmarshal(data, &otherFields)
	if err != nil {
		return fmt.Errorf("failed to unmarshal Jwk: %w", err)
	}

	// Remove known fields from otherFields
	delete(otherFields, "kid")
	delete(otherFields, "use")
	delete(otherFields, "alg")
	delete(otherFields, "kty")
	delete(otherFields, "n")
	delete(otherFields, "e")
	delete(otherFields, "crv")
	delete(otherFields, "x")
	delete(otherFields, "y")
	delete(otherFields, "x5c")
	delete(otherFields, "x5u")
	delete(otherFields, "x5t")
	delete(otherFields, "x5t#S256")

	var rsaKey *rsa.PublicKey
	if len(tmp.N) != 0 && len(tmp.E) != 0 {
		rsaKey = &rsa.PublicKey{
			N: new(big.Int).SetBytes(tmp.N),
			E: int(new(big.Int).SetBytes(tmp.E).Int64()),
		}
	}

	var eccKey *ecdsa.PublicKey
	if len(tmp.X) != 0 && len(tmp.Y) != 0 && tmp.Curve != "" {
		curve, err := getCurveByName(tmp.Curve)
		if err != nil {
			return err
		}
		eccKey = &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(tmp.X),
			Y:     new(big.Int).SetBytes(tmp.Y),
		}
	}

	*j = Jwk{
		KeyID:            tmp.KeyID,
		Use:              tmp.Use,
		Algorithm:        tmp.Algorithm,
		KeyType:          tmp.KeyType,
		RSAKey:           rsaKey,
		ECCKey:           eccKey,
		CertChain:        certChain,
		CertificateURL:   certURL,
		Sha1Thumbprint:   tmp.Sha1Thumbprint,
		Sha256Thumbprint: tmp.Sha256Thumbprint,
		OtherFields:      otherFields,
	}
	return nil
}

func getCurveByName(curve string) (elliptic.Curve, error) {
	switch curve {
	case elliptic.P256().Params().Name:
		return elliptic.P256(), nil
	case elliptic.P384().Params().Name:
		return elliptic.P384(), nil
	case elliptic.P521().Params().Name:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported elliptic curve: %s", curve)
	}
}

type Jwks struct {
	Keys []Jwk `json:"keys"`
}
