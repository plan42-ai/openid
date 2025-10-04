package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"
)

var ErrInvalidToken = errors.New("invalid jwt token")

const (
	AlgorithmRS256 = "RS256"
	AlgorithmES256 = "ES256"
)

type Token struct {
	RawHeader    string
	RawPayload   string
	RawSignature string
	Header       Header
	Payload      Payload
	Signature    []byte
}

func Parse(data string) (*Token, error) {
	var ret Token
	parts := strings.SplitN(data, ".", 3)
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	ret.RawHeader = parts[0]
	ret.RawPayload = parts[1]
	ret.RawSignature = parts[2]

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}
	err = json.Unmarshal(headerBytes, &ret.Header)
	if err != nil {
		return nil, ErrInvalidToken
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	err = json.Unmarshal(payloadBytes, &ret.Payload)
	if err != nil {
		return nil, ErrInvalidToken
	}
	ret.Signature, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidToken
	}
	return &ret, nil
}

type Header struct {
	Algorithm   string
	KeyID       string
	Type        string
	OtherFields map[string]interface{}
}

func (h Header) MarshalJSON() ([]byte, error) {
	rawFields := make(map[string]interface{})
	for k, v := range h.OtherFields {
		rawFields[k] = v
	}

	rawFields["alg"] = h.Algorithm
	rawFields["kid"] = h.KeyID
	rawFields["typ"] = h.Type

	return json.Marshal(rawFields)
}

func (h *Header) UnmarshalJSON(data []byte) error {
	var tmp struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	otherFields := make(map[string]interface{})
	err = json.Unmarshal(data, &otherFields)
	if err != nil {
		return err
	}
	delete(otherFields, "alg")
	delete(otherFields, "kid")
	delete(otherFields, "typ")
	*h = Header{
		Algorithm:   tmp.Algorithm,
		KeyID:       tmp.KeyID,
		Type:        tmp.Type,
		OtherFields: otherFields,
	}
	return nil
}

type Payload struct {
	Issuer          *url.URL
	Subject         string
	Audience        string
	AuthorizedParty *string
	AccessTokenHash *string
	Name            *string
	PictureURL      *url.URL
	GivenName       *string
	FamilyName      *string
	HostedDomain    *string
	Email           *string
	EmailVerified   *bool
	Expiration      time.Time
	NotBefore       time.Time
	IssuedAt        time.Time
	ID              string
	CustomClaims    map[string]interface{}
}

func (p *Payload) MaxAge() time.Duration {
	return p.Expiration.Sub(p.NotBefore)
}

func (p *Payload) TimeUntilExpires() time.Duration {
	return time.Until(p.Expiration)
}

func (p Payload) MarshalJSON() ([]byte, error) {
	rawClaims := make(map[string]interface{})
	for k, v := range p.CustomClaims {
		rawClaims[k] = v
	}

	if p.AuthorizedParty != nil {
		rawClaims["azp"] = p.AuthorizedParty
	}

	if p.AccessTokenHash != nil {
		rawClaims["at_hash"] = p.AccessTokenHash
	}

	if p.Name != nil {
		rawClaims["name"] = p.Name
	}

	if p.PictureURL != nil {
		rawClaims["picture"] = p.PictureURL.String()
	}

	if p.GivenName != nil {
		rawClaims["given_name"] = p.GivenName
	}

	if p.FamilyName != nil {
		rawClaims["family_name"] = p.FamilyName
	}

	if p.HostedDomain != nil {
		rawClaims["hd"] = p.HostedDomain
	}

	if p.Email != nil {
		rawClaims["email"] = p.Email
	}

	if p.EmailVerified != nil {
		rawClaims["email_verified"] = *p.EmailVerified
	}

	if p.Issuer != nil {
		rawClaims["iss"] = p.Issuer.String()
	} else {
		rawClaims["iss"] = nil
	}

	rawClaims["sub"] = p.Subject
	rawClaims["aud"] = p.Audience
	rawClaims["exp"] = p.Expiration.Unix()
	rawClaims["nbf"] = p.NotBefore.Unix()
	rawClaims["iat"] = p.IssuedAt.Unix()
	rawClaims["jti"] = p.ID

	return json.Marshal(rawClaims)
}

func (p *Payload) UnmarshalJSON(data []byte) error {
	var tmp struct {
		Issuer          string  `json:"iss"`
		Subject         string  `json:"sub"`
		Audience        string  `json:"aud"`
		Expiration      int64   `json:"exp"`
		NotBefore       int64   `json:"nbf"`
		IssuedAt        int64   `json:"iat"`
		ID              string  `json:"jti"`
		AuthorizedParty *string `json:"azp,omitempty"`
		AccessTokenHash *string `json:"at_hash,omitempty"`
		Name            *string `json:"name,omitempty"`
		PictureURL      *string `json:"picture,omitempty"`
		GivenName       *string `json:"given_name,omitempty"`
		FamilyName      *string `json:"family_name,omitempty"`
		HostedDomain    *string `json:"hd,omitempty"`
		Email           *string `json:"email,omitempty"`
		EmailVerified   *bool   `json:"email_verified,omitempty"`
	}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	customClaims := make(map[string]interface{})
	err = json.Unmarshal(data, &customClaims)
	if err != nil {
		return err
	}

	var issuer *url.URL
	if tmp.Issuer != "" {
		issuer, err = url.Parse(tmp.Issuer)
		if err != nil {
			return err
		}
	}

	var pictureURL *url.URL
	if tmp.PictureURL != nil {
		pictureURL, err = url.Parse(*tmp.PictureURL)
		if err != nil {
			return err
		}
	}

	delete(customClaims, "iss")
	delete(customClaims, "sub")
	delete(customClaims, "aud")
	delete(customClaims, "exp")
	delete(customClaims, "nbf")
	delete(customClaims, "iat")
	delete(customClaims, "jti")
	delete(customClaims, "azp")
	delete(customClaims, "at_hash")
	delete(customClaims, "name")
	delete(customClaims, "picture")
	delete(customClaims, "given_name")
	delete(customClaims, "family_name")
	delete(customClaims, "hd")
	delete(customClaims, "email")
	delete(customClaims, "email_verified")

	*p = Payload{
		Issuer:          issuer,
		Subject:         tmp.Subject,
		Audience:        tmp.Audience,
		Expiration:      time.Unix(tmp.Expiration, 0),
		NotBefore:       time.Unix(tmp.NotBefore, 0),
		IssuedAt:        time.Unix(tmp.IssuedAt, 0),
		ID:              tmp.ID,
		CustomClaims:    customClaims,
		AuthorizedParty: tmp.AuthorizedParty,
		AccessTokenHash: tmp.AccessTokenHash,
		Name:            tmp.Name,
		PictureURL:      pictureURL,
		GivenName:       tmp.GivenName,
		FamilyName:      tmp.FamilyName,
		HostedDomain:    tmp.HostedDomain,
		Email:           tmp.Email,
		EmailVerified:   tmp.EmailVerified,
	}
	return nil
}

func (t *Token) ensureRawHeader() {
	if t.RawHeader == "" {
		b, err := json.Marshal(t.Header)
		if err != nil {
			panic(err)
		}
		t.RawHeader = base64.RawURLEncoding.EncodeToString(b)
	}
}

func (t *Token) ensureRawPayload() {
	if t.RawPayload == "" {
		b, err := json.Marshal(t.Payload)
		if err != nil {
			panic(err)
		}
		t.RawPayload = base64.RawURLEncoding.EncodeToString(b)
	}
}

func (t *Token) ensureRawSignature() {
	if t.RawSignature == "" && len(t.Signature) > 0 {
		t.RawSignature = base64.RawURLEncoding.EncodeToString(t.Signature)
	}
}

func (t *Token) StringToSign() string {
	t.ensureRawHeader()
	t.ensureRawPayload()
	return t.RawHeader + "." + t.RawPayload
}

func (t *Token) String() string {
	s := t.StringToSign()
	t.ensureRawSignature()
	return s + "." + t.RawSignature
}
