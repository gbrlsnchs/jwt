package jwt

import (
	"encoding/base64"
	"errors"
)

var enc = base64.RawURLEncoding

// JWT is a JSON Web Token as per the RFC 7519.
//
// Fields are ordered according to the RFC 7519 order.
type JWT struct {
	hdr            *header
	Issuer         string `json:"iss,omitempty"`
	Subject        string `json:"sub,omitempty"`
	Audience       string `json:"aud,omitempty"`
	ExpirationTime int64  `json:"exp,omitempty"`
	NotBefore      int64  `json:"nbf,omitempty"`
	IssuedAt       int64  `json:"iat,omitempty"`
	ID             string `json:"jti,omitempty"`
}

var (
	// ErrMalformed indicates a token doesn't have
	// a valid format, as per the RFC 7519.
	ErrMalformed = errors.New("jwt: malformed token")
)

// Algorithm returns the JWT's header's algorithm.
func (jot *JWT) Algorithm() string {
	return jot.header().Algorithm
}

// ContentType returns the JWT's header's content type.
func (jot *JWT) ContentType() string {
	return jot.header().ContentType
}

// KeyID returns the JWT's header's key ID.
func (jot *JWT) KeyID() string {
	return jot.header().KeyID
}

// SetAlgorithm sets the algorithm a JWT uses to be signed.
func (jot *JWT) SetAlgorithm(s Signer) {
	jot.header().Algorithm = s.String()
}

// SetContentType sets the JWT's header's content type.
//
// This is useful if a type implements the Marshaler and the Unmarshaler
// types in order to use JWE instead of JWS for signing and verifying.
func (jot *JWT) SetContentType(cty string) {
	jot.header().ContentType = cty
}

// SetKeyID sets the key ID assigned to a JWT.
func (jot *JWT) SetKeyID(kid string) {
	jot.header().KeyID = kid
}

// Type returns the JWT's header's type.
func (jot *JWT) Type() string {
	return jot.header().Type
}

// Validate validates claims and header fields.
func (jot *JWT) Validate(validators ...ValidatorFunc) error {
	for _, v := range validators {
		if err := v(jot); err != nil {
			return err
		}
	}
	return nil
}

func (jot *JWT) header() *header {
	if jot.hdr == nil {
		jot.hdr = &header{
			Type: "JWT",
		}
	}
	return jot.hdr
}

func (jot *JWT) setHeader(hdr *header) {
	jot.hdr = hdr
}
