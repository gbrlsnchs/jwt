package jwt

import (
	"encoding/base64"
	"errors"
)

// Type is a constant value for header fields "typ" and "cty".
const Type = "JWT"

var enc = base64.RawURLEncoding

// JWT is a JSON Web Token as per the RFC 7519.
//
// Fields are ordered according to the RFC 7519.
type JWT struct {
	hdr            *header
	Issuer         string `json:"iss,omitempty"`
	Subject        string `json:"sub,omitempty"`
	Audience       string `json:"aud,omitempty"`
	ExpirationTime int64  `json:"exp,omitempty"`
	NotBefore      int64  `json:"nbf,omitempty"`
	IssuedAt       int64  `json:"iat,omitempty"`
	ID             string `json:"jti,omitempty"`
	nst            []byte
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

// KeyID returns the JWT's header's key ID.
func (jot *JWT) KeyID() string {
	return jot.header().KeyID
}

// Nest nests a already marshaled and signed JWT within the
// JWT object and sets the header parameter "cty" to "JWT".
func (jot *JWT) Nest(nst []byte) {
	jot.nst = nst
	jot.header().ContentType = Type
}

// SetAlgorithm sets the algorithm a JWT uses based on its signer.
func (jot *JWT) SetAlgorithm(s Signer) {
	jot.header().Algorithm = s.String()
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
			Type: Type,
		}
	}
	return jot.hdr
}

func (jot *JWT) nested() []byte {
	return jot.nst
}

func (jot *JWT) setHeader(hdr *header) {
	jot.hdr = hdr
}
