package jwt

import (
	"encoding/base64"
	"errors"
)

// Type is a constant value for header fields "typ" and "cty".
const Type = "JWT"

var enc = base64.RawURLEncoding

// JWT is a JSON Web Token as per the RFC 7519.
type JWT struct {
	Header *Header `json:"-"`
	*Claims
}

var (
	// ErrMalformed indicates a token doesn't have
	// a valid format, as per the RFC 7519, section 7.2.
	ErrMalformed = errors.New("jwt: malformed token")
)

// Validate validates claims and header fields.
func (jot *JWT) Validate(validators ...ValidatorFunc) error {
	for _, fn := range validators {
		if err := fn(jot); err != nil {
			return err
		}
	}
	return nil
}
