package jwt

import (
	"encoding/base64"
	"errors"
)

var enc = base64.RawURLEncoding

type JWT struct {
	Header *Header `json:"-"`
	*Claims
	nested bool // avoids nested JWT infinite loop
}

var (
	// ErrMalformedToken indicates a token doesn't have
	// a valid format, as per the RFC 7519, section 7.2.
	ErrMalformedToken = errors.New("jwt: malformed token")
	ErrNilHeader      = errors.New("jwt: nil header")
	ErrBigNest        = errors.New("jwt: more than one nested JWT")
)

func (jot *JWT) Validate(validators ...ValidatorFunc) error {
	for _, fn := range validators {
		if err := fn(jot); err != nil {
			return err
		}
	}
	return nil
}
