package jwt

import (
	"errors"
	"time"
)

// ValidatorFunc is a function for running extra
// validators when parsing a JWT string.
type ValidatorFunc func(jot *JWT) error

// ErrEmptyHeader is returned when no token
// exists in the "Authorization" header.
var ErrEmptyHeader = errors.New("jwt.FromRequest: no token could be extracted from header")

// JWT is a JSON Web Token.
type JWT struct {
	header *header
	claims *claims
}

// Algorithm returns the "alg" claim
// from the JWT's header.
func (j *JWT) Algorithm() string {
	return j.header.Algorithm
}

// Audience returns the "aud" claim
// from the JWT's payload.
func (j *JWT) Audience() string {
	return j.claims.aud
}

// ExpirationTime returns the "exp" claim
// from the JWT's payload.
func (j *JWT) ExpirationTime() time.Time {
	return j.claims.exp
}

// IssuedAt returns the "iat" claim
// from the JWT's payload.
func (j *JWT) IssuedAt() time.Time {
	return j.claims.iat
}

// Issuer returns the "iss" claim
// from the JWT's payload.
func (j *JWT) Issuer() string {
	return j.claims.iss
}

// ID returns the "jti" claim
// from the JWT's payload.
func (j *JWT) ID() string {
	return j.claims.jti
}

// KeyID returns the "kid" claim
// from the JWT's header.
func (j *JWT) KeyID() string {
	return j.header.KeyID
}

// NotBefore returns the "nbf" claim
// from the JWT's payload.
func (j *JWT) NotBefore() time.Time {
	return j.claims.nbf
}

// Public returns all public claims set.
func (j *JWT) Public() map[string]interface{} {
	return j.claims.pub
}

// Subject returns the "sub" claim
// from the JWT's payload.
func (j *JWT) Subject() string {
	return j.claims.sub
}

// Validate iterates over custom validator functions to validate the JWT.
func (j *JWT) Validate(vfuncs ...ValidatorFunc) error {
	for _, vfunc := range vfuncs {
		if err := vfunc(j); err != nil {
			return err
		}
	}

	return nil
}
