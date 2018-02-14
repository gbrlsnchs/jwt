package jwt

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// ErrEmptyHeader is returned when no token
// exists in the "Authorization" header.
var ErrEmptyHeader = errors.New("jwt.FromRequest: no token could be extracted from header")

// JWT is a JSON Web Token.
type JWT struct {
	header *header
	claims *claims
}

// FromRequest extracts a token string
// from the "Authorization" header, which
// should contain the "Bearer <token>" pattern.
func FromRequest(r *http.Request, s Signer) (*JWT, error) {
	auth := r.Header.Get("Authorization")

	if i := strings.IndexByte(auth, ' '); i >= 0 {
		return Parse(s, auth[i+1:])
	}

	return nil, ErrEmptyHeader
}

// Algorithm returns the "alg" claim
// from a JWT's header.
func (j *JWT) Algorithm() string {
	return j.header.Algorithm
}

// Audience returns the "aud" claim
// from a JWT's payload.
func (j *JWT) Audience() string {
	return j.claims.aud
}

// ExpirationTime returns the "exp" claim
// from a JWT's payload.
func (j *JWT) ExpirationTime() time.Time {
	return j.claims.exp
}

// IssuedAt returns the "iat" claim
// from a JWT's payload.
func (j *JWT) IssuedAt() time.Time {
	return j.claims.iat
}

// Issuer returns the "iss" claim
// from a JWT's payload.
func (j *JWT) Issuer() string {
	return j.claims.iss
}

// JWTID returns the "jti" claim
// from a JWT's payload.
func (j *JWT) JWTID() string {
	return j.claims.jti
}

// KeyID returns the "kid" claim
// from a JWT's header.
func (j *JWT) KeyID() string {
	return j.header.KeyID
}

// NotBefore returns the "nbf" claim
// from a JWT's payload.
func (j *JWT) NotBefore() time.Time {
	return j.claims.nbf
}

// Public returns all public claims set.
func (j *JWT) Public() map[string]interface{} {
	return j.claims.pub
}

// Subject returns the "sub" claim
// from a JWT's payload.
func (j *JWT) Subject() string {
	return j.claims.sub
}
