package jwt

import "time"

// Options is a set of options
// that defines claims that are
// included in a token.
type Options struct {
	// Audience is the "aud" claim.
	Audience string
	// ExpirationTime is the "exp" claim.
	ExpirationTime time.Time
	// Issuer is the "iss" claim.
	Issuer string
	// NotBefore is the "nbf" claim.
	NotBefore time.Time
	// Subject is the "sub" claim.
	Subject string
	// Timestamp defines whether the JWT
	// has the "iat" (issued at) claim set.
	Timestamp bool
	// KeyID is the "kid" header claim.
	KeyID string
	// Public is a collection of public claims
	// that are included to the JWT's payload.
	Public map[string]interface{}
}
