package jwt

import "time"

// JWT represents a JSON Web Token.
//
// Its claims and header properties
// are narrowed for JWT usage.
type JWT struct {
	Header *Header
	Claims *Claims
}

// IsValid returns whether a JWT has
// valid timestamps when they're not zeroed.
func (j *JWT) IsValid() bool {
	now := time.Now().Unix()

	if j.Claims == nil {
		return true
	}

	if j.Claims.Standard.IssuedAt >= now {
		return false
	}

	if nbf := j.Claims.Standard.NotBefore; nbf > 0 && nbf >= now {
		return false
	}

	if exp := j.Claims.Standard.ExpirationTime; exp > 0 && exp <= now {
		return false
	}

	return true
}
