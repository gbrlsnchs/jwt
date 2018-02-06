package jwt

import (
	"errors"
	"fmt"
	"time"
)

// JWT represents a JSON Web Token.
//
// Its claims and header properties
// are narrowed for JWT usage.
type JWT struct {
	Header *Header
	Claims *Claims
}

func (j *JWT) validate(n int64) error {
	now := time.Unix(n, 0)

	if iat := j.Claims.Standard.IssuedAt; iat != 0 {
		if iat := time.Unix(iat, 0); iat.After(now) {
			return errors.New("JWT was issued in the future")
		}
	}

	if nbf := j.Claims.Standard.NotBefore; nbf != 0 {
		if nbf := time.Unix(nbf, 0); !nbf.IsZero() && nbf.After(now) {
			return fmt.Errorf("JWT should not be valid until %s", nbf.String())
		}
	}

	if exp := j.Claims.Standard.ExpirationTime; exp != 0 {
		if exp := time.Unix(exp, 0); !exp.IsZero() && exp.Before(now) {
			return fmt.Errorf("JWT expired on %s", exp.String())
		}
	}

	return nil
}
