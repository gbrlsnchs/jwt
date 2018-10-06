package cache

import (
	"errors"
	"time"

	jwt "github.com/gbrlsnchs/jwt/v2"
)

var (
	//ErrJTIUsageExceededValidation is the error for invalid "jti" claim.
	ErrJTIUsageExceededValidation = errors.New("jwt: jti claim is invalid - too many uses")
	//ErrJTIRequiredValidation is the error for "jti" claim required but not presented.
	ErrJTIRequiredValidation = errors.New("jwt: jti claim is required")
)

// IDValidator is a JWT validator for the "jti" claim as a nonce.
func IDValidator(c *Cache) jwt.ValidatorFunc {
	return func(jot *jwt.JWT) error {
		var err error
		if jot.ID == "" {
			return ErrJTIRequiredValidation
		}
		var expiry time.Duration
		if jot.ExpirationTime > 0 {
			expiry = time.Unix(jot.ExpirationTime, 0).Sub(time.Now())
		}
		_, err = c.IncrementCounter(jot.ID, expiry)
		return err
	}
}
