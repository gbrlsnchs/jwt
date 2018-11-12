package jwt

import (
	"errors"
	"time"
)

var (
	// ErrAudValidation is the error for an invalid "aud" claim.
	ErrAudValidation = errors.New("jwt: aud claim is invalid")
	// ErrExpValidation is the error for an invalid "exp" claim.
	ErrExpValidation = errors.New("jwt: exp claim is invalid")
	// ErrIatValidation is the error for an invalid "iat" claim.
	ErrIatValidation = errors.New("jwt: iat claim is invalid")
	// ErrIssValidation is the error for an invalid "iss" claim.
	ErrIssValidation = errors.New("jwt: iss claim is invalid")
	// ErrJtiValidation is the error for an invalid "jti" claim.
	ErrJtiValidation = errors.New("jwt: jti claim is invalid")
	// ErrNbfValidation is the error for an invalid "nbf" claim.
	ErrNbfValidation = errors.New("jwt: nbf claim is invalid")
	// ErrSubValidation is the error for an invalid "sub" claim.
	ErrSubValidation = errors.New("jwt: sub claim is invalid")
)

// ValidatorFunc is a function for running extra
// validators when parsing a JWT string.
type ValidatorFunc func(jot *JWT) error

// AudienceValidator validates the "aud" claim.
func AudienceValidator(aud ...string) ValidatorFunc {
	return func(jot *JWT) error {
		if len(aud) != 0 {
			for _, singleAudClaim := range aud {
				if !contains(jot.Audience, singleAudClaim) {
					return ErrAudValidation
				}
			}
		}
		return nil
	}
}

// contains reports whether the slice contains the string.
func contains(slice []string, target string) bool {
	for _, val := range slice {
		if target == val {
			return true
		}
	}
	return false
}

// ExpirationTimeValidator validates the "exp" claim.
func ExpirationTimeValidator(now time.Time) ValidatorFunc {
	return func(jot *JWT) error {
		if exp := time.Unix(jot.ExpirationTime, 0); now.After(exp) {
			return ErrExpValidation
		}
		return nil
	}
}

// IssuedAtValidator validates the "iat" claim.
func IssuedAtValidator(now time.Time) ValidatorFunc {
	return func(jot *JWT) error {
		if iat := time.Unix(jot.IssuedAt, 0); now.Before(iat) {
			return ErrIatValidation
		}
		return nil
	}
}

// IssuerValidator validates the "iss" claim.
func IssuerValidator(iss string) ValidatorFunc {
	return func(jot *JWT) error {
		if jot.Issuer != iss {
			return ErrIssValidation
		}
		return nil
	}
}

// IDValidator validates the "jti" claim.
func IDValidator(jti string) ValidatorFunc {
	return func(jot *JWT) error {
		if jot.ID != jti {
			return ErrJtiValidation
		}
		return nil
	}
}

// NotBeforeValidator validates the "nbf" claim.
func NotBeforeValidator(now time.Time) ValidatorFunc {
	return func(jot *JWT) error {
		if nbf := time.Unix(jot.NotBefore, 0); now.Before(nbf) {
			return ErrNbfValidation
		}
		return nil
	}
}

// SubjectValidator validates the "sub" claim.
func SubjectValidator(sub string) ValidatorFunc {
	return func(jot *JWT) error {
		if jot.Subject != sub {
			return ErrSubValidation
		}
		return nil
	}
}
