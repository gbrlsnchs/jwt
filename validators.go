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
// validators when parsing a Payload string.
type ValidatorFunc func() error

// AudienceValidator validates the "aud" claim.
// It checks if at least one of the audiences in the JWT's payload is listed in aud.
func (pl *Payload) AudienceValidator(aud Audience) ValidatorFunc {
	return func() error {
		for _, serverAud := range aud {
			for _, clientAud := range pl.Audience {
				if clientAud == serverAud {
					return nil
				}
			}
		}
		return ErrAudValidation
	}
}

// ExpirationTimeValidator validates the "exp" claim.
func (pl *Payload) ExpirationTimeValidator(now time.Time, validateZero bool) ValidatorFunc {
	return func() error {
		expint := pl.ExpirationTime
		if !validateZero && expint == 0 {
			return nil
		}
		if exp := time.Unix(expint, 0); now.After(exp) {
			return ErrExpValidation
		}
		return nil
	}
}

// IssuedAtValidator validates the "iat" claim.
func (pl *Payload) IssuedAtValidator(now time.Time) ValidatorFunc {
	return func() error {
		if iat := time.Unix(pl.IssuedAt, 0); now.Before(iat) {
			return ErrIatValidation
		}
		return nil
	}
}

// IssuerValidator validates the "iss" claim.
func (pl *Payload) IssuerValidator(iss string) ValidatorFunc {
	return func() error {
		if pl.Issuer != iss {
			return ErrIssValidation
		}
		return nil
	}
}

// JWTIDValidator validates the "jti" claim.
func (pl *Payload) JWTIDValidator(jti string) ValidatorFunc {
	return func() error {
		if pl.JWTID != jti {
			return ErrJtiValidation
		}
		return nil
	}
}

// NotBeforeValidator validates the "nbf" claim.
func (pl *Payload) NotBeforeValidator(now time.Time) ValidatorFunc {
	return func() error {
		if nbf := time.Unix(pl.NotBefore, 0); now.Before(nbf) {
			return ErrNbfValidation
		}
		return nil
	}
}

// SubjectValidator validates the "sub" claim.
func (pl *Payload) SubjectValidator(sub string) ValidatorFunc {
	return func() error {
		if pl.Subject != sub {
			return ErrSubValidation
		}
		return nil
	}
}
