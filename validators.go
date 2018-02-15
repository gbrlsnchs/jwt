package jwt

import (
	"errors"
	"time"
)

var (
	ErrAlgorithmMismatch = errors.New("jwt: Algorithm mismatch")
	ErrAudienceMismatch  = errors.New("jwt: Audience mismatch")
	ErrTokenExpired      = errors.New("jwt: Token expired")
	ErrTokenFromFuture   = errors.New("jwt: Token issued at the future")
	ErrPrematureToken    = errors.New("jwt: Token is not valid yet")
	ErrIssuerMismatch    = errors.New("jwt: Issuer mismatch")
	ErrJWTIDMismatch     = errors.New("jwt: JWTID mismatch")
	ErrSubjectMismatch   = errors.New("jwt: Subject mismatch")
)

func AlgorithmValidator(alg string) ValidatorFunc {
	return func(jot *JWT) error {
		if alg != jot.Algorithm() {
			return ErrAlgorithmMismatch
		}

		return nil
	}
}

func AudienceValidator(aud string) ValidatorFunc {
	return func(jot *JWT) error {
		if jot.Audience() != aud {
			return ErrAudienceMismatch
		}

		return nil
	}
}

func ExpirationTimeValidator(now time.Time) ValidatorFunc {
	return func(jot *JWT) error {
		if exp := jot.ExpirationTime(); !exp.IsZero() && now.After(exp) {
			return ErrTokenExpired
		}

		return nil
	}
}

func IssuedAtValidator(now time.Time) ValidatorFunc {
	return func(jot *JWT) error {
		if now.Before(jot.IssuedAt()) {
			return ErrTokenFromFuture
		}

		return nil
	}
}

func IssuerValidator(iss string) ValidatorFunc {
	return func(jot *JWT) error {
		if jot.Issuer() != iss {
			return ErrIssuerMismatch
		}

		return nil
	}
}

func NotBeforeValidator(now time.Time) ValidatorFunc {
	return func(jot *JWT) error {
		if now.Before(jot.NotBefore()) {
			return ErrPrematureToken
		}

		return nil
	}
}

func JWTIDValidator(jti string) ValidatorFunc {
	return func(jot *JWT) error {
		if jot.ID() != jti {
			return ErrJWTIDMismatch
		}

		return nil
	}
}

func SubjectValidator(sub string) ValidatorFunc {
	return func(jot *JWT) error {
		if jot.Subject() != sub {
			return ErrSubjectMismatch
		}

		return nil
	}
}
