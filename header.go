package jwt

import "github.com/gbrlsnchs/jwt/v3/internal"

// ErrAlgValidation indicates an incoming JWT's "alg" field mismatches the Validator's.
var ErrAlgValidation = internal.NewError(`"alg" field mismatch`)

// Header is a JOSE header narrowed down to the JWT specification from RFC 7519.
//
// Parameters are ordered according to the RFC 7515.
type Header struct {
	Algorithm   string `json:"alg,omitempty"`
	KeyID       string `json:"kid,omitempty"`
	Type        string `json:"typ,omitempty"`
	ContentType string `json:"cty,omitempty"`
}

// Validate checks whether the incoming header contains the correct "alg" field.
func (h Header) Validate(vr Verifier) error {
	if h.Algorithm != vr.String() {
		return internal.Errorf("jwt: unexpected algorithm %q: %w", h.Algorithm, ErrAlgValidation)
	}
	return nil
}
