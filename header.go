package jwt

import "github.com/gbrlsnchs/jwt/jwtcrypto"

// Header is a JOSE header adapted for JWT usage.
type Header struct {
	Algorithm jwtcrypto.SigningMethod `json:"alg,omitempty"`
	Type      string                  `json:"typ,omitempty"`
	KeyID     string                  `json:"kid,omitempty"`
}
