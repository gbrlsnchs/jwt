package jwt

// Header is a JOSE header narrowed down to the JWT specification from RFC 7519.
//
// Parameters are ordered according to the RFC 7515.
type Header struct {
	Algorithm   string `json:"alg,omitempty"`
	KeyID       string `json:"kid,omitempty"`
	Type        string `json:"typ,omitempty"`
	ContentType string `json:"cty,omitempty"`
}

func (h Header) Validate(vr Verifier) error {
	// Check whether the incoming header contains the correct "alg" field.
	if h.Algorithm != vr.String() {
		return ErrAlgValidation
	}
	return nil
}
