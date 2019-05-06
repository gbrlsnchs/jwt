package jwt

import "github.com/gbrlsnchs/jwt/v3/internal"

// ErrMissingVerifier is the error for when a nil Verifier is used.
var ErrMissingVerifier = internal.NewError("jwt: verifier is nil")

// Decoder is a JWT decoder. It is a wrapper over RawToken.
type Decoder struct {
	token []byte
	h     Header
	vr    Verifier
}

// NewDecoder creates a JWT decoder for a particular pair of token and Verifier.
func NewDecoder(token []byte, vr Verifier) *Decoder {
	return &Decoder{
		token: token, // this ensures the Decoder is not reused, as it's not concurrency-safe
		vr:    vr,
	}
}

// Decode decodes a JWT into a Payload struct and verifies its signature.
//
// It validates the token according to section 7.1, item 3, which says that
// when creating a JWT, it "MUST conform to either the JWS or JWE specification"
// (RFC 7515 and RFC 7516 respectively). So currently, for the token to be valid,
// it must have 2 (two) periods. As JWE is not supported, it considers everything
// after the second period to be part of the JWS.
//
// The token must contain valid Base64 parts that when decoded present valid JSON inside.
// Before verifying the signature, it checks whether the "alg" field is the correct one.
//
// Also, it accepts optional ValidatorFunc trailing arguments to also validate the payload's claims.
//
// Note that running
//
//	var p jwt.Payload
//	err := jwt.NewDecoder(token, vr).
//		Decode(&p, jwt.AudienceValidator("aud"), jwt.SubjectValidator("sub"))
//	// handle error
//
// is the same as running
//
//	r, err := jwt.Parse(token)
//	// handle error
//
//	var p jwt.Payload
//	h, err := r.Decode(&p)
//	// handle error
//
//	err = h.Validate(vr)
//	// handle error
//
//	err = r.Verify(vr)
//	// handle error
//
//	err = p.Validate(jwt.AudienceValidator("aud"), jwt.SubjectValidator("sub"))
//	// handle error
//
// The main advantage of doing the latter is having more control between each step, otherwise running Decode is recommended.
func (d *Decoder) Decode(payload Validator, funcs ...ValidatorFunc) error {
	if d.vr == nil {
		return ErrMissingVerifier
	}

	r, err := Parse(d.token)
	if err != nil {
		return err
	}

	// Decode both header and payload.
	if d.h, err = r.Decode(payload); err != nil {
		return err
	}
	// Check whether the incoming header contains the correct "alg" field.
	if err = d.h.Validate(d.vr); err != nil {
		return err
	}
	// Verify the signature.
	if err = r.Verify(d.vr); err != nil {
		return err
	}
	// Validate payload claims.
	return payload.Validate(funcs...)
}

// Header returns the decoded token's JOSE header.
func (d *Decoder) Header() Header { return d.h }
