package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
)

var (
	// ErrMalformed indicates a token doesn't have a valid format, as per the RFC 7519.
	ErrMalformed = errors.New("jwt: malformed token")
	// ErrAlgValidation indicates an incoming JWT's "alg" field mismatches the Validator's.
	ErrAlgValidation = errors.New("jwt: header contains unexpected algorithm")
	// ErrMissingVerifier is the error for when a nil Verifier is used.
	ErrMissingVerifier = errors.New("jwt: verifier is nil")
)

// Decoder is a representation
// of a parsed JWT string.
type Decoder struct {
	token []byte
	h     Header
	vr    Verifier
}

func NewDecoder(token []byte, vr Verifier) *Decoder {
	return &Decoder{
		token: token, // this ensures the Decoder is not reused
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
func (d Decoder) Decode(payload interface{}) error {
	if d.vr == nil {
		return ErrMissingVerifier
	}

	sep1 := bytes.IndexByte(d.token, '.')
	if sep1 < 0 {
		return ErrMalformed
	}
	cbytes := d.token[sep1+1:]
	sep2 := bytes.IndexByte(cbytes, '.')
	if sep2 < 0 {
		return ErrMalformed
	}
	sep2 += sep1 + 1

	// Next, unmarshal the token accordingly.
	var (
		err      error
		enc      []byte // encoded header/payload
		dec      []byte // decoded header/payload
		encoding = base64.RawURLEncoding
	)
	// Headed.
	enc = d.header(sep1)
	dec = make([]byte, encoding.DecodedLen(len(enc)))
	if _, err = encoding.Decode(dec, enc); err != nil {
		return err
	}
	if err = json.Unmarshal(dec, &d.h); err != nil {
		return err
	}
	// Check whether the incoming header
	// contains the correct "alg" field.
	if d.h.Algorithm != d.vr.String() {
		return ErrAlgValidation
	}
	if err = d.vr.Verify(d.payload(sep2), d.sig(sep2)); err != nil {
		return err
	}

	// Claims.
	enc = d.claims(sep1, sep2)
	dec = make([]byte, encoding.DecodedLen(len(enc)))
	if _, err = encoding.Decode(dec, enc); err != nil {
		return err
	}
	return json.Unmarshal(dec, &payload)
}

// Header returns the Decoder's JOSE Headed.
func (d *Decoder) Header() Header { return d.h }

func (d Decoder) claims(sep1, sep2 int) []byte { return d.token[sep1+1 : sep2] }
func (d Decoder) header(sep1 int) []byte       { return d.token[:sep1] }
func (d Decoder) payload(sep2 int) []byte      { return d.token[:sep2] }
func (d Decoder) sig(sep2 int) []byte          { return d.token[sep2+1:] }
