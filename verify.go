package jwt

import (
	"bytes"

	"github.com/gbrlsnchs/jwt/v3/internal"
)

// ErrAlgValidation indicates an incoming JWT's "alg" field mismatches the Validator's.
var ErrAlgValidation = internal.NewError(`"alg" field mismatch`)

// VerifyOption is a functional option for verifying.
type VerifyOption func(*RawToken) error

// Verify verifies a token's signature using alg. Before verification, opts is iterated and
// each option in it is run.
func Verify(token []byte, payload interface{}, alg Algorithm, opts ...VerifyOption) (Header, error) {
	rt := &RawToken{
		alg: alg,
	}

	sep1 := bytes.IndexByte(token, '.')
	if sep1 < 0 {
		return rt.hd, ErrMalformed
	}

	cbytes := token[sep1+1:]
	sep2 := bytes.IndexByte(cbytes, '.')
	if sep2 < 0 {
		return rt.hd, ErrMalformed
	}
	rt.setToken(token, sep1, sep2)

	var err error
	for _, opt := range opts {
		if err = opt(rt); err != nil {
			return rt.hd, err
		}
	}
	if err = alg.Verify(rt.headerPayload(), rt.sig()); err != nil {
		return rt.hd, err
	}
	return rt.hd, rt.decode(payload)
}

// ValidateHeader checks whether the algorithm contained
// in the JOSE header is the same used by the algorithm.
func ValidateHeader(rt *RawToken) error {
	if rt.alg.Name() != rt.hd.Algorithm {
		return internal.Errorf("jwt: unexpected algorithm %q: %w", rt.hd.Algorithm, ErrAlgValidation)
	}
	return nil
}

// DecodePayload flags a payload to be decoded. After decoding, validators is iterated and
// each validator in it is run.
func DecodePayload(payload interface{}, validators ...ValidatorFunc) VerifyOption {
	return func(rt *RawToken) (err error) {
		rt.payloadAddr = payload
		rt.payloadValidators = validators
		return nil
	}
}

// Compile-time checks.
var _ VerifyOption = ValidateHeader
