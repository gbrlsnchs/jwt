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
func Verify(token []byte, alg Algorithm, opts ...VerifyOption) error {
	rt := &RawToken{alg: alg}

	sep1 := bytes.IndexByte(token, '.')
	if sep1 < 0 {
		return ErrMalformed
	}

	cbytes := token[sep1+1:]
	sep2 := bytes.IndexByte(cbytes, '.')
	if sep2 < 0 {
		return ErrMalformed
	}
	rt.setToken(token, sep1, sep2)

	var err error
	for _, opt := range opts {
		if err = opt(rt); err != nil {
			return err
		}
	}
	if err = alg.Verify(rt.headerPayload(), rt.sig()); err != nil {
		return err
	}
	if rt.payloadAddr != nil {
		if err = rt.decode(); err != nil {
			return err
		}
	}
	return nil
}

// DecodeHeader decodes into hd. If validate is truthy, hd is also validated.
func DecodeHeader(hd *Header, validate bool) VerifyOption {
	return func(rt *RawToken) error {
		if rt.hdAddr == nil {
			var hd Header
			if err := internal.Decode(rt.header(), &hd); err != nil {
				return err
			}
			rt.hdAddr = &hd
		}
		*hd = *rt.hdAddr
		if validate && rt.alg.Name() != rt.hdAddr.Algorithm {
			return internal.Errorf("jwt: unexpected algorithm %q: %w", hd.Algorithm, ErrAlgValidation)
		}
		return nil
	}
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

// ValidateHeader checks whether the algorithm contained
// in the JOSE header is the same used by the algorithm.
func ValidateHeader(rt *RawToken) error {
	var hd Header
	return DecodeHeader(&hd, true)(rt)
}

// Compile-time checks.
var _ VerifyOption = ValidateHeader
var _ VerifyOption = DecodeHeader(nil, false)
var _ VerifyOption = DecodePayload(nil)
