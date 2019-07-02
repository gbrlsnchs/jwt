package jwt

import (
	"bytes"

	"github.com/gbrlsnchs/jwt/v3/internal"
)

// ErrAlgValidation indicates an incoming JWT's "alg" field mismatches the Validator's.
var ErrAlgValidation = internal.NewError(`"alg" field mismatch`)

// Verify verifies a token's signature.
func Verify(alg Algorithm, token []byte) (RawToken, error) {
	var raw RawToken

	sep1 := bytes.IndexByte(token, '.')
	if sep1 < 0 {
		return raw, ErrMalformed
	}

	cbytes := token[sep1+1:]
	sep2 := bytes.IndexByte(cbytes, '.')
	if sep2 < 0 {
		return raw, ErrMalformed
	}
	raw = raw.withToken(token, sep1, sep2)

	if err := internal.Decode(raw.header(), &raw.hd); err != nil {
		return raw, err
	}
	raw.valid = true

	if alg.Name() != raw.hd.Algorithm {
		return raw, internal.Errorf("jwt: unexpected algorithm %q: %w", raw.hd.Algorithm, ErrAlgValidation)
	}
	return raw, alg.Verify(raw.headerPayload(), raw.sig())
}
