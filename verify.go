package jwt

import (
	"bytes"
	"errors"
)

// ErrMalformed indicates a token doesn't have a valid format, as per the RFC 7519.
var ErrMalformed = errors.New("jwt: malformed token")

// Verify verifies a JWT signature with a verifying method that
// implements the Verifier interface and returns a RawToken, which can
// be used to be decoded to a JWT struct. If a verification error occurs,
// the parsed RawToken is also returned, for debugging purposes.
func Verify(token []byte, vr Verifier) (r RawToken, err error) {
	// Firstly, parse and verify.
	if r, err = parse(token); err != nil {
		return
	}
	err = vr.Verify(r.payload(), r.sig())
	return

}

func parse(token []byte) (RawToken, error) {
	var t RawToken

	sep1 := bytes.IndexByte(token, '.')
	if sep1 < 0 {
		return t, ErrMalformed
	}
	t.sep1 = sep1

	cbytes := token[sep1+1:]
	sep2 := bytes.IndexByte(cbytes, '.')
	if sep2 < 0 {
		return t, ErrMalformed
	}
	t.sep2 = sep1 + 1 + sep2
	t.token = token
	return t, nil
}
