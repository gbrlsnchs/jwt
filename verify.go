package jwt

import (
	"bytes"
	"errors"
)

// ErrMalformed indicates a token doesn't have a valid format, as per the RFC 7519.
var ErrMalformed = errors.New("jwt: malformed token")

func Verify(token []byte, vr Verifier) (r RawToken, err error) {
	// Firstly, parse and verify.
	if r, err = parse(token); err != nil {
		return
	}
	if err = vr.Verify(r.payload(), r.sig()); err != nil {
		return
	}
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
