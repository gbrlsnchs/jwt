package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// ErrMalformed indicates a token doesn't have a valid format, as per the RFC 7519.
var ErrMalformed = errors.New("jwt: malformed token")

func Verify(token []byte, t Token, vr Verifier) error {
	// Firstly, parse and verify.
	r, err := parse(token)
	if err != nil {
		return err
	}
	if err = vr.Verify(r.payload(), r.sig()); err != nil {
		return err
	}

	// Next, unmarshal the token accordingly.
	var (
		enc []byte // encoded header/claims
		dec []byte // decoded header/claims
	)
	// Header.
	encoding := base64.RawURLEncoding
	enc = r.header()
	dec = make([]byte, encoding.DecodedLen(len(enc)))
	if _, err = encoding.Decode(dec, enc); err != nil {
		return err
	}
	if err = json.Unmarshal(dec, t.HeaderAddr()); err != nil {
		return err
	}
	// Claims.
	enc = r.claims()
	dec = make([]byte, encoding.DecodedLen(len(enc)))
	if _, err = encoding.Decode(dec, enc); err != nil {
		return err
	}
	if err = json.Unmarshal(dec, &t); err != nil {
		return err
	}
	return nil
}

func parse(token []byte) (raw, error) {
	var t raw

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
