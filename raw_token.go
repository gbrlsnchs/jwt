package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// ErrMalformed indicates a token doesn't have a valid format, as per the RFC 7519.
var ErrMalformed = errors.New("jwt: malformed token")

// RawToken is a representation
// of a parsed JWT string.
type RawToken struct {
	token      []byte
	sep1, sep2 int
}

// Parse parses a byte slice representing a JWT and returns a raw JWT,
// which can be verified and decoded into a struct that implements Token.
func Parse(token []byte) (RawToken, error) {
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

// Decode decodes a raw JWT a payload and returns its header.
func (r RawToken) Decode(payload interface{}) (h Header, err error) {
	// Next, unmarshal the token accordingly.
	var (
		enc      []byte // encoded header/payload
		dec      []byte // decoded header/payload
		encoding = base64.RawURLEncoding
	)
	// Claims.
	enc = r.claims()
	dec = make([]byte, encoding.DecodedLen(len(enc)))
	if _, err = encoding.Decode(dec, enc); err != nil {
		return
	}
	if err = json.Unmarshal(dec, payload); err != nil {
		return
	}
	// Header.
	enc = r.header()
	dec = make([]byte, encoding.DecodedLen(len(enc)))
	if _, err = encoding.Decode(dec, enc); err != nil {
		return
	}
	err = json.Unmarshal(dec, &h)
	return
}

// Verify verifies a JWT signature with a verifying method that
// implements the Verifier interface and returns a RawToken, which can
// be used to be decoded to a JWT struct. If a verification error occurs,
// the parsed RawToken is also returned, for debugging purposes.
func (r RawToken) Verify(vr Verifier) error {
	return vr.Verify(r.payload(), r.sig())
}

func (r RawToken) claims() []byte  { return r.token[r.sep1+1 : r.sep2] }
func (r RawToken) header() []byte  { return r.token[:r.sep1] }
func (r RawToken) payload() []byte { return r.token[:r.sep2] }
func (r RawToken) sig() []byte     { return r.token[r.sep2+1:] }
