package jwt

import (
	"encoding/base64"
	"encoding/json"
)

type RawToken struct {
	token      []byte
	sep1, sep2 int
}

func (r RawToken) claims() []byte  { return r.token[r.sep1+1 : r.sep2] }
func (r RawToken) header() []byte  { return r.token[:r.sep1] }
func (r RawToken) payload() []byte { return r.token[:r.sep2] }
func (r RawToken) sig() []byte     { return r.token[r.sep2+1:] }

func (r RawToken) Decode(t Token) error {
	// Next, unmarshal the token accordingly.
	var (
		enc      []byte // encoded header/claims
		dec      []byte // decoded header/claims
		encoding = base64.RawURLEncoding
		err      error
	)
	// Header.
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
