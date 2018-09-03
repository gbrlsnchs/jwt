package jwt

import (
	"bytes"
	"encoding/json"
)

// Unmarshal unmarshals a token and assign a JWT to an interface.
func Unmarshal(b []byte, v interface{}) error {
	sep := bytes.IndexByte(b, '.')
	if sep < 0 {
		return ErrMalformed
	}

	encHdr := b[:sep]
	hdrSize := enc.DecodedLen(len(encHdr))
	decHdr := make([]byte, hdrSize)
	if _, err := enc.Decode(decHdr, encHdr); err != nil {
		return err
	}
	var hdr Header
	if err := json.Unmarshal(decHdr, &hdr); err != nil {
		return err
	}

	encCls := b[sep+1:]
	clsSize := enc.DecodedLen(len(encCls))
	decCls := make([]byte, clsSize)
	if _, err := enc.Decode(decCls, encCls); err != nil {
		return err
	}
	if err := json.Unmarshal(decCls, v); err != nil {
		return err
	}

	// Extract the JWT from the interface to
	// be able to set a header to it.
	if jot := extractJWT(v); jot != nil {
		jot.Header = &hdr
	}
	return nil
}
