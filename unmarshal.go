package jwt

import (
	"bytes"
	"encoding/json"
)

// Unmarshal unmarshals a token and assign a JWT to an interface.
func Unmarshal(b []byte, v interface{}) error {
	sep := bytes.IndexByte(b, '.')
	if sep < 0 { // RFC 7519, section 7.2.1
		return ErrMalformedToken
	}

	encHdr := b[:sep] // RFC 7519, section 7.2.2
	hdrSize := enc.DecodedLen(len(encHdr))
	decHdr := make([]byte, hdrSize)
	if _, err := enc.Decode(decHdr, encHdr); err != nil { // RFC 7519, section 7.2.3
		return err
	}
	var hdr Header
	hdr.header = &header{}
	if err := json.Unmarshal(decHdr, &hdr); err != nil { // RFC 7519, sections 7.2.{4,5,6,7,8}
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
	jot, err := extractJWT(v, true)
	if err != nil {
		return err
	}
	jot.Header = &hdr
	return nil
}
