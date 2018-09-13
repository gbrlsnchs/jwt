package jwt

import (
	"bytes"
	"encoding/json"
)

// Unmarshaler is the interface inmplemented by types
// that can unmarshal a JWT description of themselves.
type Unmarshaler interface {
	UnmarshalJWT([]byte) error
}

// Unmarshal unmarshals a token according to RFC 7519 and assigns a JWT to an interface.
func Unmarshal(b []byte, v interface{}) error {
	if m, ok := v.(Unmarshaler); ok {
		return m.UnmarshalJWT(b)
	}
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
	var hdr header
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
	if jot, ok := v.(joser); ok {
		jot.setHeader(&hdr)
	}
	return nil
}
