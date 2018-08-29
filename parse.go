package jwt

import (
	"bytes"
)

func parseBytes(b []byte) ([]byte, []byte, error) {
	sep1 := bytes.IndexByte(b, '.')
	if sep1 < 0 { // RFC 7519, section 7.2.1
		return nil, nil, ErrMalformedToken
	}

	cls := b[sep1+1:]
	sep2 := bytes.IndexByte(cls, '.')
	if sep2 < 0 {
		return nil, nil, ErrMalformedToken
	}
	sep2 += sep1 + 1
	return b[:sep2], b[sep2+1:], nil
}
