package jwt

import "bytes"

// Parse splits a string JWT representation in payload and signature for further inspection.
func Parse(token string) ([]byte, []byte, error) {
	return ParseBytes([]byte(token))
}

// ParseBytes does the same parsing as Parse but accepts a byte slice instead.
func ParseBytes(token []byte) ([]byte, []byte, error) {
	sep1 := bytes.IndexByte(token, '.')
	if sep1 < 0 { // RFC 7519, section 7.2.1
		return nil, nil, ErrMalformed
	}

	cls := token[sep1+1:]
	sep2 := bytes.IndexByte(cls, '.')
	if sep2 < 0 {
		return nil, nil, ErrMalformed
	}
	sep2 += sep1 + 1
	return token[:sep2], token[sep2+1:], nil
}
