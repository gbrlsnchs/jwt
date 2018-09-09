package jwt

import "bytes"

// Parse returns both the payload and the signature encoded to Base64 or an error if token is invalid.
func Parse(token string) ([]byte, []byte, error) {
	return ParseBytes([]byte(token))
}

// ParseBytes does the same parsing as Parse but accepts a byte slice instead.
func ParseBytes(token []byte) ([]byte, []byte, error) {
	sep1 := bytes.IndexByte(token, '.')
	if sep1 < 0 {
		return nil, nil, ErrMalformed
	}

	clsBytes := token[sep1+1:]
	sep2 := bytes.IndexByte(clsBytes, '.')
	if sep2 < 0 {
		return nil, nil, ErrMalformed
	}
	sep2 += sep1 + 1
	return token[:sep2], token[sep2+1:], nil
}
