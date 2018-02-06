package jwtutil

import (
	"encoding/base64"
	"strings"
)

// Decode returns a decoded string using base64 decoding.
func Decode(src string) ([]byte, error) {
	if mod := len(src) % 4; mod > 0 {
		src += strings.Repeat(stdPadding, 4-mod)
	}

	dec, err := base64.URLEncoding.DecodeString(src)

	if err != nil {
		return nil, err
	}

	return dec, nil
}
