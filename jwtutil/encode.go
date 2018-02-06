package jwtutil

import (
	"encoding/base64"
	"strings"
)

// Encode returns an encoded string using base64 encoding.
func Encode(src []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(src), stdPadding)
}
