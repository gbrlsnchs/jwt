package jwtutil

import "encoding/base64"

const (
	// Separator is the character between
	// "Bearer" and the token itself.
	Separator  = " "
	stdPadding = string(base64.StdPadding)
)
