package jwt

import "github.com/gbrlsnchs/jwt/v3/internal"

// ErrMalformed indicates a token doesn't have a valid format, as per the RFC 7519.
var ErrMalformed = internal.NewError("jwt: malformed token")

// RawToken is a representation of a parsed JWT string.
type RawToken struct {
	token      []byte
	sep1, sep2 int
	malformed  bool

	hd Header
}

// Decode decodes a raw JWT into a payload and returns its header.
func (raw RawToken) Decode(payload interface{}) error {
	if raw.malformed {
		return ErrMalformed
	}
	return internal.Decode(raw.payload(), payload)
}

// Header returns a JOSE Header extracted from a JWT.
func (raw RawToken) Header() Header {
	return raw.hd
}

func (raw RawToken) header() []byte        { return raw.token[:raw.sep1] }
func (raw RawToken) headerPayload() []byte { return raw.token[:raw.sep2] }
func (raw RawToken) payload() []byte       { return raw.token[raw.sep1+1 : raw.sep2] }
func (raw RawToken) sig() []byte           { return raw.token[raw.sep2+1:] }

func (raw RawToken) withSeps(sep1, sep2 int) RawToken {
	raw.sep1 = sep1
	raw.sep2 = sep1 + 1 + sep2
	raw.token = token
	return r
}
