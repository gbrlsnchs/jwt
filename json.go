package jwt

import "errors"

// ErrNotJSONObject is the error for when a JWT payload is not a JSON object.
var ErrNotJSONObject = errors.New("jwt: payload is not a valid JSON object")

func isJSONObject(payload []byte) bool {
	return payload[0] == '{' && payload[len(payload)-1] == '}'
}
