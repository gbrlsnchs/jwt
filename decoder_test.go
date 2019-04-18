package jwt_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	. "github.com/gbrlsnchs/jwt/v3"
	"github.com/stretchr/testify/assert"
)

// Token extracted from https://jwt.io.
const validToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
	"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

func TestDecode(t *testing.T) {
	testCases := []struct {
		token []byte
		p     *Payload
		err   interface{}
	}{
		{[]byte(validToken), new(Payload), nil},
		{[]byte(validToken[:112]), new(Payload), ErrHMACVerification},
		{[]byte(validToken[:111]), new(Payload), ErrMalformed},
		{[]byte(".."), new(Payload), new(json.SyntaxError)},
		{[]byte("{}.{}."), new(Payload), base64.CorruptInputError(0)},
		{[]byte(validToken), nil, new(json.InvalidUnmarshalError)},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			assert := assert.New(t)
			err := NewDecoder(tc.token, NewHMAC(SHA256, []byte("your-256-bit-secret"))).Decode(tc.p)
			switch v := err.(type) {
			case base64.CorruptInputError:
				assert.IsType(tc.err, v)
			case *json.SyntaxError:
				assert.IsType(tc.err, v)
			case *json.InvalidUnmarshalError:
				assert.IsType(tc.err, v)
			default:
				assert.Equal(tc.err, v)
			}
		})
	}
}
