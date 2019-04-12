package jwt_test

import (
	"encoding/base64"
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
		token string
		err   error
	}{
		{validToken, nil},
		{validToken[:112], nil},
		{validToken[:111], ErrMalformed},
		{"..", ErrMalformed},
		{"{}..", base64.CorruptInputError},
		{"{}.{}.", base64.CorruptInputError},
		{"e30.e30.", ErrAlgValidation},
		{"not.valid.", base64.CorruptInputError},
	}
	for _, tc := range testCases {
		t.Run(tc.token, func(t *testing.T) {
			_, err := Parse([]byte(tc.token))
			assert.Equal(t, tc.err, err)
		})
	}
}
