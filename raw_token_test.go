package jwt_test

import (
	"testing"

	"github.com/gbrlsnchs/jwt/v3"
	"github.com/gbrlsnchs/jwt/v3/internal"
)

func TestParse(t *testing.T) {
	testCases := []struct {
		token []byte
		err   error
	}{
		{[]byte(validToken), nil},
		{[]byte(validToken[:112]), nil},
		{[]byte(validToken[:111]), jwt.ErrMalformed},
		{[]byte("a.a."), nil},  // parsable, not valid
		{[]byte("a.a.a"), nil}, // parsable, not valid
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			_, err := jwt.Parse(tc.token)
			if want, got := tc.err, err; !internal.ErrorIs(got, want) {
				t.Errorf("want %v, got %v", want, got)
			}
		})
	}
}
