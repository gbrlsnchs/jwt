package jwt_test

import (
	"testing"

	. "github.com/gbrlsnchs/jwt"
)

func TestNone(t *testing.T) {
	testCases := []struct {
		s, v                   Signer
		errOnSign, errOnVerify bool
	}{
		{s: None()},
		{s: HS256("secret"), v: None()},
		{s: None(), v: HS256("secret"), errOnVerify: true},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			run(t, tc.s, tc.v, tc.errOnSign, tc.errOnVerify)
		})
	}
}
