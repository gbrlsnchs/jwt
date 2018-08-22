package jwt_test

import (
	"testing"

	. "github.com/gbrlsnchs/jwt"
)

func TestHMAC(t *testing.T) {
	testCases := []struct {
		s, v                   Signer
		errOnSign, errOnVerify bool
	}{
		{s: HS256(""), errOnSign: true},
		{s: HS256("secret")},
		{s: HS256("secret"), v: HS256("terces"), errOnVerify: true},
		{s: HS384("secret")},
		{s: HS384("secret"), v: HS384("terces"), errOnVerify: true},
		{s: HS512("secret")},
		{s: HS512("secret"), v: HS512("terces"), errOnVerify: true},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			run(t, tc.s, tc.v, tc.errOnSign, tc.errOnVerify)
		})
	}
}
