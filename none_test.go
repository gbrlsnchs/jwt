package jwt_test

import (
	"testing"

	. "github.com/gbrlsnchs/jwt/v3"
)

func TestNone(t *testing.T) {
	testCases := []testCase{
		{NewNone(), NewNone(), nil, nil, nil, nil},
		{NewNone(), NewHMAC(SHA256, []byte("secret")), nil, nil, nil, ErrHMACVerification},
		{NewHMAC(SHA256, []byte("secret")), NewNone(), nil, nil, nil, nil},
	}
	testJWT(t, testCases)
}
