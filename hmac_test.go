package jwt_test

import (
	"testing"

	. "github.com/gbrlsnchs/jwt/v3"
)

func TestHMAC(t *testing.T) {
	testCases := []testCase{
		{NewHMAC(SHA256, []byte("")), NewHMAC(SHA256, []byte("")), ErrNoHMACKey, nil, nil, ErrNoHMACKey},
		{NewHMAC(SHA256, []byte("secret")), NewHMAC(SHA256, []byte("secret")), nil, nil, nil, nil},
		{NewHMAC(SHA256, []byte("secret")), NewHMAC(SHA256, []byte("not_secret")), nil, nil, nil, ErrHMACVerification},
		{NewHMAC(SHA256, []byte("not_secret")), NewHMAC(SHA256, []byte("secret")), nil, nil, nil, ErrHMACVerification},
		{NewHMAC(SHA384, []byte("")), NewHMAC(SHA384, []byte("")), ErrNoHMACKey, nil, nil, ErrNoHMACKey},
		{NewHMAC(SHA384, []byte("secret")), NewHMAC(SHA384, []byte("secret")), nil, nil, nil, nil},
		{NewHMAC(SHA384, []byte("secret")), NewHMAC(SHA384, []byte("not_secret")), nil, nil, nil, ErrHMACVerification},
		{NewHMAC(SHA384, []byte("not_secret")), NewHMAC(SHA384, []byte("secret")), nil, nil, nil, ErrHMACVerification},
		{NewHMAC(SHA512, []byte("")), NewHMAC(SHA512, []byte("")), ErrNoHMACKey, nil, nil, ErrNoHMACKey},
		{NewHMAC(SHA512, []byte("secret")), NewHMAC(SHA512, []byte("secret")), nil, nil, nil, nil},
		{NewHMAC(SHA512, []byte("secret")), NewHMAC(SHA512, []byte("not_secret")), nil, nil, nil, ErrHMACVerification},
		{NewHMAC(SHA512, []byte("not_secret")), NewHMAC(SHA512, []byte("secret")), nil, nil, nil, ErrHMACVerification},
	}
	testJWT(t, testCases)
}
