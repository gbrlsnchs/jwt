package jwt_test

import (
	"testing"

	. "github.com/gbrlsnchs/jwt/v2"
)

func TestHMAC(t *testing.T) {
	testCases := []testCase{
		{NewHS256(""), NewHS256(""), nil, ErrNoHMACKey, nil, nil, ErrNoHMACKey},
		{NewHS256("secret"), NewHS256("secret"), nil, nil, nil, nil, nil},
		{NewHS256("secret"), NewHS256("not_secret"), nil, nil, nil, nil, ErrHMACVerification},
		{NewHS256("not_secret"), NewHS256("secret"), nil, nil, nil, nil, ErrHMACVerification},
		{NewHS384(""), NewHS384(""), nil, ErrNoHMACKey, nil, nil, ErrNoHMACKey},
		{NewHS384("secret"), NewHS384("secret"), nil, nil, nil, nil, nil},
		{NewHS384("secret"), NewHS384("not_secret"), nil, nil, nil, nil, ErrHMACVerification},
		{NewHS384("not_secret"), NewHS384("secret"), nil, nil, nil, nil, ErrHMACVerification},
		{NewHS512(""), NewHS512(""), nil, ErrNoHMACKey, nil, nil, ErrNoHMACKey},
		{NewHS512("secret"), NewHS512("secret"), nil, nil, nil, nil, nil},
		{NewHS512("secret"), NewHS512("not_secret"), nil, nil, nil, nil, ErrHMACVerification},
		{NewHS512("not_secret"), NewHS512("secret"), nil, nil, nil, nil, ErrHMACVerification},
	}
	testJWT(t, testCases)
}
