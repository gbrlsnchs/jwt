package jwt_test

import (
	"testing"

	. "github.com/gbrlsnchs/jwt/v2"
)

func TestHMAC(t *testing.T) {
	testCases := []testCase{
		{NewHS256(""), NewHS256(""), nil, ErrNoHMACKey, nil, nil, ErrNoHMACKey},
		{NewHS256("secret"), NewHS256("secret"), nil, nil, nil, nil, nil},
		{NewHS256("secret"), NewHS256("not_secret"), nil, nil, nil, nil, ErrHMACInvalid},
		{NewHS256("not_secret"), NewHS256("secret"), nil, nil, nil, nil, ErrHMACInvalid},
	}
	testJWT(t, testCases)
}
