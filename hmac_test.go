package jwt_test

import (
	"testing"

	. "github.com/gbrlsnchs/jwt/v2"
)

func TestHMAC(t *testing.T) {
	testCases := []testCase{
		{HS256(""), HS256(""), nil, ErrNoHMACKey, nil, nil, ErrNoHMACKey},
		{HS256("secret"), HS256("secret"), nil, nil, nil, nil, nil},
		{HS256("secret"), HS256("not_secret"), nil, nil, nil, nil, ErrHMACInvalid},
		{HS256("not_secret"), HS256("secret"), nil, nil, nil, nil, ErrHMACInvalid},
	}
	testJWT(t, testCases)
}
