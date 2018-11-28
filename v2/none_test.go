package jwt_test

import (
	"testing"

	. "github.com/gbrlsnchs/jwt/v2"
)

func TestNone(t *testing.T) {
	testCases := []testCase{
		{None(), None(), nil, nil, nil, nil, nil},
		{None(), NewHS256("secret"), nil, nil, nil, nil, ErrHMACVerification},
		{NewHS256("secret"), None(), nil, nil, nil, nil, nil},
	}
	testJWT(t, testCases)
}
