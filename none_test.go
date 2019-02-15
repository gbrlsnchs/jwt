package jwt_test

import (
	"testing"

	. "github.com/gbrlsnchs/jwt/v3"
)

func TestNone(t *testing.T) {
	testCases := []testCase{
		{NewNone(), NewNone(), nil, nil, nil, nil, nil},
		{NewNone(), NewHS256("secret"), nil, nil, nil, nil, ErrHMACVerification},
		{NewHS256("secret"), NewNone(), nil, nil, nil, nil, nil},
	}
	testJWT(t, testCases)
}
