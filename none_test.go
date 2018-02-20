package jwt_test

import (
	"testing"

	. "github.com/gbrlsnchs/jwt"
	. "github.com/gbrlsnchs/jwt/internal"
)

func TestNone(t *testing.T) {
	tests := []*TestTable{
		{
			Signer: None(),
		},
		{
			Signer: HS256("secret"),
			Verif:  None(),
		},
		{
			Signer:     None(),
			Verif:      HS256("secret"),
			ParsingErr: true,
		},
	}

	RunTests(t, tests)
}
