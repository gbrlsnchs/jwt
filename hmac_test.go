package jwt_test

import (
	"testing"

	. "github.com/gbrlsnchs/jwt"
	. "github.com/gbrlsnchs/jwt/internal"
)

func TestHMAC(t *testing.T) {
	tests := []*TestTable{
		{
			Signer: HS256("secret"),
		},
		{
			Signer:     HS256("secret"),
			Verif:      HS256("terces"),
			ParsingErr: true,
		},
		{
			Signer: HS384("secret"),
		},
		{
			Signer:     HS384("secret"),
			Verif:      HS384("terces"),
			ParsingErr: true,
		},
		{
			Signer: HS512("secret"),
		},
		{
			Signer:     HS512("secret"),
			Verif:      HS512("terces"),
			ParsingErr: true,
		},
	}

	RunTests(t, tests)
}
