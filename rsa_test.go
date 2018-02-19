package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	. "github.com/gbrlsnchs/jwt"
	. "github.com/gbrlsnchs/jwt/internal"
)

func TestRSA(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		t.Fatalf("%v\n", err)
	}
	rsaPub := &rsaPriv.PublicKey
	rsaPriv2, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		t.Fatalf("%v\n", err)
	}
	rsaPub2 := &rsaPriv2.PublicKey
	tests := []*TestTable{
		{
			Signer: RS256(rsaPriv, rsaPub),
		},
		{
			Signer:     RS256(rsaPriv, rsaPub2),
			ParsingErr: true,
		},
		{
			Signer: RS384(rsaPriv, rsaPub),
		},
		{
			Signer:     RS384(rsaPriv, rsaPub2),
			ParsingErr: true,
		},
		{
			Signer: RS512(rsaPriv, rsaPub),
		},
		{
			Signer:     RS512(rsaPriv, rsaPub2),
			ParsingErr: true,
		},
	}

	RunTests(t, tests)
}
