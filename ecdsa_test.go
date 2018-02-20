package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	. "github.com/gbrlsnchs/jwt"
	. "github.com/gbrlsnchs/jwt/internal"
)

func TestECDSA(t *testing.T) {
	ecdsa256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		t.Fatalf("%v\n", err)
	}

	ecdsa256Pub := &ecdsa256Priv.PublicKey
	ecdsa256Priv2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		t.Fatalf("%v\n", err)
	}

	ecdsa256Pub2 := &ecdsa256Priv2.PublicKey
	ecdsa384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	if err != nil {
		t.Fatalf("%v\n", err)
	}

	ecdsa384Pub := &ecdsa384Priv.PublicKey
	ecdsa384Priv2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	if err != nil {
		t.Fatalf("%v\n", err)
	}

	ecdsa384Pub2 := &ecdsa384Priv2.PublicKey
	ecdsa512Priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	if err != nil {
		t.Fatalf("%v\n", err)
	}

	ecdsa512Pub := &ecdsa512Priv.PublicKey
	ecdsa512Priv2, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	if err != nil {
		t.Fatalf("%v\n", err)
	}

	ecdsa512Pub2 := &ecdsa512Priv2.PublicKey
	tests := []*TestTable{
		{
			Signer: ES256(ecdsa256Priv, ecdsa256Pub),
		},
		{
			Signer:     ES256(ecdsa256Priv, ecdsa256Pub2),
			ParsingErr: true,
		},
		{
			Signer: ES384(ecdsa384Priv, ecdsa384Pub),
		},
		{
			Signer:     ES384(ecdsa384Priv, ecdsa384Pub2),
			ParsingErr: true,
		},
		{
			Signer: ES512(ecdsa512Priv, ecdsa512Pub),
		},
		{
			Signer:     ES512(ecdsa512Priv, ecdsa512Pub2),
			ParsingErr: true,
		},
	}

	RunTests(t, tests)
}
