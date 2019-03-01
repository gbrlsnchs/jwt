package jwt_test

import (
	"crypto/rand"
	"testing"

	. "github.com/gbrlsnchs/jwt/v3"
	"golang.org/x/crypto/ed25519"
)

func TestEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	testCases := []testCase{
		{NewEd25519(priv, nil), NewEd25519(nil, pub), nil, nil, nil, nil},
		{NewEd25519(priv, nil), NewEd25519(nil, pub2), nil, nil, nil, ErrEd25519Verification},
		{NewEd25519(priv2, nil), NewEd25519(nil, pub), nil, nil, nil, ErrEd25519Verification},
		{NewEd25519(nil, nil), NewEd25519(nil, nil), ErrEd25519PrivKey, nil, nil, nil},
		{NewEd25519(priv, nil), NewEd25519(nil, nil), nil, nil, nil, ErrEd25519PubKey},
	}
	testJWT(t, testCases)
}
