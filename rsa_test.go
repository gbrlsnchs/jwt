package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	. "github.com/gbrlsnchs/jwt"
)

func TestRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("%v", err)
	}
	pub := &priv.PublicKey
	priv2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	pub2 := &priv2.PublicKey
	testCases := []struct {
		s, v                   Signer
		errOnSign, errOnVerify bool
	}{
		{s: RS256(nil, nil), errOnSign: true},
		{s: RS256(nil, pub), errOnSign: true},
		{s: RS256(priv, pub)},
		{s: RS256(priv, pub2), errOnVerify: true},
		{s: RS384(priv, pub)},
		{s: RS384(priv, pub2), errOnVerify: true},
		{s: RS512(priv, pub)},
		{s: RS512(priv, pub2), errOnVerify: true},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			run(t, tc.s, tc.v, tc.errOnSign, tc.errOnVerify)
		})
	}
}
