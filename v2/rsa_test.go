package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	. "github.com/gbrlsnchs/jwt/v2"
)

func TestRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	priv2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	testCases := []testCase{
		{NewRS256(priv, nil), NewRS256(nil, &priv.PublicKey), nil, nil, nil, nil, nil},
		{NewRS256(priv, nil), NewRS256(nil, &priv2.PublicKey), nil, nil, nil, nil, rsa.ErrVerification},
		{NewRS256(nil, nil), NewRS256(nil, nil), nil, ErrRSANilPrivKey, nil, nil, nil},
		{NewRS256(priv, nil), NewRS256(nil, nil), nil, nil, nil, nil, ErrRSANilPubKey},
		{NewRS384(priv, nil), NewRS384(nil, &priv.PublicKey), nil, nil, nil, nil, nil},
		{NewRS384(priv, nil), NewRS384(nil, &priv2.PublicKey), nil, nil, nil, nil, rsa.ErrVerification},
		{NewRS384(nil, nil), NewRS384(nil, nil), nil, ErrRSANilPrivKey, nil, nil, nil},
		{NewRS384(priv, nil), NewRS384(nil, nil), nil, nil, nil, nil, ErrRSANilPubKey},
		{NewRS512(priv, nil), NewRS512(nil, &priv.PublicKey), nil, nil, nil, nil, nil},
		{NewRS512(priv, nil), NewRS512(nil, &priv2.PublicKey), nil, nil, nil, nil, rsa.ErrVerification},
		{NewRS512(nil, nil), NewRS512(nil, nil), nil, ErrRSANilPrivKey, nil, nil, nil},
		{NewRS512(priv, nil), NewRS512(nil, nil), nil, nil, nil, nil, ErrRSANilPubKey},
	}
	testJWT(t, testCases)
}
