package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	. "github.com/gbrlsnchs/jwt/v3"
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
		{NewRSA(SHA256, priv, nil), NewRSA(SHA256, nil, &priv.PublicKey), nil, nil, nil, nil, nil},
		{NewRSA(SHA256, priv, nil).WithPSS(), NewRSA(SHA256, nil, &priv.PublicKey).WithPSS(), nil, nil, nil, nil, nil},
		{NewRSA(SHA256, priv, nil), NewRSA(SHA256, nil, &priv2.PublicKey), nil, nil, nil, nil, rsa.ErrVerification},
		{NewRSA(SHA256, priv, nil).WithPSS(), NewRSA(SHA256, nil, &priv2.PublicKey).WithPSS(), nil, nil, nil, nil, rsa.ErrVerification},
		{NewRSA(SHA256, nil, nil), NewRSA(SHA256, nil, nil), nil, ErrRSANilPrivKey, nil, nil, nil},
		{NewRSA(SHA256, nil, nil).WithPSS(), NewRSA(SHA256, nil, nil).WithPSS(), nil, ErrRSANilPrivKey, nil, nil, nil},
		{NewRSA(SHA256, priv, nil), NewRSA(SHA256, nil, nil), nil, nil, nil, nil, ErrRSANilPubKey},
		{NewRSA(SHA256, priv, nil).WithPSS(), NewRSA(SHA256, nil, nil).WithPSS(), nil, nil, nil, nil, ErrRSANilPubKey},
		{NewRSA(SHA384, priv, nil), NewRSA(SHA384, nil, &priv.PublicKey), nil, nil, nil, nil, nil},
		{NewRSA(SHA384, priv, nil).WithPSS(), NewRSA(SHA384, nil, &priv.PublicKey).WithPSS(), nil, nil, nil, nil, nil},
		{NewRSA(SHA384, priv, nil), NewRSA(SHA384, nil, &priv2.PublicKey), nil, nil, nil, nil, rsa.ErrVerification},
		{NewRSA(SHA384, priv, nil).WithPSS(), NewRSA(SHA384, nil, &priv2.PublicKey).WithPSS(), nil, nil, nil, nil, rsa.ErrVerification},
		{NewRSA(SHA384, nil, nil), NewRSA(SHA384, nil, nil), nil, ErrRSANilPrivKey, nil, nil, nil},
		{NewRSA(SHA384, nil, nil).WithPSS(), NewRSA(SHA384, nil, nil).WithPSS(), nil, ErrRSANilPrivKey, nil, nil, nil},
		{NewRSA(SHA384, priv, nil), NewRSA(SHA384, nil, nil), nil, nil, nil, nil, ErrRSANilPubKey},
		{NewRSA(SHA384, priv, nil).WithPSS(), NewRSA(SHA384, nil, nil).WithPSS(), nil, nil, nil, nil, ErrRSANilPubKey},
		{NewRSA(SHA512, priv, nil), NewRSA(SHA512, nil, &priv.PublicKey), nil, nil, nil, nil, nil},
		{NewRSA(SHA512, priv, nil).WithPSS(), NewRSA(SHA512, nil, &priv.PublicKey).WithPSS(), nil, nil, nil, nil, nil},
		{NewRSA(SHA512, priv, nil), NewRSA(SHA512, nil, &priv2.PublicKey), nil, nil, nil, nil, rsa.ErrVerification},
		{NewRSA(SHA512, priv, nil).WithPSS(), NewRSA(SHA512, nil, &priv2.PublicKey).WithPSS(), nil, nil, nil, nil, rsa.ErrVerification},
		{NewRSA(SHA512, nil, nil), NewRSA(SHA512, nil, nil), nil, ErrRSANilPrivKey, nil, nil, nil},
		{NewRSA(SHA512, nil, nil).WithPSS(), NewRSA(SHA512, nil, nil).WithPSS(), nil, ErrRSANilPrivKey, nil, nil, nil},
		{NewRSA(SHA512, priv, nil), NewRSA(SHA512, nil, nil), nil, nil, nil, nil, ErrRSANilPubKey},
		{NewRSA(SHA512, priv, nil).WithPSS(), NewRSA(SHA512, nil, nil).WithPSS(), nil, nil, nil, nil, ErrRSANilPubKey},
	}
	testJWT(t, testCases)
}
