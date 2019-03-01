package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	. "github.com/gbrlsnchs/jwt/v3"
)

func TestECDSA(t *testing.T) {
	priv256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv256_2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv384_2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv512, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv512_2, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	testCases := []testCase{
		{NewECDSA(SHA256, priv256, nil), NewECDSA(SHA256, nil, &priv256.PublicKey), nil, nil, nil, nil},
		{NewECDSA(SHA256, priv256, nil), NewECDSA(SHA256, nil, &priv256_2.PublicKey), nil, nil, nil, ErrECDSAVerification},
		{NewECDSA(SHA256, nil, nil), NewECDSA(SHA256, nil, nil), ErrECDSANilPrivKey, nil, nil, nil},
		{NewECDSA(SHA256, priv256, nil), NewECDSA(SHA256, nil, nil), nil, nil, nil, ErrECDSANilPubKey},
		{NewECDSA(SHA384, priv384, nil), NewECDSA(SHA384, nil, &priv384.PublicKey), nil, nil, nil, nil},
		{NewECDSA(SHA384, priv384, nil), NewECDSA(SHA384, nil, &priv384_2.PublicKey), nil, nil, nil, ErrECDSAVerification},
		{NewECDSA(SHA384, nil, nil), NewECDSA(SHA384, nil, nil), ErrECDSANilPrivKey, nil, nil, nil},
		{NewECDSA(SHA384, priv384, nil), NewECDSA(SHA384, nil, nil), nil, nil, nil, ErrECDSANilPubKey},
		{NewECDSA(SHA512, priv512, nil), NewECDSA(SHA512, nil, &priv512.PublicKey), nil, nil, nil, nil},
		{NewECDSA(SHA512, priv512, nil), NewECDSA(SHA512, nil, &priv512_2.PublicKey), nil, nil, nil, ErrECDSAVerification},
		{NewECDSA(SHA512, nil, nil), NewECDSA(SHA512, nil, nil), ErrECDSANilPrivKey, nil, nil, nil},
		{NewECDSA(SHA512, priv512, nil), NewECDSA(SHA512, nil, nil), nil, nil, nil, ErrECDSANilPubKey},
	}
	testJWT(t, testCases)
}
