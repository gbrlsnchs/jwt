package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	. "github.com/gbrlsnchs/jwt/v2"
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
		{NewES256(priv256, nil), NewES256(nil, &priv256.PublicKey), nil, nil, nil, nil, nil},
		{NewES256(priv256, nil), NewES256(nil, &priv256_2.PublicKey), nil, nil, nil, nil, ErrECDSAVerification},
		{NewES256(nil, nil), NewES256(nil, nil), nil, ErrECDSANilPrivKey, nil, nil, nil},
		{NewES256(priv256, nil), NewES256(nil, nil), nil, nil, nil, nil, ErrECDSANilPubKey},
		{NewES384(priv384, nil), NewES384(nil, &priv384.PublicKey), nil, nil, nil, nil, nil},
		{NewES384(priv384, nil), NewES384(nil, &priv384_2.PublicKey), nil, nil, nil, nil, ErrECDSAVerification},
		{NewES384(nil, nil), NewES384(nil, nil), nil, ErrECDSANilPrivKey, nil, nil, nil},
		{NewES384(priv384, nil), NewES384(nil, nil), nil, nil, nil, nil, ErrECDSANilPubKey},
		{NewES512(priv512, nil), NewES512(nil, &priv512.PublicKey), nil, nil, nil, nil, nil},
		{NewES512(priv512, nil), NewES512(nil, &priv512_2.PublicKey), nil, nil, nil, nil, ErrECDSAVerification},
		{NewES512(nil, nil), NewES512(nil, nil), nil, ErrECDSANilPrivKey, nil, nil, nil},
		{NewES512(priv512, nil), NewES512(nil, nil), nil, nil, nil, nil, ErrECDSANilPubKey},
	}
	testJWT(t, testCases)
}
