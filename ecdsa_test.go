package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	. "github.com/gbrlsnchs/jwt"
)

func TestECDSA(t *testing.T) {
	priv256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		t.Fatalf("%v", err)
	}
	pub256 := &priv256.PublicKey

	priv2562, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}
	pub2562 := &priv2562.PublicKey

	priv384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}
	pub384 := &priv384.PublicKey
	priv3842, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}
	pub3842 := &priv3842.PublicKey

	priv512, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}
	pub512 := &priv512.PublicKey
	priv5122, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}
	pub5122 := &priv5122.PublicKey
	testCases := []struct {
		s, v                   Signer
		errOnSign, errOnVerify bool
	}{
		{s: ES256(nil, pub256), errOnSign: true},
		{s: ES256(priv256, nil), errOnVerify: true},
		{s: ES256(priv256, pub256)},
		{s: ES256(priv256, pub2562), errOnVerify: true},
		{s: ES384(priv384, pub384)},
		{s: ES384(priv384, pub3842), errOnVerify: true},
		{s: ES512(priv512, pub512)},
		{s: ES512(priv512, pub5122), errOnVerify: true},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			run(t, tc.s, tc.v, tc.errOnSign, tc.errOnVerify)
		})
	}
}
