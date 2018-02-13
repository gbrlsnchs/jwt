package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/gbrlsnchs/jwt"
)

type testTable struct {
	signer     Signer
	verif      Signer
	parsingErr bool
	signingErr bool
	opts       *Options
}

func TestHMAC(t *testing.T) {
	tests := []*testTable{
		{
			signer: HS256("secret"),
		},
		{
			signer:     HS256("secret"),
			verif:      HS256("terces"),
			parsingErr: true,
		},
		{
			signer: HS384("secret"),
		},
		{
			signer:     HS384("secret"),
			verif:      HS384("terces"),
			parsingErr: true,
		},
		{
			signer: HS512("secret"),
		},
		{
			signer:     HS512("secret"),
			verif:      HS512("terces"),
			parsingErr: true,
		},
	}

	runTests(t, tests)
}

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
	tests := []*testTable{
		{
			signer: RS256(rsaPriv, rsaPub),
		},
		{
			signer:     RS256(rsaPriv, rsaPub2),
			parsingErr: true,
		},
		{
			signer: RS384(rsaPriv, rsaPub),
		},
		{
			signer:     RS384(rsaPriv, rsaPub2),
			parsingErr: true,
		},
		{
			signer: RS512(rsaPriv, rsaPub),
		},
		{
			signer:     RS512(rsaPriv, rsaPub2),
			parsingErr: true,
		},
	}

	runTests(t, tests)
}

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
	tests := []*testTable{
		{
			signer: ES256(ecdsa256Priv, ecdsa256Pub),
		},
		{
			signer:     ES256(ecdsa256Priv, ecdsa256Pub2),
			parsingErr: true,
		},
		{
			signer: ES384(ecdsa384Priv, ecdsa384Pub),
		},
		{
			signer:     ES384(ecdsa384Priv, ecdsa384Pub2),
			parsingErr: true,
		},
		{
			signer: ES512(ecdsa512Priv, ecdsa512Pub),
		},
		{
			signer:     ES512(ecdsa512Priv, ecdsa512Pub2),
			parsingErr: true,
		},
	}

	runTests(t, tests)
}

func TestNone(t *testing.T) {
	tests := []*testTable{
		{
			signer: None(),
		},
		{
			signer: HS256("secret"),
			verif:  None(),
		},
		{
			signer:     None(),
			verif:      HS256("secret"),
			parsingErr: true,
		},
	}

	runTests(t, tests)
}

func runTests(t *testing.T, tests []*testTable) {
	for _, tt := range tests {
		token, err := Sign(tt.signer, tt.opts)

		if want, got := tt.signingErr, err != nil; want != got {
			t.Errorf("jwt.Sign: want %t, got %t\n", want, got)

			if err != nil {
				t.Logf("%v\n", err)
			}

			continue
		}

		r := httptest.NewRequest(http.MethodGet, "/", nil)

		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

		s := tt.signer

		if tt.verif != nil {
			s = tt.verif
		}

		jot, err := FromRequest(r, s)

		if want, got := tt.parsingErr, err != nil; want != got {
			t.Errorf("jwt.Parse: want %t, got %t\n", want, got)

			if err != nil {
				t.Logf("%v\n", err)
			}

			continue
		}

		t.Logf("Token + %s: %s\n", tt.signer.String(), token)
		t.Logf("JWT: %#v\n", jot)
	}
}
