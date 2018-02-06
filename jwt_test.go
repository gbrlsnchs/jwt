package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"reflect"
	"testing"
	"time"

	"github.com/gbrlsnchs/jwt"
	"github.com/gbrlsnchs/jwt/jwtcrypto"
	"github.com/gbrlsnchs/jwt/jwtcrypto/ecdsasha"
	"github.com/gbrlsnchs/jwt/jwtcrypto/hmacsha"
	"github.com/gbrlsnchs/jwt/jwtcrypto/none"
	"github.com/gbrlsnchs/jwt/jwtcrypto/rsasha"
)

func TestSignAndParse(t *testing.T) {
	key, err := ioutil.ReadFile("testdata/rsa.pem")

	if err != nil {
		t.Errorf("Could not read private RSA key file: %v\n", err)

		return
	}

	dec, _ := pem.Decode(key)
	rsaPriv, err := x509.ParsePKCS1PrivateKey(dec.Bytes)

	if err != nil {
		t.Errorf("Could not parse private RSA key: %v\n", err)

		return
	}

	rsaPub := &rsaPriv.PublicKey
	ecdsaPriv256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		t.Errorf("Could not parse private ECDSA key: %v\n", err)

		return
	}

	ecdsaPriv384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	if err != nil {
		t.Errorf("Could not parse private ECDSA key: %v\n", err)

		return
	}

	ecdsaPriv512, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	if err != nil {
		t.Errorf("Could not parse private ECDSA key: %v\n", err)

		return
	}

	ecdsaPub256 := &ecdsaPriv256.PublicKey
	ecdsaPub384 := &ecdsaPriv384.PublicKey
	ecdsaPub512 := &ecdsaPriv512.PublicKey
	tests := []struct {
		signer jwtcrypto.Signer
		verif  jwtcrypto.Verifier
	}{
		{
			signer: hmacsha.New256("secret"),
			verif:  hmacsha.New256("secret"),
		},
		{
			signer: hmacsha.New384("secret"),
			verif:  hmacsha.New384("secret"),
		},
		{
			signer: hmacsha.New512("secret"),
			verif:  hmacsha.New512("secret"),
		},
		{
			signer: rsasha.New256(rsaPriv, rsaPub),
			verif:  rsasha.New256(rsaPriv, rsaPub),
		},
		{
			signer: rsasha.New384(rsaPriv, rsaPub),
			verif:  rsasha.New384(rsaPriv, rsaPub),
		},
		{
			signer: rsasha.New512(rsaPriv, rsaPub),
			verif:  rsasha.New512(rsaPriv, rsaPub),
		},
		{
			signer: ecdsasha.New256(ecdsaPriv256, ecdsaPub256),
			verif:  ecdsasha.New256(ecdsaPriv256, ecdsaPub256),
		},
		{
			signer: ecdsasha.New384(ecdsaPriv384, ecdsaPub384),
			verif:  ecdsasha.New384(ecdsaPriv384, ecdsaPub384),
		},
		{
			signer: ecdsasha.New512(ecdsaPriv512, ecdsaPub512),
			verif:  ecdsasha.New512(ecdsaPriv512, ecdsaPub512),
		},
		{
			signer: &none.None{},
			verif:  hmacsha.New256(""),
		},
		{
			signer: &none.None{},
			verif:  &none.None{},
		},
	}

	for _, tt := range tests {
		token, err := jwt.Sign(tt.signer, &jwt.JWT{
			Header: &jwt.Header{Algorithm: tt.signer.String()},
		})

		if err != nil {
			t.Errorf("Could not sign %#v: %v\n", tt, err)

			continue
		}

		t.Logf("%s: %s\n", tt.signer.String(), token)

		jot, err := jwt.Parse(token, tt.verif)

		if err != nil {
			t.Errorf("Could not parse token: %v\n", err)

			continue
		}

		t.Logf("%s: %#v\n", tt.signer.String(), jot)
		t.Logf("%s (Header): %#v\n", tt.signer.String(), jot.Header)
		t.Logf("%s (Claims.Standard): %#v\n", tt.signer.String(), jot.Claims.Standard)
		t.Logf("%s (Claims.Public): %#v\n", tt.signer.String(), jot.Claims.Public)
	}
}

func TestInvalid(t *testing.T) {
	key, err := ioutil.ReadFile("testdata/rsa.pem")

	if err != nil {
		t.Errorf("Could not read private RSA key file: %v\n", err)

		return
	}

	dec, _ := pem.Decode(key)
	rsaPriv, err := x509.ParsePKCS1PrivateKey(dec.Bytes)

	if err != nil {
		t.Errorf("Could not parse private RSA key: %v\n", err)

		return
	}

	rsaPub := &rsaPriv.PublicKey
	ecdsaPriv256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		t.Errorf("Could not parse private ECDSA key: %v\n", err)

		return
	}

	ecdsaPriv384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	if err != nil {
		t.Errorf("Could not parse private ECDSA key: %v\n", err)

		return
	}

	ecdsaPub256 := &ecdsaPriv256.PublicKey
	ecdsaPub384 := &ecdsaPriv384.PublicKey
	tests := []struct {
		signer jwtcrypto.Signer
		verif  jwtcrypto.Verifier
		token  string
	}{
		{
			signer: hmacsha.New256("secret"),
			verif:  hmacsha.New256("secret"),
			token:  "not_token",
		},
		{
			signer: hmacsha.New256("secret"),
			verif:  hmacsha.New256("secret"),
			token:  "not.token",
		},
		{
			signer: hmacsha.New256("secret"),
			verif:  hmacsha.New256("not_secret"),
		},
		{
			signer: hmacsha.New256("secret"),
			verif:  hmacsha.New384("secret"),
		},
		{
			signer: rsasha.New256(rsaPriv, rsaPub),
			verif:  rsasha.New256(rsaPriv, nil),
		},
		{
			signer: rsasha.New256(rsaPriv, rsaPub),
			verif:  rsasha.New384(rsaPriv, rsaPub),
		},
		{
			signer: ecdsasha.New256(ecdsaPriv256, ecdsaPub256),
			verif:  ecdsasha.New256(ecdsaPriv256, nil),
		},
		{
			signer: ecdsasha.New256(ecdsaPriv384, ecdsaPub384),
			verif:  ecdsasha.New384(ecdsaPriv384, ecdsaPub384),
		},
		{
			signer: &none.None{},
			verif:  hmacsha.New256("secret"),
		},
		{
			signer: &none.None{},
			verif:  rsasha.New256(rsaPriv, rsaPub),
		},
		{
			signer: &none.None{},
			verif:  ecdsasha.New256(ecdsaPriv256, ecdsaPub256),
		},
	}

	for _, tt := range tests {
		if tt.token == "" {
			tt.token, err = jwt.Sign(tt.signer, &jwt.JWT{
				Header: &jwt.Header{Algorithm: tt.signer.String()},
			})

			if err != nil {
				t.Errorf("Could not sign %#v: %v\n", tt, err)

				continue
			}
		}

		t.Logf("%s: %s\n", tt.signer.String(), tt.token)

		jot, err := jwt.Parse(tt.token, tt.verif)

		if err != nil {
			t.Logf("%v\n", err)

			continue
		}

		t.Errorf("Token is valid")
		t.Logf("%s: %#v\n", tt.signer.String(), jot)
		t.Logf("%s (Header): %#v\n", tt.signer.String(), jot.Header)
		t.Logf("%s (Claims.Standard): %#v\n", tt.signer.String(), jot.Claims.Standard)
		t.Logf("%s (Claims.Public): %#v\n", tt.signer.String(), jot.Claims.Public)
	}
}

func TestPayload(t *testing.T) {
	now := time.Now().Unix()
	nextYear := time.Unix(now, 0).Add(24 * 30 * 12 * time.Hour).Unix()
	tests := []struct {
		claims *jwt.Claims
	}{
		{},
		{
			claims: &jwt.Claims{
				Standard: &jwt.StdClaims{
					Audience:       "test",
					ExpirationTime: nextYear,
					IssuedAt:       now - 1,
					Issuer:         "tester",
					JWTID:          "1",
					NotBefore:      now,
					Subject:        "me",
				},
			},
		},
	}

	for _, tt := range tests {
		n := &none.None{}

		if tt.claims == nil {
			tt.claims = &jwt.Claims{}
		}

		if tt.claims.Standard == nil {
			tt.claims.Standard = &jwt.StdClaims{}
		}

		token, err := jwt.Sign(n, &jwt.JWT{Claims: tt.claims})

		if err != nil {
			t.Errorf("Could not sign %#v: %v\n", tt, err)

			continue
		}

		t.Logf("%s\n", token)

		jot, err := jwt.Parse(token, n)

		if err != nil {
			t.Errorf("Could not parse token: %v\n", err)

			continue
		}

		t.Logf("%#v\n", jot)
		t.Logf("(Header): %#v\n", jot.Header)
		t.Logf("(Claims.Standard): %#v\n", jot.Claims.Standard)
		t.Logf("(Claims.Public): %#v\n", jot.Claims.Public)

		if want, got := tt.claims.Standard, jot.Claims.Standard; !reflect.DeepEqual(want, got) {
			t.Errorf("Want %#v, got %#v\n", want, got)
		}
	}
}

func TestTimestamps(t *testing.T) {
	now := time.Now().Unix()
	nextYear := time.Unix(now, 0).Add(24 * 30 * 12 * time.Hour).Unix()
	tests := []struct {
		valid bool
		exp   int64
		nbf   int64
		iat   int64
	}{
		{
			valid: true,
			exp:   0,
		},
		{
			valid: false,
			exp:   time.Date(1994, 12, 8, 15, 17, 0, 0, time.Local).Unix(),
		},
		{
			valid: true,
			exp:   nextYear,
		},
		{
			valid: false,
			exp:   now - 1,
		},
		{
			valid: true,
			nbf:   now - 1,
		},
		{
			valid: false,
			nbf:   nextYear,
		},
		{
			valid: true,
			iat:   now - 1,
		},
		{
			valid: false,
			iat:   nextYear,
		},
	}

	for _, tt := range tests {
		claims := &jwt.Claims{
			Standard: &jwt.StdClaims{
				ExpirationTime: tt.exp,
				NotBefore:      tt.nbf,
				IssuedAt:       tt.iat,
			},
		}
		hs256 := hmacsha.New256("secret")
		token, err := jwt.Sign(hs256, &jwt.JWT{Claims: claims})

		if err != nil {
			t.Errorf("Could not sign %#v: %v\n", tt, err)

			continue
		}

		t.Logf("%s\n", token)

		jot, err := jwt.Parse(token, hs256)

		if want, got := tt.valid, err == nil; want != got {
			t.Errorf("Want %t, got %t\n", want, got)
		}

		if err != nil {
			t.Logf("Could not parse token: %v\n", err)

			continue
		}

		t.Logf("%#v\n", jot)
		t.Logf("(Header): %#v\n", jot.Header)
		t.Logf("(Claims.Standard): %#v\n", jot.Claims.Standard)
		t.Logf("(Claims.Public): %#v\n", jot.Claims.Public)
	}
}
