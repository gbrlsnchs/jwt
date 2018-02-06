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
	"github.com/gbrlsnchs/jwt/jwtcrypto/rsasha"
)

func TestJWT(t *testing.T) {
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
		valid  bool
		signer jwtcrypto.Signer
		verif  jwtcrypto.Verifier
		claims *jwt.Claims
	}{
		{
			valid:  true,
			signer: hmacsha.New256("secret"),
			verif:  hmacsha.New256("secret"),
		},
		{
			valid:  false,
			signer: hmacsha.New256("secret"),
			verif:  hmacsha.New256("secret"),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{ExpirationTime: time.Now().Unix() - 1}},
		},
		{
			valid:  true,
			signer: hmacsha.New256("secret"),
			verif:  hmacsha.New256("secret"),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{ExpirationTime: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  false,
			signer: hmacsha.New256("secret"),
			verif:  hmacsha.New256("secret"),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{IssuedAt: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  true,
			signer: hmacsha.New256("secret"),
			verif:  hmacsha.New256("secret"),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{IssuedAt: time.Now().Unix() - 1}},
		},
		{
			valid:  false,
			signer: hmacsha.New256("secret"),
			verif:  hmacsha.New256("secret"),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{NotBefore: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  true,
			signer: hmacsha.New384("secret"),
			verif:  hmacsha.New384("secret"),
		},
		{
			valid:  false,
			signer: hmacsha.New384("secret"),
			verif:  hmacsha.New384("secret"),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{ExpirationTime: time.Now().Unix() - 1}},
		},
		{
			valid:  true,
			signer: hmacsha.New384("secret"),
			verif:  hmacsha.New384("secret"),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{ExpirationTime: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  false,
			signer: hmacsha.New384("secret"),
			verif:  hmacsha.New384("secret"),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{IssuedAt: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  true,
			signer: hmacsha.New384("secret"),
			verif:  hmacsha.New384("secret"),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{IssuedAt: time.Now().Unix() - 1}},
		},
		{
			valid:  false,
			signer: hmacsha.New384("secret"),
			verif:  hmacsha.New384("secret"),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{NotBefore: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  true,
			signer: hmacsha.New512("secret"),
			verif:  hmacsha.New512("secret"),
		},
		{
			valid:  false,
			signer: hmacsha.New512("secret"),
			verif:  hmacsha.New512("secret"),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{ExpirationTime: time.Now().Unix() - 1}},
		},
		{
			valid:  true,
			signer: hmacsha.New512("secret"),
			verif:  hmacsha.New512("secret"),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{ExpirationTime: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  false,
			signer: hmacsha.New512("secret"),
			verif:  hmacsha.New512("secret"),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{IssuedAt: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  true,
			signer: hmacsha.New512("secret"),
			verif:  hmacsha.New512("secret"),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{IssuedAt: time.Now().Unix() - 1}},
		},
		{
			valid:  false,
			signer: hmacsha.New512("secret"),
			verif:  hmacsha.New512("secret"),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{NotBefore: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  true,
			signer: rsasha.New256(rsaPriv, rsaPub),
			verif:  rsasha.New256(rsaPriv, rsaPub),
		},
		{
			valid:  false,
			signer: rsasha.New256(rsaPriv, rsaPub),
			verif:  rsasha.New256(rsaPriv, rsaPub),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{ExpirationTime: time.Now().Unix() - 1}},
		},
		{
			valid:  true,
			signer: rsasha.New256(rsaPriv, rsaPub),
			verif:  rsasha.New256(rsaPriv, rsaPub),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{ExpirationTime: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  false,
			signer: rsasha.New256(rsaPriv, rsaPub),
			verif:  rsasha.New256(rsaPriv, rsaPub),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{IssuedAt: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  true,
			signer: rsasha.New256(rsaPriv, rsaPub),
			verif:  rsasha.New256(rsaPriv, rsaPub),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{IssuedAt: time.Now().Unix() - 1}},
		},
		{
			valid:  false,
			signer: rsasha.New256(rsaPriv, rsaPub),
			verif:  rsasha.New256(rsaPriv, rsaPub),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{NotBefore: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  true,
			signer: rsasha.New384(rsaPriv, rsaPub),
			verif:  rsasha.New384(rsaPriv, rsaPub),
		},
		{
			valid:  true,
			signer: rsasha.New384(rsaPriv, rsaPub),
			verif:  rsasha.New384(rsaPriv, rsaPub),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{ExpirationTime: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  false,
			signer: rsasha.New384(rsaPriv, rsaPub),
			verif:  rsasha.New384(rsaPriv, rsaPub),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{IssuedAt: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  true,
			signer: rsasha.New384(rsaPriv, rsaPub),
			verif:  rsasha.New384(rsaPriv, rsaPub),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{IssuedAt: time.Now().Unix() - 1}},
		},
		{
			valid:  false,
			signer: rsasha.New384(rsaPriv, rsaPub),
			verif:  rsasha.New384(rsaPriv, rsaPub),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{NotBefore: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  true,
			signer: rsasha.New512(rsaPriv, rsaPub),
			verif:  rsasha.New512(rsaPriv, rsaPub),
		},
		{
			valid:  true,
			signer: rsasha.New512(rsaPriv, rsaPub),
			verif:  rsasha.New512(rsaPriv, rsaPub),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{ExpirationTime: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  false,
			signer: rsasha.New512(rsaPriv, rsaPub),
			verif:  rsasha.New512(rsaPriv, rsaPub),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{IssuedAt: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  true,
			signer: rsasha.New512(rsaPriv, rsaPub),
			verif:  rsasha.New512(rsaPriv, rsaPub),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{IssuedAt: time.Now().Unix() - 1}},
		},
		{
			valid:  false,
			signer: rsasha.New512(rsaPriv, rsaPub),
			verif:  rsasha.New512(rsaPriv, rsaPub),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{NotBefore: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  true,
			signer: ecdsasha.New256(ecdsaPriv256, ecdsaPub256),
			verif:  ecdsasha.New256(ecdsaPriv256, ecdsaPub256),
		},
		{
			valid:  true,
			signer: ecdsasha.New256(ecdsaPriv256, ecdsaPub256),
			verif:  ecdsasha.New256(ecdsaPriv256, ecdsaPub256),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{ExpirationTime: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  false,
			signer: ecdsasha.New256(ecdsaPriv256, ecdsaPub256),
			verif:  ecdsasha.New256(ecdsaPriv256, ecdsaPub256),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{IssuedAt: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  true,
			signer: ecdsasha.New256(ecdsaPriv256, ecdsaPub256),
			verif:  ecdsasha.New256(ecdsaPriv256, ecdsaPub256),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{IssuedAt: time.Now().Unix() - 1}},
		},
		{
			valid:  false,
			signer: ecdsasha.New256(ecdsaPriv256, ecdsaPub256),
			verif:  ecdsasha.New256(ecdsaPriv256, ecdsaPub256),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{NotBefore: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  true,
			signer: ecdsasha.New384(ecdsaPriv384, ecdsaPub384),
			verif:  ecdsasha.New384(ecdsaPriv384, ecdsaPub384),
		},
		{
			valid:  true,
			signer: ecdsasha.New384(ecdsaPriv256, ecdsaPub256),
			verif:  ecdsasha.New384(ecdsaPriv256, ecdsaPub256),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{ExpirationTime: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  false,
			signer: ecdsasha.New384(ecdsaPriv256, ecdsaPub256),
			verif:  ecdsasha.New384(ecdsaPriv256, ecdsaPub256),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{IssuedAt: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  true,
			signer: ecdsasha.New384(ecdsaPriv256, ecdsaPub256),
			verif:  ecdsasha.New384(ecdsaPriv256, ecdsaPub256),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{IssuedAt: time.Now().Unix() - 1}},
		},
		{
			valid:  false,
			signer: ecdsasha.New384(ecdsaPriv256, ecdsaPub256),
			verif:  ecdsasha.New384(ecdsaPriv256, ecdsaPub256),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{NotBefore: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  true,
			signer: ecdsasha.New512(ecdsaPriv512, ecdsaPub512),
			verif:  ecdsasha.New512(ecdsaPriv512, ecdsaPub512),
		},
		{
			valid:  true,
			signer: ecdsasha.New512(ecdsaPriv256, ecdsaPub256),
			verif:  ecdsasha.New512(ecdsaPriv256, ecdsaPub256),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{ExpirationTime: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  false,
			signer: ecdsasha.New512(ecdsaPriv256, ecdsaPub256),
			verif:  ecdsasha.New512(ecdsaPriv256, ecdsaPub256),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{IssuedAt: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
		{
			valid:  true,
			signer: ecdsasha.New512(ecdsaPriv256, ecdsaPub256),
			verif:  ecdsasha.New512(ecdsaPriv256, ecdsaPub256),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{IssuedAt: time.Now().Unix() - 1}},
		},
		{
			valid:  false,
			signer: ecdsasha.New512(ecdsaPriv256, ecdsaPub256),
			verif:  ecdsasha.New512(ecdsaPriv256, ecdsaPub256),
			claims: &jwt.Claims{Standard: &jwt.StdClaims{NotBefore: time.Now().Add(24 * 30 * 12 * time.Hour).Unix()}},
		},
	}

	for _, tt := range tests {
		token, err := jwt.Sign(tt.signer, &jwt.JWT{Claims: tt.claims})

		if err != nil {
			t.Errorf("Could not sign %#v: %v\n", tt, err)

			return
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

		if want, got := tt.verif.String(), jot.Header.Algorithm; want != got {
			t.Errorf("Want %s, got %s\n", want, got)
		}

		if tt.claims != nil {
			if want, got := tt.claims.Standard, jot.Claims.Standard; !reflect.DeepEqual(want, got) {
				t.Errorf("Want %#v, got %#v\n", want, got)
			}
		}

		if want, got := tt.valid, jot.IsValid(); want != got {
			t.Errorf("Want %t, got %t\n", want, got)
		}
	}
}
