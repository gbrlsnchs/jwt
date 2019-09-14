package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/gbrlsnchs/jwt/v3"
)

var (
	es256PrivateKey1, es256PublicKey1 = genECDSAKeys(elliptic.P256())
	es256PrivateKey2, es256PublicKey2 = genECDSAKeys(elliptic.P256())

	es384PrivateKey1, es384PublicKey1 = genECDSAKeys(elliptic.P384())
	es384PrivateKey2, es384PublicKey2 = genECDSAKeys(elliptic.P384())

	es512PrivateKey1, es512PublicKey1 = genECDSAKeys(elliptic.P521())
	es512PrivateKey2, es512PublicKey2 = genECDSAKeys(elliptic.P521())

	ecdsaTestCases = []testCase{
		{
			alg:       jwt.NewES256(jwt.ECDSAPrivateKey(es256PrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewES256(jwt.ECDSAPublicKey(es256PublicKey1)),
			wantHeader: jwt.Header{
				Algorithm: "ES256",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewES256(jwt.ECDSAPrivateKey(es256PrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewES384(jwt.ECDSAPublicKey(es256PublicKey1)),
			wantHeader: jwt.Header{
				Algorithm: "ES256",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrECDSAVerification,
		},
		{
			alg:       jwt.NewES256(jwt.ECDSAPrivateKey(es256PrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewES256(jwt.ECDSAPublicKey(es256PublicKey2)),
			wantHeader: jwt.Header{
				Algorithm: "ES256",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrECDSAVerification,
		},
		{
			alg:       jwt.NewES256(jwt.ECDSAPrivateKey(es256PrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewES256(jwt.ECDSAPrivateKey(es256PrivateKey1)),
			wantHeader: jwt.Header{
				Algorithm: "ES256",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewES256(jwt.ECDSAPrivateKey(es256PrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewES256(jwt.ECDSAPrivateKey(es256PrivateKey2)),
			wantHeader: jwt.Header{
				Algorithm: "ES256",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrECDSAVerification,
		},
		{
			alg:       jwt.NewES384(jwt.ECDSAPrivateKey(es384PrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewES384(jwt.ECDSAPublicKey(es384PublicKey1)),
			wantHeader: jwt.Header{
				Algorithm: "ES384",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewES384(jwt.ECDSAPrivateKey(es384PrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewES256(jwt.ECDSAPublicKey(es384PublicKey1)),
			wantHeader: jwt.Header{
				Algorithm: "ES384",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrECDSAVerification,
		},
		{
			alg:       jwt.NewES384(jwt.ECDSAPrivateKey(es384PrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewES384(jwt.ECDSAPublicKey(es384PublicKey2)),
			wantHeader: jwt.Header{
				Algorithm: "ES384",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrECDSAVerification,
		},
		{
			alg:       jwt.NewES384(jwt.ECDSAPrivateKey(es384PrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewES384(jwt.ECDSAPrivateKey(es384PrivateKey1)),
			wantHeader: jwt.Header{
				Algorithm: "ES384",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewES384(jwt.ECDSAPrivateKey(es384PrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewES384(jwt.ECDSAPrivateKey(es384PrivateKey2)),
			wantHeader: jwt.Header{
				Algorithm: "ES384",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrECDSAVerification,
		},
		{
			alg:       jwt.NewES512(jwt.ECDSAPrivateKey(es512PrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewES512(jwt.ECDSAPublicKey(es512PublicKey1)),
			wantHeader: jwt.Header{
				Algorithm: "ES512",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewES512(jwt.ECDSAPrivateKey(es512PrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewES384(jwt.ECDSAPublicKey(es512PublicKey1)),
			wantHeader: jwt.Header{
				Algorithm: "ES512",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrECDSAVerification,
		},
		{
			alg:       jwt.NewES512(jwt.ECDSAPrivateKey(es512PrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewES512(jwt.ECDSAPublicKey(es512PublicKey2)),
			wantHeader: jwt.Header{
				Algorithm: "ES512",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrECDSAVerification,
		},
		{
			alg:       jwt.NewES512(jwt.ECDSAPrivateKey(es512PrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewES512(jwt.ECDSAPrivateKey(es512PrivateKey1)),
			wantHeader: jwt.Header{
				Algorithm: "ES512",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewES512(jwt.ECDSAPrivateKey(es512PrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewES512(jwt.ECDSAPrivateKey(es512PrivateKey2)),
			wantHeader: jwt.Header{
				Algorithm: "ES512",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrECDSAVerification,
		},
	}
)

func genECDSAKeys(c elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	priv, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv, &priv.PublicKey
}
