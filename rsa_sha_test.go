package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/gbrlsnchs/jwt/v3"
)

var (
	rsaPrivateKey1, rsaPublicKey1 = genRSAKeys()
	rsaPrivateKey2, rsaPublicKey2 = genRSAKeys()

	rsaTestCases = []testCase{
		{
			alg:       jwt.NewRS256(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewRS256(jwt.RSAPrivateKey(rsaPrivateKey1)),
			wantHeader: jwt.Header{
				Algorithm: "RS256",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewRS256(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewRS384(jwt.RSAPrivateKey(rsaPrivateKey1)),
			wantHeader: jwt.Header{
				Algorithm: "RS256",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
		{
			alg:       jwt.NewRS256(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewRS256(jwt.RSAPrivateKey(rsaPrivateKey2)),
			wantHeader: jwt.Header{
				Algorithm: "RS256",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
		{
			alg:       jwt.NewRS256(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewRS256(jwt.RSAPublicKey(rsaPublicKey1)),
			wantHeader: jwt.Header{
				Algorithm: "RS256",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewRS256(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewRS256(jwt.RSAPublicKey(rsaPublicKey2)),
			wantHeader: jwt.Header{
				Algorithm: "RS256",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
		{
			alg:       jwt.NewRS384(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewRS384(jwt.RSAPrivateKey(rsaPrivateKey1)),
			wantHeader: jwt.Header{
				Algorithm: "RS384",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewRS384(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewRS256(jwt.RSAPrivateKey(rsaPrivateKey1)),
			wantHeader: jwt.Header{
				Algorithm: "RS384",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
		{
			alg:       jwt.NewRS384(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewRS384(jwt.RSAPrivateKey(rsaPrivateKey2)),
			wantHeader: jwt.Header{
				Algorithm: "RS384",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
		{
			alg:       jwt.NewRS384(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewRS384(jwt.RSAPublicKey(rsaPublicKey1)),
			wantHeader: jwt.Header{
				Algorithm: "RS384",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewRS384(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewRS384(jwt.RSAPublicKey(rsaPublicKey2)),
			wantHeader: jwt.Header{
				Algorithm: "RS384",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
		{
			alg:       jwt.NewRS512(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewRS512(jwt.RSAPrivateKey(rsaPrivateKey1)),
			wantHeader: jwt.Header{
				Algorithm: "RS512",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewRS512(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewRS384(jwt.RSAPrivateKey(rsaPrivateKey1)),
			wantHeader: jwt.Header{
				Algorithm: "RS512",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
		{
			alg:       jwt.NewRS512(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewRS512(jwt.RSAPrivateKey(rsaPrivateKey2)),
			wantHeader: jwt.Header{
				Algorithm: "RS512",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
		{
			alg:       jwt.NewRS512(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewRS512(jwt.RSAPublicKey(rsaPublicKey1)),
			wantHeader: jwt.Header{
				Algorithm: "RS512",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewRS512(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewRS512(jwt.RSAPublicKey(rsaPublicKey2)),
			wantHeader: jwt.Header{
				Algorithm: "RS512",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
	}
	rsaPSSTestCases = []testCase{
		{
			alg:       jwt.NewPS256(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewPS256(jwt.RSAPrivateKey(rsaPrivateKey1)),
			wantHeader: jwt.Header{
				Algorithm: "PS256",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewPS256(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewRS256(jwt.RSAPrivateKey(rsaPrivateKey1)),
			wantHeader: jwt.Header{
				Algorithm: "PS256",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
		{
			alg:       jwt.NewPS256(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewPS384(jwt.RSAPrivateKey(rsaPrivateKey1)),
			wantHeader: jwt.Header{
				Algorithm: "PS256",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
		{
			alg:       jwt.NewPS256(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewPS256(jwt.RSAPrivateKey(rsaPrivateKey2)),
			wantHeader: jwt.Header{
				Algorithm: "PS256",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
		{
			alg:       jwt.NewPS256(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewPS256(jwt.RSAPublicKey(rsaPublicKey1)),
			wantHeader: jwt.Header{
				Algorithm: "PS256",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewPS256(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewPS256(jwt.RSAPublicKey(rsaPublicKey2)),
			wantHeader: jwt.Header{
				Algorithm: "PS256",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
		{
			alg:       jwt.NewPS384(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewPS384(jwt.RSAPrivateKey(rsaPrivateKey1)),
			wantHeader: jwt.Header{
				Algorithm: "PS384",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewPS384(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewRS384(jwt.RSAPrivateKey(rsaPrivateKey1)),
			wantHeader: jwt.Header{
				Algorithm: "PS384",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
		{
			alg:       jwt.NewPS384(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewPS256(jwt.RSAPrivateKey(rsaPrivateKey1)),
			wantHeader: jwt.Header{
				Algorithm: "PS384",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
		{
			alg:       jwt.NewPS384(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewPS384(jwt.RSAPrivateKey(rsaPrivateKey2)),
			wantHeader: jwt.Header{
				Algorithm: "PS384",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
		{
			alg:       jwt.NewPS384(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewPS384(jwt.RSAPublicKey(rsaPublicKey1)),
			wantHeader: jwt.Header{
				Algorithm: "PS384",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewPS384(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewPS384(jwt.RSAPublicKey(rsaPublicKey2)),
			wantHeader: jwt.Header{
				Algorithm: "PS384",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
		{
			alg:       jwt.NewPS512(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewPS512(jwt.RSAPrivateKey(rsaPrivateKey1)),
			wantHeader: jwt.Header{
				Algorithm: "PS512",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewPS512(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewRS512(jwt.RSAPrivateKey(rsaPrivateKey1)),
			wantHeader: jwt.Header{
				Algorithm: "PS512",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
		{
			alg:       jwt.NewPS512(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewPS384(jwt.RSAPrivateKey(rsaPrivateKey1)),
			wantHeader: jwt.Header{
				Algorithm: "PS512",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
		{
			alg:       jwt.NewPS512(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewPS512(jwt.RSAPrivateKey(rsaPrivateKey2)),
			wantHeader: jwt.Header{
				Algorithm: "PS512",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
		{
			alg:       jwt.NewPS512(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewPS512(jwt.RSAPublicKey(rsaPublicKey1)),
			wantHeader: jwt.Header{
				Algorithm: "PS512",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewPS512(jwt.RSAPrivateKey(rsaPrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewPS512(jwt.RSAPublicKey(rsaPublicKey2)),
			wantHeader: jwt.Header{
				Algorithm: "PS512",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrRSAVerification,
		},
	}
)

func genRSAKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return priv, &priv.PublicKey
}
