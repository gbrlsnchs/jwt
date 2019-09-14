package jwt_test

import "github.com/gbrlsnchs/jwt/v3"

var (
	hmacKey1 = []byte("secret")
	hmacKey2 = []byte("terces")

	hmacTestCases = []testCase{
		{
			alg:       jwt.NewHS256(hmacKey1),
			payload:   tp,
			verifyAlg: jwt.NewHS256(hmacKey1),
			wantHeader: jwt.Header{
				Algorithm: "HS256",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewHS256(hmacKey1),
			payload:   tp,
			verifyAlg: jwt.NewHS256(hmacKey2),
			wantHeader: jwt.Header{
				Algorithm: "HS256",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrHMACVerification,
		},
		{
			alg:       jwt.NewHS256(hmacKey1),
			payload:   tp,
			verifyAlg: jwt.NewHS384(hmacKey1),
			wantHeader: jwt.Header{
				Algorithm: "HS256",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrHMACVerification,
		},
		{
			alg:       jwt.NewHS384(hmacKey1),
			payload:   tp,
			verifyAlg: jwt.NewHS384(hmacKey1),
			wantHeader: jwt.Header{
				Algorithm: "HS384",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewHS384(hmacKey1),
			payload:   tp,
			verifyAlg: jwt.NewHS384(hmacKey2),
			wantHeader: jwt.Header{
				Algorithm: "HS384",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrHMACVerification,
		},
		{
			alg:       jwt.NewHS384(hmacKey1),
			payload:   tp,
			verifyAlg: jwt.NewHS256(hmacKey1),
			wantHeader: jwt.Header{
				Algorithm: "HS384",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrHMACVerification,
		},
		{
			alg:       jwt.NewHS512(hmacKey1),
			payload:   tp,
			verifyAlg: jwt.NewHS512(hmacKey1),
			wantHeader: jwt.Header{
				Algorithm: "HS512",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewHS512(hmacKey1),
			payload:   tp,
			verifyAlg: jwt.NewHS512(hmacKey2),
			wantHeader: jwt.Header{
				Algorithm: "HS512",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrHMACVerification,
		},
		{
			alg:       jwt.NewHS512(hmacKey1),
			payload:   tp,
			verifyAlg: jwt.NewHS256(hmacKey1),
			wantHeader: jwt.Header{
				Algorithm: "HS512",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrHMACVerification,
		},
	}
)
