package jwt_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/gbrlsnchs/jwt/v3"
)

type testPayload struct {
	jwt.Payload
	String string `json:"string,omitempty"`
	Int    int    `json:"int,omitempty"`
}

var (
	now = time.Now()
	tp  = testPayload{
		Payload: jwt.Payload{
			Issuer:         "gbrlsnchs",
			Subject:        "someone",
			Audience:       jwt.Audience{"https://golang.org", "https://jwt.io"},
			ExpirationTime: jwt.NumericDate(now.Add(24 * 30 * 12 * time.Hour)),
			NotBefore:      jwt.NumericDate(now.Add(30 * time.Minute)),
			IssuedAt:       jwt.NumericDate(now),
			JWTID:          "foobar",
		},
		String: "foobar",
		Int:    1337,
	}
)

func TestSign(t *testing.T) {
	type testCase struct {
		alg     jwt.Algorithm
		hd      jwt.Header
		payload interface{}

		verifyAlg   jwt.Algorithm
		opts        []func(*jwt.RawToken)
		wantHeader  jwt.Header
		wantPayload testPayload

		signErr   error
		verifyErr error
	}
	testCases := map[string][]testCase{
		"HMAC": []testCase{
			{
				alg:       jwt.NewHS256(hmacKey1),
				hd:        jwt.Header{},
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
				alg:       jwt.NewHS384(hmacKey1),
				hd:        jwt.Header{},
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
				alg:       jwt.NewHS512(hmacKey1),
				hd:        jwt.Header{},
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
		},
		"RSA": []testCase{
			{
				alg:       jwt.NewRS256(rsaPrivateKey1, nil),
				hd:        jwt.Header{},
				payload:   tp,
				verifyAlg: jwt.NewRS256(rsaPrivateKey1, nil),
				wantHeader: jwt.Header{
					Algorithm: "RS256",
					Type:      "JWT",
				},
				wantPayload: tp,
				signErr:     nil,
				verifyErr:   nil,
			},
			{
				alg:       jwt.NewRS256(rsaPrivateKey1, nil),
				hd:        jwt.Header{},
				payload:   tp,
				verifyAlg: jwt.NewRS256(nil, rsaPublicKey1),
				wantHeader: jwt.Header{
					Algorithm: "RS256",
					Type:      "JWT",
				},
				wantPayload: tp,
				signErr:     nil,
				verifyErr:   nil,
			},
			{
				alg:       jwt.NewRS384(rsaPrivateKey1, nil),
				hd:        jwt.Header{},
				payload:   tp,
				verifyAlg: jwt.NewRS384(rsaPrivateKey1, nil),
				wantHeader: jwt.Header{
					Algorithm: "RS384",
					Type:      "JWT",
				},
				wantPayload: tp,
				signErr:     nil,
				verifyErr:   nil,
			},
			{
				alg:       jwt.NewRS384(rsaPrivateKey1, nil),
				hd:        jwt.Header{},
				payload:   tp,
				verifyAlg: jwt.NewRS384(nil, rsaPublicKey1),
				wantHeader: jwt.Header{
					Algorithm: "RS384",
					Type:      "JWT",
				},
				wantPayload: tp,
				signErr:     nil,
				verifyErr:   nil,
			},
			{
				alg:       jwt.NewRS512(rsaPrivateKey1, nil),
				hd:        jwt.Header{},
				payload:   tp,
				verifyAlg: jwt.NewRS512(rsaPrivateKey1, nil),
				wantHeader: jwt.Header{
					Algorithm: "RS512",
					Type:      "JWT",
				},
				wantPayload: tp,
				signErr:     nil,
				verifyErr:   nil,
			},
			{
				alg:       jwt.NewRS512(rsaPrivateKey1, nil),
				hd:        jwt.Header{},
				payload:   tp,
				verifyAlg: jwt.NewRS512(nil, rsaPublicKey1),
				wantHeader: jwt.Header{
					Algorithm: "RS512",
					Type:      "JWT",
				},
				wantPayload: tp,
				signErr:     nil,
				verifyErr:   nil,
			},
		},
		"RSA-PSS": []testCase{
			{
				alg:       jwt.NewPS256(rsaPrivateKey1, nil),
				hd:        jwt.Header{},
				payload:   tp,
				verifyAlg: jwt.NewPS256(rsaPrivateKey1, nil),
				wantHeader: jwt.Header{
					Algorithm: "PS256",
					Type:      "JWT",
				},
				wantPayload: tp,
				signErr:     nil,
				verifyErr:   nil,
			},
			{
				alg:       jwt.NewPS256(rsaPrivateKey1, nil),
				hd:        jwt.Header{},
				payload:   tp,
				verifyAlg: jwt.NewPS256(nil, rsaPublicKey1),
				wantHeader: jwt.Header{
					Algorithm: "PS256",
					Type:      "JWT",
				},
				wantPayload: tp,
				signErr:     nil,
				verifyErr:   nil,
			},
			{
				alg:       jwt.NewPS384(rsaPrivateKey1, nil),
				hd:        jwt.Header{},
				payload:   tp,
				verifyAlg: jwt.NewPS384(rsaPrivateKey1, nil),
				wantHeader: jwt.Header{
					Algorithm: "PS384",
					Type:      "JWT",
				},
				wantPayload: tp,
				signErr:     nil,
				verifyErr:   nil,
			},
			{
				alg:       jwt.NewPS384(rsaPrivateKey1, nil),
				hd:        jwt.Header{},
				payload:   tp,
				verifyAlg: jwt.NewPS384(nil, rsaPublicKey1),
				wantHeader: jwt.Header{
					Algorithm: "PS384",
					Type:      "JWT",
				},
				wantPayload: tp,
				signErr:     nil,
				verifyErr:   nil,
			},
			{
				alg:       jwt.NewPS512(rsaPrivateKey1, nil),
				hd:        jwt.Header{},
				payload:   tp,
				verifyAlg: jwt.NewPS512(rsaPrivateKey1, nil),
				wantHeader: jwt.Header{
					Algorithm: "PS512",
					Type:      "JWT",
				},
				wantPayload: tp,
				signErr:     nil,
				verifyErr:   nil,
			},
			{
				alg:       jwt.NewPS512(rsaPrivateKey1, nil),
				hd:        jwt.Header{},
				payload:   tp,
				verifyAlg: jwt.NewPS512(nil, rsaPublicKey1),
				wantHeader: jwt.Header{
					Algorithm: "PS512",
					Type:      "JWT",
				},
				wantPayload: tp,
				signErr:     nil,
				verifyErr:   nil,
			},
		},
		"ECDSA": []testCase{
			{
				alg:       jwt.NewES256(es256PrivateKey1, nil),
				hd:        jwt.Header{},
				payload:   tp,
				verifyAlg: jwt.NewES256(nil, es256PublicKey1),
				wantHeader: jwt.Header{
					Algorithm: "ES256",
					Type:      "JWT",
				},
				wantPayload: tp,
				signErr:     nil,
				verifyErr:   nil,
			},
			{
				alg:       jwt.NewES256(es256PrivateKey1, nil),
				hd:        jwt.Header{},
				payload:   tp,
				verifyAlg: jwt.NewES256(es256PrivateKey1, nil),
				wantHeader: jwt.Header{
					Algorithm: "ES256",
					Type:      "JWT",
				},
				wantPayload: tp,
				signErr:     nil,
				verifyErr:   nil,
			},
			{
				alg:       jwt.NewES384(es384PrivateKey1, nil),
				hd:        jwt.Header{},
				payload:   tp,
				verifyAlg: jwt.NewES384(nil, es384PublicKey1),
				wantHeader: jwt.Header{
					Algorithm: "ES384",
					Type:      "JWT",
				},
				wantPayload: tp,
				signErr:     nil,
				verifyErr:   nil,
			},
			{
				alg:       jwt.NewES384(es384PrivateKey1, nil),
				hd:        jwt.Header{},
				payload:   tp,
				verifyAlg: jwt.NewES384(es384PrivateKey1, nil),
				wantHeader: jwt.Header{
					Algorithm: "ES384",
					Type:      "JWT",
				},
				wantPayload: tp,
				signErr:     nil,
				verifyErr:   nil,
			},
			{
				alg:       jwt.NewES512(es512PrivateKey1, nil),
				hd:        jwt.Header{},
				payload:   tp,
				verifyAlg: jwt.NewES512(nil, es512PublicKey1),
				wantHeader: jwt.Header{
					Algorithm: "ES512",
					Type:      "JWT",
				},
				wantPayload: tp,
				signErr:     nil,
				verifyErr:   nil,
			},
			{
				alg:       jwt.NewES512(es512PrivateKey1, nil),
				hd:        jwt.Header{},
				payload:   tp,
				verifyAlg: jwt.NewES512(es512PrivateKey1, nil),
				wantHeader: jwt.Header{
					Algorithm: "ES512",
					Type:      "JWT",
				},
				wantPayload: tp,
				signErr:     nil,
				verifyErr:   nil,
			},
		},
		"Ed25519": []testCase{
			{
				alg:       jwt.NewEd25519(ed25519PrivateKey1, nil),
				hd:        jwt.Header{},
				payload:   tp,
				verifyAlg: jwt.NewEd25519(ed25519PrivateKey1, nil),
				wantHeader: jwt.Header{
					Algorithm: "Ed25519",
					Type:      "JWT",
				},
				wantPayload: tp,
				signErr:     nil,
				verifyErr:   nil,
			},
		},
	}
	for k, v := range testCases {
		t.Run(k, func(t *testing.T) {
			for _, tc := range v {
				t.Run(tc.alg.Name(), func(t *testing.T) {
					token, err := jwt.Sign(tc.payload, tc.alg)
					if want, got := tc.signErr, err; got != want {
						t.Fatalf("want %v, got %v", want, got)
					}
					if err != nil {
						return
					}

					var (
						hd      jwt.Header
						payload testPayload
					)
					hd, err = jwt.Verify(token, &payload, tc.verifyAlg)
					if want, got := tc.verifyErr, err; got != want {
						t.Fatalf("want %v, got %v", want, got)
					}
					if want, got := tc.wantHeader, hd; !reflect.DeepEqual(got, want) {
						t.Errorf("want %#+v, got %#+v", want, got)
					}
					if want, got := tc.wantPayload, payload; !reflect.DeepEqual(got, want) {
						t.Errorf("want %#+v, got %#+v", want, got)
					}
				})
			}
		})
	}
}
