package jwt_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/gbrlsnchs/jwt/v3"
	"github.com/gbrlsnchs/jwt/v3/internal"
)

type testPayload struct {
	jwt.Payload
	String string `json:"string,omitempty"`
	Int    int    `json:"int,omitempty"`
}

var tp = testPayload{
	Payload: jwt.Payload{
		Subject:   "test",
		Audience:  jwt.Audience{"github.com", "gsr.dev"},
		NotBefore: time.Now().Unix(),
	},
	String: "foobar",
	Int:    1337,
}

func TestSign(t *testing.T) {
	type testCase struct {
		alg     jwt.Algorithm
		hd      jwt.Header
		payload interface{}

		verifyAlg   jwt.Algorithm
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
					token, err := jwt.Sign(tc.alg, tc.hd, tc.payload)
					if want, got := tc.signErr, err; !internal.ErrorIs(got, want) {
						t.Fatalf("want %v, got %v", want, got)
					}
					if err != nil {
						return
					}

					raw, err := jwt.Verify(tc.verifyAlg, token)
					if want, got := tc.verifyErr, err; !internal.ErrorIs(got, want) {
						t.Fatalf("want %v, got %v", want, got)
					}
					if err != nil {
						return
					}
					if want, got := tc.wantHeader, raw.Header(); !reflect.DeepEqual(got, want) {
						t.Errorf("want %#+v, got %#+v", want, got)
					}
					var payload testPayload
					if err = raw.Decode(&payload); err != nil {
						t.Fatal(err)
					}
					if want, got := tc.wantPayload, payload; !reflect.DeepEqual(got, want) {
						t.Errorf("want %#+v, got %#+v", want, got)
					}
				})
			}
		})
	}
}
