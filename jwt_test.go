package jwt_test

import (
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"strconv"
	"testing"
	"time"

	. "github.com/gbrlsnchs/jwt/v3"
)

type testCase struct {
	signer       Signer
	verifier     Verifier
	signingErr   error
	parsingErr   error
	decodingErr  error
	verifyingErr error
}

type testPayload struct {
	Payload
	Name      string  `json:"name,omitempty"`
	RandInt   int     `json:"randomInt,omitempty"`
	RandFloat float64 `json:"randomFloat,omitempty"`
}

func testJWT(t *testing.T, testCases []testCase) {
	for i, tc := range testCases {
		t.Run(tc.signer.String(), func(t *testing.T) {
			now := time.Now()
			kid := fmt.Sprintf("kid %s %d", t.Name(), i)
			typ := "JWT"
			cty := "JWT"
			iat := now.Unix()
			exp := now.Add(30 * time.Minute).Unix()
			nbf := now.Add(1 * time.Second).Unix()
			iss := fmt.Sprintf("%s %d", t.Name(), i)
			aud := Audience{fmt.Sprintf("test %d", i)}
			sub := fmt.Sprintf("sub %d", i)
			jti := strconv.Itoa(i)
			randomInt := rand.Intn(math.MaxUint32)
			randomFloat := rand.Float64() * 100
			h := Header{
				KeyID:       kid,
				ContentType: cty,
			}
			tp := &testPayload{
				Payload: Payload{
					Issuer:         iss,
					Subject:        sub,
					Audience:       aud,
					ExpirationTime: exp,
					NotBefore:      nbf,
					IssuedAt:       iat,
					JWTID:          jti,
				},
				Name:      t.Name(),
				RandInt:   randomInt,
				RandFloat: randomFloat,
			}

			// Sign.
			token, err := Sign(h, tp, tc.signer)
			if want, got := tc.signingErr, err; want != got {
				t.Errorf("want %v, got %v", want, got)
			}
			if err != nil {
				return
			}

			// Parse.
			var raw RawToken
			raw, err = Parse(token)
			if want, got := tc.parsingErr, err; want != got {
				t.Errorf("want %v, got %v", want, got)
			}

			// Verify.
			err = raw.Verify(tc.verifier)
			if want, got := tc.verifyingErr, err; want != got {
				t.Errorf("want %v, got %v", want, got)
			}
			if err != nil {
				return
			}

			// Decode token.
			var (
				h2  Header
				tp2 testPayload
			)
			h2, err = raw.Decode(&tp2)
			if want, got := tc.decodingErr, err; want != got {
				t.Errorf("want %v, got %v", want, got)
			}

			// Check new token.
			if want, got := tc.signer.String(), h2.Algorithm; want != got {
				t.Errorf("want %s, got %s", want, got)
			}

			if want, got := kid, h2.KeyID; want != got {
				t.Errorf("want %s, got %s", want, got)
			}

			if want, got := typ, h2.Type; want != got {
				t.Errorf("want %s, got %s", want, got)
			}

			if want, got := cty, h2.ContentType; want != got {
				t.Errorf("want %s, got %s", want, got)
			}

			if want, got := iat, tp2.IssuedAt; want != got {
				t.Errorf("want %d, got %d", want, got)
			}

			if want, got := exp, tp2.ExpirationTime; want != got {
				t.Errorf("want %d, got %d", want, got)
			}

			if want, got := nbf, tp2.NotBefore; want != got {
				t.Errorf("want %d, got %d", want, got)
			}

			if want, got := iss, tp2.Issuer; want != got {
				t.Errorf("want %s, got %s", want, got)
			}

			if want, got := aud, tp2.Audience; !reflect.DeepEqual(want, got) {
				t.Errorf("want %s, got %s", want, got)
			}

			if want, got := sub, tp2.Subject; want != got {
				t.Errorf("want %s, got %s", want, got)
			}

			if want, got := jti, tp2.JWTID; want != got {
				t.Errorf("want %s, got %s", want, got)
			}

			if want, got := t.Name(), tp2.Name; want != got {
				t.Errorf("want %s, got %s", want, got)
			}

			if want, got := randomInt, tp2.RandInt; want != got {
				t.Errorf("want %d, got %d", want, got)
			}

			if want, got := randomFloat, tp2.RandFloat; want != got {
				t.Errorf("want %f, got %f", want, got)
			}

			if want, got := reflect.ValueOf(h).NumField(), reflect.ValueOf(h2).NumField(); want != got {
				t.Errorf("want %d, got %d", want, got)
			}
			if want, got := reflect.ValueOf(tp).Elem().NumField(), reflect.ValueOf(&tp2).Elem().NumField(); want != got {
				t.Errorf("want %d, got %d", want, got)
			}
		})
	}
}
