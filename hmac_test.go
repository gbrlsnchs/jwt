package jwt_test

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	. "github.com/gbrlsnchs/jwt/v2"
)

type hmacTestCases struct {
	signer        Signer
	verifier      Signer
	marshalingErr error
	signingErr    error
	parsingErr    error
	unmarshalErr  error
	verifyingErr  error
}

func TestHMAC(t *testing.T) {
	testCases := []hmacTestCases{
		{HS256(""), HS256(""), nil, ErrNoHMACKey, nil, nil, ErrNoHMACKey},
		{HS256("secret"), HS256("secret"), nil, nil, nil, nil, nil},
	}
	for i, tc := range testCases {
		name := fmt.Sprintf("%s %s", tc.signer.String(), tc.verifier.String())
		t.Run(name, func(t *testing.T) {
			now := time.Now()
			jot := &testToken{
				JWT: &JWT{
					Header: &Header{
						Algorithm: tc.signer.String(),
					},
					Claims: &Claims{
						IssuedAt:   now.Unix(),
						Expiration: now.Add(30 * time.Minute).Unix(),
						NotBefore:  now.Add(1 * time.Second).Unix(),
						Issuer:     "TestHMAC",
						Audience:   "test",
						Subject:    strconv.Itoa(2 * i),
						ID:         strconv.Itoa(i),
					},
				},
				Name: name,
			}

			// 1 - Marshal.
			payload, err := Marshal(jot)
			if want, got := tc.marshalingErr, err; want != got {
				t.Errorf("want %v, got %v", want, got)
			}
			if err != nil {
				t.SkipNow()
			}

			// 2 - Sign.
			token, err := tc.signer.Sign(payload)
			if want, got := tc.signingErr, err; want != got {
				t.Errorf("want %v, got %v", want, got)
			}
			if err != nil {
				t.SkipNow()
			}

			// 3 - Parse.
			payload, sig, err := ParseBytes(token)
			if want, got := tc.parsingErr, err; want != got {
				t.Errorf("want %v, got %v", want, got)
			}
			if err != nil {
				t.SkipNow()
			}

			// 4 - Unmarshal.
			var jot2 testToken
			err = Unmarshal(payload, &jot2)
			if want, got := tc.unmarshalErr, err; want != got {
				t.Errorf("want %v, got %v", want, got)
			}
			if err != nil {
				t.SkipNow()
			}

			// 5 - Verify.
			err = tc.verifier.Verify(payload, sig)
			if want, got := tc.verifyingErr, err; want != got {
				t.Errorf("want %v, got %v", want, got)
			}
			if err != nil {
				t.SkipNow()
			}

			// 6 - Check new token.
			if want, got := tc.signer.String(), jot2.Header.Algorithm; want != got {
				t.Errorf("want %s, got %s", want, got)
			}

			// TODO: check claims and custom fields.
		})
	}
}
