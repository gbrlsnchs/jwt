package jwt_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/gbrlsnchs/jwt"
)

const mock = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ`
const mockNone = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.`
const mockMalformed = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9`

func TestFromContext(t *testing.T) {
	const key = byte(0) // cheap key
	testCases := []struct {
		jot     interface{}
		keyless bool
		err     error
	}{
		{keyless: true, err: ErrNilCtxKey},
		{jot: 1, err: ErrCtxAssertion},
		{err: ErrNilCtxValue},
		{jot: "", err: ErrMalformedToken},
		{jot: mock},
		{jot: mockNone},
		{jot: mockMalformed, err: ErrMalformedToken},
		{jot: &JWT{}},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			ctx := context.Background()
			var k interface{} = key
			if !tc.keyless {
				ctx = context.WithValue(ctx, k, tc.jot)
			} else {
				k = nil
			}
			_, err := FromContext(ctx, k)
			if want, got := tc.err, err; want != got {
				t.Errorf("want %v, got %v", want, got)
			}
		})
	}
}

func TestFromCookie(t *testing.T) {
	const name = "doge"
	testCases := []struct {
		jot string
		err error
	}{
		{jot: "", err: ErrMalformedToken},
		{jot: mock},
		{jot: mockNone},
		{jot: mockMalformed, err: ErrMalformedToken},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			c := &http.Cookie{Value: tc.jot}
			_, err := FromCookie(c)
			if want, got := tc.err, err; want != got {
				t.Errorf("want %v, got %v", want, got)
			}
		})
	}
}

func TestFromRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := FromRequest(r)

	if want, got := ErrEmptyAuthorization, err; want != got {
		errorf(t, want, got)
	}

	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", "bad_token"))

	_, err = FromRequest(r)

	if want, got := ErrMalformedToken, err; want != got {
		errorf(t, want, got)
	}

	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", mock))

	_, err = FromRequest(r)

	if want, got := (error)(nil), err; want != got {
		errorf(t, want, got)
	}
}

func errorf(t *testing.T, want, got interface{}) {
	t.Errorf("want %v, got %v\n", want, got)
}
