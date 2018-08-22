package jwt_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/gbrlsnchs/jwt"
	. "github.com/gbrlsnchs/jwt/internal"
)

const key = byte(0)
const mock = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ`

func TestFromContext(t *testing.T) {
	testCases := []struct {
		jot interface{}
		key interface{}
		err error
	}{
		{
			err: ErrNilCtxKey,
		},
		{
			key: key,
			jot: 1,
			err: ErrCtxAssertion,
		},
		{
			key: key,
			err: ErrNilCtxValue,
		},
		{
			key: key,
			jot: mock,
		},
		{
			key: key,
			jot: &JWT{},
		},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc.key), func(t *testing.T) {
			ctx := context.Background()
			if tc.key != nil {
				ctx = context.WithValue(ctx, tc.key, tc.jot)
			}
			_, err := FromContext(ctx, tc.key)
			if want, got := tc.err, err; want != got {
				t.Errorf("want %v, got %v", want, got)
			}
		})
	}
}

func TestFromCookie(t *testing.T) {
	c := &http.Cookie{Name: "test"}
	_, err := FromCookie(c)

	if want, got := ErrMalformedToken, err; want != got {
		errorf(t, want, got)
	}

	c.Value = JWTMockup
	_, err = FromCookie(c)

	if want, got := (error)(nil), err; want != got {
		errorf(t, want, got)
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
