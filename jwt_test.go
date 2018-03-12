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

func TestFromContext(t *testing.T) {
	ctx := context.Background()
	_, err := FromContext(ctx)

	if want, got := ErrNilCtxKey, err; want != got {
		errorf(t, want, got)
	}

	ctxKey := "test"
	SetCtxKey(ctxKey)

	_, err = FromContext(ctx)

	if want, got := ErrCtxAssertion, err; want != got {
		errorf(t, want, got)
	}

	ctx = context.WithValue(ctx, ctxKey, &JWT{})
	_, err = FromContext(ctx)

	if want, got := (error)(nil), err; want != got {
		errorf(t, want, got)
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

	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", JWTMockup))

	_, err = FromRequest(r)

	if want, got := (error)(nil), err; want != got {
		errorf(t, want, got)
	}
}

func errorf(t *testing.T, want, got interface{}) {
	t.Errorf("want %v, got %v\n", want, got)
}
