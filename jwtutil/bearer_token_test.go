package jwtutil_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/gbrlsnchs/jwt/jwtutil"
)

func TestValidBearerToken(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	r.Header.Set("Authorization", "Bearer token")

	_, err := BearerToken(r)

	if err != nil {
		t.Errorf("Could not extract token due to: %v\n", err)
	}
}

func TestInvalidBearerToken(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	r.Header.Set("Authorization", "Bearer")

	token, err := BearerToken(r)

	if err == nil {
		t.Errorf("No token expected, but excracted %s\n", token)
	}
}
