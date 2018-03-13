# jwt (JSON Web Token for Go)
[![Build Status](https://travis-ci.org/gbrlsnchs/jwt.svg?branch=master)](https://travis-ci.org/gbrlsnchs/jwt)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/gbrlsnchs/jwt)

## About
This package is a JWT signer, verifier and validator for [Go] (or Golang).

## Usage
Full documentation [here].

## Example (from example_test.go)
```go
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
	_, err := FromContext(ctx, nil)

	if want, got := ErrNilCtxKey, err; want != got {
		errorf(t, want, got)
	}

	key := "test"
	_, err = FromContext(ctx, key)

	if want, got := ErrCtxAssertion, err; want != got {
		errorf(t, want, got)
	}

	ctx = context.WithValue(ctx, key, &JWT{})
	_, err = FromContext(ctx, key)

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
```

## Contribution
### How to help:
- Pull Requests
- Issues
- Opinions

[Go]: https://golang.org
[here]: https://godoc.org/github.com/gbrlsnchs/jwt
