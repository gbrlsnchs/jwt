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
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/gbrlsnchs/jwt"
)

func Example() {
	now := time.Now()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	token, err := jwt.FromRequest(r)

	if err != nil {
		// Handle malformed token...
	}

	if err = token.Verify(jwt.HS256("secret")); err != nil {
		// Handle verification error...
	}

	jot, err := token.Build()

	if err != nil {
		// Handle JWT building error...
	}

	algValidator := jwt.AlgorithmValidator(jwt.MethodHS256)
	audValidator := jwt.AudienceValidator("test")
	expValidator := jwt.ExpirationTimeValidator(now)

	if err = jot.Validate(algValidator, audValidator, expValidator); err != nil {
		switch err {
		case jwt.ErrAlgorithmMismatch:
			// Handle "alg" mismatch...

		case jwt.ErrAudienceMismatch:
			// Handle "aud" mismatch...

		case jwt.ErrTokenExpired:
			// Handle "exp" being expired...
		}
	}

	token, err = jwt.Sign(jwt.HS256("secret"), &jwt.Options{Timestamp: true})

	if err != nil {
		// ...
	}

	auth := fmt.Sprintf("Bearer %s", token.String())

	w.Header().Set("Authorization", auth)
	w.WriteHeader(http.StatusOK)
	w.Write(token.Bytes())
}

func ExampleParse() {
	token, err := jwt.NewToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M")

	if err != nil {
		// Handle malformed token...
	}

	if err = token.Verify(jwt.HS256("secret")); err != nil {
		// Handle verification error...
	}

	jot, err := token.Build()

	if err != nil {
		// Handle JWT building error...
	}

	fmt.Println(jot)
}

func ExampleSign() {
	nextYear := time.Now().Add(24 * 30 * 12 * time.Hour)
	token, err := jwt.Sign(jwt.HS256("secret"), &jwt.Options{ExpirationTime: nextYear})

	if err != nil {
		// ...
	}

	fmt.Println(token.String())
}
```

## Contribution
### How to help:
- Pull Requests
- Issues
- Opinions

[Go]: https://golang.org
[here]: https://godoc.org/github.com/gbrlsnchs/jwt
