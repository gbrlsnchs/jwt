# jwt (JSON Web Token for Go)
[![Build Status](https://travis-ci.org/gbrlsnchs/jwt.svg?branch=master)](https://travis-ci.org/gbrlsnchs/jwt)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/gbrlsnchs/jwt)

## About
This package implements JWT signing and parsing for [Go] (or Golang).

It is simple and easy to use.

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
	jot, err := jwt.FromRequest(r, jwt.HS256("secret"))

	if err != nil {
		// ...
	}

	if jot.Algorithm() != jwt.MethodHS256 ||
		!jot.ExpirationTime().IsZero() &&
			now.After(jot.ExpirationTime()) ||
		now.Before(jot.NotBefore()) {
		// Repudiate token.
	}

	token, err := jwt.Sign(jwt.HS256("secret"), &jwt.Options{Timestamp: true})

	if err != nil {
		// ...
	}

	w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", token))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(token))
}

func ExampleParse() {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M"
	jot, err := jwt.Parse(jwt.HS256("secret"), token)

	if err != nil {
		// ...
	}

	fmt.Println(jot)
}

func ExampleSign() {
	nextYear := time.Now().Add(24 * 30 * 12 * time.Hour)
	token, err := jwt.Sign(jwt.HS256("secret"), &jwt.Options{ExpirationTime: nextYear})

	if err != nil {
		// ...
	}

	fmt.Println(token)
}
```

## Contribution
### How to help:
- Pull Requests
- Issues
- Opinions

[Go]: https://golang.org
[here]: https://godoc.org/github.com/gbrlsnchs/jwt
