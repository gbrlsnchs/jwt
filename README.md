# jwt (JSON Web Token for Go)
[![JWT Compatible](https://jwt.io/img/badge.svg)](https://jwt.io)

[![Build Status](https://travis-ci.org/gbrlsnchs/jwt.svg?branch=master)](https://travis-ci.org/gbrlsnchs/jwt)
[![Build status](https://ci.appveyor.com/api/projects/status/wqao7uvucce71jja/branch/master?svg=true)](https://ci.appveyor.com/project/gbrlsnchs/jwt/branch/master)
[![GoDoc](https://godoc.org/github.com/gbrlsnchs/jwt?status.svg)](https://godoc.org/github.com/gbrlsnchs/jwt)
[![Sourcegraph](https://sourcegraph.com/github.com/gbrlsnchs/jwt/-/badge.svg)](https://sourcegraph.com/github.com/gbrlsnchs/jwt?badge)

## About
This package is a JWT signer, verifier and validator for [Go] (or Golang).

There are many JWT packages out there for Go, but many lack signing/verifying methods or validation, and when they don't, they're overkill or overcomplicated. This package tries to mimic the ease of use from [Node's] JWT implementation but, of course, written in Go.

Version 1 was simple to use but not so fast and memory-efficient, that's why version 2 is a total rework that brings better performance, taking advantage of type embedding and a new `jwt.Marshaler` interface, while following the [Effective Go] guidelines.

#### `v1` on  Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
```
BenchmarkSign-4     	  200000	      9978 ns/op	    4483 B/op	      55 allocs/op
BenchmarkVerify-4   	  100000	     12848 ns/op	    3777 B/op	      80 allocs/op
```

### Benchmark
#### `v2` on  Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
```
BenchmarkSign-4     	  300000	      3633 ns/op	    1216 B/op	      12 allocs/op
BenchmarkVerify-4   	  200000	      8046 ns/op	    1504 B/op	      29 allocs/op
```

## Usage
Full documentation [here].

## Example
### Sign a JWT without public claims
```go
// Timestamp the beginning.
now := time.Now()
// Define a signer.
hs256 := jwt.HS256("my_53cr37")
jot := &jwt.JWT{
	Header: &jwt.Header{
		Algorithm: hs256.String(),
		KeyID:     "my_key",
	},
	Claims: &jwt.Claims{
		ID:         "unique_id",
		IssuedAt:   now,
		Expiration: now.Add(24 * 30 * 12 * time.Hour),
		NotBefore:  now.Add(30 * time.Minute),
		Subject:    "123",
		Audience:   "admin",
		Issuer:     "auth_server",
	},
}
token, err := hs256.Sign(jot)
if err != nil {
	// handle error
}
log.Print("token = %s", token)
```

### Sign a JWT with public claims
```go
type Token struct {
	*jwt.JWT
	Foo  string `json:"foo,omitempty"`
	Bool bool   `json:"bool"`
}

// Timestamp the beginning.
now := time.Now()
// Define a signer.
hs256 := jwt.HS256("my_53cr37")
jot := &Token{
	JWT: &jwt.JWT{
		Header: &jwt.Header{
			Algorithm: hs256.String(),
			KeyID:     "my_key",
		},
		Claims: &jwt.Claims{
			ID:         "unique_id",
			IssuedAt:   now,
			Expiration: now.Add(24 * 30 * 12 * time.Hour),
			NotBefore:  now.Add(30 * time.Minute),
			Subject:    "123",
			Audience:   "admin",
			Issuer:     "auth_server",
		},
	},
	Foo: "bar",
	Bool: true,
}
token, err := hs256.Sign(jot)
if err != nil {
	// handle error
}
log.Print("token = %s", token)
```

### Verifying and validating a JWT
```go
type Token struct {
	*jwt.JWT
	Foo  string `json:"foo,omitempty"`
	Bool bool   `json:"bool"`
}

// Timestamp the beginning.
now := time.Now()
hs256 := jwt.HS256("my_53cr37")
token := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
lZ1zDoGNAv3u-OclJtnoQKejE8_viHlMtGlAxE8AE0Q`
var jot Token

if err := hs256.Verify(string(token), &jot); err != nil {
	// handle error
}

algValidator := jwt.AlgorithmValidator(jwt.MethodHS256)
expValidator := jwt.ExpirationTimeValidator(now)
audValidator := jwt.AudienceValidator("admin")
if err = jot.Validate(algValidator, expValidator, audValidator); err != nil {
	switch err {
	case jwt.ErrAlgorithmMismatch:
		// handle "alg" mismatch
	case jwt.ErrTokenExpired:
		// handle "exp" being expired
	case jwt.ErrAudienceMismatch:
		// handle "aud" mismatch
	}
}
```

## Contribution
### How to help:
- Pull Requests
- Issues
- Opinions

[Go]: https://golang.org
[Node's]: https://github.com/auth0/node-jsonwebtoken
[Effective Go]: https://golang.org/doc/effective_go.html
[here]: https://godoc.org/github.com/gbrlsnchs/jwt
