# jwt (JSON Web Token for Go)
[![JWT Compatible](https://jwt.io/img/badge.svg)](https://jwt.io)

[![Build Status](https://travis-ci.org/gbrlsnchs/jwt.svg?branch=master)](https://travis-ci.org/gbrlsnchs/jwt)
[![Build status](https://ci.appveyor.com/api/projects/status/wqao7uvucce71jja/branch/master?svg=true)](https://ci.appveyor.com/project/gbrlsnchs/jwt/branch/master)
[![GoDoc](https://godoc.org/github.com/gbrlsnchs/jwt?status.svg)](https://godoc.org/github.com/gbrlsnchs/jwt)
[![Sourcegraph](https://sourcegraph.com/github.com/gbrlsnchs/jwt/-/badge.svg)](https://sourcegraph.com/github.com/gbrlsnchs/jwt?badge)

## About
This package is a JWT signer, verifier and validator for [Go] (or Golang).

Although there are many JWT packages out there for Go, many lack support for some signing, verifying or validation methods and, when they don't, they're overcomplicated. This package tries to mimic the ease of use from [Node JWT library]'s API while following the [Effective Go] guidelines.

## Warning
`master` branch contains bleeding edge code, therefore it sometimes introduces breaking changes.  
Using a tagged version along with a proper dependency manager is the preferred way to use this library.

From `v2` on, this library is guaranteed to work on Go1.11 or later, although Go1.10 may be compatible using `vgo`.

### `v1` vs. `v2`
`v2` is a total rework of the library's API. While `v1` was simple to use, it was neither fast nor memory-efficient. That's why `v2` came on the scene: it's got better performance, takes advantage of type embedding and uses a bit of reflection in order to allow a custom struct to be used as a JWT.

As of [version 1.1.0], the library is pretty stable, but if a better performance is desired, it is recommended to migrate from `v1` to `v2`.

A branch named `v1` is used to fix possible imminent bugs in `v1` and will be supported until `v3` is released.

### Benchmark
#### `v1` on  Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
```
BenchmarkSign-4     	  200000	      7962 ns/op	    3457 B/op	      50 allocs/op
BenchmarkVerify-4   	  100000	     13087 ns/op	    3825 B/op	      80 allocs/op
```

#### `v2` on  Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
```
BenchmarkSign-4     	  300000	      4075 ns/op	    1312 B/op	      11 allocs/op
BenchmarkVerify-4   	  200000	      8363 ns/op	    1808 B/op	      32 allocs/op
```

## Usage
Full documentation [here].

### Downloading
`go get -u github.com/gbrlsnchs/jwt/v2`

### Importing
```go
import (
	// ...

	github.com/gbrlsnchs/jwt/v2
)
```

## Example
### Sign a JWT without public claims
```go
// Timestamp the beginning.
now := time.Now()
// Define a signer.
hs256 := jwt.NewHS256("secret")
jot := &jwt.JWT{
	Header: &jwt.Header{
		Algorithm: hs256.String(),
		KeyID:     "kid",
	},
	Claims: &jwt.Claims{
		ID:         "foobar",
		IssuedAt:   now.Unix(),
		Expiration: now.Add(24 * 30 * 12 * time.Hour).Unix(),
		NotBefore:  now.Add(30 * time.Minute).Unix(),
		Subject:    "someone",
		Audience:   "gophers",
		Issuer:     "gbrlsnchs",
	},
}
payload, err := jwt.Marshal(jot)
if err != nil {
	// handle error
}
token, err := hs256.Sign(payload)
if err != nil {
	// handle error
}
log.Print("token = %s", token)
```

### Sign a JWT with public claims
#### First, create a custom type and embed a JWT pointer in it
```go
type Token struct {
	*jwt.JWT
	IsLoggedIn  bool   `json:"isLoggedIn"`
	CustomField string `json:"customField,omitempty"`
}
```

#### Now, initialize, marshal and sign it
```go
// Timestamp the beginning.
now := time.Now()
// Define a signer.
hs256 := jwt.NewHS256("secret")
jot := &Token{
	JWT: &jwt.JWT{
		Header: &jwt.Header{
			Algorithm: hs256.String(),
			KeyID:     "kid",
		},
		Claims: &jwt.Claims{
			ID:         "foobar",
			IssuedAt:   now.Unix(),
			Expiration: now.Add(24 * 30 * 12 * time.Hour).Unix(),
			NotBefore:  now.Add(30 * time.Minute).Unix(),
			Subject:    "someone",
			Audience:   "gophers",
			Issuer:     "gbrlsnchs",
		},
	},
	IsLoggedIn:  true,
	CustomField: "myCustomField",
}
payload, err := jwt.Marshal(jot)
if err != nil {
	// handle error
}
token, err := hs256.Sign(payload)
if err != nil {
	// handle error
}
log.Print("token = %s", token)
```

### Verifying and validating a JWT
#### Quick note
When signing or verifying, this library **always** base64 encodes the signature.
```go
// Timestamp the beginning.
now := time.Now()
// Define a signer.
hs256 := jwt.NewHS256("my_53cr37")
// This is a mocked token for demonstration purposes only.
token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.lZ1zDoGNAv3u-OclJtnoQKejE8_viHlMtGlAxE8AE0Q"

// First, extract the payload and signature.
// This enables unmarshaling the JWT first and
// verifying it later or vice versa.
payload, sig, err := jwt.Parse(token)
if err != nil {
	// handle error
}
var jot Token
if err = jwt.Unmarshal(&jot); err != nil {
	// handle error
}
if err = hs256.Verify(payload, sig); err != nil {
	// handle error
}

// Validate fields.
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
[Node JWT library]: https://github.com/auth0/node-jsonwebtoken
[Effective Go]: https://golang.org/doc/effective_go.html
[version 1.1.0]: https://github.com/gbrlsnchs/jwt/releases/tag/v1.1.0
[here]: https://godoc.org/github.com/gbrlsnchs/jwt
