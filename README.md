# jwt (JSON Web Token for Go)
[![JWT compatible](https://jwt.io/img/badge.svg)](https://jwt.io)

[![Build status](https://travis-ci.org/gbrlsnchs/jwt.svg?branch=master)](https://travis-ci.org/gbrlsnchs/jwt)
[![Build status](https://ci.appveyor.com/api/projects/status/wqao7uvucce71jja/branch/master?svg=true)](https://ci.appveyor.com/project/gbrlsnchs/jwt/branch/master)
[![Sourcegraph](https://sourcegraph.com/github.com/gbrlsnchs/jwt/-/badge.svg)](https://sourcegraph.com/github.com/gbrlsnchs/jwt?badge)
[![GoDoc](https://godoc.org/github.com/gbrlsnchs/jwt?status.svg)](https://godoc.org/github.com/gbrlsnchs/jwt)
[![Minimal version](https://img.shields.io/badge/minimal%20version-go1.10%2B-5272b4.svg)](https://golang.org/doc/go1.10)
[![Join the chat at https://gitter.im/gbrlsnchs/jwt](https://badges.gitter.im/gbrlsnchs/jwt.svg)](https://gitter.im/gbrlsnchs/jwt?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

## About
This package is a JWT signer, verifier and validator for [Go](https://golang.org) (or Golang).

Although there are many JWT packages out there for Go, many lack support for some signing, verifying or validation methods and, when they don't, they're overcomplicated. This package tries to mimic the ease of use from [Node JWT library](https://github.com/auth0/node-jsonwebtoken)'s API while following the [Effective Go](https://golang.org/doc/effective_go.html) guidelines.

Support for [JWE](https://tools.ietf.org/html/rfc7516) isn't provided. Instead, [JWS](https://tools.ietf.org/html/rfc7515) is used, narrowed down to the [JWT specification](https://tools.ietf.org/html/rfc7519).

### Installing
#### Go 1.10
`vgo get -u github.com/gbrlsnchs/jwt/v2`
#### Go 1.11 or after
`go get -u github.com/gbrlsnchs/jwt/v2`

### Importing
```go
import (
	// ...

	github.com/gbrlsnchs/jwt/v2
)
```

## Usage
Full documentation [here](https://godoc.org/github.com/gbrlsnchs/jwt).

### Signing a simple JWT
```go
// Timestamp the beginning.
now := time.Now()
// Define a signer.
hs256 := jwt.NewHS256("secret")
jot := &jwt.JWT{
	Issuer:         "gbrlsnchs",
	Subject:        "someone",
	Audience:       "gophers",
	ExpirationTime: now.Add(24 * 30 * 12 * time.Hour).Unix(),
	NotBefore:      now.Add(30 * time.Minute).Unix(),
	IssuedAt:       now.Unix(),
	ID:             "foobar",
}
jot.SetAlgorithm(hs256)
jot.SetKeyID("kid")
payload, err := jwt.Marshal(jot)
if err != nil {
	// handle error
}
token, err := hs256.Sign(payload)
if err != nil {
	// handle error
}
log.Printf("token = %s", token)
```

### Signing a JWT with public claims
#### First, create a custom type and embed a JWT pointer in it
```go
type Token struct {
	*jwt.JWT
	IsLoggedIn  bool   `json:"isLoggedIn"`
	CustomField string `json:"customField,omitempty"`
}
```

#### Now initialize, marshal and sign it
```go
// Timestamp the beginning.
now := time.Now()
// Define a signer.
hs256 := jwt.NewHS256("secret")
jot := &Token{
	JWT: &jwt.JWT{
		Issuer:         "gbrlsnchs",
		Subject:        "someone",
		Audience:       "gophers",
		ExpirationTime: now.Add(24 * 30 * 12 * time.Hour).Unix(),
		NotBefore:      now.Add(30 * time.Minute).Unix(),
		IssuedAt:       now.Unix(),
		ID:             "foobar",
	},
	IsLoggedIn:  true,
	CustomField: "myCustomField",
}
jot.SetAlgorithm(hs256)
jot.SetKeyID("kid")
payload, err := jwt.Marshal(jot)
if err != nil {
	// handle error
}
token, err := hs256.Sign(payload)
if err != nil {
	// handle error
}
log.Printf("token = %s", token)
```

### Verifying and validating a JWT
```go
// Timestamp the beginning.
now := time.Now()
// Define a signer.
hs256 := jwt.NewHS256("secret")
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
if err = jwt.Unmarshal(payload, &jot); err != nil {
	// handle error
}
if err = hs256.Verify(payload, sig); err != nil {
	// handle error
}

// Validate fields.
iatValidator := jwt.IssuedAtValidator(now)
expValidator := jwt.ExpirationTimeValidator(now)
audValidator := jwt.AudienceValidator("admin")
if err = jot.Validate(algValidator, expValidator, audValidator); err != nil {
	switch err {
	case jwt.ErrIatValidation:
		// handle "iat" validation error
	case jwt.ErrExpValidation:
		// handle "exp" validation error
	case jwt.ErrAudValidation:
		// handle "aud" validation error
	}
}
```

## Contributing
### How to help
- For bugs and opinions, please [open an issue](https://github.com/gbrlsnchs/jwt/issues/new)
- For pushing changes, please [open a pull request](https://github.com/gbrlsnchs/jwt/compare)
