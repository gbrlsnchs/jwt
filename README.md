# jwt (JSON Web Token for Go)
[![JWT Compatible](https://jwt.io/img/badge.svg)](https://jwt.io)

[![Build Status](https://travis-ci.org/gbrlsnchs/jwt.svg?branch=master)](https://travis-ci.org/gbrlsnchs/jwt)
[![Build status](https://ci.appveyor.com/api/projects/status/wqao7uvucce71jja/branch/master?svg=true)](https://ci.appveyor.com/project/gbrlsnchs/jwt/branch/master)
[![GoDoc](https://godoc.org/github.com/gbrlsnchs/jwt?status.svg)](https://godoc.org/github.com/gbrlsnchs/jwt)
[![Sourcegraph](https://sourcegraph.com/github.com/gbrlsnchs/jwt/-/badge.svg)](https://sourcegraph.com/github.com/gbrlsnchs/jwt?badge)

## About
This package is a JWT signer, verifier and validator for [Go] (or Golang).

When it comes to JWT, there are lots of libraries available for Go.
Still, I couldn't find one that was simple enough to use, so I decided to create this library in order to help whomever needs an easy solution for JWT.

The main difference between other libraries is ease of use.
This library is pretty straightforward and has no external dependencies.
If one is used to easy-to-use libraries, like [Node's], perhaps it is the ideal library for them to use.

Also, it supports header and payload validators and all hashing algorithms (both signing and verifying).

## Usage
Full documentation [here].

## Example
### Issue a JWT
```go
// Set the options.
now := time.Now()
opt := &jwt.Options{
	JWTID:          "unique_id",
	Timestamp:      true,
	ExpirationTime: now.Add(24 * 30 * 12 * time.Hour),
	NotBefore:      now.Add(30 * time.Minute),
	Subject:        "123",
	Audience:       "admin",
	Issuer:         "auth_server",
	KeyID:          "my_key",
	Public:         map[string]interface{}{"foo": "bar", "myBool": true},
}

// Define a signer.
s := jwt.HS256("my_53cr37")

// Issue a new token.
token, err := jwt.Sign(s, opt)
if err != nil {
	// ...
}
log.Print(token)
```

### Verify a JWT
```go
now := time.Now()
s := jwt.HS256("my_53cr37")
jot, err := jwt.FromRequest(r)
if err != nil {
	// handle malformed or inexistent token
}
if err := jot.Verify(s); err != nil {
	// token is invalid
}
```

### Validate a JWT
```go
algValidator := jwt.AlgorithmValidator(jwt.MethodHS256)
expValidator := jwt.ExpirationTimeValidator(now)
audValidator := jwt.AudienceValidator("admin")
if err = jot.Validate(algValidator, expValidator, audValidator); err != nil {
	switch err {
	case jwt.ErrAlgorithmMismatch:
		// handle "alg" mismatch
	case jwt.ErrTokenExpired:
		// handle "exp" being expired
	}
	case jwt.ErrAudienceMismatch:
		// handle "aud" mismatch
}
```

## Contribution
### How to help:
- Pull Requests
- Issues
- Opinions

[Go]: https://golang.org
[Node's]: https://github.com/auth0/node-jsonwebtoken
[here]: https://godoc.org/github.com/gbrlsnchs/jwt
