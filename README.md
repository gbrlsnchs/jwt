# jwt (JSON Web Token for Go)
[![JWT compatible](https://jwt.io/img/badge.svg)](https://jwt.io)  

[![CircleCI](https://circleci.com/gh/gbrlsnchs/jwt.svg?style=shield)](https://circleci.com/gh/gbrlsnchs/jwt)
[![Go Report Card](https://goreportcard.com/badge/github.com/gbrlsnchs/jwt)](https://goreportcard.com/report/github.com/gbrlsnchs/jwt)
[![GoDoc](https://godoc.org/github.com/gbrlsnchs/jwt?status.svg)](https://godoc.org/github.com/gbrlsnchs/jwt)
[![Join the chat at https://gitter.im/gbrlsnchs/jwt](https://badges.gitter.im/gbrlsnchs/jwt.svg)](https://gitter.im/gbrlsnchs/jwt?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

## About
This package is a JWT signer, verifier and validator for [Go](https://golang.org) (or Golang).

Although there are many JWT packages out there for Go, many lack support for some signing, verifying or validation methods and, when they don't, they're overcomplicated. This package tries to mimic the ease of use from [Node JWT library](https://github.com/auth0/node-jsonwebtoken)'s API while following the [Effective Go](https://golang.org/doc/effective_go.html) guidelines.

Support for [JWE](https://tools.ietf.org/html/rfc7516) isn't provided (not yet but is in the roadmap, see #17). Instead, [JWS](https://tools.ietf.org/html/rfc7515) is used, narrowed down to the [JWT specification](https://tools.ietf.org/html/rfc7519).

### Supported signing methods
|         | SHA-256            | SHA-384            | SHA-512            |
|:-------:|:------------------:|:------------------:|:------------------:|
| HMAC    | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| RSA     | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| RSA-PSS | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| ECDSA   | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| EdDSA   | :heavy_minus_sign: | :heavy_minus_sign: | :heavy_check_mark: |

## Important
Branch `master` is unstable, **always** use tagged versions. That way it is possible to differentiate pre-release tags from production ones.
In other words, API changes all the time in `master`. It's a place for public experiment. Thus, make use of the latest stable version via Go modules.

## Usage
Full documentation [here](https://godoc.org/github.com/gbrlsnchs/jwt).

### Installing
`GO111MODULE=on go get -u github.com/gbrlsnchs/jwt/v3`

### Importing
```go
import (
	// ...

	"github.com/gbrlsnchs/jwt/v3"
)
```

### Examples
<details><summary><b>Signing a JWT with default claims</b></summary>
<p>

```go
now := time.Now()
hs256 := jwt.NewHS256([]byte("secret"))
hd := jwt.Header{KeyID: "kid"}
pl := jwt.Payload{
	Issuer:         "gbrlsnchs",
	Subject:        "someone",
	Audience:       jwt.Audience{"https://golang.org", "https://jwt.io"},
	ExpirationTime: now.Add(24 * 30 * 12 * time.Hour).Unix(),
	NotBefore:      now.Add(30 * time.Minute).Unix(),
	IssuedAt:       now.Unix(),
	JWTID:          "foobar",
}
token, err := jwt.Sign(hs256, hd, pl)
if err != nil {
	// Handle error.
}
log.Printf("token = %s", token)
```

</p>
</details>

<details><summary><b>Signing a JWT with custom claims</b></summary>
<p>

#### First, create a custom type and embed a `Payload` in it
```go
type CustomPayload struct {
	jwt.Payload
	IsLoggedIn  bool   `json:"isLoggedIn"`
	CustomField string `json:"customField,omitempty"`
}
```

#### Now initialize and sign it
```go
now := time.Now()
hs256 := jwt.NewHS256([]byte("secret"))
hd := jwt.Header{KeyID: "kid"}
pl := CustomPayload{
	Payload: jwt.Payload{
		Issuer:         "gbrlsnchs",
		Subject:        "someone",
		Audience:       jwt.Audience{"https://golang.org", "https://jwt.io"},
		ExpirationTime: now.Add(24 * 30 * 12 * time.Hour).Unix(),
		NotBefore:      now.Add(30 * time.Minute).Unix(),
		IssuedAt:       now.Unix(),
		JWTID:          "foobar",
	},
	IsLoggedIn:  true,
	CustomField: "myCustomField",
}
token, err := jwt.Sign(hs256, hd, pl)
if err != nil {
	// Handle error.
}
log.Printf("token = %s", token)
```

</p>
</details>

<details><summary><b>Verifying and validating a JWT</b></summary>
<p>

```go
now := time.Now()
hs256 := jwt.NewHS256([]byte("secret"))
token := []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
	"lZ1zDoGNAv3u-OclJtnoQKejE8_viHlMtGlAxE8AE0Q")

raw, err := jwt.Verify(hs256, token) 
if err != nil {
	// Handle error.
}
var (
	hd = raw.Header()
	pl CustomPayload
)
if err = raw.Decode(&pl); err != nil {
	// Handle error.
}
fmt.Println(hd.Algorithm)
fmt.Println(hd.KeyID)

iatValidator := jwt.IssuedAtValidator(now)
expValidator := jwt.ExpirationTimeValidator(now, true)
audValidator := jwt.AudienceValidator(jwt.Audience{
	"https://golang.org",
	"https://jwt.io",
	"https://google.com",
	"https://reddit.com",
})
if err := pl.Validate(iatValidator, expValidator, audValidator); err != nil {
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

</p>
</details>

## Contributing
### How to help
- For bugs and opinions, please [open an issue](https://github.com/gbrlsnchs/jwt/issues/new)
- For pushing changes, please [open a pull request](https://github.com/gbrlsnchs/jwt/compare)
