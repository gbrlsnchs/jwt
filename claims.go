package jwt

import (
	"time"
)

type Claims struct {
	*claims              // necessary hack until Go omits zero value structs
	IssuedAt   time.Time `json:"-"`
	Expiration time.Time `json:"-"`
	NotBefore  time.Time `json:"-"`
	ID         string    `json:"jti,omitempty"`
	Audience   string    `json:"aud,omitempty"`
	Subject    string    `json:"sub,omitempty"`
	Issuer     string    `json:"iss,omitempty"`
}

type claims struct {
	Iat int64 `json:"iat,omitempty"`
	Exp int64 `json:"exp,omitempty"`
	Nbf int64 `json:"nbf,omitempty"`
}
