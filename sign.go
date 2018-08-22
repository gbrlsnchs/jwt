package jwt

import (
	"encoding/json"
	"errors"
	"time"
)

var ErrNoSigner = errors.New("jwt.Sign: signer is nil")

// Sign builds a full JWT and signs its last part.
func Sign(s Signer, opt *Options) (string, error) {
	now := time.Now()
	if s == nil {
		return "", ErrNoSigner
	}

	if opt == nil {
		opt = &Options{}
	}
	jot := &JWT{
		header: &header{
			Algorithm: s.String(),
			KeyID:     opt.KeyID,
			Type:      "JWT",
		},
		claims: &claims{
			aud: opt.Audience,
			exp: opt.ExpirationTime,
			iss: opt.Issuer,
			jti: opt.JWTID,
			nbf: opt.NotBefore,
			sub: opt.Subject,
			pub: make(map[string]interface{}),
		},
	}
	for k, v := range opt.Public {
		jot.claims.pub[k] = v
	}
	if opt.Timestamp {
		jot.claims.iat = now
	}
	var token []byte
	p, err := json.Marshal(jot.header)
	if err != nil {
		return "", err
	}

	token = append(token, encode(p)...)
	p, err = json.Marshal(jot.claims)
	if err != nil {
		return "", err
	}

	token = append(token, '.')
	token = append(token, encode(p)...)
	p, err = s.Sign(token)
	if err != nil {
		return "", err
	}

	token = append(token, '.')
	token = append(token, encode(p)...)
	return string(token), nil
}
