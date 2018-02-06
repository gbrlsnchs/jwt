package jwt

type StdClaims struct {
	Audience       string `json:"aud,omitempty"`
	ExpirationTime int64  `json:"exp,omitempty"`
	IssuedAt       int64  `json:"iat,omitempty"`
	Issuer         string `json:"iss,omitempty"`
	JWTID          string `json:"jti,omitempty"`
	NotBefore      int64  `json:"bnf,omitempty"`
	Subject        string `json:"sub,omitempty"`
}
