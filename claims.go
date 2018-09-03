package jwt

type Claims struct {
	IssuedAt   int64  `json:"iat,omitempty"`
	Expiration int64  `json:"exp,omitempty"`
	NotBefore  int64  `json:"nbf,omitempty"`
	ID         string `json:"jti,omitempty"`
	Audience   string `json:"aud,omitempty"`
	Subject    string `json:"sub,omitempty"`
	Issuer     string `json:"iss,omitempty"`
}
