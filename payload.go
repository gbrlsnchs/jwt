package jwt

// Payload is a JWT payload according to the RFC 7519.
type Payload struct {
	Issuer         string   `json:"iss,omitempty"`
	Subject        string   `json:"sub,omitempty"`
	Audience       Audience `json:"aud,omitempty"`
	ExpirationTime int64    `json:"exp,omitempty"`
	NotBefore      int64    `json:"nbf,omitempty"`
	IssuedAt       int64    `json:"iat,omitempty"`
	JWTID          string   `json:"jti,omitempty"`
}

// Validate validates claims and header fields.
func (p *Payload) Validate(validators ...ValidatorFunc) error {
	for _, vl := range validators {
		if err := vl(p); err != nil {
			return err
		}
	}
	return nil
}
