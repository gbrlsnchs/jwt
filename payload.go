package jwt

var (
	_ Validator = new(Payload)
	_ Validator = &struct{ Payload }{}
	_ Validator = &struct{ *Payload }{}
)

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

// Validate validates Payload claims.
func (p *Payload) Validate(funcs ...ValidatorFunc) error {
	for _, fn := range funcs {
		if err := fn(p); err != nil {
			return err
		}
	}
	return nil
}
