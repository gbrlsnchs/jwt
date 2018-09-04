package jwt

// header is a JOSE header narrowed down to the JWT specification from RFC 7519.
type header struct {
	Type        string `json:"typ,omitempty"`
	ContentType string `json:"cty,omitempty"`
	KeyID       string `json:"kid,omitempty"`
	Algorithm   string `json:"alg,omitempty"`
}
