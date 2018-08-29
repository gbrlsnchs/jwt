package jwt

// Header is a JOSE header scoped to the JWT definition.
type Header struct {
	*header
	Algorithm   string `json:"alg,omitempty"`
	KeyID       string `json:"kid,omitempty"`
	ContentType string `json:"cty,omitempty"`
}

type header struct {
	Type string `json:"typ,omitempty"`
}
