package jwt

// Header is a JOSE header scoped to the JWT definition.
type Header struct {
	Algorithm string `json:"alg,omitempty"`
	KeyID     string `json:"kid,omitempty"`
	*header
}

type header struct {
	Type string `json:"typ,omitempty"`
}
