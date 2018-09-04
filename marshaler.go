package jwt

// Marshaler is a JWT marshaler.
type Marshaler interface {
	// MarshalJWT returns a JWT payload in compliance with RFC 7519.
	MarshalJWT() ([]byte, error)
	// UnmarshalJWT parses a JWT payload according to RFC 7519.
	UnmarshalJWT(b []byte) error
}
