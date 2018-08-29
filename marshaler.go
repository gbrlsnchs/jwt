package jwt

// Marshaler marshals a struct into a JWT.
type Marshaler interface {
	MarshalJWT() ([]byte, error)
	UnmarshalJWT(b []byte) error
}
