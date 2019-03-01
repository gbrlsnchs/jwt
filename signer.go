package jwt

// Signer is a JWT signer.
type Signer interface {
	// Sign signs a JWT's header and payload.
	Sign([]byte) ([]byte, error)
	// SizeUp tries to return a signer's signature size.
	SizeUp() (int, error)
	// String returns the string representation of the signing method.
	String() string
}
