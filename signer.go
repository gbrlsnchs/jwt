package jwt

// Signer is a JWT signer.
type Signer interface {
	// Sign signs a JWT payload and returns a complete JWT (payload + signature).
	Sign([]byte) ([]byte, error)
	// Size returns the signature byte size.
	Size() int
	// String returns the string representation of the signing method.
	String() string
}
