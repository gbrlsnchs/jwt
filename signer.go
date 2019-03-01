package jwt

// Signer is a JWT signer.
type Signer interface {
	// Sign signs a JWT payload and returns a complete JWT (payload + signature).
	Sign([]byte) ([]byte, error)
	// Size is the signature size of a signer.
	Size() (int, error)
	// String returns the string representation of the signing method.
	String() string
}
