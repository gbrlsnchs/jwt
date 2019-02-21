package jwt

// Signer is a signing method capable of
// both signing and verifying a JWT.
type Signer interface {
	// Sign signs a JWT payload and returns a complete JWT (payload + signature).
	Sign([]byte) ([]byte, error)
	Size() int
	String() string // prints a specific text used in the "alg" field
}
