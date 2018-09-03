package jwt

// Signer is a signing method capable of
// both signing and verifying a JWT.
type Signer interface {
	// Sign signs a JWT payload and returns a complete JWT (payload + signature).
	Sign([]byte) ([]byte, error)
	// Verify verifies a payload and a signature.
	// It returns an error with details of why verification failed or a nil one if verification is OK.
	Verify([]byte, []byte) error
	String() string // prints a specific text used in the "alg" field
}
