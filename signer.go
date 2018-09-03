package jwt

// Signer is a signing method capable of
// both signing and verifying a JWT.
type Signer interface {
	Sign([]byte) ([]byte, error)
	Verify([]byte, []byte) error
	String() string // prints a specific text used in the "alg" field
}
