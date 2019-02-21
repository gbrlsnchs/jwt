package jwt

// Verifier is a JWT verifier.
type Verifier interface {
	Verify([]byte, []byte) error
}
