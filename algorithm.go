package jwt

// Algorithm is an algorithm for both signing and verifying a JWT.
type Algorithm interface {
	Name() string
	Sign(headerPayload []byte) ([]byte, error)
	Size() int
	Verify(headerPayload, sig []byte) error
}
