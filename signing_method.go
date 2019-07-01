package jwt

// SigningMethod is a signing method both signing and verifying a JWT.
type SigningMethod interface {
	Name() string
	Sign(headerPayload []byte) ([]byte, error)
	Size() int
	Verify(headerPayload, sig []byte) error
}
