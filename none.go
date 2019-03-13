package jwt

// None is an unsecured signer and verifier.
type None struct{}

// Sign always returns a nil byte slice and a nil error.
func (n *None) Sign(_ []byte) ([]byte, error) {
	return nil, nil
}

// SizeUp always returns 0 and a nil error.
func (n *None) SizeUp() (int, error) {
	return 0, nil
}

// String returns the string representation
// for the "none" signing method.
func (n *None) String() string {
	return MethodNone
}

// Verify always returns a nil error.
func (n *None) Verify(_, _ []byte) error {
	return nil
}
