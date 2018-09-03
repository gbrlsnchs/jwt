package jwt

type none struct{}

// None returns a Signer that
// bypasses signing and validating,
// thus implementing the "none" method.
func None() Signer {
	return &none{}
}

func (n *none) Sign(payload []byte) ([]byte, error) {
	return build(n, payload, nil), nil
}

func (n *none) String() string {
	return MethodNone
}

func (n *none) Verify(_, _ []byte) error {
	return nil
}
