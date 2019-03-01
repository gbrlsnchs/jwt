package jwt

type None struct{}

// None returns a Signer that
// bypasses signing and validating,
// thus implementing the "none" method.
func NewNone() *None {
	return &None{}
}

func (n *None) Sign(_ []byte) ([]byte, error) {
	return nil, nil
}

func (n *None) Size() (int, error) {
	return 0, nil
}

func (n *None) String() string {
	return MethodNone
}

func (n *None) Verify(_, _ []byte) error {
	return nil
}
