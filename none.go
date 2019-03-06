package jwt

type None struct{}

func (n *None) Sign(_ []byte) ([]byte, error) {
	return nil, nil
}

func (n *None) SizeUp() (int, error) {
	return 0, nil
}

func (n *None) String() string {
	return MethodNone
}

func (n *None) Verify(_, _ []byte) error {
	return nil
}
