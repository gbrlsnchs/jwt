package jwt

type none struct{}

// None returns a Signer that
// bypasses signing and validating,
// thus implementing the "none" method.
func None() Signer {
	return &none{}
}

func (n *none) Sign(jot Marshaler) ([]byte, error) {
	payload, err := jot.MarshalJWT()
	if err != nil {
		return nil, err
	}
	return build(payload, nil, n), nil
}

func (n *none) String() string {
	return MethodNone
}

func (n *none) Verify(token []byte, jot Marshaler) error {
	return jot.UnmarshalJWT(token)
}
