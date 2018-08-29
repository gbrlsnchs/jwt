package jwt

type Signer interface {
	Sign(Marshaler) ([]byte, error)
	Verify([]byte, Marshaler) error
	String() string
}
