package jwt

type Verifier interface {
	Verify([]byte, []byte) error
	String() string
}
