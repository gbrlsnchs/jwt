package jwt

import "fmt"

// Signer is a JWT signer.
type Signer interface {
	fmt.Stringer
	Sign([]byte) ([]byte, error)
	Size() int
}
