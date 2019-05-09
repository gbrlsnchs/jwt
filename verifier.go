package jwt

import "fmt"

// Verifier is a JWT verifier.
type Verifier interface {
	fmt.Stringer
	Verify([]byte, []byte) error
}
