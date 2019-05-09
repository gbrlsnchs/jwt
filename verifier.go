package jwt

import "fmt"

// Verifier is a JWT verifier.
type Verifier interface {
	fmt.Stringer
	Valid() bool
	Verify([]byte, []byte) error
}
