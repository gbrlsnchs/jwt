package jwt

import "fmt"

// Signer is a JWT signer.
type Signer interface {
	fmt.Stringer
	// Sign signs a JWT's header and payload.
	Sign([]byte) ([]byte, error)
	// SizeUp tries to return a signer's signature size.
	SizeUp() (int, error)
}
