package none

import "github.com/gbrlsnchs/jwt/jwtcrypto"

// None is a dull signing method that
// signs a message as is and is always valid.
type None struct{}

// HasKey returns false, since None
// doesn't make use of any keys.
func (n *None) HasKey() bool {
	return false
}

// Sign simply returns a message as is.
func (n *None) Sign(digest []byte) ([]byte, error) {
	return digest, nil
}

func (n *None) String() jwtcrypto.SigningMethod {
	return jwtcrypto.None
}

// Verify returns true, and thus None is always valid.
func (n *None) Verify(_, _ []byte) (bool, error) {
	return true, nil
}
