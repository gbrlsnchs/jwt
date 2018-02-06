package none

import "github.com/gbrlsnchs/jwt/jwtcrypto"

type None struct{}

func (n *None) HasKey() bool {
	return false
}

func (n *None) Sign(digest []byte) ([]byte, error) {
	return digest, nil
}

func (n *None) String() jwtcrypto.SigningMethod {
	return jwtcrypto.None
}

func (n *None) Verify(_, _ []byte) (bool, error) {
	return true, nil
}
