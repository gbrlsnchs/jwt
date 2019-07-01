// +build !go1.13

package jwt

import (
	"github.com/gbrlsnchs/jwt/v3/internal"
	"golang.org/x/crypto/ed25519"
)

var (
	// ErrEd25519PrivKey is the error for trying to sign a JWT with a nil private key.
	ErrEd25519PrivKey = internal.NewError("jwt: edDSA private key is nil")
	// ErrEd25519PubKey is the error for trying to verify a JWT with a nil public key.
	ErrEd25519PubKey = internal.NewError("jwt: edDSA public key is nil")
	// ErrEd25519Verification is the error for when verification with edDSA fails.
	ErrEd25519Verification = internal.NewError("jwt: edDSA verification failed")

	_ Algorithm = new(edDSA)
)

type edDSA struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewEd25519 creates a new algorithm using EdDSA and SHA-512.
func NewEd25519(priv ed25519.PrivateKey, pub ed25519.PublicKey) Algorithm {
	return &edDSA{priv: priv, pub: pub}
}

// Name returns the algorithm's name.
func (*edDSA) Name() string {
	return "Ed25519"
}

// Sign signs headerPayload using the Ed25519 algorithm.
func (e *edDSA) Sign(headerPayload []byte) ([]byte, error) {
	if e.priv == nil {
		return nil, ErrEd25519PrivKey
	}
	return ed25519.Sign(e.priv, headerPayload), nil
}

// Size returns the signature byte size.
func (*edDSA) Size() int {
	return ed25519.SignatureSize
}

// Verify verifies a payload and a signature.
func (e *edDSA) Verify(payload, sig []byte) (err error) {
	if e.pub == nil {
		return ErrEd25519PubKey
	}
	if sig, err = internal.DecodeToBytes(sig); err != nil {
		return err
	}
	if !ed25519.Verify(e.pub, payload, sig) {
		return ErrEd25519Verification
	}
	return nil
}
