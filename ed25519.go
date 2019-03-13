package jwt

import (
	"errors"

	"golang.org/x/crypto/ed25519"
)

var (
	// ErrEd25519PrivKey is the error for trying to sign a JWT with a nil private key.
	ErrEd25519PrivKey = errors.New("jwt: Ed25519 private key is nil")
	// ErrEd25519PubKey is the error for trying to verify a JWT with a nil public key.
	ErrEd25519PubKey = errors.New("jwt: Ed25519 public key is nil")
	// ErrEd25519Verification is the error for when verification with Ed25519 fails.
	ErrEd25519Verification = errors.New("jwt: Ed25519 verification failed")
)

// Ed25519 is a signing method that uses EdDSA
// with a SHA-512 hashing function to sign tokens.
type Ed25519 struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewEd25519 creates a new Ed25519 signing method with the SHA-512 hashing function.
func NewEd25519(priv ed25519.PrivateKey, pub ed25519.PublicKey) *Ed25519 {
	return &Ed25519{priv: priv, pub: pub}
}

// Sign signs a payload and returns the signature.
func (e *Ed25519) Sign(payload []byte) ([]byte, error) {
	if e.priv == nil {
		return nil, ErrEd25519PrivKey
	}
	return ed25519.Sign(e.priv, payload), nil
}

// SizeUp returns the signature byte size.
func (e *Ed25519) SizeUp() (int, error) {
	return ed25519.SignatureSize, nil
}

// String returns the signing method name.
func (e *Ed25519) String() string {
	return MethodEd25519
}

// Verify verifies a payload and a signature.
func (e *Ed25519) Verify(payload, sig []byte) (err error) {
	if e.pub == nil {
		return ErrEd25519PubKey
	}
	if sig, err = decodeToBytes(sig); err != nil {
		return err
	}
	if !ed25519.Verify(e.pub, payload, sig) {
		return ErrEd25519Verification
	}
	return nil
}
