package jwt

import (
	"errors"

	"golang.org/x/crypto/ed25519"
)

var (
	ErrEd25519PrivKey      = errors.New("jwt: Ed25519 private key is nil")
	ErrEd25519PubKey       = errors.New("jwt: Ed25519 public key is nil")
	ErrEd25519Verification = errors.New("jwt: Ed25519 verification failed")
)

type Ed25519 struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func NewEd25519(priv ed25519.PrivateKey, pub ed25519.PublicKey) *Ed25519 {
	return &Ed25519{priv: priv, pub: pub}
}

func (e *Ed25519) Sign(payload []byte) ([]byte, error) {
	if e.priv == nil {
		return nil, ErrEd25519PrivKey
	}
	return ed25519.Sign(e.priv, payload), nil
}

func (e *Ed25519) Size() int {
	return ed25519.SignatureSize
}

func (e *Ed25519) String() string {
	return MethodEd25519
}

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
