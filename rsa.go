package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
)

var (
	// ErrRSANilPrivKey is the error for trying to sign a JWT with a nil private key.
	ErrRSANilPrivKey = errors.New("jwt: RSA private key is nil")
	// ErrRSANilPubKey is the error for trying to verify a JWT with a nil public key.
	ErrRSANilPubKey = errors.New("jwt: RSA public key is nil")
)

type rsasha struct {
	priv *rsa.PrivateKey
	pub  *rsa.PublicKey
	hash crypto.Hash
	alg  string
}

// NewRS256 creates a signing method using RSA and SHA-256.
func NewRS256(priv *rsa.PrivateKey, pub *rsa.PublicKey) Signer {
	return &rsasha{priv: priv, pub: pub, hash: crypto.SHA256, alg: MethodRS256}
}

// NewRS384 creates a signing method using RSA and SHA-384.
func NewRS384(priv *rsa.PrivateKey, pub *rsa.PublicKey) Signer {
	return &rsasha{priv: priv, pub: pub, hash: crypto.SHA384, alg: MethodRS384}
}

// NewRS512 creates a signing method using RSA and SHA-512.
func NewRS512(priv *rsa.PrivateKey, pub *rsa.PublicKey) Signer {
	return &rsasha{priv: priv, pub: pub, hash: crypto.SHA512, alg: MethodRS512}
}

func (r *rsasha) Sign(payload []byte) ([]byte, error) {
	if r.priv == nil {
		return nil, ErrRSANilPrivKey
	}
	sig, err := r.sign(payload)
	if err != nil {
		return nil, err
	}
	return build(r, payload, sig), nil
}

func (r *rsasha) String() string {
	return r.alg
}

func (r *rsasha) Verify(payload, sig []byte) (err error) {
	if r.pub == nil {
		return ErrRSANilPubKey
	}
	if sig, err = decodeToBytes(sig); err != nil {
		return err
	}
	if err = r.verify(payload, sig); err != nil {
		return err
	}
	return nil
}

func (r *rsasha) sign(payload []byte) ([]byte, error) {
	hh := r.hash.New()
	var err error
	if _, err = hh.Write(payload); err != nil {
		return nil, err
	}

	sig, err := rsa.SignPKCS1v15(rand.Reader, r.priv, r.hash, hh.Sum(nil))
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (r *rsasha) verify(payload, sig []byte) error {
	hh := r.hash.New()
	if _, err := hh.Write(payload); err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(r.pub, r.hash, hh.Sum(nil), sig)
}
