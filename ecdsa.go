package jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"math/big"
)

var (
	// ErrECDSANilPrivKey is the error for trying to sign a JWT with a nil private key.
	ErrECDSANilPrivKey = errors.New("jwt: ECDSA private key is nil")
	// ErrECDSANilPubKey is the error for trying to verify a JWT with a nil public key.
	ErrECDSANilPubKey = errors.New("jwt: ECDSA public key is nil")
	// ErrECDSAVerification is the error for an invalid signature.
	ErrECDSAVerification = errors.New("jwt: ECDSA verification failed")
)

type ecdsasha struct {
	priv *ecdsa.PrivateKey
	pub  *ecdsa.PublicKey
	hash func() hash.Hash
	alg  string
}

// NewES256 creates a signing method using ECDSA and SHA-256.
func NewES256(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) Signer {
	return &ecdsasha{priv: priv, pub: pub, hash: sha256.New, alg: MethodES256}
}

// NewES384 creates a signing method using ECDSA and SHA-384.
func NewES384(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) Signer {
	return &ecdsasha{priv: priv, pub: pub, hash: sha512.New384, alg: MethodES384}
}

// NewES512 creates a signing method using ECDSA and SHA-512.
func NewES512(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) Signer {
	return &ecdsasha{priv: priv, pub: pub, hash: sha512.New, alg: MethodES512}
}

func (e *ecdsasha) Sign(payload []byte) ([]byte, error) {
	if e.priv == nil {
		return nil, ErrECDSANilPrivKey
	}
	sig, err := e.sign(payload)
	if err != nil {
		return nil, err
	}
	return build(e, payload, sig), nil
}

func (e *ecdsasha) String() string {
	return e.alg
}

func (e *ecdsasha) Verify(payload, sig []byte) (err error) {
	if e.pub == nil {
		return ErrECDSANilPubKey
	}
	if sig, err = decodeToBytes(sig); err != nil {
		return err
	}
	if err = e.verify(payload, sig); err != nil {
		return err
	}
	return nil
}

func (e *ecdsasha) sign(payload []byte) ([]byte, error) {
	hh := e.hash()
	var err error
	if _, err = hh.Write(payload); err != nil {
		return nil, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, e.priv, hh.Sum(nil))
	if err != nil {
		return nil, err
	}
	byteSize := byteSize(e.priv.Params().BitSize)
	rbytes := r.Bytes()
	rsig := make([]byte, byteSize)
	copy(rsig[byteSize-len(rbytes):], rbytes)

	sbytes := s.Bytes()
	ssig := make([]byte, byteSize)
	copy(ssig[byteSize-len(sbytes):], sbytes)
	return append(rsig, ssig...), nil
}

func (e *ecdsasha) verify(payload, sig []byte) error {
	byteSize := byteSize(e.pub.Params().BitSize)
	if len(sig) != byteSize*2 {
		return ErrECDSAVerification
	}

	r := big.NewInt(0).SetBytes(sig[:byteSize])
	s := big.NewInt(0).SetBytes(sig[byteSize:])
	hh := e.hash()
	if _, err := hh.Write(payload); err != nil {
		return err
	}

	if !ecdsa.Verify(e.pub, hh.Sum(nil), r, s) {
		return ErrECDSAVerification
	}
	return nil
}
