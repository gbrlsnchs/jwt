package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
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

func byteSize(bitSize int) int {
	byteSize := bitSize / 8
	if bitSize%8 > 0 {
		return byteSize + 1
	}
	return byteSize
}

// ECDSA is a signing method that uses
// elliptic curve cryptography to sign SHA hashes.
type ECDSA struct {
	priv *ecdsa.PrivateKey
	pub  *ecdsa.PublicKey
	hash crypto.Hash

	pool *pool
}

// NewECDSA creates a new ECDSA signing method with one of the available SHA functions.
// The ECDSA pointer returned can be reused both to sign and verify, as it maintains
// a pool of hashing functions to reduce garbage collection cleanups.
func NewECDSA(sha Hash, priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) *ECDSA {
	hh := sha.hash()
	return &ECDSA{
		priv: priv,
		pub:  pub,
		hash: hh,
		pool: newPool(hh.New),
	}
}

// Sign signs a payload and returns the signature.
func (e *ECDSA) Sign(payload []byte) ([]byte, error) {
	if e.priv == nil {
		return nil, ErrECDSANilPrivKey
	}
	return e.sign(payload)
}

// SizeUp returns the signature byte size.
func (e *ECDSA) SizeUp() (int, error) {
	pub := e.pub
	if pub == nil {
		priv := e.priv
		if priv == nil {
			return 0, ErrECDSANilPrivKey
		}
		pub = priv.Public().(*ecdsa.PublicKey)
	}
	return byteSize(pub.Params().BitSize) * 2, nil
}

// String returns the signing method name.
func (e *ECDSA) String() string {
	switch e.hash {
	case crypto.SHA256:
		return MethodES256
	case crypto.SHA384:
		return MethodES384
	case crypto.SHA512:
		return MethodES512
	default:
		return ""
	}
}

// Verify verifies a payload and a signature.
func (e *ECDSA) Verify(payload, sig []byte) (err error) {
	if e.pub == nil {
		return ErrECDSANilPubKey
	}
	if sig, err = decodeToBytes(sig); err != nil {
		return err
	}
	return e.verify(payload, sig)
}

func (e *ECDSA) sign(payload []byte) ([]byte, error) {
	sum, err := e.pool.sign(payload)
	if err != nil {
		return nil, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, e.priv, sum)
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

func (e *ECDSA) verify(payload, sig []byte) error {
	byteSize := byteSize(e.pub.Params().BitSize)
	if len(sig) != byteSize*2 {
		return ErrECDSAVerification
	}

	r := big.NewInt(0).SetBytes(sig[:byteSize])
	s := big.NewInt(0).SetBytes(sig[byteSize:])
	sum, err := e.pool.sign(payload)
	if err != nil {
		return err
	}
	if !ecdsa.Verify(e.pub, sum, r, s) {
		return ErrECDSAVerification
	}
	return nil
}
