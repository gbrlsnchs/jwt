package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/gbrlsnchs/jwt/v3/internal"
)

var (
	// ErrECDSANilPrivKey is the error for trying to sign a JWT with a nil private key.
	ErrECDSANilPrivKey = errors.New("jwt: ECDSA private key is nil")
	// ErrECDSANilPubKey is the error for trying to verify a JWT with a nil public key.
	ErrECDSANilPubKey = errors.New("jwt: ECDSA public key is nil")
	// ErrECDSAVerification is the error for an invalid signature.
	ErrECDSAVerification = errors.New("jwt: ECDSA verification failed")

	_ Algorithm = new(ecdsaSHA)
)

func byteSize(bitSize int) int {
	byteSize := bitSize / 8
	if bitSize%8 > 0 {
		return byteSize + 1
	}
	return byteSize
}

type ecdsaSHA struct {
	name string
	priv *ecdsa.PrivateKey
	pub  *ecdsa.PublicKey
	sha  crypto.Hash
	size int

	pool *hashPool
}

func newECDSASHA(name string, priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, sha crypto.Hash) *ecdsaSHA {
	if pub == nil {
		pub = &priv.PublicKey
	}
	return &ecdsaSHA{
		name: name,
		priv: priv,
		pub:  pub,
		sha:  sha,
		size: byteSize(pub.Params().BitSize) * 2,
		pool: newHashPool(sha.New),
	}
}

// NewES256 creates a new algorithm using ECDSA and SHA-256.
func NewES256(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) Algorithm {
	return newECDSASHA("ES256", priv, pub, crypto.SHA256)
}

// NewES384 creates a new algorithm using ECDSA and SHA-384.
func NewES384(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) Algorithm {
	return newECDSASHA("ES384", priv, pub, crypto.SHA384)
}

// NewES512 creates a new algorithm using ECDSA and SHA-512.
func NewES512(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) Algorithm {
	return newECDSASHA("ES512", priv, pub, crypto.SHA512)
}

// Name returns the algorithm's name.
func (es *ecdsaSHA) Name() string {
	return es.name
}

// Sign signs headerPayload using the ECDSA-SHA algorithm.
func (es *ecdsaSHA) Sign(headerPayload []byte) ([]byte, error) {
	if es.priv == nil {
		return nil, ErrECDSANilPrivKey
	}
	return es.sign(headerPayload)
}

// Size returns the signature's byte size.
func (es *ecdsaSHA) Size() int {
	return es.size
}

// Verify verifies a signature based on headerPayload using ECDSA-SHA.
func (es *ecdsaSHA) Verify(headerPayload, sig []byte) (err error) {
	if es.pub == nil {
		return ErrECDSANilPubKey
	}
	if sig, err = internal.DecodeToBytes(sig); err != nil {
		return err
	}
	byteSize := byteSize(es.pub.Params().BitSize)
	if len(sig) != byteSize*2 {
		return ErrECDSAVerification
	}

	r := big.NewInt(0).SetBytes(sig[:byteSize])
	s := big.NewInt(0).SetBytes(sig[byteSize:])
	sum, err := es.pool.sign(headerPayload)
	if err != nil {
		return err
	}
	if !ecdsa.Verify(es.pub, sum, r, s) {
		return ErrECDSAVerification
	}
	return nil
}

func (es *ecdsaSHA) sign(headerPayload []byte) ([]byte, error) {
	sum, err := es.pool.sign(headerPayload)
	if err != nil {
		return nil, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, es.priv, sum)
	if err != nil {
		return nil, err
	}
	byteSize := byteSize(es.priv.Params().BitSize)
	rbytes := r.Bytes()
	rsig := make([]byte, byteSize)
	copy(rsig[byteSize-len(rbytes):], rbytes)

	sbytes := s.Bytes()
	ssig := make([]byte, byteSize)
	copy(ssig[byteSize-len(sbytes):], sbytes)
	return append(rsig, ssig...), nil
}
