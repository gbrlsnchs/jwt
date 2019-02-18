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

func byteSize(bitSize int) int {
	byteSize := bitSize / 8
	if bitSize%8 > 0 {
		return byteSize + 1
	}
	return byteSize
}

type ECDSA struct {
	priv *ecdsa.PrivateKey
	pub  *ecdsa.PublicKey
	sha  SHA

	pool *pool
}

func NewECDSA(sha SHA, priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) *ECDSA {
	var hh func() hash.Hash
	switch sha {
	case SHA256:
		fallthrough
	default:
		hh = sha256.New
	case SHA384:
		hh = sha512.New384
	case SHA512:
		hh = sha512.New
	}
	return &ECDSA{
		priv: priv,
		pub:  pub,
		sha:  sha,
		pool: newPool(hh),
	}
}

func (e *ECDSA) Sign(payload []byte) ([]byte, error) {
	if e.priv == nil {
		return nil, ErrECDSANilPrivKey
	}
	return e.sign(payload)
}

func (e *ECDSA) Size() int {
	pub := e.pub
	if pub == nil {
		pub = e.priv.Public().(*ecdsa.PublicKey)
	}
	return byteSize(pub.Params().BitSize) * 2
}

func (e *ECDSA) String() string {
	switch e.sha {
	case SHA256:
		return MethodES256
	case SHA384:
		return MethodES384
	case SHA512:
		return MethodES512
	default:
		return ""
	}
}

func (e *ECDSA) Verify(payload, sig []byte) (err error) {
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
