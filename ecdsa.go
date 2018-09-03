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
	// ErrNoECDSAPrivKey is the error for trying to sign a JWT with a nil private key.
	ErrNoECDSAPrivKey = errors.New("jwt.(Signer).Sign: ECDSA private key is nil")
	// ErrNoECDSAPubKey is the error for trying to verify a JWT with a nil public key.
	ErrNoECDSAPubKey = errors.New("jwt.(Signer).Sign: ECDSA public key is nil")
	// ErrECDSAInvalid is the error for an invalid signature.
	ErrECDSAInvalid = errors.New("jwt.(Signer).Verify: ECDSA validation failed")
	// ErrECDSASigLen is the error for an invalid signature length.
	ErrECDSASigLen = errors.New("jwt.(Signer).Verify: ECDSA signature has unexpected size")
)

type ecdsasha struct {
	priv *ecdsa.PrivateKey
	pub  *ecdsa.PublicKey
	hash func() hash.Hash
	alg  string
}

// ES256 creates a signing method using ECDSA and SHA-256.
func ES256(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) Signer {
	return &ecdsasha{priv: priv, pub: pub, hash: sha256.New, alg: MethodES256}
}

// ES384 creates a signing method using ECDSA and SHA-384.
func ES384(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) Signer {
	return &ecdsasha{priv: priv, pub: pub, hash: sha512.New384, alg: MethodES384}
}

// ES512 creates a signing method using ECDSA and SHA-512.
func ES512(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) Signer {
	return &ecdsasha{priv: priv, pub: pub, hash: sha512.New, alg: MethodES512}
}

func (e *ecdsasha) Sign(payload []byte) ([]byte, error) {
	if e.priv == nil {
		return nil, ErrNoECDSAPrivKey
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
		return ErrNoECDSAPubKey
	}
	decSig := make([]byte, enc.DecodedLen(len(sig)))
	if _, err = enc.Decode(decSig, sig); err != nil {
		return err
	}
	if err = e.verify(payload, decSig); err != nil {
		return err
	}
	return nil
}

func (e *ecdsasha) sign(msg []byte) ([]byte, error) {
	hh := e.hash()
	var err error
	if _, err = hh.Write(msg); err != nil {
		return nil, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, e.priv, hh.Sum(nil))
	if err != nil {
		return nil, err
	}

	byteSize := e.byteSize(e.priv.Params().BitSize)
	rbytes := r.Bytes()
	rsig := make([]byte, byteSize)
	copy(rsig[byteSize-len(rbytes):], rbytes)

	sbytes := s.Bytes()
	ssig := make([]byte, byteSize)
	copy(ssig[byteSize-len(sbytes):], sbytes)
	return append(rsig, ssig...), nil
}

func (e *ecdsasha) verify(msg, sig []byte) error {
	byteSize := e.byteSize(e.pub.Params().BitSize)
	if len(sig) != byteSize*2 {
		return ErrECDSASigLen
	}

	r := big.NewInt(0).SetBytes(sig[:byteSize])
	s := big.NewInt(0).SetBytes(sig[byteSize:])
	hh := e.hash()
	if _, err := hh.Write(msg); err != nil {
		return err
	}

	if !ecdsa.Verify(e.pub, hh.Sum(nil), r, s) {
		return ErrECDSAInvalid
	}
	return nil
}

func (e *ecdsasha) byteSize(bitSize int) int {
	byteSize := bitSize / 8
	if bitSize%8 > 0 {
		return byteSize + 1
	}
	return byteSize
}
