package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"github.com/gbrlsnchs/jwt/v3/internal"
)

var (
	// ErrRSANilPrivKey is the error for trying to sign a JWT with a nil private key.
	ErrRSANilPrivKey = errors.New("jwt: RSA private key is nil")
	// ErrRSANilPubKey is the error for trying to verify a JWT with a nil public key.
	ErrRSANilPubKey = errors.New("jwt: RSA public key is nil")

	_ Algorithm = new(rsaSHA)
)

type rsaSHA struct {
	name string
	priv *rsa.PrivateKey
	pub  *rsa.PublicKey
	sha  crypto.Hash
	size int
	pool *hashPool
	opts *rsa.PSSOptions
}

func newRSASHA(name string, priv *rsa.PrivateKey, pub *rsa.PublicKey, sha crypto.Hash, pss bool) *rsaSHA {
	if pub == nil {
		pub = &priv.PublicKey
	}
	rs := &rsaSHA{
		name: name, // cache name
		priv: priv,
		pub:  pub,
		sha:  sha,
		size: internal.RSASignatureSize(pub), // cache size
		pool: newHashPool(sha.New),
	}
	if pss {
		rs.opts = &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       sha,
		}
	}
	return rs
}

// NewRS256 creates a new algorithm using RSA and SHA-256.
func NewRS256(priv *rsa.PrivateKey, pub *rsa.PublicKey) Algorithm {
	return newRSASHA("RS256", priv, pub, crypto.SHA256, false)
}

// NewRS384 creates a new algorithm using RSA and SHA-384.
func NewRS384(priv *rsa.PrivateKey, pub *rsa.PublicKey) Algorithm {
	return newRSASHA("RS384", priv, pub, crypto.SHA384, false)
}

// NewRS512 creates a new algorithm using RSA and SHA-512.
func NewRS512(priv *rsa.PrivateKey, pub *rsa.PublicKey) Algorithm {
	return newRSASHA("RS512", priv, pub, crypto.SHA512, false)
}

// NewPS256 creates a new algorithm using RSA-PSS and SHA-256.
func NewPS256(priv *rsa.PrivateKey, pub *rsa.PublicKey) Algorithm {
	return newRSASHA("PS256", priv, pub, crypto.SHA256, true)
}

// NewPS384 creates a new algorithm using RSA-PSS and SHA-384.
func NewPS384(priv *rsa.PrivateKey, pub *rsa.PublicKey) Algorithm {
	return newRSASHA("PS384", priv, pub, crypto.SHA384, true)
}

// NewPS512 creates a new algorithm using RSA-PSS and SHA-512.
func NewPS512(priv *rsa.PrivateKey, pub *rsa.PublicKey) Algorithm {
	return newRSASHA("PS512", priv, pub, crypto.SHA512, true)
}

// Name returns the algorithm's name.
func (rs *rsaSHA) Name() string {
	return rs.name
}

// Sign signs headerPayload using either RSA-SHA or RSA-PSS-SHA algorithms.
func (rs *rsaSHA) Sign(headerPayload []byte) ([]byte, error) {
	if rs.priv == nil {
		return nil, ErrRSANilPrivKey
	}
	sum, err := rs.pool.sign(headerPayload)
	if err != nil {
		return nil, err
	}
	if rs.opts != nil {
		return rsa.SignPSS(rand.Reader, rs.priv, rs.sha, sum, rs.opts)
	}
	return rsa.SignPKCS1v15(rand.Reader, rs.priv, rs.sha, sum)
}

// Size returns the signature's byte size.
func (rs *rsaSHA) Size() int {
	if rs.pub == nil {
		return 0
	}
	return rs.pub.Size()
}

// Verify verifies a signature based on headerPayload using either RSA-SHA or RSA-PSS-SHA.
func (rs *rsaSHA) Verify(headerPayload, sig []byte) (err error) {
	if rs.pub == nil {
		return ErrRSANilPubKey
	}
	if sig, err = internal.DecodeToBytes(sig); err != nil {
		return err
	}
	sum, err := rs.pool.sign(headerPayload)
	if err != nil {
		return err
	}
	if rs.opts != nil {
		return rsa.VerifyPSS(rs.pub, rs.sha, sum, sig, rs.opts)
	}
	return rsa.VerifyPKCS1v15(rs.pub, rs.sha, sum, sig)
}
