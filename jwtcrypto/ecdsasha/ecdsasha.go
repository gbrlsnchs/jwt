package ecdsasha

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"

	"github.com/gbrlsnchs/jwt/jwtcrypto"
)

// ECDSASHA represents a signing method
// using ECDSA signature and SHA hash algorithms.
type ECDSASHA struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	Hash       crypto.Hash
}

// New256 creates a signing method using ECDSA and SHA-256.
func New256(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) *ECDSASHA {
	return &ECDSASHA{
		PrivateKey: priv,
		PublicKey:  pub,
		Hash:       crypto.SHA256,
	}
}

// New384 creates a signing method using ECDSA and SHA-384.
func New384(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) *ECDSASHA {
	return &ECDSASHA{
		PrivateKey: priv,
		PublicKey:  pub,
		Hash:       crypto.SHA384,
	}
}

// New512 creates a signing method using ECDSA and SHA-512.
func New512(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) *ECDSASHA {
	return &ECDSASHA{
		PrivateKey: priv,
		PublicKey:  pub,
		Hash:       crypto.SHA512,
	}
}

// HasKey returns whether a public key is set.
func (e *ECDSASHA) HasKey() bool {
	return e.PublicKey != nil
}

// Sign signs a message using an ECDSA private key.
func (e *ECDSASHA) Sign(digest []byte) ([]byte, error) {
	// Use SHA256 as default algorithm.
	if e.Hash < crypto.SHA256 || e.Hash > crypto.SHA512 {
		e.Hash = crypto.SHA256
	}

	sha := e.Hash.New()

	if _, err := sha.Write(digest); err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, e.PrivateKey, sha.Sum(nil))

	if err != nil {
		return nil, err
	}

	sig := r.Bytes()
	sig = append(sig, s.Bytes()...)

	return sig, nil
}

func (e *ECDSASHA) String() jwtcrypto.SigningMethod {
	switch e.Hash {
	case crypto.SHA384:
		return jwtcrypto.ES384

	case crypto.SHA512:
		return jwtcrypto.ES512

	default:
		return jwtcrypto.ES256
	}
}

// Verify verifies a signature using ECDSA private and public keys.
func (e *ECDSASHA) Verify(digest, _ []byte) (bool, error) {
	if e.PublicKey == nil {
		return false, nil
	}

	sha := e.Hash.New()
	sum := sha.Sum(nil)

	if _, err := sha.Write(digest); err != nil {
		return false, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, e.PrivateKey, sum)

	if err != nil {
		return false, err
	}

	return ecdsa.Verify(e.PublicKey, sum, r, s), nil
}
