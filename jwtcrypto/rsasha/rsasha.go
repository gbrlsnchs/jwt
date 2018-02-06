package rsasha

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"

	"github.com/gbrlsnchs/jwt/jwtcrypto"
)

// RSASHA represents a signing method
// using RSA signature and SHA hash algorithms.
type RSASHA struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Hash       crypto.Hash
}

// New256 creates a signing method using RSA and SHA-256.
func New256(priv *rsa.PrivateKey, pub *rsa.PublicKey) *RSASHA {
	return &RSASHA{
		PrivateKey: priv,
		PublicKey:  pub,
		Hash:       crypto.SHA256,
	}
}

// New384 creates a signing method using RSA and SHA-384.
func New384(priv *rsa.PrivateKey, pub *rsa.PublicKey) *RSASHA {
	return &RSASHA{
		PrivateKey: priv,
		PublicKey:  pub,
		Hash:       crypto.SHA384,
	}
}

// New512 creates a signing method using RSA and SHA-512.
func New512(priv *rsa.PrivateKey, pub *rsa.PublicKey) *RSASHA {
	return &RSASHA{
		PrivateKey: priv,
		PublicKey:  pub,
		Hash:       crypto.SHA512,
	}
}

// HasKey returns whether a public key is set.
func (r *RSASHA) HasKey() bool {
	return r.PublicKey != nil
}

// Sign signs a message using an RSA private key.
func (r *RSASHA) Sign(digest []byte) ([]byte, error) {
	// Use SHA256 as default algorithm.
	if r.Hash < crypto.SHA256 || r.Hash > crypto.SHA512 {
		r.Hash = crypto.SHA256
	}

	sha := r.Hash.New()

	if _, err := sha.Write(digest); err != nil {
		return nil, err
	}

	sig, err := rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, r.Hash, sha.Sum(nil))

	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (r *RSASHA) String() jwtcrypto.SigningMethod {
	switch r.Hash {
	case crypto.SHA384:
		return jwtcrypto.RS384

	case crypto.SHA512:
		return jwtcrypto.RS512

	default:
		return jwtcrypto.RS256
	}
}

// Verify verifies a signature using RSA private and public keys.
func (r *RSASHA) Verify(digest, sig []byte) (bool, error) {
	sha := r.Hash.New()

	if _, err := sha.Write(digest); err != nil {
		return false, err
	}

	if err := rsa.VerifyPKCS1v15(r.PublicKey, r.Hash, sha.Sum(nil), sig); err != nil {
		return false, err
	}

	return true, nil
}
