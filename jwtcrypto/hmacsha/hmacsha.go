package hmacsha

import (
	"crypto"
	"crypto/hmac"

	"github.com/gbrlsnchs/jwt/jwtcrypto"
)

// HMACSHA represents a signing method
// using HMAC signature and SHA hash algorithms.
type HMACSHA struct {
	PrivateKey []byte
	Hash       crypto.Hash
}

// New256 creates a signing method using HMAC and SHA-256.
func New256(priv string) *HMACSHA {
	return &HMACSHA{
		PrivateKey: []byte(priv),
		Hash:       crypto.SHA256,
	}
}

// New384 creates a signing method using HMAC and SHA-384.
func New384(priv string) *HMACSHA {
	return &HMACSHA{
		PrivateKey: []byte(priv),
		Hash:       crypto.SHA384,
	}
}

// New512 creates a signing method using HMAC and SHA-512.
func New512(priv string) *HMACSHA {
	return &HMACSHA{
		PrivateKey: []byte(priv),
		Hash:       crypto.SHA512,
	}
}

// HasKey returns whether a secret key is set.
func (h *HMACSHA) HasKey() bool {
	return len(h.PrivateKey) > 0
}

// Sign signs a message using an HMAC private key.
func (h *HMACSHA) Sign(digest []byte) ([]byte, error) {
	// Use SHA256 as default algorithm.
	if h.Hash < crypto.SHA256 || h.Hash > crypto.SHA512 {
		h.Hash = crypto.SHA256
	}

	hash := hmac.New(h.Hash.New, h.PrivateKey)

	if _, err := hash.Write(digest); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func (h *HMACSHA) String() jwtcrypto.SigningMethod {
	switch h.Hash {
	case crypto.SHA384:
		return jwtcrypto.HS384

	case crypto.SHA512:
		return jwtcrypto.HS512

	default:
		return jwtcrypto.HS256
	}
}

// Verify verifies a signature using a secret key.
func (h *HMACSHA) Verify(digest, sig []byte) (bool, error) {
	sig2, err := h.Sign(digest)

	if err != nil {
		return false, err
	}

	return hmac.Equal(sig, sig2), nil
}
