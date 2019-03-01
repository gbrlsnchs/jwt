package jwt

import (
	"crypto"
	"crypto/hmac"
	"errors"
	"hash"
)

var (
	// ErrNoHMACKey is the error for trying to sign or verify a JWT with an empty key.
	ErrNoHMACKey = errors.New("jwt: HMAC key is empty")
	// ErrHMACVerification is the error for an invalid signature.
	ErrHMACVerification = errors.New("jwt: HMAC verification failed")
)

// HMAC is a signing method that uses an HMAC
// of SHA hashes to both sign and verify tokens.
type HMAC struct {
	key  []byte
	hash crypto.Hash
	pool *pool
}

// NewHMAC creates a new HMAC signing method with one of the available SHA functions.
// The HMAC pointer returned can be reused both to sign and verify, as it maintains
// a pool of hashing functions to reduce garbage collection cleanups.
func NewHMAC(sha Hash, key []byte) *HMAC {
	hh := sha.hash()
	return &HMAC{
		key:  key,
		hash: hh,
		pool: newPool(func() hash.Hash { return hmac.New(hh.New, key) }),
	}
}

// Sign signs a hp and returns the signature.
func (h *HMAC) Sign(hp []byte) ([]byte, error) {
	if string(h.key) == "" {
		return nil, ErrNoHMACKey
	}
	return h.pool.sign(hp)
}

// SizeUp returns the signature byte size.
func (h *HMAC) SizeUp() (int, error) {
	return h.hash.Size(), nil
}

// String returns the signing method name.
func (h *HMAC) String() string {
	switch h.hash {
	case crypto.SHA256:
		return MethodHS256
	case crypto.SHA384:
		return MethodHS384
	case crypto.SHA512:
		return MethodHS512
	default:
		return ""
	}
}

// Verify verifies a hp and a signature.
func (h *HMAC) Verify(hp, sig []byte) (err error) {
	if sig, err = decodeToBytes(sig); err != nil {
		return err
	}
	sig2, err := h.Sign(hp)
	if err != nil {
		return err
	}
	if !hmac.Equal(sig, sig2) {
		return ErrHMACVerification
	}
	return nil
}
