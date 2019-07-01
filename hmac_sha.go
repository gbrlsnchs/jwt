package jwt

import (
	"crypto"
	"crypto/hmac"
	"errors"
	"hash"

	"github.com/gbrlsnchs/jwt/v3/internal"
)

var (
	// ErrNoHMACKey is the error for trying to sign or verify a JWT with an empty key.
	ErrNoHMACKey = errors.New("jwt: HMAC key is empty")
	// ErrHMACVerification is the error for an invalid signature.
	ErrHMACVerification = errors.New("jwt: HMAC verification failed")

	_ Signer   = new(HMAC)
	_ Verifier = new(HMAC)
)

// HMAC is a signing method that uses an HMAC
// of SHA hashes to both sign and verify tokens.
type HMAC struct {
	key  []byte
	hash crypto.Hash
	pool *hashPool
}

// NewHMAC creates a new HMAC signing method with one of the available SHA functions.
// The HMAC pointer returned can be reused both to sign and verify, as it maintains
// a pool of hashing functions to reduce garbage collection cleanups.
func NewHMAC(sha Hash, key []byte) *HMAC {
	hh := sha.hash()
	return &HMAC{
		key:  key,
		hash: hh,
		pool: newHashPool(func() hash.Hash { return hmac.New(hh.New, key) }),
	}
}

// Sign signs a header and a payload, both encoded to Base64
// and separated by a dot, then returns the signature.
func (h *HMAC) Sign(headerPayload []byte) ([]byte, error) {
	if string(h.key) == "" {
		return nil, ErrNoHMACKey
	}
	return h.pool.sign(headerPayload)
}

// Size returns the signature byte size.
func (h *HMAC) Size() int {
	return h.hash.Size()
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

// Verify verifies a header/payload and a signature.
func (h *HMAC) Verify(headerPayload, sig []byte) (err error) {
	if sig, err = internal.DecodeToBytes(sig); err != nil {
		return err
	}
	sig2, err := h.Sign(headerPayload)
	if err != nil {
		return err
	}
	if !hmac.Equal(sig, sig2) {
		return ErrHMACVerification
	}
	return nil
}
