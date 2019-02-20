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

type HMAC struct {
	key  []byte
	hash crypto.Hash
	pool *pool
}

func NewHMAC(sha Hash, key []byte) *HMAC {
	hh := sha.hash()
	return &HMAC{
		key:  key,
		hash: hh,
		pool: newPool(func() hash.Hash { return hmac.New(hh.New, key) }),
	}
}

func (h *HMAC) Sign(payload []byte) ([]byte, error) {
	if string(h.key) == "" {
		return nil, ErrNoHMACKey
	}
	return h.pool.sign(payload)
}

func (h *HMAC) Size() int {
	return h.hash.Size()
}

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

func (h *HMAC) Verify(payload, sig []byte) (err error) {
	if sig, err = decodeToBytes(sig); err != nil {
		return err
	}
	sig2, err := h.Sign(payload)
	if err != nil {
		return err
	}
	if !hmac.Equal(sig, sig2) {
		return ErrHMACVerification
	}
	return nil
}
