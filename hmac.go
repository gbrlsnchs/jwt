package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
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
	key []byte
	sha SHA

	pool *pool
}

func NewHMAC(sha SHA, key []byte) *HMAC {
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
	return &HMAC{
		key:  key,
		sha:  sha,
		pool: newPool(func() hash.Hash { return hmac.New(hh, key) }),
	}
}

func (h *HMAC) Sign(payload []byte) ([]byte, error) {
	return h.sign(payload)
}

func (h *HMAC) Size() int {
	return int(h.sha)
}

func (h *HMAC) String() string {
	switch h.sha {
	case SHA256:
		return MethodHS256
	case SHA384:
		return MethodHS384
	case SHA512:
		return MethodHS512
	default:
		return ""
	}
}

func (h *HMAC) Verify(payload, sig []byte) (err error) {
	if sig, err = decodeToBytes(sig); err != nil {
		return err
	}
	sig2, err := h.sign(payload)
	if err != nil {
		return err
	}
	if !hmac.Equal(sig, sig2) {
		return ErrHMACVerification
	}
	return nil
}

func (h *HMAC) sign(payload []byte) ([]byte, error) {
	if string(h.key) == "" {
		return nil, ErrNoHMACKey
	}
	return h.pool.sign(payload)
}
