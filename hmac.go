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
	alg  string
	pool *pool
}

func NewHMAC(sha SHA, key []byte) *HMAC {
	var (
		hh  func() hash.Hash
		alg string
	)
	switch sha {
	case SHA256:
		fallthrough
	default:
		hh = sha256.New
		alg = MethodHS256
	case SHA384:
		hh = sha512.New384
		alg = MethodHS384
	case SHA512:
		hh = sha512.New
		alg = MethodHS512
	}
	return &HMAC{
		alg: alg,
		pool: newPool(func() (hash.Hash, error) {
			if string(key) == "" {
				return nil, ErrNoHMACKey
			}
			return hmac.New(hh, key), nil
		}),
	}
}

func (h *HMAC) Sign(payload []byte) ([]byte, error) {
	return h.sign(payload)
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

func (h *HMAC) String() string {
	return h.alg
}

func (h *HMAC) sign(payload []byte) ([]byte, error) {
	return h.pool.sign(payload)
}
