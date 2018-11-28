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

type hmacsha struct {
	key  []byte
	hash func() hash.Hash
	alg  string
}

// NewHS256 creates a signing method using HMAC and SHA-256.
func NewHS256(key string) Signer {
	return &hmacsha{key: []byte(key), hash: sha256.New, alg: MethodHS256}
}

// NewHS384 creates a signing method using HMAC and SHA-384.
func NewHS384(key string) Signer {
	return &hmacsha{key: []byte(key), hash: sha512.New384, alg: MethodHS384}
}

// NewHS512 creates a signing method using HMAC and SHA-512.
func NewHS512(key string) Signer {
	return &hmacsha{key: []byte(key), hash: sha512.New, alg: MethodHS512}
}

func (h *hmacsha) Sign(payload []byte) ([]byte, error) {
	sig, err := h.sign(payload)
	if err != nil {
		return nil, err
	}
	return build(h, payload, sig), nil
}

func (h *hmacsha) Verify(payload, sig []byte) (err error) {
	if sig, err = decodeToBytes(sig); err != nil {
		return err
	}
	return h.verify(payload, sig)
}

func (h *hmacsha) String() string {
	return h.alg
}

func (h *hmacsha) sign(payload []byte) ([]byte, error) {
	if string(h.key) == "" {
		return nil, ErrNoHMACKey
	}
	hh := hmac.New(h.hash, h.key)
	if _, err := hh.Write(payload); err != nil {
		return nil, err
	}
	return hh.Sum(nil), nil
}

func (h *hmacsha) verify(payload, sig []byte) error {
	sig2, err := h.sign(payload)
	if err != nil {
		return err
	}
	if !hmac.Equal(sig, sig2) {
		return ErrHMACVerification
	}
	return nil
}
