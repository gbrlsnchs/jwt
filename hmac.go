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
	// ErrHMACInvalid is the error for an invalid signature.
	ErrHMACInvalid = errors.New("jwt: HMAC validation failed")
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
	if string(h.key) == "" {
		return nil, ErrNoHMACKey
	}
	sig, err := h.sign(payload)
	if err != nil {
		return nil, err
	}
	return build(h, payload, sig), nil
}

func (h *hmacsha) Verify(payload, sig []byte) (err error) {
	if string(h.key) == "" {
		return ErrNoHMACKey
	}
	decSig := make([]byte, enc.DecodedLen(len(sig)))
	if _, err = enc.Decode(decSig, sig); err != nil {
		return err
	}
	if err = h.verify(payload, decSig); err != nil {
		return err
	}
	return nil
}

func (h *hmacsha) String() string {
	return h.alg
}

func (h *hmacsha) sign(msg []byte) ([]byte, error) {
	hh := hmac.New(h.hash, h.key)
	if _, err := hh.Write(msg); err != nil {
		return nil, err
	}
	return hh.Sum(nil), nil
}

func (h *hmacsha) verify(msg, sig []byte) error {
	sig2, err := h.sign(msg)
	if err != nil {
		return err
	}

	if !hmac.Equal(sig, sig2) {
		return ErrHMACInvalid
	}
	return nil
}
