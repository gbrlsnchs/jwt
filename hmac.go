package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

var (
	ErrNoHMACKey   = errors.New("jwt.(Signer).Sign: HMAC key is empty")
	ErrHMACInvalid = errors.New("jwt.(Signer).Verify: HMAC validation failed")
)

type hmacsha struct {
	key  []byte
	hash func() hash.Hash
	alg  string
}

// HS256 creates a signing method using HMAC and SHA-256.
func HS256(key string) Signer {
	return &hmacsha{key: []byte(key), hash: sha256.New, alg: MethodHS256}
}

// HS384 creates a signing method using HMAC and SHA-384.
func HS384(key string) Signer {
	return &hmacsha{key: []byte(key), hash: sha512.New384, alg: MethodHS384}
}

// HS512 creates a signing method using HMAC and SHA-512.
func HS512(key string) Signer {
	return &hmacsha{key: []byte(key), hash: sha512.New, alg: MethodHS512}
}

func (h *hmacsha) Sign(jot Marshaler) ([]byte, error) {
	if string(h.key) == "" {
		return nil, ErrNoHMACKey
	}
	payload, err := jot.MarshalJWT()
	if err != nil {
		return nil, err
	}
	sig, err := h.sign(payload)
	if err != nil {
		return nil, err
	}
	return build(payload, sig, h), nil
}

func (h *hmacsha) Verify(token []byte, jot Marshaler) error {
	if string(h.key) == "" {
		return ErrNoHMACKey
	}
	payload, sig, err := parseBytes(token)
	if err != nil {
		return err
	}
	decSig := make([]byte, enc.DecodedLen(len(sig)))
	if _, err = enc.Decode(decSig, sig); err != nil {
		return err
	}
	if err = jot.UnmarshalJWT(payload); err != nil {
		return err
	}
	return h.verify(payload, decSig)
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
