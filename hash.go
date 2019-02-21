package jwt

import (
	"crypto"

	_ "crypto/sha256" // imports SHA-256 hash function
	_ "crypto/sha512" // imports SHA-384 and SHA-512 hash functions
)

type Hash crypto.Hash

const (
	SHA256 = Hash(crypto.SHA256)
	SHA384 = Hash(crypto.SHA384)
	SHA512 = Hash(crypto.SHA512)
)

func (h Hash) hash() crypto.Hash {
	if h != SHA256 && h != SHA384 && h != SHA512 {
		h = SHA256
	}
	return crypto.Hash(h)
}
