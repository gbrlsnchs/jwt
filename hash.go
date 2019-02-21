package jwt

import (
	"crypto"

	_ "crypto/sha256" // imports SHA-256 hash function
	_ "crypto/sha512" // imports SHA-384 and SHA-512 hash functions
)

// Hash is a hashing function
// available in the JWT spec.
type Hash crypto.Hash

const (
	// SHA256 is the SHA-256 hashing function.
	SHA256 = Hash(crypto.SHA256)
	// SHA384 is the SHA-384 hashing function.
	SHA384 = Hash(crypto.SHA384)
	// SHA512 is the SHA-512 hashing function.
	SHA512 = Hash(crypto.SHA512)
)

func (h Hash) hash() crypto.Hash {
	if h != SHA256 && h != SHA384 && h != SHA512 {
		h = SHA256
	}
	return crypto.Hash(h)
}
