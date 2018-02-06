package jwtcrypto

// Verifier verifies a message.
type Verifier interface {
	// HasKey tells whether the Verifier has a key.
	// This is necessary for cases when a JWT has a "none"
	// algorithm set.
	HasKey() bool
	// String returns the signing method's name
	// according to JWT's RFC (i.e. HS256 for HMAC + SHA-256).
	String() SigningMethod
	// Verify verifies a signature, comparing it with an expected value.
	Verify(digest, sig []byte) (bool, error)
}
