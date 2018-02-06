package jwtcrypto

// Signer signs messages.
type Signer interface {
	// Sign returns a signed message.
	Sign(digest []byte) ([]byte, error)
	// String returns the signing method's name
	// according to JWT's RFC (i.e. HS256 for HMAC + SHA-256).
	String() SigningMethod
}
