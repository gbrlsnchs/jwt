package jwtcrypto

// SigningMethod is the signing method
// used to sign a JWT and generate a signature.
type SigningMethod string

const (
	// None is equivalent to "none" signing method.
	// It bypasses validation if a Verifier has no key.
	None SigningMethod = "none"
	// HS256 is equivalent to "HS256" signing method.
	// Is uses HMAC + SHA-256 to generate a signature.
	HS256 SigningMethod = "HS256"
	// HS384 is equivalent to "HS384" signing method.
	// Is uses HMAC + SHA-384 to generate a signature.
	HS384 SigningMethod = "HS384"
	// HS512 is equivalent to "HS512" signing method.
	// Is uses HMAC + SHA-512 to generate a signature.
	HS512 SigningMethod = "HS512"
	// RS256 is equivalent to "RS256" signing method.
	// Is uses RSA + SHA-256 to generate a signature.
	RS256 SigningMethod = "RS256"
	// RS384 is equivalent to "RS384" signing method.
	// Is uses RSA + SHA-384 to generate a signature.
	RS384 SigningMethod = "RS384"
	// RS512 is equivalent to "RS512" signing method.
	// Is uses RSA + SHA-512 to generate a signature.
	RS512 SigningMethod = "RS512"
	// ES256 is equivalent to "ES256" signing method.
	// It uses ECDSA + P-256 elliptic curve + SHA-256
	// to generate a signature.
	ES256 SigningMethod = "ES256"
	// ES384 is equivalent to "ES384" signing method.
	// It uses ECDSA + P-384 elliptic curve + SHA-384
	// to generate a signature.
	ES384 SigningMethod = "ES384"
	// ES512 is equivalent to "ES512" signing method.
	// It uses ECDSA + P-521 elliptic curve + SHA-512
	// to generate a signature.
	ES512 SigningMethod = "ES512"
)
