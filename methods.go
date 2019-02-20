package jwt

const (
	// MethodHS256 is the method name for HMAC and SHA-256.
	MethodHS256 = "HS256"
	// MethodHS384 is the method name for HMAC and SHA-384.
	MethodHS384 = "HS384"
	// MethodHS512 is the method name for HMAC and SHA-512.
	MethodHS512 = "HS512"
	// MethodRS256 is the method name for RSA and SHA-256.
	MethodRS256 = "RS256"
	// MethodRS384 is the method name for RSA and SHA-384.
	MethodRS384 = "RS384"
	// MethodRS512 is the method name for RSA and SHA-512.
	MethodRS512 = "RS512"
	// MethodES256 is the method name for ECDSA and SHA-256.
	MethodES256 = "ES256"
	// MethodES384 is the method name for ECDSA and SHA-384.
	MethodES384 = "ES384"
	// MethodES512 is the method name for ECDSA and SHA-512.
	MethodES512 = "ES512"
	// MethodPS256 is the method name for RSA-PSS and SHA-256.
	MethodPS256 = "PS256"
	// MethodPS384 is the method name for RSA-PSS and SHA-384.
	MethodPS384 = "PS384"
	// MethodPS512 is the method name for RSA-PSS and SHA-512.
	MethodPS512 = "PS512"
	// MethodEd25519 is the method name for EdDSA using Ed25519 and SHA-512.
	MethodEd25519 = "Ed25519"
	// MethodNone is the method name for an unsecured JWT.
	MethodNone = "none"
)
