package jwt

import "github.com/gbrlsnchs/jwt/v3/internal"

var (
	// ErrEd25519PrivKey is the error for trying to sign a JWT with a nil private key.
	ErrEd25519PrivKey = internal.ErrEd25519PrivKey
	// ErrEd25519PubKey is the error for trying to verify a JWT with a nil public key.
	ErrEd25519PubKey = internal.ErrEd25519PubKey
	// ErrEd25519Verification is the error for when verification with Ed25519 fails.
	ErrEd25519Verification = internal.ErrEd25519Verification

	_ Signer   = new(Ed25519)
	_ Verifier = new(Ed25519)

	// NewEd25519 creates a new Ed25519 signing
	// method with the SHA-512 hashing function.
	NewEd25519 = internal.NewEd25519
)

// Ed25519 is a signing method that uses EdDSA
// with a SHA-512 hashing function to sign tokens.
type Ed25519 struct {
	// There is a compatibility layer in order to make this
	// work between go1.9.7, go1.10.3, go1.11, go1.12 and go1.13+,
	// where package "ed25519" will be included in package "crypto".
	*internal.Ed25519
}

// String returns the signing method name.
func (e *Ed25519) String() string {
	return MethodEd25519
}
