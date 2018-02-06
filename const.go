package jwt

type claimsKey string

const (
	// Separator is the character between
	// a JWT's encoded parts.
	Separator                   = "."
	issuerKey         claimsKey = "iss"
	subjectKey        claimsKey = "sub"
	audienceKey       claimsKey = "aud"
	expirationTimeKey claimsKey = "exp"
	notBeforeKey      claimsKey = "nbf"
	issuedAtKey       claimsKey = "iat"
	jwtIDKey          claimsKey = "jti"
)
