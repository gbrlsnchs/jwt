package jwt

type claimsKey string

const (
	Separator                   = "."
	issuerKey         claimsKey = "iss"
	subjectKey        claimsKey = "sub"
	audienceKey       claimsKey = "aud"
	expirationTimeKey claimsKey = "exp"
	notBeforeKey      claimsKey = "nbf"
	issuedAtKey       claimsKey = "iat"
	jwtIDKey          claimsKey = "jti"
)
