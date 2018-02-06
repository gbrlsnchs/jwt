package jwt

// Payload is standard, public and private claims
// which a JWT contains in its Payload.
type Payload map[string]interface{}

// audience returns the "aud" value.
func (p Payload) audience() string {
	return p.str(audienceKey)
}

// expirationTime returns the "exp" value.
func (p Payload) expirationTime() int64 {
	return p.i64(expirationTimeKey)
}

func (p Payload) i64(k claimsKey) int64 {
	key := string(k)

	if n, ok := p[key].(float64); ok {
		delete(p, key)

		return int64(n)
	}

	return 0
}

func (p Payload) issuedAt() int64 {
	return p.i64(issuedAtKey)
}

func (p Payload) issuer() string {
	return p.str(issuerKey)
}

func (p Payload) jwtID() string {
	return p.str(jwtIDKey)
}

func (p Payload) notBefore() int64 {
	return p.i64(notBeforeKey)
}

func (p Payload) subject() string {
	return p.str(subjectKey)
}

func (p Payload) setAudience(aud string) {
	p.setStr(audienceKey, aud)
}

func (p Payload) setExpirationTime(exp int64) {
	p.setNum(expirationTimeKey, exp)
}

func (p Payload) setIssuedAt(iat int64) {
	p.setNum(issuedAtKey, iat)
}

func (p Payload) setIssuer(iss string) {
	p.setStr(issuerKey, iss)
}

func (p Payload) setJWTID(jti string) {
	p.setStr(jwtIDKey, jti)
}

func (p Payload) setNotBefore(nbf int64) {
	p.setNum(notBeforeKey, nbf)
}

func (p Payload) setNum(k claimsKey, v int64) {
	if v > 0 {
		p[string(k)] = v
	}
}

func (p Payload) setStr(k claimsKey, v string) {
	if v != "" {
		p[string(k)] = v
	}
}

func (p Payload) setSubject(sub string) {
	p.setStr(subjectKey, sub)
}

func (p Payload) str(k claimsKey) string {
	key := string(k)

	if v, ok := p[key].(string); ok {
		delete(p, key)

		return v
	}

	return ""
}
