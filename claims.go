package jwt

import "encoding/json"

// Claims is the standard JWT claims set.
type Claims struct {
	Standard *StdClaims `json:"-"`
	Public   Payload    `json:"-"`
}

// MarshalJSON arranges standard and public claims in a single map.
func (c *Claims) MarshalJSON() ([]byte, error) {
	claims := Payload{}

	if c.Standard != nil {
		claims.setAudience(c.Standard.Audience)
		claims.setExpirationTime(c.Standard.ExpirationTime)
		claims.setIssuedAt(c.Standard.IssuedAt)
		claims.setIssuer(c.Standard.Issuer)
		claims.setJWTID(c.Standard.JWTID)
		claims.setNotBefore(c.Standard.NotBefore)
		claims.setSubject(c.Standard.Subject)
	}

	for k, v := range c.Public {
		claims[k] = v
	}

	return json.Marshal(claims)
}

// UnmarshalJSON splits claims inside of a map
// into a standard claims struct and a public claims one.
func (c *Claims) UnmarshalJSON(b []byte) error {
	if c.Public == nil {
		c.Public = make(map[string]interface{})
	}

	err := json.Unmarshal(b, &c.Public)

	if err != nil {
		return err
	}

	c.Standard = &StdClaims{
		Audience:       c.Public.audience(),
		ExpirationTime: c.Public.expirationTime(),
		IssuedAt:       c.Public.issuedAt(),
		Issuer:         c.Public.issuer(),
		JWTID:          c.Public.jwtID(),
		NotBefore:      c.Public.notBefore(),
		Subject:        c.Public.subject(),
	}

	return nil
}
