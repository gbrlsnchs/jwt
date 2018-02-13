package jwt

import (
	"encoding/json"
	"time"
)

type claims struct {
	aud string
	exp time.Time
	iat time.Time
	iss string
	nbf time.Time
	sub string
	pub map[string]interface{}
}

func (c *claims) MarshalJSON() ([]byte, error) {
	if c.pub == nil {
		c.pub = make(map[string]interface{})
	}

	if len(c.aud) > 0 {
		c.pub["aud"] = c.aud
	}

	if !c.exp.IsZero() {
		c.pub["exp"] = c.exp.Unix()
	}

	if !c.iat.IsZero() {
		c.pub["iat"] = c.iat.Unix()
	}

	if len(c.iss) > 0 {
		c.pub["iss"] = c.iss
	}

	if !c.nbf.IsZero() {
		c.pub["nbf"] = c.nbf.Unix()
	}

	if len(c.sub) > 0 {
		c.pub["sub"] = c.sub
	}

	return json.Marshal(c.pub)
}

func (c *claims) UnmarshalJSON(b []byte) error {
	err := json.Unmarshal(b, &c.pub)

	if err != nil {
		return err
	}

	if v, ok := c.pub["aud"].(string); ok {
		c.aud = v
	}

	delete(c.pub, "aud")

	if v, ok := c.pub["exp"].(float64); ok {
		c.exp = time.Unix(int64(v), 0)
	}

	delete(c.pub, "exp")

	if v, ok := c.pub["iat"].(float64); ok {
		c.iat = time.Unix(int64(v), 0)
	}

	delete(c.pub, "iat")

	if v, ok := c.pub["iss"].(string); ok {
		c.iss = v
	}

	delete(c.pub, "iss")

	if v, ok := c.pub["nbf"].(float64); ok {
		c.nbf = time.Unix(int64(v), 0)
	}

	delete(c.pub, "nbf")

	if v, ok := c.pub["sub"].(string); ok {
		c.sub = v
	}

	delete(c.pub, "sub")

	return nil
}
