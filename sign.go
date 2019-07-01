package jwt

import (
	"encoding/base64"
	"encoding/json"
)

// Sign generates a JWT from hd and payload and signs it with alg.
func Sign(alg Algorithm, hd Header, payload interface{}) ([]byte, error) {
	// Override some values or set them if empty.
	hd.Algorithm = alg.Name()
	hd.Type = "JWT"
	// Marshal the header part of the JWT.
	hb, err := json.Marshal(hd)
	if err != nil {
		return nil, err
	}
	// Marshal the claims part of the JWT.
	pb, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	enc := base64.RawURLEncoding
	h64len := enc.EncodedLen(len(hb))
	p64len := enc.EncodedLen(len(pb))
	sig64len := enc.EncodedLen(alg.Size())
	token := make([]byte, h64len+1+p64len+1+sig64len)

	enc.Encode(token, hb)
	token[h64len] = '.'
	enc.Encode(token[h64len+1:], pb)
	sig, err := alg.Sign(token[:h64len+1+p64len])
	if err != nil {
		return nil, err
	}
	token[h64len+1+p64len] = '.'
	enc.Encode(token[h64len+1+p64len+1:], sig)
	return token, nil
}
