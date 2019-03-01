package jwt

import (
	"encoding/base64"
	"encoding/json"
)

// Sign signs a JWT (header and payload) with a signing method that implements the Signer interface.
func Sign(h Header, payload interface{}, s Signer) ([]byte, error) {
	// Override some values or set them if empty.
	h.Algorithm = s.String()
	h.Type = "JWT"
	// Marshal the header part of the JWT.
	hb, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	// Marshal the claims part of the JWT.
	pb, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	sigSize, err := s.SizeUp()
	if err != nil {
		return nil, err
	}
	enc := base64.RawURLEncoding
	h64len := enc.EncodedLen(len(hb))
	p64len := enc.EncodedLen(len(pb))
	sig64len := enc.EncodedLen(sigSize)
	token := make([]byte, h64len+1+p64len+1+sig64len)

	enc.Encode(token, hb)
	token[h64len] = '.'
	enc.Encode(token[h64len+1:], pb)
	sig, err := s.Sign(token[:h64len+1+p64len])
	if err != nil {
		return nil, err
	}
	token[h64len+1+p64len] = '.'
	enc.Encode(token[h64len+1+p64len+1:], sig)
	return token, nil
}
