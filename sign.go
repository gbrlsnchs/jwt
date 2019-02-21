package jwt

import (
	"encoding/base64"
	"encoding/json"
)

func Sign(t Token, s Signer) ([]byte, error) {
	// Override some values or set them if empty.
	h := t.HeaderAddr()
	h.Algorithm = s.String()
	h.Type = "JWT"
	// Marshal the header part of the JWT.
	hbytes, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}

	// Marshal the claims part of the JWT.
	cbytes, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}

	// Put both fields together.
	encoding := base64.RawURLEncoding
	hsize := encoding.EncodedLen(len(hbytes))
	csize := encoding.EncodedLen(len(cbytes))
	// Output: Base64(header).Base64(claims).signature
	payload := make([]byte, hsize+1+csize)
	encoding.Encode(payload, hbytes)
	payload[hsize] = '.'
	encoding.Encode(payload[hsize+1:], cbytes)
	sig, err := s.Sign(payload)
	if err != nil {
		return nil, err
	}
	token := make([]byte, len(payload)+1+encoding.EncodedLen(s.Size()))
	n := copy(token, payload)
	token[n] = '.'
	encoding.Encode(token[n+1:], sig)
	return token, nil
}
