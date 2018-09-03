package jwt

import "encoding/json"

// Marshal marshals a struct or a pointer to it and returns a JWT payload.
func Marshal(v interface{}) ([]byte, error) {
	jot, err := extractJWT(v, false)
	if err != nil {
		return nil, err
	}
	jot.Header.header = &header{"JWT"}
	hdr, err := json.Marshal(jot.Header)
	if err != nil {
		return nil, err
	}
	hdrSize := enc.EncodedLen(len(hdr))
	cls, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	clsSize := enc.EncodedLen(len(cls))

	payload := make([]byte, hdrSize+1+clsSize)
	enc.Encode(payload, hdr)
	payload[hdrSize] = '.'
	enc.Encode(payload[hdrSize+1:], cls)
	return payload, nil
}
