package jwt

import "encoding/json"

// Marshal marshals a struct or a pointer to it and returns a JWT payload.
func Marshal(v interface{}) ([]byte, error) {
	if m, ok := v.(Marshaler); ok {
		return m.MarshalJWT()
	}
	var hdr header
	if jot, ok := v.(joser); ok {
		hdr = *jot.header()
	}
	hdrBytes, err := json.Marshal(hdr)
	if err != nil {
		return nil, err
	}
	hdrSize := enc.EncodedLen(len(hdrBytes))

	var clsBytes []byte
	if jot, ok := v.(nest); ok {
		if nst := jot.nested(); string(nst) != "" {
			clsBytes = nst
			goto encode
		}
	}
	if clsBytes, err = json.Marshal(v); err != nil {
		return nil, err
	}

encode:
	clsSize := enc.EncodedLen(len(clsBytes))
	payload := make([]byte, hdrSize+1+clsSize)
	enc.Encode(payload, hdrBytes)
	payload[hdrSize] = '.'
	enc.Encode(payload[hdrSize+1:], clsBytes)
	return payload, nil
}
