package jwt

import (
	"encoding/base64"
	"encoding/json"
)

func decode(enc []byte, v interface{}) error {
	dec, err := decodeToBytes(enc)
	if err != nil {
		return err
	}
	return json.Unmarshal(dec, v)
}

func decodeToBytes(enc []byte) ([]byte, error) {
	encoding := base64.RawURLEncoding
	dec := make([]byte, encoding.DecodedLen(len(enc)))
	if _, err := encoding.Decode(dec, enc); err != nil {
		return nil, err
	}
	return dec, nil
}
