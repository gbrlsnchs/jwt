package jwt

import (
	"encoding/json"
	"errors"
	"strings"
)

var (
	// ErrInvalidSignature is returned when a token's
	// signature is invalidated by a signer.
	ErrInvalidSignature = errors.New("jwt.Parse: token has invalid signature")
	// ErrMalformedToken is returned when a token
	// doesn't contain a valid format of "header.payload.signature".
	ErrMalformedToken = errors.New("jwt.Parse: token is malformed")
)

// Parse parses a string token using a specific signer and returns
// a JSON Web Token if all conditions are met for parsing it.
func Parse(s Signer, token string) (*JWT, error) {
	jot := &JWT{}
	sep1 := strings.IndexByte(token, '.')

	if sep1 == -1 {
		return nil, ErrMalformedToken
	}

	sep2 := strings.IndexByte(token[sep1+1:], '.')

	if sep2 == -1 {
		return nil, ErrMalformedToken
	}

	sep2 += len(token[:sep1+1])
	dec, err := decode(token[sep2+1:])

	if err != nil {
		return nil, err
	}

	if err = s.Verify([]byte(token[:sep2]), dec); err != nil {
		return nil, err
	}

	dec, err = decode(token[:sep1])

	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(dec, &jot.header); err != nil {
		return nil, err
	}

	dec, err = decode(token[sep1+1 : sep2])

	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(dec, &jot.claims); err != nil {
		return nil, err
	}

	return jot, nil
}
