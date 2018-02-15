package jwt

import (
	"encoding/json"
	"errors"
	"strings"
)

// ValidationFunc is a function for running extra
// validators when parsing a JWT string.
type ValidationFunc func(jot *JWT) error

var (
	ErrInvalidSignature = errors.New("jwt.Parse: token has invalid signature")
	ErrMalformedToken   = errors.New("jwt.Parse: token is malformed")
)

// Parse parses a string token using a specific signer and returns
// a JSON Web Token if all conditions are met for parsing it.
func Parse(s Signer, token string, vfuncs ...ValidationFunc) (*JWT, error) {
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

	if err = runValidationFuncs(jot, vfuncs); err != nil {
		return nil, err
	}

	return jot, nil
}

func runValidationFuncs(jot *JWT, vfuncs []ValidationFunc) error {
	for _, vfunc := range vfuncs {
		if err := vfunc(jot); err != nil {
			return err
		}
	}

	return nil
}
