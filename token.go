package jwt

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

var ErrMalformedToken = errors.New("jwt.Parse: token is malformed")

// Token is a string JSON Web Token
// split as header+payload and signature.
type Token []string

// NewToken creates a Token based on a string JSON Web Token.
func NewToken(s string) (Token, error) {
	sep1 := strings.IndexByte(s, '.')

	if sep1 < 0 {
		return nil, ErrMalformedToken
	}

	sep2 := strings.IndexByte(s[sep1+1:], '.')

	if sep2 < 0 {
		return nil, ErrMalformedToken
	}

	sep2 += sep1 + 1
	token := make([]string, 2, 2)
	token[0] = s[:sep2]
	token[1] = s[sep2+1:]

	return token, nil
}

// FromRequest extracts a string JSON Web Token from the "Authorization" header.
func FromRequest(r *http.Request) (Token, error) {
	auth := r.Header.Get("Authorization")
	i := strings.IndexByte(auth, ' ')

	if i < 0 {
		return nil, ErrEmptyHeader
	}

	return NewToken(auth[i+1:])
}

// Build turns the Token into a JWT and returns it.
func (t Token) Build() (*JWT, error) {
	sep := strings.IndexByte(t[0], '.')

	if sep < 0 {
		return nil, ErrMalformedToken
	}

	dec, err := decode(t[0][:sep])

	if err != nil {
		return nil, err
	}

	jot := &JWT{}

	if err = json.Unmarshal(dec, &jot.header); err != nil {
		return nil, err
	}

	dec, err = decode(t[0][sep+1:])

	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(dec, &jot.claims); err != nil {
		return nil, err
	}

	return jot, nil
}

// Bytes returns the Token as byte array.
func (t Token) Bytes() []byte {
	return []byte(t.String())
}

func (t Token) String() string {
	return strings.Join(t, ".")
}

// Verify verifies the Token's signature.
func (t Token) Verify(s Signer) error {
	sig, err := decode(t[1])

	if err != nil {
		return err
	}

	return s.Verify([]byte(t[0]), sig)
}
