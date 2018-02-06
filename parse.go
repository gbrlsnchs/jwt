package jwt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gbrlsnchs/jwt/jwtcrypto"
	"github.com/gbrlsnchs/jwt/jwtcrypto/hmacsha"
	"github.com/gbrlsnchs/jwt/jwtcrypto/none"
	"github.com/gbrlsnchs/jwt/jwtutil"
)

// Parse parses a JWT encoded token and decodes it into a JWT pointer.
//
// It only validates the signature.
func Parse(digest string, verif jwtcrypto.Verifier) (*JWT, error) {
	now := time.Now()

	if verif == nil {
		verif = hmacsha.New256("")
	}

	parts := strings.Split(digest, Separator)

	if len(parts) < 2 || len(parts) > 3 {
		return nil, errors.New("github.com/gbrlsnchs/jwt.Parse: JWT is malformed, as per RFC 7519, section 7.2, item 1")
	}

	jot := &JWT{}
	dec, err := jwtutil.Decode(parts[0])

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(dec, &jot.Header)

	if err != nil {
		return nil, err
	}

	dec, err = jwtutil.Decode(parts[1])

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(dec, &jot.Claims)

	if err != nil {
		return nil, err
	}

	// Prevent "none" vulnerability.
	if alg := jot.Header.Algorithm; alg == jwtcrypto.None {
		if verif.HasKey() {
			return nil, errors.New("github.com/gbrlsnchs/jwt.Parse: JWT uses \"none\" algorithm but a key exists")
		}

		verif = &none.None{}
	} else if alg != verif.String() {
		return nil, fmt.Errorf(
			"github.com/gbrlsnchs/jwt.Parse: JWT signing match mismatch (want %s, got %s)",
			verif.String(),
			alg,
		)
	}

	if err = jot.validate(now); err != nil {
		return nil, fmt.Errorf("github.com/gbrlsnchs/jwt.Parse: %v", err)
	}

	var sig bytes.Buffer

	if len(parts) == 3 {
		_, err = sig.WriteString(parts[2])

		if err != nil {
			return nil, err
		}
	}

	dec, err = jwtutil.Decode(sig.String())

	if err != nil {
		return nil, err
	}

	sig.Reset()

	_, err = sig.Write(dec)

	if err != nil {
		return nil, err
	}

	meta := []byte(parts[0] + Separator + parts[1])
	valid, err := verif.Verify(meta, sig.Bytes())

	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, errors.New("github.com/gbrlsnchs/jwt.Parse: invalid token signature")
	}

	return jot, nil
}
