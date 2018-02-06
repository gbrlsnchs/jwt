package jwt

import (
	"encoding/json"

	"github.com/gbrlsnchs/jwt/jwtcrypto"
	"github.com/gbrlsnchs/jwt/jwtcrypto/hmacsha"
	"github.com/gbrlsnchs/jwt/jwtutil"
)

// Sign generates a new JWT token and returns it encoded.
//
// Standard claims are set according to the opts variable,
// while public (and also private) claims are set according
// to the pub variable.
func Sign(signer jwtcrypto.Signer, jot *JWT) (string, error) {
	if signer == nil {
		signer = hmacsha.New256("")
	}

	if jot == nil {
		jot = &JWT{}
	}

	if jot.Header == nil {
		jot.Header = &Header{}
	}

	jot.Header.Algorithm = signer.String()
	jot.Header.Type = "JWT"

	if jot.Claims == nil {
		jot.Claims = &Claims{}
	}

	header, err := json.Marshal(jot.Header)

	if err != nil {
		return "", err
	}

	claims, err := json.Marshal(jot.Claims)

	if err != nil {
		return "", err
	}

	header64 := jwtutil.Encode(header)
	claims64 := jwtutil.Encode(claims)
	meta := []byte(header64 + Separator + claims64)
	sig, err := signer.Sign(meta)

	if err != nil {
		return "", err
	}

	return string(meta) + Separator + jwtutil.Encode(sig), nil
}
