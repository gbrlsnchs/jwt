package jwt_test

import (
	"github.com/gbrlsnchs/jwt/v3"
	"github.com/gbrlsnchs/jwt/v3/internal"
)

var (
	ed25519PrivateKey1, ed25519PublicKey1 = internal.GenerateEd25519Keys()
	ed25519PrivateKey2, ed25519PublicKey2 = internal.GenerateEd25519Keys()

	ed25519TestCases = []testCase{
		{
			alg:       jwt.NewEd25519(jwt.Ed25519PrivateKey(ed25519PrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewEd25519(jwt.Ed25519PrivateKey(ed25519PrivateKey1)),
			wantHeader: jwt.Header{
				Algorithm: "Ed25519",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewEd25519(jwt.Ed25519PrivateKey(ed25519PrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewEd25519(jwt.Ed25519PublicKey(ed25519PublicKey1)),
			wantHeader: jwt.Header{
				Algorithm: "Ed25519",
				Type:      "JWT",
			},
			wantPayload: tp,
			signErr:     nil,
			verifyErr:   nil,
		},
		{
			alg:       jwt.NewEd25519(jwt.Ed25519PrivateKey(ed25519PrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewEd25519(jwt.Ed25519PrivateKey(ed25519PrivateKey2)),
			wantHeader: jwt.Header{
				Algorithm: "Ed25519",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrEd25519Verification,
		},
		{
			alg:       jwt.NewEd25519(jwt.Ed25519PrivateKey(ed25519PrivateKey1)),
			payload:   tp,
			verifyAlg: jwt.NewEd25519(jwt.Ed25519PublicKey(ed25519PublicKey2)),
			wantHeader: jwt.Header{
				Algorithm: "Ed25519",
				Type:      "JWT",
			},
			wantPayload: testPayload{},
			signErr:     nil,
			verifyErr:   jwt.ErrEd25519Verification,
		},
	}
)
