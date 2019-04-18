package jwt_test

import (
	"testing"

	. "github.com/gbrlsnchs/jwt/v3"
	"github.com/stretchr/testify/suite"
)

func TestHMAC(t *testing.T) {
	testCases := []payloadTestSuite{
		// HS256
		{
			s:       NewHMAC(SHA256, []byte("")),
			vr:      NewHMAC(SHA256, []byte("")),
			signErr: ErrNoHMACKey,
		},
		{
			s:  NewHMAC(SHA256, []byte("secret")),
			vr: NewHMAC(SHA256, []byte("secret")),
		},
		{
			s:         NewHMAC(SHA256, []byte("secret")),
			vr:        NewHMAC(SHA256, []byte("not_secret")),
			decodeErr: ErrHMACVerification,
		},
		{
			s:         NewHMAC(SHA256, []byte("not_secret")),
			vr:        NewHMAC(SHA256, []byte("secret")),
			decodeErr: ErrHMACVerification,
		},
		{
			s:         NewHMAC(SHA384, []byte("secret")),
			vr:        NewHMAC(SHA256, []byte("secret")),
			decodeErr: ErrAlgValidation,
		},
		/*
			TODO(gbrlsnchs):
			s: HS256, vr: None/RS256/ES256/Ed25519
		*/
		// HS384
		{
			s:       NewHMAC(SHA384, []byte("")),
			vr:      NewHMAC(SHA384, []byte("")),
			signErr: ErrNoHMACKey,
		},
		{
			s:  NewHMAC(SHA384, []byte("secret")),
			vr: NewHMAC(SHA384, []byte("secret")),
		},
		{
			s:         NewHMAC(SHA384, []byte("secret")),
			vr:        NewHMAC(SHA384, []byte("not_secret")),
			decodeErr: ErrHMACVerification,
		},
		{
			s:         NewHMAC(SHA384, []byte("not_secret")),
			vr:        NewHMAC(SHA384, []byte("secret")),
			decodeErr: ErrHMACVerification,
		},
		{
			s:         NewHMAC(SHA512, []byte("secret")),
			vr:        NewHMAC(SHA384, []byte("secret")),
			decodeErr: ErrAlgValidation,
		},
		/*
			TODO(gbrlsnchs):
			s: HS384, vr: None/RS384/ES384/Ed25519
		*/
		// HS512
		{
			s:       NewHMAC(SHA512, []byte("")),
			vr:      NewHMAC(SHA512, []byte("")),
			signErr: ErrNoHMACKey,
		},
		{
			s:  NewHMAC(SHA512, []byte("secret")),
			vr: NewHMAC(SHA512, []byte("secret")),
		},
		{
			s:         NewHMAC(SHA512, []byte("secret")),
			vr:        NewHMAC(SHA512, []byte("not_secret")),
			decodeErr: ErrHMACVerification,
		},
		{
			s:         NewHMAC(SHA512, []byte("not_secret")),
			vr:        NewHMAC(SHA512, []byte("secret")),
			decodeErr: ErrHMACVerification,
		},
		{
			s:         NewHMAC(SHA256, []byte("secret")),
			vr:        NewHMAC(SHA512, []byte("secret")),
			decodeErr: ErrAlgValidation,
		},
		/*
			TODO(gbrlsnchs):
			s: HS512, vr: None/RS512/ES512/Ed25519
		*/
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) { suite.Run(t, &tc) })
	}
}
