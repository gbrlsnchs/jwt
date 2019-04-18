package jwt_test

import (
	"testing"

	. "github.com/gbrlsnchs/jwt/v3"
	"github.com/stretchr/testify/suite"
)

func TestNone(t *testing.T) {
	testCases := []payloadTestSuite{
		{
			s:  new(None),
			vr: new(None),
		},
		{
			s:         new(None),
			vr:        NewHMAC(SHA256, []byte("secret")),
			decodeErr: ErrAlgValidation,
		},
		{
			s:         NewHMAC(SHA256, []byte("secret")),
			vr:        new(None),
			decodeErr: ErrAlgValidation,
		},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) { suite.Run(t, &tc) })
	}
}
