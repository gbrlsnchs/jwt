package jwt_test

import (
	"fmt"
	"testing"

	"github.com/gbrlsnchs/jwt/v3"
	"github.com/gbrlsnchs/jwt/v3/internal"
)

func TestHeaderValidate(t *testing.T) {
	testCases := []struct {
		h   jwt.Header
		vr  jwt.Verifier
		err error
	}{
		{jwt.Header{Algorithm: "HS256"}, jwt.NewHMAC(jwt.SHA256, []byte("test")), nil},
		{jwt.Header{Algorithm: "HS384"}, jwt.NewHMAC(jwt.SHA256, []byte("test")), jwt.ErrAlgValidation},
		{jwt.Header{Algorithm: "HS384"}, jwt.NewHMAC(jwt.SHA256, []byte("test")), jwt.ErrAlgValidation},
	}
	for _, tc := range testCases {
		var alg string
		if tc.vr != nil {
			alg = tc.vr.String()
		}
		t.Run(fmt.Sprintf("%s %s", tc.h.Algorithm, alg), func(t *testing.T) {
			if want, got := tc.err, tc.h.Validate(tc.vr); !internal.ErrorIs(got, want) {
				t.Errorf("want %v, got %v", want, got)
			}
		})
	}
}
