package jwt_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/gbrlsnchs/jwt/v3"
	"github.com/gbrlsnchs/jwt/v3/internal"
)

// Token extracted from https://jwt.io.
const validToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
	"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

func TestDecode(t *testing.T) {
	testCases := []struct {
		token            []byte
		p                *jwt.Payload
		jsonSyntaxErr    bool
		jsonUnmarshalErr bool
		base64InputErr   bool
		err              error
	}{
		{
			token: []byte(validToken),
			p:     new(jwt.Payload),
		},
		{
			token: []byte(validToken[:112]),
			p:     new(jwt.Payload),
			err:   jwt.ErrHMACVerification,
		},
		{
			token: []byte(validToken[:111]),
			p:     new(jwt.Payload),
			err:   jwt.ErrMalformed,
		},
		{
			token:         []byte(".."),
			p:             new(jwt.Payload),
			jsonSyntaxErr: true,
		},
		{
			token:          []byte("{}.{}."),
			p:              new(jwt.Payload),
			base64InputErr: true,
		},
		{
			token:            []byte(validToken),
			p:                nil,
			jsonUnmarshalErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			var (
				err = jwt.NewDecoder(tc.token,
					jwt.NewHMAC(jwt.SHA256, []byte("your-256-bit-secret"))).Decode(tc.p)
				syntaxErr    *json.SyntaxError
				unmarshalErr *json.InvalidUnmarshalError
				inputErr     base64.CorruptInputError
			)
			if want, got := tc.jsonSyntaxErr, internal.ErrorAs(err, &syntaxErr); want != got {
				t.Fatalf("want %t, got %t: (%T) %v", want, got, err, err)
			}
			if want, got := tc.jsonUnmarshalErr, internal.ErrorAs(err, &unmarshalErr); want != got {
				t.Fatalf("want %t, got %t: (%T) %v", want, got, err, err)
			}
			if want, got := tc.base64InputErr, internal.ErrorAs(err, &inputErr); want != got {
				t.Fatalf("want %t, got %t: (%T) %v", want, got, err, err)
			}
			if tc.jsonSyntaxErr || tc.jsonUnmarshalErr || tc.base64InputErr {
				return
			}
			if want, got := tc.err, err; !internal.ErrorIs(err, tc.err) {
				t.Errorf("want %v, got %v", want, got)
			}
		})
	}
}
