package jwt_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/gbrlsnchs/jwt/v3"
)

// Token extracted from https://jwt.io:
//
//	[Header]
//	{
//	  "alg": "HS256",
//	  "typ": "JWT"
//	}
//
//	[Payload]
//	{
//	  "sub": "1234567890",
//	  "name": "John Doe",
//	  "iat": 1516239022
//	}
const validToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
	"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

var (
	hs256 = jwt.NewHMAC(jwt.SHA256, []byte("your-256-bit-secret"))
	hs384 = jwt.NewHMAC(jwt.SHA384, []byte("your-384-bit-secret"))
	hs512 = jwt.NewHMAC(jwt.SHA512, []byte("your-512-bit-secret"))
)

func TestDecoderDecode(t *testing.T) {
	testCases := []struct {
		d       *jwt.Decoder
		payload jwt.Validator
		funcs   []jwt.ValidatorFunc
		err     error
	}{
		{jwt.NewDecoder([]byte(validToken), hs256), new(jwt.Payload), nil, nil},
		{jwt.NewDecoder([]byte(validToken), hs384), new(jwt.Payload), nil, jwt.ErrAlgValidation},
		{jwt.NewDecoder([]byte(validToken), hs512), new(jwt.Payload), nil, jwt.ErrAlgValidation},
		{jwt.NewDecoder([]byte(validToken[:112]), hs256), new(jwt.Payload), nil, jwt.ErrHMACVerification},
		{jwt.NewDecoder([]byte(validToken[:112]), hs384), new(jwt.Payload), nil, jwt.ErrAlgValidation},
		{jwt.NewDecoder([]byte(validToken[:112]), hs512), new(jwt.Payload), nil, jwt.ErrAlgValidation},
		{jwt.NewDecoder([]byte(validToken[:111]), hs256), new(jwt.Payload), nil, jwt.ErrMalformed},
		{jwt.NewDecoder([]byte(validToken[:111]), hs384), new(jwt.Payload), nil, jwt.ErrMalformed},
		{jwt.NewDecoder([]byte(validToken[:111]), hs512), new(jwt.Payload), nil, jwt.ErrMalformed},
		{jwt.NewDecoder([]byte(".."), hs256), new(jwt.Payload), nil, (*json.SyntaxError)(nil)},
		{jwt.NewDecoder([]byte(".."), hs384), new(jwt.Payload), nil, (*json.SyntaxError)(nil)},
		{jwt.NewDecoder([]byte(".."), hs512), new(jwt.Payload), nil, (*json.SyntaxError)(nil)},
		{jwt.NewDecoder([]byte("{}.{}."), hs256), new(jwt.Payload), nil, base64.CorruptInputError(0)},
		{jwt.NewDecoder([]byte("{}.{}."), hs384), new(jwt.Payload), nil, base64.CorruptInputError(0)},
		{jwt.NewDecoder([]byte("{}.{}."), hs512), new(jwt.Payload), nil, base64.CorruptInputError(0)},
		{jwt.NewDecoder([]byte(validToken), hs256), nil, nil, (*json.InvalidUnmarshalError)(nil)},
		{jwt.NewDecoder([]byte(validToken), hs384), nil, nil, (*json.InvalidUnmarshalError)(nil)},
		{jwt.NewDecoder([]byte(validToken), hs512), nil, nil, (*json.InvalidUnmarshalError)(nil)},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			err := tc.d.Decode(tc.payload)
			if want, got := tc.err, err; !checkErr(tc.err, err) {
				t.Errorf("want %v, got %v", want, got)
			}
		})
	}
}
