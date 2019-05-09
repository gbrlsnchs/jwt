package jwt_test

import (
	"testing"

	"github.com/gbrlsnchs/jwt/v3"
	"github.com/gbrlsnchs/jwt/v3/internal"
)

var (
	defaultHMACPayload  = []byte("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ")
	temperedHMACPayload = []byte("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0")

	defaultHMACSignatures = map[jwt.Hash][]byte{
		jwt.SHA256: []byte("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
		jwt.SHA384: []byte("8aMsJp4VGY_Ia2s9iWrS8jARCggx0FDRn2FehblXyvGYRrVVbu3LkKKqx_MEuDjQ"),
		jwt.SHA512: []byte("_MRZSQUbU6G_jPvXIlFsWSU-PKT203EdcU388r5EWxSxg8QpB3AmEGSo2fBfMYsOaxvzos6ehRm4CYO1MrdwUg"),
	}
	defaultHMACHeaders = map[jwt.Hash][]byte{
		jwt.SHA256: []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
		jwt.SHA384: []byte("eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9"),
		jwt.SHA512: []byte("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9"),
	}
	defaultHMACSecrets = map[jwt.Hash][]byte{
		jwt.SHA256: []byte("your-256-bit-secret"),
		jwt.SHA384: []byte("your-384-bit-secret"),
		jwt.SHA512: []byte("your-512-bit-secret"),
	}
)

func claims(header, payload []byte) (c []byte) {
	c = append(make([]byte, 0, len(header)+1+len(payload)), header...)
	c = append(c, '.')
	c = append(c, payload...)
	return
}

func TestHMACSign(t *testing.T) {
	decodedSigs := make(map[jwt.Hash][]byte, 3)
	for k, v := range defaultHMACSignatures {
		sig, err := internal.DecodeToBytes(v)
		if err != nil {
			t.Fatal(err)
		}
		decodedSigs[k] = sig
	}
	testCases := []struct {
		h             *jwt.HMAC
		headerPayload []byte
		want          []byte
		err           error
	}{
		{
			jwt.NewHMAC(jwt.SHA256, defaultHMACSecrets[jwt.SHA256]),
			claims(defaultHMACHeaders[jwt.SHA256], defaultHMACPayload),
			decodedSigs[jwt.SHA256],
			nil,
		},
		{
			jwt.NewHMAC(jwt.SHA384, defaultHMACSecrets[jwt.SHA384]),
			claims(defaultHMACHeaders[jwt.SHA384], defaultHMACPayload),
			decodedSigs[jwt.SHA384],
			nil,
		},
		{
			jwt.NewHMAC(jwt.SHA512, defaultHMACSecrets[jwt.SHA512]),
			claims(defaultHMACHeaders[jwt.SHA512], defaultHMACPayload),
			decodedSigs[jwt.SHA512],
			nil,
		},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			sig, err := tc.h.Sign(tc.headerPayload)
			if want, got := tc.want, sig; string(want) != string(got) {
				t.Errorf("\nwant %s\ngot %s", want, got)
			}
			if want, got := tc.err, err; !internal.ErrorIs(got, want) {
				t.Errorf("want %#v, got %#v", want, got)
			}
		})
	}
}
