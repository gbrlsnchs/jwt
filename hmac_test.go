package jwt_test

import (
	"crypto"
	"testing"

	"github.com/gbrlsnchs/jwt/v3"
	"github.com/gbrlsnchs/jwt/v3/internal"
)

type testTable map[jwt.Hash][]byte

var (
	defaultPayload  = []byte("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ")
	temperedPayload = []byte("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0")

	defaultHMACSignatures = testTable{
		jwt.SHA256: []byte("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
		jwt.SHA384: []byte("8aMsJp4VGY_Ia2s9iWrS8jARCggx0FDRn2FehblXyvGYRrVVbu3LkKKqx_MEuDjQ"),
		jwt.SHA512: []byte("_MRZSQUbU6G_jPvXIlFsWSU-PKT203EdcU388r5EWxSxg8QpB3AmEGSo2fBfMYsOaxvzos6ehRm4CYO1MrdwUg"),
	}
	defaultHMACHeaders = testTable{
		jwt.SHA256: []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
		jwt.SHA384: []byte("eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9"),
		jwt.SHA512: []byte("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9"),
	}
	defaultHMACSecrets = testTable{
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
	ds, err := decodeSigs(defaultHMACSignatures)
	if err != nil {
		t.Fatal(err)
	}
	testCases := []struct {
		h             *jwt.HMAC
		headerPayload []byte
		want          []byte
		err           error
	}{
		{
			jwt.NewHMAC(jwt.SHA256, defaultHMACSecrets[jwt.SHA256]),
			claims(defaultHMACHeaders[jwt.SHA256], defaultPayload),
			ds[jwt.SHA256],
			nil,
		},
		{
			jwt.NewHMAC(jwt.SHA384, defaultHMACSecrets[jwt.SHA384]),
			claims(defaultHMACHeaders[jwt.SHA384], defaultPayload),
			ds[jwt.SHA384],
			nil,
		},
		{
			jwt.NewHMAC(jwt.SHA512, defaultHMACSecrets[jwt.SHA512]),
			claims(defaultHMACHeaders[jwt.SHA512], defaultPayload),
			ds[jwt.SHA512],
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

func TestHMACSize(t *testing.T) {
	testCases := []struct {
		h    *jwt.HMAC
		want int
	}{
		{jwt.NewHMAC(jwt.SHA256, defaultHMACSecrets[jwt.SHA256]), crypto.SHA256.Size()},
		{jwt.NewHMAC(jwt.SHA384, defaultHMACSecrets[jwt.SHA384]), crypto.SHA384.Size()},
		{jwt.NewHMAC(jwt.SHA512, defaultHMACSecrets[jwt.SHA512]), crypto.SHA512.Size()},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			if want, got := tc.want, tc.h.Size(); want != got {
				t.Errorf("want %d, got %d", want, got)
			}
		})
	}
}

func TestHMACString(t *testing.T) {
	testCases := []struct {
		h    *jwt.HMAC
		want string
	}{
		{jwt.NewHMAC(jwt.SHA256, defaultHMACSecrets[jwt.SHA256]), jwt.MethodHS256},
		{jwt.NewHMAC(jwt.SHA384, defaultHMACSecrets[jwt.SHA384]), jwt.MethodHS384},
		{jwt.NewHMAC(jwt.SHA512, defaultHMACSecrets[jwt.SHA512]), jwt.MethodHS512},
		{jwt.NewHMAC(jwt.Hash(0), defaultHMACSecrets[jwt.SHA256]), jwt.MethodHS256},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			if want, got := tc.want, tc.h.String(); want != got {
				t.Errorf("want %s, got %s", want, got)
			}
		})
	}
}

func TestHMACVerify(t *testing.T) {
	testCases := []struct {
		h             *jwt.HMAC
		headerPayload []byte
		sig           []byte
		err           error
	}{
		{
			jwt.NewHMAC(jwt.SHA256, defaultHMACSecrets[jwt.SHA256]),
			claims(defaultHMACHeaders[jwt.SHA256], defaultPayload),
			defaultHMACSignatures[jwt.SHA256],
			nil,
		},
		{
			jwt.NewHMAC(jwt.SHA384, defaultHMACSecrets[jwt.SHA384]),
			claims(defaultHMACHeaders[jwt.SHA384], defaultPayload),
			defaultHMACSignatures[jwt.SHA384],
			nil,
		},
		{
			jwt.NewHMAC(jwt.SHA512, defaultHMACSecrets[jwt.SHA512]),
			claims(defaultHMACHeaders[jwt.SHA512], defaultPayload),
			defaultHMACSignatures[jwt.SHA512],
			nil,
		},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			err := tc.h.Verify(tc.headerPayload, tc.sig)
			if want, got := tc.err, err; !internal.ErrorIs(got, want) {
				t.Errorf("want %#v, got %#v", want, got)
			}
		})
	}
}

// decodeSigs returns a map with Base64 decoded signatures.
func decodeSigs(encSigs testTable) (testTable, error) {
	ds := make(testTable, 3)
	for k, v := range encSigs {
		sig, err := internal.DecodeToBytes(v)
		if err != nil {
			return nil, err
		}
		ds[k] = sig
	}
	return ds, nil
}
