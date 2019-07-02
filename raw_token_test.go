package jwt_test

import (
	"reflect"
	"testing"

	"github.com/gbrlsnchs/jwt/v3"
)

var (
	testToken = []byte(
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
			"eyJzdHJpbmciOiJmb29iYXIiLCJpbnQiOjEzMzcsImlhdCI6MTUxNjIzOTAyMn0." +
			"bVYo9Q0lGouCj1y9zFY17bfxQaRUuM6wtpnIy0m4uD0",
	)
	testRaw, _ = jwt.Verify(jwt.NewHS256([]byte("secret")), testToken)
)

func TestRawTokenDecode(t *testing.T) {
	testCases := []struct {
		raw         jwt.RawToken
		wantPayload testPayload
	}{
		{
			raw: testRaw,
			wantPayload: testPayload{
				String: "foobar",
				Int:    1337,
				Payload: jwt.Payload{
					IssuedAt: 1516239022,
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			var payload testPayload
			err := tc.raw.Decode(&payload)
			if err != nil {
				t.Fatal(err)
			}
			if want, got := tc.wantPayload, payload; !reflect.DeepEqual(got, want) {
				t.Errorf("want %#+v, got %#+v", want, got)
			}
		})
	}
}
