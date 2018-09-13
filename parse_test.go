package jwt_test

import (
	"testing"

	. "github.com/gbrlsnchs/jwt/v2"
)

var parserSigner = NewHS256("secret")

func TestParse(t *testing.T) {
	testCases := []struct {
		token string
		alg   string
		kid   string
		typ   string
		iss   string
		sub   string
		aud   string
		exp   int64
		nbf   int64
		iat   int64
		jti   string
		name  string
	}{
		{
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJleHAiOjE1MTYyMzkwMzMsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsIm5iZiI6MTUxNjIzOTA0NCwiaXNzIjoiand0LmlvIiwiYXVkIjoidGVzdCIsImp0aSI6InUzZzEyM2xrajFoZzRsMWoyZzQxaDJnIn0." +
				"ckCc4Wa7vSsFCE8smpzFmIh9w_4MmHV1w7HndGbqA-k",
			MethodHS256,
			"",
			"JWT",
			"jwt.io",
			"1234567890",
			"test",
			1516239033,
			1516239044,
			1516239022,
			"u3g123lkj1hg4l1j2g41h2g",
			"John Doe",
		},
		{
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJzdWIiOiI0ODMyNzQ4MiIsIm5hbWUiOiJHb2xhbmcgR29waGVyIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
				"PWdAiTCf5NyNunEchIOUt6mla7ie52D3xB9ihJIBwAA",
			MethodHS256,
			"",
			"JWT",
			"",
			"48327482",
			"",
			int64(0),
			int64(0),
			1516239022,
			"",
			"Golang Gopher",
		},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			payload, sig, err := Parse(tc.token)
			if want, got := (error)(nil), err; want != got {
				t.Fatalf("want %v, got %v", want, got)
			}
			if want, got := (error)(nil), parserSigner.Verify(payload, sig); want != got {
				t.Errorf("want %v, got %v", want, got)
			}
			var jot testToken
			if want, got := (error)(nil), Unmarshal(payload, &jot); want != got {
				t.Fatalf("want %v, got %v", want, got)
			}
			if want, got := tc.alg, jot.Algorithm(); want != got {
				t.Errorf("want %s, got %s", want, got)
			}
			if want, got := tc.kid, jot.KeyID(); want != got {
				t.Errorf("want %s, got %s", want, got)
			}
			if want, got := tc.typ, jot.Type(); want != got {
				t.Errorf("want %s, got %s", want, got)
			}
			if want, got := tc.iss, jot.Issuer; want != got {
				t.Errorf("want %s, got %s", want, got)
			}
			if want, got := tc.sub, jot.Subject; want != got {
				t.Errorf("want %s, got %s", want, got)
			}
			if want, got := tc.aud, jot.Audience; want != got {
				t.Errorf("want %s, got %s", want, got)
			}
			if want, got := tc.exp, jot.ExpirationTime; want != got {
				t.Errorf("want %d, got %d", want, got)
			}
			if want, got := tc.nbf, jot.NotBefore; want != got {
				t.Errorf("want %d, got %d", want, got)
			}
			if want, got := tc.iat, jot.IssuedAt; want != got {
				t.Errorf("want %d, got %d", want, got)
			}
			if want, got := tc.jti, jot.ID; want != got {
				t.Errorf("want %s, got %s", want, got)
			}
		})
	}
}
