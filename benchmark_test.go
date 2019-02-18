package jwt_test

import (
	"testing"
	"time"

	. "github.com/gbrlsnchs/jwt/v3"
)

var benchMock = []byte("eyJhbGciOiJIUzI1NiIsImtpZCI6ImtpZCIsInR5cCI6IkpXVCJ9." +
	"eyJpYXQiOjE1MzU5NDE1NjcsImV4cCI6MTU2NzA0NTU2NywibmJmIjoxNTM1OTQzMzY3LCJqdGkiOiJCZW5jaG1hcmtTaWduIiwiYXVkIjoiYmVuY2htYXJrIiwic3ViIjoibWUiLCJpc3MiOiJnYnJsc25jaHMiLCJuYW1lIjoiZm9vYmFyIiwiaXNCZW5jaCI6dHJ1ZX0." +
	"bJSm0om7-BRCuLbICllYEAH7YsAT1cW2fdSfKcMnhOg")

var hs256 = NewHMAC(SHA256, []byte("benchmark"))

type benchToken struct {
	JWT
	Name    string `json:"name,omitempty"`
	IsBench bool   `json:"isBench"`
}

func BenchmarkSign(b *testing.B) {
	now := time.Now()
	jot := &benchToken{
		JWT: JWT{
			Header: Header{KeyID: "kid"},
			Claims: &Claims{
				Issuer:         "gbrlsnchs",
				Subject:        "me",
				Audience:       Audience{"benchmark"},
				ExpirationTime: now.Add(24 * 30 * 12 * time.Hour).Unix(),
				NotBefore:      now.Add(30 * time.Minute).Unix(),
				IssuedAt:       now.Unix(),
				ID:             b.Name(),
			},
		},
		Name:    "foobar",
		IsBench: true,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Sign(jot, hs256); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		raw, err := Verify(benchMock, hs256)
		if err != nil {
			b.Fatal(err)
		}
		var jot benchToken
		if err = raw.Decode(&jot); err != nil {
			b.Fatal(err)
		}
	}
}
