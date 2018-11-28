package jwt_test

import (
	"testing"
	"time"

	. "github.com/gbrlsnchs/jwt/v2"
)

const benchMock = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtpZCIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MzU5NDE1NjcsImV4cCI6MTU2NzA0NTU2NywibmJmIjoxNTM1OTQzMzY3LCJqdGkiOiJCZW5jaG1hcmtTaWduIiwiYXVkIjoiYmVuY2htYXJrIiwic3ViIjoibWUiLCJpc3MiOiJnYnJsc25jaHMiLCJuYW1lIjoiZm9vYmFyIiwiaXNCZW5jaCI6dHJ1ZX0.bJSm0om7-BRCuLbICllYEAH7YsAT1cW2fdSfKcMnhOg"

var benchSigner = NewHS256("benchmark")

type benchToken struct {
	*JWT
	Name    string `json:"name,omitempty"`
	IsBench bool   `json:"isBench"`
}

func BenchmarkSign(b *testing.B) {
	now := time.Now()
	jot := &benchToken{
		JWT: &JWT{
			Issuer:         "gbrlsnchs",
			Subject:        "me",
			Audience:       "benchmark",
			ExpirationTime: now.Add(24 * 30 * 12 * time.Hour).Unix(),
			NotBefore:      now.Add(30 * time.Minute).Unix(),
			IssuedAt:       now.Unix(),
			ID:             b.Name(),
		},
		Name:    "foobar",
		IsBench: true,
	}
	jot.SetAlgorithm(benchSigner)
	jot.SetKeyID("kid")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		payload, err := Marshal(jot)
		if err != nil {
			b.Fatal(err)
		}
		if _, err = benchSigner.Sign(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		payload, sig, err := Parse(benchMock)
		if err != nil {
			b.Fatal(err)
		}
		var jot benchToken
		if err = Unmarshal(payload, &jot); err != nil {
			b.Fatal(err)
		}
		if err = benchSigner.Verify(payload, sig); err != nil {
			b.Fatal(err)
		}
	}
}
