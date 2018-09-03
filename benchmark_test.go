package jwt_test

import (
	"testing"
	"time"

	. "github.com/gbrlsnchs/jwt"
)

const benchMock = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtpZCIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MzU5NDE1NjcsImV4cCI6MTU2NzA0NTU2NywibmJmIjoxNTM1OTQzMzY3LCJqdGkiOiJCZW5jaG1hcmtTaWduIiwiYXVkIjoiYmVuY2htYXJrIiwic3ViIjoibWUiLCJpc3MiOiJnYnJsc25jaHMiLCJuYW1lIjoiZm9vYmFyIiwiaXNCZW5jaCI6dHJ1ZX0.bJSm0om7-BRCuLbICllYEAH7YsAT1cW2fdSfKcMnhOg"

var benchSigner = HS256("benchmark")

func BenchmarkSign(b *testing.B) {
	now := time.Now()
	opt := &Options{
		Timestamp:      true,
		JWTID:          b.Name(),
		ExpirationTime: now.Add(24 * 30 * 12 * time.Hour),
		NotBefore:      now.Add(30 * time.Minute),
		Subject:        "me",
		Audience:       "benchmark",
		Issuer:         "gbrlsnchs",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Sign(benchSigner, opt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		jot, err := FromString(benchMock)
		if err != nil {
			b.Fatal(err)
		}
		if err = jot.Verify(benchSigner); err != nil {
			b.Fatal(err)
		}
	}
}
