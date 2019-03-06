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

type benchPayload struct {
	Payload
	Name    string `json:"name,omitempty"`
	IsBench bool   `json:"isBench"`
}

func BenchmarkSign(b *testing.B) {
	now := time.Now()
	h := Header{KeyID: "kid"}
	p := &benchPayload{
		Payload: Payload{
			Issuer:         "gbrlsnchs",
			Subject:        "me",
			Audience:       Audience{"benchmark"},
			ExpirationTime: now.Add(24 * 30 * 12 * time.Hour).Unix(),
			NotBefore:      now.Add(30 * time.Minute).Unix(),
			IssuedAt:       now.Unix(),
			JWTID:          b.Name(),
		},
		Name:    "foobar",
		IsBench: true,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Sign(h, p, hs256); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		raw, err := Parse(benchMock)
		if err != nil {
			b.Fatal(err)
		}
		if err = raw.Verify(hs256); err != nil {
			b.Fatal(err)
		}
		var p benchPayload
		if _, err = raw.Decode(&p); err != nil {
			b.Fatal(err)
		}
	}
}
