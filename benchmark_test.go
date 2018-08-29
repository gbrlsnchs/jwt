package jwt_test

import (
	"testing"
	"time"

	. "github.com/gbrlsnchs/jwt"
)

var (
	benchMock   = []byte("eyJhbGciOiJIUzI1NiIsImtpZCI6Im15X2tleSIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImV4cCI6MTU2NjY1MzM3NywiZm9vIjoiYmFyIiwiaWF0IjoxNTM1NTQ5Mzc3LCJpc3MiOiJhdXRoX3NlcnZlciIsImp0aSI6InVuaXF1ZV9pZCIsIm15Qm9vbCI6dHJ1ZSwibmJmIjoxNTM1NTUxMTc3LCJzdWIiOiIxMjMifQ.ktYQOGGGYoExeH86Oh6sjTefiMSllYuBsdVE4dwwNiI")
	benchSigner = HS256("b3nchm4rk")
)

type Token struct {
	*JWT
	Foo  string `json:"foo,omitempty"`
	Bool bool   `json:"bool,omitempty"`
}

func BenchmarkSign(b *testing.B) {
	now := time.Now()
	token := &Token{
		JWT: &JWT{
			Header: &Header{
				Algorithm: benchSigner.String(),
				KeyID:     "my_key",
			},
			Claims: &Claims{
				ID:         "unique_id",
				IssuedAt:   now,
				Expiration: now.Add(24 * 30 * 12 * time.Hour),
				NotBefore:  now.Add(30 * time.Minute),
				Subject:    "123",
				Audience:   "admin",
				Issuer:     "auth_server",
			},
		},
		Foo:  "bar",
		Bool: true,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := benchSigner.Sign(token); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		var token Token
		if err := benchSigner.Verify(benchMock, &token); err != nil {
			b.Error(err)
		}
	}
}
