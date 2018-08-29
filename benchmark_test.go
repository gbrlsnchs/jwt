package jwt_test

import (
	"testing"
	"time"

	. "github.com/gbrlsnchs/jwt"
)

const benchMock = `eyJhbGciOiJIUzI1NiIsImtpZCI6Im15X2tleSIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImV4cCI6MTU2NjY1MzM3NywiZm9vIjoiYmFyIiwiaWF0IjoxNTM1NTQ5Mzc3LCJpc3MiOiJhdXRoX3NlcnZlciIsImp0aSI6InVuaXF1ZV9pZCIsIm15Qm9vbCI6dHJ1ZSwibmJmIjoxNTM1NTUxMTc3LCJzdWIiOiIxMjMifQ.ktYQOGGGYoExeH86Oh6sjTefiMSllYuBsdVE4dwwNiI`

var benchSigner = HS256("b3nchm4rk")

func BenchmarkSign(b *testing.B) {
	now := time.Now()
	opt := &Options{
		JWTID:          "unique_id",
		Timestamp:      true,
		ExpirationTime: now.Add(24 * 30 * 12 * time.Hour),
		NotBefore:      now.Add(30 * time.Minute),
		Subject:        "123",
		Audience:       "admin",
		Issuer:         "auth_server",
		KeyID:          "my_key",
		Public:         map[string]interface{}{"foo": "bar", "myBool": true},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Sign(benchSigner, opt)
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		jot, err := FromString(benchMock)
		if err != nil {
			b.Error(err)
		}
		if err = jot.Verify(benchSigner); err != nil {
			b.Error(err)
		}
	}
}
