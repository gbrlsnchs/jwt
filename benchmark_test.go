package jwt_test

import (
	"testing"

	. "github.com/gbrlsnchs/jwt"
)

func BenchmarkSign(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i <= b.N; i++ {
		_, _ = Sign(HS256("secret"), &Options{
			Public: map[string]interface{}{
				"foo": "bar",
				"bar": "foo",
				"baz": "bar",
				"qux": "baz",
			},
		})
	}
}
