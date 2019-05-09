package jwt_test

import (
	"reflect"
	"testing"

	"github.com/gbrlsnchs/jwt/v3"
	"github.com/gbrlsnchs/jwt/v3/internal"
)

var (
	validRawToken, _  = jwt.Parse([]byte(validToken))
	validRawToken2, _ = jwt.Parse([]byte(validToken[:112]))
	validRawToken3, _ = jwt.Parse([]byte("a.a."))
	validRawToken4, _ = jwt.Parse([]byte("a.a.a"))
	invalidRawToken   jwt.RawToken
)

func TestParse(t *testing.T) {
	testCases := []struct {
		token []byte
		want  jwt.RawToken
		err   error
	}{
		{[]byte(validToken), validRawToken, nil},
		{[]byte(validToken[:112]), validRawToken2, nil},
		{[]byte(validToken[:111]), invalidRawToken, jwt.ErrMalformed},
		{[]byte("a.a."), validRawToken3, nil},  // parsable, not valid
		{[]byte("a.a.a"), validRawToken4, nil}, // parsable, not valid
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			rt, err := jwt.Parse(tc.token)
			if want, got := tc.want, rt; !reflect.DeepEqual(want, got) {
				t.Errorf("want %v, got %v", want, got)
			}
			if want, got := tc.err, err; !internal.ErrorIs(got, want) {
				t.Fatalf("want %v, got %v", want, got)
			}
		})
	}
}
			}
		})
	}
}
