package jwt_test

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/gbrlsnchs/jwt/v3"
	"github.com/gbrlsnchs/jwt/v3/internal"
)

var (
	validRawToken, _         = jwt.Parse([]byte(validToken))
	validRawToken2, _        = jwt.Parse([]byte(validToken[:112]))
	validRawToken3, _        = jwt.Parse([]byte("a.a."))
	validRawToken4, _        = jwt.Parse([]byte("a.a.a"))
	invalidJSONRawToken, _   = jwt.Parse([]byte(".."))
	invalidBase64RawToken, _ = jwt.Parse([]byte("{}.{}."))
	invalidRawToken, _       = jwt.Parse(nil)
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

func TestRawTokenDecode(t *testing.T) {
	testCases := []struct {
		r       jwt.RawToken
		payload interface{}
		err     error
	}{
		{validRawToken, new(jwt.Payload), nil},
		{validRawToken2, new(jwt.Payload), nil},
		{invalidRawToken, new(jwt.Payload), jwt.ErrMalformed},
		{invalidJSONRawToken, new(jwt.Payload), (*json.SyntaxError)(nil)},
		{invalidBase64RawToken, new(jwt.Payload), base64.CorruptInputError(0)},
		{validRawToken, nil, (*json.InvalidUnmarshalError)(nil)},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			_, err := tc.r.Decode(tc.payload)
			if want, got := tc.err, err; !checkErr(want, got) {
				t.Errorf("want %#v, got %#v", want, got)
			}
		})
	}
}

func checkErr(want, got error) bool {
	switch err := want.(type) {
	case *json.SyntaxError:
		return internal.ErrorAs(got, &err)
	case *json.InvalidUnmarshalError:
		return internal.ErrorAs(got, &err)
	case base64.CorruptInputError:
		return internal.ErrorAs(got, &err)
	default:
		return internal.ErrorIs(got, err)
	}
}
