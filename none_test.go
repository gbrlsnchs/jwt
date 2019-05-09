package jwt_test

import (
	"testing"

	"github.com/gbrlsnchs/jwt/v3"
	"github.com/gbrlsnchs/jwt/v3/internal"
)

var defaultNoneHeader = []byte("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0")

func TestNoneSign(t *testing.T) {
	testCases := []struct {
		n             *jwt.None
		headerPayload []byte
		want          []byte
		err           error
	}{
		{new(jwt.None), claims(defaultNoneHeader, defaultPayload), nil, nil},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			sig, err := tc.n.Sign(tc.headerPayload)
			if want, got := tc.want, sig; string(want) != string(got) {
				t.Errorf("\nwant %s\ngot %s", want, got)
			}
			if want, got := tc.err, err; !internal.ErrorIs(got, want) {
				t.Errorf("want %#v, got %#v", want, got)
			}
		})
	}
}

func TestNoneSize(t *testing.T) {
	testCases := []struct {
		n    *jwt.None
		want int
	}{
		{new(jwt.None), 0},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			if want, got := tc.want, tc.n.Size(); want != got {
				t.Errorf("want %d, got %d", want, got)
			}
		})
	}
}

func TestNoneString(t *testing.T) {
	testCases := []struct {
		n    *jwt.None
		want string
	}{
		{new(jwt.None), jwt.MethodNone},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			if want, got := tc.want, tc.n.String(); want != got {
				t.Errorf("want %s, got %s", want, got)
			}
		})
	}
}

func TestNoneVerify(t *testing.T) {
	testCases := []struct {
		n             *jwt.None
		headerPayload []byte
		sig           []byte
		err           error
	}{
		{new(jwt.None), claims(defaultPayload, defaultNoneHeader), nil, nil},
		{new(jwt.None), nil, nil, nil},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			err := tc.n.Verify(tc.headerPayload, tc.sig)
			if want, got := tc.err, err; !internal.ErrorIs(got, want) {
				t.Errorf("want %#v, got %#v", want, got)
			}
		})
	}
}
