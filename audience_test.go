package jwt_test

import (
	"encoding/json"
	"reflect"
	"testing"

	. "github.com/gbrlsnchs/jwt/v3"
)

func TestAudienceMarshal(t *testing.T) {
	testCases := []struct {
		aud      Audience
		expected string
	}{
		{Audience{"foo"}, `"foo"`},
		{Audience{"foo", "bar"}, `["foo","bar"]`},
		{nil, `""`},
		{Audience{}, `""`},
		{Audience{""}, `""`},
	}
	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			b, err := json.Marshal(tc.aud)
			if err != nil {
				t.Fatal(err)
			}
			if want, got := tc.expected, b; want != string(got) {
				t.Errorf("want %s, got %s", want, got)
			}
		})
	}
}

func TestAudienceOmitempty(t *testing.T) {
	v := struct {
		Audience Audience `json:"aud,omitempty"`
	}{}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if want, got := "{}", b; want != string(got) {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestAudienceUnmarshal(t *testing.T) {
	testCases := []struct {
		jstr     []byte
		expected Audience
	}{
		{[]byte(`"foo"`), Audience{"foo"}},
		{[]byte(`["foo","bar"]`), Audience{"foo", "bar"}},
		{[]byte("[]"), Audience{}},
	}
	for _, tc := range testCases {
		t.Run(string(tc.jstr), func(t *testing.T) {
			var aud Audience
			if err := json.Unmarshal(tc.jstr, &aud); err != nil {
				t.Fatal(err)
			}
			if want, got := tc.expected, aud; !reflect.DeepEqual(want, got) {
				t.Errorf("want %v, got %v", want, got)
			}
		})
	}
}
