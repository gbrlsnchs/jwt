package jwt_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/gbrlsnchs/jwt/v3"
	"github.com/gbrlsnchs/jwt/v3/internal"
)

func TestTimeMarshalJSON(t *testing.T) {
	now := time.Now()
	testCases := []struct {
		tt   jwt.Time
		want int64
	}{
		{jwt.Time{}, 0},
		{jwt.Time{now}, now.Unix()},
		{jwt.Time{now.Add(24 * time.Hour)}, now.Add(24 * time.Hour).Unix()},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			b, err := tc.tt.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			var n int64
			if err = json.Unmarshal(b, &n); err != nil {
				t.Fatal(err)
			}
			if want, got := tc.want, n; got != want {
				t.Errorf("want %d, got %d", want, got)
			}
		})
	}
}

func TestTimeUnmarshalJSON(t *testing.T) {
	now := time.Now()
	testCases := []struct {
		n    int64
		want jwt.Time
	}{
		{now.Unix(), jwt.Time{now}},
		{internal.Epoch.Unix() - 1337, jwt.Time{internal.Epoch}},
		{internal.Epoch.Unix(), jwt.Time{internal.Epoch}},
		{internal.Epoch.Unix() + 1337, jwt.Time{internal.Epoch.Add(1337 * time.Second)}},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			b, err := json.Marshal(tc.n)
			if err != nil {
				t.Fatal(err)
			}
			var tt jwt.Time
			if err = tt.UnmarshalJSON(b); err != nil {
				t.Fatal(err)
			}
			if want, got := tc.want, tt; got.Unix() != want.Unix() {
				t.Errorf("want %d, got %d", want.Unix(), got.Unix())
			}
		})
	}
}