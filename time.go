package jwt

import (
	"encoding/json"
	"time"
)

var epoch = time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)

// Time is the allowed format for time, as per the RFC 7519.
type Time struct {
	time.Time
}

// MarshalJSON implements a marshaling function for time-related claims.
func (t Time) MarshalJSON() ([]byte, error) {
	if t.Before(epoch) {
		return json.Marshal(0)
	}
	return json.Marshal(t.Unix())
}

// UnmarshalJSON implements an unmarshaling function for time-related claims.
func (t *Time) UnmarshalJSON(b []byte) error {
	var tt time.Time
	if err := json.Unmarshal(b, &tt); err != nil {
		return err
	}
	if tt.Before(epoch) {
		tt = epoch
	}
	t.Time = tt
	return nil
}
