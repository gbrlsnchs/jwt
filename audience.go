package jwt

import "encoding/json"

type Audience []string

func (a Audience) MarshalJSON() ([]byte, error) {
	switch len(a) {
	case 0:
		return nil, nil
	case 1:
		return json.Marshal(a[0])
	default:
		return json.Marshal([]string(a))
	}
}

func (a *Audience) UnmarshalJSON(b []byte) error {
	var (
		v   interface{}
		err error
	)
	if err = json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch vv := v.(type) {
	case string:
		aud := make(Audience, 1)
		aud[0] = vv
		*a = aud
	case []interface{}:
		aud := make(Audience, 0, len(vv))
		for i := range vv {
			aud[i] = vv[i].(string)
		}
		*a = aud
	}
	return nil
}
