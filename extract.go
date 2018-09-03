package jwt

import "reflect"

func extractJWT(v interface{}) *JWT {
	if v == nil {
		return nil
	}
	switch jot := v.(type) {
	case JWT:
		return &jot
	case *JWT:
		return jot
	}
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		return nil
	}

	var jot *JWT
	for i := 0; i < val.NumField(); i++ {
		f := val.Field(i)
		if f.Type() == reflect.TypeOf(jot) {
			if f.IsNil() {
				f.Set(reflect.ValueOf(jot))
				break
			}
			jot = f.Interface().(*JWT)
			break
		}
	}
	return jot
}
