package jwt

import (
	"errors"
	"reflect"
)

func extractJWT(v interface{}, headless bool) (*JWT, error) {
	if v == nil {
		return nil, errors.New("jwt: marshal/unmarshal nil interface")
	}
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		return nil, errors.New("jwt: marshal/unmarshal a value that is not a struct or pointer to a struct")
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
	if jot == nil {
		if !headless {
			return nil, ErrNilHeader
		}
		jot = &JWT{
			Header: &Header{
				header: &header{},
			},
		}
	}
	if jot.Header == nil {
		if !headless {
			return nil, ErrNilHeader
		}
		jot.Header = &Header{
			header: &header{},
		}
	}
	return jot, nil
}
