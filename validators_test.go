package jwt_test

import (
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	. "github.com/gbrlsnchs/jwt/v2"
)

func TestValidators(t *testing.T) {
	var now time.Time
	jot := &JWT{
		IssuedAt:       now.Unix(),
		ExpirationTime: now.Add(24 * time.Hour).Unix(),
		NotBefore:      now.Add(15 * time.Second).Unix(),
		ID:             "jti",
		Audience:       "aud",
		Subject:        "sub",
		Issuer:         "iss",
	}
	testCases := []struct {
		validator ValidatorFunc
		err       error
	}{
		{IssuedAtValidator(now), nil},
		{IssuedAtValidator(time.Unix(now.Unix()+1, 0)), nil},
		{IssuedAtValidator(time.Unix(now.Unix()-1, 0)), ErrIatValidation},
		{ExpirationTimeValidator(now), nil},
		{ExpirationTimeValidator(time.Unix(now.Unix()-int64(24*time.Hour), 0)), nil},
		{ExpirationTimeValidator(time.Unix(now.Unix()+int64(24*time.Hour), 0)), ErrExpValidation},
		{NotBeforeValidator(now), ErrNbfValidation},
		{NotBeforeValidator(time.Unix(now.Unix()+int64(15*time.Second), 0)), nil},
		{NotBeforeValidator(time.Unix(now.Unix()-int64(15*time.Second), 0)), ErrNbfValidation},
		{IDValidator("jti"), nil},
		{IDValidator("not_jti"), ErrJtiValidation},
		{AudienceValidator("aud"), nil},
		{AudienceValidator("not_aud"), ErrAudValidation},
		{SubjectValidator("sub"), nil},
		{SubjectValidator("not_sub"), ErrSubValidation},
		{IssuerValidator("iss"), nil},
		{IssuerValidator("not_iss"), ErrIssValidation},
	}
	for _, tc := range testCases {
		fn := runtime.FuncForPC(reflect.ValueOf(tc.validator).Pointer())
		name := fn.Name()[:]
		name = strings.TrimPrefix(name, "github.com/gbrlsnchs/jwt/v2.")
		name = strings.TrimSuffix(name, ".func1")
		t.Run(name, func(t *testing.T) {
			if want, got := tc.err, tc.validator(jot); want != got {
				t.Errorf("want %v, got %v", want, got)
			}
		})
	}
}
