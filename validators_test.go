package jwt_test

import (
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	. "github.com/gbrlsnchs/jwt/v3"
)

func TestValidators(t *testing.T) {
	now := time.Now()
	iat := now.Unix()
	exp := now.Add(24 * time.Hour).Unix()
	nbf := now.Add(15 * time.Second).Unix()
	jti := "jti"
	aud := Audience{"aud", "aud1", "aud2", "aud3"}
	sub := "sub"
	iss := "iss"
	testCases := []struct {
		claims    Claims
		validator ValidatorFunc
		err       error
	}{
		{Claims{Issuer: iss}, IssuerValidator("iss"), nil},
		{Claims{Issuer: iss}, IssuerValidator("not_iss"), ErrIssValidation},
		{Claims{Subject: sub}, SubjectValidator("sub"), nil},
		{Claims{Subject: sub}, SubjectValidator("not_sub"), ErrSubValidation},
		{Claims{Audience: aud}, AudienceValidator(Audience{"aud"}), nil},
		{Claims{Audience: aud}, AudienceValidator(Audience{"foo", "aud1"}), nil},
		{Claims{Audience: aud}, AudienceValidator(Audience{"bar", "aud2"}), nil},
		{Claims{Audience: aud}, AudienceValidator(Audience{"baz", "aud3"}), nil},
		{Claims{Audience: aud}, AudienceValidator(Audience{"qux", "aud4"}), ErrAudValidation},
		{Claims{Audience: aud}, AudienceValidator(Audience{"not_aud"}), ErrAudValidation},
		{Claims{ExpirationTime: exp}, ExpirationTimeValidator(now, true), nil},
		{Claims{ExpirationTime: exp}, ExpirationTimeValidator(now, false), nil},
		{Claims{ExpirationTime: exp}, ExpirationTimeValidator(time.Unix(now.Unix()-int64(24*time.Hour), 0), true), nil},
		{Claims{ExpirationTime: exp}, ExpirationTimeValidator(time.Unix(now.Unix()-int64(24*time.Hour), 0), false), nil},
		{Claims{ExpirationTime: exp}, ExpirationTimeValidator(time.Unix(now.Unix()+int64(24*time.Hour), 0), true), ErrExpValidation},
		{Claims{ExpirationTime: exp}, ExpirationTimeValidator(time.Unix(now.Unix()+int64(24*time.Hour), 0), false), ErrExpValidation},
		{Claims{}, ExpirationTimeValidator(time.Now(), false), nil},
		{Claims{}, ExpirationTimeValidator(time.Now(), true), ErrExpValidation},
		{Claims{NotBefore: nbf}, NotBeforeValidator(now), ErrNbfValidation},
		{Claims{NotBefore: nbf}, NotBeforeValidator(time.Unix(now.Unix()+int64(15*time.Second), 0)), nil},
		{Claims{NotBefore: nbf}, NotBeforeValidator(time.Unix(now.Unix()-int64(15*time.Second), 0)), ErrNbfValidation},
		{Claims{}, NotBeforeValidator(time.Now()), nil},
		{Claims{IssuedAt: iat}, IssuedAtValidator(now), nil},
		{Claims{IssuedAt: iat}, IssuedAtValidator(time.Unix(now.Unix()+1, 0)), nil},
		{Claims{IssuedAt: iat}, IssuedAtValidator(time.Unix(now.Unix()-1, 0)), ErrIatValidation},
		{Claims{}, IssuedAtValidator(time.Now()), nil},
		{Claims{ID: jti}, IDValidator("jti"), nil},
		{Claims{ID: jti}, IDValidator("not_jti"), ErrJtiValidation},
	}
	for _, tc := range testCases {
		fn := runtime.FuncForPC(reflect.ValueOf(tc.validator).Pointer())
		name := fn.Name()[:]
		name = strings.TrimPrefix(name, "github.com/gbrlsnchs/jwt/v3.")
		name = strings.TrimSuffix(name, ".func1")
		t.Run(name, func(t *testing.T) {
			if want, got := tc.err, tc.validator(&JWT{Claims: &tc.claims}); want != got {
				t.Errorf("want %v, got %v", want, got)
			}
		})
	}
}
