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
		p   Payload
		vl  ValidatorFunc
		err error
	}{
		{Payload{Issuer: iss}, IssuerValidator("iss"), nil},
		{Payload{Issuer: iss}, IssuerValidator("not_iss"), ErrIssValidation},
		{Payload{Subject: sub}, SubjectValidator("sub"), nil},
		{Payload{Subject: sub}, SubjectValidator("not_sub"), ErrSubValidation},
		{Payload{Audience: aud}, AudienceValidator(Audience{"aud"}), nil},
		{Payload{Audience: aud}, AudienceValidator(Audience{"foo", "aud1"}), nil},
		{Payload{Audience: aud}, AudienceValidator(Audience{"bar", "aud2"}), nil},
		{Payload{Audience: aud}, AudienceValidator(Audience{"baz", "aud3"}), nil},
		{Payload{Audience: aud}, AudienceValidator(Audience{"qux", "aud4"}), ErrAudValidation},
		{Payload{Audience: aud}, AudienceValidator(Audience{"not_aud"}), ErrAudValidation},
		{Payload{ExpirationTime: exp}, ExpirationTimeValidator(now, true), nil},
		{Payload{ExpirationTime: exp}, ExpirationTimeValidator(now, false), nil},
		{Payload{ExpirationTime: exp}, ExpirationTimeValidator(time.Unix(now.Unix()-int64(24*time.Hour), 0), true), nil},
		{Payload{ExpirationTime: exp}, ExpirationTimeValidator(time.Unix(now.Unix()-int64(24*time.Hour), 0), false), nil},
		{Payload{ExpirationTime: exp}, ExpirationTimeValidator(time.Unix(now.Unix()+int64(24*time.Hour), 0), true), ErrExpValidation},
		{Payload{ExpirationTime: exp}, ExpirationTimeValidator(time.Unix(now.Unix()+int64(24*time.Hour), 0), false), ErrExpValidation},
		{Payload{}, ExpirationTimeValidator(time.Now(), false), nil},
		{Payload{}, ExpirationTimeValidator(time.Now(), true), ErrExpValidation},
		{Payload{NotBefore: nbf}, NotBeforeValidator(now), ErrNbfValidation},
		{Payload{NotBefore: nbf}, NotBeforeValidator(time.Unix(now.Unix()+int64(15*time.Second), 0)), nil},
		{Payload{NotBefore: nbf}, NotBeforeValidator(time.Unix(now.Unix()-int64(15*time.Second), 0)), ErrNbfValidation},
		{Payload{}, NotBeforeValidator(time.Now()), nil},
		{Payload{IssuedAt: iat}, IssuedAtValidator(now), nil},
		{Payload{IssuedAt: iat}, IssuedAtValidator(time.Unix(now.Unix()+1, 0)), nil},
		{Payload{IssuedAt: iat}, IssuedAtValidator(time.Unix(now.Unix()-1, 0)), ErrIatValidation},
		{Payload{}, IssuedAtValidator(time.Now()), nil},
		{Payload{JWTID: jti}, JWTIDValidator("jti"), nil},
		{Payload{JWTID: jti}, JWTIDValidator("not_jti"), ErrJtiValidation},
	}
	for _, tc := range testCases {
		fn := runtime.FuncForPC(reflect.ValueOf(tc.vl).Pointer())
		name := fn.Name()[:]
		name = strings.TrimPrefix(name, "github.com/gbrlsnchs/jwt/v3.")
		name = strings.TrimSuffix(name, ".func1")
		t.Run(name, func(t *testing.T) {
			if want, got := tc.err, tc.vl(&tc.p); want != got {
				t.Errorf("want %v, got %v", want, got)
			}
		})
	}
}
