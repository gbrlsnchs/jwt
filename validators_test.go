package jwt_test

import (
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
		claim string
		vl    ValidatorFunc
		err   error
	}{
		{"iss", (&Payload{Issuer: iss}).IssuerValidator("iss"), nil},
		{"iss", (&Payload{Issuer: iss}).IssuerValidator("not_iss"), ErrIssValidation},
		{"sub", (&Payload{Subject: sub}).SubjectValidator("sub"), nil},
		{"sub", (&Payload{Subject: sub}).SubjectValidator("not_sub"), ErrSubValidation},
		{"aud", (&Payload{Audience: aud}).AudienceValidator(Audience{"aud"}), nil},
		{"aud", (&Payload{Audience: aud}).AudienceValidator(Audience{"foo", "aud1"}), nil},
		{"aud", (&Payload{Audience: aud}).AudienceValidator(Audience{"bar", "aud2"}), nil},
		{"aud", (&Payload{Audience: aud}).AudienceValidator(Audience{"baz", "aud3"}), nil},
		{"aud", (&Payload{Audience: aud}).AudienceValidator(Audience{"qux", "aud4"}), ErrAudValidation},
		{"aud", (&Payload{Audience: aud}).AudienceValidator(Audience{"not_aud"}), ErrAudValidation},
		{"exp", (&Payload{ExpirationTime: exp}).ExpirationTimeValidator(now, true), nil},
		{"exp", (&Payload{ExpirationTime: exp}).ExpirationTimeValidator(now, false), nil},
		{"exp", (&Payload{ExpirationTime: exp}).ExpirationTimeValidator(time.Unix(now.Unix()-int64(24*time.Hour), 0), true), nil},
		{"exp", (&Payload{ExpirationTime: exp}).ExpirationTimeValidator(time.Unix(now.Unix()-int64(24*time.Hour), 0), false), nil},
		{"exp", (&Payload{ExpirationTime: exp}).ExpirationTimeValidator(time.Unix(now.Unix()+int64(24*time.Hour), 0), true), ErrExpValidation},
		{"exp", (&Payload{ExpirationTime: exp}).ExpirationTimeValidator(time.Unix(now.Unix()+int64(24*time.Hour), 0), false), ErrExpValidation},
		{"exp", (&Payload{}).ExpirationTimeValidator(time.Now(), false), nil},
		{"exp", (&Payload{}).ExpirationTimeValidator(time.Now(), true), ErrExpValidation},
		{"nbf", (&Payload{NotBefore: nbf}).NotBeforeValidator(now), ErrNbfValidation},
		{"nbf", (&Payload{NotBefore: nbf}).NotBeforeValidator(time.Unix(now.Unix()+int64(15*time.Second), 0)), nil},
		{"nbf", (&Payload{NotBefore: nbf}).NotBeforeValidator(time.Unix(now.Unix()-int64(15*time.Second), 0)), ErrNbfValidation},
		{"nbf", (&Payload{}).NotBeforeValidator(time.Now()), nil},
		{"iat", (&Payload{IssuedAt: iat}).IssuedAtValidator(now), nil},
		{"iat", (&Payload{IssuedAt: iat}).IssuedAtValidator(time.Unix(now.Unix()+1, 0)), nil},
		{"iat", (&Payload{IssuedAt: iat}).IssuedAtValidator(time.Unix(now.Unix()-1, 0)), ErrIatValidation},
		{"iat", (&Payload{}).IssuedAtValidator(time.Now()), nil},
		{"jti", (&Payload{JWTID: jti}).JWTIDValidator("jti"), nil},
		{"jti", (&Payload{JWTID: jti}).JWTIDValidator("not_jti"), ErrJtiValidation},
	}
	for _, tc := range testCases {
		t.Run(tc.claim, func(t *testing.T) {
			if want, got := tc.err, tc.vl(); want != got {
				t.Errorf("want %v, got %v", want, got)
			}
		})
	}
}
