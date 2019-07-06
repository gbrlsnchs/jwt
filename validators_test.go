package jwt_test

import (
	"testing"
	"time"

	"github.com/gbrlsnchs/jwt/v3"
)

func TestValidators(t *testing.T) {
	now := time.Now()
	iat := jwt.NumericDate(now)
	exp := jwt.NumericDate(now.Add(24 * time.Hour))
	nbf := jwt.NumericDate(now.Add(15 * time.Second))
	jti := "jti"
	aud := jwt.Audience{"aud", "aud1", "aud2", "aud3"}
	sub := "sub"
	iss := "iss"
	testCases := []struct {
		claim string
		vl    jwt.ValidatorFunc
		err   error
	}{
		{"iss", (&jwt.Payload{Issuer: iss}).IssuerValidator("iss"), nil},
		{"iss", (&jwt.Payload{Issuer: iss}).IssuerValidator("not_iss"), jwt.ErrIssValidation},
		{"sub", (&jwt.Payload{Subject: sub}).SubjectValidator("sub"), nil},
		{"sub", (&jwt.Payload{Subject: sub}).SubjectValidator("not_sub"), jwt.ErrSubValidation},
		{"aud", (&jwt.Payload{Audience: aud}).AudienceValidator(jwt.Audience{"aud"}), nil},
		{"aud", (&jwt.Payload{Audience: aud}).AudienceValidator(jwt.Audience{"foo", "aud1"}), nil},
		{"aud", (&jwt.Payload{Audience: aud}).AudienceValidator(jwt.Audience{"bar", "aud2"}), nil},
		{"aud", (&jwt.Payload{Audience: aud}).AudienceValidator(jwt.Audience{"baz", "aud3"}), nil},
		{"aud", (&jwt.Payload{Audience: aud}).AudienceValidator(jwt.Audience{"qux", "aud4"}), jwt.ErrAudValidation},
		{"aud", (&jwt.Payload{Audience: aud}).AudienceValidator(jwt.Audience{"not_aud"}), jwt.ErrAudValidation},
		{"exp", (&jwt.Payload{ExpirationTime: exp}).ExpirationTimeValidator(now), nil},
		{"exp", (&jwt.Payload{ExpirationTime: exp}).ExpirationTimeValidator(time.Unix(now.Unix()-int64(24*time.Hour), 0)), nil},
		{"exp", (&jwt.Payload{ExpirationTime: exp}).ExpirationTimeValidator(time.Unix(now.Unix()+int64(24*time.Hour), 0)), jwt.ErrExpValidation},
		{"exp", (&jwt.Payload{}).ExpirationTimeValidator(time.Now()), jwt.ErrExpValidation},
		{"nbf", (&jwt.Payload{NotBefore: nbf}).NotBeforeValidator(now), jwt.ErrNbfValidation},
		{"nbf", (&jwt.Payload{NotBefore: nbf}).NotBeforeValidator(time.Unix(now.Unix()+int64(15*time.Second), 0)), nil},
		{"nbf", (&jwt.Payload{NotBefore: nbf}).NotBeforeValidator(time.Unix(now.Unix()-int64(15*time.Second), 0)), jwt.ErrNbfValidation},
		{"nbf", (&jwt.Payload{}).NotBeforeValidator(time.Now()), nil},
		{"iat", (&jwt.Payload{IssuedAt: iat}).IssuedAtValidator(now), nil},
		{"iat", (&jwt.Payload{IssuedAt: iat}).IssuedAtValidator(time.Unix(now.Unix()+1, 0)), nil},
		{"iat", (&jwt.Payload{IssuedAt: iat}).IssuedAtValidator(time.Unix(now.Unix()-1, 0)), jwt.ErrIatValidation},
		{"iat", (&jwt.Payload{}).IssuedAtValidator(time.Now()), nil},
		{"jti", (&jwt.Payload{JWTID: jti}).JWTIDValidator("jti"), nil},
		{"jti", (&jwt.Payload{JWTID: jti}).JWTIDValidator("not_jti"), jwt.ErrJtiValidation},
	}
	for _, tc := range testCases {
		t.Run(tc.claim, func(t *testing.T) {
			if want, got := tc.err, tc.vl(); want != got {
				t.Errorf("want %v, got %v", want, got)
			}
		})
	}
}
