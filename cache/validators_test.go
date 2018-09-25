package cache

import (
	"testing"

	jwt "github.com/gbrlsnchs/jwt/v2"
)

func TestValidatorWithNoJTIClaim(t *testing.T) {
	cache := New()
	err := IDValidator(cache)(&jwt.JWT{})
	if err != ErrJTIRequiredValidation {
		t.Errorf("want %v, got %v", ErrJTIRequiredValidation, err)
	}
}

func TestValidatorWithJTIClaim(t *testing.T) {
	cache := NewWithMaxUsesAndDefaultTTL(1, DefaultTTL)
	validator := IDValidator(cache)
	jot := &jwt.JWT{ID: "jti"}
	err := validator(jot)
	if err != nil {
		t.Errorf("err should be nil but was %v", err)
	}
	err = validator(jot)
	if err != ErrJTIUsageExceededValidation {
		t.Errorf("want %v, got %v", ErrJTIUsageExceededValidation, err)
	}
}
