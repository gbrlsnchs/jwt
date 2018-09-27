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

func stressTestValidator(b *testing.B, maxUses int, numAttempts int) {
	errorChannel := make(chan error)
	startingPistol := make(chan bool)
	cache := NewWithMaxUsesAndDefaultTTL(maxUses, DefaultTTL)
	validator := IDValidator(cache)
	jot := &jwt.JWT{ID: "jti"}
	for i := 0; i < numAttempts; i++ {
		go func(token *jwt.JWT, validator jwt.ValidatorFunc, startingPistol chan bool, errorChannel chan error) {
			<-startingPistol
			errorChannel <- validator(token)
		}(jot, validator, startingPistol, errorChannel)
	}
	close(startingPistol)
	errorCount := 0
	for i := 0; i < numAttempts; i++ {
		err := <-errorChannel
		if err != nil {
			errorCount++
		}
	}
	close(errorChannel)
	if numAttempts > maxUses {
		if errorCount != numAttempts-maxUses {
			b.Errorf("Expected %d validator errors but got %d", numAttempts-maxUses, errorCount)
		}
	} else {
		if errorCount > 0 {
			b.Errorf("Expected no validator errors but got %d", errorCount)
		}
	}
}

func BenchmarkValidator1_2(b *testing.B)         { stressTestValidator(b, 1, 2) }
func BenchmarkValidator100_1000(b *testing.B)    { stressTestValidator(b, 100, 1000) }
func BenchmarkValidator5000_10000(b *testing.B)  { stressTestValidator(b, 5000, 10000) }
func BenchmarkValidator10000_10000(b *testing.B) { stressTestValidator(b, 10000, 10000) }
