package jwt_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/gbrlsnchs/jwt"
)

func Example() {
	// Timestamp the exact moment this function runs
	// for validating purposes.
	now := time.Now()
	// Mock an HTTP request for showing off token extraction.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// Build JWT from the incoming request.
	jot, err := jwt.FromRequest(r)

	if err != nil {
		// Handle malformed token...
	}

	if err = jot.Verify(jwt.HS256("secret")); err != nil {
		// Handle verification error...
	}

	// Define validators for validating the JWT. If desired, there
	// could be custom validators too, e.g. to validate public claims.
	algValidator := jwt.AlgorithmValidator(jwt.MethodHS256)
	audValidator := jwt.AudienceValidator("test")
	expValidator := jwt.ExpirationTimeValidator(now)

	if err = jot.Validate(algValidator, audValidator, expValidator); err != nil {
		switch err {
		case jwt.ErrAlgorithmMismatch:
			// Handle "alg" mismatch...

		case jwt.ErrAudienceMismatch:
			// Handle "aud" mismatch...

		case jwt.ErrTokenExpired:
			// Handle "exp" being expired...
		}
	}

	// "Sign" issues a raw string, but if desired, one could also
	// use "FromString" method to have a JWT object.
	token, err := jwt.Sign(jwt.HS256("secret"), &jwt.Options{Timestamp: true})

	if err != nil {
		// ...
	}

	auth := fmt.Sprintf("Bearer %s", token)

	w.Header().Set("Authorization", auth)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(token))
}

func ExampleFromString() {
	jot, err := jwt.FromString("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M")

	if err != nil {
		// Handle malformed token...
	}

	if err = jot.Verify(jwt.HS256("secret")); err != nil {
		// Handle verification error...
	}

	fmt.Println(jot)
}

func ExampleSign() {
	nextYear := time.Now().Add(24 * 30 * 12 * time.Hour)
	token, err := jwt.Sign(jwt.HS256("secret"), &jwt.Options{ExpirationTime: nextYear})

	if err != nil {
		// ...
	}

	fmt.Println(token)
}
