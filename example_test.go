package jwt_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/gbrlsnchs/jwt"
)

func Example() {
	now := time.Now()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	jot, err := jwt.FromRequest(r, jwt.HS256("secret"))

	if err != nil {
		// ...
	}

	if jot.Algorithm() != jwt.MethodHS256 ||
		!jot.ExpirationTime().IsZero() &&
			now.After(jot.ExpirationTime()) ||
		now.Before(jot.NotBefore()) {
		// Repudiate token.
	}

	token, err := jwt.Sign(jwt.HS256("secret"), &jwt.Options{Timestamp: true})

	if err != nil {
		// ...
	}

	w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", token))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(token))
}

func ExampleParse() {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M"
	jot, err := jwt.Parse(jwt.HS256("secret"), token)

	if err != nil {
		// ...
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
