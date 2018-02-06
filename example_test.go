package jwt_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/gbrlsnchs/jwt"
	"github.com/gbrlsnchs/jwt/jwtcrypto/hmacsha"
	"github.com/gbrlsnchs/jwt/jwtutil"
)

func ExampleSign() {
	claims := &jwt.Claims{
		Standard: &jwt.StdClaims{
			ExpirationTime: time.Now().Add(24 * time.Hour).Unix(),
		},
		Public: jwt.Payload{
			"admin": true,
		},
	}
	token, err := jwt.Sign(hmacsha.New512("foobar_sounds_safe"), &jwt.JWT{Claims: claims})

	if err != nil {
		// ...
	}

	fmt.Println(token)
}

func ExampleParse() {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	s := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M"

	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s))

	token, err := jwtutil.BearerToken(r)

	if err != nil {
		// Token could not be extracted.
	}

	jot, err := jwt.Parse(token, hmacsha.New256("foobar_sounds_safe"))

	if err != nil {
		// Unable to parse, can be due to malformed token.
	}

	fmt.Printf("%#v\n", jot)
}
