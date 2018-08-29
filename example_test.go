package jwt_test

import (
	"fmt"
	"time"

	"github.com/gbrlsnchs/jwt"
)

func Example() {
	sig := jwt.HS256("mySecret")
	type AuthToken struct {
		*jwt.JWT
		MyField string `json:"myField,omitempty"`
		MyValue int    `json:"myValue,omitempty"`
	}
	now := time.Now()
	token := &AuthToken{
		JWT: &jwt.JWT{
			Header: &jwt.Header{
				Algorithm: sig.String(),
			},
			Claims: &jwt.Claims{
				Expiration: now.Add(24 * 30 * 12 * time.Hour),
			},
		},
		MyField: "my_field",
		MyValue: 413,
	}
	s, err := sig.Sign(token)
	fmt.Println(err)
	fmt.Printf("%s\n", s)
}
