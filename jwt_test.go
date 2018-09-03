package jwt_test

import . "github.com/gbrlsnchs/jwt/v2"

type testToken struct {
	*JWT
	Name string `json:"name,omitempty"`
}
