package jwt_test

import (
	. "github.com/gbrlsnchs/jwt"
)

type testToken struct {
	*JWT
	Name string `json:"name,omitempty"`
}
