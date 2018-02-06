package jwtutil

import (
	"errors"
	"net/http"
	"strings"
)

// BearerToken parses the Authorization HTTP header
// and retrieves only the token from it.
func BearerToken(r *http.Request) (string, error) {
	bearer := r.Header.Get("Authorization")
	parts := strings.Split(bearer, Separator)

	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("github.com/gbrlsnchs/jwt/jwtutil.Extract: malformed Authorization header")
	}

	return parts[1], nil
}
