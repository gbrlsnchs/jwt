package internal

import "github.com/gbrlsnchs/jwt"

type TestTable struct {
	Signer     jwt.Signer
	Verif      jwt.Signer
	ParsingErr bool
	SigningErr bool
	Opts       *jwt.Options
}
