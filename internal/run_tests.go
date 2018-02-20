package internal

import (
	"testing"

	"github.com/gbrlsnchs/jwt"
)

func RunTests(t *testing.T, tests []*TestTable) {
	for _, tt := range tests {
		token, err := jwt.Sign(tt.Signer, tt.Opts)

		if want, got := tt.SigningErr, err != nil; want != got {
			t.Errorf("jwt.Sign: want %t, got %t\n", want, got)

			if err != nil {
				t.Logf("%v\n", err)
			}

			continue
		}

		s := tt.Signer

		if tt.Verif != nil {
			s = tt.Verif
		}

		jot, err := jwt.FromString(token)

		if err != nil {
			t.Errorf("%v\n", err)

			continue
		}

		if want, got := tt.ParsingErr, jot.Verify(s) != nil; want != got {
			t.Errorf("jwt.(*JWT).Verify: want %t, got %t\n", want, got)

			if err != nil {
				t.Logf("%v\n", err)
			}

			continue
		}

		t.Logf("Token + %s: %s\n", tt.Signer.String(), jot.String())
	}
}
