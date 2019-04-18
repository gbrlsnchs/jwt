package jwt_test

import (
	"math"
	"math/rand"
	"time"

	. "github.com/gbrlsnchs/jwt/v3"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type testPayload struct {
	Payload
	CustomField1 string  `json:"customField1,omitempty"`
	CustomField2 int     `json:"customField2,omitempty"`
	CustomField3 float64 `json:"customField3,omitempty"`
}

type payloadTestSuite struct {
	suite.Suite

	s  Signer
	vr Verifier

	signErr   error
	decodeErr error

	h Header
	p testPayload
}

func (ts *payloadTestSuite) SetupTest() {
	now := time.Now()
	tname := ts.T().Name()
	ts.h = Header{
		Algorithm:   ts.s.String(),
		Type:        "JWT",
		KeyID:       tname,
		ContentType: "JWT",
	}
	ts.p = testPayload{
		Payload: Payload{
			IssuedAt:       now.Unix(),
			ExpirationTime: now.Add(30 * time.Minute).Unix(),
			NotBefore:      now.Add(1 * time.Second).Unix(),
			Issuer:         "test_iss",
			Audience:       Audience{"test_aud"},
			Subject:        "test_sub",
			JWTID:          "test_jti",
		},
		CustomField1: tname,
		CustomField2: rand.Intn(math.MaxUint32),
		CustomField3: rand.Float64() * 100,
	}
}

func (ts *payloadTestSuite) TestPayload() {
	assert := require.New(ts.T())

	token, err := Sign(ts.h, ts.p, ts.s)
	assert.Equal(ts.signErr, err)
	if err != nil {
		return
	}

	var (
		tp  testPayload
		dec = NewDecoder(token, ts.vr)
	)
	err = dec.Decode(&tp)
	assert.Equal(ts.decodeErr, err)
	if err != nil {
		return
	}

	assert.Equal(ts.h, dec.Header())
	assert.Equal(ts.p, tp)
}
