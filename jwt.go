package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

var enc = base64.RawURLEncoding

type JWT struct {
	*Header
	*Claims
	nested bool // avoids nested JWT infinite loop
}

var (
	// ErrMalformedToken indicates a token doesn't have
	// a valid format, as per the RFC 7519, section 7.2.
	ErrMalformedToken = errors.New("jwt: malformed token")
	ErrNilHeader      = errors.New("jwt: nil header")
	ErrBigNest        = errors.New("jwt: more than one nested JWT")
)

// MarshalJWT implements JWT marshaling.
func (jot *JWT) MarshalJWT() (payload []byte, err error) {
	if jot.Header == nil {
		return nil, ErrNilHeader
	}
	jot.header = &header{"JWT"}
	hdr, err := json.Marshal(jot.Header)
	if err != nil {
		return nil, err
	}
	hdrSize := enc.EncodedLen(len(hdr))

	if jot.Claims != nil {
		jot.claims = &claims{}
		if t := jot.IssuedAt; !t.IsZero() {
			jot.Iat = t.Unix()
		}
		if t := jot.Expiration; !t.IsZero() {
			jot.Exp = t.Unix()
		}
		if t := jot.NotBefore; !t.IsZero() {
			jot.Nbf = t.Unix()
		}
	}
	cls, err := json.Marshal(jot.Claims)
	if err != nil {
		return nil, err
	}
	clsSize := enc.EncodedLen(len(cls))

	payload = make([]byte, hdrSize+1+clsSize)
	enc.Encode(payload, hdr)
	payload[hdrSize] = '.'
	enc.Encode(payload[hdrSize+1:], cls)
	return payload, nil
}

// UnmarshalJWT implements JWT unmarshaling.
func (jot *JWT) UnmarshalJWT(b []byte) error {
	if jot == nil {
		jot = &JWT{}
	}
	sep := bytes.IndexByte(b, '.')
	if sep < 0 { // RFC 7519, section 7.2.1
		return ErrMalformedToken
	}
	var err error

	encHdr := b[:sep] // RFC 7519, section 7.2.2
	hdrSize := enc.DecodedLen(len(encHdr))
	decHdr := make([]byte, hdrSize)
	if _, err = enc.Decode(decHdr, encHdr); err != nil { // RFC 7519, section 7.2.3
		return err
	}
	var hdr Header
	hdr.header = &header{}
	if err = json.Unmarshal(decHdr, &hdr); err != nil { // RFC 7519, sections 7.2.{4,5,6,7,8}
		return err
	}

	encCls := b[sep+1:]
	if hdr.ContentType == "JWT" {
		if jot.nested {
			return ErrBigNest
		}
		jot.nested = true
		return jot.UnmarshalJWT(encCls)
	}
	clsSize := enc.DecodedLen(len(encCls))
	decCls := make([]byte, clsSize)
	if _, err = enc.Decode(decCls, encCls); err != nil {
		return err
	}
	var cls Claims
	cls.claims = &claims{}
	jot.Claims = &cls
	if err = json.Unmarshal(decCls, jot); err != nil {
		return err
	}
	if jot.Iat > 0 {
		jot.IssuedAt = time.Unix(jot.Iat, 0)
	}
	if jot.Exp > 0 {
		jot.Expiration = time.Unix(jot.Exp, 0)
	}
	if jot.Nbf > 0 {
		jot.NotBefore = time.Unix(jot.Nbf, 0)
	}
	jot.Header = &hdr
	return nil
}

func (jot *JWT) Validate(validators ...ValidatorFunc) error {
	for _, fn := range validators {
		if err := fn(jot); err != nil {
			return err
		}
	}
	return nil
}
