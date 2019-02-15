package jwt

// JWT is a JSON Web Token as per the RFC 7519.
//
// Fields are ordered according to the RFC 7519 order.
type JWT struct {
	Header `json:"-"`
	*Claims
}

var (
	_ Token = &JWT{}                 // compile-time check of Token interface by JWT
	_ Token = &struct{ JWT }{JWT{}}  // compile-time check of Token interface by embedded JWT
	_ Token = struct{ *JWT }{&JWT{}} // compile-time check of Token interface by embedded JWT pointer
)

// HeaderAddr returns the JWT header's address.
// This is needed in order to implement the Token interface.
func (jot *JWT) HeaderAddr() *Header {
	return &jot.Header
}

// Validate validates claims and header fields.
func (jot *JWT) Validate(validators ...ValidatorFunc) error {
	for _, v := range validators {
		if err := v(jot); err != nil {
			return err
		}
	}
	return nil
}
