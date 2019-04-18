package jwt

type Validator interface {
	Validate(...ValidatorFunc) error
}
