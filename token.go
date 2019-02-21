package jwt

type Token interface {
	HeaderAddr() *Header // TODO(gbrlsnchs): use contracts to capture Header field
}
