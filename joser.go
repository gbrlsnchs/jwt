package jwt

type joser interface {
	header() *header
	setHeader(*header)
}
