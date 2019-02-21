package jwt

// Token is an ad hoc interface that makes defining custom claims
// easier by allowing signing any structs that embed the JWT struct.
//
// TODO(gbrlsnchs): if contracts ever become a real thing, use them
// to accept any structs that have a Header field or something similar.
type Token interface {
	HeaderAddr() *Header
}
