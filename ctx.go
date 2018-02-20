package jwt

var ctxKey interface{}

// SetCtxKey sets a context key for storing
// and retrieving a JWT in a context object.
func SetCtxKey(v interface{}) {
	if ctxKey != nil {
		return
	}

	ctxKey = v
}
