package jwt

type raw struct {
	token      []byte
	sep1, sep2 int
}

func (r *raw) claims() []byte  { return r.token[r.sep1+1 : r.sep2] }
func (r *raw) header() []byte  { return r.token[:r.sep1] }
func (r *raw) payload() []byte { return r.token[:r.sep2] }
func (r *raw) sig() []byte     { return r.token[r.sep2+1:] }
