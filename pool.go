package jwt

import (
	"hash"
	"sync"
)

type pool struct {
	sp *sync.Pool
}

func newPool(hfunc func() hash.Hash) *pool {
	var p pool
	p.sp = &sync.Pool{
		New: func() interface{} {
			return hfunc()
		},
	}
	return &p
}

func (p *pool) sign(payload []byte) ([]byte, error) {
	hh := p.sp.Get().(hash.Hash)
	defer func() {
		hh.Reset()
		p.sp.Put(hh)
	}()

	if _, err := hh.Write(payload); err != nil {
		return nil, err
	}
	return hh.Sum(nil), nil
}
