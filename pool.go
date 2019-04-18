package jwt

import (
	"hash"
	"sync"
)

type pool struct {
	*sync.Pool
}

func newPool(hfunc func() hash.Hash) *pool {
	var p pool
	p.Pool = &sync.Pool{New: func() interface{} { return hfunc() }}
	return &p
}

func (p *pool) sign(payload []byte) ([]byte, error) {
	hh := p.Pool.Get().(hash.Hash)
	defer func() {
		hh.Reset()
		p.Pool.Put(hh)
	}()

	if _, err := hh.Write(payload); err != nil {
		return nil, err
	}
	return hh.Sum(nil), nil
}
