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
			return &poolHash{
				Hash: hfunc(),
				pool: &p,
			}
		},
	}
	return &p
}

func (p *pool) get() *poolHash {
	return p.sp.Get().(*poolHash)
}

func (p *pool) put(hh hash.Hash) {
	hh.Reset()
	p.sp.Put(hh)
}
