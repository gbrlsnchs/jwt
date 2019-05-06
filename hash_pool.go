package jwt

import (
	"hash"
	"sync"
)

type hashPool struct {
	*sync.Pool
}

func newHashPool(hfunc func() hash.Hash) *hashPool {
	return &hashPool{&sync.Pool{New: func() interface{} { return hfunc() }}}
}

func (hp *hashPool) sign(payload []byte) ([]byte, error) {
	hh := hp.Pool.Get().(hash.Hash)
	defer func() {
		hh.Reset()
		hp.Pool.Put(hh)
	}()

	if _, err := hh.Write(payload); err != nil {
		return nil, err
	}
	return hh.Sum(nil), nil
}
