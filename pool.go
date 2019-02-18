package jwt

import (
	"errors"
	"hash"
	"sync"
)

type pool struct {
	sp *sync.Pool
}

func newPool(hfunc func() (hash.Hash, error)) *pool {
	return &pool{
		sp: &sync.Pool{
			New: func() interface{} {
				hh, err := hfunc()
				if err != nil {
					return err
				}
				return hh
			},
		},
	}
}

func (p *pool) sign(payload []byte) ([]byte, error) {
	v := p.sp.Get()
	switch hh := v.(type) {
	case error:
		return nil, hh
	case hash.Hash:
		defer func() {
			hh.Reset() // clean hash function
			p.sp.Put(hh)
		}()
		if _, err := hh.Write(payload); err != nil {
			return nil, err
		}
		return hh.Sum(nil), nil
	default:
		return nil, errors.New("jwt: invalid value returned from pool")
	}
}
