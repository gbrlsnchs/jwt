package jwt

import "hash"

type poolHash struct {
	hash.Hash
	pool *pool
}

func (ph *poolHash) sign(payload []byte) ([]byte, error) {
	defer func() {
		ph.pool.put(ph)
	}()
	if _, err := ph.Write(payload); err != nil {
		return nil, err
	}
	return ph.Sum(nil), nil
}
