// Package cache is copied from https://github.com/zpatrick/go-cache
package cache

import "time"

// A SetOption will perform logic after a set action completes
type SetOption func(c *Cache, key string, val int)

// Expire is a SetOption that will cause the entry to expire after the specified duration
func Expire(expiry time.Duration) SetOption {
	return func(c *Cache, key string, val int) {
		c.expiryOps <- func(expiries map[string]*time.Timer) {
			if timer, ok := expiries[key]; ok {
				timer.Stop()
			}

			expiries[key] = time.AfterFunc(expiry, func() { c.Delete(key) })
		}
	}
}
