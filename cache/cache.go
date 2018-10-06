// Package cache is copied from https://github.com/zpatrick/go-cache
package cache

import (
	"sort"
	"time"
)

// DefaultTTL is 24 hours.
var DefaultTTL = 24 * time.Hour

// A Cache is a thread-safe store for fast item storage and retrieval
type Cache struct {
	itemOps    chan func(map[string]int)
	expiryOps  chan func(map[string]*time.Timer)
	maxUses    int
	defaultTTL time.Duration
}

// New returns an empty cache with max uses set to 5.
func New() *Cache {
	return NewWithMaxUsesAndDefaultTTL(5, DefaultTTL)
}

// NewWithMaxUsesAndDefaultTTL returns an empty cache with the specified max uses.
func NewWithMaxUsesAndDefaultTTL(maxUses int, defaultTTL time.Duration) *Cache {
	c := &Cache{
		itemOps:    make(chan func(map[string]int)),
		expiryOps:  make(chan func(map[string]*time.Timer)),
		maxUses:    maxUses,
		defaultTTL: defaultTTL,
	}

	go c.loopItemOps()
	go c.loopExpiryOps()
	return c
}

func (c *Cache) loopItemOps() {
	items := map[string]int{}
	for op := range c.itemOps {
		op(items)
	}
}

func (c *Cache) loopExpiryOps() {
	expiries := map[string]*time.Timer{}
	for op := range c.expiryOps {
		op(expiries)
	}
}

// IncrementCounter increments the counter for a given key.
func (c *Cache) IncrementCounter(key string, expiry time.Duration) (int, error) {

	var val int
	var err error

	done := make(chan bool)

	c.itemOps <- func(items map[string]int) {
		var keyExists bool
		val, keyExists = items[key]
		val = 1 + val
		if val > c.maxUses {
			err = ErrJTIUsageExceededValidation
		}
		items[key] = val
		if !keyExists {
			c.expiryOps <- func(expiries map[string]*time.Timer) {
				if timer, ok := expiries[key]; ok {
					timer.Stop()
					delete(expiries, key)
				}
			}
		}
		close(done)
	}
	<-done
	if err == nil {
		var expireOption SetOption
		if expiry > 0 {
			expireOption = Expire(expiry)
		} else {
			expireOption = Expire(c.defaultTTL)
		}
		expireOption(c, key, val)
	}

	return val, err
}

// Clear removes all entries from the cache
func (c *Cache) Clear() {
	c.itemOps <- func(items map[string]int) {
		for key := range items {
			delete(items, key)
		}
	}
}

// Delete removes an entry from the cache at the specified key.
// If no entry exists at the specified key, no action is taken
func (c *Cache) Delete(key string) {
	c.itemOps <- func(items map[string]int) {
		if _, ok := items[key]; ok {
			delete(items, key)
		}
	}
}

// Get retrieves an entry at the specified key
func (c *Cache) Get(key string) int {
	result := make(chan int, 1)
	c.itemOps <- func(items map[string]int) {
		result <- items[key]
	}

	return <-result
}

// GetOK retrieves an entry at the specified key.
// Returns bool specifying if the entry exists
func (c *Cache) GetOK(key string) (int, bool) {
	result := make(chan int, 1)
	exists := make(chan bool, 1)
	c.itemOps <- func(items map[string]int) {
		v, ok := items[key]
		result <- v
		exists <- ok
	}

	return <-result, <-exists
}

// Items retrieves all entries in the cache
func (c *Cache) Items() map[string]int {
	result := make(chan map[string]int, 1)
	c.itemOps <- func(items map[string]int) {
		cp := map[string]int{}
		for key, val := range items {
			cp[key] = val
		}

		result <- cp
	}

	return <-result
}

// Keys retrieves a sorted list of all keys in the cache
func (c *Cache) Keys() []string {
	result := make(chan []string, 1)
	c.itemOps <- func(items map[string]int) {
		keys := make([]string, 0, len(items))
		for k := range items {
			keys = append(keys, k)
		}

		sort.Strings(keys)
		result <- keys
	}

	return <-result
}
