// Package cache is copied from https://github.com/zpatrick/go-cache
package cache

import (
	"math/rand"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestClear(t *testing.T) {
	c := New()
	for i := 0; i < 10; i++ {
		c.IncrementCounter(strconv.Itoa(i), 0)
	}

	c.Clear()

	if keys := c.Keys(); len(keys) != 0 {
		t.Errorf("Cache should have been empty, had keys: %v", keys)
	}
}

func TestDelete(t *testing.T) {
	c := New()
	c.IncrementCounter("1", 0)
	c.Delete("1")

	if _, exists := c.GetOK("1"); exists {
		t.Errorf("Entry for key '1' should not exist")
	}
}

func TestGet(t *testing.T) {
	c := New()
	c.IncrementCounter("1", 0)

	if result, expected := c.Get("1"), 1; !reflect.DeepEqual(result, expected) {
		t.Errorf("Result for entry '1' was %#v, expected %#v", result, expected)
	}

	if result := c.Get("2"); result > 0 {
		t.Errorf("Result for entry '2' was %#v, expected nil", result)
	}
}

func TestGetOK(t *testing.T) {
	c := New()
	c.IncrementCounter("1", 0)

	result, exists := c.GetOK("1")
	if !exists {
		t.Error("Entry for key '1' should exist")
	}

	if expected := 1; !reflect.DeepEqual(result, expected) {
		t.Errorf("Entry for key '1' was %#v, expected %#v", result, expected)
	}

	if _, exists := c.GetOK("2"); exists {
		t.Errorf("Entry for key '2' should not exist")
	}
}

func TestItems(t *testing.T) {
	c := New()
	for i := 0; i < 5; i++ {
		c.IncrementCounter(strconv.Itoa(i), 0)
	}

	expected := map[string]int{
		"0": 1,
		"1": 1,
		"2": 1,
		"3": 1,
		"4": 1,
	}

	if result := c.Items(); !reflect.DeepEqual(result, expected) {
		t.Errorf("Result was %#v, expected %#v", result, expected)
	}
}

func TestKeys(t *testing.T) {
	c := New()
	for i := 0; i < 5; i++ {
		c.IncrementCounter(strconv.Itoa(i), 0)
	}

	expected := []string{"0", "1", "2", "3", "4"}
	if result := c.Keys(); !reflect.DeepEqual(result, expected) {
		t.Errorf("Result was %#v, expected %#v", result, expected)
	}
}

func TestStressConcurrentAccess(t *testing.T) {
	c := New()

	done := make(chan bool)
	for i := 0; i < 1000; i++ {
		go func() {
			key := strconv.Itoa(rand.Int())

			switch rand.Intn(7) {
			case 0:
				c.Clear()
			case 1:
				c.Delete(key)
			case 2:
				c.Get(key)
			case 3:
				c.GetOK(key)
			case 4:
				c.Items()
			case 5:
				c.Keys()
			case 6:
				_, err := c.IncrementCounter(key, time.Nanosecond*5)
				if err != nil {
					t.Errorf("IncrementCounter returned an error for a new key")
				}
			}

			done <- true
		}()
	}

	for i := 0; i < 1000; i++ {
		<-done
	}
}

func TestStressConcurrentIncrement(t *testing.T) {
	c := New()
	done := make(chan bool)
	for i := 0; i < 1000; i++ {
		go func(i int) {
			key := strconv.Itoa(i)
			_, err := c.IncrementCounter(key, 0)
			if err != nil {
				t.Errorf("IncrementCounter returned an error for a new key: %s, error: %#v", key, err)
			}
			for j := 0; j < 4; j++ {
				_, err := c.IncrementCounter(key, 0)
				if err != nil {
					t.Errorf("IncrementCounter returned an error when incrementing the key before its max uses. key=%s", key)
				}
			}
			_, err = c.IncrementCounter(key, 0)
			if err == nil {
				t.Errorf("IncrementCounter did not return an error when max uses was exceeded. key=%s", key)
			} else if err != ErrJTIUsageExceededValidation {
				t.Errorf("IncrementCounter returned the wrong error. Expected %#v but got %#v", ErrJTIUsageExceededValidation, err)
			}
			done <- true
		}(i)
	}
	for i := 0; i < 1000; i++ {
		<-done
	}
}

func benchmarkDelete(count int, b *testing.B) {
	c := New()

	for n := 0; n < b.N; n++ {
		for i := 0; i < count; i++ {
			c.Delete(strconv.Itoa(i))
		}
	}
}

func BenchmarkDelete1(b *testing.B)     { benchmarkDelete(1, b) }
func BenchmarkDelete10(b *testing.B)    { benchmarkDelete(10, b) }
func BenchmarkDelete100(b *testing.B)   { benchmarkDelete(100, b) }
func BenchmarkDelete1000(b *testing.B)  { benchmarkDelete(1000, b) }
func BenchmarkDelete10000(b *testing.B) { benchmarkDelete(10000, b) }

func benchmarkGet(count int, b *testing.B) {
	c := New()

	for n := 0; n < b.N; n++ {
		for i := 0; i < count; i++ {
			c.Get(strconv.Itoa(i))
		}
	}
}

func BenchmarkGet1(b *testing.B)     { benchmarkGet(1, b) }
func BenchmarkGet10(b *testing.B)    { benchmarkGet(10, b) }
func BenchmarkGet100(b *testing.B)   { benchmarkGet(100, b) }
func BenchmarkGet1000(b *testing.B)  { benchmarkGet(1000, b) }
func BenchmarkGet10000(b *testing.B) { benchmarkGet(10000, b) }

func benchmarkIncrement(count int, b *testing.B) {
	c := New()

	for n := 0; n < b.N; n++ {
		for i := 0; i < count; i++ {
			c.IncrementCounter(strconv.Itoa(i), 0)
		}
	}
}

func BenchmarkIncrement1(b *testing.B)     { benchmarkIncrement(1, b) }
func BenchmarkIncrement10(b *testing.B)    { benchmarkIncrement(10, b) }
func BenchmarkIncrement100(b *testing.B)   { benchmarkIncrement(100, b) }
func BenchmarkIncrement1000(b *testing.B)  { benchmarkIncrement(1000, b) }
func BenchmarkIncrement10000(b *testing.B) { benchmarkIncrement(10000, b) }
