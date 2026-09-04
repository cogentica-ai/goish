package sync_test

import (
	"fmt"
	"sync"
	"testing"
)

// The deterministic, single-threaded half of the sync primitives: the
// TryLock family's answers, RWMutex's reader/writer exclusion, and
// WaitGroup's counter reaching zero. The blocking half needs real
// contention and is not what this pins.
func TestGoishRef(t *testing.T) {
	// Mutex.TryLock succeeds on a free mutex and fails on a held one.
	var mu sync.Mutex
	fmt.Printf("mutex trylock-free=%v\n", mu.TryLock())
	fmt.Printf("mutex trylock-held=%v\n", mu.TryLock())
	mu.Unlock()
	fmt.Printf("mutex trylock-after-unlock=%v\n", mu.TryLock())
	mu.Unlock()

	// RWMutex: many readers, no writer alongside them.
	var rw sync.RWMutex
	fmt.Printf("rw tryrlock-free=%v\n", rw.TryRLock())
	fmt.Printf("rw tryrlock-second=%v\n", rw.TryRLock())
	fmt.Printf("rw trylock-while-read-held=%v\n", rw.TryLock())
	rw.RUnlock()
	fmt.Printf("rw trylock-one-reader-left=%v\n", rw.TryLock())
	rw.RUnlock()
	fmt.Printf("rw trylock-no-readers=%v\n", rw.TryLock())
	fmt.Printf("rw tryrlock-while-write-held=%v\n", rw.TryRLock())
	fmt.Printf("rw trylock-while-write-held=%v\n", rw.TryLock())
	rw.Unlock()
	fmt.Printf("rw tryrlock-after-unlock=%v\n", rw.TryRLock())
	rw.RUnlock()

	// A fresh RWMutex allows a writer straight away.
	var rw2 sync.RWMutex
	fmt.Printf("rw2 trylock-fresh=%v\n", rw2.TryLock())
	rw2.Unlock()

	// WaitGroup: Wait on a zero counter returns immediately, and Done
	// brings a positive counter back to zero.
	var wg sync.WaitGroup
	wg.Wait()
	fmt.Printf("wg wait-on-zero=returned\n")

	wg.Add(2)
	wg.Done()
	wg.Done()
	wg.Wait()
	fmt.Printf("wg add2-done2=returned\n")

	// Add can take a negative delta directly, as long as the counter
	// does not go below zero.
	wg.Add(3)
	wg.Add(-3)
	wg.Wait()
	fmt.Printf("wg add-negative=returned\n")

	// WaitGroup.Go (Go 1.25) increments the counter and runs f in a new
	// goroutine; Wait then blocks until it finishes.
	var wg2 sync.WaitGroup
	ran := make(chan int, 3)
	for i := 0; i < 3; i++ {
		wg2.Go(func() { ran <- 1 })
	}
	wg2.Wait()
	close(ran)
	n := 0
	for range ran {
		n++
	}
	fmt.Printf("wg go-count=%d\n", n)

	// Reuse after Wait is allowed.
	wg2.Add(1)
	wg2.Done()
	wg2.Wait()
	fmt.Printf("wg reuse=returned\n")
}
