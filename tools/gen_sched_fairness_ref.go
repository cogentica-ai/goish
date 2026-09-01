package runtime_test

import (
	"fmt"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// runtime.Gosched yields the processor. A goroutine looping on it
// must not starve anyone: goschedImpl puts the yielding G on the
// GLOBAL run queue, behind every other runnable G, rather than back
// on its own P's local queue where the same M would pick it up again.
//
// The numbers below are what Go actually delivers, so the goish smoke
// can assert a bound rather than a guess.
func TestGoishRef(t *testing.T) {
	var stop atomic.Bool
	for i := 0; i < 2; i++ {
		go func() {
			for !stop.Load() {
				runtime.Gosched()
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)

	// A plain sleep alongside the spinners.
	s0 := time.Now()
	time.Sleep(200 * time.Millisecond)
	sleepNs := time.Since(s0).Nanoseconds()

	// A dial + accept alongside the spinners.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, e := ln.Accept()
		if e == nil {
			time.Sleep(300 * time.Millisecond)
			c.Close()
		}
	}()
	d0 := time.Now()
	c, err := net.Dial("tcp", ln.Addr().String())
	dialNs := time.Since(d0).Nanoseconds()
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	stop.Store(true)

	fmt.Printf("sleep_200ms_took_ms %d\n", sleepNs/1e6)
	fmt.Printf("dial_took_ms %d\n", dialNs/1e6)
	fmt.Printf("sleep_within_2x %v\n", sleepNs < 400*1e6)
	fmt.Printf("dial_under_200ms %v\n", dialNs < 200*1e6)
}
