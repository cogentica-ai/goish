// gen_signal_order_ref — does Go guarantee the ORDER in which several
// distinct pending signals reach a channel, and does it coalesce
// repeats?
//
//   scripts/goref.sh os/signal tools/gen_signal_order_ref.go
//
// goish's e2e failed with got=[USR2 WINCH USR1] where Go prints
// [USR1 USR2 WINCH]. Before changing goish's relay, establish whether
// Go's order is a guarantee or a coincidence: run it many times and see
// whether it ever varies.
package signal

import (
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestGoishRef(t *testing.T) {
	me := func(s syscall.Signal) { syscall.Kill(syscall.Getpid(), s) }

	// 1. Order, over many trials. Raised low, middle, high by number.
	orders := map[string]int{}
	for trial := 0; trial < 200; trial++ {
		c := make(chan os.Signal, 8)
		Notify(c)
		me(syscall.SIGUSR1)  // 10
		me(syscall.SIGUSR2)  // 12
		me(syscall.SIGWINCH) // 28
		time.Sleep(50 * time.Millisecond)
		got := ""
		for len(c) > 0 {
			got += (<-c).String() + "|"
		}
		orders[got]++
		Stop(c)
	}
	fmt.Printf("distinct_orders %d\n", len(orders))
	for k, v := range orders {
		fmt.Printf("order %-70s n=%d\n", k, v)
	}

	// 2. Raised HIGH to LOW: if the order were arrival order it would
	//    come back reversed; if it is signal-number order it would not.
	orders2 := map[string]int{}
	for trial := 0; trial < 200; trial++ {
		c := make(chan os.Signal, 8)
		Notify(c)
		me(syscall.SIGWINCH)
		me(syscall.SIGUSR2)
		me(syscall.SIGUSR1)
		time.Sleep(50 * time.Millisecond)
		got := ""
		for len(c) > 0 {
			got += (<-c).String() + "|"
		}
		orders2[got]++
		Stop(c)
	}
	fmt.Printf("reversed_distinct_orders %d\n", len(orders2))
	for k, v := range orders2 {
		fmt.Printf("reversed_order %-70s n=%d\n", k, v)
	}

	// 3. Coalescing: the same signal several times into a roomy channel.
	counts := map[int]int{}
	for trial := 0; trial < 100; trial++ {
		c := make(chan os.Signal, 16)
		Notify(c, syscall.SIGUSR1)
		for i := 0; i < 5; i++ {
			me(syscall.SIGUSR1)
		}
		time.Sleep(50 * time.Millisecond)
		counts[len(c)]++
		Stop(c)
	}
	fmt.Printf("repeat_delivery_counts %v\n", counts)
}
