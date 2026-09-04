package time_test

import (
	"fmt"
	"testing"
	"time"
)

func TestGoishRef(t *testing.T) {
	// Timer.Reset return value: true if the timer was active.
	{
		tm := time.NewTimer(50 * time.Millisecond)
		fmt.Printf("reset-active   %v\n", tm.Reset(50*time.Millisecond))
		tm.Stop()
	}
	{
		tm := time.NewTimer(50 * time.Millisecond)
		tm.Stop()
		fmt.Printf("reset-stopped  %v\n", tm.Reset(50*time.Millisecond))
		tm.Stop()
	}
	{
		tm := time.NewTimer(5 * time.Millisecond)
		<-tm.C
		fmt.Printf("reset-expired  %v\n", tm.Reset(50*time.Millisecond))
		tm.Stop()
	}
	// Reset re-arms: the channel fires again on the SAME channel.
	{
		tm := time.NewTimer(5 * time.Millisecond)
		<-tm.C
		tm.Reset(5 * time.Millisecond)
		select {
		case <-tm.C:
			fmt.Printf("reset-refires  %v\n", true)
		case <-time.After(2 * time.Second):
			fmt.Printf("reset-refires  %v\n", false)
		}
	}
	// Reset lengthens a pending timer: it must NOT fire at the old time.
	{
		tm := time.NewTimer(20 * time.Millisecond)
		tm.Reset(400 * time.Millisecond)
		select {
		case <-tm.C:
			fmt.Printf("reset-extends  %v\n", false)
		case <-time.After(150 * time.Millisecond):
			fmt.Printf("reset-extends  %v\n", true)
		}
		tm.Stop()
	}
	// Ticker.Reset changes the period; ticks keep coming.
	{
		tk := time.NewTicker(400 * time.Millisecond)
		tk.Reset(10 * time.Millisecond)
		got := 0
		deadline := time.After(1 * time.Second)
	loop:
		for got < 3 {
			select {
			case <-tk.C:
				got++
			case <-deadline:
				break loop
			}
		}
		tk.Stop()
		fmt.Printf("ticker-reset   ticks>=3 %v\n", got >= 3)
	}
	// Ticker.Reset after Stop does NOT resurrect it (Go 1.15+ allows
	// Reset on a stopped ticker to restart it).
	{
		tk := time.NewTicker(10 * time.Millisecond)
		tk.Stop()
		tk.Reset(10 * time.Millisecond)
		select {
		case <-tk.C:
			fmt.Printf("ticker-restart %v\n", true)
		case <-time.After(500 * time.Millisecond):
			fmt.Printf("ticker-restart %v\n", false)
		}
		tk.Stop()
	}
}
