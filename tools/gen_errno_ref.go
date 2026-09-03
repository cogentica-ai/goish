package syscall_test

import (
	"fmt"
	"syscall"
	"testing"
)

func TestGoishRef(t *testing.T) {
	for _, n := range []int{0, 1, 2, 4, 9, 11, 12, 13, 17, 20, 21, 22, 23, 24, 32, 38, 39, 95, 98, 99, 103, 104, 105, 110, 111} {
		e := syscall.Errno(n)
		fmt.Printf("errno %-4d %-34q timeout=%-5v temporary=%v\n", n, e.Error(), e.Timeout(), e.Temporary())
	}
}
