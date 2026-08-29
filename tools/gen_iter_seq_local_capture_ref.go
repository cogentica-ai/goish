// Command gen_iter_seq_local_capture_ref records Go's behavior for ordinary
// stateful iter.Seq and iter.Seq2 closures.
package main

import (
	"fmt"
	"iter"
)

func localSeq(calls *int) iter.Seq[int] {
	return func(yield func(int) bool) {
		*calls++
		yield(*calls)
	}
}

func localSeq2(calls *int) iter.Seq2[int, int] {
	return func(yield func(int, int) bool) {
		*calls++
		yield(*calls, *calls*2)
	}
}

func main() {
	calls := 0
	first := 0
	localSeq(&calls)(func(value int) bool {
		first = value
		return true
	})
	pairKey, pairValue := 0, 0
	localSeq2(&calls)(func(key, value int) bool {
		pairKey, pairValue = key, value
		return true
	})
	fmt.Println(first, pairKey, pairValue)
}
