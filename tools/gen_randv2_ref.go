package rand_test

import (
	"fmt"
	"math/rand/v2"
	"testing"
)

// math/rand/v2's PCG is a different generator from v1's ALFG, and its
// bounded forms use Lemire's multiply-and-shift rather than v1's
// rejection loop — so the values differ from v1 at every step and a
// port that borrows v1's arithmetic looks right and is not.
func TestGoishRef(t *testing.T) {
	for _, s := range [][2]uint64{{1, 2}, {0, 0}, {42, 42}, {^uint64(0), 1}} {
		p := rand.NewPCG(s[0], s[1])
		fmt.Printf("pcg %-20d %-20d", s[0], s[1])
		for i := 0; i < 6; i++ {
			fmt.Printf(" %d", p.Uint64())
		}
		fmt.Println()
	}

	mk := func() *rand.Rand { return rand.New(rand.NewPCG(1, 2)) }

	r := mk()
	fmt.Printf("int64 ")
	for i := 0; i < 5; i++ {
		fmt.Printf(" %d", r.Int64())
	}
	fmt.Println()
	r = mk()
	fmt.Printf("uint64")
	for i := 0; i < 5; i++ {
		fmt.Printf(" %d", r.Uint64())
	}
	fmt.Println()
	r = mk()
	fmt.Printf("uint32")
	for i := 0; i < 5; i++ {
		fmt.Printf(" %d", r.Uint32())
	}
	fmt.Println()
	r = mk()
	fmt.Printf("int32 ")
	for i := 0; i < 5; i++ {
		fmt.Printf(" %d", r.Int32())
	}
	fmt.Println()
	r = mk()
	fmt.Printf("int   ")
	for i := 0; i < 5; i++ {
		fmt.Printf(" %d", r.Int())
	}
	fmt.Println()

	for _, n := range []int64{1, 2, 10, 1000, 1 << 40} {
		r := mk()
		fmt.Printf("int64n %-14d", n)
		for i := 0; i < 6; i++ {
			fmt.Printf(" %d", r.Int64N(n))
		}
		fmt.Println()
	}
	for _, n := range []uint64{1, 2, 10, 1000, 1 << 40} {
		r := mk()
		fmt.Printf("uint64n %-14d", n)
		for i := 0; i < 6; i++ {
			fmt.Printf(" %d", r.Uint64N(n))
		}
		fmt.Println()
	}
	for _, n := range []uint32{1, 2, 10, 1000, 1 << 30} {
		r := mk()
		fmt.Printf("uint32n %-14d", n)
		for i := 0; i < 6; i++ {
			fmt.Printf(" %d", r.Uint32N(n))
		}
		fmt.Println()
	}
	for _, n := range []int32{1, 2, 10, 1000} {
		r := mk()
		fmt.Printf("int32n %-14d", n)
		for i := 0; i < 6; i++ {
			fmt.Printf(" %d", r.Int32N(n))
		}
		fmt.Println()
	}
	for _, n := range []int{1, 2, 10, 1000} {
		r := mk()
		fmt.Printf("intn   %-14d", n)
		for i := 0; i < 6; i++ {
			fmt.Printf(" %d", r.IntN(n))
		}
		fmt.Println()
	}

	r = mk()
	fmt.Printf("float64")
	for i := 0; i < 5; i++ {
		fmt.Printf(" %v", r.Float64())
	}
	fmt.Println()
	r = mk()
	fmt.Printf("float32")
	for i := 0; i < 5; i++ {
		fmt.Printf(" %v", r.Float32())
	}
	fmt.Println()

	for _, n := range []int{0, 1, 5, 10} {
		r := mk()
		x := make([]int, n)
		for i := range x {
			x[i] = i
		}
		r.Shuffle(n, func(i, j int) { x[i], x[j] = x[j], x[i] })
		fmt.Printf("shuffle %-3d %v\n", n, x)
	}

	// The PCG's binary form, which is what makes a generator resumable.
	p := rand.NewPCG(1, 2)
	p.Uint64()
	b, err := p.MarshalBinary()
	fmt.Printf("marshal err=%v %v\n", err, b)
	var q rand.PCG
	err = q.UnmarshalBinary(b)
	fmt.Printf("unmarshal err=%v same=%v\n", err, q.Uint64() == rand.NewPCG(1, 2).Uint64())
	p2 := rand.NewPCG(1, 2)
	p2.Uint64()
	fmt.Printf("resume same=%v\n", q.Uint64() == p2.Uint64())
}
