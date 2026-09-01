package bits_test

import (
	"fmt"
	"math/bits"
	"testing"
)

// math/bits is pure integer manipulation, so every answer is exact and
// every one of them is silent when wrong: a bad TrailingZeros or a bad
// RotateLeft produces a number, not an error, and it flows straight
// into whatever hash, allocator or codec asked for it.
func TestGoishRef(t *testing.T) {
	fmt.Printf("uintsize %d\n", bits.UintSize)

	u8s := []uint8{0, 1, 2, 3, 0x80, 0xff, 0x0f, 0xf0, 0x55}
	for _, v := range u8s {
		fmt.Printf("b8  %#04x lz=%-2d tz=%-2d oc=%-2d len=%-2d rev=%#04x rot1=%#04x rot-1=%#04x rot9=%#04x\n",
			v, bits.LeadingZeros8(v), bits.TrailingZeros8(v), bits.OnesCount8(v),
			bits.Len8(v), bits.Reverse8(v), bits.RotateLeft8(v, 1),
			bits.RotateLeft8(v, -1), bits.RotateLeft8(v, 9))
	}
	u16s := []uint16{0, 1, 0x8000, 0xffff, 0x0102, 0xff00}
	for _, v := range u16s {
		fmt.Printf("b16 %#06x lz=%-2d tz=%-2d oc=%-2d len=%-2d rev=%#06x revb=%#06x rot4=%#06x\n",
			v, bits.LeadingZeros16(v), bits.TrailingZeros16(v), bits.OnesCount16(v),
			bits.Len16(v), bits.Reverse16(v), bits.ReverseBytes16(v), bits.RotateLeft16(v, 4))
	}
	u32s := []uint32{0, 1, 0x80000000, 0xffffffff, 0x01020304, 0xdeadbeef}
	for _, v := range u32s {
		fmt.Printf("b32 %#010x lz=%-2d tz=%-2d oc=%-2d len=%-2d rev=%#010x revb=%#010x rot8=%#010x rot-8=%#010x\n",
			v, bits.LeadingZeros32(v), bits.TrailingZeros32(v), bits.OnesCount32(v),
			bits.Len32(v), bits.Reverse32(v), bits.ReverseBytes32(v),
			bits.RotateLeft32(v, 8), bits.RotateLeft32(v, -8))
	}
	u64s := []uint64{0, 1, 1 << 63, ^uint64(0), 0x0102030405060708, 0xdeadbeefcafebabe}
	for _, v := range u64s {
		fmt.Printf("b64 %#018x lz=%-2d tz=%-2d oc=%-2d len=%-2d rev=%#018x revb=%#018x rot16=%#018x\n",
			v, bits.LeadingZeros64(v), bits.TrailingZeros64(v), bits.OnesCount64(v),
			bits.Len64(v), bits.Reverse64(v), bits.ReverseBytes64(v), bits.RotateLeft64(v, 16))
	}
	// The uint-width forms.
	for _, v := range []uint{0, 1, 1 << 63, ^uint(0), 0x0102030405060708} {
		fmt.Printf("bu  %#018x lz=%-2d tz=%-2d oc=%-2d len=%-2d rev=%#018x revb=%#018x rot=%#018x\n",
			v, bits.LeadingZeros(v), bits.TrailingZeros(v), bits.OnesCount(v),
			bits.Len(v), bits.Reverse(v), bits.ReverseBytes(v), bits.RotateLeft(v, 3))
	}

	// Add / Sub with carry and borrow, at the wrap points.
	for _, c := range [][3]uint64{
		{1, 2, 0}, {1, 2, 1}, {^uint64(0), 1, 0}, {^uint64(0), 0, 1},
		{^uint64(0), ^uint64(0), 1}, {0, 0, 0},
	} {
		s, carry := bits.Add64(c[0], c[1], c[2])
		d, borrow := bits.Sub64(c[0], c[1], c[2])
		fmt.Printf("addsub %#018x %#018x %d -> add=(%#018x,%d) sub=(%#018x,%d)\n",
			c[0], c[1], c[2], s, carry, d, borrow)
	}
	for _, c := range [][3]uint32{{1, 2, 0}, {^uint32(0), 1, 0}, {0, 1, 1}} {
		s, carry := bits.Add32(c[0], c[1], c[2])
		d, borrow := bits.Sub32(c[0], c[1], c[2])
		fmt.Printf("addsub32 %#010x %#010x %d -> add=(%#010x,%d) sub=(%#010x,%d)\n",
			c[0], c[1], c[2], s, carry, d, borrow)
	}

	// Mul, Div, Rem.
	for _, c := range [][2]uint64{
		{0, 0}, {1, 1}, {^uint64(0), 2}, {^uint64(0), ^uint64(0)},
		{1 << 32, 1 << 32}, {0xdeadbeef, 0xcafebabe},
	} {
		hi, lo := bits.Mul64(c[0], c[1])
		fmt.Printf("mul64 %#018x %#018x -> (%#018x,%#018x)\n", c[0], c[1], hi, lo)
	}
	for _, c := range [][2]uint32{{0, 0}, {^uint32(0), 2}, {0x10000, 0x10000}} {
		hi, lo := bits.Mul32(c[0], c[1])
		fmt.Printf("mul32 %#010x %#010x -> (%#010x,%#010x)\n", c[0], c[1], hi, lo)
	}
	for _, c := range [][3]uint64{
		{0, 10, 3}, {0, ^uint64(0), 3}, {1, 0, 2}, {1, 0, ^uint64(0)},
		{0, 0, 1}, {2, 5, 7},
	} {
		q, r := bits.Div64(c[0], c[1], c[2])
		fmt.Printf("div64 %#018x %#018x %#018x -> (%#018x,%#018x) rem=%#018x\n",
			c[0], c[1], c[2], q, r, bits.Rem64(c[0], c[1], c[2]))
	}
	for _, c := range [][3]uint32{{0, 10, 3}, {1, 0, 2}, {0, 0, 1}} {
		q, r := bits.Div32(c[0], c[1], c[2])
		fmt.Printf("div32 %#010x %#010x %#010x -> (%#010x,%#010x) rem=%#010x\n",
			c[0], c[1], c[2], q, r, bits.Rem32(c[0], c[1], c[2]))
	}
	// Rem is defined even where Div would panic on overflow.
	fmt.Printf("rem-overflow %#018x\n", bits.Rem64(1, 0, 1))
	fmt.Printf("rem32-overflow %#010x\n", bits.Rem32(1, 0, 1))

	// The panics.
	for _, c := range []struct {
		name    string
		hi, lo, y uint64
	}{{"divzero", 0, 1, 0}, {"overflow", 1, 0, 1}} {
		func() {
			defer func() { fmt.Printf("panic %-9s %v\n", c.name, recover()) }()
			bits.Div64(c.hi, c.lo, c.y)
			fmt.Printf("panic %-9s <none>\n", c.name)
		}()
	}
}
