package binary_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"testing"
)

// binary.Read and binary.Write are the whole point of the package: they
// move fixed-width values in and out of a stream in a stated byte
// order. A port that stubs them out and returns nil reports success and
// writes nothing — a caller cannot tell the difference from a correct
// empty write.
func TestGoishRef(t *testing.T) {
	orders := []struct {
		name string
		o    binary.ByteOrder
	}{{"big", binary.BigEndian}, {"little", binary.LittleEndian}, {"native", binary.NativeEndian}}

	for _, oc := range orders {
		b := make([]byte, 8)
		oc.o.PutUint16(b, 0x0102)
		fmt.Printf("put16 %-7s %v\n", oc.name, b[:2])
		oc.o.PutUint32(b, 0x01020304)
		fmt.Printf("put32 %-7s %v\n", oc.name, b[:4])
		oc.o.PutUint64(b, 0x0102030405060708)
		fmt.Printf("put64 %-7s %v\n", oc.name, b[:8])
		fmt.Printf("get   %-7s %d %d %d str=%q\n", oc.name,
			oc.o.Uint16([]byte{1, 2}), oc.o.Uint32([]byte{1, 2, 3, 4}),
			oc.o.Uint64([]byte{1, 2, 3, 4, 5, 6, 7, 8}), fmt.Sprint(oc.o))
	}
	ab := binary.BigEndian.AppendUint32(nil, 0x01020304)
	al := binary.LittleEndian.AppendUint16([]byte{9}, 0x0102)
	fmt.Printf("append %v %v\n", ab, al)

	// Size over every fixed-size shape, and -1 for one that is not.
	var (
		i8v  int8    = -1
		u8v  uint8   = 1
		i16v int16   = -2
		u16v uint16  = 2
		i32v int32   = -3
		u32v uint32  = 3
		i64v int64   = -4
		u64v uint64  = 4
		f32v float32 = 1.5
		f64v float64 = -2.5
		bv   bool    = true
	)
	for _, v := range []any{i8v, u8v, i16v, u16v, i32v, u32v, i64v, u64v, f32v, f64v, bv,
		[]int32{1, 2, 3}, [3]uint16{1, 2, 3}, []byte{1, 2}, "abc"} {
		fmt.Printf("size %-14T %d\n", v, binary.Size(v))
	}

	// Write, then Read back, for each scalar in each order.
	for _, oc := range orders[:2] {
		var buf bytes.Buffer
		for _, v := range []any{i8v, u8v, i16v, u16v, i32v, u32v, i64v, u64v, f32v, f64v, bv} {
			if err := binary.Write(&buf, oc.o, v); err != nil {
				fmt.Printf("write err %v\n", err)
			}
		}
		fmt.Printf("wrote %-7s len=%d %v\n", oc.name, buf.Len(), buf.Bytes())
		var (
			a int8
			b uint8
			c int16
			d uint16
			e int32
			f uint32
			g int64
			h uint64
			i float32
			j float64
			k bool
		)
		for _, p := range []any{&a, &b, &c, &d, &e, &f, &g, &h, &i, &j, &k} {
			if err := binary.Read(&buf, oc.o, p); err != nil {
				fmt.Printf("read err %v\n", err)
			}
		}
		fmt.Printf("read  %-7s %d %d %d %d %d %d %d %d %v %v %v\n",
			oc.name, a, b, c, d, e, f, g, h, i, j, k)
	}

	// A slice round-trips element by element.
	var sb bytes.Buffer
	binary.Write(&sb, binary.BigEndian, []int32{1, -2, 3})
	fmt.Printf("slice %v\n", sb.Bytes())
	out := make([]int32, 3)
	binary.Read(&sb, binary.BigEndian, out)
	fmt.Printf("sliceback %v\n", out)

	// Short input is io.ErrUnexpectedEOF (or io.EOF when nothing at all).
	for _, n := range []int{0, 1, 3} {
		r := bytes.NewReader(make([]byte, n))
		var v int32
		err := binary.Read(r, binary.BigEndian, &v)
		fmt.Printf("short %d err=%v\n", n, err)
	}

	// Append / Encode / Decode.
	ap, _ := binary.Append(nil, binary.BigEndian, int32(-2))
	fmt.Printf("Append %v\n", ap)
	enc := make([]byte, 4)
	n, err := binary.Encode(enc, binary.BigEndian, int32(-2))
	fmt.Printf("Encode n=%d err=%v %v\n", n, err, enc)
	var dv int32
	n, err = binary.Decode(enc, binary.BigEndian, &dv)
	fmt.Printf("Decode n=%d err=%v v=%d\n", n, err, dv)
	small := make([]byte, 2)
	n, err = binary.Encode(small, binary.BigEndian, int32(-2))
	fmt.Printf("Encode-short n=%d err=%v\n", n, err)

	// Float bit patterns, so the port cannot invent its own.
	fmt.Printf("floats f32=%v f64=%v nan32=%v\n",
		mustAppend(binary.BigEndian, float32(1.5)),
		mustAppend(binary.BigEndian, float64(-2.5)),
		mustAppend(binary.BigEndian, float32(math.NaN())))
}

func mustAppend(o binary.ByteOrder, v any) []byte {
	b, err := binary.Append(nil, o, v)
	if err != nil {
		panic(err)
	}
	return b
}
