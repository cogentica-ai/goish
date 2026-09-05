// Go 1.25.5 linux/amd64 oracle for float -> int/int64 conversions.
// go run tools/gen_floatint_ref.go > examples/floatint_ref.txt
package main
import ("fmt"; "math"; "runtime")
func main() {
    if runtime.GOARCH != "amd64" { panic("oracle requires amd64") }
    values := []uint64{0, 1, 0x8000000000000000, 0x7ff0000000000000, 0xfff0000000000000, 0x7ff8000000000000, 0xfff8000000000001}
    for _, v := range []float64{1, -1, 1.9, -1.9, math.Exp2(53), math.Exp2(63), -math.Exp2(63), math.Exp2(64), 1e300, -1e300} {
        bits := math.Float64bits(v)
        for delta := int64(-4); delta <= 4; delta++ { values = append(values, uint64(int64(bits)+delta)) }
    }
    // Deterministic bit-pattern sweep, including subnormals and both signs.
    seed := uint64(0x123456789abcdef0)
    for i := 0; i < 4096; i++ { seed = seed*6364136223846793005+1442695040888963407; values = append(values, seed) }
    for _, bits := range values {
        v := math.Float64frombits(bits)
        f := float32(v)
        fmt.Printf("%016x|%d|%d|%d|%d\n", bits, int(v), int64(v), int(f), int64(f))
    }
}
