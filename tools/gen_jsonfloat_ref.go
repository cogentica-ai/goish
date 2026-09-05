// Go 1.25.5 json/v2 float decode status, exact bits, and decoder-state oracle.
// GOEXPERIMENT=jsonv2 go run tools/gen_jsonfloat_ref.go > examples/json_float_decode_ref.txt
package main
import (
    "encoding/json/jsontext"
    "encoding/json/v2"
    "fmt"
    "math"
    "strings"
)
func row(input string) {
    d := jsontext.NewDecoder(strings.NewReader(input))
    v := float64(91)
    err := json.UnmarshalDecode(d, &v)
    fmt.Printf("64|%s|%t|%016x|%d\n", input, err == nil, math.Float64bits(v), d.StackDepth())
    d = jsontext.NewDecoder(strings.NewReader(input))
    f := float32(91)
    err = json.UnmarshalDecode(d, &f)
    fmt.Printf("32|%s|%t|%08x|%d\n", input, err == nil, math.Float32bits(f), d.StackDepth())
}
func main() {
    for _, s := range []string{"", " ", "null", "nul", "true", `"1"`, "[]", "[1]", "[[]]", "{}", `{"x":1}`, `{"x":1,"x":2}`, "[1,]", "[1", "[1,2] 3", "1 2", "1e", "01", "-0", "0.0", "-0.0", "1.234567890123456789", "3.4028234663852886e38", "3.4028235677973366e38", "1.7976931348623157e308", "1.7976931348623159e308", "2.2250738585072014e-308", "4.9406564584124654e-324", "1e9999", "-1e9999"} { row(s) }
    for exp := -350; exp <= 350; exp++ {
        for _, mantissa := range []string{"1", "-1", "1.234567890123456789", "-9.999999999999999999"} { row(fmt.Sprintf("%se%d", mantissa, exp)) }
    }
}
