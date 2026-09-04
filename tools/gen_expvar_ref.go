package expvar

import (
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// expvar publishes process state as JSON at /debug/vars, and the names
// and values it publishes are often built from data the process did
// not choose — a URL path, a peer's identity, a header. Everything it
// emits therefore has to be VALID JSON no matter what it is handed,
// because a single unescaped quote turns the whole document into
// something a monitoring system cannot parse, and a document nobody
// can parse is a metric nobody sees.
//
// The rules worth pinning:
//
//   * Every string is JSON-quoted on the way out, including the MAP
//     KEYS, which are the ones a caller is most likely to build from
//     input. A key containing a quote, a backslash, a newline or a
//     control character has to survive as one key.
//   * Map output is SORTED by key, so a scrape is stable between
//     calls and a diff between two scrapes means something.
//   * A Float renders through Go's shortest-representation formatting,
//     and the non-finite values — NaN and ±Inf — are the interesting
//     ones because JSON has no syntax for them.
//   * Publishing a duplicate name is an ERROR in Go (it panics), and
//     Get on an unpublished name returns nil rather than a zero value.
func TestGoishRef(t *testing.T) {
	// Ints.
	{
		v := new(Int)
		fmt.Printf("int zero=%s\n", v.String())
		v.Set(42)
		fmt.Printf("int set=%s value=%d\n", v.String(), v.Value())
		v.Add(8)
		fmt.Printf("int add=%s\n", v.String())
		v.Add(-100)
		fmt.Printf("int negative=%s\n", v.String())
		v.Set(math.MaxInt64)
		fmt.Printf("int max=%s\n", v.String())
		v.Set(math.MinInt64)
		fmt.Printf("int min=%s\n", v.String())
	}

	// Floats, including the values JSON cannot express.
	{
		for _, f := range []float64{
			0, 1, -1, 0.5, 1e20, 1e-20, 1.0 / 3.0,
			math.MaxFloat64, math.SmallestNonzeroFloat64,
			math.Inf(1), math.Inf(-1), math.NaN(),
		} {
			v := new(Float)
			v.Set(f)
			fmt.Printf("float %-24g -> %s\n", f, v.String())
		}
		v := new(Float)
		v.Set(1.5)
		v.Add(0.25)
		fmt.Printf("float add -> %s value=%g\n", v.String(), v.Value())
	}

	// Strings: the quoting is the whole job.
	{
		for _, s := range []string{
			"", "plain", `with "quotes"`, `back\slash`, "new\nline",
			"tab\there", "\x00nul", "\x1f-unit-sep", "del\x7f",
			"unicode: héllo", "emoji: 🙂", "<html>&amp;</html>",
			"line sep", "\ufeffbom",
		} {
			v := new(String)
			v.Set(s)
			fmt.Printf("string %-22q -> %s value=%q\n", s, v.String(), v.Value())
		}
	}

	// Maps: sorted keys, and keys that need quoting.
	{
		// Set rather than Add throughout: goish's expvar documents
		// Map.Add and Map.AddFloat as dropped, because Go upgrades an
		// empty entry through a runtime type assertion that static
		// dispatch cannot spell. Set is the documented replacement and
		// measures the same output.
		m := new(Map).Init()
		fmt.Printf("map empty -> %s\n", m.String())
		m.Set("zeta", mkInt(1))
		m.Set("alpha", mkInt(2))
		m.Set("Mixed", mkInt(3))
		m.Set("123numeric", mkInt(4))
		fmt.Printf("map sorted -> %s\n", m.String())
		m2 := new(Map).Init()
		for _, k := range []string{
			`quo"te`, `back\slash`, "new\nline", "", "sp ace", "tab\there",
			"unicode-é", "\x01ctl",
		} {
			m2.Set(k, mkString("v"))
		}
		fmt.Printf("map quoted -> %s\n", m2.String())
		m3 := new(Map).Init()
		m3.Set("n", mkInt(1))
		m3.Set("f", mkFloat(2.5))
		m3.Set("s", mkString("str"))
		inner := new(Map).Init()
		inner.Set("deep", mkInt(7))
		m3.Set("m", inner)
		fmt.Printf("map nested -> %s\n", m3.String())
		// Do walks in sorted order too.
		var keys []string
		m3.Do(func(kv KeyValue) { keys = append(keys, kv.Key) })
		fmt.Printf("map do -> %v sorted=%v\n", keys, sort.StringsAreSorted(keys))
		fmt.Printf("map get-missing-nil=%v\n", m3.Get("nope") == nil)
		m3.Delete("n")
		fmt.Printf("map after-delete -> %s\n", m3.String())
	}

	// The published set and the HTTP handler.
	{
		Publish("goish.int", func() *Int { v := new(Int); v.Set(7); return v }())
		Publish("goish.str", func() *String { v := new(String); v.Set(`a"b`); return v }())
		fmt.Printf("get published=%v missing=%v\n",
			Get("goish.int") != nil, Get("goish.nope") == nil)

		r := httptest.NewRequest("GET", "/debug/vars", nil)
		w := httptest.NewRecorder()
		Handler().ServeHTTP(w, r)
		body := w.Body.String()
		fmt.Printf("handler code=%d ctype=%q\n", w.Code, w.Header().Get("Content-Type"))
		// The full document contains cmdline and memstats, which are
		// machine-specific; only the shape and this test's own entries
		// are pinned.
		fmt.Printf("handler starts=%q ends=%q\n", first(body, 2), last(body, 2))
		for _, want := range []string{`"goish.int": 7`, `"goish.str": "a\"b"`} {
			fmt.Printf("handler contains %-24q -> %v\n", want, strings.Contains(body, want))
		}
		lines := strings.Count(body, "\n")
		// memstats is not compared: goish documents it as dropped,
		// because runtime.MemStats is not ported. cmdline is present
		// on both.
		fmt.Printf("handler multiline=%v has-cmdline=%v\n",
			lines > 2, strings.Contains(body, `"cmdline"`))
	}
}

func mkInt(n int64) *Int {
	v := new(Int)
	v.Set(n)
	return v
}

func mkFloat(f float64) *Float {
	v := new(Float)
	v.Set(f)
	return v
}

func mkString(s string) *String {
	v := new(String)
	v.Set(s)
	return v
}

func first(s string, n int) string {
	if len(s) < n {
		return s
	}
	return s[:n]
}

func last(s string, n int) string {
	if len(s) < n {
		return s
	}
	return s[len(s)-n:]
}

var _ = http.StatusOK
