package reflect_test

import (
	"fmt"
	"reflect"
	"testing"
)

// StructTag is the smallest piece of reflect with the widest blast
// radius: encoding/json, encoding/xml, and every codec that names
// fields reads its answers. It is a hand-written parser over a string
// nobody validates, so its failure mode is not an error — it is a tag
// that silently stops being seen.
//
// The rule that matters most is that a MALFORMED tag ends the scan.
// Not skips the bad pair; ends it. So a tag like
//
//     `bad json:"name"`
//
// hides the json key entirely, because "bad" has no colon and the
// parser stops there. A field annotated that way is marshalled under
// its Go name with no warning anywhere, which is how a struct quietly
// changes its wire format.
//
// The other rules are quieter: values are strconv-unquoted, so
// backslash escapes are processed; a key is matched exactly, so case
// matters; a duplicate key resolves to the FIRST occurrence; and an
// empty value is a present key, distinct from an absent one — which is
// the whole reason Lookup exists next to Get.
func TestGoishRef(t *testing.T) {
	tags := []struct{ name, tag string }{
		{"empty", ``},
		{"simple", `json:"name"`},
		{"two-keys", `json:"name" xml:"Name"`},
		{"three-keys", `json:"a" xml:"b" yaml:"c"`},
		{"leading-space", `   json:"name"`},
		{"trailing-space", `json:"name"   `},
		{"multi-space", `json:"a"    xml:"b"`},
		{"no-space-between", `json:"a"xml:"b"`},
		{"empty-value", `json:""`},
		{"value-with-options", `json:"name,omitempty"`},
		{"value-dash", `json:"-"`},
		{"value-dash-comma", `json:"-,"`},
		{"escaped-quote", `json:"na\"me"`},
		{"escaped-backslash", `json:"na\\me"`},
		{"escaped-newline", `json:"na\nme"`},
		{"unicode-escape", `json:"naéme"`},
		{"value-with-space", `json:"na me"`},
		{"value-with-colon", `json:"na:me"`},
		{"malformed-no-colon", `bad json:"name"`},
		{"malformed-no-quote", `json:name xml:"b"`},
		{"malformed-unterminated", `json:"name`},
		{"malformed-empty-key", `:"name"`},
		{"malformed-key-space", `js on:"name"`},
		{"malformed-quote-in-key", `js"on:"name"`},
		{"duplicate-key", `json:"first" json:"second"`},
		{"case-differs", `JSON:"upper" json:"lower"`},
		{"tab-separator", "json:\"a\"\txml:\"b\""},
		{"newline-separator", "json:\"a\"\nxml:\"b\""},
		{"bad-then-good", `json:"ok" bad xml:"never"`},
		{"good-after-unterminated", `x:"a json:"name"`},
		{"only-spaces", `   `},
		{"invalid-escape", `json:"na\qme"`},
		{"control-char-key", "js\x01on:\"name\""},
		{"empty-key-value", `json:"" xml:""`},
	}
	for _, c := range tags {
		st := reflect.StructTag(c.tag)
		for _, key := range []string{"json", "xml", "yaml", "JSON", "bad", "", "x"} {
			v, ok := st.Lookup(key)
			g := st.Get(key)
			fmt.Printf("tag %-24s key=%-5q -> lookup=%-14q ok=%-5v get=%q same=%v\n",
				c.name, key, v, ok, g, v == g)
		}
	}

	// The same parser read through an actual struct, so the pinned
	// answers are the ones a codec sees rather than ones a test
	// constructed.
	//
	// Note what CANNOT be written here: `go vet` refuses a malformed
	// struct tag at build time ("bad syntax for struct tag pair"), and
	// refuses a tag on an unexported field. So the malformed cases
	// above are not merely convenient to test as strings — a string is
	// the only way such a tag can reach the parser at all, which is
	// why the silent-truncation behaviour matters: it is reached by
	// tags that were built, not written.
	type S struct {
		Plain     string
		Named     string `json:"named"`
		Omit      string `json:"omit,omitempty"`
		Skipped   string `json:"-"`
		Multi     string `json:"m" xml:"x" db:"d"`
		Escaped   string `json:"esc\"aped"`
		Empty     string `json:""`
	}
	rt := reflect.TypeOf(S{})
	fmt.Printf("struct name=%q kind=%v numfield=%d\n", rt.Name(), rt.Kind(), rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		jv, jok := f.Tag.Lookup("json")
		fmt.Printf("field %-10s tag=%-24q json=%-12q ok=%-5v xml=%q exported=%v\n",
			f.Name, string(f.Tag), jv, jok, f.Tag.Get("xml"), f.IsExported())
	}
}
