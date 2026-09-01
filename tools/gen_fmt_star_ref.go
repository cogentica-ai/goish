package fmt_test

import (
	"fmt"
	"testing"
)

// `%*d` takes its WIDTH from an argument instead of from the format
// string, and `%.*f` takes its precision the same way. A printer that
// does not know `*` is a width parses it as the VERB: it consumes the
// width argument, renders it under a meaningless verb, and copies the
// real verb letter out as a literal — so `%*d` of (6, 42) prints "6d"
// and the value never appears at all.
func TestGoishRef(t *testing.T) {
	for _, c := range []struct {
		f string
		a []any
	}{
		{"%*d", []any{6, 42}},
		{"%-*d", []any{6, 42}},
		{"%*d", []any{-6, 42}},
		{"%0*d", []any{6, 42}},
		{"%0*d", []any{-6, 42}},
		{"%*d", []any{0, 42}},
		{"%*s", []any{3, "a"}},
		{"%-*s", []any{3, "a"}},
		{"%*q", []any{6, "a"}},
		{"%*c", []any{4, 'A'}},
		{"%*x", []any{5, 255}},
		{"%#*x", []any{6, 255}},
		{"%*v", []any{6, true}},
		{"%*t", []any{6, true}},
		{"%.*f", []any{2, 3.14159}},
		{"%.*f", []any{0, 3.14159}},
		{"%.*f", []any{-1, 3.14159}},
		{"%*.*f", []any{10, 2, 3.14159}},
		{"%-*.*f", []any{10, 2, 3.14159}},
		{"%.*s", []any{2, "abcdef"}},
		{"%.*d", []any{4, 42}},
		{"%*d %*d", []any{4, 1, 5, 2}},
		{"%*d", []any{"x", 42}},
		{"%.*f", []any{"x", 3.14}},
		{"%*d", []any{6}},
		{"%*d", []any{}},
		{"%.*f", []any{2}},
		{"%*d", []any{2000000, 42}},
		{"%*d", []any{-2000000, 42}},
		{"%*d", []any{int64(6), 42}},
		{"%*d", []any{uint(6), 42}},
		{"%*d", []any{int8(6), 42}},
		{"%**d", []any{6, 42}},
		{"%*", []any{6}},
		{"%*%", []any{6}},
	} {
		fmt.Printf("%-12q %-28v -> %q\n", c.f, c.a, fmt.Sprintf(c.f, c.a...))
	}
}
