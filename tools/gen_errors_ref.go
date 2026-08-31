package errors_test

import (
	"errors"
	"fmt"
	"testing"
)

// wrapOne is the ordinary single-parent wrapper: `Unwrap() error`.
type wrapOne struct {
	msg   string
	inner error
}

func (w *wrapOne) Error() string { return w.msg + ": " + w.inner.Error() }
func (w *wrapOne) Unwrap() error { return w.inner }

// wrapMany has `Unwrap() []error`, the shape errors.Join returns and
// the one a single-chain walk cannot follow.
type wrapMany struct {
	msg  string
	errs []error
}

func (w *wrapMany) Error() string   { return w.msg }
func (w *wrapMany) Unwrap() []error { return w.errs }

// saysYes implements `Is(error) bool` so it matches a target it has no
// structural relationship to — syscall.Errno.Is is the standard-library
// example.
type saysYes struct{ target error }

func (s saysYes) Error() string     { return "saysYes" }
func (s saysYes) Is(t error) bool   { return t == s.target }

// leaf is a distinct concrete type, so errors.As has something to find.
type leaf struct{ n int }

func (l *leaf) Error() string { return fmt.Sprintf("leaf(%d)", l.n) }

func TestGoishRef(t *testing.T) {
	a := errors.New("a")
	b := errors.New("b")
	c := errors.New("c")

	// Is over a single chain — the case that already worked.
	w := &wrapOne{"w", a}
	ww := &wrapOne{"ww", w}
	fmt.Printf("chain w=%q ww=%q\n", w.Error(), ww.Error())
	for _, tgt := range []struct {
		name string
		e    error
	}{{"a", a}, {"b", b}, {"w", w}, {"ww", ww}} {
		fmt.Printf("is-chain ww,%s = %v | w,%s = %v\n",
			tgt.name, errors.Is(ww, tgt.e), tgt.name, errors.Is(w, tgt.e))
	}

	// Is over a TREE — Unwrap() []error. A single-chain walk finds the
	// first branch only.
	m := &wrapMany{"m", []error{a, b}}
	for _, tgt := range []struct {
		name string
		e    error
	}{{"a", a}, {"b", b}, {"c", c}} {
		fmt.Printf("is-tree m,%s = %v\n", tgt.name, errors.Is(m, tgt.e))
	}
	// Nested: a tree whose second branch is itself a chain.
	deep := &wrapMany{"deep", []error{a, &wrapOne{"x", c}}}
	for _, tgt := range []struct {
		name string
		e    error
	}{{"a", a}, {"b", b}, {"c", c}} {
		fmt.Printf("is-deep deep,%s = %v\n", tgt.name, errors.Is(deep, tgt.e))
	}

	// The Is(error) bool hook.
	sy := saysYes{target: b}
	fmt.Printf("is-hook sy,b = %v sy,a = %v\n", errors.Is(sy, b), errors.Is(sy, a))
	fmt.Printf("is-hook wrapped = %v\n", errors.Is(&wrapOne{"h", sy}, b))

	// nil handling.
	fmt.Printf("is-nil nil,nil = %v nil,a = %v a,nil = %v\n",
		errors.Is(nil, nil), errors.Is(nil, a), errors.Is(a, nil))

	// Unwrap: only `Unwrap() error` answers; a multi-error does not.
	fmt.Printf("unwrap w=%v ww=%v a=%v m=%v\n",
		errors.Unwrap(w), errors.Unwrap(ww), errors.Unwrap(a), errors.Unwrap(m))

	// As over a chain and over a tree.
	l := &leaf{7}
	var got *leaf
	fmt.Printf("as-chain %v %v\n", errors.As(&wrapOne{"q", l}, &got), got)
	got = nil
	fmt.Printf("as-tree %v %v\n", errors.As(&wrapMany{"t", []error{a, l}}, &got), got)
	got = nil
	fmt.Printf("as-deep %v %v\n",
		errors.As(&wrapMany{"t", []error{a, &wrapOne{"z", l}}}, &got), got)
	got = nil
	fmt.Printf("as-miss %v %v\n", errors.As(&wrapOne{"q", a}, &got), got)
	got = nil
	fmt.Printf("as-nil %v\n", errors.As(nil, &got))

	// Join: what it returns, and what it does NOT collapse.
	fmt.Printf("join-none %v\n", errors.Join())
	fmt.Printf("join-all-nil %v\n", errors.Join(nil, nil))
	j1 := errors.Join(a)
	fmt.Printf("join-one identical=%v err=%q\n", j1 == a, j1.Error())
	fmt.Printf("join-one-is-a=%v\n", errors.Is(j1, a))
	j2 := errors.Join(a, b)
	fmt.Printf("join-two err=%q is-a=%v is-b=%v is-c=%v\n",
		j2.Error(), errors.Is(j2, a), errors.Is(j2, b), errors.Is(j2, c))
	j3 := errors.Join(a, nil, b, nil, c)
	fmt.Printf("join-holes err=%q is-c=%v\n", j3.Error(), errors.Is(j3, c))
	// Join of a Join: the single-error case returns the argument
	// UNCHANGED only when it already wraps several.
	jj := errors.Join(j2)
	fmt.Printf("join-of-join identical=%v err=%q\n", jj == j2, jj.Error())
	// Nested joins still walk.
	jn := errors.Join(a, errors.Join(b, c))
	fmt.Printf("join-nested err=%q is-b=%v is-c=%v\n",
		jn.Error(), errors.Is(jn, b), errors.Is(jn, c))
	// Unwrap on a join answers nothing: it has the []error form.
	fmt.Printf("join-unwrap %v\n", errors.Unwrap(j2))
	// As reaches into a join.
	got = nil
	fmt.Printf("join-as %v %v\n", errors.As(errors.Join(a, l), &got), got)

	// New: distinct values for identical text.
	n1, n2 := errors.New("same"), errors.New("same")
	fmt.Printf("new-distinct %v texts=%q,%q\n", n1 == n2, n1.Error(), n2.Error())

	// ErrUnsupported's text.
	fmt.Printf("errunsupported %q\n", errors.ErrUnsupported.Error())
}
