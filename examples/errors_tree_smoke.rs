// errors_tree_smoke — errors.Is / As / Join against a running Go.
// (errors/wrap.go, errors/join.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_errors_ref.go` run in
// `package errors_test` by `scripts/goref.sh`.
//
// `errors.Is` and `errors.As` walk a TREE, not a chain: an error's
// children come from either `Unwrap() error` or `Unwrap() []error`, and
// when there are several the walk is depth-first across all of them.
// This port walked a single chain through `Unwrap()` only, so
// `Is(Join(a, b), b)` was FALSE — the walk stepped to `a` and stopped.
// `Join` had no way to say it wrapped more than one error, and `As`
// could not reach past the first branch either.
//
// The other missing piece was Go's `Is(error) bool` hook, the one that
// lets an error declare itself equivalent to some unrelated target.
// `syscall.Errno.Is` is the standard-library example: it is what makes
// `errors.Is(ENOENT, fs.ErrNotExist)` true. Nothing here could express
// that.
//
// Also fixed: `Join(x)` returned `x` itself. Go returns a fresh
// `joinError` around it and only passes `x` through when `x` ALREADY
// wraps several errors — so `Join(x) == x` is false for an ordinary
// error and true for a join.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::errors::{self, error, ErrorTrait};
use goish::gostring::string;
use goish::types::int;
use goish::{fmt, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: the smokes print one PASS/FAIL line per
//     numbered check; this is that line, hoisted.
fn report(failed: &mut int, ok: bool, n: &str, what: &str) {
    if ok {
        fmt::Println!("[", n, "]", what, "PASS");
    } else {
        fmt::Println!("[", n, "]", what, "FAIL");
        *failed += 1;
    }
}

// go: none — goish idiom: the Go reference's `wrapOne` — the ordinary
//     single-parent wrapper, `Unwrap() error`.
struct WrapOne {
    msg: string,
    inner: error,
}

impl ErrorTrait for WrapOne {
    fn Error(&self) -> string {
        let mut b: Vec<u8> = Vec::new();
        b.extend_from_slice(self.msg.as_bytes());
        b.extend_from_slice(b": ");
        b.extend_from_slice(self.inner.Error().as_bytes());
        return string::from_bytes(&b);
    }
    fn Unwrap(&self) -> error {
        return self.inner.clone();
    }
}

// go: none — goish idiom: the Go reference's `wrapMany` — an error with
//     `Unwrap() []error`, the shape a single-chain walk cannot follow.
struct WrapMany {
    msg: string,
    errs: Vec<error>,
}

impl ErrorTrait for WrapMany {
    fn Error(&self) -> string {
        return self.msg.clone();
    }
    fn UnwrapMulti(&self) -> Vec<error> {
        return self.errs.clone();
    }
}

// go: none — goish idiom: the Go reference's `saysYes` — implements
//     `Is(error) bool` so it matches a target it has no structural
//     relationship to.
struct SaysYes {
    target: error,
}

impl ErrorTrait for SaysYes {
    fn Error(&self) -> string {
        return s("saysYes");
    }
    fn Is(&self, target: &error) -> bool {
        return *target == self.target;
    }
}

// go: none — goish idiom: the Go reference's `leaf` — a distinct
//     concrete type, so `errors::As` has something to find.
#[derive(Default)]
struct Leaf {
    n: int,
}

impl ErrorTrait for Leaf {
    fn Error(&self) -> string {
        return s("leaf");
    }
}

fn one(msg: &str, inner: error) -> error {
    return errors::Wrap(WrapOne {
        msg: s(msg),
        inner,
    });
}

fn many(msg: &str, errs: Vec<error>) -> error {
    return errors::Wrap(WrapMany { msg: s(msg), errs });
}

fn joinOf(errs: Vec<error>) -> error {
    return errors::Join(slice::__from_vec(errs));
}

#[goish::main]
fn main() {
    let mut failed = 0;

    let a = errors::New("a");
    let b = errors::New("b");
    let c = errors::New("c");

    // 1. Is over a single chain — the case that already worked, kept so
    //    the tree walk cannot regress it.
    {
        let mut ok = true;
        let w = one("w", a.clone());
        let ww = one("ww", w.clone());
        if w.Error() != s("w: a") || ww.Error() != s("ww: w: a") {
            ok = false;
        }
        // Go: is-chain ww,a=true ww,b=false ww,w=true ww,ww=true
        if !errors::Is(ww.clone(), a.clone()) {
            ok = false;
        }
        if errors::Is(ww.clone(), b.clone()) {
            ok = false;
        }
        if !errors::Is(ww.clone(), w.clone()) {
            ok = false;
        }
        if !errors::Is(ww.clone(), ww.clone()) {
            ok = false;
        }
        // Go: w,ww=false — the walk goes down, never up.
        if errors::Is(w.clone(), ww.clone()) {
            ok = false;
        }
        report(&mut failed, ok, " 1", "Is over a chain");
    }

    // 2. Is over a TREE. `m` wraps a and b; a single-chain walk reaches
    //    `a` and stops, so `Is(m, b)` was false.
    {
        let mut ok = true;
        let m = many("m", alloc::vec![a.clone(), b.clone()]);
        if !errors::Is(m.clone(), a.clone()) {
            ok = false;
        }
        if !errors::Is(m.clone(), b.clone()) {
            ok = false;
        }
        if errors::Is(m.clone(), c.clone()) {
            ok = false;
        }
        // A branch that is itself a chain: deep = [a, wrapOne(c)].
        let deep = many("deep", alloc::vec![a.clone(), one("x", c.clone())]);
        if !errors::Is(deep.clone(), a.clone()) {
            ok = false;
        }
        if errors::Is(deep.clone(), b.clone()) {
            ok = false;
        }
        if !errors::Is(deep.clone(), c.clone()) {
            ok = false;
        }
        report(&mut failed, ok, " 2", "Is over a tree (Unwrap []error)");
    }

    // 3. The `Is(error) bool` hook, and that it is consulted at every
    //    step of the walk rather than only at the root.
    {
        let mut ok = true;
        let sy = errors::Wrap(SaysYes { target: b.clone() });
        if !errors::Is(sy.clone(), b.clone()) {
            ok = false;
        }
        if errors::Is(sy.clone(), a.clone()) {
            ok = false;
        }
        // Go: is-hook wrapped = true — the hook fires one level down.
        if !errors::Is(one("h", sy.clone()), b.clone()) {
            ok = false;
        }
        report(&mut failed, ok, " 3", "the Is(error) bool hook");
    }

    // 4. nil handling: Is(nil, nil) is true, and a nil on either side
    //    alone is false.
    {
        let mut ok = true;
        if !errors::Is(errors::nil, errors::nil) {
            ok = false;
        }
        if errors::Is(errors::nil, a.clone()) {
            ok = false;
        }
        if errors::Is(a.clone(), errors::nil) {
            ok = false;
        }
        report(&mut failed, ok, " 4", "Is with nil");
    }

    // 5. Unwrap answers only for `Unwrap() error`. A multi-error has
    //    the []error form, so Unwrap on it is nil — which is exactly
    //    why the tree walk cannot be built out of Unwrap alone.
    {
        let mut ok = true;
        let w = one("w", a.clone());
        let ww = one("ww", w.clone());
        if !errors::Unwrap(w.clone()).__ptr_eq(&a) {
            ok = false;
        }
        if !errors::Unwrap(ww.clone()).__ptr_eq(&w) {
            ok = false;
        }
        if errors::Unwrap(a.clone()) != errors::nil {
            ok = false;
        }
        let m = many("m", alloc::vec![a.clone(), b.clone()]);
        if errors::Unwrap(m) != errors::nil {
            ok = false;
        }
        report(&mut failed, ok, " 5", "Unwrap is single-parent only");
    }

    // 6. As over a chain, a tree, and a tree whose branch is a chain.
    {
        let mut ok = true;
        let l = errors::Wrap(Leaf { n: 7 });
        match errors::As::<Leaf>(one("q", l.clone())) {
            Some(g) => {
                if g.n != 7 {
                    ok = false;
                }
            }
            None => ok = false,
        }
        match errors::As::<Leaf>(many("t", alloc::vec![a.clone(), l.clone()])) {
            Some(g) => {
                if g.n != 7 {
                    ok = false;
                }
            }
            None => ok = false,
        }
        match errors::As::<Leaf>(many("t", alloc::vec![a.clone(), one("z", l.clone())])) {
            Some(g) => {
                if g.n != 7 {
                    ok = false;
                }
            }
            None => ok = false,
        }
        if errors::As::<Leaf>(one("q", a.clone())).is_some() {
            ok = false;
        }
        if errors::As::<Leaf>(errors::nil).is_some() {
            ok = false;
        }
        report(&mut failed, ok, " 6", "As over a tree");
    }

    // 7. Join: empty and all-nil are nil, and a single ORDINARY error
    //    is wrapped rather than passed through. `Join(x) == x` used to
    //    be true here and is false in Go.
    {
        let mut ok = true;
        let empty: Vec<error> = Vec::new();
        if joinOf(empty) != errors::nil {
            ok = false;
        }
        if joinOf(alloc::vec![errors::nil, errors::nil]) != errors::nil {
            ok = false;
        }
        let j1 = joinOf(alloc::vec![a.clone()]);
        // Go: join-one identical=false err="a"
        if j1.__ptr_eq(&a) {
            ok = false;
        }
        if j1.Error() != s("a") {
            ok = false;
        }
        if !errors::Is(j1, a.clone()) {
            ok = false;
        }
        report(&mut failed, ok, " 7", "Join(x) wraps, never returns x");
    }

    // 8. Join over several: the message is newline-joined, every member
    //    is reachable by Is, and nil holes are dropped.
    {
        let mut ok = true;
        let j2 = joinOf(alloc::vec![a.clone(), b.clone()]);
        if j2.Error() != s("a\nb") {
            ok = false;
        }
        if !errors::Is(j2.clone(), a.clone()) || !errors::Is(j2.clone(), b.clone()) {
            ok = false;
        }
        if errors::Is(j2.clone(), c.clone()) {
            ok = false;
        }
        let j3 = joinOf(alloc::vec![
            a.clone(),
            errors::nil,
            b.clone(),
            errors::nil,
            c.clone()
        ]);
        if j3.Error() != s("a\nb\nc") || !errors::Is(j3, c.clone()) {
            ok = false;
        }
        // Unwrap on a join is nil — it has the []error form.
        if errors::Unwrap(j2.clone()) != errors::nil {
            ok = false;
        }
        // Go: join-of-join identical=true — a value that ALREADY wraps
        // several passes straight through.
        let jj = joinOf(alloc::vec![j2.clone()]);
        if !jj.__ptr_eq(&j2) || jj.Error() != s("a\nb") {
            ok = false;
        }
        // Nested joins still walk.
        let jn = joinOf(alloc::vec![a.clone(), joinOf(alloc::vec![b.clone(), c.clone()])]);
        if jn.Error() != s("a\nb\nc") {
            ok = false;
        }
        if !errors::Is(jn.clone(), b.clone()) || !errors::Is(jn, c.clone()) {
            ok = false;
        }
        // And As reaches into one.
        let l = errors::Wrap(Leaf { n: 7 });
        match errors::As::<Leaf>(joinOf(alloc::vec![a.clone(), l])) {
            Some(g) => {
                if g.n != 7 {
                    ok = false;
                }
            }
            None => ok = false,
        }
        report(&mut failed, ok, " 8", "Join over several (Is/As reach all)");
    }

    // 9. New returns a distinct value for identical text, and
    //    ErrUnsupported reads as Go's.
    {
        let mut ok = true;
        let n1 = errors::New("same");
        let n2 = errors::New("same");
        if n1.__ptr_eq(&n2) {
            ok = false;
        }
        if n1.Error() != s("same") || n2.Error() != s("same") {
            ok = false;
        }
        let eu: error = errors::ErrUnsupported.into();
        if eu.Error() != s("unsupported operation") {
            ok = false;
        }
        report(&mut failed, ok, " 9", "New is distinct; ErrUnsupported");
    }

    if failed == 0 {
        fmt::Println!("ok 9/9");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 9");
        syscall::Exit(1);
    }
}
