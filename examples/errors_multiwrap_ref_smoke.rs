// errors_multiwrap_ref_smoke — several %w operands, past the headline
// (issue #11).
//
// `fmt.Errorf("%w: %w", a, b)` builds a multi-error whose `Unwrap()
// []error` makes both causes reachable. That pair already worked; what
// this file pins is the rest of issue #11's criteria, which a
// two-cause test does not reach:
//
//   three causes, and all three findable
//   the SAME error twice as a target
//   a single wrapper nested inside a multi one, and vice versa
//   errors::As (not AsConcrete) reaching a cause through a multi-wrap
//   %w mixed with ordinary verbs
//   a nil operand for %w
//
// The nil row is the one that was wrong, and the comment above it in
// fmt/print.rs asserted Go's behaviour and had it backwards: Go writes
// `%!w(<nil>)`, treating a nil operand as a BAD VERB ARGUMENT rather
// than formatting a nil. goish wrote a bare `<nil>`. That matters
// beyond cosmetics — `%!w(...)` is how fmt says "this operand was
// wrong", and a nil %w wraps nothing, so the caller's `errors.Is` will
// never match it however the text reads.
//
// There is no row for a NON-error operand: `go vet` rejects
// `fmt.Errorf("%w", "str")` outright, so the case cannot be written in
// a vet-clean Go program and there is nothing to pin against. goish
// writes `%!w(non-error)` there.
//
// GO[] is the verbatim output of tools/gen_multiwrap_ref.go under
// scripts/goref.sh, transcribed from the bytes rather than retyped.
// goish's output diffs IDENTICAL against it.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::errors::{self, error, ErrorTrait};
use goish::fmt;
use goish::gostring::string;
use goish::types::int;

static FAILED: AtomicUsize = AtomicUsize::new(0);

const GO: [&str; 22] = [
    "two_msg              a: b",
    "two_is_a             true",
    "two_is_b             true",
    "two_is_c             false",
    "three_msg            a/b/c",
    "three_is_a           true",
    "three_is_b           true",
    "three_is_c           true",
    "dup_msg              a and a",
    "dup_is_a             true",
    "nest_msg             a | wrapped: c",
    "nest_is_a            true",
    "nest_is_c            true",
    "outer_msg            outer: a: b",
    "outer_is_a           true",
    "outer_is_b           true",
    "as_ok                true",
    "as_n                 7",
    "mixed_msg            code=42 a tail=x",
    "mixed_is_a           true",
    "nil_msg              a: %!w(<nil>)",
    "nil_is_a             true",
];

/// A concrete error type to find with `errors::As` through the wrap.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct MyErr(i32);

impl ErrorTrait for MyErr {
    fn Error(&self) -> string {
        return fmt::Sprintf!("myErr(%d)", self.0 as i64);
    }
}

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        FAILED.fetch_add(1, Ordering::Relaxed);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
    *ln += 1;
}

fn r(ln: &mut usize, name: &'static str, v: string) {
    chk(ln, &fmt::Sprintf!("%-20s %s", string::from_static(name), v));
}

fn rb(ln: &mut usize, name: &'static str, v: bool) {
    chk(ln, &fmt::Sprintf!("%-20s %v", string::from_static(name), v));
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    let a = errors::New(string::from_static("a"));
    let b = errors::New(string::from_static("b"));
    let c = errors::New(string::from_static("c"));

    let two = fmt::Errorf!("%w: %w", a.clone(), b.clone());
    r(&mut ln, "two_msg", two.Error());
    rb(&mut ln, "two_is_a", errors::Is(two.clone(), a.clone()));
    rb(&mut ln, "two_is_b", errors::Is(two.clone(), b.clone()));
    rb(&mut ln, "two_is_c", errors::Is(two.clone(), c.clone()));

    let three = fmt::Errorf!("%w/%w/%w", a.clone(), b.clone(), c.clone());
    r(&mut ln, "three_msg", three.Error());
    rb(&mut ln, "three_is_a", errors::Is(three.clone(), a.clone()));
    rb(&mut ln, "three_is_b", errors::Is(three.clone(), b.clone()));
    rb(&mut ln, "three_is_c", errors::Is(three, c.clone()));

    // The same error twice: one target, two operands.
    let dup = fmt::Errorf!("%w and %w", a.clone(), a.clone());
    r(&mut ln, "dup_msg", dup.Error());
    rb(&mut ln, "dup_is_a", errors::Is(dup, a.clone()));

    // A single wrapper inside a multi one.
    let single = fmt::Errorf!("wrapped: %w", c.clone());
    let nest = fmt::Errorf!("%w | %w", a.clone(), single);
    r(&mut ln, "nest_msg", nest.Error());
    rb(&mut ln, "nest_is_a", errors::Is(nest.clone(), a.clone()));
    rb(&mut ln, "nest_is_c", errors::Is(nest, c.clone()));

    // A multi wrapper inside a single one.
    let outer = fmt::Errorf!("outer: %w", two);
    r(&mut ln, "outer_msg", outer.Error());
    rb(&mut ln, "outer_is_a", errors::Is(outer.clone(), a.clone()));
    rb(&mut ln, "outer_is_b", errors::Is(outer, b.clone()));

    // `errors::As` walks the tree; `AsConcrete` deliberately does NOT
    // (it is Go's shallow `err.(*T)` type switch), so this row is the
    // one that says the walk reaches a cause held by a multi-wrap.
    let t: error = MyErr(7).into();
    let with_as = fmt::Errorf!("%w: %w", a.clone(), t);
    match errors::As::<MyErr>(with_as) {
        Some(m) => {
            rb(&mut ln, "as_ok", true);
            chk(
                &mut ln,
                &fmt::Sprintf!("%-20s %d", string::from_static("as_n"), m.0 as i64),
            );
        }
        None => rb(&mut ln, "as_ok", false),
    }

    let mixed = fmt::Errorf!(
        "code=%d %w tail=%s",
        42i64,
        a.clone(),
        string::from_static("x")
    );
    r(&mut ln, "mixed_msg", mixed.Error());
    rb(&mut ln, "mixed_is_a", errors::Is(mixed, a.clone()));

    // A nil operand wraps nothing and is reported as a bad argument.
    let with_nil = fmt::Errorf!("%w: %w", a.clone(), errors::nil);
    r(&mut ln, "nil_msg", with_nil.Error());
    rb(&mut ln, "nil_is_a", errors::Is(with_nil, a));

    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
    let f = FAILED.load(Ordering::Relaxed);
    if f != 0 {
        fmt::Printf!("\nFAILED %d check(s)\n", f as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok %d/%d\n", ln as i64, GO.len() as i64);
}
