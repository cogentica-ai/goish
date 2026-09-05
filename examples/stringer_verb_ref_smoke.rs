// stringer_verb_ref_smoke — the verbs a Stringer serves, against a
// running Go 1.25.5.
//
// Go's `handleMethods` consults a type's String() for exactly %v, %s,
// %q, %x and %X, and formats the underlying VALUE for every other
// verb. A type that is both a Stringer and a number therefore answers
// two different ways, and the split is not where you would guess:
//
//     %d 90000000000      the number
//     %o 1236432602000    the number, octal
//     %b 1010011…         the number, binary
//     %v 1m30s            the string
//     %q "1m30s"          the string, quoted
//     %x 316d333073       the hex of "1m30s" — NOT of the number
//
// goish's printer dispatches on a trait rather than reflecting, so the
// blanket `impl<T: Stringer> Format for T` sends every verb through
// the string. That is right for a type with no numeric identity and
// wrong for one that has it, and all four such types in the tree were
// wrong in different ways:
//
//   Duration  every verb printed "1m30s", including %d and %o. Its
//             own comment called that "a fallback for unknown verbs",
//             but %d is not an unknown verb.
//   Month     %x printed 3 and %q printed March unquoted.
//   Weekday   %x printed 2.
//   FileMode  %o printed -rw-r----- (fixed in 29b67ed).
//
// The rule now lives once, in `fmt::__stringer_serves`, and each of
// the four asks it. %x is the case worth keeping honest: hex of the
// string is Go's answer, and "fixing" it to hex of the number would
// look tidier and be wrong.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::gostring::string;
use goish::time;
use goish::types::int;

const GO: [&str; 3] = [
    "dur v=1m30s s=1m30s d=90000000000 o=1236432602000 b=1010011110100011010110000010000000000 x=316d333073 X=316D333073 q=\"1m30s\"",
    "month v=March s=March d=3 o=3 x=4d61726368 q=\"March\"",
    "weekday v=Tuesday s=Tuesday d=2 x=54756573646179",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    let d = time::Second * 90;
    chk(&mut ln, &fmt::Sprintf!("dur v=%v s=%s d=%d o=%o b=%b x=%x X=%X q=%q",
        d, d, d, d, d, d, d, d));
    let m = time::March;
    chk(&mut ln, &fmt::Sprintf!("month v=%v s=%s d=%d o=%o x=%x q=%q", m, m, m, m, m, m));
    let w = time::Tuesday;
    chk(&mut ln, &fmt::Sprintf!("weekday v=%v s=%s d=%d x=%x", w, w, w, w));

    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
    }
}
