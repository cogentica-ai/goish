// regexp_parser_ref_smoke — `regexp/syntax`'s parser stack machinery,
// stage 2b-iii of §2c.
//
// This is the half of the parser that builds the tree: `push`,
// `maybeConcat`, `literal`, `op`, `repeat`, `concat`, `alternate`,
// `collapse` and `factor`, over the node arena. Stage 2b-iv is
// `Parse` itself and the sub-parsers that read the pattern text.
//
// Both sides are driven through the SAME script of operations and the
// stack is dumped after each, so the comparison is per-step rather
// than per-pattern. A divergence names the operation that caused it
// instead of the pattern that eventually showed it.
//
// ─── why an arena ────────────────────────────────────────────────────
//
// Go's parser works on `*Regexp` and leans on that being a pointer
// three ways. It MUTATES nodes in place while they are reachable from
// the stack and from another node's `Sub`; it keeps a FREE LIST and
// recycles them; and it keys the height and size maps on the pointer.
// `Arc<Regexp>` gives none of the three, so the parser works in an
// arena where a `u32` index is the pointer.
//
// The free list is not an allocation detail that could be skipped.
// `numRegexp` counts real allocations, and `checkSize`/`checkHeight`
// start tracking only once it crosses a threshold — so a port that
// never recycles counts higher, starts tracking sooner, and can report
// `ErrLarge` on a pattern Go accepts. That is why every row carries
// `numRegexp`: it is the observable shadow of the free list.
//
// ─── what the rows show ──────────────────────────────────────────────
//
//   concat     three literals become ONE node, incrementally
//   abstar     a repeat stops the run — `ab*` is `a` then `b*`, and
//              Go's comment says exactly why: "Otherwise ab* would
//              turn into (ab)*"
//   foldpair   `[Aa]` collapses to a FOLDED literal, which is how
//              `(?i)a` and `[Aa]` come to compile the same. `[az]`
//              does not: the two runes must be each other's whole fold
//              orbit
//   flagsplit  two literals either side of a flag change must NOT
//              merge
//   alt-nested `abc|abd|bcx|bcy` through all four factoring rounds
//   reppseudo  a repeat over a pseudo-op is refused, not applied
//
// 94 rows from `scripts/goref.sh regexp/syntax
// tools/gen_regexp_parser_ref.go`.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use goish::regexp::syntax;
use goish::regexp::syntax::parse;
use goish::types::{int, rune};
use goish::{fmt, string, strconv};

static mut FAILED: int = 0;
static mut RUN: int = 0;

const GO: [&str; 223] = [
    r#"concat  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"concat  1 L   numRegexp=2 numRunes=2 | (3 212 0 0 0 "" [97]) (3 212 0 0 0 "" [98])"#,
    r#"concat  2 L   numRegexp=3 numRunes=3 | (3 212 0 0 0 "" [97 98]) (3 212 0 0 0 "" [99])"#,
    r#"concat  3 X   numRegexp=3 numRunes=6 | (3 212 0 0 0 "" [97 98 99])"#,
    r#"abstar  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"abstar  1 L   numRegexp=2 numRunes=2 | (3 212 0 0 0 "" [97]) (3 212 0 0 0 "" [98])"#,
    r#"abstar  2 R   numRegexp=3 numRunes=2 | (3 212 0 0 0 "" [97]) (14 212 0 -1 0 "" [] (3 212 0 0 0 "" [98]))"#,
    r#"abstar  3 X   numRegexp=4 numRunes=2 | (18 0 0 0 0 "" [] (3 212 0 0 0 "" [97]) (14 212 0 -1 0 "" [] (3 212 0 0 0 "" [98])))"#,
    r#"class1  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"class1  1 C   numRegexp=2 numRunes=3 | (3 212 0 0 0 "" [97]) (3 212 0 0 0 "" [98])"#,
    r#"class1  2 X   numRegexp=2 numRunes=5 | (3 212 0 0 0 "" [97 98])"#,
    r#"foldpair  0 C   numRegexp=1 numRunes=4 | (3 213 0 0 0 "" [65])"#,
    r#"foldpair  1 X   numRegexp=1 numRunes=5 | (3 213 0 0 0 "" [65])"#,
    r#"foldadj  0 C   numRegexp=1 numRunes=2 | (4 212 0 0 0 "" [916 917])"#,
    r#"foldadj  1 X   numRegexp=1 numRunes=4 | (4 212 0 0 0 "" [916 917])"#,
    r#"foldK  0 C   numRegexp=1 numRunes=4 | (4 212 0 0 0 "" [75 75 107 107])"#,
    r#"foldK  1 X   numRegexp=1 numRunes=8 | (4 212 0 0 0 "" [75 75 107 107])"#,
    r#"notfold  0 C   numRegexp=1 numRunes=4 | (4 212 0 0 0 "" [97 97 122 122])"#,
    r#"notfold  1 X   numRegexp=1 numRunes=8 | (4 212 0 0 0 "" [97 97 122 122])"#,
    r#"flagsplit  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"flagsplit  1 F   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"flagsplit  2 L   numRegexp=2 numRunes=2 | (3 212 0 0 0 "" [97]) (3 213 0 0 0 "" [66])"#,
    r#"flagsplit  3 X   numRegexp=3 numRunes=2 | (18 0 0 0 0 "" [] (3 212 0 0 0 "" [97]) (3 213 0 0 0 "" [66]))"#,
    r#"alt-simple  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"alt-simple  1 V   numRegexp=2 numRunes=2 | (3 212 0 0 0 "" [97]) (129 212 0 0 0 "" [])"#,
    r#"alt-simple  2 L   numRegexp=3 numRunes=3 | (3 212 0 0 0 "" [97]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [98])"#,
    r#"alt-simple  3 E   numRegexp=3 numRunes=6 | (4 212 0 0 0 "" [97 98])"#,
    r#"alt-prefix  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"alt-prefix  1 L   numRegexp=2 numRunes=2 | (3 212 0 0 0 "" [97]) (3 212 0 0 0 "" [98])"#,
    r#"alt-prefix  2 L   numRegexp=3 numRunes=3 | (3 212 0 0 0 "" [97 98]) (3 212 0 0 0 "" [99])"#,
    r#"alt-prefix  3 V   numRegexp=3 numRunes=6 | (3 212 0 0 0 "" [97 98 99]) (129 212 0 0 0 "" [])"#,
    r#"alt-prefix  4 L   numRegexp=3 numRunes=7 | (3 212 0 0 0 "" [97 98 99]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97])"#,
    r#"alt-prefix  5 L   numRegexp=4 numRunes=8 | (3 212 0 0 0 "" [97 98 99]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97]) (3 212 0 0 0 "" [98])"#,
    r#"alt-prefix  6 L   numRegexp=5 numRunes=9 | (3 212 0 0 0 "" [97 98 99]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97 98]) (3 212 0 0 0 "" [100])"#,
    r#"alt-prefix  7 V   numRegexp=5 numRunes=12 | (3 212 0 0 0 "" [97 98 99]) (3 212 0 0 0 "" [97 98 100]) (129 212 0 0 0 "" [])"#,
    r#"alt-prefix  8 L   numRegexp=5 numRunes=13 | (3 212 0 0 0 "" [97 98 99]) (3 212 0 0 0 "" [97 98 100]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97])"#,
    r#"alt-prefix  9 L   numRegexp=5 numRunes=14 | (3 212 0 0 0 "" [97 98 99]) (3 212 0 0 0 "" [97 98 100]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97]) (3 212 0 0 0 "" [101])"#,
    r#"alt-prefix 10 L   numRegexp=6 numRunes=15 | (3 212 0 0 0 "" [97 98 99]) (3 212 0 0 0 "" [97 98 100]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97 101]) (3 212 0 0 0 "" [102])"#,
    r#"alt-prefix 11 E   numRegexp=9 numRunes=18 | (18 0 0 0 0 "" [] (3 0 0 0 0 "" [97]) (19 0 0 0 0 "" [] (18 0 0 0 0 "" [] (3 0 0 0 0 "" [98]) (4 212 0 0 0 "" [99 100])) (3 212 0 0 0 "" [101 102])))"#,
    r#"alt-class  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"alt-class  1 V   numRegexp=2 numRunes=2 | (3 212 0 0 0 "" [97]) (129 212 0 0 0 "" [])"#,
    r#"alt-class  2 L   numRegexp=3 numRunes=3 | (3 212 0 0 0 "" [97]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [98])"#,
    r#"alt-class  3 V   numRegexp=3 numRunes=4 | (4 212 0 0 0 "" [97 98]) (129 212 0 0 0 "" [])"#,
    r#"alt-class  4 L   numRegexp=3 numRunes=5 | (4 212 0 0 0 "" [97 98]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [99])"#,
    r#"alt-class  5 E   numRegexp=3 numRunes=8 | (4 212 0 0 0 "" [97 99])"#,
    r#"alt-empty  0 E   numRegexp=1 numRunes=0 | (2 0 0 0 0 "" [])"#,
    r#"alt-one  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"alt-one  1 E   numRegexp=1 numRunes=3 | (3 212 0 0 0 "" [97])"#,
    r#"alt-nested  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"alt-nested  1 L   numRegexp=2 numRunes=2 | (3 212 0 0 0 "" [97]) (3 212 0 0 0 "" [98])"#,
    r#"alt-nested  2 L   numRegexp=3 numRunes=3 | (3 212 0 0 0 "" [97 98]) (3 212 0 0 0 "" [99])"#,
    r#"alt-nested  3 V   numRegexp=3 numRunes=6 | (3 212 0 0 0 "" [97 98 99]) (129 212 0 0 0 "" [])"#,
    r#"alt-nested  4 L   numRegexp=3 numRunes=7 | (3 212 0 0 0 "" [97 98 99]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97])"#,
    r#"alt-nested  5 L   numRegexp=4 numRunes=8 | (3 212 0 0 0 "" [97 98 99]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97]) (3 212 0 0 0 "" [98])"#,
    r#"alt-nested  6 L   numRegexp=5 numRunes=9 | (3 212 0 0 0 "" [97 98 99]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97 98]) (3 212 0 0 0 "" [100])"#,
    r#"alt-nested  7 V   numRegexp=5 numRunes=12 | (3 212 0 0 0 "" [97 98 99]) (3 212 0 0 0 "" [97 98 100]) (129 212 0 0 0 "" [])"#,
    r#"alt-nested  8 L   numRegexp=5 numRunes=13 | (3 212 0 0 0 "" [97 98 99]) (3 212 0 0 0 "" [97 98 100]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [98])"#,
    r#"alt-nested  9 L   numRegexp=5 numRunes=14 | (3 212 0 0 0 "" [97 98 99]) (3 212 0 0 0 "" [97 98 100]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [98]) (3 212 0 0 0 "" [99])"#,
    r#"alt-nested 10 L   numRegexp=6 numRunes=15 | (3 212 0 0 0 "" [97 98 99]) (3 212 0 0 0 "" [97 98 100]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [98 99]) (3 212 0 0 0 "" [120])"#,
    r#"alt-nested 11 V   numRegexp=6 numRunes=18 | (3 212 0 0 0 "" [97 98 99]) (3 212 0 0 0 "" [97 98 100]) (3 212 0 0 0 "" [98 99 120]) (129 212 0 0 0 "" [])"#,
    r#"alt-nested 12 L   numRegexp=6 numRunes=19 | (3 212 0 0 0 "" [97 98 99]) (3 212 0 0 0 "" [97 98 100]) (3 212 0 0 0 "" [98 99 120]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [98])"#,
    r#"alt-nested 13 L   numRegexp=6 numRunes=20 | (3 212 0 0 0 "" [97 98 99]) (3 212 0 0 0 "" [97 98 100]) (3 212 0 0 0 "" [98 99 120]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [98]) (3 212 0 0 0 "" [99])"#,
    r#"alt-nested 14 L   numRegexp=7 numRunes=21 | (3 212 0 0 0 "" [97 98 99]) (3 212 0 0 0 "" [97 98 100]) (3 212 0 0 0 "" [98 99 120]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [98 99]) (3 212 0 0 0 "" [121])"#,
    r#"alt-nested 15 E   numRegexp=9 numRunes=24 | (19 0 0 0 0 "" [] (18 0 0 0 0 "" [] (3 0 0 0 0 "" [97 98]) (4 212 0 0 0 "" [99 100])) (18 0 0 0 0 "" [] (3 0 0 0 0 "" [98 99]) (4 212 0 0 0 "" [120 121])))"#,
    r#"alt-dupes  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"alt-dupes  1 V   numRegexp=2 numRunes=2 | (3 212 0 0 0 "" [97]) (129 212 0 0 0 "" [])"#,
    r#"alt-dupes  2 L   numRegexp=3 numRunes=3 | (3 212 0 0 0 "" [97]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97])"#,
    r#"alt-dupes  3 V   numRegexp=3 numRunes=4 | (3 212 0 0 0 "" [97]) (129 212 0 0 0 "" [])"#,
    r#"alt-dupes  4 L   numRegexp=3 numRunes=5 | (3 212 0 0 0 "" [97]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97])"#,
    r#"alt-dupes  5 E   numRegexp=3 numRunes=7 | (3 212 0 0 0 "" [97])"#,
    r#"empty  0 X   numRegexp=1 numRunes=0 | (2 0 0 0 0 "" [])"#,
    r#"one  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"one  1 X   numRegexp=1 numRunes=2 | (3 212 0 0 0 "" [97])"#,
    r#"rep  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"rep  1 R   numRegexp=2 numRunes=1 | (17 212 2 5 0 "" [] (3 212 0 0 0 "" [97]))"#,
    r#"rep  2 X   numRegexp=2 numRunes=1 | (17 212 2 5 0 "" [] (3 212 0 0 0 "" [97]))"#,
    r#"repinf  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"repinf  1 R   numRegexp=2 numRunes=1 | (17 212 2 -1 0 "" [] (3 212 0 0 0 "" [97]))"#,
    r#"repinf  2 X   numRegexp=2 numRunes=1 | (17 212 2 -1 0 "" [] (3 212 0 0 0 "" [97]))"#,
    r#"repnone  0 R   numRegexp=0 numRunes=0 |  err="error parsing regexp: missing argument to repetition operator: `x{2}`""#,
    r#"repbig  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"repbig  1 R   numRegexp=2 numRunes=1 | (17 212 2 5 0 "" [] (3 212 0 0 0 "" [97]))"#,
    r#"repbig  2 R   numRegexp=3 numRunes=1 | (17 212 2 5 0 "" [] (17 212 2 5 0 "" [] (3 212 0 0 0 "" [97])))"#,
    r#"repbig  3 R   numRegexp=4 numRunes=1 | (17 212 2 5 0 "" [] (17 212 2 5 0 "" [] (17 212 2 5 0 "" [] (3 212 0 0 0 "" [97]))))"#,
    r#"repbig  4 R   numRegexp=5 numRunes=1 | (17 212 2 5 0 "" [] (17 212 2 5 0 "" [] (17 212 2 5 0 "" [] (17 212 2 5 0 "" [] (3 212 0 0 0 "" [97])))))"#,
    r#"repbig  5 X   numRegexp=5 numRunes=1 | (17 212 2 5 0 "" [] (17 212 2 5 0 "" [] (17 212 2 5 0 "" [] (17 212 2 5 0 "" [] (3 212 0 0 0 "" [97])))))"#,
    r#"reppseudo  0 O   numRegexp=1 numRunes=0 | (128 212 0 0 0 "" [])"#,
    r#"reppseudo  1 R   numRegexp=1 numRunes=0 | (128 212 0 0 0 "" []) err="error parsing regexp: missing argument to repetition operator: `x{2}`""#,
    r#"alt-repclass  0 C   numRegexp=1 numRunes=2 | (4 212 0 0 0 "" [97 122])"#,
    r#"alt-repclass  1 L   numRegexp=2 numRunes=3 | (4 212 0 0 0 "" [97 122]) (3 212 0 0 0 "" [120])"#,
    r#"alt-repclass  2 V   numRegexp=4 numRunes=3 | (18 0 0 0 0 "" [] (4 212 0 0 0 "" [97 122]) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" [])"#,
    r#"alt-repclass  3 C   numRegexp=5 numRunes=5 | (18 0 0 0 0 "" [] (4 212 0 0 0 "" [97 122]) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (4 212 0 0 0 "" [97 122])"#,
    r#"alt-repclass  4 L   numRegexp=6 numRunes=6 | (18 0 0 0 0 "" [] (4 212 0 0 0 "" [97 122]) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (4 212 0 0 0 "" [97 122]) (3 212 0 0 0 "" [121])"#,
    r#"alt-repclass  5 E   numRegexp=8 numRunes=6 | (18 0 0 0 0 "" [] (4 212 0 0 0 "" [97 122]) (4 212 0 0 0 "" [120 121]))"#,
    r#"alt-starprefix  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"alt-starprefix  1 R   numRegexp=2 numRunes=1 | (14 212 0 -1 0 "" [] (3 212 0 0 0 "" [97]))"#,
    r#"alt-starprefix  2 L   numRegexp=3 numRunes=2 | (14 212 0 -1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [120])"#,
    r#"alt-starprefix  3 V   numRegexp=5 numRunes=2 | (18 0 0 0 0 "" [] (14 212 0 -1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" [])"#,
    r#"alt-starprefix  4 L   numRegexp=6 numRunes=3 | (18 0 0 0 0 "" [] (14 212 0 -1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97])"#,
    r#"alt-starprefix  5 R   numRegexp=7 numRunes=3 | (18 0 0 0 0 "" [] (14 212 0 -1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (14 212 0 -1 0 "" [] (3 212 0 0 0 "" [97]))"#,
    r#"alt-starprefix  6 L   numRegexp=8 numRunes=4 | (18 0 0 0 0 "" [] (14 212 0 -1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (14 212 0 -1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [121])"#,
    r#"alt-starprefix  7 E   numRegexp=10 numRunes=4 | (19 0 0 0 0 "" [] (18 0 0 0 0 "" [] (14 212 0 -1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [120])) (18 0 0 0 0 "" [] (14 212 0 -1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [121])))"#,
    r#"alt-plusprefix  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"alt-plusprefix  1 R   numRegexp=2 numRunes=1 | (15 212 1 -1 0 "" [] (3 212 0 0 0 "" [97]))"#,
    r#"alt-plusprefix  2 L   numRegexp=3 numRunes=2 | (15 212 1 -1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [120])"#,
    r#"alt-plusprefix  3 V   numRegexp=5 numRunes=2 | (18 0 0 0 0 "" [] (15 212 1 -1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" [])"#,
    r#"alt-plusprefix  4 L   numRegexp=6 numRunes=3 | (18 0 0 0 0 "" [] (15 212 1 -1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97])"#,
    r#"alt-plusprefix  5 R   numRegexp=7 numRunes=3 | (18 0 0 0 0 "" [] (15 212 1 -1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (15 212 1 -1 0 "" [] (3 212 0 0 0 "" [97]))"#,
    r#"alt-plusprefix  6 L   numRegexp=8 numRunes=4 | (18 0 0 0 0 "" [] (15 212 1 -1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (15 212 1 -1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [121])"#,
    r#"alt-plusprefix  7 E   numRegexp=10 numRunes=4 | (19 0 0 0 0 "" [] (18 0 0 0 0 "" [] (15 212 1 -1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [120])) (18 0 0 0 0 "" [] (15 212 1 -1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [121])))"#,
    r#"alt-questprefix  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"alt-questprefix  1 R   numRegexp=2 numRunes=1 | (16 212 0 1 0 "" [] (3 212 0 0 0 "" [97]))"#,
    r#"alt-questprefix  2 L   numRegexp=3 numRunes=2 | (16 212 0 1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [120])"#,
    r#"alt-questprefix  3 V   numRegexp=5 numRunes=2 | (18 0 0 0 0 "" [] (16 212 0 1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" [])"#,
    r#"alt-questprefix  4 L   numRegexp=6 numRunes=3 | (18 0 0 0 0 "" [] (16 212 0 1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97])"#,
    r#"alt-questprefix  5 R   numRegexp=7 numRunes=3 | (18 0 0 0 0 "" [] (16 212 0 1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (16 212 0 1 0 "" [] (3 212 0 0 0 "" [97]))"#,
    r#"alt-questprefix  6 L   numRegexp=8 numRunes=4 | (18 0 0 0 0 "" [] (16 212 0 1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (16 212 0 1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [121])"#,
    r#"alt-questprefix  7 E   numRegexp=10 numRunes=4 | (19 0 0 0 0 "" [] (18 0 0 0 0 "" [] (16 212 0 1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [120])) (18 0 0 0 0 "" [] (16 212 0 1 0 "" [] (3 212 0 0 0 "" [97])) (3 212 0 0 0 "" [121])))"#,
    r#"alt-fixedrep  0 C   numRegexp=1 numRunes=2 | (4 212 0 0 0 "" [97 122])"#,
    r#"alt-fixedrep  1 R   numRegexp=2 numRunes=2 | (17 212 2 2 0 "" [] (4 212 0 0 0 "" [97 122]))"#,
    r#"alt-fixedrep  2 L   numRegexp=3 numRunes=3 | (17 212 2 2 0 "" [] (4 212 0 0 0 "" [97 122])) (3 212 0 0 0 "" [120])"#,
    r#"alt-fixedrep  3 V   numRegexp=5 numRunes=3 | (18 0 0 0 0 "" [] (17 212 2 2 0 "" [] (4 212 0 0 0 "" [97 122])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" [])"#,
    r#"alt-fixedrep  4 C   numRegexp=6 numRunes=5 | (18 0 0 0 0 "" [] (17 212 2 2 0 "" [] (4 212 0 0 0 "" [97 122])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (4 212 0 0 0 "" [97 122])"#,
    r#"alt-fixedrep  5 R   numRegexp=7 numRunes=5 | (18 0 0 0 0 "" [] (17 212 2 2 0 "" [] (4 212 0 0 0 "" [97 122])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (17 212 2 2 0 "" [] (4 212 0 0 0 "" [97 122]))"#,
    r#"alt-fixedrep  6 L   numRegexp=8 numRunes=6 | (18 0 0 0 0 "" [] (17 212 2 2 0 "" [] (4 212 0 0 0 "" [97 122])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (17 212 2 2 0 "" [] (4 212 0 0 0 "" [97 122])) (3 212 0 0 0 "" [121])"#,
    r#"alt-fixedrep  7 E   numRegexp=10 numRunes=6 | (18 0 0 0 0 "" [] (17 212 2 2 0 "" [] (4 212 0 0 0 "" [97 122])) (4 212 0 0 0 "" [120 121]))"#,
    r#"alt-rangerep  0 C   numRegexp=1 numRunes=2 | (4 212 0 0 0 "" [97 122])"#,
    r#"alt-rangerep  1 R   numRegexp=2 numRunes=2 | (17 212 2 3 0 "" [] (4 212 0 0 0 "" [97 122]))"#,
    r#"alt-rangerep  2 L   numRegexp=3 numRunes=3 | (17 212 2 3 0 "" [] (4 212 0 0 0 "" [97 122])) (3 212 0 0 0 "" [120])"#,
    r#"alt-rangerep  3 V   numRegexp=5 numRunes=3 | (18 0 0 0 0 "" [] (17 212 2 3 0 "" [] (4 212 0 0 0 "" [97 122])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" [])"#,
    r#"alt-rangerep  4 C   numRegexp=6 numRunes=5 | (18 0 0 0 0 "" [] (17 212 2 3 0 "" [] (4 212 0 0 0 "" [97 122])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (4 212 0 0 0 "" [97 122])"#,
    r#"alt-rangerep  5 R   numRegexp=7 numRunes=5 | (18 0 0 0 0 "" [] (17 212 2 3 0 "" [] (4 212 0 0 0 "" [97 122])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (17 212 2 3 0 "" [] (4 212 0 0 0 "" [97 122]))"#,
    r#"alt-rangerep  6 L   numRegexp=8 numRunes=6 | (18 0 0 0 0 "" [] (17 212 2 3 0 "" [] (4 212 0 0 0 "" [97 122])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (17 212 2 3 0 "" [] (4 212 0 0 0 "" [97 122])) (3 212 0 0 0 "" [121])"#,
    r#"alt-rangerep  7 E   numRegexp=10 numRunes=6 | (19 0 0 0 0 "" [] (18 0 0 0 0 "" [] (17 212 2 3 0 "" [] (4 212 0 0 0 "" [97 122])) (3 212 0 0 0 "" [120])) (18 0 0 0 0 "" [] (17 212 2 3 0 "" [] (4 212 0 0 0 "" [97 122])) (3 212 0 0 0 "" [121])))"#,
    r#"alt-fixedrepgrp  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"alt-fixedrepgrp  1 L   numRegexp=2 numRunes=2 | (3 212 0 0 0 "" [97]) (3 212 0 0 0 "" [98])"#,
    r#"alt-fixedrepgrp  2 X   numRegexp=2 numRunes=4 | (3 212 0 0 0 "" [97 98])"#,
    r#"alt-fixedrepgrp  3 R   numRegexp=2 numRunes=4 | (17 212 2 2 0 "" [] (3 212 0 0 0 "" [97 98]))"#,
    r#"alt-fixedrepgrp  4 L   numRegexp=3 numRunes=5 | (17 212 2 2 0 "" [] (3 212 0 0 0 "" [97 98])) (3 212 0 0 0 "" [120])"#,
    r#"alt-fixedrepgrp  5 V   numRegexp=5 numRunes=5 | (18 0 0 0 0 "" [] (17 212 2 2 0 "" [] (3 212 0 0 0 "" [97 98])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" [])"#,
    r#"alt-fixedrepgrp  6 L   numRegexp=6 numRunes=6 | (18 0 0 0 0 "" [] (17 212 2 2 0 "" [] (3 212 0 0 0 "" [97 98])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97])"#,
    r#"alt-fixedrepgrp  7 L   numRegexp=7 numRunes=7 | (18 0 0 0 0 "" [] (17 212 2 2 0 "" [] (3 212 0 0 0 "" [97 98])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97]) (3 212 0 0 0 "" [98])"#,
    r#"alt-fixedrepgrp  8 X   numRegexp=7 numRunes=9 | (18 0 0 0 0 "" [] (17 212 2 2 0 "" [] (3 212 0 0 0 "" [97 98])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97 98])"#,
    r#"alt-fixedrepgrp  9 R   numRegexp=7 numRunes=9 | (18 0 0 0 0 "" [] (17 212 2 2 0 "" [] (3 212 0 0 0 "" [97 98])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (17 212 2 2 0 "" [] (3 212 0 0 0 "" [97 98]))"#,
    r#"alt-fixedrepgrp 10 L   numRegexp=8 numRunes=10 | (18 0 0 0 0 "" [] (17 212 2 2 0 "" [] (3 212 0 0 0 "" [97 98])) (3 212 0 0 0 "" [120])) (129 212 0 0 0 "" []) (17 212 2 2 0 "" [] (3 212 0 0 0 "" [97 98])) (3 212 0 0 0 "" [121])"#,
    r#"alt-fixedrepgrp 11 E   numRegexp=10 numRunes=10 | (19 0 0 0 0 "" [] (18 0 0 0 0 "" [] (17 212 2 2 0 "" [] (3 212 0 0 0 "" [97 98])) (3 212 0 0 0 "" [120])) (18 0 0 0 0 "" [] (17 212 2 2 0 "" [] (3 212 0 0 0 "" [97 98])) (3 212 0 0 0 "" [121])))"#,
    r#"fold-mid  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"fold-mid  1 L   numRegexp=2 numRunes=2 | (3 212 0 0 0 "" [97]) (3 212 0 0 0 "" [98])"#,
    r#"fold-mid  2 F   numRegexp=2 numRunes=2 | (3 212 0 0 0 "" [97]) (3 212 0 0 0 "" [98])"#,
    r#"fold-mid  3 L   numRegexp=3 numRunes=3 | (3 212 0 0 0 "" [97 98]) (3 213 0 0 0 "" [67])"#,
    r#"fold-mid  4 L   numRegexp=3 numRunes=4 | (3 212 0 0 0 "" [97 98]) (3 213 0 0 0 "" [67]) (3 213 0 0 0 "" [68])"#,
    r#"fold-mid  5 F   numRegexp=3 numRunes=4 | (3 212 0 0 0 "" [97 98]) (3 213 0 0 0 "" [67]) (3 213 0 0 0 "" [68])"#,
    r#"fold-mid  6 L   numRegexp=4 numRunes=5 | (3 212 0 0 0 "" [97 98]) (3 213 0 0 0 "" [67 68]) (3 212 0 0 0 "" [101])"#,
    r#"fold-mid  7 X   numRegexp=4 numRunes=5 | (18 0 0 0 0 "" [] (3 212 0 0 0 "" [97 98]) (3 213 0 0 0 "" [67 68]) (3 212 0 0 0 "" [101]))"#,
    r#"fold-all  0 L   numRegexp=1 numRunes=1 | (3 213 0 0 0 "" [65])"#,
    r#"fold-all  1 L   numRegexp=2 numRunes=2 | (3 213 0 0 0 "" [65]) (3 213 0 0 0 "" [66])"#,
    r#"fold-all  2 L   numRegexp=3 numRunes=3 | (3 213 0 0 0 "" [65 66]) (3 213 0 0 0 "" [67])"#,
    r#"fold-all  3 X   numRegexp=3 numRunes=6 | (3 213 0 0 0 "" [65 66 67])"#,
    r#"fold-alt  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"fold-alt  1 F   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"fold-alt  2 L   numRegexp=2 numRunes=2 | (3 212 0 0 0 "" [97]) (3 213 0 0 0 "" [66])"#,
    r#"fold-alt  3 V   numRegexp=4 numRunes=2 | (18 0 0 0 0 "" [] (3 212 0 0 0 "" [97]) (3 213 0 0 0 "" [66])) (129 213 0 0 0 "" [])"#,
    r#"fold-alt  4 F   numRegexp=4 numRunes=2 | (18 0 0 0 0 "" [] (3 212 0 0 0 "" [97]) (3 213 0 0 0 "" [66])) (129 213 0 0 0 "" [])"#,
    r#"fold-alt  5 L   numRegexp=5 numRunes=3 | (18 0 0 0 0 "" [] (3 212 0 0 0 "" [97]) (3 213 0 0 0 "" [66])) (129 213 0 0 0 "" []) (3 212 0 0 0 "" [97])"#,
    r#"fold-alt  6 F   numRegexp=5 numRunes=3 | (18 0 0 0 0 "" [] (3 212 0 0 0 "" [97]) (3 213 0 0 0 "" [66])) (129 213 0 0 0 "" []) (3 212 0 0 0 "" [97])"#,
    r#"fold-alt  7 L   numRegexp=6 numRunes=4 | (18 0 0 0 0 "" [] (3 212 0 0 0 "" [97]) (3 213 0 0 0 "" [66])) (129 213 0 0 0 "" []) (3 212 0 0 0 "" [97]) (3 213 0 0 0 "" [67])"#,
    r#"fold-alt  8 E   numRegexp=9 numRunes=4 | (18 0 0 0 0 "" [] (3 0 0 0 0 "" [97]) (4 213 0 0 0 "" [66 67 98 99]))"#,
    r#"fold-back  0 L   numRegexp=1 numRunes=1 | (3 213 0 0 0 "" [65])"#,
    r#"fold-back  1 F   numRegexp=1 numRunes=1 | (3 213 0 0 0 "" [65])"#,
    r#"fold-back  2 L   numRegexp=2 numRunes=2 | (3 213 0 0 0 "" [65]) (3 212 0 0 0 "" [98])"#,
    r#"fold-back  3 F   numRegexp=2 numRunes=2 | (3 213 0 0 0 "" [65]) (3 212 0 0 0 "" [98])"#,
    r#"fold-back  4 L   numRegexp=3 numRunes=3 | (3 213 0 0 0 "" [65]) (3 212 0 0 0 "" [98]) (3 213 0 0 0 "" [67])"#,
    r#"fold-back  5 X   numRegexp=4 numRunes=3 | (18 0 0 0 0 "" [] (3 213 0 0 0 "" [65]) (3 212 0 0 0 "" [98]) (3 213 0 0 0 "" [67]))"#,
    r#"swap-lit-class  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"swap-lit-class  1 V   numRegexp=2 numRunes=2 | (3 212 0 0 0 "" [97]) (129 212 0 0 0 "" [])"#,
    r#"swap-lit-class  2 C   numRegexp=3 numRunes=4 | (3 212 0 0 0 "" [97]) (129 212 0 0 0 "" []) (4 212 0 0 0 "" [120 122])"#,
    r#"swap-lit-class  3 E   numRegexp=3 numRunes=10 | (4 212 0 0 0 "" [97 97 120 122])"#,
    r#"swap-class-lit  0 C   numRegexp=1 numRunes=2 | (4 212 0 0 0 "" [120 122])"#,
    r#"swap-class-lit  1 V   numRegexp=2 numRunes=4 | (4 212 0 0 0 "" [120 122]) (129 212 0 0 0 "" [])"#,
    r#"swap-class-lit  2 L   numRegexp=3 numRunes=5 | (4 212 0 0 0 "" [120 122]) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97])"#,
    r#"swap-class-lit  3 E   numRegexp=3 numRunes=10 | (4 212 0 0 0 "" [97 97 120 122])"#,
    r#"swap-lit-any  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"swap-lit-any  1 V   numRegexp=2 numRunes=2 | (3 212 0 0 0 "" [97]) (129 212 0 0 0 "" [])"#,
    r#"swap-lit-any  2 O   numRegexp=3 numRunes=2 | (3 212 0 0 0 "" [97]) (129 212 0 0 0 "" []) (6 212 0 0 0 "" [])"#,
    r#"swap-lit-any  3 E   numRegexp=3 numRunes=2 | (6 212 0 0 0 "" [])"#,
    r#"swap-any-lit  0 O   numRegexp=1 numRunes=0 | (6 212 0 0 0 "" [])"#,
    r#"swap-any-lit  1 V   numRegexp=2 numRunes=0 | (6 212 0 0 0 "" []) (129 212 0 0 0 "" [])"#,
    r#"swap-any-lit  2 L   numRegexp=3 numRunes=1 | (6 212 0 0 0 "" []) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97])"#,
    r#"swap-any-lit  3 E   numRegexp=3 numRunes=2 | (6 212 0 0 0 "" [])"#,
    r#"swap-lit-notnl  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"swap-lit-notnl  1 V   numRegexp=2 numRunes=2 | (3 212 0 0 0 "" [97]) (129 212 0 0 0 "" [])"#,
    r#"swap-lit-notnl  2 O   numRegexp=3 numRunes=2 | (3 212 0 0 0 "" [97]) (129 212 0 0 0 "" []) (5 212 0 0 0 "" [])"#,
    r#"swap-lit-notnl  3 E   numRegexp=3 numRunes=2 | (5 212 0 0 0 "" [])"#,
    r#"swap-notnl-lit  0 O   numRegexp=1 numRunes=0 | (5 212 0 0 0 "" [])"#,
    r#"swap-notnl-lit  1 V   numRegexp=2 numRunes=0 | (5 212 0 0 0 "" []) (129 212 0 0 0 "" [])"#,
    r#"swap-notnl-lit  2 L   numRegexp=3 numRunes=1 | (5 212 0 0 0 "" []) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [97])"#,
    r#"swap-notnl-lit  3 E   numRegexp=3 numRunes=2 | (5 212 0 0 0 "" [])"#,
    r#"swap-class-any  0 C   numRegexp=1 numRunes=2 | (4 212 0 0 0 "" [120 122])"#,
    r#"swap-class-any  1 V   numRegexp=2 numRunes=4 | (4 212 0 0 0 "" [120 122]) (129 212 0 0 0 "" [])"#,
    r#"swap-class-any  2 O   numRegexp=3 numRunes=4 | (4 212 0 0 0 "" [120 122]) (129 212 0 0 0 "" []) (6 212 0 0 0 "" [])"#,
    r#"swap-class-any  3 E   numRegexp=3 numRunes=4 | (6 212 0 0 0 "" [])"#,
    r#"swap-any-class  0 O   numRegexp=1 numRunes=0 | (6 212 0 0 0 "" [])"#,
    r#"swap-any-class  1 V   numRegexp=2 numRunes=0 | (6 212 0 0 0 "" []) (129 212 0 0 0 "" [])"#,
    r#"swap-any-class  2 C   numRegexp=3 numRunes=2 | (6 212 0 0 0 "" []) (129 212 0 0 0 "" []) (4 212 0 0 0 "" [120 122])"#,
    r#"swap-any-class  3 E   numRegexp=3 numRunes=4 | (6 212 0 0 0 "" [])"#,
    r#"swap-notnl-nl  0 O   numRegexp=1 numRunes=0 | (5 212 0 0 0 "" [])"#,
    r#"swap-notnl-nl  1 V   numRegexp=2 numRunes=0 | (5 212 0 0 0 "" []) (129 212 0 0 0 "" [])"#,
    r#"swap-notnl-nl  2 L   numRegexp=3 numRunes=1 | (5 212 0 0 0 "" []) (129 212 0 0 0 "" []) (3 212 0 0 0 "" [10])"#,
    r#"swap-notnl-nl  3 E   numRegexp=3 numRunes=2 | (6 212 0 0 0 "" [])"#,
    r#"swap-three  0 L   numRegexp=1 numRunes=1 | (3 212 0 0 0 "" [97])"#,
    r#"swap-three  1 V   numRegexp=2 numRunes=2 | (3 212 0 0 0 "" [97]) (129 212 0 0 0 "" [])"#,
    r#"swap-three  2 C   numRegexp=3 numRunes=4 | (3 212 0 0 0 "" [97]) (129 212 0 0 0 "" []) (4 212 0 0 0 "" [120 122])"#,
    r#"swap-three  3 V   numRegexp=3 numRunes=6 | (4 212 0 0 0 "" [120 122 97 97]) (129 212 0 0 0 "" [])"#,
    r#"swap-three  4 O   numRegexp=3 numRunes=6 | (4 212 0 0 0 "" [120 122 97 97]) (129 212 0 0 0 "" []) (5 212 0 0 0 "" [])"#,
    r#"swap-three  5 E   numRegexp=3 numRunes=6 | (5 212 0 0 0 "" [])"#,
    r#"swap-classes  0 C   numRegexp=1 numRunes=2 | (4 212 0 0 0 "" [97 99])"#,
    r#"swap-classes  1 V   numRegexp=2 numRunes=4 | (4 212 0 0 0 "" [97 99]) (129 212 0 0 0 "" [])"#,
    r#"swap-classes  2 C   numRegexp=3 numRunes=6 | (4 212 0 0 0 "" [97 99]) (129 212 0 0 0 "" []) (4 212 0 0 0 "" [120 122])"#,
    r#"swap-classes  3 E   numRegexp=3 numRunes=12 | (4 212 0 0 0 "" [97 99 120 122])"#,
    r#"swap-bigclass  0 C   numRegexp=1 numRunes=4 | (4 212 0 0 0 "" [97 99 101 103])"#,
    r#"swap-bigclass  1 V   numRegexp=2 numRunes=8 | (4 212 0 0 0 "" [97 99 101 103]) (129 212 0 0 0 "" [])"#,
    r#"swap-bigclass  2 C   numRegexp=3 numRunes=10 | (4 212 0 0 0 "" [97 99 101 103]) (129 212 0 0 0 "" []) (4 212 0 0 0 "" [120 122])"#,
    r#"swap-bigclass  3 E   numRegexp=3 numRunes=18 | (4 212 0 0 0 "" [97 99 101 103 120 122])"#,
];

fn line(ln: &mut usize, got: string) {
    unsafe { RUN += 1 };
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        unsafe { FAILED += 1 };
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!(
            "[!!] line %d\n  got  %q\n  want %q\n",
            *ln as int + 1,
            got,
            GO[*ln]
        );
        unsafe { FAILED += 1 };
    }
    *ln += 1;
}

/// `%-Ns`, padded by RUNE count as Go's fmt measures it.
fn l(s: string, w: int) -> string {
    let mut o = s;
    while goish::len(&goish::runes(o.clone())) < w {
        o = o + string::from_static(" ");
    }
    return o;
}

/// `%Nd`
fn d(v: i64, w: int) -> string {
    let mut o = strconv::Itoa(int::from(v));
    while o.Len() < w {
        o = string::from_static(" ") + o;
    }
    return o;
}

/// One scripted operation, matching the reference's `opn`.
enum Op {
    L(rune),
    O(syntax::Op),
    C(&'static [rune]),
    X,
    A,
    /// `parseVerticalBar` — concat, then move the alternative below
    /// the `|` marker (or push one).
    V,
    /// The close sequence: concat, pop the bar, alternate.
    E,
    R(syntax::Op, i64, i64),
    F(u16),
}

fn kind(o: &Op) -> &'static str {
    return match o {
        Op::L(_) => "L",
        Op::O(_) => "O",
        Op::C(_) => "C",
        Op::X => "X",
        Op::A => "A",
        Op::V => "V",
        Op::E => "E",
        Op::R(_, _, _) => "R",
        Op::F(_) => "F",
    };
}

fn run(ln: &mut usize, name: &'static str, flags: syntax::Flags, script: &[Op]) {
    let mut p = parse::__Parser::__new(string::from_static("zz"), flags);
    for (i, o) in script.iter().enumerate() {
        let mut errs = string::from_static("");
        match o {
            Op::L(r) => p.__literal(*r),
            Op::O(op) => p.__op(*op),
            Op::C(rs) => p.__class(rs),
            Op::X => p.__concat(),
            Op::A => p.__alternate(),
            Op::V => p.__verticalBar(),
            Op::E => p.__closeGroup(),
            Op::R(op, min, max) => {
                let e = p.__repeat(*op, int::from(*min), int::from(*max));
                if !e.IsNil() {
                    errs = string::from_static(" err=") + strconv::Quote(e.Error());
                }
            }
            Op::F(f) => p.__setflags(syntax::Flags(*f)),
        }
        line(
            ln,
            string::from_static(name)
                + string::from_static(" ")
                + d(i as i64, int::from(2))
                + string::from_static(" ")
                + l(string::from_static(kind(o)), int::from(3))
                + string::from_static(" numRegexp=")
                + strconv::Itoa(p.__numRegexp())
                + string::from_static(" numRunes=")
                + strconv::Itoa(p.__numRunes())
                + string::from_static(" | ")
                + p.__dump()
                + errs,
        );
    }
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    let perl = syntax::Perl;
    let (lparen, vbar) = parse::__pseudoOps();
    let star = syntax::OpStar;
    let rep = syntax::OpRepeat;

    // Incremental concatenation: three literals become one node.
    run(
        &mut ln,
        "concat",
        perl,
        &[Op::L('a' as rune), Op::L('b' as rune), Op::L('c' as rune), Op::X],
    );

    // A repeat stops the run: `ab*` is a then b*, not (ab)*.
    run(
        &mut ln,
        "abstar",
        perl,
        &[Op::L('a' as rune), Op::L('b' as rune), Op::R(star, 0, -1), Op::X],
    );

    // A class of one rune collapses to a literal and then concatenates.
    run(
        &mut ln,
        "class1",
        perl,
        &[Op::L('a' as rune), Op::C(&['b' as rune, 'b' as rune]), Op::X],
    );

    // A fold pair collapses to a FOLDED literal.
    run(
        &mut ln,
        "foldpair",
        perl,
        &[Op::C(&['A' as rune, 'A' as rune, 'a' as rune, 'a' as rune]), Op::X],
    );
    run(&mut ln, "foldadj", perl, &[Op::C(&[0x394, 0x395]), Op::X]);
    run(
        &mut ln,
        "foldK",
        perl,
        &[Op::C(&['K' as rune, 'K' as rune, 'k' as rune, 'k' as rune]), Op::X],
    );
    run(
        &mut ln,
        "notfold",
        perl,
        &[Op::C(&['a' as rune, 'a' as rune, 'z' as rune, 'z' as rune]), Op::X],
    );

    // Fold flag changes mid-run: the two literals must not merge.
    run(
        &mut ln,
        "flagsplit",
        perl,
        &[
            Op::L('a' as rune),
            Op::F(syntax::Perl.0 | syntax::FoldCase.0),
            Op::L('b' as rune),
            Op::X,
        ],
    );

    // Alternation and the factoring rounds.
    run(
        &mut ln,
        "alt-simple",
        perl,
        &[Op::L('a' as rune), Op::V, Op::L('b' as rune), Op::E],
    );
    run(
        &mut ln,
        "alt-prefix",
        perl,
        &[
            Op::L('a' as rune), Op::L('b' as rune), Op::L('c' as rune), Op::V,
            Op::L('a' as rune), Op::L('b' as rune), Op::L('d' as rune), Op::V,
            Op::L('a' as rune), Op::L('e' as rune), Op::L('f' as rune), Op::E,
        ],
    );
    run(
        &mut ln,
        "alt-class",
        perl,
        &[
            Op::L('a' as rune), Op::V, Op::L('b' as rune), Op::V,
            Op::L('c' as rune), Op::E,
        ],
    );
    run(&mut ln, "alt-empty", perl, &[Op::E]);
    run(&mut ln, "alt-one", perl, &[Op::L('a' as rune), Op::E]);
    run(
        &mut ln,
        "alt-nested",
        perl,
        &[
            Op::L('a' as rune), Op::L('b' as rune), Op::L('c' as rune), Op::V,
            Op::L('a' as rune), Op::L('b' as rune), Op::L('d' as rune), Op::V,
            Op::L('b' as rune), Op::L('c' as rune), Op::L('x' as rune), Op::V,
            Op::L('b' as rune), Op::L('c' as rune), Op::L('y' as rune), Op::E,
        ],
    );
    run(
        &mut ln,
        "alt-dupes",
        perl,
        &[
            Op::L('a' as rune), Op::V, Op::L('a' as rune), Op::V,
            Op::L('a' as rune), Op::E,
        ],
    );

    // Empty concat, and a concat of one.
    run(&mut ln, "empty", perl, &[Op::X]);
    run(&mut ln, "one", perl, &[Op::L('a' as rune), Op::X]);

    // Repeats, and the two refusals.
    run(&mut ln, "rep", perl, &[Op::L('a' as rune), Op::R(rep, 2, 5), Op::X]);
    run(&mut ln, "repinf", perl, &[Op::L('a' as rune), Op::R(rep, 2, -1), Op::X]);
    run(&mut ln, "repnone", perl, &[Op::R(star, 0, -1)]);
    run(
        &mut ln,
        "repbig",
        perl,
        &[
            Op::L('a' as rune), Op::R(rep, 2, 5), Op::R(rep, 2, 5), Op::R(rep, 2, 5),
            Op::R(rep, 2, 5), Op::X,
        ],
    );
    run(&mut ln, "reppseudo", perl, &[Op::O(lparen), Op::R(star, 0, -1)]);

    // Round 2 factors a common leading REGEXP, but only when it is a
    // character class or a fixed repeat of one. These are both sides
    // of that restriction.
    let az: &[rune] = &['a' as rune, 'z' as rune];
    let plus = syntax::OpPlus;
    let quest = syntax::OpQuest;
    run(
        &mut ln,
        "alt-repclass",
        perl,
        &[
            Op::C(az), Op::L('x' as rune), Op::V,
            Op::C(az), Op::L('y' as rune), Op::E,
        ],
    );
    // a*x|a*y — the leading regexp is a STAR, so it must NOT factor:
    // "Complex subexpressions (e.g. involving quantifiers) are not
    // safe to factor because that collapses their distinct paths
    // through the automaton."
    run(
        &mut ln,
        "alt-starprefix",
        perl,
        &[
            Op::L('a' as rune), Op::R(star, 0, -1), Op::L('x' as rune), Op::V,
            Op::L('a' as rune), Op::R(star, 0, -1), Op::L('y' as rune), Op::E,
        ],
    );
    run(
        &mut ln,
        "alt-plusprefix",
        perl,
        &[
            Op::L('a' as rune), Op::R(plus, 1, -1), Op::L('x' as rune), Op::V,
            Op::L('a' as rune), Op::R(plus, 1, -1), Op::L('y' as rune), Op::E,
        ],
    );
    run(
        &mut ln,
        "alt-questprefix",
        perl,
        &[
            Op::L('a' as rune), Op::R(quest, 0, 1), Op::L('x' as rune), Op::V,
            Op::L('a' as rune), Op::R(quest, 0, 1), Op::L('y' as rune), Op::E,
        ],
    );
    // [a-z]{2}x|[a-z]{2}y — a FIXED repeat of a class, which may.
    run(
        &mut ln,
        "alt-fixedrep",
        perl,
        &[
            Op::C(az), Op::R(rep, 2, 2), Op::L('x' as rune), Op::V,
            Op::C(az), Op::R(rep, 2, 2), Op::L('y' as rune), Op::E,
        ],
    );
    // [a-z]{2,3}x|[a-z]{2,3}y — NOT fixed, so it must not.
    run(
        &mut ln,
        "alt-rangerep",
        perl,
        &[
            Op::C(az), Op::R(rep, 2, 3), Op::L('x' as rune), Op::V,
            Op::C(az), Op::R(rep, 2, 3), Op::L('y' as rune), Op::E,
        ],
    );
    // A repeat of a non-class, fixed count: still refused.
    run(
        &mut ln,
        "alt-fixedrepgrp",
        perl,
        &[
            Op::L('a' as rune), Op::L('b' as rune), Op::X, Op::R(rep, 2, 2),
            Op::L('x' as rune), Op::V,
            Op::L('a' as rune), Op::L('b' as rune), Op::X, Op::R(rep, 2, 2),
            Op::L('y' as rune), Op::E,
        ],
    );

    // The fold flag gates maybeConcat's merge. More than one position,
    // and inside an alternation.
    let foldperl = syntax::Perl.0 | syntax::FoldCase.0;
    run(
        &mut ln,
        "fold-mid",
        perl,
        &[
            Op::L('a' as rune), Op::L('b' as rune), Op::F(foldperl),
            Op::L('c' as rune), Op::L('d' as rune), Op::F(syntax::Perl.0),
            Op::L('e' as rune), Op::X,
        ],
    );
    run(
        &mut ln,
        "fold-all",
        syntax::Flags(foldperl),
        &[Op::L('a' as rune), Op::L('b' as rune), Op::L('c' as rune), Op::X],
    );
    run(
        &mut ln,
        "fold-alt",
        perl,
        &[
            Op::L('a' as rune), Op::F(foldperl), Op::L('b' as rune), Op::V,
            Op::F(syntax::Perl.0), Op::L('a' as rune), Op::F(foldperl),
            Op::L('c' as rune), Op::E,
        ],
    );
    run(
        &mut ln,
        "fold-back",
        syntax::Flags(foldperl),
        &[
            Op::L('a' as rune), Op::F(syntax::Perl.0), Op::L('b' as rune),
            Op::F(foldperl), Op::L('c' as rune), Op::X,
        ],
    );

    // swapVerticalBar merges two single-rune alternatives, and swaps so
    // the MORE COMPLEX one is the destination. Without the swap,
    // mergeCharClass's OpLiteral arm reads src.Rune[0] out of a CLASS,
    // where it is a range start and not a rune. Every ordering of the
    // four ranks — literal(3) < class(4) < anynotnl(5) < any(6).
    let anych = syntax::OpAnyChar;
    let notnl = syntax::OpAnyCharNotNL;
    let xz: &[rune] = &['x' as rune, 'z' as rune];
    run(&mut ln, "swap-lit-class", perl, &[Op::L('a' as rune), Op::V, Op::C(xz), Op::E]);
    run(&mut ln, "swap-class-lit", perl, &[Op::C(xz), Op::V, Op::L('a' as rune), Op::E]);
    run(&mut ln, "swap-lit-any", perl, &[Op::L('a' as rune), Op::V, Op::O(anych), Op::E]);
    run(&mut ln, "swap-any-lit", perl, &[Op::O(anych), Op::V, Op::L('a' as rune), Op::E]);
    run(&mut ln, "swap-lit-notnl", perl, &[Op::L('a' as rune), Op::V, Op::O(notnl), Op::E]);
    run(&mut ln, "swap-notnl-lit", perl, &[Op::O(notnl), Op::V, Op::L('a' as rune), Op::E]);
    run(&mut ln, "swap-class-any", perl, &[Op::C(xz), Op::V, Op::O(anych), Op::E]);
    run(&mut ln, "swap-any-class", perl, &[Op::O(anych), Op::V, Op::C(xz), Op::E]);
    run(&mut ln, "swap-notnl-nl", perl, &[Op::O(notnl), Op::V, Op::L('\n' as rune), Op::E]);
    run(
        &mut ln,
        "swap-three",
        perl,
        &[Op::L('a' as rune), Op::V, Op::C(xz), Op::V, Op::O(notnl), Op::E],
    );
    run(
        &mut ln,
        "swap-classes",
        perl,
        &[Op::C(&['a' as rune, 'c' as rune]), Op::V, Op::C(xz), Op::E],
    );
    run(
        &mut ln,
        "swap-bigclass",
        perl,
        &[
            Op::C(&['a' as rune, 'c' as rune, 'e' as rune, 'g' as rune]),
            Op::V, Op::C(xz), Op::E,
        ],
    );

    let run_ = unsafe { RUN };
    let f = unsafe { FAILED };
    if run_ != GO.len() as int {
        fmt::Printf!("\nFAIL ran %d of %d rows\n", run_, GO.len() as int);
        goish::os::Exit(1);
    }
    if f == 0 {
        fmt::Printf!("\nok %d/%d\n", run_, run_);
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAIL %d\n", f);
    goish::os::Exit(1);
}
