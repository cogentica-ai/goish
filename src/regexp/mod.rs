// regexp — Go's `regexp` package, on the RE2 construction.
//
// ─── the linear-time guarantee, kept ─────────────────────────────────
//
// Go's package documentation makes a promise:
//
//   "The regexp implementation provided by this package is guaranteed
//    to run in time linear in the size of the input."
//
// Until 2026-09-14 this file did NOT keep it. It was a backtracking
// matcher over an AST, and a pattern with nested quantifiers was
// exponential in the input. Measured then, `(a+)+$` against n 'a's and
// a '!', release build:
//
//     n=14     90 ms          n=20   6,194 ms
//     n=18  1,467 ms          n=22  27,338 ms
//
// Each character doubled the work, so twenty-five bytes hung the
// process and n=40 was about eighty days. The ANSWER was correct at
// every size; the time was not bounded. Any port relying on the
// guarantee — a router, a log filter, an input validator — inherited a
// denial of service it did not have in Go.
//
// It now runs Go's construction, ported in `syntax/` and `exec.rs`:
// parse to an AST, simplify the counted repetitions away, compile to an
// instruction program, and simulate the NFA with a thread list. Same
// pattern, same machine, release build:
//
//     n=22     42 µs          n=200    334 µs
//
// The bound is not a measurement, it is structural. `exec.rs`'s `add`
// refuses to enqueue a program counter already on the queue, so each
// input position does at most O(len(prog)) work and the whole match is
// O(len(prog) x len(input)). `examples/regexp_exec_ref_smoke.rs`
// asserts it by COUNTING those calls rather than timing them — 6n+4,
// exactly linear — because a wall-clock assertion is a flake waiting to
// happen on shared CI.
//
// ─── what is not ported ──────────────────────────────────────────────
//
// Go has three engines: `onepass` for patterns whose automaton never
// branches, `backtrack` for small programs and short inputs, and the
// NFA. goish has only the NFA. The other two are OPTIMISATIONS over it
// — which is why Go falls back to it — so they change how fast an
// answer arrives, not what it is.
//
// `\p{Han}` and every other named Unicode group is refused with
// `invalid character class range`, because `unicode.Categories` and
// `unicode.Scripts` are not in goish's `unicode`. `\p{Any}` and
// `\p{ASCII}` work. See ROADMAP §2c; it is a `unicode` gap that
// `regexp` inherits, and it is a refusal rather than a wrong match.


// §2c: the RE2 construction. `syntax` parses, simplifies and compiles;
// `exec` runs the NFA. Both were built beside the old backtracker and
// swapped in only once complete — see their module headers.
pub mod exec;
pub mod syntax;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::convert::{int as toint, int32 as toint32, int64 as toint64};
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int, rune};

// ─── QuoteMeta ─────────────────────────────────────────────────────────

#[inline]
fn is_meta(b: byte) -> bool {
    return matches!(
        b,
        b'\\'
            | b'.'
            | b'+'
            | b'*'
            | b'?'
            | b'('
            | b')'
            | b'|'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b'^'
            | b'$'
    );
}

/// `regexp.QuoteMeta(s)` (Go 1.25 regexp.go:706). Backslash-escapes every
/// regexp metacharacter in `s` so the result, treated as a pattern,
/// matches the original `s` literally.
pub fn QuoteMeta<S: Into<string>>(s: S) -> string {
    let s = s.into();
    let bytes: &[u8] = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() && !is_meta(bytes[i]) {
        i += 1;
    }
    if i >= bytes.len() {
        return s;
    }
    let mut buf: Vec<u8> = Vec::with_capacity(bytes.len() * 2 - i);
    buf.extend_from_slice(&bytes[..i]);
    while i < bytes.len() {
        if is_meta(bytes[i]) {
            buf.push(b'\\');
        }
        buf.push(bytes[i]);
        i += 1;
    }
    return string::__from_vec(buf);
}

// ─── Regexp (compiled) ─────────────────────────────────────────────────

/// Compiled regular expression. Mirrors Go's `*Regexp` opaque pointer.
///
/// Go caches machines in a `sync.Pool` on this struct and keeps the
/// `onepass` program beside the NFA one. goish keeps only the program:
/// a machine is cheap to build and there is only one engine to choose
/// from.
#[derive(Clone)]
pub struct Regexp {
    /// The compiled program the NFA walks.
    prog: Arc<crate::regexp::syntax::prog::Prog>,
    /// `2 * (MaxCap + 1)` — the machine's capture-slot count.
    ncap: usize,
    n_caps: usize,
    /// Go's `subexpNames`, from `syntax.Regexp.CapNames`.
    names: Vec<string>,
    /// Go's `cond`: the empty-width conditions every match must satisfy.
    /// `^EmptyOp(0)` means no match is possible.
    cond: crate::regexp::syntax::prog::EmptyOp,
    /// Go's `longest`. Set by [`Regexp::Longest`].
    longest: bool,
    /// Original source pattern. Returned by `String()` (Go's
    /// `regexp.Regexp.String() string`, regexp.go:142).
    pattern: string,
}

impl Regexp {
    fn n_groups(&self) -> usize {
        return self.n_caps + 1;
    }

    /// `Regexp.String() string` — returns the source text of the
    /// pattern. Mirrors Go's `regexp.Regexp.String()`.
    #[allow(non_snake_case)]
    pub fn String(&self) -> string {
        return self.pattern.clone();
    }

    // go: sdk 1.25.5 regexp/regexp.go:163-165 Regexp.Longest
    /// Go: "Longest makes future searches prefer the leftmost-longest
    /// match… This method modifies the Regexp and may not be called
    /// concurrently with any other methods."
    ///
    /// `a|ab` against `"ab"` matches `a` by default and `ab` after
    /// this. The difference lives in one branch of the machine's
    /// `step`, and it was unreachable before the NFA landed.
    #[allow(non_snake_case)]
    pub fn Longest(&mut self) {
        self.longest = true;
    }
}

// ─── Compile / MustCompile ─────────────────────────────────────────────

// go: sdk 1.25.5 regexp/regexp.go:130-132 Compile
/// Go: "Compile parses a regular expression and returns, if
/// successful, a Regexp object that can be used to match against text."
///
/// The whole pipeline: parse to an AST, simplify the counted
/// repetitions away — the program has no repeat instruction, so they
/// have to go — and compile to the instruction array the NFA walks.
///
/// The error is `syntax.Error`'s, which is Go's text
/// (`error parsing regexp: <code>: \`<expr>\``). goish used to invent
/// its own; this is one of the things the swap fixes for free.
pub fn Compile<S: Into<string>>(expr: S) -> (Regexp, error) {
    let expr_s = expr.into();
    let (re, err) = crate::regexp::syntax::Parse(expr_s.clone(), crate::regexp::syntax::Perl);
    if !err.IsNil() {
        return (__empty_regexp(&expr_s), err);
    }
    let re = re.MustTake();
    let names_slice = re.CapNames();
    let mut names: Vec<string> = Vec::new();
    let mut i: int = 0;
    while i < crate::len(&names_slice) {
        names.push(names_slice[i].clone());
        i += 1;
    }
    let n_caps = crate::int64(re.MaxCap()) as usize;
    let sre = re.Simplify();
    let (prog, _) = crate::regexp::syntax::Compile(&sre);
    let cond = prog.StartCond();
    return (
        Regexp {
            prog: Arc::new(prog),
            ncap: 2 * (n_caps + 1),
            n_caps,
            names,
            cond,
            longest: false,
            pattern: expr_s,
        },
        crate::nilval::nil.into(),
    );
}

// go: none — goish idiom: Go returns a nil `*Regexp` beside the error.
//     goish's `Compile` returns a value, so a failed compile needs one
//     that is inert: an empty program whose only instruction is `fail`.
/// The `Regexp` a failed [`Compile`] returns.
fn __empty_regexp(expr: &string) -> Regexp {
    let mut prog = crate::regexp::syntax::prog::Prog::default();
    let mut fail = crate::regexp::syntax::prog::Inst::default();
    fail.Op = crate::regexp::syntax::prog::InstFail;
    prog.Inst.push(fail);
    prog.Start = 0;
    return Regexp {
        prog: Arc::new(prog),
        ncap: 2,
        n_caps: 0,
        names: alloc::vec![string::from_static("")],
        cond: crate::regexp::syntax::prog::EmptyOp(0),
        longest: false,
        pattern: expr.clone(),
    };
}

/// `regexp.Match(pattern, b) (matched bool, err error)` — one-shot
/// compile + match. Mirrors Go's `regexp.Match` (regexp.go:472) so
/// callers don't pre-compile when they only need a single check.
pub fn Match<S: Into<string>, B: AsRef<[byte]>>(pattern: S, b: B) -> (bool, error) {
    let (re, err) = Compile(pattern);
    if err != crate::nilval::nil {
        return (false, err);
    }
    // Reuse MatchString's logic via a byte-side helper. The pattern
    // matches if find_first returns Some.
    let matched = re.find_first(b.as_ref()).is_some();
    return (matched, crate::nilval::nil.into());
}

/// `regexp.MatchString(pattern, s) (matched bool, err error)` — same
/// shape as `Match` but for `string` input.
pub fn MatchString<S: Into<string>, S2: Into<string>>(pattern: S, s: S2) -> (bool, error) {
    let s = s.into();
    return Match(pattern, s.as_bytes());
}

/// `regexp.MustCompile(expr)` — panics on parse error.
pub fn MustCompile<S: Into<string>>(expr: S) -> Regexp {
    let expr_s = expr.into();
    let (re, err) = Compile(expr_s.clone());
    if err != crate::nilval::nil {
        panic!("regexp: Compile failed");
    }
    return re;
}

// go: none — goish idiom: Go's search drivers step by rune through
//     the `input` interface. goish's step over a byte slice, so they
//     need the width of the rune at a position.
/// Go: `utf8.DecodeRuneInString(s[pos:])`'s width, as `allMatches` uses
/// it to step past an empty match. 0 at end of input; 1 for an invalid
/// leading byte, which is what DecodeRune returns for RuneError.
fn rune_width(text: &[u8], pos: usize) -> usize {
    if pos >= text.len() {
        return 0;
    }
    let b = text[pos];
    let want = if b < 0x80 {
        1
    } else if b >= 0xF0 {
        4
    } else if b >= 0xE0 {
        3
    } else if b >= 0xC0 {
        2
    } else {
        return 1; // continuation byte in leading position — RuneError
    };
    if pos + want > text.len() {
        return 1;
    }
    for k in 1..want {
        if text[pos + k] & 0xC0 != 0x80 {
            return 1;
        }
    }
    return want;
}

// ─── Public API: search drivers ────────────────────────────────────────

// go: none — goish idiom: Go's `Capture` equivalent is a flat `[]int`
//     of alternating starts and ends. goish's search drivers were
//     written against pairs, so the machine's flat slice is folded into
//     them at this one boundary.
/// One capture group's `(start, end)`, `(-1, -1)` when unset.
type Capture = (i32, i32);

impl Regexp {
    // go: none — goish idiom: Go's `doExecute` picks between three
    //     engines and threads a machine pool through a sync.Pool.
    //     goish has one engine and builds a machine per search, so this
    //     is the whole of it.
    /// Find the leftmost match at or after `from`.
    ///
    /// The scan itself is the MACHINE's: `exec.rs`'s `match` advances
    /// its own position and re-adds the start thread at each one while
    /// unmatched. goish used to loop here, calling a backtracker at
    /// every offset — which is where the second factor of the
    /// exponential came from.
    fn find_from(&self, text: &[u8], from: usize) -> Option<(usize, usize, Vec<Capture>)> {
        if from > text.len() {
            return None;
        }
        let mut m = crate::regexp::exec::machine::__new(
            &self.prog,
            self.ncap,
            self.longest,
            self.cond,
        );
        if !m.__run(text, from) {
            return None;
        }
        let mc = m.__matchcap();
        let mut caps: Vec<Capture> = Vec::with_capacity(self.n_groups());
        let mut g = 0usize;
        while g < self.n_groups() {
            let lo = if 2 * g < mc.len() {
                crate::int64(mc[2 * g]) as i32
            } else {
                -1
            };
            let hi = if 2 * g + 1 < mc.len() {
                crate::int64(mc[2 * g + 1]) as i32
            } else {
                -1
            };
            caps.push((lo, hi));
            g += 1;
        }
        let start = caps[0].0 as usize;
        let end = caps[0].1 as usize;
        return Some((start, end, caps));
    }

    /// Find the leftmost match in `text`, scanning from offset 0.
    fn find_first(&self, text: &[u8]) -> Option<(usize, usize, Vec<Capture>)> {
        return self.find_from(text, 0);
    }

    /// Go: `func (re *Regexp) allMatches(s string, b []byte, n int,
    /// deliver func([]int))` (regexp.go:1039).
    ///
    /// The successive-match scan, shared by every FindAll method and by
    /// Split. It is one routine rather than a loop per method because
    /// of two rules that are easy to get wrong independently:
    ///  - an empty match whose START equals the PREVIOUS match's end is
    ///    dropped, so `a*` over "abaab" yields "a", "", "aa", "" — not
    ///    an extra empty at each seam;
    ///  - after any empty match the scan advances one RUNE, not one
    ///    byte, so a multi-byte character is never split.
    fn all_matches(&self, text: &[u8], n: int, deliver: &mut dyn FnMut(usize, usize, &[Capture])) {
        // Go: `if n < 0 { n = len(s) + 1 }` at each caller.
        let max = if n < 0 { text.len() + 1 } else { n as usize };
        let end = text.len();
        let mut pos = 0usize;
        let mut i = 0usize;
        let mut prevMatchEnd: i64 = -1;
        while i < max && pos <= end {
            let (lo, hi, caps) = match self.find_from(text, pos) {
                None => break,
                Some(t) => t,
            };
            let mut accept = true;
            if hi == pos {
                if lo as i64 == prevMatchEnd {
                    // An empty match colliding with the previous match.
                    accept = false;
                }
                let width = rune_width(text, pos);
                if width > 0 {
                    pos += width;
                } else {
                    pos = end + 1;
                }
            } else {
                pos = hi;
            }
            prevMatchEnd = hi as i64;
            if accept {
                deliver(lo, hi, &caps);
                i += 1;
            }
        }
    }

    /// The capture vector of one match, rendered as Go renders it: an
    /// unset group is the empty string.
    fn caps_to_row(&self, text: &[u8], caps: &[Capture]) -> slice<string> {
        let mut row: Vec<string> = Vec::with_capacity(self.n_groups());
        for &(lo, hi) in caps {
            if lo < 0 || hi < 0 {
                row.push(string::from_static(""));
            } else {
                row.push(string::from_bytes(&text[lo as usize..hi as usize]));
            }
        }
        return slice::__from_vec(row);
    }

    /// Go: `func (re *Regexp) MatchString(s string) bool` (regexp.go:447).
    /// Reports whether the pattern matches anywhere in `s`.
    pub fn MatchString<S: Into<string>>(&self, s: S) -> bool {
        let s = s.into();
        return self.find_first(s.as_bytes()).is_some();
    }

    /// Go: `func (re *Regexp) FindStringSubmatch(s string) []string`
    /// (regexp.go:1020). Returns whole match + capture-group strings,
    /// or an empty (nil-equivalent) slice if no match.
    pub fn FindStringSubmatch<S: Into<string>>(&self, s: S) -> slice<string> {
        let s = s.into();
        let text = s.as_bytes();
        return match self.find_first(text) {
            None => slice::new(),
            Some((_, _, caps)) => {
                let mut out: Vec<string> = Vec::with_capacity(self.n_groups());
                for &(lo, hi) in &caps {
                    if lo < 0 || hi < 0 {
                        out.push(string::from_static(""));
                    } else {
                        out.push(string::from_bytes(&text[lo as usize..hi as usize]));
                    }
                }
                slice::__from_vec(out)
            }
        };
    }

    /// Go: `func (re *Regexp) FindAllString(s string, n int) []string`
    /// (regexp.go:953). Successive non-overlapping matches; `n < 0`
    /// means all.
    pub fn FindAllString<S: Into<string>>(&self, s: S, n: int) -> slice<string> {
        let s = s.into();
        let text = s.as_bytes();
        let mut out: Vec<string> = Vec::new();
        self.all_matches(text, n, &mut |lo, hi, _| {
            out.push(string::from_bytes(&text[lo..hi]));
        });
        return if out.is_empty() {
            slice::new()
        } else {
            slice::__from_vec(out)
        };
    }

    /// Go: `func (re *Regexp) FindAllStringIndex(s string, n int) [][]int`
    /// (regexp.go:1100). Each element is the two-element `[start, end]`
    /// byte range of one match.
    pub fn FindAllStringIndex<S: Into<string>>(&self, s: S, n: int) -> slice<slice<int>> {
        let s = s.into();
        let text = s.as_bytes();
        let mut out: Vec<slice<int>> = Vec::new();
        self.all_matches(text, n, &mut |lo, hi, _| {
            out.push(slice::__from_vec(alloc::vec![lo as int, hi as int]));
        });
        return if out.is_empty() {
            slice::new()
        } else {
            slice::__from_vec(out)
        };
    }

    /// Go: `func (re *Regexp) Split(s string, n int) []string`
    /// (regexp.go:1246). The substrings BETWEEN the matches.
    ///
    ///   n > 0: at most n substrings; the last is the unsplit remainder
    ///   n == 0: nil
    ///   n < 0: all
    pub fn Split<S: Into<string>>(&self, s: S, n: int) -> slice<string> {
        let s = s.into();
        if n == 0 {
            return slice::new();
        }
        let text = s.as_bytes();
        // Go: `if len(re.expr) > 0 && len(s) == 0 { return []string{""} }`
        if !self.pattern.as_bytes().is_empty() && text.is_empty() {
            return slice::__from_vec(alloc::vec![string::from_static("")]);
        }

        let matches = self.FindAllStringIndex(s.clone(), n);
        let mut out: Vec<string> = Vec::new();
        let mut beg = 0usize;
        let mut end = 0usize;
        for m in matches.as_ref().iter() {
            if n > 0 && out.len() as int >= n - 1 {
                break;
            }
            let (lo, hi) = (m[0] as usize, m[1] as usize);
            end = lo;
            // Go's guard is `match[1] != 0`: a match ending at offset 0
            // is the empty match before the first character, and the
            // empty prefix it would contribute is dropped.
            if hi != 0 {
                out.push(string::from_bytes(&text[beg..end]));
            }
            beg = hi;
        }

        if end != text.len() {
            out.push(string::from_bytes(&text[beg..]));
        }

        return if out.is_empty() {
            slice::new()
        } else {
            slice::__from_vec(out)
        };
    }

    /// Go: `func (re *Regexp) FindAllStringSubmatch(s string, n int) [][]string`
    /// (regexp.go:1126).
    pub fn FindAllStringSubmatch<S: Into<string>>(&self, s: S, n: int) -> slice<slice<string>> {
        let s = s.into();
        let text = s.as_bytes();
        let mut out: Vec<slice<string>> = Vec::new();
        self.all_matches(text, n, &mut |_, _, caps| {
            out.push(self.caps_to_row(text, caps));
        });
        return if out.is_empty() {
            slice::new()
        } else {
            slice::__from_vec(out)
        };
    }

    // go: sdk 1.25.5 regexp/regexp.go:337-339 Regexp.NumSubexp
    /// Go: `func (re *Regexp) ReplaceAllString(src, repl string) string`
    /// (regexp.go:822). Replacement is treated as literal text — `$1`
    /// group expansion isn't supported in the v1 subset (extend when a
    /// Go: "NumSubexp returns the number of parenthesized subexpressions
    /// in this Regexp."
    pub fn NumSubexp(&self) -> int {
        return toint(self.names.len() - 1);
    }

    // go: sdk 1.25.5 regexp/regexp.go:346-348 Regexp.SubexpNames
    /// Go: "SubexpNames returns the names of the parenthesized
    /// subexpressions in this Regexp. The name for the first sub-
    /// expression is names[1] … the slice should not be modified."
    pub fn SubexpNames(&self) -> slice<string> {
        return slice::__from_vec(self.names.clone());
    }

    // go: sdk 1.25.5 regexp/regexp.go:357-366 Regexp.SubexpIndex
    /// Go: "SubexpIndex returns the index of the first subexpression
    /// with the given name, or -1 if there is no subexpression with
    /// that name. Note that multiple subexpressions can be written
    /// using the same name … so this will return the index of the
    /// first one."
    pub fn SubexpIndex<S: Into<string>>(&self, name: S) -> int {
        let name = name.into();
        if name.Len() == 0 {
            return -1;
        }
        let mut i = 0usize;
        while i < self.names.len() {
            if self.names[i] == name {
                return toint(i);
            }
            i += 1;
        }
        return -1;
    }

    // go: sdk 1.25.5 regexp/regexp.go:1058-1060 Regexp.FindStringSubmatchIndex
    /// Go: "a slice holding the index pairs identifying the leftmost
    /// match … and the matches, if any, of its subexpressions".
    pub fn FindStringSubmatchIndex<S: Into<string>>(&self, s: S) -> slice<int> {
        let s = s.into();
        return match self.find_first(s.as_bytes()) {
            None => slice::new(),
            Some((_, _, caps)) => {
                let mut out: Vec<int> = Vec::with_capacity(caps.len() * 2);
                for &(lo, hi) in &caps {
                    out.push(toint(lo));
                    out.push(toint(hi));
                }
                slice::__from_vec(out)
            }
        };
    }

    // go: sdk 1.25.5 regexp/regexp.go:926-970 Regexp.expand
    /// Go: "In the template, a variable is denoted by a substring of the
    /// form $name or ${name}, where name is a non-empty sequence of
    /// letters, digits, and underscores … A reference to an out of range
    /// or unmatched index or a name that is not present in the regular
    /// expression is replaced with an empty slice."
    ///
    /// goish's `ReplaceAllString` did NO expansion: it copied the
    /// template through byte for byte, which is exactly Go's
    /// `ReplaceAllLiteralString`. So `re.ReplaceAllString(s, "$1")`
    /// emitted the two characters `$1` where Go substitutes the first
    /// capture — silently, with no error and plausible-looking output.
    fn expand_into(&self, out: &mut Vec<u8>, template: &[u8], text: &[u8], m: &[Capture]) {
        let mut i = 0usize;
        while i < template.len() {
            // Go: `before, after, ok := strings.Cut(template, "$")`.
            let dollar = match template[i..].iter().position(|&c| c == b'$') {
                None => break,
                Some(k) => i + k,
            };
            out.extend_from_slice(&template[i..dollar]);
            i = dollar + 1;
            // Go: "Treat $$ as $."
            if i < template.len() && template[i] == b'$' {
                out.push(b'$');
                i += 1;
                continue;
            }
            let (name, num, rest, ok) = extract(&template[i..]);
            if !ok {
                // Go: "Malformed; treat $ as raw text."
                out.push(b'$');
                continue;
            }
            i += rest;
            if num >= 0 {
                let g = num as usize;
                if g < m.len() && m[g].0 >= 0 {
                    out.extend_from_slice(&text[m[g].0 as usize..m[g].1 as usize]);
                }
                continue;
            }
            let mut g = 0usize;
            while g < self.names.len() {
                if self.names[g].as_bytes() == name && g < m.len() && m[g].0 >= 0 {
                    out.extend_from_slice(&text[m[g].0 as usize..m[g].1 as usize]);
                    break;
                }
                g += 1;
            }
        }
        out.extend_from_slice(&template[i..]);
    }

    // go: sdk 1.25.5 regexp/regexp.go:603-666 Regexp.replaceAll
    /// The shared skeleton behind every Replace method. Go's, exactly —
    /// including the two rules a hand-rolled loop gets wrong:
    ///
    ///   * the unmatched run copied before a match is measured from
    ///     `lastMatchEnd`, not from the search position; and
    ///   * "insert a copy of the replacement string, but not for a
    ///     match of the empty string immediately after another match.
    ///     (Otherwise, we get double replacement for patterns that match
    ///     both empty and nonempty strings.)"
    ///
    /// goish had its own loop with neither, so `a*` over "bab" replaced
    /// four times where Go replaces three: "-b--b-" against "-b-b-".
    fn replace_all(&self, text: &[u8], repl: &mut dyn FnMut(&mut Vec<u8>, &[Capture])) -> string {
        let mut out: Vec<u8> = Vec::with_capacity(text.len());
        let mut last_match_end = 0usize;
        let mut search_pos = 0usize;
        let end_pos = text.len();
        while search_pos <= end_pos {
            let (lo, hi, caps) = match self.find_from(text, search_pos) {
                None => break,
                Some(t) => t,
            };
            // Go: copy the unmatched characters before this match.
            out.extend_from_slice(&text[last_match_end..lo]);
            // Go: `if a[1] > lastMatchEnd || a[0] == 0`.
            if hi > last_match_end || lo == 0 {
                repl(&mut out, &caps);
            }
            last_match_end = hi;
            // Go: "Advance past this match; always advance at least one
            // character."
            let width = rune_width(text, search_pos);
            if search_pos + width > hi {
                search_pos += width;
            } else if search_pos + 1 > hi {
                search_pos += 1;
            } else {
                search_pos = hi;
            }
            if width == 0 && search_pos <= hi {
                break;
            }
        }
        out.extend_from_slice(&text[last_match_end..]);
        return string::__from_vec(out);
    }

    // go: sdk 1.25.5 regexp/regexp.go:572-581 Regexp.ReplaceAllString
    /// Go: "ReplaceAllString returns a copy of src, replacing matches of
    /// the Regexp with the replacement text repl. Inside repl, $ signs
    /// are interpreted as in Expand."
    pub fn ReplaceAllString<S: Into<string>, R: Into<string>>(&self, src: S, repl: R) -> string {
        let src = src.into();
        let repl = repl.into();
        let text = src.as_bytes();
        let rb = repl.as_bytes();
        return self.replace_all(text, &mut |out, caps| {
            self.expand_into(out, rb, text, caps);
        });
    }

    // go: sdk 1.25.5 regexp/regexp.go:586-590 Regexp.ReplaceAllLiteralString
    /// Go: "the replacement text repl is substituted directly, without
    /// using Expand." This is what goish's `ReplaceAllString` was
    /// already doing; now it is the method that says so.
    pub fn ReplaceAllLiteralString<S: Into<string>, R: Into<string>>(
        &self,
        src: S,
        repl: R,
    ) -> string {
        let src = src.into();
        let repl = repl.into();
        let text = src.as_bytes();
        let rb = repl.as_bytes();
        return self.replace_all(text, &mut |out, _| {
            out.extend_from_slice(rb);
        });
    }

    // go: sdk 1.25.5 regexp/regexp.go:596-601 Regexp.ReplaceAllStringFunc
    /// Go: "the replacement returned by repl is substituted directly,
    /// without using Expand."
    pub fn ReplaceAllStringFunc<S: Into<string>, F: Fn(string) -> string>(
        &self,
        src: S,
        repl: F,
    ) -> string {
        let src = src.into();
        let text = src.as_bytes();
        return self.replace_all(text, &mut |out, caps| {
            let (lo, hi) = (caps[0].0 as usize, caps[0].1 as usize);
            let r = repl(string::from_bytes(&text[lo..hi]));
            out.extend_from_slice(r.as_bytes());
        });
    }
}

// go: sdk 1.25.5 regexp/regexp.go:975-1022 extract
/// Go: "extract returns the name from a leading "name" or "{name}" in
/// str. (The $ has already been removed by the caller.) If it is a
/// number, extract returns num set to that number; otherwise num = -1."
///
/// Returns `(name, num, consumed, ok)`. The subtlety worth keeping is
/// that a name is letters, digits and underscores — so `$1c` is the
/// NAME "1c", not group 1 followed by a 'c', and since no group is
/// called "1c" Go expands it to nothing at all.
fn extract(str_: &[u8]) -> (&[u8], i64, usize, bool) {
    /// Go writes `rune != '_'`; a Rust char literal would need a cast.
    const UNDERSCORE: rune = 0x5F;
    if str_.is_empty() {
        return (b"", 0, 0, false);
    }
    let mut s = str_;
    let mut brace = false;
    if s[0] == b'{' {
        brace = true;
        s = &s[1..];
    }
    let mut i = 0usize;
    while i < s.len() {
        let (r, size) = crate::unicode::utf8::DecodeRune(&s[i..]);
        if !crate::unicode::IsLetter(r) && !crate::unicode::IsDigit(r) && r != UNDERSCORE {
            break;
        }
        i += size as usize;
    }
    // Go: "empty name is not okay".
    if i == 0 {
        return (b"", 0, 0, false);
    }
    let name = &s[..i];
    if brace {
        if i >= s.len() || s[i] != b'}' {
            return (b"", 0, 0, false);
        }
        i += 1;
    }
    // Go: parse number.
    let mut num: i64 = 0;
    let mut k = 0usize;
    while k < name.len() {
        if name[k] < b'0' || name[k] > b'9' || num >= 100_000_000 {
            num = -1;
            break;
        }
        num = num * 10 + toint64(name[k] - b'0');
        k += 1;
    }
    // Go: "Disallow leading zeros."
    if name[0] == b'0' && name.len() > 1 {
        num = -1;
    }
    let consumed = (str_.len() - s.len()) + i;
    return (name, num, consumed, true);
}
