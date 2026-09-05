// regexp — Go's `regexp` package, RE2-style subset (backtracking matcher).
//
// ─── DIVERGENCE: no linear-time guarantee ────────────────────────────
//
// Go's package documentation makes a promise this implementation does
// NOT keep:
//
//   "The regexp implementation provided by this package is guaranteed
//    to run in time linear in the size of the input."
//
// Go keeps it by simulating an NFA (RE2). This is a BACKTRACKING
// matcher, so a pattern with nested quantifiers is exponential in the
// input length. Measured 2026-09-05, `(a+)+$` against n 'a's followed
// by '!' — Go answers every one of these in under a millisecond:
//
//     n=10      5 ms          n=20   5,939 ms
//     n=14     95 ms          n=21  13,124 ms
//     n=18  1,419 ms          n=22  27,338 ms
//
// Each additional character roughly DOUBLES the work. Extrapolating,
// n=30 is about two hours and n=40 about eighty days. The ANSWER is
// correct at every size — this is not a wrong result, it is an
// unbounded one.
//
// What that means for a caller: Go's regexp is safe to run against an
// untrusted pattern or an untrusted subject, and this is not. Roughly
// twenty-five bytes of input hangs the process indefinitely. Any port
// of Go code that relies on the linear-time guarantee — a router, a
// log filter, an input validator — inherits a denial of service here
// that it did not have in Go.
//
// Closing it means the RE2 construction: compile to an instruction
// program and simulate the NFA with a thread list, which is
// `regexp/exec.go` plus `regexp/syntax/`. That is a rewrite of the
// matcher, not a patch to it, and it is recorded in ROADMAP.md rather
// than attempted here. A step budget was considered and rejected: it
// would trade an unbounded hang for a WRONG answer on patterns Go
// answers correctly, which is a worse divergence than the one it
// fixes.
//
// Verified against Go 1.25 `src/regexp/regexp.go` for API shapes and
// `src/regexp/syntax/parse.go` for parser semantics, and against a
// running Go by `examples/regexp_ref_smoke.rs`: 70 patterns x 31 inputs,
// compared on the compile outcome and on every submatch.
//
// The matcher works in RUNES, as Go's does. `.`, a negated class and
// `\D`/`\W`/`\S` each consume one whole character, so a match against
// non-ASCII text can never cut a rune in half.
//
// Supported:
//
//   - Literals (any rune), `\X` escapes, `\xHH`, `\x{HHHH}` and octal
//     `\NNN`.
//   - `.` — any rune except newline; `(?s)` makes it match newline too.
//   - `^` and `$` — text start/end; `(?m)` makes them line start/end.
//     `\A` and `\z` are always text start/end.
//   - `\b` and `\B` word boundaries.
//   - Char classes `[...]`, `[^...]`, ranges `a-z`, escapes inside, and
//     the fourteen POSIX names `[[:alpha:]]` … `[[:xdigit:]]`.
//   - Predefined classes `\d` `\D` `\w` `\W` `\s` `\S`.
//   - Quantifiers `*` `+` `?` `{n}` `{n,}` `{n,m}`, greedy and — with a
//     trailing `?` — non-greedy. A `{` that does not open a valid
//     repetition is a literal, as in Go.
//   - Capturing groups `(...)`, non-capturing `(?:...)`, and named
//     `(?P<name>...)` / `(?<name>...)` (the name is parsed and
//     discarded — there is no SubexpNames).
//   - Alternation `|`.
//   - Flags `i`, `s`, `m`, in all of `(?i)`, `(?-i)`, `(?i:...)`, with
//     Go's scoping (a flag runs to the end of the enclosing group).
//     Case folding is ASCII-only.
//
// NOT supported (all fail loudly at Compile time — none of them
// silently compiles to something else):
//   - `\p{...}` / `\pX` Unicode classes: they need the script tables.
//   - Lookahead/lookbehind `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`.
//   - Backreferences `\1`, and the `U` flag.
//   - Any other alphanumeric escape, which is Go's rule too.
//
// API surface mirrors Go 1.25 regexp.go:
//
//   Compile / MustCompile / QuoteMeta — package-level.
//   (*Regexp).MatchString
//   (*Regexp).FindStringSubmatch
//   (*Regexp).FindAllString
//   (*Regexp).FindAllStringIndex
//   (*Regexp).FindAllStringSubmatch
//   (*Regexp).Split
//   (*Regexp).ReplaceAllString
//
// All return Goish slices/strings (never `Vec`/`&str`) per the public-API
// contract.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
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

// ─── AST ───────────────────────────────────────────────────────────────

/// Atom in the regex AST. Atoms are the things a quantifier can apply to.
#[derive(Clone)]
enum Node {
    /// Matches one literal RUNE. Go's parser works in runes and so does
    /// the matcher: a pattern byte is never compared against half of a
    /// multi-byte character.
    Literal(rune),
    /// `.` — matches any single rune EXCEPT newline, which is Go's
    /// default.
    AnyCharNotNL,
    /// `.` under the `s` flag — any rune, newline included.
    AnyChar,
    /// `[...]` or shorthand class, over RUNE ranges. `negate` flips
    /// membership, and a negated class spans the whole rune space —
    /// which is what makes `[^abc]` and `\D` match a non-ASCII rune
    /// whole instead of one byte of it.
    Class {
        negate: bool,
        ranges: Vec<(rune, rune)>,
    },
    /// `\b` (`word` = true) and `\B` (`word` = false) — zero-width
    /// word-boundary assertions.
    WordBoundary(bool),
    /// Capturing group. `idx` is the 1-based capture slot (slot 0 is
    /// whole match). The inner Node is whatever the group contains
    /// (typically a Concat or Alt).
    Group { idx: usize, inner: Box<Node> },
    /// Non-capturing group `(?:...)`. Behaves like Concat but is its
    /// own AST node so quantifiers can bind to the whole group.
    NonCap(Box<Node>),
    /// Sequence of nodes matched in order.
    Concat(Vec<Node>),
    /// Alternation. Tries branches left-to-right.
    Alt(Vec<Node>),
    /// `node{min,max}`. `max == usize::MAX` for unbounded. `greedy` is
    /// false for the `?`-suffixed forms (`a*?`), which prefer the
    /// FEWEST repetitions.
    Repeat {
        node: Box<Node>,
        min: usize,
        max: usize,
        greedy: bool,
    },
    /// `^` — text start (matches only at offset 0).
    AnchorStart,
    /// `$` — text end (matches only at end-of-input).
    AnchorEnd,
    /// `^` under the `m` flag — start of text or just after a newline.
    BeginLine,
    /// `$` under the `m` flag — end of text or just before a newline.
    EndLine,
    /// Internal-only continuation marker. Never produced by the parser.
    /// Pushed onto the continuation by the Group matcher so the captured
    /// group's end offset is recorded at the point in the match where
    /// the inner subexpression's success has been verified together with
    /// any trailing pattern. Backtrackable: the prior end is restored if
    /// the continuation tail fails after this marker.
    EndGroup(usize),
    /// Internal-only continuation marker. Pushed onto the continuation
    /// by `match_repeat` when chaining successive reps in CPS form.
    /// Carries `last_pos` — the position at which the most recent rep
    /// began — so the next invocation can detect a zero-width match
    /// (current pos == last_pos) and terminate the chain instead of
    /// recursing forever.
    RepeatTail {
        node: Box<Node>,
        min: usize,
        max: usize,
        last_pos: usize,
        greedy: bool,
        /// The captures as they stood BEFORE the iteration that is about
        /// to be judged. Go does not take an empty iteration of a
        /// repeated group, so when the chain stops on a zero-width rep
        /// the captures that rep wrote have to be rolled back — without
        /// this, `(a*)*b` against "ab" reported group 1 as "" where Go
        /// reports "a".
        saved: Vec<Capture>,
    },
}

// ─── Parser ────────────────────────────────────────────────────────────
//
// Recursive-descent, mirroring Go's regexp/syntax/parse.go shape (much
// reduced). Returns `error` (Goish error) on bad pattern.

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
    /// Next 1-based capture index to assign.
    next_cap: usize,
    /// Go's `re.subexpNames`, built as the groups are parsed: index 0
    /// is the whole match and is always "", then one entry per
    /// capturing group, "" for an unnamed one.
    ///
    /// goish parsed `(?P<name>…)` and threw the name away, so
    /// `SubexpNames`, `SubexpIndex` and `$name` in a replacement
    /// template had nothing to look at.
    names: Vec<string>,
    /// `i` flag state. Go's `(?i)` sets it for the remainder of the
    /// ENCLOSING GROUP (parse.go `parsePerlFlags`), so it is parser
    /// state saved and restored around every group body, not a
    /// whole-pattern switch.
    fold: bool,
    /// `s` flag — `.` matches newline. Same scoping as `fold`.
    dot_nl: bool,
    /// `m` flag — `^`/`$` match at line boundaries. Same scoping.
    multi: bool,
}

impl<'a> Parser<'a> {
    fn new(src: &'a [u8]) -> Self {
        return Self {
            src,
            pos: 0,
            next_cap: 1,
            names: alloc::vec![string::from_static("")],
            fold: false,
            dot_nl: false,
            multi: false,
        };
    }

    fn peek(&self) -> Option<byte> {
        return self.src.get(self.pos).copied();
    }

    fn bump(&mut self) -> Option<byte> {
        let b = self.peek()?;
        self.pos += 1;
        return Some(b);
    }

    /// Top-level: parse one alternation.
    fn parse_alt(&mut self) -> Result<Node, &'static str> {
        let first = self.parse_concat()?;
        let mut branches: Vec<Node> = Vec::new();
        while let Some(b'|') = self.peek() {
            if branches.is_empty() {
                branches.push(first.clone());
            }
            self.bump();
            branches.push(self.parse_concat()?);
        }
        return if branches.is_empty() {
            Ok(first)
        } else {
            Ok(Node::Alt(branches))
        };
    }

    /// Parse a concatenation of atoms-with-quantifiers, stopping at
    /// `|` or `)` or end-of-input.
    fn parse_concat(&mut self) -> Result<Node, &'static str> {
        let mut items: Vec<Node> = Vec::new();
        while let Some(b) = self.peek() {
            if b == b'|' || b == b')' {
                break;
            }
            let atom = self.parse_atom()?;
            let q = self.parse_quant_opt(atom)?;
            items.push(q);
        }
        return if items.len() == 1 {
            Ok(items.pop().unwrap())
        } else {
            Ok(Node::Concat(items))
        };
    }

    /// After parsing one atom, optionally consume a quantifier and
    /// return the (possibly wrapped) node.
    fn parse_quant_opt(&mut self, atom: Node) -> Result<Node, &'static str> {
        // A `(?flags)` setter parses to the empty node. Go rejects a
        // quantifier on it — "missing argument to repetition operator"
        // (parse.go) — and binding one here would build a Repeat around
        // a zero-width node.
        if matches!(&atom, Node::Concat(items) if items.is_empty())
            && matches!(self.peek(), Some(b'*' | b'+' | b'?'))
        {
            return Err("missing argument to repetition operator");
        }
        return match self.peek() {
            Some(b'*') => {
                self.bump();
                let greedy = self.take_greedy();
                Ok(Node::Repeat {
                    node: Box::new(atom),
                    min: 0,
                    max: usize::MAX,
                    greedy,
                })
            }
            Some(b'+') => {
                self.bump();
                let greedy = self.take_greedy();
                Ok(Node::Repeat {
                    node: Box::new(atom),
                    min: 1,
                    max: usize::MAX,
                    greedy,
                })
            }
            Some(b'?') => {
                self.bump();
                let greedy = self.take_greedy();
                Ok(Node::Repeat {
                    node: Box::new(atom),
                    min: 0,
                    max: 1,
                    greedy,
                })
            }
            Some(b'{') => {
                // Go: a `{` that does not open a well-formed repetition
                // is an ordinary literal — `a{,3}` is the five-character
                // string. goish returned "missing number in {n,m}" and
                // refused to compile the pattern at all.
                let save = self.pos;
                self.bump();
                match self.parse_brace_count() {
                    Ok((min, max)) => {
                        // Go: "if min < 0 || min > 1000 || max == -2 ||
                        // max > 1000 || max >= 0 && min > max { …
                        // ErrInvalidRepeatSize }". A WELL-FORMED brace
                        // with impossible counts is a hard error, not a
                        // literal `{` — the fall-back above is only for
                        // a brace that does not parse as a repetition at
                        // all, like `a{,3}`.
                        //
                        // goish had no check, so `a{2,1}` compiled to a
                        // repetition that can never be satisfied and
                        // matched nothing, and `a{99999}` built a
                        // 99999-deep matcher.
                        if min > 1000 || (max != usize::MAX && (max > 1000 || min > max)) {
                            return Err("invalid repeat count");
                        }
                        let greedy = self.take_greedy();
                        Ok(Node::Repeat {
                            node: Box::new(atom),
                            min,
                            max,
                            greedy,
                        })
                    }
                    Err(_) => {
                        self.pos = save;
                        Ok(atom)
                    }
                }
            }
            _ => Ok(atom),
        };
    }

    // go: none — this file is still one unanchored module root; splitting
    //     it per Go file (regexp.go, syntax/parse.go, exec.go) and anchoring
    //     it is its own unit. Go reads the `?` suffix in `parse.go`'s
    //     repeat handling.
    /// A `?` right after a quantifier makes it non-greedy.
    fn take_greedy(&mut self) -> bool {
        if self.peek() == Some(b'?') {
            self.bump();
            return false;
        }
        return true;
    }

    /// Parse `{n}`, `{n,}`, `{n,m}` (closing brace already pending).
    fn parse_brace_count(&mut self) -> Result<(usize, usize), &'static str> {
        let mut n: usize = 0;
        let mut have_n = false;
        while let Some(b) = self.peek() {
            if !b.is_ascii_digit() {
                break;
            }
            self.bump();
            n = n.saturating_mul(10).saturating_add((b - b'0') as usize);
            have_n = true;
        }
        if !have_n {
            return Err("missing number in {n,m}");
        }
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok((n, n));
        }
        if self.peek() != Some(b',') {
            return Err("expected ',' or '}' in {n,m}");
        }
        self.bump();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok((n, usize::MAX));
        }
        let mut m: usize = 0;
        let mut have_m = false;
        while let Some(b) = self.peek() {
            if !b.is_ascii_digit() {
                break;
            }
            self.bump();
            m = m.saturating_mul(10).saturating_add((b - b'0') as usize);
            have_m = true;
        }
        if !have_m {
            return Err("missing upper bound in {n,m}");
        }
        if self.peek() != Some(b'}') {
            return Err("expected '}' in {n,m}");
        }
        self.bump();
        return Ok((n, m));
    }

    /// Parse a single atom (literal, escape, class, group, anchor).
    fn parse_atom(&mut self) -> Result<Node, &'static str> {
        let b = self.peek().ok_or("unexpected end of pattern")?;
        return match b {
            b'(' => {
                self.bump();
                // `(?...)` — non-capturing group, or a Perl flag group.
                if self.peek() == Some(b'?') {
                    self.bump();
                    if self.peek() != Some(b':') {
                        return self.parse_perl_flags();
                    }
                    self.bump();
                    // The group body's flags do not escape it.
                    let saved = self.flags();
                    let inner = self.parse_alt()?;
                    if self.peek() != Some(b')') {
                        return Err("unmatched '('");
                    }
                    self.bump();
                    self.set_flags(saved);
                    return Ok(Node::NonCap(Box::new(inner)));
                }
                let idx = self.next_cap;
                self.next_cap += 1;
                self.names.push(string::from_static(""));
                let saved = self.flags();
                let inner = self.parse_alt()?;
                if self.peek() != Some(b')') {
                    return Err("unmatched '('");
                }
                self.bump();
                self.set_flags(saved);
                Ok(Node::Group {
                    idx,
                    inner: Box::new(inner),
                })
            }
            b'[' => {
                self.bump();
                self.parse_class()
            }
            b'.' => {
                self.bump();
                if self.dot_nl {
                    return Ok(Node::AnyChar);
                }
                Ok(Node::AnyCharNotNL)
            }
            b'^' => {
                self.bump();
                if self.multi {
                    return Ok(Node::BeginLine);
                }
                Ok(Node::AnchorStart)
            }
            b'$' => {
                self.bump();
                if self.multi {
                    return Ok(Node::EndLine);
                }
                Ok(Node::AnchorEnd)
            }
            b'\\' => {
                self.bump();
                let nb = self.peek().ok_or("trailing backslash")?;
                // Numeric escapes: `\x41`, `\x{1F600}` and the octal
                // `\101`. Go's parser reads these before the
                // single-letter table; goish accepted them as the
                // literal letter, so `\x41` never matched 'A' and never
                // said why.
                if nb == b'x' || (b'0' <= nb && nb <= b'7') {
                    if let Some(r) = self.parse_numeric_escape()? {
                        return Ok(self.fold_node(Node::Literal(r)));
                    }
                }
                self.bump();
                // Go rejects any ALPHANUMERIC escape it does not know —
                // parse.go's "invalid escape sequence". goish accepted
                // every one as the literal letter, so `\p{L}` became the
                // five-character string "p{L}" and `\q` became "q":
                // patterns that compiled and never matched, with nothing
                // said. `\p`/`\P` are Go's Unicode classes and need the
                // script tables, which this matcher does not carry.
                if nb.is_ascii_alphanumeric() && !is_known_escape(nb) {
                    return Err("invalid escape sequence");
                }
                // NOT COVERED by the differential, and uncoverable there:
                // the fold can only fire for an escaped ASCII LETTER, and
                // Go rejects every letter escape that has a case
                // (`\q` → "invalid escape sequence"), so no Go-valid
                // pattern reaches it. goish accepts unknown escapes as
                // literals, so the call is what keeps `(?i)\q` consistent
                // with `(?i)q` inside goish.
                Ok(self.fold_node(escape_to_node(nb)))
            }
            b')' | b'|' | b'*' | b'+' | b'?' => Err("unexpected metacharacter"),
            // Go treats a `{` that does not open a valid repetition, and
            // a bare `}`, as ordinary literals — `a{,3}` is the
            // five-character string, not a repeat.
            _ => {
                let (r, w) = decode_rune(self.src, self.pos);
                self.pos += w;
                Ok(self.fold_node(Node::Literal(r)))
            }
        };
    }

    /// Parse the flag list of `(?flags)` or `(?flags:re)`. The leading
    /// `(?` is consumed and the next byte is known not to be `:`.
    ///
    /// Go: regexp/syntax/parse.go `parsePerlFlags`. Goish v1 implements
    /// the `i` flag only; `s`, `m` and `U` still fail at Compile time,
    /// as does any other `(?...)` construct (lookaround, named groups).
    fn parse_perl_flags(&mut self) -> Result<Node, &'static str> {
        // `(?P<name>re)` and `(?<name>re)` — a named CAPTURING group.
        // The name is parsed and discarded: goish has no SubexpNames,
        // but the group still has to capture, and rejecting the whole
        // pattern was the wrong answer.
        if self.peek() == Some(b'P') && self.src.get(self.pos + 1) == Some(&b'<')
            || self.peek() == Some(b'<')
        {
            if self.peek() == Some(b'P') {
                self.bump();
            }
            self.bump(); // '<'
            let name_start = self.pos;
            while let Some(c) = self.peek() {
                if c == b'>' {
                    break;
                }
                if !(c.is_ascii_alphanumeric() || c == b'_') {
                    return Err("invalid named capture");
                }
                self.bump();
            }
            if self.peek() != Some(b'>') {
                return Err("invalid named capture");
            }
            // Go: "if name == \"\" { return … ErrInvalidNamedCapture }".
            // goish accepted `(?P<>a)` and gave the group no name.
            if self.pos == name_start {
                return Err("invalid named capture");
            }
            let name = string::from_bytes(&self.src[name_start..self.pos]);
            // Go: "Like ordinary capture, but named."  Duplicate names
            // are rejected there too.
            let mut k = 1usize;
            while k < self.names.len() {
                if self.names[k] == name {
                    return Err("duplicate capture group name");
                }
                k += 1;
            }
            self.bump();
            let idx = self.next_cap;
            self.next_cap += 1;
            self.names.push(name);
            let saved = self.flags();
            let inner = self.parse_alt()?;
            if self.peek() != Some(b')') {
                return Err("unmatched '('");
            }
            self.bump();
            self.set_flags(saved);
            return Ok(Node::Group {
                idx,
                inner: Box::new(inner),
            });
        }

        let saved = self.flags();
        let (mut fold, mut dot_nl, mut multi) = saved;
        let mut neg = false;
        let mut sawFlag = false;
        loop {
            match self.peek() {
                Some(b'i') => {
                    self.bump();
                    fold = !neg;
                    sawFlag = true;
                }
                Some(b's') => {
                    self.bump();
                    dot_nl = !neg;
                    sawFlag = true;
                }
                Some(b'm') => {
                    self.bump();
                    multi = !neg;
                    sawFlag = true;
                }
                Some(b'-') if !neg => {
                    self.bump();
                    neg = true;
                }
                Some(b':') | Some(b')') => break,
                _ => return Err("unsupported (?...) construct"),
            }
        }
        // Go: `(?)` and `(?-)` are "invalid or unsupported Perl syntax".
        if !sawFlag {
            return Err("unsupported (?...) construct");
        }
        return match self.bump() {
            // `(?flags)` — applies to the rest of the enclosing group.
            // Matches the empty string, which an empty Concat already is.
            Some(b')') => {
                self.set_flags((fold, dot_nl, multi));
                Ok(Node::Concat(Vec::new()))
            }
            // `(?flags:re)` — applies to `re` only.
            Some(b':') => {
                self.set_flags((fold, dot_nl, multi));
                let inner = self.parse_alt()?;
                if self.peek() != Some(b')') {
                    return Err("unmatched '('");
                }
                self.bump();
                self.set_flags(saved);
                Ok(Node::NonCap(Box::new(inner)))
            }
            _ => Err("unmatched '('"),
        };
    }

    // go: none — this file is still one unanchored module root; splitting
    //     it per Go file (regexp.go, syntax/parse.go, exec.go) and anchoring
    //     it is its own unit. Go carries the scoped flags in one `Flags` word on
    //     the parser.
    /// The three scoped flags, as Go's parser carries them in one word.
    fn flags(&self) -> (bool, bool, bool) {
        return (self.fold, self.dot_nl, self.multi);
    }

    // go: none — this file is still one unanchored module root; splitting
    //     it per Go file (regexp.go, syntax/parse.go, exec.go) and anchoring
    //     it is its own unit. See the note on `flags`.
    fn set_flags(&mut self, f: (bool, bool, bool)) {
        self.fold = f.0;
        self.dot_nl = f.1;
        self.multi = f.2;
    }

    /// Under the `i` flag, a literal ASCII letter matches either case.
    /// Go folds at the rune level in the parser (parse.go `literal`);
    /// this fold is ASCII-only, which is the whole of the byte-oriented
    /// matcher's alphabet. Non-literal nodes (`\d`, `\w`, …) pass
    /// through: Go's fold does not touch a predefined class either.
    fn fold_node(&self, n: Node) -> Node {
        if !self.fold {
            return n;
        }
        return match n {
            Node::Literal(r) if is_ascii_letter(r) => Node::Class {
                negate: false,
                ranges: vec![(r | 0x20, r | 0x20), (r & !0x20, r & !0x20)],
            },
            other => other,
        };
    }

    /// Parse a `[...]` class body. Opening `[` already consumed.
    fn parse_class(&mut self) -> Result<Node, &'static str> {
        let mut negate = false;
        if self.peek() == Some(b'^') {
            self.bump();
            negate = true;
        }
        let mut ranges: Vec<(rune, rune)> = Vec::new();
        let mut first = true;
        loop {
            match self.peek() {
                None => return Err("unterminated character class"),
                // `]` closes the class — except when it appears as the
                // first character (Go: `[]]` is the class containing `]`).
                Some(b']') if !first => {
                    self.bump();
                    break;
                }
                _ => {}
            }
            first = false;
            let atom = self.parse_class_atom()?;
            match atom {
                ClassAtom::Expanded(sub_ranges) => {
                    // \w, \d, \s etc. inside a class — merge their ranges in
                    ranges.extend(sub_ranges);
                }
                ClassAtom::Rune(lo) => {
                    // Range `a-b`?
                    if self.peek() == Some(b'-') {
                        // Peek ahead — `-` followed by `]` is a literal `-`.
                        if self.src.get(self.pos + 1) == Some(&b']') {
                            ranges.push((lo, lo));
                            continue;
                        }
                        self.bump();
                        let hi_atom = self.parse_class_atom()?;
                        let hi = match hi_atom {
                            ClassAtom::Rune(r) => r,
                            ClassAtom::Expanded(_) => return Err("invalid character range"),
                        };
                        if hi < lo {
                            return Err("invalid character range");
                        }
                        ranges.push((lo, hi));
                    } else {
                        ranges.push((lo, lo));
                    }
                }
            }
        }
        if self.fold {
            // Go folds the class MEMBERS and negates afterwards
            // (parse.go: `cc.AddRangeFlags` with FoldCase, then
            // `cc.Negate()`), so `(?i)[^a-z]` excludes 'A'-'Z' too.
            // Adding the folded ranges before the `negate` flag is
            // consulted reproduces that ordering.
            let mut folded: Vec<(rune, rune)> = Vec::new();
            for &(lo, hi) in &ranges {
                if let Some(r) = fold_range(lo, hi, toint32(b'a'), toint32(b'z')) {
                    folded.push(r);
                }
                if let Some(r) = fold_range(lo, hi, toint32(b'A'), toint32(b'Z')) {
                    folded.push(r);
                }
            }
            ranges.extend(folded);
        }
        return Ok(Node::Class { negate, ranges });
    }

    /// Parse one atom inside `[...]`. Returns a `ClassAtom`:
    /// - `Rune(r)` for a single rune (literal or simple escape)
    /// - `Expanded(ranges)` for the shorthand and POSIX classes
    fn parse_class_atom(&mut self) -> Result<ClassAtom, &'static str> {
        // `[:alpha:]` and its thirteen siblings, which only mean
        // anything inside a class. goish accepted the bytes as ordinary
        // members, so `[[:alpha:]]` compiled to the class `{[, :, a, l,
        // p, h}` and never matched a letter — and never said why.
        if self.peek() == Some(b'[') && self.src.get(self.pos + 1) == Some(&b':') {
            if let Some(r) = self.parse_posix_class()? {
                return Ok(ClassAtom::Expanded(r));
            }
        }
        let b = self.peek().ok_or("unterminated character class")?;
        if b == b'\\' {
            self.bump();
            let nb = self.peek().ok_or("trailing backslash in class")?;
            if nb == b'x' || (b'0' <= nb && nb <= b'7') {
                if let Some(r) = self.parse_numeric_escape()? {
                    return Ok(ClassAtom::Rune(r));
                }
            }
            self.bump();
            match nb {
                b'd' => return Ok(ClassAtom::Expanded(digit_ranges())),
                b'D' => return Ok(ClassAtom::Expanded(negate_ranges(digit_ranges()))),
                b'w' => return Ok(ClassAtom::Expanded(word_ranges())),
                b'W' => return Ok(ClassAtom::Expanded(negate_ranges(word_ranges()))),
                b's' => return Ok(ClassAtom::Expanded(space_ranges())),
                b'S' => return Ok(ClassAtom::Expanded(negate_ranges(space_ranges()))),
                _ => return Ok(ClassAtom::Rune(escape_rune(nb))),
            }
        }
        let (r, w) = decode_rune(self.src, self.pos);
        self.pos += w;
        return Ok(ClassAtom::Rune(r));
    }

    // go: none — this file is still one unanchored module root; splitting
    //     it per Go file (regexp.go, syntax/parse.go, exec.go) and anchoring
    //     it is its own unit. Go: `parse.go`'s `parseNamedClass`.
    /// `[:name:]` inside a class. Returns None (consuming nothing) when
    /// what follows `[:` is not one of Go's fourteen POSIX names, which
    /// is how `[[:foo]` stays a plain class of literals.
    fn parse_posix_class(&mut self) -> Result<Option<Vec<(rune, rune)>>, &'static str> {
        let start = self.pos;
        let mut j = self.pos + 2;
        let mut neg = false;
        if self.src.get(j) == Some(&b'^') {
            neg = true;
            j += 1;
        }
        let name_start = j;
        while j < self.src.len() && self.src[j] != b':' {
            j += 1;
        }
        if j + 1 >= self.src.len() || self.src[j] != b':' || self.src[j + 1] != b']' {
            self.pos = start;
            return Ok(None);
        }
        let name = &self.src[name_start..j];
        let ranges = match posix_ranges(name) {
            Some(r) => r,
            None => return Err("invalid character class range"),
        };
        self.pos = j + 2;
        if neg {
            return Ok(Some(negate_ranges(ranges)));
        }
        return Ok(Some(ranges));
    }

    // go: none — this file is still one unanchored module root; splitting
    //     it per Go file (regexp.go, syntax/parse.go, exec.go) and anchoring
    //     it is its own unit. Go: the `\\x` and octal arms of
    //     `parse.go`'s `parseEscape`.
    /// `\x41`, `\x{1F600}` or the octal `\101`, with the backslash
    /// consumed and the next byte known to be `x` or an octal digit.
    /// Returns None (consuming nothing) when the text does not in fact
    /// form one, so the caller can fall back to its escape table.
    fn parse_numeric_escape(&mut self) -> Result<Option<rune>, &'static str> {
        let start = self.pos;
        if self.peek() == Some(b'x') {
            self.bump();
            if self.peek() == Some(b'{') {
                self.bump();
                let mut v: rune = 0;
                let mut n = 0;
                while let Some(c) = self.peek() {
                    let d = match hex_digit(c) {
                        Some(d) => d,
                        None => break,
                    };
                    self.bump();
                    v = v * 16 + d;
                    n += 1;
                    if v > MAX_RUNE {
                        return Err("invalid escape sequence");
                    }
                }
                if n == 0 || self.peek() != Some(b'}') {
                    return Err("invalid escape sequence");
                }
                self.bump();
                return Ok(Some(v));
            }
            // Exactly two hex digits.
            let d1 = self.peek().and_then(hex_digit);
            let d2 = self.src.get(self.pos + 1).copied().and_then(hex_digit);
            match (d1, d2) {
                (Some(a), Some(b)) => {
                    self.pos += 2;
                    return Ok(Some(a * 16 + b));
                }
                _ => return Err("invalid escape sequence"),
            }
        }
        // Octal: up to three digits, `\0` through `\377`.
        let mut v: rune = 0;
        let mut n = 0;
        while n < 3 {
            match self.peek() {
                Some(c) if b'0' <= c && c <= b'7' => {
                    self.bump();
                    v = v * 8 + toint32(c - b'0');
                    n += 1;
                }
                _ => break,
            }
        }
        if n == 0 {
            self.pos = start;
            return Ok(None);
        }
        return Ok(Some(v));
    }
}

// go: none — this file is still one unanchored module root; splitting
//     it per Go file (regexp.go, syntax/parse.go, exec.go) and anchoring
//     it is its own unit. Go's matcher steps in runes via
//     `utf8.DecodeRuneInString`.
/// One rune at `pos`, with its width. Go's matcher steps in runes, and
/// an invalid leading byte is `utf8.RuneError` of width 1 — the same
/// answer `utf8.DecodeRune` gives, so an ill-formed input still
/// advances.
fn decode_rune(text: &[u8], pos: usize) -> (rune, usize) {
    let (r, w) = crate::unicode::utf8::DecodeRune(&text[pos..]);
    return (r, w as usize);
}

// go: none — this file is still one unanchored module root; splitting
//     it per Go file (regexp.go, syntax/parse.go, exec.go) and anchoring
//     it is its own unit. Go: `regexp/syntax.IsWordChar`.
/// A word character for `\b`/`\B` — Go's `syntax.IsWordChar`:
/// `[0-9A-Za-z_]`.
fn is_word_rune(r: rune) -> bool {
    return (toint32(b'0') <= r && r <= toint32(b'9'))
        || (toint32(b'A') <= r && r <= toint32(b'Z'))
        || (toint32(b'a') <= r && r <= toint32(b'z'))
        || r == toint32(b'_');
}

// go: none — this file is still one unanchored module root; splitting
//     it per Go file (regexp.go, syntax/parse.go, exec.go) and anchoring
//     it is its own unit. Go computes this as the `EmptyWordBoundary` op
//     from the runes either side of the position.
/// Whether `pos` sits on a word boundary: exactly one side is a word
/// rune. Go: `regexp/syntax` EmptyWordBoundary, computed from the runes
/// either side of the position.
fn is_word_boundary(text: &[u8], pos: usize) -> bool {
    let before = if pos == 0 {
        false
    } else {
        // Step back over continuation bytes to the rune's leading byte.
        let mut i = pos - 1;
        while i > 0 && text[i] & 0xC0 == 0x80 {
            i -= 1;
        }
        let (r, _) = decode_rune(text, i);
        is_word_rune(r)
    };
    let after = if pos >= text.len() {
        false
    } else {
        let (r, _) = decode_rune(text, pos);
        is_word_rune(r)
    };
    return before != after;
}

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

/// The case-flipped image of `[lo,hi] ∩ [clipLo,clipHi]`, or None when
/// the intersection is empty. `clip` is one of the two ASCII letter
/// runs; flipping the intersection gives the other run's counterpart,
/// which is what the `i` flag adds to a class.
fn fold_range(lo: rune, hi: rune, clipLo: rune, clipHi: rune) -> Option<(rune, rune)> {
    let lo = if lo > clipLo { lo } else { clipLo };
    let hi = if hi < clipHi { hi } else { clipHi };
    if lo > hi {
        return None;
    }
    // 'a' - 'A' == 32; flipping bit 5 maps each run onto the other.
    return Some((lo ^ 0x20, hi ^ 0x20));
}

/// Atom returned from `parse_class_atom` — either a single byte or
/// multiple expanded ranges (from `\w`, `\d`, `\s`).
enum ClassAtom {
    Rune(rune),
    Expanded(Vec<(rune, rune)>),
}

/// Translate a `\X` escape OUTSIDE a class to a Node. Predefined classes
/// like `\d` expand to a class node; literal escapes return a Literal.
fn escape_to_node(b: byte) -> Node {
    return match b {
        b'd' => Node::Class {
            negate: false,
            ranges: digit_ranges(),
        },
        b'D' => Node::Class {
            negate: true,
            ranges: digit_ranges(),
        },
        b'w' => Node::Class {
            negate: false,
            ranges: word_ranges(),
        },
        b'W' => Node::Class {
            negate: true,
            ranges: word_ranges(),
        },
        b's' => Node::Class {
            negate: false,
            ranges: space_ranges(),
        },
        b'S' => Node::Class {
            negate: true,
            ranges: space_ranges(),
        },
        b'b' => Node::WordBoundary(true),
        b'B' => Node::WordBoundary(false),
        b'A' => Node::AnchorStart,
        b'z' => Node::AnchorEnd,
        b'a' => Node::Literal(0x07),
        b'f' => Node::Literal(0x0C),
        b'n' => Node::Literal(toint32(b'\n')),
        b'r' => Node::Literal(toint32(b'\r')),
        b't' => Node::Literal(toint32(b'\t')),
        b'v' => Node::Literal(0x0B),
        _ => Node::Literal(toint32(b)),
    };
}

/// Translate a `\X` escape INSIDE a class to a literal byte. We don't
/// expand `\d`/`\w`/`\s` inside classes (semver patterns don't use it).
fn escape_rune(b: byte) -> rune {
    return match b {
        b'a' => 0x07,
        b'f' => 0x0C,
        b'n' => toint32(b'\n'),
        b'r' => toint32(b'\r'),
        b't' => toint32(b'\t'),
        b'v' => 0x0B,
        _ => toint32(b),
    };
}

// go: none — this file is still one unanchored module root; splitting
//     it per Go file (regexp.go, syntax/parse.go, exec.go) and anchoring
//     it is its own unit. a digit reader for `\\xHH`; Go uses `unhex`.
/// A hex digit's value, or None.
fn hex_digit(c: byte) -> Option<rune> {
    if b'0' <= c && c <= b'9' {
        return Some(toint32(c - b'0'));
    }
    if b'a' <= c && c <= b'f' {
        return Some(toint32(c - b'a') + 10);
    }
    if b'A' <= c && c <= b'F' {
        return Some(toint32(c - b'A') + 10);
    }
    return None;
}

// go: none — this file is still one unanchored module root; splitting
//     it per Go file (regexp.go, syntax/parse.go, exec.go) and anchoring
//     it is its own unit. the escape set `parse.go`'s `parseEscape`
//     accepts; everything else alphanumeric is an error there too.
/// The escapes this matcher understands after a backslash. Anything
/// else that is alphanumeric is an error, as it is in Go.
fn is_known_escape(b: byte) -> bool {
    return matches!(
        b,
        b'a' | b'f'
            | b'n'
            | b'r'
            | b't'
            | b'v'
            | b'd'
            | b'D'
            | b's'
            | b'S'
            | b'w'
            | b'W'
            | b'b'
            | b'B'
            | b'A'
            | b'z'
            | b'x'
    );
}

// go: none — this file is still one unanchored module root; splitting
//     it per Go file (regexp.go, syntax/parse.go, exec.go) and anchoring
//     it is its own unit. the ASCII half of Go's case folding.
fn is_ascii_letter(r: rune) -> bool {
    return (toint32(b'A') <= r && r <= toint32(b'Z'))
        || (toint32(b'a') <= r && r <= toint32(b'z'));
}

// go: none — this file is still one unanchored module root; splitting
//     it per Go file (regexp.go, syntax/parse.go, exec.go) and anchoring
//     it is its own unit. Go: `CharClass.negateClass`.
/// The complement of a rune-range set over `0..=MAX_RUNE`. Go's
/// `CharClass.Negate` does the same after sorting and merging; the sets
/// here are small and already ordered by construction.
fn negate_ranges(ranges: Vec<(rune, rune)>) -> Vec<(rune, rune)> {
    let mut rs = ranges;
    rs.sort();
    let mut out: Vec<(rune, rune)> = Vec::new();
    let mut next: rune = 0;
    for &(lo, hi) in rs.iter() {
        if lo > next {
            out.push((next, lo - 1));
        }
        if hi + 1 > next {
            next = hi + 1;
        }
    }
    if next <= MAX_RUNE {
        out.push((next, MAX_RUNE));
    }
    return out;
}

// go: none — this file is still one unanchored module root; splitting
//     it per Go file (regexp.go, syntax/parse.go, exec.go) and anchoring
//     it is its own unit. Go: the `posixGroup` map in
//     `regexp/syntax/parse.go`.
/// Go: `regexp/syntax.posixGroup` — the fourteen `[:name:]` classes.
/// All are ASCII-only, as they are in Go.
fn posix_ranges(name: &[u8]) -> Option<Vec<(rune, rune)>> {
    let d = |a: u8, b: u8| (toint32(a), toint32(b));
    return match name {
        b"alnum" => Some(vec![d(b'0', b'9'), d(b'A', b'Z'), d(b'a', b'z')]),
        b"alpha" => Some(vec![d(b'A', b'Z'), d(b'a', b'z')]),
        b"ascii" => Some(vec![(0, 0x7F)]),
        b"blank" => Some(vec![d(b'\t', b'\t'), d(b' ', b' ')]),
        b"cntrl" => Some(vec![(0, 0x1F), (0x7F, 0x7F)]),
        b"digit" => Some(digit_ranges()),
        b"graph" => Some(vec![(0x21, 0x7E)]),
        b"lower" => Some(vec![d(b'a', b'z')]),
        b"print" => Some(vec![(0x20, 0x7E)]),
        b"punct" => Some(vec![(0x21, 0x2F), (0x3A, 0x40), (0x5B, 0x60), (0x7B, 0x7E)]),
        b"space" => Some(vec![(0x09, 0x0D), d(b' ', b' ')]),
        b"upper" => Some(vec![d(b'A', b'Z')]),
        b"word" => Some(word_ranges()),
        b"xdigit" => Some(vec![d(b'0', b'9'), d(b'A', b'F'), d(b'a', b'f')]),
        _ => None,
    };
}

/// The largest valid rune, and the top of every negated class.
const MAX_RUNE: rune = 0x10FFFF;

// go: none — this file is still one unanchored module root; splitting
//     it per Go file (regexp.go, syntax/parse.go, exec.go) and anchoring
//     it is its own unit. the `\\d` range set, which Go builds from its
//     `perlGroup` table.
#[inline]
fn digit_ranges() -> Vec<(rune, rune)> {
    return vec![(toint32(b'0'), toint32(b'9'))];
}

#[inline]
fn word_ranges() -> Vec<(rune, rune)> {
    return vec![
        (toint32(b'0'), toint32(b'9')),
        (toint32(b'A'), toint32(b'Z')),
        (toint32(b'_'), toint32(b'_')),
        (toint32(b'a'), toint32(b'z')),
    ];
}

#[inline]
fn space_ranges() -> Vec<(rune, rune)> {
    return vec![
        (toint32(b'\t'), toint32(b'\t')),
        (toint32(b'\n'), toint32(b'\n')),
        (0x0B, 0x0B),
        (0x0C, 0x0C),
        (toint32(b'\r'), toint32(b'\r')),
        (toint32(b' '), toint32(b' ')),
    ];
}

// ─── Regexp (compiled) ─────────────────────────────────────────────────

/// Compiled regular expression. Mirrors Go's `*Regexp` opaque pointer.
#[derive(Clone)]
pub struct Regexp {
    root: Arc<Node>,
    n_caps: usize,
    /// Go's `subexpNames`; see the field of the same name on `Parser`.
    names: Vec<string>,
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
}

// ─── Compile / MustCompile ─────────────────────────────────────────────

/// `regexp.Compile(expr)` — parse a pattern. Returns the compiled
/// Regexp + nil on success, or empty Regexp + error on parse failure.
pub fn Compile<S: Into<string>>(expr: S) -> (Regexp, error) {
    let expr_s = expr.into();
    if !crate::unicode::utf8::Valid(expr_s.as_bytes()) {
        return (
            Regexp {
                root: Arc::new(Node::Concat(Vec::new())),
                n_caps: 0,
                names: alloc::vec![string::from_static("")],
                pattern: expr_s.clone(),
            },
            compile_err(&expr_s, "invalid UTF-8"),
        );
    }
    let mut p = Parser::new(expr_s.as_bytes());
    return match p.parse_alt() {
        Ok(node) => {
            if p.pos != p.src.len() {
                return (
                    Regexp {
                        root: Arc::new(Node::Concat(Vec::new())),
                        n_caps: 0,
                        names: alloc::vec![string::from_static("")],
                        pattern: expr_s.clone(),
                    },
                    compile_err(&expr_s, "trailing junk in pattern"),
                );
            }
            (
                Regexp {
                    root: Arc::new(node),
                    n_caps: p.next_cap - 1,
                    names: p.names,
                    pattern: expr_s,
                },
                crate::nilval::nil.into(),
            )
        }
        Err(why) => (
            Regexp {
                root: Arc::new(Node::Concat(Vec::new())),
                n_caps: 0,
                names: alloc::vec![string::from_static("")],
                pattern: expr_s.clone(),
            },
            compile_err(&expr_s, why),
        ),
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

fn compile_err(expr: &string, why: &'static str) -> error {
    let mut b = crate::strings::Builder::new();
    let _ = b.WriteString(string::from_static("regexp: "));
    let _ = b.WriteString(string::from_static(why));
    let _ = b.WriteString(string::from_static(": `"));
    let _ = b.WriteString(expr.clone());
    let _ = b.WriteString(string::from_static("`"));
    return errors::New(b.String());
}

// ─── Backtracking matcher ──────────────────────────────────────────────
//
// Continuation-passing backtracker. `try_match(node, …, cont)` returns
// `Some(end_pos)` if `node` matches at `pos` AND the remaining pattern
// (`cont`) succeeds from wherever `node` ends, otherwise `None`. The
// continuation is a flat slice of `Node`s yet to be matched — each
// `Node` is matched in order via `match_cont`. Captures are
// written/restored across backtracks per-node.
//
// Why CPS, not local matching: an alternation branch that locally
// matches but is followed by a failing tail must yield to the next
// alternative. Local matching commits prematurely. By threading the
// outer-pattern continuation into every branch, Alt iterates branches
// against the same tail and only commits when the *whole* remaining
// pattern succeeds. Mirrors Go's `regexp` (NFA simulator) and
// `backtrack.go` semantics; see exec.go:339 InstAlt and
// backtrack.go:171 InstAlt for the equivalent reference behaviour.

type Capture = (i32, i32); // (-1, -1) = unset

/// Walk the continuation: if empty, the match has succeeded at `pos`;
/// otherwise dispatch to the head item with the rest as its cont.
fn match_cont(text: &[u8], pos: usize, caps: &mut Vec<Capture>, cont: &[Node]) -> Option<usize> {
    if cont.is_empty() {
        return Some(pos);
    }
    return try_match(&cont[0], text, pos, caps, &cont[1..]);
}

/// Match the whole node tree starting at `pos`. `caps` is a flat array
/// indexed by capture slot (index 0 = whole match, 1..=n_caps = groups).
/// `cont` is the rest of the surrounding pattern, threaded through so
/// alternation and grouping can backtrack across concat boundaries.
fn try_match(
    node: &Node,
    text: &[u8],
    pos: usize,
    caps: &mut Vec<Capture>,
    cont: &[Node],
) -> Option<usize> {
    return match node {
        Node::Literal(r) => {
            if pos >= text.len() {
                return None;
            }
            let (c, w) = decode_rune(text, pos);
            if c == *r {
                match_cont(text, pos + w, caps, cont)
            } else {
                None
            }
        }
        Node::AnyCharNotNL => {
            if pos >= text.len() {
                return None;
            }
            let (c, w) = decode_rune(text, pos);
            if c == toint32(b'\n') {
                return None;
            }
            match_cont(text, pos + w, caps, cont)
        }
        Node::AnyChar => {
            if pos >= text.len() {
                return None;
            }
            let (_, w) = decode_rune(text, pos);
            match_cont(text, pos + w, caps, cont)
        }
        Node::Class { negate, ranges } => {
            if pos >= text.len() {
                return None;
            }
            let (c, w) = decode_rune(text, pos);
            let mut hit = false;
            for &(lo, hi) in ranges {
                if c >= lo && c <= hi {
                    hit = true;
                    break;
                }
            }
            if hit ^ *negate {
                match_cont(text, pos + w, caps, cont)
            } else {
                None
            }
        }
        Node::WordBoundary(want) => {
            if is_word_boundary(text, pos) == *want {
                match_cont(text, pos, caps, cont)
            } else {
                None
            }
        }
        Node::AnchorStart => {
            if pos == 0 {
                match_cont(text, pos, caps, cont)
            } else {
                None
            }
        }
        Node::AnchorEnd => {
            if pos == text.len() {
                match_cont(text, pos, caps, cont)
            } else {
                None
            }
        }
        Node::BeginLine => {
            if pos == 0 || text[pos - 1] == b'\n' {
                match_cont(text, pos, caps, cont)
            } else {
                None
            }
        }
        Node::EndLine => {
            if pos == text.len() || text[pos] == b'\n' {
                match_cont(text, pos, caps, cont)
            } else {
                None
            }
        }
        Node::Concat(items) => {
            if items.is_empty() {
                return match_cont(text, pos, caps, cont);
            }
            // Splice items[1..] in front of the outer cont; first item
            // is matched immediately with the spliced cont as its tail.
            let mut new_cont: Vec<Node> = Vec::with_capacity(items.len() - 1 + cont.len());
            new_cont.extend_from_slice(&items[1..]);
            new_cont.extend_from_slice(cont);
            try_match(&items[0], text, pos, caps, &new_cont)
        }
        Node::Alt(branches) => {
            // Try each branch against the SAME outer cont so a branch
            // that locally matches but fails downstream yields to the
            // next branch. This is the fix for the alternation /
            // concat-boundary backtracking gap.
            for b in branches {
                let saved = caps.clone();
                if let Some(end) = try_match(b, text, pos, caps, cont) {
                    return Some(end);
                }
                *caps = saved;
            }
            None
        }
        Node::Group { idx, inner } => {
            let prev = caps[*idx];
            caps[*idx] = (pos as i32, -1);
            // Insert EndGroup marker between the inner subexpression
            // and the outer cont. The marker sets caps[idx].1 when
            // reached and is reverted on tail failure.
            let mut new_cont: Vec<Node> = Vec::with_capacity(1 + cont.len());
            new_cont.push(Node::EndGroup(*idx));
            new_cont.extend_from_slice(cont);
            match try_match(inner, text, pos, caps, &new_cont) {
                Some(end) => Some(end),
                None => {
                    caps[*idx] = prev;
                    None
                }
            }
        }
        Node::NonCap(inner) => try_match(inner, text, pos, caps, cont),
        Node::Repeat {
            node,
            min,
            max,
            greedy,
        } => match_repeat(node, *min, *max, *greedy, text, pos, caps, cont, None),
        Node::RepeatTail {
            node,
            min,
            max,
            last_pos,
            greedy,
            saved,
        } => match_repeat(
            node,
            *min,
            *max,
            *greedy,
            text,
            pos,
            caps,
            cont,
            Some((*last_pos, saved)),
        ),
        Node::EndGroup(idx) => {
            let prev_end = caps[*idx].1;
            caps[*idx].1 = pos as i32;
            match match_cont(text, pos, caps, cont) {
                Some(end) => Some(end),
                None => {
                    caps[*idx].1 = prev_end;
                    None
                }
            }
        }
    };
}

/// Greedy `node{min,max}` followed by `cont`, CPS-style. Each rep
/// attempts to match `node` against the continuation
/// `[RepeatTail{...}, ...cont]`, so Alt and Group choices inside
/// `node` can backtrack across rep counts AND across the outer
/// continuation. On rep failure, falls back to "zero reps from here"
/// when `min` is already satisfied. `prev_pos` is `Some(start_of_last_rep)`
/// when re-entered via `RepeatTail` — equal-to-current-pos means the
/// previous rep was zero-width, so the chain stops to avoid infinite
/// recursion (mirrors Go's behavior on zero-width quantifiers; see
/// `regexp/exec.go` InstAlt / NFA simulator).
fn match_repeat(
    node: &Node,
    min: usize,
    max: usize,
    greedy: bool,
    text: &[u8],
    pos: usize,
    caps: &mut Vec<Capture>,
    cont: &[Node],
    prev: Option<(usize, &Vec<Capture>)>,
) -> Option<usize> {
    if let Some((p, before)) = prev {
        if pos == p {
            // The iteration just finished consumed nothing. Go stops
            // here and does NOT keep that iteration's captures.
            *caps = before.clone();
            return match_cont(text, pos, caps, cont);
        }
    }
    if max == 0 {
        return match_cont(text, pos, caps, cont);
    }

    let next_min = if min == 0 { 0 } else { min - 1 };
    let next_max = if max == usize::MAX {
        usize::MAX
    } else {
        max - 1
    };

    let saved = caps.clone();

    let mut rep_cont: Vec<Node> = Vec::with_capacity(1 + cont.len());
    rep_cont.push(Node::RepeatTail {
        node: Box::new((*node).clone()),
        min: next_min,
        max: next_max,
        last_pos: pos,
        greedy,
        saved: saved.clone(),
    });
    rep_cont.extend_from_slice(cont);

    // Go: a non-greedy repetition prefers the FEWEST reps, so once the
    // minimum is met it tries the continuation before trying another
    // one. Greedy is the other order.
    if !greedy && min == 0 {
        if let Some(end) = match_cont(text, pos, caps, cont) {
            return Some(end);
        }
        *caps = saved.clone();
    }

    if let Some(end) = try_match(node, text, pos, caps, &rep_cont) {
        return Some(end);
    }
    *caps = saved;

    if greedy && min == 0 {
        return match_cont(text, pos, caps, cont);
    }
    return None;
}

// ─── Public API: search drivers ────────────────────────────────────────

impl Regexp {
    /// Try to match the pattern starting at `pos`. Used for both
    /// MatchString (cares only about success) and FindStringSubmatch
    /// (returns capture vector).
    fn match_at(&self, text: &[u8], pos: usize) -> Option<(usize, Vec<Capture>)> {
        let mut caps: Vec<Capture> = vec![(-1, -1); self.n_groups()];
        caps[0] = (pos as i32, -1);
        let end = try_match(&self.root, text, pos, &mut caps, &[])?;
        caps[0] = (pos as i32, end as i32);
        return Some((end, caps));
    }

    /// Find the leftmost match in `text`, scanning from offset 0.
    fn find_first(&self, text: &[u8]) -> Option<(usize, usize, Vec<Capture>)> {
        return self.find_from(text, 0);
    }

    /// Find the leftmost match at or after `from`.
    // goishlint:ignore GOISH023 — the body ends in an unconditional
    // loop whose every exit is an explicit `return`.
    fn find_from(&self, text: &[u8], from: usize) -> Option<(usize, usize, Vec<Capture>)> {
        let mut start = from;
        if start > text.len() {
            return None;
        }
        loop {
            if let Some((end, caps)) = self.match_at(text, start) {
                return Some((start, end, caps));
            }
            if start >= text.len() {
                return None;
            }
            start += 1;
        }
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

    /// Go: `func (re *Regexp) ReplaceAllString(src, repl string) string`
    /// (regexp.go:822). Replacement is treated as literal text — `$1`
    /// group expansion isn't supported in the v1 subset (extend when a
    // go: sdk 1.25.5 regexp/regexp.go:337-339 Regexp.NumSubexp
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
