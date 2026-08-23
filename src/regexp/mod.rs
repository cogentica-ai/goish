// regexp — Go's `regexp` package, RE2-style subset (backtracking matcher).
//
// Verified against Go 1.25 `src/regexp/regexp.go` for API shapes and
// `src/regexp/syntax/parse.go` for parser semantics.
//
// Goish v1 ships a single backtracking matcher that covers the forms
// real ports use today:
//
//   - Literals, `\X` escape (any meta char).
//   - `.` (any byte, NOT newline-special — full Go has /s flag for that).
//   - `^` and `$` anchors (text-start / text-end; multiline /m not yet).
//   - Char classes `[...]`, `[^...]`, ranges `a-z`, escaped `\X` inside.
//   - Predefined classes `\d` `\D` `\w` `\W` `\s` `\S`.
//   - Quantifiers `*` `+` `?` `{n}` `{n,}` `{n,m}` (greedy only).
//   - Capturing groups `(...)` and non-capturing `(?:...)`.
//   - Alternation `|`.
//   - The `i` flag: `(?i)`, `(?-i)`, `(?i:...)`, with Go's scoping (the
//     flag runs to the end of the enclosing group). ASCII fold only.
//
// NOT supported (fail loudly at Compile time):
//   - Lookahead/lookbehind `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`.
//   - Named groups `(?P<name>...)`.
//   - Backreferences `\1`.
//   - Flags `(?s)`/`(?m)`/`(?U)`.
//   - Lazy quantifiers `*?`, `+?`, `??`.
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

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int};

// ─── QuoteMeta ─────────────────────────────────────────────────────────

#[inline]
fn is_meta(b: byte) -> bool {
    matches!(
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
    )
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
    string::__from_vec(buf)
}

// ─── AST ───────────────────────────────────────────────────────────────

/// Atom in the regex AST. Atoms are the things a quantifier can apply to.
#[derive(Clone)]
enum Node {
    /// Matches one literal byte.
    Literal(byte),
    /// `.` — matches any single byte (Goish v1 doesn't special-case `\n`).
    AnyByte,
    /// `[...]` or shorthand class. `negate` flips membership.
    Class {
        negate: bool,
        ranges: Vec<(byte, byte)>,
    },
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
    /// `node{min,max}` greedy. `max == usize::MAX` for unbounded.
    Repeat {
        node: Box<Node>,
        min: usize,
        max: usize,
    },
    /// `^` — text start (Goish v1: matches only at offset 0).
    AnchorStart,
    /// `$` — text end (matches only at end-of-input).
    AnchorEnd,
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
    /// `i` flag state. Go's `(?i)` sets it for the remainder of the
    /// ENCLOSING GROUP (parse.go `parsePerlFlags`), so it is parser
    /// state saved and restored around every group body, not a
    /// whole-pattern switch.
    fold: bool,
}

impl<'a> Parser<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            pos: 0,
            next_cap: 1,
            fold: false,
        }
    }

    fn peek(&self) -> Option<byte> {
        self.src.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<byte> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
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
        if branches.is_empty() {
            Ok(first)
        } else {
            Ok(Node::Alt(branches))
        }
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
        if items.len() == 1 {
            Ok(items.pop().unwrap())
        } else {
            Ok(Node::Concat(items))
        }
    }

    /// After parsing one atom, optionally consume a quantifier and
    /// return the (possibly wrapped) node.
    fn parse_quant_opt(&mut self, atom: Node) -> Result<Node, &'static str> {
        // A `(?flags)` setter parses to the empty node. Go rejects a
        // quantifier on it — "missing argument to repetition operator"
        // (parse.go) — and binding one here would build a Repeat around
        // a zero-width node.
        if matches!(&atom, Node::Concat(items) if items.is_empty())
            && matches!(self.peek(), Some(b'*' | b'+' | b'?' | b'{'))
        {
            return Err("missing argument to repetition operator");
        }
        match self.peek() {
            Some(b'*') => {
                self.bump();
                Ok(Node::Repeat {
                    node: Box::new(atom),
                    min: 0,
                    max: usize::MAX,
                })
            }
            Some(b'+') => {
                self.bump();
                Ok(Node::Repeat {
                    node: Box::new(atom),
                    min: 1,
                    max: usize::MAX,
                })
            }
            Some(b'?') => {
                self.bump();
                Ok(Node::Repeat {
                    node: Box::new(atom),
                    min: 0,
                    max: 1,
                })
            }
            Some(b'{') => {
                self.bump();
                let (min, max) = self.parse_brace_count()?;
                Ok(Node::Repeat {
                    node: Box::new(atom),
                    min,
                    max,
                })
            }
            _ => Ok(atom),
        }
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
        Ok((n, m))
    }

    /// Parse a single atom (literal, escape, class, group, anchor).
    fn parse_atom(&mut self) -> Result<Node, &'static str> {
        let b = self.peek().ok_or("unexpected end of pattern")?;
        match b {
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
                    let saved = self.fold;
                    let inner = self.parse_alt()?;
                    if self.peek() != Some(b')') {
                        return Err("unmatched '('");
                    }
                    self.bump();
                    self.fold = saved;
                    return Ok(Node::NonCap(Box::new(inner)));
                }
                let idx = self.next_cap;
                self.next_cap += 1;
                let saved = self.fold;
                let inner = self.parse_alt()?;
                if self.peek() != Some(b')') {
                    return Err("unmatched '('");
                }
                self.bump();
                self.fold = saved;
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
                Ok(Node::AnyByte)
            }
            b'^' => {
                self.bump();
                Ok(Node::AnchorStart)
            }
            b'$' => {
                self.bump();
                Ok(Node::AnchorEnd)
            }
            b'\\' => {
                self.bump();
                let nb = self.bump().ok_or("trailing backslash")?;
                // NOT COVERED by the differential, and uncoverable there:
                // the fold can only fire for an escaped ASCII LETTER, and
                // Go rejects every letter escape that has a case
                // (`\q` → "invalid escape sequence"), so no Go-valid
                // pattern reaches it. goish accepts unknown escapes as
                // literals, so the call is what keeps `(?i)\q` consistent
                // with `(?i)q` inside goish.
                Ok(self.fold_node(escape_to_node(nb)))
            }
            b')' | b'|' | b'*' | b'+' | b'?' | b'{' | b'}' => Err("unexpected metacharacter"),
            _ => {
                self.bump();
                Ok(self.fold_node(Node::Literal(b)))
            }
        }
    }

    /// Parse the flag list of `(?flags)` or `(?flags:re)`. The leading
    /// `(?` is consumed and the next byte is known not to be `:`.
    ///
    /// Go: regexp/syntax/parse.go `parsePerlFlags`. Goish v1 implements
    /// the `i` flag only; `s`, `m` and `U` still fail at Compile time,
    /// as does any other `(?...)` construct (lookaround, named groups).
    fn parse_perl_flags(&mut self) -> Result<Node, &'static str> {
        let saved = self.fold;
        let mut fold = self.fold;
        let mut neg = false;
        let mut sawFlag = false;
        loop {
            match self.peek() {
                Some(b'i') => {
                    self.bump();
                    fold = !neg;
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
        match self.bump() {
            // `(?flags)` — applies to the rest of the enclosing group.
            // Matches the empty string, which an empty Concat already is.
            Some(b')') => {
                self.fold = fold;
                Ok(Node::Concat(Vec::new()))
            }
            // `(?flags:re)` — applies to `re` only.
            Some(b':') => {
                self.fold = fold;
                let inner = self.parse_alt()?;
                if self.peek() != Some(b')') {
                    return Err("unmatched '('");
                }
                self.bump();
                self.fold = saved;
                Ok(Node::NonCap(Box::new(inner)))
            }
            _ => Err("unmatched '('"),
        }
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
        match n {
            Node::Literal(b) if b.is_ascii_alphabetic() => Node::Class {
                negate: false,
                ranges: vec![
                    (b.to_ascii_lowercase(), b.to_ascii_lowercase()),
                    (b.to_ascii_uppercase(), b.to_ascii_uppercase()),
                ],
            },
            other => other,
        }
    }

    /// Parse a `[...]` class body. Opening `[` already consumed.
    fn parse_class(&mut self) -> Result<Node, &'static str> {
        let mut negate = false;
        if self.peek() == Some(b'^') {
            self.bump();
            negate = true;
        }
        let mut ranges: Vec<(byte, byte)> = Vec::new();
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
                ClassAtom::Byte(lo) => {
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
                            ClassAtom::Byte(b) => b,
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
            let mut folded: Vec<(byte, byte)> = Vec::new();
            for &(lo, hi) in &ranges {
                if let Some(r) = fold_range(lo, hi, b'a', b'z') {
                    folded.push(r);
                }
                if let Some(r) = fold_range(lo, hi, b'A', b'Z') {
                    folded.push(r);
                }
            }
            ranges.extend(folded);
        }
        Ok(Node::Class { negate, ranges })
    }

    /// Parse one atom inside `[...]`. Returns a `ClassAtom`:
    /// - `Byte(b)` for a single byte (literal or simple escape)
    /// - `Expanded(ranges)` for shorthand classes like `\w`, `\d`, `\s`
    fn parse_class_atom(&mut self) -> Result<ClassAtom, &'static str> {
        let b = self.bump().ok_or("unterminated character class")?;
        if b == b'\\' {
            let nb = self.bump().ok_or("trailing backslash in class")?;
            match nb {
                b'd' => return Ok(ClassAtom::Expanded(vec![(b'0', b'9')])),
                b'D' => {
                    return Ok(ClassAtom::Expanded(vec![
                        (0u8, b'0' - 1),
                        (b'9' + 1, 255u8),
                    ]))
                }
                b'w' => return Ok(ClassAtom::Expanded(word_ranges())),
                b'W' => {
                    // complement of word_ranges: [^0-9A-Z_a-z]
                    return Ok(ClassAtom::Expanded(vec![
                        (0u8, b'0' - 1),
                        (b'9' + 1, b'A' - 1),
                        (b'Z' + 1, b'_' - 1),
                        (b'_' + 1, b'a' - 1),
                        (b'z' + 1, 255u8),
                    ]));
                }
                b's' => return Ok(ClassAtom::Expanded(space_ranges())),
                b'S' => {
                    return Ok(ClassAtom::Expanded(vec![
                        (0u8, b'\t' - 1),
                        (b'\t' + 1, b'\n' - 1),
                        (b'\n' + 1, b'\x0C' - 1),
                        (b'\x0C' + 1, b'\r' - 1),
                        (b'\r' + 1, b' ' - 1),
                        (b' ' + 1, 255u8),
                    ]));
                }
                _ => return Ok(ClassAtom::Byte(escape_byte(nb))),
            }
        }
        Ok(ClassAtom::Byte(b))
    }
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
    want
}

/// The case-flipped image of `[lo,hi] ∩ [clipLo,clipHi]`, or None when
/// the intersection is empty. `clip` is one of the two ASCII letter
/// runs; flipping the intersection gives the other run's counterpart,
/// which is what the `i` flag adds to a class.
fn fold_range(lo: byte, hi: byte, clipLo: byte, clipHi: byte) -> Option<(byte, byte)> {
    let lo = if lo > clipLo { lo } else { clipLo };
    let hi = if hi < clipHi { hi } else { clipHi };
    if lo > hi {
        return None;
    }
    // 'a' - 'A' == 32; flipping bit 5 maps each run onto the other.
    Some((lo ^ 0x20, hi ^ 0x20))
}

/// Atom returned from `parse_class_atom` — either a single byte or
/// multiple expanded ranges (from `\w`, `\d`, `\s`).
enum ClassAtom {
    Byte(byte),
    Expanded(Vec<(byte, byte)>),
}

/// Translate a `\X` escape OUTSIDE a class to a Node. Predefined classes
/// like `\d` expand to a class node; literal escapes return a Literal.
fn escape_to_node(b: byte) -> Node {
    match b {
        b'd' => Node::Class {
            negate: false,
            ranges: vec![(b'0', b'9')],
        },
        b'D' => Node::Class {
            negate: true,
            ranges: vec![(b'0', b'9')],
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
        b'n' => Node::Literal(b'\n'),
        b'r' => Node::Literal(b'\r'),
        b't' => Node::Literal(b'\t'),
        _ => Node::Literal(b),
    }
}

/// Translate a `\X` escape INSIDE a class to a literal byte. We don't
/// expand `\d`/`\w`/`\s` inside classes (semver patterns don't use it).
fn escape_byte(b: byte) -> byte {
    match b {
        b'n' => b'\n',
        b'r' => b'\r',
        b't' => b'\t',
        _ => b,
    }
}

#[inline]
fn word_ranges() -> Vec<(byte, byte)> {
    vec![(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')]
}

#[inline]
fn space_ranges() -> Vec<(byte, byte)> {
    vec![
        (b'\t', b'\t'),
        (b'\n', b'\n'),
        (b'\x0C', b'\x0C'),
        (b'\r', b'\r'),
        (b' ', b' '),
    ]
}

// ─── Regexp (compiled) ─────────────────────────────────────────────────

/// Compiled regular expression. Mirrors Go's `*Regexp` opaque pointer.
#[derive(Clone)]
pub struct Regexp {
    root: Arc<Node>,
    n_caps: usize,
    /// Original source pattern. Returned by `String()` (Go's
    /// `regexp.Regexp.String() string`, regexp.go:142).
    pattern: string,
}

impl Regexp {
    fn n_groups(&self) -> usize {
        self.n_caps + 1
    }

    /// `Regexp.String() string` — returns the source text of the
    /// pattern. Mirrors Go's `regexp.Regexp.String()`.
    #[allow(non_snake_case)]
    pub fn String(&self) -> string {
        self.pattern.clone()
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
                pattern: expr_s.clone(),
            },
            compile_err(&expr_s, "invalid UTF-8"),
        );
    }
    let mut p = Parser::new(expr_s.as_bytes());
    match p.parse_alt() {
        Ok(node) => {
            if p.pos != p.src.len() {
                return (
                    Regexp {
                        root: Arc::new(Node::Concat(Vec::new())),
                        n_caps: 0,
                        pattern: expr_s.clone(),
                    },
                    compile_err(&expr_s, "trailing junk in pattern"),
                );
            }
            (
                Regexp {
                    root: Arc::new(node),
                    n_caps: p.next_cap - 1,
                    pattern: expr_s,
                },
                crate::nilval::nil.into(),
            )
        }
        Err(why) => (
            Regexp {
                root: Arc::new(Node::Concat(Vec::new())),
                n_caps: 0,
                pattern: expr_s.clone(),
            },
            compile_err(&expr_s, why),
        ),
    }
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
    (matched, crate::nilval::nil.into())
}

/// `regexp.MatchString(pattern, s) (matched bool, err error)` — same
/// shape as `Match` but for `string` input.
pub fn MatchString<S: Into<string>, S2: Into<string>>(pattern: S, s: S2) -> (bool, error) {
    let s = s.into();
    Match(pattern, s.as_bytes())
}

/// `regexp.MustCompile(expr)` — panics on parse error.
pub fn MustCompile<S: Into<string>>(expr: S) -> Regexp {
    let expr_s = expr.into();
    let (re, err) = Compile(expr_s.clone());
    if err != crate::nilval::nil {
        panic!("regexp: Compile failed");
    }
    re
}

fn compile_err(expr: &string, why: &'static str) -> error {
    let mut b = crate::strings::Builder::new();
    let _ = b.WriteString(string::from_static("regexp: "));
    let _ = b.WriteString(string::from_static(why));
    let _ = b.WriteString(string::from_static(": `"));
    let _ = b.WriteString(expr.clone());
    let _ = b.WriteString(string::from_static("`"));
    errors::New(b.String())
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
    try_match(&cont[0], text, pos, caps, &cont[1..])
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
    match node {
        Node::Literal(b) => {
            if pos < text.len() && text[pos] == *b {
                match_cont(text, pos + 1, caps, cont)
            } else {
                None
            }
        }
        Node::AnyByte => {
            if pos < text.len() {
                match_cont(text, pos + 1, caps, cont)
            } else {
                None
            }
        }
        Node::Class { negate, ranges } => {
            if pos >= text.len() {
                return None;
            }
            let c = text[pos];
            let mut hit = false;
            for &(lo, hi) in ranges {
                if c >= lo && c <= hi {
                    hit = true;
                    break;
                }
            }
            if hit ^ *negate {
                match_cont(text, pos + 1, caps, cont)
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
        Node::Repeat { node, min, max } => {
            match_repeat(node, *min, *max, text, pos, caps, cont, None)
        }
        Node::RepeatTail {
            node,
            min,
            max,
            last_pos,
        } => match_repeat(node, *min, *max, text, pos, caps, cont, Some(*last_pos)),
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
    }
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
    text: &[u8],
    pos: usize,
    caps: &mut Vec<Capture>,
    cont: &[Node],
    prev_pos: Option<usize>,
) -> Option<usize> {
    if let Some(p) = prev_pos {
        if pos == p {
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

    let mut rep_cont: Vec<Node> = Vec::with_capacity(1 + cont.len());
    rep_cont.push(Node::RepeatTail {
        node: Box::new((*node).clone()),
        min: next_min,
        max: next_max,
        last_pos: pos,
    });
    rep_cont.extend_from_slice(cont);

    let saved = caps.clone();
    if let Some(end) = try_match(node, text, pos, caps, &rep_cont) {
        return Some(end);
    }
    *caps = saved;

    if min == 0 {
        return match_cont(text, pos, caps, cont);
    }
    None
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
        Some((end, caps))
    }

    /// Find the leftmost match in `text`, scanning from offset 0.
    fn find_first(&self, text: &[u8]) -> Option<(usize, usize, Vec<Capture>)> {
        self.find_from(text, 0)
    }

    /// Find the leftmost match at or after `from`.
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
        slice::__from_vec(row)
    }

    /// Go: `func (re *Regexp) MatchString(s string) bool` (regexp.go:447).
    /// Reports whether the pattern matches anywhere in `s`.
    pub fn MatchString<S: Into<string>>(&self, s: S) -> bool {
        let s = s.into();
        self.find_first(s.as_bytes()).is_some()
    }

    /// Go: `func (re *Regexp) FindStringSubmatch(s string) []string`
    /// (regexp.go:1020). Returns whole match + capture-group strings,
    /// or an empty (nil-equivalent) slice if no match.
    pub fn FindStringSubmatch<S: Into<string>>(&self, s: S) -> slice<string> {
        let s = s.into();
        let text = s.as_bytes();
        match self.find_first(text) {
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
        }
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
        if out.is_empty() {
            slice::new()
        } else {
            slice::__from_vec(out)
        }
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
        if out.is_empty() {
            slice::new()
        } else {
            slice::__from_vec(out)
        }
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

        if out.is_empty() {
            slice::new()
        } else {
            slice::__from_vec(out)
        }
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
        if out.is_empty() {
            slice::new()
        } else {
            slice::__from_vec(out)
        }
    }

    /// Go: `func (re *Regexp) ReplaceAllString(src, repl string) string`
    /// (regexp.go:822). Replacement is treated as literal text — `$1`
    /// group expansion isn't supported in the v1 subset (extend when a
    /// port surfaces the need).
    pub fn ReplaceAllString<S: Into<string>, R: Into<string>>(&self, src: S, repl: R) -> string {
        let src = src.into();
        let repl = repl.into();
        let text = src.as_bytes();
        let repl_bytes = repl.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(text.len());
        let mut i = 0usize;
        while i <= text.len() {
            if let Some((end, _)) = self.match_at(text, i) {
                out.extend_from_slice(repl_bytes);
                if end > i {
                    i = end;
                } else {
                    if i < text.len() {
                        out.push(text[i]);
                    }
                    i += 1;
                }
            } else if i < text.len() {
                out.push(text[i]);
                i += 1;
            } else {
                break;
            }
        }
        string::__from_vec(out)
    }

    /// `re.ReplaceAllStringFunc(src, repl)` (regexp.go:988) — returns a
    /// copy of src in which all matches have been replaced by the
    /// return value of `repl` applied to the matched string. No
    /// Expand-style $-substitution is performed on the output.
    pub fn ReplaceAllStringFunc<S: Into<string>, F: Fn(string) -> string>(
        &self,
        src: S,
        repl: F,
    ) -> string {
        let src = src.into();
        let text = src.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(text.len());
        let mut i = 0usize;
        while i <= text.len() {
            if let Some((end, _)) = self.match_at(text, i) {
                let replaced = repl(string::from_bytes(&text[i..end]));
                out.extend_from_slice(replaced.as_bytes());
                if end > i {
                    i = end;
                } else {
                    if i < text.len() {
                        out.push(text[i]);
                    }
                    i += 1;
                }
            } else if i < text.len() {
                out.push(text[i]);
                i += 1;
            } else {
                break;
            }
        }
        string::__from_vec(out)
    }
}
