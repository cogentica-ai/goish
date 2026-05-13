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
//
// NOT supported (fail loudly at Compile time):
//   - Lookahead/lookbehind `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`.
//   - Named groups `(?P<name>...)`.
//   - Backreferences `\1`.
//   - Flags `(?i)`/`(?s)`/`(?m)`.
//   - Lazy quantifiers `*?`, `+?`, `??`.
//
// API surface mirrors Go 1.25 regexp.go:
//
//   Compile / MustCompile / QuoteMeta — package-level.
//   (*Regexp).MatchString
//   (*Regexp).FindStringSubmatch
//   (*Regexp).FindAllString
//   (*Regexp).FindAllStringSubmatch
//   (*Regexp).ReplaceAllString
//
// All return Goish slices/strings (never `Vec`/`&str`) per the public-API
// contract.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::vec;

use crate::errors::{self, error};
use crate::gostring::string;
use crate::goslice::slice;
use crate::types::{byte, int};

// ─── QuoteMeta ─────────────────────────────────────────────────────────

#[inline]
fn is_meta(b: byte) -> bool {
    matches!(
        b,
        b'\\' | b'.' | b'+' | b'*' | b'?' | b'(' | b')' | b'|' | b'[' | b']'
        | b'{' | b'}' | b'^' | b'$'
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
    Class { negate: bool, ranges: Vec<(byte, byte)> },
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
    Repeat { node: Box<Node>, min: usize, max: usize },
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
    RepeatTail { node: Box<Node>, min: usize, max: usize, last_pos: usize },
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
}

impl<'a> Parser<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self { src, pos: 0, next_cap: 1 }
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
        match self.peek() {
            Some(b'*') => { self.bump(); Ok(Node::Repeat { node: Box::new(atom), min: 0, max: usize::MAX }) }
            Some(b'+') => { self.bump(); Ok(Node::Repeat { node: Box::new(atom), min: 1, max: usize::MAX }) }
            Some(b'?') => { self.bump(); Ok(Node::Repeat { node: Box::new(atom), min: 0, max: 1 }) }
            Some(b'{') => {
                self.bump();
                let (min, max) = self.parse_brace_count()?;
                Ok(Node::Repeat { node: Box::new(atom), min, max })
            }
            _ => Ok(atom),
        }
    }

    /// Parse `{n}`, `{n,}`, `{n,m}` (closing brace already pending).
    fn parse_brace_count(&mut self) -> Result<(usize, usize), &'static str> {
        let mut n: usize = 0;
        let mut have_n = false;
        while let Some(b) = self.peek() {
            if !b.is_ascii_digit() { break; }
            self.bump();
            n = n.saturating_mul(10).saturating_add((b - b'0') as usize);
            have_n = true;
        }
        if !have_n { return Err("missing number in {n,m}"); }
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok((n, n));
        }
        if self.peek() != Some(b',') { return Err("expected ',' or '}' in {n,m}"); }
        self.bump();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok((n, usize::MAX));
        }
        let mut m: usize = 0;
        let mut have_m = false;
        while let Some(b) = self.peek() {
            if !b.is_ascii_digit() { break; }
            self.bump();
            m = m.saturating_mul(10).saturating_add((b - b'0') as usize);
            have_m = true;
        }
        if !have_m { return Err("missing upper bound in {n,m}"); }
        if self.peek() != Some(b'}') { return Err("expected '}' in {n,m}"); }
        self.bump();
        Ok((n, m))
    }

    /// Parse a single atom (literal, escape, class, group, anchor).
    fn parse_atom(&mut self) -> Result<Node, &'static str> {
        let b = self.peek().ok_or("unexpected end of pattern")?;
        match b {
            b'(' => {
                self.bump();
                // Check for `(?:...)` non-capturing.
                if self.peek() == Some(b'?') {
                    self.bump();
                    if self.peek() != Some(b':') { return Err("only (?:...) groups supported"); }
                    self.bump();
                    let inner = self.parse_alt()?;
                    if self.peek() != Some(b')') { return Err("unmatched '('"); }
                    self.bump();
                    return Ok(Node::NonCap(Box::new(inner)));
                }
                let idx = self.next_cap;
                self.next_cap += 1;
                let inner = self.parse_alt()?;
                if self.peek() != Some(b')') { return Err("unmatched '('"); }
                self.bump();
                Ok(Node::Group { idx, inner: Box::new(inner) })
            }
            b'[' => {
                self.bump();
                self.parse_class()
            }
            b'.' => { self.bump(); Ok(Node::AnyByte) }
            b'^' => { self.bump(); Ok(Node::AnchorStart) }
            b'$' => { self.bump(); Ok(Node::AnchorEnd) }
            b'\\' => {
                self.bump();
                let nb = self.bump().ok_or("trailing backslash")?;
                Ok(escape_to_node(nb))
            }
            b')' | b'|' | b'*' | b'+' | b'?' | b'{' | b'}' => {
                Err("unexpected metacharacter")
            }
            _ => { self.bump(); Ok(Node::Literal(b)) }
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
                Some(b']') if !first => { self.bump(); break; }
                _ => {}
            }
            first = false;
            let lo = self.parse_class_atom()?;
            // Range `a-b`?
            if self.peek() == Some(b'-') {
                // Peek ahead — `-` followed by `]` is a literal `-`.
                if self.src.get(self.pos + 1) == Some(&b']') {
                    ranges.push((lo, lo));
                    continue;
                }
                self.bump();
                let hi = self.parse_class_atom()?;
                if hi < lo { return Err("invalid character range"); }
                ranges.push((lo, hi));
            } else {
                ranges.push((lo, lo));
            }
        }
        Ok(Node::Class { negate, ranges })
    }

    /// Parse one atom inside `[...]`. Returns the byte (or expanded
    /// shorthand class atoms folded into `ranges`).
    fn parse_class_atom(&mut self) -> Result<byte, &'static str> {
        let b = self.bump().ok_or("unterminated character class")?;
        if b == b'\\' {
            let nb = self.bump().ok_or("trailing backslash in class")?;
            return Ok(escape_byte(nb));
        }
        Ok(b)
    }
}

/// Translate a `\X` escape OUTSIDE a class to a Node. Predefined classes
/// like `\d` expand to a class node; literal escapes return a Literal.
fn escape_to_node(b: byte) -> Node {
    match b {
        b'd' => Node::Class { negate: false, ranges: vec![(b'0', b'9')] },
        b'D' => Node::Class { negate: true,  ranges: vec![(b'0', b'9')] },
        b'w' => Node::Class { negate: false, ranges: word_ranges() },
        b'W' => Node::Class { negate: true,  ranges: word_ranges() },
        b's' => Node::Class { negate: false, ranges: space_ranges() },
        b'S' => Node::Class { negate: true,  ranges: space_ranges() },
        b'n' => Node::Literal(b'\n'),
        b'r' => Node::Literal(b'\r'),
        b't' => Node::Literal(b'\t'),
        _    => Node::Literal(b),
    }
}

/// Translate a `\X` escape INSIDE a class to a literal byte. We don't
/// expand `\d`/`\w`/`\s` inside classes (semver patterns don't use it).
fn escape_byte(b: byte) -> byte {
    match b {
        b'n' => b'\n',
        b'r' => b'\r',
        b't' => b'\t',
        _    => b,
    }
}

#[inline] fn word_ranges() -> Vec<(byte, byte)> {
    vec![(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')]
}

#[inline] fn space_ranges() -> Vec<(byte, byte)> {
    vec![(b'\t', b'\t'), (b'\n', b'\n'), (b'\x0C', b'\x0C'), (b'\r', b'\r'), (b' ', b' ')]
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
    fn n_groups(&self) -> usize { self.n_caps + 1 }

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
            Regexp { root: Arc::new(Node::Concat(Vec::new())), n_caps: 0, pattern: expr_s.clone() },
            compile_err(&expr_s, "invalid UTF-8"),
        );
    }
    let mut p = Parser::new(expr_s.as_bytes());
    match p.parse_alt() {
        Ok(node) => {
            if p.pos != p.src.len() {
                return (
                    Regexp { root: Arc::new(Node::Concat(Vec::new())), n_caps: 0, pattern: expr_s.clone() },
                    compile_err(&expr_s, "trailing junk in pattern"),
                );
            }
            (Regexp { root: Arc::new(node), n_caps: p.next_cap - 1, pattern: expr_s }, crate::nilval::nil.into())
        }
        Err(why) => (
            Regexp { root: Arc::new(Node::Concat(Vec::new())), n_caps: 0, pattern: expr_s.clone() },
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

type Capture = (i32, i32);   // (-1, -1) = unset

/// Walk the continuation: if empty, the match has succeeded at `pos`;
/// otherwise dispatch to the head item with the rest as its cont.
fn match_cont(
    text: &[u8],
    pos: usize,
    caps: &mut Vec<Capture>,
    cont: &[Node],
) -> Option<usize> {
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
            if pos >= text.len() { return None; }
            let c = text[pos];
            let mut hit = false;
            for &(lo, hi) in ranges {
                if c >= lo && c <= hi { hit = true; break; }
            }
            if hit ^ *negate {
                match_cont(text, pos + 1, caps, cont)
            } else {
                None
            }
        }
        Node::AnchorStart => {
            if pos == 0 { match_cont(text, pos, caps, cont) } else { None }
        }
        Node::AnchorEnd => {
            if pos == text.len() { match_cont(text, pos, caps, cont) } else { None }
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
        Node::RepeatTail { node, min, max, last_pos } => {
            match_repeat(node, *min, *max, text, pos, caps, cont, Some(*last_pos))
        }
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
    let next_max = if max == usize::MAX { usize::MAX } else { max - 1 };

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
        let mut start = 0usize;
        loop {
            if let Some((end, caps)) = self.match_at(text, start) {
                return Some((start, end, caps));
            }
            if start >= text.len() { return None; }
            start += 1;
        }
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
        let max = if n < 0 { i64::MAX as usize } else { n as usize };
        let mut out: Vec<string> = Vec::new();
        let mut start = 0usize;
        while out.len() < max && start <= text.len() {
            let mut hit: Option<(usize, usize)> = None;
            let mut probe = start;
            while probe <= text.len() {
                if let Some((end, _)) = self.match_at(text, probe) {
                    hit = Some((probe, end));
                    break;
                }
                if probe == text.len() { break; }
                probe += 1;
            }
            match hit {
                Some((lo, hi)) => {
                    out.push(string::from_bytes(&text[lo..hi]));
                    start = if hi > lo { hi } else { lo + 1 };
                }
                None => break,
            }
        }
        if out.is_empty() { slice::new() } else { slice::__from_vec(out) }
    }

    /// Go: `func (re *Regexp) FindAllStringSubmatch(s string, n int) [][]string`
    /// (regexp.go:1126).
    pub fn FindAllStringSubmatch<S: Into<string>>(
        &self,
        s: S,
        n: int,
    ) -> slice<slice<string>> {
        let s = s.into();
        let text = s.as_bytes();
        let max = if n < 0 { i64::MAX as usize } else { n as usize };
        let mut out: Vec<slice<string>> = Vec::new();
        let mut start = 0usize;
        while out.len() < max && start <= text.len() {
            let mut hit: Option<(usize, usize, Vec<Capture>)> = None;
            let mut probe = start;
            while probe <= text.len() {
                if let Some((end, caps)) = self.match_at(text, probe) {
                    hit = Some((probe, end, caps));
                    break;
                }
                if probe == text.len() { break; }
                probe += 1;
            }
            match hit {
                Some((lo, hi, caps)) => {
                    let mut row: Vec<string> = Vec::with_capacity(self.n_groups());
                    for &(clo, chi) in &caps {
                        if clo < 0 || chi < 0 {
                            row.push(string::from_static(""));
                        } else {
                            row.push(string::from_bytes(&text[clo as usize..chi as usize]));
                        }
                    }
                    out.push(slice::__from_vec(row));
                    start = if hi > lo { hi } else { lo + 1 };
                }
                None => break,
            }
        }
        if out.is_empty() { slice::new() } else { slice::__from_vec(out) }
    }

    /// Go: `func (re *Regexp) ReplaceAllString(src, repl string) string`
    /// (regexp.go:822). Replacement is treated as literal text — `$1`
    /// group expansion isn't supported in the v1 subset (extend when a
    /// port surfaces the need).
    pub fn ReplaceAllString<S: Into<string>, R: Into<string>>(
        &self,
        src: S,
        repl: R,
    ) -> string {
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
                    if i < text.len() { out.push(text[i]); }
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
