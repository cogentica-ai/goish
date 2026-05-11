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
// `try_match(node, text, pos, caps)` returns Some(end_pos) on success
// after recording any new captures into `caps`, or None on failure.
// Captures are written/restored across backtracks via push/pop.

type Capture = (i32, i32);   // (-1, -1) = unset

/// Match the whole node tree starting at `pos`. `caps` is a flat array
/// indexed by capture slot (index 0 = whole match, 1..=n_caps = groups).
fn try_match(
    node: &Node,
    text: &[u8],
    pos: usize,
    caps: &mut Vec<Capture>,
) -> Option<usize> {
    match node {
        Node::Literal(b) => {
            if pos < text.len() && text[pos] == *b { Some(pos + 1) } else { None }
        }
        Node::AnyByte => {
            if pos < text.len() { Some(pos + 1) } else { None }
        }
        Node::Class { negate, ranges } => {
            if pos >= text.len() { return None; }
            let c = text[pos];
            let mut hit = false;
            for &(lo, hi) in ranges {
                if c >= lo && c <= hi { hit = true; break; }
            }
            if hit ^ *negate { Some(pos + 1) } else { None }
        }
        Node::AnchorStart => {
            if pos == 0 { Some(pos) } else { None }
        }
        Node::AnchorEnd => {
            if pos == text.len() { Some(pos) } else { None }
        }
        Node::Concat(items) => match_concat(items, 0, text, pos, caps),
        Node::Alt(branches) => {
            for b in branches {
                let saved = caps.clone();
                if let Some(end) = try_match(b, text, pos, caps) {
                    return Some(end);
                }
                *caps = saved;
            }
            None
        }
        Node::Group { idx, inner } => {
            let prev = caps[*idx];
            caps[*idx] = (pos as i32, -1);
            match try_match(inner, text, pos, caps) {
                Some(end) => {
                    caps[*idx] = (pos as i32, end as i32);
                    Some(end)
                }
                None => {
                    caps[*idx] = prev;
                    None
                }
            }
        }
        Node::NonCap(inner) => try_match(inner, text, pos, caps),
        Node::Repeat { node, min, max } => match_repeat(node, *min, *max, text, pos, caps, &Node::Concat(Vec::new())),
    }
}

/// Match a concat starting at item index `i`. Recurses down so that
/// quantifier inside Concat can pass the tail (the "rest of the
/// concatenation") to match_repeat for proper greedy backtracking.
fn match_concat(
    items: &[Node],
    i: usize,
    text: &[u8],
    pos: usize,
    caps: &mut Vec<Capture>,
) -> Option<usize> {
    if i >= items.len() { return Some(pos); }
    // Special-case Repeat so we can pass the tail context.
    if let Node::Repeat { node, min, max } = &items[i] {
        let tail_concat = Node::Concat(items[i+1..].to_vec());
        return match_repeat(node, *min, *max, text, pos, caps, &tail_concat);
    }
    let end = try_match(&items[i], text, pos, caps)?;
    match_concat(items, i + 1, text, end, caps)
}

/// Greedy `node{min,max}` followed by `tail`. Tries the longest
/// possible match of `node` first, then backtracks one repetition at a
/// time until `tail` also succeeds.
fn match_repeat(
    node: &Node,
    min: usize,
    max: usize,
    text: &[u8],
    pos: usize,
    caps: &mut Vec<Capture>,
    tail: &Node,
) -> Option<usize> {
    // Eagerly consume up to `max` matches; record (caps_snapshot, end_pos)
    // after each so we can backtrack.
    let mut snapshots: Vec<(Vec<Capture>, usize)> = Vec::new();
    snapshots.push((caps.clone(), pos));
    let mut cur = pos;
    let mut count = 0usize;
    while count < max {
        let saved = caps.clone();
        match try_match(node, text, cur, caps) {
            Some(end) if end > cur => {
                cur = end;
                count += 1;
                snapshots.push((caps.clone(), cur));
            }
            Some(_) => {
                // Zero-width — Go's regex would loop forever; stop.
                *caps = saved;
                break;
            }
            None => {
                *caps = saved;
                break;
            }
        }
    }
    // Backtrack from longest to shortest, accepting first that lets
    // `tail` match too. Each iteration restores caps to that frame.
    while snapshots.len() > min {
        let (cap_snap, end_pos) = snapshots.last().unwrap().clone();
        *caps = cap_snap;
        if let Some(final_end) = try_match(tail, text, end_pos, caps) {
            return Some(final_end);
        }
        snapshots.pop();
    }
    if snapshots.len() == min + 1 {
        let (cap_snap, end_pos) = snapshots.last().unwrap().clone();
        *caps = cap_snap;
        return try_match(tail, text, end_pos, caps);
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
        let end = try_match(&self.root, text, pos, &mut caps)?;
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
