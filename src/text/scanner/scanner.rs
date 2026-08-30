// go: file text/scanner/scanner.go decls: Position.IsValid, Position.String, TokenString, Scanner.Init, Scanner.next, Scanner.Next, Scanner.Peek, Scanner.error, Scanner.errorf, Scanner.isIdentRune, Scanner.scanIdentifier, lower, isDecimal, isHex, Scanner.digits, Scanner.scanNumber, litname, invalidSep, digitVal, Scanner.scanDigits, Scanner.scanEscape, Scanner.scanString, Scanner.scanRawString, Scanner.scanChar, Scanner.scanComment, Scanner.Scan, Scanner.Pos, Scanner.TokenText
//
// goishlint:ignore GOISH019 Scanner — Go *embeds* `Position` in
//     `Scanner`, so its four components are promoted and `s.Line`
//     works alongside `s.Position`. goish has no embedding, so the
//     field is named `Position` and the components are reached through
//     it. That is the one field-layout divergence, and it is a
//     language gap, not a redesign.
//
// The `decls:` manifest above lists scanner.go's funcs and methods
// only. GOISH017 matches a manifest entry against Rust `fn` items, so
// naming `Position`, `Scanner`, `tokenString` or the mode and token
// constants there would report them as dropped ports. They are not
// dropped — each carries its own `// go: sdk` anchor below.
//
// text/scanner/scanner.go — a scanner and tokenizer for UTF-8 text.
//
// The scanner reads through a 1024-byte window over an `io.Reader` and
// never materialises the whole source. Three details follow from that
// and are the ones a port can get wrong quietly:
//
//   * `srcBuf` is one byte longer than `bufLen` and that extra byte is
//     always `utf8.RuneSelf`. It is a sentinel: `next` reads
//     `srcBuf[srcPos]` unconditionally and lets the `>= RuneSelf` test
//     catch both "not ASCII" and "past the end" in one branch.
//   * A token can straddle a refill. `tokBuf` holds the head that has
//     already scrolled out of `srcBuf` while `tokPos..tokEnd` holds the
//     tail, and `TokenText` stitches them. `tokPos < 0` means "not
//     collecting", which is how `Next` and `SkipComments` opt out.
//   * `column` counts characters, not bytes, and is reset to 0 by a
//     newline — so `Pos` has to look at `lastLineLen` when `column`
//     is 0 to report a position on the *previous* line.
//
// Deviations from Go, each forced:
//
//   * `Scanner<R>` is generic over its source. Go's `src` field is an
//     `io.Reader` interface, so Go can `Init` one scanner with sources
//     of different types; a goish scanner is fixed to one at
//     construction, as `compress/flate`'s decompressor is.
//   * `Error` and `IsIdentRune` are `Option<fn(...)>` raw function
//     pointers, not closures. §5 rule 3 bans `dyn Fn` in a public
//     struct field, and rule 4 says to use the simplest representation
//     that works until the runtime gap is filled; a raw `fn` cannot
//     capture, which is the known limitation.
//   * Go embeds `Position` in `Scanner`, so `s.Line` and `s.Position`
//     both work. goish has no embedding: the field is `Position` and
//     the components are reached through it.
//   * Go's `Scan` uses `goto redo` to restart after a skipped comment;
//     goish spells the same control flow as a `loop` with `continue`.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::bytes;
use crate::convert::{int as toint, rune as torune, uint as touint};
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int, rune, uint};
use crate::unicode;
use crate::unicode::utf8;

// go: sdk 1.25.5 text/scanner/scanner.go:28-33 Position
/// `scanner.Position` — a source position. Valid if `Line > 0`.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Position {
    // Go: Filename string
    pub Filename: string,
    // Go: Offset int — byte offset, starting at 0
    pub Offset: int,
    // Go: Line int — line number, starting at 1
    pub Line: int,
    // Go: Column int — column number, starting at 1 (characters per line)
    pub Column: int,
}

impl Position {
    // go: sdk 1.25.5 text/scanner/scanner.go:36-36 Position.IsValid
    /// `(pos *Position).IsValid()` — whether the position is valid.
    pub fn IsValid(&self) -> bool {
        return self.Line > 0;
    }

    // go: sdk 1.25.5 text/scanner/scanner.go:38-46 Position.String
    /// `(pos Position).String()` — `filename:line:column`, with
    /// `<input>` standing in for an empty filename.
    pub fn String(&self) -> string {
        // Go: s := pos.Filename; if s == "" { s = "<input>" }
        let mut s = self.Filename.clone();
        if s.Len() == 0 {
            s = string::from("<input>");
        }
        // Go: if pos.IsValid() { s += fmt.Sprintf(":%d:%d", pos.Line, pos.Column) }
        if self.IsValid() {
            s = s + crate::Sprintf!(":%d:%d", self.Line, self.Column);
        }
        return s;
    }
}

// ─── token values (scanner.go:74-86) ─────────────────────────────────
//
// Go writes these as `EOF = -(iota + 1)` and counts down, so that the
// mode bit for a token is `1 << -tok`.

// go: sdk 1.25.5 text/scanner/scanner.go:74-88 EOF
/// `scanner.EOF` — returned at the end of the source.
pub const EOF: rune = -1;
// go: sdk 1.25.5 text/scanner/scanner.go:74-88 Ident
pub const Ident: rune = -2;
// go: sdk 1.25.5 text/scanner/scanner.go:74-88 Int
pub const Int: rune = -3;
// go: sdk 1.25.5 text/scanner/scanner.go:74-88 Float
pub const Float: rune = -4;
// go: sdk 1.25.5 text/scanner/scanner.go:74-88 Char
pub const Char: rune = -5;
// go: sdk 1.25.5 text/scanner/scanner.go:74-88 String
pub const String: rune = -6;
// go: sdk 1.25.5 text/scanner/scanner.go:74-88 RawString
pub const RawString: rune = -7;
// go: sdk 1.25.5 text/scanner/scanner.go:74-88 Comment
pub const Comment: rune = -8;
// go: sdk 1.25.5 text/scanner/scanner.go:74-88 skipComment
/// Internal use only.
const skipComment: rune = -9;

// ─── mode bits (scanner.go:63-71) ────────────────────────────────────

// go: sdk 1.25.5 text/scanner/scanner.go:63-72 ScanIdents
/// `scanner.ScanIdents` — recognise identifiers.
pub const ScanIdents: uint = 1 << -Ident;
// go: sdk 1.25.5 text/scanner/scanner.go:63-72 ScanInts
pub const ScanInts: uint = 1 << -Int;
// go: sdk 1.25.5 text/scanner/scanner.go:63-72 ScanFloats
/// Includes ints and hexadecimal floats.
pub const ScanFloats: uint = 1 << -Float;
// go: sdk 1.25.5 text/scanner/scanner.go:63-72 ScanChars
pub const ScanChars: uint = 1 << -Char;
// go: sdk 1.25.5 text/scanner/scanner.go:63-72 ScanStrings
pub const ScanStrings: uint = 1 << -String;
// go: sdk 1.25.5 text/scanner/scanner.go:63-72 ScanRawStrings
pub const ScanRawStrings: uint = 1 << -RawString;
// go: sdk 1.25.5 text/scanner/scanner.go:63-72 ScanComments
pub const ScanComments: uint = 1 << -Comment;
// go: sdk 1.25.5 text/scanner/scanner.go:63-72 SkipComments
/// If set with [`ScanComments`], comments become white space.
pub const SkipComments: uint = 1 << -skipComment;
// go: sdk 1.25.5 text/scanner/scanner.go:63-72 GoTokens
/// Every Go literal token, with comments skipped.
pub const GoTokens: uint = ScanIdents
    | ScanFloats
    | ScanChars
    | ScanStrings
    | ScanRawStrings
    | ScanComments
    | SkipComments;

// go: sdk 1.25.5 text/scanner/scanner.go:90-99 tokenString
//
// Go uses a `map[rune]string`; goish uses a match, since the table is
// eight fixed entries and a map would need lazy initialisation.
fn tokenString(tok: rune) -> (string, bool) {
    let s = match tok {
        EOF => "EOF",
        Ident => "Ident",
        Int => "Int",
        Float => "Float",
        Char => "Char",
        String => "String",
        RawString => "RawString",
        Comment => "Comment",
        _ => return (string::new(), false),
    };
    return (string::from(s), true);
}

// go: sdk 1.25.5 text/scanner/scanner.go:102-107 TokenString
/// `scanner.TokenString(tok)` — a printable string for a token or
/// Unicode character.
pub fn TokenString(tok: rune) -> string {
    // Go: if s, found := tokenString[tok]; found { return s }
    let (s, found) = tokenString(tok);
    if found {
        return s;
    }
    // Go: return fmt.Sprintf("%q", string(tok))
    return crate::Sprintf!("%q", crate::convert::string(tok));
}

// go: sdk 1.25.5 text/scanner/scanner.go:111-111 GoWhitespace
/// `scanner.GoWhitespace` — the default [`Scanner::Whitespace`]: tab,
/// newline, carriage return and space.
pub const GoWhitespace: u64 = (1u64 << b'\t') | (1u64 << b'\n') | (1u64 << b'\r') | (1u64 << b' ');

// go: sdk 1.25.5 text/scanner/scanner.go:113-113 bufLen
/// At least `utf8.UTFMax`.
const bufLen: usize = 1024;

// go: sdk 1.25.5 text/scanner/scanner.go:116-175 Scanner
/// `scanner.Scanner` — reads Unicode characters and tokens from an
/// `io.Reader`.
pub struct Scanner<R: io::Reader> {
    // Go: src io.Reader
    src: R,

    // Go: srcBuf [bufLen + 1]byte — +1 for the `next()` sentinel
    srcBuf: Vec<byte>,
    // Go: srcPos int — reading position (srcBuf index)
    srcPos: int,
    // Go: srcEnd int — source end (srcBuf index)
    srcEnd: int,

    // Go: srcBufOffset int — byte offset of srcBuf[0] in source
    srcBufOffset: int,
    // Go: line int
    line: int,
    // Go: column int
    column: int,
    // Go: lastLineLen int — for correct column reporting
    lastLineLen: int,
    // Go: lastCharLen int — length of last character in bytes
    lastCharLen: int,

    // Go: tokBuf bytes.Buffer — token text head no longer in srcBuf
    tokBuf: bytes::Buffer,
    // Go: tokPos int — token text tail position; valid if >= 0
    tokPos: int,
    // Go: tokEnd int — token text tail end
    tokEnd: int,

    // Go: ch rune — one character look-ahead
    ch: rune,

    /// Go: `Error func(s *Scanner, msg string)` — called for each
    /// error. If unset, errors go to `os.Stderr`.
    pub Error: Option<fn(&mut Scanner<R>, string)>,

    /// Go: `ErrorCount int` — incremented once per error.
    pub ErrorCount: int,

    /// Go: `Mode uint` — which tokens are recognised.
    pub Mode: uint,

    /// Go: `Whitespace uint64` — which characters are white space.
    pub Whitespace: u64,

    /// Go: `IsIdentRune func(ch rune, i int) bool` — the characters
    /// accepted as the ith rune of an identifier.
    pub IsIdentRune: Option<fn(rune, int) -> bool>,

    /// Go embeds `Position`; goish names the field. Start position of
    /// the most recently scanned token, set by [`Scanner::Scan`].
    pub Position: Position,
}

// go: none — goish idiom: Go's zero `Scanner` is usable and `Init`
//     fills it. goish's owns its source, so it has to be built with
//     one; this is `new(Scanner).Init(src)` in a single step.
/// Build a `Scanner` over `src` and initialise it.
pub fn NewScanner<R: io::Reader>(src: R) -> Scanner<R> {
    let mut s = Scanner {
        src,
        srcBuf: Vec::new(),
        srcPos: 0,
        srcEnd: 0,
        srcBufOffset: 0,
        line: 0,
        column: 0,
        lastLineLen: 0,
        lastCharLen: 0,
        tokBuf: bytes::Buffer::new(),
        tokPos: -1,
        tokEnd: 0,
        ch: -2,
        Error: None,
        ErrorCount: 0,
        Mode: 0,
        Whitespace: 0,
        IsIdentRune: None,
        Position: Position::default(),
    };
    s.Init();
    return s;
}

impl<R: io::Reader> Scanner<R> {
    // go: sdk 1.25.5 text/scanner/scanner.go:181-212 Scanner.Init
    // goishlint:ignore GOISH020 — Go's `Init(src io.Reader)` also
    //     installs the source, because a Go `Scanner` can be re-pointed
    //     at a different reader. goish's owns `R` by value and takes it
    //     in `NewScanner`, so only the reset half is left here.
    /// `(s *Scanner).Init()` — reset the scanner. `Error` is cleared,
    /// `ErrorCount` zeroed, `Mode` set to [`GoTokens`] and
    /// `Whitespace` to [`GoWhitespace`].
    pub fn Init(&mut self) -> &mut Self {
        // Go: s.srcBuf[0] = utf8.RuneSelf — sentinel
        self.srcBuf = alloc::vec![0; bufLen + 1];
        self.srcBuf[0] = utf8::RuneSelf;
        self.srcPos = 0;
        self.srcEnd = 0;

        // Go: initialize source position
        self.srcBufOffset = 0;
        self.line = 1;
        self.column = 0;
        self.lastLineLen = 0;
        self.lastCharLen = 0;

        // Go: s.tokPos = -1
        self.tokPos = -1;

        // Go: s.ch = -2 — no char read yet, not EOF
        self.ch = -2;

        // Go: initialize public fields
        self.Error = None;
        self.ErrorCount = 0;
        self.Mode = GoTokens;
        self.Whitespace = GoWhitespace;
        self.Position.Line = 0; // invalidate token position
        return self;
    }

    // go: sdk 1.25.5 text/scanner/scanner.go:218-296 Scanner.next
    /// `(s *Scanner).next()` — read and return the next Unicode
    /// character. Structured so the common ASCII case costs one test
    /// for "not ASCII or end of buffer" and one for newline.
    fn next(&mut self) -> rune {
        // Go: ch, width := rune(s.srcBuf[s.srcPos]), 1
        let mut ch: rune = torune(self.srcBuf[self.srcPos as usize]);
        let mut width: int = 1;

        if ch >= torune(utf8::RuneSelf) {
            // Go: uncommon case — not ASCII, or not enough bytes.
            while self.srcPos + utf8::UTFMax > self.srcEnd
                && !utf8::FullRune(&self.srcBuf[self.srcPos as usize..self.srcEnd as usize])
            {
                // Go: save away token text if any
                if self.tokPos >= 0 {
                    let head: Vec<byte> =
                        self.srcBuf[self.tokPos as usize..self.srcPos as usize].to_vec();
                    let _ = self.tokBuf.Write(crate::goslice::slice::__from_vec(head));
                    self.tokPos = 0;
                    // s.tokEnd is set by Scan()
                }
                // Go: copy(s.srcBuf[0:], s.srcBuf[s.srcPos:s.srcEnd])
                self.srcBuf
                    .copy_within(self.srcPos as usize..self.srcEnd as usize, 0);
                self.srcBufOffset += self.srcPos;
                // Go: i := s.srcEnd - s.srcPos; n, err := s.src.Read(s.srcBuf[i:bufLen])
                let i = self.srcEnd - self.srcPos;
                let mut tmp = crate::make!([]byte, toint(bufLen) - i);
                let (n, err) = self.src.Read(&mut tmp);
                let mut k: int = 0;
                while k < n {
                    self.srcBuf[(i + k) as usize] = tmp[k];
                    k += 1;
                }
                self.srcPos = 0;
                self.srcEnd = i + n;
                self.srcBuf[self.srcEnd as usize] = utf8::RuneSelf; // sentinel
                if !err.IsNil() {
                    if err != io::EOF {
                        let msg = err.Error();
                        self.error(msg);
                    }
                    if self.srcEnd == 0 {
                        if self.lastCharLen > 0 {
                            // Go: previous character was not EOF
                            self.column += 1;
                        }
                        self.lastCharLen = 0;
                        return EOF;
                    }
                    // Go: EOF means no more bytes; anything else means
                    // we do not know. Either way, break.
                    break;
                }
            }
            // Go: at least one byte
            ch = torune(self.srcBuf[self.srcPos as usize]);
            if ch >= torune(utf8::RuneSelf) {
                // Go: uncommon case — not ASCII
                let (c, w) =
                    utf8::DecodeRune(&self.srcBuf[self.srcPos as usize..self.srcEnd as usize]);
                ch = c;
                width = w;
                if ch == utf8::RuneError && width == 1 {
                    // Go: advance for correct error position
                    self.srcPos += width;
                    self.lastCharLen = width;
                    self.column += 1;
                    self.error(string::from("invalid UTF-8 encoding"));
                    return ch;
                }
            }
        }

        // Go: advance
        self.srcPos += width;
        self.lastCharLen = width;
        self.column += 1;

        // Go: special situations
        if ch == 0 {
            // Go: for compatibility with other tools
            self.error(string::from("invalid character NUL"));
        } else if ch == torune(b'\n') {
            self.line += 1;
            self.lastLineLen = self.column;
            self.column = 0;
        }

        return ch;
    }

    // go: sdk 1.25.5 text/scanner/scanner.go:304-311 Scanner.Next
    /// `(s *Scanner).Next()` — read and return the next Unicode
    /// character, or [`EOF`]. Does not update `Position`; use
    /// [`Scanner::Pos`].
    pub fn Next(&mut self) -> rune {
        self.tokPos = -1; // don't collect token text
        self.Position.Line = 0; // invalidate token position
        let ch = self.Peek();
        if ch != EOF {
            self.ch = self.next();
        }
        return ch;
    }

    // go: sdk 1.25.5 text/scanner/scanner.go:317-325 Scanner.Peek
    /// `(s *Scanner).Peek()` — the next character without advancing.
    pub fn Peek(&mut self) -> rune {
        if self.ch == -2 {
            // Go: only run for the very first character
            self.ch = self.next();
            if self.ch == 0xFEFF {
                self.ch = self.next(); // ignore BOM
            }
        }
        return self.ch;
    }

    // go: sdk 1.25.5 text/scanner/scanner.go:328-339 Scanner.error
    /// `(s *Scanner).error(msg)` — report an error through `Error`, or
    /// to standard error if it is unset.
    fn error(&mut self, msg: string) {
        // Go: make sure token text is terminated
        self.tokEnd = self.srcPos - self.lastCharLen;
        self.ErrorCount += 1;
        if let Some(f) = self.Error {
            f(self, msg);
            return;
        }
        // Go: pos := s.Position; if !pos.IsValid() { pos = s.Pos() }
        let mut pos = self.Position.clone();
        if !pos.IsValid() {
            pos = self.Pos();
        }
        // Go: fmt.Fprintf(os.Stderr, "%s: %s\n", pos, msg)
        let line = crate::Sprintf!("%s: %s\n", pos.String(), msg);
        let e = crate::os::Stderr();
        let _ = e.Write(crate::convert::bytes(line));
    }

    // go: sdk 1.25.5 text/scanner/scanner.go:342-344 Scanner.errorf
    /// `(s *Scanner).errorf(format, args...)` — [`Scanner::error`] with
    /// a formatted message.
    ///
    /// Go is variadic over `any`; goish takes the already-formatted
    /// string, since a goish variadic would be a macro and this is an
    /// unexported helper with three call sites.
    fn errorf(&mut self, msg: string) {
        self.error(msg);
    }

    // go: sdk 1.25.5 text/scanner/scanner.go:346-351 Scanner.isIdentRune
    /// `(s *Scanner).isIdentRune(ch, i)` — whether `ch` is accepted as
    /// the ith rune of an identifier.
    fn isIdentRune(&self, ch: rune, i: int) -> bool {
        if let Some(f) = self.IsIdentRune {
            return ch != EOF && f(ch, i);
        }
        return ch == torune(b'_') || unicode::IsLetter(ch) || (unicode::IsDigit(ch) && i > 0);
    }

    // go: sdk 1.25.5 text/scanner/scanner.go:353-360 Scanner.scanIdentifier
    /// `(s *Scanner).scanIdentifier()` — consume an identifier, whose
    /// zeroth rune is already known to be acceptable.
    fn scanIdentifier(&mut self) -> rune {
        let mut ch = self.next();
        let mut i: int = 1;
        while self.isIdentRune(ch, i) {
            ch = self.next();
            i += 1;
        }
        return ch;
    }

    // go: sdk 1.25.5 text/scanner/scanner.go:372-397 Scanner.digits
    /// `(s *Scanner).digits(ch0, base, invalid)` — accept
    /// `{ digit | '_' }` starting at `ch0`.
    ///
    /// Returns the first rune that is no longer part of the sequence
    /// and a bitset: bit 0 means a digit was seen, bit 1 a separator.
    /// For `base <= 10` any decimal digit is accepted, and the first
    /// one that is `>= base` is recorded in `invalid` if it is still 0.
    fn digits(&mut self, ch0: rune, base: int, invalid: &mut rune) -> (rune, int) {
        let mut ch = ch0;
        let mut digsep: int = 0;
        if base <= 10 {
            let max = torune(b'0') + torune(base);
            while isDecimal(ch) || ch == torune(b'_') {
                let mut ds: int = 1;
                if ch == torune(b'_') {
                    ds = 2;
                } else if ch >= max && *invalid == 0 {
                    *invalid = ch;
                }
                digsep |= ds;
                ch = self.next();
            }
        } else {
            while isHex(ch) || ch == torune(b'_') {
                let mut ds: int = 1;
                if ch == torune(b'_') {
                    ds = 2;
                }
                digsep |= ds;
                ch = self.next();
            }
        }
        return (ch, digsep);
    }

    // go: sdk 1.25.5 text/scanner/scanner.go:399-483 Scanner.scanNumber
    /// `(s *Scanner).scanNumber(ch, seenDot)` — scan an integer or
    /// float literal, returning its token and the next rune.
    fn scanNumber(&mut self, ch0: rune, seenDot0: bool) -> (rune, rune) {
        let mut ch = ch0;
        let mut seenDot = seenDot0;
        let mut base: int = 10;
        let mut prefix: rune = 0;
        let mut digsep: int = 0;
        let mut invalid: rune = 0;

        // Go: integer part
        let mut tok: rune = 0;
        let mut ds: int;
        if !seenDot {
            tok = Int;
            if ch == torune(b'0') {
                ch = self.next();
                let l = lower(ch);
                if l == torune(b'x') {
                    ch = self.next();
                    base = 16;
                    prefix = torune(b'x');
                } else if l == torune(b'o') {
                    ch = self.next();
                    base = 8;
                    prefix = torune(b'o');
                } else if l == torune(b'b') {
                    ch = self.next();
                    base = 2;
                    prefix = torune(b'b');
                } else {
                    base = 8;
                    prefix = torune(b'0');
                    digsep = 1; // leading 0
                }
            }
            let (c, d) = self.digits(ch, base, &mut invalid);
            ch = c;
            ds = d;
            digsep |= ds;
            if ch == torune(b'.') && (self.Mode & ScanFloats) != 0 {
                ch = self.next();
                seenDot = true;
            }
        }

        // Go: fractional part
        if seenDot {
            tok = Float;
            if prefix == torune(b'o') || prefix == torune(b'b') {
                let msg = string::from("invalid radix point in ") + litname(prefix);
                self.error(msg);
            }
            let (c, d) = self.digits(ch, base, &mut invalid);
            ch = c;
            ds = d;
            digsep |= ds;
        }

        if digsep & 1 == 0 {
            let msg = litname(prefix) + " has no digits";
            self.error(msg);
        }

        // Go: exponent
        let e = lower(ch);
        if (e == torune(b'e') || e == torune(b'p')) && (self.Mode & ScanFloats) != 0 {
            if e == torune(b'e') && prefix != 0 && prefix != torune(b'0') {
                let msg = crate::Sprintf!("%q exponent requires decimal mantissa", ch);
                self.errorf(msg);
            } else if e == torune(b'p') && prefix != torune(b'x') {
                let msg = crate::Sprintf!("%q exponent requires hexadecimal mantissa", ch);
                self.errorf(msg);
            }
            ch = self.next();
            tok = Float;
            if ch == torune(b'+') || ch == torune(b'-') {
                ch = self.next();
            }
            let mut ignored: rune = 0;
            let (c, d) = self.digits(ch, 10, &mut ignored);
            ch = c;
            ds = d;
            digsep |= ds;
            if ds & 1 == 0 {
                self.error(string::from("exponent has no digits"));
            }
        } else if prefix == torune(b'x') && tok == Float {
            self.error(string::from("hexadecimal mantissa requires a 'p' exponent"));
        }

        if tok == Int && invalid != 0 {
            let msg = crate::Sprintf!("invalid digit %q in %s", invalid, litname(prefix));
            self.errorf(msg);
        }

        if digsep & 2 != 0 {
            // Go: make sure token text is terminated
            self.tokEnd = self.srcPos - self.lastCharLen;
            let text = self.TokenText();
            if invalidSep(&text) >= 0 {
                self.error(string::from("'_' must separate successive digits"));
            }
        }

        return (tok, ch);
    }

    // go: sdk 1.25.5 text/scanner/scanner.go:548-557 Scanner.scanDigits
    /// `(s *Scanner).scanDigits(ch, base, n)` — consume exactly `n`
    /// digits of `base`, erroring if fewer are available.
    fn scanDigits(&mut self, ch0: rune, base: int, n0: int) -> rune {
        let mut ch = ch0;
        let mut n = n0;
        while n > 0 && digitVal(ch) < base {
            ch = self.next();
            n -= 1;
        }
        if n > 0 {
            self.error(string::from("invalid char escape"));
        }
        return ch;
    }

    // go: sdk 1.25.5 text/scanner/scanner.go:559-577 Scanner.scanEscape
    /// `(s *Scanner).scanEscape(quote)` — consume a `\` escape.
    fn scanEscape(&mut self, quote: rune) -> rune {
        let mut ch = self.next(); // read character after '\'
        if ch == torune(b'a')
            || ch == torune(b'b')
            || ch == torune(b'f')
            || ch == torune(b'n')
            || ch == torune(b'r')
            || ch == torune(b't')
            || ch == torune(b'v')
            || ch == torune(b'\\')
            || ch == quote
        {
            // Go: nothing to do
            ch = self.next();
        } else if ch >= torune(b'0') && ch <= torune(b'7') {
            ch = self.scanDigits(ch, 8, 3);
        } else if ch == torune(b'x') {
            let c = self.next();
            ch = self.scanDigits(c, 16, 2);
        } else if ch == torune(b'u') {
            let c = self.next();
            ch = self.scanDigits(c, 16, 4);
        } else if ch == torune(b'U') {
            let c = self.next();
            ch = self.scanDigits(c, 16, 8);
        } else {
            self.error(string::from("invalid char escape"));
        }
        return ch;
    }

    // go: sdk 1.25.5 text/scanner/scanner.go:579-594 Scanner.scanString
    /// `(s *Scanner).scanString(quote)` — consume a quoted literal,
    /// returning the number of characters in it.
    fn scanString(&mut self, quote: rune) -> int {
        let mut n: int = 0;
        let mut ch = self.next(); // read character after quote
        while ch != quote {
            if ch == torune(b'\n') || ch < 0 {
                self.error(string::from("literal not terminated"));
                return n;
            }
            if ch == torune(b'\\') {
                ch = self.scanEscape(quote);
            } else {
                ch = self.next();
            }
            n += 1;
        }
        return n;
    }

    // go: sdk 1.25.5 text/scanner/scanner.go:596-605 Scanner.scanRawString
    /// `(s *Scanner).scanRawString()` — consume a backquoted literal.
    fn scanRawString(&mut self) {
        let mut ch = self.next(); // read character after '`'
        while ch != torune(b'`') {
            if ch < 0 {
                self.error(string::from("literal not terminated"));
                return;
            }
            ch = self.next();
        }
    }

    // go: sdk 1.25.5 text/scanner/scanner.go:607-611 Scanner.scanChar
    /// `(s *Scanner).scanChar()` — consume a rune literal, which must
    /// contain exactly one character.
    fn scanChar(&mut self) {
        if self.scanString(torune(b'\'')) != 1 {
            self.error(string::from("invalid char literal"));
        }
    }

    // go: sdk 1.25.5 text/scanner/scanner.go:613-639 Scanner.scanComment
    /// `(s *Scanner).scanComment(ch)` — consume a `//` or `/* */`
    /// comment; `ch` is the character after the opening `/`.
    fn scanComment(&mut self, ch0: rune) -> rune {
        let mut ch = ch0;
        if ch == torune(b'/') {
            // Go: line comment
            ch = self.next(); // read character after "//"
            while ch != torune(b'\n') && ch >= 0 {
                ch = self.next();
            }
            return ch;
        }

        // Go: general comment
        ch = self.next(); // read character after "/*"
        loop {
            if ch < 0 {
                self.error(string::from("comment not terminated"));
                break;
            }
            let ch0 = ch;
            ch = self.next();
            if ch0 == torune(b'*') && ch == torune(b'/') {
                ch = self.next();
                break;
            }
        }
        return ch;
    }

    // go: sdk 1.25.5 text/scanner/scanner.go:646-742 Scanner.Scan
    /// `(s *Scanner).Scan()` — read the next token or Unicode
    /// character. Only tokens whose `Mode` bit `1 << -tok` is set are
    /// recognised; everything else comes back as its own character.
    pub fn Scan(&mut self) -> rune {
        let mut ch = self.Peek();

        // Go: reset token text position
        self.tokPos = -1;
        self.Position.Line = 0;

        let tok: rune;
        // Go writes `redo:` and a `goto redo` from the skipped-comment
        // branch; goish spells the same control flow as a loop.
        loop {
            // Go: for s.Whitespace&(1<<uint(ch)) != 0
            //
            // `uint(ch)` is huge when ch is negative — EOF is -1 — and
            // Go defines a shift by at least the operand width as 0,
            // so the loop simply ends. Rust panics on that shift
            // instead, so the width test is written out.
            loop {
                let sh = touint(ch);
                if sh >= 64 || (self.Whitespace & (1u64 << sh)) == 0 {
                    break;
                }
                ch = self.next();
            }

            // Go: start collecting token text
            self.tokBuf.Reset();
            self.tokPos = self.srcPos - self.lastCharLen;

            // Go: set token position (an inlined, slimmer Pos())
            self.Position.Offset = self.srcBufOffset + self.tokPos;
            if self.column > 0 {
                // Go: common case — last character was not a '\n'
                self.Position.Line = self.line;
                self.Position.Column = self.column;
            } else {
                // Go: last character was a '\n'. We cannot be at the
                // start of the source, since next() has run at least once.
                self.Position.Line = self.line - 1;
                self.Position.Column = self.lastLineLen;
            }

            // Go: determine token value
            let mut t = ch;
            if self.isIdentRune(ch, 0) {
                if (self.Mode & ScanIdents) != 0 {
                    t = Ident;
                    ch = self.scanIdentifier();
                } else {
                    ch = self.next();
                }
            } else if isDecimal(ch) {
                if (self.Mode & (ScanInts | ScanFloats)) != 0 {
                    let (tk, c) = self.scanNumber(ch, false);
                    t = tk;
                    ch = c;
                } else {
                    ch = self.next();
                }
            } else if ch == EOF {
                // Go: break out of the inner switch
            } else if ch == torune(b'"') {
                if (self.Mode & ScanStrings) != 0 {
                    self.scanString(torune(b'"'));
                    t = String;
                }
                ch = self.next();
            } else if ch == torune(b'\'') {
                if (self.Mode & ScanChars) != 0 {
                    self.scanChar();
                    t = Char;
                }
                ch = self.next();
            } else if ch == torune(b'.') {
                ch = self.next();
                if isDecimal(ch) && (self.Mode & ScanFloats) != 0 {
                    let (tk, c) = self.scanNumber(ch, true);
                    t = tk;
                    ch = c;
                }
            } else if ch == torune(b'/') {
                ch = self.next();
                if (ch == torune(b'/') || ch == torune(b'*')) && (self.Mode & ScanComments) != 0 {
                    if (self.Mode & SkipComments) != 0 {
                        self.tokPos = -1; // don't collect token text
                        ch = self.scanComment(ch);
                        continue; // Go: goto redo
                    }
                    ch = self.scanComment(ch);
                    t = Comment;
                }
            } else if ch == torune(b'`') {
                if (self.Mode & ScanRawStrings) != 0 {
                    self.scanRawString();
                    t = RawString;
                }
                ch = self.next();
            } else {
                ch = self.next();
            }
            tok = t;
            break;
        }

        // Go: end of token text
        self.tokEnd = self.srcPos - self.lastCharLen;

        self.ch = ch;
        return tok;
    }

    // go: sdk 1.25.5 text/scanner/scanner.go:748-765 Scanner.Pos
    /// `(s *Scanner).Pos()` — the position of the character just after
    /// the one returned by the last [`Scanner::Next`] or
    /// [`Scanner::Scan`]. For the *start* of the last token, read the
    /// `Position` field.
    pub fn Pos(&self) -> Position {
        let mut pos = Position {
            Filename: self.Position.Filename.clone(),
            Offset: self.srcBufOffset + self.srcPos - self.lastCharLen,
            Line: 0,
            Column: 0,
        };
        if self.column > 0 {
            // Go: common case — last character was not a '\n'
            pos.Line = self.line;
            pos.Column = self.column;
        } else if self.lastLineLen > 0 {
            // Go: last character was a '\n'
            pos.Line = self.line - 1;
            pos.Column = self.lastLineLen;
        } else {
            // Go: at the beginning of the source
            pos.Line = 1;
            pos.Column = 1;
        }
        return pos;
    }

    // go: sdk 1.25.5 text/scanner/scanner.go:769-791 Scanner.TokenText
    /// `(s *Scanner).TokenText()` — the text of the most recently
    /// scanned token. Valid after [`Scanner::Scan`] and inside `Error`.
    pub fn TokenText(&mut self) -> string {
        if self.tokPos < 0 {
            // Go: no token text
            return string::new();
        }

        if self.tokEnd < self.tokPos {
            // Go: if EOF was reached, s.tokEnd is set to -1
            self.tokEnd = self.tokPos;
        }
        // Go: s.tokEnd >= s.tokPos

        if self.tokBuf.Len() == 0 {
            // Go: common case — the whole token text is still in srcBuf
            return string::from_bytes(&self.srcBuf[self.tokPos as usize..self.tokEnd as usize]);
        }

        // Go: part of the token text was saved in tokBuf; save the rest
        // there too and return its content.
        let tail: Vec<byte> = self.srcBuf[self.tokPos as usize..self.tokEnd as usize].to_vec();
        let _ = self.tokBuf.Write(crate::goslice::slice::__from_vec(tail));
        self.tokPos = self.tokEnd; // ensure idempotency
        return self.tokBuf.String();
    }
}

// go: sdk 1.25.5 text/scanner/scanner.go:362-362 lower
/// Lower-case `ch` iff it is an ASCII letter.
fn lower(ch: rune) -> rune {
    return (torune(b'a') - torune(b'A')) | ch;
}

// go: sdk 1.25.5 text/scanner/scanner.go:363-363 isDecimal
fn isDecimal(ch: rune) -> bool {
    return torune(b'0') <= ch && ch <= torune(b'9');
}

// go: sdk 1.25.5 text/scanner/scanner.go:364-364 isHex
fn isHex(ch: rune) -> bool {
    return (torune(b'0') <= ch && ch <= torune(b'9'))
        || (torune(b'a') <= lower(ch) && lower(ch) <= torune(b'f'));
}

// go: sdk 1.25.5 text/scanner/scanner.go:485-497 litname
/// The name of the literal kind a numeric prefix introduces.
fn litname(prefix: rune) -> string {
    if prefix == torune(b'x') {
        return string::from("hexadecimal literal");
    }
    if prefix == torune(b'o') || prefix == torune(b'0') {
        return string::from("octal literal");
    }
    if prefix == torune(b'b') {
        return string::from("binary literal");
    }
    return string::from("decimal literal");
}

// go: sdk 1.25.5 text/scanner/scanner.go:499-536 invalidSep
/// The index of the first invalid `_` separator in `x`, or -1.
fn invalidSep(x: &string) -> int {
    let b = crate::gostring::__crate_as_bytes(x);
    let mut x1: rune = torune(b' '); // prefix char; only 'x' matters
    let mut d: rune = torune(b'.'); // '_', '0' (a digit), or '.' (anything else)
    let mut i: usize = 0;

    // Go: a prefix counts as a digit
    if b.len() >= 2 && b[0] == b'0' {
        x1 = lower(torune(b[1]));
        if x1 == torune(b'x') || x1 == torune(b'o') || x1 == torune(b'b') {
            d = torune(b'0');
            i = 2;
        }
    }

    // Go: mantissa and exponent
    while i < b.len() {
        let p = d; // previous digit
        d = torune(b[i]);
        if d == torune(b'_') {
            if p != torune(b'0') {
                return toint(i);
            }
        } else if isDecimal(d) || (x1 == torune(b'x') && isHex(d)) {
            d = torune(b'0');
        } else {
            if p == torune(b'_') {
                return toint(i) - 1;
            }
            d = torune(b'.');
        }
        i += 1;
    }
    if d == torune(b'_') {
        return toint(b.len()) - 1;
    }

    return -1;
}

// go: sdk 1.25.5 text/scanner/scanner.go:538-546 digitVal
/// The value of a hex digit, or 16 for anything that is not one.
fn digitVal(ch: rune) -> int {
    if torune(b'0') <= ch && ch <= torune(b'9') {
        return toint(ch - torune(b'0'));
    }
    if torune(b'a') <= lower(ch) && lower(ch) <= torune(b'f') {
        return toint(lower(ch) - torune(b'a') + 10);
    }
    return 16; // larger than any legal digit val
}
