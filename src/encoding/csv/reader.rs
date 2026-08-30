// go: file encoding/csv/reader.go decls: ParseError.Error, ParseError.Unwrap, errInvalidDelim, validDelim, NewReader, Reader.Read, Reader.FieldPos, Reader.InputOffset, Reader.ReadAll, Reader.readLine, lengthNL, nextRune, Reader.readRecord
//
// The `decls:` manifest above lists reader.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// `ParseError`, `Reader`, `position` or the sentinel errors there would
// report them as dropped ports. They are not dropped - each carries its
// own `// go: sdk` anchor below.
//
// encoding/csv/reader.go - reading RFC 4180 records.
//
// The reader is line-oriented but a *record* is not a line: a quoted
// field may contain the record separator, so `readRecord` loops calling
// `readLine` until the quotes balance. Two consequences are what a port
// gets wrong:
//
//   * Positions are tracked per field, not per record, because an
//     error inside a multi-line quoted field has to point at the right
//     line. That is what `fieldPositions` and `FieldPos` are for, and
//     why `FieldPos` panics rather than returning an error for an
//     out-of-range index - it is a programming mistake, not input.
//   * `FieldsPerRecord` has three modes in one int: negative disables
//     the check, zero adopts the first record's count, positive
//     enforces it. `ErrFieldCount` is returned *with* the record, not
//     instead of it.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::bufio;
use crate::bytes;
use crate::convert::{int as toint, rune as torune};
use crate::errors::{error, nil, ErrorTrait, Wrap};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int, rune};
use crate::unicode;
use crate::unicode::utf8;

// ─── Sentinel errors (reader.go:88) + validDelim (reader.go:98) ──────

crate::var! {
    pub ErrBareQuote: error  = "bare \" in non-quoted-field";
    pub ErrQuote: error      = "extraneous or missing \" in quoted-field";
    pub ErrFieldCount: error = "wrong number of fields";
}
// go: sdk 1.25.5 encoding/csv/reader.go:96-96 errInvalidDelim
/// `csv.errInvalidDelim` — an invalid `Comma` or `Comment` rune.
///
/// Go declares it as a package-level `var`; goish builds it per call,
/// since it is compared by message rather than by identity.
pub(super) fn errInvalidDelim() -> error {
    return crate::errors::New(string::from_static(
        "csv: invalid field or comment delimiter",
    ));
}

// go: sdk 1.25.5 encoding/csv/reader.go:98-100 validDelim
// Go: reader.go:98
pub(super) fn validDelim(r: rune) -> bool {
    return r != 0
        && r != torune(b'"')
        && r != torune(b'\r')
        && r != torune(b'\n')
        && utf8::ValidRune(r)
        && r != utf8::RuneError;
}

// ─── ParseError (reader.go:67) ──────────────────────────────────────

/// `csv.ParseError` (reader.go:67). Returned for parse failures.
pub struct ParseError {
    pub StartLine: int,
    pub Line: int,
    pub Column: int,
    pub Err: error,
}

impl ErrorTrait for ParseError {
    // go: sdk 1.25.5 encoding/csv/reader.go:74-82 ParseError.Error
    fn Error(&self) -> string {
        // Go: e.Err == ErrFieldCount — a pointer comparison against the
        // package sentinel, which is `errors::Is` here.
        if errors_is_field_count(&self.Err) {
            // Go: fmt.Sprintf("record on line %d: %v", e.Line, e.Err)
            return string::from_static("record on line ")
                + crate::strconv::Itoa(self.Line)
                + ": "
                + self.Err.Error();
        }
        if self.StartLine != self.Line {
            // Go: "record on line %d; parse error on line %d, column %d: %v"
            return string::from_static("record on line ")
                + crate::strconv::Itoa(self.StartLine)
                + "; parse error on line "
                + crate::strconv::Itoa(self.Line)
                + ", column "
                + crate::strconv::Itoa(self.Column)
                + ": "
                + self.Err.Error();
        }
        // Go: "parse error on line %d, column %d: %v"
        return string::from_static("parse error on line ")
            + crate::strconv::Itoa(self.Line)
            + ", column "
            + crate::strconv::Itoa(self.Column)
            + ": "
            + self.Err.Error();
    }
    // go: sdk 1.25.5 encoding/csv/reader.go:84-84 ParseError.Unwrap
    fn Unwrap(&self) -> error {
        return self.Err.clone();
    }
}

// go: none — goish idiom: `errors.Is(e, ErrFieldCount)` spelled once,
//     so `ParseError::Error` reads like Go's first branch.
pub(super) fn errors_is_field_count(e: &error) -> bool {
    return crate::errors::Is(e.clone(), ErrFieldCount);
}

// ─── Reader (reader.go:111) ─────────────────────────────────────────

/// `csv.Reader` (reader.go:111).
pub struct Reader<R: io::Reader> {
    pub Comma: rune,
    pub Comment: rune,
    pub FieldsPerRecord: int,
    pub LazyQuotes: bool,
    pub TrimLeadingSpace: bool,
    pub ReuseRecord: bool,
    /// Deprecated: ignored (kept for API parity).
    pub TrailingComma: bool,

    r: bufio::Reader<R>,
    numLine: int,
    offset: int,
    rawBuffer: Vec<byte>,
    recordBuffer: Vec<byte>,
    fieldIndexes: Vec<int>,
    fieldPositions: Vec<position>,
    lastRecord: slice<string>,
}

#[derive(Clone, Copy, Default)]
struct position {
    line: int,
    col: int,
}

// go: sdk 1.25.5 encoding/csv/reader.go:181-186 NewReader
/// `csv.NewReader(r)` (reader.go:181).
pub fn NewReader<R: io::Reader>(r: R) -> Reader<R> {
    return Reader {
        Comma: torune(b','),
        Comment: 0,
        FieldsPerRecord: 0,
        LazyQuotes: false,
        TrimLeadingSpace: false,
        ReuseRecord: false,
        TrailingComma: false,
        r: bufio::NewReader(r),
        numLine: 0,
        offset: 0,
        rawBuffer: Vec::new(),
        recordBuffer: Vec::new(),
        fieldIndexes: Vec::new(),
        fieldPositions: Vec::new(),
        lastRecord: slice::__from_vec(Vec::new()),
    };
}

impl<R: io::Reader> Reader<R> {
    // go: sdk 1.25.5 encoding/csv/reader.go:197-205 Reader.Read
    /// `(*Reader).Read()` (reader.go:197).
    pub fn Read(&mut self) -> (slice<string>, error) {
        // Go: r.readRecord(nil) — ReuseRecord optimization is a no-op
        // in this port; both branches return a fresh slice.
        let _ = self.lastRecord.clone();
        let (rec, err) = self.readRecord();
        if self.ReuseRecord {
            self.lastRecord = rec.clone();
        }
        return (rec, err);
    }

    // go: sdk 1.25.5 encoding/csv/reader.go:213-219 Reader.FieldPos
    /// `(*Reader).FieldPos(field)` (reader.go:213).
    pub fn FieldPos(&self, field: int) -> (int, int) {
        if field < 0 || field as usize >= self.fieldPositions.len() {
            panic!("out of range index passed to FieldPos");
        }
        let p = self.fieldPositions[field as usize];
        return (p.line, p.col);
    }

    // go: sdk 1.25.5 encoding/csv/reader.go:224-226 Reader.InputOffset
    /// `(*Reader).InputOffset()` (reader.go:224).
    pub fn InputOffset(&self) -> int {
        return self.offset;
    }

    // go: sdk 1.25.5 encoding/csv/reader.go:238-249 Reader.ReadAll
    /// `(*Reader).ReadAll()` (reader.go:238).
    pub fn ReadAll(&mut self) -> (slice<slice<string>>, error) {
        let mut records: Vec<slice<string>> = Vec::new();
        return loop {
            let (record, err) = self.readRecord();
            if crate::errors::Is(err.clone(), io::EOF) {
                return (slice::__from_vec(records), nil);
            }
            if !err.IsNil() {
                return (slice::__from_vec(Vec::new()), err);
            }
            records.push(record);
        };
    }

    // go: sdk 1.25.5 encoding/csv/reader.go:255-281 Reader.readLine
    // Go: reader.go:255
    fn readLine(&mut self) -> (Vec<byte>, error) {
        // Go: line, err := r.r.ReadSlice('\n')
        let (line, mut err) = self.r.ReadSlice(b'\n');
        let mut line: Vec<byte> = line.__into_vec();
        // Go: if err == bufio.ErrBufferFull { ... }
        if !err.IsNil() && crate::errors::Is(err.clone(), bufio::ErrBufferFull) {
            self.rawBuffer.clear();
            self.rawBuffer.extend_from_slice(&line);
            while crate::errors::Is(err.clone(), bufio::ErrBufferFull) {
                let (chunk, err2) = self.r.ReadSlice(b'\n');
                let chunk_v: Vec<byte> = chunk.__into_vec();
                err = err2;
                self.rawBuffer.extend_from_slice(&chunk_v);
            }
            line = self.rawBuffer.clone();
        }
        let readSize = line.len();
        // Go: if readSize > 0 && err == io.EOF { err = nil; if line[end] == '\r' { line = line[:end-1] } }
        if readSize > 0 && crate::errors::Is(err.clone(), io::EOF) {
            err = nil;
            if line[readSize - 1] == b'\r' {
                line.pop();
            }
        }
        self.numLine += 1;
        self.offset += toint(readSize);
        // Go: normalize \r\n to \n.
        let n = line.len();
        if n >= 2 && line[n - 2] == b'\r' && line[n - 1] == b'\n' {
            line[n - 2] = b'\n';
            line.pop();
        }
        return (line, err);
    }

    // go: sdk 1.25.5 encoding/csv/reader.go:297-467 Reader.readRecord
    // goishlint:ignore GOISH020 — Go's `readRecord(dst []string)` takes
    //     the previous record so `Read` can reuse its backing array.
    //     goish returns a fresh `slice<string>`, since a goish slice
    //     owns its buffer and handing one back to be overwritten would
    //     alias it.
    fn readRecord(&mut self) -> (slice<string>, error) {
        // Go: if r.Comma == r.Comment || !validDelim(r.Comma) || ...
        if self.Comma == self.Comment
            || !validDelim(self.Comma)
            || (self.Comment != 0 && !validDelim(self.Comment))
        {
            return (slice::__from_vec(Vec::new()), errInvalidDelim());
        }

        // Go: read line, skipping empty lines and comment lines.
        let mut line: Vec<byte>;
        let mut errRead;
        loop {
            let (l, e) = self.readLine();
            line = l;
            errRead = e;
            // Go: if r.Comment != 0 && nextRune(line) == r.Comment { line = nil; continue }
            if self.Comment != 0 && nextRune(&line) == self.Comment {
                line.clear();
                if errRead.IsNil() {
                    continue;
                } else {
                    break;
                }
            }
            // Go: if errRead == nil && len(line) == lengthNL(line) { line = nil; continue }
            if errRead.IsNil() && line.len() == lengthNL(&line) as usize {
                line.clear();
                continue;
            }
            break;
        }
        if crate::errors::Is(errRead.clone(), io::EOF) {
            return (slice::__from_vec(Vec::new()), errRead);
        }

        // Go: parse each field.
        let mut err: error = nil;
        let quote_len: usize = 1;
        let comma_len = utf8::RuneLen(self.Comma) as usize;
        let recLine = self.numLine;
        self.recordBuffer.clear();
        self.fieldIndexes.clear();
        self.fieldPositions.clear();
        let mut pos = position {
            line: self.numLine,
            col: 1,
        };

        let mut line_off: usize = 0;
        'parseField: loop {
            // Slice helper: line[line_off..]
            macro_rules! cur {
                () => {
                    &line[line_off..]
                };
            }

            // Go: if r.TrimLeadingSpace { ... }
            if self.TrimLeadingSpace {
                let i = bytes_index_func(cur!(), |r| !unicode::IsSpace(r));
                let i = if i < 0 {
                    let len_now = cur!().len();
                    pos.col -= lengthNL(cur!());
                    len_now
                } else {
                    i as usize
                };
                line_off += i;
                pos.col += toint(i);
            }

            // Go: if len(line) == 0 || line[0] != '"' { non-quoted field }
            if cur!().is_empty() || cur!()[0] != b'"' {
                let i_signed = bytes::IndexRune(slice::__from_vec(cur!().to_vec()), self.Comma);
                let cur_len = cur!().len();
                let (field_end, advance_after, found_comma) = if i_signed >= 0 {
                    let i = i_signed as usize;
                    (i, i + comma_len, true)
                } else {
                    let nl = lengthNL(cur!());
                    (cur_len - nl as usize, cur_len, false)
                };
                let field: Vec<byte> = cur!()[..field_end].to_vec();
                // Go: if !r.LazyQuotes
                if !self.LazyQuotes {
                    let j = bytes::IndexByte(slice::__from_vec(field.clone()), b'"');
                    if j >= 0 {
                        let col = pos.col + j;
                        err = Wrap(ParseError {
                            StartLine: recLine,
                            Line: self.numLine,
                            Column: col,
                            Err: ErrBareQuote.into(),
                        });
                        break 'parseField;
                    }
                }
                self.recordBuffer.extend_from_slice(&field);
                self.fieldIndexes.push(toint(self.recordBuffer.len()));
                self.fieldPositions.push(pos);
                if found_comma {
                    line_off += advance_after;
                    pos.col += toint(advance_after);
                    continue 'parseField;
                }
                break 'parseField;
            }

            // Quoted-field branch.
            let fieldPos = pos;
            line_off += quote_len;
            pos.col += toint(quote_len);
            loop {
                let i = bytes::IndexByte(slice::__from_vec(cur!().to_vec()), b'"');
                if i >= 0 {
                    let i_us = i as usize;
                    self.recordBuffer.extend_from_slice(&cur!()[..i_us]);
                    line_off += i_us + quote_len;
                    pos.col += toint(i_us + quote_len);
                    let rn = nextRune(cur!());
                    if rn == torune(b'"') {
                        // `""` -> append quote.
                        self.recordBuffer.push(b'"');
                        line_off += quote_len;
                        pos.col += toint(quote_len);
                    } else if rn == self.Comma {
                        line_off += comma_len;
                        pos.col += toint(comma_len);
                        self.fieldIndexes.push(toint(self.recordBuffer.len()));
                        self.fieldPositions.push(fieldPos);
                        continue 'parseField;
                    } else if lengthNL(cur!()) as usize == cur!().len() {
                        // `"\n` -> end of line.
                        self.fieldIndexes.push(toint(self.recordBuffer.len()));
                        self.fieldPositions.push(fieldPos);
                        break 'parseField;
                    } else if self.LazyQuotes {
                        self.recordBuffer.push(b'"');
                    } else {
                        err = Wrap(ParseError {
                            StartLine: recLine,
                            Line: self.numLine,
                            Column: pos.col - toint(quote_len),
                            Err: ErrQuote.into(),
                        });
                        break 'parseField;
                    }
                } else if !cur!().is_empty() {
                    let cur_len = cur!().len();
                    self.recordBuffer.extend_from_slice(cur!());
                    if !errRead.IsNil() {
                        break 'parseField;
                    }
                    pos.col += toint(cur_len);
                    let (nl, e) = self.readLine();
                    line = nl;
                    errRead = e;
                    line_off = 0;
                    if !line.is_empty() {
                        pos.line += 1;
                        pos.col = 1;
                    }
                    if crate::errors::Is(errRead.clone(), io::EOF) {
                        errRead = nil;
                    }
                } else {
                    if !self.LazyQuotes && errRead.IsNil() {
                        err = Wrap(ParseError {
                            StartLine: recLine,
                            Line: pos.line,
                            Column: pos.col,
                            Err: ErrQuote.into(),
                        });
                        break 'parseField;
                    }
                    self.fieldIndexes.push(toint(self.recordBuffer.len()));
                    self.fieldPositions.push(fieldPos);
                    break 'parseField;
                }
            }
        }

        if err.IsNil() {
            err = errRead;
        }

        // Go: build dst from recordBuffer + fieldIndexes.
        let str_b = self.recordBuffer.clone();
        let mut dst: Vec<string> = Vec::with_capacity(self.fieldIndexes.len());
        let mut preIdx: usize = 0;
        for &idx in self.fieldIndexes.iter() {
            let idx_us = idx as usize;
            dst.push(string::from_bytes(&str_b[preIdx..idx_us]));
            preIdx = idx_us;
        }

        // Go: FieldsPerRecord enforcement.
        if self.FieldsPerRecord > 0 {
            if toint(dst.len()) != self.FieldsPerRecord && err.IsNil() {
                err = Wrap(ParseError {
                    StartLine: recLine,
                    Line: recLine,
                    Column: 1,
                    Err: ErrFieldCount.into(),
                });
            }
        } else if self.FieldsPerRecord == 0 {
            self.FieldsPerRecord = toint(dst.len());
        }

        return (slice::__from_vec(dst), err);
    }
}

// go: sdk 1.25.5 encoding/csv/reader.go:284-289 lengthNL
// Go: reader.go:283 — lengthNL
pub(super) fn lengthNL(b: &[byte]) -> int {
    return if !b.is_empty() && b[b.len() - 1] == b'\n' {
        1
    } else {
        0
    };
}

// go: sdk 1.25.5 encoding/csv/reader.go:292-295 nextRune
// Go: reader.go:291 — nextRune
pub(super) fn nextRune(b: &[byte]) -> rune {
    let (r, _) = utf8::DecodeRune(b);
    return r;
}

// go: none — goish idiom: `bytes.IndexFunc` over a borrowed slice.
//     goish's takes a `slice<byte>`, which owns its buffer.
pub(super) fn bytes_index_func<F: Fn(rune) -> bool>(b: &[byte], f: F) -> int {
    return bytes::IndexFunc(slice::__from_vec(b.to_vec()), f);
}
