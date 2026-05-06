// encoding/csv — comma-separated values reader/writer.
//
// Line-by-line port of:
//   /nix/store/60z37432vmgkg54krwr1z057bqwp7583-go-1.25.5/share/go/src/
//     encoding/csv/reader.go
//     encoding/csv/writer.go
//
// Slim deviations:
//   * Reader returns `slice<string>` instead of `[]string`; goish lacks a
//     fixed-Vec field that can hold a Go-style `lastRecord` cache, so
//     `ReuseRecord` is accepted as a field but the optimization is a
//     no-op (each Read returns a fresh slice).
//   * `FieldPos` panics with goish-style panic.
//   * Empty-line + comment-line handling matches Go reader.go:305-319.

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
use alloc::vec::Vec;

use crate::bufio;
use crate::bytes;
use crate::errors::{error, nil, ErrorTrait, Wrap};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::strings;
use crate::types::{byte, int, rune};
use crate::unicode;
use crate::unicode::utf8;

// ─── Sentinel errors (reader.go:88) + validDelim (reader.go:98) ──────

crate::var! {
    pub ErrBareQuote: error  = "bare \" in non-quoted-field";
    pub ErrQuote: error      = "extraneous or missing \" in quoted-field";
    pub ErrFieldCount: error = "wrong number of fields";
}
fn errInvalidDelim() -> error {
    crate::errors::New(string::from_static("csv: invalid field or comment delimiter"))
}

// Go: reader.go:98
fn validDelim(r: rune) -> bool {
    r != 0
        && r != ('"' as rune)
        && r != ('\r' as rune)
        && r != ('\n' as rune)
        && utf8::ValidRune(r)
        && r != utf8::RuneError
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
    fn Error(&self) -> string {
        // Go: reader.go:74
        // We can't use Sprintf!(...) cleanly with a dynamic error, so
        // build the message manually.
        let mut out = alloc::string::String::new();
        if errors_is_field_count(&self.Err) {
            out.push_str("record on line ");
            push_dec(&mut out, self.Line);
            out.push_str(": ");
            push_str(&mut out, &self.Err.Error());
        } else if self.StartLine != self.Line {
            out.push_str("record on line ");
            push_dec(&mut out, self.StartLine);
            out.push_str("; parse error on line ");
            push_dec(&mut out, self.Line);
            out.push_str(", column ");
            push_dec(&mut out, self.Column);
            out.push_str(": ");
            push_str(&mut out, &self.Err.Error());
        } else {
            out.push_str("parse error on line ");
            push_dec(&mut out, self.Line);
            out.push_str(", column ");
            push_dec(&mut out, self.Column);
            out.push_str(": ");
            push_str(&mut out, &self.Err.Error());
        }
        string::from_bytes(out.as_bytes())
    }
    // Go: reader.go:84 — Unwrap returns inner.
    fn Unwrap(&self) -> error {
        self.Err.clone()
    }
}

fn errors_is_field_count(e: &error) -> bool {
    crate::errors::Is(e.clone(), ErrFieldCount)
}

fn push_str(out: &mut alloc::string::String, s: &string) {
    let b = crate::gostring::__crate_as_bytes(s);
    if let Ok(s) = core::str::from_utf8(b) {
        out.push_str(s);
    }
}

fn push_dec(out: &mut alloc::string::String, mut n: int) {
    if n == 0 {
        out.push('0');
        return;
    }
    if n < 0 {
        out.push('-');
        n = -n;
    }
    let mut digits: Vec<u8> = Vec::new();
    while n > 0 {
        digits.push(b'0' + ((n % 10) as u8));
        n /= 10;
    }
    for &d in digits.iter().rev() {
        out.push(d as char);
    }
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

/// `csv.NewReader(r)` (reader.go:181).
pub fn NewReader<R: io::Reader>(r: R) -> Reader<R> {
    Reader {
        Comma: ',' as rune,
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
    }
}

impl<R: io::Reader> Reader<R> {
    /// `(*Reader).Read()` (reader.go:197).
    pub fn Read(&mut self) -> (slice<string>, error) {
        // Go: r.readRecord(nil) — ReuseRecord optimization is a no-op
        // in this port; both branches return a fresh slice.
        let _ = self.lastRecord.clone();
        let (rec, err) = self.readRecord();
        if self.ReuseRecord {
            self.lastRecord = rec.clone();
        }
        (rec, err)
    }

    /// `(*Reader).FieldPos(field)` (reader.go:213).
    pub fn FieldPos(&self, field: int) -> (int, int) {
        if field < 0 || field as usize >= self.fieldPositions.len() {
            panic!("out of range index passed to FieldPos");
        }
        let p = self.fieldPositions[field as usize];
        (p.line, p.col)
    }

    /// `(*Reader).InputOffset()` (reader.go:224).
    pub fn InputOffset(&self) -> int {
        self.offset
    }

    /// `(*Reader).ReadAll()` (reader.go:238).
    pub fn ReadAll(&mut self) -> (slice<slice<string>>, error) {
        let mut records: Vec<slice<string>> = Vec::new();
        loop {
            let (record, err) = self.readRecord();
            if crate::errors::Is(err.clone(), io::EOF) {
                return (slice::__from_vec(records), nil);
            }
            if !err.IsNil() {
                return (slice::__from_vec(Vec::new()), err);
            }
            records.push(record);
        }
    }

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
        self.offset += readSize as int;
        // Go: normalize \r\n to \n.
        let n = line.len();
        if n >= 2 && line[n - 2] == b'\r' && line[n - 1] == b'\n' {
            line[n - 2] = b'\n';
            line.pop();
        }
        (line, err)
    }

    // Go: reader.go:297
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
                pos.col += i as int;
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
                self.fieldIndexes.push(self.recordBuffer.len() as int);
                self.fieldPositions.push(pos);
                if found_comma {
                    line_off += advance_after;
                    pos.col += advance_after as int;
                    continue 'parseField;
                }
                break 'parseField;
            }

            // Quoted-field branch.
            let fieldPos = pos;
            line_off += quote_len;
            pos.col += quote_len as int;
            loop {
                let i = bytes::IndexByte(slice::__from_vec(cur!().to_vec()), b'"');
                if i >= 0 {
                    let i_us = i as usize;
                    self.recordBuffer.extend_from_slice(&cur!()[..i_us]);
                    line_off += i_us + quote_len;
                    pos.col += (i_us + quote_len) as int;
                    let rn = nextRune(cur!());
                    if rn == ('"' as rune) {
                        // `""` -> append quote.
                        self.recordBuffer.push(b'"');
                        line_off += quote_len;
                        pos.col += quote_len as int;
                    } else if rn == self.Comma {
                        line_off += comma_len;
                        pos.col += comma_len as int;
                        self.fieldIndexes.push(self.recordBuffer.len() as int);
                        self.fieldPositions.push(fieldPos);
                        continue 'parseField;
                    } else if lengthNL(cur!()) as usize == cur!().len() {
                        // `"\n` -> end of line.
                        self.fieldIndexes.push(self.recordBuffer.len() as int);
                        self.fieldPositions.push(fieldPos);
                        break 'parseField;
                    } else if self.LazyQuotes {
                        self.recordBuffer.push(b'"');
                    } else {
                        err = Wrap(ParseError {
                            StartLine: recLine,
                            Line: self.numLine,
                            Column: pos.col - quote_len as int,
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
                    pos.col += cur_len as int;
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
                    self.fieldIndexes.push(self.recordBuffer.len() as int);
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
            if (dst.len() as int) != self.FieldsPerRecord && err.IsNil() {
                err = Wrap(ParseError {
                    StartLine: recLine,
                    Line: recLine,
                    Column: 1,
                    Err: ErrFieldCount.into(),
                });
            }
        } else if self.FieldsPerRecord == 0 {
            self.FieldsPerRecord = dst.len() as int;
        }

        (slice::__from_vec(dst), err)
    }
}

// Go: reader.go:283 — lengthNL
fn lengthNL(b: &[byte]) -> int {
    if !b.is_empty() && b[b.len() - 1] == b'\n' {
        1
    } else {
        0
    }
}

// Go: reader.go:291 — nextRune
fn nextRune(b: &[byte]) -> rune {
    let (r, _) = utf8::DecodeRune(b);
    r
}

// bytes.IndexFunc adapted to &[byte].
fn bytes_index_func<F: Fn(rune) -> bool>(b: &[byte], f: F) -> int {
    bytes::IndexFunc(slice::__from_vec(b.to_vec()), f)
}

// ─── Writer (writer.go:32) ──────────────────────────────────────────

/// `csv.Writer` (writer.go:32).
pub struct Writer<W: io::Writer> {
    pub Comma: rune,
    pub UseCRLF: bool,
    w: bufio::Writer<W>,
}

/// `csv.NewWriter(w)` (writer.go:39).
pub fn NewWriter<W: io::Writer>(w: W) -> Writer<W> {
    Writer {
        Comma: ',' as rune,
        UseCRLF: false,
        w: bufio::NewWriter(w),
    }
}

impl<W: io::Writer> Writer<W> {
    /// `(*Writer).Write(record)` (writer.go:50).
    pub fn Write(&mut self, record: &[string]) -> error {
        if !validDelim(self.Comma) {
            return errInvalidDelim();
        }
        for n in 0..record.len() {
            if n > 0 {
                let (_, err) = self.w.WriteRune(self.Comma);
                if !err.IsNil() {
                    return err;
                }
            }
            let mut field = record[n].clone();
            if !self.fieldNeedsQuotes(&field) {
                let (_, err) = self.w.WriteString(field);
                if !err.IsNil() {
                    return err;
                }
                continue;
            }
            let err = self.w.WriteByte(b'"');
            if !err.IsNil() {
                return err;
            }
            while crate::builtin::len(&field) > 0 {
                // Go: i := strings.IndexAny(field, "\"\r\n")
                let i = strings::IndexAny(field.clone(), string::from_static("\"\r\n"));
                let i = if i < 0 { crate::builtin::len(&field) } else { i };
                // Go: writes field[:i] verbatim.
                let head = string_slice(&field, 0, i);
                let (_, err) = self.w.WriteString(head);
                if !err.IsNil() {
                    return err;
                }
                field = string_slice(&field, i, crate::builtin::len(&field));
                if crate::builtin::len(&field) > 0 {
                    let fb = crate::gostring::__crate_as_bytes(&field);
                    let head_byte = fb[0];
                    let werr = match head_byte {
                        b'"' => {
                            let (_, e) = self.w.WriteString(string::from_static("\"\""));
                            e
                        }
                        b'\r' => {
                            if !self.UseCRLF {
                                self.w.WriteByte(b'\r')
                            } else {
                                nil
                            }
                        }
                        b'\n' => {
                            if self.UseCRLF {
                                let (_, e) = self.w.WriteString(string::from_static("\r\n"));
                                e
                            } else {
                                self.w.WriteByte(b'\n')
                            }
                        }
                        _ => nil,
                    };
                    field = string_slice(&field, 1, crate::builtin::len(&field));
                    if !werr.IsNil() {
                        return werr;
                    }
                }
            }
            let err = self.w.WriteByte(b'"');
            if !err.IsNil() {
                return err;
            }
        }
        // Trailing newline.
        if self.UseCRLF {
            let (_, e) = self.w.WriteString(string::from_static("\r\n"));
            e
        } else {
            self.w.WriteByte(b'\n')
        }
    }

    /// `(*Writer).Flush()` (writer.go:125).
    pub fn Flush(&mut self) {
        let _ = self.w.Flush();
    }

    /// `(*Writer).Error()` (writer.go:131).
    pub fn Error(&mut self) -> error {
        let (_, err) = self.w.Write(slice::__from_vec(Vec::new()));
        err
    }

    /// `(*Writer).WriteAll(records)` (writer.go:138).
    pub fn WriteAll(&mut self, records: &[slice<string>]) -> error {
        for r in records.iter() {
            let v: Vec<string> = r.clone().__into_vec();
            let err = self.Write(&v);
            if !err.IsNil() {
                return err;
            }
        }
        let (_, err) = self.w.Write(slice::__from_vec(Vec::new()));
        if !err.IsNil() {
            return err;
        }
        let _ = self.w.Flush();
        nil
    }

    // Go: writer.go:160 — fieldNeedsQuotes.
    fn fieldNeedsQuotes(&self, field: &string) -> bool {
        if *field == string::new() {
            return false;
        }
        // Go: if field == `\.` { return true }
        if *field == string::from_static("\\.") {
            return true;
        }
        // Go: if w.Comma < utf8.RuneSelf { byte-wise scan } else { unicode helpers }
        if (self.Comma as u32) < (utf8::RuneSelf as u32) {
            let fb = crate::gostring::__crate_as_bytes(field);
            for &c in fb.iter() {
                if c == b'\n' || c == b'\r' || c == b'"' || c == self.Comma as byte {
                    return true;
                }
            }
        } else {
            if strings::ContainsRune(field.clone(), self.Comma)
                || strings::ContainsAny(field.clone(), string::from_static("\"\r\n"))
            {
                return true;
            }
        }
        let (r1, _) = utf8::DecodeRuneInString(field);
        unicode::IsSpace(r1)
    }
}

// Helpers — slim string slice (Go: s[i:j]).
fn string_slice(s: &string, i: int, j: int) -> string {
    let b = crate::gostring::__crate_as_bytes(s);
    string::from_bytes(&b[i as usize..j as usize])
}
