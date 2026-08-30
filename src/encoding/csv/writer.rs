// go: file encoding/csv/writer.go decls: NewWriter, Writer.Write, Writer.Flush, Writer.Error, Writer.WriteAll, Writer.fieldNeedsQuotes
//
// The `decls:` manifest above lists writer.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// the `Writer` type there would report it as a dropped port. It is not
// dropped - it carries its own `// go: sdk` anchor below.
//
// encoding/csv/writer.go - writing RFC 4180 records.
//
// `fieldNeedsQuotes` is the whole of the format's subtlety, and it is
// asymmetric in a way that is easy to "fix" by mistake. A field is
// quoted if it contains the delimiter, a quote, a CR or an LF; if it is
// exactly `\.`, which some readers treat as end-of-data; or if its
// first *rune* is white space. A trailing space is **not** quoted, and
// the empty string is never quoted. Both asymmetries are Go's and are
// pinned by csv_smoke's byte-for-byte comparison.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::bufio;
use crate::convert::{byte as tobyte, rune as torune, uint32 as touint32};
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::strings;
use crate::types::{int, rune};
use crate::unicode;
use crate::unicode::utf8;

use super::reader::{errInvalidDelim, validDelim};

// ─── Writer (writer.go:32) ──────────────────────────────────────────

/// `csv.Writer` (writer.go:32).
pub struct Writer<W: io::Writer> {
    pub Comma: rune,
    pub UseCRLF: bool,
    w: bufio::Writer<W>,
}

// go: sdk 1.25.5 encoding/csv/writer.go:39-44 NewWriter
/// `csv.NewWriter(w)` (writer.go:39).
pub fn NewWriter<W: io::Writer>(w: W) -> Writer<W> {
    return Writer {
        Comma: torune(b','),
        UseCRLF: false,
        w: bufio::NewWriter(w),
    };
}

impl<W: io::Writer> Writer<W> {
    // go: sdk 1.25.5 encoding/csv/writer.go:50-121 Writer.Write
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
                let i = if i < 0 {
                    crate::builtin::len(&field)
                } else {
                    i
                };
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
        return if self.UseCRLF {
            let (_, e) = self.w.WriteString(string::from_static("\r\n"));
            e
        } else {
            self.w.WriteByte(b'\n')
        };
    }

    // go: sdk 1.25.5 encoding/csv/writer.go:125-127 Writer.Flush
    /// `(*Writer).Flush()` (writer.go:125).
    pub fn Flush(&mut self) {
        let _ = self.w.Flush();
    }

    // go: sdk 1.25.5 encoding/csv/writer.go:131-134 Writer.Error
    /// `(*Writer).Error()` (writer.go:131).
    pub fn Error(&mut self) -> error {
        let (_, err) = self.w.Write(slice::__from_vec(Vec::new()));
        return err;
    }

    // go: sdk 1.25.5 encoding/csv/writer.go:138-146 Writer.WriteAll
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
        return nil;
    }

    // go: sdk 1.25.5 encoding/csv/writer.go:160-184 Writer.fieldNeedsQuotes
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
        if touint32(self.Comma) < touint32(utf8::RuneSelf) {
            let fb = crate::gostring::__crate_as_bytes(field);
            for &c in fb.iter() {
                if c == b'\n' || c == b'\r' || c == b'"' || c == tobyte(self.Comma) {
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
        return unicode::IsSpace(r1);
    }
}

// go: none — goish idiom: Go's `s[i:j]` on a string is a view; a goish
//     `string` owns its bytes, so a substring is a copy.
fn string_slice(s: &string, i: int, j: int) -> string {
    let b = crate::gostring::__crate_as_bytes(s);
    return string::from_bytes(&b[i as usize..j as usize]);
}
