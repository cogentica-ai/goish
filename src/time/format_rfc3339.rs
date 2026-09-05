// go: file time/format_rfc3339.go decls: Time.appendStrictRFC3339
//
// goishlint:ignore GOISH018 — three of this file's four decls are
// deliberately absent, for two different reasons.
//
// `appendFormatRFC3339` and `parseRFC3339` are hand-rolled fast paths
// for the one layout the standard library sees most; they produce the
// same bytes as the general `appendFormat`/`Parse` walk, which goish
// has. Porting them would add a second formatter to keep in sync for
// no observable behaviour.
//
// `parseStrictRFC3339` is different: it REJECTS inputs Go's own Parse
// accepts, so it is real behaviour, and it is deferred rather than
// dismissed. goish's UnmarshalText/UnmarshalJSON still go through
// Parse, which closes the round trip against what the marshallers
// emit but is more permissive than Go on input. That needs its own
// measurement.
//
// Deviation: Go's `appendFormatRFC3339` and `parseRFC3339` in this file
// are hand-rolled fast paths for the layout the standard library sees
// most, producing the same bytes as the general
// `appendFormat`/`Parse` walk. goish has the general walk and no
// measured need for the fast path, so only the part with OBSERVABLE
// behaviour is ported: `appendStrictRFC3339`, whose validation is not
// an optimisation and has no equivalent anywhere else.
//
// `parseStrictRFC3339` is not ported yet. goish's Parse already accepts
// exactly the fractional-second forms this file's marshallers emit, so
// the round trip closes; what is missing is Go's REJECTION of inputs
// its own Parse would accept, which is its own measurement.

#![allow(non_snake_case)]

extern crate alloc;

use crate::error;
use crate::errors;
use crate::gostring::string;
use crate::types::byte;

use super::format::RFC3339Nano;
use super::time_go::Time;

impl Time {
    // go: sdk 1.25.5 time/format_rfc3339.go:62-80 Time.appendStrictRFC3339
    /// Append `t` in RFC 3339 form with sub-second precision, and report
    /// whether the result is actually valid RFC 3339.
    ///
    /// Not every valid Go timestamp can be serialised as RFC 3339, and
    /// the two edge cases are Go's own (go.dev/issue/4556 and
    /// go.dev/issue/54580): a year outside [0,9999] does not fit the
    /// four-digit field, and a zone offset with an hour past 23 does
    /// not fit `Z07:00`. Both render without complaint through the
    /// ordinary layout walk, which is why this check exists separately
    /// from formatting.
    ///
    /// The bytes are appended either way — Go appends first and
    /// validates the result — so a caller that reports the error must
    /// discard the buffer rather than use it.
    pub(crate) fn appendStrictRFC3339(self, b: &mut alloc::vec::Vec<byte>) -> error {
        // Go: n0 := len(b); b = t.appendFormatRFC3339(b, true)
        let n0 = b.len();
        let s = self.Format(string::from(RFC3339Nano));
        b.extend_from_slice(s.as_bytes());

        // Go: num2 := func(b []byte) byte { return 10*(b[0]-'0') + (b[1]-'0') }
        let num2 = |p: &[byte]| -> u32 { 10 * u32::from(p[0] - b'0') + u32::from(p[1] - b'0') };

        // Go: case b[n0+len("9999")] != '-': year must be exactly 4 digits wide
        if b.len() <= n0 + 4 || b[n0 + 4] != b'-' {
            return errors::New("year outside of range [0,9999]");
        }
        // Go: case b[len(b)-1] != 'Z':
        if b[b.len() - 1] != b'Z' {
            if b.len() < n0 + 6 {
                return errors::New("timezone hour outside of range [0,23]");
            }
            // Go: c := b[len(b)-len("Z07:00")]
            let c = b[b.len() - 6];
            // A digit here means the offset hour needed three columns,
            // so the sign has been pushed out of the field.
            if c.is_ascii_digit() || num2(&b[b.len() - 5..]) >= 24 {
                return errors::New("timezone hour outside of range [0,23]");
            }
        }
        return errors::nil;
    }
}
