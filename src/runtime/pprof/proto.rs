// runtime/pprof/proto — the profile.proto wire format.
//
// go: none — goish-only: Go's encoder lives in `internal/profile`
// (proto.go, encode.go), which is not importable and not part of the
// ported surface. The FIELD NUMBERS and the packing rule below are read
// from it, because `go tool pprof` is the consumer and it only accepts
// what that writes.
//
// proto3, hand-rolled: varints are LEB128, which `encoding/binary`'s
// `AppendUvarint` already produces, and everything else is a
// length-delimited byte string. There is no schema compiler here and
// none is needed — profile.proto has six message types and no nesting
// deeper than two.
//
// The one rule that is not obvious: Go emits a repeated varint field
// PACKED only when it has more than two elements, and as separate
// fields otherwise (proto.go:69). Both are legal proto3 and any reader
// accepts either, so this is not about correctness — it is so a
// goish-written profile can be compared byte-for-byte against Go's
// rather than only "parsed by the same tool".

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

/// Wire type 0 — varint.
const WIRE_VARINT: u64 = 0;
/// Wire type 2 — length-delimited.
const WIRE_BYTES: u64 = 2;

// go: none — goish-only: see the module header.
/// A proto3 field key: `(tag << 3) | wire_type`.
fn key(tag: u64, wire: u64) -> u64 {
    return (tag << 3) | wire;
}

// go: none — goish-only: LEB128, the same encoding
// `binary::AppendUvarint` writes. Open-coded on a `Vec<u8>` because the
// profile buffer is built with raw bytes and converting to a
// `slice<byte>` per field would allocate per field.
/// Append `x` as a base-128 varint.
fn put_varint(b: &mut Vec<u8>, x: u64) {
    let mut v = x;
    while v >= 0x80 {
        b.push(crate::convert::uint8(v & 0x7f) | 0x80);
        v >>= 7;
    }
    b.push(crate::convert::uint8(v));
}

// go: none — goish-only: see the module header.
/// `tag` with wire type 0, then the value.
fn put_uint64(b: &mut Vec<u8>, tag: u64, x: u64) {
    put_varint(b, key(tag, WIRE_VARINT));
    put_varint(b, x);
}

// go: none — goish-only: see the module header.
/// As [`put_uint64`], but a zero is OMITTED — proto3's default, and
/// what Go's `encodeUint64Opt` does. Emitting it would be legal and
/// would differ from Go's bytes.
fn put_uint64_opt(b: &mut Vec<u8>, tag: u64, x: u64) {
    if x == 0 {
        return;
    }
    put_uint64(b, tag, x);
}

// go: none — goish-only: see the module header.
/// A signed value on the wire as a plain varint, which is what
/// profile.proto uses (`int64`, not `sint64` — so no zigzag). A
/// negative value therefore costs ten bytes, exactly as in Go.
fn put_int64(b: &mut Vec<u8>, tag: u64, x: i64) {
    put_uint64(b, tag, x as u64); // goishlint:ignore GOISH005 — a signed value reinterpreted, not converted: profile.proto uses int64, so a negative must keep its two's-complement bits.
}

// go: none — goish-only: see the module header.
/// As [`put_int64`], omitting a zero.
fn put_int64_opt(b: &mut Vec<u8>, tag: u64, x: i64) {
    if x == 0 {
        return;
    }
    put_int64(b, tag, x);
}

// go: none — goish-only: see the module header.
/// A length-delimited field: key, length, then `body`.
fn put_bytes(b: &mut Vec<u8>, tag: u64, body: &[u8]) {
    put_varint(b, key(tag, WIRE_BYTES));
    put_varint(b, crate::convert::uint64(body.len()));
    b.extend_from_slice(body);
}

// go: none — goish-only: see the module header.
/// A string field. proto3 strings are UTF-8 bytes with no terminator.
fn put_string(b: &mut Vec<u8>, tag: u64, s: &[u8]) {
    put_bytes(b, tag, s);
}

// go: none — goish-only: see the module header.
/// A repeated varint field, packed when it has more than two elements
/// and as separate fields otherwise — Go's rule, see the module header.
fn put_uint64s(b: &mut Vec<u8>, tag: u64, xs: &[u64]) {
    if xs.len() > 2 {
        let mut packed: Vec<u8> = Vec::new();
        for &x in xs {
            put_varint(&mut packed, x);
        }
        put_bytes(b, tag, &packed);
        return;
    }
    for &x in xs {
        put_uint64(b, tag, x);
    }
}

// ─── the profile.proto messages ─────────────────────────────────────
//
// Field numbers are from Go's `internal/profile/encode.go`, which is
// the writer `go tool pprof` was built against:
//
//   Profile   1 sample_type  2 sample  3 mapping  4 location
//             5 function     6 string_table      9 time_nanos
//            10 duration_nanos  11 period_type  12 period
//   ValueType 1 type  2 unit                  (both string-table idx)
//   Sample    1 location_id (repeated)  2 value (repeated)
//   Location  1 id  2 mapping_id  3 address  4 line
//   Line      1 function_id  2 line
//   Function  1 id  2 name  3 system_name  4 filename  5 start_line
//
// Every string is an INDEX into string_table, and index 0 must be the
// empty string — pprof requires it, and a profile whose table starts
// with a real string loads with every name shifted by one.

// go: none — goish-only: see the module header.
/// A `(type, unit)` pair naming what a sample's values measure.
///
/// Strings, not string-table indexes. Go's `preEncode` builds the table
/// itself in a fixed traversal order, and matching that order is what
/// makes the bytes identical rather than merely valid — see
/// [`Profile::marshal`].
pub struct ValueType {
    pub ty: crate::gostring::string,
    pub unit: crate::gostring::string,
}

// go: none — goish-only: see the module header.
/// One sample: the stack it was taken on (location ids, leaf first) and
/// one value per `sample_type`.
pub struct Sample {
    pub location_id: Vec<u64>,
    pub value: Vec<i64>,
}

// go: none — goish-only: see the module header.
/// A program counter, and the source lines it maps to.
pub struct Location {
    pub id: u64,
    pub address: u64,
    pub line: Vec<Line>,
}

// go: none — goish-only: see the module header.
/// One `(function, line)` pair inside a [`Location`].
pub struct Line {
    pub function_id: u64,
    pub line: i64,
}

// go: none — goish-only: see the module header.
/// A function, named by string-table indexes.
pub struct Function {
    pub id: u64,
    pub name: crate::gostring::string,
    pub system_name: crate::gostring::string,
    pub filename: crate::gostring::string,
    pub start_line: i64,
}

// go: none — goish-only: see the module header.
/// A whole profile, ready to encode.
pub struct Profile {
    pub sample_type: Vec<ValueType>,
    pub sample: Vec<Sample>,
    pub location: Vec<Location>,
    pub function: Vec<Function>,
    pub time_nanos: i64,
    pub duration_nanos: i64,
    pub period_type: Option<ValueType>,
    pub period: i64,
    /// Which sample_type a viewer should show first. The ONLY thing
    /// that distinguishes Go's `heap` profile from its `allocs`
    /// profile: measured, both carry the same four value types, and
    /// heap leaves this empty while allocs sets "alloc_space".
    pub default_sample_type: crate::gostring::string,
}

impl Profile {
    // go: none — goish-only: see the module header.
    /// An empty profile.
    pub fn new() -> Self {
        return Profile {
            sample_type: Vec::new(),
            sample: Vec::new(),
            location: Vec::new(),
            function: Vec::new(),
            time_nanos: 0,
            duration_nanos: 0,
            period_type: None,
            period: 0,
            default_sample_type: crate::gostring::string::new(),
        };
    }

    // go: none — goish-only: Go's `preEncode` (encode.go:20), whose
    // traversal ORDER is the contract: "" first, then every
    // SampleType's type and unit, then mappings, then every Function's
    // name, system name and filename, then DropFrames/KeepFrames, then
    // PeriodType.
    //
    // Interning in a different order produces a profile that `go tool
    // pprof` reads identically and whose BYTES differ — which is how
    // this was caught: goish's first version let the caller intern, the
    // output was the same 182 bytes, and every string index was
    // permuted.
    fn pre_encode(&self) -> Vec<crate::gostring::string> {
        let mut st: Vec<crate::gostring::string> = Vec::new();
        st.push(crate::gostring::string::new());
        let mut add = |st: &mut Vec<crate::gostring::string>, s: &str| {
            for have in st.iter() {
                if (have.as_ref() as &str) == s {
                    return;
                }
            }
            st.push(crate::gostring::string::from(s));
        };
        for t in &self.sample_type {
            add(&mut st, t.ty.as_ref());
            add(&mut st, t.unit.as_ref());
        }
        // Sample labels and mappings would be interned here; goish emits
        // neither yet, and their absence is what keeps this short.
        for f in &self.function {
            add(&mut st, f.name.as_ref());
            add(&mut st, f.system_name.as_ref());
            add(&mut st, f.filename.as_ref());
        }
        // DropFrames and KeepFrames are always empty here, and the empty
        // string is already index 0 — Go interns them anyway, to the
        // same slot.
        if let Some(pt) = &self.period_type {
            add(&mut st, pt.ty.as_ref());
            add(&mut st, pt.unit.as_ref());
        }
        // Comments would be interned here. `default_sample_type` is
        // LAST in Go's traversal (encode.go), after them — and for the
        // heap profile it is the empty string, which is already index 0,
        // so this adds a slot only for `allocs`.
        add(&mut st, self.default_sample_type.as_ref());
        return st;
    }

    // go: none — goish-only: see the module header.
    /// The index of `s` in a table built by [`Self::pre_encode`].
    fn idx(st: &[crate::gostring::string], s: &str) -> i64 {
        for (i, have) in st.iter().enumerate() {
            if (have.as_ref() as &str) == s {
                return crate::convert::int64(i);
            }
        }
        return 0;
    }

    // go: none — goish-only: see the module header.
    /// The uncompressed protobuf bytes. `WriteTo(w, 0)` gzips these.
    ///
    /// Byte-identical to Go's `internal/profile` encoder for the same
    /// profile, verified against `tools/gen_pprof_proto_ref.go`.
    pub fn marshal(&self) -> crate::goslice::slice<crate::types::byte> {
        let st = self.pre_encode();
        let mut b: Vec<u8> = Vec::new();
        for t in &self.sample_type {
            let mut m: Vec<u8> = Vec::new();
            put_int64_opt(&mut m, 1, Self::idx(&st, t.ty.as_ref()));
            put_int64_opt(&mut m, 2, Self::idx(&st, t.unit.as_ref()));
            put_bytes(&mut b, 1, &m);
        }
        for s in &self.sample {
            let mut m: Vec<u8> = Vec::new();
            put_uint64s(&mut m, 1, &s.location_id);
            for &v in &s.value {
                // NOT the _opt form: a sample value of zero is
                // meaningful, and dropping it would desynchronise
                // value[] from sample_type[].
                put_int64(&mut m, 2, v);
            }
            put_bytes(&mut b, 2, &m);
        }
        // Field 3 is mapping; goish emits none, which pprof accepts — an
        // absent mapping means addresses are not relocatable, and a
        // profile of this process does not need to be.
        for l in &self.location {
            let mut m: Vec<u8> = Vec::new();
            put_uint64_opt(&mut m, 1, l.id);
            put_uint64_opt(&mut m, 3, l.address);
            for ln in &l.line {
                let mut lm: Vec<u8> = Vec::new();
                put_uint64_opt(&mut lm, 1, ln.function_id);
                put_int64_opt(&mut lm, 2, ln.line);
                put_bytes(&mut m, 4, &lm);
            }
            put_bytes(&mut b, 4, &m);
        }
        for f in &self.function {
            let mut m: Vec<u8> = Vec::new();
            put_uint64_opt(&mut m, 1, f.id);
            put_int64_opt(&mut m, 2, Self::idx(&st, f.name.as_ref()));
            put_int64_opt(&mut m, 3, Self::idx(&st, f.system_name.as_ref()));
            put_int64_opt(&mut m, 4, Self::idx(&st, f.filename.as_ref()));
            put_int64_opt(&mut m, 5, f.start_line);
            put_bytes(&mut b, 5, &m);
        }
        for s in &st {
            // NOT the _opt form: index 0 is the empty string and must
            // occupy a slot, so every entry is written.
            put_string(&mut b, 6, s.as_bytes());
        }
        put_int64_opt(&mut b, 9, self.time_nanos);
        put_int64_opt(&mut b, 10, self.duration_nanos);
        if let Some(pt) = &self.period_type {
            let mut m: Vec<u8> = Vec::new();
            put_int64_opt(&mut m, 1, Self::idx(&st, pt.ty.as_ref()));
            put_int64_opt(&mut m, 2, Self::idx(&st, pt.unit.as_ref()));
            put_bytes(&mut b, 11, &m);
        }
        put_int64_opt(&mut b, 12, self.period);
        // Field 13 is `comment`; goish emits none. Field 14 is
        // `default_sample_type`, written in the _opt form because Go's
        // own encoder omits it when the index is 0 — the reference
        // bytes in pprof_proto_ref_smoke end at field 12, which is how
        // that is known rather than assumed.
        put_int64_opt(
            &mut b,
            14,
            Self::idx(&st, self.default_sample_type.as_ref()),
        );
        return crate::goslice::slice::__from_vec(b);
    }
}

// go: none — goish-only: Go's `Profile.Write` gzips in
// `internal/profile/profile.go`; goish keeps the compression next to the
// encoder so a caller cannot forget it.
/// The gzip-compressed protobuf, which is what `Profile.WriteTo(w, 0)`
/// must emit and what `go tool pprof` expects from a file.
///
/// `go tool pprof` also accepts the raw protobuf, so a missing gzip
/// looks fine locally and differs from Go on the wire — which is why
/// this lives here rather than at the call site.
pub fn marshal_gzip(p: &Profile) -> (crate::goslice::slice<crate::types::byte>, crate::errors::error) {
    use crate::io::Closer;
    let raw = p.marshal();
    let mut sink = crate::bytes::Buffer::default();
    {
        let mut zw = crate::compress::gzip::NewWriter(&mut sink);
        let (_, err) = zw.Write(raw);
        if err != crate::errors::nil {
            return (crate::goslice::slice::new(), err);
        }
        let err = zw.Close();
        if err != crate::errors::nil {
            return (crate::goslice::slice::new(), err);
        }
    }
    return (sink.Bytes(), crate::errors::nil);
}
