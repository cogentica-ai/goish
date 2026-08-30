// go: file hash/crc64/crc64.go decls: buildSlicing8TablesOnce, buildSlicing8Tables, MakeTable, makeTable, makeSlicingBy8Table, New, digest.Size, digest.BlockSize, digest.Reset, digest.AppendBinary, digest.MarshalBinary, digest.UnmarshalBinary, digest.Clone, update, Update, digest.Write, digest.Sum64, digest.Sum, Checksum, tableSum
//
// The `decls:` manifest above lists crc64.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// the file's consts, types and vars there would report every one of
// them as a dropped port. They are not dropped — `Size`, `ISO`, `ECMA`,
// `Table`, `slicing8TableISO`, `slicing8TableECMA`, `digest`, `magic`
// and `marshaledSize` each carry their own `// go: sdk` anchor below,
// which is what GOISH019/020/021 read.
//
// hash/crc64/crc64.go — the 64-bit cyclic redundancy check.
//
// The polynomial is held in LSB-first form, so the shift in every inner
// loop is a right shift and the table is indexed by the low byte of the
// running CRC. Go's `update` has two paths and this port keeps both:
// the byte-at-a-time table lookup, and the slicing-by-8 loop that eats
// eight bytes per round out of a `[8]Table` helper table. The helper is
// pre-built for the two predefined polynomials and built on demand for
// any other one — but only past 2 KiB of input, because below that the
// 16 KiB of table construction costs more than it saves. That threshold
// and the `len(p) >= 64` guard around the whole fast path are Go's, and
// are reproduced rather than re-derived.
//
// Deviations from Go, each forced by a goish/Rust distinction rather
// than chosen:
//
//   * Go's `MakeTable` returns a `*Table` aliasing `slicing8TableISO[0]`
//     for the predefined polynomials. goish has no interior-pointer into
//     a shared array, so it returns `Arc<Table>` — a handle with the
//     same sharing semantics. `update` selects its fast path by *value*
//     comparison (`*tab == slicing8TableECMA[0]`), which is what Go
//     writes too, so the aliasing is never load-bearing.
//   * `tableSum` takes `&Table`, not a nilable pointer. Go's `t != nil`
//     guard exists because `MakeTable` can be handed a nil `*Table`;
//     a goish `digest` holds `Arc<Table>`, which cannot be nil, so the
//     nil arm is unreachable here.
//   * Go's `buildSlicing8TablesOnce` is a `sync.OnceFunc` *variable*;
//     goish spells it as a function over a `sync::Once` static, since a
//     package-level closure value has no goish equivalent.
//   * `ISOTable()` / `ECMATable()` have no Go counterpart — they are the
//     goish spelling of the `crc64.MakeTable(crc64.ISO)` idiom and
//     predate this file. They are thin wrappers over `MakeTable`.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use crate::convert::{byte as tobyte, uint64 as touint64};
use crate::encoding;
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::hash::{Cloner, Hash, Hash64};
use crate::internal::byteorder;
use crate::io;
use crate::runtime::spin::SpinLock;
use crate::sync;
use crate::types::{byte, int, uint64};

extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

// go: sdk 1.25.5 hash/crc64/crc64.go:18-18 Size
/// `crc64.Size` — the size of a CRC-64 checksum in bytes.
pub const Size: int = 8;

// go: sdk 1.25.5 hash/crc64/crc64.go:21-27 ISO
/// `crc64.ISO` — the ISO polynomial, defined in ISO 3309 and used in HDLC.
pub const ISO: uint64 = 0xD800000000000000;

// go: sdk 1.25.5 hash/crc64/crc64.go:21-27 ECMA
/// `crc64.ECMA` — the ECMA polynomial, defined in ECMA 182.
pub const ECMA: uint64 = 0xC96C5795D7870F42;

// go: sdk 1.25.5 hash/crc64/crc64.go:30-30 Table
/// `crc64.Table` — a 256-word table representing the polynomial for
/// efficient processing. The contents must not be modified.
///
/// Go's is `type Table [256]uint64`; goish wraps the array in a struct
/// so the type is nominal (a bare array alias could not carry the
/// `at` accessor or take part in `PartialEq` dispatch below).
#[derive(Clone, PartialEq, Eq)]
pub struct Table {
    entries: [uint64; 256],
}

impl Table {
    // go: none — goish idiom: Go writes `t[i]` on a `*Table`, which is
    //     an array type and indexes directly. `entries` is private, so
    //     goish exposes the read through a method.
    /// Index access matching Go's `t[i]`.
    pub fn at(&self, i: usize) -> uint64 {
        return self.entries[i];
    }
}

// go: sdk 1.25.5 hash/crc64/crc64.go:32-35 slicing8TableISO
/// `crc64.slicing8TableISO` — the ISO helper table, built once.
static slicing8TableISO: SpinLock<Option<Arc<[Table; 8]>>> = SpinLock::new(None);

// go: sdk 1.25.5 hash/crc64/crc64.go:32-35 slicing8TableECMA
/// `crc64.slicing8TableECMA` — the ECMA helper table, built once.
static slicing8TableECMA: SpinLock<Option<Arc<[Table; 8]>>> = SpinLock::new(None);

// go: none — goish idiom: the `sync.Once` behind the `sync.OnceFunc`
//     value Go stores in `buildSlicing8TablesOnce`.
static buildOnce: sync::Once = sync::Once::new();

// go: sdk 1.25.5 hash/crc64/crc64.go:37-37 buildSlicing8TablesOnce
/// `crc64.buildSlicing8TablesOnce()` — run [`buildSlicing8Tables`] on
/// the first call and never again.
fn buildSlicing8TablesOnce() {
    buildOnce.Do(buildSlicing8Tables);
}

// go: sdk 1.25.5 hash/crc64/crc64.go:39-42 buildSlicing8Tables
/// `crc64.buildSlicing8Tables()` — fill both predefined helper tables.
fn buildSlicing8Tables() {
    // Go: slicing8TableISO = makeSlicingBy8Table(makeTable(ISO))
    let iso = Arc::new(makeSlicingBy8Table(&makeTable(ISO)));
    *slicing8TableISO.lock() = Some(iso);
    // Go: slicing8TableECMA = makeSlicingBy8Table(makeTable(ECMA))
    let ecma = Arc::new(makeSlicingBy8Table(&makeTable(ECMA)));
    *slicing8TableECMA.lock() = Some(ecma);
}

// go: none — goish idiom: Go reads the package-level `*[8]Table` vars
//     directly once the OnceFunc has run; goish's are lazily filled
//     slots, so reaching one is a call. The returned `Arc` is a handle
//     clone, not a copy of the 16 KiB table.
fn slicing8(slot: &SpinLock<Option<Arc<[Table; 8]>>>) -> Arc<[Table; 8]> {
    buildSlicing8TablesOnce();
    let g = slot.lock();
    return g.as_ref().unwrap().clone();
}

// go: sdk 1.25.5 hash/crc64/crc64.go:46-56 MakeTable
/// `crc64.MakeTable(poly)` — a [`Table`] constructed from `poly`. The
/// contents of the returned table must not be modified.
pub fn MakeTable(poly: uint64) -> Arc<Table> {
    // Go: buildSlicing8TablesOnce()
    buildSlicing8TablesOnce();
    // Go: switch poly { case ISO: return &slicing8TableISO[0] ... }
    if poly == ISO {
        return Arc::new(slicing8(&slicing8TableISO)[0].clone());
    }
    if poly == ECMA {
        return Arc::new(slicing8(&slicing8TableECMA)[0].clone());
    }
    return Arc::new(makeTable(poly));
}

// go: sdk 1.25.5 hash/crc64/crc64.go:58-72 makeTable
/// `crc64.makeTable(poly)` — the plain 256-entry table for `poly`.
fn makeTable(poly: uint64) -> Table {
    // Go: t := new(Table)
    let mut t = Table { entries: [0; 256] };
    // Go: for i := 0; i < 256; i++
    let mut i: usize = 0;
    while i < 256 {
        // Go: crc := uint64(i)
        let mut crc: uint64 = touint64(i);
        // Go: for j := 0; j < 8; j++
        let mut j: usize = 0;
        while j < 8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        // Go: t[i] = crc
        t.entries[i] = crc;
        i += 1;
    }
    return t;
}

// go: sdk 1.25.5 hash/crc64/crc64.go:74-85 makeSlicingBy8Table
/// `crc64.makeSlicingBy8Table(t)` — the eight-deep helper table that
/// lets `update` consume eight input bytes per round.
fn makeSlicingBy8Table(t: &Table) -> [Table; 8] {
    // Go: var helperTable [8]Table; helperTable[0] = *t
    let mut helperTable: [Table; 8] = core::array::from_fn(|_| Table { entries: [0; 256] });
    helperTable[0] = t.clone();
    // Go: for i := 0; i < 256; i++
    let mut i: usize = 0;
    while i < 256 {
        // Go: crc := t[i]
        let mut crc = t.entries[i];
        // Go: for j := 1; j < 8; j++
        let mut j: usize = 1;
        while j < 8 {
            // Go: crc = t[crc&0xff] ^ (crc >> 8)
            crc = t.entries[usize::from(tobyte(crc))] ^ (crc >> 8);
            // Go: helperTable[j][i] = crc
            helperTable[j].entries[i] = crc;
            j += 1;
        }
        i += 1;
    }
    return helperTable;
}

// go: sdk 1.25.5 hash/crc64/crc64.go:88-91 digest
/// `crc64.digest` — the partial evaluation of a checksum.
#[derive(Clone)]
pub struct digest {
    // Go: crc uint64
    crc: uint64,
    // Go: tab *Table
    tab: Arc<Table>,
}

// go: sdk 1.25.5 hash/crc64/crc64.go:98-98 New
/// `crc64.New(tab)` — a new `hash.Hash64` computing the CRC-64 checksum
/// using the polynomial represented by `tab`. Its `Sum` method lays the
/// value out in big-endian byte order. The result also implements
/// `encoding.BinaryMarshaler` / `encoding.BinaryUnmarshaler`, so a
/// running hash can be saved and resumed.
pub fn New(tab: Arc<Table>) -> digest {
    // Go: return &digest{0, tab}
    return digest { crc: 0, tab };
}

// go: sdk 1.25.5 hash/crc64/crc64.go:106-109 magic
const magic: &[byte] = b"crc\x02";

// go: sdk 1.25.5 hash/crc64/crc64.go:106-109 marshaledSize
///
/// Go types this `int`; goish keeps it `usize` because every use is a
/// buffer length compared against `len(b)`.
const marshaledSize: usize = magic.len() + 8 + 8;

impl digest {
    // go: sdk 1.25.5 hash/crc64/crc64.go:111-116 digest.AppendBinary
    /// `(*digest).AppendBinary(b)` — append the marshaled state to `b`.
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        // Go: b = append(b, magic...)
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(magic);
        // Go: b = byteorder.BEAppendUint64(b, tableSum(d.tab))
        let acc = byteorder::BEAppendUint64(slice::__from_vec(out), tableSum(&self.tab));
        // Go: b = byteorder.BEAppendUint64(b, d.crc); return b, nil
        return (byteorder::BEAppendUint64(acc, self.crc), nil);
    }

    // go: sdk 1.25.5 hash/crc64/crc64.go:118-120 digest.MarshalBinary
    /// `(*digest).MarshalBinary()` — the digest's internal state.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        // Go: return d.AppendBinary(make([]byte, 0, marshaledSize))
        let buf: Vec<byte> = Vec::with_capacity(marshaledSize);
        return self.AppendBinary(slice::__from_vec(buf));
    }

    // go: sdk 1.25.5 hash/crc64/crc64.go:122-134 digest.UnmarshalBinary
    /// `(*digest).UnmarshalBinary(b)` — restore state produced by
    /// [`digest::MarshalBinary`]. The table is not carried in the state;
    /// its ISO checksum is, so a mismatched table is rejected.
    pub fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        let raw: &[byte] = &b;
        // Go: if len(b) < len(magic) || string(b[:len(magic)]) != magic
        if raw.len() < magic.len() || &raw[..magic.len()] != magic {
            return crate::errors::New("hash/crc64: invalid hash state identifier");
        }
        // Go: if len(b) != marshaledSize
        if raw.len() != marshaledSize {
            return crate::errors::New("hash/crc64: invalid hash state size");
        }
        // Go: if tableSum(d.tab) != byteorder.BEUint64(b[4:])
        let want = byteorder::BEUint64(slice::__from_vec(raw[4..12].to_vec()));
        if tableSum(&self.tab) != want {
            return crate::errors::New("hash/crc64: tables do not match");
        }
        // Go: d.crc = byteorder.BEUint64(b[12:]); return nil
        self.crc = byteorder::BEUint64(slice::__from_vec(raw[12..].to_vec()));
        return nil;
    }

    // go: sdk 1.25.5 hash/crc64/crc64.go:136-139 digest.Clone
    /// `(*digest).Clone()` — an independent copy of this digest's state.
    /// Never fails, so the error is always nil, as in Go.
    pub fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        // Go: r := *d; return &r, nil
        let r = Clone::clone(self);
        return (Box::new(r), nil);
    }
}

// go: sdk 1.25.5 hash/crc64/crc64.go:141-178 update
/// `crc64.update(crc, tab, p)` — extend `crc` by the bytes of `p`.
///
/// Takes a borrowed `&[byte]` rather than `slice<byte>`: the
/// slicing-by-8 loop walks a cursor forward eight bytes at a time
/// (Go's `p = p[8:]`), and re-wrapping a goish slice per round would
/// allocate inside the hot loop. It is unexported, so no goish API
/// surface sees the borrow.
fn update(crc: uint64, tab: &Table, p: &[byte]) -> uint64 {
    // Go: buildSlicing8TablesOnce()
    buildSlicing8TablesOnce();
    // Go: crc = ^crc
    let mut crc = !crc;
    let mut q: &[byte] = p;
    // Go: for len(p) >= 64 — table comparison is expensive, so it is
    // avoided entirely for small inputs.
    while q.len() >= 64 {
        let helperTable: Arc<[Table; 8]>;
        let ecma = slicing8(&slicing8TableECMA);
        let iso = slicing8(&slicing8TableISO);
        if *tab == ecma[0] {
            helperTable = ecma;
        } else if *tab == iso[0] {
            helperTable = iso;
        } else if q.len() >= 2048 {
            // Go: for smaller sizes creating the extended table takes
            // too much time; 2k is the measured threshold.
            helperTable = Arc::new(makeSlicingBy8Table(tab));
        } else {
            break;
        }
        // Go: update using slicing-by-8
        while q.len() > 8 {
            // Go: crc ^= byteorder.LEUint64(p)
            let mut w: [byte; 8] = [0; 8];
            w.copy_from_slice(&q[..8]);
            crc ^= uint64::from_le_bytes(w);
            crc = helperTable[7].entries[usize::from(tobyte(crc))]
                ^ helperTable[6].entries[usize::from(tobyte(crc >> 8))]
                ^ helperTable[5].entries[usize::from(tobyte(crc >> 16))]
                ^ helperTable[4].entries[usize::from(tobyte(crc >> 24))]
                ^ helperTable[3].entries[usize::from(tobyte(crc >> 32))]
                ^ helperTable[2].entries[usize::from(tobyte(crc >> 40))]
                ^ helperTable[1].entries[usize::from(tobyte(crc >> 48))]
                ^ helperTable[0].entries[usize::from(tobyte(crc >> 56))];
            // Go: p = p[8:]
            q = &q[8..];
        }
    }
    // Go: for _, v := range p — reminders or small sizes.
    let mut i: usize = 0;
    while i < q.len() {
        // Go: crc = tab[byte(crc)^v] ^ (crc >> 8)
        crc = tab.entries[usize::from(tobyte(crc) ^ q[i])] ^ (crc >> 8);
        i += 1;
    }
    // Go: return ^crc
    return !crc;
}

// go: sdk 1.25.5 hash/crc64/crc64.go:181-183 Update
/// `crc64.Update(crc, tab, p)` — the result of adding the bytes in `p`
/// to `crc`.
pub fn Update(crc: uint64, tab: &Table, p: slice<byte>) -> uint64 {
    let raw: &[byte] = &p;
    return update(crc, tab, raw);
}

// go: sdk 1.25.5 hash/crc64/crc64.go:199-199 Checksum
/// `crc64.Checksum(data, tab)` — the CRC-64 checksum of `data` using
/// the polynomial represented by `tab`.
pub fn Checksum(data: slice<byte>, tab: &Table) -> uint64 {
    let raw: &[byte] = &data;
    return update(0, tab, raw);
}

// go: sdk 1.25.5 hash/crc64/crc64.go:202-211 tableSum
/// `crc64.tableSum(t)` — the ISO checksum of table `t`, used to detect
/// a marshaled state being restored into a digest built on a different
/// polynomial.
///
/// Go's parameter is a nilable `*Table` and its body guards on
/// `t != nil`; a goish `digest` holds `Arc<Table>`, so the nil arm has
/// no reachable caller and is not reproduced. Go's fixed `[2048]byte`
/// scratch array becomes a `Vec` with the same capacity.
fn tableSum(t: &Table) -> uint64 {
    // Go: var a [2048]byte; b := a[:0]
    let mut b: slice<byte> = slice::__from_vec(Vec::with_capacity(2048));
    // Go: for _, x := range t { b = byteorder.BEAppendUint64(b, x) }
    let mut i: usize = 0;
    while i < 256 {
        b = byteorder::BEAppendUint64(b, t.entries[i]);
        i += 1;
    }
    // Go: return Checksum(b, MakeTable(ISO))
    return Checksum(b, &MakeTable(ISO));
}

// ─── goish-only table accessors ───────────────────────────────────────

// go: none — goish idiom: the spelling of Go's `crc64.MakeTable(crc64.ISO)`
//     that this package shipped before `MakeTable` returned a handle.
//     Kept so existing callers keep compiling; it is now a wrapper.
/// The ISO polynomial table.
pub fn ISOTable() -> Arc<Table> {
    return MakeTable(ISO);
}

// go: none — goish idiom: see [`ISOTable`].
/// The ECMA polynomial table.
pub fn ECMATable() -> Arc<Table> {
    return MakeTable(ECMA);
}

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registries for the types this package declares. See AGENTS.md §9b.
/// Register `digest` into the `hash` / `io` / `encoding` registries.
/// Idempotent; called from `goish::init()`.
pub fn register_crc64_impls() {
    crate::hash::__goish_register_Hash_impl::<digest>();
    crate::hash::__goish_register_Cloner_impl::<digest>();
    crate::io::__goish_register_Writer_impl::<digest>();
    encoding::__goish_register_BinaryMarshaler_impl::<digest>();
    encoding::__goish_register_BinaryAppender_impl::<digest>();
    encoding::__goish_register_BinaryUnmarshaler_impl::<digest>();
}

// ─── hash.Hash64 / hash.Cloner / encoding interface impls ─────────────
//
// Go's `digest` satisfies these structurally. goish's interfaces are
// nominal, so each impl is spelled out; the marshaling ones forward to
// the inherent methods above.

impl io::Writer for digest {
    // go: sdk 1.25.5 hash/crc64/crc64.go:185-188 digest.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: d.crc = update(d.crc, d.tab, p); return len(p), nil
        let raw: &[byte] = &p;
        let tab = self.tab.clone();
        self.crc = update(self.crc, &tab, raw);
        return (int::try_from(raw.len()).unwrap_or(0), nil);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see `__goish_as_dyn_any`.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl Hash for digest {
    // go: sdk 1.25.5 hash/crc64/crc64.go:192-195 digest.Sum
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: s := d.Sum64()
        let s = self.crc;
        // Go: return append(in, byte(s>>56), …, byte(s))
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(&s.to_be_bytes());
        return slice::__from_vec(out);
    }
    // go: sdk 1.25.5 hash/crc64/crc64.go:104-104 digest.Reset
    fn Reset(&mut self) {
        // Go: d.crc = 0
        self.crc = 0;
    }
    // go: sdk 1.25.5 hash/crc64/crc64.go:100-100 digest.Size
    fn Size(&self) -> int {
        return Size;
    }
    // go: sdk 1.25.5 hash/crc64/crc64.go:102-102 digest.BlockSize
    fn BlockSize(&self) -> int {
        return 1;
    }
}

impl Hash64 for digest {
    // go: sdk 1.25.5 hash/crc64/crc64.go:190-190 digest.Sum64
    fn Sum64(&self) -> uint64 {
        return self.crc;
    }
}

impl Cloner for digest {
    // go: sdk 1.25.5 hash/crc64/crc64.go:136-139 digest.Clone
    fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        return digest::Clone(self);
    }
}

impl encoding::BinaryMarshaler for digest {
    // go: sdk 1.25.5 hash/crc64/crc64.go:118-120 digest.MarshalBinary
    fn MarshalBinary(&self) -> (slice<byte>, error) {
        return digest::MarshalBinary(self);
    }
    // go: none — goish idiom: see `io::Writer::__goish_as_dyn_any`.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see `io::Writer::__goish_as_dyn_any`.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl encoding::BinaryAppender for digest {
    // go: sdk 1.25.5 hash/crc64/crc64.go:111-116 digest.AppendBinary
    fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        return digest::AppendBinary(self, b);
    }
    // go: none — goish idiom: see `io::Writer::__goish_as_dyn_any`.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see `io::Writer::__goish_as_dyn_any`.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl encoding::BinaryUnmarshaler for digest {
    // go: sdk 1.25.5 hash/crc64/crc64.go:122-134 digest.UnmarshalBinary
    fn UnmarshalBinary(&mut self, data: slice<byte>) -> error {
        return digest::UnmarshalBinary(self, data);
    }
    // go: none — goish idiom: see `io::Writer::__goish_as_dyn_any`.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see `io::Writer::__goish_as_dyn_any`.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}
