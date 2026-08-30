// go: file hash/crc32/crc32.go decls: updateCastagnoli, castagnoliInitOnce, IEEETable, updateIEEE, ieeeInitOnce, MakeTable, New, NewIEEE, digest.Size, digest.BlockSize, digest.Reset, digest.AppendBinary, digest.MarshalBinary, digest.UnmarshalBinary, digest.Clone, update, Update, digest.Write, digest.Sum32, digest.Sum, Checksum, ChecksumIEEE, tableSum
//
// The `decls:` manifest above lists crc32.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// the file's consts, types and vars there would report every one of
// them as a dropped port. They are not dropped — `Size`, `IEEE`,
// `Castagnoli`, `Koopman`, `Table`, `castagnoliTable`,
// `castagnoliTable8`, `haveCastagnoli`, `ieeeTable8`, `digest`,
// `magic` and `marshaledSize` each carry their own `// go: sdk`
// anchor below. The five Go *vars* that goish ports as functions —
// `updateCastagnoli`, `castagnoliInitOnce`, `IEEETable`, `updateIEEE`
// and `ieeeInitOnce` — are listed, because a Rust `fn` is what
// GOISH017 sees.
//
// hash/crc32/crc32.go — the 32-bit cyclic redundancy check.
//
// Polynomials are held in LSB-first (reversed) form, so the shift in
// every inner loop is a right shift and the table is indexed by the
// low byte of the running CRC.
//
// The dispatch in `update` is the part worth reading. Go keeps a
// lazily built table per predefined polynomial and picks the fastest
// available implementation once, behind a `sync.OnceFunc`, then
// selects on *table identity* at every call. goish reproduces the
// structure with the arch half answered by crc32_otherarch.rs — goish
// has no SSE 4.2 or PCLMUL — so both predefined polynomials land on
// crc32_generic.rs's slicing-by-8 path and everything else on the
// simple one, which is what Go does on any host without acceleration.
//
// Deviations from Go, each forced by a goish/Rust distinction:
//
//   * Go's `MakeTable` returns a `*Table` whose *pointer* is compared
//     against `IEEETable` and `castagnoliTable` to route the update.
//     goish has no stable interior pointer to hand out, so `MakeTable`
//     returns `Arc<Table>` and the routing compares by value. A table
//     built by `simpleMakeTable(IEEE)` is bit-identical to `IEEETable`,
//     so value comparison routes it the same way — which is the
//     behaviour a caller would expect and Go's pointer test misses.
//   * `IEEETable` is a function, not a package-level var: goish has no
//     package-level lazily initialized statics outside a lock, and the
//     table cannot be built in a `const`.
//   * Go's `updateIEEE` / `updateCastagnoli` are package-level *func
//     values* rewritten by the init-once. goish spells each as a plain
//     function that reads the lazily built table, since a func-valued
//     global would need the `dyn Fn` this project bans (§5 rule 3).
//   * `tableSum` takes `&Table`, not a nilable pointer: a goish
//     `digest` holds `Arc<Table>`, which cannot be nil, so Go's
//     `t != nil` arm is unreachable here.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use crate::encoding;
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::hash::{Cloner, Hash, Hash32};
use crate::internal::byteorder;
use crate::io;
use crate::runtime::spin::SpinLock;
use crate::sync;
use crate::types::{byte, int, uint32};

extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, Ordering};

use super::crc32_generic::{
    simpleMakeTable, simpleUpdate, slicing8Table, slicingMakeTable, slicingUpdate,
};
use super::crc32_otherarch::{
    archAvailableCastagnoli, archAvailableIEEE, archInitCastagnoli, archInitIEEE,
    archUpdateCastagnoli, archUpdateIEEE,
};

// go: sdk 1.25.5 hash/crc32/crc32.go:24-24 Size
/// `crc32.Size` — the size of a CRC-32 checksum in bytes.
pub const Size: int = 4;

// go: sdk 1.25.5 hash/crc32/crc32.go:27-41 IEEE
/// `crc32.IEEE` — by far and away the most common CRC-32 polynomial.
/// Used by ethernet (IEEE 802.3), v.42, fddi, gzip, zip, png, …
pub const IEEE: uint32 = 0xedb88320;

// go: sdk 1.25.5 hash/crc32/crc32.go:27-41 Castagnoli
/// `crc32.Castagnoli` — Castagnoli's polynomial, used in iSCSI. Has
/// better error detection characteristics than [`IEEE`].
pub const Castagnoli: uint32 = 0x82f63b78;

// go: sdk 1.25.5 hash/crc32/crc32.go:27-41 Koopman
/// `crc32.Koopman` — Koopman's polynomial. Also has better error
/// detection characteristics than [`IEEE`].
pub const Koopman: uint32 = 0xeb31d82e;

// go: sdk 1.25.5 hash/crc32/crc32.go:44-44 Table
/// `crc32.Table` — a 256-word table representing the polynomial for
/// efficient processing. The contents must not be modified.
///
/// Go's is `type Table [256]uint32`; goish wraps the array in a struct
/// so the type is nominal.
#[derive(Clone, PartialEq, Eq)]
pub struct Table {
    entries: [uint32; 256],
}

impl Table {
    // go: none — goish idiom: Go writes `t[i]` on a `*Table`, which is
    //     an array type and indexes directly. `entries` is private, so
    //     goish exposes the read through a method.
    /// Index access matching Go's `t[i]`.
    pub fn at(&self, i: usize) -> uint32 {
        return self.entries[i];
    }

    // go: none — goish idiom: the write half of `at`, used by
    //     crc32_generic.rs's table builders (Go's `t[i] = crc`).
    #[doc(hidden)]
    pub(super) fn __set(&mut self, i: usize, v: uint32) {
        self.entries[i] = v;
    }

    // go: none — goish idiom: Go's `new(Table)` zero value. A struct
    //     wrapping a private array needs a constructor to be built
    //     from another module in the package.
    #[doc(hidden)]
    pub(super) fn __zero() -> Table {
        return Table { entries: [0; 256] };
    }
}

// go: sdk 1.25.5 hash/crc32/crc32.go:78-78 castagnoliTable
/// `crc32.castagnoliTable` — the lazily initialized [`Table`] for the
/// Castagnoli polynomial. [`MakeTable`] always returns this value when
/// asked for a Castagnoli table, so [`update`] can compare against it
/// to find when the caller is using this polynomial.
static castagnoliTable: SpinLock<Option<Arc<Table>>> = SpinLock::new(None);

// go: sdk 1.25.5 hash/crc32/crc32.go:79-79 castagnoliTable8
/// `crc32.castagnoliTable8` — the slicing-by-8 table for Castagnoli.
static castagnoliTable8: SpinLock<Option<Arc<slicing8Table>>> = SpinLock::new(None);

// go: sdk 1.25.5 hash/crc32/crc32.go:81-81 haveCastagnoli
/// `crc32.haveCastagnoli` — set once [`castagnoliInitOnce`] has run, so
/// [`update`] can skip the table comparison entirely until then.
static haveCastagnoli: AtomicBool = AtomicBool::new(false);

// go: none — goish idiom: the `sync.Once` behind Go's
//     `castagnoliInitOnce` / `ieeeInitOnce` `sync.OnceFunc` values.
static castagnoliOnce: sync::Once = sync::Once::new();

// go: none — goish idiom: see `castagnoliOnce`.
static ieeeOnce: sync::Once = sync::Once::new();

// go: sdk 1.25.5 hash/crc32/crc32.go:83-98 castagnoliInitOnce
/// `crc32.castagnoliInitOnce()` — build the Castagnoli tables and
/// choose the update implementation, once.
fn castagnoliInitOnce() {
    castagnoliOnce.Do(|| {
        // Go: castagnoliTable = simpleMakeTable(Castagnoli)
        *castagnoliTable.lock() = Some(Arc::new(simpleMakeTable(Castagnoli)));
        // Go: if archAvailableCastagnoli() { archInitCastagnoli(); … }
        if archAvailableCastagnoli() {
            archInitCastagnoli();
        } else {
            // Go: castagnoliTable8 = slicingMakeTable(Castagnoli)
            *castagnoliTable8.lock() = Some(slicingMakeTable(Castagnoli));
        }
        // Go: haveCastagnoli.Store(true)
        haveCastagnoli.store(true, Ordering::Release);
    });
}

// go: sdk 1.25.5 hash/crc32/crc32.go:80-80 updateCastagnoli
/// `crc32.updateCastagnoli(crc, p)` — Go stores this as a func value
/// rewritten by the init-once. goish spells it as a function that makes
/// the same choice on each call: a func-valued global would need the
/// `dyn Fn` this project bans.
fn updateCastagnoli(crc: uint32, p: &[byte]) -> uint32 {
    if archAvailableCastagnoli() {
        return archUpdateCastagnoli(crc, p);
    }
    // Go: return slicingUpdate(crc, castagnoliTable8, p)
    let t = castagnoliTable8.lock().as_ref().unwrap().clone();
    return slicingUpdate(crc, &t, p);
}

// go: sdk 1.25.5 hash/crc32/crc32.go:101-101 IEEETable
/// `crc32.IEEETable` — the table for the [`IEEE`] polynomial. Go
/// initializes a package-level `*Table` at program start; goish builds
/// it under a lock on first use and hands back a handle.
pub fn IEEETable() -> Arc<Table> {
    static SLOT: SpinLock<Option<Arc<Table>>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(Arc::new(simpleMakeTable(IEEE)));
    }
    return g.as_ref().unwrap().clone();
}

// go: sdk 1.25.5 hash/crc32/crc32.go:104-104 ieeeTable8
/// `crc32.ieeeTable8` — the slicing-by-8 table for [`IEEE`].
static ieeeTable8: SpinLock<Option<Arc<slicing8Table>>> = SpinLock::new(None);

// go: sdk 1.25.5 hash/crc32/crc32.go:107-118 ieeeInitOnce
/// `crc32.ieeeInitOnce()` — build the IEEE slicing table and choose the
/// update implementation, once.
fn ieeeInitOnce() {
    ieeeOnce.Do(|| {
        // Go: if archAvailableIEEE() { archInitIEEE(); … }
        if archAvailableIEEE() {
            archInitIEEE();
        } else {
            // Go: ieeeTable8 = slicingMakeTable(IEEE)
            *ieeeTable8.lock() = Some(slicingMakeTable(IEEE));
        }
    });
}

// go: sdk 1.25.5 hash/crc32/crc32.go:105-105 updateIEEE
/// `crc32.updateIEEE(crc, p)` — see [`updateCastagnoli`] for why this
/// is a function rather than the func-valued global Go uses.
fn updateIEEE(crc: uint32, p: &[byte]) -> uint32 {
    if archAvailableIEEE() {
        return archUpdateIEEE(crc, p);
    }
    // Go: return slicingUpdate(crc, ieeeTable8, p)
    let t = ieeeTable8.lock().as_ref().unwrap().clone();
    return slicingUpdate(crc, &t, p);
}

// go: sdk 1.25.5 hash/crc32/crc32.go:122-133 MakeTable
/// `crc32.MakeTable(poly)` — a [`Table`] constructed from `poly`. The
/// contents of the returned table must not be modified.
pub fn MakeTable(poly: uint32) -> Arc<Table> {
    // Go: switch poly { case IEEE: ieeeInitOnce(); return IEEETable … }
    if poly == IEEE {
        ieeeInitOnce();
        return IEEETable();
    }
    if poly == Castagnoli {
        castagnoliInitOnce();
        return castagnoliTable.lock().as_ref().unwrap().clone();
    }
    return Arc::new(simpleMakeTable(poly));
}

// go: sdk 1.25.5 hash/crc32/crc32.go:136-139 digest
/// `crc32.digest` — the partial evaluation of a checksum.
#[derive(Clone)]
pub struct digest {
    // Go: crc uint32
    crc: uint32,
    // Go: tab *Table
    tab: Arc<Table>,
}

// go: sdk 1.25.5 hash/crc32/crc32.go:146-151 New
/// `crc32.New(tab)` — a new `hash.Hash32` computing the CRC-32
/// checksum using the polynomial represented by `tab`. Its `Sum`
/// method lays the value out in big-endian byte order. The result also
/// implements `encoding.BinaryMarshaler` / `encoding.BinaryUnmarshaler`.
pub fn New(tab: Arc<Table>) -> digest {
    // Go: if tab == IEEETable { ieeeInitOnce() }
    if *tab == *IEEETable() {
        ieeeInitOnce();
    }
    // Go: return &digest{0, tab}
    return digest { crc: 0, tab };
}

// go: sdk 1.25.5 hash/crc32/crc32.go:158-158 NewIEEE
/// `crc32.NewIEEE()` — a new `hash.Hash32` using the [`IEEE`]
/// polynomial.
pub fn NewIEEE() -> digest {
    // Go: return New(IEEETable)
    return New(IEEETable());
}

// go: sdk 1.25.5 hash/crc32/crc32.go:166-169 magic
const magic: &[byte] = b"crc\x01";

// go: sdk 1.25.5 hash/crc32/crc32.go:166-169 marshaledSize
///
/// Go types this `int`; goish keeps it `usize` because every use is a
/// buffer length compared against `len(b)`.
const marshaledSize: usize = magic.len() + 4 + 4;

impl digest {
    // go: sdk 1.25.5 hash/crc32/crc32.go:171-176 digest.AppendBinary
    /// `(*digest).AppendBinary(b)` — append the marshaled state to `b`.
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        // Go: b = append(b, magic...)
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(magic);
        // Go: b = byteorder.BEAppendUint32(b, tableSum(d.tab))
        let acc = byteorder::BEAppendUint32(slice::__from_vec(out), tableSum(&self.tab));
        // Go: b = byteorder.BEAppendUint32(b, d.crc); return b, nil
        return (byteorder::BEAppendUint32(acc, self.crc), nil);
    }

    // go: sdk 1.25.5 hash/crc32/crc32.go:178-181 digest.MarshalBinary
    /// `(*digest).MarshalBinary()` — the digest's internal state.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        // Go: return d.AppendBinary(make([]byte, 0, marshaledSize))
        let buf: Vec<byte> = Vec::with_capacity(marshaledSize);
        return self.AppendBinary(slice::__from_vec(buf));
    }

    // go: sdk 1.25.5 hash/crc32/crc32.go:183-195 digest.UnmarshalBinary
    /// `(*digest).UnmarshalBinary(b)` — restore state produced by
    /// [`digest::MarshalBinary`]. The table is not carried in the
    /// state; its IEEE checksum is, so a mismatched table is rejected.
    pub fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        let raw: &[byte] = &b;
        // Go: if len(b) < len(magic) || string(b[:len(magic)]) != magic
        if raw.len() < magic.len() || &raw[..magic.len()] != magic {
            return crate::errors::New("hash/crc32: invalid hash state identifier");
        }
        // Go: if len(b) != marshaledSize
        if raw.len() != marshaledSize {
            return crate::errors::New("hash/crc32: invalid hash state size");
        }
        // Go: if tableSum(d.tab) != byteorder.BEUint32(b[4:])
        let want = byteorder::BEUint32(slice::__from_vec(raw[4..8].to_vec()));
        if tableSum(&self.tab) != want {
            return crate::errors::New("hash/crc32: tables do not match");
        }
        // Go: d.crc = byteorder.BEUint32(b[8:]); return nil
        self.crc = byteorder::BEUint32(slice::__from_vec(raw[8..].to_vec()));
        return nil;
    }

    // go: sdk 1.25.5 hash/crc32/crc32.go:197-200 digest.Clone
    /// `(*digest).Clone()` — an independent copy of this digest's
    /// state. Never fails, so the error is always nil, as in Go.
    pub fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        // Go: r := *d; return &r, nil
        let r = Clone::clone(self);
        return (Box::new(r), nil);
    }
}

// go: sdk 1.25.5 hash/crc32/crc32.go:202-214 update
/// `crc32.update(crc, tab, p, checkInitIEEE)` — route to the fastest
/// implementation for `tab`'s polynomial.
///
/// Takes a borrowed `&[byte]`, which the generic algorithms below walk
/// as a cursor. It is unexported, so no goish API surface sees it.
fn update(crc: uint32, tab: &Table, p: &[byte], checkInitIEEE: bool) -> uint32 {
    // Go: case haveCastagnoli.Load() && tab == castagnoliTable
    if haveCastagnoli.load(Ordering::Acquire) {
        let ct = castagnoliTable.lock().as_ref().unwrap().clone();
        if *tab == *ct {
            return updateCastagnoli(crc, p);
        }
    }
    // Go: case tab == IEEETable
    if *tab == *IEEETable() {
        // Go: if checkInitIEEE { ieeeInitOnce() }
        if checkInitIEEE {
            ieeeInitOnce();
        }
        return updateIEEE(crc, p);
    }
    // Go: default: return simpleUpdate(crc, tab, p)
    return simpleUpdate(crc, tab, p);
}

// go: sdk 1.25.5 hash/crc32/crc32.go:217-221 Update
/// `crc32.Update(crc, tab, p)` — the result of adding the bytes in `p`
/// to `crc`.
pub fn Update(crc: uint32, tab: &Table, p: slice<byte>) -> uint32 {
    // Go: because IEEETable is exported, IEEE may be used without a
    // call to MakeTable, so this path has to force initialization.
    let raw: &[byte] = &p;
    return update(crc, tab, raw, true);
}

// go: sdk 1.25.5 hash/crc32/crc32.go:239-239 Checksum
/// `crc32.Checksum(data, tab)` — the CRC-32 checksum of `data` using
/// the polynomial represented by `tab`.
pub fn Checksum(data: slice<byte>, tab: &Table) -> uint32 {
    // Go: return Update(0, tab, data)
    return Update(0, tab, data);
}

// go: sdk 1.25.5 hash/crc32/crc32.go:243-246 ChecksumIEEE
/// `crc32.ChecksumIEEE(data)` — the CRC-32 checksum of `data` using
/// the [`IEEE`] polynomial.
pub fn ChecksumIEEE(data: slice<byte>) -> uint32 {
    // Go: ieeeInitOnce(); return updateIEEE(0, data)
    ieeeInitOnce();
    let raw: &[byte] = &data;
    return updateIEEE(0, raw);
}

// go: sdk 1.25.5 hash/crc32/crc32.go:249-258 tableSum
/// `crc32.tableSum(t)` — the IEEE checksum of table `t`, used to detect
/// a marshaled state being restored into a digest built on a different
/// polynomial.
///
/// Go's parameter is a nilable `*Table` and its body guards on
/// `t != nil`; a goish `digest` holds `Arc<Table>`, so the nil arm has
/// no reachable caller and is not reproduced. Go's fixed `[1024]byte`
/// scratch array becomes a `Vec` with the same capacity.
fn tableSum(t: &Table) -> uint32 {
    // Go: var a [1024]byte; b := a[:0]
    let mut b: slice<byte> = slice::__from_vec(Vec::with_capacity(1024));
    // Go: for _, x := range t { b = byteorder.BEAppendUint32(b, x) }
    let mut i: usize = 0;
    while i < 256 {
        b = byteorder::BEAppendUint32(b, t.at(i));
        i += 1;
    }
    // Go: return ChecksumIEEE(b)
    return ChecksumIEEE(b);
}

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registries for the types this package declares. See AGENTS.md §9b.
/// Register `digest` into the `hash` / `io` / `encoding` registries.
/// Idempotent; called from `goish::init()`.
pub fn register_crc32_impls() {
    crate::hash::__goish_register_Hash_impl::<digest>();
    crate::hash::__goish_register_Cloner_impl::<digest>();
    crate::io::__goish_register_Writer_impl::<digest>();
    encoding::__goish_register_BinaryMarshaler_impl::<digest>();
    encoding::__goish_register_BinaryAppender_impl::<digest>();
    encoding::__goish_register_BinaryUnmarshaler_impl::<digest>();
}

// ─── hash.Hash32 / hash.Cloner / encoding interface impls ─────────────
//
// Go's `digest` satisfies these structurally. goish's interfaces are
// nominal, so each impl is spelled out; the marshaling ones forward to
// the inherent methods above.

impl io::Writer for digest {
    // go: sdk 1.25.5 hash/crc32/crc32.go:223-228 digest.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: digests are only created through New(), which takes care
        // of initialization, so this passes checkInitIEEE = false.
        let raw: &[byte] = &p;
        let tab = self.tab.clone();
        self.crc = update(self.crc, &tab, raw, false);
        // Go: return len(p), nil
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
    // go: sdk 1.25.5 hash/crc32/crc32.go:232-235 digest.Sum
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: s := d.Sum32()
        let s = self.crc;
        // Go: return append(in, byte(s>>24), byte(s>>16), byte(s>>8), byte(s))
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(&s.to_be_bytes());
        return slice::__from_vec(out);
    }
    // go: sdk 1.25.5 hash/crc32/crc32.go:164-164 digest.Reset
    fn Reset(&mut self) {
        // Go: d.crc = 0
        self.crc = 0;
    }
    // go: sdk 1.25.5 hash/crc32/crc32.go:160-160 digest.Size
    fn Size(&self) -> int {
        return Size;
    }
    // go: sdk 1.25.5 hash/crc32/crc32.go:162-162 digest.BlockSize
    fn BlockSize(&self) -> int {
        return 1;
    }
}

impl Hash32 for digest {
    // go: sdk 1.25.5 hash/crc32/crc32.go:230-230 digest.Sum32
    fn Sum32(&self) -> uint32 {
        return self.crc;
    }
}

impl Cloner for digest {
    // go: sdk 1.25.5 hash/crc32/crc32.go:197-200 digest.Clone
    fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        return digest::Clone(self);
    }
}

impl encoding::BinaryMarshaler for digest {
    // go: sdk 1.25.5 hash/crc32/crc32.go:178-181 digest.MarshalBinary
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
    // go: sdk 1.25.5 hash/crc32/crc32.go:171-176 digest.AppendBinary
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
    // go: sdk 1.25.5 hash/crc32/crc32.go:183-195 digest.UnmarshalBinary
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
