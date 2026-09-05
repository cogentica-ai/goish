// sync/atomic/doc_64 — Go 1.25.5 src/sync/atomic/doc_64.go.
//
// One `.rs` per `.go` (§33). Go splits the 64-bit atomics into their
// own file because 32-bit platforms cannot guarantee the alignment
// they need. goish is amd64-only, so they are always available and
// this file exists for provenance rather than for a build constraint.

#![allow(non_snake_case)]

use super::type_::{Int64, Uint64};

// go: sdk 1.25.5 sync/atomic/doc_64.go:42-42 AddInt64
#[inline]
pub fn AddInt64(addr: &Int64, delta: i64) -> i64 {
    return addr.Add(delta);
}

// go: sdk 1.25.5 sync/atomic/doc_64.go:51-51 AddUint64
#[inline]
pub fn AddUint64(addr: &Uint64, delta: u64) -> u64 {
    return addr.Add(delta);
}

// go: sdk 1.25.5 sync/atomic/doc_64.go:86-86 LoadInt64
#[inline]
pub fn LoadInt64(addr: &Int64) -> i64 {
    return addr.Load();
}

// go: sdk 1.25.5 sync/atomic/doc_64.go:93-93 LoadUint64
#[inline]
pub fn LoadUint64(addr: &Uint64) -> u64 {
    return addr.Load();
}

// go: sdk 1.25.5 sync/atomic/doc_64.go:100-100 StoreInt64
#[inline]
pub fn StoreInt64(addr: &Int64, v: i64) {
    return addr.Store(v);
}

// go: sdk 1.25.5 sync/atomic/doc_64.go:107-107 StoreUint64
#[inline]
pub fn StoreUint64(addr: &Uint64, v: u64) {
    return addr.Store(v);
}

// go: sdk 1.25.5 sync/atomic/doc_64.go:14-14 SwapInt64
#[inline]
pub fn SwapInt64(addr: &Int64, new: i64) -> i64 {
    return addr.Swap(new);
}

// go: sdk 1.25.5 sync/atomic/doc_64.go:21-21 SwapUint64
#[inline]
pub fn SwapUint64(addr: &Uint64, new: u64) -> u64 {
    return addr.Swap(new);
}

// go: sdk 1.25.5 sync/atomic/doc_64.go:28-28 CompareAndSwapInt64
#[inline]
pub fn CompareAndSwapInt64(addr: &Int64, old: i64, new: i64) -> bool {
    return addr.CompareAndSwap(old, new);
}

// go: sdk 1.25.5 sync/atomic/doc_64.go:35-35 CompareAndSwapUint64
#[inline]
pub fn CompareAndSwapUint64(addr: &Uint64, old: u64, new: u64) -> bool {
    return addr.CompareAndSwap(old, new);
}

// go: sdk 1.25.5 sync/atomic/doc_64.go:58-58 AndInt64
#[inline]
pub fn AndInt64(addr: &Int64, mask: i64) -> i64 {
    return addr.And(mask);
}

// go: sdk 1.25.5 sync/atomic/doc_64.go:65-65 AndUint64
#[inline]
pub fn AndUint64(addr: &Uint64, mask: u64) -> u64 {
    return addr.And(mask);
}

// go: sdk 1.25.5 sync/atomic/doc_64.go:72-72 OrInt64
#[inline]
pub fn OrInt64(addr: &Int64, mask: i64) -> i64 {
    return addr.Or(mask);
}

// go: sdk 1.25.5 sync/atomic/doc_64.go:79-79 OrUint64
#[inline]
pub fn OrUint64(addr: &Uint64, mask: u64) -> u64 {
    return addr.Or(mask);
}

// go: none — goish-only: Go has NO atomic Xor. It added And and
// Or in 1.23 (type.go) and stopped there, so this is an
// extension rather than a port. Kept because removing public
// API is a breaking change, and marked so nobody looks for the
// Go declaration it was ported from.
#[inline]
pub fn XorInt64(addr: &Int64, mask: i64) -> i64 {
    return addr.Xor(mask);
}

// go: none — goish-only: Go has NO atomic Xor. It added And and
// Or in 1.23 (type.go) and stopped there, so this is an
// extension rather than a port. Kept because removing public
// API is a breaking change, and marked so nobody looks for the
// Go declaration it was ported from.
#[inline]
pub fn XorUint64(addr: &Uint64, mask: u64) -> u64 {
    return addr.Xor(mask);
}
