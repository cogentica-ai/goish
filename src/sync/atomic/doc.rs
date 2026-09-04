// sync/atomic/doc — Go 1.25.5 src/sync/atomic/doc.go.
//
// One `.rs` per `.go` (§33): the package-level functions Go declares
// in doc.go and implements in assembly. They predate the typed
// wrappers in type.rs and remain documented API.
//
// goish takes `&Int32` where Go takes `*int32`: a pointer-to-int has
// no safe Rust spelling, and the typed wrapper already IS the atomic
// cell.

#![allow(non_snake_case)]

use super::type_::{Int32, Uint32, Uintptr};

// ─── Free-function variants (legacy Go pre-1.19 API) ──────────────────
//
// Go's `sync/atomic` package historically exposed `AddInt32`,
// `LoadUint32`, etc. as free functions taking `*T`. The Go 1.19+
// `atomic.Int32` struct API is the recommended form, but a lot of
// existing code (and ports — rs/xid is one) still uses the free-fn
// shape. Goish accepts both: the free fns delegate to the typed
// struct's method via a `&Uint32`/`&Int32`/… handle. Callers pass
// the same `&counter` they'd pass in Go.

// go: sdk 1.25.5 sync/atomic/doc.go:115-115 AddInt32
#[inline]
pub fn AddInt32(addr: &Int32, delta: i32) -> i32 {
    return addr.Add(delta);
}

// go: sdk 1.25.5 sync/atomic/doc.go:123-123 AddUint32
#[inline]
pub fn AddUint32(addr: &Uint32, delta: u32) -> u32 {
    return addr.Add(delta);
}

// go: sdk 1.25.5 sync/atomic/doc.go:129-129 AddUintptr
#[inline]
pub fn AddUintptr(addr: &Uintptr, delta: usize) -> usize {
    return addr.Add(delta);
}

// go: sdk 1.25.5 sync/atomic/doc.go:177-177 LoadInt32
#[inline]
pub fn LoadInt32(addr: &Int32) -> i32 {
    return addr.Load();
}

// go: sdk 1.25.5 sync/atomic/doc.go:183-183 LoadUint32
#[inline]
pub fn LoadUint32(addr: &Uint32) -> u32 {
    return addr.Load();
}

// go: sdk 1.25.5 sync/atomic/doc.go:199-199 StoreInt32
#[inline]
pub fn StoreInt32(addr: &Int32, v: i32) {
    return addr.Store(v);
}

// go: sdk 1.25.5 sync/atomic/doc.go:205-205 StoreUint32
#[inline]
pub fn StoreUint32(addr: &Uint32, v: u32) {
    return addr.Store(v);
}

// go: sdk 1.25.5 sync/atomic/doc.go:71-71 SwapInt32
#[inline]
pub fn SwapInt32(addr: &Int32, new: i32) -> i32 {
    return addr.Swap(new);
}

// go: sdk 1.25.5 sync/atomic/doc.go:77-77 SwapUint32
#[inline]
pub fn SwapUint32(addr: &Uint32, new: u32) -> u32 {
    return addr.Swap(new);
}

// go: sdk 1.25.5 sync/atomic/doc.go:93-93 CompareAndSwapInt32
#[inline]
pub fn CompareAndSwapInt32(addr: &Int32, old: i32, new: i32) -> bool {
    return addr.CompareAndSwap(old, new);
}

// go: sdk 1.25.5 sync/atomic/doc.go:99-99 CompareAndSwapUint32
#[inline]
pub fn CompareAndSwapUint32(addr: &Uint32, old: u32, new: u32) -> bool {
    return addr.CompareAndSwap(old, new);
}

// go: sdk 1.25.5 sync/atomic/doc.go:136-136 AndInt32
#[inline]
pub fn AndInt32(addr: &Int32, mask: i32) -> i32 {
    return addr.And(mask);
}

// go: sdk 1.25.5 sync/atomic/doc.go:143-143 AndUint32
#[inline]
pub fn AndUint32(addr: &Uint32, mask: u32) -> u32 {
    return addr.And(mask);
}

// go: sdk 1.25.5 sync/atomic/doc.go:157-157 OrInt32
#[inline]
pub fn OrInt32(addr: &Int32, mask: i32) -> i32 {
    return addr.Or(mask);
}

// go: sdk 1.25.5 sync/atomic/doc.go:164-164 OrUint32
#[inline]
pub fn OrUint32(addr: &Uint32, mask: u32) -> u32 {
    return addr.Or(mask);
}

// go: none — goish-only: Go has NO atomic Xor. It added And and
// Or in 1.23 (type.go) and stopped there, so this is an
// extension rather than a port. Kept because removing public
// API is a breaking change, and marked so nobody looks for the
// Go declaration it was ported from.
#[inline]
pub fn XorInt32(addr: &Int32, mask: i32) -> i32 {
    return addr.Xor(mask);
}

// go: none — goish-only: Go has NO atomic Xor. It added And and
// Or in 1.23 (type.go) and stopped there, so this is an
// extension rather than a port. Kept because removing public
// API is a breaking change, and marked so nobody looks for the
// Go declaration it was ported from.
#[inline]
pub fn XorUint32(addr: &Uint32, mask: u32) -> u32 {
    return addr.Xor(mask);
}
