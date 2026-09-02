// go: file net/netip/uint128.go decls: mask6, uint128.isZero, uint128.and, uint128.xor, uint128.or, uint128.not, uint128.subOne, uint128.addOne, uint128.bitsSetFrom, uint128.bitsClearedFrom
//
// uint128.go — the 128-bit value an Addr is, as two 64-bit halves.

#![allow(non_snake_case)]
// Go declares the full 128-bit arithmetic surface here and uses parts
// of it from files this port has not reached (netipx-style prefix
// arithmetic). Dropping the unreached ones would read as a partial
// port to GOISH018, so they are ported and marked rather than omitted.
#![allow(dead_code)]
// goishlint:ignore GOISH018 halves — Go's `halves` hands back `[2]*uint64` so a caller can mutate hi and lo through pointers; the only user is `Prefix.Masked`'s in-place loop, which goish writes as a value return. Rust cannot hand out two aliasing `&mut` into one struct, and nothing here needs it.

use crate::types::int;

// go: sdk 1.25.5 net/netip/uint128.go:13-16 uint128
/// Go: "uint128 represents a uint128 using two uint64s. When the
/// methods below mention a bit number, bit 0 is the most significant
/// bit (in hi) and bit 127 is the lowest (lo&1)."
#[derive(Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub struct uint128 {
    pub(crate) hi: u64,
    pub(crate) lo: u64,
}

// go: sdk 1.25.5 net/netip/uint128.go:20-22 mask6
/// Go: "mask6 returns a uint128 bitmask with the topmost n bits of a
/// 128 bit number."
///
/// Note both shifts are by a value that can be 0 or 64+: Go's shift of
/// a uint64 by 64 yields 0 rather than being undefined, which is what
/// makes `mask6(0)` all-zero and `mask6(128)` all-ones. Rust's `>>`
/// panics there instead, so the two ends are spelled out.
pub fn mask6(n: int) -> uint128 {
    let hi = if n == 0 {
        0
    } else if n >= 64 {
        u64::MAX
    } else {
        !(u64::MAX >> n)
    };
    let lo = if n <= 64 {
        0
    } else if n >= 128 {
        u64::MAX
    } else {
        u64::MAX << (128 - n)
    };
    return uint128 { hi, lo };
}

impl uint128 {
    // go: sdk 1.25.5 net/netip/uint128.go:29-29 uint128.isZero
    pub(crate) fn isZero(self) -> bool {
        return self.hi | self.lo == 0;
    }

    // go: sdk 1.25.5 net/netip/uint128.go:32-34 uint128.and
    pub(crate) fn and(self, m: uint128) -> uint128 {
        return uint128 {
            hi: self.hi & m.hi,
            lo: self.lo & m.lo,
        };
    }

    // go: sdk 1.25.5 net/netip/uint128.go:37-39 uint128.xor
    pub(crate) fn xor(self, m: uint128) -> uint128 {
        return uint128 {
            hi: self.hi ^ m.hi,
            lo: self.lo ^ m.lo,
        };
    }

    // go: sdk 1.25.5 net/netip/uint128.go:42-44 uint128.or
    pub(crate) fn or(self, m: uint128) -> uint128 {
        return uint128 {
            hi: self.hi | m.hi,
            lo: self.lo | m.lo,
        };
    }

    // go: sdk 1.25.5 net/netip/uint128.go:47-49 uint128.not
    pub(crate) fn not(self) -> uint128 {
        return uint128 {
            hi: !self.hi,
            lo: !self.lo,
        };
    }

    // go: sdk 1.25.5 net/netip/uint128.go:52-55 uint128.subOne
    pub(crate) fn subOne(self) -> uint128 {
        let (lo, borrow) = self.lo.overflowing_sub(1);
        let hi = if borrow {
            self.hi.wrapping_sub(1)
        } else {
            self.hi
        };
        return uint128 { hi, lo };
    }

    // go: sdk 1.25.5 net/netip/uint128.go:58-61 uint128.addOne
    pub(crate) fn addOne(self) -> uint128 {
        let (lo, carry) = self.lo.overflowing_add(1);
        let hi = if carry {
            self.hi.wrapping_add(1)
        } else {
            self.hi
        };
        return uint128 { hi, lo };
    }

    // go: sdk 1.25.5 net/netip/uint128.go:73-75 uint128.bitsSetFrom
    /// Go: "bitsSetFrom returns a copy of u with the given bit and all
    /// subsequent ones set."
    pub(crate) fn bitsSetFrom(self, bit: u8) -> uint128 {
        return self.or(mask6(crate::int64(bit)).not());
    }

    // go: sdk 1.25.5 net/netip/uint128.go:79-81 uint128.bitsClearedFrom
    /// Go: "bitsClearedFrom returns a copy of u with the given bit and
    /// all subsequent ones cleared."
    pub(crate) fn bitsClearedFrom(self, bit: u8) -> uint128 {
        return self.and(mask6(crate::int64(bit)));
    }
}
