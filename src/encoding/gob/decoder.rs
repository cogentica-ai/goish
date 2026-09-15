// goishlint:ignore GOISH018 Decoder.recvType, Decoder.recvMessage, Decoder.readMessage, Decoder.nextInt, Decoder.nextUint, Decoder.decodeTypeSequence, Decoder.Decode, Decoder.DecodeValue, NewDecoder — the Decoder itself, ABSENT because every one of these drives decode.go's decOp engine, which walks and WRITES a reflect.Value; goish's reflect::Value is a read-only deep clone. See the module banner in mod.rs and ROADMAP §2.
// goishlint:ignore GOISH021 Decoder, debugFunc — same reason: the Decoder struct holds the free list, the wire-type map and the engine cache that the absent methods above use, and debugFunc is the debug.go hook they call.
// go: file encoding/gob/decoder.go decls: errBadCount, toInt
//
// encoding/gob/decoder.go — only the two constants and the one pure
// function that the wire primitives need. The Decoder is not here.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]

extern crate alloc;

use crate::int;
use crate::int64;
use crate::uint64;

// go: sdk 1.25.5 encoding/gob/decoder.go:16-19 tooBig
/// Go: "tooBig provides a sanity check for sizes; used in several
/// places. Upper limit of is 1GB on 32-bit systems, 8GB on 64-bit,
/// allowing room to grow a little without overflow."
///
/// Go writes it as `(1 << 30) << (^uint(0) >> 62)`, which is a
/// word-size test: `^uint(0) >> 62` is 3 on a 64-bit build and 0 on a
/// 32-bit one. goish is amd64 only, so the shift is 3 and the constant
/// is 8 GiB. Measured against Go: 8589934592.
pub const tooBig: int = (1 << 30) << 3;

// go: sdk 1.25.5 encoding/gob/decoder.go:78-78 errBadCount
/// Go: `var errBadCount = errors.New("invalid message length")`
pub fn errBadCount() -> crate::error {
    return crate::errors::New("invalid message length");
}

// go: sdk 1.25.5 encoding/gob/decoder.go:113-119 toInt
/// Go: the signed half of gob's integer encoding — the low bit says
/// whether to bit-complement the rest. Note it is NOT zigzag: Go
/// complements rather than negates, so 1 decodes to -1 and 3 to -2.
pub fn toInt(x: uint64) -> int64 {
    let mut i: int64 = int64(x >> 1);
    if x & 1 != 0 {
        i = !i;
    }
    return i;
}
