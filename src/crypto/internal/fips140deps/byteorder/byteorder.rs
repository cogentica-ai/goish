// go: file crypto/internal/fips140deps/byteorder/byteorder.go decls: LEUint16, BEUint32, BEUint64, LEUint64, BEPutUint16, BEPutUint32, BEPutUint64, LEPutUint64, BEAppendUint16, BEAppendUint32, BEAppendUint64
//
// crypto/internal/fips140deps/byteorder — the byte-order codecs the
// FIPS 140-3 module is allowed to reach for. Every function forwards to
// `internal/byteorder`; the indirection exists so the module's source
// can be vendored and validated with an explicit dependency list.

#![allow(non_snake_case)]

use crate::goslice::slice;
use crate::internal::byteorder;
use crate::types::{byte, uint16, uint32, uint64};

// go: sdk 1.25.5 crypto/internal/fips140deps/byteorder/byteorder.go:11-13 LEUint16
/// `byteorder.LEUint16(b)` — decode `b[0:2]` little-endian.
pub fn LEUint16(b: slice<byte>) -> uint16 {
    return byteorder::LEUint16(b);
}

// go: sdk 1.25.5 crypto/internal/fips140deps/byteorder/byteorder.go:15-17 BEUint32
/// `byteorder.BEUint32(b)` — decode `b[0:4]` big-endian.
pub fn BEUint32(b: slice<byte>) -> uint32 {
    return byteorder::BEUint32(b);
}

// go: sdk 1.25.5 crypto/internal/fips140deps/byteorder/byteorder.go:19-21 BEUint64
/// `byteorder.BEUint64(b)` — decode `b[0:8]` big-endian.
pub fn BEUint64(b: slice<byte>) -> uint64 {
    return byteorder::BEUint64(b);
}

// go: sdk 1.25.5 crypto/internal/fips140deps/byteorder/byteorder.go:23-25 LEUint64
/// `byteorder.LEUint64(b)` — decode `b[0:8]` little-endian.
pub fn LEUint64(b: slice<byte>) -> uint64 {
    return byteorder::LEUint64(b);
}

// go: sdk 1.25.5 crypto/internal/fips140deps/byteorder/byteorder.go:27-29 BEPutUint16
/// `byteorder.BEPutUint16(b, v)` — encode `v` big-endian into `b[0:2]`.
pub fn BEPutUint16(b: &mut slice<byte>, v: uint16) {
    byteorder::BEPutUint16(b, v);
}

// go: sdk 1.25.5 crypto/internal/fips140deps/byteorder/byteorder.go:31-33 BEPutUint32
/// `byteorder.BEPutUint32(b, v)` — encode `v` big-endian into `b[0:4]`.
pub fn BEPutUint32(b: &mut slice<byte>, v: uint32) {
    byteorder::BEPutUint32(b, v);
}

// go: sdk 1.25.5 crypto/internal/fips140deps/byteorder/byteorder.go:35-37 BEPutUint64
/// `byteorder.BEPutUint64(b, v)` — encode `v` big-endian into `b[0:8]`.
pub fn BEPutUint64(b: &mut slice<byte>, v: uint64) {
    byteorder::BEPutUint64(b, v);
}

// go: sdk 1.25.5 crypto/internal/fips140deps/byteorder/byteorder.go:39-41 LEPutUint64
/// `byteorder.LEPutUint64(b, v)` — encode `v` little-endian into `b[0:8]`.
pub fn LEPutUint64(b: &mut slice<byte>, v: uint64) {
    byteorder::LEPutUint64(b, v);
}

// go: sdk 1.25.5 crypto/internal/fips140deps/byteorder/byteorder.go:43-45 BEAppendUint16
/// `byteorder.BEAppendUint16(b, v)` — append `v` big-endian to `b`.
pub fn BEAppendUint16(b: slice<byte>, v: uint16) -> slice<byte> {
    return byteorder::BEAppendUint16(b, v);
}

// go: sdk 1.25.5 crypto/internal/fips140deps/byteorder/byteorder.go:47-49 BEAppendUint32
/// `byteorder.BEAppendUint32(b, v)` — append `v` big-endian to `b`.
pub fn BEAppendUint32(b: slice<byte>, v: uint32) -> slice<byte> {
    return byteorder::BEAppendUint32(b, v);
}

// go: sdk 1.25.5 crypto/internal/fips140deps/byteorder/byteorder.go:51-53 BEAppendUint64
/// `byteorder.BEAppendUint64(b, v)` — append `v` big-endian to `b`.
pub fn BEAppendUint64(b: slice<byte>, v: uint64) -> slice<byte> {
    return byteorder::BEAppendUint64(b, v);
}
