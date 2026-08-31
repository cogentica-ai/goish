// go: file time/zoneinfo.go decls: Location.String
//
// zoneinfo.go — Location, and the UTC and Local singletons.

extern crate alloc;
#[allow(unused_imports)]
use alloc::vec::Vec;
#[allow(unused_imports)]
use core::ops::{Add, Div, Mul, Sub};

#[allow(unused_imports)]
use crate::convert::{
    byte as tobyte, int as toint, int16 as toint16, int32 as toint32, int64 as toint64,
    uint as touint, uint16 as touint16, uint32 as touint32, uint64 as touint64,
};
#[allow(unused_imports)]
use crate::fmt::{self, FmtBuf};
#[allow(unused_imports)]
use crate::gostring::string;
#[allow(unused_imports)]
use crate::syscall::{self, Timespec};
#[allow(unused_imports)]
use crate::types::int;

#[allow(unused_imports)]
use super::*;

/// `time.Location` (time.go:38) — opaque time-zone descriptor. Slim
/// runtime is UTC-only; this carries no real state. Present so the
/// `Date(..., loc)` 8-arg signature lines up with Go and so port
/// code spelling `time.UTC` resolves to a value.
#[derive(Clone, Copy, Default)]
pub struct Location {
    _utc: (),
}

impl Location {
    // go: none — goish idiom: Go's `UTC` and `Local` are package-level
    //     pointers into a zone database; goish has no database, so the
    //     singleton is a `const fn` with no state.
    #[doc(hidden)]
    pub const fn __new() -> Self {
        return Self { _utc: () };
    }
    // go: sdk 1.25.5 time/zoneinfo.go:103-105 Location.String
    /// `(*Location).String()` (time.go:101) — name of the zone.
    /// Slim runtime returns `"UTC"` for the singleton.
    #[allow(non_snake_case)]
    pub fn String(self) -> crate::gostring::string {
        return crate::gostring::string::from_static("UTC");
    }
}

/// `time.UTC` (time.go:1067) — the UTC location singleton. v1 has
/// no other zones; passing this to `Date` is a no-op (every Time is
/// internally UTC).
pub const UTC: Location = Location::__new();

/// `time.Local` (time.go:1071) — Go's "system local zone" sentinel.
/// v1 has no zone-database — folds to UTC.
pub const Local: Location = Location::__new();
