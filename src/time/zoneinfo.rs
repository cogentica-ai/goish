// go: file time/zoneinfo.go decls: Location.String, FixedZone
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

/// `time.Location` (zoneinfo.go:40) — a time zone.
///
/// Go's is a pointer to a struct holding the whole zone history read
/// from the tzdata: transition times, DST rules, the lot. goish has no
/// zone database and does not read one, so a Location here is what a
/// database-free program can still have — a NAME and a FIXED offset,
/// which is exactly what `FixedZone` builds and what a parsed
/// `+02:00` carries.
///
/// It is `Copy`, and the name is an inline buffer rather than a
/// `string`, because `Time` embeds a Location and `Time` is `Copy`;
/// every method on it takes `self` by value. Zone abbreviations are
/// short — Go's own are at most six bytes — so sixteen is generous.
///
/// Before this, `Location` carried NO state at all: `FixedZone` did not
/// exist, `Time.Zone()` always answered ("UTC", 0), and an offset
/// parsed out of an RFC 3339 timestamp was computed into the instant
/// and then thrown away, so `Parse` followed by `Format` turned
/// `2024-01-02T03:04:05+02:00` into `2024-01-02T01:04:05Z`. The instant
/// was right and the rendering was not, which is the shape of bug this
/// tree keeps finding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Location {
    name: [u8; 16],
    nlen: u8,
    /// Seconds east of UTC.
    offset: crate::types::int,
    /// 0 = a named zone, 1 = the `Local` sentinel. Go's `Local.String()`
    /// is "Local" while the zone ABBREVIATION it resolves to comes from
    /// the database; with no database the abbreviation is "UTC".
    is_local: bool,
}

impl Default for Location {
    // go: none — goish idiom: Go's zero `Location` is a nil pointer,
    //     which every method treats as UTC. goish's is a value, so the
    //     default IS UTC.
    fn default() -> Self {
        return UTC;
    }
}

impl Location {
    // go: none — goish idiom: a const constructor for the two package
    //     singletons, since `FixedZone` cannot be const.
    #[doc(hidden)]
    pub const fn __new(name: &'static [u8], offset: crate::types::int, is_local: bool) -> Self {
        let mut buf = [0u8; 16];
        let mut i = 0;
        while i < name.len() && i < 16 {
            buf[i] = name[i];
            i += 1;
        }
        return Self {
            name: buf,
            nlen: i as u8, // goishlint:ignore GOISH005 - a length for a u8 field, in a `const fn` where `uint8()` cannot run.
            offset,
            is_local,
        };
    }

    // go: none — goish idiom: the zone ABBREVIATION, which is what a
    //     `MST` layout element prints and what `Time.Zone` returns.
    //     Distinct from `String`, which names the LOCATION.
    #[doc(hidden)]
    pub(crate) fn __abbrev(&self) -> &[u8] {
        return &self.name[..self.nlen as usize];
    }

    // go: none — goish idiom: seconds east of UTC.
    #[doc(hidden)]
    pub(crate) fn __offset(&self) -> crate::types::int {
        return self.offset;
    }

    // go: sdk 1.25.5 time/zoneinfo.go:103-105 Location.String
    /// Go: "String returns a descriptive name for the time zone
    /// information, corresponding to the name argument to LoadLocation
    /// or FixedZone."
    #[allow(non_snake_case)]
    pub fn String(self) -> crate::gostring::string {
        if self.is_local {
            return crate::gostring::string::from_static("Local");
        }
        return crate::gostring::string::from_bytes(self.__abbrev());
    }
}

// go: sdk 1.25.5 time/zoneinfo.go:112-128 FixedZone
/// Go: "FixedZone returns a Location that always uses the given zone
/// name and offset (seconds east of UTC)."
#[allow(non_snake_case)]
pub fn FixedZone<S: Into<crate::gostring::string>>(name: S, offset: crate::types::int) -> Location {
    let name: crate::gostring::string = name.into();
    let b = name.as_bytes();
    let mut buf = [0u8; 16];
    let mut i = 0usize;
    while i < b.len() && i < 16 {
        buf[i] = b[i];
        i += 1;
    }
    return Location {
        name: buf,
        nlen: tobyte(i),
        offset,
        is_local: false,
    };
}

/// `time.UTC` — the UTC location.
pub const UTC: Location = Location::__new(b"UTC", 0, false);

/// `time.Local` — Go's "system local zone".
///
/// goish has no zone database to read, so this resolves to UTC while
/// still naming itself "Local", which is what Go's own `Local.String()`
/// answers. On a machine whose TZ is UTC — the only configuration this
/// can match without a database — the two agree completely.
pub const Local: Location = Location::__new(b"UTC", 0, true);
