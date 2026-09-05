// go: package time
//
// time — Go's `time` package.
//
// Module root only: one `.rs` per Go `.go`, and the `pub use` surface.
//
//   time.rs      time/time.go      — Time, Duration, Month, Weekday,
//                                     Now, Unix, Date, the calendar math
//   format.rs    time/format.go    — the layout constants, Format,
//                                     Parse, Duration.String,
//                                     ParseDuration
//   sleep.rs     time/sleep.go     — Sleep, Timer, NewTimer, AfterFunc,
//                                     After
//   tick.rs      time/tick.go      — Ticker, NewTicker, Tick
//   zoneinfo.rs  time/zoneinfo.go  — Location, UTC, Local
//
// v1 differences from Go semantics:
//
//   * There is no zone database. `Location` carries no state, `UTC`
//     and `Local` are the same singleton, and every `Time` is stored
//     and rendered in UTC.
//   * `Duration.String()` writes ASCII "us" where Go writes "µs",
//     because goish's formatter is ASCII-clean.
//   * `Parse` recognises a fixed set of layouts rather than scanning
//     an arbitrary one — see the note on it in format.rs.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

#[path = "time.rs"]
mod time_go;
pub use time_go::*;

#[path = "format.rs"]
mod format;
pub use format::*;

#[path = "format_rfc3339.rs"]
mod format_rfc3339;

#[path = "sleep.rs"]
mod sleep;
pub use sleep::*;

#[path = "tick.rs"]
mod tick;
pub use tick::*;

#[path = "zoneinfo.rs"]
mod zoneinfo;
pub use zoneinfo::*;
