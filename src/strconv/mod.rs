// go: package strconv
//
// strconv — conversions to and from string representations of basic
// data types.
//
// Module root only: one `.rs` per Go `.go`, and the `pub use` surface.
//
//   atoi.rs     strconv/atoi.go    — ParseUint, ParseInt, Atoi, NumError
//   itoa.rs     strconv/itoa.go    — FormatInt/Uint, AppendInt/Uint,
//                                    Itoa and the shared formatBits
//   atob.rs     strconv/atob.go    — ParseBool, FormatBool, AppendBool
//   quote.rs    strconv/quote.go   — Quote and its family, Unquote,
//                                    IsPrint, IsGraphic
//   isprint.rs  strconv/isprint.go — the generated range tables
//                                    IsPrint and IsGraphic search
//   atof.rs     strconv/atof.go    — ParseFloat
//   ftoa.rs     strconv/ftoa.go    — FormatFloat, AppendFloat
//   decimal.rs  strconv/decimal.go — the multiprecision decimal both
//                                    float paths share
//
// Not yet ported:
//
//   * The Eisel-Lemire fast path in atof.go and the Ryū shortest-form
//     path in ftoa.go. Both files carry the slow path only, which is
//     correct but not fast; the fast paths are recorded as open
//     findings in scripts/lint_baseline.json.
//   * ParseComplex / FormatComplex — no `complex` type yet.
//
// v1 differences from Go semantics:
//
//   * goish `int` is i64 always (amd64-pinned), so `IntSize` is 64 and
//     ParseInt with bit_size=0 is identical to bit_size=64.
//
// String inputs are generic over `S: Into<string>` so call sites stay
// tight: `strconv::Atoi("42")` works without `string("42")` wrapping.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate alloc;

mod atof;
mod decimal;
mod ftoa;

#[path = "isprint.rs"]
mod isprint;

pub use atof::ParseFloat;
pub use ftoa::{AppendFloat, FormatFloat};

#[path = "atoi.rs"]
mod atoi;
pub use atoi::*;

#[path = "itoa.rs"]
mod itoa;
pub use itoa::*;

#[path = "atob.rs"]
mod atob;
pub use atob::*;

#[path = "quote.rs"]
mod quote;
pub use quote::*;
