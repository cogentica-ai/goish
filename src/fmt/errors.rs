// go: file fmt/errors.go decls: Errorf, wrapError.Error, wrapError.Unwrap
//
// errors.go — Errorf and the error values it wraps.

extern crate alloc;
#[allow(unused_imports)]
use alloc::vec::Vec;

#[allow(unused_imports)]
use crate::convert::{
    byte as tobyte, int as toint, int32 as toint32, int64 as toint64, uint as touint,
    uint32 as touint32, uint64 as touint64,
};
#[allow(unused_imports)]
use crate::errors::nil;
#[allow(unused_imports)]
use crate::errors::{self, error, ErrorTrait};
#[allow(unused_imports)]
use crate::goslice::slice;
#[allow(unused_imports)]
use crate::gostring::string;
#[allow(unused_imports)]
use crate::io;
#[allow(unused_imports)]
use crate::os;
#[allow(unused_imports)]
use crate::types::{byte, int, rune};
#[allow(unused_imports)]
use crate::unicode::utf8;

#[allow(unused_imports)]
use super::print::{do_format, FmtArg, FmtBuf};
#[allow(unused_imports)]
use super::*;

// go: sdk 1.25.5 fmt/errors.go:19-52 Errorf
/// `fmt.Errorf` — format according to `format` and return the string as
/// a value satisfying `error`. A `%w` verb makes the returned error
/// wrap its operand, so `errors::Unwrap` and `errors::Is` reach it.
///
/// goish reaches this through the `fmt::Errorf!` macro, which is where
/// the argument types are resolved; `errorf_impl` is the body.
// goishlint:ignore GOISH014 errorf_impl — the anchor names Go's
// `Errorf`; goish spells the caller-facing half as a macro, so the
// Rust function that carries the body cannot take that name.
#[doc(hidden)]
pub fn errorf_impl(format: &[byte], args: &[FmtArg]) -> error {
    let mut f = FmtBuf::new();
    let wrap = do_format(format, args, &mut f);
    let msg = string::from_bytes(f.as_slice());
    return match wrap {
        Some(inner) => errors::Wrap(wrapError { msg, err: inner }),
        None => errors::Wrap(SimpleErr { msg }),
    };
}

// Internal error types backing fmt::Errorf. SimpleErr just carries
// the formatted msg. wrapError also carries the %w target so
// errors::Is / Unwrap can walk to it.
struct SimpleErr {
    msg: string,
}
impl ErrorTrait for SimpleErr {
    // go: none — goish idiom: see the note on `SimpleErr`.
    fn Error(&self) -> string {
        return self.msg.clone();
    }
}

// go: sdk 1.25.5 fmt/errors.go:54-57 wrapError
struct wrapError {
    msg: string,
    err: error,
}
impl ErrorTrait for wrapError {
    // go: sdk 1.25.5 fmt/errors.go:59-61 wrapError.Error
    fn Error(&self) -> string {
        return self.msg.clone();
    }
    // go: sdk 1.25.5 fmt/errors.go:63-65 wrapError.Unwrap
    fn Unwrap(&self) -> error {
        return self.err.clone();
    }
}
