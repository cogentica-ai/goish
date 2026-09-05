// go: file fmt/errors.go decls: Errorf, wrapError.Error, wrapError.Unwrap, wrapErrors.Error, wrapErrors.UnwrapMulti
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
    let wrapped = do_format(format, args, &mut f);
    let msg = string::from_bytes(f.as_slice());
    // Go switches on the COUNT of %w operands (fmt/errors.go:24-49):
    // none is a plain errors.New, one is a wrapError with
    // `Unwrap() error`, and two or more is a wrapErrors with
    // `Unwrap() []error` — for which the single-error errors.Unwrap
    // returns nil while errors.Is and errors.As walk every branch.
    if wrapped.is_empty() {
        return errors::Wrap(SimpleErr { msg });
    }
    if wrapped.len() == 1 {
        return errors::Wrap(wrapError {
            msg,
            err: wrapped[0].clone(),
        });
    }
    return errors::Wrap(wrapErrors { msg, errs: wrapped });
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

// go: sdk 1.25.5 fmt/errors.go:67-70 wrapErrors
/// Go: what `Errorf` returns when the format has TWO OR MORE `%w`.
///
/// The distinction is observable and was missing here: `errors.Unwrap`
/// takes the single-error interface, which this type does NOT have, so
/// it answers nil — while `errors.Is` and `errors.As` use the
/// `Unwrap() []error` form and reach every branch. goish wrapped only
/// the first `%w`, so `Is(err, second)` was false and `Unwrap(err)`
/// returned the first error instead of nil.
struct wrapErrors {
    msg: string,
    errs: crate::goslice::slice<error>,
}
impl ErrorTrait for wrapErrors {
    // go: sdk 1.25.5 fmt/errors.go:72-74 wrapErrors.Error
    fn Error(&self) -> string {
        return self.msg.clone();
    }
    // go: sdk 1.25.5 fmt/errors.go:76-78
    // (Go's `wrapErrors.Unwrap`; the name diverges because goish
    // spells the []error arity as UnwrapMulti — see the doc below.)
    /// goish spells Go's `Unwrap() []error` as `UnwrapMulti`, because
    /// one Rust trait cannot carry both arities — the same split
    /// errors::Join uses.
    fn UnwrapMulti(&self) -> Vec<error> {
        let mut out: Vec<error> = Vec::new();
        let mut i: int = 0;
        while i < self.errs.Len() {
            out.push(self.errs[i].clone());
            i += 1;
        }
        return out;
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
