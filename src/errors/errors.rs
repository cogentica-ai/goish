// go: file errors/errors.go decls: New, errorString.Error

// errors.go — New, the trivial error behind it, and ErrUnsupported.

extern crate alloc;
use alloc::sync::Arc;

use crate::convert::__StringConv;
use crate::gostring::string;

use super::*;

// ─── New / Wrap ─────────────────────────────────────────────────────────

/// Internal: the trivial `error` produced by `errors::New`. Mirrors Go's
/// `*errorString`. Each `New` call allocates a fresh Arc, so two errors
/// with the same text compare *not equal* — matches Go's "Each call to
/// New returns a distinct error value even if the text is identical."
struct __ErrorString {
    msg: string,
}

impl ErrorTrait for __ErrorString {
    // go: sdk 1.25.5 errors/errors.go:73-75 errorString.Error
    fn Error(&self) -> string {
        return self.msg.clone();
    }
}

// go: sdk 1.25.5 errors/errors.go:64-67 New
/// `errors.New(text)` — basic error from a message.
pub fn New<S: __StringConv>(text: S) -> error {
    return error(Some(Arc::new(__ErrorString {
        msg: text.__to_string(),
    })));
}

// go: sdk 1.25.5 errors/errors.go:90-90 ErrUnsupported
// `errors.ErrUnsupported` — sentinel returned
// when a feature is unsupported. Use sites compare bare:
// `errors::Is(x, errors::ErrUnsupported)` and `if x == errors::ErrUnsupported`.
crate::var! { pub ErrUnsupported: error = "unsupported operation"; }
