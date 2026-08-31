// go: file errors/join.go decls: Join, joinError.Error, joinError.Unwrap

// join.go — Join and the multi-error it returns.

extern crate alloc;
use alloc::sync::Arc;

use super::*;

// ─── Join ────────────────────────────────────────────────────────────

// go: sdk 1.25.5 errors/join.go:19-50 Join
/// `errors.Join(errs...)` — combine several errors into one. Nil
/// entries are discarded, and the result is nil if every entry is.
///
/// goish flavor: Go's variadic `...error` is a `slice<error>`.
///
/// The single-error case is Go's, and it is narrow: `Join(err)` returns
/// `err` itself ONLY when `err` already wraps several errors. Anything
/// else gets a fresh `joinError` around it — so `Join(x) == x` is false
/// for an ordinary `x`, and the result's `Unwrap() []error` has one
/// element. This used to return the original unconditionally, which
/// made `Join(x) == x` true and lost the wrapper Go's callers can
/// assert on.
pub fn Join(errs: crate::goslice::slice<error>) -> error {
    let mut n: crate::types::int = 0;
    let mut i: crate::types::int = 0;
    while i < errs.Len() {
        if !errs[i].IsNil() {
            n += 1;
        }
        i += 1;
    }
    if n == 0 {
        return nil;
    }
    if n == 1 {
        // Go: if _, ok := err.(interface{ Unwrap() []error }); ok { return err }
        let mut j: crate::types::int = 0;
        while j < errs.Len() {
            if !errs[j].IsNil() {
                if let Some(e) = errs[j].0.as_ref() {
                    if !e.UnwrapMulti().is_empty() {
                        return errs[j].clone();
                    }
                }
                break;
            }
            j += 1;
        }
    }

    let mut filtered: alloc::vec::Vec<error> = alloc::vec::Vec::with_capacity(n as usize);
    let mut k: crate::types::int = 0;
    while k < errs.Len() {
        if !errs[k].IsNil() {
            filtered.push(errs[k].clone());
        }
        k += 1;
    }
    return error(Some(Arc::new(JoinError { errs: filtered })));
}

// go: sdk 1.25.5 errors/join.go:52-54 joinError
/// The value [`Join`] returns. Go keeps it unexported and hands back
/// the `error` interface; goish does the same.
struct JoinError {
    errs: alloc::vec::Vec<error>,
}

impl ErrorTrait for JoinError {
    // go: sdk 1.25.5 errors/join.go:56-70 joinError.Error
    /// One error's text is that text; several are joined by newlines.
    fn Error(&self) -> crate::gostring::string {
        if self.errs.is_empty() {
            return crate::gostring::string::new();
        }
        if self.errs.len() == 1 {
            return self.errs[0].Error();
        }
        let mut b: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        b.extend_from_slice(self.errs[0].Error().as_bytes());
        for e in self.errs.iter().skip(1) {
            b.push(b'\n');
            b.extend_from_slice(e.Error().as_bytes());
        }
        return crate::gostring::string::from_bytes(&b);
    }

    // go: sdk 1.25.5 errors/join.go:72-74 joinError.Unwrap
    // goishlint:ignore GOISH014 - the anchor names the GO symbol. Go
    //     has TWO optional unwrap methods with the same name and
    //     different signatures, `Unwrap() error` and `Unwrap() []error`,
    //     and picks whichever the concrete type has. One Rust trait
    //     cannot carry both, so the multi form is `UnwrapMulti`.
    /// Every error this joined, so `errors::Is` and `errors::As` walk
    /// all of them.
    ///
    /// This is the whole point of the type, and it used to be spelled
    /// as a single-error `Unwrap` returning `errs[0]` — so `Is(joined,
    /// second)` was false and `As` could not reach anything but the
    /// first branch.
    fn UnwrapMulti(&self) -> alloc::vec::Vec<error> {
        return self.errs.clone();
    }
}
