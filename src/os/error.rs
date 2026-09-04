// go: file os/error.go decls: SyscallError.Error, SyscallError.Unwrap, SyscallError.Timeout, NewSyscallError, IsExist, IsNotExist, IsPermission, IsTimeout, underlyingErrorIs, underlyingError
// goishlint:ignore GOISH018 errNoDeadline, errDeadlineExceeded — Go writes two one-line accessors because the values live in `internal/poll` and `os` only re-exports them; goish re-exports them directly, so the accessors would be functions returning a constant already in scope. The `pub use` is above.
// goishlint:ignore GOISH021 PathError — `type PathError = fs.PathError` is an exact ALIAS in Go, and the port is the `pub use` of the same name below. A second declaration is what this file used to have, and it was the bug.

use crate::errors::{self, error, ErrorTrait};
use crate::gostring::string;
use crate::syscall;

// go: sdk 1.25.5 os/error.go:16-27 ErrInvalid
// goishlint:ignore GOISH021 ErrPermission, ErrExist, ErrNotExist, ErrClosed — one `var (` block in Go, one `pub use` here; the anchor covers the whole block and naming each member again would be five anchors on one line.
/// Go: `ErrInvalid = fs.ErrInvalid` and its four siblings — os aliases
/// the `io/fs` sentinels rather than declaring its own, so that
/// `errors.Is(err, os.ErrNotExist)` and `errors.Is(err, fs.ErrNotExist)`
/// are the same question. One identity, exactly as in Go.
pub use crate::io::fs::{ErrClosed, ErrExist, ErrInvalid, ErrNotExist, ErrPermission};

// go: sdk 1.25.5 os/error.go:30-30 errNoDeadline
// goishlint:ignore GOISH021 ErrDeadlineExceeded — the two sentinels come from one place and are re-exported on one line; the anchor above names the first of the two accessors Go writes for them.
/// Go: `ErrNoDeadline = errNoDeadline()` and `ErrDeadlineExceeded =
/// errDeadlineExceeded()`, each a one-line accessor returning the
/// `internal/poll` value. Go's comment on the second says why they live
/// there: `net` must return `os.ErrDeadlineExceeded` for an expired
/// socket deadline without `internal/poll` importing `os`.
///
/// goish had neither. A caller asking `errors.Is(err,
/// os.ErrDeadlineExceeded)` — the check Go's own docs recommend over
/// `IsTimeout` — had nothing to ask about.
pub use crate::internal::poll::{ErrDeadlineExceeded, ErrNoDeadline};

// go: sdk 1.25.5 os/error.go:46-46 PathError
/// Go: `type PathError = fs.PathError` — an exact type ALIAS, not a
/// separate declaration.
///
/// goish had declared a second `os::PathError` struct with the same
/// three fields, so the tree carried two unrelated types: `os::Mkdir`
/// returned one and `os::File::Read` the other, and
/// `errors::As::<fs::PathError>` on the first was a miss. This is the
/// alias Go writes.
pub use crate::io::fs::PathError;

// go: sdk 1.25.5 os/error.go:41-43 timeout
/// Go: `type timeout interface { Timeout() bool }` — the private
/// assertion `SyscallError.Timeout` and [`IsTimeout`] make.
///
/// Go's is satisfied STRUCTURALLY, by any error that has the method,
/// and Go declares this interface twice — once here and once in `net`
/// (net.go:535) — with no consequence at all, because the two
/// anonymous shapes are the same shape.
///
/// goish cannot copy that. A goish interface is satisfied by an
/// explicit impl plus a registry entry keyed on the TRAIT'S identity,
/// so two identically-shaped traits are two different keys, and a type
/// registered for one is invisible to the other. os declared its own
/// and registered the deadline and errno errors against it; net's
/// `OpError.Timeout` asks net's — and missed every one of them, so a
/// socket read that hit its deadline reported `Timeout() == false` to
/// the caller doing the standard `if ne, ok := err.(net.Error); ok &&
/// ne.Timeout()` retry check.
///
/// So there is ONE trait, net's, and this is a re-export of it. Note
/// that Go does not export either copy; the `pub` here is goish-only
/// and kept for source compatibility.
pub use crate::net::net::{temporary, timeout};

// go: none — goish idiom: `syscall.Errno` satisfies Go's `timeout`
//     structurally, by having `Timeout()`. The impl is written here
//     rather than in `syscall` so the lower package does not have to
//     know about this one; the method it forwards to is Errno's own.
impl timeout for syscall::Errno {
    // go: none — goish idiom: forwards to Errno's own method, which is
    //     the anchored one.
    fn Timeout(&self) -> bool {
        return syscall::Errno::Timeout(self);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: none — goish idiom: as above, for the value behind
//     `ErrDeadlineExceeded`. Without it `os::IsTimeout(ErrDeadlineExceeded)`
//     is false, which is the one answer that sentinel exists to give.
impl timeout for crate::internal::poll::DeadlineExceededError {
    // go: none — goish idiom: forwards to the anchored method on the
    //     concrete type in internal/poll.
    fn Timeout(&self) -> bool {
        return crate::internal::poll::DeadlineExceededError::Timeout(self);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: none — goish idiom: the `temporary` half of the same structural
//     satisfaction, for the two types whose Go originals answer it.
impl temporary for syscall::Errno {
    // go: none — goish idiom: forwards to Errno's own anchored method.
    fn Temporary(&self) -> bool {
        return syscall::Errno::Temporary(self);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: none — goish idiom: as above, for the value behind
//     `ErrDeadlineExceeded`.
impl temporary for crate::internal::poll::DeadlineExceededError {
    // go: none — goish idiom: forwards to the anchored method on the
    //     concrete type in internal/poll.
    fn Temporary(&self) -> bool {
        return crate::internal::poll::DeadlineExceededError::Temporary(self);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: none — goish idiom: `os.ErrDeadlineExceeded` satisfies Go's
//     `net.Error` structurally — it has Error, Timeout and Temporary —
//     and callers assert exactly that on a socket deadline. goish needs
//     the impl spelled out.
impl crate::net::net::Error for crate::internal::poll::DeadlineExceededError {
    // go: none — goish idiom: the interface VIEW of the anchored
    //     inherent method.
    fn Error(&self) -> crate::gostring::string {
        return ErrorTrait::Error(self);
    }
    // go: none — goish idiom: as above.
    fn Timeout(&self) -> bool {
        return crate::internal::poll::DeadlineExceededError::Timeout(self);
    }
    // go: none — goish idiom: as above.
    fn Temporary(&self) -> bool {
        return crate::internal::poll::DeadlineExceededError::Temporary(self);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: none — goish idiom: fill the `#[goish::interface]` downcast
//     registry for the types this package asserts `timeout` on. See
//     AGENTS.md §9b. Called from `goish::init()`; idempotent.
pub fn register_os_error_impls() {
    use crate::net::net::{__goish_register_temporary_impl, __goish_register_timeout_impl};
    __goish_register_timeout_impl::<syscall::Errno>();
    __goish_register_timeout_impl::<crate::internal::poll::DeadlineExceededError>();
    __goish_register_timeout_impl::<SyscallError>();
    // Go's deadline error answers Temporary() too, and `net.Error`
    // needs all three methods — without these, `os.ErrDeadlineExceeded`
    // does not satisfy net.Error at all, where in Go it does.
    __goish_register_temporary_impl::<syscall::Errno>();
    __goish_register_temporary_impl::<crate::internal::poll::DeadlineExceededError>();
    crate::net::net::__goish_register_Error_impl::<crate::internal::poll::DeadlineExceededError>();
}

// go: sdk 1.25.5 os/error.go:49-52 SyscallError
/// Go: "SyscallError records an error from a specific system call."
///
/// goish had no such type, though `os::Pipe` and `os::Setenv` both
/// carry a `// Go: … NewSyscallError(…)` comment where one belongs:
/// the port dropped the wrapper and returned the bare errno, losing the
/// name of the call that failed.
#[derive(Clone, Default)]
pub struct SyscallError {
    pub Syscall: string,
    pub Err: error,
}

impl ErrorTrait for SyscallError {
    // go: sdk 1.25.5 os/error.go:54-54 SyscallError.Error
    fn Error(&self) -> string {
        // Go: e.Syscall + ": " + e.Err.Error()
        return self.Syscall.clone() + string::from_static(": ") + self.Err.Error();
    }

    // go: sdk 1.25.5 os/error.go:56-56 SyscallError.Unwrap
    fn Unwrap(&self) -> error {
        return self.Err.clone();
    }
}

impl SyscallError {
    // go: sdk 1.25.5 os/error.go:59-62 SyscallError.Timeout
    /// Go: `t, ok := e.Err.(timeout); return ok && t.Timeout()`.
    pub fn Timeout(&self) -> bool {
        let (t, ok) = errors::AsIface::<crate::d!(timeout)>(&self.Err);
        return ok && t.Timeout();
    }
}

// go: none — goish idiom: `*SyscallError` has a `Timeout()` method, so
//     in Go it satisfies the private `timeout` interface above like any
//     other error that has one. Nested SyscallErrors are not a shape Go
//     builds, but the impl costs nothing and keeps the registry honest.
impl timeout for SyscallError {
    // go: none — goish idiom: forwards to the anchored inherent method.
    fn Timeout(&self) -> bool {
        return SyscallError::Timeout(self);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: sdk 1.25.5 os/error.go:67-72 NewSyscallError
/// Go: "NewSyscallError returns, as an error, a new SyscallError with
/// the given system call name and error details. As a convenience, if
/// err is nil, NewSyscallError returns nil."
pub fn NewSyscallError<S: Into<string>>(syscall: S, err: error) -> error {
    if err == errors::nil {
        return errors::nil;
    }
    return errors::Wrap(SyscallError {
        Syscall: syscall.into(),
        Err: err,
    });
}

// go: sdk 1.25.5 os/error.go:80-82 IsExist
/// Go: "IsExist returns a boolean indicating whether its argument is
/// known to report that a file or directory already exists. It is
/// satisfied by ErrExist as well as some syscall errors."
///
/// goish had `err == ErrExist`, an identity test against the sentinel.
/// That is false for every error `os` itself returns: a real `Mkdir`
/// failure is a `*PathError` wrapping `EEXIST`, and neither the wrapper
/// nor the errno is that sentinel.
pub fn IsExist(err: error) -> bool {
    return underlyingErrorIs(err, ErrExist.into());
}

// go: sdk 1.25.5 os/error.go:90-92 IsNotExist
/// Go: "IsNotExist returns a boolean indicating whether its argument is
/// known to report that a file or directory does not exist."
pub fn IsNotExist(err: error) -> bool {
    return underlyingErrorIs(err, ErrNotExist.into());
}

// go: sdk 1.25.5 os/error.go:100-102 IsPermission
/// Go: "IsPermission returns a boolean indicating whether its argument
/// is known to report that permission is denied."
pub fn IsPermission(err: error) -> bool {
    return underlyingErrorIs(err, ErrPermission.into());
}

// go: sdk 1.25.5 os/error.go:112-115 IsTimeout
/// Go: "IsTimeout returns a boolean indicating whether its argument is
/// known to report that a timeout occurred."
///
/// Note that this asks the UNDERLYING error, so a `*PathError` around
/// an `ETIMEDOUT` answers true while the historical `Is*` predicates
/// above stop at the sentinel comparison.
pub fn IsTimeout(err: error) -> bool {
    let u = underlyingError(err);
    let (terr, ok) = errors::AsIface::<crate::d!(timeout)>(&u);
    return ok && terr.Timeout();
}

// go: sdk 1.25.5 os/error.go:117-129 underlyingErrorIs
/// Go: "Note that this function is not errors.Is: underlyingError only
/// unwraps the specific error-wrapping types that it historically did,
/// not all errors implementing Unwrap()."
///
/// The difference is observable and pinned in the smoke: for
/// `fmt.Errorf("ctx: %w", syscall.ENOENT)`, `errors.Is(err,
/// fs.ErrNotExist)` is true and `os.IsNotExist(err)` is FALSE.
pub fn underlyingErrorIs(err: error, target: error) -> bool {
    // Go: err = underlyingError(err); if err == target { return true }
    let err = underlyingError(err);
    if err == target {
        return true;
    }
    // Go: "To preserve prior behavior, only examine syscall errors."
    // The concrete assertion is `err.(syscallErrorType)`, which on unix
    // is `syscall.Errno`; `e.Is(target)` is the errno→sentinel table.
    return match errors::AsConcrete::<syscall::Errno>(&err) {
        Some(e) => ErrorTrait::Is(e, &target),
        None => false,
    };
}

// go: sdk 1.25.5 os/error.go:131-140 underlyingError
/// Go: "underlyingError returns the underlying error for known os error
/// types." A SHALLOW type switch — it peels exactly one layer, and only
/// off the three types os itself builds.
pub fn underlyingError(err: error) -> error {
    if let Some(e) = errors::AsConcrete::<PathError>(&err) {
        return e.Err.clone();
    }
    if let Some(e) = errors::AsConcrete::<super::LinkError>(&err) {
        return e.Err.clone();
    }
    if let Some(e) = errors::AsConcrete::<SyscallError>(&err) {
        return e.Err.clone();
    }
    return err;
}
