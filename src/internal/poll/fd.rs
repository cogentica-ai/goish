// go: file internal/poll/fd.go decls: DeadlineExceededError.Error, DeadlineExceededError.Timeout, DeadlineExceededError.Temporary
// goishlint:ignore GOISH021 String, errNetClosing, ErrFileClosing, ErrNetClosing, TestHookDidWritev — the same reason as the line below: these belong to the FD type and its closing protocol, which goish does not have.
// goishlint:ignore GOISH018 errClosing, FD.eofError, FD.Shutdown, FD.Fchown, FD.Ftruncate, FD.Fsync, FD.RawControl, consume, ignoringEINTRIO — fd.go is mostly the FD type and its methods, and goish's descriptor runtime is not this one: sockets go through `net`, files through `os`, and both call the kernel directly rather than through a shared poller. What the rest of the tree DOES need from this file is the pair of deadline sentinels `os` re-exports, and they cannot be declared anywhere else without giving `os.ErrDeadlineExceeded` and `net`'s deadline error two different identities — which is exactly the bug Go's comment on `errDeadlineExceeded` warns about.

use crate::errors::ErrorTrait;
use crate::gostring::string;

// go: sdk 1.25.5 internal/poll/fd.go:54-54 DeadlineExceededError
/// Go: "DeadlineExceededError is returned for an expired deadline."
///
/// The concrete type is public because an interface assertion in goish
/// reaches the concrete error, not the handle — see `errors::AsIface`.
#[derive(Copy, Clone, Default)]
pub struct DeadlineExceededError;

impl ErrorTrait for DeadlineExceededError {
    // go: sdk 1.25.5 internal/poll/fd.go:60-60 DeadlineExceededError.Error
    /// Go: "The string is "i/o timeout" because that is what was
    /// returned by earlier Go versions. Changing it may break programs
    /// that match on error strings."
    fn Error(&self) -> string {
        return string::from_static("i/o timeout");
    }
}

impl DeadlineExceededError {
    // go: sdk 1.25.5 internal/poll/fd.go:61-61 DeadlineExceededError.Timeout
    pub fn Timeout(&self) -> bool {
        return true;
    }

    // go: sdk 1.25.5 internal/poll/fd.go:62-62 DeadlineExceededError.Temporary
    pub fn Temporary(&self) -> bool {
        return true;
    }
}

// Go: fd.go:37-51
//
//   var ErrNoDeadline = errors.New("file type does not support deadline")
//   var ErrDeadlineExceeded error = &DeadlineExceededError{}
//   var ErrNotPollable = errors.New("not pollable")
//
// Cached singletons, so `errors::Is(err, os::ErrDeadlineExceeded)`
// compares one identity and not two copies of a string.
//
// Go's comment on `os.errDeadlineExceeded` explains why the middle one
// lives here rather than in `os`: "This error comes from the
// internal/poll package, which is also used by package net. Doing it
// this way ensures that the net package will return
// os.ErrDeadlineExceeded for an exceeded deadline … without requiring
// the internal/poll package to import os (which it cannot, because that
// would be circular)."
crate::var! {
    pub ErrNoDeadline: error = "file type does not support deadline";
    pub ErrDeadlineExceeded: error = { DeadlineExceededError };
    pub ErrNotPollable: error = "not pollable";
}
