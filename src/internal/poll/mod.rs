// go: package internal/poll
//
// Package poll supports non-blocking I/O on file descriptors with
// polling. goish's fd runtime lives in `runtime` and `net`, so this
// ports only the piece the rest of the tree cannot do without: the two
// deadline sentinels `os` re-exports, and the error type behind one of
// them.

mod fd;

pub use fd::{
    DeadlineExceededError, ErrDeadlineExceeded, ErrFileClosing, ErrNoDeadline, ErrNotPollable,
};
