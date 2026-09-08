// term — module root for goish's `golang.org/x/term` port.
//
// The port itself is in `term.rs`, one `.rs` per `.go` as everywhere
// else; this file only re-exports it, so `term::IsTerminal(fd)` and
// the rest keep the spelling Go gives them.

mod term;

pub use term::{GetSize, GetState, IsTerminal, MakeRaw, Restore, State};
