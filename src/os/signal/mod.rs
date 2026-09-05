// os/signal — Go's `os/signal` package.
//
// One `.rs` per `.go` (§33): the declarations live in signal.rs,
// which is where Go declares them (os/signal/signal.go). This root
// carries only the module wiring.
//
// Goish uses `chan<i32>` (the signal number) where Go uses
// `chan<- os.Signal`. Go's `os.Signal` is an interface with `String()`
// and `Signal()` over what is internally a `syscall.Signal` — an int
// wrapped. The integer form is more direct and avoids the interface.
// `os::exec_posix::SignalString` renders the name when one is wanted.

mod signal;
pub use signal::{Ignore, Ignored, Notify, NotifyContext, Reset, Stop};
