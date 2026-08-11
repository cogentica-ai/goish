// go: file internal/syscall/unix/sysnum_linux_amd64.go decls:
//
// The Go file declares only syscall-number constants — no functions —
// so the manifest is empty.
//
// Linux/amd64 system-call numbers used by `internal/syscall/unix`.
// Every one of Go's five is carried so the file stays a 1:1 mirror,
// even though only `getrandomTrap` has a caller in goish today —
// `copy_file_range`, `pidfd_send_signal`, `pidfd_open` and `openat2`
// arrive with their own ports.

#![allow(non_upper_case_globals, dead_code)]

use crate::types::uintptr;

// go: sdk 1.25.5 internal/syscall/unix/sysnum_linux_amd64.go:8 getrandomTrap
pub(crate) const getrandomTrap: uintptr = 318;

// go: sdk 1.25.5 internal/syscall/unix/sysnum_linux_amd64.go:9 copyFileRangeTrap
pub(crate) const copyFileRangeTrap: uintptr = 326;

// go: sdk 1.25.5 internal/syscall/unix/sysnum_linux_amd64.go:10 pidfdSendSignalTrap
pub(crate) const pidfdSendSignalTrap: uintptr = 424;

// go: sdk 1.25.5 internal/syscall/unix/sysnum_linux_amd64.go:11 pidfdOpenTrap
pub(crate) const pidfdOpenTrap: uintptr = 434;

// go: sdk 1.25.5 internal/syscall/unix/sysnum_linux_amd64.go:12 openat2Trap
pub(crate) const openat2Trap: uintptr = 437;
