// go: file internal/syscall/unix/getrandom_linux.go decls:
//
// The Go file declares only the two `GetRandomFlag` constants — no
// functions — so the manifest is empty.

#![allow(non_upper_case_globals, dead_code)]

use super::getrandom::GetRandomFlag;

// go: sdk 1.25.5 internal/syscall/unix/getrandom_linux.go:9 GRND_NONBLOCK
/// `GRND_NONBLOCK` means return EAGAIN rather than blocking.
pub const GRND_NONBLOCK: GetRandomFlag = 0x0001;

// go: sdk 1.25.5 internal/syscall/unix/getrandom_linux.go:12 GRND_RANDOM
/// `GRND_RANDOM` means use the /dev/random pool instead of /dev/urandom.
pub const GRND_RANDOM: GetRandomFlag = 0x0002;
