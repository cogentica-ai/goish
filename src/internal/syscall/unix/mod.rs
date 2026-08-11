// go: package internal/syscall/unix

mod getrandom;
mod getrandom_linux;
mod sysnum_linux_amd64;

pub use getrandom::{GetRandom, GetRandomFlag};
pub use getrandom_linux::{GRND_NONBLOCK, GRND_RANDOM};
