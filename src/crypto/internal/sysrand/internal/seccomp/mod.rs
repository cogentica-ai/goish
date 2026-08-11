// go: package crypto/internal/sysrand/internal/seccomp

mod seccomp_unsupported;

pub use seccomp_unsupported::DisableGetrandom;
