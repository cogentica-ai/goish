// net/tcpsock — Go 1.25.5 src/net/tcpsock.go.
//
// One `.rs` per `.go` (§33). The TCP socket-option setters live here;
// TCPConn itself and its I/O methods are still declared in net/mod.rs
// and carry no `go: sdk` anchor, so goishlint does not yet see mod.rs
// as holding this file's declarations. Moving them is worth doing and
// is the reason this file exists now rather than later: the setters
// had to go somewhere, and tcpsock.go is where Go declares them.
//
// goishlint reports the rest of tcpsock.go as unported, which it is.
// Of its 32 declarations goish had none of these eighteen before this
// file: SetLinger, SetKeepAlive, SetKeepAlivePeriod, SetNoDelay,
// ReadFrom, WriteTo, SyscallConn, MultipathTCP, ResolveTCPAddr,
// TCPAddrFromAddrPort, AcceptTCP, DialTCP, ListenTCP, roundDurationUp,
// KeepAliveConfig, TCPAddr.AddrPort, isWildcard, opAddr. Four land
// here; the list is the to-do.

#![allow(non_snake_case)]

use crate::errors::error;
use crate::net::TCPConn;
use crate::syscall;
use crate::time::Duration;
use crate::types::int;

// go: sdk 1.25.5 net/tcpsock.go:469-471 roundDurationUp
/// Go: "(d + to - 1) / to" — divide, rounding up, because the kernel
/// takes whole seconds and truncating would arm a shorter timer than
/// the caller asked for.
pub(crate) fn roundDurationUp(d: Duration, to: Duration) -> i64 {
    return (d.0 + to.0 - 1) / to.0;
}

impl TCPConn {
    // go: sdk 1.25.5 net/tcpsock.go:222-231 TCPConn.SetLinger
    /// Go: "sec < 0 (the default) … the operating system finishes
    /// sending the data in the background. If sec == 0, the operating
    /// system discards any unsent or unacknowledged data."
    ///
    /// A negative `sec` clears the option (onoff 0); zero and positive
    /// both set it, with `linger` carrying the seconds.
    pub fn SetLinger(&self, sec: int) -> error {
        // Go's syscall.Linger: two int32s, onoff then linger.
        let secs = i32::try_from(sec).unwrap_or(i32::MAX);
        let l: [i32; 2] = if sec >= 0 { [1, secs] } else { [0, 0] };
        let len = core::mem::size_of::<[i32; 2]>() as u32; // goishlint:ignore GOISH005 - socklen_t, a C ABI width, not a Go value
        return self.__setsockopt(
            syscall::SOL_SOCKET,
            syscall::SO_LINGER,
            l.as_ptr() as *const u8,
            len,
        );
    }

    // go: sdk 1.25.5 net/tcpsock.go:234-242 TCPConn.SetKeepAlive
    /// Go: "sets whether the operating system should send keep-alive
    /// messages on the connection."
    pub fn SetKeepAlive(&self, keepalive: bool) -> error {
        return self.__setsockopt_int(
            syscall::SOL_SOCKET,
            syscall::SO_KEEPALIVE,
            if keepalive { 1 } else { 0 },
        );
    }

    // go: sdk 1.25.5 net/tcpsock.go:249-257 TCPConn.SetKeepAlivePeriod
    /// Go: "sets the duration the connection needs to remain idle
    /// before TCP starts sending keepalive probes."
    ///
    /// IDLE only. It calls `setKeepAliveIdle`, which touches
    /// TCP_KEEPIDLE and leaves TCP_KEEPINTVL where it was — measured:
    /// after SetKeepAlivePeriod(30s), KEEPIDLE is 30 and KEEPINTVL is
    /// still 15. A port that sets both, as older Go did, diverges.
    ///
    /// Zero means the default idle, and NEGATIVE is a no-op returning
    /// nil rather than an error (tcpsockopt_unix.go:18-20).
    pub fn SetKeepAlivePeriod(&self, d: Duration) -> error {
        let d = if d.0 == 0 {
            super::dial::defaultTCPKeepAliveIdle
        } else if d.0 < 0 {
            return crate::errors::nil;
        } else {
            d
        };
        // The kernel expects seconds, rounded to the next highest.
        let secs = roundDurationUp(d, crate::time::Second);
        let secs = i32::try_from(secs).unwrap_or(i32::MAX);
        return self.__setsockopt_int(syscall::IPPROTO_TCP, syscall::TCP_KEEPIDLE, secs);
    }

    // go: sdk 1.25.5 net/tcpsock.go:263-271 TCPConn.SetNoDelay
    /// Go: "controls whether the operating system should delay packet
    /// transmission in hopes of sending fewer packets (Nagle's
    /// algorithm). The default is true (no delay)."
    pub fn SetNoDelay(&self, noDelay: bool) -> error {
        return self.__setsockopt_int(
            syscall::IPPROTO_TCP,
            syscall::TCP_NODELAY,
            if noDelay { 1 } else { 0 },
        );
    }
}
