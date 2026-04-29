// net — Go's `net` package, ported (M27b — TCP only, blocking I/O).
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   net.Listen("tcp", ":8080")           net::Listen(string("tcp"), string(":8080"))
//   net.Dial("tcp", "127.0.0.1:8080")    net::Dial(string("tcp"), string("127.0.0.1:8080"))
//   ln.Accept()                          ln.Accept()
//   conn.Read(buf)                       conn.Read(buf)   // io::Reader
//   conn.Write(buf)                      conn.Write(buf)  // io::Writer
//   conn.Close()                         conn.Close()     // io::Closer
//
// **Public-API discipline (priority #2/#3)**: every signature uses
// goish lowercase types (`string`, `slice<byte>`, `int`, multi-return
// tuples). No `Vec<u8>`, `&str`, `&[u8]`, `String` leak. Internal
// scratch is plain Rust; convert at the boundary.
//
// **Concurrency model — Phase A (M27b)**: blocking syscalls. A
// goroutine that calls `Accept` / `Read` / `Write` blocks the OS
// thread (M) hosting it. With NumCPU Ms, that caps in-flight blocking
// calls at NumCPU. For HTTP-server-style "goroutine per connection"
// this means you get NumCPU concurrent in-flight requests; the rest
// queue. Sufficient for a useful demo. Phase B (M27e) introduces an
// epoll netpoller that lifts this cap.
//
// **What's not in v1**:
//   - DNS resolution: only IP-literal addresses (`127.0.0.1:8080`,
//     `0.0.0.0:8080`, `[::1]:8080`). Hostnames return an error.
//   - IPv6: stub TCPAddr only stores v4; the parser rejects v6.
//   - UDP / Unix domain: TCP only.
//   - Deadlines / timeouts: the API surface is present but a no-op
//     in Phase A; needs the netpoller to be useful.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::string;
use crate::io;
use crate::syscall;
use crate::types::{byte, int};

mod parse;
pub mod http;

pub use parse::TCPAddr;

// ─── Listener ────────────────────────────────────────────────────────

/// `net.Listener` for TCP. Wraps a listening socket fd.
pub struct Listener {
    fd: i32,
    addr: TCPAddr,
}

impl Listener {
    /// `(*TCPListener).Accept` — block until a peer connects, return a
    /// new `Conn`. Mirrors Go's `func (l *TCPListener) Accept() (Conn, error)`
    /// (net/tcpsock.go).
    pub fn Accept(&self) -> (Conn, error) {
        let mut peer = syscall::SockaddrIn::loopback(0);
        let mut peer_len: u32 = core::mem::size_of::<syscall::SockaddrIn>() as u32;
        let fd = syscall::Accept4(
            self.fd,
            &mut peer,
            &mut peer_len,
            syscall::SOCK_CLOEXEC,
        );
        if fd < 0 {
            return (
                Conn::dead(),
                errno_error("accept", -fd),
            );
        }
        (
            Conn {
                fd,
                local: self.addr.clone(),
                remote: TCPAddr::from_sockaddr_in(&peer),
            },
            errors::nil,
        )
    }

    /// `(*TCPListener).Close` — stop listening and drop the fd.
    pub fn Close(&self) -> error {
        let r = syscall::Close(self.fd);
        if r < 0 {
            errno_error("close", -r)
        } else {
            errors::nil
        }
    }

    /// `(*TCPListener).Addr` — return the bound address (with the
    /// kernel-assigned port substituted in if the user asked for `:0`).
    pub fn Addr(&self) -> TCPAddr {
        self.addr.clone()
    }
}

// ─── Conn ────────────────────────────────────────────────────────────

/// TCP `net.Conn`. Implements `io::{Reader, Writer, Closer}`.
pub struct Conn {
    fd: i32,
    local: TCPAddr,
    remote: TCPAddr,
}

impl Conn {
    /// Internal: dead-conn placeholder returned alongside an error.
    /// Caller must ignore the conn when the error is non-nil.
    fn dead() -> Self {
        Conn {
            fd: -1,
            local: TCPAddr::zero(),
            remote: TCPAddr::zero(),
        }
    }

    /// Local end address.
    pub fn LocalAddr(&self) -> TCPAddr {
        self.local.clone()
    }

    /// Remote (peer) address.
    pub fn RemoteAddr(&self) -> TCPAddr {
        self.remote.clone()
    }

    /// Half-close the write direction (sends FIN). Mirrors
    /// `(*TCPConn).CloseWrite`. Useful for "I'm done sending; expect
    /// EOF on the read side from the peer's response now."
    pub fn CloseWrite(&self) -> error {
        let r = syscall::Shutdown(self.fd, syscall::SHUT_WR);
        if r < 0 {
            errno_error("shutdown(write)", -r)
        } else {
            errors::nil
        }
    }

    /// Half-close the read direction.
    pub fn CloseRead(&self) -> error {
        let r = syscall::Shutdown(self.fd, syscall::SHUT_RD);
        if r < 0 {
            errno_error("shutdown(read)", -r)
        } else {
            errors::nil
        }
    }

    /// Internal raw fd accessor — used by `bufio` adapters and by
    /// the (future) netpoller. **Not** part of the public Go API.
    #[doc(hidden)]
    pub fn __fd(&self) -> i32 {
        self.fd
    }
}

impl io::Reader for Conn {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        let len = p.len();
        let ptr = p.as_mut_ptr();
        let n = syscall::Read(self.fd, ptr, len);
        if n < 0 {
            return (0, errno_error("read", -(n as i32)));
        }
        if n == 0 {
            return (0, io::EOF());
        }
        (n as int, errors::nil)
    }
}

impl io::Writer for Conn {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let n = syscall::Write(self.fd, p.as_ptr(), p.len());
        if n < 0 {
            return (0, errno_error("write", -(n as i32)));
        }
        (n as int, errors::nil)
    }
}

impl io::Closer for Conn {
    fn Close(&mut self) -> error {
        if self.fd < 0 {
            return errors::nil;
        }
        let r = syscall::Close(self.fd);
        self.fd = -1;
        if r < 0 {
            errno_error("close", -r)
        } else {
            errors::nil
        }
    }
}

// ─── Listen / Dial ───────────────────────────────────────────────────

/// `net.Listen` — open a listening socket. `network` must be `"tcp"`
/// or `"tcp4"`; other values return an error. `addr` is in
/// `"host:port"` form. `host` may be empty (binds wildcard) or an
/// IPv4 dotted literal; hostname resolution is not implemented in
/// v1. Port `:0` lets the kernel pick a free port (recovered via
/// `Listener.Addr()`).
pub fn Listen(network: string, addr: string) -> (Listener, error) {
    if !is_tcp_network(&network) {
        return (
            dead_listener(),
            errors::New(string("net: only \"tcp\" / \"tcp4\" supported")),
        );
    }
    let parsed = match parse::parse_listen_addr(&addr) {
        Ok(s) => s,
        Err(msg) => return (dead_listener(), errors::New(msg)),
    };

    let fd = syscall::Socket(
        syscall::AF_INET,
        syscall::SOCK_STREAM | syscall::SOCK_CLOEXEC,
        syscall::IPPROTO_TCP,
    );
    if fd < 0 {
        return (dead_listener(), errno_error("socket", -fd));
    }

    // SO_REUSEADDR so a quick restart doesn't fail on TIME_WAIT.
    let one: i32 = 1;
    let _ = syscall::Setsockopt(
        fd,
        syscall::SOL_SOCKET,
        syscall::SO_REUSEADDR,
        &one as *const i32 as *const u8,
        core::mem::size_of::<i32>() as u32,
    );

    let r = syscall::Bind(
        fd,
        &parsed,
        core::mem::size_of::<syscall::SockaddrIn>() as u32,
    );
    if r < 0 {
        let _ = syscall::Close(fd);
        return (dead_listener(), errno_error("bind", -r));
    }

    // Recover the kernel-assigned port if the user passed `:0`.
    let mut got = syscall::SockaddrIn::loopback(0);
    let mut got_len: u32 = core::mem::size_of::<syscall::SockaddrIn>() as u32;
    let r = unsafe {
        syscall::syscall3(
            syscall::SYS_GETSOCKNAME,
            fd as usize,
            &mut got as *mut _ as usize,
            &mut got_len as *mut _ as usize,
        )
    };
    if r < 0 {
        let _ = syscall::Close(fd);
        return (dead_listener(), errno_error("getsockname", (-r) as i32));
    }

    let r = syscall::Listen(fd, 128);
    if r < 0 {
        let _ = syscall::Close(fd);
        return (dead_listener(), errno_error("listen", -r));
    }

    (
        Listener {
            fd,
            addr: TCPAddr::from_sockaddr_in(&got),
        },
        errors::nil,
    )
}

/// `net.Dial` — connect to a TCP peer. `network` must be `"tcp"` or
/// `"tcp4"`. `addr` is `"host:port"` with `host` an IPv4 literal
/// (DNS resolution is not implemented in v1).
pub fn Dial(network: string, addr: string) -> (Conn, error) {
    if !is_tcp_network(&network) {
        return (
            Conn::dead(),
            errors::New(string("net: only \"tcp\" / \"tcp4\" supported")),
        );
    }
    let parsed = match parse::parse_dial_addr(&addr) {
        Ok(s) => s,
        Err(msg) => return (Conn::dead(), errors::New(msg)),
    };

    let fd = syscall::Socket(
        syscall::AF_INET,
        syscall::SOCK_STREAM | syscall::SOCK_CLOEXEC,
        syscall::IPPROTO_TCP,
    );
    if fd < 0 {
        return (Conn::dead(), errno_error("socket", -fd));
    }

    let r = syscall::Connect(
        fd,
        &parsed,
        core::mem::size_of::<syscall::SockaddrIn>() as u32,
    );
    if r < 0 {
        let _ = syscall::Close(fd);
        return (Conn::dead(), errno_error("connect", -r));
    }

    // Recover both ends.
    let mut local = syscall::SockaddrIn::loopback(0);
    let mut local_len: u32 = core::mem::size_of::<syscall::SockaddrIn>() as u32;
    let _ = unsafe {
        syscall::syscall3(
            syscall::SYS_GETSOCKNAME,
            fd as usize,
            &mut local as *mut _ as usize,
            &mut local_len as *mut _ as usize,
        )
    };

    (
        Conn {
            fd,
            local: TCPAddr::from_sockaddr_in(&local),
            remote: TCPAddr::from_sockaddr_in(&parsed),
        },
        errors::nil,
    )
}

// ─── helpers ─────────────────────────────────────────────────────────

fn is_tcp_network(s: &string) -> bool {
    let bytes = s.as_bytes();
    bytes == b"tcp" || bytes == b"tcp4"
}

fn dead_listener() -> Listener {
    Listener {
        fd: -1,
        addr: TCPAddr::zero(),
    }
}

/// Build a goish `error` from a syscall errno. Includes the operation
/// name and a short message for the most common errnos so callers
/// don't have to map numbers themselves.
fn errno_error(op: &str, errno: i32) -> error {
    let mut buf: Vec<u8> = Vec::with_capacity(64);
    buf.extend_from_slice(op.as_bytes());
    buf.extend_from_slice(b": ");
    buf.extend_from_slice(errno_message(errno).as_bytes());
    errors::New(string::from_bytes(&buf))
}

fn errno_message(errno: i32) -> &'static str {
    match errno {
        0 => "ok",
        1 => "operation not permitted",
        4 => "interrupted system call",
        9 => "bad file descriptor",
        11 => "resource temporarily unavailable",
        13 => "permission denied",
        22 => "invalid argument",
        24 => "too many open files",
        32 => "broken pipe",
        98 => "address already in use",
        99 => "cannot assign requested address",
        103 => "connection aborted",
        104 => "connection reset by peer",
        110 => "connection timed out",
        111 => "connection refused",
        _ => "i/o error",
    }
}
