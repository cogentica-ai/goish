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
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::string;
use crate::io;
use crate::runtime::netpoll::{self, BlockResult, PollDesc};
use alloc::sync::Arc;
use crate::syscall;
use crate::types::{byte, int};

mod parse;
pub mod http;

pub use parse::TCPAddr;

/// `EAGAIN` / `EWOULDBLOCK` (Linux: same value, 11). The non-blocking
/// I/O retry signal — caller parks on the netpoller and re-attempts.
const EAGAIN: i32 = 11;
/// `EINPROGRESS` (Linux: 115). Returned by non-blocking `connect(2)`
/// to indicate the connection handshake is underway.
const EINPROGRESS: i32 = 115;
/// `EINTR` (Linux: 4). Syscall interrupted by signal — caller retries
/// the syscall directly without parking.
const EINTR: i32 = 4;

// ─── Listener ────────────────────────────────────────────────────────

/// `net.Listener` for TCP. Wraps a listening socket fd plus a lazily-
/// registered netpoll `PollDesc`. Send across goroutines is sound: the
/// fd is read-only after construction and `pd` / `closed` are atomic.
pub struct Listener {
    fd: i32,
    addr: TCPAddr,
    /// PollDesc registered the first time `Accept` hits EAGAIN; null
    /// before that. Lazy registration matches Go's `internal/poll.FD`
    /// shape and avoids paying epoll_ctl on a one-shot listener.
    pd: AtomicPtr<PollDesc>,
    /// True after `Close` has run. Used by `Close` itself for
    /// idempotency and by `Drop` to skip the close on a Listener
    /// that the user already closed explicitly.
    closed: AtomicBool,
}

unsafe impl Send for Listener {}
unsafe impl Sync for Listener {}

impl Listener {
    /// `(*TCPListener).Accept` — return a new `Conn` for the next
    /// connecting peer, parking the calling goroutine on the netpoller
    /// while the accept queue is empty. Mirrors Go's
    /// `func (l *TCPListener) Accept() (Conn, error)` (net/tcpsock.go).
    pub fn Accept(&self) -> (Conn, error) {
        loop {
            let mut peer = syscall::SockaddrIn::loopback(0);
            let mut peer_len: u32 = core::mem::size_of::<syscall::SockaddrIn>() as u32;
            let fd = syscall::Accept4(
                self.fd,
                &mut peer,
                &mut peer_len,
                syscall::SOCK_CLOEXEC | syscall::SOCK_NONBLOCK,
            );
            if fd >= 0 {
                return (
                    Conn::from_accepted(fd, self.addr.clone(), TCPAddr::from_sockaddr_in(&peer)),
                    errors::nil,
                );
            }
            let errno = -fd;
            if errno == EINTR {
                continue;
            }
            if errno == EAGAIN {
                let pd = self.ensure_pd();
                if pd.is_null() {
                    return (Conn::dead(), errno_error("accept", errno));
                }
                match netpoll::block(unsafe { &*pd }, b'r') {
                    BlockResult::Ready | BlockResult::Aborted => continue,
                    BlockResult::Timedout => {
                        return (Conn::dead(), timeout_error("accept"));
                    }
                }
            }
            return (Conn::dead(), errno_error("accept", errno));
        }
    }

    /// `(*TCPListener).Close` — stop listening and drop the fd.
    /// Idempotent: a second call is a no-op (mirrors Go's
    /// `onceCloseListener` server-side wrapper).
    pub fn Close(&self) -> error {
        if self.closed.swap(true, Ordering::AcqRel) {
            return errors::nil;
        }
        let pd_raw = self.pd.swap(ptr::null_mut(), Ordering::AcqRel);
        if !pd_raw.is_null() {
            // Reconstitute the Arc that ensure_pd stashed via
            // Arc::into_raw, then hand to netpoll::close which
            // releases the slab's clone and drops the caller's Arc.
            let arc = unsafe { Arc::from_raw(pd_raw as *const PollDesc) };
            netpoll::close(arc);
        }
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

    /// Internal raw fd accessor — used by `http::Server.Shutdown` to
    /// close the listening socket from another goroutine. Not part
    /// of the public Go API.
    #[doc(hidden)]
    pub fn __fd(&self) -> i32 {
        self.fd
    }

    /// Internal: wake any goroutine parked in Accept by force-
    /// expiring the read deadline on the listener's PollDesc.
    /// Closing the underlying fd alone does not wake an Accept
    /// parked on netpoll — kernel `close(2)` removes the fd from
    /// epoll's interest set and pending events on it are dropped,
    /// leaving any parked goroutine permanently stuck. Used by
    /// `http::Server.Shutdown` to break out of a blocked Accept.
    #[doc(hidden)]
    pub fn __wake_accept(&self) {
        let pd = self.ensure_pd();
        if !pd.is_null() {
            netpoll::set_deadline(unsafe { &*pd }, -1, b'r');
        }
    }

    /// `(*TCPListener).SetDeadline(t time.Time)` — set the deadline
    /// for `Accept` calls. Zero `t` clears.
    pub fn SetDeadline(&self, t: crate::time::Time) -> error {
        if self.fd < 0 {
            return errno_error("set deadline", 9);
        }
        let pd = self.ensure_pd();
        if pd.is_null() {
            return errno_error("set deadline/poll_open", 0);
        }
        let dl_ns = deadline_from_time(t);
        netpoll::set_deadline(unsafe { &*pd }, dl_ns, b'r');
        errors::nil
    }

    /// Lazily register the listening fd with the netpoller on the
    /// first EAGAIN. Idempotent / race-safe via AtomicPtr CAS.
    ///
    /// **Lifetime**: the AtomicPtr stores an `Arc<PollDesc>` consumed
    /// via `Arc::into_raw`. `Listener` owns one strong reference for
    /// its lifetime; `Close` / `Drop` recover the Arc with
    /// `Arc::from_raw` and pass it to `netpoll::close`. Reading the
    /// pointer as `&PollDesc` is sound because the Listener is the
    /// owner — the Arc cannot be freed while `&self` is held.
    fn ensure_pd(&self) -> *const PollDesc {
        let cur = self.pd.load(Ordering::Acquire);
        if !cur.is_null() {
            return cur;
        }
        let arc = match netpoll::open(self.fd) {
            Some(a) => a,
            None => return self.pd.load(Ordering::Acquire),
        };
        let new = Arc::into_raw(arc) as *mut PollDesc;
        match self.pd.compare_exchange(
            ptr::null_mut(),
            new,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => new as *const PollDesc,
            Err(_) => {
                // Lost the install race — close our orphan Arc (which
                // also unregisters from the slab/epoll) and use the
                // winner.
                let orphan = unsafe { Arc::from_raw(new as *const PollDesc) };
                netpoll::close(orphan);
                self.pd.load(Ordering::Acquire)
            }
        }
    }
}

// ─── Conn ────────────────────────────────────────────────────────────

/// TCP `net.Conn`. Implements `io::{Reader, Writer, Closer}`. The fd
/// is set non-blocking; Read/Write park on the netpoller when the
/// kernel returns EAGAIN.
pub struct Conn {
    fd: i32,
    local: TCPAddr,
    remote: TCPAddr,
    /// Lazy-init netpoll registration. Null on a `dead()` conn or
    /// before the first EAGAIN; populated via `ensure_pd`.
    pd: AtomicPtr<PollDesc>,
}

unsafe impl Send for Conn {}
unsafe impl Sync for Conn {}

impl Conn {
    /// Internal: dead-conn placeholder returned alongside an error.
    /// Caller must ignore the conn when the error is non-nil.
    fn dead() -> Self {
        Conn {
            fd: -1,
            local: TCPAddr::zero(),
            remote: TCPAddr::zero(),
            pd: AtomicPtr::new(ptr::null_mut()),
        }
    }

    /// Wrap a freshly-accepted fd. The fd is already SOCK_NONBLOCK
    /// (the Accept4 caller passed the flag).
    fn from_accepted(fd: i32, local: TCPAddr, remote: TCPAddr) -> Self {
        Conn {
            fd,
            local,
            remote,
            pd: AtomicPtr::new(ptr::null_mut()),
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

    /// `(*TCPConn).SetReadDeadline(t time.Time)` — set the deadline
    /// for future Read calls. Zero `t` clears any existing deadline.
    /// A read in progress when the deadline expires returns
    /// `"i/o timeout"`.
    pub fn SetReadDeadline(&self, t: crate::time::Time) -> error {
        self.set_deadline_internal(t, b'r')
    }

    /// `(*TCPConn).SetWriteDeadline(t time.Time)` — set the deadline
    /// for future Write calls. Same semantics as SetReadDeadline.
    pub fn SetWriteDeadline(&self, t: crate::time::Time) -> error {
        self.set_deadline_internal(t, b'w')
    }

    /// `(*TCPConn).SetDeadline(t time.Time)` — set both read and
    /// write deadlines. Equivalent to calling SetReadDeadline +
    /// SetWriteDeadline with the same `t`.
    pub fn SetDeadline(&self, t: crate::time::Time) -> error {
        let _ = self.set_deadline_internal(t, b'r');
        self.set_deadline_internal(t, b'w')
    }

    fn set_deadline_internal(&self, t: crate::time::Time, mode: u8) -> error {
        if self.fd < 0 {
            return errno_error("set deadline", 9);
        }
        let pd = self.ensure_pd();
        if pd.is_null() {
            return errno_error("set deadline/poll_open", 0);
        }
        let dl_ns = deadline_from_time(t);
        netpoll::set_deadline(unsafe { &*pd }, dl_ns, mode);
        errors::nil
    }

    /// Lazy netpoll registration on first EAGAIN. Idempotent.
    /// See `Listener::ensure_pd` for the lifetime invariants of the
    /// AtomicPtr ↔ Arc conversion.
    fn ensure_pd(&self) -> *const PollDesc {
        let cur = self.pd.load(Ordering::Acquire);
        if !cur.is_null() {
            return cur;
        }
        let arc = match netpoll::open(self.fd) {
            Some(a) => a,
            None => return self.pd.load(Ordering::Acquire),
        };
        let new = Arc::into_raw(arc) as *mut PollDesc;
        match self.pd.compare_exchange(
            ptr::null_mut(),
            new,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => new as *const PollDesc,
            Err(_) => {
                let orphan = unsafe { Arc::from_raw(new as *const PollDesc) };
                netpoll::close(orphan);
                self.pd.load(Ordering::Acquire)
            }
        }
    }
}

impl io::Reader for Conn {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        let len = p.len();
        let ptr = p.as_mut_ptr();
        loop {
            let n = syscall::Read(self.fd, ptr, len);
            if n >= 0 {
                if n == 0 {
                    return (0, io::EOF());
                }
                return (n as int, errors::nil);
            }
            let errno = -(n as i32);
            if errno == EINTR {
                continue;
            }
            if errno == EAGAIN {
                let pd = self.ensure_pd();
                if pd.is_null() {
                    return (0, errno_error("read", errno));
                }
                match netpoll::block(unsafe { &*pd }, b'r') {
                    BlockResult::Ready | BlockResult::Aborted => continue,
                    BlockResult::Timedout => return (0, timeout_error("read")),
                }
            }
            return (0, errno_error("read", errno));
        }
    }
}

impl io::Writer for Conn {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Drain the buffer; partial writes loop. Matches Go's
        // internal/poll.FD.Write which keeps writing until n == len(p)
        // or an error is hit.
        let total = p.len();
        let base = p.as_ptr();
        let mut off: usize = 0;
        while off < total {
            let n = syscall::Write(self.fd, unsafe { base.add(off) }, total - off);
            if n > 0 {
                off += n as usize;
                continue;
            }
            if n == 0 {
                // Linux write(2) returning 0 on a non-zero buffer is
                // unexpected for sockets; treat as a generic I/O
                // error rather than spinning.
                return (off as int, errno_error("write", 5));
            }
            let errno = -(n as i32);
            if errno == EINTR {
                continue;
            }
            if errno == EAGAIN {
                let pd = self.ensure_pd();
                if pd.is_null() {
                    return (off as int, errno_error("write", errno));
                }
                match netpoll::block(unsafe { &*pd }, b'w') {
                    BlockResult::Ready | BlockResult::Aborted => continue,
                    BlockResult::Timedout => {
                        return (off as int, timeout_error("write"));
                    }
                }
            }
            return (off as int, errno_error("write", errno));
        }
        (off as int, errors::nil)
    }
}

impl io::Closer for Conn {
    fn Close(&mut self) -> error {
        if self.fd < 0 {
            return errors::nil;
        }
        let pd_raw = self.pd.swap(ptr::null_mut(), Ordering::AcqRel);
        if !pd_raw.is_null() {
            // Reconstitute the Arc<PollDesc> that ensure_pd installed
            // via Arc::into_raw, then hand to netpoll::close (which
            // unregisters from the slab and drops the caller's Arc).
            let arc = unsafe { Arc::from_raw(pd_raw as *const PollDesc) };
            netpoll::close(arc);
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

/// Drop closes the fd and unregisters from the netpoller if the user
/// didn't call `Close()` explicitly. Idempotent with `Close` — that
/// path already swaps `pd` to null and `fd` to `-1`, so a Drop on a
/// closed Conn is a no-op. Without this, dropping a Conn without
/// calling Close would leak the OS file descriptor for the lifetime
/// of the process.
impl Drop for Conn {
    fn drop(&mut self) {
        let _ = <Self as io::Closer>::Close(self);
    }
}

/// Same idempotent-Close on Drop for Listener. The `closed` flag in
/// `Close` makes second-call a no-op, so explicit-Close-then-Drop
/// is harmless. This fixes the listening-fd leak when a user binds
/// a Listener and drops it without closing.
impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.Close();
    }
}

// ─── SplitHostPort / JoinHostPort ────────────────────────────────────

/// `net.SplitHostPort(hostport)` (ipsock.go:165) — split a network
/// address of the form `"host:port"`, `"host%zone:port"`,
/// `"[host]:port"`, or `"[host%zone]:port"` into its host and port
/// components. Mirrors Go's strict validation:
///   - Missing port → error.
///   - Host containing ':' (without brackets) → "too many colons".
///   - Stray '[' / ']' outside the IPv6 brackets → error.
pub fn SplitHostPort(hostport: crate::string) -> (crate::string, crate::string, crate::errors::error) {
    let missing_port = "missing port in address";
    let too_many_colons = "too many colons in address";

    // Go: i := bytealg.LastIndexByteString(hostport, ':')
    let i = crate::bytes::LastIndexByte(crate::convert::bytes(hostport.clone()), b':');
    if i < 0 {
        return (
            crate::string::new(),
            crate::string::new(),
            addr_error(hostport, missing_port),
        );
    }

    let i = i as i64;
    let h_bytes = hostport.as_bytes();
    let mut host: crate::string;
    let mut j: i64 = 0;
    let mut k: i64 = 0;

    if h_bytes[0] == b'[' {
        // Go: end := bytealg.IndexByteString(hostport, ']')
        let end = crate::bytes::IndexByte(crate::convert::bytes(hostport.clone()), b']');
        if end < 0 {
            return (
                crate::string::new(),
                crate::string::new(),
                addr_error(hostport, "missing ']' in address"),
            );
        }
        let end = end as i64;
        // Go: switch end+1 { case len(hostport): … case i: … default: … }
        if end + 1 == hostport.Len() {
            return (
                crate::string::new(),
                crate::string::new(),
                addr_error(hostport, missing_port),
            );
        } else if end + 1 == i {
            // ok
        } else if h_bytes[(end + 1) as usize] == b':' {
            return (
                crate::string::new(),
                crate::string::new(),
                addr_error(hostport, too_many_colons),
            );
        } else {
            return (
                crate::string::new(),
                crate::string::new(),
                addr_error(hostport, missing_port),
            );
        }
        // Go: host = hostport[1:end]
        host = crate::string::from_bytes(&h_bytes[1..end as usize]);
        // Go: j, k = 1, end+1
        j = 1;
        k = end + 1;
    } else {
        // Go: host = hostport[:i]
        host = crate::string::from_bytes(&h_bytes[..i as usize]);
        // Go: if bytealg.IndexByteString(host, ':') >= 0 { tooManyColons }
        if crate::bytes::IndexByte(crate::convert::bytes(host.clone()), b':') >= 0 {
            return (
                crate::string::new(),
                crate::string::new(),
                addr_error(hostport, too_many_colons),
            );
        }
    }
    // Go: if bytealg.IndexByteString(hostport[j:], '[') >= 0 { ... }
    if crate::bytes::IndexByte(
        crate::convert::bytes(crate::string::from_bytes(&h_bytes[j as usize..])),
        b'[',
    ) >= 0
    {
        return (
            crate::string::new(),
            crate::string::new(),
            addr_error(hostport, "unexpected '[' in address"),
        );
    }
    // Go: if bytealg.IndexByteString(hostport[k:], ']') >= 0 { ... }
    if crate::bytes::IndexByte(
        crate::convert::bytes(crate::string::from_bytes(&h_bytes[k as usize..])),
        b']',
    ) >= 0
    {
        return (
            crate::string::new(),
            crate::string::new(),
            addr_error(hostport, "unexpected ']' in address"),
        );
    }
    // Go: port = hostport[i+1:]
    let port = crate::string::from_bytes(&h_bytes[(i + 1) as usize..]);
    let _ = host.clone(); // silence unused-mut
    (host, port, crate::errors::nil)
}

/// `net.JoinHostPort(host, port)` (ipsock.go:236) — combine `host`
/// and `port` into a `"host:port"` (or `"[host]:port"` for IPv6
/// literals containing `:`).
pub fn JoinHostPort(host: crate::string, port: crate::string) -> crate::string {
    // Go: if bytealg.IndexByteString(host, ':') >= 0 { return "[" + host + "]:" + port }
    if crate::bytes::IndexByte(crate::convert::bytes(host.clone()), b':') >= 0 {
        let mut b = crate::strings::Builder::new();
        b.Grow(host.Len() + port.Len() + 3);
        let _ = b.WriteByte(b'[');
        let _ = b.WriteString(host);
        let _ = b.WriteString("]:");
        let _ = b.WriteString(port);
        return b.String();
    }
    // Go: return host + ":" + port
    let mut b = crate::strings::Builder::new();
    b.Grow(host.Len() + port.Len() + 1);
    let _ = b.WriteString(host);
    let _ = b.WriteByte(b':');
    let _ = b.WriteString(port);
    b.String()
}

/// Slim `*AddrError` analogue for SplitHostPort error messages.
fn addr_error(addr: crate::string, why: &str) -> crate::errors::error {
    let mut b = crate::strings::Builder::new();
    let _ = b.WriteString("address ");
    let _ = b.WriteString(addr);
    let _ = b.WriteString(": ");
    let _ = b.WriteString(why);
    crate::errors::New(b.String())
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
        syscall::SOCK_STREAM | syscall::SOCK_CLOEXEC | syscall::SOCK_NONBLOCK,
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
            pd: AtomicPtr::new(ptr::null_mut()),
            closed: AtomicBool::new(false),
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
        syscall::SOCK_STREAM | syscall::SOCK_CLOEXEC | syscall::SOCK_NONBLOCK,
        syscall::IPPROTO_TCP,
    );
    if fd < 0 {
        return (Conn::dead(), errno_error("socket", -fd));
    }

    // Non-blocking connect: returns 0 if the kernel completed the
    // handshake immediately (rare for TCP), or -EINPROGRESS while the
    // SYN/SYN-ACK exchange is in flight. In the in-flight case we
    // park on the netpoller for write-readiness, then read SO_ERROR
    // to learn the connect outcome (Go's `internal/poll.FD.Connect`).
    let r = syscall::Connect(
        fd,
        &parsed,
        core::mem::size_of::<syscall::SockaddrIn>() as u32,
    );
    if r < 0 {
        let errno = -r;
        if errno != EINPROGRESS {
            let _ = syscall::Close(fd);
            return (Conn::dead(), errno_error("connect", errno));
        }
        // Wait for the connect to finalize.
        let arc = match netpoll::open(fd) {
            Some(a) => a,
            None => {
                let _ = syscall::Close(fd);
                return (Conn::dead(), errno_error("connect/poll_open", 0));
            }
        };
        // Connect has no deadline in this Dial path (v1); a future
        // DialTimeout would `set_deadline(pd, …, b'w')` before this
        // call and translate Timedout into a connect-timeout error.
        if let BlockResult::Timedout = netpoll::block(&arc, b'w') {
            netpoll::close(arc);
            let _ = syscall::Close(fd);
            return (Conn::dead(), timeout_error("connect"));
        }
        // SO_ERROR carries the asynchronous connect result. Zero
        // means success; anything else is the errno from the failed
        // 3-way handshake.
        let mut so_err: i32 = 0;
        let mut so_err_len: u32 = core::mem::size_of::<i32>() as u32;
        let _ = syscall::Getsockopt(
            fd,
            syscall::SOL_SOCKET,
            syscall::SO_ERROR,
            &mut so_err as *mut i32 as *mut u8,
            &mut so_err_len,
        );
        if so_err != 0 {
            netpoll::close(arc);
            let _ = syscall::Close(fd);
            return (Conn::dead(), errno_error("connect", so_err));
        }
        // Connect succeeded — recover both ends. We move the Arc
        // into the new Conn's AtomicPtr via Arc::into_raw, so the
        // strong count is preserved (Conn owns one ref; slab owns
        // one ref).
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
        let pd_raw = Arc::into_raw(arc) as *mut PollDesc;
        return (
            Conn {
                fd,
                local: TCPAddr::from_sockaddr_in(&local),
                remote: TCPAddr::from_sockaddr_in(&parsed),
                pd: AtomicPtr::new(pd_raw),
            },
            errors::nil,
        );
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
            pd: AtomicPtr::new(ptr::null_mut()),
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
        pd: AtomicPtr::new(ptr::null_mut()),
        // Mark as already-closed so Drop skips the syscall::Close(-1)
        // round-trip — fd is the sentinel, not a real handle.
        closed: AtomicBool::new(true),
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

/// Convert a `time.Time` deadline to a CLOCK_MONOTONIC-nanos value
/// suitable for `netpoll::set_deadline`. Zero time → 0 (clear);
/// already-past time → -1 (immediate expiry); future time → absolute
/// monotonic ns of the deadline. Mirrors the start of Go's
/// `poll_runtime_pollSetDeadline` (netpoll.go:380), where `d > 0`
/// gets `d += nanotime()`.
fn deadline_from_time(t: crate::time::Time) -> i64 {
    if t.IsZero() {
        return 0;
    }
    let dur = crate::time::Until(t);
    let ns = dur.Nanoseconds();
    if ns <= 0 {
        return -1;
    }
    crate::runtime::sysmon::monotonic_ns().wrapping_add(ns as i64)
}

/// Build a "i/o timeout" error matching Go's net.OpError +
/// `Err: errors.New("i/o timeout")` pattern. Returned when a
/// `SetReadDeadline` / `SetWriteDeadline` fires before the I/O
/// completes. Callers can still inspect the error; v1 does not yet
/// expose `IsTimeout()` — the message is the contract.
fn timeout_error(op: &str) -> error {
    let mut buf: Vec<u8> = Vec::with_capacity(32);
    buf.extend_from_slice(op.as_bytes());
    buf.extend_from_slice(b": i/o timeout");
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
