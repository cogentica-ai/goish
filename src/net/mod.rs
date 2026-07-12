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
mod mac;
pub mod dnsmessage;
mod dnsconfig;
pub mod dnsclient;
pub mod lookup;
pub mod http;
pub mod mail;
pub mod textproto;
pub mod url;

pub use mac::{HardwareAddr, HardwareAddrString, ParseMAC};
pub use parse::TCPAddr;
pub use lookup::{
    Resolver, IPAddr as LookupIPAddr, SRV, MX, NS,
    LookupHost, LookupIP, LookupCNAME, LookupAddr,
    LookupTXT, LookupNS, LookupMX, LookupSRV,
};

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
    /// `(*TCPListener).Accept` — return a new `TCPConn` for the next
    /// connecting peer, parking the calling goroutine on the netpoller
    /// while the accept queue is empty. Mirrors Go's
    /// `func (l *TCPListener) Accept() (TCPConn, error)` (net/tcpsock.go).
    pub fn Accept(&self) -> (TCPConn, error) {
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
                    TCPConn::from_accepted(fd, self.addr.clone(), TCPAddr::from_sockaddr_in(&peer)),
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
                    return (TCPConn::dead(), errno_error("accept", errno));
                }
                match netpoll::block(unsafe { &*pd }, b'r') {
                    BlockResult::Ready | BlockResult::Aborted => continue,
                    BlockResult::Timedout => {
                        return (TCPConn::dead(), timeout_error("accept"));
                    }
                }
            }
            return (TCPConn::dead(), errno_error("accept", errno));
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

// ─── Conn (trait) and TCPConn (one impl) ───────────────────────────────
//
// Go's `net.Conn` is an interface; Goish carries it as the `Conn`
// trait. `TCPConn` (this file) is the TCP socket implementation that
// `Dial("tcp", …)` / `(*TCPListener).Accept` produce. Other concrete
// impls (UnixConn, future TLSConn) would live in sibling files and
// also implement `Conn`. The reasoner cache shows 51 stdlib slots
// carry `Arc<dyn net::Conn>` — that's why the trait exists separate
// from the struct.

/// Go's `net.Conn` — the connection interface. Method set matches
/// Go's interface verbatim. Anything that wants to be carried as
/// `Arc<dyn net::Conn>` must implement this trait.
#[goish::interface]
pub trait Conn: Send + Sync {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error);
    fn Write(&mut self, p: slice<byte>) -> (int, error);
    fn Close(&mut self) -> error;
    fn LocalAddr(&self) -> TCPAddr;
    fn RemoteAddr(&self) -> TCPAddr;
    fn SetDeadline(&self, t: crate::time::Time) -> error;
    fn SetReadDeadline(&self, t: crate::time::Time) -> error;
    fn SetWriteDeadline(&self, t: crate::time::Time) -> error;
}

/// TCP `net.TCPConn`. Implements `Conn` plus `io::{Reader, Writer, Closer}`.
/// The fd is set non-blocking; Read/Write park on the netpoller when
/// the kernel returns EAGAIN.
pub struct TCPConn {
    fd: i32,
    local: TCPAddr,
    remote: TCPAddr,
    /// Lazy-init netpoll registration. Null on a `dead()` conn or
    /// before the first EAGAIN; populated via `ensure_pd`.
    pd: AtomicPtr<PollDesc>,
}

unsafe impl Send for TCPConn {}
unsafe impl Sync for TCPConn {}

/// `net.Dialer` (Go 1.25 src/net/dial.go) — connection-establishing
/// configuration. Goish v1 carries the Timeout / KeepAlive fields
/// most commonly read; the actual `DialContext`/`Dial` method-typed
/// resolver is exposed via `.DialContext()` returning an opaque
/// `Arc<dyn Fn>` that can be assigned to
/// `http::Transport.DialContext` etc. The closure is inert in v1
/// (each `RoundTrip` dials via `crate::net::Dial` directly).
#[derive(Clone, Default)]
pub struct Dialer {
    pub Timeout: crate::time::Duration,
    pub KeepAlive: crate::time::Duration,
    /// Allow IPv4-or-IPv6 dialing on systems with both stacks. Inert
    /// in v1 (the dial path picks whichever the kernel's address
    /// resolver returns first).
    pub DualStack: bool,
}

impl Dialer {
    /// `(*Dialer).DialContext` — Go method that returns the dial
    /// callback. Goish exposes it as a no-op closure for now (the
    /// real implementation routes through `net::Dial` with the
    /// Dialer's timeouts; deferred until the connection-pool layer
    /// lands).
    pub fn DialContext(&self) -> crate::net::http::DialContextFn {
        alloc::sync::Arc::new(|| {})
    }
}

impl TCPConn {
    /// Internal: dead-conn placeholder returned alongside an error.
    /// Caller must ignore the conn when the error is non-nil.
    fn dead() -> Self {
        TCPConn {
            fd: -1,
            local: TCPAddr::zero(),
            remote: TCPAddr::zero(),
            pd: AtomicPtr::new(ptr::null_mut()),
        }
    }

    /// Wrap a freshly-accepted fd. The fd is already SOCK_NONBLOCK
    /// (the Accept4 caller passed the flag).
    fn from_accepted(fd: i32, local: TCPAddr, remote: TCPAddr) -> Self {
        TCPConn {
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

    /// Internal (net/http server): fd + netpoll registration for the
    /// client-disconnect watcher. Registers the fd with the
    /// netpoller if it isn't yet (idempotent). The returned pointer
    /// stays valid until the conn is Closed/dropped — the caller
    /// (serve_conn) joins its watcher goroutine before either.
    /// Null pd ⇒ registration failed; caller skips watching.
    #[doc(hidden)]
    pub fn __disconnect_watch_parts(&self) -> (i32, *const PollDesc) {
        if self.fd < 0 {
            return (self.fd, ptr::null());
        }
        (self.fd, self.ensure_pd())
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

impl io::Reader for TCPConn {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        let len = p.len();
        let ptr = p.as_mut_ptr();
        loop {
            let n = syscall::Read(self.fd, ptr, len);
            if n >= 0 {
                if n == 0 {
                    return (0, io::EOF.into());
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

impl io::Writer for TCPConn {
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

impl io::Closer for TCPConn {
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

/// `net.Conn` impl for TCPConn — forwards each method to the inherent
/// implementations. Same body, just expressed through the trait so
/// callers can hold `Arc<dyn Conn>` polymorphically (e.g. a future
/// `UnixConn` would also implement this trait).
impl Conn for TCPConn {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        <Self as io::Reader>::Read(self, p)
    }
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        <Self as io::Writer>::Write(self, p)
    }
    fn Close(&mut self) -> error {
        <Self as io::Closer>::Close(self)
    }
    fn LocalAddr(&self) -> TCPAddr {
        TCPConn::LocalAddr(self)
    }
    fn RemoteAddr(&self) -> TCPAddr {
        TCPConn::RemoteAddr(self)
    }
    fn SetDeadline(&self, t: crate::time::Time) -> error {
        TCPConn::SetDeadline(self, t)
    }
    fn SetReadDeadline(&self, t: crate::time::Time) -> error {
        TCPConn::SetReadDeadline(self, t)
    }
    fn SetWriteDeadline(&self, t: crate::time::Time) -> error {
        TCPConn::SetWriteDeadline(self, t)
    }
}

/// Drop closes the fd and unregisters from the netpoller if the user
/// didn't call `Close()` explicitly. Idempotent with `Close` — that
/// path already swaps `pd` to null and `fd` to `-1`, so a Drop on a
/// closed TCPConn is a no-op. Without this, dropping a TCPConn without
/// calling Close would leak the OS file descriptor for the lifetime
/// of the process.
impl Drop for TCPConn {
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
/// `net.IP` (ip.go:37) — `type IP []byte`. Slim port: holds either a
/// 4-byte IPv4 representation or an unset (length-0) "nil" sentinel.
/// IPv6 is deferred (16-byte form not yet supported by the parser).
///
///   Go                                   goish
///   ──────────────────────────────────   ──────────────────────────────────
///   net.IPv4(192, 0, 2, 1)               IPv4(192, 0, 2, 1)            -> IP
///   net.ParseIP("127.0.0.1")             ParseIP(string("127.0.0.1"))  -> IP
///   ip == nil                            ip.IsNil()
///   ip.To4()                             ip.To4()
///   ip.String()                          ip.String()
#[derive(Clone, Default)]
pub struct IP {
    /// Backing bytes. Length 4 for IPv4; length 0 means "nil".
    pub bytes: slice<byte>,
}

impl IP {
    /// `IsNil()` — slim helper, true when the IP is the zero value
    /// (no backing bytes). Mirrors `ip == nil` in Go.
    pub fn IsNil(&self) -> bool {
        self.bytes.Len() == 0
    }

    /// `IP.To4()` (ip.go:255) — return the 4-byte form, or nil-IP if
    /// the address isn't an IPv4. Slim port: with IPv4-only support
    /// the 4-byte form is already canonical, so this returns a clone
    /// when len==4 and a nil IP otherwise.
    pub fn To4(&self) -> IP {
        // Go: if 4-byte → return. If 16-byte v4-mapped → return last 4.
        // Slim: only the 4-byte case exists.
        if self.bytes.Len() == 4 {
            return self.clone();
        }
        IP::default()
    }

    /// `IP.IsUnspecified()` (ip.go:121) — slim. True for the IPv4
    /// "unspecified" address `0.0.0.0`. (Go also matches IPv6 `::`,
    /// but slim has no IPv6 representation.)
    pub fn IsUnspecified(&self) -> bool {
        // Go: ip.Equal(IPv4zero) || ip.Equal(IPv6unspecified)
        let ip4 = self.To4();
        if ip4.bytes.Len() == 4 {
            return ip4.bytes[0] == 0
                && ip4.bytes[1] == 0
                && ip4.bytes[2] == 0
                && ip4.bytes[3] == 0;
        }
        false
    }

    /// `IP.IsLoopback()` (ip.go:126) — slim. True when the IPv4
    /// first octet is 127 (RFC 5735 loopback range 127.0.0.0/8).
    /// IPv6 `::1` not supported in slim.
    pub fn IsLoopback(&self) -> bool {
        // Go: if ip4 := ip.To4(); ip4 != nil { return ip4[0] == 127 }
        let ip4 = self.To4();
        if ip4.bytes.Len() == 4 {
            return ip4.bytes[0] == 127;
        }
        // Go: return ip.Equal(IPv6loopback)
        false
    }

    /// `IP.IsPrivate()` (ip.go:135) — slim. RFC 1918 IPv4 ranges:
    ///   10.0.0.0/8    — first octet 10
    ///   172.16.0.0/12 — first octet 172, second octet 16..31
    ///   192.168.0.0/16 — first octet 192, second octet 168
    /// RFC 4193 IPv6 (fc00::/7) not supported in slim.
    pub fn IsPrivate(&self) -> bool {
        let ip4 = self.To4();
        if ip4.bytes.Len() == 4 {
            // Go: ip4[0] == 10
            if ip4.bytes[0] == 10 {
                return true;
            }
            // Go: ip4[0] == 172 && ip4[1]&0xf0 == 16
            // (`b & 0xf0 == 16` matches 16..31 inclusive — RFC 1918 172.16/12)
            if ip4.bytes[0] == 172 && (ip4.bytes[1] & 0xf0) == 16 {
                return true;
            }
            // Go: ip4[0] == 192 && ip4[1] == 168
            if ip4.bytes[0] == 192 && ip4.bytes[1] == 168 {
                return true;
            }
            return false;
        }
        // Slim: IPv6 unique-local (fc00::/7) not supported.
        false
    }

    /// `IP.IsMulticast()` (ip.go:153) — slim. IPv4 multicast is
    /// 224.0.0.0/4 (first octet's high nibble == 0xE).
    pub fn IsMulticast(&self) -> bool {
        let ip4 = self.To4();
        if ip4.bytes.Len() == 4 {
            // Go: return ip4[0]&0xf0 == 0xe0
            return (ip4.bytes[0] & 0xf0) == 0xe0;
        }
        false
    }

    /// `IP.IsInterfaceLocalMulticast()` (ip.go:162) — slim. IPv6-only
    /// concept (`ff01::/16`); always false for IPv4 / nil. Goish slim
    /// has no IPv6 representation, so this is a constant `false`.
    pub fn IsInterfaceLocalMulticast(&self) -> bool {
        // Go: return len(ip) == IPv6len && ip[0] == 0xff && ip[1]&0x0f == 0x01
        // Slim: no IPv6 → always false.
        false
    }

    /// `IP.IsLinkLocalMulticast()` (ip.go:168) — slim. IPv4
    /// link-local multicast is 224.0.0.0/24 (224.0.0.x).
    pub fn IsLinkLocalMulticast(&self) -> bool {
        let ip4 = self.To4();
        if ip4.bytes.Len() == 4 {
            // Go: ip4[0] == 224 && ip4[1] == 0 && ip4[2] == 0
            return ip4.bytes[0] == 224
                && ip4.bytes[1] == 0
                && ip4.bytes[2] == 0;
        }
        false
    }

    /// `IP.IsLinkLocalUnicast()` (ip.go:177) — slim. IPv4 link-local
    /// unicast is 169.254.0.0/16 (RFC 3927).
    pub fn IsLinkLocalUnicast(&self) -> bool {
        let ip4 = self.To4();
        if ip4.bytes.Len() == 4 {
            // Go: ip4[0] == 169 && ip4[1] == 254
            return ip4.bytes[0] == 169 && ip4.bytes[1] == 254;
        }
        false
    }

    /// `IP.IsGlobalUnicast()` (ip.go:192) — slim. True for every
    /// IPv4 unicast address that isn't broadcast / unspecified /
    /// loopback / multicast / link-local-unicast. Slim only checks
    /// IPv4 (length 4); the IPv6 branch is unreachable.
    pub fn IsGlobalUnicast(&self) -> bool {
        // Go: (len(ip) == IPv4len || len(ip) == IPv6len) && ...
        if self.bytes.Len() != 4 {
            return false;
        }
        // Go: !ip.Equal(IPv4bcast) — 255.255.255.255
        let bcast = IPv4(255, 255, 255, 255);
        if self.Equal(&bcast) {
            return false;
        }
        // Go: !ip.IsUnspecified() && !ip.IsLoopback() &&
        //     !ip.IsMulticast()  && !ip.IsLinkLocalUnicast()
        !self.IsUnspecified()
            && !self.IsLoopback()
            && !self.IsMulticast()
            && !self.IsLinkLocalUnicast()
    }

    /// `IP.Equal(x)` (ip.go:391) — byte-wise equality. Slim: with
    /// IPv4-only support both IPs are 4 bytes (or both nil), so the
    /// 4-vs-16 v4-mapped-prefix path from Go is skipped.
    pub fn Equal(&self, x: &IP) -> bool {
        // Go: len(ip) == len(x) → bytealg.Equal(ip, x)
        let a: &[byte] = &self.bytes;
        let b: &[byte] = &x.bytes;
        a == b
    }

    /// `IP.AppendText(b)` (ip.go:349) — append the string form to `b`.
    /// `(b, nil)` for valid IPv4 / nil IP. Returns an error for any
    /// non-canonical length (slim accepts only 0 or 4 bytes).
    pub fn AppendText(&self, b: slice<byte>) -> (slice<byte>, error) {
        // Go: if len(ip) == 0 { return b, nil }
        if self.bytes.Len() == 0 {
            return (b, errors::nil);
        }
        // Slim: only IPv4 (4 bytes) is canonical.
        if self.bytes.Len() != 4 {
            return (b, errors::New(string("invalid IP address")));
        }
        // Go: return ip.appendTo(b), nil
        // Slim: render dotted-decimal directly.
        let s = self.String();
        let mut v: alloc::vec::Vec<byte> = b.__into_vec();
        v.extend_from_slice(s.as_bytes());
        (slice::<byte>::__from_vec(v), errors::nil)
    }

    /// `IP.MarshalText()` (ip.go:363) — encoding.TextMarshaler.
    /// Returns the dotted-decimal bytes for IPv4, empty for nil IP.
    pub fn MarshalText(&self) -> (slice<byte>, error) {
        // Go: b, err := ip.AppendText(make([]byte, 0, 24))
        let buf = slice::<byte>::__from_vec(alloc::vec::Vec::with_capacity(24));
        let (out, err) = self.AppendText(buf);
        if !err.IsNil() {
            return (
                slice::<byte>::__from_vec(alloc::vec::Vec::new()),
                err,
            );
        }
        (out, errors::nil)
    }

    /// `IP.UnmarshalText(text)` (ip.go:374) — encoding.TextUnmarshaler.
    /// Empty `text` resets `*ip` to nil; otherwise parses via ParseIP.
    /// Returns an error if the text is non-empty but unparseable.
    pub fn UnmarshalText(&mut self, text: slice<byte>) -> error {
        // Go: if len(text) == 0 { *ip = nil; return nil }
        if text.Len() == 0 {
            *self = IP::default();
            return errors::nil;
        }
        // Go: s := string(text); x := ParseIP(s)
        let s = string::from_bytes(&text);
        let x = ParseIP(s.clone());
        if x.IsNil() {
            // Go: return &ParseError{Type: "IP address", Text: s}
            return errors::New(string("invalid IP address"));
        }
        *self = x;
        errors::nil
    }

    /// `IP.String()` (ip.go:299) — slim. IPv4 addresses render as
    /// `"a.b.c.d"`. The nil sentinel renders as `"<nil>"` (matches Go).
    /// IPv6 forms are not supported in slim and render as `"<nil>"`.
    pub fn String(&self) -> string {
        // Go: if len(p) == 0 { return "<nil>" }
        if self.bytes.Len() == 0 {
            return string::from_static("<nil>");
        }
        // Go: if 4-byte → render dotted-decimal.
        if self.bytes.Len() == 4 {
            // strconv::AppendInt + literal '.' separators.
            let mut buf: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(15);
            buf = crate::strconv::AppendInt(
                slice::<byte>::__from_vec(buf),
                self.bytes[0] as int,
                10,
            )
            .__into_vec();
            buf.push(b'.');
            buf = crate::strconv::AppendInt(
                slice::<byte>::__from_vec(buf),
                self.bytes[1] as int,
                10,
            )
            .__into_vec();
            buf.push(b'.');
            buf = crate::strconv::AppendInt(
                slice::<byte>::__from_vec(buf),
                self.bytes[2] as int,
                10,
            )
            .__into_vec();
            buf.push(b'.');
            buf = crate::strconv::AppendInt(
                slice::<byte>::__from_vec(buf),
                self.bytes[3] as int,
                10,
            )
            .__into_vec();
            return string::from_bytes(&buf);
        }
        // Slim: any other length is not a recognized form.
        string::from_static("<nil>")
    }
}

/// `net.IPMask` (ip.go:43) — bitmask used to manipulate IP addresses
/// for routing. Slim port keeps the same backing as `IP` (slice<byte>);
/// length 4 is the IPv4 form (`/0` … `/32`). IPv6 length-16 masks are
/// accepted for length checks but not produced by `CIDRMask` in slim.
#[derive(Clone, Default)]
pub struct IPMask {
    /// Backing bytes. Length 4 for an IPv4 mask; length 0 means "nil".
    pub bytes: slice<byte>,
}

impl IPMask {
    /// `IPMask.Size()` (ip.go:440) — return `(ones, bits)` where `ones`
    /// is the count of leading 1-bits and `bits` is the total mask
    /// width. Returns `(0, 0)` if the mask isn't canonical (ones
    /// followed by zeros).
    pub fn Size(&self) -> (int, int) {
        // Go: ones, bits = simpleMaskLength(m), len(m)*8
        let ones = simple_mask_length(self);
        let bits = (self.bytes.Len() as int) * 8;
        // Go: if ones == -1 { return 0, 0 }
        if ones == -1 {
            return (0, 0);
        }
        (ones, bits)
    }

    /// `IPMask.String()` (ip.go:449) — hex form, no punctuation.
    /// Returns `"<nil>"` for the empty mask.
    pub fn String(&self) -> string {
        // Go: if len(m) == 0 { return "<nil>" }
        if self.bytes.Len() == 0 {
            return string::from_static("<nil>");
        }
        // Go: return hexString(m)
        hex_string(&self.bytes)
    }
}

/// `simpleMaskLength` (ip.go:410) — return number of leading 1-bits
/// when `mask` is canonical (1s followed by 0s), else -1.
fn simple_mask_length(m: &IPMask) -> int {
    let mut n: int = 0;
    let len = m.bytes.Len();
    let mut i: int = 0;
    while i < len {
        let mut v = m.bytes[i];
        // Go: if v == 0xff { n += 8; continue }
        if v == 0xff {
            n += 8;
            i += 1;
            continue;
        }
        // Go: count 1 bits in this non-ff byte.
        while (v & 0x80) != 0 {
            n += 1;
            v <<= 1;
        }
        // Go: rest must be 0 bits.
        if v != 0 {
            return -1;
        }
        i += 1;
        while i < len {
            // Go: if mask[i] != 0 { return -1 }
            if m.bytes[i] != 0 {
                return -1;
            }
            i += 1;
        }
        break;
    }
    n
}

/// `hexString` (ip.go:318) — render bytes as lowercase hex with no
/// punctuation.
fn hex_string(b: &slice<byte>) -> string {
    const HEX: &[byte] = b"0123456789abcdef";
    let mut buf: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity((b.Len() as usize) * 2);
    for (_, c) in crate::range!(b.clone()) {
        buf.push(HEX[(c >> 4) as usize]);
        buf.push(HEX[(c & 0x0f) as usize]);
    }
    string::from_bytes(&buf)
}

/// `net.IPv4Mask(a, b, c, d)` (ip.go:67) — IPv4 4-byte mask.
pub fn IPv4Mask(a: byte, b: byte, c: byte, d: byte) -> IPMask {
    // Go: p := make(IPMask, IPv4len); p[0]=a; p[1]=b; p[2]=c; p[3]=d.
    let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(4);
    v.push(a);
    v.push(b);
    v.push(c);
    v.push(d);
    IPMask {
        bytes: slice::<byte>::__from_vec(v),
    }
}

/// `net.CIDRMask(ones, bits)` (ip.go:79) — `ones` 1-bits followed by
/// 0s up to total `bits` width. Slim: accepts `bits` of 32 or 128,
/// matching Go; for 128 we still produce a 16-byte mask buffer.
/// Returns the nil-IPMask if inputs are invalid.
pub fn CIDRMask(ones: int, bits: int) -> IPMask {
    // Go: if bits != 8*IPv4len && bits != 8*IPv6len { return nil }
    if bits != 32 && bits != 128 {
        return IPMask::default();
    }
    // Go: if ones < 0 || ones > bits { return nil }
    if ones < 0 || ones > bits {
        return IPMask::default();
    }
    // Go: l := bits / 8; m := make(IPMask, l)
    let l = (bits / 8) as usize;
    let mut m: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(l);
    m.resize(l, 0u8);
    // Go: n := uint(ones); for i := 0; i < l; i++ { ... }
    let mut n = ones as u32;
    for i in 0..l {
        if n >= 8 {
            m[i] = 0xff;
            n -= 8;
            continue;
        }
        // Go: m[i] = ^byte(0xff >> n)
        m[i] = !(0xff_u8 >> n);
        n = 0;
    }
    IPMask {
        bytes: slice::<byte>::__from_vec(m),
    }
}

impl IP {
    /// `IP.DefaultMask()` (ip.go:248) — RFC 791 default classful mask.
    /// Returns the nil-IPMask if the IP isn't IPv4.
    pub fn DefaultMask(&self) -> IPMask {
        // Go: if ip = ip.To4(); ip == nil { return nil }
        let ip4 = self.To4();
        if ip4.bytes.Len() != 4 {
            return IPMask::default();
        }
        // Go: switch { case ip[0] < 0x80: classA; case ip[0] < 0xC0: classB; default: classC }
        let first = ip4.bytes[0];
        if first < 0x80 {
            return IPv4Mask(0xff, 0, 0, 0);
        }
        if first < 0xC0 {
            return IPv4Mask(0xff, 0xff, 0, 0);
        }
        IPv4Mask(0xff, 0xff, 0xff, 0)
    }

    /// `IP.Mask(mask)` (ip.go:272) — bitwise-AND ip with mask. Returns
    /// the nil-IP if shapes don't line up. Slim: only the IPv4×IPv4
    /// path is taken (the v4-mapped-v6 reductions in Go are for IPs
    /// goish doesn't construct).
    pub fn Mask(&self, mask: IPMask) -> IP {
        // Go: shape-normalize mismatched lengths via v4InV6Prefix.
        // Slim: skip; both must be 4-byte IPv4 (or both nil).
        let n = self.bytes.Len();
        // Go: if n != len(mask) { return nil }
        if n != mask.bytes.Len() {
            return IP::default();
        }
        // Go: out := make(IP, n); for i := 0; i < n; i++ { out[i] = ip[i] & mask[i] }
        let mut out: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(n as usize);
        let mut i: int = 0;
        while i < n {
            out.push(self.bytes[i] & mask.bytes[i]);
            i += 1;
        }
        IP {
            bytes: slice::<byte>::__from_vec(out),
        }
    }
}

/// `net.IPNet` (ip.go:46) — IP network: address + mask. Slim
/// IPv4-only port; both fields are 4-byte.
#[derive(Clone, Default)]
pub struct IPNet {
    /// Network number (network address part of the CIDR).
    pub IP: IP,
    /// Network mask.
    pub Mask: IPMask,
}

impl IPNet {
    /// `IPNet.Network()` (ip.go:498) — constant `"ip+net"`.
    pub fn Network(&self) -> string {
        // Go: return "ip+net"
        string::from_static("ip+net")
    }

    /// `IPNet.Contains(ip)` (ip.go:480) — true when `ip` lies in this
    /// network. Slim: only the IPv4×IPv4 path is reachable.
    pub fn Contains(&self, ip: IP) -> bool {
        // Go: nn, m := networkNumberAndMask(n)
        let (nn, m) = network_number_and_mask(self);
        if nn.bytes.Len() == 0 || m.bytes.Len() == 0 {
            return false;
        }
        // Go: if x := ip.To4(); x != nil { ip = x }
        let ip4 = ip.To4();
        let needle: IP = if ip4.bytes.Len() == 4 { ip4 } else { ip };
        // Go: if l != len(nn) { return false }
        let l = needle.bytes.Len();
        if l != nn.bytes.Len() {
            return false;
        }
        // Go: for i := 0; i < l; i++ { ... }
        let mut i: int = 0;
        while i < l {
            // Go: if nn[i]&m[i] != ip[i]&m[i] { return false }
            if (nn.bytes[i] & m.bytes[i]) != (needle.bytes[i] & m.bytes[i]) {
                return false;
            }
            i += 1;
        }
        true
    }

    /// `IPNet.String()` (ip.go:506) — CIDR notation, e.g. `"192.0.2.0/24"`.
    /// Falls back to `"ip/<hex-mask>"` when the mask isn't canonical.
    pub fn String(&self) -> string {
        // Go: nn, m := networkNumberAndMask(n)
        let (nn, m) = network_number_and_mask(self);
        if nn.bytes.Len() == 0 || m.bytes.Len() == 0 {
            return string::from_static("<nil>");
        }
        // Go: l := simpleMaskLength(m)
        let l = simple_mask_length(&m);
        // Go: if l == -1 { return nn.String() + "/" + m.String() }
        if l == -1 {
            return nn.String() + string::from_static("/") + m.String();
        }
        // Go: return nn.String() + "/" + itoa.Uitoa(uint(l))
        nn.String() + string::from_static("/") + crate::strconv::Itoa(l)
    }
}

/// `networkNumberAndMask` (ip.go:456) — normalize the (ip, mask) pair.
/// Slim: returns the IP/Mask as-is when both are 4-byte; nil/nil
/// otherwise (no IPv6 reduction).
fn network_number_and_mask(n: &IPNet) -> (IP, IPMask) {
    // Go: if ip = n.IP.To4(); ip == nil { ... }
    let ip = n.IP.To4();
    if ip.bytes.Len() != 4 {
        return (IP::default(), IPMask::default());
    }
    // Go: switch len(m) { case IPv4len: ... default: return nil, nil }
    if n.Mask.bytes.Len() != 4 {
        return (IP::default(), IPMask::default());
    }
    (ip, n.Mask.clone())
}

/// `net.ParseCIDR(s)` (ip.go:550) — parse `"a.b.c.d/n"` into the IP
/// address and the implied IPNet. Slim: IPv4 only; rejects v6 forms.
pub fn ParseCIDR(s: crate::string) -> (IP, IPNet, error) {
    // Go: addr, mask, found := stringslite.Cut(s, "/")
    let (addr, mask, found) = crate::strings::Cut(s.clone(), string::from_static("/"));
    // Go: if !found { return nil, nil, &ParseError{Type: "CIDR address", Text: s} }
    if !found {
        return (
            IP::default(),
            IPNet::default(),
            errors::New(string("invalid CIDR address: ") + s),
        );
    }
    // Go: ipAddr, err := netip.ParseAddr(addr)
    let ip_addr = ParseIP(addr);
    if ip_addr.IsNil() {
        return (
            IP::default(),
            IPNet::default(),
            errors::New(string("invalid CIDR address: ") + s),
        );
    }
    // Go: n, i, ok := dtoi(mask); validate range.
    let (n_val, ok) = parse_decimal_int(&mask);
    let bit_len: int = 32; // slim: IPv4 only.
    if !ok || n_val < 0 || n_val > bit_len {
        return (
            IP::default(),
            IPNet::default(),
            errors::New(string("invalid CIDR address: ") + s),
        );
    }
    // Go: m := CIDRMask(n, ipAddr.BitLen())
    let m = CIDRMask(n_val, bit_len);
    // Go: return IP(addr16[:]), &IPNet{IP: IP(addr16[:]).Mask(m), Mask: m}, nil
    let net_ip = ip_addr.Mask(m.clone());
    (
        ip_addr,
        IPNet {
            IP: net_ip,
            Mask: m,
        },
        errors::nil,
    )
}

/// Parse a non-negative decimal integer from a goish `string`.
/// Returns (value, true) on success; (0, false) on any non-digit
/// or empty input. Mirrors Go's `dtoi` strict-prefix decode but
/// rejects trailing junk to match `i != len(mask)`.
fn parse_decimal_int(s: &crate::string) -> (int, bool) {
    let bs = crate::convert::bytes(s.clone());
    if bs.Len() == 0 {
        return (0, false);
    }
    let mut n: int = 0;
    let mut i: int = 0;
    while i < bs.Len() {
        let c = bs[i];
        if c < b'0' || c > b'9' {
            return (0, false);
        }
        n = n * 10 + (c - b'0') as int;
        i += 1;
    }
    (n, true)
}

/// `net.IPv4(a, b, c, d)` (ip.go:43) — construct an IPv4 net.IP.
/// Slim port returns the 4-byte form directly (Go returns the
/// 16-byte v4-mapped-v6 form, which `To4()` then collapses).
pub fn IPv4(a: byte, b: byte, c: byte, d: byte) -> IP {
    let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(4);
    v.push(a);
    v.push(b);
    v.push(c);
    v.push(d);
    IP {
        bytes: slice::<byte>::__from_vec(v),
    }
}

/// `net.ParseIP(s)` (ip.go:527) — parse a textual IP address.
/// Slim port: IPv4 dotted-decimal only (`"a.b.c.d"`). IPv6 forms
/// (`"::1"`, `"fe80::1"`, etc.) return the nil-IP sentinel.
///
/// Each octet must be 1-3 ASCII digits with value in 0..=255 and no
/// leading zeros beyond a single '0' (matches Go's strict parser).
pub fn ParseIP(s: crate::string) -> IP {
    let bs = crate::convert::bytes(s);
    let raw: &[byte] = &bs;
    parse_ipv4(raw).unwrap_or_default()
}

fn parse_ipv4(s: &[byte]) -> Option<IP> {
    let mut octets: [byte; 4] = [0; 4];
    let mut i = 0usize;
    let mut field = 0usize;
    while field < 4 {
        // Each octet: 1-3 digits.
        if i >= s.len() {
            return None;
        }
        let mut n: u32 = 0;
        let mut digits = 0;
        while i < s.len() && s[i] >= b'0' && s[i] <= b'9' {
            // Reject leading zero followed by another digit (Go strict).
            if digits == 1 && octets[field] == 0 && n == 0 {
                return None;
            }
            n = n * 10 + (s[i] - b'0') as u32;
            if n > 255 {
                return None;
            }
            octets[field] = n as byte;
            digits += 1;
            i += 1;
            if digits > 3 {
                return None;
            }
        }
        if digits == 0 {
            return None;
        }
        // Separator: '.' between octets, EOF after the 4th.
        if field < 3 {
            if i >= s.len() || s[i] != b'.' {
                return None;
            }
            i += 1; // consume '.'
        } else if i != s.len() {
            return None; // trailing junk
        }
        field += 1;
    }
    Some(IPv4(octets[0], octets[1], octets[2], octets[3]))
}

pub fn SplitHostPort(hostport: crate::string) -> (crate::string, crate::string, crate::error) {
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
    let host: crate::string;
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

/// `net.AddrError` (net.go:1064) — the typed error for address-shape
/// failures. Carries the bad address and the diagnostic. Satisfies the
/// `error` interface via its `Error()` method.
///
/// User code constructs it as `net::AddrError { Err: …, Addr: … }` and
/// returns it through `errors::Wrap` (per the standard goish error-
/// chaining pattern), e.g.:
///
///   return (string(""), -1, errors::Wrap(net::AddrError {
///       Err: string("missing port in address"),
///       Addr: addr,
///   }));
#[derive(Clone)]
pub struct AddrError {
    pub Err: crate::string,
    pub Addr: crate::string,
}

impl crate::errors::ErrorTrait for AddrError {
    fn Error(&self) -> crate::string {
        // Mirror Go's `*AddrError.Error()` (net/net.go:1069). On bare
        // `Err` (no Addr) we just return Err; otherwise prepend
        // `address <addr>: `.
        if self.Addr == crate::string::from_static("") {
            return self.Err.clone();
        }
        let mut b = crate::strings::Builder::new();
        let _ = b.WriteString(crate::string::from_static("address "));
        let _ = b.WriteString(self.Addr.clone());
        let _ = b.WriteString(crate::string::from_static(": "));
        let _ = b.WriteString(self.Err.clone());
        b.String()
    }
}

impl AddrError {
    /// Go: `func (e *AddrError) Timeout() bool { return false }`
    /// (net/net.go:1078).
    pub fn Timeout(&self) -> bool { false }
    /// Go: `func (e *AddrError) Temporary() bool { return false }`
    /// (net/net.go:1079).
    pub fn Temporary(&self) -> bool { false }
}

// `AddrError → error` via `.into()` is now provided by the blanket
// `impl<E: ErrorTrait> From<E> for error` in errors/mod.rs.

/// Internal helper retained for SplitHostPort's existing call sites —
/// returns a typed `AddrError` wrapped through `errors::Wrap`. `why`
/// must be a `&'static str` because the AddrError stores it as a
/// `string` constructed via `from_static` (zero-alloc path).
fn addr_error(addr: crate::string, why: &'static str) -> crate::error {
    crate::errors::Wrap(AddrError {
        Err: crate::string::from_static(why),
        Addr: addr,
    })
}

// ─── Listen / Dial ───────────────────────────────────────────────────

/// `net.Listen` — open a listening socket. `network` must be `"tcp"`
/// or `"tcp4"`; other values return an error. `addr` is in
/// `"host:port"` form. `host` may be empty (binds wildcard) or an
/// IPv4 dotted literal; hostname resolution is not implemented in
/// v1. Port `:0` lets the kernel pick a free port (recovered via
/// `Listener.Addr()`).
pub fn Listen<N: Into<string>, A: Into<string>>(network: N, addr: A) -> (Listener, error) {
    let network: string = network.into();
    let addr: string = addr.into();
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
pub fn Dial<N: Into<string>, A: Into<string>>(network: N, addr: A) -> (TCPConn, error) {
    let network: string = network.into();
    let addr: string = addr.into();
    if !is_tcp_network(&network) {
        return (
            TCPConn::dead(),
            errors::New(string("net: only \"tcp\" / \"tcp4\" supported")),
        );
    }
    let parsed = match parse::parse_dial_addr(&addr) {
        Ok(s) => s,
        Err(msg) => return (TCPConn::dead(), errors::New(msg)),
    };

    let fd = syscall::Socket(
        syscall::AF_INET,
        syscall::SOCK_STREAM | syscall::SOCK_CLOEXEC | syscall::SOCK_NONBLOCK,
        syscall::IPPROTO_TCP,
    );
    if fd < 0 {
        return (TCPConn::dead(), errno_error("socket", -fd));
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
            return (TCPConn::dead(), errno_error("connect", errno));
        }
        // Wait for the connect to finalize.
        let arc = match netpoll::open(fd) {
            Some(a) => a,
            None => {
                let _ = syscall::Close(fd);
                return (TCPConn::dead(), errno_error("connect/poll_open", 0));
            }
        };
        // Connect has no deadline in this Dial path (v1); a future
        // DialTimeout would `set_deadline(pd, …, b'w')` before this
        // call and translate Timedout into a connect-timeout error.
        if let BlockResult::Timedout = netpoll::block(&arc, b'w') {
            netpoll::close(arc);
            let _ = syscall::Close(fd);
            return (TCPConn::dead(), timeout_error("connect"));
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
            return (TCPConn::dead(), errno_error("connect", so_err));
        }
        // Connect succeeded — recover both ends. We move the Arc
        // into the new TCPConn's AtomicPtr via Arc::into_raw, so the
        // strong count is preserved (TCPConn owns one ref; slab owns
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
            TCPConn {
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
        TCPConn {
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

// ─── Reflect ─────────────────────────────────────────────────────────
//
// `reflect.TypeOf(net.IP{})` keys fmt-style formatter tables — ports
// like kylelemons/godebug/pretty register `fmt.Sprint` under this key.
// Go's reflect describes `net.IP` as a named slice over bytes; mirror
// that via Kind::Slice so callers using `.Kind() == reflect.Slice`
// stay correct.
impl crate::reflect::Reflect for IP {
    #[inline]
    fn __reflect_type() -> crate::reflect::Type {
        crate::reflect::Type::__new(crate::reflect::Kind::Slice, "net.IP", &[])
    }
    #[inline]
    fn __reflect_value(&self) -> crate::reflect::Value {
        crate::reflect::Value::Slice {
            elem_type: <byte as crate::reflect::Reflect>::__reflect_type,
            items: alloc::vec::Vec::new(),
        }
    }
}
