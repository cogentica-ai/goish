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
use crate::io;
use crate::runtime::netpoll::{self, BlockResult, PollDesc};
use crate::string;
use crate::syscall;
use crate::types::{byte, int};
use alloc::sync::Arc;

pub mod dnsclient;
mod dnsconfig;
pub mod dnsmessage;
pub mod http;
pub mod lookup;
mod mac;
pub mod mail;
pub mod net;
mod parse;

pub mod ip;
pub use ip::{
    CIDRMask, IPMask, IPNet, IPv4, IPv4Mask, IPv4allrouter, IPv4allsys, IPv4bcast, IPv4len,
    IPv4zero, IPv6interfacelocalallnodes, IPv6len, IPv6linklocalallnodes, IPv6linklocalallrouters,
    IPv6loopback, IPv6unspecified, IPv6zero, ParseCIDR, ParseIP, IP,
};
pub use net::{
    Addr, AddrError, DNSConfigError, DNSError, ErrClosed, ErrWriteToConnected, InvalidAddrError,
    OpError, ParseError, UnknownNetworkError,
};
pub mod netip;
pub mod textproto;
pub mod url;

pub use lookup::{
    IPAddr as LookupIPAddr, LookupAddr, LookupCNAME, LookupHost, LookupIP, LookupMX, LookupNS,
    LookupSRV, LookupTXT, Resolver, MX, NS, SRV,
};
pub use mac::{HardwareAddr, HardwareAddrString, ParseMAC};
pub use parse::TCPAddr;

/// `EAGAIN` / `EWOULDBLOCK` (Linux: same value, 11). The non-blocking
/// I/O retry signal — caller parks on the netpoller and re-attempts.
const EAGAIN: i32 = 11;
const ECONNABORTED: i32 = 103;
const EMFILE: i32 = 24;
const ENFILE: i32 = 23;
const ENOBUFS: i32 = 105;
const ENOMEM: i32 = 12;
/// `EINPROGRESS` (Linux: 115). Returned by non-blocking `connect(2)`
/// to indicate the connection handshake is underway.
const EINPROGRESS: i32 = 115;
/// `EINTR` (Linux: 4). Syscall interrupted by signal — caller retries
/// the syscall directly without parking.
const EINTR: i32 = 4;
/// `EBADF` (Linux: 9). Surfaces when Close races an in-flight retry
/// loop; paired with the `closed` flag it maps to `ErrClosed`.
const EBADF: i32 = 9;

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

// go: none — goish-only: Go's accept errors are
// `&OpError{Op: "accept", Net: "tcp", Addr: laddr, Err: …}`, built
// where the listener is in scope because only it knows its address.
impl Listener {
    // go: none — goish-only: see the note on the impl block.
    /// The listener's own `*net.OpError` for a failed accept.
    fn op_err(&self, syscall_name: &str, errno: i32) -> error {
        return errors::Wrap(net::OpError {
            Op: string::from_static("accept"),
            Net: string::from_static("tcp"),
            Source: None,
            Addr: Some(alloc::sync::Arc::new(self.addr.clone())),
            Err: crate::os::NewSyscallError(
                string::from_bytes(syscall_name.as_bytes()),
                errors::Wrap(syscall::Errno(errno as _)),
            ),
        });
    }

    // go: none — goish-only: see the note on the impl block.
    /// The listener's accept-deadline error, in the same shape.
    fn timeout_err(&self) -> error {
        return errors::Wrap(net::OpError {
            Op: string::from_static("accept"),
            Net: string::from_static("tcp"),
            Source: None,
            Addr: Some(alloc::sync::Arc::new(self.addr.clone())),
            Err: net::errTimeout(),
        });
    }

    // go: none — goish-only: see the note on the impl block.
    /// The listener's `use of closed network connection`, wrapped as
    /// Go wraps it — an OpError naming the listener, not a bare
    /// sentinel. `errors::Is(err, net::ErrClosed)` still matches,
    /// because OpError unwraps to it.
    fn closed_err(&self) -> error {
        return errors::Wrap(net::OpError {
            Op: string::from_static("accept"),
            Net: string::from_static("tcp"),
            Source: None,
            Addr: Some(alloc::sync::Arc::new(self.addr.clone())),
            Err: ErrClosed.into(),
        });
    }
}

impl Listener {
    /// `(*TCPListener).Accept` — return a new `TCPConn` for the next
    /// connecting peer, parking the calling goroutine on the netpoller
    /// while the accept queue is empty. Mirrors Go's
    /// `func (l *TCPListener) Accept() (TCPConn, error)` (net/tcpsock.go).
    pub fn Accept(&self) -> (TCPConn, error) {
        let (conn, err, _temporary) = self.__accept_classified();
        (conn, err)
    }

    /// Accept plus a Go `net.Error.Temporary()` verdict on the error.
    /// goish has no typed `Errno` error carrier yet, so the http
    /// server's Go-parity accept backoff (server.go:3428
    /// `ne.Temporary()`) gets the classification out-of-band.
    /// Temporary set mirrors `syscall.Errno.Temporary()`
    /// (syscall/syscall_unix.go): EMFILE, ENFILE, plus the resource
    /// errnos Linux accept(2) can transiently return (ENOBUFS,
    /// ENOMEM). ECONNABORTED never surfaces — retried inline below,
    /// mirroring Go's `internal/poll.FD.Accept`.
    pub(crate) fn __accept_classified(&self) -> (TCPConn, error, bool) {
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
                    false,
                );
            }
            let errno = -fd;
            if errno == EINTR || errno == ECONNABORTED {
                continue;
            }
            if errno == EAGAIN {
                let pd = self.ensure_pd();
                if pd.is_null() {
                    return (TCPConn::dead(), self.op_err("accept", errno), false);
                }
                match netpoll::block(unsafe { &*pd }, b'r') {
                    BlockResult::Ready | BlockResult::Aborted => continue,
                    BlockResult::Timedout => {
                        // A real deadline and a Close-eviction both
                        // surface as Timedout; `closed` says which.
                        // Go: Accept on a closed listener returns
                        // ErrClosed (net.go:747).
                        if self.closed.load(Ordering::Acquire) {
                            return (TCPConn::dead(), self.closed_err(), false);
                        }
                        return (TCPConn::dead(), self.timeout_err(), false);
                    }
                }
            }
            if errno == EBADF && self.closed.load(Ordering::Acquire) {
                // The fd was closed under us mid-loop (Close raced the
                // retry) — same contract as the parked case.
                return (TCPConn::dead(), self.closed_err(), false);
            }
            let temporary =
                errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM;
            return (TCPConn::dead(), self.op_err("accept", errno), temporary);
        }
    }

    /// `(*TCPListener).Close` — stop listening and drop the fd.
    /// Idempotent: a second call is a no-op (mirrors Go's
    /// `onceCloseListener` server-side wrapper).
    ///
    /// Wakes any goroutine parked in `Accept` first — Go's Close does
    /// this via `pd.evict()` (internal/poll/fd_mutex.go), and without
    /// it a ported teardown hangs forever at `wg.Wait()` with every
    /// assertion already green: kernel `close(2)` drops the fd from
    /// epoll's interest set without delivering anything to existing
    /// parkers. The woken Accept observes `closed` and returns
    /// `ErrClosed`, as Go's does.
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
            // Force-expire the read deadline: unblocks a parked
            // Accept with Timedout, which the accept path converts to
            // ErrClosed via the `closed` flag. Same wake `Shutdown`
            // has always done through `__wake_accept`; folded into
            // Close so every caller gets Go's semantics. (The woken
            // parker's post-resume reads of the PollDesc race the
            // free below exactly as the pre-existing __wake_accept →
            // Close sequence did — the pd-lifetime hardening is
            // tracked separately.)
            netpoll::set_deadline(&arc, -1, b'r');
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
        match self
            .pd
            .compare_exchange(ptr::null_mut(), new, Ordering::AcqRel, Ordering::Acquire)
        {
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

// go: none — goish-only: Go has no such constant. It keeps the same
// distinction in `poll.fdMutex`, whose `increfAndClose` succeeds
// once per descriptor (internal/poll/fd_mutex.go); goish's conn
// holds a bare fd, so the state lives in the fd field itself.
/// Marks a fd this conn has already closed, as distinct from `-1`,
/// which is a conn that was never opened (`dead()`, the value Dial
/// returns beside a non-nil error).
///
/// Go keeps the distinction in `poll.fdMutex`: `increfAndClose`
/// succeeds once and every later Close, Read or Write on that
/// descriptor returns `ErrNetClosing` rather than the kernel's EBADF.
/// A `dead()` conn never got that far, so Closing it stays a no-op —
/// `defer c.Close()` after a failed Dial must not manufacture an
/// error. Every fd guard in this file tests `< 0`, which both
/// sentinels satisfy.
const FD_CLOSED: i32 = -2;

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
    /// `(*Dialer).DialContext` — Go's bound method value, the closure
    /// `http.Transport.DialContext` defaults to.
    ///
    /// This used to return `Arc::new(|| {})`, a closure that took no
    /// arguments and did nothing, on the note that the real form was
    /// "deferred until the connection-pool layer lands". It dials now.
    /// The Dialer's Timeout and KeepAlive are still not threaded
    /// through — `net::Dial` has no deadline argument to give them to
    /// — so a Dialer carrying them dials as if they were zero, which
    /// is the same thing it did before and is recorded here rather
    /// than pinned in a smoke.
    pub fn DialContext(&self) -> crate::net::http::DialContextFn {
        alloc::sync::Arc::new(
            |_ctx: Option<alloc::sync::Arc<dyn crate::context::Context>>,
             network: crate::gostring::string,
             addr: crate::gostring::string| {
                let (conn, err) = crate::net::Dial(network, addr);
                if !err.IsNil() {
                    return (None, err);
                }
                let boxed: alloc::boxed::Box<dyn Conn> = alloc::boxed::Box::new(conn);
                return (Some(boxed), crate::errors::nil);
            },
        )
    }
}

impl TCPConn {
    /// Internal: dead-conn placeholder returned alongside an error.
    /// Caller must ignore the conn when the error is non-nil.
    ///
    /// pub(crate) so net/http can return it from a failed Hijack, which
    /// is Go returning a nil net.Conn beside the error.
    pub(crate) fn dead() -> Self {
        TCPConn {
            fd: -1,
            local: TCPAddr::zero(),
            remote: TCPAddr::zero(),
            pd: AtomicPtr::new(ptr::null_mut()),
        }
    }

    // go: none — goish-only: full-duplex sharing for protocol-switch
    // pumps (httputil's switchProtocolCopier). Go hands ONE net.Conn
    // interface value to two goroutines; Rust ownership wants two
    // OWNED handles. F_DUPFD_CLOEXEC shares the open socket
    // description — reads, writes and shutdown(2) act on the same
    // socket (O_NONBLOCK lives on the description, so the new handle
    // is non-blocking too), each handle lazily registers its own fd
    // with the netpoller, and the socket dies when the LAST handle
    // closes.
    pub(crate) fn __dup_handle(&self) -> (TCPConn, error) {
        const F_DUPFD_CLOEXEC: i32 = 1030;
        let nfd = syscall::Fcntl(self.fd, F_DUPFD_CLOEXEC, 0);
        if nfd < 0 {
            return (TCPConn::dead(), errno_error("dup", -nfd));
        }
        return (
            TCPConn {
                fd: nfd,
                local: self.local.clone(),
                remote: self.remote.clone(),
                pd: AtomicPtr::new(ptr::null_mut()),
            },
            errors::nil,
        );
    }

    // go: none — goish-only: Go's Hijack hands the caller `c.rwc` and
    // the server simply stops using it. goish's conn owns its fd, so
    // the transfer is explicit.
    /// Internal: hand this conn's fd to a new owner, leaving this one
    /// dead. `Close` on a dead conn is a no-op, so the fd has exactly
    /// one closer either side of the transfer.
    ///
    /// pub(crate) for `net/http`'s Hijack, which is precisely an
    /// ownership transfer out of the serve loop.
    pub(crate) fn __take_over(&mut self) -> TCPConn {
        let fd = self.fd;
        let out = TCPConn {
            fd,
            local: self.local.clone(),
            remote: self.remote.clone(),
            pd: AtomicPtr::new(self.pd.load(core::sync::atomic::Ordering::Acquire)),
        };
        self.fd = -1;
        self.pd
            .store(ptr::null_mut(), core::sync::atomic::Ordering::Release);
        return out;
    }

    /// Wrap a freshly-accepted fd. The fd is already SOCK_NONBLOCK
    /// (the Accept4 caller passed the flag).
    fn from_accepted(fd: i32, local: TCPAddr, remote: TCPAddr) -> Self {
        set_tcp_conn_defaults(fd);
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
        match self
            .pd
            .compare_exchange(ptr::null_mut(), new, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => new as *const PollDesc,
            Err(_) => {
                let orphan = unsafe { Arc::from_raw(new as *const PollDesc) };
                netpoll::close(orphan);
                self.pd.load(Ordering::Acquire)
            }
        }
    }
}

// go: none — goish-only: Go's read/write errors are
// `&OpError{Op, Net, Source: laddr, Addr: raddr, Err: …}`, built where
// the conn is in scope because only the conn knows its addresses.
impl TCPConn {
    // go: none — goish-only: see the note on the impl block.
    /// The conn's own `*net.OpError` for a failed syscall.
    ///
    /// Go renders "read tcp 127.0.0.1:55922->127.0.0.1:37159: i/o
    /// timeout" — the local address, an arrow, the remote. Without
    /// Source and Addr the message is just "read: …", which says
    /// nothing about WHICH connection failed; on a server holding
    /// hundreds that is the only part worth logging.
    fn op_err(&self, op: &str, syscall_name: &str, errno: i32) -> error {
        return errors::Wrap(net::OpError {
            Op: string::from_bytes(op.as_bytes()),
            Net: string::from_static("tcp"),
            Source: Some(alloc::sync::Arc::new(self.local.clone())),
            Addr: Some(alloc::sync::Arc::new(self.remote.clone())),
            Err: crate::os::NewSyscallError(
                string::from_bytes(syscall_name.as_bytes()),
                errors::Wrap(syscall::Errno(errno as _)),
            ),
        });
    }

    // go: none — goish-only: see the note on the impl block.
    /// The conn's own timeout error, in the same shape.
    fn timeout_err(&self, op: &str) -> error {
        return errors::Wrap(net::OpError {
            Op: string::from_bytes(op.as_bytes()),
            Net: string::from_static("tcp"),
            Source: Some(alloc::sync::Arc::new(self.local.clone())),
            Addr: Some(alloc::sync::Arc::new(self.remote.clone())),
            Err: net::errTimeout(),
        });
    }

    // go: none — goish-only: see the note on the impl block.
    /// The conn's `use of closed network connection`, in the same
    /// shape. Go builds this one in three places — `(*conn).Close`,
    /// `.Read` and `.Write` all wrap `poll`'s `ErrNetClosing` in an
    /// `OpError` naming both addresses — so `op` selects which.
    fn closed_err(&self, op: &str) -> error {
        return errors::Wrap(net::OpError {
            Op: string::from_bytes(op.as_bytes()),
            Net: string::from_static("tcp"),
            Source: Some(alloc::sync::Arc::new(self.local.clone())),
            Addr: Some(alloc::sync::Arc::new(self.remote.clone())),
            Err: ErrClosed.into(),
        });
    }
}

impl io::Reader for TCPConn {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if self.fd == FD_CLOSED {
            return (0, self.closed_err("read"));
        }
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
                    return (0, self.op_err("read", "read", errno));
                }
                match netpoll::block(unsafe { &*pd }, b'r') {
                    BlockResult::Ready | BlockResult::Aborted => continue,
                    BlockResult::Timedout => return (0, self.timeout_err("read")),
                }
            }
            return (0, self.op_err("read", "read", errno));
        }
    }
}

impl io::Writer for TCPConn {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Drain the buffer; partial writes loop. Matches Go's
        // internal/poll.FD.Write which keeps writing until n == len(p)
        // or an error is hit.
        if self.fd == FD_CLOSED {
            return (0, self.closed_err("write"));
        }
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
        if self.fd == FD_CLOSED {
            return self.closed_err("close");
        }
        if self.fd < 0 {
            return errors::nil;
        }
        let pd_raw = self.pd.swap(ptr::null_mut(), Ordering::AcqRel);
        if !pd_raw.is_null() {
            // Reconstitute the Arc<PollDesc> that ensure_pd installed
            // via Arc::into_raw, then hand to netpoll::close (which
            // unregisters from the slab and drops the caller's Arc).
            let arc = unsafe { Arc::from_raw(pd_raw as *const PollDesc) };
            // Wake any goroutine parked on this conn in Read or Write
            // (possible through shared handles, e.g. the http server's
            // per-conn reader) — Go's Close evicts them with
            // ErrNetClosing; without the wake they park forever, since
            // kernel close(2) delivers nothing to existing parkers.
            netpoll::set_deadline(&arc, -1, b'r');
            netpoll::set_deadline(&arc, -1, b'w');
            netpoll::close(arc);
        }
        let r = syscall::Close(self.fd);
        self.fd = FD_CLOSED;
        if r < 0 {
            self.op_err("close", "close", -r)
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
/// `"[host]:port"`, or `"[host%zone]:port"` into its host and port.
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

// AddrError moved to src/net/net.rs, where net.go's error hierarchy
// lives and where it can carry an anchor — a module root cannot
// (GOISH015). Re-exported below so `net::AddrError` still resolves.

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

/// `net.ListenConfig.Control`'s function shape (dial.go:751) — called
/// after socket creation (and the default listener sockopts) but
/// before bind, with the resolved network ("tcp4"), the resolved
/// listen address, and a `syscall.RawConn` giving raw fd access.
/// Named so user code can spell the field type without writing the
/// `dyn Fn` form (same pattern as `http::BaseContextFn`).
pub type ControlFn = Arc<dyn Fn(string, string, syscall::RawConn) -> error + Send + Sync>;

/// `net.ListenConfig` (dial.go:741) — options for listening to an
/// address. v1 carries the `Control` hook (the field callers use for
/// SO_REUSEPORT and friends, since Go deliberately has no first-class
/// flag for it); `KeepAlive` / `KeepAliveConfig` / MPTCP are deferred
/// — accepted-conn keep-alive currently applies the Go defaults
/// unconditionally (`set_tcp_conn_defaults`).
pub struct ListenConfig {
    /// If set, called after creating the socket but before binding
    /// it. The network/address arguments are the resolved forms
    /// ("tcp4", "127.0.0.1:8091"), not necessarily what was passed
    /// to Listen — mirroring the Go doc.
    pub Control: Option<ControlFn>,
}

impl Default for ListenConfig {
    fn default() -> Self {
        ListenConfig { Control: None }
    }
}

impl ListenConfig {
    /// `(*ListenConfig).Listen(ctx, network, address)` (dial.go:804)
    /// — announce on the local network address. In Go the ctx only
    /// scopes address resolution; v1 does no resolution, so it is
    /// accepted for shape and unused.
    #[allow(non_snake_case)]
    pub fn Listen<N: Into<string>, A: Into<string>>(
        &self,
        _ctx: Arc<dyn crate::context::Context>,
        network: N,
        address: A,
    ) -> (Listener, error) {
        listen_with_config(network.into(), address.into(), self.Control.as_ref())
    }
}

/// `net.Listen` — open a listening socket. `network` must be `"tcp"`
/// or `"tcp4"`; other values return an error. `addr` is in
/// `"host:port"` form. `host` may be empty (binds wildcard) or an
/// IPv4 dotted literal; hostname resolution is not implemented in
/// v1. Port `:0` lets the kernel pick a free port (recovered via
/// `Listener.Addr()`).
///
/// Go-shape: a zero `ListenConfig` delegating to
/// `ListenConfig.Listen` (dial.go:897).
pub fn Listen<N: Into<string>, A: Into<string>>(network: N, addr: A) -> (Listener, error) {
    listen_with_config(network.into(), addr.into(), None)
}

/// Shared body of `Listen` / `ListenConfig.Listen` — Go's
/// `sysListener.listenTCP` → `netFD.listenStream`
/// (net/sock_posix.go:171): socket → default listener sockopts →
/// Control hook → bind → listen.
fn listen_with_config(
    network: string,
    addr: string,
    control: Option<&ControlFn>,
) -> (Listener, error) {
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

    // SO_REUSEADDR so a quick restart doesn't fail on TIME_WAIT
    // (Go `setDefaultListenerSockopts`, net/sockopt_linux.go:14).
    let one: i32 = 1;
    let _ = syscall::Setsockopt(
        fd,
        syscall::SOL_SOCKET,
        syscall::SO_REUSEADDR,
        &one as *const i32 as *const u8,
        core::mem::size_of::<i32>() as u32,
    );

    // Control hook — after default sockopts, before bind
    // (net/sock_posix.go:190, `listenStream`'s ctrlCtxFn call).
    // The network/address handed to the hook are the resolved forms
    // (`fd.ctrlNetwork()` / `laddr.String()`).
    if let Some(ctrl) = control {
        let e = ctrl(
            string("tcp4"),
            TCPAddr::from_sockaddr_in(&parsed).String(),
            syscall::RawConn::__from_fd(fd),
        );
        if !e.IsNil() {
            let _ = syscall::Close(fd);
            return (dead_listener(), e);
        }
    }

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
/// Go-parity TCP connection defaults, applied to every dialed and
/// accepted conn:
///
///   * `TCP_NODELAY = 1` — Go sets it on every TCP conn
///     (`net/tcpsockopt_posix.go setNoDelay`, called from
///     `newTCPConn`). Nagle off matters for small keep-alive
///     responses behind an LB.
///   * `SO_KEEPALIVE` with idle 15s / interval 15s / count 9 — Go's
///     `defaultTCPKeepAliveIdle` / `Interval` / `Count`
///     (`net/dial.go:19-26`), applied by `newTCPConn` on both the
///     dial (`Dialer.KeepAlive` zero value) and accept
///     (`ListenConfig.KeepAlive`) paths. Detects dead peers holding
///     conns half-open.
///
/// Failures are ignored (Go's test hooks aside, these setsockopts
/// are best-effort on exotic transports).
fn set_tcp_conn_defaults(fd: i32) {
    let one: i32 = 1;
    let _ = syscall::Setsockopt(
        fd,
        syscall::IPPROTO_TCP,
        syscall::TCP_NODELAY,
        &one as *const i32 as *const u8,
        core::mem::size_of::<i32>() as u32,
    );
    let _ = syscall::Setsockopt(
        fd,
        syscall::SOL_SOCKET,
        syscall::SO_KEEPALIVE,
        &one as *const i32 as *const u8,
        core::mem::size_of::<i32>() as u32,
    );
    let idle_secs: i32 = 15;
    let _ = syscall::Setsockopt(
        fd,
        syscall::IPPROTO_TCP,
        syscall::TCP_KEEPIDLE,
        &idle_secs as *const i32 as *const u8,
        core::mem::size_of::<i32>() as u32,
    );
    let intvl_secs: i32 = 15;
    let _ = syscall::Setsockopt(
        fd,
        syscall::IPPROTO_TCP,
        syscall::TCP_KEEPINTVL,
        &intvl_secs as *const i32 as *const u8,
        core::mem::size_of::<i32>() as u32,
    );
    let cnt: i32 = 9;
    let _ = syscall::Setsockopt(
        fd,
        syscall::IPPROTO_TCP,
        syscall::TCP_KEEPCNT,
        &cnt as *const i32 as *const u8,
        core::mem::size_of::<i32>() as u32,
    );
}

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
    // Options persist across connect(2); setting them here covers
    // both the immediate- and in-flight-connect return paths.
    set_tcp_conn_defaults(fd);

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
            return (
                TCPConn::dead(),
                op_error(
                    "dial",
                    &network,
                    Some(alloc::sync::Arc::new(TCPAddr::from_sockaddr_in(&parsed))),
                    "connect",
                    errno,
                ),
            );
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
            return (
                TCPConn::dead(),
                op_error(
                    "dial",
                    &network,
                    Some(alloc::sync::Arc::new(TCPAddr::from_sockaddr_in(&parsed))),
                    "connect",
                    so_err,
                ),
            );
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

pub(crate) fn dead_listener() -> Listener {
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

// go: none — goish-only: Go builds `&OpError{Op, Net, Addr, Err:
// &os.SyscallError{Syscall, Err: errno}}` inline at each site; this
// names the composition once.
/// The error a failed socket syscall produces, in Go's shape.
///
/// goish used to return `errno_error(syscall, errno)` here — the right
/// INNER text ("connect: connection refused") and no type at all, so
/// `errors.As(err, &opErr)` and `err.(net.Error)` both missed and a
/// caller could not tell a refused connection from any other failure
/// except by matching on the message. Go's text for the same failure
/// is "dial tcp 127.0.0.1:1: connect: connection refused"; goish was
/// producing exactly its inner half and dropping the wrapper that
/// carries the operation, the network and the address.
fn op_error(
    op: &str,
    network: &string,
    addr: Option<alloc::sync::Arc<dyn net::Addr>>,
    syscall_name: &str,
    errno: i32,
) -> error {
    let inner = crate::os::NewSyscallError(
        string::from_bytes(syscall_name.as_bytes()),
        errors::Wrap(syscall::Errno(errno as _)),
    );
    return errors::Wrap(net::OpError {
        Op: string::from_bytes(op.as_bytes()),
        Net: network.clone(),
        Source: None,
        Addr: addr,
        Err: inner,
    });
}

/// Build a "i/o timeout" error matching Go's net.OpError +
/// `Err: errors.New("i/o timeout")` pattern. Returned when a
/// `SetReadDeadline` / `SetWriteDeadline` fires before the I/O
/// completes.
///
/// The message is unchanged, and it is now TYPED: `net::timeoutError`
/// answers `Timeout()` and `Temporary()` and satisfies `net.Error`, so
/// `os.IsTimeout(err)` and `err.(net.Error).Timeout()` — the two ways
/// Go's own documentation tells a caller to ask — both work. Before,
/// this was an `errors::New` string and every typed assertion on it
/// missed.
fn timeout_error(op: &str) -> error {
    // Go: &OpError{Op: op, Err: errTimeout} — the same composition,
    // so the rendered text is unchanged ("read: i/o timeout") and the
    // value is now typed all the way down: OpError.Timeout() asks its
    // inner error, and errTimeout answers.
    errors::Wrap(net::OpError {
        Op: string::from_bytes(op.as_bytes()),
        Net: string::new(),
        Source: None,
        Addr: None,
        Err: net::errTimeout(),
    })
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

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registries for the types this package declares. See AGENTS.md §9b.
/// Register `net::TCPConn` into the `io` and `net` interface
/// registries. Idempotent; called from `goish::init()`.
pub fn register_net_impls() {
    use crate::io::{
        __goish_register_Closer_impl, __goish_register_Reader_impl, __goish_register_Writer_impl,
    };
    __goish_register_Reader_impl::<TCPConn>();
    __goish_register_Writer_impl::<TCPConn>();
    __goish_register_Closer_impl::<TCPConn>();
    __goish_register_Conn_impl::<TCPConn>();
    net::register_net_error_impls();
}
