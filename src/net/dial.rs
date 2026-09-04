// net/dial — Go 1.25.5 src/net/dial.go.
//
// One `.rs` per `.go` (§33). These declarations lived in `net/mod.rs`
// while `Dial` was the only one of them; `DialTimeout` and
// `Dialer.Dial` made it a second file's worth of surface, so they
// moved here together rather than growing the module root.
//
// The dial BODY stays in mod.rs: `dial_deadline` is goish-only
// plumbing over the socket, netpoll and TCPConn internals that mod.rs
// declares, and corresponds to no single declaration in dial.go.

#![allow(non_snake_case)]

use crate::errors::error;
use crate::gostring::string;
use crate::net::{dial_deadline, Conn, TCPConn};

// go: sdk 1.25.5 net/dial.go:19 defaultTCPKeepAliveIdle
/// Go: "a default constant value for TCP_KEEPIDLE. See
/// go.dev/issue/31510 for details."
pub(crate) const defaultTCPKeepAliveIdle: crate::time::Duration =
    crate::time::Duration(15 * 1_000_000_000);

// go: sdk 1.25.5 net/dial.go:23 defaultTCPKeepAliveInterval
/// Go: "a default constant value for TCP_KEEPINTVL. It is the same as
/// defaultTCPKeepAliveIdle."
pub(crate) const defaultTCPKeepAliveInterval: crate::time::Duration =
    crate::time::Duration(15 * 1_000_000_000);

// go: sdk 1.25.5 net/dial.go:26 defaultTCPKeepAliveCount
/// Go: "a default constant value for TCP_KEEPCNT."
pub(crate) const defaultTCPKeepAliveCount: i32 = 9;

// go: sdk 1.25.5 net/dial.go:469-472 Dial
/// `net.Dial` — connect to `addr`. No deadline: the connect waits as
/// long as the kernel does. `DialTimeout` bounds it.
pub fn Dial<N: Into<string>, A: Into<string>>(network: N, addr: A) -> (TCPConn, error) {
    return dial_deadline(network.into(), addr.into(), 0);
}

// go: sdk 1.25.5 net/dial.go:484-487 DialTimeout
/// Go: `d := Dialer{Timeout: timeout}; return d.Dial(network, address)`.
///
/// A zero (or negative) timeout means NO timeout, not an instant one —
/// Go's `Dialer.deadline` returns the zero Time when `d.Timeout <= 0`,
/// and a zero deadline is no deadline.
pub fn DialTimeout<N: Into<string>, A: Into<string>>(
    network: N,
    addr: A,
    timeout: crate::time::Duration,
) -> (TCPConn, error) {
    return dial_deadline(network.into(), addr.into(), deadline_from_timeout(timeout));
}

// go: none — goish-only: NOT a port of `Dialer.deadline`
// (dial.go:250), which folds the Dialer's Timeout together with the
// context's and answers a `time.Time`. goish's dial takes no context
// and the netpoller wants absolute monotonic nanoseconds, so this
// covers only that function's Timeout arm, in the units the caller
// needs. Porting `deadline` proper waits on a context-carrying dial.
/// The absolute monotonic deadline a timeout implies, in the form
/// `netpoll::set_deadline` wants: 0 for "no deadline".
fn deadline_from_timeout(timeout: crate::time::Duration) -> i64 {
    if timeout.0 <= 0 {
        return 0;
    }
    return crate::runtime::sysmon::monotonic_ns().wrapping_add(timeout.0);
}

// go: sdk 1.25.5 net/dial.go:125-230 Dialer
/// `net.Dialer` — connection-establishing configuration.
///
/// goish carries the three fields callers most often set. Timeout is
/// LIVE: `Dial` and the `DialContext` closure both bound the connect
/// with it. KeepAlive and DualStack are not — this doc used to say
/// the whole thing was "inert in v1", which stopped being true when
/// Timeout started working.
///
/// Go's own struct is far wider (Resolver, LocalAddr, FallbackDelay,
/// Control, ControlContext, KeepAliveConfig); goishlint reports the
/// rest of dial.go as unported, which it is.
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
    // go: sdk 1.25.5 net/dial.go:503-505 Dialer.Dial
    /// Go: `return d.DialContext(context.Background(), network, address)`.
    /// goish's `DialContext` is the bound-method-value form (it takes
    /// no arguments and RETURNS the closure), so this dials directly
    /// with the Dialer's Timeout rather than routing through it.
    pub fn Dial<N: Into<crate::gostring::string>, A: Into<crate::gostring::string>>(
        &self,
        network: N,
        addr: A,
    ) -> (TCPConn, error) {
        return crate::net::DialTimeout(network.into(), addr.into(), self.Timeout);
    }

    // go: none — goish-only: Go's `Dialer.DialContext` is a method
    // taking (ctx, network, address); this is the BOUND METHOD VALUE
    // of it — `dialer.DialContext` as a first-class function, which is
    // what `transport_default_other.go` assigns to
    // `Transport.DialContext`. Rust has no method values, so the
    // closure is built explicitly.
    /// The closure `http.Transport.DialContext` defaults to.
    ///
    /// This used to return `Arc::new(|| {})` — no arguments, no return
    /// — on the note that the real form was "deferred until the
    /// connection-pool layer lands". It dials now, bounded by the
    /// Dialer's Timeout. KeepAlive is still not threaded through:
    /// `set_tcp_conn_defaults` sets the keepalive socket options
    /// unconditionally, so a Dialer carrying a KeepAlive interval
    /// dials with goish's defaults rather than that one.
    pub fn DialContext(&self) -> crate::net::http::DialContextFn {
        let timeout = self.Timeout;
        return alloc::sync::Arc::new(
            move |_ctx: Option<alloc::sync::Arc<dyn crate::context::Context>>,
                  network: crate::gostring::string,
                  addr: crate::gostring::string| {
                let (conn, err) = crate::net::DialTimeout(network, addr, timeout);
                if !err.IsNil() {
                    return (None, err);
                }
                let boxed: alloc::boxed::Box<dyn Conn> = alloc::boxed::Box::new(conn);
                return (Some(boxed), crate::errors::nil);
            },
        );
    }
}
