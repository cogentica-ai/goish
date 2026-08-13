// go: package net
//
// go: file net/net.go decls: mapErr, OpError.Unwrap, OpError.Error, OpError.Timeout, OpError.Temporary, ParseError.Error, ParseError.Timeout, ParseError.Temporary, AddrError.Error, AddrError.Timeout, AddrError.Temporary, UnknownNetworkError.Error, UnknownNetworkError.Timeout, UnknownNetworkError.Temporary, InvalidAddrError.Error, InvalidAddrError.Timeout, InvalidAddrError.Temporary, timeoutError.Error, timeoutError.Timeout, timeoutError.Temporary, timeoutError.Is, DNSConfigError.Unwrap, DNSConfigError.Error, DNSConfigError.Timeout, DNSConfigError.Temporary, notFoundError.Error, temporaryError.Error, temporaryError.Temporary, temporaryError.Timeout, newDNSError, DNSError.Unwrap, DNSError.Error, DNSError.Timeout, DNSError.Temporary, canceledError.Error, canceledError.Is
//
// net.go's error hierarchy, and the `Addr` interface everything in the
// package returns addresses through.
//
// This file is what unblocks net/http's remaining transport work.
// `socks_bundle.go`, `httputil/persist.go`, `Transport.DialContext` and
// `DumpRequestOut` all take or return `net.Addr` and wrap failures in
// `*net.OpError`; without those two types none of them can be written
// at all, which is why a net/http port has to come through here.
//
// Twenty of net.go's declarations are waived rather than ported, in two
// groups, both listed with reasons at the foot of the file:
//
//   * `conn.*` — Go layers `conn{fd *netFD}` under TCPConn/UDPConn and
//     puts Read/Write/Close/deadlines on the wrapper. goish has no
//     netFD: TCPConn owns its fd directly and carries those twelve
//     methods itself. Same shape as the //go:linkname pairs crypto/sha3
//     waives — the body is written once, on the side that can reach the
//     field.
//   * the netFD-dependent I/O paths — sendfile, writev and the
//     thread limiter, none of which goish's net has a counterpart for.
//
// `AddrError` moved here from mod.rs, which is a module root and so
// cannot hold anchored code (GOISH015).
//
// goishlint's GOISH018/021 do not read `// go: waived`, which is
// port_coverage's mechanism, so the same set is spelled again as
// suppressions. Every name below is either implemented on TCPConn
// (Go puts it on the `conn{fd *netFD}` wrapper that goish does not
// have) or is a netFD-dependent I/O path — sendfile, writev, the
// thread limiter — with no goish counterpart. The reasons are on the
// individual `// go: waived` lines at the foot of the file.
//
// goishlint:ignore GOISH018 ok, Read, Write, Close, LocalAddr, RemoteAddr, SetDeadline, SetReadDeadline, SetWriteDeadline, SetReadBuffer, SetWriteBuffer, File, ReadFrom, WriteTo, consume, genericReadFrom, genericWriteTo, acquireThread, releaseThread, listenerBacklog — see the waivers at the foot of the file.
//
// goishlint:ignore GOISH021 conn, Buffers, buffersWriter, noReadFrom, noWriteTo, tcpConnWithoutReadFrom, tcpConnWithoutWriteTo, Listener, PacketConn, listenerBacklogCache, threadLimit, threadOnce — the netFD layering goish does not have; Conn, Listener and PacketConn are declared in src/net/mod.rs, which is a module root and cannot carry anchors (GOISH015), so they stay there until net.go's interfaces move as a unit.

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

extern crate alloc;

use alloc::sync::Arc;

use crate::errors::{self, error, ErrorTrait};
use crate::gostring::string;

// ─── Addr ───────────────────────────────────────────────────────────

// go: sdk 1.25.5 net/net.go:116-119 Addr
/// Go: "Addr represents a network end point address."
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait Addr: Send + Sync {
    /// Go: "name of the network (for example, "tcp", "udp")".
    fn Network(&self) -> string;
    /// Go: "string form of address (for example, "192.0.2.1:25",
    /// "[2001:db8::1]:80")".
    fn String(&self) -> string;
}

// go: sdk 1.25.5 net/net.go:424-433 Error
/// Go: "An Error represents a network error."
///
/// Go embeds `error` and adds Timeout/Temporary. goish's `error` is a
/// concrete Arc-backed type rather than an interface to embed, so the
/// Error method is spelled out.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait Error: Send + Sync {
    fn Error(&self) -> string;
    /// Go: "Is the error a timeout?"
    fn Timeout(&self) -> bool;
    /// Go: "Deprecated: Temporary errors are not well-defined."
    fn Temporary(&self) -> bool;
}

// go: sdk 1.25.5 net/net.go:535-537 timeout
/// Go: `type timeout interface { Timeout() bool }` — the probe OpError
/// uses on its wrapped error.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait timeout: Send + Sync {
    fn Timeout(&self) -> bool;
}

// go: sdk 1.25.5 net/net.go:548-550 temporary
/// Go: `type temporary interface { Temporary() bool }`.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait temporary: Send + Sync {
    fn Temporary(&self) -> bool;
}

// ─── package errors ─────────────────────────────────────────────────

crate::var! {
    // go: sdk 1.25.5 net/net.go:436-446 errNoSuitableAddress
    /// Go: "For connection setup operations."
    pub(crate) errNoSuitableAddress: error = "no suitable address found";
    // go: sdk 1.25.5 net/net.go:436-446 errMissingAddress
    /// Go: "For connection setup and write operations."
    pub(crate) errMissingAddress: error = "missing address";
    // go: sdk 1.25.5 net/net.go:436-446 ErrWriteToConnected
    pub ErrWriteToConnected: error = "use of WriteTo with pre-connected connection";
    // go: sdk 1.25.5 net/net.go:744-750 ErrClosed
    /// Go: "ErrClosed is the error returned by an I/O call on a network
    /// connection that has already been closed... should normally be
    /// tested using errors.Is(err, net.ErrClosed)."
    pub ErrClosed: error = "use of closed network connection";

    // go: sdk 1.25.5 net/net.go:647-650 errNoSuchHost
    /// Go: "Various errors contained in DNSError."
    ///
    /// Go builds these as `&notFoundError{...}`; goish's var! makes
    /// them pointer-stable sentinels, which is what newDNSError's
    /// IsNotFound test needs.
    pub(crate) errNoSuchHost: error = "no such host";
    // go: sdk 1.25.5 net/net.go:647-650 errUnknownPort
    pub(crate) errUnknownPort: error = "unknown port";
}

// go: sdk 1.25.5 net/net.go:450-450 canceledError
/// Go: "canceledError lets us return the same error string we have
/// always returned, while still being Is context.Canceled."
pub(crate) struct canceledError;

impl ErrorTrait for canceledError {
    // go: sdk 1.25.5 net/net.go:452-452 canceledError.Error
    fn Error(&self) -> string {
        return string::from_static("operation was canceled");
    }
}

impl canceledError {
    // go: sdk 1.25.5 net/net.go:454-454 canceledError.Is
    /// Go: `func (canceledError) Is(err error) bool { return err == context.Canceled }`
    pub(crate) fn Is(&self, err: &error) -> bool {
        return errors::Is(err.clone(), crate::context::Canceled);
    }
}

// go: sdk 1.25.5 net/net.go:626-626 timeoutError
/// Go: "errTimeout exists to return the historical "i/o timeout" string
/// for context.DeadlineExceeded. See mapErr."
pub(crate) struct timeoutError;

impl ErrorTrait for timeoutError {
    // go: sdk 1.25.5 net/net.go:628-628 timeoutError.Error
    fn Error(&self) -> string {
        return string::from_static("i/o timeout");
    }
}

impl timeoutError {
    // go: sdk 1.25.5 net/net.go:629-629 timeoutError.Timeout
    pub(crate) fn Timeout(&self) -> bool {
        return true;
    }
    // go: sdk 1.25.5 net/net.go:630-630 timeoutError.Temporary
    pub(crate) fn Temporary(&self) -> bool {
        return true;
    }
    // go: sdk 1.25.5 net/net.go:632-634 timeoutError.Is
    /// Go: "error.Is(errTimeout, context.DeadlineExceeded) returns
    /// true."
    pub(crate) fn Is(&self, err: &error) -> bool {
        return errors::Is(err.clone(), crate::context::DeadlineExceeded);
    }
}

// go: none — goish-only: Go writes `var errTimeout error = &timeoutError{}`
// and `errCanceled = canceledError{}`. goish's errors are Arc-backed, so
// the singletons are built here rather than by a composite literal.
pub(crate) fn errTimeout() -> error {
    return errors::Wrap(timeoutError);
}

// go: none — goish-only, see errTimeout.
pub(crate) fn errCanceled() -> error {
    return errors::Wrap(canceledError);
}

// go: sdk 1.25.5 net/net.go:458-467 mapErr
/// Go: "mapErr maps from the context errors to the historical internal
/// net error values."
pub(crate) fn mapErr(err: error) -> error {
    if errors::Is(err.clone(), crate::context::Canceled) {
        return errCanceled();
    }
    if errors::Is(err.clone(), crate::context::DeadlineExceeded) {
        return errTimeout();
    }
    return err;
}

// ─── OpError ────────────────────────────────────────────────────────

// go: sdk 1.25.5 net/net.go:472-497 OpError
/// Go: "OpError is the error type usually returned by functions in the
/// net package. It describes the operation, network type, and address
/// of an error."
pub struct OpError {
    /// Go: "the operation which caused the error, such as "read" or
    /// "write"."
    pub Op: string,
    /// Go: "the network type on which this error occurred, such as
    /// "tcp" or "udp6"."
    pub Net: string,
    /// Go: "For operations involving a remote network connection, like
    /// Dial, Read, or Write, Source is the corresponding local network
    /// address."
    pub Source: Option<Arc<dyn Addr>>,
    /// Go: "the network address for which this error occurred."
    pub Addr: Option<Arc<dyn Addr>>,
    /// Go: "the error that occurred during the operation."
    pub Err: error,
}

impl ErrorTrait for OpError {
    // go: sdk 1.25.5 net/net.go:501-522 OpError.Error
    fn Error(&self) -> string {
        let mut s = self.Op.clone();
        if self.Net.Len() != 0 {
            s = s + string::from_static(" ") + self.Net.clone();
        }
        if let Some(src) = self.Source.as_ref() {
            s = s + string::from_static(" ") + src.String();
        }
        if let Some(a) = self.Addr.as_ref() {
            if self.Source.is_some() {
                s = s + string::from_static("->");
            } else {
                s = s + string::from_static(" ");
            }
            s = s + a.String();
        }
        return s + string::from_static(": ") + self.Err.Error();
    }

    // go: sdk 1.25.5 net/net.go:499-499 OpError.Unwrap
    fn Unwrap(&self) -> error {
        return self.Err.clone();
    }
}

impl OpError {
    // go: sdk 1.25.5 net/net.go:539-546 OpError.Timeout
    /// Go probes the wrapped error for a `timeout` interface, first
    /// through an `*os.SyscallError` if that is what it holds. goish
    /// has no os.SyscallError, so only the direct probe applies.
    pub fn Timeout(&self) -> bool {
        let (t, ok) = crate::cast!(&self.Err, timeout);
        return ok && t.Timeout();
    }

    // go: sdk 1.25.5 net/net.go:552-567 OpError.Temporary
    /// Go: "Treat ECONNRESET and ECONNABORTED as temporary errors when
    /// they come from calling accept. See issue 6163."
    pub fn Temporary(&self) -> bool {
        if self.Op == "accept" && isConnError(&self.Err) {
            return true;
        }
        let (t, ok) = crate::cast!(&self.Err, temporary);
        return ok && t.Temporary();
    }
}

// go: none — goish-only: Go's isConnError lives in error_posix.go and
// asks whether a syscall.Errno is ECONNRESET or ECONNABORTED. goish's
// net does not carry Errno through its error values, so this is the
// conservative answer — false — which only ever makes Temporary()
// stricter, never more permissive.
fn isConnError(_err: &error) -> bool {
    return false;
}

// ─── ParseError / AddrError ─────────────────────────────────────────

// go: sdk 1.25.5 net/net.go:568-575 ParseError
/// Go: "A ParseError is the error type of literal network address
/// parsers."
pub struct ParseError {
    /// Go: "the type of string that was expected, such as "IP address",
    /// "CIDR address"."
    pub Type: string,
    /// Go: "the malformed text string."
    pub Text: string,
}

impl ErrorTrait for ParseError {
    // go: sdk 1.25.5 net/net.go:577-577 ParseError.Error
    fn Error(&self) -> string {
        return string::from_static("invalid ")
            + self.Type.clone()
            + string::from_static(": ")
            + self.Text.clone();
    }
}

impl ParseError {
    // go: sdk 1.25.5 net/net.go:579-579 ParseError.Timeout
    pub fn Timeout(&self) -> bool {
        return false;
    }
    // go: sdk 1.25.5 net/net.go:580-580 ParseError.Temporary
    pub fn Temporary(&self) -> bool {
        return false;
    }
}

// go: sdk 1.25.5 net/net.go:582-585 AddrError
pub struct AddrError {
    pub Err: string,
    pub Addr: string,
}

impl ErrorTrait for AddrError {
    // go: sdk 1.25.5 net/net.go:587-596 AddrError.Error
    fn Error(&self) -> string {
        if self.Addr.Len() == 0 {
            return self.Err.clone();
        }
        return string::from_static("address ")
            + self.Addr.clone()
            + string::from_static(": ")
            + self.Err.clone();
    }
}

impl AddrError {
    // go: sdk 1.25.5 net/net.go:598-598 AddrError.Timeout
    pub fn Timeout(&self) -> bool {
        return false;
    }
    // go: sdk 1.25.5 net/net.go:599-599 AddrError.Temporary
    pub fn Temporary(&self) -> bool {
        return false;
    }
}

// go: sdk 1.25.5 net/net.go:601-601 UnknownNetworkError
pub struct UnknownNetworkError(pub string);

impl ErrorTrait for UnknownNetworkError {
    // go: sdk 1.25.5 net/net.go:603-603 UnknownNetworkError.Error
    fn Error(&self) -> string {
        return string::from_static("unknown network ") + self.0.clone();
    }
}

impl UnknownNetworkError {
    // go: sdk 1.25.5 net/net.go:604-604 UnknownNetworkError.Timeout
    pub fn Timeout(&self) -> bool {
        return false;
    }
    // go: sdk 1.25.5 net/net.go:605-605 UnknownNetworkError.Temporary
    pub fn Temporary(&self) -> bool {
        return false;
    }
}

// go: sdk 1.25.5 net/net.go:607-607 InvalidAddrError
pub struct InvalidAddrError(pub string);

impl ErrorTrait for InvalidAddrError {
    // go: sdk 1.25.5 net/net.go:609-609 InvalidAddrError.Error
    fn Error(&self) -> string {
        return self.0.clone();
    }
}

impl InvalidAddrError {
    // go: sdk 1.25.5 net/net.go:610-610 InvalidAddrError.Timeout
    pub fn Timeout(&self) -> bool {
        return false;
    }
    // go: sdk 1.25.5 net/net.go:611-611 InvalidAddrError.Temporary
    pub fn Temporary(&self) -> bool {
        return false;
    }
}

// ─── DNS errors ─────────────────────────────────────────────────────

// go: sdk 1.25.5 net/net.go:638-640 DNSConfigError
/// Go: "DNSConfigError represents an error reading the machine's DNS
/// configuration. (No longer used; kept for compatibility.)"
pub struct DNSConfigError {
    pub Err: error,
}

impl ErrorTrait for DNSConfigError {
    // go: sdk 1.25.5 net/net.go:643-643 DNSConfigError.Error
    fn Error(&self) -> string {
        return string::from_static("error reading DNS config: ") + self.Err.Error();
    }

    // go: sdk 1.25.5 net/net.go:642-642 DNSConfigError.Unwrap
    fn Unwrap(&self) -> error {
        return self.Err.clone();
    }
}

impl DNSConfigError {
    // go: sdk 1.25.5 net/net.go:644-644 DNSConfigError.Timeout
    pub fn Timeout(&self) -> bool {
        return false;
    }
    // go: sdk 1.25.5 net/net.go:645-645 DNSConfigError.Temporary
    pub fn Temporary(&self) -> bool {
        return false;
    }
}

// go: sdk 1.25.5 net/net.go:655-655 notFoundError
/// Go: "notFoundError is a special error understood by the newDNSError
/// function, which causes a creation of a DNSError with IsNotFound
/// field set to true."
pub(crate) struct notFoundError {
    pub(crate) s: string,
}

impl ErrorTrait for notFoundError {
    // go: sdk 1.25.5 net/net.go:657-657 notFoundError.Error
    fn Error(&self) -> string {
        return self.s.clone();
    }
}

// go: sdk 1.25.5 net/net.go:661-661 temporaryError
/// Go: "temporaryError is an error type that implements the [Error]
/// interface. It returns true from the Temporary method."
pub(crate) struct temporaryError {
    pub(crate) s: string,
}

impl ErrorTrait for temporaryError {
    // go: sdk 1.25.5 net/net.go:663-663 temporaryError.Error
    fn Error(&self) -> string {
        return self.s.clone();
    }
}

impl temporaryError {
    // go: sdk 1.25.5 net/net.go:664-664 temporaryError.Temporary
    pub(crate) fn Temporary(&self) -> bool {
        return true;
    }
    // go: sdk 1.25.5 net/net.go:665-665 temporaryError.Timeout
    pub(crate) fn Timeout(&self) -> bool {
        return false;
    }
}

// go: sdk 1.25.5 net/net.go:666-679 DNSError
/// Go: "DNSError represents a DNS lookup error."
#[derive(Clone, Default)]
pub struct DNSError {
    /// Go: "error returned by the [DNSError.Unwrap] method, might be
    /// nil".
    pub UnwrapErr: error,
    /// Go: "description of the error".
    pub Err: string,
    /// Go: "name looked for".
    pub Name: string,
    /// Go: "server used".
    pub Server: string,
    /// Go: "if true, timed out; not all timeouts set this".
    pub IsTimeout: bool,
    /// Go: "if true, error is temporary; not all errors set this".
    pub IsTemporary: bool,
    /// Go: "set to true when the requested name does not contain any
    /// records of the requested type (data not found), or the name
    /// itself was not found (NXDOMAIN)."
    pub IsNotFound: bool,
}

impl ErrorTrait for DNSError {
    // go: sdk 1.25.5 net/net.go:717-727 DNSError.Error
    fn Error(&self) -> string {
        let mut s = string::from_static("lookup ") + self.Name.clone();
        if self.Server.Len() != 0 {
            s = s + string::from_static(" on ") + self.Server.clone();
        }
        return s + string::from_static(": ") + self.Err.clone();
    }

    // go: sdk 1.25.5 net/net.go:715-715 DNSError.Unwrap
    fn Unwrap(&self) -> error {
        return self.UnwrapErr.clone();
    }
}

impl DNSError {
    // go: sdk 1.25.5 net/net.go:732-732 DNSError.Timeout
    /// Go: "Timeout reports whether the DNS lookup is known to have
    /// timed out. This is not always known."
    pub fn Timeout(&self) -> bool {
        return self.IsTimeout;
    }

    // go: sdk 1.25.5 net/net.go:737-737 DNSError.Temporary
    /// Go: "Temporary reports whether the DNS error is known to be
    /// temporary."
    pub fn Temporary(&self) -> bool {
        return self.IsTimeout || self.IsTemporary;
    }
}

// go: sdk 1.25.5 net/net.go:683-712 newDNSError
/// Go: "newDNSError creates a new *DNSError. Based on the err, it sets
/// the UnwrapErr, IsTimeout, IsTemporary, IsNotFound fields."
pub(crate) fn newDNSError(err: error, name: string, server: string) -> DNSError {
    let mut isTimeout = false;
    let mut isTemporary = false;
    let mut unwrapErr: error = errors::nil;

    let (e, ok) = crate::cast!(&err, Error);
    if ok {
        isTimeout = e.Timeout();
        isTemporary = e.Temporary();
    }

    // Go: "At this time, the only errors we wrap are context errors, to
    // allow users to check for canceled/timed out requests."
    if errors::Is(err.clone(), crate::context::DeadlineExceeded)
        || errors::Is(err.clone(), crate::context::Canceled)
    {
        unwrapErr = err.clone();
    }

    // Go asserts `err.(*notFoundError)`. goish's `error` carries no
    // type assertion to a concrete struct, but notFoundError has
    // exactly two instances in the package — errNoSuchHost and
    // errUnknownPort — so matching those two sentinels by identity is
    // the same set.
    let nsh: error = errNoSuchHost.into();
    let up: error = errUnknownPort.into();
    let isNotFound = errors::Is(err.clone(), nsh) || errors::Is(err.clone(), up);

    return DNSError {
        UnwrapErr: unwrapErr,
        Err: err.Error(),
        Name: name,
        Server: server,
        IsTimeout: isTimeout,
        IsTemporary: isTemporary,
        IsNotFound: isNotFound,
    };
}

// ─── waived ─────────────────────────────────────────────────────────
//
// Go layers `conn{fd *netFD}` beneath TCPConn/UDPConn/UnixConn and puts
// the whole io surface on that wrapper. goish's TCPConn owns its fd
// directly and carries these twelve methods itself, so writing them
// here would be a second copy with no caller — the same situation
// crypto/sha3 waives for a //go:linkname pair, where the body is
// written once on the side that can reach the field.

// go: waived conn.ok — goish's TCPConn owns its fd directly; there is no netFD wrapper to nil-check.
// go: waived conn.Read — implemented on TCPConn, which is what Go's conn wraps.
// go: waived conn.Write — implemented on TCPConn.
// go: waived conn.Close — implemented on TCPConn.
// go: waived conn.LocalAddr — implemented on TCPConn.
// go: waived conn.RemoteAddr — implemented on TCPConn.
// go: waived conn.SetDeadline — implemented on TCPConn.
// go: waived conn.SetReadDeadline — implemented on TCPConn.
// go: waived conn.SetWriteDeadline — implemented on TCPConn.
// go: waived conn.SetReadBuffer — SO_RCVBUF tuning; goish's TCPConn takes the kernel default.
// go: waived conn.SetWriteBuffer — SO_SNDBUF tuning; goish's TCPConn takes the kernel default.
// go: waived conn.File — returns an *os.File duplicating the netFD; goish has no netFD to dup.
//
// The netFD-dependent I/O paths have no goish counterpart either:
//
// go: waived genericReadFrom — the io.Copy fallback for sendfile, which goish's net does not implement.
// go: waived genericWriteTo — the io.Copy fallback for splice, which goish's net does not implement.
// go: waived Buffers.WriteTo — writev over netFD; goish writes buffers one at a time.
// go: waived Buffers.Read — the io.Reader half of the writev buffer list.
// go: waived Buffers.consume — advances the writev buffer list after a partial write.
// go: waived acquireThread — the js/wasm thread limiter; goish is linux-only and has no such cap.
// go: waived releaseThread — pairs with acquireThread.
// go: waived listenerBacklog — caches maxListenerBacklog(), a /proc probe; goish's Listen uses a fixed backlog.

// ─── Addr implementors ──────────────────────────────────────────────

// go: none — goish-only: Go declares TCPAddr's Network/String in
// tcpsock.go, not net.go, so this impl carries no net.go anchor. It is
// here because `Addr` is declared here and Rust wants the trait in
// scope; the two methods forward to TCPAddr's own.
impl Addr for crate::net::TCPAddr {
    // go: none — goish-only, see the note above the impl.
    fn Network(&self) -> string {
        return string::from_static("tcp");
    }
    // go: none — goish-only, see the note above the impl.
    fn String(&self) -> string {
        return crate::net::TCPAddr::String(self);
    }
    // go: none — goish-only: the Any view `cast!` needs.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}
