// go: file crypto/tls/tls.go decls: timeoutError.Error, timeoutError.Timeout, timeoutError.Temporary, Dialer.netDialer
//
// crypto/tls — the package's dial/listen entry points.
//
// **Partial port.** tls.go's Server/Client/Listen/Dial/X509KeyPair
// surface is hand-written in mod[rs] and is not yet a port; this file
// holds what has been ported verbatim. The two are separate so that
// GOISH015 can tell them apart — a module root may not hold anchored
// code, which is what moved this out of mod[rs].
//
// goishlint:ignore GOISH018 Server, Client, Accept, NewListener, Listen, DialWithDialer, dial, Dial, DialContext, LoadX509KeyPair, X509KeyPair, parsePrivateKey — hand-written in mod[rs], not yet ports. See ROADMAP.md.
// goishlint:ignore GOISH019 listener — same.
// goishlint:ignore GOISH021 listener, errNoCertificates, x509keypairleaf — same; `x509keypairleaf` is an internal/godebug var, and godebug is not ported (every GODEBUG branch takes the unset default).

#![allow(non_snake_case, dead_code)]

use crate::errors;

// Go: tls.go:114
//   type timeoutError struct{}
/// `tls.timeoutError` — the error `DialWithDialer` returns when its
/// deadline elapses. Unexported in Go; it satisfies `net.Error` through
/// its `Timeout`/`Temporary` methods.
///
/// goishlint:ignore GOISH021 timeoutError — declared here, in mod[rs], because tls.go's dial path lives here
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct timeoutError {}

impl timeoutError {
    // go: sdk 1.25.5 crypto/tls/tls.go:116-116 timeoutError.Error
    /// Go: `func (timeoutError) Error() string { return "tls: DialWithDialer timed out" }`
    pub fn Error(&self) -> crate::gostring::string {
        return crate::gostring::string::from_static("tls: DialWithDialer timed out");
    }

    // go: sdk 1.25.5 crypto/tls/tls.go:117-117 timeoutError.Timeout
    /// Go: `func (timeoutError) Timeout() bool { return true }`
    pub fn Timeout(&self) -> bool {
        return true;
    }

    // go: sdk 1.25.5 crypto/tls/tls.go:118-118 timeoutError.Temporary
    /// Go: `func (timeoutError) Temporary() bool { return true }`
    pub fn Temporary(&self) -> bool {
        return true;
    }
}

impl errors::ErrorTrait for timeoutError {
    // go: none — goish idiom: Go's timeoutError satisfies `error` by
    // having an `Error() string` method; goish needs the impl spelled.
    fn Error(&self) -> crate::gostring::string {
        return timeoutError::Error(self);
    }
}


// ─── Dialer ───────────────────────────────────────────────────────────

// Go: tls.go:139-152
//   type Dialer struct { NetDialer *net.Dialer; Config *Config }
/// Go: "Dialer dials TLS connections given a configuration and a Dialer
/// for the underlying connection."
#[derive(Clone, Default)]
pub struct Dialer {
    /// Go: "NetDialer is the optional dialer to use for the TLS
    /// connections' underlying TCP connections. A nil NetDialer is
    /// equivalent to the net.Dialer zero value."
    pub NetDialer: Option<crate::net::Dialer>,
    /// Go: "Config is the TLS configuration to use for new connections.
    /// A nil configuration is equivalent to the zero configuration; see
    /// the documentation of Config for the defaults."
    pub Config: Option<super::Config>,
}

impl Dialer {
    // go: sdk 1.25.5 crypto/tls/tls.go:154-159 Dialer.netDialer
    pub(crate) fn netDialer(&self) -> crate::net::Dialer {
        // Go: if d.NetDialer != nil { return d.NetDialer }
        //     return new(net.Dialer)
        if self.NetDialer.is_some() {
            return self.NetDialer.clone().unwrap();
        }
        return crate::net::Dialer::default();
    }
}
