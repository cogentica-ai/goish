// go: file crypto/tls/tls.go decls: timeoutError.Error, timeoutError.Timeout, timeoutError.Temporary, Dialer.netDialer, Dialer.DialContext, Dialer.Dial, dial, DialWithDialer
//
// crypto/tls — the package's dial/listen entry points.
//
// **Partial port.** tls.go's Server/Client/Listen/Dial/X509KeyPair
// surface is hand-written in mod[rs] and is not yet a port; this file
// holds what has been ported verbatim. The two are separate so that
// GOISH015 can tell them apart — a module root may not hold anchored
// code, which is what moved this out of mod[rs].
//
// goishlint:ignore GOISH018 Server, Client, Accept, NewListener, Listen, LoadX509KeyPair, X509KeyPair, parsePrivateKey — hand-written in mod[rs], not yet ports. See ROADMAP.md.
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
    // go: sdk 1.25.5 crypto/tls/tls.go:214-219 Dialer.netDialer
    pub(crate) fn netDialer(&self) -> crate::net::Dialer {
        // Go: if d.NetDialer != nil { return d.NetDialer }
        //     return new(net.Dialer)
        if self.NetDialer.is_some() {
            return self.NetDialer.clone().unwrap();
        }
        return crate::net::Dialer::default();
    }

    // go: sdk 1.25.5 crypto/tls/tls.go:230-237 Dialer.DialContext
    /// Go: connect to the given address and initiate a TLS handshake,
    /// returning the resulting TLS connection.
    ///
    /// Deviation: Go's `ctx context.Context` is dropped — goish has no
    /// context cancellation.
    /// goishlint:ignore GOISH020 DialContext — Go's context.Context parameter is not plumbed
    pub fn DialContext(
        &self,
        network: impl Into<crate::gostring::string>,
        addr: impl Into<crate::gostring::string>,
    ) -> (super::Conn, errors::error) {
        // Go: c, err := dial(ctx, d.netDialer(), network, addr, d.Config)
        //     if err != nil { return nil, err }
        //     return c, nil
        let (c, err) = dial(
            &self.netDialer(),
            network.into(),
            addr.into(),
            self.Config.as_ref(),
        );
        if !err.IsNil() {
            // Go: "Don't return c (a typed nil) in an interface."
            return (super::make_dead_conn(&super::Config::default()), err);
        }
        return (c, errors::nil);
    }

    // go: sdk 1.25.5 crypto/tls/tls.go:210-212 Dialer.Dial
    /// Go: connect using `context.Background`; use `DialContext` for
    /// control over cancellation.
    pub fn Dial(
        &self,
        network: impl Into<crate::gostring::string>,
        addr: impl Into<crate::gostring::string>,
    ) -> (super::Conn, errors::error) {
        // Go: return d.DialContext(context.Background(), network, addr)
        return self.DialContext(network, addr);
    }
}

// go: sdk 1.25.5 crypto/tls/tls.go:134-176 dial
/// Go: the shared dial path — dial the raw connection, infer the
/// ServerName from the address host when the config leaves it empty,
/// wrap the connection in a TLS client, and drive the handshake.
///
/// Deviations: Go's `ctx context.Context` is dropped (goish has no
/// context cancellation); `netDialer.Timeout`/`Deadline` are accepted
/// but not enforced (goish's `net.Dial` takes no deadline); and
/// `conn.HandshakeContext(ctx)` becomes `conn.Handshake()`.
pub(crate) fn dial(
    _netDialer: &crate::net::Dialer,
    network: crate::gostring::string,
    addr: crate::gostring::string,
    config: Option<&super::Config>,
) -> (super::Conn, errors::error) {
    // Go: the netDialer.Timeout / netDialer.Deadline context wrapping is
    // absent — see the deviation note.

    // Go: rawConn, err := netDialer.DialContext(ctx, network, addr)
    //     if err != nil { return nil, err }
    let (rawConn, err) = crate::net::Dial(network, addr.clone());
    if !err.IsNil() {
        return (super::make_dead_conn(&super::Config::default()), err);
    }

    // Go: colonPos := strings.LastIndex(addr, ":")
    //     if colonPos == -1 { colonPos = len(addr) }
    //     hostname := addr[:colonPos]
    let addr_str: &str = addr.as_ref();
    let hostname = if let Some(pos) = addr_str.rfind(':') {
        crate::gostring::string::from_bytes(addr_str[..pos].as_bytes())
    } else {
        addr.clone()
    };

    // Go: if config == nil { config = defaultConfig() }
    //     if config.ServerName == "" {
    //         c := config.Clone(); c.ServerName = hostname; config = c }
    let mut cfg = match config {
        Some(c) => c.clone(),
        None => super::common::defaultConfig(),
    };
    if cfg.ServerName.Len() == 0 {
        cfg.ServerName = hostname;
    }

    // Go: conn := Client(rawConn, config)
    //     if err := conn.HandshakeContext(ctx); err != nil {
    //         rawConn.Close(); return nil, err }
    //     return conn, nil
    let box_conn: alloc::boxed::Box<dyn crate::net::Conn> =
        alloc::boxed::Box::new(rawConn);
    let mut conn = super::Client(box_conn, &cfg);
    let herr = conn.Handshake();
    if !herr.IsNil() {
        conn.Close();
        return (conn, herr);
    }
    return (conn, errors::nil);
}

// go: sdk 1.25.5 crypto/tls/tls.go:130-132 DialWithDialer
/// Go: connect to `addr` on `network` using `dialer` and initiate a TLS
/// handshake with `config`, returning the resulting TLS connection.
pub fn DialWithDialer(
    dialer: &crate::net::Dialer,
    network: impl Into<crate::gostring::string>,
    addr: impl Into<crate::gostring::string>,
    config: &super::Config,
) -> (super::Conn, errors::error) {
    // Go: return dial(context.Background(), dialer, network, addr, config)
    return dial(dialer, network.into(), addr.into(), Some(config));
}
