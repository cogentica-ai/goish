// go: sdk 1.25.5 net/http/httptest/server.go
//
// Implementation of Server — an HTTP server listening on a
// system-chosen port on the local loopback interface, for use in
// end-to-end HTTP tests.
//
// ## What is NOT ported, and why
//
// * `StartTLS`, `NewTLSServer`, `Certificate`, `closeIdleTransport` —
//   need `crypto/tls.NewListener` (absent: goish's tls is
//   client-side plus a server handshake, with no `Listener` wrapper)
//   and `net/http/internal/testcert` (unported). The plain-HTTP half
//   stands alone; the TLS half is a separate unit.
// * `wrap`, `closeConn`, `closeConnChan`, `CloseClientConnections`,
//   `logCloseHangDebugInfo` — all hang off `Server.Config.ConnState`,
//   a hook field goish's `http::Server` does not have. `ConnState`
//   the TYPE is ported (server.rs:1447) but nothing invokes it, so
//   there is no per-conn state map for these to read. Porting them
//   would produce five functions that can never fire.
// * `init` / `serveFlag` — need `flag`, and the flag is explicitly
//   not part of Go's API ("Don't depend on this"). Its only effects
//   are a debugging listen address and a `select{}` block in Start;
//   `newLocalListener` and `Start` carry the `serveFlag == ""` branch
//   they take when it is unset, which is always, here.

#![allow(non_snake_case)]

use crate::net;
use crate::string;
use crate::sync;
use alloc::sync::Arc;

// goishlint:ignore GOISH019 Server — Go's httptest.Server exposes
// URL, TLS and certificate as plain fields; goish holds all three
// behind mutexes because Start/StartTLS write them through an
// already-shared Arc (see the URL field comment). Same data, and the
// accessors carry the Go names.
// go: sdk 1.25.5 net/http/httptest/server.go:26-57 Server
//
// A Server is an HTTP server listening on a system-chosen port on
// the local loopback interface, for use in end-to-end HTTP tests.
//
// goish divergences from Go's field set, each forced:
//
//   * `Listener` is an `Arc<net::Listener>`, not a `net.Listener`
//     interface value. Go can hand the listener to `Serve` and still
//     hold it for `Close`; sharing in Rust is explicit.
//   * `EnableHTTP2`, `TLS`, `certificate` are omitted with the TLS
//     half above.
//   * `conns` is omitted with the ConnState half above; `closed`
//     keeps its mutex because `Close` must stay idempotent.
pub struct Server {
    /// Base URL of form `http://ipaddr:port` with no trailing slash.
    ///
    /// Go exposes this as a plain field, written by `Start`. goish
    /// keeps it behind a mutex and an accessor (`ts.URL()`), because
    /// `Start` runs on an already-shared `Arc<Server>` — mutating a
    /// bare field through the Arc would need `unsafe` and alias a
    /// reference any other holder could be reading. The mutex is
    /// uncontended in practice: `Start` is the only writer.
    URL: sync::Mutex<string>,
    pub Listener: Arc<net::Listener>,

    /// Go's `TLS *tls.Config` — "the optional TLS configuration,
    /// populated with a new config after TLS is started." Behind a
    /// mutex for the same reason `URL` is: StartTLS writes it through
    /// an already-shared Arc.
    TLS: sync::Mutex<Option<crate::crypto::tls::Config>>,
    /// Go's `certificate *x509.Certificate`, parsed from the config's
    /// first cert so a test can trust it explicitly.
    certificate: sync::Mutex<Option<crate::crypto::x509::Certificate>>,

    /// May be changed after calling `NewUnstartedServer` and before
    /// `Start`.
    pub Config: Arc<super::super::Server>,

    /// Counts the number of outstanding HTTP requests on this
    /// server. `Close` blocks until all requests are finished.
    wg: sync::WaitGroup,

    /// Guards `closed`.
    mu: sync::Mutex<bool>,

    /// Go's `conns map[net.Conn]http.ConnState`. goish's ConnState
    /// hook reports the connection's FD rather than the conn itself
    /// (a borrowed conn cannot outlive the callback), so the fd is the
    /// key — it is the same identity for as long as the conn is open,
    /// which is exactly the window this map covers.
    conns: sync::Mutex<crate::gomap::map<crate::types::int, super::super::server::ConnState>>,

    /// Configured for use with the server.
    client: Arc<super::super::Client>,
}

// go: sdk 1.25.5 net/http/httptest/server.go:94-101 strSliceContainsPrefix
//
// Unwired on purpose, which is normally a bug smell: its ONLY Go
// caller is the `init` that registers `-httptest.serve`, waived at
// the top of this file. Ported anyway because it is pure, is exactly
// what Go declares, and would otherwise be silently missing from the
// package; delete it only if the flag half is ruled out for good.
#[allow(dead_code)]
fn strSliceContainsPrefix(v: &crate::slice<string>, pre: string) -> bool {
    for i in 0..v.len() {
        if crate::strings::HasPrefix(v[i].clone(), pre.clone()) {
            return true;
        }
    }
    return false;
}

// go: sdk 1.25.5 net/http/httptest/server.go:60-75 newLocalListener
//
// The `serveFlag` branch is omitted with `init` above: with no
// `flag` package the flag is always unset, so only the fallback path is
// reachable. Go tries tcp4 loopback then tcp6.
fn newLocalListener() -> net::Listener {
    let (l, err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if err != crate::nil {
        let (l6, err6) = net::Listen(string("tcp6"), string("[::1]:0"));
        if err6 != crate::nil {
            panic!("httptest: failed to listen on a port: {}", err6.Error());
        }
        return l6;
    }
    return l;
}

// go: sdk 1.25.5 net/http/httptest/server.go:190-194 NewTLSServer
/// Go: "starts and returns a new Server using TLS. The caller should
/// call Close when finished, to shut it down."
pub fn NewTLSServer(handler: Arc<dyn super::super::Handler>) -> Arc<Server> {
    let ts = NewUnstartedServer(handler);
    ts.clone().StartTLS();
    return ts;
}
// go: sdk 1.25.5 net/http/httptest/server.go:105-109 NewServer
//
// Starts and returns a new Server. The caller should call `Close`
// when finished, to shut it down.
pub fn NewServer(handler: Arc<dyn super::super::Handler>) -> Arc<Server> {
    let ts = NewUnstartedServer(handler);
    ts.clone().Start();
    return ts;
}

// go: sdk 1.25.5 net/http/httptest/server.go:117-122 NewUnstartedServer
//
// Returns a new Server but doesn't start it. After changing its
// configuration, the caller should call `Start`.
pub fn NewUnstartedServer(handler: Arc<dyn super::super::Handler>) -> Arc<Server> {
    return Arc::new(Server {
        URL: sync::Mutex::new(string("")),
        TLS: sync::Mutex::new(None),
        certificate: sync::Mutex::new(None),
        Listener: Arc::new(newLocalListener()),
        Config: Arc::new(super::super::Server {
            Handler: handler,
            ..Default::default()
        }),
        wg: sync::WaitGroup::new(),
        mu: sync::Mutex::new(false),
        conns: sync::Mutex::new(crate::gomap::map::new()),
        client: Arc::new(super::super::Client::default()),
    });
}

impl Server {
    // go: sdk 1.25.5 net/http/httptest/server.go:125-139 Server.Start
    //
    // Starts a server from `NewUnstartedServer`.
    //
    // goish takes `Arc<Self>` because `goServe` hands the server to a
    // goroutine, and sets `URL` through a helper rather than by
    // assignment for the same reason. The `serveFlag` tail (print to
    // stderr, then `select{}`) is omitted with `init` above.
    pub fn Start(self: Arc<Self>) {
        {
            let mut u = self.URL.Lock();
            if *u != "" {
                panic!("Server already started");
            }
            *u = crate::fmt::Sprintf!("http://%s", self.Listener.Addr().String());
        }
        self.clone().wrap();
        self.goServe();
    }

    // go: sdk 1.25.5 net/http/httptest/server.go:317-373 Server.wrap
    /// Install the `ConnState` hook that maintains `conns`.
    ///
    /// Go panics on an invalid transition; that is a real assertion
    /// about the server's own state machine, so it is kept. The
    /// waitgroup accounting is the load-bearing half: `Close` waits on
    /// `wg`, so a conn that is added and never removed hangs Close
    /// forever, and one removed twice makes Close return early with
    /// requests still in flight.
    pub fn wrap(self: Arc<Self>) {
        let oldHook = self.Config.ConnState.Lock().clone();
        let me = self.clone();
        self.Config.SetConnState(Some(alloc::sync::Arc::new(
            move |fd: crate::types::int, cs: super::super::server::ConnState| {
                {
                    // Go has ONE mutex guarding both `closed` and
                    // `conns`; goish has two, so the ORDER matters —
                    // `Close` takes mu then conns, and taking them the
                    // other way round here deadlocks the pair. (It
                    // did: http_httptest_server_smoke hung.)
                    let closed = *me.mu.Lock();
                    let mut conns = me.conns.Lock();
                    if cs == super::super::server::StateNew {
                        let (_, exists) = conns.Get(fd);
                        if exists {
                            panic!("invalid state transition");
                        }
                        // Go: add c to the tracked set and increment
                        // the waitgroup.
                        me.wg.Add(1);
                        conns.Set(fd, cs);
                        if closed {
                            // Go: "Probably just a socket-late-binding
                            // dial from the default transport that lost
                            // the race (and thus this connection is now
                            // idle and will never be used)."
                            me.closeConn(fd);
                        }
                    } else if cs == super::super::server::StateActive {
                        let (oldState, ok) = conns.Get(fd);
                        if ok {
                            if oldState != super::super::server::StateNew
                                && oldState != super::super::server::StateIdle
                            {
                                panic!("invalid state transition");
                            }
                            conns.Set(fd, cs);
                        }
                    } else if cs == super::super::server::StateIdle {
                        let (oldState, ok) = conns.Get(fd);
                        if ok {
                            if oldState != super::super::server::StateActive {
                                panic!("invalid state transition");
                            }
                            conns.Set(fd, cs);
                        }
                        if closed {
                            me.closeConn(fd);
                        }
                    } else if cs == super::super::server::StateHijacked
                        || cs == super::super::server::StateClosed
                    {
                        // Go: remove from the tracked set and decrement
                        // the waitgroup, "unless it was previously
                        // removed".
                        let (_, ok) = conns.Get(fd);
                        if ok {
                            conns.Delete(fd);
                            me.wg.Done();
                        }
                    }
                }
                if let Some(h) = oldHook.as_ref() {
                    h(fd, cs);
                }
            },
        )));
        return;
    }

    // go: sdk 1.25.5 net/http/httptest/server.go:377-377 Server.closeConn
    /// Go: "closeConn closes c. s.mu must be held." goish closes the
    /// fd directly — the conn value itself belongs to the serve loop.
    fn closeConn(&self, fd: crate::types::int) {
        self.closeConnChan(fd, None);
        return;
    }

    // go: sdk 1.25.5 net/http/httptest/server.go:381-386 Server.closeConnChan
    /// Go: "like closeConn, but takes an optional channel to receive a
    /// value when the goroutine closing c is done."
    fn closeConnChan(&self, fd: crate::types::int, done: Option<crate::gochan::chan<()>>) {
        // Go closes the conn, and its netpoller wakes the goroutine
        // parked reading it. goish's does not — closing an fd drops
        // queued epoll events but fires no EPOLLHUP at an existing
        // parker, the same wall `Listener.Close` hits above. shutdown(2)
        // DOES wake a blocked reader (it returns EOF), and leaves the
        // fd's single owner — the serve loop — to do the close, so
        // there is no double-close race.
        //
        // SHUT_RDWR
        let _ = crate::syscall::Shutdown(crate::int32(fd), 2);
        if let Some(ch) = done {
            let _ = ch.__try_send(());
        }
        return;
    }

    // go: sdk 1.25.5 net/http/httptest/server.go:254-263 Server.logCloseHangDebugInfo
    /// Go dumps each stuck conn's type, pointer, remote address and
    /// state. goish's tracked identity is the fd, so that is what is
    /// printed — the state is the part that says WHY Close is stuck.
    fn logCloseHangDebugInfo(&self) {
        let conns = self.conns.Lock();
        let mut buf = crate::strings::Builder::new();
        let _ = buf.WriteString(string(
            "httptest.Server blocked in Close after 5 seconds, waiting for connections:\n",
        ));
        let keys = conns.Keys();
        for i in 0..keys.len() {
            let fd = keys[i];
            let (st, _) = conns.Get(fd);
            let _ = buf.WriteString(crate::fmt::Sprintf!(
                "  fd %d in state %s\n",
                crate::int64(fd),
                super::super::server::ConnStateString(st)
            ));
        }
        crate::log::Printf!("%s", buf.String());
        return;
    }

    // go: sdk 1.25.5 net/http/httptest/server.go:266-291 Server.CloseClientConnections
    /// Go: "closes any open HTTP connections to the test Server."
    ///
    /// The five-second bound is Go's, and its comment explains why it
    /// exists rather than waiting forever: "Out of paranoia for making
    /// a late change in Go 1.6 […] golang.org/issue/14291 isn't fully
    /// understood yet."
    pub fn CloseClientConnections(&self) {
        let nconn = {
            let conns = self.conns.Lock();
            let keys = conns.Keys();
            let ch: crate::gochan::chan<()> = crate::make!(chan(), crate::int64(keys.len()));
            for i in 0..keys.len() {
                let _ = self.closeConnChan(keys[i], Some(ch.clone()));
            }
            (keys.len(), ch)
        };
        let (n, ch) = nconn;
        // Go waits on the close goroutines with a 5s timer; goish
        // closes inline, so the sends are already queued on a buffered
        // chan and this drains them without ever blocking.
        let deadline = crate::time::Now().Add(crate::time::Duration(5 * 1_000_000_000));
        let mut i = 0;
        while i < n {
            match ch.__try_recv() {
                Some(_) => {
                    i += 1;
                }
                None => {
                    if crate::time::Now().After(deadline) {
                        // Go: "Too slow. Give up."
                        return;
                    }
                    crate::runtime::sched::Gosched();
                }
            }
        }
        return;
    }

    // go: none — goish-only accessor for the `URL` field, which is
    // mutex-held here; see the field comment.
    pub fn URL(&self) -> string {
        return self.URL.Lock().clone();
    }

    // go: sdk 1.25.5 net/http/httptest/server.go:202-251 Server.Close
    //
    // Shuts down the server and blocks until all outstanding requests
    // on this server have completed.
    //
    // Go arms `time.AfterFunc(5*time.Second, s.logCloseHangDebugInfo)`
    // and stops it on return. goish does not: a stopped AfterFunc
    // still holds its sleeper goroutine for the full duration, and
    // the runtime waits for every goroutine at exit, so every test
    // that closes an httptest server would take five extra seconds.
    // The wait loop below checks the same deadline itself and logs
    // once — same diagnostic, no leaked sleeper.
    //
    // **`__wake_accept` is load-bearing, and is why this is not a
    // transcription of Go's two lines.** Go's `s.Listener.Close()`
    // alone unblocks the `Serve` goroutine parked in `Accept`,
    // because Go's netpoller reports the close to the waiter. goish's
    // does not: closing the fd drops queued epoll events but fires no
    // EPOLLHUP at an existing parker, so a bare `Listener.Close()`
    // leaves `Serve` parked forever and `wg.Wait()` below never
    // returns — a hang, reproduced before this line was added.
    // `Server::Close`/`Shutdown` (server.rs:2009) hit the same wall
    // and solve it the same way, wake-then-close.
    pub fn Close(self: Arc<Self>) {
        {
            let mut closed = self.mu.Lock();
            if !*closed {
                *closed = true;
                self.Listener.__wake_accept();
                let _ = self.Listener.Close();
                self.Config.SetKeepAlivesEnabled(false);
                // Go: "Force-close any idle connections (those between
                // requests) and new connections (those which connected
                // but never sent a request). […] We only close
                // StateIdle and StateNew because they're not doing
                // anything."
                let conns = self.conns.Lock();
                let keys = conns.Keys();
                for i in 0..keys.len() {
                    let fd = keys[i];
                    let (st, _) = conns.Get(fd);
                    if st == super::super::server::StateIdle || st == super::super::server::StateNew
                    {
                        self.closeConn(fd);
                    }
                }
            }
        }
        // Go: "If this server doesn't shut down in 5 seconds, tell the
        // user why." See the note above on why this is a poll rather
        // than an AfterFunc.
        let deadline = crate::time::Now().Add(crate::time::Duration(5 * 1_000_000_000));
        let mut logged = false;
        while !self.wg.__try_wait() {
            if !logged && crate::time::Now().After(deadline) {
                self.logCloseHangDebugInfo();
                logged = true;
            }
            crate::runtime::sched::Gosched();
        }
    }

    // go: sdk 1.25.5 net/http/httptest/server.go:303-305 Server.Client
    //
    // Returns an HTTP client configured for making requests to the
    // server. Use `Server.URL` as the base URL to send requests to.
    pub fn Client(&self) -> Arc<super::super::Client> {
        return self.client.clone();
    }

    // go: sdk 1.25.5 net/http/httptest/server.go:141-188 Server.StartTLS
    /// Go: start the server with TLS, using the embedded localhost
    /// certificate unless the caller supplied `TLS.Certificates`.
    ///
    /// Partial, and the omissions have no goish counterpart to have:
    /// Go also sets NextProtos ("http/1.1", or "h2" when EnableHTTP2)
    /// and builds a CertPool for `s.client`'s transport. goish has no
    /// ALPN dispatch and httptest's Client is not TLS-configurable
    /// yet, so callers verify with InsecureSkipVerify or
    /// `Certificate()`.
    pub fn StartTLS(self: Arc<Self>) {
        {
            let u = self.URL.Lock();
            if *u != "" {
                panic!("Server already started");
            }
        }
        let (cert, err) = crate::crypto::tls::X509KeyPair(
            &super::super::internal::testcert::LocalhostCert(),
            &super::super::internal::testcert::LocalhostKey(),
        );
        if !err.IsNil() {
            panic!("httptest: NewTLSServer: bad embedded certificate");
        }
        let mut cfg = self.TLS.Lock().clone().unwrap_or_default();
        // Go: only install the test cert when the caller supplied none.
        if cfg.Certificates.Len() == 0 {
            cfg.Certificates =
                crate::goslice::slice::<crate::crypto::tls::Certificate>::__from_vec(alloc::vec![
                    cert
                ]);
        }
        // Go: `x509.ParseCertificate(s.TLS.Certificates[0].Certificate[0])`
        let leaf = cfg.Certificates[crate::int(0)].Certificate[crate::int(0)].clone();
        let (parsed, perr) = crate::crypto::x509::ParseCertificate(leaf);
        if perr.IsNil() {
            *self.certificate.Lock() = Some(parsed);
        }
        *self.TLS.Lock() = Some(cfg.clone());
        {
            let mut u = self.URL.Lock();
            *u = crate::fmt::Sprintf!("https://%s", self.Listener.Addr().String());
        }
        self.clone().wrap();
        self.goServeTLS(cfg);
        return;
    }

    // go: sdk 1.25.5 net/http/httptest/server.go:295-297 Server.Certificate
    /// Go: "returns the certificate used by the server, or nil if the
    /// server doesn't use TLS."
    pub fn Certificate(&self) -> Option<crate::crypto::x509::Certificate> {
        return self.certificate.Lock().clone();
    }

    // go: none — goish-only: the TLS twin of goServe. Go reaches
    // ServeTLS through `s.Config.Serve(tls.NewListener(…))`; goish's
    // HTTPS loop is a separate function, so this calls the Arc-taking
    // entry point with the config StartTLS just built.
    fn goServeTLS(self: Arc<Self>, cfg: crate::crypto::tls::Config) {
        self.wg.Add(1);
        let me = self.clone();
        crate::go!(stack(1024 * 1024), move || {
            let _ = me.Config.clone().__serve_tls_arc(me.Listener.clone(), cfg);
            me.wg.Done();
        });
        return;
    }
    // go: sdk 1.25.5 net/http/httptest/server.go:307-313 Server.goServe
    fn goServe(self: Arc<Self>) {
        self.wg.Add(1);
        let me = self.clone();
        crate::go!(stack(64 * 1024), move || {
            let _ = me.Config.clone().__serve_arc(me.Listener.clone());
            me.wg.Done();
        });
    }
}
