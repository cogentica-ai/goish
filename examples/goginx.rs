// goginx — an nginx clone written in Goish.
//
// A single-binary web server / reverse proxy driven by an nginx.conf-
// style configuration file, exercising the whole goish net stack:
// static file serving, virtual hosts, upstream round-robin proxying,
// TLS termination (M32), access logging, and graceful SIGTERM drain.
//
// Supported configuration subset (nginx grammar — directives end with
// `;`, blocks with `{ }`, comments with `#`):
//
//   events { worker_connections 1024; }        # parsed, informational
//   http {
//     upstream backend {
//       server 127.0.0.1:9001;                 # round-robin pool,
//       server 127.0.0.1:9002;                 # next-upstream retry
//     }
//     server {
//       listen 127.0.0.1:8080;                 # `listen 8443 ssl;`
//       server_name a.test www.a.test;         # Host-based vhosts;
//                                              # first block = default
//       location / { root /srv/www; index index.html; }
//       location /files/ { root /srv/www; autoindex on; }
//       location /api/ { proxy_pass http://backend; }
//     }
//   }
//
// nginx behaviours reproduced:
//   - longest-prefix `location` matching
//   - `root`-semantics file mapping (root + full URI), index files,
//     301 directory redirect, autoindex listings, MIME by extension,
//     nginx-style error pages, dot-dot traversal rejection
//   - upstream round-robin with retry-next-upstream on connect
//     failure and 502 when the whole pool is down
//   - X-Forwarded-For / X-Forwarded-Proto / X-Forwarded-Host
//     injection and hop-by-hop header stripping on both legs
//   - `listen ... ssl` TLS termination (one cert per listener;
//     SNI-based per-vhost certs are out of scope)
//   - `listen ... reuseport` — one SO_REUSEPORT listener per CPU
//     (nginx: one per worker), bound via `net.ListenConfig.Control`,
//     kernel hash-sharding accepts across the per-CPU accept loops
//   - combined-ish access log, SIGTERM/SIGINT graceful drain
//
// Modes:
//   GOGINX_CONF=/path/goginx.conf ./goginx     # real server, runs
//                                              # until SIGTERM
//   ./goginx                                   # self-test (e2e mode):
//                                              # builds a doc tree +
//                                              # config + 2 upstream
//                                              # backends in a temp
//                                              # dir, asserts the lot
//
// Marker on success: GOGINX_OK <n>/<n>

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;

use goish::context;
use goish::crypto::tls;
use goish::io;
use goish::net;
use goish::net::http;
use goish::net::http::ResponseWriter;
use goish::net::Conn;
use goish::os;
use goish::os::signal;
use goish::strconv;
use goish::strings;
use goish::sync::atomic;
use goish::sync::Mutex;
use goish::{
    append, byte, bytes, chan, error, go, int, len, make, map, nil, range, select, slice, string,
    syscall, time, Sprintf,
};

// ─── configuration model ────────────────────────────────────────────

#[derive(Clone)]
struct Directive {
    Name: string,
    Args: slice<string>,
    Block: slice<Directive>,
}

#[derive(Clone)]
struct Location {
    Prefix: string,
    Root: string,
    Index: string,
    ProxyPass: string,
    Autoindex: bool,
}

#[derive(Clone)]
struct ServerConf {
    Listen: string,
    TLS: bool,
    ReusePort: bool,
    CertFile: string,
    KeyFile: string,
    ServerNames: slice<string>,
    Locations: slice<Location>,
}

#[derive(Clone)]
struct Upstream {
    Name: string,
    Servers: slice<string>,
}

struct Config {
    Servers: slice<ServerConf>,
    Upstreams: slice<Upstream>,
    Mime: map<string, string>,
    // Round-robin cursor per upstream pool. nginx keeps peer state in
    // a shared zone; a mutex'd map is the goish equivalent.
    rr: Mutex<map<string, int>>,
}

// ─── config parser (tokenizer + recursive descent) ──────────────────

fn tokenize(src: string) -> slice<string> {
    let b = bytes(src);
    let n = len(&b);
    let mut toks = slice!([]string {});
    let mut i: int = 0;
    while i < n {
        let c = b[i];
        if c == b'#' {
            while i < n && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b' ' || c == b'\t' || c == b'\r' || c == b'\n' {
            i += 1;
            continue;
        }
        if c == b'{' {
            toks = append!(toks, "{");
            i += 1;
            continue;
        }
        if c == b'}' {
            toks = append!(toks, "}");
            i += 1;
            continue;
        }
        if c == b';' {
            toks = append!(toks, ";");
            i += 1;
            continue;
        }
        let mut word = slice!([]byte {});
        while i < n {
            let d = b[i];
            if d == b' '
                || d == b'\t'
                || d == b'\r'
                || d == b'\n'
                || d == b'{'
                || d == b'}'
                || d == b';'
                || d == b'#'
            {
                break;
            }
            word = append!(word, d);
            i += 1;
        }
        toks = append!(toks, string(word));
    }
    toks
}

/// Parse directives until end-of-tokens or a closing `}`.
fn parseBlock(toks: &slice<string>, pos: &mut int) -> slice<Directive> {
    let mut out = slice!([]Directive {});
    while *pos < len(toks) {
        if toks[*pos] == "}" {
            *pos += 1;
            return out;
        }
        let name = toks[*pos].clone();
        *pos += 1;
        let mut args = slice!([]string {});
        let mut block = slice!([]Directive {});
        while *pos < len(toks) {
            if toks[*pos] == ";" {
                *pos += 1;
                break;
            }
            if toks[*pos] == "{" {
                *pos += 1;
                block = parseBlock(toks, pos);
                break;
            }
            args = append!(args, toks[*pos].clone());
            *pos += 1;
        }
        out = append!(
            out,
            Directive {
                Name: name,
                Args: args,
                Block: block,
            }
        );
    }
    out
}

/// Collect `server` and `upstream` blocks, descending into `http {}`.
fn collectHttp(dirs: &slice<Directive>) -> (slice<ServerConf>, slice<Upstream>) {
    let mut servers = slice!([]ServerConf {});
    let mut ups = slice!([]Upstream {});
    for (_, d) in range!(dirs) {
        if d.Name == "http" {
            let (s2, u2) = collectHttp(&d.Block);
            for (_, s) in range!(&s2) {
                servers = append!(servers, s.clone());
            }
            for (_, u) in range!(&u2) {
                ups = append!(ups, u.clone());
            }
        } else if d.Name == "upstream" && len(&d.Args) > 0 {
            let mut pool = slice!([]string {});
            for (_, s) in range!(&d.Block) {
                if s.Name == "server" && len(&s.Args) > 0 {
                    pool = append!(pool, s.Args[0].clone());
                }
            }
            ups = append!(
                ups,
                Upstream {
                    Name: d.Args[0].clone(),
                    Servers: pool,
                }
            );
        } else if d.Name == "server" {
            servers = append!(servers, buildServer(&d.Block));
        }
    }
    (servers, ups)
}

fn buildServer(block: &slice<Directive>) -> ServerConf {
    let mut sc = ServerConf {
        Listen: string("127.0.0.1:8080"),
        TLS: false,
        ReusePort: false,
        CertFile: string(""),
        KeyFile: string(""),
        ServerNames: slice!([]string {}),
        Locations: slice!([]Location {}),
    };
    for (_, d) in range!(block) {
        if d.Name == "listen" && len(&d.Args) > 0 {
            sc.Listen = d.Args[0].clone();
            for (_, a) in range!(&d.Args) {
                if *a == "ssl" {
                    sc.TLS = true;
                }
                if *a == "reuseport" {
                    sc.ReusePort = true;
                }
            }
        } else if d.Name == "server_name" {
            for (_, a) in range!(&d.Args) {
                sc.ServerNames = append!(sc.ServerNames.clone(), a.clone());
            }
        } else if d.Name == "ssl_certificate" && len(&d.Args) > 0 {
            sc.CertFile = d.Args[0].clone();
        } else if d.Name == "ssl_certificate_key" && len(&d.Args) > 0 {
            sc.KeyFile = d.Args[0].clone();
        } else if d.Name == "location" && len(&d.Args) > 0 {
            sc.Locations = append!(sc.Locations.clone(), buildLocation(&d.Args[0], &d.Block));
        }
    }
    sc
}

fn buildLocation(prefix: &string, block: &slice<Directive>) -> Location {
    let mut loc = Location {
        Prefix: prefix.clone(),
        Root: string(""),
        Index: string("index.html"),
        ProxyPass: string(""),
        Autoindex: false,
    };
    for (_, d) in range!(block) {
        if d.Name == "root" && len(&d.Args) > 0 {
            loc.Root = d.Args[0].clone();
        } else if d.Name == "index" && len(&d.Args) > 0 {
            loc.Index = d.Args[0].clone();
        } else if d.Name == "proxy_pass" && len(&d.Args) > 0 {
            loc.ProxyPass = d.Args[0].clone();
        } else if d.Name == "autoindex" && len(&d.Args) > 0 {
            loc.Autoindex = d.Args[0] == "on";
        }
    }
    loc
}

fn mimeTable() -> map<string, string> {
    let mut m = make!(map[string]string);
    m.Set("html", "text/html");
    m.Set("htm", "text/html");
    m.Set("css", "text/css");
    m.Set("js", "application/javascript");
    m.Set("json", "application/json");
    m.Set("txt", "text/plain");
    m.Set("png", "image/png");
    m.Set("jpg", "image/jpeg");
    m.Set("jpeg", "image/jpeg");
    m.Set("gif", "image/gif");
    m.Set("svg", "image/svg+xml");
    m.Set("ico", "image/x-icon");
    m.Set("wasm", "application/wasm");
    m.Set("xml", "application/xml");
    m.Set("pdf", "application/pdf");
    m
}

fn loadConfig(src: string) -> Config {
    let toks = tokenize(src);
    let mut pos: int = 0;
    let dirs = parseBlock(&toks, &mut pos);
    let (servers, ups) = collectHttp(&dirs);
    Config {
        Servers: servers,
        Upstreams: ups,
        Mime: mimeTable(),
        rr: Mutex::new(make!(map[string]int)),
    }
}

// ─── request routing ────────────────────────────────────────────────

/// Pick the `server` block for this Host header — exact server_name
/// match wins; otherwise the first block on the listener is the
/// default server (nginx default_server semantics).
fn pickServer(cfg: &Config, idxs: &slice<int>, host: &string) -> int {
    let (h, _, _) = strings::Cut(host.clone(), ":");
    for (_, si) in range!(idxs) {
        for (_, name) in range!(&cfg.Servers[*si].ServerNames) {
            if *name == h {
                return *si;
            }
        }
    }
    idxs[0]
}

/// nginx prefix-location matching: the longest matching prefix wins,
/// regardless of registration order.
fn matchLocation(sc: &ServerConf, path: &string) -> (int, bool) {
    let mut best: int = -1;
    let mut bestLen: int = -1;
    for (i, loc) in range!(&sc.Locations) {
        if strings::HasPrefix(path.clone(), loc.Prefix.clone()) && loc.Prefix.Len() > bestLen {
            best = i;
            bestLen = loc.Prefix.Len();
        }
    }
    (best, best >= 0)
}

/// Per-request entry: route, serve, access-log. Returns nothing; the
/// (status, bytes) pair from the serving helpers feeds the log line.
fn serveOne(
    cfg: &Arc<Config>,
    idxs: &slice<int>,
    is_tls: bool,
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    r: &http::Request,
) {
    let start = time::Now();
    let si = pickServer(cfg, idxs, &r.Host);
    let sc = cfg.Servers[si].clone();
    let (li, ok) = matchLocation(&sc, &r.URL.Path);
    let (status, sent) = if !ok {
        errorPage(w, 404)
    } else {
        let loc = sc.Locations[li].clone();
        if loc.ProxyPass.Len() > 0 {
            proxyTo(cfg, &loc, is_tls, w, r)
        } else {
            serveStatic(cfg, &loc, w, r)
        }
    };
    // combined-ish access log
    let (ip, _, _) = strings::Cut(r.RemoteAddr.clone(), ":");
    goish::Printf!(
        "%s - - [%s] \"%s %s %s\" %d %d\n",
        ip,
        start.Format("02/Jan/2006:15:04:05"),
        r.Method.clone(),
        r.URL.Path.clone(),
        r.Proto.clone(),
        status,
        sent
    );
}

// ─── static files ───────────────────────────────────────────────────

fn serveStatic(
    cfg: &Config,
    loc: &Location,
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    r: &http::Request,
) -> (int, int) {
    let path = r.URL.Path.clone();
    // nginx rejects dot-dot traversal at URI level.
    if strings::Contains(path.clone(), "..") {
        return errorPage(w, 403);
    }
    // `root` semantics: file = root + full URI path.
    let fpath = Sprintf!("%s%s", loc.Root, path);
    let (fi, serr) = os::Stat(fpath.clone());
    if serr != nil {
        return errorPage(w, 404);
    }
    if fi.IsDir() {
        if !strings::HasSuffix(path.clone(), "/") {
            // nginx replies 301 with the slash-terminated URI.
            w.Header().Set("Location", Sprintf!("%s/", path));
            return errorPage(w, 301);
        }
        let ipath = Sprintf!("%s%s", fpath, loc.Index);
        let (ifi, ierr) = os::Stat(ipath.clone());
        if ierr == nil && !ifi.IsDir() {
            return sendFile(cfg, w, ipath);
        }
        if loc.Autoindex {
            return sendListing(w, fpath, path);
        }
        return errorPage(w, 403);
    }
    sendFile(cfg, w, fpath)
}

fn sendFile(
    cfg: &Config,
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    fpath: string,
) -> (int, int) {
    let (data, err) = os::ReadFile(fpath.clone());
    if err != nil {
        return errorPage(w, 500);
    }
    w.Header().Set("Content-Type", mimeOf(cfg, &fpath));
    w.Header().Set("Server", "goginx/0.1");
    w.WriteHeader(200);
    let n = len(&data);
    let _ = w.Write(data);
    (200, n)
}

fn mimeOf(cfg: &Config, path: &string) -> string {
    let segs = strings::Split(path.clone(), "/");
    let base = segs[len(&segs) - 1].clone();
    let parts = strings::Split(base, ".");
    if len(&parts) < 2 {
        return string("application/octet-stream");
    }
    let ext = strings::ToLower(parts[len(&parts) - 1].clone());
    let (mt, ok) = cfg.Mime.Get(ext);
    if ok {
        return mt;
    }
    string("application/octet-stream")
}

/// `autoindex on;` — a minimal nginx-style directory listing.
fn sendListing(
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    dir: string,
    urlpath: string,
) -> (int, int) {
    let (entries, err) = os::ReadDir(dir);
    if err != nil {
        return errorPage(w, 500);
    }
    let mut b = strings::Builder::new();
    let _ = b.WriteString(Sprintf!(
        "<html>\r\n<head><title>Index of %s</title></head>\r\n<body>\r\n<h1>Index of %s</h1><hr><pre><a href=\"../\">../</a>\n",
        urlpath.clone(),
        urlpath
    ));
    for (_, e) in range!(&entries) {
        let mut name = e.Name();
        if e.IsDir() {
            name = Sprintf!("%s/", name);
        }
        let _ = b.WriteString(Sprintf!("<a href=\"%s\">%s</a>\n", name.clone(), name));
    }
    let _ = b.WriteString("</pre><hr></body>\r\n</html>\r\n");
    let body = bytes(b.String());
    let n = len(&body);
    w.Header().Set("Content-Type", "text/html");
    w.Header().Set("Server", "goginx/0.1");
    w.WriteHeader(200);
    let _ = w.Write(body);
    (200, n)
}

/// nginx-style error / redirect page.
fn errorPage(w: &(dyn ResponseWriter + Send + Sync + 'static), code: int) -> (int, int) {
    let text = http::StatusText(code);
    let body = bytes(Sprintf!(
        "<html>\r\n<head><title>%d %s</title></head>\r\n<body>\r\n<center><h1>%d %s</h1></center>\r\n<hr><center>goginx/0.1</center>\r\n</body>\r\n</html>\r\n",
        code,
        text.clone(),
        code,
        text
    ));
    let n = len(&body);
    w.Header().Set("Content-Type", "text/html");
    w.Header().Set("Server", "goginx/0.1");
    w.WriteHeader(code);
    let _ = w.Write(body);
    (code, n)
}

// ─── reverse proxy ──────────────────────────────────────────────────

fn isHopHeader(name: &string) -> bool {
    strings::EqualFold(name.clone(), "Connection")
        || strings::EqualFold(name.clone(), "Proxy-Connection")
        || strings::EqualFold(name.clone(), "Keep-Alive")
        || strings::EqualFold(name.clone(), "Proxy-Authenticate")
        || strings::EqualFold(name.clone(), "Proxy-Authorization")
        || strings::EqualFold(name.clone(), "Te")
        || strings::EqualFold(name.clone(), "Trailer")
        || strings::EqualFold(name.clone(), "Transfer-Encoding")
        || strings::EqualFold(name.clone(), "Upgrade")
}

/// `proxy_pass` — forward the request to an upstream pool (round-
/// robin + retry-next-upstream on connect failure) or a literal
/// `http://host:port` target. 502 when every peer is down.
fn proxyTo(
    cfg: &Config,
    loc: &Location,
    is_tls: bool,
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    r: &http::Request,
) -> (int, int) {
    let mut target = strings::TrimPrefix(loc.ProxyPass.clone(), "http://");
    target = strings::TrimSuffix(target, "/");

    // Resolve an upstream pool by name, else treat as a literal addr.
    let mut pool = slice!([]string {});
    for (_, u) in range!(&cfg.Upstreams) {
        if u.Name == target {
            pool = u.Servers.clone();
            break;
        }
    }
    if len(&pool) == 0 {
        pool = append!(pool, target.clone());
    }
    let n = len(&pool);

    // Advance the shared round-robin cursor for this pool.
    let rr_start = {
        let mut g = cfg.rr.Lock();
        let (cur, _) = g.Get(target.clone());
        g.Set(target.clone(), cur + 1);
        cur
    };

    let mut attempt: int = 0;
    while attempt < n {
        let addr = pool[(rr_start + attempt) % n].clone();
        attempt += 1;

        let mut url = Sprintf!("http://%s%s", addr, r.URL.Path.clone());
        if r.URL.RawQuery.Len() > 0 {
            url = Sprintf!("%s?%s", url, r.URL.RawQuery.clone());
        }
        let (mut outreq, rqerr) = http::NewRequest(r.Method.clone(), url, r.Body.clone());
        if rqerr != nil {
            continue;
        }
        // Copy end-to-end headers; drop hop-by-hop ones (RFC 7230).
        for (k, vs) in range!(&r.Header) {
            if isHopHeader(k) || *k == "Host" || *k == "Content-Length" {
                continue;
            }
            for (_, v) in range!(vs) {
                outreq.Header.Add(k.clone(), v.clone());
            }
        }
        // nginx-style forwarding headers.
        let (client_ip, _, _) = strings::Cut(r.RemoteAddr.clone(), ":");
        let prior = r.Header.Get("X-Forwarded-For");
        if prior.Len() > 0 {
            outreq
                .Header
                .Set("X-Forwarded-For", Sprintf!("%s, %s", prior, client_ip));
        } else {
            outreq.Header.Set("X-Forwarded-For", client_ip);
        }
        let proto = if is_tls {
            string("https")
        } else {
            string("http")
        };
        outreq.Header.Set("X-Forwarded-Proto", proto);
        outreq.Header.Set("X-Forwarded-Host", r.Host.clone());

        let client = http::Client::default();
        let (mut resp, derr) = client.Do(&outreq);
        if derr != nil {
            // proxy_next_upstream: try the next peer.
            continue;
        }
        for (k, vs) in range!(&resp.Header) {
            if isHopHeader(k) {
                continue;
            }
            for (_, v) in range!(vs) {
                w.Header().Add(k.clone(), v.clone());
            }
        }
        w.Header().Set("Server", "goginx/0.1");
        w.WriteHeader(resp.StatusCode);
        let (body, _) = io::ReadAll(&mut resp.Body);
        let _ = io::Closer::Close(&mut resp.Body);
        let nb = len(&body);
        let _ = w.Write(body);
        return (resp.StatusCode, nb);
    }
    errorPage(w, 502)
}

// ─── listeners ──────────────────────────────────────────────────────

#[derive(Clone)]
struct ListenGroup {
    Key: string,
    Addr: string,
    TLS: bool,
    ReusePort: bool,
    CertFile: string,
    KeyFile: string,
    Idxs: slice<int>,
}

/// nginx merges `server` blocks that share a `listen` address onto
/// one listening socket (vhosts). Group by (addr, ssl).
fn groupListens(cfg: &Config) -> slice<ListenGroup> {
    let mut groups = slice!([]ListenGroup {});
    for (i, sc) in range!(&cfg.Servers) {
        let key = Sprintf!("%s|%t", sc.Listen.clone(), sc.TLS);
        let mut found = false;
        let mut gi: int = 0;
        for (j, g) in range!(&groups) {
            if g.Key == key {
                found = true;
                gi = j;
                break;
            }
        }
        if found {
            let mut idxs = groups[gi].Idxs.clone();
            idxs = append!(idxs, i);
            groups[gi].Idxs = idxs;
        } else {
            let mut idxs = slice!([]int {});
            idxs = append!(idxs, i);
            groups = append!(
                groups,
                ListenGroup {
                    Key: key,
                    Addr: sc.Listen.clone(),
                    TLS: sc.TLS,
                    ReusePort: sc.ReusePort,
                    CertFile: sc.CertFile.clone(),
                    KeyFile: sc.KeyFile.clone(),
                    Idxs: idxs,
                }
            );
        }
    }
    groups
}

/// nginx `listen ... reuseport` — bind with SO_REUSEPORT set before
/// bind, via the Go idiom: a `net.ListenConfig` whose `Control` hook
/// runs setsockopt(2) on the raw fd pre-bind (Go deliberately has no
/// first-class flag for this). Each such listener is its own kernel
/// accept queue; the kernel hash-shards incoming connections across
/// all listeners bound to the same address — exactly what nginx's
/// per-worker `reuseport` sockets do.
fn listenReusePort(addr: string) -> (net::Listener, error) {
    let lc = net::ListenConfig {
        Control: Some(Arc::new(
            |_network: string, _address: string, c: syscall::RawConn| -> error {
                c.Control(|fd| {
                    let _ = syscall::SetsockoptInt(
                        int(fd),
                        int(syscall::SOL_SOCKET),
                        int(syscall::SO_REUSEPORT),
                        1,
                    );
                })
            },
        )),
    };
    lc.Listen(context::Background(), "tcp", addr)
}

/// Bind every listen group and start its serve loop. Returns the
/// actual bound addresses (kernel-assigned ports resolved) in group
/// order, plus the servers for graceful shutdown. A `reuseport`
/// group binds one listener per CPU (nginx: one per worker), all
/// served on the same `http::Server` so one `Shutdown` drains every
/// accept loop.
fn startServers(cfg: &Arc<Config>) -> (slice<string>, slice<Arc<http::Server>>, error) {
    let groups = groupListens(cfg);
    let mut bounds = slice!([]string {});
    let mut servers = slice!([]Arc<http::Server> {});
    for (_, g) in range!(&groups) {
        let mut addr = g.Addr.clone();
        if !strings::Contains(addr.clone(), ":") {
            addr = Sprintf!(":%s", addr);
        }
        let (ln, err) = if g.ReusePort {
            listenReusePort(addr.clone())
        } else {
            net::Listen("tcp", addr.clone())
        };
        if err != nil {
            return (bounds, servers, err);
        }
        let port = ln.Addr().Port;
        let bound = Sprintf!("127.0.0.1:%d", port);
        bounds = append!(bounds, bound.clone());

        let mux = http::ServeMux::new();
        let cfgc = cfg.clone();
        let idxs = g.Idxs.clone();
        let is_tls = g.TLS;
        mux.HandleFunc("/", move |w, r| {
            serveOne(&cfgc, &idxs, is_tls, w, r);
        });

        let mut s = http::Server::default();
        s.Handler = Arc::new(mux);
        s.ReadHeaderTimeout = time::Second * 10;
        s.IdleTimeout = time::Second * 60;
        let srv = Arc::new(s);
        servers = append!(servers, srv.clone());

        let scheme = if is_tls {
            string("https")
        } else {
            string("http")
        };
        goish::Printf!("goginx: %s server on %s\n", scheme, bound);
        let run = srv.clone();
        if is_tls {
            let cert = g.CertFile.clone();
            let key = g.KeyFile.clone();
            go!(move || {
                let _ = run.ServeTLS(ln, cert, key);
            });
        } else {
            go!(move || {
                let _ = run.Serve(ln);
            });
        }

        // reuseport: the remaining per-CPU listeners bind the SAME
        // host:port (resolved, so `listen 127.0.0.1:0 reuseport`
        // works too) and serve on the same Server — its Shutdown
        // closes every one of them.
        if g.ReusePort && !is_tls {
            let (host, _, herr) = net::SplitHostPort(addr.clone());
            if herr != nil {
                return (bounds, servers, herr);
            }
            let real_addr = Sprintf!("%s:%d", host, port);
            let workers = goish::runtime::NumCPU();
            for _ in 1..workers {
                let (ln2, err2) = listenReusePort(real_addr.clone());
                if err2 != nil {
                    return (bounds, servers, err2);
                }
                let run2 = srv.clone();
                go!(move || {
                    let _ = run2.Serve(ln2);
                });
            }
            goish::Printf!("goginx: reuseport x%d on %s\n", workers, real_addr);
        }
    }
    (bounds, servers, nil.into())
}

/// `nginx -s quit` equivalent: park a goroutine on SIGTERM/SIGINT,
/// then drain every listener via Server::Shutdown.
fn installSignalDrain(servers: slice<Arc<http::Server>>, done: chan<bool>) {
    let (sig_ctx, _sig_stop) = signal::NotifyContext(
        context::Background(),
        &[syscall::SIGTERM, syscall::SIGINT],
    );
    go!(move || {
        let _ = sig_ctx.Done().Recv();
        goish::Printf!("goginx: signal received, draining\n");
        for (_, s) in range!(&servers) {
            let _ = s.clone().Shutdown(time::Second * 10);
        }
        done.Send(true);
    });
}

// ─── main ───────────────────────────────────────────────────────────

#[goish::main]
fn main() {
    let conf_path = os::Getenv("GOGINX_CONF");
    if conf_path.Len() > 0 {
        runStandalone(conf_path);
        return;
    }
    selfTest();
}

fn runStandalone(conf_path: string) {
    let (data, err) = os::ReadFile(conf_path.clone());
    if err != nil {
        goish::Printf!("goginx: %s: %v\n", conf_path, err);
        os::Exit(1);
    }
    let cfg = Arc::new(loadConfig(string(data)));
    let (_, servers, lerr) = startServers(&cfg);
    if lerr != nil {
        goish::Printf!("goginx: listen: %v\n", lerr);
        os::Exit(1);
    }
    let done = make!(chan bool);
    installSignalDrain(servers, done.clone());
    let _ = done.Recv();
    goish::Printf!("goginx: bye\n");
}

// ─── self-test ──────────────────────────────────────────────────────

static PASSED: atomic::Int64 = atomic::Int64::new(0);
static FAILED: atomic::Int64 = atomic::Int64::new(0);

fn pass(name: &'static str) {
    PASSED.Add(1);
    goish::Printf!("PASS: %s\n", name);
}

fn fail<S: Into<string>>(msg: S) {
    FAILED.Add(1);
    goish::Printf!("FAIL: %s\n", msg.into());
}

fn finish() {
    let p = PASSED.Load();
    let f = FAILED.Load();
    if f == 0 {
        goish::Printf!("GOGINX_OK %d/%d\n", p, p);
        os::Exit(0);
    }
    goish::Printf!("GOGINX_FAIL %d failures\n", f);
    os::Exit(1);
}

/// Fetch via the goish HTTP client: (status, body, content-type).
fn get(url: string) -> (int, string, string) {
    let (mut resp, err) = http::Get(url.clone());
    if err != nil {
        return (-1, Sprintf!("get %s: %v", url, err), string(""));
    }
    let (body, _) = io::ReadAll(&mut resp.Body);
    let _ = io::Closer::Close(&mut resp.Body);
    (
        resp.StatusCode,
        string(body),
        resp.Header.Get("Content-Type"),
    )
}

/// One raw HTTP/1.1 request (Connection: close) over plain TCP —
/// used where the test needs Host-header or redirect control.
fn rawRoundtrip(addr: string, req: string) -> (int, string) {
    let (mut conn, err) = net::Dial("tcp", addr);
    if err != nil {
        return (-1, string(""));
    }
    let _ = conn.Write(bytes(req));
    let _ = conn.SetReadDeadline(time::Now().Add(time::Second * 3));
    let mut out = slice!([]byte {});
    loop {
        let mut buf = make!([]byte, 4096);
        let (nr, rerr) = conn.Read(&mut buf);
        let mut i: int = 0;
        while i < nr {
            out = append!(out, buf[i]);
            i += 1;
        }
        if nr == 0 || rerr != nil {
            break;
        }
    }
    let _ = conn.Close();
    let resp = string(out);
    (parseStatus(&resp), resp)
}

/// Same, but over TLS with certificate verification disabled (the
/// self-signed test cert) — the curl -k of this self-test.
fn tlsRoundtrip(addr: string, req: string) -> (int, string) {
    let cfg = tls::Config {
        InsecureSkipVerify: true,
        ServerName: string("localhost"),
        ..Default::default()
    };
    let (mut conn, err) = tls::Dial("tcp", addr, &cfg);
    if err != nil {
        return (-1, Sprintf!("tls dial: %v", err));
    }
    let _ = conn.Write(bytes(req));
    let mut out = slice!([]byte {});
    loop {
        let mut buf = make!([]byte, 8192);
        let (nr, rerr) = conn.Read(&mut buf);
        let mut i: int = 0;
        while i < nr {
            out = append!(out, buf[i]);
            i += 1;
        }
        if nr == 0 || rerr != nil {
            break;
        }
    }
    let _ = conn.Close();
    let resp = string(out);
    (parseStatus(&resp), resp)
}

fn parseStatus(resp: &string) -> int {
    // "HTTP/1.1 200 OK\r\n..."
    let (_, rest, ok) = strings::Cut(resp.clone(), " ");
    if !ok {
        return -1;
    }
    let (code, _, _) = strings::Cut(rest, " ");
    let (n, err) = strconv::Atoi(code);
    if err != nil {
        return -1;
    }
    n
}

/// An upstream app server that echoes which backend it is plus the
/// forwarding headers goginx injected.
fn startBackend(name: &'static str) -> string {
    let mux = http::ServeMux::new();
    let label = string(name);
    mux.HandleFunc("/", move |w, r| {
        let _ = w.Write(bytes(Sprintf!(
            "%s xff=%s xfh=%s path=%s",
            label.clone(),
            r.Header.Get("X-Forwarded-For"),
            r.Header.Get("X-Forwarded-Host"),
            r.URL.Path.clone()
        )));
    });
    let (ln, err) = net::Listen("tcp", "127.0.0.1:0");
    if err != nil {
        fail(Sprintf!("backend listen: %v", err));
        return string("");
    }
    let addr = Sprintf!("127.0.0.1:%d", ln.Addr().Port);
    let mut s = http::Server::default();
    s.Handler = Arc::new(mux);
    let srv = Arc::new(s);
    go!(move || {
        let _ = srv.Serve(ln);
    });
    addr
}

/// An address that is guaranteed dead: bind, read the port, close.
fn deadAddr() -> string {
    let (ln, err) = net::Listen("tcp", "127.0.0.1:0");
    if err != nil {
        return string("127.0.0.1:9");
    }
    let addr = Sprintf!("127.0.0.1:%d", ln.Addr().Port);
    let _ = ln.Close();
    addr
}

// Self-signed RSA-2048 localhost certificate (100y), same pair the
// tls_server_smoke example embeds.
const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDRzCCAi+gAwIBAgIUExsnkkUFaklsYSdfl+loT602qZYwDQYJKoZIhvcNAQEL
BQAwJDEOMAwGA1UECgwFR29pc2gxEjAQBgNVBAMMCWxvY2FsaG9zdDAgFw0yNjA3
MTkxNDAzMDNaGA8yMTI2MDYyNTE0MDMwM1owJDEOMAwGA1UECgwFR29pc2gxEjAQ
BgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AL71SKjOEwMD+eKxArRXXzDYEQSZGvOZVsNEzvqO1U3ExcFQE7dT7tONmhkKOj4a
QzwHTSdqN3okuZowKXbBf+zmLtU/yJqVx9X3CJKeXexIHRYjCALBsejooa3RJhiR
3tVvEdNOGsZtiKO/BUWccUseaLqWBm4FF49w+bT4QWcB5abk+vRTMpBDJXY/e6lN
/BY74xBM2KidcHk2jt4QRzd6Ana7/+FI1tTKTPka6yiF99jHXeL55nlNwxmb829d
iT+xhvGDRnL/ko7mQieuVTTdnJIxVJLmRSs/UO47c0UOcGI8vkx88H5phfetmj6x
rVwLrG7cz3P+PR371u8lM7MCAwEAAaNvMG0wHQYDVR0OBBYEFLtTGr0kjsxYion9
b78o00eWI/sSMB8GA1UdIwQYMBaAFLtTGr0kjsxYion9b78o00eWI/sSMA8GA1Ud
EwEB/wQFMAMBAf8wGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMA0GCSqGSIb3
DQEBCwUAA4IBAQAu8dsWK1iCB/rbVQJ72vTn9aWFLW4TofxAgktLBJ0nHOHNJ1xS
yHyqCMz7iVhYKw9HsCcAJZxLsZCwHKlGVw2wvNOvOxB+PwVAVI9RNurAOl16djPW
HUODLOteW8fWsjYwBXBDbseVy3Jkq68qA24nOasFSJpj2Ay5L5Z95hEHshl0M4WS
wytOjSWvohLEA+ui2kl9izXjqSainxgR2Fy3JMydG5/hyj9vhN1KMX6z35/C0LuU
pGdh5BY9K5w6njHPtK+euG6V3Orkgj5CXvF77KOP869Fafvlxxi7wBerD29LECog
85yHo8ucdwukzqcy7NoMlnDHf20O8wBEZ56n
-----END CERTIFICATE-----
";

const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC+9UiozhMDA/ni
sQK0V18w2BEEmRrzmVbDRM76jtVNxMXBUBO3U+7TjZoZCjo+GkM8B00najd6JLma
MCl2wX/s5i7VP8ialcfV9wiSnl3sSB0WIwgCwbHo6KGt0SYYkd7VbxHTThrGbYij
vwVFnHFLHmi6lgZuBRePcPm0+EFnAeWm5Pr0UzKQQyV2P3upTfwWO+MQTNionXB5
No7eEEc3egJ2u//hSNbUykz5GusohffYx13i+eZ5TcMZm/NvXYk/sYbxg0Zy/5KO
5kInrlU03ZySMVSS5kUrP1DuO3NFDnBiPL5MfPB+aYX3rZo+sa1cC6xu3M9z/j0d
+9bvJTOzAgMBAAECggEAM6OL/w4fKQkZuZpJk3AvLzu2umoW1joossx4NlyKxSmJ
msGnW0OoyW+49L2Fy4Z5mRGWZSq9jtvAjzgn9lPUXsFOd990RY1siWlw2YlW9872
gqZ9g5VSoZvLIQB2j11fB5OuG9i6t98l/LXq3Iy2PGygQJjSa00YNnOEK1KZCRwM
IX7wxcJI1jfSqeF8lTaYGADssPgK+p7m8oQaaZ3zlTtvDh0MoaaLQ5T7IiPy2Xaq
quo9CO9fytnVOnRspqcF4NEqNpxBy7au+CoCuB2V+pL3GdaopZgFQYU8xo900/bA
ai74bVJYb65o3mVrRpjEkKc4o9+ajE/YgYegMqq8VQKBgQDf+GnvislCbhboIXg2
rPIMGdHW89xiUMgewmi0r+pt1i0y70Fxf2sfRls+9QvuGI+Tv/QHZD7NH/EfbEBo
rNTVjbN62xYEXBraRTehpqVVMCuBl5siUNeImHSpjRNL1IzI2WDbcLZIuLj0gJQ+
SZUJXfDku3GLiq3JaTnhaNDC3QKBgQDaREmus7DjKXNjxCHPi7U5aHgbS1L5RtN7
1FQrWawec/hINz4xzyWERm35uelfxd/PzA1bScqjckjmNNAEXtq2ZhdINA+bHSX8
kFyEO8gl9KI/43Ez/rhdjARdPJfqfYUqkpT/A7+UsoQto6Sc6KcKzi/LDtSDFmJJ
b1Gs65x/zwKBgBbWwx69PVa72TQkrZiNvEUFoQNVbMTNzgps8rZyNeqra4KFKVxE
jQzsZMOfw26tLH75lQ3n6AuM1U7KACtsbGu2fnXpv24EYmydoFWoo7VzKwyVBCnU
qpXwTf04OJ6D9zNID3txG/WAeMPeFL/hSwRggv8gKiz7oEsootFcmeU1AoGAaOD1
UtgPQChTxPWilXr5OrujMuJP3W4WAuN1CluNZBivjevVm9OAoH3DLIMTy6xmLhBL
vrjHgSBSPSPVbLQzff+yYkR51zv7W8/2VKfxNaPGLtLYO3bDGlhEZJTQHqHv0hQb
OiqP7SCWeOOwHqGAWqXWu0jF/rNLySOPaHrSeWsCgYAYN6DznwaMUQpyai/BObGf
L41DhsrRVfZpQaLFJUqztgy7+0uWWowmz/3FVTAd6iutAMqHO3KlQpdhpb9dLFJJ
EWyvWmpojOOUhO57GR6qmIZ5aElOpRnQpRv8yXIfO0huzOCe40gtwRxAuPGZQrzc
rTXGcd5XGWoS0+AF8t1cUw==
-----END PRIVATE KEY-----
";

fn selfTest() {
    goish::Printf!("goginx self-test\n");

    // ── build a doc tree + certs in a temp dir ──
    let (dir, terr) = os::MkdirTemp(os::TempDir(), "goginx-");
    if terr != nil {
        fail(Sprintf!("MkdirTemp: %v", terr));
        finish();
    }
    let www_a = Sprintf!("%s/site-a", dir);
    let www_b = Sprintf!("%s/site-b", dir);
    let _ = os::MkdirAll(Sprintf!("%s/sub", www_a), 0o755);
    let _ = os::MkdirAll(Sprintf!("%s/files", www_a), 0o755);
    let _ = os::MkdirAll(www_b.clone(), 0o755);
    let _ = os::WriteFile(Sprintf!("%s/index.html", www_a), bytes("<h1>site-a</h1>\n"), 0o644);
    let _ = os::WriteFile(
        Sprintf!("%s/hello.txt", www_a),
        bytes("hello from goginx\n"),
        0o644,
    );
    let _ = os::WriteFile(
        Sprintf!("%s/app.js", www_a),
        bytes("console.log(\"goginx\");\n"),
        0o644,
    );
    let _ = os::WriteFile(Sprintf!("%s/sub/index.html", www_a), bytes("sub index\n"), 0o644);
    let _ = os::WriteFile(Sprintf!("%s/files/a.txt", www_a), bytes("A\n"), 0o644);
    let _ = os::WriteFile(Sprintf!("%s/files/b.txt", www_a), bytes("B\n"), 0o644);
    let _ = os::WriteFile(Sprintf!("%s/index.html", www_b), bytes("<h1>site-b</h1>\n"), 0o644);
    // Outside every root — must never be reachable.
    let _ = os::WriteFile(Sprintf!("%s/secret.txt", dir), bytes("TOPSECRET\n"), 0o644);
    let cert_path = Sprintf!("%s/cert.pem", dir);
    let key_path = Sprintf!("%s/key.pem", dir);
    let _ = os::WriteFile(cert_path.clone(), bytes(CERT_PEM), 0o644);
    let _ = os::WriteFile(key_path.clone(), bytes(KEY_PEM), 0o600);

    // ── two upstream app backends + one dead peer ──
    let back_a = startBackend("backend-a");
    let back_b = startBackend("backend-b");
    let dead = deadAddr();

    // ── generate goginx.conf and load it from disk ──
    let mut cb = strings::Builder::new();
    let _ = cb.WriteString("# generated by the goginx self-test\n");
    let _ = cb.WriteString("events { worker_connections 1024; }\n");
    let _ = cb.WriteString("http {\n");
    let _ = cb.WriteString(Sprintf!(
        "  upstream backend {\n    server %s;\n    server %s;\n  }\n",
        back_a,
        back_b
    ));
    let _ = cb.WriteString(Sprintf!(
        "  upstream flaky {\n    server %s;\n    server %s;\n  }\n",
        dead,
        back_a
    ));
    let _ = cb.WriteString("  server {\n    listen 127.0.0.1:0;\n    server_name a.test;\n");
    let _ = cb.WriteString(Sprintf!(
        "    location / { root %s; index index.html; }\n    location /files/ { root %s; autoindex on; }\n",
        www_a.clone(),
        www_a.clone()
    ));
    let _ = cb.WriteString("    location /api/ { proxy_pass http://backend; }\n");
    let _ = cb.WriteString("    location /flaky/ { proxy_pass http://flaky; }\n");
    let _ = cb.WriteString(Sprintf!(
        "    location /down/ { proxy_pass http://%s; }\n  }\n",
        dead.clone()
    ));
    let _ = cb.WriteString("  server {\n    listen 127.0.0.1:0;\n    server_name b.test;\n");
    let _ = cb.WriteString(Sprintf!(
        "    location / { root %s; index index.html; }\n  }\n",
        www_b.clone()
    ));
    let _ = cb.WriteString("  server {\n    listen 127.0.0.1:0 ssl;\n    server_name tls.test;\n");
    let _ = cb.WriteString(Sprintf!(
        "    ssl_certificate %s;\n    ssl_certificate_key %s;\n",
        cert_path.clone(),
        key_path.clone()
    ));
    let _ = cb.WriteString(Sprintf!(
        "    location / { root %s; index index.html; }\n  }\n}\n",
        www_a.clone()
    ));
    let conf_path = Sprintf!("%s/goginx.conf", dir);
    let _ = os::WriteFile(conf_path.clone(), bytes(cb.String()), 0o644);

    let (cdata, cerr) = os::ReadFile(conf_path.clone());
    if cerr != nil {
        fail(Sprintf!("read conf: %v", cerr));
        finish();
    }
    let cfg = Arc::new(loadConfig(string(cdata)));

    // 1. parser sanity
    if len(&cfg.Servers) == 3 && len(&cfg.Upstreams) == 2 {
        pass("config parse: 3 server blocks, 2 upstreams");
    } else {
        fail(Sprintf!(
            "config parse: servers=%d upstreams=%d",
            len(&cfg.Servers),
            len(&cfg.Upstreams)
        ));
    }

    // ── boot ──
    let (bounds, servers, lerr) = startServers(&cfg);
    if lerr != nil || len(&bounds) != 2 {
        fail(Sprintf!("startServers: %v (groups=%d)", lerr, len(&bounds)));
        finish();
    }
    let plain = bounds[0].clone(); // a.test + b.test vhosts
    let tls_addr = bounds[1].clone(); // tls.test
    time::Sleep(time::Millisecond * 50);

    // 2. static index + MIME
    let (st, body, ct) = get(Sprintf!("http://%s/", plain));
    if st == 200 && strings::Contains(body.clone(), "site-a") && strings::Contains(ct.clone(), "text/html")
    {
        pass("GET / -> 200 index.html, text/html");
    } else {
        fail(Sprintf!("GET /: st=%d ct=%s body=%s", st, ct, body));
    }

    // 3. plain file + text/plain
    let (st, body, ct) = get(Sprintf!("http://%s/hello.txt", plain));
    if st == 200 && body == "hello from goginx\n" && strings::Contains(ct.clone(), "text/plain") {
        pass("GET /hello.txt -> exact bytes, text/plain");
    } else {
        fail(Sprintf!("hello.txt: st=%d ct=%s", st, ct));
    }

    // 4. MIME by extension
    let (st, _, ct) = get(Sprintf!("http://%s/app.js", plain));
    if st == 200 && strings::Contains(ct.clone(), "application/javascript") {
        pass("GET /app.js -> application/javascript");
    } else {
        fail(Sprintf!("app.js: st=%d ct=%s", st, ct));
    }

    // 5. nginx-style 404 page
    let (st, body, _) = get(Sprintf!("http://%s/missing", plain));
    if st == 404 && strings::Contains(body.clone(), "404 Not Found") && strings::Contains(body.clone(), "goginx")
    {
        pass("GET /missing -> nginx-style 404 page");
    } else {
        fail(Sprintf!("404 page: st=%d body=%s", st, body));
    }

    // 6. dot-dot traversal blocked
    let (st, body) = rawRoundtrip(
        plain.clone(),
        string("GET /../secret.txt HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n"),
    );
    if st != 200 && !strings::Contains(body.clone(), "TOPSECRET") {
        pass("dot-dot traversal blocked");
    } else {
        fail(Sprintf!("traversal: st=%d", st));
    }

    // 7. directory 301 redirect
    let (st, body) = rawRoundtrip(
        plain.clone(),
        string("GET /sub HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n"),
    );
    if st == 301 && strings::Contains(body.clone(), "Location: /sub/") {
        pass("GET /sub -> 301 Location: /sub/");
    } else {
        fail(Sprintf!("dir redirect: st=%d", st));
    }

    // 8. index resolution inside a subdirectory
    let (st, body, _) = get(Sprintf!("http://%s/sub/", plain));
    if st == 200 && strings::Contains(body.clone(), "sub index") {
        pass("GET /sub/ -> subdirectory index.html");
    } else {
        fail(Sprintf!("sub index: st=%d", st));
    }

    // 9. autoindex listing
    let (st, body, _) = get(Sprintf!("http://%s/files/", plain));
    if st == 200 && strings::Contains(body.clone(), "a.txt") && strings::Contains(body.clone(), "b.txt")
    {
        pass("autoindex on -> directory listing");
    } else {
        fail(Sprintf!("autoindex: st=%d body=%s", st, body));
    }

    // 10. upstream round-robin (4 requests -> 2 hits per backend)
    let mut seen_a: int = 0;
    let mut seen_b: int = 0;
    let mut k: int = 0;
    while k < 4 {
        let (st, body, _) = get(Sprintf!("http://%s/api/ping", plain));
        if st == 200 {
            if strings::Contains(body.clone(), "backend-a") {
                seen_a += 1;
            }
            if strings::Contains(body.clone(), "backend-b") {
                seen_b += 1;
            }
        }
        k += 1;
    }
    if seen_a == 2 && seen_b == 2 {
        pass("proxy_pass round-robin: 2+2 across the pool");
    } else {
        fail(Sprintf!("round-robin: a=%d b=%d", seen_a, seen_b));
    }

    // 11. forwarding headers reach the upstream
    let (st, body, _) = get(Sprintf!("http://%s/api/ping", plain));
    if st == 200
        && strings::Contains(body.clone(), "xff=127.0.0.1")
        && strings::Contains(body.clone(), "path=/api/ping")
    {
        pass("X-Forwarded-For + full path forwarded upstream");
    } else {
        fail(Sprintf!("fwd headers: st=%d body=%s", st, body));
    }

    // 12. retry-next-upstream: first peer dead, second alive
    let (st, body, _) = get(Sprintf!("http://%s/flaky/", plain));
    if st == 200 && strings::Contains(body.clone(), "backend-a") {
        pass("proxy_next_upstream: dead peer skipped");
    } else {
        fail(Sprintf!("flaky: st=%d body=%s", st, body));
    }

    // 13. whole pool down -> 502
    let (st, body, _) = get(Sprintf!("http://%s/down/", plain));
    if st == 502 && strings::Contains(body.clone(), "502 Bad Gateway") {
        pass("all upstreams down -> nginx-style 502");
    } else {
        fail(Sprintf!("502: st=%d body=%s", st, body));
    }

    // 14. virtual hosts on one listener
    let (st, body) = rawRoundtrip(
        plain.clone(),
        string("GET / HTTP/1.1\r\nHost: b.test\r\nConnection: close\r\n\r\n"),
    );
    if st == 200 && strings::Contains(body.clone(), "site-b") {
        pass("vhost: Host: b.test -> site-b root");
    } else {
        fail(Sprintf!("vhost: st=%d", st));
    }

    // 15. HEAD suppression with correct Content-Length
    let (st, body) = rawRoundtrip(
        plain.clone(),
        string("HEAD /hello.txt HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n"),
    );
    if st == 200
        && strings::Contains(body.clone(), "Content-Length: 18")
        && !strings::Contains(body.clone(), "hello from goginx")
    {
        pass("HEAD -> headers + Content-Length, no body");
    } else {
        fail(Sprintf!("HEAD: st=%d body=%s", st, body));
    }

    // 16. TLS termination (listen ... ssl) — M32 server-side TLS 1.3
    let (st, body) = tlsRoundtrip(
        tls_addr.clone(),
        string("GET / HTTP/1.1\r\nHost: tls.test\r\nConnection: close\r\n\r\n"),
    );
    if st == 200 && strings::Contains(body.clone(), "site-a") {
        pass("listen ssl -> TLS 1.3 handshake + response");
    } else {
        fail(Sprintf!("tls: st=%d body=%s", st, body));
    }

    // 17. SIGTERM graceful drain closes every listener
    let done = make!(chan bool);
    installSignalDrain(servers.clone(), done.clone());
    syscall::Kill(syscall::Getpid(), syscall::SIGTERM);
    select! {
        let _ = done.Recv() => {},
        let _ = (time::After(time::Second * 10)).Recv() => {
            fail("drain: timed out waiting for done");
        },
    }
    let (mut c, derr) = net::Dial("tcp", plain.clone());
    let plain_refused = derr != nil;
    if !plain_refused {
        let _ = c.Close();
    }
    let (mut c2, derr2) = net::Dial("tcp", tls_addr.clone());
    let tls_refused = derr2 != nil;
    if !tls_refused {
        let _ = c2.Close();
    }
    if plain_refused && tls_refused {
        pass("SIGTERM drain: both listeners closed");
    } else {
        fail(Sprintf!(
            "drain: plain_refused=%t tls_refused=%t",
            plain_refused,
            tls_refused
        ));
    }

    // 18. listen ... reuseport — one kernel-sharded listener per CPU
    // on the same port; every request lands on some listener, and a
    // single Shutdown closes ALL of them (if even one leaked, the
    // kernel would keep routing connects to it and the post-drain
    // dial would succeed).
    let mut rb = strings::Builder::new();
    let _ = rb.WriteString(
        "http {\n  server {\n    listen 127.0.0.1:0 reuseport;\n    server_name r.test;\n",
    );
    let _ = rb.WriteString(Sprintf!(
        "    location / { root %s; index index.html; }\n  }\n}\n",
        www_a.clone()
    ));
    let rcfg = Arc::new(loadConfig(rb.String()));
    let (rbounds, rservers, rerr) = startServers(&rcfg);
    if rerr != nil {
        fail(Sprintf!("reuseport boot: %v", rerr));
    } else {
        let raddr = rbounds[0].clone();
        let mut ok_count = int(0);
        let total = goish::runtime::NumCPU() * 2;
        for _ in 0..total {
            let (st, body) = rawRoundtrip(
                raddr.clone(),
                string("GET / HTTP/1.1\r\nHost: r.test\r\nConnection: close\r\n\r\n"),
            );
            if st == 200 && strings::Contains(body.clone(), "site-a") {
                ok_count += 1;
            }
        }
        for (_, s) in range!(&rservers) {
            let _ = s.clone().Shutdown(time::Second * 5);
        }
        let (mut rc, rderr) = net::Dial("tcp", raddr.clone());
        let refused = rderr != nil;
        if !refused {
            let _ = rc.Close();
        }
        if ok_count == total && refused {
            pass("reuseport: per-CPU listeners serve one port, Shutdown drains all");
        } else {
            fail(Sprintf!(
                "reuseport: ok=%d/%d refused=%t",
                ok_count,
                total,
                refused
            ));
        }
    }

    finish();
}
