#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::net::http;
use goish::net::http::httptest;
use goish::net::http::httputil;
use goish::net::http::{Handler, ResponseWriter};
use goish::net::url;
use goish::sort;
use goish::strings;
use goish::types::int;
fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn hdrDump(h: &http::Header) -> string {
    let mut keys: Vec<string> = Vec::new();
    for (k, _) in h.__inner().__iter() {
        keys.push(k.clone());
    }
    let mut ks = slice::<string>::__from_vec(keys);
    sort::Strings(&mut ks);
    let mut parts: Vec<string> = Vec::new();
    for i in 0..ks.Len() {
        let k = ks[i].clone();
        let vs = h.Values(k.clone());
        let mut joined = string::new();
        for j in 0..vs.Len() {
            if j > 0 {
                joined = joined + "|";
            }
            joined = joined + vs[j].clone();
        }
        parts.push(fmt::Sprintf!("%s=%q", k, joined));
    }
    return strings::Join(slice::<string>::__from_vec(parts), s(" "));
}
#[goish::main]
fn main() {
    let echo = http::NewServeMux();
    echo.HandleFunc(
        s("/"),
        |w: &(dyn ResponseWriter + Send + Sync + 'static), r: &http::Request| {
            let out = fmt::Sprintf!(
                "method=%s uri=%q proto=%s host=%q hdr=[%s]",
                r.Method.clone(),
                r.RequestURI.clone(),
                r.Proto.clone(),
                r.Host.clone(),
                hdrDump(&r.Header)
            );
            let _ = w.Write(slice::__from_vec(out.as_bytes().to_vec()));
        },
    );
    let backend = httptest::NewServer(echo);
    let backurl = backend.URL();
    let (burl, _) = url::Parse(backurl.clone());
    let bhost = burl.Host.clone();
    let norm = |x: string| -> string {
        return strings::ReplaceAll(x, bhost.clone(), s("BACKEND"));
    };
    let mkreq = |target: &str, hdrs: &[(&str, &str)]| -> http::Request {
        let mut r = httptest::NewRequest(s("GET"), s(target), ());
        r.RemoteAddr = s("192.0.2.9:1234");
        for (k, v) in hdrs.iter() {
            r.Header.Add(s(k), s(v));
        }
        return r;
    };
    let run = |label: &str, target: &url::URL, r: &http::Request| {
        let p = httputil::NewSingleHostReverseProxy(target.clone());
        let w = httptest::NewRecorder();
        p.ServeHTTP(&w, r);
        let body = string::from_bytes(&w.Body().to_vec());
        fmt::Printf!("%-28s code=%d %s\n", s(label), w.Code(), norm(body));
    };
    run("hop/plain", &burl, &mkreq("http://front/x", &[]));
    run(
        "hop/connection-close",
        &burl,
        &mkreq(
            "http://front/x",
            &[("Connection", "close"), ("X-Keep", "yes")],
        ),
    );
    run(
        "hop/connection-names",
        &burl,
        &mkreq(
            "http://front/x",
            &[
                ("Connection", "X-Secret"),
                ("X-Secret", "sensitive"),
                ("X-Keep", "yes"),
            ],
        ),
    );
    run(
        "hop/connection-multi",
        &burl,
        &mkreq(
            "http://front/x",
            &[
                ("Connection", "X-A, X-B"),
                ("X-A", "1"),
                ("X-B", "2"),
                ("X-C", "3"),
            ],
        ),
    );
    run(
        "hop/connection-empty-item",
        &burl,
        &mkreq(
            "http://front/x",
            &[("Connection", "X-A,,X-B"), ("X-A", "1"), ("X-B", "2")],
        ),
    );
    run(
        "hop/connection-spaces",
        &burl,
        &mkreq("http://front/x", &[("Connection", "  X-A  "), ("X-A", "1")]),
    );
    run(
        "hop/all-hop-headers",
        &burl,
        &mkreq(
            "http://front/x",
            &[
                ("Keep-Alive", "timeout=5"),
                ("Proxy-Connection", "keep-alive"),
                ("Proxy-Authenticate", "Basic"),
                ("Proxy-Authorization", "Basic x"),
                ("Te", "trailers"),
                ("Trailer", "X-T"),
                ("Upgrade", "websocket"),
                ("X-Survives", "yes"),
            ],
        ),
    );
    run(
        "hop/te-not-trailers",
        &burl,
        &mkreq("http://front/x", &[("Te", "gzip"), ("X-Keep", "yes")]),
    );
    run(
        "hop/connection-names-xff",
        &burl,
        &mkreq(
            "http://front/x",
            &[
                ("Connection", "X-Forwarded-For"),
                ("X-Forwarded-For", "1.2.3.4"),
            ],
        ),
    );
    run("xff/absent", &burl, &mkreq("http://front/x", &[]));
    run(
        "xff/present",
        &burl,
        &mkreq("http://front/x", &[("X-Forwarded-For", "1.2.3.4")]),
    );
    run(
        "xff/chain",
        &burl,
        &mkreq("http://front/x", &[("X-Forwarded-For", "1.2.3.4, 5.6.7.8")]),
    );
    run(
        "xff/multi-header",
        &burl,
        &mkreq(
            "http://front/x",
            &[
                ("X-Forwarded-For", "1.2.3.4"),
                ("X-Forwarded-For", "5.6.7.8"),
            ],
        ),
    );
    run(
        "xff/spoofed-private",
        &burl,
        &mkreq("http://front/x", &[("X-Forwarded-For", "127.0.0.1")]),
    );
    run(
        "xff/client-sets-proto",
        &burl,
        &mkreq(
            "http://front/x",
            &[
                ("X-Forwarded-Proto", "https"),
                ("X-Forwarded-Host", "evil.example"),
            ],
        ),
    );
    run(
        "xff/connection-names-xff",
        &burl,
        &mkreq(
            "http://front/x",
            &[
                ("Connection", "X-Forwarded-For"),
                ("X-Forwarded-For", "1.2.3.4"),
            ],
        ),
    );
    let paths: [(&str, &str, &str); 13] = [
        ("root->root", "", "http://front/x"),
        ("prefix", "/api", "http://front/x"),
        ("prefix-slash", "/api/", "http://front/x"),
        ("prefix+slash-req", "/api/", "http://front//x"),
        ("req-root", "/api", "http://front/"),
        ("req-empty", "/api", "http://front"),
        ("escaped-req", "/api", "http://front/a%2Fb"),
        ("dots-req", "/api", "http://front/a/../b"),
        ("query-req", "/api", "http://front/x?a=1"),
        ("query-both", "/api?t=9", "http://front/x?a=1"),
        ("query-target-only", "/api?t=9", "http://front/x"),
        ("semicolon-query", "/api", "http://front/x?a=1;b=2"),
        ("unicode", "/api", "http://front/%E2%98%83"),
    ];
    for (name, target, req) in paths.iter() {
        let u = if *target == "" {
            burl.clone()
        } else {
            let (tu, _) = url::Parse(backurl.clone() + s(target));
            tu
        };
        let label = string::from("path/") + s(name);
        let p = httputil::NewSingleHostReverseProxy(u);
        let w = httptest::NewRecorder();
        let r = mkreq(req, &[]);
        p.ServeHTTP(&w, &r);
        let body = string::from_bytes(&w.Body().to_vec());
        fmt::Printf!("%-28s code=%d %s\n", label, w.Code(), norm(body));
    }
    {
        let (dead, _) = url::Parse(s("http://127.0.0.1:1"));
        let p = httputil::NewSingleHostReverseProxy(dead);
        let w = httptest::NewRecorder();
        let r = mkreq("http://front/x", &[]);
        p.ServeHTTP(&w, &r);
        fmt::Printf!(
            "%-28s code=%d body=%q\n",
            s("error/unreachable"),
            w.Code(),
            string::from_bytes(&w.Body().to_vec())
        );
    }
    {
        let mux2 = http::NewServeMux();
        mux2.HandleFunc(
            s("/"),
            |w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &http::Request| {
                w.Header().Set(s("Connection"), s("X-Backend-Secret"));
                w.Header().Set(s("X-Backend-Secret"), s("leaked"));
                w.Header().Set(s("Keep-Alive"), s("timeout=5"));
                w.Header().Set(s("X-Ok"), s("fine"));
                w.Header().Set(s("Trailer"), s("X-T"));
                w.WriteHeader(203);
                let _ = w.Write(slice::__from_vec(b"body".to_vec()));
            },
        );
        let b2 = httptest::NewServer(mux2);
        let (u2, _) = url::Parse(b2.URL());
        let p = httputil::NewSingleHostReverseProxy(u2);
        let w = httptest::NewRecorder();
        let r = mkreq("http://front/x", &[]);
        p.ServeHTTP(&w, &r);
        let hm = w.HeaderMap();
        let mut keys: Vec<string> = Vec::new();
        for (k, _) in hm.__inner().__iter() {
            if k == "Date" || k == "Content-Length" {
                continue;
            }
            keys.push(k.clone());
        }
        let mut ks = slice::<string>::__from_vec(keys);
        sort::Strings(&mut ks);
        let mut parts: Vec<string> = Vec::new();
        for i in 0..ks.Len() {
            let k = ks[i].clone();
            let vs = hm.Values(k.clone());
            let mut joined = string::new();
            for j in 0..vs.Len() {
                if j > 0 {
                    joined = joined + "|";
                }
                joined = joined + vs[j].clone();
            }
            parts.push(fmt::Sprintf!("%s=%q", k, joined));
        }
        fmt::Printf!(
            "%-28s code=%d hdr=[%s] body=%q\n",
            s("resp/hop-stripped"),
            w.Code(),
            strings::Join(slice::<string>::__from_vec(parts), s(" ")),
            string::from_bytes(&w.Body().to_vec())
        );
        Arc::clone(&b2).Close();
    }
    Arc::clone(&backend).Close();
    let _: int = 0;
}
