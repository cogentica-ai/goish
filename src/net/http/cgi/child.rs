// net/http/cgi/child.go — CGI from the perspective of a child process.
//
// Ported: envMap and RequestFromMap, the pair that turns a CGI
// environment into an http.Request. net/http/fcgi's child.go calls
// RequestFromMap, so this is the piece that unblocks it.
//
// NOT ported: Request(), Serve() and the `response` writer. Request()
// wants os.Environ (present) but returns a Request whose Body is
// populated from stdin; Serve() and `response` need an
// http.ResponseWriter over stdout, which is the same conn/writer
// design the fcgi record layer is waiting on.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::gomap::map;
use crate::goslice::slice;
use crate::string;
use crate::strings;
use crate::types::{byte, int};

use super::super::header::Header;
use super::super::request::{Request, ParseHTTPVersion};
use super::super::url::URL;

// go: sdk 1.25.5 net/http/cgi/child.go:39-48 envMap
//
/// Split `KEY=VALUE` environment strings into a map. An entry with no
/// `=` is skipped, and a later duplicate key wins.
pub fn envMap(env: slice<string>) -> map<string, string> {
    let mut m: map<string, string> = map::new();
    let n = crate::len(&env);
    let mut i: int = 0;
    while i < n {
        let (k, v, ok) = strings::Cut(env[i].clone(), string("="));
        i += 1;
        if ok {
            m.Set(k, v);
        }
    }
    return m;
}

// go: sdk 1.25.5 net/http/cgi/child.go:50-141 RequestFromMap
//
/// Build an [`Request`] from CGI variables.
///
/// Go's note: "The returned Request's Body field is not populated."
///
/// The URL is assembled rather than taken whole, because CGI gives the
/// pieces: REQUEST_URI when the server supplies it, otherwise
/// SCRIPT_NAME + PATH_INFO + "?" + QUERY_STRING. The scheme comes from
/// the de-facto HTTPS variable, which servers set to "on", "ON" or
/// "1" — all three are accepted, matching Go.
pub fn RequestFromMap(params: &map<string, string>) -> (Request, error) {
    let get = |k: &'static str| -> string {
        let (v, _) = params.Get(string(k));
        return v;
    };

    let mut r = Request {
        Close: true, // Go: r.Close = true
        Trailer: Header::new(),
        TLS: None,
        RequestURI: string::new(),
        Method: get("REQUEST_METHOD"),
        URL: URL::empty(),
        Proto: string::new(),
        ProtoMajor: 0,
        ProtoMinor: 0,
        Header: Header::new(),
        Host: string::new(),
        ContentLength: 0,
        Body: slice::<byte>::__from_vec(Vec::new()),
        RemoteAddr: string::new(),
        path_values: map::<string, string>::new(),
        form_state: Arc::new(crate::sync::Mutex::new(Default::default())),
        ctx: None,
    };

    if r.Method == "" {
        return (r, errors::New(string("cgi: no REQUEST_METHOD in environment")));
    }

    r.Proto = get("SERVER_PROTOCOL");
    let (major, minor, ok) = ParseHTTPVersion(r.Proto.clone());
    if !ok {
        return (r, errors::New(string("cgi: invalid SERVER_PROTOCOL version")));
    }
    r.ProtoMajor = major;
    r.ProtoMinor = minor;

    r.Host = get("HTTP_HOST");

    let lenstr = get("CONTENT_LENGTH");
    if lenstr != "" {
        let (clen, err) = crate::strconv::ParseInt(lenstr.clone(), 10, 64);
        if err != crate::nil {
            return (
                r,
                errors::New(
                    string("cgi: bad CONTENT_LENGTH in environment: ") + lenstr,
                ),
            );
        }
        r.ContentLength = clen;
    }

    let ct = get("CONTENT_TYPE");
    if ct != "" {
        r.Header.Set(string("Content-Type"), ct);
    }

    // Go: copy "HTTP_FOO_BAR" variables to "Foo-Bar" headers.
    // HTTP_HOST is skipped because it is already r.Host.
    for (k, v) in params.__iter() {
        if k == "HTTP_HOST" {
            continue;
        }
        let (after, found) = strings::CutPrefix(k.clone(), string("HTTP_"));
        if found {
            r.Header
                .Add(strings::ReplaceAll(after, string("_"), string("-")), v.clone());
        }
    }

    let mut uriStr = get("REQUEST_URI");
    if uriStr == "" {
        // Go: fall back to SCRIPT_NAME, PATH_INFO and QUERY_STRING.
        uriStr = get("SCRIPT_NAME") + get("PATH_INFO");
        let s = get("QUERY_STRING");
        if s != "" {
            uriStr = uriStr + "?" + s;
        }
    }

    // Go: "There's apparently a de-facto standard for this."
    let https = get("HTTPS");
    if https == "on" || https == "ON" || https == "1" {
        r.TLS = Some(Arc::new(crate::crypto::tls::ConnectionState {
            HandshakeComplete: true,
            ..Default::default()
        }));
    }

    let mut haveURL = false;
    if r.Host != "" {
        // Go: hostname is provided, so we can reasonably construct a URL.
        let mut rawurl = r.Host.clone() + uriStr.clone();
        if r.TLS.is_none() {
            rawurl = string("http://") + rawurl;
        } else {
            rawurl = string("https://") + rawurl;
        }
        let (u, err) = super::super::url::Parse(rawurl.clone());
        if err != crate::nil {
            return (
                r,
                errors::New(
                    string("cgi: failed to parse host and REQUEST_URI into a URL: ") + rawurl,
                ),
            );
        }
        r.URL = u;
        haveURL = true;
    }
    // Go: fallback logic if we don't have a Host header or the URL
    // failed to parse.
    if !haveURL {
        let (u, err) = super::super::url::Parse(uriStr.clone());
        if err != crate::nil {
            return (
                r,
                errors::New(
                    string("cgi: failed to parse REQUEST_URI into a URL: ") + uriStr,
                ),
            );
        }
        r.URL = u;
    }

    // Go: "Request.RemoteAddr has its port set by Go's standard http
    // server, so we do here too." Atoi's error is deliberately dropped
    // — an unset or invalid REMOTE_PORT becomes zero.
    let (remotePort, _) = crate::strconv::Atoi(get("REMOTE_PORT"));
    r.RemoteAddr = crate::net::JoinHostPort(
        get("REMOTE_ADDR"),
        crate::strconv::Itoa(remotePort),
    );

    return (r, errors::nil);
}
