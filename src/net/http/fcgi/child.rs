// net/http/fcgi/child.go — FastCGI from the perspective of a child
// process (the application side of the protocol).
//
// Ported here: the parameter-decoding half — `request`, `newRequest`,
// `parseParams` — plus the two pure environment predicates
// `addFastCGIEnvToContext` and `filterOutUsedEnvVars`.
//
// NOT ported, with the reason MEASURED rather than assumed:
//
//   * `child`, `newChild`, `serve`, `handleRecord`, `serveRequest`,
//     `cleanUp`, `Serve`, and `response` with its methods — the
//     connection serve loop. **No known blocker**: `io::Pipe` exists
//     (io/pipe.rs:341), `cgi::RequestFromMap` is ported, and
//     `response` is the same ResponseWriter shape as cgi/child.rs's.
//     It is just the next unit of work, ~200 lines. An earlier draft
//     of this comment claimed io.Pipe was missing; it was not, and
//     one grep would have said so.
//   * `ProcessEnv` / `envVarsContextKey` — need a context Value keyed
//     by a private type.

#![allow(non_snake_case)]

extern crate alloc;

use crate::gomap::map;
use crate::goslice::slice;
use crate::string;
use crate::strings;
use crate::types::{byte, uint16, uint8};

use super::fcgi::{flagKeepConn, readSize, readString};

// go: sdk 1.25.5 net/http/fcgi/child.go:24-32 request
//
/// One in-flight FastCGI request, accumulated across records.
///
/// Go's `buf [1024]byte` with `rawParams = r.buf[:0]` is an inline
/// arena so short param blocks need no allocation; goish grows a
/// slice instead, which is the same observable behaviour. `pw
/// *io.PipeWriter` is omitted with the serve loop above.
pub struct request {
    pub reqId: uint16,
    pub params: map<string, string>,
    pub rawParams: slice<byte>,
    pub keepConn: bool,
}

// go: sdk 1.25.5 net/http/fcgi/child.go:37-45 newRequest
pub fn newRequest(reqId: uint16, flags: uint8) -> request {
    return request {
        reqId,
        params: map::new(),
        rawParams: slice::<byte>::new(),
        keepConn: flags & flagKeepConn != 0,
    };
}

impl request {
    // go: sdk 1.25.5 net/http/fcgi/child.go:48-71 request.parseParams
    //
    /// Reads an encoded `[]byte` into `params`.
    ///
    /// Every early `return` is a malformed-input bail-out that keeps
    /// whatever was parsed so far — Go does not report the error, and
    /// neither does this.
    pub fn parseParams(&mut self) {
        let mut text = self.rawParams.clone();
        self.rawParams = slice::<byte>::new();
        while crate::len(&text) > 0 {
            let (keyLen, n) = readSize(text.clone());
            if n == 0 {
                return;
            }
            text = slice::<byte>::__from_vec((&(&*text)[n as usize..]).to_vec());

            let (valLen, n) = readSize(text.clone());
            if n == 0 {
                return;
            }
            text = slice::<byte>::__from_vec((&(&*text)[n as usize..]).to_vec());

            if crate::int(keyLen) + crate::int(valLen) > crate::len(&text) {
                return;
            }
            let key = readString(text.clone(), keyLen);
            text = slice::<byte>::__from_vec((&(&*text)[keyLen as usize..]).to_vec());
            let val = readString(text.clone(), valLen);
            text = slice::<byte>::__from_vec((&(&*text)[valLen as usize..]).to_vec());
            self.params.Set(key, val);
        }
    }
}

// go: sdk 1.25.5 net/http/fcgi/child.go:373-395 addFastCGIEnvToContext
//
/// Reports whether to include the FastCGI environment variable `s` in
/// the `http.Request.Context`, accessible via `ProcessEnv`.
pub fn addFastCGIEnvToContext(s: string) -> bool {
    // Exclude things supported by net/http natively:
    if s == "CONTENT_LENGTH"
        || s == "CONTENT_TYPE"
        || s == "HTTPS"
        || s == "PATH_INFO"
        || s == "QUERY_STRING"
        || s == "REMOTE_ADDR"
        || s == "REMOTE_HOST"
        || s == "REMOTE_PORT"
        || s == "REQUEST_METHOD"
        || s == "REQUEST_URI"
        || s == "SCRIPT_NAME"
        || s == "SERVER_PROTOCOL"
    {
        return false;
    }
    if strings::HasPrefix(s.clone(), string("HTTP_")) {
        return false;
    }
    // Explicitly include FastCGI-specific things. This list is
    // redundant with the default `return true` below. Consider this
    // documentation of the sorts of things we expect to maybe see.
    if s == "REMOTE_USER" {
        return true;
    }
    // Unknown, so include it to be safe.
    return true;
}

// go: sdk 1.25.5 net/http/fcgi/child.go:280-288 filterOutUsedEnvVars
//
/// Drops the environment variables net/http already surfaces on the
/// Request, leaving only what `ProcessEnv` should expose.
pub fn filterOutUsedEnvVars(envVars: &map<string, string>) -> map<string, string> {
    let mut withoutUsedEnvVars: map<string, string> = map::new();
    let keys = envVars.Keys();
    for i in 0..keys.len() {
        let k = keys[i].clone();
        if addFastCGIEnvToContext(k.clone()) {
            let (v, _) = envVars.Get(k.clone());
            withoutUsedEnvVars.Set(k, v);
        }
    }
    return withoutUsedEnvVars;
}
