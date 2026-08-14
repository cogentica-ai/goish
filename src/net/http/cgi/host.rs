// net/http/cgi/host — the CGI host side (running a child process as
// a Handler).
//
// PARTIAL port of Go 1.25.5 net/http/cgi/host.go. What lands here are
// the two pure helpers that shape the child's environment; `Handler`
// and its ServeHTTP need os/exec process spawning with piped stdio,
// which goish does not have yet.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::goslice::slice;
use crate::string;
use crate::types::rune;

// go: sdk 1.25.5 net/http/cgi/host.go:393-407 upperCaseAndUnderscore
/// Map one rune of an HTTP header name into its CGI environment form:
/// lowercase to uppercase, `-` to `_`, and `=` to `_`.
///
/// The `=` case is the one worth keeping the comment for. Go: "Maybe
/// not part of the CGI 'spec' but would mess up the environment in any
/// case, as Go represents the environment as a slice of 'key=value'
/// strings." A header named `X=Y` would otherwise inject a second
/// `=` into the env entry and split it in the wrong place.
pub fn upperCaseAndUnderscore(r: rune) -> rune {
    if r >= crate::rune('a') && r <= crate::rune('z') {
        return r - (crate::rune('a') - crate::rune('A'));
    }
    if r == crate::rune('-') {
        return crate::rune('_');
    }
    if r == crate::rune('=') {
        return crate::rune('_');
    }
    // Go: "TODO: other transformations in spec or practice?"
    return r;
}

// go: sdk 1.25.5 net/http/cgi/host.go:98-115 removeLeadingDuplicates
/// Drop every `key=value` entry that a LATER entry with the same key
/// overrides, keeping the last occurrence.
///
/// Order matters and the direction is easy to invert: Go scans forward
/// and drops entry `i` if any entry AFTER it shares its `key=` prefix,
/// so the SURVIVOR is the last one. An environment is applied
/// last-wins, so keeping the first instead would silently hand the
/// child the value it was meant to override.
///
/// An entry with no `=` at all is never treated as a duplicate — Go
/// only compares when `IndexByte(e, '=')` finds one.
pub fn removeLeadingDuplicates(env: slice<string>) -> slice<string> {
    let mut ret: Vec<string> = Vec::new();
    for i in 0..env.Len() {
        let e = env[i].clone();
        let mut found = false;
        let eq = crate::strings::IndexByte(e.clone(), b'=');
        if eq != -1 {
            // Go: `keq := e[:eq+1]` — the key INCLUDING its '=', so
            // "PATH=" cannot match "PATH_EXTRA=".
            let eb = e.as_bytes();
            let keq = string::from_bytes(
                &eb[..crate::builtin::__make_size(eq) + 1],
            );
            for j in (i + 1)..env.Len() {
                if crate::strings::HasPrefix(env[j].clone(), keq.clone()) {
                    found = true;
                    break;
                }
            }
        }
        if !found {
            ret.push(e);
        }
    }
    return slice::<string>::__from_vec(ret);
}
