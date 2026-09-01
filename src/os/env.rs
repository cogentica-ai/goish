// go: file os/env.go decls: Expand, isShellSpecialVar, isAlphaNum, getShellName, ExpandEnv, Getenv, LookupEnv, Setenv, Unsetenv, Clearenv, Environ
//
// env.go — the process environment, and the `${var}` expander.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::errors::{self, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::runtime;

use super::{bytes_of, error};

// go: sdk 1.25.5 os/env.go:106-116 LookupEnv
/// Return `(value, true)` if `key`
/// is set in the process environment, `("", false)` otherwise.
pub fn LookupEnv<K: Into<string>>(key: K) -> (string, bool) {
    let key: string = key.into();
    let bytes_key = bytes_of(&key);
    let val_bytes = unsafe { runtime::args::envp_lookup(bytes_key) };
    return match val_bytes {
        Some(b) => (string::from_bytes(b), true),
        None => (string::new(), false),
    };
}

// go: sdk 1.25.5 os/env.go:98-104 Getenv
/// Return the value of `key` in the
/// process environment, or "" if not present.
pub fn Getenv<K: Into<string>>(key: K) -> string {
    let key: string = key.into();
    let (v, _) = LookupEnv(key);
    return v;
}

// go: sdk 1.25.5 os/env.go:118-125 Setenv
/// Set the
/// value of the environment variable named `key`. Goish slim: writes
/// to a process-wide overlay rather than the kernel envp, so child
/// processes won't inherit the change (no exec support yet).
pub fn Setenv<K: Into<string>, V: Into<string>>(key: K, value: V) -> error {
    let key: string = key.into();
    let value: string = value.into();
    // Go: err := syscall.Setenv(key, value); ... return NewSyscallError("setenv", err)
    let kb = bytes_of(&key);
    if kb.is_empty() {
        return errors::New("setenv: key is empty");
    }
    for &c in kb {
        if c == b'=' || c == 0 {
            return errors::New("setenv: invalid argument");
        }
    }
    let vb = bytes_of(&value);
    for &c in vb {
        if c == 0 {
            return errors::New("setenv: invalid argument");
        }
    }
    runtime::args::envp_set(kb, vb);
    return nil;
}

// go: sdk 1.25.5 os/env.go:127-130 Unsetenv
/// Unset the
/// environment variable named `key`. Goish slim: writes a tombstone
/// to the overlay rather than mutating kernel envp.
pub fn Unsetenv<K: Into<string>>(key: K) -> error {
    let key: string = key.into();
    // Go: return syscall.Unsetenv(key)
    let kb = bytes_of(&key);
    if kb.is_empty() {
        return errors::New("unsetenv: key is empty");
    }
    for &c in kb {
        if c == b'=' || c == 0 {
            return errors::New("unsetenv: invalid argument");
        }
    }
    runtime::args::envp_unset(kb);
    return nil;
}

// go: sdk 1.25.5 os/env.go:136-141 Environ
/// Return a copy of
/// the entire visible environment as a slice of `KEY=VALUE` strings.
/// Goish merges kernel envp with the Setenv/Unsetenv overlay; tombstoned
/// keys are omitted, and Setenv'd keys appear after the kernel entries.
pub fn Environ() -> slice<string> {
    // Go: copyenv(); a := make([]string, 0, len(envs)); for _, env := range envs { ... }; return a
    let bufs = unsafe { runtime::args::envp_environ() };
    let mut out: Vec<string> = Vec::with_capacity(bufs.len());
    for b in bufs.iter() {
        out.push(string::from_bytes(b));
    }
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 os/env.go:47-51 ExpandEnv
/// Replace `${var}` or `$var` in `s`
/// using `os.Getenv`. Equivalent to `os.Expand(s, os.Getenv)`.
pub fn ExpandEnv<S: Into<string>>(s: S) -> string {
    return Expand(s, Getenv);
}

// go: sdk 1.25.5 os/env.go:10-45 Expand
/// `os.Expand(s, mapping)` — replace `${var}` or `$var` in `s` based on
/// the mapping function.
///
/// goish's version was hand-written and got the shell rules wrong in
/// three places, all of which this port fixes:
///
///   * `$$` was treated as an ESCAPE producing a literal `$`. Go has no
///     such escape: `$` is a shell special variable, so `$$` expands
///     `mapping("$")` — usually the empty string.
///   * The other shell specials — `*`, `#`, `@`, `!`, `?`, `-` — were
///     not recognised at all, so `$*` came out as a literal `$*` where
///     Go expands `mapping("*")`.
///   * An unterminated `${` swallowed the whole rest of the string as a
///     variable name. Go eats the `${` as bad syntax and carries on.
pub fn Expand<S: Into<string>, F: Fn(string) -> string>(s: S, mapping: F) -> string {
    let s: string = s.into();
    let sb = s.as_bytes();
    let mut buf: Option<Vec<u8>> = None;
    // ${} is all ASCII, so bytes are fine for this operation.
    let mut i = 0usize;
    let mut j = 0usize;
    while j < sb.len() {
        if sb[j] == b'$' && j + 1 < sb.len() {
            if buf.is_none() {
                buf = Some(Vec::with_capacity(2 * sb.len()));
            }
            let b = buf.as_mut().unwrap();
            b.extend_from_slice(&sb[i..j]);
            let (name, w) = getShellName(&sb[j + 1..]);
            if name.is_empty() && w > 0 {
                // Encountered invalid syntax; eat the characters.
            } else if name.is_empty() {
                // Valid syntax, but $ was not followed by a name. Leave
                // the dollar character untouched.
                b.push(sb[j]);
            } else {
                let v = mapping(string::from_bytes(name));
                b.extend_from_slice(v.as_bytes());
            }
            j += w;
            i = j + 1;
        }
        j += 1;
    }
    return match buf {
        None => s,
        Some(b) => string::__from_vec(b) + string::from_bytes(&sb[i..]),
    };
}

// go: sdk 1.25.5 os/env.go:54-62 isShellSpecialVar
/// Whether the character identifies a special shell variable such as
/// `$*`.
fn isShellSpecialVar(c: u8) -> bool {
    return matches!(
        c,
        b'*' | b'#'
            | b'$'
            | b'@'
            | b'!'
            | b'?'
            | b'-'
            | b'0'
            | b'1'
            | b'2'
            | b'3'
            | b'4'
            | b'5'
            | b'6'
            | b'7'
            | b'8'
            | b'9'
    );
}

// go: sdk 1.25.5 os/env.go:64-67 isAlphaNum
/// Whether the byte is an ASCII letter, number, or underscore.
fn isAlphaNum(c: u8) -> bool {
    return c == b'_'
        || (b'0' <= c && c <= b'9')
        || (b'a' <= c && c <= b'z')
        || (b'A' <= c && c <= b'Z');
}

// go: sdk 1.25.5 os/env.go:69-97 getShellName
/// The name that begins the string and the number of bytes consumed to
/// extract it. If the name is enclosed in `{}` it is part of a `${}`
/// expansion and two more bytes are needed than the length of the name.
fn getShellName(s: &[u8]) -> (&[u8], usize) {
    if s[0] == b'{' {
        if s.len() > 2 && isShellSpecialVar(s[1]) && s[2] == b'}' {
            return (&s[1..2], 3);
        }
        // Scan to the closing brace.
        let mut i = 1usize;
        while i < s.len() {
            if s[i] == b'}' {
                if i == 1 {
                    return (b"", 2); // Bad syntax; eat "${}"
                }
                return (&s[1..i], i + 1);
            }
            i += 1;
        }
        return (b"", 1); // Bad syntax; eat "${"
    }
    if isShellSpecialVar(s[0]) {
        return (&s[0..1], 1);
    }
    // Scan alphanumerics.
    let mut i = 0usize;
    while i < s.len() && isAlphaNum(s[i]) {
        i += 1;
    }
    return (&s[..i], i);
}

// go: sdk 1.25.5 os/env.go:132-134 Clearenv
/// Delete every
/// environment variable visible to this process. Goish slim: installs
/// a tombstone for every kernel-envp key and drops overlay sets, since
/// kernel envp is read-only.
pub fn Clearenv() {
    // Go: syscall.Clearenv()
    unsafe { runtime::args::envp_clear() };
}
