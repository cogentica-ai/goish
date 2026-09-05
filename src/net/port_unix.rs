// net/port_unix — Go 1.25.5 src/net/port_unix.go.
//
// One `.rs` per `.go` (§33). Go's header: "Read system port mappings
// from /etc/services".

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::errors::error;
use crate::types::int;

// go: none — goish-only: Go opens the file through net's own `open`
// and `readLine` (net/parse.go), which stream it. goish's net has a
// reader in dnsconfig.rs, but it is a single 8 KiB read sized for
// /etc/resolv.conf — /etc/services is commonly 19 KiB and would be
// silently truncated, losing every service past the cut. This one
// loops to EOF.
/// Read a whole file via raw syscalls (no std fs in no_std).
fn read_whole_file(path: &str) -> Option<Vec<u8>> {
    let mut path_bytes: Vec<u8> = alloc::vec::Vec::from(path.as_bytes());
    path_bytes.push(0);
    let raw = unsafe {
        crate::syscall::syscall3(crate::syscall::SYS_OPEN, path_bytes.as_ptr() as usize, 0, 0)
    };
    let fd = raw as i32; // goishlint:ignore GOISH005 - a kernel fd, not a Go value
    if fd < 0 {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 8192];
    loop {
        let n = unsafe {
            crate::syscall::syscall3(
                crate::syscall::SYS_READ,
                fd as usize,
                chunk.as_mut_ptr() as usize,
                chunk.len(),
            ) as isize
        };
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n as usize]);
    }
    let _ = unsafe { crate::syscall::syscall1(crate::syscall::SYS_CLOSE, fd as usize) };
    if out.is_empty() {
        return None;
    }
    return Some(out);
}

// go: sdk 1.25.5 net/port_unix.go:18-50 readServices
/// Go: parse "/etc/services" into the package's `services` map.
///
/// Format, from Go's own comment on the parse loop:
///
///     "http 80/tcp www www-http # World Wide Web HTTP"
///
/// Everything from `#` is dropped, field 1 is `port/network`, and
/// EVERY other field is an alias for that port — which is why
/// `www-http` resolves as well as `http` does.
///
/// A line whose port does not parse, is not positive, or is not
/// followed by `/`, is skipped rather than failing the file.
///
/// goish answers the question directly instead of filling a package
/// map, and does NOT cache behind a `sync.Once` as Go does. The cache
/// is an optimisation, not a behaviour: the file is read only when a
/// service NAME is looked up, and net/dnsclient.rs already re-reads
/// /etc/resolv.conf per lookup for the same reason.
// goishlint:ignore GOISH020 readServices — Go's takes no arguments
// because it fills a package map that lookupPortMap then reads. goish
// answers the one question asked instead of holding shared mutable
// state, so the query is the argument list.
fn readServices(network: &str, service: &str) -> Option<int> {
    let content = read_whole_file("/etc/services")?;
    let text = core::str::from_utf8(&content).ok()?;
    for line in text.lines() {
        let line = match line.find('#') {
            Some(i) => &line[..i],
            None => line,
        };
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 2 {
            continue;
        }
        let portnet = f[1]; // "80/tcp"
        let slash = match portnet.find('/') {
            Some(j) => j,
            None => continue,
        };
        let port: i64 = match portnet[..slash].parse::<i64>() {
            Ok(p) if p > 0 => p,
            _ => continue,
        };
        if &portnet[slash + 1..] != network {
            continue;
        }
        for (i, name) in f.iter().enumerate() {
            // Go: every field but f[1] is an alias for this port.
            if i != 1 && name.eq_ignore_ascii_case(service) {
                return Some(int::from(port));
            }
        }
    }
    return None;
}

// go: sdk 1.25.5 net/port_unix.go:53-57 goLookupPort
/// Go: "the native Go implementation of LookupPort." Read the system
/// table, then answer from it and the built-in map together.
pub(crate) fn goLookupPort(network: &str, service: &str) -> (int, error) {
    return super::lookup::lookupPortMap(network, service);
}

// go: none — goish-only: the shape `lookupPortMapWithNetwork` needs of
// the system table, which in Go is just a map read because
// readServices has already merged the file into it.
/// The system table's answer for one (network, service), or None.
pub(crate) fn systemPort(network: &str, service: &str) -> Option<int> {
    return readServices(network, service);
}
