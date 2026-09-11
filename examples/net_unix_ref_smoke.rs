// net_unix_ref_smoke — AF_UNIX stream sockets, pinned to Go (issue #8).
//
// `net.Listen("unix", path)` / `net.Dial("unix", path)` is what an API
// pipe transport needs. Three of the rows below are the ones that
// separate a correct port from one that merely round-trips:
//
//   close_unlinks    — Go's (*UnixListener).close REMOVES the socket
//                      file before closing the fd
//                      (net/unixsock_posix.go:179); the kernel does
//                      not. Skip it and the next Listen on that path
//                      fails, with every other assertion still green.
//   listen_inuse     — and that next Listen is exactly what Go reports
//                      as `bind: address already in use`. Go does NOT
//                      silently unlink a live path, which is why a
//                      caller's own os.Remove before Listen is not
//                      redundant.
//   conn_local /
//   srv_addrs        — an unbound client's address is "@", not "" and
//                      not the socket path: Go's anyToSockaddr rewrites
//                      a leading NUL to '@' for display. A port that
//                      echoed the path back would pass a round-trip
//                      test and still report the wrong peer.
//
// GO[] is the verbatim output of tools/gen_net_unix_ref.go under
// scripts/goref.sh, with the temp path rewritten to <sock> and the
// deliberately-missing directory to <bad> so the transcript is stable.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::fmt;
use goish::gostring::string;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::os;
use goish::strings;
use goish::sync::Mutex;
use goish::types::int;
use goish::{go, slice};
use alloc::sync::Arc;

static FAILED: AtomicUsize = AtomicUsize::new(0);
static SRV: Mutex<Option<string>> = Mutex::new(None);

const GO: [&str; 14] = [
    "listen_err         <nil>",
    "listen_network     unix",
    "listen_addr        <sock>",
    "sockfile_is_sock   true",
    "listen_inuse       listen unix <sock>: bind: address already in use",
    "dial_err           <nil>",
    "dial_network       unix",
    "conn_local         \"@\"",
    "conn_remote        \"<sock>\"",
    "roundtrip          \"got:hello\"",
    "srv_addrs          \"<sock>\"|\"@\"",
    "close_unlinks      true",
    "dial_missing       dial unix <sock>: connect: no such file or directory",
    "listen_baddir      listen unix <bad>: bind: no such file or directory",
];

const BAD: &str = "/nonexistent-dir-goish/x.sock";

fn errstr(e: &goish::errors::error) -> string {
    if e.IsNil() {
        return string::from_static("<nil>");
    }
    return e.Error();
}

struct Chk {
    ln: usize,
    sock: string,
}

impl Chk {
    /// Print one row, with the run-specific paths normalised out, and
    /// compare it to the pinned Go line at the same index.
    fn row(&mut self, name: &str, value: &string) {
        let line = fmt::Sprintf!("%-18s %s", string::from_bytes(name.as_bytes()), value);
        let line = strings::ReplaceAll(line, self.sock.clone(), string::from_static("<sock>"));
        let line = strings::ReplaceAll(line, string::from_static(BAD), string::from_static("<bad>"));
        if self.ln >= GO.len() {
            fmt::Printf!("[!!] extra line %d: %q\n", self.ln as int + 1, line);
            FAILED.fetch_add(1, Ordering::Relaxed);
            self.ln += 1;
            return;
        }
        if line == GO[self.ln] {
            fmt::Printf!("[ok] %s\n", line);
        } else {
            fmt::Printf!(
                "[!!] line %d\n  got  %q\n  want %q\n",
                self.ln as int + 1,
                line,
                GO[self.ln]
            );
            FAILED.fetch_add(1, Ordering::Relaxed);
        }
        self.ln += 1;
    }
}

/// Accept one connection, record both of its addresses, echo the
/// request back with a "got:" prefix. Mirrors the goroutine in
/// tools/gen_net_unix_ref.go.
fn serve(ln: Arc<net::Listener>) {
    let (mut c, e) = ln.Accept();
    if !e.IsNil() {
        *SRV.Lock() = Some(fmt::Sprintf!("accept: %s", e.Error()));
        return;
    }
    *SRV.Lock() = Some(fmt::Sprintf!(
        "%q|%q",
        c.LocalAddr().String(),
        c.RemoteAddr().String()
    ));
    let mut buf = goish::make!([]goish::byte, 32);
    let (n, _) = c.Read(&mut buf);
    let mut out = alloc::vec::Vec::new();
    out.extend_from_slice(b"got:");
    for i in 0..n {
        out.push(buf[i as usize]);
    }
    let _ = c.Write(slice::<goish::byte>::__from_vec(out));
    let _ = c.Close();
}

#[goish::main]
fn main() {
    let (dir, err) = os::MkdirTemp(string::from_static(""), string::from_static("goishunix"));
    if !err.IsNil() {
        fmt::Printf!("[!!] MkdirTemp: %s\n", err.Error());
        os::Exit(1);
    }
    let sock = fmt::Sprintf!("%s/s.sock", dir);
    let mut k = Chk {
        ln: 0,
        sock: sock.clone(),
    };

    let (ln, err) = net::Listen(string::from_static("unix"), sock.clone());
    k.row("listen_err", &errstr(&err));
    if !err.IsNil() {
        let _ = os::RemoveAll(dir);
        os::Exit(1);
    }
    k.row("listen_network", &ln.Addr().Network());
    k.row("listen_addr", &ln.Addr().String());

    let (st, serr) = os::Stat(sock.clone());
    if !serr.IsNil() {
        fmt::Printf!("[!!] Stat(sock): %s\n", serr.Error());
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
    k.row(
        "sockfile_is_sock",
        &fmt::Sprintf!("%v", st.Mode() & os::ModeSocket != os::FileMode(0)),
    );

    // Binding a live path is refused; the stale-socket cleanup is the
    // caller's job in Go, so it must be the caller's job here too.
    let (ln2, err2) = net::Listen(string::from_static("unix"), sock.clone());
    k.row("listen_inuse", &errstr(&err2));
    if err2.IsNil() {
        let _ = ln2.Close();
    }

    let ln = Arc::new(ln);
    let wg = Arc::new(goish::sync::WaitGroup::default());
    {
        let ln = ln.clone();
        let wg2 = wg.clone();
        wg.Add(1);
        go!(move || {
            serve(ln);
            wg2.Done();
        });
    }

    let (mut c, derr) = net::Dial(string::from_static("unix"), sock.clone());
    k.row("dial_err", &errstr(&derr));
    if !derr.IsNil() {
        let _ = os::RemoveAll(dir);
        os::Exit(1);
    }
    k.row("dial_network", &c.RemoteAddr().Network());
    k.row("conn_local", &fmt::Sprintf!("%q", c.LocalAddr().String()));
    k.row("conn_remote", &fmt::Sprintf!("%q", c.RemoteAddr().String()));

    let _ = c.Write(slice::<goish::byte>::__from_vec(b"hello".to_vec()));
    let mut buf = goish::make!([]goish::byte, 32);
    let (n, _) = c.Read(&mut buf);
    let mut got = alloc::vec::Vec::new();
    for i in 0..n {
        got.push(buf[i as usize]);
    }
    k.row(
        "roundtrip",
        &fmt::Sprintf!("%q", string::from_bytes(&got)),
    );
    wg.Wait();
    let srv = SRV.Lock().clone().unwrap_or(string::from_static("<none>"));
    k.row("srv_addrs", &srv);
    let _ = c.Close();

    let cerr = ln.Close();
    if !cerr.IsNil() {
        fmt::Printf!("[!!] ln.Close: %s\n", cerr.Error());
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
    let (_, serr) = os::Stat(sock.clone());
    k.row("close_unlinks", &fmt::Sprintf!("%v", os::IsNotExist(serr)));

    let (_, derr) = net::Dial(string::from_static("unix"), sock.clone());
    k.row("dial_missing", &errstr(&derr));

    let (_, lerr) = net::Listen(string::from_static("unix"), string::from_static(BAD));
    k.row("listen_baddir", &errstr(&lerr));

    let _ = os::RemoveAll(dir);

    if k.ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", k.ln as int, GO.len() as int);
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
    let f = FAILED.load(Ordering::Relaxed);
    if f != 0 {
        fmt::Printf!("\nFAILED %d check(s)\n", f as i64);
        os::Exit(1);
    }
    fmt::Printf!("\nok %d/%d\n", k.ln as i64, GO.len() as i64);
}
