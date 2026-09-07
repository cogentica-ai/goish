// http_upgrade_client_ref_smoke — a 101 you can write to.
//
// After a 101 Switching Protocols the response body IS the
// connection. Go's transport hands back a readWriteCloserBody and the
// caller asserts `res.Body.(io.ReadWriteCloser)` to speak whatever
// protocol was negotiated — WebSocket, a database wire protocol, a
// CONNECT tunnel.
//
// goish had the carrier and kept it crate-private: the reverse proxy
// used it, an external caller could only READ. That is half an
// upgrade, and the half that cannot send a WebSocket frame. `Upgraded`
// is the extraction goish spells where Go writes the comma-ok, and
// UpgradedConn carries Go's Read/Write/Close/CloseWrite.
//
// GO[] is the verbatim output of tools/gen_upgrade_client_ref.go
// under scripts/goref.sh against Go 1.25.5.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::io::{Reader as _, Writer as _};
use goish::net;
use goish::net::http;
use goish::types::byte;
use goish::{go, string, time};

static FAILED: AtomicUsize = AtomicUsize::new(0);
static SEEN: AtomicUsize = AtomicUsize::new(0);

static GO: [&str; 3] = [
    "status=101 upgrade=\"echo\"",
    "body is ReadWriteCloser=true",
    "read back=\"echo:ping\\n\"",
];

fn chk(got: goish::string) {
    let i = SEEN.fetch_add(1, Ordering::Relaxed);
    if i < GO.len() && got == string(GO[i]) {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d\n  got:  %s\n  want: %s\n",
            i as i64,
            got,
            string(if i < GO.len() { GO[i] } else { "" })
        );
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    let (ln, le) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !le.IsNil() {
        fmt::Printf!("listen: %v\n", le);
        goish::os::Exit(1);
    }
    let port = ln.Addr().Port;
    go!(stack(512 * 1024), move || {
        let (mut c, e) = ln.Accept();
        if !e.IsNil() {
            return;
        }
        let mut br = goish::bufio::NewReader(&mut c);
        let _ = http::ReadRequest(&mut br);
        // Read the client's post-upgrade line through the SAME reader,
        // so anything it buffered past the head is not lost.
        let _ = goish::io::Writer::Write(
            &mut c,
            goish::bytes(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n",
            ),
        );
        let mut br2 = goish::bufio::NewReader(&mut c);
        let (line, _) = br2.ReadString(b'\n');
        drop(br2);
        let _ = goish::io::Writer::Write(&mut c, goish::bytes(string("echo:") + line));
        time::Sleep(time::Duration(300 * 1_000_000));
        let _ = goish::io::Closer::Close(&mut c);
    });
    time::Sleep(time::Duration(150_000_000));

    let (mut req, _) = http::NewRequest(
        string("GET"),
        fmt::Sprintf!("http://127.0.0.1:%d/", port as i64),
        goish::nil,
    );
    req.Header.Set(string("Connection"), string("Upgrade"));
    req.Header.Set(string("Upgrade"), string("echo"));
    let tr = http::Transport::default();
    let (resp, rerr) = http::RoundTripper::RoundTrip(&tr, &req);
    if !rerr.IsNil() {
        fmt::Printf!("roundtrip err=%v\n", rerr);
        goish::os::Exit(1);
    }
    chk(fmt::Sprintf!(
        "status=%d upgrade=%q",
        resp.StatusCode as i64,
        resp.Header.Get(string("Upgrade"))
    ));

    let up = resp.Body.Upgraded();
    chk(fmt::Sprintf!("body is ReadWriteCloser=%v", up.is_some()));
    let mut rwc = match up {
        Some(c) => c,
        None => {
            fmt::Printf!("\nFAILED (no upgrade carrier)\n");
            goish::os::Exit(1);
        }
    };
    let _ = rwc.Write(goish::bytes("ping\n"));
    let mut buf = goish::make!([]byte, 32);
    let (n, _) = rwc.Read(&mut buf);
    chk(fmt::Sprintf!(
        "read back=%q",
        goish::string::from_bytes(&buf.slice(0, n))
    ));
    let _ = goish::io::Closer::Close(&mut rwc);

    let f = FAILED.load(Ordering::Relaxed);
    let seen = SEEN.load(Ordering::Relaxed);
    // Nothing failed AND every row RAN. Checking only FAILED lets a
    // smoke whose assertions were never wired report success — which
    // happened once, in os_file_readdir_ref_smoke.
    if f == 0 && seen == GO.len() {
        fmt::Printf!("\nok 3/3\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d of 3\n", f as i64);
    goish::os::Exit(1);
}
