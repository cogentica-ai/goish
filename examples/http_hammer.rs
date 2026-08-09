// http_hammer — concurrency stress test for the goish net/http stack.
//
// Spawns a minimal HTTP server (one /healthz route), then fires N
// concurrent client goroutines that each do http.Get(/healthz) and
// assert 200. Reports total time, success/fail counts, and process
// VmRSS / VmSize before and after the storm.
//
// Tunables:
//   N            — number of concurrent requests (default 5_000)
//   CLIENT_STACK — per-client-goroutine stack size (default 64 KiB)
//
// Build release for tightest frames; the auto-grow default keeps the
// server-side per-connection goroutines on a 2 KiB carve until they
// pivot.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;

use goish::encoding::json;
use goish::net;
use goish::net::http;
use goish::os;
use goish::runtime::sched::schedule;
use goish::sync::atomic::Uint64;
use goish::sync::WaitGroup;
use goish::time;
use goish::{
    bytes, float64, go, int, make, nil, string, syscall, uint64, Eprintln, Println, Sprintf, KB,
};

const N: i64 = 5_000;
const CLIENT_STACK: usize = 64 * KB;

static SERVER_PORT: Uint64 = Uint64::new(0);
static OK_COUNT: Uint64 = Uint64::new(0);
static FAIL_COUNT: Uint64 = Uint64::new(0);
static SERVE_DONE: Uint64 = Uint64::new(0);

static WG: WaitGroup = WaitGroup::new();

// ─── server ──────────────────────────────────────────────────────────

fn healthz(w: &(dyn http::ResponseWriter + Send + Sync + 'static), _r: &http::Request) {
    let mut obj = make!(map[string]json::Value);
    obj.Set("ok", json::Value::Bool(true));
    let (body, err) = json::Marshal(&json::Value::Object(obj));
    if err != nil {
        http::Error(w, err.Error(), http::StatusInternalServerError);
        return;
    }
    w.Header().Set("Content-Type", "application/json");
    w.Write(body);
}

// ─── /proc/self/status sampler ───────────────────────────────────────

fn print_proc_status(label: &[u8]) {
    static PATH: &[u8] = b"/proc/self/status\0";
    let fd = syscall::Open(PATH.as_ptr(), syscall::O_RDONLY | syscall::O_CLOEXEC, 0);
    if fd < 0 {
        return;
    }
    let mut buf = [0u8; 4096];
    let n = syscall::Read(fd, buf.as_mut_ptr(), buf.len());
    syscall::Close(fd);
    if n <= 0 {
        return;
    }
    syscall::Write(syscall::STDOUT, label.as_ptr(), label.len());
    syscall::Write(syscall::STDOUT, b":\n".as_ptr(), 2);
    let data = &buf[..(n as usize)];
    for prefix in [
        b"VmPeak:" as &[u8],
        b"VmSize:",
        b"VmHWM:",
        b"VmRSS:",
        b"Threads:",
    ] {
        if let Some(line) = find_line(data, prefix) {
            syscall::Write(syscall::STDOUT, b"  ".as_ptr(), 2);
            syscall::Write(syscall::STDOUT, line.as_ptr(), line.len());
            syscall::Write(syscall::STDOUT, b"\n".as_ptr(), 1);
        }
    }
    syscall::Write(syscall::STDOUT, b"\n".as_ptr(), 1);
}

fn find_line<'a>(data: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let mut i = 0;
    while i + prefix.len() <= data.len() {
        let line_start = i;
        if &data[i..i + prefix.len()] == prefix {
            let mut j = i;
            while j < data.len() && data[j] != b'\n' {
                j += 1;
            }
            return Some(&data[line_start..j]);
        }
        while i < data.len() && data[i] != b'\n' {
            i += 1;
        }
        i += 1;
    }
    None
}

fn url_at(path: &str) -> string {
    let port = int(SERVER_PORT.Load());
    Sprintf!("http://127.0.0.1:%d%s", port, path)
}

// ─── main ────────────────────────────────────────────────────────────

#[goish::main]
fn main() {
    let pid = syscall::Getpid();
    Println!("http_hammer PID:", int(pid));
    Println!("target: N=", int(N), " concurrent clients @ ", int(CLIENT_STACK), " B stack each");

    // Bind first, then report port.
    let (ln, err) = net::Listen("tcp", "127.0.0.1:0");
    if err != nil {
        Eprintln!("listen failed:", err.Error());
        os::Exit(1);
    }
    let port = ln.Addr().Port;
    SERVER_PORT.Store(uint64(port));
    Println!("server listening on", int(port));

    let mux = http::ServeMux::new();
    mux.HandleFunc("/healthz", healthz);

    let srv = Arc::new(http::Server {
        Handler: http::handler(mux),
        ReadHeaderTimeout: time::Second * 5,
        ReadTimeout: time::Second * 10,
        WriteTimeout: time::Second * 10,
        ..Default::default()
    });

    // Spawn the accept loop.
    let srv_run = srv.clone();
    go!(move || {
        srv_run.Serve(ln);
        SERVE_DONE.Store(1);
    });

    // Driver — runs the storm. Must be a goroutine because `WG.Wait`,
    // `time::Sleep`, etc. need a real G context (the `#[goish::main]`
    // body is the bootstrap thread, not a goroutine).
    let srv_for_shutdown = srv.clone();
    go!(move || {
        // Wait briefly for the server to be ready.
        time::Sleep(time::Millisecond * 100);

        print_proc_status(b"BEFORE");

        // Storm.
        let started = time::Now();
        WG.Add(N);
        for _ in 0..N {
            go!(move || {
                let (mut resp, err) = http::Get(url_at("/healthz"));
                if err != nil {
                    FAIL_COUNT.Add(1);
                } else if resp.StatusCode != 200 {
                    FAIL_COUNT.Add(1);
                } else {
                    let (body, _) = goish::io::ReadAll(&mut resp.Body);
                    let _ = goish::io::Closer::Close(&mut resp.Body);
                    if !goish::bytes::Contains(&body, bytes("\"ok\":true")) {
                        FAIL_COUNT.Add(1);
                    } else {
                        OK_COUNT.Add(1);
                    }
                }
                WG.Done();
            });
        }
        WG.Wait();
        let elapsed = time::Since(started);

        print_proc_status(b"AFTER");

        let ok = OK_COUNT.Load();
        let fl = FAIL_COUNT.Load();
        let secs = elapsed.Seconds();
        let rps = if secs > 0.0 { float64(ok) / secs } else { 0.0_f64 };
        Println!("storm complete: ok=", int(ok), "/", int(N), "  fail=", int(fl));
        Println!("elapsed:", Sprintf!("%.3f", secs), "s  rps:", Sprintf!("%.0f", rps));

        // Graceful shutdown.
        let err = srv_for_shutdown.Shutdown(time::Second * 5);
        if err != nil {
            Eprintln!("Shutdown error:", err.Error());
        }
        let mut tries = 0;
        while SERVE_DONE.Load() == 0 && tries < 60 {
            time::Sleep(time::Millisecond * 50);
            tries += 1;
        }

        if int(ok) != N || int(fl) != 0 {
            Eprintln!("HAMMER_FAIL", int(ok), "/", int(N));
            os::Exit(1);
        }
        Println!("HAMMER_OK", int(N));
        os::Exit(0);
    });

    schedule();
}
