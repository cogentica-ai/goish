// http_server_timeouts_smoke — net/http server.go's small Server
// accessors: maxHeaderBytes (:933), initialReadLimitSize (:940),
// tlsHandshakeTimeout (:944), idleTimeout (:3636), readHeaderTimeout
// (:3643), shuttingDown (:3654) and doKeepAlives (:3650).
//
// Every expected value is Go 1.25.5 output, produced by constructing
// the same twelve Servers inside a writable GOROOT (scripts/goref.sh
// net/http) — not reasoned out from the source.
//
// Two cases exist because they are easy to get wrong:
//
//   * MaxHeaderBytes is guarded with `> 0`, so a NEGATIVE value falls
//     back to DefaultMaxHeaderBytes.
//   * ReadHeaderTimeout and IdleTimeout are guarded with `!= 0`, so a
//     NEGATIVE value is returned AS IS rather than falling back to
//     ReadTimeout. Using `> 0` for both would look symmetric and be
//     wrong in opposite directions.
//
// tlsHandshakeTimeout is the minimum of the POSITIVE values among
// ReadHeaderTimeout, ReadTimeout and WriteTimeout, or zero when none
// is positive — not the minimum of all three.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http::server::{DefaultMaxHeaderBytes, Server};
use goish::time;
use goish::{fmt, syscall};

fn ms(n: i64) -> time::Duration {
    return time::Duration(n * 1_000_000);
}

fn srv(rh: time::Duration, rt: time::Duration, wt: time::Duration, it: time::Duration, mhb: i64) -> Server {
    let mut s = Server::default();
    s.ReadHeaderTimeout = rh;
    s.ReadTimeout = rt;
    s.WriteTimeout = wt;
    s.IdleTimeout = it;
    s.MaxHeaderBytes = mhb;
    return s;
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let z = time::Duration(0);
    let def = DefaultMaxHeaderBytes;

    // (rh, rt, wt, it, mhb) -> (maxHeaderBytes, initialReadLimitSize,
    //                           tlsHandshakeTimeout, idleTimeout,
    //                           readHeaderTimeout)
    let cases: &[(time::Duration, time::Duration, time::Duration, time::Duration, i64,
                  i64, i64, time::Duration, time::Duration, time::Duration)] = &[
        (z, z, z, z, 0,       def, def + 4096, z,      z,      z),
        (z, z, z, z, 4096,    4096, 8192,       z,      z,      z),
        (z, z, z, z, -1,      def, def + 4096, z,      z,      z),
        (ms(30), ms(20), ms(10), z, 0,  def, def + 4096, ms(10), ms(20), ms(30)),
        (ms(10), ms(20), ms(30), z, 0,  def, def + 4096, ms(10), ms(20), ms(10)),
        (z, ms(20), ms(30), z, 0,       def, def + 4096, ms(20), ms(20), ms(20)),
        (z, z, ms(30), z, 0,            def, def + 4096, ms(30), z,      z),
        (time::Duration(-1_000_000_000), ms(20), z, z, 0,
                                        def, def + 4096, ms(20), ms(20),
                                        time::Duration(-1_000_000_000)),
        (ms(5), ms(20), ms(5), z, 0,    def, def + 4096, ms(5),  ms(20), ms(5)),
        (z, ms(7), z, ms(9), 0,         def, def + 4096, ms(7),  ms(9),  ms(7)),
        (z, ms(7), z, z, 0,             def, def + 4096, ms(7),  ms(7),  ms(7)),
        (ms(3), ms(7), z, z, 0,         def, def + 4096, ms(3),  ms(7),  ms(3)),
    ];

    let mut bad = 0;
    let mut i = 0;
    while i < cases.len() {
        let c = &cases[i];
        let s = srv(c.0, c.1, c.2, c.3, c.4);
        if s.maxHeaderBytes() != c.5 {
            fmt::Println!("     case ", i as i64, " maxHeaderBytes got=", s.maxHeaderBytes());
            bad += 1;
        }
        if s.initialReadLimitSize() != c.6 {
            fmt::Println!("     case ", i as i64, " initialReadLimitSize got=", s.initialReadLimitSize());
            bad += 1;
        }
        if s.tlsHandshakeTimeout() != c.7 {
            fmt::Println!("     case ", i as i64, " tlsHandshakeTimeout got=", s.tlsHandshakeTimeout().0);
            bad += 1;
        }
        if s.idleTimeout() != c.8 {
            fmt::Println!("     case ", i as i64, " idleTimeout got=", s.idleTimeout().0);
            bad += 1;
        }
        if s.readHeaderTimeout() != c.9 {
            fmt::Println!("     case ", i as i64, " readHeaderTimeout got=", s.readHeaderTimeout().0);
            bad += 1;
        }
        i += 1;
    }
    if bad == 0 {
        fmt::Println!("[1] 12 Server configs x 5 accessors vs Go  PASS");
    } else {
        fmt::Println!("[1] Server accessors  FAIL ", bad, " mismatches");
        failed += 1;
    }

    // 2. DefaultMaxHeaderBytes is 1 MB.
    {
        if DefaultMaxHeaderBytes == 1048576 {
            fmt::Println!("[2] DefaultMaxHeaderBytes == 1 MB  PASS");
        } else {
            fmt::Println!("[2] DefaultMaxHeaderBytes  FAIL got=", DefaultMaxHeaderBytes);
            failed += 1;
        }
    }

    // 3. A fresh Server is not shutting down and keeps connections alive.
    {
        let s = Server::default();
        if !s.shuttingDown() && s.doKeepAlives() {
            fmt::Println!("[3] fresh Server: !shuttingDown && doKeepAlives  PASS");
        } else {
            fmt::Println!("[3] fresh Server  FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 3/3");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of 3");
        syscall::Exit(1);
    }
}
