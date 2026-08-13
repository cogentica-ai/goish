// Client.CheckRedirect against Go 1.25.5. Expected values from a
// goref run.
//
//   default            -> follows, 200, no error
//   ErrUseLastResponse -> returns the 302 ITSELF, no error, body open
//   a custom error     -> returns the 302 response AND the error
//   via                -> holds ONE entry on the first redirect
//
// The `via` length is the fiddly part: Go appends the request it just
// SENT before calling the hook, so a hook counting hops sees 1 on the
// first redirect. Off by one there and the default 10-redirect limit
// runs an extra hop.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, Ordering};
use goish::net::http;
use goish::{errors, fmt, net, string, syscall};

static VIA_LEN: AtomicI32 = AtomicI32::new(-1);

#[goish::main]
fn main() {
    goish::go!(stack(512 * 1024), move || {
        let mut bad = 0i32;

        let mux = http::ServeMux::new();
        mux.HandleFunc(string("/a"), |w, r| {
            http::Redirect(w, r, string("/b"), 302);
        });
        mux.HandleFunc(string("/b"), |w, _r| {
            w.WriteHeader(200);
        });
        let (ln, e) = net::Listen(string("tcp"), string("127.0.0.1:0"));
        if e != errors::nil {
            fmt::Println!("listen: ", e.Error());
            syscall::Exit(1);
        }
        let url = string("http://") + ln.Addr().String();
        goish::go!(stack(512 * 1024), move || {
            let _ = http::Serve(ln, Arc::new(mux) as Arc<dyn http::Handler>);
        });

        // 1. default follows to 200.
        {
            let c = http::Client::default();
            let (resp, err) = c.Get(url.clone() + string("/a"));
            if err != errors::nil || resp.StatusCode != 200 {
                fmt::Println!("FAIL default: status ", resp.StatusCode, " err ", err.Error());
                bad += 1;
            }
        }

        // 2. ErrUseLastResponse returns the 302 with no error.
        {
            let mut c = http::Client::default();
            c.CheckRedirect = Some(Arc::new(|_req: &http::Request, _via: &[http::Request]| {
                let e: goish::error = http::ErrUseLastResponse.into();
                e
            }));
            let (resp, err) = c.Get(url.clone() + string("/a"));
            if err != errors::nil {
                fmt::Println!("FAIL ErrUseLastResponse: unexpected err ", err.Error());
                bad += 1;
            }
            if resp.StatusCode != 302 {
                fmt::Println!("FAIL ErrUseLastResponse: status ", resp.StatusCode, " want 302");
                bad += 1;
            }
            if resp.Header.Get(string("Location")) != "/b" {
                fmt::Println!("FAIL ErrUseLastResponse: Location missing");
                bad += 1;
            }
        }

        // 3. A custom error aborts and is returned.
        {
            let mut c = http::Client::default();
            c.CheckRedirect = Some(Arc::new(|_req: &http::Request, _via: &[http::Request]| {
                errors::New(string("nope"))
            }));
            let (resp, err) = c.Get(url.clone() + string("/a"));
            if err == errors::nil {
                fmt::Println!("FAIL custom error: expected an error");
                bad += 1;
            } else if !goish::strings::Contains(err.Error(), string("nope")) {
                fmt::Println!("FAIL custom error: got ", err.Error());
                bad += 1;
            }
            if resp.StatusCode != 302 {
                fmt::Println!("FAIL custom error: status ", resp.StatusCode, " want 302");
                bad += 1;
            }
        }

        // 4. via holds ONE entry on the first redirect.
        {
            let mut c = http::Client::default();
            c.CheckRedirect = Some(Arc::new(|_req: &http::Request, via: &[http::Request]| {
                VIA_LEN.store(via.len() as i32, Ordering::SeqCst);
                errors::nil
            }));
            let (_, _) = c.Get(url.clone() + string("/a"));
            let n = VIA_LEN.load(Ordering::SeqCst);
            if n != 1 {
                fmt::Println!("FAIL via len: ", n, " want 1");
                bad += 1;
            }
        }

        if bad == 0 {
            fmt::Println!("CHECKREDIRECT_OK 4/4");
            syscall::Exit(0);
        } else {
            fmt::Println!("FAILED ", bad);
            syscall::Exit(1);
        }
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}
