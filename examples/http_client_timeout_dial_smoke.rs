// http_client_timeout_dial_smoke — Client.Timeout must bound a dial
// that never completes.
//
// Go's Client.Timeout is documented to cover "the time limit for
// requests made by this Client... including connection time". goish's
// did not reach the connect: `dialConn` called `net::Dial`, which takes
// no deadline, so a GET to an address that black-holes packets never
// returned. Measured against 192.0.2.1 with Client.Timeout at two
// seconds, the call was still blocked when the harness killed it at
// forty.
//
// The capability was already there and unused: `net::DialTimeout`
// bounds the same connect correctly and shares `dial_deadline` with
// `net::Dial`. Client.Timeout reaches the transport as a ctx deadline
// (context.WithDeadline, in setRequestCancel) and `effective_deadline`
// already combined it with Transport.Timeout — nothing read it at the
// dial.
//
// Go 1.25.5, same two cases:
//
//   timeout=500ms  within=true err=Get "http://192.0.2.1/x": context
//     deadline exceeded (Client.Timeout exceeded while awaiting headers)
//   timeout=2s     within=true  (same error)
//
// The suffix is the second half of the fix. Go wraps the error in
// net/http's `timeoutError` when the Client's own deadline is what
// ended the request; goish had neither that type nor the wrap, and bound
// `didTimeout` to `_did_timeout` and dropped it. Without it a caller
// cannot tell "my Client.Timeout fired" from "the context I was handed
// expired", and `err.(net.Error).Timeout()` answers false.
//
// WHY THIS DOES NOT PIN A FIXED LINE: 192.0.2.1 is TEST-NET-1
// (RFC 5737), which is never routed, but what a host DOES with it
// varies. Here the SYN goes unanswered and the connect hangs, which is
// the case under test. Somewhere with a null route it can fail
// immediately with "network unreachable" instead, and that is not a
// defect. So both outcomes are accepted and the smoke says which one it
// saw — but a dial that neither times out nor fails is a FAILURE, and
// the original defect (no bound at all) shows up as the harness killing
// this example.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::net::http;
use goish::string;
use goish::time;

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
    let _ = goish::os::Unsetenv(string("HTTP_PROXY"));
    let _ = goish::os::Unsetenv(string("http_proxy"));
    let _ = goish::os::Unsetenv(string("ALL_PROXY"));
    http::transport::resetProxyConfig();

    let mut bad = 0;
    for ms in [500i64, 2000i64].iter() {
        let budget = time::Duration(*ms * 1_000_000);
        let mut c = http::Client::default();
        c.Timeout = budget;
        let (r, _) = http::NewRequest(string("GET"), string("http://192.0.2.1/x"), goish::nil);
        let t0 = time::Now();
        let (_resp, err) = c.Do(&r);
        let took = time::Since(t0);

        if err.IsNil() {
            fmt::Printf!("[!!] timeout=%v: expected an error, got a response\n", budget);
            bad += 1;
            continue;
        }
        let msg = err.Error();
        let m: &str = msg.as_ref();
        if m.contains("Client.Timeout exceeded while awaiting headers") {
            // The case under test: the connect hung and the Client's
            // deadline ended it. Go's exact wording, and it must not
            // have fired early either.
            if took < budget {
                fmt::Printf!("[!!] timeout=%v: fired EARLY after %v\n", budget, took);
                bad += 1;
            } else if took > budget + time::Second * 5 {
                fmt::Printf!("[!!] timeout=%v: overran, took %v\n", budget, took);
                bad += 1;
            } else {
                fmt::Printf!("ok   timeout=%v bounded the dial, took %v\n", budget, took);
            }
        } else if took < time::Second {
            // A null route answered immediately. Not the case under
            // test and not a defect; say so rather than pretend.
            fmt::Printf!(
                "ok   timeout=%v: host rejected TEST-NET-1 immediately (%v), dial-hang case not exercised here: %v\n",
                budget, took, err
            );
        } else {
            fmt::Printf!("[!!] timeout=%v: took %v with an unexpected error: %v\n", budget, took, err);
            bad += 1;
        }
    }

    if bad == 0 {
        fmt::Printf!("\nok 2/2\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d\n", bad as i64);
    goish::os::Exit(1);
}
