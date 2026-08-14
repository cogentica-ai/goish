// net/http/transport_default_other — the non-wasm default dialer hook.
//
// One `.rs` per `.go` (§33): this file mirrors Go 1.25.5
// net/http/transport_default_other.go, whose whole content is the one
// function below. (Its wasm sibling, transport_default_wasm.go,
// returns nil — not applicable on this target.)

#![allow(non_snake_case)]

// go: sdk 1.25.5 net/http/transport_default_other.go:14-16 defaultTransportDialContext
//
/// Go returns the bound method value `dialer.DialContext`; goish's
/// `Dialer::DialContext()` already IS that closure-shaped handle
/// (`DialContextFn`), so the port is the same one-liner.
pub fn defaultTransportDialContext(
    dialer: crate::net::Dialer,
) -> super::client::DialContextFn {
    return dialer.DialContext();
}
