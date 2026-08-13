// httptrace — Go's `net/http/httptrace` package.
//
//   Go                                       goish
//   ──────────────────────────────────────   ─────────────────────────────────
//   httptrace.WithClientTrace(ctx, tr)       httptrace::WithClientTrace(ctx, tr)
//   httptrace.ContextClientTrace(ctx)        httptrace::ContextClientTrace(&ctx)
//
// The code lives in trace.rs, mirroring Go's single trace.go, because
// anchored code may not sit in a module root (GOISH015).

#![allow(non_snake_case)]

mod trace;

pub use trace::{
    ClientTrace, ConnectDoneHook, ConnectStartHook, ContextClientTrace, DNSDoneHook, DNSDoneInfo,
    DNSStartHook, DNSStartInfo, Got100ContinueHook, Got1xxResponseHook, GotConnHook, GotConnInfo,
    GotFirstResponseByteHook, GetConnHook, PutIdleConnHook, TLSHandshakeDoneHook,
    TLSHandshakeStartHook, Wait100ContinueHook, WithClientTrace, WroteHeaderFieldHook,
    WroteHeadersHook, WroteRequestHook, WroteRequestInfo,
};

#[allow(unused_imports)]
pub(crate) use trace::CLIENT_EVENT_CONTEXT_KEY;
