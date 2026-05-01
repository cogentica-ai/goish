// net/http — Go's HTTP/1.x server, ported.
//
//   Go                                      goish
//   ─────────────────────────────────────   ──────────────────────────────────
//   http.ListenAndServe(":8080", h)         http::ListenAndServe(string(":8080"), &h)
//   http.HandleFunc("/", fn)                mux.HandleFunc(string("/"), fn)
//   http.ReadRequest(b)                     http::ReadRequest(&mut br)
//
// Phases:
//   M27c — request parser (this commit): URL, Header, Request,
//          ReadRequest. ports of net/url/url.go,
//          net/http/header.go, net/http/request.go.
//   M27d — server: ResponseWriter, Server, ServeMux, ListenAndServe.

#![allow(non_snake_case)]

pub mod chunked;
pub mod client;
pub mod cookie;
pub mod header;
pub mod request;
pub mod response;
pub mod server;
pub mod url;

pub use client::{
    Client, Get, Head, NewRequest, Post, PostForm, ReadResponse, Response, RoundTripper, Transport,
};
pub use cookie::{Cookie, ParseCookie, ParseSetCookie, SameSite, SetCookie};
pub use header::Header;
pub use request::{ReadRequest, Request};
pub use response::ResponseWriter;
pub use server::{
    ErrServerClosed, Handler, HandlerFunc, ListenAndServe, NotFoundHandler, Serve, ServeMux, Server,
};
pub use url::URL;
