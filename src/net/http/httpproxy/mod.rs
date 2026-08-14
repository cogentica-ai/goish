// go: package vendor/golang.org/x/net/http/httpproxy
// vendor/golang.org/x/net/http/httpproxy — module index only (one
// `.rs` per `.go`; the package's single proxy.go lives in proxy.rs).

pub mod proxy;
#[allow(unused_imports)]
pub use proxy::{Config, FromEnvironment};
