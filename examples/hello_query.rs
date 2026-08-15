// hello_query — the classic Go hello-server, in goish.
//
//   go run . & curl 'localhost:8080/hello?name=world'
//   → Hello, world
//
// Go:
//   func main() {
//       http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
//           fmt.Fprintln(w, "Hello,", r.URL.Query().Get("name"))
//       })
//       log.Fatal(http.ListenAndServe(":8080", nil))
//   }

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::log;
use goish::net::http;
use goish::string;

#[goish::main]
fn main() {
    http::HandleFunc(string("/hello"), |mut w, r| {
        // Go's url.Values.Get returns the FIRST value, or "" when the
        // key is absent. goish's Values is a plain map<string,
        // slice<string>>, so its Get is the map's comma-ok — the
        // first-or-empty step is explicit here.
        let (vals, ok) = r.URL.Query().Get(string("name"));
        let name = if ok && vals.Len() > 0 {
            vals[0 as goish::int].clone()
        } else {
            string("")
        };
        // Go's `fmt.Fprintln(w, "Hello,", name)` works because a
        // ResponseWriter's method set contains Write([]byte) (int, error),
        // so it satisfies io.Writer structurally. goish's ResponseWriter
        // takes &self where io::Writer takes &mut self, so the two do not
        // unify — http::AsWriter is the explicit bridge.
        fmt::Fprintln!(w, string("Hello,"), name);
    });

    // Go passes nil for the handler to mean DefaultServeMux; goish takes
    // the handler by value, so name the mux that HandleFunc registered on.
    log::Fatal!(http::ListenAndServe(string(":8080"), http::DefaultServeMux()));
}
