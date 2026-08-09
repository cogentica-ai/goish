// encoding/json convergence: read JSON from stdin, parse to Value,
// re-emit with indentation.
//
//   $ printf '{"name":"alice","tags":["go","rs"],"count":3}' | json_pretty
//   {
//     "count": 3,
//     "name": "alice",
//     "tags": [
//       "go",
//       "rs"
//     ]
//   }

#![no_std]
#![no_main]

use goish::fmt;
use goish::encoding::json;
use goish::{append, byte, bytes, int, make, nil, os, slice, string};

fn read_all<R: goish::io::Reader>(mut r: R) -> slice<byte> {
    let mut out = make!([]byte, 0, 1024);
    let mut buf = make!([]byte, 4096);
    loop {
        let (n, err) = r.Read(&mut buf);
        if n > 0 {
            let mut i: int = 0;
            while i < n {
                out = append!(out, buf[i]);
                i += 1;
            }
        }
        if err != nil {
            break;
        }
        if n == 0 {
            break;
        }
    }
    out
}

#[goish::main]
fn main() {
    let raw = read_all(os::Stdin());
    let raw_bytes: &[byte] = &raw;
    let mut v = json::Value::Null; let err = json::Unmarshal(raw_bytes, &mut v);
    if err != nil {
        let mut e = os::Stderr();
        fmt::Fprintln!(e, "parse:", err);
        os::Exit(1);
    }
    let (out, _) = json::MarshalIndent(&v, "", "  ");
    let o = os::Stdout();
    let _ = o.Write(out);
    let _ = o.Write(bytes(string("\n")));
}
