// json_dup_diff — differential sweep for jsontext's duplicate-object-
// member-name check.
//
// goish's Decoder recorded `AllowDuplicateNames` and never enforced it,
// on a header claim that this "matches the options typescript-go's json
// shim sets globally". That claim was false — internal/json/json.go:12
// sets only AllowInvalidUTF8(true) — so a package.json with a repeated
// key was silently accepted where tsc rejects it.
//
// Reference: `GOEXPERIMENT=jsonv2 go run tools/gen_jsondup_ref.go >
// examples/jsondup_ref.txt`, byte-compared here. The sweep drives the
// DECODER rather than json.Unmarshal, so it stays on the layer that
// does the checking; each row is the sequence of token kinds read, or
// the error.
//
// What it pins beyond "a repeat is an error":
//   - names are compared DECODED, so `{"a":1,"a":2}` is a
//     duplicate and a raw-literal comparison would miss it;
//   - each object frame has its OWN namespace — `{"a":{"a":1}}` is
//     fine, and a shared set would wrongly reject it;
//   - a name reused after a sibling object CLOSED is still a duplicate
//     at its own level, which is the frame-pop being right;
//   - the `within "<json pointer>"` suffix Go appends when the object
//     is not the root, including array-index segments and RFC 6901
//     escaping of `/` (~1) and `~` (~0) inside a name;
//   - AllowDuplicateNames(true) turns all of it off.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::string::String as RustString;
use alloc::vec::Vec;

use goish::bytes;
use goish::encoding::json::jsontext;
use goish::io;
use goish::syscall;

const REF: &str = include_str!("jsondup_ref.txt");

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn push_usize(out: &mut RustString, v: usize) {
    let mut d = [0u8; 20];
    let mut i = 0;
    let mut n = v;
    loop {
        d[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
        if n == 0 {
            break;
        }
    }
    while i > 0 {
        i -= 1;
        out.push(d[i] as char);
    }
}

fn push_esc(out: &mut RustString, s: &[u8]) {
    if s.is_empty() {
        out.push('-');
        return;
    }
    for &c in s {
        if c >= 0x21 && c < 0x7f && c != b'\\' {
            out.push(c as char);
        } else {
            out.push_str("\\x");
            let hex = b"0123456789abcdef";
            out.push(hex[(c >> 4) as usize] as char);
            out.push(hex[(c & 0xf) as usize] as char);
        }
    }
}

fn corpus() -> Vec<&'static str> {
    alloc::vec![
        r#"{}"#,
        r#"{"a":1}"#,
        r#"{"a":1,"b":2}"#,
        r#"{"a":1,"a":2}"#,
        r#"{"a":1,"b":2,"a":3}"#,
        r#"{"a":1,"A":2}"#,
        // Escaped spellings — raw Rust strings, so the backslashes are
        // in the DOCUMENT, matching the generator's corpus byte for byte.
        r#"{"\u0061":1,"a":2}"#,
        r#"{"a":1,"\u0061":2}"#,
        r#"{"a\u0062":1,"ab":2}"#,
        r#"{"\u00e9":1,"\u00e9":2}"#,
        r#"{"a":{"a":1}}"#,
        r#"{"a":{"a":1},"b":{"a":2}}"#,
        r#"{"a":{"b":1,"b":2}}"#,
        r#"{"a":[{"x":1},{"x":2}]}"#,
        r#"{"a":{"z":1},"a":2}"#,
        r#"{"a":{"z":1},"b":{"z":2},"a":3}"#,
        r#"[{"a":1},{"a":2}]"#,
        r#"[1,1,1]"#,
        r#"{"a":{"b":{"c":{"d":1,"d":2}}}}"#,
        r#"{"":1}"#,
        r#"{"":1,"":2}"#,
        r#"{"":1,"a":2}"#,
        r#"[{"a":1,"a":2}]"#,
        r#"[0,{"a":1,"a":2}]"#,
        r#"{"a/b":{"x":1,"x":2}}"#,
        r#"{"a~b":{"x":1,"x":2}}"#,
        r#"{"a":[[{"q":1,"q":2}]]}"#,
        // See the note in tools/gen_jsondup_ref.go.
        r#"{"a":"a","b":"a"}"#,
        r#"{"x":"y","y":"z"}"#,
        r#"{"a":"b","b":"a"}"#,
    ]
}

#[goish::main]
fn main() {
    let mut got = RustString::new();

    for (i, doc) in corpus().iter().enumerate() {
        for allow in [false, true] {
            let tag = if allow { "allow" } else { "strict" };
            let mut dec = jsontext::NewDecoder(
                bytes::NewReader(goish::goslice::slice::from(doc.as_bytes())),
                [jsontext::AllowDuplicateNames(allow)],
            );
            let mut kinds = RustString::new();
            let mut failure: Option<RustString> = None;
            loop {
                let (tok, err) = dec.ReadToken();
                if err != goish::nil {
                    if err == io::EOF {
                        break;
                    }
                    let mut m = RustString::new();
                    match ::core::str::from_utf8(err.Error().as_bytes()) {
                        Ok(t) => m.push_str(t),
                        Err(_) => die(b"json_dup: non-UTF-8 error\n"),
                    }
                    failure = Some(m);
                    break;
                }
                match ::core::str::from_utf8(tok.Kind().String().as_bytes()) {
                    Ok(t) => kinds.push_str(t),
                    Err(_) => die(b"json_dup: non-UTF-8 kind\n"),
                }
            }
            got.push_str("D ");
            push_usize(&mut got, i);
            got.push(' ');
            got.push_str(tag);
            got.push(' ');
            push_esc(&mut got, doc.as_bytes());
            match failure {
                Some(f) => {
                    got.push_str(" err ");
                    push_esc(&mut got, f.as_bytes());
                }
                None => {
                    got.push_str(" ok ");
                    push_esc(&mut got, kinds.as_bytes());
                }
            }
            got.push('\n');
        }
    }

    if got != REF {
        let mut line = 1usize;
        let mut gi = got.lines();
        let mut ri = REF.lines();
        loop {
            match (gi.next(), ri.next()) {
                (None, None) => break,
                (Some(g), Some(r)) if g == r => line += 1,
                (g, r) => {
                    let mut m = RustString::from("JSON_DUP MISMATCH at line ");
                    push_usize(&mut m, line);
                    m.push_str("\n want: ");
                    m.push_str(r.unwrap_or("<eof>"));
                    m.push_str("\n got:  ");
                    m.push_str(g.unwrap_or("<eof>"));
                    m.push('\n');
                    die(m.as_bytes());
                }
            }
            if line > 10000 {
                die(b"json_dup: runaway diff\n");
            }
        }
    }

    let mut msg = RustString::from("JSON_DUP_OK ");
    push_usize(&mut msg, REF.lines().count());
    msg.push_str(" rows byte-exact vs real Go jsontext\n");
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}
