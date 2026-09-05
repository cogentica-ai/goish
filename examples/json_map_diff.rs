// json_map_diff — differential sweep for json/v2 map decoding, and in
// particular the PARTIAL STATE a failed decode leaves behind.
//
// goish returned from a bad value without storing anything, so
// `{"a":1}` into a map<string,string> yielded an EMPTY map. Go decodes
// into the existing value (zero for a new key) and stores it even on
// error. This primitive failure therefore yields {"a": ""} plus an
// error, and the walk stops at the first failure. Composite partial
// state and pre-populated maps are covered by json_map_state_diff.
//
// That is observable, not internal: typescript-go's
// packagejson.Expected[T] DISCARDS the decode error and keeps whatever
// landed in the value, so a caller reading a partially decoded
// dependency map sees Go's keys or goish's absence of them.
//
// Reference: `GOEXPERIMENT=jsonv2 go run tools/gen_jsonmap_ref.go >
// examples/jsonmap_ref.txt`, byte-compared here. Failures are placed at
// the first, middle and last member so "stops at the first" is pinned
// rather than assumed, and every non-string value shape is swept
// (number, array, object, null, bool) against both a string-valued and
// an int-valued map.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::string::String as RustString;
use alloc::vec::Vec;

use goish::encoding::json::v2 as json2;
use goish::gomap::map;
use goish::gostring::string;
use goish::syscall;
use goish::types::int;

const REF: &str = include_str!("jsonmap_ref.txt");

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn push_usize(out: &mut RustString, v: usize) {
    let mut d = [0u8; 24];
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

fn push_i64(out: &mut RustString, v: i64) {
    if v < 0 {
        out.push('-');
        push_usize(out, (-v) as usize);
    } else {
        push_usize(out, v as usize);
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

fn sortedKeys<V: Clone>(m: &map<string, V>) -> Vec<string> {
    let mut keys: Vec<string> = Vec::new();
    for k in m.Keys().as_ref().iter() {
        keys.push(k.clone());
    }
    keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    keys
}

fn corpus() -> Vec<&'static str> {
    alloc::vec![
        r#"{}"#,
        r#"{"a":"x"}"#,
        r#"{"a":"x","b":"y"}"#,
        r#"{"b":"y","a":"x"}"#,
        r#"{"a":1}"#,
        r#"{"a":"x","b":1}"#,
        r#"{"a":1,"b":"x"}"#,
        r#"{"a":"x","b":1,"c":"z"}"#,
        r#"{"a":[1]}"#,
        r#"{"a":{}}"#,
        r#"{"a":null}"#,
        r#"{"a":true}"#,
        r#"null"#,
        r#"[]"#,
        r#""x""#,
        r#"1"#,
    ]
}

#[goish::main]
fn main() {
    let mut got = RustString::new();

    for (i, doc) in corpus().iter().enumerate() {
        let mut ms: map<string, string> = Default::default();
        let e1 = json2::Unmarshal(doc.as_bytes(), &mut ms, &[]);
        got.push_str("M ");
        push_usize(&mut got, i);
        got.push(' ');
        got.push_str(doc);
        got.push_str(" err=");
        got.push_str(if e1 != goish::nil { "true" } else { "false" });
        got.push_str(" {");
        for (j, k) in sortedKeys(&ms).iter().enumerate() {
            if j > 0 {
                got.push(' ');
            }
            push_esc(&mut got, k.as_bytes());
            got.push('=');
            push_esc(&mut got, ms.Get(k.clone()).0.as_bytes());
        }
        got.push_str("}\n");

        let mut mi: map<string, int> = Default::default();
        let e2 = json2::Unmarshal(doc.as_bytes(), &mut mi, &[]);
        got.push_str("I ");
        push_usize(&mut got, i);
        got.push(' ');
        got.push_str(doc);
        got.push_str(" err=");
        got.push_str(if e2 != goish::nil { "true" } else { "false" });
        got.push_str(" {");
        for (j, k) in sortedKeys(&mi).iter().enumerate() {
            if j > 0 {
                got.push(' ');
            }
            push_esc(&mut got, k.as_bytes());
            got.push('=');
            push_i64(&mut got, mi.Get(k.clone()).0);
        }
        got.push_str("}\n");
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
                    let mut m = RustString::from("JSON_MAP MISMATCH at line ");
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
                die(b"json_map: runaway diff\n");
            }
        }
    }

    let mut msg = RustString::from("JSON_MAP_OK ");
    push_usize(&mut msg, REF.lines().count());
    msg.push_str(" rows byte-exact vs real Go json/v2\n");
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}
