// json_mapkey_ref_smoke — a NAMED STRING type as a JSON object key
// (issue #17).
//
// Go lets any string-kinded type be a map key and writes it as the
// member name unchanged, so `map[DocumentUri][]*TextEdit` is an
// ordinary field. goish's map codec was written for `map<string, V>`
// only; it is now generic over `v2::ObjectKey`, which a newtype
// implements in two delegating lines.
//
// The rows here are not only the key conversion. Everything the
// `map<string, V>` codec already decided has to keep holding under a
// named key, and those rules are not obvious:
//
//   dec_null_over   `null` NILS a populated map — not an error, and
//                   not a no-op.
//   dec_dup         a duplicate member name is an ERROR in v2 (v1
//                   took the last one), and the map keeps the first.
//   dec_merge       keys the document does not mention SURVIVE.
//   dec_bad_value   a value that fails to decode is still STORED, at
//                   its zero — so `x:0` is present alongside the
//                   error.
//   dec_wrong_kind  a wrong outer kind leaves the map untouched.
//
// NOT pinned: member order for more than one key. v2 emits Go's map
// iteration order, which is randomised — three runs of the generator
// gave two different orders — so there is no expectation to write
// down. goish sorts instead; that divergence is in the module header
// and is why `marshal_1` uses a single-key map.
//
// `dec_null` and `dec_null_over` say `true` for "the map is nil".
// goish has no nil-map state distinct from empty (issues #7 and #14),
// so those rows check emptiness, which is the same observable for
// every operation goish supports on the result.
//
// GO[] is the output of tools/gen_json_mapkey_ref.go under
//   GOEXPERIMENT=jsonv2 scripts/goref.sh encoding/json/v2 …

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use goish::encoding::json::v2::{self as json, ObjectKey};
use goish::fmt;
use goish::gomap::{map, GoHash};
use goish::gostring::string;
use goish::types::int;

static FAILED: AtomicUsize = AtomicUsize::new(0);

const GO: [&str; 11] = [
    "marshal_1          err=false got={\"file:///a.ts\":1}",
    "marshal_empty      err=false got={}",
    "marshal_escape     err=false got={\"a\\\"b\\n\":1}",
    "dec_into_nil       err=false got=map[x:1]",
    "dec_null           err=false got=true",
    "dec_null_over      err=false got=true",
    "dec_dup            err=true  got=map[d:1]",
    "dec_merge          err=false got=map[keep:9 x:1]",
    "dec_bad_value      err=true  got=map[keep:9 x:0]",
    "dec_wrong_kind     err=true  got=map[keep:9]",
    "marshal_edits      err=false got={\"file:///a.ts\":[{\"newText\":\"hi\"}]}",
];

/// `type DocumentUri string` — the upstream LSP declaration, ported
/// with its real shape rather than replaced by a bare `string`.
#[derive(Clone, PartialEq, Default)]
struct DocumentUri(string);

impl GoHash for DocumentUri {
    fn go_hash(&self, seed: u64) -> u64 {
        return self.0.go_hash(seed);
    }
}

/// The two lines issue #17 is about.
impl ObjectKey for DocumentUri {
    fn __object_key(&self) -> string {
        return self.0.clone();
    }
    fn __from_object_key(name: string) -> DocumentUri {
        return DocumentUri(name);
    }
}

#[goish::reflect]
#[derive(Default, Clone)]
struct TextEdit {
    #[tag(r#"json:"newText""#)]
    NewText: string,
}

fn uri(s: &'static str) -> DocumentUri {
    return DocumentUri(string::from_static(s));
}

/// Go's `%v` for a map: `map[k:v k:v]`, keys sorted so the line is
/// stable to compare (Go's own print sorts too).
fn show(m: &map<DocumentUri, int>) -> string {
    let mut keys: Vec<string> = Vec::new();
    for (k, _) in m.__iter() {
        keys.push(k.__object_key());
    }
    keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let mut out = string::from_static("map[");
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            out = out + string::from_static(" ");
        }
        let (v, _) = m.Get(DocumentUri(k.clone()));
        out = out + fmt::Sprintf!("%s:%d", k, v);
    }
    return out + string::from_static("]");
}

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        FAILED.fetch_add(1, Ordering::Relaxed);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
    *ln += 1;
}

fn marshal_row(ln: &mut usize, name: &'static str, m: &map<DocumentUri, int>) {
    let (out, err) = json::Marshal(m, []);
    chk(
        ln,
        &fmt::Sprintf!(
            "%-18s err=%-5v got=%s",
            string::from_static(name),
            !err.IsNil(),
            string::from_bytes(out.as_ref())
        ),
    );
}

fn dec_row(ln: &mut usize, name: &'static str, doc: &[u8], m: &mut map<DocumentUri, int>) {
    let err = json::Unmarshal(doc, m, []);
    chk(
        ln,
        &fmt::Sprintf!(
            "%-18s err=%-5v got=%s",
            string::from_static(name),
            !err.IsNil(),
            show(m)
        ),
    );
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    let mut m: map<DocumentUri, int> = map::new();
    m.Set(uri("file:///a.ts"), int::from(1));
    marshal_row(&mut ln, "marshal_1", &m);

    let empty: map<DocumentUri, int> = map::new();
    marshal_row(&mut ln, "marshal_empty", &empty);

    let mut esc: map<DocumentUri, int> = map::new();
    esc.Set(uri("a\"b\n"), int::from(1));
    marshal_row(&mut ln, "marshal_escape", &esc);

    let mut g: map<DocumentUri, int> = map::new();
    dec_row(&mut ln, "dec_into_nil", b"{\"x\":1}", &mut g);

    // "the map is nil" — goish reads that as "the map is empty"; see
    // the header.
    let mut g: map<DocumentUri, int> = map::new();
    let err = json::Unmarshal(&b"null"[..], &mut g, []);
    chk(&mut ln, &fmt::Sprintf!("%-18s err=%-5v got=%v",
        string::from_static("dec_null"), !err.IsNil(), g.Len() == int::from(0)));

    let mut g: map<DocumentUri, int> = map::new();
    g.Set(uri("keep"), int::from(9));
    let err = json::Unmarshal(&b"null"[..], &mut g, []);
    chk(&mut ln, &fmt::Sprintf!("%-18s err=%-5v got=%v",
        string::from_static("dec_null_over"), !err.IsNil(), g.Len() == int::from(0)));

    let mut g: map<DocumentUri, int> = map::new();
    dec_row(&mut ln, "dec_dup", b"{\"d\":1,\"d\":2}", &mut g);

    let mut g: map<DocumentUri, int> = map::new();
    g.Set(uri("keep"), int::from(9));
    dec_row(&mut ln, "dec_merge", b"{\"x\":1}", &mut g);

    let mut g: map<DocumentUri, int> = map::new();
    g.Set(uri("keep"), int::from(9));
    dec_row(&mut ln, "dec_bad_value", b"{\"x\":\"nope\"}", &mut g);

    let mut g: map<DocumentUri, int> = map::new();
    g.Set(uri("keep"), int::from(9));
    dec_row(&mut ln, "dec_wrong_kind", b"[1]", &mut g);

    // The field the issue is actually blocked on:
    // `map[DocumentUri][]*TextEdit`.
    let mut edits: map<DocumentUri, goish::slice<TextEdit>> = map::new();
    let mut one = goish::make!([]TextEdit, 0);
    one = goish::append!(one, TextEdit { NewText: string::from_static("hi") });
    edits.Set(uri("file:///a.ts"), one);
    let (out, err) = json::Marshal(&edits, []);
    chk(&mut ln, &fmt::Sprintf!("%-18s err=%-5v got=%s",
        string::from_static("marshal_edits"), !err.IsNil(),
        string::from_bytes(out.as_ref())));

    // And back, which is the round-trip the generated codec needs.
    let mut back: map<DocumentUri, goish::slice<TextEdit>> = map::new();
    let err = json::Unmarshal(out.as_ref(), &mut back, []);
    let (got, ok) = back.Get(uri("file:///a.ts"));
    if err.IsNil() && ok && got.Len() == int::from(1)
        && got[0].NewText == string::from_static("hi")
    {
        fmt::Printf!("[ok] dec_edits          round-trips\n");
    } else {
        fmt::Printf!("[!!] dec_edits          did not round-trip\n");
        FAILED.fetch_add(1, Ordering::Relaxed);
    }

    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
    let f = FAILED.load(Ordering::Relaxed);
    if f != 0 {
        fmt::Printf!("\nFAILED %d check(s)\n", f as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok %d/%d\n", ln as i64, GO.len() as i64);
}
