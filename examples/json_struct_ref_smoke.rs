// json_struct_ref_smoke — struct and map encoding vs Go.
// (encoding/json/encode.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_jsonstruct_ref.go` and
// `tools/gen_jsonmap_ref.go` run in `package json_test` by
// `scripts/goref.sh`.
//
// goish's encoding/json had never been diffed. Two of its behaviours
// turned out to be WRONG and are fixed in the two commits before this
// one; everything below turned out to be RIGHT, and this file is here
// so it stays that way. Behaviour that is correct and unpinned is one
// refactor away from being neither.
//
// The rules are small individually and change every response a server
// sends:
//
//   * Struct fields keep DECLARATION order. Map keys are SORTED. Those
//     are opposite rules in the same encoder, and a port that applied
//     either to the other would still produce valid JSON.
//   * Sorted map keys are what make a marshalled map usable as a cache
//     key, a signature input or a golden fixture — the vectors marshal
//     the same map three times and require the same bytes.
//   * `json:"-"` skips a field; `json:"-,"` NAMES it "-". One trailing
//     comma is the whole difference.
//   * `omitempty` drops a field for its type's ZERO value only, so
//     false and 0 and "" go and everything else stays.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::encoding::json;
use goish::gomap::map;
use goish::gostring::string;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn eq(failed: &mut int, got: string, want: &str, what: &str) {
    if got == s(want) {
        return;
    }
    fmt::Printf!(
        "[!!] %s FAIL\n     got  %s\n     want %s\n",
        s(what),
        got,
        s(want)
    );
    *failed += 1;
}

#[goish::reflect]
#[derive(Clone, Default)]
pub struct S {
    Plain: int,
    #[tag(r#"json:"renamed""#)]
    Renamed: int,
    #[tag(r#"json:"-""#)]
    Skipped: int,
    #[tag(r#"json:"omit,omitempty""#)]
    Omit: int,
    #[tag(r#"json:"omitstr,omitempty""#)]
    OmitStr: string,
    #[tag(r#"json:"omitbool,omitempty""#)]
    OmitBool: bool,
    #[tag(r#"json:"keep""#)]
    Keep: int,
    #[tag(r#"json:"-,""#)]
    DashName: int,
}

#[goish::reflect]
#[derive(Clone, Default)]
pub struct Ord {
    #[tag(r#"json:"z""#)]
    Z: int,
    #[tag(r#"json:"a""#)]
    A: int,
    #[tag(r#"json:"m""#)]
    M: int,
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. omitempty drops the zero values, `-` skips, `-,` names the
    //    field "-", and an untagged field keeps its Go name.
    {
        let mut a = S::default();
        a.Plain = 1;
        a.Renamed = 2;
        a.Skipped = 3;
        a.Keep = 7;
        a.DashName = 9;
        let (b, _) = json::Marshal(&a);
        eq(
            &mut failed,
            string::from_bytes(&b.clone().__into_vec()),
            "{\"Plain\":1,\"renamed\":2,\"keep\":7,\"-\":9}",
            "zero-omits",
        );

        // …and keeps them when they are set. `omitbool` is the one
        // worth having: `false` is dropped and `true` is kept, so a
        // port that tested only integers would not notice.
        let mut c = S::default();
        c.Plain = 1;
        c.Renamed = 2;
        c.Omit = 5;
        c.OmitStr = s("x");
        c.OmitBool = true;
        c.Keep = 7;
        c.DashName = 9;
        let (b2, _) = json::Marshal(&c);
        eq(
            &mut failed,
            string::from_bytes(&b2.clone().__into_vec()),
            "{\"Plain\":1,\"renamed\":2,\"omit\":5,\"omitstr\":\"x\",\"omitbool\":true,\"keep\":7,\"-\":9}",
            "all-set",
        );
        fmt::Println!("[  1 ] tags, omitempty and the two dash forms");
    }

    // 2. Struct fields keep DECLARATION order — z, a, m, not sorted.
    {
        let o = Ord { Z: 1, A: 2, M: 3 };
        let (b, _) = json::Marshal(&o);
        eq(
            &mut failed,
            string::from_bytes(&b.clone().__into_vec()),
            "{\"z\":1,\"a\":2,\"m\":3}",
            "struct order",
        );
        fmt::Println!("[  2 ] struct fields keep declaration order");
    }

    // 3. Map keys are SORTED, byte-wise — so digits come before
    //    capitals and capitals before lowercase, and the empty key
    //    sorts first. The same map marshals to the same bytes every
    //    time, which is what makes the output usable as a key.
    {
        let mut m: map<string, int> = map::new();
        let pairs: [(&str, i64); 7] = [
            ("zebra", 1),
            ("apple", 2),
            ("Mango", 3),
            ("banana", 4),
            ("", 5),
            ("10", 6),
            ("2", 7),
        ];
        let mut i = 0;
        while i < pairs.len() {
            let (k, v) = pairs[i];
            m.Set(s(k), v);
            i += 1;
        }
        let want = "{\"\":5,\"10\":6,\"2\":7,\"Mango\":3,\"apple\":2,\"banana\":4,\"zebra\":1}";
        let mut run = 0;
        while run < 3 {
            let (b, _) = json::Marshal(&m);
            eq(
                &mut failed,
                string::from_bytes(&b.clone().__into_vec()),
                want,
                "map order",
            );
            run += 1;
        }

        // The byte-wise ordering spelled out on a set chosen to
        // separate it from any case-insensitive or locale ordering.
        let mut o: map<string, int> = map::new();
        let ps: [(&str, i64); 6] = [("B", 1), ("a", 2), ("A", 3), ("b", 4), ("_", 5), ("0", 6)];
        let mut j = 0;
        while j < ps.len() {
            let (k, v) = ps[j];
            o.Set(s(k), v);
            j += 1;
        }
        let (b2, _) = json::Marshal(&o);
        eq(
            &mut failed,
            string::from_bytes(&b2.clone().__into_vec()),
            "{\"0\":6,\"A\":3,\"B\":1,\"_\":5,\"a\":2,\"b\":4}",
            "map byte order",
        );

        let empty: map<string, int> = map::new();
        let (b3, _) = json::Marshal(&empty);
        eq(
            &mut failed,
            string::from_bytes(&b3.clone().__into_vec()),
            "{}",
            "empty map",
        );
        fmt::Println!("[  3 ] map keys are sorted and deterministic");
    }

    if failed == 0 {
        fmt::Println!("ok - json struct and map encoding match Go");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed);
        syscall::Exit(1);
    }
}
