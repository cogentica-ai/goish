// Smoke test: tag-driven json.MarshalReflect over #[goish::reflect]
// structs. This is the user-visible payoff of M14b — write Go-shape
// struct tags, get JSON for free.

#![no_std]
#![no_main]

use goish::encoding::json;
use goish::{int, make, slice, string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[goish::reflect]
pub struct Person {
    #[tag(r#"json:"name""#)]
    Name: string,

    #[tag(r#"json:"age,omitempty""#)]
    Age: int,

    #[tag(r#"json:"-""#)]
    Hidden: int,
}

#[goish::reflect]
pub struct Bag {
    #[tag(r#"json:"items""#)]
    Items: slice<string>,

    #[tag(r#"json:"count""#)]
    Count: int,
}

#[goish::reflect]
pub struct Bare {
    Field: int, // no tag — falls back to field name
}

#[goish::main]
fn main() {
    // ─── Basic struct: tag-renamed keys, omitempty skip ──────────────
    {
        let p = Person {
            Name: string("alice"),
            Age: 30,
            Hidden: 999, // dropped via "-"
        };
        let (b, err) = json::Marshal(&p);
        check(err == goish::nil, b"reflect-json: marshal err\n");
        let got = string::from_bytes(&b.__into_vec());
        // Field order = declaration order. Hidden is "-".
        check(
            got == r#"{"name":"alice","age":30}"#,
            b"reflect-json: person body\n",
        );
    }

    // ─── omitempty skips zero values ─────────────────────────────────
    {
        let p = Person {
            Name: string("bob"),
            Age: 0, // omitempty skips this
            Hidden: 0,
        };
        let (b, _) = json::Marshal(&p);
        let got = string::from_bytes(&b.__into_vec());
        check(got == r#"{"name":"bob"}"#, b"reflect-json: omitempty\n");
    }

    // ─── Nested slice<string> ────────────────────────────────────────
    {
        let bag = Bag {
            Items: goish::slice!([]string{"a", "b", "c"}),
            Count: 3,
        };
        let (b, _) = json::Marshal(&bag);
        let got = string::from_bytes(&b.__into_vec());
        check(
            got == r#"{"items":["a","b","c"],"count":3}"#,
            b"reflect-json: bag\n",
        );
    }

    // ─── No tag → field name verbatim ────────────────────────────────
    {
        let x = Bare { Field: 42 };
        let (b, _) = json::Marshal(&x);
        let got = string::from_bytes(&b.__into_vec());
        check(got == r#"{"Field":42}"#, b"reflect-json: bare\n");
    }

    // ─── MarshalIndent — pretty-print struct ─────────────────────────
    {
        let p = Person {
            Name: string("carol"),
            Age: 7,
            Hidden: 0,
        };
        let (b, _) = json::MarshalIndent(&p, "", "  ");
        let got = string::from_bytes(&b.__into_vec());
        let want = "{\n  \"name\": \"carol\",\n  \"age\": 7\n}";
        check(got == want, b"reflect-json: indent\n");
    }

    // ─── map<string, int> — direct Marshal via Reflect ───────────────
    // BTreeMap-backed map<K,V> walks keys in sorted order, so output is
    // deterministic without extra effort.
    {
        let mut m = make!(map[string]int);
        m.Set(string("zeta"), 3);
        m.Set(string("alpha"), 1);
        m.Set(string("mu"), 2);
        let (b, err) = json::Marshal(&m);
        check(err == goish::nil, b"reflect-json: map err\n");
        let got = string::from_bytes(&b.__into_vec());
        check(
            got == r#"{"alpha":1,"mu":2,"zeta":3}"#,
            b"reflect-json: map body\n",
        );
    }

    // ─── json::Value still flows through Marshal — round-trip ────────
    // Pre-unification this was `Marshal(&value)` over a json::Value;
    // post-unification the same call goes through Reflect (json::Value
    // impls Reflect by emitting Map / Slice variants).
    {
        let mut obj = make!(map[string]json::Value);
        obj.Set(string("k"), json::Value::String(string("v")));
        obj.Set(string("n"), json::Value::Number(3.5));
        let v = json::Value::Object(obj);
        let (b, _) = json::Marshal(&v);
        let got = string::from_bytes(&b.__into_vec());
        check(got == r#"{"k":"v","n":3.5}"#, b"reflect-json: Value path\n");
    }

    // ─── Unmarshal: tag-driven into a typed struct ───────────────────
    {
        let mut p = Person {
            Name: string::new(),
            Age: 0,
            Hidden: 0,
        };
        let err = json::Unmarshal(br#"{"name":"alice","age":30}"#, &mut p);
        check(err == goish::nil, b"reflect-json: unmarshal err\n");
        check(p.Name == "alice", b"reflect-json: unmarshal Name\n");
        check(p.Age == 30, b"reflect-json: unmarshal Age\n");
    }

    // ─── Unmarshal: missing fields stay at zero ──────────────────────
    {
        let mut p = Person {
            Name: string::new(),
            Age: 0,
            Hidden: 0,
        };
        let err = json::Unmarshal(br#"{"name":"bob"}"#, &mut p);
        check(err == goish::nil, b"reflect-json: missing-field err\n");
        check(p.Name == "bob", b"reflect-json: missing-field Name\n");
        check(p.Age == 0, b"reflect-json: missing-field Age zero\n");
    }

    // ─── Unmarshal: "-" tag drops fields on input too ────────────────
    {
        let mut p = Person {
            Name: string::new(),
            Age: 0,
            Hidden: 0,
        };
        let err = json::Unmarshal(br#"{"name":"x","Hidden":99}"#, &mut p);
        check(err == goish::nil, b"reflect-json: dash err\n");
        // Hidden has json:"-" — must NOT be populated.
        check(p.Hidden == 0, b"reflect-json: dash Hidden zero\n");
    }

    // ─── Unmarshal: nested slice<string> field ───────────────────────
    {
        let mut bag = Bag {
            Items: goish::slice!([]string{}),
            Count: 0,
        };
        let err = json::Unmarshal(br#"{"items":["x","y","z"],"count":3}"#, &mut bag);
        check(err == goish::nil, b"reflect-json: bag err\n");
        check(bag.Count == 3, b"reflect-json: bag Count\n");
        check(bag.Items.Len() == 3, b"reflect-json: bag Items len\n");
        check(bag.Items[0] == "x", b"reflect-json: bag Items[0]\n");
    }

    // ─── Unmarshal: round-trip via dynamic Value (FromValue identity) ─
    {
        let mut v = json::Value::Null;
        let err = json::Unmarshal(br#"{"a":1,"b":[2,3]}"#, &mut v);
        check(err == goish::nil, b"reflect-json: dynamic err\n");
        let (b, _) = json::Marshal(&v);
        let got = string::from_bytes(&b.__into_vec());
        check(
            got == r#"{"a":1,"b":[2,3]}"#,
            b"reflect-json: dynamic round-trip\n",
        );
    }

    const OK: &[u8] = b"reflect-json: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
