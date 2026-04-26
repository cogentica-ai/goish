// Smoke test: tag-driven json.MarshalReflect over #[goish::reflect]
// structs. This is the user-visible payoff of M14b — write Go-shape
// struct tags, get JSON for free.

#![no_std]
#![no_main]

use goish::encoding::json;
use goish::{int, slice, string, syscall};

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
    Field: int,    // no tag — falls back to field name
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
        let (b, err) = json::MarshalReflect(&p);
        check(err == goish::nil, b"reflect-json: marshal err\n");
        let got = string::from_bytes(&b.__into_vec());
        // Field order = declaration order. Hidden is "-".
        check(got == r#"{"name":"alice","age":30}"#, b"reflect-json: person body\n");
    }

    // ─── omitempty skips zero values ─────────────────────────────────
    {
        let p = Person {
            Name: string("bob"),
            Age: 0, // omitempty skips this
            Hidden: 0,
        };
        let (b, _) = json::MarshalReflect(&p);
        let got = string::from_bytes(&b.__into_vec());
        check(got == r#"{"name":"bob"}"#, b"reflect-json: omitempty\n");
    }

    // ─── Nested slice<string> ────────────────────────────────────────
    {
        let bag = Bag {
            Items: goish::slice!([]string{"a", "b", "c"}),
            Count: 3,
        };
        let (b, _) = json::MarshalReflect(&bag);
        let got = string::from_bytes(&b.__into_vec());
        check(
            got == r#"{"items":["a","b","c"],"count":3}"#,
            b"reflect-json: bag\n",
        );
    }

    // ─── No tag → field name verbatim ────────────────────────────────
    {
        let x = Bare { Field: 42 };
        let (b, _) = json::MarshalReflect(&x);
        let got = string::from_bytes(&b.__into_vec());
        check(got == r#"{"Field":42}"#, b"reflect-json: bare\n");
    }

    // ─── MarshalIndentReflect — pretty-print struct ─────────────────
    {
        let p = Person {
            Name: string("carol"),
            Age: 7,
            Hidden: 0,
        };
        let (b, _) = json::MarshalIndentReflect(&p, "", "  ");
        let got = string::from_bytes(&b.__into_vec());
        let want = "{\n  \"name\": \"carol\",\n  \"age\": 7\n}";
        check(got == want, b"reflect-json: indent\n");
    }

    const OK: &[u8] = b"reflect-json: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
