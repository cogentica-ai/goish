// Smoke test: nested #[goish::reflect] structs work end-to-end —
// %v recursion, SetField/SetFieldByName with a nested-struct payload,
// and json Marshal/Unmarshal round-trip.

#![no_std]
#![no_main]

use goish::fmt;
use goish::encoding::json;
use goish::{int, reflect, string, syscall};

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
pub struct Address {
    #[tag(r#"json:"street""#)]
    Street: string,

    #[tag(r#"json:"zip""#)]
    Zip: int,
}

#[goish::reflect]
pub struct User {
    #[tag(r#"json:"name""#)]
    Name: string,

    #[tag(r#"json:"home""#)]
    Home: Address,
}

#[goish::main]
fn main() {
    let u = User {
        Name: string("alice"),
        Home: Address {
            Street: string("Main"),
            Zip: 123,
        },
    };

    // ─── %v / %+v recurse into nested struct ─────────────────────────
    let v = fmt::Sprintf!("%v", &u);
    check(v == "{alice {Main 123}}", b"nested: %v body\n");

    let pv = fmt::Sprintf!("%+v", &u);
    check(
        pv == "{Name:alice Home:{Street:Main Zip:123}}",
        b"nested: %+v body\n",
    );

    // ─── SetFieldByName with a nested-struct payload ────────────────
    let mut u2 = User {
        Name: string("orig"),
        Home: Address {
            Street: string::new(),
            Zip: 0,
        },
    };
    let new_home = Address {
        Street: string("Elm"),
        Zip: 999,
    };
    let err = reflect::SetFieldByName(&mut u2, "Home", reflect::ValueOf(&new_home));
    check(err == goish::nil, b"nested: SetField err\n");
    check(u2.Home.Street == "Elm", b"nested: SetField Street\n");
    check(u2.Home.Zip == 999, b"nested: SetField Zip\n");

    // ─── json Marshal — nested object ───────────────────────────────
    let (b, err) = json::Marshal(&u);
    check(err == goish::nil, b"nested: marshal err\n");
    let got = string::from_bytes(&b.__into_vec());
    check(
        got == r#"{"name":"alice","home":{"street":"Main","zip":123}}"#,
        b"nested: marshal body\n",
    );

    // ─── json Unmarshal — round-trip via DeepEqual ──────────────────
    let mut u3 = User {
        Name: string::new(),
        Home: Address {
            Street: string::new(),
            Zip: 0,
        },
    };
    let err = json::Unmarshal(
        br#"{"name":"alice","home":{"street":"Main","zip":123}}"#,
        &mut u3,
    );
    check(err == goish::nil, b"nested: unmarshal err\n");
    check(reflect::DeepEqual(&u, &u3), b"nested: DeepEqual round-trip\n");

    const OK: &[u8] = b"reflect_nested: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
