// Smoke test: collections of nested #[goish::reflect] structs —
// slice<Address> and map<string, Address> as field types of a User
// struct. Exercises %v, json Marshal/Unmarshal, SetField, DeepEqual.

#![no_std]
#![no_main]

use goish::encoding::json;
use goish::{int, make, reflect, slice, string, syscall, Sprintf};

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

    #[tag(r#"json:"addrs""#)]
    Addrs: slice<Address>,

    #[tag(r#"json:"by_name""#)]
    ByName: goish::map<string, Address>,
}

#[goish::main]
fn main() {
    // Build a User with a slice<Address> and map<string, Address>.
    let addr_a = Address { Street: string("Main"), Zip: 1 };
    let addr_b = Address { Street: string("Elm"),  Zip: 2 };

    let mut by = make!(map[string]Address);
    by.Set(string("home"), Address { Street: string("Oak"), Zip: 3 });
    by.Set(string("work"), Address { Street: string("Ash"), Zip: 4 });

    let u = User {
        Name: string("alice"),
        Addrs: goish::slice!([]Address { addr_a.clone(), addr_b.clone() }),
        ByName: by,
    };

    // ─── %+v recurses into every nested element ─────────────────────
    let pv = Sprintf!("%+v", &u);
    check(
        pv == "{Name:alice \
               Addrs:[{Street:Main Zip:1} {Street:Elm Zip:2}] \
               ByName:map[home:{Street:Oak Zip:3} work:{Street:Ash Zip:4}]}",
        b"collections: %+v body\n",
    );

    // ─── json Marshal — nested array + nested object ────────────────
    let (b, err) = json::Marshal(&u);
    check(err == goish::nil, b"collections: marshal err\n");
    let got = string::from_bytes(&b.__into_vec());
    let want = r#"{"name":"alice","addrs":[{"street":"Main","zip":1},{"street":"Elm","zip":2}],"by_name":{"home":{"street":"Oak","zip":3},"work":{"street":"Ash","zip":4}}}"#;
    check(got == want, b"collections: marshal body\n");

    // ─── json Unmarshal round-trip via DeepEqual ────────────────────
    let mut u2: User = Default::default();
    let err = json::Unmarshal(want.as_bytes(), &mut u2);
    check(err == goish::nil, b"collections: unmarshal err\n");
    check(reflect::DeepEqual(&u, &u2), b"collections: DeepEqual round-trip\n");

    // ─── SetField with a fresh slice<Address> ───────────────────────
    let mut u3 = u.clone();
    let new_addrs = goish::slice!([]Address {
        Address { Street: string("Pine"), Zip: 9 }
    });
    let err = reflect::SetFieldByName(&mut u3, "Addrs", reflect::ValueOf(&new_addrs));
    check(err == goish::nil, b"collections: SetField slice err\n");
    check(u3.Addrs.Len() == 1, b"collections: SetField slice len\n");
    check(u3.Addrs[0].Street == "Pine", b"collections: SetField slice[0]\n");

    // ─── SetField with a fresh map<string, Address> ─────────────────
    let mut new_by = make!(map[string]Address);
    new_by.Set(string("only"), Address { Street: string("Birch"), Zip: 7 });
    let err = reflect::SetFieldByName(&mut u3, "ByName", reflect::ValueOf(&new_by));
    check(err == goish::nil, b"collections: SetField map err\n");
    let (got, ok) = u3.ByName.Get(string("only"));
    check(ok && got.Street == "Birch", b"collections: SetField map lookup\n");

    const OK: &[u8] = b"reflect_collections: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
