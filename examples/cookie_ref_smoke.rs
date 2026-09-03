// cookie_ref_smoke — Set-Cookie parsing, Cookie serialisation, and
// Cookie-header parsing, against a running Go.
//
// Reference: Go 1.25.5 net/http/cookie.go, measured by
// tools/gen_cookie_ref.go. Every GO[] line is Go's verbatim output.
//
// Cookies decide who a request is. A cookie goish accepts that Go
// rejects — or spells differently on the way out — is an
// authentication difference, not a formatting one, and the interesting
// inputs are the malformed ones: a NUL in a name, a newline in a
// domain, a semicolon inside a path, a bare attribute with no value, a
// duplicate flag, a comma that looks like a second cookie.
//
// 59 cases across three surfaces:
//
//   ParseSetCookie — SameSite spellings and an unknown one, Max-Age
//   forms including "0", "-1", "007" and "abc", both Expires layouts
//   and an unparseable one, quoted values, __Host- prefix,
//   Partitioned, empty and NUL-bearing names and values, repeated
//   attributes, and the "a=b, c=d" case where the comma is NOT a
//   separator.
//
//   Cookie.String() — attribute order (Path, Domain, HttpOnly,
//   Secure), when a value gets quoted, and what is silently STRIPPED
//   rather than escaped: a quote in a value, a newline anywhere, a
//   semicolon in a path. A cookie whose name is invalid renders as the
//   empty string, so it never reaches the wire at all.
//
//   Request.Cookies() — separators with and without spaces, an empty
//   pair, a bare name, a quoted value, and an invalid cookie sitting
//   next to a valid one (the invalid one is dropped, the valid one
//   survives).
//
// goish matched Go on 58 of 59 before this smoke existed, which for a
// surface this fiddly is the result worth recording. The one
// divergence: an Expires that neither layout parses was dropped
// silently instead of being reported in Unparsed, so a caller
// inspecting that slice could not tell "no expiry was sent" from "an
// expiry was sent and could not be read". Go `break`s out of its
// attribute switch there, falling into the same append every
// unrecognised attribute takes; the successful path `continue`s past
// it. goish now does the same.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::fmt;
use goish::net::http;
use goish::{string, time};

// Go's verbatim output.
const GO: [&str; 59] = [
    "set \"a=b\"                                      name=\"a\" val=\"b\" q=false path=\"\" dom=\"\" ma=0 sec=false ho=false ss=0 part=false raw_exp=\"\" unp=[]",
    "set \"a=b; Path=/x; Domain=example.com; Secure; HttpOnly\" name=\"a\" val=\"b\" q=false path=\"/x\" dom=\"example.com\" ma=0 sec=true ho=true ss=0 part=false raw_exp=\"\" unp=[]",
    "set \"a=b; SameSite=Strict\"                     name=\"a\" val=\"b\" q=false path=\"\" dom=\"\" ma=0 sec=false ho=false ss=3 part=false raw_exp=\"\" unp=[]",
    "set \"a=b; SameSite=lax\"                        name=\"a\" val=\"b\" q=false path=\"\" dom=\"\" ma=0 sec=false ho=false ss=2 part=false raw_exp=\"\" unp=[]",
    "set \"a=b; SameSite=None\"                       name=\"a\" val=\"b\" q=false path=\"\" dom=\"\" ma=0 sec=false ho=false ss=4 part=false raw_exp=\"\" unp=[]",
    "set \"a=b; SameSite=bogus\"                      name=\"a\" val=\"b\" q=false path=\"\" dom=\"\" ma=0 sec=false ho=false ss=1 part=false raw_exp=\"\" unp=[]",
    "set \"a=b; Max-Age=100\"                         name=\"a\" val=\"b\" q=false path=\"\" dom=\"\" ma=100 sec=false ho=false ss=0 part=false raw_exp=\"\" unp=[]",
    "set \"a=b; Max-Age=0\"                           name=\"a\" val=\"b\" q=false path=\"\" dom=\"\" ma=-1 sec=false ho=false ss=0 part=false raw_exp=\"\" unp=[]",
    "set \"a=b; Max-Age=-1\"                          name=\"a\" val=\"b\" q=false path=\"\" dom=\"\" ma=-1 sec=false ho=false ss=0 part=false raw_exp=\"\" unp=[]",
    "set \"a=b; Max-Age=007\"                         name=\"a\" val=\"b\" q=false path=\"\" dom=\"\" ma=0 sec=false ho=false ss=0 part=false raw_exp=\"\" unp=[\"Max-Age=007\"]",
    "set \"a=b; Max-Age=abc\"                         name=\"a\" val=\"b\" q=false path=\"\" dom=\"\" ma=0 sec=false ho=false ss=0 part=false raw_exp=\"\" unp=[\"Max-Age=abc\"]",
    "set \"a=b; Expires=Mon, 02 Jan 2006 15:04:05 GMT\" name=\"a\" val=\"b\" q=false path=\"\" dom=\"\" ma=0 sec=false ho=false ss=0 part=false raw_exp=\"Mon, 02 Jan 2006 15:04:05 GMT\" unp=[]",
    "set \"a=b; Expires=bogus\"                       name=\"a\" val=\"b\" q=false path=\"\" dom=\"\" ma=0 sec=false ho=false ss=0 part=false raw_exp=\"bogus\" unp=[\"Expires=bogus\"]",
    "set \"a=\\\"quoted\\\"\"                             name=\"a\" val=\"quoted\" q=true path=\"\" dom=\"\" ma=0 sec=false ho=false ss=0 part=false raw_exp=\"\" unp=[]",
    "set \"a=\\\"qu oted\\\"\"                            name=\"a\" val=\"qu oted\" q=true path=\"\" dom=\"\" ma=0 sec=false ho=false ss=0 part=false raw_exp=\"\" unp=[]",
    "set \"a=b; Partitioned\"                         name=\"a\" val=\"b\" q=false path=\"\" dom=\"\" ma=0 sec=false ho=false ss=0 part=true raw_exp=\"\" unp=[]",
    "set \"a=b; Unknown=thing\"                       name=\"a\" val=\"b\" q=false path=\"\" dom=\"\" ma=0 sec=false ho=false ss=0 part=false raw_exp=\"\" unp=[\"Unknown=thing\"]",
    "set \"a=b; Path\"                                name=\"a\" val=\"b\" q=false path=\"\" dom=\"\" ma=0 sec=false ho=false ss=0 part=false raw_exp=\"\" unp=[]",
    "set \"=b\"                                       err=http: invalid cookie name",
    "set \"a=\"                                       name=\"a\" val=\"\" q=false path=\"\" dom=\"\" ma=0 sec=false ho=false ss=0 part=false raw_exp=\"\" unp=[]",
    "set \"a=b; Domain=.example.com\"                 name=\"a\" val=\"b\" q=false path=\"\" dom=\".example.com\" ma=0 sec=false ho=false ss=0 part=false raw_exp=\"\" unp=[]",
    "set \"a=b; Domain=\"                             name=\"a\" val=\"b\" q=false path=\"\" dom=\"\" ma=0 sec=false ho=false ss=0 part=false raw_exp=\"\" unp=[]",
    "set \"a\\x00b=c\"                                 err=http: invalid cookie name",
    "set \"a=b\\x00c\"                                 err=http: invalid cookie value",
    "set \"a=b; Path=/x\\x00y\"                        name=\"a\" val=\"b\" q=false path=\"\" dom=\"\" ma=0 sec=false ho=false ss=0 part=false raw_exp=\"\" unp=[\"Path=/x\\x00y\"]",
    "set \"a=b;;Secure\"                              name=\"a\" val=\"b\" q=false path=\"\" dom=\"\" ma=0 sec=true ho=false ss=0 part=false raw_exp=\"\" unp=[]",
    "set \"  a  =  b  \"                              name=\"a\" val=\"  b\" q=false path=\"\" dom=\"\" ma=0 sec=false ho=false ss=0 part=false raw_exp=\"\" unp=[]",
    "set \"__Host-a=b; Path=/; Secure\"               name=\"__Host-a\" val=\"b\" q=false path=\"/\" dom=\"\" ma=0 sec=true ho=false ss=0 part=false raw_exp=\"\" unp=[]",
    "set \"a=b; Secure; Secure\"                      name=\"a\" val=\"b\" q=false path=\"\" dom=\"\" ma=0 sec=true ho=false ss=0 part=false raw_exp=\"\" unp=[]",
    "set \"a=b, c=d\"                                 name=\"a\" val=\"b, c=d\" q=false path=\"\" dom=\"\" ma=0 sec=false ho=false ss=0 part=false raw_exp=\"\" unp=[]",
    "str name=\"a\"    val=\"b\"      -> \"a=b\"",
    "str name=\"a\"    val=\"b\"      -> \"a=b; Path=/x; Domain=example.com; HttpOnly; Secure\"",
    "str name=\"a\"    val=\"b\"      -> \"a=b; Max-Age=100\"",
    "str name=\"a\"    val=\"b\"      -> \"a=b; Max-Age=0\"",
    "str name=\"a\"    val=\"b\"      -> \"a=b\"",
    "str name=\"a\"    val=\"b\"      -> \"a=b; SameSite=Strict\"",
    "str name=\"a\"    val=\"b\"      -> \"a=b; SameSite=None\"",
    "str name=\"a\"    val=\"b\"      -> \"a=b\"",
    "str name=\"a\"    val=\"b\"      -> \"a=b; Partitioned\"",
    "str name=\"a\"    val=\"b c\"    -> \"a=\\\"b c\\\"\"",
    "str name=\"a\"    val=\"b\\\"c\"   -> \"a=bc\"",
    "str name=\"a\"    val=\"b\"      -> \"a=\\\"b\\\"\"",
    "str name=\"a\"    val=\"b\\nc\"   -> \"a=bc\"",
    "str name=\"a\\nb\" val=\"c\"      -> \"\"",
    "str name=\"a\"    val=\"b\"      -> \"a=b; Path=/xy\"",
    "str name=\"a\"    val=\"b\"      -> \"a=b\"",
    "str name=\"a\"    val=\"b\"      -> \"a=b\"",
    "str name=\"\"     val=\"b\"      -> \"\"",
    "str name=\"a\"    val=\"b\"      -> \"a=b; Path=/xy\"",
    "req \"a=b\"                    -> [\"a=b\"]",
    "req \"a=b; c=d\"               -> [\"a=b\" \"c=d\"]",
    "req \"a=b;c=d\"                -> [\"a=b\" \"c=d\"]",
    "req \"a=b; ; c=d\"             -> [\"a=b\" \"c=d\"]",
    "req \"a=b; c\"                 -> [\"a=b\" \"c=\"]",
    "req \"a=\\\"b\\\"\"                -> [\"a=b\"]",
    "req \"a=b\\x00c; d=e\"          -> [\"d=e\"]",
    "req \"a b=c; d=e\"             -> [\"d=e\"]",
    "req \"a=b; a=c\"               -> [\"a=b\" \"a=c\"]",
    "req \"  a=b  ;  c=d  \"        -> [\"a=b\" \"c=d\"]",
];

static FAILED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static LN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn chk(got: goish::string) {
    use core::sync::atomic::Ordering;
    let i = LN.fetch_add(1, Ordering::Relaxed);
    let g: &str = got.as_ref();
    if i >= GO.len() {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!] extra line %d: %s\n", i as i64, got);
        return;
    }
    if g == GO[i] {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d\n  got:  %s\n  want: %s\n",
            i as i64,
            got,
            string(GO[i])
        );
    }
}

#[goish::main]
fn main() {
    let set_lines: [&str; 30] = [
        "a=b",
        "a=b; Path=/x; Domain=example.com; Secure; HttpOnly",
        "a=b; SameSite=Strict",
        "a=b; SameSite=lax",
        "a=b; SameSite=None",
        "a=b; SameSite=bogus",
        "a=b; Max-Age=100",
        "a=b; Max-Age=0",
        "a=b; Max-Age=-1",
        "a=b; Max-Age=007",
        "a=b; Max-Age=abc",
        "a=b; Expires=Mon, 02 Jan 2006 15:04:05 GMT",
        "a=b; Expires=bogus",
        "a=\"quoted\"",
        "a=\"qu oted\"",
        "a=b; Partitioned",
        "a=b; Unknown=thing",
        "a=b; Path",
        "=b",
        "a=",
        "a=b; Domain=.example.com",
        "a=b; Domain=",
        "a\u{0}b=c",
        "a=b\u{0}c",
        "a=b; Path=/x\u{0}y",
        "a=b;;Secure",
        "  a  =  b  ",
        "__Host-a=b; Path=/; Secure",
        "a=b; Secure; Secure",
        "a=b, c=d",
    ];
    for l in set_lines.iter() {
        let ls = goish::string::from_bytes(l.as_bytes());
        let (c, err) = http::ParseSetCookie(ls.clone());
        if !err.IsNil() {
            chk(fmt::Sprintf!("set %-42q err=%v", ls, err));
            continue;
        }
        chk(fmt::Sprintf!(
            "set %-42q name=%q val=%q q=%v path=%q dom=%q ma=%d sec=%v ho=%v ss=%d part=%v raw_exp=%q unp=%q",
            ls, c.Name, c.Value, c.Quoted, c.Path, c.Domain, c.MaxAge,
            c.Secure, c.HttpOnly, c.SameSite as i64, c.Partitioned, c.RawExpires, c.Unparsed
        ));
    }

    let mk = |n: &str, v: &str| http::Cookie {
        Name: goish::string::from_bytes(n.as_bytes()),
        Value: goish::string::from_bytes(v.as_bytes()),
        ..Default::default()
    };
    let mut cookies: Vec<http::Cookie> = Vec::new();
    cookies.push(mk("a", "b"));
    cookies.push(http::Cookie {
        Path: string("/x"),
        Domain: string("example.com"),
        Secure: true,
        HttpOnly: true,
        ..mk("a", "b")
    });
    cookies.push(http::Cookie {
        MaxAge: 100,
        ..mk("a", "b")
    });
    cookies.push(http::Cookie {
        MaxAge: -1,
        ..mk("a", "b")
    });
    cookies.push(http::Cookie {
        MaxAge: 0,
        ..mk("a", "b")
    });
    cookies.push(http::Cookie {
        SameSite: http::SameSiteStrictMode,
        ..mk("a", "b")
    });
    cookies.push(http::Cookie {
        SameSite: http::SameSiteNoneMode,
        ..mk("a", "b")
    });
    cookies.push(http::Cookie {
        SameSite: http::SameSiteDefaultMode,
        ..mk("a", "b")
    });
    cookies.push(http::Cookie {
        Partitioned: true,
        ..mk("a", "b")
    });
    cookies.push(mk("a", "b c"));
    cookies.push(mk("a", "b\"c"));
    cookies.push(http::Cookie {
        Quoted: true,
        ..mk("a", "b")
    });
    cookies.push(mk("a", "b\nc"));
    cookies.push(mk("a\nb", "c"));
    cookies.push(http::Cookie {
        Path: string("/x\ny"),
        ..mk("a", "b")
    });
    cookies.push(http::Cookie {
        Domain: string("exa\nmple.com"),
        ..mk("a", "b")
    });
    cookies.push(http::Cookie {
        Domain: string("-bad.com"),
        ..mk("a", "b")
    });
    cookies.push(mk("", "b"));
    cookies.push(http::Cookie {
        Path: string("/x;y"),
        ..mk("a", "b")
    });
    for c in cookies.iter() {
        chk(fmt::Sprintf!(
            "str name=%-6q val=%-8q -> %q",
            c.Name,
            c.Value,
            c.String()
        ));
    }

    let req_lines: [&str; 10] = [
        "a=b",
        "a=b; c=d",
        "a=b;c=d",
        "a=b; ; c=d",
        "a=b; c",
        "a=\"b\"",
        "a=b\u{0}c; d=e",
        "a b=c; d=e",
        "a=b; a=c",
        "  a=b  ;  c=d  ",
    ];
    for l in req_lines.iter() {
        let ls = goish::string::from_bytes(l.as_bytes());
        let (mut r, _) = http::NewRequest(string("GET"), string("http://x/"), goish::nil);
        r.Header.Set(string("Cookie"), ls.clone());
        let cs = r.Cookies();
        let mut got: goish::slice<goish::string> =
            goish::slice::<goish::string>::__from_vec(Vec::new());
        for i in 0..cs.Len() {
            got = goish::append!(got, cs[i].Name.clone() + string("=") + cs[i].Value.clone());
        }
        chk(fmt::Sprintf!("req %-24q -> %q", ls, got));
    }
    let _ = time::Now();

    use core::sync::atomic::Ordering;
    let f = FAILED.load(Ordering::Relaxed);
    let n = LN.load(Ordering::Relaxed);
    if f == 0 && n == GO.len() {
        fmt::Printf!("\nok %d/%d\n", n as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!(
        "\nFAILED %d of %d (%d lines)\n",
        f as i64,
        GO.len() as i64,
        n as i64
    );
    goish::os::Exit(1);
}
