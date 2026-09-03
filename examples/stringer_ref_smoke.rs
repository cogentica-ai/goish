// stringer_ref_smoke — %v and %s on the stdlib's Stringer types, against a running Go.
// (fmt/print.go's handleMethods, and each type's own String)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_stringer_ref.go` run in
// `package fmt_test` by `scripts/goref.sh`.
//
// Go's fmt finds String() by structural assertion: any value whose
// METHOD SET includes it is printed through it by %v and %s. That is
// why `fmt.Printf("%v", ip)` on a net.IP prints "192.0.2.1" rather than
// a byte slice, and it is entirely ordinary code.
//
// Sixteen types could not be printed at all. Not printed WRONGLY —
// `fmt.Printf("%v", x)` did not COMPILE, for net.IP, net.IPMask,
// netip.Addr, netip.AddrPort, netip.Prefix, crypto.Hash,
// tls.SignatureScheme, tls.CurveID, tls.ClientAuthType,
// x509.SignatureAlgorithm, x509.PublicKeyAlgorithm, x509.OID,
// pkix.RDNSequence, json.Number, slog.Attr and scanner.Position. Every
// one had a correct String() that goish's printer could not dispatch
// to, because it reaches String through a `Stringer` impl and none
// existed.
//
// This is the fourth appearance of one pattern. io/fs's FileMode,
// FileInfo and DirEntry were the first three; reflect.Kind and
// reflect.Type the next two. Rather than wait to trip over a
// seventeenth, the whole tree was scanned for types with an inherent
// String() and no way for fmt to reach it — which is how this list was
// built, and why it is one commit instead of six.
//
// THE METHOD-SET RULE IS WHY THIS IS NOT SIMPLY "ADD THEM ALL". Go
// puts a pointer-receiver String in the POINTER's method set only, so
// printing the VALUE prints the struct and only printing the pointer
// calls String(). goish has no value/pointer distinction, so an impl
// on such a type would print where Go does not. net.IPNet, url.URL,
// url.Userinfo, http.Cookie, mail.Address and regexp.Regexp all have
// pointer-receiver String methods and are deliberately left alone —
// their receivers were checked against the Go source, not assumed.
//
// What the pinned lines are worth beyond compiling:
//
//   * A nil net.IP prints "<nil>", not "" — so a log line about a
//     missing address says so.
//   * An IPv4-mapped IPv6 address prints as IPv4 through net.IP and as
//     "::ffff:192.0.2.1" through netip.Addr. The two types disagree on
//     purpose and both are pinned.
//   * The ZERO netip.Addr, AddrPort and Prefix print "invalid IP",
//     "invalid AddrPort" and "invalid Prefix" — a caller that logs one
//     without checking Is Valid gets a readable answer rather than
//     "0.0.0.0".
//   * Out-of-range enum values print a numbered fallback rather than
//     panicking or printing nothing: crypto.Hash(99), CurveID(9999),
//     SignatureAlgorithm(99) and friends each have a pinned shape.
//   * json.Number is a string type, so it prints its raw text —
//     including when that text is not a number at all.
//   * %q quotes the STRING form, not the underlying value.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::crypto;
use goish::crypto::tls;
use goish::crypto::x509;
use goish::crypto::x509::pkix;
use goish::encoding::json;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::log::slog;
use goish::net;
use goish::net::netip;
use goish::syscall;
use goish::text::scanner;
use goish::types::int;
const GO: [&str; 72] = [
    "net.IP/192.0.2.1             v=192.0.2.1 s=192.0.2.1 q=\"192.0.2.1\" nil=false",
    "net.IP/2001:db8::1           v=2001:db8::1 s=2001:db8::1 q=\"2001:db8::1\" nil=false",
    "net.IP/::ffff:192.0.2.1      v=192.0.2.1 s=192.0.2.1 q=\"192.0.2.1\" nil=false",
    "net.IP/<empty>               v=<nil> s=<nil> q=\"<nil>\" nil=true",
    "net.IPMask/4                 v=ffffff00 s=ffffff00 q=\"ffffff00\"",
    "net.IPMask/4                 v=00000000 s=00000000 q=\"00000000\"",
    "net.IPMask/4                 v=ffffffff s=ffffffff q=\"ffffffff\"",
    "net.IPMask/16                v=ffffffffffffffff0000000000000000 s=ffffffffffffffff0000000000000000 q=\"ffffffffffffffff0000000000000000\"",
    "net.IPMask/0                 v=<nil> s=<nil> q=\"<nil>\"",
    "netip.Addr/192.0.2.1         v=192.0.2.1 s=192.0.2.1 q=\"192.0.2.1\"",
    "netip.Addr/2001:db8::1       v=2001:db8::1 s=2001:db8::1 q=\"2001:db8::1\"",
    "netip.Addr/::ffff:192.0.2.1  v=::ffff:192.0.2.1 s=::ffff:192.0.2.1 q=\"::ffff:192.0.2.1\"",
    "netip.Addr/192.0.2.1%eth0    parse-err=\"ParseAddr(\\\"192.0.2.1%eth0\\\"): unexpected character (at \\\"%eth0\\\")\"",
    "netip.Addr/zero              v=invalid IP s=invalid IP q=\"invalid IP\"",
    "netip.AddrPort/192.0.2.1:80  v=192.0.2.1:80 s=192.0.2.1:80 q=\"192.0.2.1:80\"",
    "netip.AddrPort/[2001:db8::1]:443 v=[2001:db8::1]:443 s=[2001:db8::1]:443 q=\"[2001:db8::1]:443\"",
    "netip.AddrPort/zero          v=invalid AddrPort s=invalid AddrPort q=\"invalid AddrPort\"",
    "netip.Prefix/192.0.2.0/24    v=192.0.2.0/24 s=192.0.2.0/24 q=\"192.0.2.0/24\"",
    "netip.Prefix/2001:db8::/32   v=2001:db8::/32 s=2001:db8::/32 q=\"2001:db8::/32\"",
    "netip.Prefix/0.0.0.0/0       v=0.0.0.0/0 s=0.0.0.0/0 q=\"0.0.0.0/0\"",
    "netip.Prefix/zero            v=invalid Prefix s=invalid Prefix q=\"invalid Prefix\"",
    "crypto.Hash/0                v=unknown hash value 0 s=unknown hash value 0 q=\"unknown hash value 0\"",
    "crypto.Hash/2                v=MD5 s=MD5 q=\"MD5\"",
    "crypto.Hash/3                v=SHA-1 s=SHA-1 q=\"SHA-1\"",
    "crypto.Hash/5                v=SHA-256 s=SHA-256 q=\"SHA-256\"",
    "crypto.Hash/7                v=SHA-512 s=SHA-512 q=\"SHA-512\"",
    "crypto.Hash/11               v=SHA3-256 s=SHA3-256 q=\"SHA3-256\"",
    "crypto.Hash/99               v=unknown hash value 99 s=unknown hash value 99 q=\"unknown hash value 99\"",
    "tls.SignatureScheme/0401     v=PKCS1WithSHA256 s=PKCS1WithSHA256 q=\"PKCS1WithSHA256\"",
    "tls.SignatureScheme/0403     v=ECDSAWithP256AndSHA256 s=ECDSAWithP256AndSHA256 q=\"ECDSAWithP256AndSHA256\"",
    "tls.SignatureScheme/0807     v=Ed25519 s=Ed25519 q=\"Ed25519\"",
    "tls.SignatureScheme/0806     v=PSSWithSHA512 s=PSSWithSHA512 q=\"PSSWithSHA512\"",
    "tls.SignatureScheme/0000     v=SignatureScheme(0) s=SignatureScheme(0) q=\"SignatureScheme(0)\"",
    "tls.SignatureScheme/ffff     v=SignatureScheme(65535) s=SignatureScheme(65535) q=\"SignatureScheme(65535)\"",
    "tls.CurveID/23               v=CurveP256 s=CurveP256 q=\"CurveP256\"",
    "tls.CurveID/24               v=CurveP384 s=CurveP384 q=\"CurveP384\"",
    "tls.CurveID/25               v=CurveP521 s=CurveP521 q=\"CurveP521\"",
    "tls.CurveID/29               v=X25519 s=X25519 q=\"X25519\"",
    "tls.CurveID/0                v=CurveID(0) s=CurveID(0) q=\"CurveID(0)\"",
    "tls.CurveID/9999             v=CurveID(9999) s=CurveID(9999) q=\"CurveID(9999)\"",
    "tls.ClientAuthType/0         v=NoClientCert s=NoClientCert q=\"NoClientCert\"",
    "tls.ClientAuthType/1         v=RequestClientCert s=RequestClientCert q=\"RequestClientCert\"",
    "tls.ClientAuthType/4         v=RequireAndVerifyClientCert s=RequireAndVerifyClientCert q=\"RequireAndVerifyClientCert\"",
    "tls.ClientAuthType/99        v=ClientAuthType(99) s=ClientAuthType(99) q=\"ClientAuthType(99)\"",
    "x509.SigAlg/0                v=0 s=0 q=\"0\"",
    "x509.SigAlg/4                v=SHA256-RSA s=SHA256-RSA q=\"SHA256-RSA\"",
    "x509.SigAlg/11               v=ECDSA-SHA384 s=ECDSA-SHA384 q=\"ECDSA-SHA384\"",
    "x509.SigAlg/16               v=Ed25519 s=Ed25519 q=\"Ed25519\"",
    "x509.SigAlg/99               v=99 s=99 q=\"99\"",
    "x509.PubAlg/0                v=0 s=0 q=\"0\"",
    "x509.PubAlg/1                v=RSA s=RSA q=\"RSA\"",
    "x509.PubAlg/3                v=ECDSA s=ECDSA q=\"ECDSA\"",
    "x509.PubAlg/4                v=Ed25519 s=Ed25519 q=\"Ed25519\"",
    "x509.PubAlg/99               v=99 s=99 q=\"99\"",
    "x509.OID/1.2.840.113549.1.1.11 v=1.2.840.113549.1.1.11 s=1.2.840.113549.1.1.11 q=\"1.2.840.113549.1.1.11\"",
    "x509.OID/2.5.4.3             v=2.5.4.3 s=2.5.4.3 q=\"2.5.4.3\"",
    "x509.OID/1.2.3               v=1.2.3 s=1.2.3 q=\"1.2.3\"",
    "pkix.RDNSequence             v=CN=example,O=Org,C=GB s=CN=example,O=Org,C=GB q=\"CN=example,O=Org,C=GB\"",
    "pkix.RDNSequence/empty       v= s= q=\"\"",
    "json.Number/1                v=1 s=1 q=\"1\"",
    "json.Number/-2.5             v=-2.5 s=-2.5 q=\"-2.5\"",
    "json.Number/1e10             v=1e10 s=1e10 q=\"1e10\"",
    "json.Number/<empty>          v= s= q=\"\"",
    "json.Number/not-a-number     v=not-a-number s=not-a-number q=\"not-a-number\"",
    "slog.Attr/k                  v=k=v s=k=v q=\"k=v\"",
    "slog.Attr/n                  v=n=42 s=n=42 q=\"n=42\"",
    "slog.Attr/b                  v=b=true s=b=true q=\"b=true\"",
    "slog.Attr/<empty>            v==<nil> s==<nil> q=\"=<nil>\"",
    "slog.Attr/<empty>            v== s== q=\"=\"",
    "scanner.Position/3:7         v=f.go:3:7 s=f.go:3:7 q=\"f.go:3:7\"",
    "scanner.Position/1:1         v=<input>:1:1 s=<input>:1:1 q=\"<input>:1:1\"",
    "scanner.Position/0:0         v=f.go s=f.go q=\"f.go\"",
];

fn chk(failed: &mut int, ln: &mut int, got: string) {
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *failed += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *failed += 1;
}

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn qe(x: &str) -> string {
    if x == "" {
        return s("<empty>");
    }
    return s(x);
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    for spec in ["192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1", ""] {
        let ip = net::ParseIP(s(spec));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-28s v=%v s=%s q=%q nil=%v",
                string::from("net.IP/") + qe(spec),
                ip.clone(),
                ip.clone(),
                ip.clone(),
                ip.IsNil()
            ),
        );
    }
    let masks: [net::IPMask; 5] = [
        net::CIDRMask(24, 32),
        net::CIDRMask(0, 32),
        net::CIDRMask(32, 32),
        net::CIDRMask(64, 128),
        net::IPMask {
            bytes: slice::__from_vec(alloc::vec![]),
        },
    ];
    for m in masks.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-28s v=%v s=%s q=%q",
                fmt::Sprintf!("net.IPMask/%d", m.bytes.Len()),
                m.clone(),
                m.clone(),
                m.clone()
            ),
        );
    }
    for spec in [
        "192.0.2.1",
        "2001:db8::1",
        "::ffff:192.0.2.1",
        "192.0.2.1%eth0",
    ] {
        let (a, e) = netip::ParseAddr(s(spec));
        if e != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "%-28s parse-err=%q",
                    string::from("netip.Addr/") + s(spec),
                    e.Error()
                ),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-28s v=%v s=%s q=%q",
                string::from("netip.Addr/") + s(spec),
                a,
                a,
                a
            ),
        );
    }
    let za = netip::Addr::default();
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!("%-28s v=%v s=%s q=%q", s("netip.Addr/zero"), za, za, za),
    );
    for spec in ["192.0.2.1:80", "[2001:db8::1]:443"] {
        let (ap, _) = netip::ParseAddrPort(s(spec));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-28s v=%v s=%s q=%q",
                string::from("netip.AddrPort/") + s(spec),
                ap,
                ap,
                ap
            ),
        );
    }
    let zap = netip::AddrPort::default();
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "%-28s v=%v s=%s q=%q",
            s("netip.AddrPort/zero"),
            zap,
            zap,
            zap
        ),
    );
    for spec in ["192.0.2.0/24", "2001:db8::/32", "0.0.0.0/0"] {
        let (p, _) = netip::ParsePrefix(s(spec));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-28s v=%v s=%s q=%q",
                string::from("netip.Prefix/") + s(spec),
                p,
                p,
                p
            ),
        );
    }
    let zp = netip::Prefix::default();
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!("%-28s v=%v s=%s q=%q", s("netip.Prefix/zero"), zp, zp, zp),
    );
    let hashes: [crypto::Hash; 7] = [
        crypto::Hash(0),
        crypto::MD5,
        crypto::SHA1,
        crypto::SHA256,
        crypto::SHA512,
        crypto::SHA3_256,
        crypto::Hash(99),
    ];
    for h in hashes.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-28s v=%v s=%s q=%q",
                fmt::Sprintf!("crypto.Hash/%d", h.0 as int),
                *h,
                *h,
                *h
            ),
        );
    }
    let schemes: [tls::SignatureScheme; 6] = [
        tls::PKCS1WithSHA256,
        tls::ECDSAWithP256AndSHA256,
        tls::Ed25519,
        tls::PSSWithSHA512,
        tls::SignatureScheme(0),
        tls::SignatureScheme(0xffff),
    ];
    for sc in schemes.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-28s v=%v s=%s q=%q",
                fmt::Sprintf!("tls.SignatureScheme/%04x", sc.0),
                *sc,
                *sc,
                *sc
            ),
        );
    }
    let curves: [tls::CurveID; 6] = [
        tls::CurveP256,
        tls::CurveP384,
        tls::CurveP521,
        tls::X25519,
        tls::CurveID(0),
        tls::CurveID(9999),
    ];
    for c in curves.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-28s v=%v s=%s q=%q",
                fmt::Sprintf!("tls.CurveID/%d", c.0),
                *c,
                *c,
                *c
            ),
        );
    }
    let auths: [tls::ClientAuthType; 4] = [
        tls::NoClientCert,
        tls::RequestClientCert,
        tls::RequireAndVerifyClientCert,
        tls::ClientAuthType(99),
    ];
    for a in auths.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-28s v=%v s=%s q=%q",
                fmt::Sprintf!("tls.ClientAuthType/%d", a.0 as int),
                *a,
                *a,
                *a
            ),
        );
    }
    let sigalgs: [x509::SignatureAlgorithm; 5] = [
        x509::UnknownSignatureAlgorithm,
        x509::SHA256WithRSA,
        x509::ECDSAWithSHA384,
        x509::PureEd25519,
        x509::SignatureAlgorithm(99),
    ];
    for a in sigalgs.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-28s v=%v s=%s q=%q",
                fmt::Sprintf!("x509.SigAlg/%d", a.0 as int),
                *a,
                *a,
                *a
            ),
        );
    }
    let pubalgs: [x509::PublicKeyAlgorithm; 5] = [
        x509::UnknownPublicKeyAlgorithm,
        x509::RSA,
        x509::ECDSA,
        x509::Ed25519,
        x509::PublicKeyAlgorithm(99),
    ];
    for a in pubalgs.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-28s v=%v s=%s q=%q",
                fmt::Sprintf!("x509.PubAlg/%d", a.0 as int),
                *a,
                *a,
                *a
            ),
        );
    }
    let oids: [(&str, &[u64]); 3] = [
        ("1.2.840.113549.1.1.11", &[1, 2, 840, 113549, 1, 1, 11]),
        ("2.5.4.3", &[2, 5, 4, 3]),
        ("1.2.3", &[1, 2, 3]),
    ];
    for (name, ints) in oids.iter() {
        let (oid, e) = x509::OIDFromInts(slice::<u64>::__from_vec(ints.to_vec()));
        if e != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "%-28s err=%q",
                    string::from("x509.OID/") + s(name),
                    e.Error()
                ),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-28s v=%v s=%s q=%q",
                string::from("x509.OID/") + s(name),
                oid.clone(),
                oid.clone(),
                oid.clone()
            ),
        );
    }
    {
        let mut n = pkix::Name::default();
        n.CommonName = s("example");
        n.Country = slice::__from_vec(alloc::vec![s("GB")]);
        n.Organization = slice::__from_vec(alloc::vec![s("Org")]);
        let rdn = n.ToRDNSequence();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-28s v=%v s=%s q=%q",
                s("pkix.RDNSequence"),
                rdn.clone(),
                rdn.clone(),
                rdn.clone()
            ),
        );
        let empty = pkix::RDNSequence::default();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-28s v=%v s=%s q=%q",
                s("pkix.RDNSequence/empty"),
                empty.clone(),
                empty.clone(),
                empty
            ),
        );
    }
    for nv in ["1", "-2.5", "1e10", "", "not-a-number"] {
        let n = json::Number(s(nv));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-28s v=%v s=%s q=%q",
                string::from("json.Number/") + qe(nv),
                n.clone(),
                n.clone(),
                n.clone()
            ),
        );
    }
    let attrs: [slog::Attr; 5] = [
        slog::String(s("k"), s("v")),
        slog::Int(s("n"), 42),
        slog::Bool(s("b"), true),
        slog::Attr::default(),
        slog::String(string::new(), string::new()),
    ];
    for a in attrs.iter() {
        let key = a.Key.clone();
        let shown = if key.Len() == 0 { s("<empty>") } else { key };
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-28s v=%v s=%s q=%q",
                string::from("slog.Attr/") + shown,
                a.clone(),
                a.clone(),
                a.clone()
            ),
        );
    }
    let positions: [scanner::Position; 3] = [
        scanner::Position {
            Filename: s("f.go"),
            Offset: 10,
            Line: 3,
            Column: 7,
        },
        scanner::Position {
            Filename: string::new(),
            Offset: 0,
            Line: 1,
            Column: 1,
        },
        scanner::Position {
            Filename: s("f.go"),
            Offset: 0,
            Line: 0,
            Column: 0,
        },
    ];
    for p in positions.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-28s v=%v s=%s q=%q",
                fmt::Sprintf!("scanner.Position/%d:%d", p.Line, p.Column),
                p.clone(),
                p.clone(),
                p.clone()
            ),
        );
    }
    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
