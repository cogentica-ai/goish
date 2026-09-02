// dnsmessage_ref_smoke — net/dnsmessage against a running Go.
// (vendor/golang.org/x/net/dns/dnsmessage/message.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_dnsmessage_ref.go` run in
// `package dnsmessage` by `scripts/goref.sh`.
//
// This package parses bytes that arrive from the network, from a server
// nobody in the process chose to trust, and goish had 1971 lines of it
// with ZERO anchors. Its whole job is to refuse hostile input without
// reading outside the buffer or looping forever, and each refusal is a
// specific error — a port that answers "some error" to all of them
// looks fine on a happy path and says nothing when it matters.
//
// The compression pointer is the sharp edge. A name may jump backwards
// to a prior offset, so a message can encode a cycle, a jump past the
// end, or a chain that makes progress forever. Go bounds this three
// ways, and all three are pinned below:
//
//   * a pointer must point BACKWARDS (a forward one runs off the end
//     and is refused as insufficient data, not followed),
//   * at most 10 pointers per name — a chain of 10 resolves, 11 is
//     "too many pointers (>10)",
//   * the two reserved prefix bits (0x80, 0x40) are refused outright.
//
// A legal backward pointer must still WORK: case 4 packs two questions
// where the second reuses the first name, because refusing that would
// break real DNS.
//
// The other half is packing. Compression is the part a port is most
// likely to skip, so both packed LENGTHS are pinned. That is what
// caught this file's one defect: SOAResource packed its NS and MBox
// names with no compression map, making every SOA answer 12 bytes
// longer than Go's for the same record. Wire-valid, so nothing failed
// visibly — but DNS over UDP is size-bounded, and a response Go fits
// in a datagram is one goish could push over the limit.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::string::String;
use alloc::vec::Vec;
use goish::gostring::string;
use goish::net::dnsmessage as dm;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: the reference lines, in the order Go printed
//     them. Comparing whole rendered lines keeps this smoke and the
//     generator in lockstep: a case added to one is a mismatch in the
//     other, never a silent pass.
const GO: [&str; 99] = [
    "newname len=1    -> \".\"",
    "newname len=2    -> \"a.\"",
    "newname len=7    -> \"go.dev.\"",
    "newname len=8    -> \"a.b.c.d.\"",
    "newname len=0    -> \"\"",
    "newname len=6    -> \"go.dev\"",
    "newname len=5    -> \"a\\\\.b.\"",
    "newname len=5    -> \"a\\\\\\\\b.\"",
    "newname len=5    -> \"\\\\255.\"",
    "newname len=5    -> \"\\\\256.\"",
    "newname len=3    -> \"\\\\0.\"",
    "newname len=255  -> \"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00.\"",
    "newname len=256  -> err=\"insufficient data for calculated length type\"",
    "escape 016100                 -> \"a.\" len=2",
    "escape 03612e6200             -> err=\"unpacking Question.Name: invalid dns name\"",
    "escape 015c00                 -> \"\\\\.\" len=2",
    "escape 010000                 -> \"\\x00.\" len=2",
    "escape 01ff00                 -> \"\\xff.\" len=2",
    "escape 012000                 -> \" .\" len=2",
    "escape 017e00                 -> \"~.\" len=2",
    "escape 017f00                 -> \"\\x7f.\" len=2",
    "ptr self-pointer       -> err=\"unpacking Question.Name: too many pointers (>10)\"",
    "ptr forward-pointer    -> err=\"unpacking Question.Name: insufficient data for base length type\"",
    "ptr pointer-past-end   -> err=\"unpacking Question.Name: insufficient data for base length type\"",
    "ptr pointer-to-header  -> ok \".\"",
    "ptr reserved-0x80      -> err=\"unpacking Question.Name: segment prefix is reserved\"",
    "ptr reserved-0x40      -> err=\"unpacking Question.Name: segment prefix is reserved\"",
    "ptr truncated-label    -> err=\"unpacking Question.Name: insufficient data for calculated length type\"",
    "ptr no-terminator      -> err=\"unpacking Question.Name: insufficient data for base length type\"",
    "ptr empty              -> err=\"unpacking Question.Name: insufficient data for base length type\"",
    "ptr label-too-long     -> ok \"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00.\"",
    "compress q1=\"go.dev.\" e1=<nil> q2=\"go.dev.\" e2=<nil>",
    "chain hops=2   -> ok \"a.b.\"",
    "chain hops=10  -> ok \"a.b.c.d.e.f.g.h.i.j.\"",
    "chain hops=11  -> err=\"unpacking Question.Name: too many pointers (>10)\"",
    "chain hops=20  -> err=\"unpacking Question.Name: too many pointers (>10)\"",
    "pack compress=false -> len=257",
    "  walk compress=false hdr id=4660 rcode=0 qr=true",
    "  walk compress=false q \"go.dev.\" type=1 class=1",
    "  walk compress=false q \"go.dev.\" type=28 class=1",
    "  walk compress=false a \"go.dev.\" type=1 ttl=300 A=1.2.3.4",
    "  walk compress=false a \"go.dev.\" type=5 ttl=60 CNAME=\"alias.go.dev.\"",
    "  walk compress=false a \"go.dev.\" type=16 ttl=60 TXT=\"hello|world\"",
    "  walk compress=false a \"go.dev.\" type=15 ttl=60 MX=10,\"mail.go.dev.\"",
    "  walk compress=false a \"go.dev.\" type=33 ttl=60 SRV=1,2,443,\"srv.go.dev.\"",
    "  walk compress=false a \"go.dev.\" type=6 ttl=60 SOA=\"ns.go.dev.\",\"hostmaster.go.dev.\",1,2,3,4,5",
    "  walk compress=false done",
    "pack compress=true  -> len=191",
    "  walk compress=true  hdr id=4660 rcode=0 qr=true",
    "  walk compress=true  q \"go.dev.\" type=1 class=1",
    "  walk compress=true  q \"go.dev.\" type=28 class=1",
    "  walk compress=true  a \"go.dev.\" type=1 ttl=300 A=1.2.3.4",
    "  walk compress=true  a \"go.dev.\" type=5 ttl=60 CNAME=\"alias.go.dev.\"",
    "  walk compress=true  a \"go.dev.\" type=16 ttl=60 TXT=\"hello|world\"",
    "  walk compress=true  a \"go.dev.\" type=15 ttl=60 MX=10,\"mail.go.dev.\"",
    "  walk compress=true  a \"go.dev.\" type=33 ttl=60 SRV=1,2,443,\"srv.go.dev.\"",
    "  walk compress=true  a \"go.dev.\" type=6 ttl=60 SOA=\"ns.go.dev.\",\"hostmaster.go.dev.\",1,2,3,4,5",
    "  walk compress=true  done",
    "truncate full=245 firstOK=245 distinct-errors=37",
    "  trunc-err Class: insufficient data for base length type            x12",
    "  trunc-err Expire: insufficient data for base length type           x4",
    "  trunc-err Length: insufficient data for base length type           x12",
    "  trunc-err MBox: insufficient data for base length type             x4",
    "  trunc-err MBox: insufficient data for calculated length type       x15",
    "  trunc-err MX: insufficient data for base length type               x4",
    "  trunc-err MX: insufficient data for calculated length type         x9",
    "  trunc-err MinTTL: insufficient data for base length type           x4",
    "  trunc-err NS: insufficient data for base length type               x4",
    "  trunc-err NS: insufficient data for calculated length type         x7",
    "  trunc-err Name: insufficient data for base length type             x18",
    "  trunc-err Name: insufficient data for calculated length type       x30",
    "  trunc-err Port: insufficient data for base length type             x2",
    "  trunc-err Pref: insufficient data for base length type             x2",
    "  trunc-err Priority: insufficient data for base length type         x2",
    "  trunc-err Refresh: insufficient data for base length type          x4",
    "  trunc-err Retry: insufficient data for base length type            x4",
    "  trunc-err Serial: insufficient data for base length type           x4",
    "  trunc-err TTL: insufficient data for base length type              x24",
    "  trunc-err Target: insufficient data for base length type           x4",
    "  trunc-err Target: insufficient data for calculated length type     x8",
    "  trunc-err Type: insufficient data for base length type             x12",
    "  trunc-err Weight: insufficient data for base length type           x2",
    "  trunc-err insufficient data for base length type                   x8",
    "  trunc-err insufficient data for calculated length type             x10",
    "  trunc-err text: insufficient data for base length type             x2",
    "  trunc-err text: insufficient data for calculated length type       x10",
    "  trunc-err unpacking Question.Class: insufficient data for base length type x2",
    "  trunc-err unpacking Question.Name: insufficient data for base length type x3",
    "  trunc-err unpacking Question.Name: insufficient data for calculated length type x5",
    "  trunc-err unpacking Question.Type: insufficient data for base length type x2",
    "  trunc-err unpacking header: additionals: insufficient data for base length type x2",
    "  trunc-err unpacking header: answers: insufficient data for base length type x2",
    "  trunc-err unpacking header: authorities: insufficient data for base length type x2",
    "  trunc-err unpacking header: bits: insufficient data for base length type x2",
    "  trunc-err unpacking header: id: insufficient data for base length type x2",
    "  trunc-err unpacking header: questions: insufficient data for base length type x2",
    "state answer-before-question err=parsing/packing of this type isn't available yet",
    "state wrong-body type=1 err=parsing/packing of this type isn't available yet",
    "state question-after-done err=parsing/packing of this section has completed",
];

// go: none — goish idiom: one comparison, printing the divergence when
//     it is one, so a FAIL says what it got and not just that it did.
fn chk(failed: &mut int, n: &mut int, got: string) {
    if *n >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *n + 1, got);
        *failed += 1;
        *n += 1;
        return;
    }
    let want = s(GO[*n as usize]);
    *n += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *n, got, want);
    *failed += 1;
}

fn hdr(qd: u16, an: u16) -> Vec<u8> {
    return alloc::vec![
        0,
        1,
        0,
        0,
        (qd >> 8) as u8,
        qd as u8,
        (an >> 8) as u8,
        an as u8,
        0,
        0,
        0,
        0
    ];
}

fn walk(msg: Vec<u8>) -> Vec<string> {
    let mut out: Vec<string> = Vec::new();
    let mut p = dm::Parser::new();
    let (h, err) = p.Start(msg);
    if err != goish::errors::nil {
        out.push(fmt::Sprintf!("%s", err.Error()));
        return out;
    }
    out.push(fmt::Sprintf!(
        "hdr id=%d rcode=%d qr=%v",
        h.ID as i64,
        h.RCode as i64,
        h.Response
    ));
    loop {
        let (q, err) = p.Question();
        if err == dm::ErrSectionDone {
            break;
        }
        if err != goish::errors::nil {
            out.push(fmt::Sprintf!("%s", err.Error()));
            return out;
        }
        out.push(fmt::Sprintf!(
            "q %q type=%d class=%d",
            q.Name.String(),
            q.Type as i64,
            q.Class as i64
        ));
    }
    loop {
        let (rh, err) = p.AnswerHeader();
        if err == dm::ErrSectionDone {
            break;
        }
        if err != goish::errors::nil {
            out.push(fmt::Sprintf!("%s", err.Error()));
            return out;
        }
        let mut line = fmt::Sprintf!(
            "a %q type=%d ttl=%d",
            rh.Name.String(),
            rh.Type as i64,
            rh.TTL as i64
        );
        let berr;
        if rh.Type == dm::TypeA {
            let (r, e) = p.AResource();
            berr = e;
            line = line
                + fmt::Sprintf!(
                    " A=%d.%d.%d.%d",
                    r.A[0] as i64,
                    r.A[1] as i64,
                    r.A[2] as i64,
                    r.A[3] as i64
                );
        } else if rh.Type == dm::TypeCNAME {
            let (r, e) = p.CNAMEResource();
            berr = e;
            line = line + fmt::Sprintf!(" CNAME=%q", r.CNAME.String());
        } else if rh.Type == dm::TypeTXT {
            let (r, e) = p.TXTResource();
            berr = e;
            let mut joined = string::default();
            for (i, tx) in r.TXT.iter().enumerate() {
                if i > 0 {
                    joined = joined + s("|");
                }
                joined = joined + s(tx.as_str());
            }
            line = line + fmt::Sprintf!(" TXT=%q", joined);
        } else if rh.Type == dm::TypeMX {
            let (r, e) = p.MXResource();
            berr = e;
            line = line + fmt::Sprintf!(" MX=%d,%q", r.Pref as i64, r.MX.String());
        } else if rh.Type == dm::TypeSRV {
            let (r, e) = p.SRVResource();
            berr = e;
            line = line
                + fmt::Sprintf!(
                    " SRV=%d,%d,%d,%q",
                    r.Priority as i64,
                    r.Weight as i64,
                    r.Port as i64,
                    r.Target.String()
                );
        } else if rh.Type == dm::TypeSOA {
            let (r, e) = p.SOAResource();
            berr = e;
            line = line
                + fmt::Sprintf!(
                    " SOA=%q,%q,%d,%d,%d,%d,%d",
                    r.NS.String(),
                    r.MBox.String(),
                    r.Serial as i64,
                    r.Refresh as i64,
                    r.Retry as i64,
                    r.Expire as i64,
                    r.MinTTL as i64
                );
        } else {
            berr = p.SkipAnswer();
        }
        if berr != goish::errors::nil {
            out.push(fmt::Sprintf!("%s", berr.Error()));
            return out;
        }
        out.push(line);
    }
    out.push(s("done"));
    return out;
}

fn pack_ref(qs: &[dm::Question], compress: bool) -> (Vec<u8>, goish::errors::error) {
    let h = dm::Header {
        ID: 0x1234,
        Response: true,
        Authoritative: true,
        RecursionDesired: true,
        ..Default::default()
    };
    let mut b = dm::NewBuilder(Vec::new(), h);
    if compress {
        b.EnableCompression();
    }
    let e = b.StartQuestions();
    if e != goish::errors::nil {
        return (Vec::new(), e);
    }
    for q in qs {
        let e = b.Question(q.clone());
        if e != goish::errors::nil {
            return (Vec::new(), e);
        }
    }
    let e = b.StartAnswers();
    if e != goish::errors::nil {
        return (Vec::new(), e);
    }
    let mk = |t: dm::Type, ttl: u32| dm::ResourceHeader {
        Name: dm::MustNewName("go.dev."),
        Type: t,
        Class: dm::ClassINET,
        TTL: ttl,
        Length: 0,
    };
    let e = b.AResource(mk(dm::TypeA, 300), dm::AResource { A: [1, 2, 3, 4] });
    if e != goish::errors::nil {
        return (Vec::new(), e);
    }
    let e = b.CNAMEResource(
        mk(dm::TypeCNAME, 60),
        dm::CNAMEResource {
            CNAME: dm::MustNewName("alias.go.dev."),
        },
    );
    if e != goish::errors::nil {
        return (Vec::new(), e);
    }
    let e = b.TXTResource(
        mk(dm::TypeTXT, 60),
        dm::TXTResource {
            TXT: alloc::vec![String::from("hello"), String::from("world")],
        },
    );
    if e != goish::errors::nil {
        return (Vec::new(), e);
    }
    let e = b.MXResource(
        mk(dm::TypeMX, 60),
        dm::MXResource {
            Pref: 10,
            MX: dm::MustNewName("mail.go.dev."),
        },
    );
    if e != goish::errors::nil {
        return (Vec::new(), e);
    }
    let e = b.SRVResource(
        mk(dm::TypeSRV, 60),
        dm::SRVResource {
            Priority: 1,
            Weight: 2,
            Port: 443,
            Target: dm::MustNewName("srv.go.dev."),
        },
    );
    if e != goish::errors::nil {
        return (Vec::new(), e);
    }
    let e = b.SOAResource(
        mk(dm::TypeSOA, 60),
        dm::SOAResource {
            NS: dm::MustNewName("ns.go.dev."),
            MBox: dm::MustNewName("hostmaster.go.dev."),
            Serial: 1,
            Refresh: 2,
            Retry: 3,
            Expire: 4,
            MinTTL: 5,
        },
    );
    if e != goish::errors::nil {
        return (Vec::new(), e);
    }
    return b.Finish();
}

#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut n: int = 0;

    // 1. NewName
    let mut long254: Vec<u8> = alloc::vec![0u8; 254];
    long254.push(b'.');
    let mut long255: Vec<u8> = alloc::vec![0u8; 255];
    long255.push(b'.');
    let mut names: Vec<Vec<u8>> = Vec::new();
    for lit in [
        ".", "a.", "go.dev.", "a.b.c.d.", "", "go.dev", "a\\.b.", "a\\\\b.", "\\255.", "\\256.",
        "\\0.",
    ] {
        names.push(lit.as_bytes().to_vec());
    }
    names.push(long254);
    names.push(long255);
    for nm in names.iter() {
        let as_str = unsafe { core::str::from_utf8_unchecked(nm) };
        let (parsed, err) = dm::NewName(as_str);
        if err != goish::errors::nil {
            chk(
                &mut failed,
                &mut n,
                fmt::Sprintf!("newname len=%-4d -> err=%q", nm.len() as i64, err.Error()),
            );
        } else {
            chk(
                &mut failed,
                &mut n,
                fmt::Sprintf!("newname len=%-4d -> %q", nm.len() as i64, parsed.String()),
            );
        }
    }
    // 2. escapes
    for raw in [
        &[1u8, b'a', 0][..],
        &[3, b'a', b'.', b'b', 0][..],
        &[1, b'\\', 0][..],
        &[1, 0, 0][..],
        &[1, 255, 0][..],
        &[1, b' ', 0][..],
        &[1, b'~', 0][..],
        &[1, 0x7f, 0][..],
    ] {
        let mut msg = hdr(1, 0);
        msg.extend_from_slice(raw);
        msg.extend_from_slice(&[0, 1, 0, 1]);
        const HEX: &[u8] = b"0123456789abcdef";
        let mut hxb: Vec<u8> = Vec::new();
        for b in raw {
            hxb.push(HEX[(b >> 4) as usize]);
            hxb.push(HEX[(b & 0xf) as usize]);
        }
        let hx = string::from_bytes(&hxb);
        let mut p = dm::Parser::new();
        let (_, err) = p.Start(msg);
        if err != goish::errors::nil {
            chk(
                &mut failed,
                &mut n,
                fmt::Sprintf!("escape %-22s -> start err=%q", hx.clone(), err.Error()),
            );
            continue;
        }
        let (q, err) = p.Question();
        if err != goish::errors::nil {
            chk(
                &mut failed,
                &mut n,
                fmt::Sprintf!("escape %-22s -> err=%q", hx.clone(), err.Error()),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut n,
            fmt::Sprintf!(
                "escape %-22s -> %q len=%d",
                hx.clone(),
                q.Name.String(),
                q.Name.Length as i64
            ),
        );
    }
    // 3. pointers
    let mut big = alloc::vec![63u8];
    big.extend_from_slice(&[0u8; 63]);
    big.extend_from_slice(&[0, 0, 1, 0, 1]);
    let cases: [(&str, Vec<u8>); 10] = [
        ("self-pointer", alloc::vec![0xC0, 0x0C, 0, 1, 0, 1]),
        ("forward-pointer", alloc::vec![0xC0, 0x20, 0, 1, 0, 1]),
        ("pointer-past-end", alloc::vec![0xC0, 0xFF, 0, 1, 0, 1]),
        ("pointer-to-header", alloc::vec![0xC0, 0x00, 0, 1, 0, 1]),
        ("reserved-0x80", alloc::vec![0x80, 0, 0, 1, 0, 1]),
        ("reserved-0x40", alloc::vec![0x40, 0, 0, 1, 0, 1]),
        ("truncated-label", alloc::vec![5, b'a', b'b']),
        ("no-terminator", alloc::vec![1, b'a']),
        ("empty", alloc::vec![]),
        ("label-too-long", big),
    ];
    for (name, body) in cases.iter() {
        let mut msg = hdr(1, 0);
        msg.extend_from_slice(body);
        let mut p = dm::Parser::new();
        let (_, err) = p.Start(msg);
        if err != goish::errors::nil {
            chk(
                &mut failed,
                &mut n,
                fmt::Sprintf!("ptr %-18s -> start err=%q", s(name), err.Error()),
            );
            continue;
        }
        let (q, err) = p.Question();
        if err != goish::errors::nil {
            chk(
                &mut failed,
                &mut n,
                fmt::Sprintf!("ptr %-18s -> err=%q", s(name), err.Error()),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut n,
            fmt::Sprintf!("ptr %-18s -> ok %q", s(name), q.Name.String()),
        );
    }
    // 4. legal backward pointer
    {
        let mut msg = hdr(2, 0);
        msg.extend_from_slice(&[2, b'g', b'o', 3, b'd', b'e', b'v', 0, 0, 1, 0, 1]);
        msg.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        let mut p = dm::Parser::new();
        let (_, err) = p.Start(msg);
        if err != goish::errors::nil {
            chk(
                &mut failed,
                &mut n,
                fmt::Sprintf!("compress start err=%q", err.Error()),
            );
        } else {
            let (q1, e1) = p.Question();
            let (q2, e2) = p.Question();
            chk(
                &mut failed,
                &mut n,
                fmt::Sprintf!(
                    "compress q1=%q e1=%v q2=%q e2=%v",
                    q1.Name.String(),
                    e1,
                    q2.Name.String(),
                    e2
                ),
            );
        }
    }
    // 5. pointer chains
    for hops in [2usize, 10, 11, 20] {
        let msg = build_chain(hops);
        let mut p = dm::Parser::new();
        let (_, err) = p.Start(msg);
        if err != goish::errors::nil {
            chk(
                &mut failed,
                &mut n,
                fmt::Sprintf!("chain hops=%-3d -> start err=%q", hops as i64, err.Error()),
            );
            continue;
        }
        let (q, err) = p.Question();
        if err != goish::errors::nil {
            chk(
                &mut failed,
                &mut n,
                fmt::Sprintf!("chain hops=%-3d -> err=%q", hops as i64, err.Error()),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut n,
            fmt::Sprintf!("chain hops=%-3d -> ok %q", hops as i64, q.Name.String()),
        );
    }
    // 6. round trip
    for compress in [false, true] {
        let qs = alloc::vec![
            dm::Question {
                Name: dm::MustNewName("go.dev."),
                Type: dm::TypeA,
                Class: dm::ClassINET
            },
            dm::Question {
                Name: dm::MustNewName("go.dev."),
                Type: dm::TypeAAAA,
                Class: dm::ClassINET
            }
        ];
        let (b, err) = pack_ref(&qs, compress);
        if err != goish::errors::nil {
            chk(
                &mut failed,
                &mut n,
                fmt::Sprintf!("pack compress=%-5v -> err=%q", compress, err.Error()),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut n,
            fmt::Sprintf!("pack compress=%-5v -> len=%d", compress, b.len() as i64),
        );
        for line in walk(b).iter() {
            chk(
                &mut failed,
                &mut n,
                fmt::Sprintf!("  walk compress=%-5v %s", compress, line.clone()),
            );
        }
    }
    // 7. truncation
    {
        let qs = alloc::vec![dm::Question {
            Name: dm::MustNewName("go.dev."),
            Type: dm::TypeA,
            Class: dm::ClassINET
        }];
        let (b, _) = pack_ref(&qs, false);
        let mut first_ok: i64 = -1;
        let mut errs: Vec<(string, i64)> = Vec::new();
        for i in 0..=b.len() {
            let lines = walk(b[..i].to_vec());
            let last = lines[lines.len() - 1].clone();
            if last == s("done") {
                if first_ok < 0 {
                    first_ok = i as i64;
                }
                continue;
            }
            match errs.iter_mut().find(|(k, _)| *k == last) {
                Some((_, c)) => {
                    *c += 1;
                }
                None => {
                    errs.push((last, 1));
                }
            }
        }
        // Same hand-rolled sort as the Go side, so the ordering cannot
        // come from two different comparators.
        for i in 0..errs.len() {
            for j in (i + 1)..errs.len() {
                if errs[j].0.as_bytes() < errs[i].0.as_bytes() {
                    errs.swap(i, j);
                }
            }
        }
        chk(
            &mut failed,
            &mut n,
            fmt::Sprintf!(
                "truncate full=%d firstOK=%d distinct-errors=%d",
                b.len() as i64,
                first_ok,
                errs.len() as i64
            ),
        );
        for (k, c) in errs.iter() {
            chk(
                &mut failed,
                &mut n,
                fmt::Sprintf!("  trunc-err %-56s x%d", k.clone(), *c),
            );
        }
    }
    // 8. section state machine
    {
        let qs = alloc::vec![dm::Question {
            Name: dm::MustNewName("go.dev."),
            Type: dm::TypeA,
            Class: dm::ClassINET
        }];
        let (b, _) = pack_ref(&qs, false);
        let mut p = dm::Parser::new();
        let _ = p.Start(b.clone());
        let (_, e1) = p.AnswerHeader();
        chk(
            &mut failed,
            &mut n,
            fmt::Sprintf!("state answer-before-question err=%v", e1),
        );
        let mut p2 = dm::Parser::new();
        let _ = p2.Start(b.clone());
        let _ = p2.SkipAllQuestions();
        let (h, _) = p2.AnswerHeader();
        let (_, e2) = p2.AAAAResource();
        chk(
            &mut failed,
            &mut n,
            fmt::Sprintf!("state wrong-body type=%d err=%v", h.Type as i64, e2),
        );
        let mut p3 = dm::Parser::new();
        let _ = p3.Start(b);
        let _ = p3.SkipAllQuestions();
        let _ = p3.SkipAllAnswers();
        let (_, e3) = p3.Question();
        chk(
            &mut failed,
            &mut n,
            fmt::Sprintf!("state question-after-done err=%v", e3),
        );
    }
    if n != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", n, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", n, n);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, n);
    syscall::Exit(1);
}

fn build_chain(hops: usize) -> Vec<u8> {
    let mut msg = hdr(1, 0);
    let start = msg.len();
    msg.extend_from_slice(&[0xC0, 0]);
    msg.extend_from_slice(&[0, 1, 0, 1]);
    let mut offs: Vec<usize> = alloc::vec![0; hops];
    for i in 0..hops {
        offs[i] = msg.len();
        msg.push(1);
        msg.push(b'a' + (i % 26) as u8);
        msg.push(0xC0);
        msg.push(0);
    }
    let l = msg.len();
    msg[l - 2] = 0;
    msg[l - 1] = 0;
    msg.truncate(l - 1);
    for i in 0..hops.saturating_sub(1) {
        let p = offs[i] + 2;
        msg[p] = 0xC0 | ((offs[i + 1] >> 8) as u8);
        msg[p + 1] = offs[i + 1] as u8;
    }
    msg[start + 1] = offs[0] as u8;
    return msg;
}
