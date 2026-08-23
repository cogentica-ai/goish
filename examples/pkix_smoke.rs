// pkix_smoke — crypto/x509/pkix's Name <-> RDNSequence conversions and
// their RFC 2253 string forms, vs Go 1.25.5.
//
// Every expectation is `scripts/goref.sh crypto/x509/pkix` output, not a
// transcription. The cases pin what these functions actually decide:
//
//   * the ORDER ToRDNSequence emits (Country, Province, Locality,
//     StreetAddress, PostalCode, Organization, OrganizationalUnit, then
//     CommonName and SerialNumber) — a resequencing here changes the DER
//     of every certificate subject;
//   * that multi-value fields become ONE multi-entry RDN rather than
//     several single-entry ones;
//   * that an ExtraNames entry SUPPRESSES the standard field with the
//     same OID rather than appending to it — Go emits one RDN, not two;
//   * the `oid=#<hex>` form for an attribute OID with no short name.
//     That branch is the whole reason `String` was deferred a session:
//     it needs `asn1.Marshal(tv.Value)` on a type-erased value, and a
//     Marshal that merely errored would print `oid=<value>` and look
//     fine. Both spellings are checked against Go here, on the same
//     OID, so the two cannot be confused;
//   * every RFC 2253 escaping rule — the seven metacharacters, leading
//     and trailing space (by BYTE offset, so a multi-byte rune before a
//     trailing space does not defeat it) and leading `#`;
//   * that a value with no goish reflection FAILS LOUDLY rather than
//     reflecting as the invalid (nil) value. See `nonReflectable` below.

#![no_std]
#![no_main]
#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::crypto::x509::pkix::{
    AttributeTypeAndValue, Name, RDNSequence, RelativeDistinguishedNameSET,
};
use goish::encoding::asn1;
use goish::encoding::asn1::ObjectIdentifier;
use goish::goany::Any;
use goish::goslice::slice;
use goish::{fmt, reflect, string, strings};

static RAN: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(ok: bool, label: &'static str) {
    RAN.fetch_add(1, Ordering::AcqRel);
    if ok {
        fmt::Printf!("PASS: %s\n", string(label));
    } else {
        FAILED.fetch_add(1, Ordering::AcqRel);
        fmt::Printf!("FAIL: %s\n", string(label));
    }
}

/// `got == want`, printing both on a miss — a wrong DN string is far
/// easier to fix when the diff is on screen.
fn checkStr(got: goish::string, want: &'static str, label: &'static str) {
    RAN.fetch_add(1, Ordering::AcqRel);
    if got.as_bytes() == want.as_bytes() {
        fmt::Printf!("PASS: %s\n", string(label));
    } else {
        FAILED.fetch_add(1, Ordering::AcqRel);
        fmt::Printf!(
            "FAIL: %s\n  got  %q\n  want %q\n",
            string(label),
            got,
            string(want)
        );
    }
}

/// One RDN holding one attribute — the shape most String cases need.
fn one(t: ObjectIdentifier, v: Any) -> RDNSequence {
    let atv = AttributeTypeAndValue { Type: t, Value: v };
    let set = RelativeDistinguishedNameSET(slice::__from_vec(alloc::vec![atv]));
    return RDNSequence(slice::__from_vec(alloc::vec![set]));
}

/// `CN=<val>` — the escaping cases all run through a KNOWN OID, because
/// an unknown one would take the hex path and never escape anything.
fn cn(v: &'static str) -> goish::string {
    return one(oid(&[2, 5, 4, 3]), Any::new(string(v))).String();
}

/// A type with `PartialEq` (so it can sit in an `Any`) and deliberately
/// NO `Reflect` impl. `Any::new` would reject it at compile time; only
/// `Any::new_opaque` accepts it, and that is the point — "this value
/// cannot be reflected" is a property stated at the wrap site.
#[derive(PartialEq)]
struct nonReflectable {
    n: i64,
}

fn strs(v: &[&'static str]) -> slice<goish::string> {
    let mut out: alloc::vec::Vec<goish::string> = alloc::vec::Vec::new();
    for s in v.iter() {
        out.push(string(*s));
    }
    return slice::__from_vec(out);
}

fn oid(parts: &[i64]) -> ObjectIdentifier {
    return ObjectIdentifier::New(slice::__from_vec(parts.to_vec()));
}

/// `(oid string, value string)` for the j'th entry of the i'th RDN.
fn at(r: &RDNSequence, i: i64, j: i64) -> (goish::string, goish::string) {
    let rdn = r.0[i].clone();
    let atv = rdn.0[j].clone();
    let v = match atv.Value.As::<goish::string>() {
        Some(s) => s.clone(),
        None => goish::string::default(),
    };
    return (atv.Type.String(), v);
}

fn eq(got: (goish::string, goish::string), o: &'static str, v: &'static str) -> bool {
    return got.0.as_bytes() == o.as_bytes() && got.1.as_bytes() == v.as_bytes();
}

#[goish::main]
fn main() {
    let n = Name {
        Country: strs(&["US", "GB"]),
        Organization: strs(&["Acme"]),
        OrganizationalUnit: strs(&["Eng", "Ops"]),
        Locality: strs(&["Springfield"]),
        Province: strs(&["CA"]),
        StreetAddress: strs(&["1 Main St"]),
        PostalCode: strs(&["12345"]),
        CommonName: string("example.com"),
        SerialNumber: string("SN-1"),
        Names: slice::default(),
        ExtraNames: slice::default(),
    };

    let rdns = n.ToRDNSequence();
    check(rdns.0.Len() == 9, "ToRDNSequence emits 9 RDNs");

    // Order and grouping, straight from the Go reference.
    check(eq(at(&rdns, 0, 0), "2.5.4.6", "US"), "rdn[0][0] C=US");
    check(
        eq(at(&rdns, 0, 1), "2.5.4.6", "GB"),
        "rdn[0][1] C=GB (one multi-entry RDN)",
    );
    check(eq(at(&rdns, 1, 0), "2.5.4.8", "CA"), "rdn[1] ST=CA");
    check(
        eq(at(&rdns, 2, 0), "2.5.4.7", "Springfield"),
        "rdn[2] L=Springfield",
    );
    check(eq(at(&rdns, 3, 0), "2.5.4.9", "1 Main St"), "rdn[3] STREET");
    check(
        eq(at(&rdns, 4, 0), "2.5.4.17", "12345"),
        "rdn[4] POSTALCODE",
    );
    check(eq(at(&rdns, 5, 0), "2.5.4.10", "Acme"), "rdn[5] O=Acme");
    check(eq(at(&rdns, 6, 0), "2.5.4.11", "Eng"), "rdn[6][0] OU=Eng");
    check(eq(at(&rdns, 6, 1), "2.5.4.11", "Ops"), "rdn[6][1] OU=Ops");
    check(eq(at(&rdns, 7, 0), "2.5.4.3", "example.com"), "rdn[7] CN");
    check(
        eq(at(&rdns, 8, 0), "2.5.4.5", "SN-1"),
        "rdn[8] SERIALNUMBER",
    );

    // Round-trip back into a Name.
    let mut back = Name::default();
    back.FillFromRDNSequence(&rdns);
    check(
        back.Country.Len() == 2
            && back.Country[0].as_bytes() == b"US"
            && back.Country[1].as_bytes() == b"GB",
        "FillFromRDNSequence Country=[US GB]",
    );
    check(
        back.OrganizationalUnit.Len() == 2 && back.OrganizationalUnit[1].as_bytes() == b"Ops",
        "FillFromRDNSequence OU=[Eng Ops]",
    );
    check(back.Organization.Len() == 1, "FillFromRDNSequence O=[Acme]");
    check(
        back.Locality[0].as_bytes() == b"Springfield",
        "FillFromRDNSequence L",
    );
    check(
        back.Province[0].as_bytes() == b"CA",
        "FillFromRDNSequence ST",
    );
    check(
        back.StreetAddress[0].as_bytes() == b"1 Main St",
        "FillFromRDNSequence STREET",
    );
    check(
        back.PostalCode[0].as_bytes() == b"12345",
        "FillFromRDNSequence POSTALCODE",
    );
    check(
        back.CommonName.as_bytes() == b"example.com",
        "FillFromRDNSequence CN",
    );
    check(
        back.SerialNumber.as_bytes() == b"SN-1",
        "FillFromRDNSequence SERIALNUMBER",
    );
    // Go: back.Names len=11 — every attribute, flattened, grouping lost.
    check(
        back.Names.Len() == 11,
        "FillFromRDNSequence Names has all 11 flattened",
    );

    // An ExtraNames entry suppresses the standard field with the same OID.
    // Go emits ONE RDN here, not two.
    let extra = slice::__from_vec(alloc::vec![AttributeTypeAndValue {
        Type: oid(&[2, 5, 4, 6]),
        Value: Any::new(string("ZZ")),
    }]);
    let n2 = Name {
        Country: strs(&["US"]),
        ExtraNames: extra,
        ..Default::default()
    };
    let r2 = n2.ToRDNSequence();
    check(
        r2.0.Len() == 1,
        "ExtraNames suppresses the standard Country RDN",
    );
    check(eq(at(&r2, 0, 0), "2.5.4.6", "ZZ"), "ExtraNames value wins");

    // ── RDNSequence.String / Name.String ────────────────────────────
    //
    // Reference: `scripts/goref.sh crypto/x509/pkix`.

    checkStr(
        n.String(),
        "SERIALNUMBER=SN-1,CN=example.com,OU=Eng+OU=Ops,O=Acme,POSTALCODE=12345,\
         STREET=1 Main St,L=Springfield,ST=CA,C=US+C=GB",
        "Name.String — full standard name",
    );
    checkStr(
        rdns.String(),
        "SERIALNUMBER=SN-1,CN=example.com,OU=Eng+OU=Ops,O=Acme,POSTALCODE=12345,\
         STREET=1 Main St,L=Springfield,ST=CA,C=US+C=GB",
        "RDNSequence.String — same, via ToRDNSequence",
    );

    // The nine short names, one per attribute type.
    checkStr(
        one(oid(&[2, 5, 4, 6]), Any::new(string("v"))).String(),
        "C=v",
        "shortname C",
    );
    checkStr(
        one(oid(&[2, 5, 4, 10]), Any::new(string("v"))).String(),
        "O=v",
        "shortname O",
    );
    checkStr(
        one(oid(&[2, 5, 4, 11]), Any::new(string("v"))).String(),
        "OU=v",
        "shortname OU",
    );
    checkStr(
        one(oid(&[2, 5, 4, 3]), Any::new(string("v"))).String(),
        "CN=v",
        "shortname CN",
    );
    checkStr(
        one(oid(&[2, 5, 4, 5]), Any::new(string("v"))).String(),
        "SERIALNUMBER=v",
        "shortname SERIALNUMBER",
    );
    checkStr(
        one(oid(&[2, 5, 4, 7]), Any::new(string("v"))).String(),
        "L=v",
        "shortname L",
    );
    checkStr(
        one(oid(&[2, 5, 4, 8]), Any::new(string("v"))).String(),
        "ST=v",
        "shortname ST",
    );
    checkStr(
        one(oid(&[2, 5, 4, 9]), Any::new(string("v"))).String(),
        "STREET=v",
        "shortname STREET",
    );
    checkStr(
        one(oid(&[2, 5, 4, 17]), Any::new(string("v"))).String(),
        "POSTALCODE=v",
        "shortname POSTALCODE",
    );

    // ── the oid=#hex fallback — the branch String was deferred for ──
    //
    // 1.2.3.4 is in no short-name table, so Go marshals the value and
    // prints its DER in hex. `#130568656c6c6f` is PrintableString(5)
    // "hello"; `#02012a` is INTEGER 42. A Marshal that merely errored
    // would print `1.2.3.4=hello` here and look entirely plausible —
    // which is exactly the divergence these two lines exist to catch.
    checkStr(
        one(oid(&[1, 2, 3, 4]), Any::new(string("hello"))).String(),
        "1.2.3.4=#130568656c6c6f",
        "unknown OID -> #hex (string value)",
    );
    checkStr(
        one(oid(&[1, 2, 3, 4]), Any::new(42_i64)).String(),
        "1.2.3.4=#02012a",
        "unknown OID -> #hex (int value)",
    );
    // Same value, KNOWN OID: short name plus the escaped value, no hex.
    checkStr(
        one(oid(&[2, 5, 4, 3]), Any::new(string("hello"))).String(),
        "CN=hello",
        "known OID never takes the hex path",
    );

    // ── the Marshal-failed fallback: typeName = oidString ───────────
    //
    // Go reaches this with a value asn1 cannot encode (it prints
    // `1.2.3.4={map[]}` for a struct holding a map). goish reaches it
    // with a value that has no reflection at all. Either way the OID
    // stands in for the short name and the VALUE is printed, escaped —
    // never `#hex` of nothing.
    //
    // The rendered value differs because `fmt::Sprint` has no reflective
    // struct printer and substitutes its `<unsupported %T>` placeholder
    // where Go prints `{map[]}`. What is being pinned here is the SHAPE
    // — `oid=<escaped value>`, with `<` and `>` escaped per RFC 2253 —
    // not fmt's rendering of an unprintable value.
    let opaque = Any::new_opaque(nonReflectable { n: 7 });
    checkStr(
        one(oid(&[1, 2, 3, 4]), opaque.clone()).String(),
        "1.2.3.4=\\<unsupported %T\\>",
        "Marshal failure falls back to oid=<value>, not oid=#hex",
    );

    // ── a non-reflectable Any fails LOUDLY ──────────────────────────
    //
    // The bridge's contract: `ok == false` means "no reflection", which
    // is NOT the same as reflecting to the invalid (nil) value. Both
    // are Marshal errors, but different ones, and only the first names
    // the offending type.
    let (v, ok) = reflect::ValueOfAny(&opaque);
    check(!ok, "ValueOfAny(opaque) reports ok=false");
    check(!v.IsValid(), "ValueOfAny(opaque) value is Invalid");
    let (_t, tok) = reflect::TypeOfAny(&opaque);
    check(!tok, "TypeOfAny(opaque) reports ok=false");

    let (b, err) = asn1::MarshalAny(&opaque);
    check(b.Len() == 0, "MarshalAny(opaque) emits no bytes");
    check(err != goish::nil, "MarshalAny(opaque) errors");
    check(
        strings::Contains(err.Error(), "no goish reflection"),
        "MarshalAny(opaque) says WHY — no reflection, not 'nil value'",
    );
    check(
        strings::Contains(err.Error(), "nonReflectable"),
        "MarshalAny(opaque) names the offending type",
    );

    // nil, by contrast, reflects fine — to the invalid value — and gets
    // Go's own nil diagnostic. Distinguishing the two is the whole
    // point of the comma-ok.
    let nilAny: Any = goish::nil.into();
    let (nv, nok) = reflect::ValueOfAny(&nilAny);
    check(nok, "ValueOfAny(nil) reports ok=TRUE — nil reflects");
    check(!nv.IsValid(), "ValueOfAny(nil) value is Invalid");
    let (_nb, nerr) = asn1::MarshalAny(&nilAny);
    check(
        strings::Contains(nerr.Error(), "cannot marshal nil value"),
        "MarshalAny(nil) gives Go's nil diagnostic, not the reflection one",
    );

    // A reflectable Any round-trips through the bridge.
    let (sv, sok) = reflect::ValueOfAny(&Any::new(string("hi")));
    check(
        sok && sv.String().as_bytes() == b"hi",
        "ValueOfAny(string) -> Value::String",
    );
    let (tv2, tok2) = reflect::TypeOfAny(&Any::new(42_i64));
    check(
        tok2 && tv2.Kind() == reflect::Kind::Int,
        "TypeOfAny(int64) -> Kind::Int",
    );

    // ── RFC 2253 escaping, every rule ───────────────────────────────
    checkStr(cn("a,b"), "CN=a\\,b", "escape ,");
    checkStr(cn("a+b"), "CN=a\\+b", "escape +");
    checkStr(cn("a\"b"), "CN=a\\\"b", "escape \"");
    checkStr(cn("a\\b"), "CN=a\\\\b", "escape backslash");
    checkStr(cn("a<b"), "CN=a\\<b", "escape <");
    checkStr(cn("a>b"), "CN=a\\>b", "escape >");
    checkStr(cn("a;b"), "CN=a\\;b", "escape ;");
    checkStr(
        cn(",+\"\\<>;"),
        "CN=\\,\\+\\\"\\\\\\<\\>\\;",
        "escape all seven at once",
    );
    checkStr(cn(" ab"), "CN=\\ ab", "escape leading space");
    checkStr(cn("ab "), "CN=ab\\ ", "escape trailing space");
    checkStr(cn(" ab "), "CN=\\ ab\\ ", "escape both spaces");
    checkStr(cn("a b"), "CN=a b", "inner space NOT escaped");
    checkStr(
        cn(" "),
        "CN=\\ ",
        "a lone space is both leading and trailing",
    );
    checkStr(cn(""), "CN=", "empty value");
    checkStr(cn("#ab"), "CN=\\#ab", "escape leading #");
    checkStr(cn("a#b"), "CN=a#b", "inner # NOT escaped");
    // k is a BYTE offset and Len() a BYTE length, exactly as in Go, so
    // the trailing-space test still fires after a two-byte rune.
    checkStr(
        cn("é "),
        "CN=é\\ ",
        "trailing space after a multi-byte rune",
    );
    checkStr(
        cn(" é"),
        "CN=\\ é",
        "leading space before a multi-byte rune",
    );
    checkStr(cn("héllo"), "CN=héllo", "multi-byte runes pass through");

    // ── separators: RDNs REVERSED and joined by ',', entries within
    //      one RDN in order and joined by '+' ─────────────────────────
    let mk = |t: &[i64], v: &'static str| AttributeTypeAndValue {
        Type: oid(t),
        Value: Any::new(string(v)),
    };
    let seps = RDNSequence(slice::__from_vec(alloc::vec![
        RelativeDistinguishedNameSET(slice::__from_vec(alloc::vec![mk(&[2, 5, 4, 6], "US")])),
        RelativeDistinguishedNameSET(slice::__from_vec(alloc::vec![
            mk(&[2, 5, 4, 10], "Acme"),
            mk(&[2, 5, 4, 11], "Eng"),
        ])),
        RelativeDistinguishedNameSET(slice::__from_vec(alloc::vec![mk(
            &[2, 5, 4, 3],
            "example.com"
        )])),
    ]));
    checkStr(
        seps.String(),
        "CN=example.com,O=Acme+OU=Eng,C=US",
        "RDNs reversed, entries within an RDN in order",
    );

    // An empty RDN still contributes its ',' — String has no
    // skip-empty guard, unlike FillFromRDNSequence.
    let withEmpty = RDNSequence(slice::__from_vec(alloc::vec![
        RelativeDistinguishedNameSET(slice::__from_vec(alloc::vec![mk(&[2, 5, 4, 6], "US")])),
        RelativeDistinguishedNameSET(slice::default()),
        RelativeDistinguishedNameSET(slice::__from_vec(alloc::vec![mk(&[2, 5, 4, 3], "cn")])),
    ]));
    checkStr(
        withEmpty.String(),
        "CN=cn,,C=US",
        "an empty RDN still emits its separator",
    );
    checkStr(
        RDNSequence::default().String(),
        "",
        "the empty sequence is the empty string",
    );

    // ── Name.String's Names branch (Go issue 39924) ─────────────────
    //
    // With ExtraNames unset, the attributes parsed into Names that did
    // NOT land in a named field are surfaced — placed at the front of
    // the sequence, so they come out at the END of the string.
    let n3 = Name {
        CommonName: string("cn"),
        Names: slice::__from_vec(alloc::vec![
            mk(&[2, 5, 4, 3], "cn"), // standard: skipped
            mk(&[2, 5, 4, 6], "US"), // standard: skipped
            mk(&[1, 2, 840, 113549, 1, 9, 1], "a@b.c"),
            mk(&[0, 9, 2342, 19200300, 100, 1, 25], "com"),
        ]),
        ..Default::default()
    };
    checkStr(
        n3.String(),
        "CN=cn,0.9.2342.19200300.100.1.25=#1303636f6d,1.2.840.113549.1.9.1=#0c056140622e63",
        "Name.String surfaces non-standard Names at the end",
    );

    // ExtraNames present suppresses the Names branch entirely.
    let mut n4 = n3.clone();
    n4.ExtraNames = slice::__from_vec(alloc::vec![mk(&[2, 5, 4, 6], "ZZ")]);
    checkStr(
        n4.String(),
        "C=ZZ,CN=cn",
        "ExtraNames suppresses the Names branch",
    );

    checkStr(
        Name::default().String(),
        "",
        "the zero Name is the empty string",
    );

    let failed = FAILED.load(Ordering::Acquire);
    let ran = RAN.load(Ordering::Acquire);
    if failed == 0 {
        fmt::Printf!("pkix_smoke OK %d/%d\n", ran as i64, ran as i64);
    } else {
        fmt::Printf!("pkix_smoke FAILED %d of %d\n", failed as i64, ran as i64);
        goish::syscall::Exit(1);
    }
}
