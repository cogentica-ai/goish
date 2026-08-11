// pkix_smoke — crypto/x509/pkix's Name <-> RDNSequence conversions vs Go 1.25.5.
//
// Every expectation is `scripts/goref.sh crypto/x509/pkix` output, not a
// transcription. The cases pin the three things these functions actually
// decide:
//
//   * the ORDER ToRDNSequence emits (Country, Province, Locality,
//     StreetAddress, PostalCode, Organization, OrganizationalUnit, then
//     CommonName and SerialNumber) — a resequencing here changes the DER
//     of every certificate subject;
//   * that multi-value fields become ONE multi-entry RDN rather than
//     several single-entry ones;
//   * that an ExtraNames entry SUPPRESSES the standard field with the
//     same OID rather than appending to it — Go emits one RDN, not two.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::crypto::x509::pkix::{AttributeTypeAndValue, Name, RDNSequence};
use goish::encoding::asn1::ObjectIdentifier;
use goish::goany::Any;
use goish::goslice::slice;
use goish::{fmt, string};

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
    check(eq(at(&rdns, 0, 1), "2.5.4.6", "GB"), "rdn[0][1] C=GB (one multi-entry RDN)");
    check(eq(at(&rdns, 1, 0), "2.5.4.8", "CA"), "rdn[1] ST=CA");
    check(eq(at(&rdns, 2, 0), "2.5.4.7", "Springfield"), "rdn[2] L=Springfield");
    check(eq(at(&rdns, 3, 0), "2.5.4.9", "1 Main St"), "rdn[3] STREET");
    check(eq(at(&rdns, 4, 0), "2.5.4.17", "12345"), "rdn[4] POSTALCODE");
    check(eq(at(&rdns, 5, 0), "2.5.4.10", "Acme"), "rdn[5] O=Acme");
    check(eq(at(&rdns, 6, 0), "2.5.4.11", "Eng"), "rdn[6][0] OU=Eng");
    check(eq(at(&rdns, 6, 1), "2.5.4.11", "Ops"), "rdn[6][1] OU=Ops");
    check(eq(at(&rdns, 7, 0), "2.5.4.3", "example.com"), "rdn[7] CN");
    check(eq(at(&rdns, 8, 0), "2.5.4.5", "SN-1"), "rdn[8] SERIALNUMBER");

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
    check(back.Locality[0].as_bytes() == b"Springfield", "FillFromRDNSequence L");
    check(back.Province[0].as_bytes() == b"CA", "FillFromRDNSequence ST");
    check(back.StreetAddress[0].as_bytes() == b"1 Main St", "FillFromRDNSequence STREET");
    check(back.PostalCode[0].as_bytes() == b"12345", "FillFromRDNSequence POSTALCODE");
    check(back.CommonName.as_bytes() == b"example.com", "FillFromRDNSequence CN");
    check(back.SerialNumber.as_bytes() == b"SN-1", "FillFromRDNSequence SERIALNUMBER");
    // Go: back.Names len=11 — every attribute, flattened, grouping lost.
    check(back.Names.Len() == 11, "FillFromRDNSequence Names has all 11 flattened");

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
    check(r2.0.Len() == 1, "ExtraNames suppresses the standard Country RDN");
    check(eq(at(&r2, 0, 0), "2.5.4.6", "ZZ"), "ExtraNames value wins");

    let failed = FAILED.load(Ordering::Acquire);
    let ran = RAN.load(Ordering::Acquire);
    if failed == 0 {
        fmt::Printf!("pkix_smoke OK %d/%d\n", ran as i64, ran as i64);
    } else {
        fmt::Printf!("pkix_smoke FAILED %d of %d\n", failed as i64, ran as i64);
        goish::syscall::Exit(1);
    }
}
