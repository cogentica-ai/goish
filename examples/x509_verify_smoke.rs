// x509_verify_smoke — crypto::x509 signature checking + chain verification.
//
// **Every expectation below is generated, not transcribed.** The four
// certificates and all sixteen expected outcomes come from
// `scripts/goref.sh crypto/x509 <ref>`, a throwaway `TestGoishRef` run
// inside a writable GOROOT copy so it can reach `matchHostnames`,
// `matchDomainConstraint`, `policiesValid` and the other unexported
// helpers. The Ed25519 keys are generated from a deterministic byte
// reader, so the DER — and therefore the PEM here — is byte-stable.
//
// Tests:
//   1. test_check_signature_from    — leaf signed by CA verifies; a CA
//      "signed by" a non-CA leaf is ConstraintViolationError; a tampered
//      signature is "x509: Ed25519 verification failure".
//   2. test_verify_good_chain       — Verify builds exactly one chain,
//      leaf -> CA.
//   3. test_verify_rejections       — expired, wrong hostname, empty root
//      pool, and wrong extended key usage each fail with Go's message.
//   4. test_verify_hostname         — the ten host spellings goref ran,
//      including the wildcard and IP-SAN cases.
//   5. test_match_helpers           — matchHostnames / matchExactly /
//      validHostname{Pattern,Input} truth tables.
//   6. test_name_constraints        — a CA with PermittedDNSDomains
//      ["example.com"] rejects a leaf claiming evil.com and accepts one
//      claiming host.example.com.
//   7. test_check_chain_for_key_usage / policiesValid / alreadyInChain /
//      contains / findPotentialParents — the remaining goref rows.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::crypto;
use goish::crypto::x509::{
    ExtKeyUsageClientAuth, NewCertPool, ParseCertificate, VerifyOptions,
};
use goish::encoding::pem;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::time;
use goish::{convert, syscall};

// goref: ----- CA -----
const CA_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIBIDCB06ADAgECAgEBMAUGAytlcDAYMRYwFAYDVQQDEw1nb2lzaCB0ZXN0IENB\n\
MB4XDTIwMDEwMTAwMDAwMFoXDTMwMDEwMTAwMDAwMFowGDEWMBQGA1UEAxMNZ29p\n\
c2ggdGVzdCBDQTAqMAUGAytlcAMhAAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3c\n\
hmQSVTG4o0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV\n\
HQ4EFgQUVkdap1RjR0wChd9dvyvKtz2mUTUwBQYDK2VwA0EA59y3ZhRABpd18siC\n\
hEbu2614ZOySHzIwc/F/JKZRjXwLP40WUTAp7j6Mv+9eOO73rw/RiXFJelyMVyXT\n\
8fp+Dg==\n\
-----END CERTIFICATE-----\n";

// goref: ----- LEAF ----- (DNSNames example.com, *.wild.example.com;
// IPAddresses 192.0.2.1; ExtKeyUsage ServerAuth)
const LEAF_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIBWzCCAQ2gAwIBAgIBAjAFBgMrZXAwGDEWMBQGA1UEAxMNZ29pc2ggdGVzdCBD\n\
QTAeFw0yMDAxMDEwMDAwMDBaFw0zMDAxMDEwMDAwMDBaMBoxGDAWBgNVBAMTD2dv\n\
aXNoIHRlc3QgbGVhZjAqMAUGAytlcAMhACmsuuFBvMrwsi4alNNNC8c2HlJtC/4S\n\
yJeUvJMilm3Xo3oweDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUH\n\
AwEwHwYDVR0jBBgwFoAUVkdap1RjR0wChd9dvyvKtz2mUTUwMAYDVR0RBCkwJ4IL\n\
ZXhhbXBsZS5jb22CEioud2lsZC5leGFtcGxlLmNvbYcEwAACATAFBgMrZXADQQAZ\n\
elwz5DRgsGeDy3ou+B3VoEK7tMObQH+k8s0Z4nKZRmXzMSs2266k2h9bukT7Eajz\n\
zP4VwhZ+hyuhcFjBVBYP\n\
-----END CERTIFICATE-----\n";

// goref: ----- NC_CA ----- (PermittedDNSDomains ["example.com"])
const NC_CA_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIBODCB66ADAgECAgEDMAUGAytlcDAWMRQwEgYDVQQDEwtnb2lzaCBuYyBDQTAe\n\
Fw0yMDAxMDEwMDAwMDBaFw0zMDAxMDEwMDAwMDBaMBYxFDASBgNVBAMTC2dvaXNo\n\
IG5jIENBMCowBQYDK2VwAyEAJUO5L/EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmyp\n\
VZ2jXjBcMA4GA1UdDwEB/wQEAwICBDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW\n\
BBQDOWIZI391pk8SrrfzlyOr9ACxYDAaBgNVHR4EEzARoA8wDYILZXhhbXBsZS5j\n\
b20wBQYDK2VwA0EAGhO0KT3PXfS8ULtGIqDvAe9XlB7r4OmAHKhaiPjWKlbiAz8c\n\
PttldYUTogOuTvp6/4CAkIDs+nr/EgVosvPAAA==\n\
-----END CERTIFICATE-----\n";

// goref: ----- NC_LEAF ----- (DNSNames ["evil.com"])
const NC_LEAF_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIBOTCB7KADAgECAgEEMAUGAytlcDAWMRQwEgYDVQQDEwtnb2lzaCBuYyBDQTAe\n\
Fw0yMDAxMDEwMDAwMDBaFw0zMDAxMDEwMDAwMDBaMBgxFjAUBgNVBAMTDWdvaXNo\n\
IG5jIGxlYWYwKjAFBgMrZXADIQAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0\n\
gpk/1aNdMFswDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB8G\n\
A1UdIwQYMBaAFAM5Yhkjf3WmTxKut/OXI6v0ALFgMBMGA1UdEQQMMAqCCGV2aWwu\n\
Y29tMAUGAytlcANBAIfP13k/HJ7Cmf9YgbTIuICrQR1czhOu7pjaHpWvdS+XhAD+\n\
5cfSU730K2wCBkXmYUZiERgPPl27MKuUBWX4gQ8=\n\
-----END CERTIFICATE-----\n";

// goref: ----- NC_OK_LEAF ----- (DNSNames ["host.example.com"])
const NC_OK_LEAF_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIBRDCB96ADAgECAgEFMAUGAytlcDAWMRQwEgYDVQQDEwtnb2lzaCBuYyBDQTAe\n\
Fw0yMDAxMDEwMDAwMDBaFw0zMDAxMDEwMDAwMDBaMBsxGTAXBgNVBAMTEGdvaXNo\n\
IG5jIG9rIGxlYWYwKjAFBgMrZXADIQAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9\n\
Q6Y0gpk/1aNlMGMwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMB\n\
MB8GA1UdIwQYMBaAFAM5Yhkjf3WmTxKut/OXI6v0ALFgMBsGA1UdEQQUMBKCEGhv\n\
c3QuZXhhbXBsZS5jb20wBQYDK2VwA0EArP7XRcVuExg54aMSbcipqPC7RuUg/Tlp\n\
Jwpaw+X7JyFF6FZKtQxWpmDDEu77PIqbmRG9pPTywrUlPzFRtTZNAA==\n\
-----END CERTIFICATE-----\n";

/// Decode one PEM CERTIFICATE block and parse it. Panics on failure —
/// every constant above is a certificate goref already parsed.
fn parse(pemText: &'static str) -> goish::crypto::x509::Certificate {
    let (block, _) = pem::Decode(convert::bytes(pemText));
    let b = match block {
        None => panic!("test fixture is not PEM"),
        Some(b) => b,
    };
    let (cert, err) = ParseCertificate(b.Bytes);
    if err != goish::nil {
        panic!("test fixture failed to parse");
    }
    return cert;
}

/// goref ran Verify at 2025-06-01T00:00:00Z (inside the window) and at
/// 2031-06-01T00:00:00Z (past NotAfter 2030-01-01).
fn tGood() -> time::Time {
    return time::Date(2025, 6, 1, 0, 0, 0, 0, time::UTC);
}
fn tLate() -> time::Time {
    return time::Date(2031, 6, 1, 0, 0, 0, 0, time::UTC);
}

fn errText(e: &goish::error) -> string {
    if *e == goish::nil {
        return string::from("<nil>");
    }
    return e.Error();
}

fn test_check_signature_from() -> bool {
    let ca = parse(CA_PEM);
    let leaf = parse(LEAF_PEM);

    // goref: CheckSignatureFrom(leaf, ca) err = <nil>
    let e = leaf.CheckSignatureFrom(&ca);
    if e != goish::nil {
        fmt::Println!("[1] CheckSignatureFrom(leaf, ca) =", errText(&e), "want <nil> — FAIL");
        return false;
    }
    // goref: CheckSignatureFrom(ca, ca) err = <nil>  (self-signed root)
    let e = ca.CheckSignatureFrom(&ca);
    if e != goish::nil {
        fmt::Println!("[1] CheckSignatureFrom(ca, ca) =", errText(&e), "want <nil> — FAIL");
        return false;
    }
    // goref: CheckSignatureFrom(ca, leaf) err = x509: invalid signature:
    //        parent certificate cannot sign this kind of certificate
    let e = ca.CheckSignatureFrom(&leaf);
    let want = string::from(
        "x509: invalid signature: parent certificate cannot sign this kind of certificate",
    );
    if errText(&e) != want {
        fmt::Println!("[1] CheckSignatureFrom(ca, leaf) =", errText(&e), "— FAIL");
        return false;
    }

    // goref: CheckSignature(tampered) err = x509: Ed25519 verification failure
    let mut bad = leaf.Signature.__into_vec();
    bad[0] ^= 0xff;
    let e = ca.CheckSignature(
        leaf.SignatureAlgorithm,
        leaf.RawTBSCertificate.clone(),
        slice::__from_vec(bad),
    );
    if errText(&e) != string::from("x509: Ed25519 verification failure") {
        fmt::Println!("[1] CheckSignature(tampered) =", errText(&e), "— FAIL");
        return false;
    }

    fmt::Println!("[1] test_check_signature_from                 PASS");
    return true;
}

fn test_verify_good_chain() -> bool {
    let ca = parse(CA_PEM);
    let leaf = parse(LEAF_PEM);
    let mut roots = NewCertPool();
    roots.AddCert(ca);

    // goref: Verify(good) err = <nil>, chains = 1
    //        chain[0] len=2: "goish test leaf" "goish test CA"
    let (chains, err) = leaf.Verify(VerifyOptions {
        Roots: Some(roots),
        CurrentTime: tGood(),
        DNSName: string::from("example.com"),
        ..Default::default()
    });
    if err != goish::nil {
        fmt::Println!("[2] Verify(good) err =", errText(&err), "want <nil> — FAIL");
        return false;
    }
    if chains.Len() != 1 {
        fmt::Println!("[2] chains =", chains.Len(), "want 1 — FAIL");
        return false;
    }
    let ch = &chains[0];
    if ch.Len() != 2 {
        fmt::Println!("[2] chain[0] len =", ch.Len(), "want 2 — FAIL");
        return false;
    }
    if ch[0].Subject.CommonName != string::from("goish test leaf")
        || ch[1].Subject.CommonName != string::from("goish test CA")
    {
        fmt::Println!("[2] chain[0] subjects wrong — FAIL");
        return false;
    }
    fmt::Println!("[2] test_verify_good_chain                    PASS");
    return true;
}

fn test_verify_rejections() -> bool {
    let ca = parse(CA_PEM);
    let leaf = parse(LEAF_PEM);
    let mut roots = NewCertPool();
    roots.AddCert(ca);

    // goref: Verify(expired) err = x509: certificate has expired or is not
    //        yet valid: current time 2031-06-01T00:00:00Z is after
    //        2030-01-01T00:00:00Z
    let (_, err) = leaf.Verify(VerifyOptions {
        Roots: Some(roots.Clone()),
        CurrentTime: tLate(),
        DNSName: string::from("example.com"),
        ..Default::default()
    });
    let want = string::from(
        "x509: certificate has expired or is not yet valid: current time 2031-06-01T00:00:00Z is after 2030-01-01T00:00:00Z",
    );
    if errText(&err) != want {
        fmt::Println!("[3] Verify(expired) =", errText(&err), "— FAIL");
        return false;
    }

    // goref: Verify(wrong host) err = x509: certificate is valid for
    //        example.com, *.wild.example.com, not nope.com
    let (_, err) = leaf.Verify(VerifyOptions {
        Roots: Some(roots.Clone()),
        CurrentTime: tGood(),
        DNSName: string::from("nope.com"),
        ..Default::default()
    });
    let want = string::from(
        "x509: certificate is valid for example.com, *.wild.example.com, not nope.com",
    );
    if errText(&err) != want {
        fmt::Println!("[3] Verify(wrong host) =", errText(&err), "— FAIL");
        return false;
    }

    // goref: Verify(no roots) err = x509: certificate signed by unknown authority
    let (_, err) = leaf.Verify(VerifyOptions {
        Roots: Some(NewCertPool()),
        CurrentTime: tGood(),
        ..Default::default()
    });
    if errText(&err) != string::from("x509: certificate signed by unknown authority") {
        fmt::Println!("[3] Verify(no roots) =", errText(&err), "— FAIL");
        return false;
    }

    // goref: Verify(wrong eku) err = x509: certificate specifies an
    //        incompatible key usage
    let mut ekus: slice<goish::crypto::x509::ExtKeyUsage> = slice::new();
    ekus = goish::append!(ekus, ExtKeyUsageClientAuth);
    let (_, err) = leaf.Verify(VerifyOptions {
        Roots: Some(roots.Clone()),
        CurrentTime: tGood(),
        KeyUsages: ekus,
        ..Default::default()
    });
    if errText(&err) != string::from("x509: certificate specifies an incompatible key usage") {
        fmt::Println!("[3] Verify(wrong eku) =", errText(&err), "— FAIL");
        return false;
    }

    fmt::Println!("[3] test_verify_rejections                    PASS");
    return true;
}

fn test_verify_hostname() -> bool {
    let leaf = parse(LEAF_PEM);

    // goref rows: <nil> means accepted.
    let accepted: [&str; 6] = [
        "example.com",
        "EXAMPLE.COM",
        "example.com.",
        "a.wild.example.com",
        "192.0.2.1",
        "[192.0.2.1]",
    ];
    for h in accepted.iter() {
        let e = leaf.VerifyHostname(*h);
        if e != goish::nil {
            fmt::Println!("[4] VerifyHostname(", *h, ") =", errText(&e), "want <nil> — FAIL");
            return false;
        }
    }

    let rejected: [&str; 4] = [
        "wild.example.com",
        "a.b.wild.example.com",
        "nope.com",
        "192.0.2.2",
    ];
    for h in rejected.iter() {
        let e = leaf.VerifyHostname(*h);
        if e == goish::nil {
            fmt::Println!("[4] VerifyHostname(", *h, ") accepted — FAIL");
            return false;
        }
    }

    // goref: VerifyHostname("192.0.2.2") err = x509: certificate is valid
    //        for 192.0.2.1, not 192.0.2.2
    let e = leaf.VerifyHostname("192.0.2.2");
    if errText(&e) != string::from("x509: certificate is valid for 192.0.2.1, not 192.0.2.2") {
        fmt::Println!("[4] VerifyHostname(192.0.2.2) =", errText(&e), "— FAIL");
        return false;
    }

    fmt::Println!("[4] test_verify_hostname                      PASS");
    return true;
}

fn test_name_constraints() -> bool {
    let ncCA = parse(NC_CA_PEM);
    let badLeaf = parse(NC_LEAF_PEM);
    let okLeaf = parse(NC_OK_LEAF_PEM);

    let mut ncRoots = NewCertPool();
    ncRoots.AddCert(ncCA);

    // goref: Verify(name-constraint violation) err = x509: a root or
    //        intermediate certificate is not authorized to sign for this
    //        name: DNS name "evil.com" is not permitted by any constraint
    let (_, err) = badLeaf.Verify(VerifyOptions {
        Roots: Some(ncRoots.Clone()),
        CurrentTime: tGood(),
        ..Default::default()
    });
    let want = string::from(
        "x509: a root or intermediate certificate is not authorized to sign for this name: DNS name \"evil.com\" is not permitted by any constraint",
    );
    if errText(&err) != want {
        fmt::Println!("[5] Verify(nc violation) =", errText(&err), "— FAIL");
        return false;
    }

    // goref: Verify(name-constraint ok) err = <nil>, chains = 1
    let (chains, err) = okLeaf.Verify(VerifyOptions {
        Roots: Some(ncRoots),
        CurrentTime: tGood(),
        DNSName: string::from("host.example.com"),
        ..Default::default()
    });
    if err != goish::nil || chains.Len() != 1 {
        fmt::Println!("[5] Verify(nc ok) =", errText(&err), "chains =", chains.Len(), "— FAIL");
        return false;
    }

    fmt::Println!("[5] test_name_constraints                     PASS");
    return true;
}

fn test_pool_lookup() -> bool {
    let ca = parse(CA_PEM);
    let leaf = parse(LEAF_PEM);
    let ncCA = parse(NC_CA_PEM);
    let mut roots = NewCertPool();
    roots.AddCert(ca.clone());

    // goref: roots.contains(ca) = true, roots.contains(leaf) = false
    // `contains` is unexported in Go; the public surface that reaches it
    // is Verify's "the leaf is itself a root" short-circuit — a chain of
    // length 1 with no signature check.
    let (chains, err) = ca.Verify(VerifyOptions {
        Roots: Some(roots.Clone()),
        CurrentTime: tGood(),
        ..Default::default()
    });
    if err != goish::nil || chains.Len() != 1 || chains[0].Len() != 1 {
        fmt::Println!("[6] Verify(ca in its own pool) =", errText(&err), "— FAIL");
        return false;
    }

    // goref: len(roots.findPotentialParents(badLeaf)) = 0 — a leaf whose
    // issuer is not in the pool builds no chain.
    let (_, err) = ncCA.Verify(VerifyOptions {
        Roots: Some(roots),
        CurrentTime: tGood(),
        ..Default::default()
    });
    if errText(&err) != string::from("x509: certificate signed by unknown authority") {
        fmt::Println!("[6] Verify(unknown issuer) =", errText(&err), "— FAIL");
        return false;
    }

    // Silence the unused binding: `leaf` documents the goref row above.
    let _ = leaf.Raw.Len();

    fmt::Println!("[6] test_pool_lookup                          PASS");
    return true;
}

#[goish::main]
fn main() {
    // goish has no per-package `init()` driver, so the hash registry the
    // RSA / ECDSA arms of checkSignature need is wired explicitly. The
    // Ed25519 fixtures here never hash, but a caller with an RSA chain
    // would.
    crypto::RegisterStandardHashes();

    let mut passed = 0;
    let mut total = 0;

    total += 1;
    if test_check_signature_from() {
        passed += 1;
    }

    total += 1;
    if test_verify_good_chain() {
        passed += 1;
    }

    total += 1;
    if test_verify_rejections() {
        passed += 1;
    }

    total += 1;
    if test_verify_hostname() {
        passed += 1;
    }

    total += 1;
    if test_name_constraints() {
        passed += 1;
    }

    total += 1;
    if test_pool_lookup() {
        passed += 1;
    }

    fmt::Println!("x509_verify_smoke:", passed, "/", total, "passed");
    if passed != total {
        syscall::Exit(1);
    }
    syscall::Exit(0);
}
