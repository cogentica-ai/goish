// x509_create_smoke — crypto/x509's certificate / CRL *creation* half
// vs Go 1.25.5.
//
// EVERY expectation below is `scripts/goref.sh crypto/x509` output — a
// throwaway `TestGoishRef` run inside a writable GOROOT copy, so it can
// call the unexported `marshalPublicKey`, `buildCertExtensions`,
// `signTBS` and friends directly. Nothing here is transcribed from a
// spec, from a published vector, or from memory.
//
// The strategy is a **byte-exact round trip**, not a field-by-field
// comparison. The signing key is Ed25519 built from the fixed 32-byte
// seed 00,01,…,1f, and Ed25519 signing is deterministic — so Go's
// `CreateCertificate` and goish's must agree on the complete DER, byte
// for byte, signature included. That single assertion transitively pins
// every unexported helper the creation path runs through:
//
//   marshalPublicKey  subjectBytes         signingParamsForKey
//   buildCertExtensions                    signTBS
//   marshalKeyUsage   marshalExtKeyUsage   marshalBasicConstraints
//   marshalSANs       marshalCertificatePolicies
//   reverseBitsInAByte                     asn1BitLength
//
// which is why they are exercised through `CreateCertificate` templates
// rather than exported for the test's benefit — Go keeps them
// unexported and so does goish.
//
// The CERT_KITCHEN case deliberately populates every single branch of
// `buildCertExtensions`, so all ten extension writers plus the
// ExtraExtensions tail run in one certificate.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::crypto::ed25519;
use goish::crypto::x509::{
    CertificateRequest, CreateCertificate, CreateCertificateRequest, CreateRevocationList,
    MarshalPKIXPublicKey, OIDFromInts, ParseCertificate, RevocationList, RevocationListEntry, OID,
};
use goish::crypto::x509::pkix;
use goish::encoding::asn1;
use goish::encoding::hex;
use goish::error;
use goish::goany::Any;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io;
use goish::math::big;
use goish::net;
use goish::net::url;
use goish::time;
use goish::types::byte;
use goish::{fmt, int};

static RAN: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(ok: bool, label: &'static str) {
    RAN.fetch_add(1, Ordering::AcqRel);
    if ok {
        fmt::Printf!("PASS: %s\n", string::from(label));
    } else {
        FAILED.fetch_add(1, Ordering::AcqRel);
        fmt::Printf!("FAIL: %s\n", string::from(label));
    }
}

/// Compare a DER blob against Go's hex, printing both on a mismatch so
/// a failure names the first differing byte rather than just "false".
fn checkHex(got: &slice<byte>, want: &'static str, label: &'static str) {
    let g = hex::EncodeToString(got);
    let ok = g == want;
    check(ok, label);
    if !ok {
        fmt::Printf!("   want %s\n", string::from(want));
        fmt::Printf!("   got  %s\n", g);
    }
}

fn checkErr(err: error, want: &'static str, label: &'static str) {
    let got = if err == goish::nil {
        string::from("<nil>")
    } else {
        err.Error()
    };
    let ok = got == want;
    check(ok, label);
    if !ok {
        fmt::Printf!("   want %s\n", string::from(want));
        fmt::Printf!("   got  %s\n", got);
    }
}

// Go's ref program signs with a reader that yields 0,1,2,… — the same
// shape as its `fixedReader`. Ed25519 ignores it, but
// `CreateCertificate`'s generated-serial path does not, so the two
// implementations must draw the identical bytes.
struct fixedReader {
    n: byte,
}

impl io::Reader for fixedReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        let n = p.Len();
        let mut i: int = 0;
        while i < n {
            p[i] = self.n;
            self.n = self.n.wrapping_add(1);
            i += 1;
        }
        return (n, goish::nil.into());
    }
}

fn refKey() -> ed25519::PrivateKey {
    let mut seed: Vec<byte> = Vec::with_capacity(32);
    let mut i: byte = 0;
    while i < 32 {
        seed.push(i);
        i += 1;
    }
    return ed25519::NewKeyFromSeed(slice::__from_vec(seed));
}

fn strs(xs: &[&'static str]) -> slice<string> {
    let mut v: Vec<string> = Vec::with_capacity(xs.len());
    for x in xs {
        v.push(string::from(*x));
    }
    return slice::__from_vec(v);
}

fn bs(xs: &[byte]) -> slice<byte> {
    return slice::__from_vec(xs.to_vec());
}

fn notBefore() -> time::Time {
    return time::Date(2024, time::January, 2, 3, 4, 5, 0, time::UTC);
}

fn notAfter() -> time::Time {
    return time::Date(2034, time::January, 2, 3, 4, 5, 0, time::UTC);
}

fn oidOf(parts: &[int]) -> asn1::ObjectIdentifier {
    return asn1::ObjectIdentifier::New(slice::__from_vec(parts.to_vec()));
}

fn cidr(s: &'static str) -> net::IPNet {
    let (_, n, err) = net::ParseCIDR(string::from(s));
    if err != goish::nil {
        fmt::Printf!("FATAL: ParseCIDR(%s) failed\n", string::from(s));
    }
    return n;
}

#[goish::main]
fn main() {
    let priv_ = refKey();
    let pubKey = priv_.PublicKey();
    let pub_ = Any::new_fn(pubKey.clone());
    let privAny = Any::new_fn(priv_.clone());

    // ── MarshalPKIXPublicKey ─────────────────────────────────────────
    // goref: SPKI_ED25519
    {
        let (spki, err) = MarshalPKIXPublicKey(&pub_);
        checkErr(err, "<nil>", "MarshalPKIXPublicKey err");
        checkHex(
            &spki,
            "302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
            "MarshalPKIXPublicKey(ed25519) == Go SPKI",
        );
    }

    // ── CreateCertificate: self-signed, byte-exact ───────────────────
    // goref: CERT_SELFSIGNED
    {
        let mut tmpl = x509Cert();
        tmpl.SerialNumber = bigFromI64(0x0123456789);
        tmpl.Subject.CommonName = string::from("goish root");
        tmpl.Subject.Organization = strs(&["Goish"]);
        tmpl.NotBefore = notBefore();
        tmpl.NotAfter = notAfter();
        tmpl.KeyUsage = goish::crypto::x509::KeyUsageCertSign
            | goish::crypto::x509::KeyUsageCRLSign
            | goish::crypto::x509::KeyUsageDigitalSignature;
        tmpl.BasicConstraintsValid = true;
        tmpl.IsCA = true;
        tmpl.SubjectKeyId = bs(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]);
        tmpl.DNSNames = strs(&["example.com"]);

        let mut r = fixedReader { n: 0 };
        let (der, err) = CreateCertificate(&mut r, &tmpl, &tmpl, &pub_, &privAny);
        checkErr(err, "<nil>", "CreateCertificate self-signed err");
        checkHex(&der, CERT_SELFSIGNED, "CreateCertificate self-signed == Go DER");

        // And it parses back, through the sibling parser.
        let (_, perr) = ParseCertificate(der.clone());
        checkErr(perr, "<nil>", "the DER goish wrote parses back");
    }

    // ── CreateCertificate: SubjectKeyId derived from SHA-256 ─────────
    // goref: CERT_DERIVED_SKID
    {
        let mut tmpl = x509Cert();
        tmpl.SerialNumber = bigFromI64(42);
        tmpl.Subject.CommonName = string::from("goish skid");
        tmpl.NotBefore = notBefore();
        tmpl.NotAfter = notAfter();
        tmpl.BasicConstraintsValid = true;
        tmpl.IsCA = true;

        let mut r = fixedReader { n: 0 };
        let (der, err) = CreateCertificate(&mut r, &tmpl, &tmpl, &pub_, &privAny);
        checkErr(err, "<nil>", "CreateCertificate derived-SKID err");
        checkHex(&der, CERT_DERIVED_SKID, "SubjectKeyId derived per RFC 7093 == Go");
    }

    // ── CreateCertificate: every buildCertExtensions branch ──────────
    // goref: CERT_KITCHEN
    {
        let (u, _) = url::Parse("https://example.com/x");
        let (p1, _) = OIDFromInts(slice::__from_vec(alloc::vec![1u64, 2, 3, 4]));
        let (p2, _) = OIDFromInts(slice::__from_vec(alloc::vec![2u64, 23, 140, 1, 2, 1]));

        let mut tmpl = x509Cert();
        tmpl.SerialNumber = bigFromI64(0x0123456789);
        tmpl.Subject.CommonName = string::from("goish kitchen sink");
        tmpl.Subject.Organization = strs(&["Goish"]);
        tmpl.Subject.Country = strs(&["TH"]);
        tmpl.NotBefore = notBefore();
        tmpl.NotAfter = notAfter();

        tmpl.KeyUsage = goish::crypto::x509::KeyUsageDigitalSignature
            | goish::crypto::x509::KeyUsageCertSign
            | goish::crypto::x509::KeyUsageCRLSign;
        tmpl.ExtKeyUsage = slice::__from_vec(alloc::vec![
            goish::crypto::x509::ExtKeyUsageServerAuth,
            goish::crypto::x509::ExtKeyUsageClientAuth,
        ]);
        tmpl.UnknownExtKeyUsage = slice::__from_vec(alloc::vec![oidOf(&[1, 2, 3, 4])]);

        tmpl.BasicConstraintsValid = true;
        tmpl.IsCA = true;
        tmpl.MaxPathLen = 2;

        tmpl.SubjectKeyId = bs(&[0xde, 0xad, 0xbe, 0xef]);
        tmpl.AuthorityKeyId = bs(&[0xca, 0xfe]);

        tmpl.OCSPServer = strs(&["http://ocsp.example.com"]);
        tmpl.IssuingCertificateURL = strs(&["http://ca.example.com/ca.crt"]);

        tmpl.DNSNames = strs(&["example.com", "www.example.com"]);
        tmpl.EmailAddresses = strs(&["a@example.com"]);
        tmpl.IPAddresses = slice::__from_vec(alloc::vec![
            net::ParseIP(string::from("127.0.0.1")),
            net::ParseIP(string::from("10.1.2.3")),
        ]);
        tmpl.URIs = slice::__from_vec(alloc::vec![u]);

        tmpl.Policies = slice::__from_vec(alloc::vec![p1, p2]);

        tmpl.PermittedDNSDomainsCritical = true;
        tmpl.PermittedDNSDomains = strs(&["example.com"]);
        tmpl.ExcludedDNSDomains = strs(&["bad.example.com"]);
        tmpl.PermittedIPRanges = slice::__from_vec(alloc::vec![cidr("10.0.0.0/8")]);
        tmpl.ExcludedIPRanges = slice::__from_vec(alloc::vec![cidr("192.168.0.0/16")]);
        tmpl.PermittedEmailAddresses = strs(&["ok@example.com"]);
        tmpl.ExcludedEmailAddresses = strs(&["no@example.com"]);
        tmpl.PermittedURIDomains = strs(&["uri.example.com"]);
        tmpl.ExcludedURIDomains = strs(&["nouri.example.com"]);

        tmpl.CRLDistributionPoints = strs(&["http://crl.example.com/x.crl"]);

        tmpl.ExtraExtensions = slice::__from_vec(alloc::vec![pkix::Extension {
            Id: oidOf(&[1, 2, 3, 4, 5]),
            Critical: false,
            Value: bs(&[0x05, 0x00]),
        }]);

        let mut r = fixedReader { n: 0 };
        let (der, err) = CreateCertificate(&mut r, &tmpl, &tmpl, &pub_, &privAny);
        checkErr(err, "<nil>", "CreateCertificate kitchen-sink err");
        checkHex(&der, CERT_KITCHEN, "every buildCertExtensions branch == Go DER");
    }

    // ── KeyUsage bit layout: reverseBitsInAByte + asn1BitLength ──────
    // goref: CERT_KU
    {
        let cases: [(goish::crypto::x509::KeyUsage, &'static str, &'static str); 5] = [
            (goish::crypto::x509::KeyUsageDigitalSignature, CERT_KU_1, "KeyUsage digitalSignature"),
            (
                goish::crypto::x509::KeyUsage(
                    goish::crypto::x509::KeyUsageCertSign.0 | goish::crypto::x509::KeyUsageCRLSign.0,
                ),
                CERT_KU_96,
                "KeyUsage certSign|cRLSign",
            ),
            (
                goish::crypto::x509::KeyUsage(
                    goish::crypto::x509::KeyUsageDigitalSignature.0
                        | goish::crypto::x509::KeyUsageKeyEncipherment.0,
                ),
                CERT_KU_5,
                "KeyUsage digitalSignature|keyEncipherment",
            ),
            (
                goish::crypto::x509::KeyUsageDecipherOnly,
                CERT_KU_256,
                "KeyUsage decipherOnly (two-byte bit string)",
            ),
            (
                goish::crypto::x509::KeyUsage(
                    goish::crypto::x509::KeyUsageEncipherOnly.0
                        | goish::crypto::x509::KeyUsageDecipherOnly.0,
                ),
                CERT_KU_384,
                "KeyUsage encipherOnly|decipherOnly",
            ),
        ];
        for c in cases.iter() {
            let mut tmpl = x509Cert();
            tmpl.SerialNumber = bigFromI64(1);
            tmpl.Subject.CommonName = string::from("ku");
            tmpl.NotBefore = notBefore();
            tmpl.NotAfter = notAfter();
            tmpl.KeyUsage = c.0;
            let mut r = fixedReader { n: 0 };
            let (der, _) = CreateCertificate(&mut r, &tmpl, &tmpl, &pub_, &privAny);
            checkHex(&der, c.1, c.2);
        }
    }

    // ── Generated serial number: the 20 bytes come from `rand` ───────
    // goref: CERT_GENSERIAL
    {
        let mut tmpl = x509Cert();
        tmpl.Subject.CommonName = string::from("gen serial");
        tmpl.NotBefore = notBefore();
        tmpl.NotAfter = notAfter();
        let mut r = fixedReader { n: 0 };
        let (der, err) = CreateCertificate(&mut r, &tmpl, &tmpl, &pub_, &privAny);
        checkErr(err, "<nil>", "CreateCertificate generated-serial err");
        checkHex(&der, CERT_GENSERIAL, "nil SerialNumber draws 20 bytes from rand == Go");
    }

    // ── Empty subject forces a critical SAN (RFC 5280 4.2.1.6) ───────
    // goref: CERT_EMPTYSUBJ
    {
        let mut tmpl = x509Cert();
        tmpl.SerialNumber = bigFromI64(2);
        tmpl.NotBefore = notBefore();
        tmpl.NotAfter = notAfter();
        tmpl.DNSNames = strs(&["nosubject.example.com"]);
        let mut r = fixedReader { n: 0 };
        let (der, err) = CreateCertificate(&mut r, &tmpl, &tmpl, &pub_, &privAny);
        checkErr(err, "<nil>", "CreateCertificate empty-subject err");
        checkHex(&der, CERT_EMPTYSUBJ, "empty subject marks SAN critical == Go");
    }

    // ── CreateCertificate rejections ─────────────────────────────────
    // goref: CERT_ERR_*
    {
        let mut r = fixedReader { n: 0 };
        let mut bad = x509Cert();
        bad.SerialNumber = bigFromI64(-1);
        bad.NotBefore = notBefore();
        bad.NotAfter = notAfter();
        bad.BasicConstraintsValid = true;
        let (_, err) = CreateCertificate(&mut r, &bad, &bad, &pub_, &privAny);
        checkErr(err, "x509: serial number must be positive", "negative serial rejected");

        let mut bad2 = x509Cert();
        bad2.SerialNumber = bigFromI64(1);
        bad2.NotBefore = notBefore();
        bad2.NotAfter = notAfter();
        bad2.BasicConstraintsValid = true;
        bad2.MaxPathLen = -2;
        let (_, err) = CreateCertificate(&mut r, &bad2, &bad2, &pub_, &privAny);
        checkErr(
            err,
            "x509: invalid MaxPathLen, must be greater or equal to -1",
            "MaxPathLen < -1 rejected",
        );

        let mut bad3 = x509Cert();
        bad3.SerialNumber = bigFromI64(1);
        bad3.NotBefore = notBefore();
        bad3.NotAfter = notAfter();
        bad3.BasicConstraintsValid = true;
        bad3.IsCA = false;
        bad3.MaxPathLen = 3;
        let (_, err) = CreateCertificate(&mut r, &bad3, &bad3, &pub_, &privAny);
        checkErr(
            err,
            "x509: only CAs are allowed to specify MaxPathLen",
            "non-CA MaxPathLen rejected",
        );
    }

    // ── CreateRevocationList ─────────────────────────────────────────
    let ca = {
        let mut caTmpl = x509Cert();
        caTmpl.SerialNumber = bigFromI64(0x0123456789);
        caTmpl.Subject.CommonName = string::from("goish root");
        caTmpl.Subject.Organization = strs(&["Goish"]);
        caTmpl.NotBefore = notBefore();
        caTmpl.NotAfter = notAfter();
        caTmpl.KeyUsage = goish::crypto::x509::KeyUsageCertSign
            | goish::crypto::x509::KeyUsageCRLSign
            | goish::crypto::x509::KeyUsageDigitalSignature;
        caTmpl.BasicConstraintsValid = true;
        caTmpl.IsCA = true;
        caTmpl.SubjectKeyId = bs(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]);
        let mut r = fixedReader { n: 0 };
        let (caDER, _) = CreateCertificate(&mut r, &caTmpl, &caTmpl, &pub_, &privAny);
        let (ca, err) = ParseCertificate(caDER);
        checkErr(err, "<nil>", "CA certificate parses back");
        ca
    };

    // goref: CRL
    {
        let mut rl = RevocationList::default();
        rl.Number = bigFromI64(7);
        rl.ThisUpdate = notBefore();
        rl.NextUpdate = notAfter();
        rl.RevokedCertificateEntries = slice::__from_vec(alloc::vec![
            RevocationListEntry {
                SerialNumber: bigFromI64(0xaa),
                RevocationTime: notBefore(),
                ReasonCode: 1,
                ..Default::default()
            },
            RevocationListEntry {
                SerialNumber: bigFromI64(0xbb),
                RevocationTime: notBefore(),
                ..Default::default()
            },
        ]);
        let mut r = fixedReader { n: 0 };
        let (der, err) = CreateRevocationList(&mut r, &rl, &ca, &priv_);
        checkErr(err, "<nil>", "CreateRevocationList err");
        checkHex(&der, CRL, "CreateRevocationList (reasonCode + plain entry) == Go");
    }

    // goref: CRL_EMPTY — revokedCertificates must be omitted entirely
    {
        let mut rl = RevocationList::default();
        rl.Number = bigFromI64(1);
        rl.ThisUpdate = notBefore();
        rl.NextUpdate = notAfter();
        let mut r = fixedReader { n: 0 };
        let (der, err) = CreateRevocationList(&mut r, &rl, &ca, &priv_);
        checkErr(err, "<nil>", "CreateRevocationList empty err");
        checkHex(&der, CRL_EMPTY, "no entries omits revokedCertificates == Go");
    }

    // goref: CRL_DEPRECATED — the RevokedCertificates fallback
    {
        let mut rl = RevocationList::default();
        rl.Number = bigFromI64(2);
        rl.ThisUpdate = notBefore();
        rl.NextUpdate = notAfter();
        rl.RevokedCertificates = slice::__from_vec(alloc::vec![pkix::RevokedCertificate {
            SerialNumber: bigFromI64(0x11),
            RevocationTime: notBefore(),
            ..Default::default()
        }]);
        let mut r = fixedReader { n: 0 };
        let (der, err) = CreateRevocationList(&mut r, &rl, &ca, &priv_);
        checkErr(err, "<nil>", "CreateRevocationList deprecated-field err");
        checkHex(&der, CRL_DEPRECATED, "deprecated RevokedCertificates path == Go");
    }

    // goref: CRL_EXTRAEXT
    {
        let mut rl = RevocationList::default();
        rl.Number = bigFromI64(3);
        rl.ThisUpdate = notBefore();
        rl.NextUpdate = notAfter();
        rl.ExtraExtensions = slice::__from_vec(alloc::vec![pkix::Extension {
            Id: oidOf(&[1, 2, 3, 4, 5]),
            Critical: false,
            Value: bs(&[0x05, 0x00]),
        }]);
        let mut r = fixedReader { n: 0 };
        let (der, err) = CreateRevocationList(&mut r, &rl, &ca, &priv_);
        checkErr(err, "<nil>", "CreateRevocationList ExtraExtensions err");
        checkHex(&der, CRL_EXTRAEXT, "CRL ExtraExtensions appended == Go");
    }

    // ── CreateRevocationList rejections ──────────────────────────────
    // goref: CRL_ERR_*
    {
        let mut r = fixedReader { n: 0 };

        let mut rl = RevocationList::default();
        rl.Number = bigFromI64(1);
        rl.ThisUpdate = notAfter();
        rl.NextUpdate = notBefore();
        let (_, err) = CreateRevocationList(&mut r, &rl, &ca, &priv_);
        checkErr(
            err,
            "x509: template.ThisUpdate is after template.NextUpdate",
            "ThisUpdate after NextUpdate rejected",
        );

        let mut rl = RevocationList::default();
        rl.ThisUpdate = notBefore();
        rl.NextUpdate = notAfter();
        let (_, err) = CreateRevocationList(&mut r, &rl, &ca, &priv_);
        checkErr(err, "x509: template contains nil Number field", "nil Number rejected");

        let mut noCRLSign = ca.clone();
        noCRLSign.KeyUsage = goish::crypto::x509::KeyUsageCertSign;
        let mut rl = RevocationList::default();
        rl.Number = bigFromI64(1);
        rl.ThisUpdate = notBefore();
        rl.NextUpdate = notAfter();
        let (_, err) = CreateRevocationList(&mut r, &rl, &noCRLSign, &priv_);
        checkErr(
            err,
            "x509: issuer must have the crlSign key usage bit set",
            "issuer without crlSign rejected",
        );

        let mut noSKID = ca.clone();
        noSKID.SubjectKeyId = slice::new();
        let (_, err) = CreateRevocationList(&mut r, &rl, &noSKID, &priv_);
        checkErr(
            err,
            "x509: issuer certificate doesn't contain a subject key identifier",
            "issuer without SubjectKeyId rejected",
        );

        let mut rl = RevocationList::default();
        rl.Number = bigFromI64(4);
        rl.ThisUpdate = notBefore();
        rl.NextUpdate = notAfter();
        rl.RevokedCertificateEntries = slice::__from_vec(alloc::vec![RevocationListEntry {
            RevocationTime: notBefore(),
            ..Default::default()
        }]);
        let (_, err) = CreateRevocationList(&mut r, &rl, &ca, &priv_);
        checkErr(
            err,
            "x509: template contains entry with nil SerialNumber field",
            "entry with nil SerialNumber rejected",
        );

        let mut rl = RevocationList::default();
        rl.Number = bigFromI64(5);
        rl.ThisUpdate = notBefore();
        rl.NextUpdate = notAfter();
        rl.RevokedCertificateEntries = slice::__from_vec(alloc::vec![RevocationListEntry {
            SerialNumber: bigFromI64(1),
            ..Default::default()
        }]);
        let (_, err) = CreateRevocationList(&mut r, &rl, &ca, &priv_);
        checkErr(
            err,
            "x509: template contains entry with zero RevocationTime field",
            "entry with zero RevocationTime rejected",
        );

        let mut rl = RevocationList::default();
        rl.Number = bigFromI64(6);
        rl.ThisUpdate = notBefore();
        rl.NextUpdate = notAfter();
        rl.RevokedCertificateEntries = slice::__from_vec(alloc::vec![RevocationListEntry {
            SerialNumber: bigFromI64(1),
            RevocationTime: notBefore(),
            ExtraExtensions: slice::__from_vec(alloc::vec![pkix::Extension {
                Id: oidOf(&[2, 5, 29, 21]),
                Critical: false,
                Value: bs(&[0x0a, 0x01, 0x01]),
            }]),
            ..Default::default()
        }]);
        let (_, err) = CreateRevocationList(&mut r, &rl, &ca, &priv_);
        checkErr(
            err,
            "x509: template contains entry with ReasonCode ExtraExtension; use ReasonCode field instead",
            "entry carrying a reasonCode ExtraExtension rejected",
        );

        // A 21-octet CRL number.
        let mut big21 = big::Int::default();
        big21.SetBytes(bs(&[
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]));
        let mut rl = RevocationList::default();
        rl.Number = big21;
        rl.ThisUpdate = notBefore();
        rl.NextUpdate = notAfter();
        let (_, err) = CreateRevocationList(&mut r, &rl, &ca, &priv_);
        checkErr(err, "x509: CRL number exceeds 20 octets", "21-octet CRL number rejected");
    }

    // ── Certificate.CreateCRL (deprecated) ───────────────────────────
    // goref: CREATECRL
    {
        let mut caTmpl = x509Cert();
        caTmpl.SerialNumber = bigFromI64(0x0123456789);
        caTmpl.Subject.CommonName = string::from("goish root");
        caTmpl.Subject.Organization = strs(&["Goish"]);
        caTmpl.NotBefore = notBefore();
        caTmpl.NotAfter = notAfter();
        caTmpl.KeyUsage =
            goish::crypto::x509::KeyUsageCertSign | goish::crypto::x509::KeyUsageCRLSign;
        caTmpl.BasicConstraintsValid = true;
        caTmpl.IsCA = true;
        caTmpl.SubjectKeyId = bs(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]);
        let mut r = fixedReader { n: 0 };
        let (caDER, _) = CreateCertificate(&mut r, &caTmpl, &caTmpl, &pub_, &privAny);
        let (ca2, _) = ParseCertificate(caDER);

        let revoked = slice::__from_vec(alloc::vec![pkix::RevokedCertificate {
            SerialNumber: bigFromI64(0xaa),
            RevocationTime: notBefore(),
            ..Default::default()
        }]);
        let mut r = fixedReader { n: 0 };
        let (der, err) = ca2.CreateCRL(&mut r, &privAny, &revoked, notBefore(), notAfter());
        checkErr(err, "<nil>", "Certificate.CreateCRL err");
        checkHex(&der, CREATECRL, "Certificate.CreateCRL == Go DER");
    }

    // ── The one primitive marshalCertificatePolicies' unreachable
    //    `policyIdentifiers` branch stands on ───────────────────────
    //
    // That branch is Go's `child.AddASN1ObjectIdentifier(v)`, and it is
    // only taken under `GODEBUG=x509usepolicies=0` — a setting goish
    // cannot express, so the branch is dead here. What it is *spelled*
    // as, `asn1::Marshal(&oid)`, is not dead, and this pins the claim
    // that the two emit the same element.
    // goref: OIDDER
    {
        let cases: [(&[int], &'static str, &'static str); 3] = [
            (&[1, 2, 3, 4], "06032a0304", "OID DER 1.2.3.4"),
            (&[2, 23, 140, 1, 2, 1], "060667810c010201", "OID DER 2.23.140.1.2.1"),
            (
                &[1, 3, 6, 1, 4, 1, 311, 21, 8],
                "06092b0601040182371508",
                "OID DER 1.3.6.1.4.1.311.21.8 (multi-byte base-128)",
            ),
        ];
        for c in cases.iter() {
            let (der, _) = asn1::Marshal(&oidOf(c.0));
            checkHex(&der, c.1, c.2);
        }
    }

    // ── CreateCertificateRequest ─────────────────────────────────────
    // goref: CSR_PLAIN / CSR_BARE / CSR_FULL / CSR_APPENDED / CSR_DUP
    {
        // Plain: buildCSRExtensions produces a SAN, and since
        // template.Attributes is empty a fresh extensionRequest
        // attribute is synthesized for it.
        let mut t = CertificateRequest::default();
        t.Subject.CommonName = string::from("goish csr");
        t.Subject.Organization = strs(&["Goish"]);
        t.DNSNames = strs(&["csr.example.com"]);
        let mut r = fixedReader { n: 0 };
        let (der, err) = CreateCertificateRequest(&mut r, &t, &privAny);
        checkErr(err, "<nil>", "CreateCertificateRequest err");
        checkHex(&der, CSR_PLAIN, "CreateCertificateRequest == Go DER");

        // No SANs: no extensionRequest attribute at all.
        let mut t = CertificateRequest::default();
        t.Subject.CommonName = string::from("bare");
        let mut r = fixedReader { n: 0 };
        let (der, err) = CreateCertificateRequest(&mut r, &t, &privAny);
        checkErr(err, "<nil>", "CreateCertificateRequest bare err");
        checkHex(&der, CSR_BARE, "CSR with no extensions == Go DER");

        // Every SAN kind plus ExtraExtensions.
        let (u, _) = url::Parse("https://csr.example.com/z");
        let mut t = CertificateRequest::default();
        t.Subject.CommonName = string::from("goish csr full");
        t.Subject.Country = strs(&["TH"]);
        t.DNSNames = strs(&["a.example.com", "b.example.com"]);
        t.EmailAddresses = strs(&["e@example.com"]);
        t.IPAddresses = slice::__from_vec(alloc::vec![net::ParseIP(string::from("127.0.0.1"))]);
        t.URIs = slice::__from_vec(alloc::vec![u]);
        t.ExtraExtensions = slice::__from_vec(alloc::vec![pkix::Extension {
            Id: oidOf(&[1, 2, 3, 4, 5]),
            Critical: false,
            Value: bs(&[0x05, 0x00]),
        }]);
        let mut r = fixedReader { n: 0 };
        let (der, err) = CreateCertificateRequest(&mut r, &t, &privAny);
        checkErr(err, "<nil>", "CreateCertificateRequest full err");
        checkHex(&der, CSR_FULL, "CSR with every SAN kind + ExtraExtensions == Go DER");

        // The extensionsAppended path: Attributes already carries an
        // extensionRequest, so the SAN is merged into it. This is the
        // branch where Go mutates through a shared slice header and
        // goish has to write back by index.
        let mut t = CertificateRequest::default();
        t.Subject.CommonName = string::from("goish csr attrs");
        t.DNSNames = strs(&["attr.example.com"]);
        t.Attributes = slice::__from_vec(alloc::vec![pkix::AttributeTypeAndValueSET {
            Type: oidOf(&[1, 2, 840, 113549, 1, 9, 14]),
            Value: slice::__from_vec(alloc::vec![slice::__from_vec(alloc::vec![
                pkix::AttributeTypeAndValue {
                    Type: oidOf(&[2, 5, 29, 19]),
                    Value: Any::new(bs(&[0x30, 0x00])),
                }
            ])]),
        }]);
        let mut r = fixedReader { n: 0 };
        let (der, err) = CreateCertificateRequest(&mut r, &t, &privAny);
        checkErr(err, "<nil>", "CreateCertificateRequest appended err");
        checkHex(&der, CSR_APPENDED, "SAN merged into an existing attribute == Go DER");

        // Same, but Attributes already specifies the SAN OID, so the
        // attribute wins and buildCSRExtensions' value is dropped.
        let mut t = CertificateRequest::default();
        t.Subject.CommonName = string::from("goish csr dup");
        t.DNSNames = strs(&["dup.example.com"]);
        t.Attributes = slice::__from_vec(alloc::vec![pkix::AttributeTypeAndValueSET {
            Type: oidOf(&[1, 2, 840, 113549, 1, 9, 14]),
            Value: slice::__from_vec(alloc::vec![slice::__from_vec(alloc::vec![
                pkix::AttributeTypeAndValue {
                    Type: oidOf(&[2, 5, 29, 17]),
                    Value: Any::new(bs(&[0x30, 0x00])),
                }
            ])]),
        }]);
        let mut r = fixedReader { n: 0 };
        let (der, err) = CreateCertificateRequest(&mut r, &t, &privAny);
        checkErr(err, "<nil>", "CreateCertificateRequest dup-OID err");
        checkHex(&der, CSR_DUP, "an Attributes-specified extension takes priority == Go DER");
    }

    // -- An OPTIONAL time::Time at its zero value ---------------------
    //
    // `tbsCertificateList.NextUpdate` is `asn1:"optional"`, so its zero
    // is omitted. Which value *is* the zero differs between the two
    // languages, and the difference belongs to `time`, not to x509:
    //
    //   Go     `time.Time{}` is year 1. Go omits NextUpdate at year 1
    //          and EMITS it at the Unix epoch — goref CRL_EXPIRY_EPOCH
    //          carries `170d3730303130313030303030305a`, which is
    //          "700101000000Z".
    //   goish  `time::Time` has no year-1 value at all.
    //          `Time::default()` and `time::Unix(0, 0)` are the same
    //          value: both `IsZero()`, both `Unix() == 0`, both
    //          `Year() == 1970`. So goish omits at the epoch.
    //
    // The assertion is therefore the semantic one — goish's zero time
    // produces exactly the CRL Go's zero time produces (goref
    // CRL_EXPIRY_GOZERO, byte-identical because every other field
    // agrees). The residue is only that goish cannot say "the epoch,
    // deliberately"; a caller who means 1970 gets the field dropped
    // where Go would write it. Should `time::Time` ever grow Go's
    // year-1 zero, this case splits in two and the explicit
    // `Unix(0, 0)` half expects CRL_EXPIRY_EPOCH instead.
    //
    // goref: CRL_EXPIRY_GOZERO
    {
        let mut caTmpl = x509Cert();
        caTmpl.SerialNumber = bigFromI64(0x0123456789);
        caTmpl.Subject.CommonName = string::from("goish root");
        caTmpl.Subject.Organization = strs(&["Goish"]);
        caTmpl.NotBefore = notBefore();
        caTmpl.NotAfter = notAfter();
        caTmpl.KeyUsage =
            goish::crypto::x509::KeyUsageCertSign | goish::crypto::x509::KeyUsageCRLSign;
        caTmpl.BasicConstraintsValid = true;
        caTmpl.IsCA = true;
        caTmpl.SubjectKeyId = bs(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]);
        let mut r = fixedReader { n: 0 };
        let (caDER, _) = CreateCertificate(&mut r, &caTmpl, &caTmpl, &pub_, &privAny);
        let (ca3, _) = ParseCertificate(caDER);

        let revoked = slice::__from_vec(alloc::vec![pkix::RevokedCertificate {
            SerialNumber: bigFromI64(0xaa),
            RevocationTime: notBefore(),
            ..Default::default()
        }]);
        let mut r = fixedReader { n: 0 };
        let (der, err) = ca3.CreateCRL(
            &mut r,
            &privAny,
            &revoked,
            notBefore(),
            time::Time::default(),
        );
        checkErr(err, "<nil>", "CreateCRL zero-expiry err");
        checkHex(
            &der,
            CRL_EXPIRY_GOZERO,
            "a zero NextUpdate is omitted, as Go omits its own zero",
        );
    }

    let ran = RAN.load(Ordering::Acquire);
    let failed = FAILED.load(Ordering::Acquire);
    fmt::Printf!("x509_create_smoke: %d checks, %d failed\n", int(ran), int(failed));
    if failed != 0 {
        goish::os::Exit(1);
    }
}

// go: none — goish idiom: Go writes `&Certificate{…}` composite
// literals; `Certificate` has ~50 fields, so the test builds a zero one
// and assigns the handful each case needs.
fn x509Cert() -> goish::crypto::x509::Certificate {
    return goish::crypto::x509::Certificate::default();
}

// go: none — goish idiom: `big.NewInt(n)`.
fn bigFromI64(n: i64) -> big::Int {
    let mut v = big::Int::default();
    v.SetInt64(n);
    return v;
}

// ── Go 1.25.5 reference DER, from scripts/goref.sh crypto/x509 ───────

const CERT_SELFSIGNED: &str = "3082014a3081fda00302010202050123456789300506032b65703025310e300c060355040a1305476f697368311330110603550403130a676f69736820726f6f74301e170d3234303130323033303430355a170d3334303130323033303430355a3025310e300c060355040a1305476f697368311330110603550403130a676f69736820726f6f74302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8a34e304c300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff30110603551d0e040a0408deadbeef0102030430160603551d11040f300d820b6578616d706c652e636f6d300506032b6570034100155857b8fe77f79b6f31476ee5e375a03ef3e72834659be5eca86c1cafadb0c4689f0ba2a0edb30ad31e99c0025e5eb5ffe3a4154750d1d939b5e8099a9d1f05";

const CERT_DERIVED_SKID: &str = "3082010a3081bda00302010202012a300506032b65703015311330110603550403130a676f69736820736b6964301e170d3234303130323033303430355a170d3334303130323033303430355a3015311330110603550403130a676f69736820736b6964302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8a3323030300f0603551d130101ff040530030101ff301d0603551d0e0416041456475aa75463474c0285df5dbf2bcab73da65135300506032b65700341004f7baec28bbee82b4c36249cdcbc48e3d1fa2ea37f7089915d957612044a74f4899c366ae6428fef9df06d8790d986748d75c9caa1322dafd003977b77450309";

const CERT_KITCHEN: &str = "3082033f308202f1a00302010202050123456789300506032b6570303a310b3009060355040613025448310e300c060355040a1305476f697368311b301906035504031312676f697368206b69746368656e2073696e6b301e170d3234303130323033303430355a170d3334303130323033303430355a303a310b3009060355040613025448310e300c060355040a1305476f697368311b301906035504031312676f697368206b69746368656e2073696e6b302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8a382021630820212300e0603551d0f0101ff04040302018630220603551d25041b301906082b0601050507030106082b0601050507030206032a030430120603551d130101ff040830060101ff020102300d0603551d0e04060404deadbeef300d0603551d23040630048002cafe305d06082b060105050701010451304f302306082b060105050730018617687474703a2f2f6f6373702e6578616d706c652e636f6d302806082b06010505073002861c687474703a2f2f63612e6578616d706c652e636f6d2f63612e63727430590603551d1104523050820b6578616d706c652e636f6d820f7777772e6578616d706c652e636f6d810d61406578616d706c652e636f6d87047f00000187040a010203861568747470733a2f2f6578616d706c652e636f6d2f78301a0603551d2004133011300506032a03043008060667810c0102013081980603551d1e0101ff04818d30818aa040300d820b6578616d706c652e636f6d300a87080a000000ff0000003010810e6f6b406578616d706c652e636f6d3011860f7572692e6578616d706c652e636f6da1463011820f6261642e6578616d706c652e636f6d300a8708c0a80000ffff00003010810e6e6f406578616d706c652e636f6d301386116e6f7572692e6578616d706c652e636f6d302d0603551d1f042630243022a020a01e861c687474703a2f2f63726c2e6578616d706c652e636f6d2f782e63726c300a06042a03040504020500300506032b657003410027fc51b379431b720810eada7ed284fc537288616d08e59fafd2e74d401121e860f2e1dc8e8e8fc1129e3f378bd26250e48ad90a7f8216f42b098859ce8cdb0e";

const CERT_KU_1: &str = "3081da30818da003020102020101300506032b6570300d310b3009060355040313026b75301e170d3234303130323033303430355a170d3334303130323033303430355a300d310b3009060355040313026b75302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8a3123010300e0603551d0f0101ff040403020780300506032b6570034100a6158d67a802a0052c4c0c82b70c1fb48a900528456883282b736e8fc6b1098cc0903485d932049802ea46ea3b196686913b798e4a5950ac96412b63cfae3b0a";

const CERT_KU_96: &str = "3081da30818da003020102020101300506032b6570300d310b3009060355040313026b75301e170d3234303130323033303430355a170d3334303130323033303430355a300d310b3009060355040313026b75302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8a3123010300e0603551d0f0101ff040403020106300506032b657003410031b2f4362aaed2fbffedbda4b6fb7ebdd10fbcafa56df601270eaecca1fbf42a2ba8a3d6d00e4099ad4280d03e869db459bd22ee45307d999826361718315904";

const CERT_KU_5: &str = "3081da30818da003020102020101300506032b6570300d310b3009060355040313026b75301e170d3234303130323033303430355a170d3334303130323033303430355a300d310b3009060355040313026b75302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8a3123010300e0603551d0f0101ff0404030205a0300506032b6570034100209b1e097e1b9b6f4be312e691835fc809a1081ba03c1826a5e7720dc2a0739b1aa9a611952d1444ce740df196f0b358f0106538c1f4feb2b4143d1d4298c60a";

const CERT_KU_256: &str = "3081db30818ea003020102020101300506032b6570300d310b3009060355040313026b75301e170d3234303130323033303430355a170d3334303130323033303430355a300d310b3009060355040313026b75302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8a3133011300f0603551d0f0101ff04050303070080300506032b6570034100eb6969b308e137e7a087093b87deeda45871296bb63a1bbd03dd64e0c8652d16f38356fd02ce6d7ea8c22d4fdc9747f40ecf985cc22b49bf1300166ad3413d00";

const CERT_KU_384: &str = "3081db30818ea003020102020101300506032b6570300d310b3009060355040313026b75301e170d3234303130323033303430355a170d3334303130323033303430355a300d310b3009060355040313026b75302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8a3133011300f0603551d0f0101ff04050303070180300506032b6570034100063b2cdf0ab31be0f45789a4ddbb243c0623c7a4d79e78185ef0dce4e246d91ea5718d277622b55bd70678cf103217817d0f8ec7ca0c4462b95a1a6dadab5e0f";

const CERT_GENSERIAL: &str = "3081e830819ba00302010202130102030405060708090a0b0c0d0e0f10111213300506032b65703015311330110603550403130a67656e2073657269616c301e170d3234303130323033303430355a170d3334303130323033303430355a3015311330110603550403130a67656e2073657269616c302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8300506032b65700341001db7e95aca09ea0988e68a5184dd625cfa6e04c3e4370a81b10769cffb1d6d9a4703635289d9a6862faa3286f8879e3ed4f9b2e2cb621e5b2e622108d339ba0c";

const CERT_EMPTYSUBJ: &str = "3081d5308188a003020102020102300506032b65703000301e170d3234303130323033303430355a170d3334303130323033303430355a3000302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8a327302530230603551d110101ff0419301782156e6f7375626a6563742e6578616d706c652e636f6d300506032b65700341001275d01f3aa9bb2e91bbddba48dee9b3e77058540bafbc9709e987d2051a907670439a40498cca18e5552018d6122980a635542e8034b2357028e495c3593701";

const CRL: &str = "3081fb3081ae020101300506032b65703025310e300c060355040a1305476f697368311330110603550403130a676f69736820726f6f74170d3234303130323033303430355a170d3334303130323033303430355a30383021020200aa170d3234303130323033303430355a300c300a0603551d1504030a01013013020200bb170d3234303130323033303430355aa023302130130603551d23040c300a8008deadbeef01020304300a0603551d140403020107300506032b65700341004d0b67817ddba39d6e76819372577b6afd56a1e63c862265d61e38812e46221ce7854c605e4692a5a1f4c3b1b05603240b298524600163b729b1140190a90e06";

const CRL_EMPTY: &str = "3081c03074020101300506032b65703025310e300c060355040a1305476f697368311330110603550403130a676f69736820726f6f74170d3234303130323033303430355a170d3334303130323033303430355aa023302130130603551d23040c300a8008deadbeef01020304300a0603551d140403020101300506032b6570034100322c86927f91b3954a0fdd8a009bf104a6e88b602c705cad3c86dfbb715325e99cd95a002fd3262ba97eb055a4219402ec52b1a616481b02de81ad219e5c6104";

const CRL_DEPRECATED: &str = "3081d730818a020101300506032b65703025310e300c060355040a1305476f697368311330110603550403130a676f69736820726f6f74170d3234303130323033303430355a170d3334303130323033303430355a30143012020111170d3234303130323033303430355aa023302130130603551d23040c300a8008deadbeef01020304300a0603551d140403020102300506032b6570034100844f6052f547258b3aa02f8b963de7b1bacdd023229da8d5edd96746072047aa66c87030e76f10769267d62c0704287145aa51ccb40c0afb6133365d55402c08";

const CRL_EXTRAEXT: &str = "3081cd308180020101300506032b65703025310e300c060355040a1305476f697368311330110603550403130a676f69736820726f6f74170d3234303130323033303430355a170d3334303130323033303430355aa02f302d30130603551d23040c300a8008deadbeef01020304300a0603551d140403020103300a06042a03040504020500300506032b65700341004d44d498685696c6f35bd7971c668734116ab652996691b140cc6a8280b6989e56791dde5f99976afaf3ff2878954ee13fd8116441461b160116a41d068e0f0f";

const CREATECRL: &str = "3081cb307f020101300506032b65703025310e300c060355040a1305476f697368311330110603550403130a676f69736820726f6f74170d3234303130323033303430355a170d3334303130323033303430355a30153013020200aa170d3234303130323033303430355aa017301530130603551d23040c300a8008deadbeef01020304300506032b65700341000e40d5391b410eb43423561f4c50fc20bb42bf754b52764f2f640d9edc1fad0c9b2ce7714185232390ad0507814d944554b043e14e72b0f56ce641ff2312af07";

const CSR_PLAIN: &str = "3081d13081840201003024310e300c060355040a1305476f6973683112301006035504031309676f69736820637372302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8a02d302b06092a864886f70d01090e311e301c301a0603551d1104133011820f6373722e6578616d706c652e636f6d300506032b6570034100b59cf507af6fd0e083fbb0b7b07d0b3e830292dd80d7c2406b2dbd8653a23eb87818d0a291c14a7b39cb674c68909ce0c1dc45b826c0054ad7997c05e1d3070f";

const CSR_BARE: &str = "30818e3042020100300f310d300b0603550403130462617265302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8a000300506032b6570034100f3b9eeb3ebb58d8661bf68efa1175f1cfdd4c70f1f09fe1c44e46298d79b381af03118573b0a8404e857420871bbf18aa5e82a4a2ce65dde651997c54118e203";

const CSR_FULL: &str = "3082011c3081cf0201003026310b3009060355040613025448311730150603550403130e676f697368206373722066756c6c302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8a076307406092a864886f70d01090e3167306530570603551d110450304e820d612e6578616d706c652e636f6d820d622e6578616d706c652e636f6d810d65406578616d706c652e636f6d87047f000001861968747470733a2f2f6373722e6578616d706c652e636f6d2f7a300a06042a03040504020500300506032b65700341003aad31de13b5194e6f6c28cfc2fa89ed26def5269e01d6bbe6f7d2563deabdb5fdb3211155b75ef9420cd3a09139f5fa0f8ae30bceb25e7f4dc6765499a18c05";

const CSR_APPENDED: &str = "3081d3308186020100301a311830160603550403130f676f69736820637372206174747273302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8a039303706092a864886f70d01090e312a302830090603551d1304023000301b0603551d11041430128210617474722e6578616d706c652e636f6d300506032b6570034100f93698823a7fb4c8cb4de4bb7ab407c67b09116e4843975303f656dd39c60e3f63592db581856006b8ccc8fc97ce9ab207ef396c39d7f8d457197aada8d4b703";

const CSR_DUP: &str = "3081b330670201003018311630140603550403130d676f6973682063737220647570302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8a01c301a06092a864886f70d01090e310d300b30090603551d1104023000300506032b65700341009c22b4f17a6cb5e287fa04df9a15f32fe3f5fbaaeac62648243a401745b1229773b2b54ecf8ce875808f471d774503671fe93efc37161dab2d30ceb017f12601";

const CRL_EXPIRY_GOZERO: &str = "3081bc3070020101300506032b65703025310e300c060355040a1305476f697368311330110603550403130a676f69736820726f6f74170d3234303130323033303430355a30153013020200aa170d3234303130323033303430355aa017301530130603551d23040c300a8008deadbeef01020304300506032b65700341007f13aedbb11a5e9ebb7660042180a8c70ed950a3b67fd3d3ccc977686b7a4f7438d269a00c4cb75bd825ec582e52bd5e0714f607a5d92a770cdf379d16057201";
