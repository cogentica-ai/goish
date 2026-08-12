// x509_parse_smoke — crypto/x509's certificate parser vs Go 1.25.5.
//
// The certificate below and EVERY expectation in this file are
// `scripts/goref.sh crypto/x509` output — a `TestGoishRef` that builds a
// certificate with `CreateCertificate` and then prints what Go's own
// (unexported) `parseCertificate` reads back out of it. Nothing here is
// transcribed from a spec or from memory.
//
// The certificate carries eight extensions on purpose, so that the eight
// live branches of `processExtensions` all run:
//
//   2.5.29.15  keyUsage              (critical)
//   2.5.29.37  extKeyUsage
//   2.5.29.19  basicConstraints      (critical, pathLen 2)
//   2.5.29.14  subjectKeyIdentifier
//   1.3.6.1.5.5.7.1.1 authorityInfoAccess (OCSP + caIssuers)
//   2.5.29.17  subjectAltName        (DNS x2, email, IP, URI)
//   2.5.29.30  nameConstraints       (permitted DNS + IP, excluded DNS)
//   2.5.29.31  cRLDistributionPoints
//
// It also pins the two "read the element including its header" reads
// that `Certificate.Raw` / `RawTBSCertificate` / `RawSubject` /
// `RawIssuer` / `RawSubjectPublicKeyInfo` depend on: a one-byte slip in
// `ReadASN1Element` moves every one of those five lengths.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::crypto::rsa;
use goish::crypto::x509::{ParseCertificate, ParseCertificates};
use goish::encoding::pem;
use goish::goslice::slice;
use goish::types::byte;
use goish::{convert, fmt, string};

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

/// Self-signed RSA-2048 CA emitted by the goref run described above.
pub const CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIE4DCCA8igAwIBAgIFAQIDBAUwDQYJKoZIhvcNAQELBQAwbDELMAkGA1UEBhMC\n\
VEgxEDAOBgNVBAcTB0Jhbmdrb2sxFzAVBgNVBAoTDkdvaXNoIFRlc3QgT3JnMQ4w\n\
DAYDVQQLEwVQb3J0czETMBEGA1UEAxMKZ29pc2ggbGVhZjENMAsGA1UEBRMEU04t\n\
NzAeFw0yNDAzMDExMjAwMDBaFw0zMzA0MDIxMzE0MTVaMGwxCzAJBgNVBAYTAlRI\n\
MRAwDgYDVQQHEwdCYW5na29rMRcwFQYDVQQKEw5Hb2lzaCBUZXN0IE9yZzEOMAwG\n\
A1UECxMFUG9ydHMxEzARBgNVBAMTCmdvaXNoIGxlYWYxDTALBgNVBAUTBFNOLTcw\n\
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEE3zZMggLiQDVMKhbusFF\n\
qr5rE7BxpUMyaL9fCRhQHqKRaqwBHzo7fry6P9/SQmGQehkiS4ciMyhFI8YtYjHq\n\
dCT/K0o5Y0kk2gFBzmEWNKRN3J+dxZWYrA5gExmMpQCTdsYUSHG1683Z7a+S1rcL\n\
c+rHxhYDswT6HIioJfiF+Mko+27mtCirEJzHe/wA0NzHv6Wk+rQmjA8spQ4azr88\n\
duWqrxmh5l6Xcy6l1pnHaOvsIk78JtP7KTTeTvtLKCqdzrRrBKj+ISBj2gXopXJW\n\
ROUBenJhcyNYROah0woJNrNw0Eq1ILBLBree7hx6rGog90dUn8lGkW7FWVnRgH8t\n\
AgMBAAGjggGHMIIBgzAOBgNVHQ8BAf8EBAMCAqQwHQYDVR0lBBYwFAYIKwYBBQUH\n\
AwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQIwDgYDVR0OBAcEBQECAwQF\n\
MGEGCCsGAQUFBwEBBFUwUzAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AuZ29pc2gu\n\
ZXhhbXBsZTAqBggrBgEFBQcwAoYeaHR0cDovL2NhLmdvaXNoLmV4YW1wbGUvY2Eu\n\
Y3J0MF8GA1UdEQRYMFaCDWdvaXNoLmV4YW1wbGWCEXd3dy5nb2lzaC5leGFtcGxl\n\
gRJwb3J0QGdvaXNoLmV4YW1wbGWHBMAAAgqGGGh0dHBzOi8vZ29pc2guZXhhbXBs\n\
ZS9jYTA5BgNVHR4EMjAwoB0wD4INZ29pc2guZXhhbXBsZTAKhwgKAAAA/wAAAKEP\n\
MA2CC2JhZC5leGFtcGxlMC8GA1UdHwQoMCYwJKAioCCGHmh0dHA6Ly9jcmwuZ29p\n\
c2guZXhhbXBsZS94LmNybDANBgkqhkiG9w0BAQsFAAOCAQEAdIYb7TNaVRqsSMoV\n\
fCf+IcCmKjZaKJfIkxrOpupQZK205mzX+/w3szqUl/EUFhFrmqWCBAgntuZ7VZDN\n\
XF9KBrNjNwbCkV8EkP/uyNDzr0PYuutfhEY7V7GbJX4aUU+i+unHbTEcPbQjoVTW\n\
g6DVUUihnejtkee3b88GaRQFWhWy1GgwUPLe3xx2UEsok7bcBfFOzsOwyU8jcdl6\n\
YXQca37j974lL9Ej/C6lnO+ilk45+T08TVx3YQCmQGJWXYmmUQOL7WYZOPXEhreo\n\
gZrVDGi8Uw80/fjU2zWB58JCMly/pK9s3yGcYqYSmDZfZZ3PR4appnTEXHCBV6AY\n\
Rr1Nlw==\n\
-----END CERTIFICATE-----\n";

/// The DER inside CERT_PEM.
pub fn cert_der() -> slice<byte> {
    let (block, _) = pem::Decode(convert::bytes(CERT_PEM));
    let block = match block {
        None => {
            fmt::Printf!("pem::Decode returned nil block\n");
            goish::syscall::Exit(1);
        }
        Some(b) => b,
    };
    return block.Bytes;
}

fn hexs(b: &slice<byte>) -> goish::string {
    return goish::encoding::hex::EncodeToString(b.as_ref());
}

#[goish::main]
fn main() {
    let der = cert_der();
    // goref: len(Raw)=1252
    check(der.Len() == 1252, "PEM decodes to Go's 1252-byte DER");

    let (c, err) = ParseCertificate(der.clone());
    check(err == goish::nil, "ParseCertificate returns no error");
    if err != goish::nil {
        fmt::Printf!("  err=%s\n", err.Error());
        goish::syscall::Exit(1);
    }

    // ── the TBS scaffolding ──────────────────────────────────────────
    check(c.Version == 3, "Version=3");
    // goref: SerialNumber=4328719365
    check(c.SerialNumber.Int64() == 4328719365, "SerialNumber=4328719365");
    check(
        c.SignatureAlgorithm.String().as_bytes() == b"SHA256-RSA",
        "SignatureAlgorithm=SHA256-RSA",
    );
    check(
        c.PublicKeyAlgorithm.String().as_bytes() == b"RSA",
        "PublicKeyAlgorithm=RSA",
    );

    // ── the five ReadASN1Element-derived raw spans ───────────────────
    // goref: len(Raw)=1252 len(RawTBSCertificate)=972 len(RawSubject)=110
    //        len(RawIssuer)=110 len(RawSPKI)=294 len(Signature)=256
    check(c.Raw.Len() == 1252, "len(Raw)=1252");
    check(c.RawTBSCertificate.Len() == 972, "len(RawTBSCertificate)=972");
    check(c.RawSubject.Len() == 110, "len(RawSubject)=110");
    check(c.RawIssuer.Len() == 110, "len(RawIssuer)=110");
    check(c.RawSubjectPublicKeyInfo.Len() == 294, "len(RawSubjectPublicKeyInfo)=294");
    check(c.Signature.Len() == 256, "len(Signature)=256");
    // goref: RawSubjectHex=306c310b3009060355040613025448...
    check(
        hexs(&c.RawSubject).as_bytes().starts_with(b"306c310b30090603550406130254483110300e0603550407130742616e676b6f6b"),
        "RawSubject DER matches Go byte-for-byte (prefix)",
    );

    // ── the RDN walk (parseName + parseASN1String) ───────────────────
    check(c.Subject.CommonName.as_bytes() == b"goish leaf", "Subject.CommonName");
    check(
        c.Subject.Organization.Len() == 1
            && c.Subject.Organization[0].as_bytes() == b"Goish Test Org",
        "Subject.Organization",
    );
    check(
        c.Subject.OrganizationalUnit.Len() == 1
            && c.Subject.OrganizationalUnit[0].as_bytes() == b"Ports",
        "Subject.OrganizationalUnit",
    );
    check(
        c.Subject.Country.Len() == 1 && c.Subject.Country[0].as_bytes() == b"TH",
        "Subject.Country",
    );
    check(
        c.Subject.Locality.Len() == 1 && c.Subject.Locality[0].as_bytes() == b"Bangkok",
        "Subject.Locality",
    );
    check(c.Subject.SerialNumber.as_bytes() == b"SN-7", "Subject.SerialNumber");
    check(c.Issuer.CommonName.as_bytes() == b"goish leaf", "Issuer.CommonName");

    // ── validity (cryptobyte's UTCTime reader) ───────────────────────
    // goref: NotBefore=1709294400 NotAfter=1996060455
    check(c.NotBefore.Unix() == 1709294400, "NotBefore=1709294400");
    check(c.NotAfter.Unix() == 1996060455, "NotAfter=1996060455");

    // ── extensions ───────────────────────────────────────────────────
    // goref: len(Extensions)=8, ids/criticality/value-lengths in order.
    check(c.Extensions.Len() == 8, "len(Extensions)=8");
    let want_ids: [&str; 8] = [
        "2.5.29.15",
        "2.5.29.37",
        "2.5.29.19",
        "2.5.29.14",
        "1.3.6.1.5.5.7.1.1",
        "2.5.29.17",
        "2.5.29.30",
        "2.5.29.31",
    ];
    let want_crit: [bool; 8] = [true, false, true, false, false, false, false, false];
    let want_len: [i64; 8] = [4, 22, 8, 7, 85, 88, 50, 40];
    let mut ext_ok = c.Extensions.Len() == 8;
    if ext_ok {
        for (i, e) in goish::range!(c.Extensions.clone()) {
            let k = i as usize;
            if e.Id.String().as_bytes() != want_ids[k].as_bytes()
                || e.Critical != want_crit[k]
                || e.Value.Len() != want_len[k]
            {
                ext_ok = false;
            }
        }
    }
    check(ext_ok, "Extensions: ids, criticality and value lengths in Go's order");
    check(
        c.UnhandledCriticalExtensions.Len() == 0,
        "len(UnhandledCriticalExtensions)=0",
    );

    // keyUsage — goref: KeyUsage=37 (DigitalSignature|KeyEncipherment|CertSign)
    check(c.KeyUsage.0 == 37, "KeyUsage=37");

    // extKeyUsage — goref: ExtKeyUsage=[1 2] (ServerAuth, ClientAuth)
    check(
        c.ExtKeyUsage.Len() == 2 && c.ExtKeyUsage[0].0 == 1 && c.ExtKeyUsage[1].0 == 2,
        "ExtKeyUsage=[ServerAuth ClientAuth]",
    );

    // basicConstraints — goref: valid=true IsCA=true MaxPathLen=2 zero=false
    check(
        c.BasicConstraintsValid && c.IsCA && c.MaxPathLen == 2 && !c.MaxPathLenZero,
        "basicConstraints: CA, pathLen 2",
    );

    // subjectKeyIdentifier — goref: SubjectKeyId=0102030405, AuthorityKeyId empty
    check(
        hexs(&c.SubjectKeyId).as_bytes() == b"0102030405",
        "SubjectKeyId=0102030405",
    );
    check(c.AuthorityKeyId.Len() == 0, "AuthorityKeyId empty");

    // subjectAltName — goref: two DNS, one email, one IP, one URI
    check(
        c.DNSNames.Len() == 2
            && c.DNSNames[0].as_bytes() == b"goish.example"
            && c.DNSNames[1].as_bytes() == b"www.goish.example",
        "DNSNames",
    );
    check(
        c.EmailAddresses.Len() == 1
            && c.EmailAddresses[0].as_bytes() == b"port@goish.example",
        "EmailAddresses",
    );
    check(
        c.IPAddresses.Len() == 1 && hexs(&c.IPAddresses[0].bytes).as_bytes() == b"c000020a",
        "IPAddresses=[192.0.2.10]",
    );
    check(
        c.URIs.Len() == 1 && c.URIs[0].String().as_bytes() == b"https://goish.example/ca",
        "URIs=[https://goish.example/ca]",
    );

    // authorityInfoAccess — goref: one OCSP, one caIssuers
    check(
        c.OCSPServer.Len() == 1
            && c.OCSPServer[0].as_bytes() == b"http://ocsp.goish.example",
        "OCSPServer",
    );
    check(
        c.IssuingCertificateURL.Len() == 1
            && c.IssuingCertificateURL[0].as_bytes() == b"http://ca.goish.example/ca.crt",
        "IssuingCertificateURL",
    );

    // cRLDistributionPoints
    check(
        c.CRLDistributionPoints.Len() == 1
            && c.CRLDistributionPoints[0].as_bytes() == b"http://crl.goish.example/x.crl",
        "CRLDistributionPoints",
    );

    // nameConstraints — goref: permitted DNS + IP 10.0.0.0/8, excluded DNS
    check(
        c.PermittedDNSDomains.Len() == 1
            && c.PermittedDNSDomains[0].as_bytes() == b"goish.example",
        "PermittedDNSDomains",
    );
    check(
        c.ExcludedDNSDomains.Len() == 1
            && c.ExcludedDNSDomains[0].as_bytes() == b"bad.example",
        "ExcludedDNSDomains",
    );
    check(
        c.PermittedIPRanges.Len() == 1
            && hexs(&c.PermittedIPRanges[0].IP.bytes).as_bytes() == b"0a000000"
            && hexs(&c.PermittedIPRanges[0].Mask.bytes).as_bytes() == b"ff000000",
        "PermittedIPRanges=[10.0.0.0/8]",
    );
    check(
        !c.PermittedDNSDomainsCritical,
        "PermittedDNSDomainsCritical=false",
    );

    // ── the public key (parsePublicKey, RSA arm) ─────────────────────
    // goref: PublicKey.E=65537 BitLen=2048 N.Bytes[0:8]=c4137cd932080b89
    let pk = match c.PublicKey.As::<rsa::PublicKey>() {
        None => {
            check(false, "PublicKey downcasts to rsa::PublicKey");
            goish::syscall::Exit(1);
        }
        Some(k) => k.clone(),
    };
    check(true, "PublicKey downcasts to rsa::PublicKey");
    check(pk.E == 65537, "PublicKey.E=65537");
    check(pk.N.BitLen() == 2048, "PublicKey.N.BitLen=2048");
    check(
        hexs(&pk.N.Bytes()).as_bytes().starts_with(b"c4137cd932080b89"),
        "PublicKey.N.Bytes[0:8]=c4137cd932080b89",
    );

    // ── ParseCertificate's trailing-data guard ───────────────────────
    let mut extra = der.as_ref().to_vec();
    extra.push(0x00);
    let (_, err) = ParseCertificate(slice::__from_vec(extra));
    check(
        err != goish::nil && err.Error().as_bytes() == b"x509: trailing data",
        "one trailing byte => \"x509: trailing data\"",
    );

    // ── ParseCertificates walks a concatenation ──────────────────────
    let mut two = der.as_ref().to_vec();
    two.extend_from_slice(der.as_ref());
    let (certs, err) = ParseCertificates(slice::__from_vec(two));
    check(err == goish::nil, "ParseCertificates(der||der) succeeds");
    check(certs.Len() == 2, "ParseCertificates yields 2 certificates");
    check(
        certs.Len() == 2 && certs[0 as i64].Raw.Len() == 1252 && certs[1 as i64].Raw.Len() == 1252,
        "both halves keep their own 1252-byte Raw",
    );

    // ── a truncated certificate is an error, not a panic ─────────────
    let head = der.as_ref()[..600].to_vec();
    let (_, err) = ParseCertificate(slice::__from_vec(head));
    check(err != goish::nil, "truncated DER => error");

    let failed = FAILED.load(Ordering::Acquire);
    let ran = RAN.load(Ordering::Acquire);
    if failed == 0 {
        fmt::Printf!("x509_parse_smoke OK %d/%d\n", ran as i64, ran as i64);
    } else {
        fmt::Printf!("x509_parse_smoke FAILED %d of %d\n", failed as i64, ran as i64);
        goish::syscall::Exit(1);
    }
}
