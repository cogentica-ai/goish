// go: file crypto/x509/parser.go decls: isPrintable, parseASN1String, parseName, parseAI, parseTime, parseValidity, parseExtension, parsePublicKey, parseKeyUsageExtension, parseBasicConstraintsExtension, forEachSAN, parseSANExtension, parseAuthorityKeyIdentifier, parseExtKeyUsageExtension, parseCertificatePoliciesExtension, isValidIPMask, parseNameConstraintsExtension, processExtensions, parseCertificate, ParseCertificate, ParseCertificates, domainNameValid
//
// The cryptobyte-based DER parser for X.509 certificates.
//
// parser.go uses `cryptobyte` exclusively and contains zero
// `asn1.Unmarshal` calls, which is why it is the reachable half of
// crypto/x509: goish has `crypto/cryptobyte` and does not have
// `encoding/asn1.Unmarshal`.
//
// **What is not here:** `ParseRevocationList` and the `x509v2Version`
// const it uses. A CRL parse needs `RevocationList` and
// `RevocationListEntry`, whose home is x509.go's unported CRL half.
// Everything on the certificate path is here.
//
// Deviations from parser[go] @ Go 1.25.5:
//
//   * `parseCertificate`'s negative-serial branch is gated on
//     `x509negativeserial`, an `internal/godebug` knob. goish has no
//     godebug, so the branch takes the default: a negative serial number
//     is an error, unconditionally. Setting `GODEBUG=x509negativeserial=1`
//     has no effect because there is nothing to read it.
//   * Go returns `*Certificate` and `nil` on error; goish returns the
//     zero `Certificate` beside the error, the shape the rest of the
//     repo uses for a Go pointer-or-nil return.
//   * `forEachSAN`'s `callback func(tag int, data []byte) error` is a
//     generic `FnMut` parameter rather than a `dyn Fn` — AGENTS.md §5
//     rule 3 bans trait objects from the public surface, and a generic
//     is the closer reading of a Go func parameter anyway.
//   * `parseSANExtension` accumulates into locals and returns them,
//     because Go's named-result closure capture (`emailAddresses =
//     append(emailAddresses, …)` inside the callback) needs a `&mut`
//     borrow that a single closure can hold; the four slices are bundled
//     into one `sanResult` the closure mutates.
//   * `processExtensions`'s `seenExts map[string]bool` keys on
//     `ext.Id.String()`; `parseCertificatePoliciesExtension`'s
//     `seenOIDs map[string]bool` keys on the raw OID bytes, which Go
//     spells `string(OIDBytes)`. goish uses `string::from_bytes`, the
//     same byte-for-byte conversion.
//   * Go's `net.IP(ip)` conversion of a byte slice becomes
//     `net::IP { bytes: … }`; goish's `net::IP` names the backing field
//     instead of being a defined slice type.
//
// goishlint:ignore GOISH018 ParseRevocationList — a CRL parse needs RevocationList and RevocationListEntry, which live in x509.go's unported CRL half; see the banner.
// goishlint:ignore GOISH021 x509negativeserial, x509v2Version — the godebug knob has no goish counterpart (the default, reject, is unconditional) and the CRL version const lands with ParseRevocationList.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use super::oid::{newOIDFromDER, OID};
use super::verify::parseRFC2821Mailbox;
use super::x509::{
    extKeyUsageFromOID, getPublicKeyAlgorithmFromOID, getSignatureAlgorithmFromAI, isIA5String,
    namedCurveFromOID, nameTypeDNS, nameTypeEmail, nameTypeIP, nameTypeURI,
    oidAuthorityInfoAccessIssuers, oidAuthorityInfoAccessOcsp, oidExtensionAuthorityInfoAccess,
    oidPublicKeyDSA, oidPublicKeyECDSA, oidPublicKeyEd25519, oidPublicKeyRSA, oidPublicKeyX25519,
    publicKeyInfo, Certificate, ExtKeyUsage, KeyUsage, PolicyMapping, UnknownPublicKeyAlgorithm,
};
use crate::crypto::cryptobyte::asn1 as cryptobyte_asn1;
use crate::crypto::cryptobyte::String as CBString;
use crate::crypto::x509::pkix;
use crate::crypto::{dsa, ecdh, ecdsa, ed25519, elliptic, rsa};
use crate::encoding::asn1;
use crate::error;
use crate::errors;
use crate::goany::Any;
use crate::gomap::map;
use crate::goslice::slice;
use crate::gostring::string;
use crate::math::big;
use crate::net;
use crate::net::url;
use crate::strings;
use crate::time;
use crate::int;
use crate::types::byte;
use crate::unicode::{utf16, utf8};

// go: sdk 1.25.5 crypto/x509/parser.go:34-55 isPrintable
/// Report whether the given b is in the ASN.1 PrintableString set. This
/// is a simplified version of `encoding/asn1.isPrintable`.
fn isPrintable(b: byte) -> bool {
    return b'a' <= b && b <= b'z'
        || b'A' <= b && b <= b'Z'
        || b'0' <= b && b <= b'9'
        || b'\'' <= b && b <= b')'
        || b'+' <= b && b <= b'/'
        || b == b' '
        || b == b':'
        || b == b'='
        || b == b'?'
        // This is technically not allowed in a PrintableString.
        // However, x509 certificates with wildcard strings don't
        // always use the correct string type so we permit it.
        || b == b'*'
        // This is not technically allowed either. However, not
        // only is it relatively common, but there are also a
        // handful of CA certificates that contain it. At least
        // one of which will not expire until 2027.
        || b == b'&';
}

// go: sdk 1.25.5 crypto/x509/parser.go:57-140 parseASN1String
/// Parse the ASN.1 string types T61String, PrintableString, UTF8String,
/// BMPString, IA5String, and NumericString. This is mostly copied from
/// the respective `encoding/asn1.parse...` methods, rather than just
/// increasing the API surface of that package.
fn parseASN1String(tag: cryptobyte_asn1::Tag, value: slice<byte>) -> (string, error) {
    if tag == cryptobyte_asn1::T61String {
        // T.61 is a defunct ITU 8-bit character encoding which preceded Unicode.
        // T.61 uses a code page layout that _almost_ exactly maps to the code
        // page layout of the ISO 8859-1 (Latin-1) character encoding, with the
        // exception that a number of characters in Latin-1 are not present
        // in T.61.
        //
        // Instead of mapping which characters are present in Latin-1 but not T.61,
        // we just treat these strings as being encoded using Latin-1. This matches
        // what most of the world does, including BoringSSL.
        let mut buf = slice::__from_vec(Vec::<byte>::with_capacity(value.Len() as usize));
        for (_, v) in crate::range!(value.clone()) {
            // All the 1-byte UTF-8 runes map 1-1 with Latin-1.
            buf = utf8::AppendRune(buf, crate::rune(*v));
        }
        return (string::from_bytes(&buf), errors::nil);
    }
    if tag == cryptobyte_asn1::PrintableString {
        for (_, b) in crate::range!(value.clone()) {
            if !isPrintable(*b) {
                return (string::default(), errors::New("invalid PrintableString"));
            }
        }
        return (string::from_bytes(&value), errors::nil);
    }
    if tag == cryptobyte_asn1::UTF8String {
        if !utf8::Valid(&value) {
            return (string::default(), errors::New("invalid UTF-8 string"));
        }
        return (string::from_bytes(&value), errors::nil);
    }
    if tag == cryptobyte_asn1::Tag(crate::uint8(asn1::TagBMPString)) {
        // BMPString uses the defunct UCS-2 16-bit character encoding, which
        // covers the Basic Multilingual Plane (BMP). UTF-16 was an extension of
        // UCS-2, containing all of the same code points, but also including
        // multi-code point characters (by using surrogate code points). We can
        // treat a UCS-2 encoded string as a UTF-16 encoded string, as long as
        // we reject out the UTF-16 specific code points. This matches the
        // BoringSSL behavior.

        let mut value: Vec<byte> = value.as_ref().to_vec();
        if value.len() % 2 != 0 {
            return (string::default(), errors::New("invalid BMPString"));
        }

        // Strip terminator if present.
        let l = value.len();
        if l >= 2 && value[l - 1] == 0 && value[l - 2] == 0 {
            value.truncate(l - 2);
        }

        let mut s: Vec<u16> = Vec::with_capacity(value.len() / 2);
        let mut i: usize = 0;
        while i < value.len() {
            let point: crate::types::uint16 = (crate::uint16(value[i]) << 8) + crate::uint16(value[i + 1]);
            // Reject UTF-16 code points that are permanently reserved
            // noncharacters (0xfffe, 0xffff, and 0xfdd0-0xfdef) and surrogates
            // (0xd800-0xdfff).
            if point == 0xfffe
                || point == 0xffff
                || (point >= 0xfdd0 && point <= 0xfdef)
                || (point >= 0xd800 && point <= 0xdfff)
            {
                return (string::default(), errors::New("invalid BMPString"));
            }
            s.push(point);
            i += 2;
        }

        let runes = utf16::Decode(slice::__from_vec(s));
        return (crate::convert::string(runes), errors::nil);
    }
    if tag == cryptobyte_asn1::IA5String {
        let s = string::from_bytes(&value);
        if isIA5String(&s) != crate::nil {
            return (string::default(), errors::New("invalid IA5String"));
        }
        return (s, errors::nil);
    }
    if tag == cryptobyte_asn1::Tag(crate::uint8(asn1::TagNumericString)) {
        for (_, b) in crate::range!(value.clone()) {
            if !(b'0' <= *b && *b <= b'9' || *b == b' ') {
                return (string::default(), errors::New("invalid NumericString"));
            }
        }
        return (string::from_bytes(&value), errors::nil);
    }
    return (
        string::default(),
        crate::fmt::Errorf!("unsupported string type: %v", tag.0),
    );
}

// go: sdk 1.25.5 crypto/x509/parser.go:142-182 parseName
/// Parse a DER encoded Name as defined in RFC 5280.
fn parseName(raw: CBString) -> (pkix::RDNSequence, error) {
    let mut raw = raw;
    let mut inner = CBString::default();
    if !raw.ReadASN1(&mut inner, cryptobyte_asn1::SEQUENCE) {
        return (
            pkix::RDNSequence::default(),
            errors::New("x509: invalid RDNSequence"),
        );
    }
    let mut raw = inner;

    let mut rdnSeq: Vec<pkix::RelativeDistinguishedNameSET> = Vec::new();
    while !raw.Empty() {
        let mut rdnSet: Vec<pkix::AttributeTypeAndValue> = Vec::new();
        let mut set = CBString::default();
        if !raw.ReadASN1(&mut set, cryptobyte_asn1::SET) {
            return (
                pkix::RDNSequence::default(),
                errors::New("x509: invalid RDNSequence"),
            );
        }
        while !set.Empty() {
            let mut atav = CBString::default();
            if !set.ReadASN1(&mut atav, cryptobyte_asn1::SEQUENCE) {
                return (
                    pkix::RDNSequence::default(),
                    errors::New("x509: invalid RDNSequence: invalid attribute"),
                );
            }
            let mut attr = pkix::AttributeTypeAndValue::default();
            if !atav.ReadASN1ObjectIdentifier(&mut attr.Type) {
                return (
                    pkix::RDNSequence::default(),
                    errors::New("x509: invalid RDNSequence: invalid attribute type"),
                );
            }
            let mut rawValue = CBString::default();
            let mut valueTag = cryptobyte_asn1::Tag::default();
            if !atav.ReadAnyASN1(&mut rawValue, &mut valueTag) {
                return (
                    pkix::RDNSequence::default(),
                    errors::New("x509: invalid RDNSequence: invalid attribute value"),
                );
            }
            let (v, err) = parseASN1String(valueTag, rawValue.0);
            if err != crate::nil {
                return (
                    pkix::RDNSequence::default(),
                    crate::fmt::Errorf!(
                        "x509: invalid RDNSequence: invalid attribute value: %s",
                        err.Error()
                    ),
                );
            }
            attr.Value = Any::new(v);
            rdnSet.push(attr);
        }

        rdnSeq.push(pkix::RelativeDistinguishedNameSET(slice::__from_vec(rdnSet)));
    }

    return (
        pkix::RDNSequence(slice::__from_vec(rdnSeq)),
        errors::nil,
    );
}

// go: sdk 1.25.5 crypto/x509/parser.go:184-200 parseAI
fn parseAI(der: CBString) -> (pkix::AlgorithmIdentifier, error) {
    let mut der = der;
    let mut ai = pkix::AlgorithmIdentifier::default();
    if !der.ReadASN1ObjectIdentifier(&mut ai.Algorithm) {
        return (ai, errors::New("x509: malformed OID"));
    }
    if der.Empty() {
        return (ai, errors::nil);
    }
    let mut params = CBString::default();
    let mut tag = cryptobyte_asn1::Tag::default();
    if !der.ReadAnyASN1Element(&mut params, &mut tag) {
        return (ai, errors::New("x509: malformed parameters"));
    }
    ai.Parameters.Tag = int(tag.0);
    ai.Parameters.FullBytes = params.0;
    return (ai, errors::nil);
}

// go: sdk 1.25.5 crypto/x509/parser.go:202-217 parseTime
fn parseTime(der: &mut CBString) -> (time::Time, error) {
    let mut t = time::Time::default();
    if der.PeekASN1Tag(cryptobyte_asn1::UTCTime) {
        if !der.ReadASN1UTCTime(&mut t) {
            return (t, errors::New("x509: malformed UTCTime"));
        }
    } else if der.PeekASN1Tag(cryptobyte_asn1::GeneralizedTime) {
        if !der.ReadASN1GeneralizedTime(&mut t) {
            return (t, errors::New("x509: malformed GeneralizedTime"));
        }
    } else {
        return (t, errors::New("x509: unsupported time format"));
    }
    return (t, errors::nil);
}

// go: sdk 1.25.5 crypto/x509/parser.go:219-230 parseValidity
fn parseValidity(der: CBString) -> (time::Time, time::Time, error) {
    let mut der = der;
    let (notBefore, err) = parseTime(&mut der);
    if err != crate::nil {
        return (time::Time::default(), time::Time::default(), err);
    }
    let (notAfter, err) = parseTime(&mut der);
    if err != crate::nil {
        return (time::Time::default(), time::Time::default(), err);
    }

    return (notBefore, notAfter, errors::nil);
}

// go: sdk 1.25.5 crypto/x509/parser.go:232-248 parseExtension
fn parseExtension(der: CBString) -> (pkix::Extension, error) {
    let mut der = der;
    let mut ext = pkix::Extension::default();
    if !der.ReadASN1ObjectIdentifier(&mut ext.Id) {
        return (ext, errors::New("x509: malformed extension OID field"));
    }
    if der.PeekASN1Tag(cryptobyte_asn1::BOOLEAN) {
        let mut critical = false;
        if !der.ReadASN1Boolean(&mut critical) {
            return (ext, errors::New("x509: malformed extension critical field"));
        }
        ext.Critical = critical;
    }
    let mut val = CBString::default();
    if !der.ReadASN1(&mut val, cryptobyte_asn1::OCTET_STRING) {
        return (ext, errors::New("x509: malformed extension value field"));
    }
    ext.Value = val.0;
    return (ext, errors::nil);
}

// go: sdk 1.25.5 crypto/x509/parser.go:250-350 parsePublicKey
/// Decode the SubjectPublicKeyInfo carried by `keyData`. Go's `any`
/// return is `goany::Any`; see x509.rs's banner for why the key is
/// wrapped with `Any::new_fn`.
fn parsePublicKey(keyData: &publicKeyInfo) -> (Any, error) {
    let oid = keyData.Algorithm.Algorithm.clone();
    let params = keyData.Algorithm.Parameters.clone();
    let mut der = CBString::New(keyData.PublicKey.RightAlign());
    if oid.Equal(&oidPublicKeyRSA()) {
        // RSA public keys must have a NULL in the parameters.
        // See RFC 3279, Section 2.3.1.
        if !crate::bytes::Equal(params.FullBytes.clone(), asn1::NullBytes()) {
            return (
                Any::default(),
                errors::New("x509: RSA key missing NULL parameters"),
            );
        }

        let mut pN = big::Int::default();
        let mut pE: int = 0;
        let mut inner = CBString::default();
        if !der.ReadASN1(&mut inner, cryptobyte_asn1::SEQUENCE) {
            return (Any::default(), errors::New("x509: invalid RSA public key"));
        }
        der = inner;
        if !der.ReadASN1Integer(&mut pN) {
            return (Any::default(), errors::New("x509: invalid RSA modulus"));
        }
        if !der.ReadASN1Integer(&mut pE) {
            return (
                Any::default(),
                errors::New("x509: invalid RSA public exponent"),
            );
        }

        if pN.Sign() <= 0 {
            return (
                Any::default(),
                errors::New("x509: RSA modulus is not a positive number"),
            );
        }
        if pE <= 0 {
            return (
                Any::default(),
                errors::New("x509: RSA public exponent is not a positive number"),
            );
        }

        let pub_ = rsa::PublicKey { E: pE, N: pN };
        return (Any::new_fn(pub_), errors::nil);
    }
    if oid.Equal(&oidPublicKeyECDSA()) {
        let mut paramsDer = CBString::New(params.FullBytes.clone());
        let mut namedCurveOID = asn1::ObjectIdentifier::default();
        if !paramsDer.ReadASN1ObjectIdentifier(&mut namedCurveOID) {
            return (Any::default(), errors::New("x509: invalid ECDSA parameters"));
        }
        let namedCurve = match namedCurveFromOID(&namedCurveOID) {
            None => {
                return (
                    Any::default(),
                    errors::New("x509: unsupported elliptic curve"),
                )
            }
            Some(c) => c,
        };
        let (x, y, ok) = elliptic::Unmarshal(namedCurve, &der.0);
        if !ok {
            return (
                Any::default(),
                errors::New("x509: failed to unmarshal elliptic curve point"),
            );
        }
        let pub_ = ecdsa::PublicKey {
            Curve: namedCurve,
            X: x,
            Y: y,
        };
        return (Any::new_fn(pub_), errors::nil);
    }
    if oid.Equal(&oidPublicKeyEd25519()) {
        // RFC 8410, Section 3
        // > For all of the OIDs, the parameters MUST be absent.
        if params.FullBytes.Len() != 0 {
            return (
                Any::default(),
                errors::New("x509: Ed25519 key encoded with illegal parameters"),
            );
        }
        if der.0.Len() != ed25519::PublicKeySize {
            return (
                Any::default(),
                errors::New("x509: wrong Ed25519 public key size"),
            );
        }
        return (Any::new_fn(ed25519::PublicKey(der.0)), errors::nil);
    }
    if oid.Equal(&oidPublicKeyX25519()) {
        // RFC 8410, Section 3
        // > For all of the OIDs, the parameters MUST be absent.
        if params.FullBytes.Len() != 0 {
            return (
                Any::default(),
                errors::New("x509: X25519 key encoded with illegal parameters"),
            );
        }
        let (k, err) = ecdh::X25519().NewPublicKey(&der.0);
        if err != crate::nil {
            return (Any::default(), err);
        }
        return (Any::new_fn(k), errors::nil);
    }
    if oid.Equal(&oidPublicKeyDSA()) {
        let mut y = big::Int::default();
        if !der.ReadASN1Integer(&mut y) {
            return (Any::default(), errors::New("x509: invalid DSA public key"));
        }
        let mut pub_ = dsa::PublicKey::default();
        pub_.Y = y;
        let mut paramsDer = CBString::New(params.FullBytes.clone());
        let mut inner = CBString::default();
        if !paramsDer.ReadASN1(&mut inner, cryptobyte_asn1::SEQUENCE) {
            return (Any::default(), errors::New("x509: invalid DSA parameters"));
        }
        paramsDer = inner;
        if !paramsDer.ReadASN1Integer(&mut pub_.Parameters.P)
            || !paramsDer.ReadASN1Integer(&mut pub_.Parameters.Q)
            || !paramsDer.ReadASN1Integer(&mut pub_.Parameters.G)
        {
            return (Any::default(), errors::New("x509: invalid DSA parameters"));
        }
        if pub_.Y.Sign() <= 0
            || pub_.Parameters.P.Sign() <= 0
            || pub_.Parameters.Q.Sign() <= 0
            || pub_.Parameters.G.Sign() <= 0
        {
            return (
                Any::default(),
                errors::New("x509: zero or negative DSA parameter"),
            );
        }
        return (Any::new_fn(pub_), errors::nil);
    }
    return (
        Any::default(),
        errors::New("x509: unknown public key algorithm"),
    );
}

// go: sdk 1.25.5 crypto/x509/parser.go:352-365 parseKeyUsageExtension
fn parseKeyUsageExtension(der: CBString) -> (KeyUsage, error) {
    let mut der = der;
    let mut usageBits = asn1::BitString::default();
    if !der.ReadASN1BitString(&mut usageBits) {
        return (KeyUsage(0), errors::New("x509: invalid key usage"));
    }

    let mut usage: int = 0;
    let mut i: int = 0;
    while i < 9 {
        if usageBits.At(i) != 0 {
            usage |= 1 << i;
        }
        i += 1;
    }
    return (KeyUsage(usage), errors::nil);
}

// go: sdk 1.25.5 crypto/x509/parser.go:367-388 parseBasicConstraintsExtension
fn parseBasicConstraintsExtension(der: CBString) -> (bool, int, error) {
    let mut der = der;
    let mut isCA = false;
    let mut inner = CBString::default();
    if !der.ReadASN1(&mut inner, cryptobyte_asn1::SEQUENCE) {
        return (false, 0, errors::New("x509: invalid basic constraints"));
    }
    der = inner;
    if der.PeekASN1Tag(cryptobyte_asn1::BOOLEAN) {
        if !der.ReadASN1Boolean(&mut isCA) {
            return (false, 0, errors::New("x509: invalid basic constraints"));
        }
    }

    let mut maxPathLen: int = -1;
    if der.PeekASN1Tag(cryptobyte_asn1::INTEGER) {
        let mut mpl: crate::types::uint = 0;
        // Go also rejects `mpl > math.MaxInt`; `uint` is 64-bit here and
        // `MaxInt` is 2^63-1, so the guard is the sign test below.
        if !der.ReadASN1Integer(&mut mpl) || mpl > crate::uint(int::MAX) {
            return (false, 0, errors::New("x509: invalid basic constraints"));
        }
        maxPathLen = int(mpl);
    }

    return (isCA, maxPathLen, errors::nil);
}

// go: sdk 1.25.5 crypto/x509/parser.go:390-406 forEachSAN
pub(super) fn forEachSAN<F: FnMut(int, slice<byte>) -> error>(der: CBString, mut callback: F) -> error {
    let mut der = der;
    let mut inner = CBString::default();
    if !der.ReadASN1(&mut inner, cryptobyte_asn1::SEQUENCE) {
        return errors::New("x509: invalid subject alternative names");
    }
    der = inner;
    while !der.Empty() {
        let mut san = CBString::default();
        let mut tag = cryptobyte_asn1::Tag::default();
        if !der.ReadAnyASN1(&mut san, &mut tag) {
            return errors::New("x509: invalid subject alternative name");
        }
        let err = callback(int(tag.0 ^ 0x80), san.0);
        if err != crate::nil {
            return err;
        }
    }

    return errors::nil;
}

// go: none — goish idiom: `parseSANExtension`'s four named results, so a
// single `FnMut` can own the one `&mut` borrow the callback needs.
#[derive(Default)]
struct sanResult {
    dnsNames: Vec<string>,
    emailAddresses: Vec<string>,
    ipAddresses: Vec<net::IP>,
    uris: Vec<url::URL>,
}

// go: sdk 1.25.5 crypto/x509/parser.go:408-449 parseSANExtension
fn parseSANExtension(
    der: CBString,
) -> (
    slice<string>,
    slice<string>,
    slice<net::IP>,
    slice<url::URL>,
    error,
) {
    let mut out = sanResult::default();
    let err = forEachSAN(der, |tag: int, data: slice<byte>| -> error {
        if tag == nameTypeEmail {
            let email = string::from_bytes(&data);
            if isIA5String(&email) != crate::nil {
                return errors::New("x509: SAN rfc822Name is malformed");
            }
            out.emailAddresses.push(email);
        } else if tag == nameTypeDNS {
            let name = string::from_bytes(&data);
            if isIA5String(&name) != crate::nil {
                return errors::New("x509: SAN dNSName is malformed");
            }
            out.dnsNames.push(name);
        } else if tag == nameTypeURI {
            let uriStr = string::from_bytes(&data);
            if isIA5String(&uriStr) != crate::nil {
                return errors::New("x509: SAN uniformResourceIdentifier is malformed");
            }
            let (uri, err) = url::Parse(uriStr.clone());
            if err != crate::nil {
                return crate::fmt::Errorf!(
                    "x509: cannot parse URI %q: %s",
                    uriStr.clone(),
                    err.Error()
                );
            }
            if uri.Host.Len() > 0 && !domainNameValid(&uri.Host, false) {
                return crate::fmt::Errorf!("x509: cannot parse URI %q: invalid domain", uriStr);
            }
            out.uris.push(uri);
        } else if tag == nameTypeIP {
            match data.Len() {
                4 | 16 => out.ipAddresses.push(net::IP { bytes: data }),
                _ => {
                    return errors::New(
                        string::from("x509: cannot parse IP address of length ")
                            + crate::strconv::Itoa(data.Len()),
                    )
                }
            }
        }

        return errors::nil;
    });

    return (
        slice::__from_vec(out.dnsNames),
        slice::__from_vec(out.emailAddresses),
        slice::__from_vec(out.ipAddresses),
        slice::__from_vec(out.uris),
        err,
    );
}

// go: sdk 1.25.5 crypto/x509/parser.go:451-469 parseAuthorityKeyIdentifier
fn parseAuthorityKeyIdentifier(e: &pkix::Extension) -> (slice<byte>, error) {
    // RFC 5280, Section 4.2.1.1
    if e.Critical {
        // Conforming CAs MUST mark this extension as non-critical
        return (
            slice::__from_vec(Vec::<byte>::new()),
            errors::New("x509: authority key identifier incorrectly marked critical"),
        );
    }
    let mut val = CBString::New(e.Value.clone());
    let mut akid = CBString::default();
    if !val.ReadASN1(&mut akid, cryptobyte_asn1::SEQUENCE) {
        return (
            slice::__from_vec(Vec::<byte>::new()),
            errors::New("x509: invalid authority key identifier"),
        );
    }
    if akid.PeekASN1Tag(cryptobyte_asn1::Tag(0).ContextSpecific()) {
        let mut inner = CBString::default();
        if !akid.ReadASN1(&mut inner, cryptobyte_asn1::Tag(0).ContextSpecific()) {
            return (
                slice::__from_vec(Vec::<byte>::new()),
                errors::New("x509: invalid authority key identifier"),
            );
        }
        return (inner.0, errors::nil);
    }
    return (slice::__from_vec(Vec::<byte>::new()), errors::nil);
}

// go: sdk 1.25.5 crypto/x509/parser.go:471-489 parseExtKeyUsageExtension
fn parseExtKeyUsageExtension(
    der: CBString,
) -> (slice<ExtKeyUsage>, slice<asn1::ObjectIdentifier>, error) {
    let mut der = der;
    let mut extKeyUsages: Vec<ExtKeyUsage> = Vec::new();
    let mut unknownUsages: Vec<asn1::ObjectIdentifier> = Vec::new();
    let mut inner = CBString::default();
    if !der.ReadASN1(&mut inner, cryptobyte_asn1::SEQUENCE) {
        return (
            slice::__from_vec(Vec::new()),
            slice::__from_vec(Vec::new()),
            errors::New("x509: invalid extended key usages"),
        );
    }
    der = inner;
    while !der.Empty() {
        let mut eku = asn1::ObjectIdentifier::default();
        if !der.ReadASN1ObjectIdentifier(&mut eku) {
            return (
                slice::__from_vec(Vec::new()),
                slice::__from_vec(Vec::new()),
                errors::New("x509: invalid extended key usages"),
            );
        }
        let (extKeyUsage, ok) = extKeyUsageFromOID(&eku);
        if ok {
            extKeyUsages.push(extKeyUsage);
        } else {
            unknownUsages.push(eku);
        }
    }
    return (
        slice::__from_vec(extKeyUsages),
        slice::__from_vec(unknownUsages),
        errors::nil,
    );
}

// go: sdk 1.25.5 crypto/x509/parser.go:491-514 parseCertificatePoliciesExtension
fn parseCertificatePoliciesExtension(der: CBString) -> (slice<OID>, error) {
    let mut der = der;
    let mut oids: Vec<OID> = Vec::new();
    let mut seenOIDs: map<string, bool> = map::new();
    let mut inner = CBString::default();
    if !der.ReadASN1(&mut inner, cryptobyte_asn1::SEQUENCE) {
        return (
            slice::__from_vec(Vec::new()),
            errors::New("x509: invalid certificate policies"),
        );
    }
    der = inner;
    while !der.Empty() {
        let mut cp = CBString::default();
        let mut OIDBytes = CBString::default();
        if !der.ReadASN1(&mut cp, cryptobyte_asn1::SEQUENCE)
            || !cp.ReadASN1(&mut OIDBytes, cryptobyte_asn1::OBJECT_IDENTIFIER)
        {
            return (
                slice::__from_vec(Vec::new()),
                errors::New("x509: invalid certificate policies"),
            );
        }
        let key = string::from_bytes(&OIDBytes.0);
        let (seen, _) = seenOIDs.Get(key.clone());
        if seen {
            return (
                slice::__from_vec(Vec::new()),
                errors::New("x509: invalid certificate policies"),
            );
        }
        seenOIDs.Set(key, true);
        let (oid, ok) = newOIDFromDER(OIDBytes.0);
        if !ok {
            return (
                slice::__from_vec(Vec::new()),
                errors::New("x509: invalid certificate policies"),
            );
        }
        oids.push(oid);
    }
    return (slice::__from_vec(oids), errors::nil);
}

// go: sdk 1.25.5 crypto/x509/parser.go:516-539 isValidIPMask
/// Report whether mask consists of zero or more 1 bits, followed by zero
/// bits.
fn isValidIPMask(mask: &slice<byte>) -> bool {
    let mut seenZero = false;

    for (_, b) in crate::range!(mask.clone()) {
        if seenZero {
            if *b != 0 {
                return false;
            }

            continue;
        }

        match *b {
            0x00 | 0x80 | 0xc0 | 0xe0 | 0xf0 | 0xf8 | 0xfc | 0xfe => seenZero = true,
            0xff => {}
            _ => return false,
        }
    }

    return true;
}

// go: none — goish idiom: `parseNameConstraintsExtension`'s `getValues`
// closure returns four named results plus the shared `unhandled` flag,
// which Rust cannot capture and return at once from a closure; the
// closure becomes this free function and `unhandled` an out-parameter.
fn nameConstraintValues(
    subtrees: CBString,
    unhandled: &mut bool,
) -> (
    slice<string>,
    slice<net::IPNet>,
    slice<string>,
    slice<string>,
    error,
) {
    let mut subtrees = subtrees;
    let mut dnsNames: Vec<string> = Vec::new();
    let mut ips: Vec<net::IPNet> = Vec::new();
    let mut emails: Vec<string> = Vec::new();
    let mut uriDomains: Vec<string> = Vec::new();
    let none = || {
        return (
            slice::__from_vec(Vec::<string>::new()),
            slice::__from_vec(Vec::<net::IPNet>::new()),
            slice::__from_vec(Vec::<string>::new()),
            slice::__from_vec(Vec::<string>::new()),
        );
    };
    while !subtrees.Empty() {
        let mut seq = CBString::default();
        let mut value = CBString::default();
        let mut tag = cryptobyte_asn1::Tag::default();
        if !subtrees.ReadASN1(&mut seq, cryptobyte_asn1::SEQUENCE)
            || !seq.ReadAnyASN1(&mut value, &mut tag)
        {
            let (a, b, c, d) = none();
            return (
                a,
                b,
                c,
                d,
                crate::fmt::Errorf!("x509: invalid NameConstraints extension"),
            );
        }

        let dnsTag = cryptobyte_asn1::Tag(2).ContextSpecific();
        let emailTag = cryptobyte_asn1::Tag(1).ContextSpecific();
        let ipTag = cryptobyte_asn1::Tag(7).ContextSpecific();
        let uriTag = cryptobyte_asn1::Tag(6).ContextSpecific();

        if tag == dnsTag {
            let domain = string::from_bytes(&value.0);
            let err = isIA5String(&domain);
            if err != crate::nil {
                let (a, b, c, d) = none();
                return (
                    a,
                    b,
                    c,
                    d,
                    errors::New(
                        string::from("x509: invalid constraint value: ") + err.Error(),
                    ),
                );
            }

            if !domainNameValid(&domain, true) {
                let (a, b, c, d) = none();
                return (
                    a,
                    b,
                    c,
                    d,
                    crate::fmt::Errorf!(
                        "x509: failed to parse dnsName constraint %q",
                        domain
                    ),
                );
            }
            dnsNames.push(domain);
        } else if tag == ipTag {
            let l = value.0.Len();
            let raw: &[byte] = &value.0;
            let (ip, mask): (slice<byte>, slice<byte>) = match l {
                8 => (
                    slice::__from_vec(raw[..4].to_vec()),
                    slice::__from_vec(raw[4..].to_vec()),
                ),
                32 => (
                    slice::__from_vec(raw[..16].to_vec()),
                    slice::__from_vec(raw[16..].to_vec()),
                ),
                _ => {
                    let (a, b, c, d) = none();
                    return (
                        a,
                        b,
                        c,
                        d,
                        crate::fmt::Errorf!(
                            "x509: IP constraint contained value of length %d",
                            l
                        ),
                    );
                }
            };

            if !isValidIPMask(&mask) {
                let (a, b, c, d) = none();
                return (
                    a,
                    b,
                    c,
                    d,
                    crate::fmt::Errorf!(
                        "x509: IP constraint contained invalid mask %x",
                        mask
                    ),
                );
            }

            ips.push(net::IPNet {
                IP: net::IP { bytes: ip },
                Mask: net::IPMask { bytes: mask },
            });
        } else if tag == emailTag {
            let constraint = string::from_bytes(&value.0);
            let err = isIA5String(&constraint);
            if err != crate::nil {
                let (a, b, c, d) = none();
                return (
                    a,
                    b,
                    c,
                    d,
                    errors::New(
                        string::from("x509: invalid constraint value: ") + err.Error(),
                    ),
                );
            }

            // If the constraint contains an @ then
            // it specifies an exact mailbox name.
            if strings::Contains(constraint.clone(), "@") {
                let (_, ok) = parseRFC2821Mailbox(&constraint);
                if !ok {
                    let (a, b, c, d) = none();
                    return (
                        a,
                        b,
                        c,
                        d,
                        crate::fmt::Errorf!(
                            "x509: failed to parse rfc822Name constraint %q",
                            constraint
                        ),
                    );
                }
            } else if !domainNameValid(&constraint, true) {
                let (a, b, c, d) = none();
                return (
                    a,
                    b,
                    c,
                    d,
                    crate::fmt::Errorf!(
                        "x509: failed to parse rfc822Name constraint %q",
                        constraint
                    ),
                );
            }
            emails.push(constraint);
        } else if tag == uriTag {
            let domain = string::from_bytes(&value.0);
            let err = isIA5String(&domain);
            if err != crate::nil {
                let (a, b, c, d) = none();
                return (
                    a,
                    b,
                    c,
                    d,
                    errors::New(
                        string::from("x509: invalid constraint value: ") + err.Error(),
                    ),
                );
            }

            if !net::ParseIP(domain.clone()).IsNil() {
                let (a, b, c, d) = none();
                return (
                    a,
                    b,
                    c,
                    d,
                    crate::fmt::Errorf!(
                        "x509: failed to parse URI constraint %q: cannot be IP address",
                        domain
                    ),
                );
            }

            if !domainNameValid(&domain, true) {
                let (a, b, c, d) = none();
                return (
                    a,
                    b,
                    c,
                    d,
                    crate::fmt::Errorf!("x509: failed to parse URI constraint %q", domain),
                );
            }
            uriDomains.push(domain);
        } else {
            *unhandled = true;
        }
    }

    return (
        slice::__from_vec(dnsNames),
        slice::__from_vec(ips),
        slice::__from_vec(emails),
        slice::__from_vec(uriDomains),
        errors::nil,
    );
}

// go: sdk 1.25.5 crypto/x509/parser.go:541-678 parseNameConstraintsExtension
fn parseNameConstraintsExtension(out: &mut Certificate, e: &pkix::Extension) -> (bool, error) {
    // RFC 5280, 4.2.1.10

    // NameConstraints ::= SEQUENCE {
    //      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
    //      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
    //
    // GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
    //
    // GeneralSubtree ::= SEQUENCE {
    //      base                    GeneralName,
    //      minimum         [0]     BaseDistance DEFAULT 0,
    //      maximum         [1]     BaseDistance OPTIONAL }
    //
    // BaseDistance ::= INTEGER (0..MAX)

    let mut outer = CBString::New(e.Value.clone());
    let mut toplevel = CBString::default();
    let mut permitted = CBString::default();
    let mut excluded = CBString::default();
    let mut havePermitted = false;
    let mut haveExcluded = false;
    if !outer.ReadASN1(&mut toplevel, cryptobyte_asn1::SEQUENCE)
        || !outer.Empty()
        || !toplevel.ReadOptionalASN1(
            &mut permitted,
            Some(&mut havePermitted),
            cryptobyte_asn1::Tag(0).ContextSpecific().Constructed(),
        )
        || !toplevel.ReadOptionalASN1(
            &mut excluded,
            Some(&mut haveExcluded),
            cryptobyte_asn1::Tag(1).ContextSpecific().Constructed(),
        )
        || !toplevel.Empty()
    {
        return (false, errors::New("x509: invalid NameConstraints extension"));
    }

    if !havePermitted && !haveExcluded
        || permitted.0.Len() == 0 && excluded.0.Len() == 0
    {
        // From RFC 5280, Section 4.2.1.10:
        //   "either the permittedSubtrees field
        //   or the excludedSubtrees MUST be
        //   present"
        return (false, errors::New("x509: empty name constraints extension"));
    }

    let mut unhandled = false;

    let (dnsNames, ips, emails, uriDomains, err) =
        nameConstraintValues(permitted, &mut unhandled);
    if err != crate::nil {
        return (false, err);
    }
    out.PermittedDNSDomains = dnsNames;
    out.PermittedIPRanges = ips;
    out.PermittedEmailAddresses = emails;
    out.PermittedURIDomains = uriDomains;

    let (dnsNames, ips, emails, uriDomains, err) =
        nameConstraintValues(excluded, &mut unhandled);
    if err != crate::nil {
        return (false, err);
    }
    out.ExcludedDNSDomains = dnsNames;
    out.ExcludedIPRanges = ips;
    out.ExcludedEmailAddresses = emails;
    out.ExcludedURIDomains = uriDomains;
    out.PermittedDNSDomainsCritical = e.Critical;

    return (unhandled, errors::nil);
}

// go: sdk 1.25.5 crypto/x509/parser.go:680-890 processExtensions
fn processExtensions(out: &mut Certificate) -> error {
    for (_, e) in crate::range!(out.Extensions.clone()) {
        let mut unhandled = false;

        if e.Id.0.Len() == 4 && e.Id.0[int(0)] == 2 && e.Id.0[int(1)] == 5 && e.Id.0[int(2)] == 29 {
            match e.Id.0[int(3)] {
                15 => {
                    let (ku, err) = parseKeyUsageExtension(CBString::New(e.Value.clone()));
                    if err != crate::nil {
                        return err;
                    }
                    out.KeyUsage = ku;
                }
                19 => {
                    let (isCA, mpl, err) =
                        parseBasicConstraintsExtension(CBString::New(e.Value.clone()));
                    if err != crate::nil {
                        return err;
                    }
                    out.IsCA = isCA;
                    out.MaxPathLen = mpl;
                    out.BasicConstraintsValid = true;
                    out.MaxPathLenZero = out.MaxPathLen == 0;
                }
                17 => {
                    let (dnsNames, emailAddresses, ipAddresses, uris, err) =
                        parseSANExtension(CBString::New(e.Value.clone()));
                    if err != crate::nil {
                        return err;
                    }
                    out.DNSNames = dnsNames;
                    out.EmailAddresses = emailAddresses;
                    out.IPAddresses = ipAddresses;
                    out.URIs = uris;

                    if out.DNSNames.Len() == 0
                        && out.EmailAddresses.Len() == 0
                        && out.IPAddresses.Len() == 0
                        && out.URIs.Len() == 0
                    {
                        // If we didn't parse anything then we do the critical check, below.
                        unhandled = true;
                    }
                }
                30 => {
                    let (u, err) = parseNameConstraintsExtension(out, &e);
                    if err != crate::nil {
                        return err;
                    }
                    unhandled = u;
                }
                31 => {
                    // RFC 5280, 4.2.1.13

                    // CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
                    //
                    // DistributionPoint ::= SEQUENCE {
                    //     distributionPoint       [0]     DistributionPointName OPTIONAL,
                    //     reasons                 [1]     ReasonFlags OPTIONAL,
                    //     cRLIssuer               [2]     GeneralNames OPTIONAL }
                    //
                    // DistributionPointName ::= CHOICE {
                    //     fullName                [0]     GeneralNames,
                    //     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
                    let mut val = CBString::New(e.Value.clone());
                    let mut inner = CBString::default();
                    if !val.ReadASN1(&mut inner, cryptobyte_asn1::SEQUENCE) {
                        return errors::New("x509: invalid CRL distribution points");
                    }
                    val = inner;
                    while !val.Empty() {
                        let mut dpDER = CBString::default();
                        if !val.ReadASN1(&mut dpDER, cryptobyte_asn1::SEQUENCE) {
                            return errors::New("x509: invalid CRL distribution point");
                        }
                        let mut dpNameDER = CBString::default();
                        let mut dpNamePresent = false;
                        if !dpDER.ReadOptionalASN1(
                            &mut dpNameDER,
                            Some(&mut dpNamePresent),
                            cryptobyte_asn1::Tag(0).Constructed().ContextSpecific(),
                        ) {
                            return errors::New("x509: invalid CRL distribution point");
                        }
                        if !dpNamePresent {
                            continue;
                        }
                        let mut inner = CBString::default();
                        if !dpNameDER.ReadASN1(
                            &mut inner,
                            cryptobyte_asn1::Tag(0).Constructed().ContextSpecific(),
                        ) {
                            return errors::New("x509: invalid CRL distribution point");
                        }
                        dpNameDER = inner;
                        while !dpNameDER.Empty() {
                            if !dpNameDER
                                .PeekASN1Tag(cryptobyte_asn1::Tag(6).ContextSpecific())
                            {
                                break;
                            }
                            let mut uri = CBString::default();
                            if !dpNameDER
                                .ReadASN1(&mut uri, cryptobyte_asn1::Tag(6).ContextSpecific())
                            {
                                return errors::New("x509: invalid CRL distribution point");
                            }
                            out.CRLDistributionPoints = crate::append!(
                                out.CRLDistributionPoints.clone(),
                                string::from_bytes(&uri.0)
                            );
                        }
                    }
                }
                35 => {
                    let (akid, err) = parseAuthorityKeyIdentifier(&e);
                    if err != crate::nil {
                        return err;
                    }
                    out.AuthorityKeyId = akid;
                }
                36 => {
                    let mut val = CBString::New(e.Value.clone());
                    let mut inner = CBString::default();
                    if !val.ReadASN1(&mut inner, cryptobyte_asn1::SEQUENCE) {
                        return errors::New("x509: invalid policy constraints extension");
                    }
                    val = inner;
                    if val.PeekASN1Tag(cryptobyte_asn1::Tag(0).ContextSpecific()) {
                        let mut v: crate::types::int64 = 0;
                        if !val.ReadASN1Int64WithTag(
                            &mut v,
                            cryptobyte_asn1::Tag(0).ContextSpecific(),
                        ) {
                            return errors::New("x509: invalid policy constraints extension");
                        }
                        out.RequireExplicitPolicy = v;
                        // Go re-checks `int64(out.RequireExplicitPolicy) != v`
                        // for overflow; `int` is `int64` here, so it cannot fire.
                        out.RequireExplicitPolicyZero = out.RequireExplicitPolicy == 0;
                    }
                    if val.PeekASN1Tag(cryptobyte_asn1::Tag(1).ContextSpecific()) {
                        let mut v: crate::types::int64 = 0;
                        if !val.ReadASN1Int64WithTag(
                            &mut v,
                            cryptobyte_asn1::Tag(1).ContextSpecific(),
                        ) {
                            return errors::New("x509: invalid policy constraints extension");
                        }
                        out.InhibitPolicyMapping = v;
                        out.InhibitPolicyMappingZero = out.InhibitPolicyMapping == 0;
                    }
                }
                37 => {
                    let (eku, unknown, err) =
                        parseExtKeyUsageExtension(CBString::New(e.Value.clone()));
                    if err != crate::nil {
                        return err;
                    }
                    out.ExtKeyUsage = eku;
                    out.UnknownExtKeyUsage = unknown;
                }
                14 => {
                    // RFC 5280, 4.2.1.2
                    if e.Critical {
                        // Conforming CAs MUST mark this extension as non-critical
                        return errors::New(
                            "x509: subject key identifier incorrectly marked critical",
                        );
                    }
                    let mut val = CBString::New(e.Value.clone());
                    let mut skid = CBString::default();
                    if !val.ReadASN1(&mut skid, cryptobyte_asn1::OCTET_STRING) {
                        return errors::New("x509: invalid subject key identifier");
                    }
                    out.SubjectKeyId = skid.0;
                }
                32 => {
                    let (policies, err) =
                        parseCertificatePoliciesExtension(CBString::New(e.Value.clone()));
                    if err != crate::nil {
                        return err;
                    }
                    out.Policies = policies;
                    let mut pids: Vec<asn1::ObjectIdentifier> =
                        Vec::with_capacity(out.Policies.Len() as usize);
                    for (_, oid) in crate::range!(out.Policies.clone()) {
                        let (o, ok) = oid.toASN1OID();
                        if ok {
                            pids.push(o);
                        }
                    }
                    out.PolicyIdentifiers = slice::__from_vec(pids);
                }
                33 => {
                    let mut val = CBString::New(e.Value.clone());
                    let mut inner = CBString::default();
                    if !val.ReadASN1(&mut inner, cryptobyte_asn1::SEQUENCE) {
                        return errors::New("x509: invalid policy mappings extension");
                    }
                    val = inner;
                    while !val.Empty() {
                        let mut s = CBString::default();
                        let mut issuer = CBString::default();
                        let mut subject = CBString::default();
                        if !val.ReadASN1(&mut s, cryptobyte_asn1::SEQUENCE)
                            || !s.ReadASN1(&mut issuer, cryptobyte_asn1::OBJECT_IDENTIFIER)
                            || !s.ReadASN1(&mut subject, cryptobyte_asn1::OBJECT_IDENTIFIER)
                        {
                            return errors::New("x509: invalid policy mappings extension");
                        }
                        out.PolicyMappings = crate::append!(
                            out.PolicyMappings.clone(),
                            PolicyMapping {
                                IssuerDomainPolicy: OID { der: issuer.0 },
                                SubjectDomainPolicy: OID { der: subject.0 },
                            }
                        );
                    }
                }
                54 => {
                    let mut val = CBString::New(e.Value.clone());
                    let mut iap: int = 0;
                    if !val.ReadASN1Integer(&mut iap) {
                        return errors::New("x509: invalid inhibit any policy extension");
                    }
                    out.InhibitAnyPolicy = iap;
                    out.InhibitAnyPolicyZero = out.InhibitAnyPolicy == 0;
                }
                _ => {
                    // Unknown extensions are recorded if critical.
                    unhandled = true;
                }
            }
        } else if e.Id.Equal(&oidExtensionAuthorityInfoAccess()) {
            // RFC 5280 4.2.2.1: Authority Information Access
            if e.Critical {
                // Conforming CAs MUST mark this extension as non-critical
                return errors::New("x509: authority info access incorrectly marked critical");
            }
            let mut val = CBString::New(e.Value.clone());
            let mut inner = CBString::default();
            if !val.ReadASN1(&mut inner, cryptobyte_asn1::SEQUENCE) {
                return errors::New("x509: invalid authority info access");
            }
            val = inner;
            while !val.Empty() {
                let mut aiaDER = CBString::default();
                if !val.ReadASN1(&mut aiaDER, cryptobyte_asn1::SEQUENCE) {
                    return errors::New("x509: invalid authority info access");
                }
                let mut method = asn1::ObjectIdentifier::default();
                if !aiaDER.ReadASN1ObjectIdentifier(&mut method) {
                    return errors::New("x509: invalid authority info access");
                }
                if !aiaDER.PeekASN1Tag(cryptobyte_asn1::Tag(6).ContextSpecific()) {
                    continue;
                }
                let mut inner = CBString::default();
                if !aiaDER.ReadASN1(&mut inner, cryptobyte_asn1::Tag(6).ContextSpecific()) {
                    return errors::New("x509: invalid authority info access");
                }
                aiaDER = inner;
                if method.Equal(&oidAuthorityInfoAccessOcsp()) {
                    out.OCSPServer =
                        crate::append!(out.OCSPServer.clone(), string::from_bytes(&aiaDER.0));
                } else if method.Equal(&oidAuthorityInfoAccessIssuers()) {
                    out.IssuingCertificateURL = crate::append!(
                        out.IssuingCertificateURL.clone(),
                        string::from_bytes(&aiaDER.0)
                    );
                }
            }
        } else {
            // Unknown extensions are recorded if critical.
            unhandled = true;
        }

        if e.Critical && unhandled {
            out.UnhandledCriticalExtensions =
                crate::append!(out.UnhandledCriticalExtensions.clone(), e.Id.clone());
        }
    }

    return errors::nil;
}

// go: sdk 1.25.5 crypto/x509/parser.go:894-1077 parseCertificate
/// Decode a single certificate from `der`, without the trailing-data
/// check `ParseCertificate` adds.
///
/// Deviation: Go gates the negative-serial rejection on the
/// `x509negativeserial` GODEBUG; goish has no `internal/godebug`, so the
/// default (reject) is unconditional.
fn parseCertificate(der: &slice<byte>) -> (Certificate, error) {
    let mut cert = Certificate::default();

    let mut input = CBString::New(der.clone());
    // we read the SEQUENCE including length and tag bytes so that
    // we can populate Certificate.Raw, before unwrapping the
    // SEQUENCE so it can be operated on
    let mut elem = CBString::default();
    if !input.ReadASN1Element(&mut elem, cryptobyte_asn1::SEQUENCE) {
        return (Certificate::default(), errors::New("x509: malformed certificate"));
    }
    input = elem;
    cert.Raw = input.0.clone();
    let mut inner = CBString::default();
    if !input.ReadASN1(&mut inner, cryptobyte_asn1::SEQUENCE) {
        return (Certificate::default(), errors::New("x509: malformed certificate"));
    }
    input = inner;

    let mut tbs = CBString::default();
    // do the same trick again as above to extract the raw
    // bytes for Certificate.RawTBSCertificate
    if !input.ReadASN1Element(&mut tbs, cryptobyte_asn1::SEQUENCE) {
        return (
            Certificate::default(),
            errors::New("x509: malformed tbs certificate"),
        );
    }
    cert.RawTBSCertificate = tbs.0.clone();
    let mut inner = CBString::default();
    if !tbs.ReadASN1(&mut inner, cryptobyte_asn1::SEQUENCE) {
        return (
            Certificate::default(),
            errors::New("x509: malformed tbs certificate"),
        );
    }
    tbs = inner;

    if !tbs.ReadOptionalASN1Integer(
        &mut cert.Version,
        cryptobyte_asn1::Tag(0).Constructed().ContextSpecific(),
        0,
    ) {
        return (Certificate::default(), errors::New("x509: malformed version"));
    }
    if cert.Version < 0 {
        return (Certificate::default(), errors::New("x509: malformed version"));
    }
    // for backwards compat reasons Version is one-indexed,
    // rather than zero-indexed as defined in 5280
    cert.Version += 1;
    if cert.Version > 3 {
        return (Certificate::default(), errors::New("x509: invalid version"));
    }

    let mut serial = big::Int::default();
    if !tbs.ReadASN1Integer(&mut serial) {
        return (
            Certificate::default(),
            errors::New("x509: malformed serial number"),
        );
    }
    if serial.Sign() == -1 {
        return (
            Certificate::default(),
            errors::New("x509: negative serial number"),
        );
    }
    cert.SerialNumber = serial;

    let mut sigAISeq = CBString::default();
    if !tbs.ReadASN1(&mut sigAISeq, cryptobyte_asn1::SEQUENCE) {
        return (
            Certificate::default(),
            errors::New("x509: malformed signature algorithm identifier"),
        );
    }
    // Before parsing the inner algorithm identifier, extract
    // the outer algorithm identifier and make sure that they
    // match.
    let mut outerSigAISeq = CBString::default();
    if !input.ReadASN1(&mut outerSigAISeq, cryptobyte_asn1::SEQUENCE) {
        return (
            Certificate::default(),
            errors::New("x509: malformed algorithm identifier"),
        );
    }
    if !crate::bytes::Equal(outerSigAISeq.0.clone(), sigAISeq.0.clone()) {
        return (
            Certificate::default(),
            errors::New("x509: inner and outer signature algorithm identifiers don't match"),
        );
    }
    let (sigAI, err) = parseAI(sigAISeq);
    if err != crate::nil {
        return (Certificate::default(), err);
    }
    cert.SignatureAlgorithm = getSignatureAlgorithmFromAI(&sigAI);

    let mut issuerSeq = CBString::default();
    if !tbs.ReadASN1Element(&mut issuerSeq, cryptobyte_asn1::SEQUENCE) {
        return (Certificate::default(), errors::New("x509: malformed issuer"));
    }
    cert.RawIssuer = issuerSeq.0.clone();
    let (issuerRDNs, err) = parseName(issuerSeq);
    if err != crate::nil {
        return (Certificate::default(), err);
    }
    cert.Issuer.FillFromRDNSequence(&issuerRDNs);

    let mut validity = CBString::default();
    if !tbs.ReadASN1(&mut validity, cryptobyte_asn1::SEQUENCE) {
        return (Certificate::default(), errors::New("x509: malformed validity"));
    }
    let (notBefore, notAfter, err) = parseValidity(validity);
    if err != crate::nil {
        return (Certificate::default(), err);
    }
    cert.NotBefore = notBefore;
    cert.NotAfter = notAfter;

    let mut subjectSeq = CBString::default();
    if !tbs.ReadASN1Element(&mut subjectSeq, cryptobyte_asn1::SEQUENCE) {
        return (Certificate::default(), errors::New("x509: malformed issuer"));
    }
    cert.RawSubject = subjectSeq.0.clone();
    let (subjectRDNs, err) = parseName(subjectSeq);
    if err != crate::nil {
        return (Certificate::default(), err);
    }
    cert.Subject.FillFromRDNSequence(&subjectRDNs);

    let mut spki = CBString::default();
    if !tbs.ReadASN1Element(&mut spki, cryptobyte_asn1::SEQUENCE) {
        return (Certificate::default(), errors::New("x509: malformed spki"));
    }
    cert.RawSubjectPublicKeyInfo = spki.0.clone();
    let mut inner = CBString::default();
    if !spki.ReadASN1(&mut inner, cryptobyte_asn1::SEQUENCE) {
        return (Certificate::default(), errors::New("x509: malformed spki"));
    }
    spki = inner;
    let mut pkAISeq = CBString::default();
    if !spki.ReadASN1(&mut pkAISeq, cryptobyte_asn1::SEQUENCE) {
        return (
            Certificate::default(),
            errors::New("x509: malformed public key algorithm identifier"),
        );
    }
    let (pkAI, err) = parseAI(pkAISeq);
    if err != crate::nil {
        return (Certificate::default(), err);
    }
    cert.PublicKeyAlgorithm = getPublicKeyAlgorithmFromOID(&pkAI.Algorithm);
    let mut spk = asn1::BitString::default();
    if !spki.ReadASN1BitString(&mut spk) {
        return (
            Certificate::default(),
            errors::New("x509: malformed subjectPublicKey"),
        );
    }
    if cert.PublicKeyAlgorithm != UnknownPublicKeyAlgorithm {
        let (pk, err) = parsePublicKey(&publicKeyInfo {
            Raw: asn1::RawContent::default(),
            Algorithm: pkAI,
            PublicKey: spk,
        });
        if err != crate::nil {
            return (Certificate::default(), err);
        }
        cert.PublicKey = pk;
    }

    if cert.Version > 1 {
        if !tbs.SkipOptionalASN1(cryptobyte_asn1::Tag(1).ContextSpecific()) {
            return (
                Certificate::default(),
                errors::New("x509: malformed issuerUniqueID"),
            );
        }
        if !tbs.SkipOptionalASN1(cryptobyte_asn1::Tag(2).ContextSpecific()) {
            return (
                Certificate::default(),
                errors::New("x509: malformed subjectUniqueID"),
            );
        }
        if cert.Version == 3 {
            let mut extensions = CBString::default();
            let mut present = false;
            if !tbs.ReadOptionalASN1(
                &mut extensions,
                Some(&mut present),
                cryptobyte_asn1::Tag(3).Constructed().ContextSpecific(),
            ) {
                return (
                    Certificate::default(),
                    errors::New("x509: malformed extensions"),
                );
            }
            if present {
                let mut seenExts: map<string, bool> = map::new();
                let mut inner = CBString::default();
                if !extensions.ReadASN1(&mut inner, cryptobyte_asn1::SEQUENCE) {
                    return (
                        Certificate::default(),
                        errors::New("x509: malformed extensions"),
                    );
                }
                extensions = inner;
                while !extensions.Empty() {
                    let mut extension = CBString::default();
                    if !extensions.ReadASN1(&mut extension, cryptobyte_asn1::SEQUENCE) {
                        return (
                            Certificate::default(),
                            errors::New("x509: malformed extension"),
                        );
                    }
                    let (ext, err) = parseExtension(extension);
                    if err != crate::nil {
                        return (Certificate::default(), err);
                    }
                    let oidStr = ext.Id.String();
                    let (seen, _) = seenExts.Get(oidStr.clone());
                    if seen {
                        return (
                            Certificate::default(),
                            crate::fmt::Errorf!(
                                "x509: certificate contains duplicate extension with OID %q",
                                oidStr
                            ),
                        );
                    }
                    seenExts.Set(oidStr, true);
                    cert.Extensions = crate::append!(cert.Extensions.clone(), ext);
                }
                let err = processExtensions(&mut cert);
                if err != crate::nil {
                    return (Certificate::default(), err);
                }
            }
        }
    }

    let mut signature = asn1::BitString::default();
    if !input.ReadASN1BitString(&mut signature) {
        return (Certificate::default(), errors::New("x509: malformed signature"));
    }
    cert.Signature = signature.RightAlign();

    return (cert, errors::nil);
}

// go: sdk 1.25.5 crypto/x509/parser.go:1079-1093 ParseCertificate
/// Parse a single certificate from the given ASN.1 DER data.
///
/// Go documents that `GODEBUG=x509negativeserial=1` restores acceptance
/// of negative serial numbers; goish has no GODEBUG, so a negative
/// serial is always an error.
pub fn ParseCertificate(der: slice<byte>) -> (Certificate, error) {
    let (cert, err) = parseCertificate(&der);
    if err != crate::nil {
        return (Certificate::default(), err);
    }
    if der.Len() != cert.Raw.Len() {
        return (Certificate::default(), errors::New("x509: trailing data"));
    }
    return (cert, errors::nil);
}

// go: sdk 1.25.5 crypto/x509/parser.go:1095-1108 ParseCertificates
/// Parse one or more certificates from the given ASN.1 DER data. The
/// certificates must be concatenated with no intermediate padding.
pub fn ParseCertificates(der: slice<byte>) -> (slice<Certificate>, error) {
    let mut certs: Vec<Certificate> = Vec::new();
    let mut der = der;
    while der.Len() > 0 {
        let (cert, err) = parseCertificate(&der);
        if err != crate::nil {
            return (slice::__from_vec(Vec::new()), err);
        }
        let n = cert.Raw.Len();
        certs.push(cert);
        let raw: &[byte] = &der;
        der = slice::__from_vec(raw[n as usize..].to_vec());
    }
    return (slice::__from_vec(certs), errors::nil);
}

// go: sdk 1.25.5 crypto/x509/parser.go:1298-1355 domainNameValid
/// An alloc-less version of the checks that `domainToReverseLabels` does.
pub(super) fn domainNameValid(s: &string, constraint: bool) -> bool {
    // TODO(#75835): This function omits a number of checks which we
    // really should be doing to enforce that domain names are valid names per
    // RFC 1034. We previously enabled these checks, but this broke a
    // significant number of certificates we previously considered valid, and we
    // happily create via CreateCertificate (et al). We should enable these
    // checks, but will need to gate them behind a GODEBUG.
    //
    // I have left the checks we previously enabled, noted with "TODO(#75835)" so
    // that we can easily re-enable them once we unbreak everyone.

    // TODO(#75835): this should only be true for constraints.
    let b = s.as_bytes();
    if b.is_empty() {
        return true;
    }

    // Do not allow trailing period (FQDN format is not allowed in SANs or
    // constraints).
    if b[b.len() - 1] == b'.' {
        return false;
    }

    // TODO(#75835): domains must have at least one label, cannot have
    // a leading empty label, and cannot be longer than 253 characters.

    let mut lastDot: int = -1;
    let mut start: usize = 0;
    if constraint && b[0] == b'.' {
        start = 1;
    }
    let b = &b[start..];

    let mut i: usize = 0;
    while i <= b.len() {
        if i < b.len() && (b[i] < 33 || b[i] > 126) {
            // Invalid character.
            return false;
        }
        if i == b.len() || b[i] == b'.' {
            let mut labelLen = int(i);
            if lastDot >= 0 {
                labelLen -= lastDot + 1;
            }
            if labelLen == 0 {
                return false;
            }
            // TODO(#75835): labels cannot be longer than 63 characters.
            lastDot = int(i);
        }
        i += 1;
    }

    return true;
}

