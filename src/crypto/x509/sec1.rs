// go: file crypto/x509/sec1.go decls: ParseECPrivateKey, MarshalECPrivateKey, marshalECPrivateKeyWithOID, marshalECDHPrivateKey, parseECPrivateKey
//
// SEC 1 / RFC 5915 elliptic-curve private-key serialisation — all five
// functions of sec1.go, plus the `ecPrivateKey` ASN.1 shape struct.
//
// Deviations from sec1[go] @ Go 1.25.5:
//
//   * `*ecdsa.PrivateKey` / `*ecdh.PrivateKey` parameters and returns are
//     values, per goish's pointer-to-struct-is-the-value convention. The
//     `nil` return on the error path is the zero key.
//
//   * `parseECPrivateKey(namedCurveOID *asn1.ObjectIdentifier, …)` uses
//     the pointer's nil-ness to mean "no OID supplied by the caller".
//     goish spells that `Option<&asn1::ObjectIdentifier>`, which is the
//     same three-state logic without a pointer — the shape common.rs
//     already uses for `fieldParameters.tag`.
//
//   * `marshalECPrivateKeyWithOID(key, oid)` is called with a nil `oid`
//     from pkcs8.go to mean "omit the curve OID". Same `Option` spelling.
//     The omitted case is expressed as the *empty* ObjectIdentifier,
//     which is what `asn1.Marshal` skips for an `optional,explicit` field
//     — Go's nil slice and goish's empty slice marshal identically.
//
//   * `key.Curve.Params()` returns a `CurveParams` value in goish rather
//     than a pointer; `.N` is reached the same way.
//
//   * The `ecPrivateKey` reflect descriptor is hand-written rather than
//     `#[goish::reflect]`-generated; the reason is at the foot of
//     crypto/x509/pkix/pkix.rs.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::crypto::ecdh;
use crate::crypto::ecdsa;
use crate::crypto::elliptic;
use crate::encoding::asn1;
use crate::error;
use crate::errors;
use crate::fmt;
use crate::goslice::slice;
use crate::gostring::string;
use crate::math::big;
use crate::reflect;
use crate::strings;
use crate::types::{byte, int};

// go: sdk 1.25.5 crypto/x509/sec1.go:17 ecPrivKeyVersion
goish::var! { pub(super) ecPrivKeyVersion: int = 1; }

// Go: sec1.go:19-31
//   type ecPrivateKey struct {
//       Version int
//       PrivateKey []byte
//       NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
//       PublicKey asn1.BitString `asn1:"optional,explicit,tag:1"` }
/// Reflects an ASN.1 Elliptic Curve Private Key Structure.
/// References: RFC 5915; SEC1 — http://www.secg.org/sec1-v2.pdf
///
/// Per RFC 5915 the NamedCurveOID is marked as ASN.1 OPTIONAL, however in
/// most cases it is not.
#[derive(Clone, Default)]
pub struct ecPrivateKey {
    pub Version: int,
    pub PrivateKey: slice<byte>,
    pub NamedCurveOID: asn1::ObjectIdentifier,
    pub PublicKey: asn1::BitString,
}

// go: sdk 1.25.5 crypto/x509/sec1.go:36-38 ParseECPrivateKey
/// Parse an EC private key in SEC 1, ASN.1 DER form.
///
/// This kind of key is commonly encoded in PEM blocks of type
/// "EC PRIVATE KEY".
pub fn ParseECPrivateKey(der: slice<byte>) -> (ecdsa::PrivateKey, error) {
    return parseECPrivateKey(None, der);
}

// go: sdk 1.25.5 crypto/x509/sec1.go:45-52 MarshalECPrivateKey
/// Convert an EC private key to SEC 1, ASN.1 DER form.
///
/// This kind of key is commonly encoded in PEM blocks of type
/// "EC PRIVATE KEY". For a more flexible key format which is not EC
/// specific, use [`super::MarshalPKCS8PrivateKey`].
pub fn MarshalECPrivateKey(key: &ecdsa::PrivateKey) -> (slice<byte>, error) {
    let (oid, ok) = super::x509::oidFromNamedCurve(key.PublicKey.Curve);
    if !ok {
        return (
            slice::default(),
            errors::New("x509: unknown elliptic curve"),
        );
    }

    return marshalECPrivateKeyWithOID(key, Some(&oid));
}

// go: sdk 1.25.5 crypto/x509/sec1.go:57-68 marshalECPrivateKeyWithOID
/// Marshal an EC private key into ASN.1, DER format and set the curve ID
/// to the given OID, or omit it if the OID is `None`.
pub fn marshalECPrivateKeyWithOID(
    key: &ecdsa::PrivateKey,
    oid: Option<&asn1::ObjectIdentifier>,
) -> (slice<byte>, error) {
    if !key
        .PublicKey
        .Curve
        .IsOnCurve(&key.PublicKey.X, &key.PublicKey.Y)
    {
        return (
            slice::default(),
            errors::New("invalid elliptic key public key"),
        );
    }
    // Go: privateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
    let n = key.PublicKey.Curve.Params().N;
    let privateKey: slice<byte> =
        slice::__from_vec(alloc::vec![0u8; ((n.BitLen() + 7) / 8) as usize]);
    let named = match oid {
        Some(o) => o.clone(),
        None => asn1::ObjectIdentifier::default(),
    };
    return asn1::Marshal(&ecPrivateKey {
        Version: 1,
        PrivateKey: key.D.FillBytes(privateKey),
        NamedCurveOID: named,
        PublicKey: asn1::BitString {
            Bytes: elliptic::Marshal(key.PublicKey.Curve, &key.PublicKey.X, &key.PublicKey.Y),
            BitLength: 0,
        },
    });
}

// go: sdk 1.25.5 crypto/x509/sec1.go:72-78 marshalECDHPrivateKey
/// Marshal an EC private key into ASN.1, DER format suitable for NIST
/// curves.
pub fn marshalECDHPrivateKey(key: &ecdh::PrivateKey) -> (slice<byte>, error) {
    return asn1::Marshal(&ecPrivateKey {
        Version: 1,
        PrivateKey: key.Bytes(),
        NamedCurveOID: asn1::ObjectIdentifier::default(),
        PublicKey: asn1::BitString {
            Bytes: key.PublicKey().Bytes(),
            BitLength: 0,
        },
    });
}

// go: sdk 1.25.5 crypto/x509/sec1.go:82-135 parseECPrivateKey
/// Parse an ASN.1 Elliptic Curve Private Key Structure. The OID for the
/// named curve may be provided from another source (such as the PKCS8
/// container) — if it is provided then use this instead of the OID that
/// may exist in the EC private key structure.
pub fn parseECPrivateKey(
    namedCurveOID: Option<&asn1::ObjectIdentifier>,
    der: slice<byte>,
) -> (ecdsa::PrivateKey, error) {
    let mut privKey = ecPrivateKey::default();
    let (_, err) = asn1::Unmarshal(der.clone(), &mut privKey);
    if err != errors::nil {
        let mut p8 = super::pkcs8::pkcs8::default();
        let (_, e) = asn1::Unmarshal(der.clone(), &mut p8);
        if e == errors::nil {
            return (
                crate::nil.into(),
                errors::New(
                    "x509: failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)",
                ),
            );
        }
        let mut p1 = super::pkcs1::pkcs1PrivateKey::default();
        let (_, e) = asn1::Unmarshal(der.clone(), &mut p1);
        if e == errors::nil {
            return (
                crate::nil.into(),
                errors::New(
                    "x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)",
                ),
            );
        }
        return (
            crate::nil.into(),
            errors::New(concat2(
                "x509: failed to parse EC private key: ",
                err.Error(),
            )),
        );
    }
    if privKey.Version != ecPrivKeyVersion {
        return (
            crate::nil.into(),
            fmt::Errorf!("x509: unknown EC private key version %d", privKey.Version),
        );
    }

    // Go: `curve` is a nil `elliptic.Curve` interface for an unknown OID.
    // goish's `namedCurveFromOID` returns `Option`, the nil-able shape
    // for a `&'static dyn` with no sentinel, so the nil test is the
    // `None` arm.
    let curveOpt = match namedCurveOID {
        Some(o) => super::x509::namedCurveFromOID(o),
        None => super::x509::namedCurveFromOID(&privKey.NamedCurveOID),
    };
    let curve = match curveOpt {
        Some(c) => c,
        None => {
            return (
                crate::nil.into(),
                errors::New("x509: unknown elliptic curve"),
            )
        }
    };

    let mut k = big::Int::new();
    k.SetBytes(privKey.PrivateKey.clone());
    let curveOrder = curve.Params().N;
    if k.Cmp(&curveOrder) >= 0 {
        return (
            crate::nil.into(),
            errors::New("x509: invalid elliptic curve private key value"),
        );
    }
    let mut priv_: ecdsa::PrivateKey = crate::nil.into();
    priv_.PublicKey.Curve = curve;
    priv_.D = k;

    let plen = (curveOrder.BitLen() + 7) / 8;
    let mut privateKey: Vec<byte> = alloc::vec![0u8; plen as usize];

    // Some private keys have leading zero padding. This is invalid
    // according to [SEC1], but this code will ignore it.
    while privKey.PrivateKey.Len() > plen {
        if privKey.PrivateKey[0i64] != 0 {
            return (
                crate::nil.into(),
                errors::New("x509: invalid private key length"),
            );
        }
        privKey.PrivateKey = privKey.PrivateKey.slice(1, privKey.PrivateKey.Len());
    }

    // Some private keys remove all leading zeros, this is also invalid
    // according to [SEC1] but since OpenSSL used to do this, we ignore
    // this too.
    //
    // Go: copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
    let start = plen - privKey.PrivateKey.Len();
    for (i, b) in crate::range!(privKey.PrivateKey.clone()) {
        privateKey[(start + i) as usize] = *b;
    }
    let (x, y) = priv_
        .PublicKey
        .Curve
        .ScalarBaseMult(&slice::__from_vec(privateKey));
    priv_.PublicKey.X = x;
    priv_.PublicKey.Y = y;

    return (priv_, errors::nil);
}

// go: none — goish idiom: Go writes `"prefix: " + err.Error()` on
// strings; goish concatenates through a Builder.
pub(super) fn concat2(a: &str, b: string) -> string {
    let mut s = strings::Builder::new();
    let _ = s.WriteString(a);
    let _ = s.WriteString(b);
    return s.String();
}

// ─── reflect descriptor ───────────────────────────────────────────────
//
// go: none — goish-only, and a prerequisite rather than a port. See the
// banner at the foot of crypto/x509/pkix/pkix.rs.

static EC_PRIVATE_KEY_FIELDS: [reflect::StructField; 4] = [
    reflect::StructField {
        Name: "Version",
        Tag: reflect::StructTag::__new(""),
        Type: <int as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    reflect::StructField {
        Name: "PrivateKey",
        Tag: reflect::StructTag::__new(""),
        Type: <slice<byte> as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    reflect::StructField {
        Name: "NamedCurveOID",
        Tag: reflect::StructTag::__new("asn1:\"optional,explicit,tag:0\""),
        Type: <asn1::ObjectIdentifier as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    reflect::StructField {
        Name: "PublicKey",
        Tag: reflect::StructTag::__new("asn1:\"optional,explicit,tag:1\""),
        Type: <asn1::BitString as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];

impl reflect::Reflect for ecPrivateKey {
    // go: none — goish-only: the reflect descriptor. See the banner above.
    fn __reflect_type() -> reflect::Type {
        return reflect::Type::__new(
            reflect::Kind::Struct,
            "ecPrivateKey",
            &EC_PRIVATE_KEY_FIELDS,
        );
    }

    // go: none — goish-only: the reflect descriptor. See the banner above.
    fn __reflect_value(&self) -> reflect::Value {
        return reflect::Value::Struct {
            ty: <ecPrivateKey as reflect::Reflect>::__reflect_type(),
            fields: alloc::vec![
                reflect::Value::Int(self.Version),
                reflect::Reflect::__reflect_value(&self.PrivateKey),
                reflect::Reflect::__reflect_value(&self.NamedCurveOID),
                reflect::Reflect::__reflect_value(&self.PublicKey),
            ],
        };
    }
}

impl reflect::FromReflectValue for ecPrivateKey {
    // go: none — goish-only: the write half of the descriptor above.
    fn from_reflect_value(v: reflect::Value) -> (Self, error) {
        if v.Kind() != reflect::Kind::Struct {
            return (
                ecPrivateKey::default(),
                errors::New("x509: expected ecPrivateKey"),
            );
        }
        let (oid, err) =
            <asn1::ObjectIdentifier as reflect::FromReflectValue>::from_reflect_value(v.Field(2));
        if err != errors::nil {
            return (ecPrivateKey::default(), err);
        }
        let (bs, err) =
            <asn1::BitString as reflect::FromReflectValue>::from_reflect_value(v.Field(3));
        if err != errors::nil {
            return (ecPrivateKey::default(), err);
        }
        return (
            ecPrivateKey {
                Version: v.Field(0).Int(),
                PrivateKey: v.Field(1).Bytes(),
                NamedCurveOID: oid,
                PublicKey: bs,
            },
            errors::nil,
        );
    }
}
