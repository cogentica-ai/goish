// go: file crypto/x509/pkcs8.go decls: ParsePKCS8PrivateKey, MarshalPKCS8PrivateKey
//
// PKCS #8 private-key serialisation — both exported functions of
// pkcs8.go, plus the `pkcs8` ASN.1 shape struct.
//
// Deviations from pkcs8[go] @ Go 1.25.5:
//
//   * `key any` in and out is `goany::Any`, the same carrier
//     `Certificate.PublicKey` already uses. The four concrete types it
//     can hold are unchanged: `rsa::PrivateKey`, `ecdsa::PrivateKey`,
//     `ed25519::PrivateKey`, `ecdh::PrivateKey`. Retrieval is
//     `key.As::<T>()`. `Any::new_fn` is used rather than `Any::new` for
//     the same reason x509.rs states for public keys — none of the four
//     is `==`-comparable in goish.
//
//   * `switch k := key.(type)` in `MarshalPKCS8PrivateKey` becomes a
//     chain of `As::<T>()` probes in the same order. Go's ordering is
//     load-bearing: `*ecdh.PrivateKey` is tested last, after the X25519
//     carve-out inside it, and that order is preserved.
//
//   * `asn1.Unmarshal(bytes, namedCurveOID)` where `namedCurveOID` is a
//     `*asn1.ObjectIdentifier` set to nil on failure: goish spells the
//     nil-ness as `Option`, matching `parseECPrivateKey`'s parameter.
//
//   * The `pkcs8` struct's reflect descriptor is hand-written rather than
//     `#[goish::reflect]`-generated; the reason is at the foot of
//     crypto/x509/pkix/pkix.rs.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::crypto::ecdh;
use crate::crypto::ecdsa;
use crate::crypto::ed25519;
use crate::crypto::rsa;
use crate::crypto::x509::pkix;
use crate::encoding::asn1;
use crate::error;
use crate::errors;
use crate::fmt;
use crate::goany::Any;
use crate::goslice::slice;
use crate::reflect;
use crate::types::{byte, int};

// Go: pkcs8.go:20-25
//   type pkcs8 struct { Version int
//                       Algo pkix.AlgorithmIdentifier
//                       PrivateKey []byte }
/// Reflects an ASN.1, PKCS #8 PrivateKey. See
/// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn and RFC 5208.
///
/// Optional attributes omitted.
#[derive(Clone, Default)]
pub struct pkcs8 {
    pub Version: int,
    pub Algo: pkix::AlgorithmIdentifier,
    pub PrivateKey: slice<byte>,
}

// go: sdk 1.25.5 crypto/x509/pkcs8.go:37-95 ParsePKCS8PrivateKey
/// Parse an unencrypted private key in PKCS #8, ASN.1 DER form.
///
/// It returns an `rsa::PrivateKey`, an `ecdsa::PrivateKey`, an
/// `ed25519::PrivateKey`, or an `ecdh::PrivateKey` (for X25519), wrapped
/// in `Any`. More types might be supported in the future.
///
/// This kind of key is commonly encoded in PEM blocks of type
/// "PRIVATE KEY".
pub fn ParsePKCS8PrivateKey(der: slice<byte>) -> (Any, error) {
    let mut privKey = pkcs8::default();
    let (_, err) = asn1::Unmarshal(der.clone(), &mut privKey);
    if err != errors::nil {
        let mut ec = super::sec1::ecPrivateKey::default();
        let (_, e) = asn1::Unmarshal(der.clone(), &mut ec);
        if e == errors::nil {
            return (
                Any::default(),
                errors::New(
                    "x509: failed to parse private key (use ParseECPrivateKey instead for this key format)",
                ),
            );
        }
        let mut p1 = super::pkcs1::pkcs1PrivateKey::default();
        let (_, e) = asn1::Unmarshal(der.clone(), &mut p1);
        if e == errors::nil {
            return (
                Any::default(),
                errors::New(
                    "x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)",
                ),
            );
        }
        return (Any::default(), err);
    }

    if privKey
        .Algo
        .Algorithm
        .Equal(&super::x509::oidPublicKeyRSA())
    {
        let (key, err) = super::pkcs1::ParsePKCS1PrivateKey(privKey.PrivateKey.clone());
        if err != errors::nil {
            return (
                Any::default(),
                errors::New(super::sec1::concat2(
                    "x509: failed to parse RSA private key embedded in PKCS#8: ",
                    err.Error(),
                )),
            );
        }
        return (Any::new_fn(key), errors::nil);
    }

    if privKey
        .Algo
        .Algorithm
        .Equal(&super::x509::oidPublicKeyECDSA())
    {
        let bytes = privKey.Algo.Parameters.FullBytes.clone();
        let mut oid = asn1::ObjectIdentifier::default();
        let (_, e) = asn1::Unmarshal(bytes, &mut oid);
        // Go: `namedCurveOID = nil` when the inner Unmarshal fails.
        let namedCurveOID = if e == errors::nil { Some(&oid) } else { None };
        let (key, err) = super::sec1::parseECPrivateKey(namedCurveOID, privKey.PrivateKey.clone());
        if err != errors::nil {
            return (
                Any::default(),
                errors::New(super::sec1::concat2(
                    "x509: failed to parse EC private key embedded in PKCS#8: ",
                    err.Error(),
                )),
            );
        }
        return (Any::new_fn(key), errors::nil);
    }

    if privKey
        .Algo
        .Algorithm
        .Equal(&super::x509::oidPublicKeyEd25519())
    {
        if privKey.Algo.Parameters.FullBytes.Len() != 0 {
            return (
                Any::default(),
                errors::New("x509: invalid Ed25519 private key parameters"),
            );
        }
        let mut curvePrivateKey: slice<byte> = slice::default();
        let (_, e) = asn1::Unmarshal(privKey.PrivateKey.clone(), &mut curvePrivateKey);
        if e != errors::nil {
            return (
                Any::default(),
                fmt::Errorf!("x509: invalid Ed25519 private key: %v", e),
            );
        }
        let l = curvePrivateKey.Len();
        if l != ed25519::SeedSize {
            return (
                Any::default(),
                fmt::Errorf!("x509: invalid Ed25519 private key length: %d", l),
            );
        }
        let key = ed25519::NewKeyFromSeed(curvePrivateKey);
        return (Any::new_fn(key), errors::nil);
    }

    if privKey
        .Algo
        .Algorithm
        .Equal(&super::x509::oidPublicKeyX25519())
    {
        if privKey.Algo.Parameters.FullBytes.Len() != 0 {
            return (
                Any::default(),
                errors::New("x509: invalid X25519 private key parameters"),
            );
        }
        let mut curvePrivateKey: slice<byte> = slice::default();
        let (_, e) = asn1::Unmarshal(privKey.PrivateKey.clone(), &mut curvePrivateKey);
        if e != errors::nil {
            return (
                Any::default(),
                fmt::Errorf!("x509: invalid X25519 private key: %v", e),
            );
        }
        let (key, err) = ecdh::X25519().NewPrivateKey(&curvePrivateKey);
        if err != errors::nil {
            return (Any::default(), err);
        }
        return (Any::new_fn(key), errors::nil);
    }

    return (
        Any::default(),
        fmt::Errorf!(
            "x509: PKCS#8 wrapping contained private key with unknown algorithm: %v",
            privKey.Algo.Algorithm.String()
        ),
    );
}

// go: sdk 1.25.5 crypto/x509/pkcs8.go:105-184 MarshalPKCS8PrivateKey
/// Convert a private key to PKCS #8, ASN.1 DER form.
///
/// The following key types are currently supported: `rsa::PrivateKey`,
/// `ecdsa::PrivateKey`, `ed25519::PrivateKey`, and `ecdh::PrivateKey`.
/// Unsupported key types result in an error.
///
/// This kind of key is commonly encoded in PEM blocks of type
/// "PRIVATE KEY".
///
/// `MarshalPKCS8PrivateKey` runs `rsa::PrivateKey::Precompute` on RSA
/// keys.
pub fn MarshalPKCS8PrivateKey(key: &Any) -> (slice<byte>, error) {
    let mut privKey = pkcs8::default();

    // Go: switch k := key.(type) { case *rsa.PrivateKey: … }
    if let Some(k) = key.As::<rsa::PrivateKey>() {
        privKey.Algo = pkix::AlgorithmIdentifier {
            Algorithm: super::x509::oidPublicKeyRSA(),
            Parameters: asn1::NullRawValue(),
        };
        let mut k = k.clone();
        k.Precompute();
        let err = k.Validate();
        if err != errors::nil {
            return (slice::default(), err);
        }
        privKey.PrivateKey = super::pkcs1::MarshalPKCS1PrivateKey(&mut k);
        return asn1::Marshal(&privKey);
    }

    if let Some(k) = key.As::<ecdsa::PrivateKey>() {
        let (oid, ok) = super::x509::oidFromNamedCurve(k.PublicKey.Curve);
        if !ok {
            return (
                slice::default(),
                errors::New("x509: unknown curve while marshaling to PKCS#8"),
            );
        }
        let (oidBytes, err) = asn1::Marshal(&oid);
        if err != errors::nil {
            return (
                slice::default(),
                errors::New(super::sec1::concat2(
                    "x509: failed to marshal curve OID: ",
                    err.Error(),
                )),
            );
        }
        privKey.Algo = pkix::AlgorithmIdentifier {
            Algorithm: super::x509::oidPublicKeyECDSA(),
            Parameters: asn1::RawValue {
                Class: 0,
                Tag: 0,
                IsCompound: false,
                Bytes: slice::default(),
                FullBytes: oidBytes,
            },
        };
        let (b, err) = super::sec1::marshalECPrivateKeyWithOID(k, None);
        if err != errors::nil {
            return (
                slice::default(),
                errors::New(super::sec1::concat2(
                    "x509: failed to marshal EC private key while building PKCS#8: ",
                    err.Error(),
                )),
            );
        }
        privKey.PrivateKey = b;
        return asn1::Marshal(&privKey);
    }

    if let Some(k) = key.As::<ed25519::PrivateKey>() {
        privKey.Algo = pkix::AlgorithmIdentifier {
            Algorithm: super::x509::oidPublicKeyEd25519(),
            Parameters: asn1::RawValue::default(),
        };
        let (curvePrivateKey, err) = asn1::Marshal(&k.Seed());
        if err != errors::nil {
            return (
                slice::default(),
                fmt::Errorf!("x509: failed to marshal private key: %v", err),
            );
        }
        privKey.PrivateKey = curvePrivateKey;
        return asn1::Marshal(&privKey);
    }

    if let Some(k) = key.As::<ecdh::PrivateKey>() {
        if k.Curve().String() == ecdh::X25519().String() {
            privKey.Algo = pkix::AlgorithmIdentifier {
                Algorithm: super::x509::oidPublicKeyX25519(),
                Parameters: asn1::RawValue::default(),
            };
            let (b, err) = asn1::Marshal(&k.Bytes());
            if err != errors::nil {
                return (
                    slice::default(),
                    fmt::Errorf!("x509: failed to marshal private key: %v", err),
                );
            }
            privKey.PrivateKey = b;
        } else {
            let (oid, ok) = super::x509::oidFromECDHCurve(k.Curve());
            if !ok {
                return (
                    slice::default(),
                    errors::New("x509: unknown curve while marshaling to PKCS#8"),
                );
            }
            let (oidBytes, err) = asn1::Marshal(&oid);
            if err != errors::nil {
                return (
                    slice::default(),
                    errors::New(super::sec1::concat2(
                        "x509: failed to marshal curve OID: ",
                        err.Error(),
                    )),
                );
            }
            privKey.Algo = pkix::AlgorithmIdentifier {
                Algorithm: super::x509::oidPublicKeyECDSA(),
                Parameters: asn1::RawValue {
                    Class: 0,
                    Tag: 0,
                    IsCompound: false,
                    Bytes: slice::default(),
                    FullBytes: oidBytes,
                },
            };
            let (b, err) = super::sec1::marshalECDHPrivateKey(k);
            if err != errors::nil {
                return (
                    slice::default(),
                    errors::New(super::sec1::concat2(
                        "x509: failed to marshal EC private key while building PKCS#8: ",
                        err.Error(),
                    )),
                );
            }
            privKey.PrivateKey = b;
        }
        return asn1::Marshal(&privKey);
    }

    return (
        slice::default(),
        errors::New("x509: unknown key type while marshaling PKCS#8"),
    );
}

// ─── reflect descriptor ───────────────────────────────────────────────
//
// go: none — goish-only, and a prerequisite rather than a port. See the
// banner at the foot of crypto/x509/pkix/pkix.rs.

static PKCS8_FIELDS: [reflect::StructField; 3] = [
    reflect::StructField {
        Name: "Version",
        Tag: reflect::StructTag::__new(""),
        Type: <int as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    reflect::StructField {
        Name: "Algo",
        Tag: reflect::StructTag::__new(""),
        Type: <pkix::AlgorithmIdentifier as reflect::Reflect>::__reflect_type,
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
];

impl reflect::Reflect for pkcs8 {
    // go: none — goish-only: the reflect descriptor. See the banner above.
    fn __reflect_type() -> reflect::Type {
        return reflect::Type::__new(reflect::Kind::Struct, "pkcs8", &PKCS8_FIELDS);
    }

    // go: none — goish-only: the reflect descriptor. See the banner above.
    fn __reflect_value(&self) -> reflect::Value {
        return reflect::Value::Struct {
            ty: <pkcs8 as reflect::Reflect>::__reflect_type(),
            fields: alloc::vec![
                reflect::Value::Int(self.Version),
                reflect::Reflect::__reflect_value(&self.Algo),
                reflect::Reflect::__reflect_value(&self.PrivateKey),
            ],
        };
    }
}

impl reflect::FromReflectValue for pkcs8 {
    // go: none — goish-only: the write half of the descriptor above.
    fn from_reflect_value(v: reflect::Value) -> (Self, error) {
        if v.Kind() != reflect::Kind::Struct {
            return (pkcs8::default(), errors::New("x509: expected pkcs8"));
        }
        let (algo, err) =
            <pkix::AlgorithmIdentifier as reflect::FromReflectValue>::from_reflect_value(
                v.Field(1),
            );
        if err != errors::nil {
            return (pkcs8::default(), err);
        }
        return (
            pkcs8 {
                Version: v.Field(0).Int(),
                Algo: algo,
                PrivateKey: v.Field(2).Bytes(),
            },
            errors::nil,
        );
    }
}
