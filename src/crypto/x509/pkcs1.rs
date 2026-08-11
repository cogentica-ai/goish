// go: file crypto/x509/pkcs1.go decls: ParsePKCS1PrivateKey, MarshalPKCS1PrivateKey, ParsePKCS1PublicKey, MarshalPKCS1PublicKey
//
// PKCS #1 RSA key serialisation — all four exported functions of
// pkcs1.go, plus the three ASN.1 shape structs they hand to
// `asn1.Marshal` / `asn1.Unmarshal`.
//
// Deviations from pkcs1[go] @ Go 1.25.5:
//
//   * `*big.Int` is `big::Int` throughout — goish models a Go
//     pointer-to-struct as the value, and `big::Int` carries the
//     polymorphic-nil impls (`== nil` is "is zero"), which is what makes
//     the OPTIONAL CRT-parameter guards below port verbatim: Go's
//     `priv.Dp != nil && priv.Dp.Sign() <= 0` reads the same here and
//     means the same thing. The one behaviour it cannot reproduce is a
//     CRT parameter that is *present and zero on the wire* — Go rejects
//     it explicitly, goish sees the absent value and lets `Precompute` /
//     `Validate` reject it downstream.
//
//   * `*rsa.PrivateKey` / `*rsa.PublicKey` returns are `rsa::PrivateKey`
//     / `rsa::PublicKey` values, same reason. The `nil` return on the
//     error path is the zero key.
//
//   * `x509rsacrt` (`internal/godebug`) is absent: goish has no godebug,
//     so the GODEBUG=x509rsacrt=0 fallback that retries without the CRT
//     values is not reachable. `ParsePKCS1PrivateKey` therefore takes the
//     default branch — return the validation error — which is what Go
//     does whenever the variable is unset. Stated, not silently dropped.
//
//   * The three structs' `reflect` descriptors are hand-written rather
//     than `#[goish::reflect]`-generated; the reason is the same one
//     stated at the foot of crypto/x509/pkix/pkix.rs (the macro also
//     emits JSON codecs, which DER shape types have no meaning for).
//
// goishlint:ignore GOISH021 x509rsacrt — internal/godebug is not ported; see the banner.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::crypto::rsa;
use crate::encoding::asn1;
use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::gostring::string;
use crate::math::big;
use crate::reflect;
use crate::types::{byte, int};

// Go: pkcs1.go:15-26
//   type pkcs1PrivateKey struct {
//       Version int; N *big.Int; E int; D, P, Q *big.Int
//       Dp, Dq, Qinv *big.Int `asn1:"optional"`
//       AdditionalPrimes []pkcs1AdditionalRSAPrime `asn1:"optional,omitempty"` }
/// Mirrors the PKCS #1 ASN.1 for an RSA private key.
#[derive(Clone, Default)]
pub struct pkcs1PrivateKey {
    pub Version: int,
    pub N: big::Int,
    pub E: int,
    pub D: big::Int,
    pub P: big::Int,
    pub Q: big::Int,
    pub Dp: big::Int,
    pub Dq: big::Int,
    pub Qinv: big::Int,
    pub AdditionalPrimes: slice<pkcs1AdditionalRSAPrime>,
}

// Go: pkcs1.go:28-34
//   type pkcs1AdditionalRSAPrime struct { Prime, Exp, Coeff *big.Int }
/// One of the 3rd-and-later primes of a multi-prime RSA key.
#[derive(Clone, Default)]
pub struct pkcs1AdditionalRSAPrime {
    pub Prime: big::Int,

    /// We ignore these values because rsa will calculate them.
    pub Exp: big::Int,
    pub Coeff: big::Int,
}

// Go: pkcs1.go:36-40
//   type pkcs1PublicKey struct { N *big.Int; E int }
/// Reflects the ASN.1 structure of a PKCS #1 public key.
#[derive(Clone, Default)]
pub struct pkcs1PublicKey {
    pub N: big::Int,
    pub E: int,
}

// go: sdk 1.25.5 crypto/x509/pkcs1.go:52-118 ParsePKCS1PrivateKey
/// Parse an RSA private key in PKCS #1, ASN.1 DER form.
///
/// This kind of key is commonly encoded in PEM blocks of type
/// "RSA PRIVATE KEY".
pub fn ParsePKCS1PrivateKey(der: slice<byte>) -> (rsa::PrivateKey, error) {
    let mut priv_ = pkcs1PrivateKey::default();
    let (rest, err) = asn1::Unmarshal(der.clone(), &mut priv_);
    if rest.Len() > 0 {
        return (
            rsa::PrivateKey::default(),
            asn1::SyntaxError {
                Msg: string::from_static("trailing data"),
            }
            .into(),
        );
    }
    if err != errors::nil {
        let mut ec = super::sec1::ecPrivateKey::default();
        let (_, e) = asn1::Unmarshal(der.clone(), &mut ec);
        if e == errors::nil {
            return (
                rsa::PrivateKey::default(),
                errors::New(
                    "x509: failed to parse private key (use ParseECPrivateKey instead for this key format)",
                ),
            );
        }
        let mut p8 = super::pkcs8::pkcs8::default();
        let (_, e) = asn1::Unmarshal(der.clone(), &mut p8);
        if e == errors::nil {
            return (
                rsa::PrivateKey::default(),
                errors::New(
                    "x509: failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)",
                ),
            );
        }
        return (rsa::PrivateKey::default(), err);
    }

    if priv_.Version > 1 {
        return (
            rsa::PrivateKey::default(),
            errors::New("x509: unsupported private key version"),
        );
    }

    if priv_.N.Sign() <= 0
        || priv_.D.Sign() <= 0
        || priv_.P.Sign() <= 0
        || priv_.Q.Sign() <= 0
        || (priv_.Dp != crate::nil && priv_.Dp.Sign() <= 0)
        || (priv_.Dq != crate::nil && priv_.Dq.Sign() <= 0)
        || (priv_.Qinv != crate::nil && priv_.Qinv.Sign() <= 0)
    {
        return (
            rsa::PrivateKey::default(),
            errors::New("x509: private key contains zero or negative value"),
        );
    }

    let mut key = rsa::PrivateKey::default();
    key.PublicKey = rsa::PublicKey {
        E: priv_.E,
        N: priv_.N.clone(),
    };

    key.D = priv_.D.clone();
    // Go: key.Primes = make([]*big.Int, 2+len(priv.AdditionalPrimes))
    let nprimes = 2 + priv_.AdditionalPrimes.Len();
    let mut primes: Vec<big::Int> = Vec::with_capacity(nprimes as usize);
    primes.push(priv_.P.clone());
    primes.push(priv_.Q.clone());
    key.Precomputed.Dp = priv_.Dp.clone();
    key.Precomputed.Dq = priv_.Dq.clone();
    key.Precomputed.Qinv = priv_.Qinv.clone();
    for (_i, a) in crate::range!(priv_.AdditionalPrimes) {
        if a.Prime.Sign() <= 0 {
            return (
                rsa::PrivateKey::default(),
                errors::New("x509: private key contains zero or negative prime"),
            );
        }
        // Go: key.Primes[i+2] = a.Prime
        //
        // We ignore the other two values because rsa will calculate them
        // as needed.
        primes.push(a.Prime.clone());
    }
    key.Primes = slice::__from_vec(primes);

    key.Precompute();
    let err = key.Validate();
    if err != errors::nil {
        // Go retries here without the CRT values when GODEBUG
        // x509rsacrt=0 is set. Not reachable — see the banner.
        return (rsa::PrivateKey::default(), err);
    }

    return (key, errors::nil);
}

// go: sdk 1.25.5 crypto/x509/pkcs1.go:129-159 MarshalPKCS1PrivateKey
/// Convert an RSA private key to PKCS #1, ASN.1 DER form.
///
/// This kind of key is commonly encoded in PEM blocks of type
/// "RSA PRIVATE KEY". For a more flexible key format which is not RSA
/// specific, use [`super::MarshalPKCS8PrivateKey`].
///
/// The key must have passed validation by calling
/// `rsa::PrivateKey::Validate` first. `MarshalPKCS1PrivateKey` calls
/// `rsa::PrivateKey::Precompute`, which may modify the key if not already
/// precomputed.
pub fn MarshalPKCS1PrivateKey(key: &mut rsa::PrivateKey) -> slice<byte> {
    key.Precompute();

    let mut version: int = 0;
    if key.Primes.Len() > 2 {
        version = 1;
    }

    let mut priv_ = pkcs1PrivateKey {
        Version: version,
        N: key.PublicKey.N.clone(),
        E: key.PublicKey.E,
        D: key.D.clone(),
        P: key.Primes[0i64].clone(),
        Q: key.Primes[1i64].clone(),
        Dp: key.Precomputed.Dp.clone(),
        Dq: key.Precomputed.Dq.clone(),
        Qinv: key.Precomputed.Qinv.clone(),
        AdditionalPrimes: slice::default(),
    };

    // Go: priv.AdditionalPrimes = make(…, len(key.Precomputed.CRTValues))
    let mut extra: Vec<pkcs1AdditionalRSAPrime> =
        Vec::with_capacity(key.Precomputed.CRTValues.Len() as usize);
    for (i, values) in crate::range!(key.Precomputed.CRTValues) {
        extra.push(pkcs1AdditionalRSAPrime {
            Prime: key.Primes[2 + i].clone(),
            Exp: values.Exp.clone(),
            Coeff: values.Coeff.clone(),
        });
    }
    priv_.AdditionalPrimes = slice::__from_vec(extra);

    let (b, _err) = asn1::Marshal(&priv_); // goishlint:ignore GOISH012 — Go writes `b, _ := asn1.Marshal(priv)`; the signature has no error to return.
    return b;
}

// go: sdk 1.25.5 crypto/x509/pkcs1.go:164-185 ParsePKCS1PublicKey
/// Parse an RSA public key in PKCS #1, ASN.1 DER form.
///
/// This kind of key is commonly encoded in PEM blocks of type
/// "RSA PUBLIC KEY".
pub fn ParsePKCS1PublicKey(der: slice<byte>) -> (rsa::PublicKey, error) {
    let mut pubk = pkcs1PublicKey::default();
    let (rest, err) = asn1::Unmarshal(der.clone(), &mut pubk);
    if err != errors::nil {
        let mut pki = super::x509::publicKeyInfo::default();
        let (_, e) = asn1::Unmarshal(der.clone(), &mut pki);
        if e == errors::nil {
            return (
                rsa::PublicKey::default(),
                errors::New(
                    "x509: failed to parse public key (use ParsePKIXPublicKey instead for this key format)",
                ),
            );
        }
        return (rsa::PublicKey::default(), err);
    }
    if rest.Len() > 0 {
        return (
            rsa::PublicKey::default(),
            asn1::SyntaxError {
                Msg: string::from_static("trailing data"),
            }
            .into(),
        );
    }

    if pubk.N.Sign() <= 0 || pubk.E <= 0 {
        return (
            rsa::PublicKey::default(),
            errors::New("x509: public key contains zero or negative value"),
        );
    }
    if pubk.E > (1 << 31) - 1 {
        return (
            rsa::PublicKey::default(),
            errors::New("x509: public key contains large public exponent"),
        );
    }

    return (
        rsa::PublicKey {
            E: pubk.E,
            N: pubk.N,
        },
        errors::nil,
    );
}

// go: sdk 1.25.5 crypto/x509/pkcs1.go:190-196 MarshalPKCS1PublicKey
/// Convert an RSA public key to PKCS #1, ASN.1 DER form.
///
/// This kind of key is commonly encoded in PEM blocks of type
/// "RSA PUBLIC KEY".
pub fn MarshalPKCS1PublicKey(key: &rsa::PublicKey) -> slice<byte> {
    let (derBytes, _err) = asn1::Marshal(&pkcs1PublicKey {
        N: key.N.clone(),
        E: key.E,
    }); // goishlint:ignore GOISH012 — Go writes `derBytes, _ := asn1.Marshal(…)`; the signature has no error to return.
    return derBytes;
}

// ─── reflect descriptors ──────────────────────────────────────────────
//
// go: none — goish-only, and a prerequisite rather than a port. The
// rationale is the one at the foot of crypto/x509/pkix/pkix.rs: the
// structs above exist only to be handed to `asn1.Marshal` /
// `asn1.Unmarshal`, both of which reach them through `reflect`, and the
// `#[goish::reflect]` macro cannot be used because it also demands JSON
// codecs on `big::Int`. The `asn1:"…"` tags live in the descriptor
// because that is where `parseFieldParameters` reads them from.

static PKCS1_PRIVATE_KEY_FIELDS: [reflect::StructField; 10] = [
    reflect::StructField {
        Name: "Version",
        Tag: reflect::StructTag::__new(""),
        Type: <int as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    reflect::StructField {
        Name: "N",
        Tag: reflect::StructTag::__new(""),
        Type: <big::Int as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    reflect::StructField {
        Name: "E",
        Tag: reflect::StructTag::__new(""),
        Type: <int as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    reflect::StructField {
        Name: "D",
        Tag: reflect::StructTag::__new(""),
        Type: <big::Int as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    reflect::StructField {
        Name: "P",
        Tag: reflect::StructTag::__new(""),
        Type: <big::Int as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    reflect::StructField {
        Name: "Q",
        Tag: reflect::StructTag::__new(""),
        Type: <big::Int as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    reflect::StructField {
        Name: "Dp",
        Tag: reflect::StructTag::__new("asn1:\"optional\""),
        Type: <big::Int as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    reflect::StructField {
        Name: "Dq",
        Tag: reflect::StructTag::__new("asn1:\"optional\""),
        Type: <big::Int as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    reflect::StructField {
        Name: "Qinv",
        Tag: reflect::StructTag::__new("asn1:\"optional\""),
        Type: <big::Int as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    reflect::StructField {
        Name: "AdditionalPrimes",
        Tag: reflect::StructTag::__new("asn1:\"optional,omitempty\""),
        Type: <slice<pkcs1AdditionalRSAPrime> as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];

impl reflect::Reflect for pkcs1PrivateKey {
    // go: none — goish-only: the reflect descriptor. See the banner above.
    fn __reflect_type() -> reflect::Type {
        return reflect::Type::__new(
            reflect::Kind::Struct,
            "pkcs1PrivateKey",
            &PKCS1_PRIVATE_KEY_FIELDS,
        );
    }

    // go: none — goish-only: the reflect descriptor. See the banner above.
    fn __reflect_value(&self) -> reflect::Value {
        return reflect::Value::Struct {
            ty: <pkcs1PrivateKey as reflect::Reflect>::__reflect_type(),
            fields: alloc::vec![
                reflect::Value::Int(self.Version),
                reflect::Reflect::__reflect_value(&self.N),
                reflect::Value::Int(self.E),
                reflect::Reflect::__reflect_value(&self.D),
                reflect::Reflect::__reflect_value(&self.P),
                reflect::Reflect::__reflect_value(&self.Q),
                reflect::Reflect::__reflect_value(&self.Dp),
                reflect::Reflect::__reflect_value(&self.Dq),
                reflect::Reflect::__reflect_value(&self.Qinv),
                reflect::Reflect::__reflect_value(&self.AdditionalPrimes),
            ],
        };
    }
}

impl reflect::FromReflectValue for pkcs1PrivateKey {
    // go: none — goish-only: the write half of the descriptor above.
    fn from_reflect_value(v: reflect::Value) -> (Self, error) {
        if v.Kind() != reflect::Kind::Struct {
            return (
                pkcs1PrivateKey::default(),
                errors::New("x509: expected pkcs1PrivateKey"),
            );
        }
        let mut out = pkcs1PrivateKey::default();
        out.Version = v.Field(0).Int();
        out.E = v.Field(2).Int();
        let bigs: [(int, usize); 7] = [(1, 0), (3, 1), (4, 2), (5, 3), (6, 4), (7, 5), (8, 6)];
        let mut vals: [big::Int; 7] = core::array::from_fn(|_| big::Int::new());
        for (idx, slot) in bigs.iter() {
            let (n, err) = <big::Int as reflect::FromReflectValue>::from_reflect_value(
                v.Field(*idx),
            );
            if err != errors::nil {
                return (pkcs1PrivateKey::default(), err);
            }
            vals[*slot] = n;
        }
        out.N = vals[0].clone();
        out.D = vals[1].clone();
        out.P = vals[2].clone();
        out.Q = vals[3].clone();
        out.Dp = vals[4].clone();
        out.Dq = vals[5].clone();
        out.Qinv = vals[6].clone();
        let (ap, err) =
            <slice<pkcs1AdditionalRSAPrime> as reflect::FromReflectValue>::from_reflect_value(
                v.Field(9),
            );
        if err != errors::nil {
            return (pkcs1PrivateKey::default(), err);
        }
        out.AdditionalPrimes = ap;
        return (out, errors::nil);
    }
}

static PKCS1_ADDITIONAL_PRIME_FIELDS: [reflect::StructField; 3] = [
    reflect::StructField {
        Name: "Prime",
        Tag: reflect::StructTag::__new(""),
        Type: <big::Int as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    reflect::StructField {
        Name: "Exp",
        Tag: reflect::StructTag::__new(""),
        Type: <big::Int as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    reflect::StructField {
        Name: "Coeff",
        Tag: reflect::StructTag::__new(""),
        Type: <big::Int as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];

impl reflect::Reflect for pkcs1AdditionalRSAPrime {
    // go: none — goish-only: the reflect descriptor. See the banner above.
    fn __reflect_type() -> reflect::Type {
        return reflect::Type::__new(
            reflect::Kind::Struct,
            "pkcs1AdditionalRSAPrime",
            &PKCS1_ADDITIONAL_PRIME_FIELDS,
        );
    }

    // go: none — goish-only: the reflect descriptor. See the banner above.
    fn __reflect_value(&self) -> reflect::Value {
        return reflect::Value::Struct {
            ty: <pkcs1AdditionalRSAPrime as reflect::Reflect>::__reflect_type(),
            fields: alloc::vec![
                reflect::Reflect::__reflect_value(&self.Prime),
                reflect::Reflect::__reflect_value(&self.Exp),
                reflect::Reflect::__reflect_value(&self.Coeff),
            ],
        };
    }
}

impl reflect::FromReflectValue for pkcs1AdditionalRSAPrime {
    // go: none — goish-only: the write half of the descriptor above.
    fn from_reflect_value(v: reflect::Value) -> (Self, error) {
        if v.Kind() != reflect::Kind::Struct {
            return (
                pkcs1AdditionalRSAPrime::default(),
                errors::New("x509: expected pkcs1AdditionalRSAPrime"),
            );
        }
        let (prime, err) =
            <big::Int as reflect::FromReflectValue>::from_reflect_value(v.Field(0));
        if err != errors::nil {
            return (pkcs1AdditionalRSAPrime::default(), err);
        }
        let (exp, err) = <big::Int as reflect::FromReflectValue>::from_reflect_value(v.Field(1));
        if err != errors::nil {
            return (pkcs1AdditionalRSAPrime::default(), err);
        }
        let (coeff, err) = <big::Int as reflect::FromReflectValue>::from_reflect_value(v.Field(2));
        if err != errors::nil {
            return (pkcs1AdditionalRSAPrime::default(), err);
        }
        return (
            pkcs1AdditionalRSAPrime {
                Prime: prime,
                Exp: exp,
                Coeff: coeff,
            },
            errors::nil,
        );
    }
}

static PKCS1_PUBLIC_KEY_FIELDS: [reflect::StructField; 2] = [
    reflect::StructField {
        Name: "N",
        Tag: reflect::StructTag::__new(""),
        Type: <big::Int as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    reflect::StructField {
        Name: "E",
        Tag: reflect::StructTag::__new(""),
        Type: <int as reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];

impl reflect::Reflect for pkcs1PublicKey {
    // go: none — goish-only: the reflect descriptor. See the banner above.
    fn __reflect_type() -> reflect::Type {
        return reflect::Type::__new(
            reflect::Kind::Struct,
            "pkcs1PublicKey",
            &PKCS1_PUBLIC_KEY_FIELDS,
        );
    }

    // go: none — goish-only: the reflect descriptor. See the banner above.
    fn __reflect_value(&self) -> reflect::Value {
        return reflect::Value::Struct {
            ty: <pkcs1PublicKey as reflect::Reflect>::__reflect_type(),
            fields: alloc::vec![
                reflect::Reflect::__reflect_value(&self.N),
                reflect::Value::Int(self.E),
            ],
        };
    }
}

impl reflect::FromReflectValue for pkcs1PublicKey {
    // go: none — goish-only: the write half of the descriptor above.
    fn from_reflect_value(v: reflect::Value) -> (Self, error) {
        if v.Kind() != reflect::Kind::Struct {
            return (
                pkcs1PublicKey::default(),
                errors::New("x509: expected pkcs1PublicKey"),
            );
        }
        let (n, err) = <big::Int as reflect::FromReflectValue>::from_reflect_value(v.Field(0));
        if err != errors::nil {
            return (pkcs1PublicKey::default(), err);
        }
        return (
            pkcs1PublicKey {
                N: n,
                E: v.Field(1).Int(),
            },
            errors::nil,
        );
    }
}
