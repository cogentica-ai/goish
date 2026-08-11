// go: file crypto/x509/pkix/pkix.go decls: FillFromRDNSequence, appendRDNs, ToRDNSequence, oidInAttributeTypeAndValue, HasExpired
//
// Shared, low-level structures for ASN.1 parsing and serialization of
// X.509 certificates, CRLs and OCSP.
//
// The whole package hangs on `encoding/asn1`, which is why it sat
// unported for four sessions; `asn1::Marshal` landed in 568f5fb and
// `port_deps crypto/x509/pkix` flipped to GO.
//
// Deviations from pkix[go] @ Go 1.25.5:
//
//   * Go's `RDNSequence` and `RelativeDistinguishedNameSET` are named
//     slice types. goish spells them as newtypes, not aliases, for the
//     reason `asn1::ObjectIdentifier` did: `RDNSequence` carries a
//     `String()` method, and `getUniversalType`'s `HasSuffix(name,
//     "SET")` branch keys on the name — an alias for
//     `slice<AttributeTypeAndValue>` would encode a
//     RelativeDistinguishedNameSET as a SEQUENCE rather than a SET.
//   * Go's package-level `oidCountry = []int{2, 5, 4, 6}` and friends
//     are `var`s holding heap slices. goish has no const slice, so each
//     is a function returning its ObjectIdentifier. Same values, same
//     names.
//   * `AttributeTypeAndValue.Value` is Go's `any`; goish holds
//     `goany::Any`, the runtime's `interface{}` carrier. The
//     `atv.Value.(string)` assertion in FillFromRDNSequence becomes
//     `As::<string>()`, which is the same comma-ok test.
//
// NOT ported, and specifically so — `RDNSequence.String` and
// `Name.String`. Both need `asn1::Marshal(tv.Value)`, and `tv.Value` is
// a `goany::Any`. goish has two type-erasure mechanisms that do not
// meet: `goany::AnyVal` gives downcast but no reflection, while
// `asn1::Marshal` needs `reflect::Reflect`. There is no way today to get
// a `reflect::Value` out of an `Any`, so the `oid=#<hex>` fallback for
// an unrecognised attribute OID cannot be written.
//
// It is deliberately absent rather than stubbed. Go falls through to
// `typeName = oidString` when Marshal fails, so a stub that always
// errors compiles and looks like it works, while printing `oid=value`
// where Go prints `oid=#hex` for every unrecognised OID — a silent
// divergence in user-visible output. The prerequisite is unifying
// `goany::Any` with `reflect::AnyReflect`; everything else in the file
// is here.
// goishlint:ignore GOISH018 String — see the note above; needs Any -> reflect::Value
// goishlint:ignore GOISH021 attributeTypeNames — the OID->short-name map is read
//   only by RDNSequence.String, which is not ported; it lands with it.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::encoding::asn1;
use crate::goany::Any;
use crate::goslice::slice;
use crate::gostring::string;
use crate::math::big::Int;
use crate::time;
use crate::types::{byte, int};

// Go: pkix.go:19-22
//   type AlgorithmIdentifier struct {
//       Algorithm  asn1.ObjectIdentifier
//       Parameters asn1.RawValue `asn1:"optional"`
//   }
/// The ASN.1 structure of the same name. See RFC 5280, section 4.1.1.2.
#[derive(Clone, Default, PartialEq)]
pub struct AlgorithmIdentifier {
    pub Algorithm: asn1::ObjectIdentifier,
    pub Parameters: asn1::RawValue,
}

// Go: pkix.go:24 — `type RDNSequence []RelativeDistinguishedNameSET`
/// A sequence of relative distinguished names. See the banner for why
/// this is a newtype rather than an alias.
#[derive(Clone, Default, PartialEq)]
pub struct RDNSequence(pub slice<RelativeDistinguishedNameSET>);

// Go: pkix.go:95 — `type RelativeDistinguishedNameSET []AttributeTypeAndValue`
#[derive(Clone, Default, PartialEq)]
pub struct RelativeDistinguishedNameSET(pub slice<AttributeTypeAndValue>);

// Go: pkix.go:99-102
/// Mirrors the ASN.1 structure of the same name in RFC 5280,
/// Section 4.1.2.4.
#[derive(Clone, Default, PartialEq)]
pub struct AttributeTypeAndValue {
    pub Type: asn1::ObjectIdentifier,
    pub Value: Any,
}

// Go: pkix.go:106-109
/// A set of ASN.1 sequences of [`AttributeTypeAndValue`] sequences from
/// RFC 2986 (PKCS #10).
#[derive(Clone, Default, PartialEq)]
pub struct AttributeTypeAndValueSET {
    pub Type: asn1::ObjectIdentifier,
    pub Value: slice<slice<AttributeTypeAndValue>>,
}

// Go: pkix.go:113-117
/// The ASN.1 structure of the same name. See RFC 5280, section 4.2.
#[derive(Clone, Default, PartialEq)]
pub struct Extension {
    pub Id: asn1::ObjectIdentifier,
    pub Critical: bool,
    pub Value: slice<byte>,
}

// Go: pkix.go:123-142
/// An X.509 distinguished name. This only includes the common elements
/// of a DN, and is only an approximation of the X.509 structure — if an
/// accurate representation is needed, `asn1::Unmarshal` the raw subject
/// or issuer as an [`RDNSequence`].
#[derive(Clone, Default, PartialEq)]
pub struct Name {
    pub Country: slice<string>,
    pub Organization: slice<string>,
    pub OrganizationalUnit: slice<string>,
    pub Locality: slice<string>,
    pub Province: slice<string>,
    pub StreetAddress: slice<string>,
    pub PostalCode: slice<string>,
    pub SerialNumber: string,
    pub CommonName: string,
    /// All parsed attributes. When parsing distinguished names this can
    /// be used to extract non-standard attributes the package does not
    /// parse. Ignored when marshaling — see `ExtraNames`.
    pub Names: slice<AttributeTypeAndValue>,
    /// Attributes to be copied, raw, into any marshaled distinguished
    /// name. Values override any attributes with the same OID. Not
    /// populated when parsing — see `Names`.
    pub ExtraNames: slice<AttributeTypeAndValue>,
}

impl Name {
    // go: sdk 1.25.5 crypto/x509/pkix/pkix.go:144-182 Name.FillFromRDNSequence
    /// Populate `self` from the provided [`RDNSequence`]. Multi-entry
    /// RDNs are flattened, all entries are added to the relevant fields,
    /// and the grouping is not preserved.
    pub fn FillFromRDNSequence(&mut self, rdns: &RDNSequence) {
        for (_, rdn) in crate::range!(rdns.0.clone()) {
            if rdn.0.Len() == 0 {
                continue;
            }

            for (_, atv) in crate::range!(rdn.0.clone()) {
                self.Names = crate::append!(self.Names.clone(), atv.clone());
                // Go: value, ok := atv.Value.(string); if !ok { continue }
                let value = match atv.Value.As::<string>() {
                    Some(v) => v.clone(),
                    None => {
                        continue;
                    }
                };

                let t = &atv.Type;
                if t.Len() == 4 && t[0] == 2 && t[1] == 5 && t[2] == 4 {
                    match t[3] {
                        3 => {
                            self.CommonName = value;
                        }
                        5 => {
                            self.SerialNumber = value;
                        }
                        6 => {
                            self.Country = crate::append!(self.Country.clone(), value);
                        }
                        7 => {
                            self.Locality = crate::append!(self.Locality.clone(), value);
                        }
                        8 => {
                            self.Province = crate::append!(self.Province.clone(), value);
                        }
                        9 => {
                            self.StreetAddress = crate::append!(self.StreetAddress.clone(), value);
                        }
                        10 => {
                            self.Organization = crate::append!(self.Organization.clone(), value);
                        }
                        11 => {
                            self.OrganizationalUnit =
                                crate::append!(self.OrganizationalUnit.clone(), value);
                        }
                        17 => {
                            self.PostalCode = crate::append!(self.PostalCode.clone(), value);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // go: sdk 1.25.5 crypto/x509/pkix/pkix.go:200-216 Name.appendRDNs
    /// Append a relativeDistinguishedNameSET to `in_` and return the new
    /// value. The set contains an attributeTypeAndValue for each of the
    /// given values. See RFC 5280, A.1.
    fn appendRDNs(
        &self,
        in_: RDNSequence,
        values: slice<string>,
        oid: asn1::ObjectIdentifier,
    ) -> RDNSequence {
        if values.Len() == 0 || oidInAttributeTypeAndValue(&oid, &self.ExtraNames) {
            return in_;
        }

        let mut s: Vec<AttributeTypeAndValue> = Vec::new();
        for (_, value) in crate::range!(values.clone()) {
            s.push(AttributeTypeAndValue {
                Type: oid.clone(),
                Value: Any::new(value.clone()),
            });
        }

        return RDNSequence(crate::append!(
            in_.0,
            RelativeDistinguishedNameSET(slice::__from_vec(s))
        ));
    }

    // go: sdk 1.25.5 crypto/x509/pkix/pkix.go:226-247 Name.ToRDNSequence
    /// Convert `self` into a single [`RDNSequence`]. Country,
    /// Organization, OrganizationalUnit, Locality, Province,
    /// StreetAddress and PostalCode are encoded as multi-value RDNs;
    /// each `ExtraNames` entry is encoded as an individual RDN.
    pub fn ToRDNSequence(&self) -> RDNSequence {
        let mut ret = RDNSequence::default();
        ret = self.appendRDNs(ret, self.Country.clone(), oidCountry());
        ret = self.appendRDNs(ret, self.Province.clone(), oidProvince());
        ret = self.appendRDNs(ret, self.Locality.clone(), oidLocality());
        ret = self.appendRDNs(ret, self.StreetAddress.clone(), oidStreetAddress());
        ret = self.appendRDNs(ret, self.PostalCode.clone(), oidPostalCode());
        ret = self.appendRDNs(ret, self.Organization.clone(), oidOrganization());
        ret = self.appendRDNs(ret, self.OrganizationalUnit.clone(), oidOrganizationalUnit());
        if self.CommonName.Len() > 0 {
            let one = slice::__from_vec(alloc::vec![self.CommonName.clone()]);
            ret = self.appendRDNs(ret, one, oidCommonName());
        }
        if self.SerialNumber.Len() > 0 {
            let one = slice::__from_vec(alloc::vec![self.SerialNumber.clone()]);
            ret = self.appendRDNs(ret, one, oidSerialNumber());
        }
        for (_, atv) in crate::range!(self.ExtraNames.clone()) {
            let one = slice::__from_vec(alloc::vec![atv.clone()]);
            ret = RDNSequence(crate::append!(ret.0, RelativeDistinguishedNameSET(one)));
        }

        return ret;
    }
}

// ─── the nine attribute-type OIDs (pkix.go:184-194) ──────────────────
//
// goish has no const slice, so each of Go's `var`s is a function.

// go: none — goish idiom: Go's `oidCountry = []int{2, 5, 4, 6}`.
fn oidCountry() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 4, 6]);
}
// go: none — goish idiom: see oidCountry.
fn oidOrganization() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 4, 10]);
}
// go: none — goish idiom: see oidCountry.
fn oidOrganizationalUnit() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 4, 11]);
}
// go: none — goish idiom: see oidCountry.
fn oidCommonName() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 4, 3]);
}
// go: none — goish idiom: see oidCountry.
fn oidSerialNumber() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 4, 5]);
}
// go: none — goish idiom: see oidCountry.
fn oidLocality() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 4, 7]);
}
// go: none — goish idiom: see oidCountry.
fn oidProvince() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 4, 8]);
}
// go: none — goish idiom: see oidCountry.
fn oidStreetAddress() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 4, 9]);
}
// go: none — goish idiom: see oidCountry.
fn oidPostalCode() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 4, 17]);
}

// go: none — goish idiom: build an ObjectIdentifier from a literal.
fn oid(parts: &[int]) -> asn1::ObjectIdentifier {
    return asn1::ObjectIdentifier::New(slice::__from_vec(parts.to_vec()));
}

// go: sdk 1.25.5 crypto/x509/pkix/pkix.go:274-282 oidInAttributeTypeAndValue
/// Report whether a type with the given OID exists in `atv`.
fn oidInAttributeTypeAndValue(
    oid: &asn1::ObjectIdentifier,
    atv: &slice<AttributeTypeAndValue>,
) -> bool {
    for (_, a) in crate::range!(atv.clone()) {
        if a.Type.Equal(oid) {
            return true;
        }
    }
    return false;
}

// Go: pkix.go:288-293
/// The ASN.1 structure of the same name. See RFC 5280, section 5.1. Use
/// `Certificate::CheckCRLSignature` to verify the signature.
///
/// Deprecated: `x509::RevocationList` should be used instead.
// No `PartialEq`: `time::Time` has none and `big::Int`'s is against
// a different RHS. Go compares neither of these structs with `==`.
#[derive(Clone, Default)]
pub struct CertificateList {
    pub TBSCertList: TBSCertificateList,
    pub SignatureAlgorithm: AlgorithmIdentifier,
    pub SignatureValue: asn1::BitString,
}

impl CertificateList {
    // go: sdk 1.25.5 crypto/x509/pkix/pkix.go:295-297 CertificateList.HasExpired
    /// Report whether `self` should have been updated by now.
    pub fn HasExpired(&self, now: time::Time) -> bool {
        return !now.Before(self.TBSCertList.NextUpdate.clone());
    }
}

// Go: pkix.go:303-312
/// The ASN.1 structure of the same name. See RFC 5280, section 5.1.
///
/// Deprecated: `x509::RevocationList` should be used instead.
// No `PartialEq`: `time::Time` has none and `big::Int`'s is against
// a different RHS. Go compares neither of these structs with `==`.
#[derive(Clone, Default)]
pub struct TBSCertificateList {
    pub Raw: asn1::RawContent,
    pub Version: int,
    pub Signature: AlgorithmIdentifier,
    pub Issuer: RDNSequence,
    pub ThisUpdate: time::Time,
    pub NextUpdate: time::Time,
    pub RevokedCertificates: slice<RevokedCertificate>,
    pub Extensions: slice<Extension>,
}

// Go: pkix.go:316-320
/// The ASN.1 structure of the same name. See RFC 5280, section 5.1.
// No `PartialEq`: `time::Time` has none and `big::Int`'s is against
// a different RHS. Go compares neither of these structs with `==`.
#[derive(Clone, Default)]
pub struct RevokedCertificate {
    pub SerialNumber: Int,
    pub RevocationTime: time::Time,
    pub Extensions: slice<Extension>,
}
