// go: file crypto/x509/pkix/pkix.go decls: String, FillFromRDNSequence, appendRDNs, ToRDNSequence, oidInAttributeTypeAndValue, HasExpired
//
// Shared, low-level structures for ASN.1 parsing and serialization of
// X.509 certificates, CRLs and OCSP.
//
// The whole package hangs on `encoding/asn1`, which is why it sat
// unported for four sessions; `asn1::Marshal` landed in 568f5fb and
// `port_deps crypto/x509/pkix` flipped to GO.
//
// `RDNSequence.String` and `Name.String` then sat out one more session
// on top of that, for a second reason: they call
// `asn1.Marshal(tv.Value)` where `tv.Value` is Go's `any`, and goish's
// two type-erasure mechanisms did not meet — `goany::Any` gave
// downcast but no reflection, `asn1::Marshal` wanted `reflect::Reflect`,
// and nothing turned one into the other. They are here now because
// `reflect::ValueOfAny` + `asn1::MarshalAny` close that gap.
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
//     names. `attributeTypeNames`, Go's `map[string]string` var, is a
//     function for the same reason.
//   * `AttributeTypeAndValue.Value` is Go's `any`; goish holds
//     `goany::Any`, the runtime's `interface{}` carrier. The
//     `atv.Value.(string)` assertion in FillFromRDNSequence becomes
//     `As::<string>()`, which is the same comma-ok test, and
//     `asn1.Marshal(tv.Value)` becomes `asn1::MarshalAny(&tv.Value)`.
//   * `Name.String` branches on `n.ExtraNames == nil`. goish's
//     `slice<T>` has no nil-versus-empty distinction (goslice.rs:167 —
//     `s == nil` is `len(s) == 0`), so a Name carrying a non-nil but
//     EMPTY ExtraNames takes the Names branch here and does not in Go.
//     Verified against the reference: Go prints `"CN=cn"` for that
//     shape, goish prints the Names entries too. Every other shape
//     agrees. Closing it needs a nil-vs-empty slice header runtime
//     wide, not a change here.
//   * Go's escaping switch is over rune literals (`case ',', '+', …`).
//     `rune` is an integer type in goish and AGENTS.md §2a rules out
//     `',' as rune`, so the RFC 2253 metacharacters are matched at
//     their code points, each spelled beside its arm.
//   * `RDNSequence.String`'s Marshal-failed fallback prints
//     `fmt.Sprint(tv.Value)`. goish's `fmt::Sprint` has no reflective
//     struct printer and renders a type it does not recognise as
//     `<unsupported %T>` where Go prints e.g. `{map[]}`. The branch,
//     the escaping and the `oid=` prefix are identical; only fmt's
//     rendering of an unprintable value differs, and that belongs to
//     fmt, not here.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::encoding::asn1;
use crate::encoding::hex;
use crate::fmt;
use crate::goany::Any;
use crate::gomap::map;
use crate::goslice::slice;
use crate::gostring::string;
use crate::math::big::Int;
use crate::time;
use crate::types::{byte, int, rune};

// Go: pkix.go:19-22
//   type AlgorithmIdentifier struct {
//       Algorithm  asn1.ObjectIdentifier
//       Parameters asn1.RawValue `asn1:"optional"`
//   }
/// The ASN.1 structure of the same name. See RFC 5280, section 4.1.1.2.
#[goish::reflect(reflect_only)]
#[derive(Clone, Default, PartialEq)]
pub struct AlgorithmIdentifier {
    pub Algorithm: asn1::ObjectIdentifier,
    #[tag(r#"asn1:"optional""#)]
    pub Parameters: asn1::RawValue,
}

// Go: pkix.go:24 — `type RDNSequence []RelativeDistinguishedNameSET`
/// A sequence of relative distinguished names. See the banner for why
/// this is a newtype rather than an alias.
#[derive(Clone, Default, PartialEq)]
pub struct RDNSequence(pub slice<RelativeDistinguishedNameSET>);

// go: none — goish idiom: same delegation as
// `RelativeDistinguishedNameSET` below. `type RDNSequence
// []RelativeDistinguishedNameSET` is a Go slice type; the newtype is
// goish's spelling of it, and this makes `reflect` see through it.
impl crate::reflect::Reflect for RDNSequence {
    // go: none — goish idiom (reflect descriptor for a named slice type)
    fn __reflect_type() -> crate::reflect::Type {
        return <slice<RelativeDistinguishedNameSET> as crate::reflect::Reflect>::__reflect_type();
    }
    // go: none — goish idiom (reflect descriptor for a named slice type)
    fn __reflect_value(&self) -> crate::reflect::Value {
        return <slice<RelativeDistinguishedNameSET> as crate::reflect::Reflect>::__reflect_value(
            &self.0,
        );
    }
}

// go: none — goish idiom: Go's `attributeTypeNames` is a package-level
// `map[string]string` var (pkix.go:26-36). goish has no const map, so —
// exactly as the nine `oid*` vars above — it is a function returning
// the same nine entries.
/// Dotted OID -> RFC 2253 short name, for the nine attribute types
/// [`RDNSequence::String`] knows how to abbreviate. An OID absent from
/// this table is printed as `oid=#<DER hex>` instead.
fn attributeTypeNames() -> map<string, string> {
    let mut m = crate::make!(map[string]string);
    m.Set("2.5.4.6", "C");
    m.Set("2.5.4.10", "O");
    m.Set("2.5.4.11", "OU");
    m.Set("2.5.4.3", "CN");
    m.Set("2.5.4.5", "SERIALNUMBER");
    m.Set("2.5.4.7", "L");
    m.Set("2.5.4.8", "ST");
    m.Set("2.5.4.9", "STREET");
    m.Set("2.5.4.17", "POSTALCODE");
    return m;
}

impl RDNSequence {
    // go: sdk 1.25.5 crypto/x509/pkix/pkix.go:40-93 RDNSequence.String
    /// A string representation of the sequence, roughly following the
    /// RFC 2253 Distinguished Names syntax.
    ///
    /// RDNs are emitted in reverse order joined by `,`; the entries
    /// within one RDN keep their order and are joined by `+`. An
    /// attribute whose OID has no short name in [`attributeTypeNames`]
    /// is printed as `oid=#<hex of its DER>`; only if that DER cannot
    /// be produced does it fall back to `oid=<escaped value>`.
    pub fn String(&self) -> string {
        let mut s = string::from_static("");
        let mut i: int = 0;
        while i < self.0.Len() {
            let rdn = self.0[self.0.Len() - 1 - i].clone();
            if i > 0 {
                s += ",";
            }
            for (j, tv) in crate::range!(rdn.0.clone()) {
                if j > 0 {
                    s += "+";
                }

                let oidString = tv.Type.String();
                let (mut typeName, ok) = attributeTypeNames().Get(oidString.clone());
                if !ok {
                    // Go: derBytes, err := asn1.Marshal(tv.Value).
                    // `tv.Value` is the erased carrier, so this is
                    // `MarshalAny` — see the note in asn1/marshal.rs
                    // about why goish needs the second door.
                    let (derBytes, err) = asn1::MarshalAny(&tv.Value);
                    if err == crate::errors::nil {
                        s += oidString.clone();
                        s += "=#";
                        s += hex::EncodeToString(&derBytes);
                        continue; // No value escaping necessary.
                    }

                    typeName = oidString.clone();
                }

                // Go: fmt.Sprint(tv.Value). `tv.Value` is already an
                // `Any`, so it becomes the one-element argument slice
                // directly — `any_args!` would wrap the carrier in a
                // second `Any` and print `<any>`.
                let valueString = fmt::Sprint(slice::__from_vec(alloc::vec![tv.Value.clone()]));
                let mut escaped: slice<rune> = crate::make!([]rune, 0, valueString.Len());

                for (k, c) in crate::range!(valueString) {
                    let mut escape = false;

                    match c {
                        0x2C            // ','
                        | 0x2B          // '+'
                        | 0x22          // '"'
                        | 0x5C          // '\\'
                        | 0x3C          // '<'
                        | 0x3E          // '>'
                        | 0x3B          // ';'
                        => {
                            escape = true;
                        }

                        // ' ' — leading or trailing. `k` is a BYTE
                        // offset and `Len()` a BYTE length, as in Go,
                        // so a space after a multi-byte rune is still
                        // caught by the `len-1` test.
                        0x20 => {
                            escape = k == 0 || k == valueString.Len() - 1;
                        }

                        // '#' — leading only.
                        0x23 => {
                            escape = k == 0;
                        }

                        _ => {}
                    }

                    if escape {
                        escaped = crate::append!(escaped, backslash, c);
                    } else {
                        escaped = crate::append!(escaped, c);
                    }
                }

                s += typeName;
                s += "=";
                s += crate::string(escaped);
            }
            i += 1;
        }

        return s;
    }
}

// go: none — goish idiom: Go writes the escape as the rune literal
// `'\\'` inside `append(escaped, '\\', c)`; see the banner for why
// goish names the code point instead.
const backslash: rune = 0x5C;

// Go: pkix.go:95 — `type RelativeDistinguishedNameSET []AttributeTypeAndValue`
#[derive(Clone, Default, PartialEq)]
pub struct RelativeDistinguishedNameSET(pub slice<AttributeTypeAndValue>);

// go: none — goish idiom: Go's `RelativeDistinguishedNameSET` IS a slice
// type, so `reflect.ValueOf` of one reports `reflect.Slice` and
// `asn1.Marshal` walks its elements. goish spells the same Go type as a
// newtype (see the banner), and `#[goish::reflect(reflect_only)]` only
// parses named-field structs, so the delegation to the inner `slice<T>`
// is written out.
//
// The descriptor's **name** is load-bearing, not cosmetic:
// `asn1::getUniversalType` picks `TagSet` over `TagSequence` via
// `strings.HasSuffix(t.Name(), "SET")` (common.rs:204) — which is the
// very reason the banner gives for these being newtypes and not
// aliases. A bare `Value::Slice` reports an empty name from `Type()`
// (reflect/mod.rs:784) and would encode this SET as `0x30` where Go
// writes `0x31`, so the value is wrapped in `Value::Named`, the variant
// that exists to carry exactly this.
impl crate::reflect::Reflect for RelativeDistinguishedNameSET {
    // go: none — goish idiom (reflect descriptor for a named slice type)
    fn __reflect_type() -> crate::reflect::Type {
        return crate::reflect::Type::__new(
            crate::reflect::Kind::Slice,
            "RelativeDistinguishedNameSET",
            &[],
        )
        .__with_elem(<AttributeTypeAndValue as crate::reflect::Reflect>::__reflect_type);
    }
    // go: none — goish idiom (reflect descriptor for a named slice type)
    fn __reflect_value(&self) -> crate::reflect::Value {
        return crate::reflect::Value::Named {
            ty: <Self as crate::reflect::Reflect>::__reflect_type(),
            inner: alloc::boxed::Box::new(
                <slice<AttributeTypeAndValue> as crate::reflect::Reflect>::__reflect_value(&self.0),
            ),
        };
    }
}

// Go: pkix.go:99-102
/// Mirrors the ASN.1 structure of the same name in RFC 5280,
/// Section 4.1.2.4.
#[goish::reflect(reflect_only)]
#[derive(Clone, Default, PartialEq)]
pub struct AttributeTypeAndValue {
    pub Type: asn1::ObjectIdentifier,
    pub Value: Any,
}

// Go: pkix.go:106-109
/// A set of ASN.1 sequences of [`AttributeTypeAndValue`] sequences from
/// RFC 2986 (PKCS #10).
#[goish::reflect(reflect_only)]
#[derive(Clone, Default, PartialEq)]
pub struct AttributeTypeAndValueSET {
    pub Type: asn1::ObjectIdentifier,
    #[tag(r#"asn1:"set""#)]
    pub Value: slice<slice<AttributeTypeAndValue>>,
}

// Go: pkix.go:113-117
/// The ASN.1 structure of the same name. See RFC 5280, section 4.2.
#[goish::reflect(reflect_only)]
#[derive(Clone, Default, PartialEq)]
pub struct Extension {
    pub Id: asn1::ObjectIdentifier,
    #[tag(r#"asn1:"optional""#)]
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
        ret = self.appendRDNs(
            ret,
            self.OrganizationalUnit.clone(),
            oidOrganizationalUnit(),
        );
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

    // go: sdk 1.25.5 crypto/x509/pkix/pkix.go:249-270 Name.String
    /// The string form of `self`, roughly following the RFC 2253
    /// Distinguished Names syntax.
    ///
    /// When there are no `ExtraNames`, the parsed values in `Names` are
    /// surfaced instead — the ones that did not land in a named field.
    /// They go at the *front* of the sequence so they come out at the
    /// end of the string (Go issue 39924).
    pub fn String(&self) -> string {
        let mut rdns = RDNSequence::default();
        // If there are no ExtraNames, surface the parsed value (all
        // entries in Names) instead.
        if self.ExtraNames == crate::nil {
            for (_, atv) in crate::range!(self.Names.clone()) {
                let t = &atv.Type;
                if t.Len() == 4 && t[0] == 2 && t[1] == 5 && t[2] == 4 {
                    match t[3] {
                        // These attributes were already parsed into
                        // named fields.
                        3 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 17 => {
                            continue;
                        }
                        _ => {}
                    }
                }
                // Place non-standard parsed values at the beginning of
                // the sequence so they will be at the end of the
                // string. See Issue 39924.
                let one = slice::__from_vec(alloc::vec![atv.clone()]);
                rdns = RDNSequence(crate::append!(rdns.0, RelativeDistinguishedNameSET(one)));
            }
        }
        rdns = RDNSequence(crate::append!(rdns.0, self.ToRDNSequence().0...));
        return rdns.String();
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
#[goish::reflect(reflect_only)]
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
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
pub struct TBSCertificateList {
    pub Raw: asn1::RawContent,
    #[tag(r#"asn1:"optional,default:0""#)]
    pub Version: int,
    pub Signature: AlgorithmIdentifier,
    pub Issuer: RDNSequence,
    pub ThisUpdate: time::Time,
    #[tag(r#"asn1:"optional""#)]
    pub NextUpdate: time::Time,
    #[tag(r#"asn1:"optional""#)]
    pub RevokedCertificates: slice<RevokedCertificate>,
    #[tag(r#"asn1:"tag:0,optional,explicit""#)]
    pub Extensions: slice<Extension>,
}

// Go: pkix.go:316-320
/// The ASN.1 structure of the same name. See RFC 5280, section 5.1.
// No `PartialEq`: `time::Time` has none and `big::Int`'s is against
// a different RHS. Go compares neither of these structs with `==`.
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
pub struct RevokedCertificate {
    pub SerialNumber: Int,
    pub RevocationTime: time::Time,
    #[tag(r#"asn1:"optional""#)]
    pub Extensions: slice<Extension>,
}

// ─── reflect descriptors ──────────────────────────────────────────────
//
// go: none — goish-only, and a prerequisite rather than a port.
//
// `asn1.Marshal` takes a `&impl reflect::Reflect` and `asn1.Unmarshal` a
// `&mut impl Reflect + FromReflectValue`, because goish has no universal
// runtime reflection (the deviation is stated in full at the head of
// encoding/asn1/marshal.rs and asn1.rs). Every struct handed to either
// therefore needs a descriptor.
//
// The **read** half is `#[goish::reflect(reflect_only)]`, on each struct
// above, carrying Go's own `asn1:"…"` tag in a `#[tag(...)]` attribute —
// which is where `parseFieldParameters` reads it from
// (`field.Tag.Get("asn1")` in asn1's `parseField` and `makeBody`).
// `reflect_only` exists precisely for this shape: the attribute's default
// expansion also emits `json::FromValue`, `json::v2::MarshalerTo` and
// `json::v2::UnmarshalerFrom`, which would demand JSON codecs on
// `asn1::ObjectIdentifier` and `asn1::RawValue` — types that exist to
// carry DER and have no JSON meaning.
//
// The **write** half — `FromReflectValue`, which `reflect_only` does not
// emit and which only an `Unmarshal` target needs — is hand-written, and
// only for the one struct that is one.
//
// `RDNSequence` and `RelativeDistinguishedNameSET` are the exception in
// both directions: they are named *slice* types, which the attribute
// (named-field structs only) cannot parse, so their `Reflect` impls are
// written out beside their declarations.

impl crate::reflect::FromReflectValue for AlgorithmIdentifier {
    // go: none — goish-only: the write half of the descriptor above.
    fn from_reflect_value(v: crate::reflect::Value) -> (Self, crate::error) {
        if v.Kind() != crate::reflect::Kind::Struct {
            return (
                AlgorithmIdentifier::default(),
                crate::errors::New("pkix: expected AlgorithmIdentifier"),
            );
        }
        let (algorithm, err) =
            <asn1::ObjectIdentifier as crate::reflect::FromReflectValue>::from_reflect_value(
                v.Field(0),
            );
        if err != crate::errors::nil {
            return (AlgorithmIdentifier::default(), err);
        }
        let (parameters, err) =
            <asn1::RawValue as crate::reflect::FromReflectValue>::from_reflect_value(v.Field(1));
        if err != crate::errors::nil {
            return (AlgorithmIdentifier::default(), err);
        }
        return (
            AlgorithmIdentifier {
                Algorithm: algorithm,
                Parameters: parameters,
            },
            crate::errors::nil,
        );
    }
}

// go: none — goish-only: the remaining write halves. `reflect_only` emits
// the read half; `asn1::Unmarshal` needs this direction too, and it is
// pure field-by-field plumbing, so one macro carries all of it rather
// than seven hand-copied bodies that could each drift a field.
macro_rules! __pkix_from_reflect {
    ($ty:ident { $($idx:literal => $field:ident : $fty:ty),+ $(,)? }) => {
        impl crate::reflect::FromReflectValue for $ty {
            fn from_reflect_value(v: crate::reflect::Value) -> (Self, crate::error) {
                if v.Kind() != crate::reflect::Kind::Struct {
                    return (
                        <$ty>::default(),
                        crate::errors::New(concat!("pkix: expected ", stringify!($ty))),
                    );
                }
                let mut out = <$ty>::default();
                $(
                    let (f, err) =
                        <$fty as crate::reflect::FromReflectValue>::from_reflect_value(v.Field($idx));
                    if err != crate::errors::nil {
                        return (<$ty>::default(), err);
                    }
                    out.$field = f;
                )+
                return (out, crate::errors::nil);
            }
        }
    };
}

__pkix_from_reflect!(AttributeTypeAndValue {
    0 => Type: asn1::ObjectIdentifier,
    1 => Value: Any,
});

__pkix_from_reflect!(AttributeTypeAndValueSET {
    0 => Type: asn1::ObjectIdentifier,
    1 => Value: slice<slice<AttributeTypeAndValue>>,
});

__pkix_from_reflect!(Extension {
    0 => Id: asn1::ObjectIdentifier,
    1 => Critical: bool,
    2 => Value: slice<byte>,
});

__pkix_from_reflect!(CertificateList {
    0 => TBSCertList: TBSCertificateList,
    1 => SignatureAlgorithm: AlgorithmIdentifier,
    2 => SignatureValue: asn1::BitString,
});

__pkix_from_reflect!(TBSCertificateList {
    0 => Raw: asn1::RawContent,
    1 => Version: int,
    2 => Signature: AlgorithmIdentifier,
    3 => Issuer: RDNSequence,
    4 => ThisUpdate: time::Time,
    5 => NextUpdate: time::Time,
    6 => RevokedCertificates: slice<RevokedCertificate>,
    7 => Extensions: slice<Extension>,
});

__pkix_from_reflect!(RevokedCertificate {
    0 => SerialNumber: Int,
    1 => RevocationTime: time::Time,
    2 => Extensions: slice<Extension>,
});

// The two named-slice types: `reflect_only` cannot parse them (it takes
// named-field structs), so their read halves are written out beside
// their declarations and their write halves are here.
// A named slice round-trips as `Value::Named { ty, inner: Slice }` — the
// wrapper is what keeps `getUniversalType` able to see the name (it
// picks SET vs SEQUENCE off `HasSuffix(name, "SET")`). The generic
// `slice<T>` write half only knows `Value::Slice`, so unwrap first.

// go: none — goish-only: Go's reflect keeps the named type on the same
// Value; goish spells it as a wrapper, so it needs unwrapping.
fn __unwrap_named(v: crate::reflect::Value) -> crate::reflect::Value {
    return match v {
        crate::reflect::Value::Named { inner, .. } => *inner,
        other => other,
    };
}

impl crate::reflect::FromReflectValue for RelativeDistinguishedNameSET {
    // go: none — goish-only: see the banner above.
    fn from_reflect_value(v: crate::reflect::Value) -> (Self, crate::error) {
        let (inner, err) =
            <slice<AttributeTypeAndValue> as crate::reflect::FromReflectValue>::from_reflect_value(
                __unwrap_named(v),
            );
        return (RelativeDistinguishedNameSET(inner), err);
    }
}

impl crate::reflect::FromReflectValue for RDNSequence {
    // go: none — goish-only: see the banner above.
    fn from_reflect_value(v: crate::reflect::Value) -> (Self, crate::error) {
        let (inner, err) =
            <slice<RelativeDistinguishedNameSET> as crate::reflect::FromReflectValue>::from_reflect_value(
                __unwrap_named(v),
            );
        return (RDNSequence(inner), err);
    }
}

// go: none — goish idiom: Go's `fmt` finds `String()` by structural
// assertion, so `%%v` and `%%s` on a value whose METHOD SET includes it
// print through it. goish's printer dispatches on `Format`, which a
// type reaches through `Stringer`, and these did not implement it —
// so `fmt.Printf("%%v", x)`, entirely ordinary Go, did not compile.
//
// Only VALUE-receiver String methods are bridged. Go puts a
// pointer-receiver String in the POINTER's method set only, so
// printing the value prints the struct instead; goish has no
// value/pointer distinction, and implementing Stringer for those types
// would print where Go does not. net.IPNet, url.URL, url.Userinfo,
// http.Cookie, mail.Address and regexp.Regexp are left alone for that
// reason.
impl crate::fmt::Stringer for RDNSequence {
    // go: none — goish idiom: see the note above.
    fn String(&self) -> crate::gostring::string {
        let v = self;
        return RDNSequence::String(v);
    }
}
