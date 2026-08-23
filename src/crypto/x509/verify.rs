// go: file crypto/x509/verify.go decls: CertificateInvalidError.Error, HostnameError.Error, UnknownAuthorityError.Error, SystemRootsError.Error, SystemRootsError.Unwrap, parseRFC2821Mailbox, domainToReverseLabels, matchEmailConstraint, matchURIConstraint, matchIPConstraint, matchDomainConstraint, checkNameConstraints, isValid, Verify, appendToFreshChain, alreadyInChain, buildChains, validHostnamePattern, validHostnameInput, validHostname, matchExactly, matchHostnames, toLowerCaseASCII, VerifyHostname, checkChainForKeyUsage, mustNewOIDFromInts, newPolicyGraphNode, newPolicyGraph, insert, parentsWithExpected, parentWithAnyPolicy, parents, leaves, leafWithPolicy, deleteLeaf, validPolicyNodes, prune, incrDepth, policiesValid
//
// Chain building, name-constraint checking, hostname matching and the
// RFC 5280 / RFC 9618 certificate-policy graph.
//
// Deviations from verify[go] @ Go 1.25.5:
//
//   * **`net/netip` is not in goish.** verify.go imports it in exactly
//     one place: `matchURIConstraint` calls `netip.ParseAddr(host)` to
//     reject a URI whose authority is an IP literal. goish uses
//     `net::ParseIP` for the same test. The two differ in two ways that
//     matter here, both narrowing:
//       - `netip.ParseAddr` accepts a zone suffix (`fe80::1%eth0`);
//         `net.ParseIP` does not. A zoned literal is therefore *not*
//         rejected by the goish port and falls through to the domain
//         match, which then fails to parse it as a domain.
//       - goish's `net::ParseIP` is IPv4-only (see its own doc), so an
//         IPv6 literal is not recognised by the `ParseIP` half. Go's
//         comment on that line says the check is `_either_` a parseable
//         IP `_or_` a `[`…`]`-enclosed string, and the bracket half —
//         which is the only spelling a URI authority may use for IPv6 —
//         is ported verbatim. So IPv6 URI authorities are still
//         rejected, by the second half of the same condition.
//     This is a real narrowing, not a rounding, and it is why the
//     `%!q`-free anchor below carries a GOISH017 waiver.
//   * `checkNameConstraints` is `func(..., parsedName any, match func(
//     parsedName, constraint any, excluded bool) (bool, error),
//     permitted, excluded any)` in Go, and reaches into the two `any`
//     slices with `reflect.ValueOf(x).Len()` / `.Index(i).Interface()`.
//     goish makes the same function generic over the parsed-name type
//     `P` and the constraint element type `C`, so `permitted` and
//     `excluded` are `slice<C>` and the reflection disappears. Parameter
//     count, order and meaning are unchanged.
//   * Go formats the offending constraint with `%q`. That is a quoted
//     string for the DNS / email / URI constraints (all `string`) and
//     `%!q(*net.IPNet=&{…})` for the IP ones. goish's
//     `constraintQuoted` trait yields `IPNet.String()` for that last
//     case rather than reproducing Go's malformed-verb output.
//   * **The policy graph is an arena.** Go's `policyGraphNode` links
//     `parents`/`children` with `map[*policyGraphNode]bool` — GC pointer
//     identity. goish stores the nodes in one `Vec<policyGraphNode>` on
//     the graph and links them with `map<int, bool>` of arena indices.
//     Every method that Go writes as `func (pg *policyGraph)` keeps its
//     name and its meaning; `newPolicyGraphNode` gains the graph as a
//     first parameter (it has to allocate into the arena) and returns an
//     index instead of a pointer.
//   * `parents()` returns `iter.Seq[*policyGraphNode]` in Go via
//     `maps.Values`. goish's `iter` package is a squatter (0/4 ported),
//     so this returns `slice<int>` — the same elements, materialised.
//     `maps.Clone` at verify.go:1642 is likewise a `.clone()`.
//   * `VerifyOptions.Roots` / `.Intermediates` are `*CertPool` in Go,
//     where nil means "use the system roots" (Roots) or "no
//     intermediates" (Intermediates) — a distinction an empty pool does
//     *not* carry. goish spells the nilable pointer as `Option<CertPool>`,
//     the same shape `rsa::VerifyPSS` already uses for Go's
//     `*rsa.PSSOptions`.
//   * `buildChains`'s `considerCandidate` is an anonymous closure in Go
//     that captures `chains`, `err`, `hintErr`, `hintCert` and
//     `sigChecks` by reference. Rust cannot both capture those mutably
//     and recurse through them, so it is a named private helper taking
//     the same state as `&mut` parameters. Same body, same order.
//   * `buildChains`'s `sigChecks *int` is lazily `new(int)`-allocated in
//     Go; goish threads a `&mut int` that starts at zero. Identical
//     counting.
//   * `potentialParent.constraint` does not exist: `cert_pool.rs` drops
//     the per-cert `constraint func([]*Certificate) error` closure (see
//     its banner), so `buildChains`'s `if candidate.constraint != nil`
//     branch has nothing to test and is absent.
//   * `Verify`'s `runtime.GOOS == "windows" || "darwin" || "ios"` arm is
//     dead code on goish, which is linux/amd64 only, and is not ported.
//     `Certificate.systemVerify` — the hook that arm calls — *is*
//     ported, in `root_unix.rs`, where its Go source lives; it is the
//     Unix no-op stub and nothing reaches it.
//   * Go's error structs satisfy `error` implicitly through their
//     `Error() string` method; goish needs an explicit
//     `impl errors::ErrorTrait`, which is written next to each one.
//   * `VerifyOptions`'s three policy-testing fields are unexported in Go
//     and `pub` here — a Go composite literal in another package omits an
//     unexported field, but Rust's `..Default::default()` needs every
//     field visible. See the comment on the fields.
//
// goishlint:ignore GOISH017 matchURIConstraint — netip.ParseAddr has no goish equivalent; see the banner.
// goishlint:ignore GOISH018 validPolicyNodes — ported as a policyGraph method, see below.
// goishlint:ignore GOISH020 newPolicyGraphNode — takes the arena-owning graph as a first parameter; see the banner.
// goishlint:ignore GOISH021 leafCertificate, intermediateCertificate, rootCertificate, maxChainSignatureChecks, errNotParsed, anyPolicyOID — ported, but as `pub(super) const` / a function (goish has no const slice, and `anyPolicyOID` is a heap OID).

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use super::cert_pool::{potentialParent, CertPool};
use super::oid::{OIDFromInts, OID};
use super::parser::{domainNameValid, forEachSAN};
use super::x509::{
    nameTypeDNS, nameTypeEmail, nameTypeIP, nameTypeURI, Certificate, ExtKeyUsage, ExtKeyUsageAny,
    ExtKeyUsageServerAuth, UnhandledCriticalExtension,
};
use crate::crypto::cryptobyte::String as CBString;
use crate::error;
use crate::errors;
use crate::gomap::map;
use crate::goslice::slice;
use crate::gostring::string;
use crate::int;
use crate::net;
use crate::net::url;
use crate::rune;
use crate::strings;
use crate::time;
use crate::types::byte;
use crate::unicode::utf8;

// Go: verify.go:25 — `type InvalidReason int`
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct InvalidReason(pub int);

// Go: verify.go:27-64 — the iota block.
/// Results when a certificate is signed by another which isn't marked as
/// a CA certificate.
pub const NotAuthorizedToSign: InvalidReason = InvalidReason(0);
/// Results when a certificate has expired, based on the time given in
/// the VerifyOptions.
pub const Expired: InvalidReason = InvalidReason(1);
/// Results when an intermediate or root certificate has a name
/// constraint which doesn't permit a DNS or other name (including IP
/// address) in the leaf certificate.
pub const CANotAuthorizedForThisName: InvalidReason = InvalidReason(2);
/// Results when a path length constraint is violated.
pub const TooManyIntermediates: InvalidReason = InvalidReason(3);
/// Results when the certificate's key usage indicates that it may only
/// be used for a different purpose.
pub const IncompatibleUsage: InvalidReason = InvalidReason(4);
/// Results when the subject name of a parent certificate does not match
/// the issuer name in the child.
pub const NameMismatch: InvalidReason = InvalidReason(5);
/// A legacy error and is no longer returned.
pub const NameConstraintsWithoutSANs: InvalidReason = InvalidReason(6);
/// Results when a CA certificate contains permitted name constraints,
/// but leaf certificate contains a name of an unsupported or
/// unconstrained type.
pub const UnconstrainedName: InvalidReason = InvalidReason(7);
/// Results when the number of comparison operations needed to check a
/// certificate exceeds the limit set by
/// `VerifyOptions.MaxConstraintComparisions`.
pub const TooManyConstraints: InvalidReason = InvalidReason(8);
/// Results when an intermediate or root certificate does not permit a
/// requested extended key usage.
pub const CANotAuthorizedForExtKeyUsage: InvalidReason = InvalidReason(9);
/// Results when there are no valid chains to return.
pub const NoValidChains: InvalidReason = InvalidReason(10);

// Go: verify.go:66-72
/// Results when an odd error occurs. Users of this library probably want
/// to handle all these errors uniformly.
#[derive(Clone, Default)]
pub struct CertificateInvalidError {
    pub Cert: Certificate,
    pub Reason: InvalidReason,
    pub Detail: string,
}

impl CertificateInvalidError {
    // go: sdk 1.25.5 crypto/x509/verify.go:74-102 CertificateInvalidError.Error
    pub fn Error(&self) -> string {
        if self.Reason == NotAuthorizedToSign {
            return string::from("x509: certificate is not authorized to sign other certificates");
        } else if self.Reason == Expired {
            return string::from("x509: certificate has expired or is not yet valid: ")
                + self.Detail.clone();
        } else if self.Reason == CANotAuthorizedForThisName {
            return string::from(
                "x509: a root or intermediate certificate is not authorized to sign for this name: ",
            ) + self.Detail.clone();
        } else if self.Reason == CANotAuthorizedForExtKeyUsage {
            return string::from(
                "x509: a root or intermediate certificate is not authorized for an extended key usage: ",
            ) + self.Detail.clone();
        } else if self.Reason == TooManyIntermediates {
            return string::from("x509: too many intermediates for path length constraint");
        } else if self.Reason == IncompatibleUsage {
            return string::from("x509: certificate specifies an incompatible key usage");
        } else if self.Reason == NameMismatch {
            return string::from(
                "x509: issuer name does not match subject from issuing certificate",
            );
        } else if self.Reason == NameConstraintsWithoutSANs {
            return string::from(
                "x509: issuer has name constraints but leaf doesn't have a SAN extension",
            );
        } else if self.Reason == UnconstrainedName {
            return string::from(
                "x509: issuer has name constraints but leaf contains unknown or unconstrained name: ",
            ) + self.Detail.clone();
        } else if self.Reason == NoValidChains {
            let mut s = string::from("x509: no valid chains built");
            if self.Detail.Len() != 0 {
                s = crate::fmt::Sprintf!("%s: %s", s, self.Detail.clone());
            }
            return s;
        }
        return string::from("x509: unknown error");
    }
}

// go: none — goish idiom: Go's struct satisfies `error` through its
// `Error() string` method; goish needs the trait impl spelled out.
impl errors::ErrorTrait for CertificateInvalidError {
    // go: none — goish idiom: forwards to the ported inherent `Error`.
    fn Error(&self) -> string {
        return CertificateInvalidError::Error(self);
    }
}

// Go: verify.go:104-109
/// Results when the set of authorized names doesn't match the requested
/// name.
#[derive(Clone, Default)]
pub struct HostnameError {
    pub Certificate: Certificate,
    pub Host: string,
}

impl HostnameError {
    // go: sdk 1.25.5 crypto/x509/verify.go:111-145 HostnameError.Error
    pub fn Error(&self) -> string {
        let c = &self.Certificate;
        let maxNamesIncluded: int = 100;

        if !c.hasSANExtension() && matchHostnames(&c.Subject.CommonName, &self.Host) {
            return string::from(
                "x509: certificate relies on legacy Common Name field, use SANs instead",
            );
        }

        let mut valid = strings::Builder::default();
        let ip = net::ParseIP(self.Host.clone());
        if !ip.IsNil() {
            // Trying to validate an IP
            if c.IPAddresses.Len() == 0 {
                return string::from("x509: cannot validate certificate for ")
                    + self.Host.clone()
                    + string::from(" because it doesn't contain any IP SANs");
            }
            if c.IPAddresses.Len() >= maxNamesIncluded {
                return crate::fmt::Sprintf!(
                    "x509: certificate is valid for %d IP SANs, but none matched %s",
                    c.IPAddresses.Len(),
                    self.Host.clone()
                );
            }
            for (_, san) in crate::range!(c.IPAddresses.clone()) {
                if valid.Len() > 0 {
                    let _ = valid.WriteString(", ");
                }
                let _ = valid.WriteString(san.String());
            }
        } else {
            if c.DNSNames.Len() >= maxNamesIncluded {
                return crate::fmt::Sprintf!(
                    "x509: certificate is valid for %d names, but none matched %s",
                    c.DNSNames.Len(),
                    self.Host.clone()
                );
            }
            let _ = valid.WriteString(strings::Join(c.DNSNames.clone(), ", "));
        }

        if valid.Len() == 0 {
            return string::from(
                "x509: certificate is not valid for any names, but wanted to match ",
            ) + self.Host.clone();
        }
        return string::from("x509: certificate is valid for ")
            + valid.String()
            + string::from(", not ")
            + self.Host.clone();
    }
}

// go: none — goish idiom: see `impl ErrorTrait for CertificateInvalidError`.
impl errors::ErrorTrait for HostnameError {
    // go: none — goish idiom: forwards to the ported inherent `Error`.
    fn Error(&self) -> string {
        return HostnameError::Error(self);
    }
}

// Go: verify.go:147-156
/// Results when the certificate issuer is unknown.
#[derive(Clone, Default)]
pub struct UnknownAuthorityError {
    pub Cert: Certificate,
    /// Contains an error that may be helpful in determining why an
    /// authority wasn't found.
    pub(super) hintErr: error,
    /// Contains a possible authority certificate that was rejected
    /// because of the error in hintErr.
    pub(super) hintCert: Certificate,
}

impl UnknownAuthorityError {
    // go: sdk 1.25.5 crypto/x509/verify.go:158-172 UnknownAuthorityError.Error
    pub fn Error(&self) -> string {
        let mut s = string::from("x509: certificate signed by unknown authority");
        if self.hintErr != crate::nil {
            let mut certName = self.hintCert.Subject.CommonName.clone();
            if certName.Len() == 0 {
                if self.hintCert.Subject.Organization.Len() > 0 {
                    certName = self.hintCert.Subject.Organization[int(0)].clone();
                } else {
                    // goish's `big::Int` has no `String()`; Go's is `Text(10)`.
                    certName = string::from("serial:") + self.hintCert.SerialNumber.Text(10);
                }
            }
            s = s + crate::fmt::Sprintf!(
                " (possibly because of %q while trying to verify candidate authority certificate %q)",
                self.hintErr.Error(),
                certName
            );
        }
        return s;
    }
}

// go: none — goish idiom: see `impl ErrorTrait for CertificateInvalidError`.
impl errors::ErrorTrait for UnknownAuthorityError {
    // go: none — goish idiom: forwards to the ported inherent `Error`.
    fn Error(&self) -> string {
        return UnknownAuthorityError::Error(self);
    }
}

// Go: verify.go:174-177
/// Results when we fail to load the system root certificates.
#[derive(Clone, Default)]
pub struct SystemRootsError {
    pub Err: error,
}

impl SystemRootsError {
    // go: sdk 1.25.5 crypto/x509/verify.go:179-185 SystemRootsError.Error
    pub fn Error(&self) -> string {
        let msg = string::from("x509: failed to load system roots and no roots provided");
        if self.Err != crate::nil {
            return msg + string::from("; ") + self.Err.Error();
        }
        return msg;
    }

    // go: sdk 1.25.5 crypto/x509/verify.go:187-187 SystemRootsError.Unwrap
    pub fn Unwrap(&self) -> error {
        return self.Err.clone();
    }
}

// go: none — goish idiom: Go asserts `interface { Unwrap() error }` at
// the `errors` package boundary; goish's `ErrorTrait` carries `Unwrap`
// as a defaulted method, so the two ported methods land in one impl.
impl errors::ErrorTrait for SystemRootsError {
    // go: none — goish idiom: forwards to the ported inherent `Error`.
    fn Error(&self) -> string {
        return SystemRootsError::Error(self);
    }
    // go: none — goish idiom: forwards to the ported inherent `Unwrap`.
    fn Unwrap(&self) -> error {
        return SystemRootsError::Unwrap(self);
    }
}

goish::var! {
    /// Returned when a certificate without ASN.1 contents is verified.
    /// Platform-specific verification needs the ASN.1 contents.
    errNotParsed: error = "x509: missing ASN.1 contents; use ParseCertificate";
}

// Go: verify.go:193-243
/// Contains parameters for `Certificate::Verify`.
///
/// `Intermediates` and `Roots` are `*CertPool` in Go; a nil `Roots`
/// means "use the system roots". See the banner.
#[derive(Clone, Default)]
pub struct VerifyOptions {
    /// If set, is checked against the leaf certificate with
    /// `Certificate::VerifyHostname`.
    pub DNSName: string,

    /// An optional pool of certificates that are not trust anchors, but
    /// can be used to form a chain from the leaf certificate to a root
    /// certificate.
    pub Intermediates: Option<CertPool>,
    /// The set of trusted root certificates the leaf certificate needs
    /// to chain up to. If `None`, the system roots are used.
    pub Roots: Option<CertPool>,

    /// Used to check the validity of all certificates in the chain. If
    /// zero, the current time is used.
    pub CurrentTime: time::Time,

    /// Specifies which Extended Key Usage values are acceptable. A chain
    /// is accepted if it allows any of the listed values. An empty list
    /// means `ExtKeyUsageServerAuth`. To accept any key usage, include
    /// `ExtKeyUsageAny`.
    pub KeyUsages: slice<ExtKeyUsage>,

    /// The maximum number of comparisons to perform when checking a
    /// given certificate's name constraints. If zero, a sensible default
    /// is used.
    pub MaxConstraintComparisions: int,

    /// Specifies which certificate policy OIDs are acceptable during
    /// policy validation. An empty field implies any valid policy is
    /// acceptable.
    pub CertificatePolicies: slice<OID>,

    // The following three are unexported in Go: "we do not expect users
    // to actually need to use them, but [they] are useful for testing the
    // policy validation code". They are `pub` here for a Rust reason
    // only: a Go composite literal in another package simply omits an
    // unexported field, but Rust's `..Default::default()` needs every
    // field visible at the call site, and `VerifyOptions` is exactly the
    // struct users fill in that way. Nothing outside this file reads
    // them.
    /// Indicates if policy mapping should be allowed during path
    /// validation.
    pub inhibitPolicyMapping: bool,

    /// Indicates if explicit policies must be present for each
    /// certificate being validated.
    pub requireExplicitPolicy: bool,

    /// Indicates if the anyPolicy policy should be processed if present
    /// in a certificate being validated.
    pub inhibitAnyPolicy: bool,
}

// Go: verify.go:245-249 — the iota block.
pub(super) const leafCertificate: int = 0;
pub(super) const intermediateCertificate: int = 1;
pub(super) const rootCertificate: int = 2;

// Go: verify.go:250-255
//   type rfc2821Mailbox struct { local, domain string }
/// Represents a "mailbox" (which is an email address to most people) by
/// breaking it into the "local" (i.e. before the '@') and "domain" parts.
#[derive(Clone, Default)]
pub(super) struct rfc2821Mailbox {
    pub local: string,
    pub domain: string,
}

// go: sdk 1.25.5 crypto/x509/verify.go:262-396 parseRFC2821Mailbox
/// Parse an email address into local and domain parts, based on the ABNF
/// for a "Mailbox" from RFC 2821. According to RFC 5280, Section 4.2.1.6
/// that's correct for an rfc822Name from a certificate.
///
/// Go's two labelled loops (`QuotedString`, `NextChar`) become a plain
/// `loop`/`while` with a `break`, and its `fallthrough` in the atom
/// branch becomes a re-test of the same byte — the escaped byte is
/// appended by the branch below either way.
pub(super) fn parseRFC2821Mailbox(in_: &string) -> (rfc2821Mailbox, bool) {
    let mut mailbox = rfc2821Mailbox::default();
    let all = in_.as_bytes().to_vec();
    if all.is_empty() {
        return (mailbox, false);
    }
    // Go re-slices `in` as it consumes; goish tracks the offset.
    let mut p: usize = 0;

    let mut localPartBytes: Vec<byte> = Vec::with_capacity(all.len() / 2);

    if all[0] == b'"' {
        // Quoted-string = DQUOTE *qcontent DQUOTE
        // non-whitespace-control = %d1-8 / %d11 / %d12 / %d14-31 / %d127
        // qcontent = qtext / quoted-pair
        // qtext = non-whitespace-control /
        //         %d33 / %d35-91 / %d93-126
        // quoted-pair = ("\" text) / obs-qp
        // text = %d1-9 / %d11 / %d12 / %d14-127 / obs-text
        //
        // (Names beginning with "obs-" are the obsolete syntax from RFC 2822,
        // Section 4. Since it has been 16 years, we no longer accept that.)
        p += 1;
        loop {
            if p >= all.len() {
                return (mailbox, false);
            }
            let c = all[p];
            p += 1;

            if c == b'"' {
                break;
            } else if c == b'\\' {
                // quoted-pair
                if p >= all.len() {
                    return (mailbox, false);
                }
                let n = all[p];
                if n == 11 || n == 12 || (1 <= n && n <= 9) || (14 <= n && n <= 127) {
                    localPartBytes.push(n);
                    p += 1;
                } else {
                    return (mailbox, false);
                }
            } else if c == 11
                || c == 12
                // Space (char 32) is not allowed based on the BNF, but
                // RFC 3696 gives an example that assumes that it is.
                // Several "verified" errata continue to argue about this
                // point. We choose to accept it.
                || c == 32
                || c == 33
                || c == 127
                || (1 <= c && c <= 8)
                || (14 <= c && c <= 31)
                || (35 <= c && c <= 91)
                || (93 <= c && c <= 126)
            {
                // qtext
                localPartBytes.push(c);
            } else {
                return (mailbox, false);
            }
        }
    } else {
        // Atom ("." Atom)*
        while p < all.len() {
            // atext from RFC 2822, Section 3.2.4
            let mut c = all[p];

            if c == b'\\' {
                // Examples given in RFC 3696 suggest that escaped
                // characters can appear outside of a quoted string.
                // Several "verified" errata continue to argue the point.
                // We choose to accept it. Go falls through to the atext
                // arm, which appends `in[0]` — the escaped byte.
                p += 1;
                if p >= all.len() {
                    return (mailbox, false);
                }
                c = all[p];
                localPartBytes.push(c);
                p += 1;
                continue;
            }

            if (b'0' <= c && c <= b'9')
                || (b'a' <= c && c <= b'z')
                || (b'A' <= c && c <= b'Z')
                || c == b'!'
                || c == b'#'
                || c == b'$'
                || c == b'%'
                || c == b'&'
                || c == b'\''
                || c == b'*'
                || c == b'+'
                || c == b'-'
                || c == b'/'
                || c == b'='
                || c == b'?'
                || c == b'^'
                || c == b'_'
                || c == b'`'
                || c == b'{'
                || c == b'|'
                || c == b'}'
                || c == b'~'
                || c == b'.'
            {
                localPartBytes.push(c);
                p += 1;
            } else {
                break;
            }
        }

        if localPartBytes.is_empty() {
            return (mailbox, false);
        }

        // From RFC 3696, Section 3:
        // "period (".") may also appear, but may not be used to start
        // or end the local part, nor may two or more consecutive
        // periods appear."
        let twoDots = slice::__from_vec(alloc::vec![b'.', b'.']);
        if localPartBytes[0] == b'.'
            || localPartBytes[localPartBytes.len() - 1] == b'.'
            || crate::bytes::Contains(slice::__from_vec(localPartBytes.clone()), twoDots)
        {
            return (mailbox, false);
        }
    }

    if p >= all.len() || all[p] != b'@' {
        return (mailbox, false);
    }
    p += 1;

    // The RFC species a format for domains, but that's known to be
    // violated in practice so we accept that anything after an '@' is the
    // domain part.
    let rest = string::from_bytes(&all[p..]);
    let (_, ok) = domainToReverseLabels(&rest);
    if !ok {
        return (mailbox, false);
    }

    mailbox.local = string::from_bytes(&localPartBytes);
    mailbox.domain = rest;
    return (mailbox, true);
}

// go: sdk 1.25.5 crypto/x509/verify.go:398-436 domainToReverseLabels
/// Convert a textual domain name like foo.example.com to the list of
/// labels in reverse order, e.g. ["com", "example", "foo"].
pub(super) fn domainToReverseLabels(domain: &string) -> (slice<string>, bool) {
    let mut reverseLabels: Vec<string> =
        Vec::with_capacity(usize::try_from(strings::Count(domain.clone(), ".") + 1).unwrap_or(0));
    let mut domain = domain.clone();
    while domain.Len() > 0 {
        let i = strings::LastIndexByte(domain.clone(), b'.');
        if i == -1 {
            reverseLabels.push(domain.clone());
            domain = string::from("");
        } else {
            let b = domain.as_bytes().to_vec();
            reverseLabels.push(string::from_bytes(&b[(i + 1) as usize..]));
            domain = string::from_bytes(&b[..i as usize]);
            if i == 0 {
                // domain is prefixed with an empty label, append an empty
                // string to reverseLabels to indicate this.
                reverseLabels.push(string::from(""));
            }
        }
    }

    let reverseLabels: slice<string> = slice::__from_vec(reverseLabels);

    if reverseLabels.Len() > 0 && reverseLabels[int(0)].Len() == 0 {
        // An empty label at the end indicates an absolute value.
        return (slice::__from_vec(Vec::<string>::new()), false);
    }

    for (_, label) in crate::range!(reverseLabels.clone()) {
        if label.Len() == 0 {
            // Empty labels are otherwise invalid.
            return (slice::__from_vec(Vec::<string>::new()), false);
        }

        for (_, c) in crate::range!(label) {
            if c < 33 || c > 126 {
                // Invalid character.
                return (slice::__from_vec(Vec::<string>::new()), false);
            }
        }
    }

    return (reverseLabels, true);
}

// go: none — goish idiom: Go formats the offending constraint with
// `%q`, which is a quoted string for the DNS / email / URI constraints
// and the malformed `%!q(*net.IPNet=&{…})` for the IP ones. This trait
// supplies the value `%q` is handed; the IP arm yields `IPNet.String()`
// rather than reproducing Go's bad-verb output.
pub(super) trait constraintQuoted {
    fn __quoted(&self) -> string;
}

// go: none — goish idiom: the `string` arm of `constraintQuoted`.
impl constraintQuoted for string {
    // go: none — goish idiom: the `string` arm; see the trait.
    fn __quoted(&self) -> string {
        return self.clone();
    }
}

// go: none — goish idiom: the `*net.IPNet` arm of `constraintQuoted`.
impl constraintQuoted for net::IPNet {
    // go: none — goish idiom: the `*net.IPNet` arm; see the trait.
    fn __quoted(&self) -> string {
        return self.String();
    }
}

// go: sdk 1.25.5 crypto/x509/verify.go:439-453 matchEmailConstraint
pub(super) fn matchEmailConstraint(
    mailbox: &rfc2821Mailbox,
    constraint: &string,
    excluded: bool,
    reversedDomainsCache: &mut map<string, slice<string>>,
    reversedConstraintsCache: &mut map<string, slice<string>>,
) -> (bool, error) {
    // If the constraint contains an @, then it specifies an exact mailbox
    // name.
    if strings::Contains(constraint.clone(), "@") {
        let (constraintMailbox, ok) = parseRFC2821Mailbox(constraint);
        if !ok {
            return (
                false,
                crate::fmt::Errorf!(
                    "x509: internal error: cannot parse constraint %q",
                    constraint.clone()
                ),
            );
        }
        return (
            mailbox.local == constraintMailbox.local
                && strings::EqualFold(mailbox.domain.clone(), constraintMailbox.domain.clone()),
            errors::nil,
        );
    }

    // Otherwise the constraint is like a DNS constraint of the domain part
    // of the mailbox.
    return matchDomainConstraint(
        &mailbox.domain,
        constraint,
        excluded,
        reversedDomainsCache,
        reversedConstraintsCache,
    );
}

// go: sdk 1.25.5 crypto/x509/verify.go:455-485 matchURIConstraint
/// Go's IP-literal rejection is `netip.ParseAddr(host)`; goish has no
/// `net/netip`, so it is `net::ParseIP(host)`. See the banner for the two
/// ways the two parsers differ. The bracket half of the same condition —
/// the only spelling a URI authority may use for IPv6 — is verbatim.
pub(super) fn matchURIConstraint(
    uri: &url::URL,
    constraint: &string,
    excluded: bool,
    reversedDomainsCache: &mut map<string, slice<string>>,
    reversedConstraintsCache: &mut map<string, slice<string>>,
) -> (bool, error) {
    // From RFC 5280, Section 4.2.1.10:
    // "a uniformResourceIdentifier that does not include an authority
    // component with a host name specified as a fully qualified domain
    // name (e.g., if the URI either does not include an authority
    // component or includes an authority component in which the host name
    // is specified as an IP address), then the application MUST reject the
    // certificate."

    let mut host = uri.Host.clone();
    if host.Len() == 0 {
        return (
            false,
            crate::fmt::Errorf!(
                "URI with empty host (%q) cannot be matched against constraints",
                uri.String()
            ),
        );
    }

    if strings::Contains(host.clone(), ":") && !strings::HasSuffix(host.clone(), "]") {
        let (h, _, err) = net::SplitHostPort(uri.Host.clone());
        if err != crate::nil {
            return (false, err);
        }
        host = h;
    }

    // netip.ParseAddr will reject the URI IPv6 literal form "[...]", so we
    // check if _either_ the string parses as an IP, or if it is enclosed in
    // square brackets.
    if !net::ParseIP(host.clone()).IsNil()
        || (strings::HasPrefix(host.clone(), "[") && strings::HasSuffix(host.clone(), "]"))
    {
        return (
            false,
            crate::fmt::Errorf!(
                "URI with IP (%q) cannot be matched against constraints",
                uri.String()
            ),
        );
    }

    return matchDomainConstraint(
        &host,
        constraint,
        excluded,
        reversedDomainsCache,
        reversedConstraintsCache,
    );
}

// go: sdk 1.25.5 crypto/x509/verify.go:487-499 matchIPConstraint
pub(super) fn matchIPConstraint(ip: &net::IP, constraint: &net::IPNet) -> (bool, error) {
    if ip.bytes.Len() != constraint.IP.bytes.Len() {
        return (false, errors::nil);
    }

    for (i, b) in crate::range!(ip.bytes.clone()) {
        let mask = constraint.Mask.bytes[i];
        if b & mask != constraint.IP.bytes[i] & mask {
            return (false, errors::nil);
        }
    }

    return (true, errors::nil);
}

// go: sdk 1.25.5 crypto/x509/verify.go:501-561 matchDomainConstraint
pub(super) fn matchDomainConstraint(
    domain: &string,
    constraint: &string,
    excluded: bool,
    reversedDomainsCache: &mut map<string, slice<string>>,
    reversedConstraintsCache: &mut map<string, slice<string>>,
) -> (bool, error) {
    // The meaning of zero length constraints is not specified, but this
    // code follows NSS and accepts them as matching everything.
    if constraint.Len() == 0 {
        return (true, errors::nil);
    }

    let (mut domainLabels, found) = reversedDomainsCache.Get(domain.clone());
    if !found {
        let (labels, ok) = domainToReverseLabels(domain);
        if !ok {
            return (
                false,
                crate::fmt::Errorf!(
                    "x509: internal error: cannot parse domain %q",
                    domain.clone()
                ),
            );
        }
        domainLabels = labels;
        reversedDomainsCache.Set(domain.clone(), domainLabels.clone());
    }

    let mut wildcardDomain = false;
    if domain.Len() > 0 && domain.as_bytes()[0] == b'*' {
        wildcardDomain = true;
    }

    // RFC 5280 says that a leading period in a domain name means that at
    // least one label must be prepended, but only for URI and email
    // constraints, not DNS constraints. The code also supports that
    // behaviour for DNS constraints.

    let mut mustHaveSubdomains = false;
    let mut constraint = constraint.clone();
    if constraint.as_bytes()[0] == b'.' {
        mustHaveSubdomains = true;
        let b = constraint.as_bytes().to_vec();
        constraint = string::from_bytes(&b[1..]);
    }

    let (mut constraintLabels, found) = reversedConstraintsCache.Get(constraint.clone());
    if !found {
        let (labels, ok) = domainToReverseLabels(&constraint);
        if !ok {
            return (
                false,
                crate::fmt::Errorf!(
                    "x509: internal error: cannot parse domain %q",
                    constraint.clone()
                ),
            );
        }
        constraintLabels = labels;
        reversedConstraintsCache.Set(constraint.clone(), constraintLabels.clone());
    }

    if domainLabels.Len() < constraintLabels.Len()
        || (mustHaveSubdomains && domainLabels.Len() == constraintLabels.Len())
    {
        return (false, errors::nil);
    }

    if excluded && wildcardDomain && domainLabels.Len() > 1 && constraintLabels.Len() > 0 {
        domainLabels = domainLabels.slice(0, domainLabels.Len() - 1);
        constraintLabels = constraintLabels.slice(0, constraintLabels.Len() - 1);
    }

    for (i, constraintLabel) in crate::range!(constraintLabels.clone()) {
        if !strings::EqualFold(constraintLabel, domainLabels[i].clone()) {
            return (false, errors::nil);
        }
    }

    return (true, errors::nil);
}

impl Certificate {
    // go: sdk 1.25.5 crypto/x509/verify.go:563-621 Certificate.checkNameConstraints
    /// Check that c permits a child certificate to claim the given name,
    /// of type nameType. The argument parsedName contains the parsed form
    /// of name, suitable for passing to the match function. The total
    /// number of comparisons is tracked in the given count and should not
    /// exceed the given limit.
    ///
    /// Go reaches into `permitted` / `excluded` — both declared `any` —
    /// with `reflect.ValueOf(x).Len()` and `.Index(i).Interface()`. goish
    /// makes the function generic over the constraint element type
    /// instead, so the two are `slice<C>` and no reflection is needed.
    /// Same eight parameters, same order, same meaning.
    pub(super) fn checkNameConstraints<P, C, F>(
        &self,
        count: &mut int,
        maxConstraintComparisons: int,
        nameType: &str,
        name: &string,
        parsedName: &P,
        mut match_: F,
        permitted: &slice<C>,
        excluded: &slice<C>,
    ) -> error
    where
        C: Clone + constraintQuoted,
        F: FnMut(&P, &C, bool) -> (bool, error),
    {
        *count += excluded.Len();
        if *count > maxConstraintComparisons {
            return CertificateInvalidError {
                Cert: self.clone(),
                Reason: TooManyConstraints,
                Detail: string::new(),
            }
            .into();
        }

        for (_, constraint) in crate::range!(excluded.clone()) {
            let (m, err) = match_(parsedName, &constraint, true);
            if err != crate::nil {
                return CertificateInvalidError {
                    Cert: self.clone(),
                    Reason: CANotAuthorizedForThisName,
                    Detail: err.Error(),
                }
                .into();
            }

            if m {
                return CertificateInvalidError {
                    Cert: self.clone(),
                    Reason: CANotAuthorizedForThisName,
                    Detail: crate::fmt::Sprintf!(
                        "%s %q is excluded by constraint %q",
                        string::from(nameType),
                        name.clone(),
                        constraint.__quoted()
                    ),
                }
                .into();
            }
        }

        *count += permitted.Len();
        if *count > maxConstraintComparisons {
            return CertificateInvalidError {
                Cert: self.clone(),
                Reason: TooManyConstraints,
                Detail: string::new(),
            }
            .into();
        }

        let mut ok = true;
        for (_, constraint) in crate::range!(permitted.clone()) {
            let (m, err) = match_(parsedName, &constraint, false);
            if err != crate::nil {
                return CertificateInvalidError {
                    Cert: self.clone(),
                    Reason: CANotAuthorizedForThisName,
                    Detail: err.Error(),
                }
                .into();
            }
            ok = m;

            if ok {
                break;
            }
        }

        if !ok {
            return CertificateInvalidError {
                Cert: self.clone(),
                Reason: CANotAuthorizedForThisName,
                Detail: crate::fmt::Sprintf!(
                    "%s %q is not permitted by any constraint",
                    string::from(nameType),
                    name.clone()
                ),
            }
            .into();
        }

        return errors::nil;
    }

    // go: sdk 1.25.5 crypto/x509/verify.go:623-787 Certificate.isValid
    /// Perform validity checks on c given that it is a candidate to append
    /// to the chain in currentChain.
    ///
    /// Go's `fmt.Errorf("x509: cannot parse rfc822Name %q", mailbox)`
    /// formats the *struct*, which renders as `{%!q(string=) …}`. goish
    /// formats the name that failed to parse instead.
    // goishlint:ignore GOISH017 isValid — the rfc822Name error formats the name, not the struct; see the doc comment.
    pub(super) fn isValid(
        &self,
        certType: int,
        currentChain: &slice<Certificate>,
        opts: &VerifyOptions,
    ) -> error {
        if self.UnhandledCriticalExtensions.Len() > 0 {
            return UnhandledCriticalExtension {}.into();
        }

        if currentChain.Len() > 0 {
            let child = currentChain[currentChain.Len() - 1].clone();
            if !crate::bytes::Equal(child.RawIssuer.clone(), self.RawSubject.clone()) {
                return CertificateInvalidError {
                    Cert: self.clone(),
                    Reason: NameMismatch,
                    Detail: string::new(),
                }
                .into();
            }
        }

        let mut now = opts.CurrentTime;
        if now.IsZero() {
            now = time::Now();
        }
        if now.Before(self.NotBefore) {
            return CertificateInvalidError {
                Cert: self.clone(),
                Reason: Expired,
                Detail: crate::fmt::Sprintf!(
                    "current time %s is before %s",
                    now.Format(string::from(time::RFC3339)),
                    self.NotBefore.Format(string::from(time::RFC3339))
                ),
            }
            .into();
        } else if now.After(self.NotAfter) {
            return CertificateInvalidError {
                Cert: self.clone(),
                Reason: Expired,
                Detail: crate::fmt::Sprintf!(
                    "current time %s is after %s",
                    now.Format(string::from(time::RFC3339)),
                    self.NotAfter.Format(string::from(time::RFC3339))
                ),
            }
            .into();
        }

        let mut maxConstraintComparisons = opts.MaxConstraintComparisions;
        if maxConstraintComparisons == 0 {
            maxConstraintComparisons = 250000;
        }
        let mut comparisonCount: int = 0;

        if certType == intermediateCertificate || certType == rootCertificate {
            if currentChain.Len() == 0 {
                return errors::New("x509: internal error: empty chain when appending CA cert");
            }
        }

        // Each time we do constraint checking, we need to check the constraints in
        // the current certificate against all of the names that preceded it. We
        // reverse these names using domainToReverseLabels, which is a relatively
        // expensive operation. Since we check each name against each constraint,
        // this requires us to do N*C calls to domainToReverseLabels (where N is the
        // total number of names that preceed the certificate, and C is the total
        // number of constraints in the certificate). By caching the results of
        // calling domainToReverseLabels, we can reduce that to N+C calls at the
        // cost of keeping all of the parsed names and constraints in memory until
        // we return from isValid.
        let mut reversedDomainsCache: map<string, slice<string>> = map::new();
        let mut reversedConstraintsCache: map<string, slice<string>> = map::new();

        if (certType == intermediateCertificate || certType == rootCertificate)
            && self.hasNameConstraints()
        {
            let mut toCheck: slice<Certificate> = slice::new();
            for (_, c) in crate::range!(currentChain.clone()) {
                if c.hasSANExtension() {
                    toCheck = crate::append!(toCheck, c.clone());
                }
            }
            for (_, sanCert) in crate::range!(toCheck) {
                let err = forEachSAN(
                    CBString::New(sanCert.getSANExtension()),
                    |tag: int, data: slice<byte>| -> error {
                        if tag == nameTypeEmail {
                            let name = string::from_bytes(&data);
                            let (mailbox, ok) = parseRFC2821Mailbox(&name);
                            if !ok {
                                return crate::fmt::Errorf!(
                                    "x509: cannot parse rfc822Name %q",
                                    name.clone()
                                );
                            }

                            let err = self.checkNameConstraints(
                                &mut comparisonCount,
                                maxConstraintComparisons,
                                "email address",
                                &name,
                                &mailbox,
                                |parsedName: &rfc2821Mailbox,
                                 constraint: &string,
                                 excluded: bool|
                                 -> (bool, error) {
                                    return matchEmailConstraint(
                                        parsedName,
                                        constraint,
                                        excluded,
                                        &mut reversedDomainsCache,
                                        &mut reversedConstraintsCache,
                                    );
                                },
                                &self.PermittedEmailAddresses,
                                &self.ExcludedEmailAddresses,
                            );
                            if err != crate::nil {
                                return err;
                            }
                        } else if tag == nameTypeDNS {
                            let name = string::from_bytes(&data);
                            if !domainNameValid(&name, false) {
                                return crate::fmt::Errorf!(
                                    "x509: cannot parse dnsName %q",
                                    name.clone()
                                );
                            }

                            let err = self.checkNameConstraints(
                                &mut comparisonCount,
                                maxConstraintComparisons,
                                "DNS name",
                                &name,
                                &name,
                                |parsedName: &string,
                                 constraint: &string,
                                 excluded: bool|
                                 -> (bool, error) {
                                    return matchDomainConstraint(
                                        parsedName,
                                        constraint,
                                        excluded,
                                        &mut reversedDomainsCache,
                                        &mut reversedConstraintsCache,
                                    );
                                },
                                &self.PermittedDNSDomains,
                                &self.ExcludedDNSDomains,
                            );
                            if err != crate::nil {
                                return err;
                            }
                        } else if tag == nameTypeURI {
                            let name = string::from_bytes(&data);
                            let (uri, err) = url::Parse(name.clone());
                            if err != crate::nil {
                                return crate::fmt::Errorf!(
                                    "x509: internal error: URI SAN %q failed to parse",
                                    name.clone()
                                );
                            }

                            let err = self.checkNameConstraints(
                                &mut comparisonCount,
                                maxConstraintComparisons,
                                "URI",
                                &name,
                                &uri,
                                |parsedName: &url::URL,
                                 constraint: &string,
                                 excluded: bool|
                                 -> (bool, error) {
                                    return matchURIConstraint(
                                        parsedName,
                                        constraint,
                                        excluded,
                                        &mut reversedDomainsCache,
                                        &mut reversedConstraintsCache,
                                    );
                                },
                                &self.PermittedURIDomains,
                                &self.ExcludedURIDomains,
                            );
                            if err != crate::nil {
                                return err;
                            }
                        } else if tag == nameTypeIP {
                            let ip = net::IP {
                                bytes: data.clone(),
                            };
                            let l = ip.bytes.Len();
                            if l != net::IPv4len && l != net::IPv6len {
                                return crate::fmt::Errorf!(
                                    "x509: internal error: IP SAN %x failed to parse",
                                    data.clone()
                                );
                            }

                            let err = self.checkNameConstraints(
                                &mut comparisonCount,
                                maxConstraintComparisons,
                                "IP address",
                                &ip.String(),
                                &ip,
                                |parsedName: &net::IP,
                                 constraint: &net::IPNet,
                                 _excluded: bool|
                                 -> (bool, error) {
                                    return matchIPConstraint(parsedName, constraint);
                                },
                                &self.PermittedIPRanges,
                                &self.ExcludedIPRanges,
                            );
                            if err != crate::nil {
                                return err;
                            }
                        }
                        // Unknown SAN types are ignored.

                        return errors::nil;
                    },
                );

                if err != crate::nil {
                    return err;
                }
            }
        }

        // KeyUsage status flags are ignored. From Engineering Security, Peter
        // Gutmann: A European government CA marked its signing certificates as
        // being valid for encryption only, but no-one noticed. Another
        // European CA marked its signature keys as not being valid for
        // signatures. A different CA marked its own trusted root certificate
        // as being invalid for certificate signing. Another national CA
        // distributed a certificate to be used to encrypt data for the
        // country's tax authority that was marked as only being usable for
        // digital signatures but not for encryption. Yet another CA reversed
        // the order of the bit flags in the keyUsage due to confusion over
        // encoding endianness, essentially setting a random keyUsage in
        // certificates that it issued. Another CA created a self-invalidating
        // certificate by adding a certificate policy statement stipulating
        // that the certificate had to be used strictly as specified in the
        // keyUsage, and a keyUsage containing a flag indicating that the RSA
        // encryption key could only be used for Diffie-Hellman key agreement.

        if certType == intermediateCertificate && (!self.BasicConstraintsValid || !self.IsCA) {
            return CertificateInvalidError {
                Cert: self.clone(),
                Reason: NotAuthorizedToSign,
                Detail: string::new(),
            }
            .into();
        }

        if self.BasicConstraintsValid && self.MaxPathLen >= 0 {
            let numIntermediates = currentChain.Len() - 1;
            if numIntermediates > self.MaxPathLen {
                return CertificateInvalidError {
                    Cert: self.clone(),
                    Reason: TooManyIntermediates,
                    Detail: string::new(),
                }
                .into();
            }
        }

        return errors::nil;
    }

    // go: sdk 1.25.5 crypto/x509/verify.go:789-940 Certificate.Verify
    /// Attempt to verify c by building one or more chains from c to a
    /// certificate in opts.Roots, using certificates in opts.Intermediates
    /// if needed. If successful, it returns one or more chains where the
    /// first element of the chain is c and the last element is from
    /// opts.Roots.
    ///
    /// If opts.Roots is `None`, the system roots are used. If system roots
    /// are unavailable the returned error will be of type
    /// `SystemRootsError`.
    ///
    /// Go's `runtime.GOOS == "windows" || "darwin" || "ios"` platform-
    /// verifier arm is dead on goish (linux/amd64 only) and is not ported.
    ///
    /// WARNING: this function doesn't do any revocation checking.
    // goishlint:ignore GOISH017 Verify — the platform-verifier arm is dead on linux/amd64; see the doc comment.
    pub fn Verify(&self, opts: VerifyOptions) -> (slice<slice<Certificate>>, error) {
        let mut opts = opts;
        // Platform-specific verification needs the ASN.1 contents so
        // this makes the behavior consistent across platforms.
        if self.Raw.Len() == 0 {
            return (slice::new(), errNotParsed.into());
        }
        let intermediatesLen = match &opts.Intermediates {
            Some(p) => p.len(),
            None => 0,
        };
        let mut i: int = 0;
        while i < intermediatesLen {
            let c = match &opts.Intermediates {
                Some(p) => p.cert(i),
                None => Certificate::default(),
            };
            if c.Raw.Len() == 0 {
                return (slice::new(), errNotParsed.into());
            }
            i += 1;
        }

        if opts.Roots.is_none() {
            opts.Roots = super::root::systemRootsPool();
            if opts.Roots.is_none() {
                return (
                    slice::new(),
                    SystemRootsError {
                        Err: super::root::systemRootsErr(),
                    }
                    .into(),
                );
            }
        }

        let err = self.isValid(leafCertificate, &slice::new(), &opts);
        if err != crate::nil {
            return (slice::new(), err);
        }

        if opts.DNSName.Len() > 0 {
            let err = self.VerifyHostname(opts.DNSName.clone());
            if err != crate::nil {
                return (slice::new(), err);
            }
        }

        let mut candidateChains: slice<slice<Certificate>> = slice::new();
        let rootsContains = match &opts.Roots {
            Some(p) => p.contains(self),
            None => false,
        };
        if rootsContains {
            let mut one: slice<Certificate> = slice::new();
            one = crate::append!(one, self.clone());
            candidateChains = crate::append!(candidateChains, one);
        } else {
            let mut start: slice<Certificate> = slice::new();
            start = crate::append!(start, self.clone());
            let (built, err) = self.buildChains(&start, &mut 0, &opts);
            if err != crate::nil {
                return (slice::new(), err);
            }
            candidateChains = built;
        }

        let mut chains: slice<slice<Certificate>> = slice::new();

        let mut invalidPoliciesChains: int = 0;
        for (_, candidate) in crate::range!(candidateChains.clone()) {
            if !policiesValid(&candidate, &opts) {
                invalidPoliciesChains += 1;
                continue;
            }
            chains = crate::append!(chains, candidate);
        }

        if chains.Len() == 0 {
            return (
                slice::new(),
                CertificateInvalidError {
                    Cert: self.clone(),
                    Reason: NoValidChains,
                    Detail: string::from("all candidate chains have invalid policies"),
                }
                .into(),
            );
        }

        for (_, eku) in crate::range!(opts.KeyUsages.clone()) {
            if *eku == ExtKeyUsageAny {
                // If any key usage is acceptable, no need to check the chain for
                // key usages.
                return (chains, errors::nil);
            }
        }

        if opts.KeyUsages.Len() == 0 {
            opts.KeyUsages = crate::append!(slice::<ExtKeyUsage>::new(), ExtKeyUsageServerAuth);
        }

        candidateChains = chains;
        chains = slice::new();

        let mut incompatibleKeyUsageChains: int = 0;
        for (_, candidate) in crate::range!(candidateChains.clone()) {
            if !checkChainForKeyUsage(&candidate, &opts.KeyUsages) {
                incompatibleKeyUsageChains += 1;
                continue;
            }
            chains = crate::append!(chains, candidate);
        }

        if chains.Len() == 0 {
            let mut details: slice<string> = slice::new();
            if incompatibleKeyUsageChains > 0 {
                if invalidPoliciesChains == 0 {
                    return (
                        slice::new(),
                        CertificateInvalidError {
                            Cert: self.clone(),
                            Reason: IncompatibleUsage,
                            Detail: string::new(),
                        }
                        .into(),
                    );
                }
                details = crate::append!(
                    details,
                    crate::fmt::Sprintf!(
                        "%d chains with incompatible key usage",
                        incompatibleKeyUsageChains
                    )
                );
            }
            if invalidPoliciesChains > 0 {
                details = crate::append!(
                    details,
                    crate::fmt::Sprintf!("%d chains with invalid policies", invalidPoliciesChains)
                );
            }
            let err: error = CertificateInvalidError {
                Cert: self.clone(),
                Reason: NoValidChains,
                Detail: strings::Join(details, ", "),
            }
            .into();
            return (slice::new(), err);
        }

        return (chains, errors::nil);
    }
}

// go: sdk 1.25.5 crypto/x509/verify.go:942-947 appendToFreshChain
pub(super) fn appendToFreshChain(
    chain: &slice<Certificate>,
    cert: &Certificate,
) -> slice<Certificate> {
    let mut n: Vec<Certificate> = Vec::with_capacity((chain.Len() + 1) as usize);
    for (_, c) in crate::range!(chain.clone()) {
        n.push(c.clone());
    }
    n.push(cert.clone());
    return slice::__from_vec(n);
}

// go: sdk 1.25.5 crypto/x509/verify.go:949-994 alreadyInChain
/// Check whether a candidate certificate is present in a chain. Rather
/// than doing a direct byte for byte equivalency check, we check if the
/// subject, public key, and SAN, if present, are equal. This prevents
/// loops that are created by mutual cross-signatures, or other
/// cross-signature bridge oddities.
///
/// Go declares a local `type pubKeyEqual interface { Equal(...) bool }`
/// that it never uses; goish drops the dead declaration.
pub(super) fn alreadyInChain(candidate: &Certificate, chain: &slice<Certificate>) -> bool {
    let mut candidateSAN: Option<crate::crypto::x509::pkix::Extension> = None;
    for (_, ext) in crate::range!(candidate.Extensions.clone()) {
        if ext.Id.Equal(&super::x509::oidExtensionSubjectAltName()) {
            candidateSAN = Some(ext.clone());
            break;
        }
    }

    for (_, cert) in crate::range!(chain.clone()) {
        if !crate::bytes::Equal(candidate.RawSubject.clone(), cert.RawSubject.clone()) {
            continue;
        }
        // We enforce the canonical encoding of SPKI (by only allowing the
        // correct AI paremeter encodings in parseCertificate), so it's safe to
        // directly compare the raw bytes.
        if !crate::bytes::Equal(
            candidate.RawSubjectPublicKeyInfo.clone(),
            cert.RawSubjectPublicKeyInfo.clone(),
        ) {
            continue;
        }
        let mut certSAN: Option<crate::crypto::x509::pkix::Extension> = None;
        for (_, ext) in crate::range!(cert.Extensions.clone()) {
            if ext.Id.Equal(&super::x509::oidExtensionSubjectAltName()) {
                certSAN = Some(ext.clone());
                break;
            }
        }
        if candidateSAN.is_none() && certSAN.is_none() {
            return true;
        } else if candidateSAN.is_none() || certSAN.is_none() {
            return false;
        }
        if crate::bytes::Equal(
            candidateSAN.as_ref().unwrap().Value.clone(),
            certSAN.as_ref().unwrap().Value.clone(),
        ) {
            return true;
        }
    }
    return false;
}

// Go: verify.go:996-1000
/// The maximum number of CheckSignatureFrom calls that an invocation of
/// buildChains will (transitively) make. Most chains are less than 15
/// certificates long, so this leaves space for multiple chains and for
/// failed checks due to different intermediates having the same Subject.
pub(super) const maxChainSignatureChecks: int = 100;

impl Certificate {
    // go: none — goish idiom: Go writes `considerCandidate` as an
    // anonymous closure inside `buildChains` that captures `chains`,
    // `err`, `hintErr`, `hintCert` and `sigChecks` by reference. Rust
    // cannot both capture those mutably and recurse through them, so the
    // body is a named private helper taking the same state as `&mut`
    // parameters. Body and ordering are verbatim.
    #[allow(clippy::too_many_arguments)]
    fn considerCandidate(
        &self,
        certType: int,
        candidate: &potentialParent,
        currentChain: &slice<Certificate>,
        sigChecks: &mut int,
        opts: &VerifyOptions,
        chains: &mut slice<slice<Certificate>>,
        hintErr: &mut error,
        hintCert: &mut Certificate,
        err: &mut error,
    ) {
        if candidate.cert.PublicKey == crate::nil || alreadyInChain(&candidate.cert, currentChain) {
            return;
        }

        *sigChecks += 1;
        if *sigChecks > maxChainSignatureChecks {
            *err = errors::New(
                "x509: signature check attempts limit reached while verifying certificate chain",
            );
            return;
        }

        let e = self.CheckSignatureFrom(&candidate.cert);
        if e != crate::nil {
            if *hintErr == crate::nil {
                *hintErr = e;
                *hintCert = candidate.cert.clone();
            }
            return;
        }

        *err = candidate.cert.isValid(certType, currentChain, opts);
        if *err != crate::nil {
            if *hintErr == crate::nil {
                *hintErr = err.clone();
                *hintCert = candidate.cert.clone();
            }
            return;
        }

        // Go tests `candidate.constraint != nil` here; cert_pool.rs does
        // not carry the per-cert constraint closure, so the branch has
        // nothing to test. See the banner.

        if certType == rootCertificate {
            *chains = crate::append!(
                chains.clone(),
                appendToFreshChain(currentChain, &candidate.cert)
            );
        } else if certType == intermediateCertificate {
            let (childChains, e) = candidate.cert.buildChains(
                &appendToFreshChain(currentChain, &candidate.cert),
                sigChecks,
                opts,
            );
            *err = e;
            for (_, cc) in crate::range!(childChains) {
                *chains = crate::append!(chains.clone(), cc);
            }
        }
    }

    // go: sdk 1.25.5 crypto/x509/verify.go:1002-1074 Certificate.buildChains
    /// Go's `sigChecks *int` is lazily `new(int)`-allocated; goish threads
    /// a `&mut int` that starts at zero, which counts identically.
    pub(super) fn buildChains(
        &self,
        currentChain: &slice<Certificate>,
        sigChecks: &mut int,
        opts: &VerifyOptions,
    ) -> (slice<slice<Certificate>>, error) {
        let mut hintErr: error = errors::nil;
        let mut hintCert = Certificate::default();
        let mut chains: slice<slice<Certificate>> = slice::new();
        let mut err: error = errors::nil;

        let rootParents = match &opts.Roots {
            Some(p) => p.findPotentialParents(self),
            None => slice::new(),
        };
        for (_, root) in crate::range!(rootParents) {
            self.considerCandidate(
                rootCertificate,
                &root,
                currentChain,
                sigChecks,
                opts,
                &mut chains,
                &mut hintErr,
                &mut hintCert,
                &mut err,
            );
        }
        let intermediateParents = match &opts.Intermediates {
            Some(p) => p.findPotentialParents(self),
            None => slice::new(),
        };
        for (_, intermediate) in crate::range!(intermediateParents) {
            self.considerCandidate(
                intermediateCertificate,
                &intermediate,
                currentChain,
                sigChecks,
                opts,
                &mut chains,
                &mut hintErr,
                &mut hintCert,
                &mut err,
            );
        }

        if chains.Len() > 0 {
            err = errors::nil;
        }
        if chains.Len() == 0 && err == crate::nil {
            err = UnknownAuthorityError {
                Cert: self.clone(),
                hintErr: hintErr,
                hintCert: hintCert,
            }
            .into();
        }

        return (chains, err);
    }
}

// go: sdk 1.25.5 crypto/x509/verify.go:1076-1076 validHostnamePattern
pub(super) fn validHostnamePattern(host: &string) -> bool {
    return validHostname(host, true);
}

// go: sdk 1.25.5 crypto/x509/verify.go:1077-1077 validHostnameInput
pub(super) fn validHostnameInput(host: &string) -> bool {
    return validHostname(host, false);
}

// go: sdk 1.25.5 crypto/x509/verify.go:1079-1129 validHostname
/// Report whether host is a valid hostname that can be matched or matched
/// against according to RFC 6125 2.2, with some leniency to accommodate
/// legacy values.
pub(super) fn validHostname(host: &string, isPattern: bool) -> bool {
    let mut host = host.clone();
    if !isPattern {
        host = strings::TrimSuffix(host, ".");
    }
    if host.Len() == 0 {
        return false;
    }
    if host == string::from("*") {
        // Bare wildcards are not allowed, they are not valid DNS names,
        // nor are they allowed per RFC 6125.
        return false;
    }

    for (i, part) in crate::range!(strings::Split(host, ".")) {
        if part.Len() == 0 {
            // Empty label.
            return false;
        }
        if isPattern && i == 0 && part == string::from("*") {
            // Only allow full left-most wildcards, as those are the only ones
            // we match, and matching literal '*' characters is probably never
            // the expected behavior.
            continue;
        }
        for (j, c) in crate::range!(part) {
            if rune(b'a') <= c && c <= rune(b'z') {
                continue;
            }
            if rune(b'0') <= c && c <= rune(b'9') {
                continue;
            }
            if rune(b'A') <= c && c <= rune(b'Z') {
                continue;
            }
            if c == rune(b'-') && j != 0 {
                continue;
            }
            if c == rune(b'_') {
                // Not a valid character in hostnames, but commonly
                // found in deployments outside the WebPKI.
                continue;
            }
            return false;
        }
    }

    return true;
}

// go: sdk 1.25.5 crypto/x509/verify.go:1131-1136 matchExactly
pub(super) fn matchExactly(hostA: &string, hostB: &string) -> bool {
    if hostA.Len() == 0
        || hostA == &string::from(".")
        || hostB.Len() == 0
        || hostB == &string::from(".")
    {
        return false;
    }
    return toLowerCaseASCII(hostA) == toLowerCaseASCII(hostB);
}

// go: sdk 1.25.5 crypto/x509/verify.go:1138-1163 matchHostnames
pub(super) fn matchHostnames(pattern: &string, host: &string) -> bool {
    let pattern = toLowerCaseASCII(pattern);
    let host = toLowerCaseASCII(&strings::TrimSuffix(host.clone(), "."));

    if pattern.Len() == 0 || host.Len() == 0 {
        return false;
    }

    let patternParts = strings::Split(pattern, ".");
    let hostParts = strings::Split(host, ".");

    if patternParts.Len() != hostParts.Len() {
        return false;
    }

    for (i, patternPart) in crate::range!(patternParts.clone()) {
        if i == 0 && patternPart == string::from("*") {
            continue;
        }
        if patternPart != hostParts[i] {
            return false;
        }
    }

    return true;
}

// go: sdk 1.25.5 crypto/x509/verify.go:1165-1195 toLowerCaseASCII
/// Return a lower-case version of in. See RFC 6125 6.4.1. We use an
/// explicitly ASCII function to avoid any sharp corners resulting from
/// performing Unicode operations on DNS labels.
pub(super) fn toLowerCaseASCII(in_: &string) -> string {
    // If the string is already lower-case then there's nothing to do.
    let mut isAlreadyLowerCase = true;
    for (_, c) in crate::range!(in_) {
        if c == utf8::RuneError {
            // If we get a UTF-8 error then there might be
            // upper-case ASCII bytes in the invalid sequence.
            isAlreadyLowerCase = false;
            break;
        }
        if rune(b'A') <= c && c <= rune(b'Z') {
            isAlreadyLowerCase = false;
            break;
        }
    }

    if isAlreadyLowerCase {
        return in_.clone();
    }

    let mut out = in_.as_bytes().to_vec();
    for i in 0..out.len() {
        let c = out[i];
        if b'A' <= c && c <= b'Z' {
            out[i] += b'a' - b'A';
        }
    }
    return string::from_bytes(&out);
}

impl Certificate {
    // go: sdk 1.25.5 crypto/x509/verify.go:1197-1244 Certificate.VerifyHostname
    /// Return nil if c is a valid certificate for the named host.
    /// Otherwise it returns an error describing the mismatch.
    ///
    /// IP addresses can be optionally enclosed in square brackets and are
    /// checked against the IPAddresses field. Other names are checked case
    /// insensitively against the DNSNames field. If the names are valid
    /// hostnames, the certificate fields can have a wildcard as the
    /// complete left-most label (e.g. *.example.com).
    ///
    /// Note that the legacy Common Name field is ignored.
    pub fn VerifyHostname<H: Into<string>>(&self, h: H) -> error {
        let h: string = h.into();
        // IP addresses may be written in [ ].
        let mut candidateIP = h.clone();
        let hb = h.as_bytes();
        if hb.len() >= 3 && hb[0] == b'[' && hb[hb.len() - 1] == b']' {
            candidateIP = string::from_bytes(&hb[1..hb.len() - 1]);
        }
        let ip = net::ParseIP(candidateIP.clone());
        if !ip.IsNil() {
            // We only match IP addresses against IP SANs.
            // See RFC 6125, Appendix B.2.
            for (_, candidate) in crate::range!(self.IPAddresses.clone()) {
                if ip.Equal(&candidate) {
                    return errors::nil;
                }
            }
            return HostnameError {
                Certificate: self.clone(),
                Host: candidateIP,
            }
            .into();
        }

        // Save allocations inside the loop.
        let candidateName = toLowerCaseASCII(&h);
        let validCandidateName = validHostnameInput(&candidateName);

        for (_, m) in crate::range!(self.DNSNames.clone()) {
            // Ideally, we'd only match valid hostnames according to RFC 6125 like
            // browsers (more or less) do, but in practice Go is used in a wider
            // array of contexts and can't even assume DNS resolution. Instead,
            // always allow perfect matches, and only apply wildcard and trailing
            // dot processing to valid hostnames.
            if validCandidateName && validHostnamePattern(&m) {
                if matchHostnames(&m, &candidateName) {
                    return errors::nil;
                }
            } else if matchExactly(&m, &candidateName) {
                return errors::nil;
            }
        }

        return HostnameError {
            Certificate: self.clone(),
            Host: h,
        }
        .into();
    }
}

// go: sdk 1.25.5 crypto/x509/verify.go:1246-1298 checkChainForKeyUsage
/// Go's two labelled `continue`s (`NextCert`, `NextRequestedUsage`)
/// become boolean flags; the walk order and the crossing-out are
/// unchanged.
pub(super) fn checkChainForKeyUsage(
    chain: &slice<Certificate>,
    keyUsages: &slice<ExtKeyUsage>,
) -> bool {
    let mut usages = keyUsages.clone();

    if chain.Len() == 0 {
        return false;
    }

    let mut usagesRemaining = usages.Len();

    // We walk down the list and cross out any usages that aren't supported
    // by each certificate. If we cross out all the usages, then the chain
    // is unacceptable.

    let mut i = chain.Len() - 1;
    while i >= 0 {
        let cert = chain[i].clone();
        i -= 1;
        if cert.ExtKeyUsage.Len() == 0 && cert.UnknownExtKeyUsage.Len() == 0 {
            // The certificate doesn't have any extended key usage specified.
            continue;
        }

        let mut anyUsage = false;
        for (_, usage) in crate::range!(cert.ExtKeyUsage.clone()) {
            if *usage == ExtKeyUsageAny {
                // The certificate is explicitly good for any usage.
                anyUsage = true;
                break;
            }
        }
        if anyUsage {
            continue;
        }

        const invalidUsage: ExtKeyUsage = ExtKeyUsage(-1);

        let mut j: int = 0;
        while j < usages.Len() {
            let requestedUsage = usages[j];
            let k = j;
            j += 1;
            if requestedUsage == invalidUsage {
                continue;
            }

            let mut supported = false;
            for (_, usage) in crate::range!(cert.ExtKeyUsage.clone()) {
                if requestedUsage == *usage {
                    supported = true;
                    break;
                }
            }
            if supported {
                continue;
            }

            usages[k] = invalidUsage;
            usagesRemaining -= 1;
            if usagesRemaining == 0 {
                return false;
            }
        }
    }

    return true;
}

// go: sdk 1.25.5 crypto/x509/verify.go:1300-1306 mustNewOIDFromInts
pub(super) fn mustNewOIDFromInts(ints: slice<u64>) -> OID {
    let (oid, err) = OIDFromInts(ints.clone());
    if err != crate::nil {
        panic!("OIDFromInts unexpected error");
    }
    return oid;
}

// Go: verify.go:1308-1315
/// A node of the RFC 5280 policy graph.
///
/// Go links `parents` / `children` with `map[*policyGraphNode]bool` —
/// GC pointer identity. goish stores every node in one arena on the
/// graph and links them by arena index. See the banner.
#[derive(Clone, Default)]
pub(super) struct policyGraphNode {
    pub validPolicy: OID,
    pub expectedPolicySet: slice<OID>,
    // we do not implement qualifiers, so we don't track qualifier_set
    pub parents: map<int, bool>,
    pub children: map<int, bool>,
}

// Go: verify.go:1331-1336
pub(super) struct policyGraph {
    // go: none — goish idiom: the arena Go does not need. See the banner.
    pub nodes: Vec<policyGraphNode>,
    pub strata: Vec<map<string, int>>,
    /// map of OID -> nodes at strata[depth-1] with OID in their
    /// expectedPolicySet
    pub parentIndex: map<string, slice<int>>,
    pub depth: int,
}

// go: none — goish idiom: Go declares `var anyPolicyOID = mustNewOIDFromInts(...)`
// at verify.go:1338; goish has no const heap value, so it is a function.
// Same name, same value.
pub(super) fn anyPolicyOID() -> OID {
    return mustNewOIDFromInts(slice::__from_vec(alloc::vec![2u64, 5, 29, 32, 0]));
}

// go: none — goish idiom: `string(oid.der)` in Go is a map key built
// from the DER bytes; goish spells the same conversion once.
fn derKey(o: &OID) -> string {
    return string::from_bytes(&o.der);
}

// go: sdk 1.25.5 crypto/x509/verify.go:1317-1329 newPolicyGraphNode
/// Go returns `*policyGraphNode`; goish allocates into `pg`'s arena and
/// returns the index. That is why the graph is a parameter here and is
/// not in Go. See the banner.
pub(super) fn newPolicyGraphNode(pg: &mut policyGraph, valid: OID, parents: &slice<int>) -> int {
    let mut expected: slice<OID> = slice::new();
    expected = crate::append!(expected, valid.clone());
    let n = policyGraphNode {
        validPolicy: valid,
        expectedPolicySet: expected,
        children: map::new(),
        parents: map::new(),
    };
    pg.nodes.push(n);
    let id = int(pg.nodes.len() - 1);
    for (_, p) in crate::range!(parents.clone()) {
        let p = *p;
        pg.nodes[p as usize].children.Set(id, true);
        pg.nodes[id as usize].parents.Set(p, true);
    }
    return id;
}

// go: sdk 1.25.5 crypto/x509/verify.go:1340-1351 newPolicyGraph
pub(super) fn newPolicyGraph() -> policyGraph {
    let any = anyPolicyOID();
    let mut expected: slice<OID> = slice::new();
    expected = crate::append!(expected, any.clone());
    let root = policyGraphNode {
        validPolicy: any.clone(),
        expectedPolicySet: expected,
        children: map::new(),
        parents: map::new(),
    };
    let mut stratum0: map<string, int> = map::new();
    stratum0.Set(derKey(&any), 0);
    return policyGraph {
        nodes: alloc::vec![root],
        strata: alloc::vec![stratum0],
        parentIndex: map::new(),
        depth: 0,
    };
}

impl policyGraph {
    // go: sdk 1.25.5 crypto/x509/verify.go:1353-1355 policyGraph.insert
    pub(super) fn insert(&mut self, n: int) {
        let k = derKey(&self.nodes[n as usize].validPolicy);
        let d = self.depth as usize;
        self.strata[d].Set(k, n);
    }

    // go: sdk 1.25.5 crypto/x509/verify.go:1357-1362 policyGraph.parentsWithExpected
    pub(super) fn parentsWithExpected(&self, expected: &OID) -> slice<int> {
        if self.depth == 0 {
            return slice::new();
        }
        let (v, _) = self.parentIndex.Get(derKey(expected));
        return v;
    }

    // go: sdk 1.25.5 crypto/x509/verify.go:1364-1369 policyGraph.parentWithAnyPolicy
    /// Go returns a nil `*policyGraphNode` when there is none; goish
    /// returns `-1`, the arena's out-of-band index.
    pub(super) fn parentWithAnyPolicy(&self) -> int {
        if self.depth == 0 {
            return -1;
        }
        let (v, ok) = self.strata[(self.depth - 1) as usize].Get(derKey(&anyPolicyOID()));
        if !ok {
            return -1;
        }
        return v;
    }

    // go: sdk 1.25.5 crypto/x509/verify.go:1371-1376 policyGraph.parents
    /// Go returns `iter.Seq[*policyGraphNode]` via `maps.Values`; goish's
    /// `iter` package is unported, so this materialises the same elements
    /// into a slice of arena indices. See the banner.
    pub(super) fn parents(&self) -> slice<int> {
        if self.depth == 0 {
            return slice::new();
        }
        let mut out: slice<int> = slice::new();
        for (_, v) in crate::range!(self.strata[(self.depth - 1) as usize].clone()) {
            out = crate::append!(out, *v);
        }
        return out;
    }

    // go: sdk 1.25.5 crypto/x509/verify.go:1378-1380 policyGraph.leaves
    pub(super) fn leaves(&self) -> map<string, int> {
        return self.strata[self.depth as usize].clone();
    }

    // go: sdk 1.25.5 crypto/x509/verify.go:1382-1384 policyGraph.leafWithPolicy
    /// Go returns a nil `*policyGraphNode` when there is none; goish
    /// returns `-1`.
    pub(super) fn leafWithPolicy(&self, policy: &OID) -> int {
        let (v, ok) = self.strata[self.depth as usize].Get(derKey(policy));
        if !ok {
            return -1;
        }
        return v;
    }

    // go: sdk 1.25.5 crypto/x509/verify.go:1386-1398 policyGraph.deleteLeaf
    pub(super) fn deleteLeaf(&mut self, policy: &OID) {
        let key = derKey(policy);
        let (n, ok) = self.strata[self.depth as usize].Get(key.clone());
        if !ok {
            return;
        }
        let parents = self.nodes[n as usize].parents.clone();
        for (p, _) in crate::range!(parents) {
            let p = *p;
            self.nodes[p as usize].children.Delete(n);
        }
        let children = self.nodes[n as usize].children.clone();
        for (c, _) in crate::range!(children) {
            let c = *c;
            self.nodes[c as usize].parents.Delete(n);
        }
        let d = self.depth as usize;
        self.strata[d].Delete(key);
    }

    // go: sdk 1.25.5 crypto/x509/verify.go:1400-1418 policyGraph.validPolicyNodes
    pub(super) fn validPolicyNodes(&self) -> slice<int> {
        let any = anyPolicyOID();
        let mut validNodes: slice<int> = slice::new();
        let mut i = self.depth;
        while i >= 0 {
            for (_, n) in crate::range!(self.strata[i as usize].clone()) {
                let n = *n;
                if self.nodes[n as usize].validPolicy.Equal(&any) {
                    continue;
                }

                if self.nodes[n as usize].parents.Len() == 1 {
                    for (p, _) in crate::range!(self.nodes[n as usize].parents.clone()) {
                        let p = *p;
                        if self.nodes[p as usize].validPolicy.Equal(&any) {
                            validNodes = crate::append!(validNodes, n);
                        }
                    }
                }
            }
            i -= 1;
        }
        return validNodes;
    }

    // go: sdk 1.25.5 crypto/x509/verify.go:1420-1431 policyGraph.prune
    pub(super) fn prune(&mut self) {
        let mut i = self.depth - 1;
        while i > 0 {
            // Go deletes from the map it is ranging over, which Go
            // permits; goish snapshots the entries first.
            let stratum = self.strata[i as usize].clone();
            for (_, n) in crate::range!(stratum) {
                let n = *n;
                if self.nodes[n as usize].children.Len() == 0 {
                    let parents = self.nodes[n as usize].parents.clone();
                    for (p, _) in crate::range!(parents) {
                        self.nodes[*p as usize].children.Delete(n);
                    }
                    let k = derKey(&self.nodes[n as usize].validPolicy);
                    self.strata[i as usize].Delete(k);
                }
            }
            i -= 1;
        }
    }

    // go: sdk 1.25.5 crypto/x509/verify.go:1433-1443 policyGraph.incrDepth
    pub(super) fn incrDepth(&mut self) {
        self.parentIndex = map::new();
        let stratum = self.strata[self.depth as usize].clone();
        for (_, n) in crate::range!(stratum) {
            let n = *n;
            for (_, e) in crate::range!(self.nodes[n as usize].expectedPolicySet.clone()) {
                let k = derKey(&e);
                let (cur, _) = self.parentIndex.Get(k.clone());
                self.parentIndex.Set(k, crate::append!(cur, n));
            }
        }

        self.depth += 1;
        self.strata.push(map::new());
    }
}

// go: sdk 1.25.5 crypto/x509/verify.go:1445-1664 policiesValid
/// Go passes `opts VerifyOptions` by value; goish takes it by reference,
/// which the body never mutates either way.
pub(super) fn policiesValid(chain: &slice<Certificate>, opts: &VerifyOptions) -> bool {
    // The following code implements the policy verification algorithm as
    // specified in RFC 5280 and updated by RFC 9618. In particular the
    // following sections are replaced by RFC 9618:
    //	* 6.1.2 (a)
    //	* 6.1.3 (d)
    //	* 6.1.3 (e)
    //	* 6.1.3 (f)
    //	* 6.1.4 (b)
    //	* 6.1.5 (g)

    if chain.Len() == 1 {
        return true;
    }

    let any = anyPolicyOID();
    let anyKey = derKey(&any);

    // n is the length of the chain minus the trust anchor
    let n = chain.Len() - 1;

    // Go sets `pg = nil` to mean "the graph is gone"; goish keeps the
    // value in an Option for the same reason.
    let mut pg: Option<policyGraph> = Some(newPolicyGraph());
    let mut inhibitAnyPolicy: int = 0;
    let mut explicitPolicy: int = 0;
    let mut policyMapping: int = 0;
    if !opts.inhibitAnyPolicy {
        inhibitAnyPolicy = n + 1;
    }
    if !opts.requireExplicitPolicy {
        explicitPolicy = n + 1;
    }
    if !opts.inhibitPolicyMapping {
        policyMapping = n + 1;
    }

    let mut initialUserPolicySet: map<string, bool> = map::new();
    for (_, p) in crate::range!(opts.CertificatePolicies.clone()) {
        initialUserPolicySet.Set(derKey(&p), true);
    }
    // If the user does not pass any policies, we consider
    // that equivalent to passing anyPolicyOID.
    if initialUserPolicySet.Len() == 0 {
        initialUserPolicySet.Set(anyKey.clone(), true);
    }

    let mut i = n - 1;
    while i >= 0 {
        let cert = chain[i].clone();

        let isSelfSigned = crate::bytes::Equal(cert.RawIssuer.clone(), cert.RawSubject.clone());

        // 6.1.3 (e) -- as updated by RFC 9618
        if cert.Policies.Len() == 0 {
            pg = None;
        }

        // 6.1.3 (f) -- as updated by RFC 9618
        if explicitPolicy == 0 && pg.is_none() {
            return false;
        }

        if let Some(g) = pg.as_mut() {
            g.incrDepth();

            let mut policies: map<string, bool> = map::new();

            // 6.1.3 (d) (1) -- as updated by RFC 9618
            for (_, policy) in crate::range!(cert.Policies.clone()) {
                policies.Set(derKey(&policy), true);

                if policy.Equal(&any) {
                    continue;
                }

                // 6.1.3 (d) (1) (i) -- as updated by RFC 9618
                let mut parents = g.parentsWithExpected(&policy);
                if parents.Len() == 0 {
                    // 6.1.3 (d) (1) (ii) -- as updated by RFC 9618
                    let anyParent = g.parentWithAnyPolicy();
                    if anyParent != -1 {
                        parents = crate::append!(slice::<int>::new(), anyParent);
                    }
                }
                if parents.Len() > 0 {
                    let node = newPolicyGraphNode(g, policy.clone(), &parents);
                    g.insert(node);
                }
            }

            // 6.1.3 (d) (2) -- as updated by RFC 9618
            // NOTE: in the check "n-i < n" our i is different from the i in the specification.
            // In the specification chains go from the trust anchor to the leaf, whereas our
            // chains go from the leaf to the trust anchor, so our i's our inverted. Our
            // check here matches the check "i < n" in the specification.
            let (hasAny, _) = policies.Get(anyKey.clone());
            if hasAny && (inhibitAnyPolicy > 0 || (n - i < n && isSelfSigned)) {
                let mut missing: map<string, slice<int>> = map::new();
                let leaves = g.leaves();
                for (_, p) in crate::range!(g.parents()) {
                    let p = *p;
                    for (_, expected) in
                        crate::range!(g.nodes[p as usize].expectedPolicySet.clone())
                    {
                        let k = derKey(&expected);
                        let (_, present) = leaves.Get(k.clone());
                        if !present {
                            let (cur, _) = missing.Get(k.clone());
                            missing.Set(k, crate::append!(cur, p));
                        }
                    }
                }

                for (oidStr, parents) in crate::range!(missing) {
                    let node = newPolicyGraphNode(
                        g,
                        OID {
                            der: crate::convert::bytes(oidStr.clone()),
                        },
                        &parents,
                    );
                    g.insert(node);
                }
            }

            // 6.1.3 (d) (3) -- as updated by RFC 9618
            g.prune();

            if i != 0 {
                // 6.1.4 (b) -- as updated by RFC 9618
                if cert.PolicyMappings.Len() > 0 {
                    // collect map of issuer -> []subject
                    let mut mappings: map<string, slice<OID>> = map::new();

                    for (_, mapping) in crate::range!(cert.PolicyMappings.clone()) {
                        if policyMapping > 0 {
                            if mapping.IssuerDomainPolicy.Equal(&any)
                                || mapping.SubjectDomainPolicy.Equal(&any)
                            {
                                // Invalid mapping
                                return false;
                            }
                            let k = derKey(&mapping.IssuerDomainPolicy);
                            let (cur, _) = mappings.Get(k.clone());
                            mappings
                                .Set(k, crate::append!(cur, mapping.SubjectDomainPolicy.clone()));
                        } else {
                            // 6.1.4 (b) (3) (i) -- as updated by RFC 9618
                            g.deleteLeaf(&mapping.IssuerDomainPolicy);

                            // 6.1.4 (b) (3) (ii) -- as updated by RFC 9618
                            g.prune();
                        }
                    }

                    for (issuerStr, subjectPolicies) in crate::range!(mappings) {
                        let issuerOID = OID {
                            der: crate::convert::bytes(issuerStr.clone()),
                        };
                        // 6.1.4 (b) (1) -- as updated by RFC 9618
                        let matching = g.leafWithPolicy(&issuerOID);
                        if matching != -1 {
                            g.nodes[matching as usize].expectedPolicySet = subjectPolicies.clone();
                        } else {
                            let matching = g.leafWithPolicy(&any);
                            if matching != -1 {
                                // 6.1.4 (b) (2) -- as updated by RFC 9618
                                let parents = crate::append!(slice::<int>::new(), matching);
                                let node = newPolicyGraphNode(g, issuerOID, &parents);
                                g.nodes[node as usize].expectedPolicySet = subjectPolicies.clone();
                                g.insert(node);
                            }
                        }
                    }
                }
            }
        }

        if i != 0 {
            // 6.1.4 (h)
            if !isSelfSigned {
                if explicitPolicy > 0 {
                    explicitPolicy -= 1;
                }
                if policyMapping > 0 {
                    policyMapping -= 1;
                }
                if inhibitAnyPolicy > 0 {
                    inhibitAnyPolicy -= 1;
                }
            }

            // 6.1.4 (i)
            if (cert.RequireExplicitPolicy > 0 || cert.RequireExplicitPolicyZero)
                && cert.RequireExplicitPolicy < explicitPolicy
            {
                explicitPolicy = cert.RequireExplicitPolicy;
            }
            if (cert.InhibitPolicyMapping > 0 || cert.InhibitPolicyMappingZero)
                && cert.InhibitPolicyMapping < policyMapping
            {
                policyMapping = cert.InhibitPolicyMapping;
            }
            // 6.1.4 (j)
            if (cert.InhibitAnyPolicy > 0 || cert.InhibitAnyPolicyZero)
                && cert.InhibitAnyPolicy < inhibitAnyPolicy
            {
                inhibitAnyPolicy = cert.InhibitAnyPolicy;
            }
        }

        i -= 1;
    }

    // 6.1.5 (a)
    if explicitPolicy > 0 {
        explicitPolicy -= 1;
    }

    // 6.1.5 (b)
    if chain[int(0)].RequireExplicitPolicyZero {
        explicitPolicy = 0;
    }

    // 6.1.5 (g) (1) -- as updated by RFC 9618
    // Go declares the set here and leaves it nil when `pg` is nil; the
    // zero value is never read on that path, hence the allow.
    #[allow(unused_assignments)]
    let mut validPolicyNodeSet: slice<int> = slice::new();
    // 6.1.5 (g) (2) -- as updated by RFC 9618
    let mut authorityConstrainedPolicySet: map<string, bool> = map::new();
    if let Some(g) = pg.as_ref() {
        validPolicyNodeSet = g.validPolicyNodes();
        // 6.1.5 (g) (3) -- as updated by RFC 9618
        let currentAny = g.leafWithPolicy(&any);
        if currentAny != -1 {
            validPolicyNodeSet = crate::append!(validPolicyNodeSet, currentAny);
        }

        // 6.1.5 (g) (4) -- as updated by RFC 9618
        for (_, n) in crate::range!(validPolicyNodeSet.clone()) {
            authorityConstrainedPolicySet.Set(derKey(&g.nodes[*n as usize].validPolicy), true);
        }
    }
    // 6.1.5 (g) (5) -- as updated by RFC 9618
    let mut userConstrainedPolicySet = authorityConstrainedPolicySet.clone();
    // 6.1.5 (g) (6) -- as updated by RFC 9618
    let (userHasAny, _) = initialUserPolicySet.Get(anyKey.clone());
    if initialUserPolicySet.Len() != 1 || !userHasAny {
        // 6.1.5 (g) (6) (i) -- as updated by RFC 9618
        for (p, _) in crate::range!(userConstrainedPolicySet.clone()) {
            let (allowed, _) = initialUserPolicySet.Get(p.clone());
            if !allowed {
                userConstrainedPolicySet.Delete(p);
            }
        }
        // 6.1.5 (g) (6) (ii) -- as updated by RFC 9618
        let (authAny, _) = authorityConstrainedPolicySet.Get(anyKey.clone());
        if authAny {
            for (policy, _) in crate::range!(initialUserPolicySet.clone()) {
                userConstrainedPolicySet.Set(policy, true);
            }
        }
    }

    if explicitPolicy == 0 && userConstrainedPolicySet.Len() == 0 {
        return false;
    }

    return true;
}
