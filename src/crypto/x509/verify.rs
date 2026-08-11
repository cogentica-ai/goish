// go: file crypto/x509/verify.go decls: parseRFC2821Mailbox, domainToReverseLabels
//
// **Two functions of verify.go, and nothing else.** Chain building and
// name-constraint *checking* are out of reach: `verify.go` imports
// `net/netip`, which goish does not have. What is here is the pair
// `parser.go`'s `parseNameConstraintsExtension` calls — pure string
// parsing with no netip in sight — so that the name-constraints branch
// of `processExtensions` can be a verbatim port instead of a hole.
//
// Everything else in verify.go is absent, not stubbed.
//
// goishlint:ignore GOISH018 Error, Unwrap, matchEmailConstraint, matchURIConstraint, matchIPConstraint, matchDomainConstraint, checkNameConstraints, isValid, Verify, appendToFreshChain, alreadyInChain, buildChains, validHostnamePattern, validHostnameInput, validHostname, matchExactly, matchHostnames, toLowerCaseASCII, VerifyHostname, checkChainForKeyUsage, mustNewOIDFromInts, newPolicyGraphNode, newPolicyGraph, insert, parentsWithExpected, parentWithAnyPolicy, parents, leaves, leafWithPolicy, deleteLeaf, validPolicyNodes, prune, incrDepth, policiesValid — blocked on net/netip; see the banner.
// goishlint:ignore GOISH019 CertificateInvalidError, HostnameError, UnknownAuthorityError, SystemRootsError, VerifyOptions, policyGraphNode, policyGraph — types of the unported remainder.
// goishlint:ignore GOISH021 CertificateInvalidError, HostnameError, UnknownAuthorityError, SystemRootsError, VerifyOptions, policyGraphNode, policyGraph, InvalidReason, NotAuthorizedToSign, Expired, CANotAuthorizedForThisName, TooManyIntermediates, IncompatibleUsage, NameMismatch, NameConstraintsWithoutSANs, UnconstrainedName, TooManyConstraints, CANotAuthorizedForExtKeyUsage, NoValidChains, errNotParsed, maxChainSignatureChecks, maxConstraintComparisons, anyPolicyOID, rfc2821Mailbox, leafCertificate, intermediateCertificate, rootCertificate — consts, vars and types of the unported remainder.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::goslice::slice;
use crate::gostring::string;
use crate::strings;
use crate::int;
use crate::types::byte;

// Go: verify.go:250-255
//   type rfc2821Mailbox struct { local, domain string }
/// Represents a "mailbox" (which is an email address to most people) by
/// breaking it into the "local" (i.e. before the '@') and "domain" parts.
#[derive(Clone, Default)]
pub(super) struct rfc2821Mailbox {
    pub local: string,
    pub domain: string,
}

// go: sdk 1.25.5 crypto/x509/verify.go:257-386 parseRFC2821Mailbox
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
            || crate::bytes::Contains(
                slice::__from_vec(localPartBytes.clone()),
                twoDots,
            )
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

