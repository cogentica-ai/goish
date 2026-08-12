// go: file crypto/tls/handshake_server.go decls: supportsECDHE, negotiateALPN
//
// crypto/tls — the server handshake state machine.
//
// **Partial port.** handshake_server.go is 1000 lines of
// `serverHandshakeState`, which owns a Conn and drives the TLS 1.0-1.2
// handshake. What is here is the one function that does not: the ECDHE
// support check, which `ClientHelloInfo.SupportsCertificate` also calls.
//
// goishlint:ignore GOISH018 serverHandshake, handshake, readClientHello, processClientHello, pickCipherSuite, cipherSuiteOk, checkForResumption, doResumeHandshake, doFullHandshake, establishKeys, readFinished, sendSessionTicket, sendFinished, processCertsFromClient, clientHelloInfo — serverHandshakeState and Conn; see the banner. ROADMAP.md.
// goishlint:ignore GOISH019 serverHandshakeState — same.
// goishlint:ignore GOISH021 serverHandshakeState — same.

#![allow(non_snake_case, dead_code)]

extern crate alloc;

use super::common::{pointFormatUncompressed, CurveID};
use super::Config;
use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::types::{uint16, uint8};

// go: sdk 1.25.5 crypto/tls/handshake_server.go:243-269 supportsECDHE
/// Go: "supportsECDHE returns whether ECDHE key exchanges can be used
/// with this pre-TLS 1.3 client."
pub(crate) fn supportsECDHE(
    c: &Config,
    version: uint16,
    supportedCurves: slice<CurveID>,
    supportedPoints: slice<uint8>,
) -> (bool, error) {
    // Go: supportsCurve := false
    //     for _, curve := range supportedCurves {
    //         if c.supportsCurve(version, curve) { supportsCurve = true; break } }
    let mut supportsCurve = false;
    for (_, curve) in crate::range!(supportedCurves) {
        if c.supportsCurve(version, *curve) {
            supportsCurve = true;
            break;
        }
    }

    // Go: supportsPointFormat := false
    //     offeredNonCompressedFormat := false
    //     for _, pointFormat := range supportedPoints {
    //         if pointFormat == pointFormatUncompressed { supportsPointFormat = true }
    //         else { offeredNonCompressedFormat = true } }
    let mut supportsPointFormat = false;
    let mut offeredNonCompressedFormat = false;
    for (_, pointFormat) in crate::range!(supportedPoints.clone()) {
        if *pointFormat == pointFormatUncompressed {
            supportsPointFormat = true;
        } else {
            offeredNonCompressedFormat = true;
        }
    }
    // Go: Per RFC 8422, Section 5.1.2, if the Supported Point Formats
    // extension is missing, uncompressed points are supported. If
    // supportedPoints is empty, the extension must be missing, as an
    // empty extension body is rejected by the parser. See
    // https://go.dev/issue/49126.
    if supportedPoints.Len() == 0 {
        supportsPointFormat = true;
    } else if offeredNonCompressedFormat && !supportsPointFormat {
        return (
            false,
            errors::New("tls: client offered only incompatible point formats"),
        );
    }

    // Go: return supportsCurve && supportsPointFormat, nil
    return (supportsCurve && supportsPointFormat, errors::nil);
}

// go: sdk 1.25.5 crypto/tls/handshake_server.go:334-361 negotiateALPN
/// Pick the application protocol both sides offered, in the *server's*
/// preference order.
pub(crate) fn negotiateALPN(
    serverProtos: slice<crate::gostring::string>,
    clientProtos: slice<crate::gostring::string>,
    quic: bool,
) -> (crate::gostring::string, error) {
    // Go: if len(serverProtos) == 0 || len(clientProtos) == 0 {
    //         if quic && len(serverProtos) != 0 {
    //             // RFC 9001, Section 8.1
    //             return "", fmt.Errorf("tls: client did not request an application protocol") }
    //         return "", nil }
    if serverProtos.Len() == 0 || clientProtos.Len() == 0 {
        if quic && serverProtos.Len() != 0 {
            return (
                crate::gostring::string::from_static(""),
                errors::New("tls: client did not request an application protocol"),
            );
        }
        return (crate::gostring::string::from_static(""), errors::nil);
    }
    // Go: var http11fallback bool
    //     for _, s := range serverProtos {
    //         for _, c := range clientProtos {
    //             if s == c { return s, nil }
    //             if s == "h2" && c == "http/1.1" { http11fallback = true } } }
    let mut http11fallback = false;
    for (_, sp) in crate::range!(serverProtos.clone()) {
        for (_, cp) in crate::range!(clientProtos.clone()) {
            if *sp == *cp {
                return (sp.clone(), errors::nil);
            }
            if *sp == crate::gostring::string::from_static("h2")
                && *cp == crate::gostring::string::from_static("http/1.1")
            {
                http11fallback = true;
            }
        }
    }
    // Go: As a special case, let http/1.1 clients connect to h2 servers as
    // if they didn't support ALPN. We used not to enforce protocol overlap,
    // so over time a number of HTTP servers were configured with only "h2",
    // but expected to accept connections from "http/1.1" clients. See Issue
    // 46310.
    if http11fallback {
        return (crate::gostring::string::from_static(""), errors::nil);
    }
    // Go: return "", fmt.Errorf("tls: client requested unsupported
    //     application protocols (%q)", clientProtos)
    let mut list = crate::gostring::string::from_static("[");
    for (i, cp) in crate::range!(clientProtos) {
        if i > 0 {
            list = list + crate::gostring::string::from_static(" ");
        }
        list = list
            + crate::gostring::string::from_static("\"")
            + cp.clone()
            + crate::gostring::string::from_static("\"");
    }
    list = list + crate::gostring::string::from_static("]");
    return (
        crate::gostring::string::from_static(""),
        crate::fmt::Errorf!(
            "tls: client requested unsupported application protocols (%s)",
            list
        ),
    );
}
