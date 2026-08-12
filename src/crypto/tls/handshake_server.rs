// go: file crypto/tls/handshake_server.go decls: supportsECDHE, negotiateALPN, serverHandshakeState.cipherSuiteOk, clientHelloInfo
//
// crypto/tls — the server handshake state machine.
//
// **Partial port.** handshake_server.go is 1000 lines of
// `serverHandshakeState`, which owns a Conn and drives the TLS 1.0-1.2
// handshake. What is here is the one function that does not: the ECDHE
// support check, which `ClientHelloInfo.SupportsCertificate` also calls.
//
// goishlint:ignore GOISH018 serverHandshake, handshake, readClientHello, processClientHello, pickCipherSuite, checkForResumption, doResumeHandshake, doFullHandshake, establishKeys, readFinished, sendSessionTicket, sendFinished, processCertsFromClient — serverHandshakeState and Conn; see the banner. ROADMAP.md.

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


// Go: handshake_server.go:24-40
//   type serverHandshakeState struct { c *Conn; ctx context.Context
//       clientHello *clientHelloMsg; hello *serverHelloMsg
//       suite *cipherSuite; ecdheOk, ecSignOk, rsaDecryptOk, rsaSignOk bool
//       sessionState *SessionState; finishedHash finishedHash
//       masterSecret []byte; cert *Certificate }
/// The TLS 1.0-1.2 server handshake state.
///
/// **Partial record.** Only the fields the ported methods read are
/// present; the key schedule and transcript land with `handshake`,
/// which drives the whole exchange.
pub(crate) struct serverHandshakeState {
    pub c: super::conn::Conn,
    pub ecdheOk: bool,
    pub ecSignOk: bool,
    pub rsaDecryptOk: bool,
    pub rsaSignOk: bool,
}

impl serverHandshakeState {
    // go: sdk 1.25.5 crypto/tls/handshake_server.go:441-460 serverHandshakeState.cipherSuiteOk
    /// Whether a candidate suite is usable given what the certificate
    /// and the client's extensions allow. `pickCipherSuite` passes this
    /// to `selectCipherSuite` as its filter.
    pub(crate) fn cipherSuiteOk(&self, c: &super::cipher_suites::cipherSuite) -> bool {
        // Go: if c.flags&suiteECDHE != 0 {
        //         if !hs.ecdheOk { return false }
        //         if c.flags&suiteECSign != 0 {
        //             if !hs.ecSignOk { return false }
        //         } else if !hs.rsaSignOk { return false }
        //     } else if !hs.rsaDecryptOk { return false }
        if c.flags & super::cipher_suites::suiteECDHE != 0 {
            if !self.ecdheOk {
                return false;
            }
            if c.flags & super::cipher_suites::suiteECSign != 0 {
                if !self.ecSignOk {
                    return false;
                }
            } else if !self.rsaSignOk {
                return false;
            }
        } else if !self.rsaDecryptOk {
            return false;
        }
        // Go: if hs.c.vers < VersionTLS12 && c.flags&suiteTLS12 != 0 { return false }
        //     return true
        if self.c.__vers() < super::common::VersionTLS12
            && c.flags & super::cipher_suites::suiteTLS12 != 0
        {
            return false;
        }
        return true;
    }
}

// go: sdk 1.25.5 crypto/tls/handshake_server.go:1002-1021 clientHelloInfo
///
/// Deviations: Go's leading `ctx context.Context` has nowhere to go, and
/// `ClientHelloInfo.Conn` is absent from goish's record — both arrive
/// with the handshake driver.
/// goishlint:ignore GOISH020 clientHelloInfo — Go's context.Context parameter has no field to land in yet
pub(crate) fn clientHelloInfo(
    c: &super::conn::Conn,
    clientHello: &super::handshake_messages::clientHelloMsg,
) -> super::common::ClientHelloInfo {
    // Go: supportedVersions := clientHello.supportedVersions
    //     if len(clientHello.supportedVersions) == 0 {
    //         supportedVersions = supportedVersionsFromMax(clientHello.vers) }
    let supportedVersions = if clientHello.supportedVersions.len() == 0 {
        super::common::supportedVersionsFromMax(clientHello.vers)
    } else {
        slice::__from_vec(clientHello.supportedVersions.clone())
    };

    // Go: return &ClientHelloInfo{ CipherSuites: …, ServerName: …, … }
    let mut chi = super::common::ClientHelloInfo::default();
    chi.CipherSuites = slice::__from_vec(clientHello.cipherSuites.clone());
    chi.ServerName =
        crate::gostring::string::from_bytes(clientHello.serverName.as_bytes());
    chi.SupportedCurves = slice::__from_vec(
        clientHello
            .supportedCurves
            .iter()
            .map(|v| CurveID(*v))
            .collect(),
    );
    chi.SupportedPoints = slice::__from_vec(clientHello.supportedPoints.clone());
    chi.SignatureSchemes = slice::__from_vec(
        clientHello
            .supportedSignatureAlgorithms
            .iter()
            .map(|v| super::common::SignatureScheme(*v))
            .collect(),
    );
    chi.SupportedProtos = slice::__from_vec(
        clientHello
            .alpnProtocols
            .iter()
            .map(|p| crate::gostring::string::from_bytes(p.as_bytes()))
            .collect(),
    );
    chi.SupportedVersions = supportedVersions;
    chi.Extensions = slice::__from_vec(clientHello.extensions.clone());
    chi.__setConfig(c.__config());
    return chi;
}
