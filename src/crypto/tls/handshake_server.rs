// go: file crypto/tls/handshake_server.go decls: supportsECDHE, negotiateALPN, serverHandshakeState.cipherSuiteOk, clientHelloInfo, serverHandshakeState.pickCipherSuite, serverHandshakeState.establishKeys, serverHandshakeState.checkForResumption, serverHandshakeState.readFinished, serverHandshakeState.sendFinished, Conn.processCertsFromClient, serverHandshakeState.handshake, serverHandshakeState.processClientHello, serverHandshakeState.doResumeHandshake, serverHandshakeState.doFullHandshake, serverHandshakeState.sendSessionTicket, Conn.serverHandshake, Conn.readClientHello
//
// crypto/tls — the server handshake state machine.
//
// This banner said, until 2026-09-06: "**Partial port.**
// handshake_server.go is 1000 lines of `serverHandshakeState` … What is
// here is the one function that does not [own a Conn]: the ECDHE
// support check."
//
// The state machine is here. `serverHandshakeState.handshake` (132
// lines), `processClientHello` (222), `doFullHandshake` (421),
// `checkForResumption` (164), `Conn.serverHandshake` (62) and
// `readClientHello` (151) are all implemented, in this file's 1989
// lines against Go's 1000, and the manifest above names seventeen
// declarations rather than one. `tls::handshake_loopback`
// (mod.rs:8933) runs this server against the ported client for both
// TLS 1.2 and 1.3, from tls_common_smoke.
//
// A reader taking that paragraph at face value concludes goish cannot
// terminate a TLS connection. The GOISH018 ignore below still lists the
// same names; that is belt-and-braces now, not a statement about what
// the file contains.
//
// goishlint:ignore GOISH018 serverHandshake, handshake, readClientHello, processClientHello, doResumeHandshake, doFullHandshake, sendSessionTicket — serverHandshakeState and Conn; see the banner. ROADMAP.md.

#![allow(non_snake_case, dead_code)]

extern crate alloc;

use super::common::{pointFormatUncompressed, CurveID};
use super::Config;
use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::types::{int, uint16, uint8};

// go: sdk 1.25.5 crypto/tls/handshake_server.go:365-394 supportsECDHE
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
    pub clientHello: super::handshake_messages::clientHelloMsg,
    pub hello: super::handshake_messages::serverHelloMsg,
    pub suite: Option<&'static super::cipher_suites::cipherSuite>,
    pub finishedHash: super::prf::finishedHash,
    pub masterSecret: slice<crate::types::byte>,
    pub sessionState: Option<super::ticket::SessionState>,
    pub ecdheOk: bool,
    pub ecSignOk: bool,
    pub rsaDecryptOk: bool,
    pub rsaSignOk: bool,
    pub cert: Option<super::common::Certificate>,
}

impl serverHandshakeState {
    // go: sdk 1.25.5 crypto/tls/handshake_server.go:66-131 serverHandshakeState.handshake
    /// Go: the TLS 1.0–1.2 server handshake driver — process the
    /// ClientHello, split on resumption, and sequence the flights and
    /// session ticket in the order the resumption decision dictates.
    pub(crate) fn handshake(&mut self) -> crate::error {
        // Go: if err := hs.processClientHello(); err != nil { return err }
        let err = self.processClientHello();
        if err != crate::errors::nil {
            return err;
        }

        // Go: "For an overview of TLS handshaking, see RFC 5246, Section 7.3."
        //     c.buffering = true
        //     if err := hs.checkForResumption(); err != nil { return err }
        self.c.buffering = true;
        let err = self.checkForResumption();
        if err != crate::errors::nil {
            return err;
        }
        // Go: if hs.sessionState != nil {
        if self.sessionState.is_some() {
            // Go: "The client has included a session ticket and so we
            // do an abbreviated handshake."
            //     if err := hs.doResumeHandshake(); err != nil { return err }
            //     if err := hs.establishKeys(); err != nil { return err }
            //     if err := hs.sendSessionTicket(); err != nil { return err }
            //     if err := hs.sendFinished(c.serverFinished[:]); err != nil { return err }
            //     if _, err := c.flush(); err != nil { return err }
            //     c.clientFinishedIsFirst = false
            //     if err := hs.readFinished(nil); err != nil { return err }
            let err = self.doResumeHandshake();
            if err != crate::errors::nil {
                return err;
            }
            let err = self.establishKeys();
            if err != crate::errors::nil {
                return err;
            }
            let err = self.sendSessionTicket();
            if err != crate::errors::nil {
                return err;
            }
            let mut out = slice::__from_vec(self.c.serverFinished.to_vec());
            let err = self.sendFinished(&mut out);
            if err != crate::errors::nil {
                return err;
            }
            {
                let raw: &[crate::types::byte] = &out;
                self.c.serverFinished.copy_from_slice(raw);
            }
            let (_, err) = self.c.flush();
            if err != crate::errors::nil {
                return err;
            }
            self.c.clientFinishedIsFirst = false;
            // Go passes nil; a zero-length slice makes the copy a no-op.
            let mut out = slice::new();
            let err = self.readFinished(&mut out);
            if err != crate::errors::nil {
                return err;
            }
        } else {
            // Go: "The client didn't include a session ticket, or it
            // wasn't valid so we do a full handshake."
            //     if err := hs.pickCipherSuite(); err != nil { return err }
            //     if err := hs.doFullHandshake(); err != nil { return err }
            //     if err := hs.establishKeys(); err != nil { return err }
            //     if err := hs.readFinished(c.clientFinished[:]); err != nil { return err }
            //     c.clientFinishedIsFirst = true
            //     c.buffering = true
            //     if err := hs.sendSessionTicket(); err != nil { return err }
            //     if err := hs.sendFinished(nil); err != nil { return err }
            //     if _, err := c.flush(); err != nil { return err }
            let err = self.pickCipherSuite();
            if err != crate::errors::nil {
                return err;
            }
            let err = self.doFullHandshake();
            if err != crate::errors::nil {
                return err;
            }
            let err = self.establishKeys();
            if err != crate::errors::nil {
                return err;
            }
            let mut out = slice::__from_vec(self.c.clientFinished.to_vec());
            let err = self.readFinished(&mut out);
            if err != crate::errors::nil {
                return err;
            }
            {
                let raw: &[crate::types::byte] = &out;
                self.c.clientFinished.copy_from_slice(raw);
            }
            self.c.clientFinishedIsFirst = true;
            self.c.buffering = true;
            let err = self.sendSessionTicket();
            if err != crate::errors::nil {
                return err;
            }
            // Go passes nil; a zero-length slice makes the copy a no-op.
            let mut out = slice::new();
            let err = self.sendFinished(&mut out);
            if err != crate::errors::nil {
                return err;
            }
            let (_, err) = self.c.flush();
            if err != crate::errors::nil {
                return err;
            }
        }

        // Go: c.ekm = ekmFromMasterSecret(c.vers, hs.suite, hs.masterSecret,
        //         hs.clientHello.random, hs.hello.random)
        //     c.isHandshakeComplete.Store(true)
        //     return nil
        self.c.ekm = Some(super::prf::ekmFromMasterSecret(
            self.c.vers,
            self.suite.unwrap(),
            self.masterSecret.clone(),
            slice::__from_vec(self.clientHello.random.clone()),
            slice::__from_vec(self.hello.random.clone()),
        ));
        self.c.isHandshakeComplete = true;
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_server.go:219-329 serverHandshakeState.processClientHello
    /// Go: vet the ClientHello and build the ServerHello scaffold —
    /// compression, the downgrade canaries in the server random,
    /// renegotiation, ALPN, certificate selection, and the key-type
    /// capability flags the cipher suite choice depends on.
    ///
    /// Deviation: the `testingOnlyForceDowngradeCanary` test hook is
    /// absent.
    pub(crate) fn processClientHello(&mut self) -> crate::error {
        // Go: hs.hello = new(serverHelloMsg)
        //     hs.hello.vers = c.vers
        self.hello = super::handshake_messages::serverHelloMsg::default();
        self.hello.vers = self.c.vers;

        // Go: foundCompression := false
        //     for _, compression := range hs.clientHello.compressionMethods {
        //         if compression == compressionNone { foundCompression = true; break } }
        //     if !foundCompression {
        //         c.sendAlert(alertIllegalParameter)
        //         return errors.New("tls: client does not support uncompressed connections") }
        let mut foundCompression = false;
        for compression in self.clientHello.compressionMethods.iter() {
            if *compression == super::common::compressionNone {
                foundCompression = true;
                break;
            }
        }
        if !foundCompression {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return crate::errors::New("tls: client does not support uncompressed connections");
        }

        // Go: hs.hello.random = make([]byte, 32)
        //     serverRandom := hs.hello.random
        //     "Downgrade protection canaries. See RFC 8446, Section 4.1.3."
        //     maxVers := c.config.maxSupportedVersion(roleServer)
        //     if maxVers >= VersionTLS12 && c.vers < maxVers || testingOnlyForceDowngradeCanary {
        //         if c.vers == VersionTLS12 { copy(serverRandom[24:], downgradeCanaryTLS12) }
        //         else { copy(serverRandom[24:], downgradeCanaryTLS11) }
        //         serverRandom = serverRandom[:24] }
        //     _, err := io.ReadFull(c.config.rand(), serverRandom)
        //     if err != nil { c.sendAlert(alertInternalError); return err }
        self.hello.random = alloc::vec![0u8; 32];
        let maxVers = self.c.config.maxSupportedVersion(super::common::roleServer);
        let mut randomLen = 32;
        if maxVers >= super::common::VersionTLS12 && self.c.vers < maxVers {
            if self.c.vers == super::common::VersionTLS12 {
                self.hello.random[24..].copy_from_slice(super::common::downgradeCanaryTLS12);
            } else {
                self.hello.random[24..].copy_from_slice(super::common::downgradeCanaryTLS11);
            }
            randomLen = 24;
        }
        let err = {
            let mut r = self.c.config.rand();
            let mut buf = slice::__from_vec(self.hello.random[..randomLen].to_vec());
            let (_, err) = crate::io::ReadFull(&mut *r, &mut buf);
            let raw: &[crate::types::byte] = &buf;
            self.hello.random[..randomLen].copy_from_slice(raw);
            err
        };
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertInternalError);
            return err;
        }

        // Go: if len(hs.clientHello.secureRenegotiation) != 0 {
        //         c.sendAlert(alertHandshakeFailure)
        //         return errors.New("tls: initial handshake had non-empty renegotiation extension") }
        if self.clientHello.secureRenegotiation.len() != 0 {
            self.c.sendAlert(super::alert::alertHandshakeFailure);
            return crate::errors::New(
                "tls: initial handshake had non-empty renegotiation extension",
            );
        }

        // Go: hs.hello.extendedMasterSecret = hs.clientHello.extendedMasterSecret
        //     hs.hello.secureRenegotiationSupported = hs.clientHello.secureRenegotiationSupported
        //     hs.hello.compressionMethod = compressionNone
        //     if len(hs.clientHello.serverName) > 0 { c.serverName = hs.clientHello.serverName }
        self.hello.extendedMasterSecret = self.clientHello.extendedMasterSecret;
        self.hello.secureRenegotiationSupported = self.clientHello.secureRenegotiationSupported;
        self.hello.compressionMethod = super::common::compressionNone;
        if self.clientHello.serverName.len() > 0 {
            self.c.serverName =
                crate::gostring::string::from_bytes(self.clientHello.serverName.as_bytes());
        }

        // Go: selectedProto, err := negotiateALPN(c.config.NextProtos,
        //         hs.clientHello.alpnProtocols, false)
        //     if err != nil { c.sendAlert(alertNoApplicationProtocol); return err }
        //     hs.hello.alpnProtocol = selectedProto
        //     c.clientProtocol = selectedProto
        let (selectedProto, err) = negotiateALPN(
            self.c.config.NextProtos.clone(),
            slice::__from_vec(
                self.clientHello
                    .alpnProtocols
                    .iter()
                    .map(|p| crate::gostring::string::from_bytes(p.as_bytes()))
                    .collect::<alloc::vec::Vec<_>>(),
            ),
            false,
        );
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertNoApplicationProtocol);
            return err;
        }
        self.hello.alpnProtocol = core::str::from_utf8(selectedProto.as_bytes())
            .map(|s| s.into())
            .unwrap_or_default();
        self.c.clientProtocol = selectedProto;

        // Go: hs.cert, err = c.config.getCertificate(clientHelloInfo(hs.ctx, c, hs.clientHello))
        //     if err != nil {
        //         if err == errNoCertificates { c.sendAlert(alertUnrecognizedName) }
        //         else { c.sendAlert(alertInternalError) }
        //         return err }
        let (cert, err) = self
            .c
            .config
            .getCertificate(&clientHelloInfo(&self.c, &self.clientHello));
        if err != crate::errors::nil {
            if crate::errors::Is(err.clone(), super::common::errNoCertificates.clone()) {
                self.c.sendAlert(super::alert::alertUnrecognizedName);
            } else {
                self.c.sendAlert(super::alert::alertInternalError);
            }
            return err;
        }
        self.cert = Some(cert);
        // Go: if hs.clientHello.scts { hs.hello.scts = hs.cert.SignedCertificateTimestamps }
        if self.clientHello.scts {
            self.hello.scts = self
                .cert
                .as_ref()
                .unwrap()
                .SignedCertificateTimestamps
                .iter()
                .map(|s| s.to_vec())
                .collect::<alloc::vec::Vec<_>>();
        }

        // Go: hs.ecdheOk, err = supportsECDHE(c.config, c.vers,
        //         hs.clientHello.supportedCurves, hs.clientHello.supportedPoints)
        //     if err != nil { c.sendAlert(alertMissingExtension); return err }
        let (ecdheOk, err) = supportsECDHE(
            &self.c.config,
            self.c.vers,
            slice::__from_vec(
                self.clientHello
                    .supportedCurves
                    .iter()
                    .map(|c| CurveID(*c))
                    .collect::<alloc::vec::Vec<_>>(),
            ),
            slice::__from_vec(self.clientHello.supportedPoints.clone()),
        );
        self.ecdheOk = ecdheOk;
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertMissingExtension);
            return err;
        }

        // Go: if hs.ecdheOk && len(hs.clientHello.supportedPoints) > 0 {
        //         "Although omitting the ec_point_formats extension is
        //         permitted, some old OpenSSL version will refuse to
        //         handshake if not present. […] See golang.org/issue/31943."
        //         hs.hello.supportedPoints = []uint8{pointFormatUncompressed} }
        if self.ecdheOk && self.clientHello.supportedPoints.len() > 0 {
            self.hello.supportedPoints = alloc::vec![pointFormatUncompressed];
        }

        // Go: if priv, ok := hs.cert.PrivateKey.(crypto.Signer); ok {
        //         switch priv.Public().(type) {
        //         case *ecdsa.PublicKey: hs.ecSignOk = true
        //         case ed25519.PublicKey: hs.ecSignOk = true
        //         case *rsa.PublicKey: hs.rsaSignOk = true
        //         default: c.sendAlert(alertInternalError)
        //             return fmt.Errorf("tls: unsupported signing key type (%T)", priv.Public()) } }
        if let Some(priv_) = super::auth::signerOf(&self.cert.as_ref().unwrap().PrivateKey) {
            let pub_ = priv_.Public();
            if pub_
                .downcast_ref::<crate::crypto::ecdsa::PublicKey>()
                .is_some()
            {
                self.ecSignOk = true;
            } else if pub_
                .downcast_ref::<crate::crypto::ed25519::PublicKey>()
                .is_some()
            {
                self.ecSignOk = true;
            } else if pub_
                .downcast_ref::<crate::crypto::rsa::PublicKey>()
                .is_some()
            {
                self.rsaSignOk = true;
            } else {
                self.c.sendAlert(super::alert::alertInternalError);
                return crate::errors::New("tls: unsupported signing key type");
            }
        }
        // Go: if priv, ok := hs.cert.PrivateKey.(crypto.Decrypter); ok {
        //         switch priv.Public().(type) {
        //         case *rsa.PublicKey: hs.rsaDecryptOk = true
        //         default: c.sendAlert(alertInternalError)
        //             return fmt.Errorf("tls: unsupported decryption key type (%T)", priv.Public()) } }
        if let Some(priv_) =
            super::key_agreement::decrypterOf(&self.cert.as_ref().unwrap().PrivateKey)
        {
            let pub_ = priv_.Public();
            if pub_
                .downcast_ref::<crate::crypto::rsa::PublicKey>()
                .is_some()
            {
                self.rsaDecryptOk = true;
            } else {
                self.c.sendAlert(super::alert::alertInternalError);
                return crate::errors::New("tls: unsupported decryption key type");
            }
        }

        // Go: return nil
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_server.go:557-588 serverHandshakeState.doResumeHandshake
    /// Go: the abbreviated handshake — echo the session ID so the
    /// client knows it's a resumption, always offer a fresh ticket, and
    /// take the master secret straight from the resumed session.
    pub(crate) fn doResumeHandshake(&mut self) -> crate::error {
        // Go: hs.hello.cipherSuite = hs.suite.id
        //     c.cipherSuite = hs.suite.id
        //     hs.hello.sessionId = hs.clientHello.sessionId
        //     hs.hello.ticketSupported = true
        self.hello.cipherSuite = self.suite.unwrap().id;
        self.c.cipherSuite = self.suite.unwrap().id;
        self.hello.sessionId = self.clientHello.sessionId.clone();
        self.hello.ticketSupported = true;
        // Go: hs.finishedHash = newFinishedHash(c.vers, hs.suite)
        //     hs.finishedHash.discardHandshakeBuffer()
        //     if err := transcriptMsg(hs.clientHello, &hs.finishedHash); err != nil { return err }
        //     if _, err := hs.c.writeHandshakeRecord(hs.hello, &hs.finishedHash); err != nil { return err }
        self.finishedHash = super::prf::newFinishedHash(self.c.vers, self.suite.unwrap());
        self.finishedHash.discardHandshakeBuffer();
        let err =
            super::handshake_messages::transcriptMsg(&self.clientHello, &mut self.finishedHash);
        if err != crate::errors::nil {
            return err;
        }
        let (_, err) = self
            .c
            .writeHandshakeRecord(&self.hello, Some(&mut self.finishedHash));
        if err != crate::errors::nil {
            return err;
        }

        // Go: if c.config.VerifyConnection != nil {
        //         if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
        //             c.sendAlert(alertBadCertificate); return err } }
        if let Some(verify) = self.c.config.VerifyConnection.clone() {
            let err = verify(self.c.connectionStateLocked());
            if err != crate::errors::nil {
                self.c.sendAlert(super::alert::alertBadCertificate);
                return err;
            }
        }

        // Go: hs.masterSecret = hs.sessionState.secret
        //     return nil
        self.masterSecret = self.sessionState.as_ref().unwrap().secret.clone();
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_server.go:590-806 serverHandshakeState.doFullHandshake
    /// Go: the full (non-resumed) TLS 1.0–1.2 server handshake — send
    /// the ServerHello, Certificate, optional CertificateStatus,
    /// ServerKeyExchange, optional CertificateRequest, and
    /// ServerHelloDone, then read the client's Certificate,
    /// ClientKeyExchange, and CertificateVerify, and derive the master
    /// secret.
    ///
    /// Deviation: the `tlssha1` GODEBUG counter bump when a SHA-1
    /// signature is used is absent — goish ships no godebug.
    pub(crate) fn doFullHandshake(&mut self) -> crate::error {
        // Go: if hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0 {
        //         hs.hello.ocspStapling = true }
        if self.clientHello.ocspStapling && self.cert.as_ref().unwrap().OCSPStaple.Len() > 0 {
            self.hello.ocspStapling = true;
        }

        // Go: if hs.clientHello.serverName != "" { hs.hello.serverNameAck = true }
        if self.clientHello.serverName.len() != 0 {
            self.hello.serverNameAck = true;
        }

        // Go: hs.hello.ticketSupported = hs.clientHello.ticketSupported && !c.config.SessionTicketsDisabled
        //     hs.hello.cipherSuite = hs.suite.id
        self.hello.ticketSupported =
            self.clientHello.ticketSupported && !self.c.config.SessionTicketsDisabled;
        self.hello.cipherSuite = self.suite.unwrap().id;

        // Go: hs.finishedHash = newFinishedHash(hs.c.vers, hs.suite)
        //     if c.config.ClientAuth == NoClientCert { hs.finishedHash.discardHandshakeBuffer() }
        self.finishedHash = super::prf::newFinishedHash(self.c.vers, self.suite.unwrap());
        if self.c.config.ClientAuth == super::common::NoClientCert {
            self.finishedHash.discardHandshakeBuffer();
        }
        // Go: if err := transcriptMsg(hs.clientHello, &hs.finishedHash); err != nil { return err }
        //     if _, err := hs.c.writeHandshakeRecord(hs.hello, &hs.finishedHash); err != nil { return err }
        let err =
            super::handshake_messages::transcriptMsg(&self.clientHello, &mut self.finishedHash);
        if err != crate::errors::nil {
            return err;
        }
        let (_, err) = self
            .c
            .writeHandshakeRecord(&self.hello, Some(&mut self.finishedHash));
        if err != crate::errors::nil {
            return err;
        }

        // Go: certMsg := new(certificateMsg)
        //     certMsg.certificates = hs.cert.Certificate
        //     if _, err := hs.c.writeHandshakeRecord(certMsg, &hs.finishedHash); err != nil { return err }
        let mut certMsg = super::handshake_messages::certificateMsg::default();
        certMsg.certificates = self.cert.as_ref().unwrap().Certificate.clone();
        let (_, err) = self
            .c
            .writeHandshakeRecord(&certMsg, Some(&mut self.finishedHash));
        if err != crate::errors::nil {
            return err;
        }

        // Go: if hs.hello.ocspStapling {
        //         certStatus := new(certificateStatusMsg)
        //         certStatus.response = hs.cert.OCSPStaple
        //         if _, err := hs.c.writeHandshakeRecord(certStatus, &hs.finishedHash); err != nil { return err } }
        if self.hello.ocspStapling {
            let mut certStatus = super::handshake_messages::certificateStatusMsg::default();
            certStatus.response = self.cert.as_ref().unwrap().OCSPStaple.clone();
            let (_, err) = self
                .c
                .writeHandshakeRecord(&certStatus, Some(&mut self.finishedHash));
            if err != crate::errors::nil {
                return err;
            }
        }

        // Go: keyAgreement := hs.suite.ka(c.vers)
        //     skx, err := keyAgreement.generateServerKeyExchange(c.config, hs.cert, hs.clientHello, hs.hello)
        //     if err != nil { c.sendAlert(alertHandshakeFailure); return err }
        let mut keyAgreement = (self.suite.unwrap().ka)(self.c.vers);
        let (skx, err) = keyAgreement.generateServerKeyExchange(
            &self.c.config,
            self.cert.as_ref().unwrap(),
            &self.clientHello,
            &self.hello,
        );
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertHandshakeFailure);
            return err;
        }
        // Go: if skx != nil {
        //         if keyAgreement, ok := keyAgreement.(*ecdheKeyAgreement); ok {
        //             c.curveID = keyAgreement.curveID
        //             c.peerSigAlg = keyAgreement.signatureAlgorithm }
        //         if _, err := hs.c.writeHandshakeRecord(skx, &hs.finishedHash); err != nil { return err } }
        if let Some(skx) = skx.as_ref() {
            if let Some(ecdhe) = keyAgreement
                .asAny()
                .downcast_ref::<super::key_agreement::ecdheKeyAgreement>()
            {
                self.c.curveID = ecdhe.curveID;
                self.c.peerSigAlg = ecdhe.signatureAlgorithm;
            }
            let (_, err) = self
                .c
                .writeHandshakeRecord(skx, Some(&mut self.finishedHash));
            if err != crate::errors::nil {
                return err;
            }
        }

        // Go: var certReq *certificateRequestMsg
        //     if c.config.ClientAuth >= RequestClientCert {
        let mut certReq: Option<super::handshake_messages::certificateRequestMsg> = None;
        if self.c.config.ClientAuth >= super::common::RequestClientCert {
            // Go: certReq = new(certificateRequestMsg)
            //     certReq.certificateTypes = []byte{byte(certTypeRSASign), byte(certTypeECDSASign)}
            //     if c.vers >= VersionTLS12 {
            //         certReq.hasSignatureAlgorithm = true
            //         certReq.supportedSignatureAlgorithms = supportedSignatureAlgorithms(c.vers) }
            let mut cr = super::handshake_messages::certificateRequestMsg::default();
            cr.certificateTypes = slice::__from_vec(alloc::vec![
                super::common::certTypeRSASign,
                super::common::certTypeECDSASign,
            ]);
            if self.c.vers >= super::common::VersionTLS12 {
                cr.hasSignatureAlgorithm = true;
                cr.supportedSignatureAlgorithms =
                    super::common::supportedSignatureAlgorithms(self.c.vers);
            }

            // Go: "An empty list of certificateAuthorities signals to
            // the client that it may send any certificate […]"
            //     if c.config.ClientCAs != nil {
            //         certReq.certificateAuthorities = c.config.ClientCAs.Subjects() }
            //     if _, err := hs.c.writeHandshakeRecord(certReq, &hs.finishedHash); err != nil { return err }
            if let Some(cas) = self.c.config.ClientCAs.as_ref() {
                cr.certificateAuthorities = cas.Subjects();
            }
            let (_, err) = self
                .c
                .writeHandshakeRecord(&cr, Some(&mut self.finishedHash));
            if err != crate::errors::nil {
                return err;
            }
            certReq = Some(cr);
        }

        // Go: helloDone := new(serverHelloDoneMsg)
        //     if _, err := hs.c.writeHandshakeRecord(helloDone, &hs.finishedHash); err != nil { return err }
        //     if _, err := c.flush(); err != nil { return err }
        let helloDone = super::handshake_messages::serverHelloDoneMsg::default();
        let (_, err) = self
            .c
            .writeHandshakeRecord(&helloDone, Some(&mut self.finishedHash));
        if err != crate::errors::nil {
            return err;
        }
        let (_, err) = self.c.flush();
        if err != crate::errors::nil {
            return err;
        }

        // Go: var pub crypto.PublicKey // public key for client auth, if any
        //     msg, err := c.readHandshake(&hs.finishedHash)
        //     if err != nil { return err }
        let mut pub_: Option<crate::goany::Any> = None;
        let (msg, err) = self.c.readHandshake(Some(&mut self.finishedHash));
        if err != crate::errors::nil {
            return err;
        }
        let mut msg = match msg {
            Some(m) => m,
            None => return crate::errors::New("tls: internal error: no handshake message"),
        };

        // Go: "If we requested a client certificate, then the client
        // must send a certificate message, even if it's empty."
        //     if c.config.ClientAuth >= RequestClientCert {
        if self.c.config.ClientAuth >= super::common::RequestClientCert {
            // Go: certMsg, ok := msg.(*certificateMsg)
            //     if !ok { c.sendAlert(alertUnexpectedMessage)
            //         return unexpectedMessageError(certMsg, msg) }
            let certMsg = match msg
                .asAny()
                .downcast_ref::<super::handshake_messages::certificateMsg>()
            {
                Some(cm) => cm.clone(),
                None => {
                    self.c.sendAlert(super::alert::alertUnexpectedMessage);
                    return super::common::unexpectedMessageError(
                        crate::gostring::string::from_static("*tls.certificateMsg"),
                        super::handshake_messages::handshakeMessageTypeName(&*msg),
                    );
                }
            };

            // Go: if err := c.processCertsFromClient(Certificate{
            //         Certificate: certMsg.certificates }); err != nil { return err }
            let mut chain = super::common::Certificate::default();
            chain.Certificate = certMsg.certificates.clone();
            let err = self.c.processCertsFromClient(chain);
            if err != crate::errors::nil {
                return err;
            }
            // Go: if len(certMsg.certificates) != 0 {
            //         pub = c.peerCertificates[0].PublicKey }
            if certMsg.certificates.Len() != 0 {
                pub_ = Some(self.c.peerCertificates[0].PublicKey.clone());
            }

            // Go: msg, err = c.readHandshake(&hs.finishedHash)
            //     if err != nil { return err }
            let (nextMsg, err) = self.c.readHandshake(Some(&mut self.finishedHash));
            if err != crate::errors::nil {
                return err;
            }
            msg = match nextMsg {
                Some(m) => m,
                None => return crate::errors::New("tls: internal error: no handshake message"),
            };
        }
        // Go: if c.config.VerifyConnection != nil {
        //         if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
        //             c.sendAlert(alertBadCertificate); return err } }
        if let Some(verify) = self.c.config.VerifyConnection.clone() {
            let err = verify(self.c.connectionStateLocked());
            if err != crate::errors::nil {
                self.c.sendAlert(super::alert::alertBadCertificate);
                return err;
            }
        }

        // Go: "Get client key exchange"
        //     ckx, ok := msg.(*clientKeyExchangeMsg)
        //     if !ok { c.sendAlert(alertUnexpectedMessage)
        //         return unexpectedMessageError(ckx, msg) }
        let ckx = match msg
            .asAny()
            .downcast_ref::<super::handshake_messages::clientKeyExchangeMsg>()
        {
            Some(k) => k.clone(),
            None => {
                self.c.sendAlert(super::alert::alertUnexpectedMessage);
                return super::common::unexpectedMessageError(
                    crate::gostring::string::from_static("*tls.clientKeyExchangeMsg"),
                    super::handshake_messages::handshakeMessageTypeName(&*msg),
                );
            }
        };

        // Go: preMasterSecret, err := keyAgreement.processClientKeyExchange(
        //         c.config, hs.cert, ckx, c.vers)
        //     if err != nil { c.sendAlert(alertIllegalParameter); return err }
        let (preMasterSecret, err) = keyAgreement.processClientKeyExchange(
            &self.c.config,
            self.cert.as_ref().unwrap(),
            &ckx,
            self.c.vers,
        );
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return err;
        }
        // Go: if hs.hello.extendedMasterSecret {
        //         c.extMasterSecret = true
        //         hs.masterSecret = extMasterFromPreMasterSecret(c.vers, hs.suite,
        //             preMasterSecret, hs.finishedHash.Sum())
        //     } else {
        //         if fips140tls.Required() { c.sendAlert(alertHandshakeFailure)
        //             return errors.New("tls: FIPS 140-3 requires the use of Extended Master Secret") }
        //         hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite,
        //             preMasterSecret, hs.clientHello.random, hs.hello.random) }
        if self.hello.extendedMasterSecret {
            self.c.extMasterSecret = true;
            let sum = self.finishedHash.Sum();
            self.masterSecret = super::prf::extMasterFromPreMasterSecret(
                self.c.vers,
                self.suite.unwrap(),
                preMasterSecret,
                sum,
            );
        } else {
            if super::internal::fips140tls::Required() {
                self.c.sendAlert(super::alert::alertHandshakeFailure);
                return crate::errors::New(
                    "tls: FIPS 140-3 requires the use of Extended Master Secret",
                );
            }
            self.masterSecret = super::prf::masterFromPreMasterSecret(
                self.c.vers,
                self.suite.unwrap(),
                preMasterSecret,
                slice::__from_vec(self.clientHello.random.clone()),
                slice::__from_vec(self.hello.random.clone()),
            );
        }
        // Go: if err := c.config.writeKeyLog(keyLogLabelTLS12, hs.clientHello.random, hs.masterSecret); err != nil {
        //         c.sendAlert(alertInternalError); return err }
        let err = self.c.config.writeKeyLog(
            crate::gostring::string::from_static(super::common::keyLogLabelTLS12),
            slice::__from_vec(self.clientHello.random.clone()),
            self.masterSecret.clone(),
        );
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertInternalError);
            return err;
        }

        // Go: "If we received a client cert in response to our
        // certificate request message, the client will send us a
        // certificateVerifyMsg immediately after the
        // clientKeyExchangeMsg. […]"
        //     if len(c.peerCertificates) > 0 {
        if self.c.peerCertificates.Len() > 0 {
            // Go: "certificateVerifyMsg is included in the transcript,
            // but not until after we verify the handshake signature,
            // since the state before this message was sent is used."
            //     msg, err = c.readHandshake(nil)
            //     if err != nil { return err }
            //     certVerify, ok := msg.(*certificateVerifyMsg)
            //     if !ok { c.sendAlert(alertUnexpectedMessage)
            //         return unexpectedMessageError(certVerify, msg) }
            let (msg, err) = self.c.readHandshake(None);
            if err != crate::errors::nil {
                return err;
            }
            let msg = match msg {
                Some(m) => m,
                None => return crate::errors::New("tls: internal error: no handshake message"),
            };
            let certVerify = match msg
                .asAny()
                .downcast_ref::<super::handshake_messages::certificateVerifyMsg>()
            {
                Some(cv) => cv.clone(),
                None => {
                    self.c.sendAlert(super::alert::alertUnexpectedMessage);
                    return super::common::unexpectedMessageError(
                        crate::gostring::string::from_static("*tls.certificateVerifyMsg"),
                        super::handshake_messages::handshakeMessageTypeName(&*msg),
                    );
                }
            };

            // Go: var sigType uint8
            //     var sigHash crypto.Hash
            //     if c.vers >= VersionTLS12 {
            //         if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm,
            //             certReq.supportedSignatureAlgorithms) {
            //             c.sendAlert(alertIllegalParameter)
            //             return errors.New("tls: client certificate used with invalid signature algorithm") }
            //         sigType, sigHash, err = typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
            //         if err != nil { return c.sendAlert(alertInternalError) }
            //         if sigHash == crypto.SHA1 { tlssha1.Value(); tlssha1.IncNonDefault() }
            //     } else {
            //         sigType, sigHash, err = legacyTypeAndHashFromPublicKey(pub)
            //         if err != nil { c.sendAlert(alertIllegalParameter); return err } }
            let sigType: crate::types::uint8;
            let sigHash: crate::crypto::Hash;
            let sigAlg = super::common::SignatureScheme(certVerify.signatureAlgorithm);
            if self.c.vers >= super::common::VersionTLS12 {
                if !super::common::isSupportedSignatureAlgorithm(
                    sigAlg,
                    certReq
                        .as_ref()
                        .unwrap()
                        .supportedSignatureAlgorithms
                        .clone(),
                ) {
                    self.c.sendAlert(super::alert::alertIllegalParameter);
                    return crate::errors::New(
                        "tls: client certificate used with invalid signature algorithm",
                    );
                }
                let (st, sh, err) = super::auth::typeAndHashFromSignatureScheme(sigAlg);
                if err != crate::errors::nil {
                    return self.c.sendAlert(super::alert::alertInternalError);
                }
                sigType = st;
                sigHash = sh;
            } else {
                let (st, sh, err) =
                    super::auth::legacyTypeAndHashFromPublicKey(pub_.as_ref().unwrap());
                if err != crate::errors::nil {
                    self.c.sendAlert(super::alert::alertIllegalParameter);
                    return err;
                }
                sigType = st;
                sigHash = sh;
            }

            // Go: signed := hs.finishedHash.hashForClientCertificate(sigType, sigHash)
            //     if err := verifyHandshakeSignature(sigType, pub, sigHash, signed,
            //         certVerify.signature); err != nil {
            //         c.sendAlert(alertDecryptError)
            //         return errors.New("tls: invalid signature by the client certificate: " + err.Error()) }
            //     c.peerSigAlg = certVerify.signatureAlgorithm
            let signed = self.finishedHash.hashForClientCertificate(sigType, sigHash);
            let err = super::auth::verifyHandshakeSignature(
                sigType,
                pub_.as_ref().unwrap(),
                sigHash,
                signed,
                slice::__from_vec(certVerify.signature.clone()),
            );
            if err != crate::errors::nil {
                self.c.sendAlert(super::alert::alertDecryptError);
                return crate::fmt::Errorf!(
                    "tls: invalid signature by the client certificate: %s",
                    err.Error()
                );
            }
            self.c.peerSigAlg = sigAlg;

            // Go: if err := transcriptMsg(certVerify, &hs.finishedHash); err != nil { return err }
            let err = super::handshake_messages::transcriptMsg(&certVerify, &mut self.finishedHash);
            if err != crate::errors::nil {
                return err;
            }
        }

        // Go: hs.finishedHash.discardHandshakeBuffer()
        //     return nil
        self.finishedHash.discardHandshakeBuffer();
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_server.go:868-905 serverHandshakeState.sendSessionTicket
    /// Go: wrap the session (via `Config.WrapSession` or the ticket
    /// keys) and send the NewSessionTicket message. Re-wrapping an old
    /// ticket keeps the original creation time.
    pub(crate) fn sendSessionTicket(&mut self) -> crate::error {
        // Go: if !hs.hello.ticketSupported { return nil }
        if !self.hello.ticketSupported {
            return crate::errors::nil;
        }

        // Go: m := new(newSessionTicketMsg)
        //     state := c.sessionState()
        //     state.secret = hs.masterSecret
        //     if hs.sessionState != nil { state.createdAt = hs.sessionState.createdAt }
        let mut m = super::handshake_messages::newSessionTicketMsg::default();
        let mut state = self.c.sessionState();
        state.secret = self.masterSecret.clone();
        if let Some(prev) = self.sessionState.as_ref() {
            state.createdAt = prev.createdAt;
        }
        // Go: if c.config.WrapSession != nil {
        //         m.ticket, err = c.config.WrapSession(c.connectionStateLocked(), state)
        //         if err != nil { return err }
        //     } else {
        //         stateBytes, err := state.Bytes()
        //         if err != nil { return err }
        //         m.ticket, err = c.config.encryptTicket(stateBytes, c.ticketKeys)
        //         if err != nil { return err } }
        if let Some(wrap) = self.c.config.WrapSession.clone() {
            let (ticket, err) = wrap(self.c.connectionStateLocked(), state);
            if err != crate::errors::nil {
                return err;
            }
            m.ticket = ticket;
        } else {
            let (stateBytes, err) = state.Bytes();
            if err != crate::errors::nil {
                return err;
            }
            let (ticket, err) = self
                .c
                .config
                .encryptTicket(stateBytes, self.c.ticketKeys.clone());
            if err != crate::errors::nil {
                return err;
            }
            m.ticket = ticket;
        }

        // Go: if _, err := hs.c.writeHandshakeRecord(m, &hs.finishedHash); err != nil { return err }
        //     return nil
        let (_, err) = self
            .c
            .writeHandshakeRecord(&m, Some(&mut self.finishedHash));
        if err != crate::errors::nil {
            return err;
        }
        return crate::errors::nil;
    }
}

impl serverHandshakeState {
    // go: sdk 1.25.5 crypto/tls/handshake_server.go:432-451 serverHandshakeState.cipherSuiteOk
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

// go: sdk 1.25.5 crypto/tls/handshake_server.go:1009-1028 clientHelloInfo
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
    chi.ServerName = crate::gostring::string::from_bytes(clientHello.serverName.as_bytes());
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

impl serverHandshakeState {
    // go: sdk 1.25.5 crypto/tls/handshake_server.go:396-430 serverHandshakeState.pickCipherSuite
    ///
    /// Deviation: the two GODEBUG counter bumps (`tlsrsakex`, `tls3des`)
    /// are absent — `internal/godebug` is not ported.
    pub(crate) fn pickCipherSuite(&mut self) -> error {
        // Go: preferenceList := c.config.cipherSuites(
        //         isAESGCMPreferred(hs.clientHello.cipherSuites))
        let offered = slice::__from_vec(self.clientHello.cipherSuites.clone());
        let preferenceList = self
            .c
            .__config()
            .cipherSuites(super::cipher_suites::isAESGCMPreferred(offered.clone()));

        // Go: hs.suite = selectCipherSuite(preferenceList,
        //         hs.clientHello.cipherSuites, hs.cipherSuiteOk)
        //     if hs.suite == nil {
        //         c.sendAlert(alertHandshakeFailure)
        //         return fmt.Errorf("tls: no cipher suite supported by both client and
        //             server; client offered: %x", hs.clientHello.cipherSuites) }
        //
        // Go passes the method value `hs.cipherSuiteOk`; Rust cannot
        // borrow `self` into a closure that `self` also calls, so the
        // four flags it reads are copied out first. Same predicate.
        let (ecdheOk, ecSignOk, rsaDecryptOk, rsaSignOk) = (
            self.ecdheOk,
            self.ecSignOk,
            self.rsaDecryptOk,
            self.rsaSignOk,
        );
        let vers = self.c.__vers();
        self.suite = super::cipher_suites::selectCipherSuite(
            preferenceList,
            offered.clone(),
            &|c: &'static super::cipher_suites::cipherSuite| {
                if c.flags & super::cipher_suites::suiteECDHE != 0 {
                    if !ecdheOk {
                        return false;
                    }
                    if c.flags & super::cipher_suites::suiteECSign != 0 {
                        if !ecSignOk {
                            return false;
                        }
                    } else if !rsaSignOk {
                        return false;
                    }
                } else if !rsaDecryptOk {
                    return false;
                }
                if vers < super::common::VersionTLS12
                    && c.flags & super::cipher_suites::suiteTLS12 != 0
                {
                    return false;
                }
                return true;
            },
        );
        if self.suite.is_none() {
            self.c.sendAlert(super::alert::alertHandshakeFailure);
            return crate::fmt::Errorf!(
                "tls: no cipher suite supported by both client and server; client offered: %s",
                hexList(&offered)
            );
        }
        // Go: c.cipherSuite = hs.suite.id
        self.c.__setCipherSuite(self.suite.unwrap().id);

        // Go: for _, id := range hs.clientHello.cipherSuites {
        //         if id == TLS_FALLBACK_SCSV {
        //             // The client is doing a fallback connection. See RFC 7507.
        //             if hs.clientHello.vers < c.config.maxSupportedVersion(roleServer) {
        //                 c.sendAlert(alertInappropriateFallback)
        //                 return errors.New("tls: client using inappropriate protocol fallback") }
        //             break } }
        for (_, id) in crate::range!(offered) {
            if *id == super::cipher_suites::TLS_FALLBACK_SCSV {
                if self.clientHello.vers
                    < self
                        .c
                        .__config()
                        .maxSupportedVersion(super::common::roleServer)
                {
                    self.c.sendAlert(super::alert::alertInappropriateFallback);
                    return errors::New("tls: client using inappropriate protocol fallback");
                }
                break;
            }
        }

        // Go: return nil
        return errors::nil;
    }
}

// go: none — goish-only: Go's `%x` on a `[]uint16` renders a bracketed,
// space-separated list of minimal-width hex values — `[c02f 5600]`, not
// a flat byte string. goish's Sprintf has no verb for that shape, so the
// list is built here.
fn hexList(v: &slice<uint16>) -> crate::gostring::string {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    out.push(b'[');
    for (i, x) in crate::range!(v.clone()) {
        if i > 0 {
            out.push(b' ');
        }
        let mut started = false;
        let mut sh: int = 12;
        while sh >= 0 {
            let nib = ((*x >> sh) & 0xf) as usize;
            if nib != 0 || started || sh == 0 {
                out.push(HEX[nib]);
                started = true;
            }
            sh -= 4;
        }
    }
    out.push(b']');
    return crate::gostring::string::from_bytes(&out);
}

impl serverHandshakeState {
    // go: sdk 1.25.5 crypto/tls/handshake_server.go:808-831 serverHandshakeState.establishKeys
    /// Derive the six connection keys and stage them on both half
    /// connections, ready for the ChangeCipherSpec that activates them.
    pub(crate) fn establishKeys(&mut self) -> error {
        let suite = self.suite.unwrap();
        // Go: clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
        //         keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret,
        //             hs.clientHello.random, hs.hello.random,
        //             hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
        let (clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV) =
            super::prf::keysFromMasterSecret(
                self.c.__vers(),
                suite,
                self.masterSecret.clone(),
                slice::__from_vec(self.clientHello.random.clone()),
                slice::__from_vec(self.hello.random.clone()),
                suite.macLen,
                suite.keyLen,
                suite.ivLen,
            );

        // Go: var clientCipher, serverCipher any
        //     var clientHash, serverHash hash.Hash
        //     if hs.suite.aead == nil {
        //         clientCipher = hs.suite.cipher(clientKey, clientIV, true /* for reading */)
        //         clientHash = hs.suite.mac(clientMAC)
        //         serverCipher = hs.suite.cipher(serverKey, serverIV, false /* not for reading */)
        //         serverHash = hs.suite.mac(serverMAC)
        //     } else {
        //         clientCipher = hs.suite.aead(clientKey, clientIV)
        //         serverCipher = hs.suite.aead(serverKey, serverIV)
        //     }
        let clientCipher: super::conn::halfConnCipher;
        let serverCipher: super::conn::halfConnCipher;
        let mut clientHash: Option<alloc::boxed::Box<dyn crate::hash::Hash + Send + Sync>> = None;
        let mut serverHash: Option<alloc::boxed::Box<dyn crate::hash::Hash + Send + Sync>> = None;
        if suite.aead.is_none() {
            let cipherFn = suite.cipher.unwrap();
            let macFn = suite.mac.unwrap();
            clientCipher = super::conn::halfConnCipherOf(cipherFn(clientKey, clientIV, true));
            clientHash = Some(macFn(clientMAC));
            serverCipher = super::conn::halfConnCipherOf(cipherFn(serverKey, serverIV, false));
            serverHash = Some(macFn(serverMAC));
        } else {
            let aeadFn = suite.aead.unwrap();
            clientCipher = super::conn::halfConnCipher::AEAD(aeadFn(clientKey, clientIV));
            serverCipher = super::conn::halfConnCipher::AEAD(aeadFn(serverKey, serverIV));
        }

        // Go: c.in.prepareCipherSpec(c.vers, clientCipher, clientHash)
        //     c.out.prepareCipherSpec(c.vers, serverCipher, serverHash)
        //     return nil
        let vers = self.c.__vers();
        self.c
            .__prepareCipherSpecs(vers, clientCipher, clientHash, serverCipher, serverHash);
        return errors::nil;
    }
}

impl serverHandshakeState {
    // go: sdk 1.25.5 crypto/tls/handshake_server.go:454-555 serverHandshakeState.checkForResumption
    /// Whether the ClientHello's session ticket may be resumed, and if
    /// so, adopt the session it carries.
    ///
    /// Deviation: Go tries `c.config.UnwrapSession` first; goish's
    /// `Config` has no such callback field, so that arm is unreachable
    /// and the ticket is always opened with `decryptTicket`.
    pub(crate) fn checkForResumption(&mut self) -> error {
        // Go: if c.config.SessionTicketsDisabled { return nil }
        if self.c.__configSessionTicketsDisabled() {
            return errors::nil;
        }

        // Go: plaintext := c.config.decryptTicket(hs.clientHello.sessionTicket, c.ticketKeys)
        //     if plaintext == nil { return nil }
        //     ss, err := ParseSessionState(plaintext)
        //     if err != nil { return nil }
        //     sessionState = ss
        let ticket = slice::__from_vec(self.clientHello.sessionTicket.clone());
        let plaintext = self
            .c
            .__config()
            .decryptTicket(ticket, self.c.__ticketKeys());
        if plaintext.is_none() {
            return errors::nil;
        }
        let (sessionState, err) = super::ticket::ParseSessionState(plaintext.unwrap());
        if err != errors::nil {
            return errors::nil;
        }

        // Go: TLS 1.2 tickets don't natively have a lifetime, but we want
        // to avoid re-wrapping the same master secret in different tickets
        // over and over for too long, weakening forward secrecy.
        // Go: createdAt := time.Unix(int64(sessionState.createdAt), 0)
        //     if c.config.time().Sub(createdAt) > maxSessionTicketLifetime { return nil }
        let createdAt = crate::time::Unix(sessionState.__createdAt() as crate::types::int64, 0);
        if self.c.__config().time().Sub(createdAt) > super::common::maxSessionTicketLifetime {
            return errors::nil;
        }

        // Go: Never resume a session for a different TLS version.
        if self.c.__vers() != sessionState.__version() {
            return errors::nil;
        }

        // Go: cipherSuiteOk := false
        //     // Check that the client is still offering the ciphersuite in the session.
        //     for _, id := range hs.clientHello.cipherSuites {
        //         if id == sessionState.cipherSuite { cipherSuiteOk = true; break } }
        //     if !cipherSuiteOk { return nil }
        let mut cipherSuiteOk = false;
        for id in self.clientHello.cipherSuites.iter() {
            if *id == sessionState.__cipherSuite() {
                cipherSuiteOk = true;
                break;
            }
        }
        if !cipherSuiteOk {
            return errors::nil;
        }

        // Go: Check that we also support the ciphersuite from the session.
        // Go: suite := selectCipherSuite([]uint16{sessionState.cipherSuite},
        //         c.config.supportedCipherSuites(), hs.cipherSuiteOk)
        //     if suite == nil { return nil }
        let (ecdheOk, ecSignOk, rsaDecryptOk, rsaSignOk) = (
            self.ecdheOk,
            self.ecSignOk,
            self.rsaDecryptOk,
            self.rsaSignOk,
        );
        let vers = self.c.__vers();
        let suite = super::cipher_suites::selectCipherSuite(
            slice::__from_vec(alloc::vec![sessionState.__cipherSuite()]),
            self.c.__config().supportedCipherSuites(),
            &|c: &'static super::cipher_suites::cipherSuite| {
                if c.flags & super::cipher_suites::suiteECDHE != 0 {
                    if !ecdheOk {
                        return false;
                    }
                    if c.flags & super::cipher_suites::suiteECSign != 0 {
                        if !ecSignOk {
                            return false;
                        }
                    } else if !rsaSignOk {
                        return false;
                    }
                } else if !rsaDecryptOk {
                    return false;
                }
                if vers < super::common::VersionTLS12
                    && c.flags & super::cipher_suites::suiteTLS12 != 0
                {
                    return false;
                }
                return true;
            },
        );
        if suite.is_none() {
            return errors::nil;
        }

        // Go: sessionHasClientCerts := len(sessionState.peerCertificates) != 0
        //     needClientCerts := requiresClientCert(c.config.ClientAuth)
        //     if needClientCerts && !sessionHasClientCerts { return nil }
        //     if sessionHasClientCerts && c.config.ClientAuth == NoClientCert { return nil }
        //     if sessionHasClientCerts && c.config.time().After(
        //         sessionState.peerCertificates[0].NotAfter) { return nil }
        //     if sessionHasClientCerts && c.config.ClientAuth >= VerifyClientCertIfGiven &&
        //         len(sessionState.verifiedChains) == 0 { return nil }
        let peers = sessionState.__peerCertificates();
        let sessionHasClientCerts = peers.Len() != 0;
        let clientAuth = self.c.__configClientAuth();
        let needClientCerts = super::common::requiresClientCert(clientAuth);
        if needClientCerts && !sessionHasClientCerts {
            return errors::nil;
        }
        if sessionHasClientCerts && clientAuth == super::common::NoClientCert {
            return errors::nil;
        }
        if sessionHasClientCerts && self.c.__config().time().After(peers[0].NotAfter) {
            return errors::nil;
        }
        if sessionHasClientCerts
            && clientAuth.0 >= super::common::VerifyClientCertIfGiven.0
            && sessionState.__verifiedChains().Len() == 0
        {
            return errors::nil;
        }

        // Go: RFC 7627, Section 5.3
        // Go: if !sessionState.extMasterSecret && hs.clientHello.extendedMasterSecret {
        //         return nil }
        //     if sessionState.extMasterSecret && !hs.clientHello.extendedMasterSecret {
        //         // Aborting is somewhat harsh, but it's a MUST and it would
        //         // indicate a weird downgrade in client capabilities.
        //         return errors.New("tls: session supported extended_master_secret
        //             but client does not") }
        if !sessionState.__extMasterSecret() && self.clientHello.extendedMasterSecret {
            return errors::nil;
        }
        if sessionState.__extMasterSecret() && !self.clientHello.extendedMasterSecret {
            return errors::New(
                "tls: session supported extended_master_secret but client does not",
            );
        }
        // Go: if !sessionState.extMasterSecret && fips140tls.Required() {
        //         // FIPS 140-3 requires the use of Extended Master Secret.
        //         return nil }
        if !sessionState.__extMasterSecret() && super::internal::fips140tls::Required() {
            return errors::nil;
        }

        // Go: c.peerCertificates = sessionState.peerCertificates … c.didResume = true
        self.c.__adoptSession(&sessionState);
        self.sessionState = Some(sessionState);
        self.suite = suite;
        return errors::nil;
    }
}

impl serverHandshakeState {
    // go: sdk 1.25.5 crypto/tls/handshake_server.go:833-866 serverHandshakeState.readFinished
    /// Go: read the client's ChangeCipherSpec and Finished, check the
    /// verify_data in constant time, and only then add the message to
    /// the transcript.
    ///
    /// Deviation: `out` is `&mut slice<byte>` — goish slices do not share
    /// a backing array across handles, so Go's `copy(out, …)` would be
    /// invisible to the caller through a by-value parameter.
    pub(crate) fn readFinished(&mut self, out: &mut slice<crate::types::byte>) -> crate::error {
        // Go: if err := c.readChangeCipherSpec(); err != nil { return err }
        let err = self.c.readChangeCipherSpec();
        if err != crate::errors::nil {
            return err;
        }

        // Go: "finishedMsg is included in the transcript, but not until
        // after we check the client version, since the state before this
        // message was sent is used during verification."
        let (msg, err) = self.c.readHandshake(None);
        if err != crate::errors::nil {
            return err;
        }
        // Go: clientFinished, ok := msg.(*finishedMsg); if !ok { … }
        let msg = match msg {
            Some(m) => m,
            None => return crate::errors::New("tls: internal error: no handshake message"),
        };
        let clientFinished = match msg
            .asAny()
            .downcast_ref::<super::handshake_messages::finishedMsg>()
        {
            Some(f) => f.clone(),
            None => {
                self.c.sendAlert(super::alert::alertUnexpectedMessage);
                return super::common::unexpectedMessageError(
                    crate::gostring::string::from_static("*tls.finishedMsg"),
                    super::handshake_messages::handshakeMessageTypeName(&*msg),
                );
            }
        };

        // Go: verify := hs.finishedHash.clientSum(hs.masterSecret)
        //     if len(verify) != len(clientFinished.verifyData) ||
        //         subtle.ConstantTimeCompare(verify, clientFinished.verifyData) != 1 {
        //         c.sendAlert(alertHandshakeFailure)
        //         return errors.New("tls: client's Finished message is incorrect") }
        let verify = self.finishedHash.clientSum(self.masterSecret.clone());
        let got = slice::__from_vec(clientFinished.verifyData.clone());
        if verify.Len() != got.Len()
            || crate::crypto::subtle::ConstantTimeCompare(&verify, &got) != 1
        {
            self.c.sendAlert(super::alert::alertHandshakeFailure);
            return crate::errors::New("tls: client's Finished message is incorrect");
        }

        // Go: if err := transcriptMsg(clientFinished, &hs.finishedHash); err != nil { return err }
        let err = super::handshake_messages::transcriptMsg(&clientFinished, &mut self.finishedHash);
        if err != crate::errors::nil {
            return err;
        }

        // Go: copy(out, verify)
        super::handshake_client::copyInto(out, &verify.__into_vec());
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_server.go:907-923 serverHandshakeState.sendFinished
    /// Go: flush the pending records under a ChangeCipherSpec, then send
    /// the server's Finished and copy its verify_data into `out`.
    ///
    /// Deviation: `out` is `&mut slice<byte>`; see `readFinished`.
    pub(crate) fn sendFinished(&mut self, out: &mut slice<crate::types::byte>) -> crate::error {
        // Go: if err := c.writeChangeCipherRecord(); err != nil { return err }
        let err = self.c.writeChangeCipherRecord();
        if err != crate::errors::nil {
            return err;
        }

        // Go: finished := new(finishedMsg)
        //     finished.verifyData = hs.finishedHash.serverSum(hs.masterSecret)
        let mut finished = super::handshake_messages::finishedMsg::default();
        finished.verifyData = self
            .finishedHash
            .serverSum(self.masterSecret.clone())
            .__into_vec();
        // Go: if _, err := hs.c.writeHandshakeRecord(finished, &hs.finishedHash); err != nil { return err }
        let (_, err) = self
            .c
            .writeHandshakeRecord(&finished, Some(&mut self.finishedHash));
        if err != crate::errors::nil {
            return err;
        }

        // Go: copy(out, finished.verifyData)
        super::handshake_client::copyInto(out, &finished.verifyData);
        return crate::errors::nil;
    }
}

use super::conn::Conn;

impl Conn {
    // go: sdk 1.25.5 crypto/tls/handshake_server.go:927-1007 Conn.processCertsFromClient
    /// Go: parse the client's certificate chain, enforce the RSA key-size
    /// cap, verify it against ClientCAs when the policy requires it, record
    /// the peer material, check the leaf key type, and run any
    /// VerifyPeerCertificate hook.
    pub(crate) fn processCertsFromClient(
        &mut self,
        certificate: super::common::Certificate,
    ) -> crate::error {
        use crate::goslice::slice;
        // Go: certificates := certificate.Certificate
        //     certs := make([]*x509.Certificate, len(certificates))
        let certificates = certificate.Certificate.clone();
        let mut certs: alloc::vec::Vec<crate::crypto::x509::Certificate> = alloc::vec::Vec::new();
        // Go: for i, asn1Data := range certificates {
        //         if certs[i], err = x509.ParseCertificate(asn1Data); err != nil {
        //             c.sendAlert(alertDecodeError)
        //             return errors.New("tls: failed to parse client certificate: " + err.Error()) }
        //         if certs[i].PublicKeyAlgorithm == x509.RSA {
        //             n := certs[i].PublicKey.(*rsa.PublicKey).N.BitLen()
        //             if max, ok := checkKeySize(n); !ok {
        //                 c.sendAlert(alertBadCertificate)
        //                 return fmt.Errorf("tls: client sent certificate containing RSA key larger than %d bits", max) } } }
        for (_, asn1Data) in crate::range!(certificates.clone()) {
            let (cert, err) = crate::crypto::x509::ParseCertificate(asn1Data.clone());
            if err != crate::errors::nil {
                self.sendAlert(super::alert::alertDecodeError);
                return crate::fmt::Errorf!(
                    "tls: failed to parse client certificate: %s",
                    err.Error()
                );
            }
            if cert.PublicKeyAlgorithm == crate::crypto::x509::RSA {
                let n = match cert.PublicKey.As::<crate::crypto::rsa::PublicKey>() {
                    Some(k) => k.N.BitLen(),
                    None => 0,
                };
                let (max, ok) = super::handshake_client::checkKeySize(n);
                if !ok {
                    self.sendAlert(super::alert::alertBadCertificate);
                    return crate::fmt::Errorf!(
                        "tls: client sent certificate containing RSA key larger than %d bits",
                        max
                    );
                }
            }
            certs.push(cert);
        }

        // Go: if len(certs) == 0 && requiresClientCert(c.config.ClientAuth) {
        //         if c.vers == VersionTLS13 { c.sendAlert(alertCertificateRequired) }
        //         else { c.sendAlert(alertHandshakeFailure) }
        //         return errors.New("tls: client didn't provide a certificate") }
        if certs.is_empty() && super::common::requiresClientCert(self.config.ClientAuth) {
            if self.vers == super::common::VersionTLS13 {
                self.sendAlert(super::alert::alertCertificateRequired);
            } else {
                self.sendAlert(super::alert::alertHandshakeFailure);
            }
            return crate::errors::New("tls: client didn't provide a certificate");
        }

        // Go: if c.config.ClientAuth >= VerifyClientCertIfGiven && len(certs) > 0 {
        if self.config.ClientAuth >= super::common::VerifyClientCertIfGiven && !certs.is_empty() {
            // Go: opts := x509.VerifyOptions{ Roots: c.config.ClientCAs,
            //         CurrentTime: c.config.time(), Intermediates: x509.NewCertPool(),
            //         KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }
            let mut opts = crate::crypto::x509::VerifyOptions::default();
            opts.Roots = self.config.ClientCAs.clone();
            opts.CurrentTime = self.config.time();
            let mut inter = crate::crypto::x509::NewCertPool();
            // Go: for _, cert := range certs[1:] { opts.Intermediates.AddCert(cert) }
            for cert in certs[1..].iter() {
                inter.AddCert(cert.clone());
            }
            opts.Intermediates = Some(inter);
            opts.KeyUsages =
                slice::__from_vec(alloc::vec![crate::crypto::x509::ExtKeyUsageClientAuth]);

            // Go: chains, err := certs[0].Verify(opts)
            //     if err != nil { … alert by error type …
            //         return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err} }
            let (chains, err) = certs[0].Verify(opts);
            if err != crate::errors::nil {
                if crate::errors::As::<crate::crypto::x509::UnknownAuthorityError>(err.clone())
                    .is_some()
                {
                    self.sendAlert(super::alert::alertUnknownCA);
                } else if let Some(ci) =
                    crate::errors::As::<crate::crypto::x509::CertificateInvalidError>(err.clone())
                {
                    if ci.Reason == crate::crypto::x509::Expired {
                        self.sendAlert(super::alert::alertCertificateExpired);
                    } else {
                        self.sendAlert(super::alert::alertBadCertificate);
                    }
                } else {
                    self.sendAlert(super::alert::alertBadCertificate);
                }
                return super::common::CertificateVerificationError {
                    UnverifiedCertificates: slice::__from_vec(certs.clone()),
                    Err: err,
                }
                .into();
            }

            // Go: c.verifiedChains, err = fipsAllowedChains(chains)
            //     if err != nil { c.sendAlert(alertBadCertificate)
            //         return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err} }
            let (allowed, err) = super::common::fipsAllowedChains(chains);
            if err != crate::errors::nil {
                self.sendAlert(super::alert::alertBadCertificate);
                return super::common::CertificateVerificationError {
                    UnverifiedCertificates: slice::__from_vec(certs.clone()),
                    Err: err,
                }
                .into();
            }
            self.verifiedChains = allowed;
        }

        // Go: c.peerCertificates = certs
        //     c.ocspResponse = certificate.OCSPStaple
        //     c.scts = certificate.SignedCertificateTimestamps
        self.peerCertificates = slice::__from_vec(certs.clone());
        self.ocspResponse = certificate.OCSPStaple.clone();
        self.scts = certificate.SignedCertificateTimestamps.clone();

        // Go: if len(certs) > 0 { switch certs[0].PublicKey.(type) {
        //         case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
        //         default: c.sendAlert(alertUnsupportedCertificate)
        //             return fmt.Errorf("tls: client certificate contains an unsupported public key of type %T", certs[0].PublicKey) } }
        if !certs.is_empty() {
            let supported = certs[0]
                .PublicKey
                .As::<crate::crypto::ecdsa::PublicKey>()
                .is_some()
                || certs[0]
                    .PublicKey
                    .As::<crate::crypto::rsa::PublicKey>()
                    .is_some()
                || certs[0]
                    .PublicKey
                    .As::<crate::crypto::ed25519::PublicKey>()
                    .is_some();
            if !supported {
                self.sendAlert(super::alert::alertUnsupportedCertificate);
                return crate::fmt::Errorf!(
                    "tls: client certificate contains an unsupported public key of type %s",
                    super::handshake_client::publicKeyTypeName(&certs[0])
                );
            }
        }

        // Go: if c.config.VerifyPeerCertificate != nil {
        //         if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
        //             c.sendAlert(alertBadCertificate); return err } }
        if let Some(verify) = self.config.VerifyPeerCertificate.clone() {
            let err = verify(
                slice::__from_vec(certificates.iter().cloned().collect()),
                self.verifiedChains.clone(),
            );
            if err != crate::errors::nil {
                self.sendAlert(super::alert::alertBadCertificate);
                return err;
            }
        }

        // Go: return nil
        return crate::errors::nil;
    }
}

impl super::conn::Conn {
    // go: sdk 1.25.5 crypto/tls/handshake_server.go:42-64 Conn.serverHandshake
    /// Go: the server handshake entry point — read the ClientHello,
    /// then dispatch to the TLS 1.3 or TLS 1.0–1.2 server driver.
    ///
    /// Deviation: Go's `ctx context.Context` parameter has no field to
    /// land in on either handshake state.
    /// goishlint:ignore GOISH020 serverHandshake — Go's context.Context parameter has no field to land in
    pub(crate) fn serverHandshake(&mut self) -> crate::error {
        // Go: clientHello, ech, err := c.readClientHello(ctx)
        //     if err != nil { return err }
        let (clientHello, ech, err) = self.readClientHello();
        if err != crate::errors::nil {
            return err;
        }
        let clientHello = clientHello.unwrap();

        // Go: if c.vers == VersionTLS13 {
        //         hs := serverHandshakeStateTLS13{ c: c, ctx: ctx,
        //             clientHello: clientHello, echContext: ech }
        //         return hs.handshake() }
        if self.vers == super::common::VersionTLS13 {
            let mut hs = super::handshake_server_tls13::serverHandshakeStateTLS13 {
                c: core::mem::take(self),
                clientHello,
                echContext: ech,
                ..Default::default()
            };
            let err = hs.handshake();
            *self = hs.c;
            return err;
        }

        // Go: hs := serverHandshakeState{ c: c, ctx: ctx, clientHello: clientHello }
        //     return hs.handshake()
        let mut hs = serverHandshakeState {
            c: core::mem::take(self),
            clientHello,
            hello: super::handshake_messages::serverHelloMsg::default(),
            suite: None,
            finishedHash: super::prf::newFinishedHash(
                super::common::VersionTLS12,
                super::cipher_suites::cipherSuiteByID(
                    super::cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                )
                .unwrap(),
            ),
            masterSecret: slice::new(),
            sessionState: None,
            ecdheOk: false,
            ecSignOk: false,
            rsaDecryptOk: false,
            rsaSignOk: false,
            cert: None,
        };
        let err = hs.handshake();
        *self = hs.c;
        return err;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_server.go:134-217 Conn.readClientHello
    /// Go: read and pre-process the ClientHello — decrypt an ECH
    /// extension if present (it may swap the hello out entirely), then
    /// negotiate the protocol version.
    ///
    /// Deviations: Go's `ctx context.Context` has nowhere to go; the
    /// `GetConfigForClient` per-connection config override is absent
    /// (goish's Config has no such field); the `tls10server` GODEBUG
    /// bump is absent.
    /// goishlint:ignore GOISH020 readClientHello — Go's context.Context parameter has no field to land in
    pub(crate) fn readClientHello(
        &mut self,
    ) -> (
        Option<super::handshake_messages::clientHelloMsg>,
        Option<super::handshake_server_tls13::echServerContext>,
        crate::error,
    ) {
        // Go: "clientHelloMsg is included in the transcript, but we
        // haven't initialized it yet. […]"
        //     msg, err := c.readHandshake(nil)
        //     if err != nil { return nil, nil, err }
        let (msg, err) = self.readHandshake(None);
        if err != crate::errors::nil {
            return (None, None, err);
        }
        // Go: clientHello, ok := msg.(*clientHelloMsg)
        //     if !ok { c.sendAlert(alertUnexpectedMessage)
        //         return nil, nil, unexpectedMessageError(clientHello, msg) }
        let msg = match msg {
            Some(m) => m,
            None => {
                return (
                    None,
                    None,
                    crate::errors::New("tls: internal error: no handshake message"),
                )
            }
        };
        let mut clientHello = match msg
            .asAny()
            .downcast_ref::<super::handshake_messages::clientHelloMsg>()
        {
            Some(ch) => ch.clone(),
            None => {
                self.sendAlert(super::alert::alertUnexpectedMessage);
                return (
                    None,
                    None,
                    super::common::unexpectedMessageError(
                        crate::gostring::string::from_static("*tls.clientHelloMsg"),
                        super::handshake_messages::handshakeMessageTypeName(&*msg),
                    ),
                );
            }
        };

        // Go: "ECH processing has to be done before we do any other
        // negotiation based on the contents of the client hello […]"
        //     var ech *echServerContext
        //     if len(clientHello.encryptedClientHello) != 0 {
        //         echKeys := c.config.EncryptedClientHelloKeys
        //         if c.config.GetEncryptedClientHelloKeys != nil {
        //             echKeys, err = c.config.GetEncryptedClientHelloKeys(clientHelloInfo(ctx, c, clientHello))
        //             if err != nil { c.sendAlert(alertInternalError); return nil, nil, err } }
        //         clientHello, ech, err = c.processECHClientHello(clientHello, echKeys)
        //         if err != nil { return nil, nil, err } }
        let mut ech: Option<super::handshake_server_tls13::echServerContext> = None;
        if clientHello.encryptedClientHello.len() != 0 {
            let mut echKeys = self.config.EncryptedClientHelloKeys.clone();
            if let Some(get) = self.config.GetEncryptedClientHelloKeys.clone() {
                let (keys, err) = get(clientHelloInfo(self, &clientHello));
                if err != crate::errors::nil {
                    self.sendAlert(super::alert::alertInternalError);
                    return (None, None, err);
                }
                echKeys = keys;
            }
            let (newHello, newEch, err) = self.processECHClientHello(&clientHello, echKeys);
            if err != crate::errors::nil {
                return (None, None, err);
            }
            clientHello = newHello.unwrap();
            ech = newEch;
        }

        // Go: c.ticketKeys = originalConfig.ticketKeys(configForClient)
        //
        // goish: the GetConfigForClient override is not ported, so
        // `configForClient` is always nil and the original config's keys
        // apply.
        self.ticketKeys = self.config.ticketKeys(None);

        // Go: clientVersions := clientHello.supportedVersions
        //     if clientHello.vers >= VersionTLS13 && len(clientVersions) == 0 {
        //         clientVersions = supportedVersionsFromMax(VersionTLS12)
        //     } else if len(clientVersions) == 0 {
        //         clientVersions = supportedVersionsFromMax(clientHello.vers) }
        let mut clientVersions = slice::__from_vec(clientHello.supportedVersions.clone());
        if clientHello.vers >= super::common::VersionTLS13 && clientVersions.len() == 0 {
            clientVersions = super::common::supportedVersionsFromMax(super::common::VersionTLS12);
        } else if clientVersions.len() == 0 {
            clientVersions = super::common::supportedVersionsFromMax(clientHello.vers);
        }
        // Go: c.vers, ok = c.config.mutualVersion(roleServer, clientVersions)
        //     if !ok { c.sendAlert(alertProtocolVersion)
        //         return nil, nil, fmt.Errorf("tls: client offered only unsupported versions: %x", clientVersions) }
        let (vers, ok) = self
            .config
            .mutualVersion(super::common::roleServer, clientVersions.clone());
        if !ok {
            self.sendAlert(super::alert::alertProtocolVersion);
            // Go formats the []uint16 itself, so `%x` renders each
            // version as its own hex number inside brackets: "[304]".
            // goish used to flatten the versions into BYTES first,
            // which `%x` then renders as one hex STRING — "0304" — a
            // different message for the same condition. That predates
            // fmt handling `%x` on a non-byte slice; it does now, so
            // the slice goes through as Go's does.
            return (
                None,
                None,
                crate::fmt::Errorf!(
                    "tls: client offered only unsupported versions: %x",
                    clientVersions.clone()
                ),
            );
        }
        self.vers = vers;
        // Go: c.haveVers = true
        //     c.in.version = c.vers
        //     c.out.version = c.vers
        self.haveVers = true;
        self.in_.version = self.vers;
        self.out.version = self.vers;

        // Go: "This check reflects some odd specification implied
        // behavior. […]"
        //     if c.vers != VersionTLS13 && (ech != nil && !ech.inner) {
        //         c.sendAlert(alertIllegalParameter)
        //         return nil, nil, errors.New("tls: Encrypted Client Hello cannot be used pre-TLS 1.3") }
        if self.vers != super::common::VersionTLS13
            && ech.as_ref().map(|e| !e.inner).unwrap_or(false)
        {
            self.sendAlert(super::alert::alertIllegalParameter);
            return (
                None,
                None,
                crate::errors::New("tls: Encrypted Client Hello cannot be used pre-TLS 1.3"),
            );
        }

        // Go: if c.config.MinVersion == 0 && c.vers < VersionTLS12 {
        //         tls10server.Value(); tls10server.IncNonDefault() }
        //
        // goish: godebug counters are not ported.

        // Go: return clientHello, ech, nil
        return (Some(clientHello), ech, crate::errors::nil);
    }
}
