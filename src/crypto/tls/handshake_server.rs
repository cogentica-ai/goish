// go: file crypto/tls/handshake_server.go decls: supportsECDHE, negotiateALPN, serverHandshakeState.cipherSuiteOk, clientHelloInfo, serverHandshakeState.pickCipherSuite, serverHandshakeState.establishKeys, serverHandshakeState.checkForResumption
//
// crypto/tls — the server handshake state machine.
//
// **Partial port.** handshake_server.go is 1000 lines of
// `serverHandshakeState`, which owns a Conn and drives the TLS 1.0-1.2
// handshake. What is here is the one function that does not: the ECDHE
// support check, which `ClientHelloInfo.SupportsCertificate` also calls.
//
// goishlint:ignore GOISH018 serverHandshake, handshake, readClientHello, processClientHello, doResumeHandshake, doFullHandshake, readFinished, sendSessionTicket, sendFinished, processCertsFromClient — serverHandshakeState and Conn; see the banner. ROADMAP.md.

#![allow(non_snake_case, dead_code)]

extern crate alloc;

use super::common::{pointFormatUncompressed, CurveID};
use super::Config;
use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::types::{int, uint16, uint8};

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
    pub clientHello: super::handshake_messages::clientHelloMsg,
    pub hello: super::handshake_messages::serverHelloMsg,
    pub suite: Option<&'static super::cipher_suites::cipherSuite>,
    pub masterSecret: slice<crate::types::byte>,
    pub sessionState: Option<super::ticket::SessionState>,
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


impl serverHandshakeState {
    // go: sdk 1.25.5 crypto/tls/handshake_server.go:406-439 serverHandshakeState.pickCipherSuite
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
        let (ecdheOk, ecSignOk, rsaDecryptOk, rsaSignOk) =
            (self.ecdheOk, self.ecSignOk, self.rsaDecryptOk, self.rsaSignOk);
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
    // go: sdk 1.25.5 crypto/tls/handshake_server.go:770-791 serverHandshakeState.establishKeys
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
        self.c.__prepareCipherSpecs(vers, clientCipher, clientHash, serverCipher, serverHash);
        return errors::nil;
    }
}


impl serverHandshakeState {
    // go: sdk 1.25.5 crypto/tls/handshake_server.go:566-664 serverHandshakeState.checkForResumption
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
        let plaintext = self.c.__config().decryptTicket(ticket, self.c.__ticketKeys());
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
        let (ecdheOk, ecSignOk, rsaDecryptOk, rsaSignOk) =
            (self.ecdheOk, self.ecSignOk, self.rsaDecryptOk, self.rsaSignOk);
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
        if !sessionState.__extMasterSecret()
            && super::internal::fips140tls::Required()
        {
            return errors::nil;
        }

        // Go: c.peerCertificates = sessionState.peerCertificates … c.didResume = true
        self.c.__adoptSession(&sessionState);
        self.sessionState = Some(sessionState);
        self.suite = suite;
        return errors::nil;
    }
}
