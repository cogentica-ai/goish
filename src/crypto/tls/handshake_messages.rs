// goishlint:ignore GOISH018 addBytesWithLength, addUint64, clone, marshalCertificate, marshalMsg, marshalWithoutBinders, originalBytes, readUint16LengthPrefixed, readUint24LengthPrefixed, readUint64, readUint8LengthPrefixed, transcriptMsg, unmarshalCertificate, updateBinders — handshake_messages.go is 1963 lines and 52 functions; this file is a deliberate SUBSET covering only the messages goish's own TLS 1.3 client and server exchange. The six it does port are anchored above and diffed against Go; everything listed here is genuinely absent, not renamed. See ROADMAP.md.
// goishlint:ignore GOISH021 certificateMsg, certificateRequestMsg, certificateRequestMsgTLS13, certificateStatusMsg, clientKeyExchangeMsg, endOfEarlyDataMsg, helloRequestMsg, keyUpdateMsg, marshalingFunction, newSessionTicketMsg, newSessionTicketMsgTLS13, serverHelloDoneMsg, serverKeyExchangeMsg, transcriptHash — same: the message types the subset does not handle.
// go: file crypto/tls/handshake_messages.go decls: clientHelloMsg.unmarshal, serverHelloMsg.marshal, encryptedExtensionsMsg.marshal, certificateMsgTLS13.marshal, certificateVerifyMsg.marshal, finishedMsg.marshal, keyUpdateMsg.marshal, keyUpdateMsg.unmarshal, endOfEarlyDataMsg.marshal, endOfEarlyDataMsg.unmarshal, certificateStatusMsg.marshal, certificateStatusMsg.unmarshal, readUint8LengthPrefixed, readUint16LengthPrefixed, readUint24LengthPrefixed
// crypto/tls/handshake_messages.rs — TLS handshake message
// marshal/unmarshal, server-side subset.
//
// Port of Go 1.25.5 crypto/tls/handshake_messages.go:
//   clientHelloMsg + unmarshal          (handshake_messages.go:418)
//   serverHelloMsg + marshal            (handshake_messages.go:746)
//   encryptedExtensionsMsg + marshal    (handshake_messages.go:1011)
//   certificateMsgTLS13 + marshal       (handshake_messages.go:1465)
//   marshalCertificate                  (handshake_messages.go:1484)
//   certificateVerifyMsg + marshal      (handshake_messages.go:1854)
//   finishedMsg + marshal               (handshake_messages.go:1697)
//
// Go builds/parses these with golang.org/x/crypto/cryptobyte; the
// `builder` / `cbs` types below are a minimal port of the
// cryptobyte.Builder / cryptobyte.String operations those functions
// use (AddUint8/16/24, length-prefixed groups, ReadUintN,
// ReadUintNLengthPrefixed).
//
// These structs are unexported in Go (`clientHelloMsg` etc.), so the
// Rust-internal `Vec<byte>` / `String` field types are acceptable here
// — nothing in this file is part of the public Goish API surface.

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]
#![allow(dead_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::types::byte;

// ─── handshake message types (common.go:81) ─────────────────────────

pub(crate) const typeClientHello: byte = 1;
pub(crate) const typeServerHello: byte = 2;
pub(crate) const typeNewSessionTicket: byte = 4;
pub(crate) const typeEncryptedExtensions: byte = 8;
pub(crate) const typeCertificate: byte = 11;
pub(crate) const typeCertificateRequest: byte = 13;
pub(crate) const typeCertificateVerify: byte = 15;
pub(crate) const typeFinished: byte = 20;

// ─── TLS extension numbers (common.go:110) ──────────────────────────

pub(crate) const extensionServerName: u16 = 0;
pub(crate) const extensionStatusRequest: u16 = 5;
pub(crate) const extensionSupportedCurves: u16 = 10;
pub(crate) const extensionSupportedPoints: u16 = 11;
pub(crate) const extensionSignatureAlgorithms: u16 = 13;
pub(crate) const extensionALPN: u16 = 16;
pub(crate) const extensionSCT: u16 = 18;
pub(crate) const extensionExtendedMasterSecret: u16 = 23;
pub(crate) const extensionSessionTicket: u16 = 35;
pub(crate) const extensionPreSharedKey: u16 = 41;
pub(crate) const extensionEarlyData: u16 = 42;
pub(crate) const extensionSupportedVersions: u16 = 43;
pub(crate) const extensionCookie: u16 = 44;
pub(crate) const extensionPSKModes: u16 = 45;
pub(crate) const extensionSignatureAlgorithmsCert: u16 = 50;
pub(crate) const extensionKeyShare: u16 = 51;
pub(crate) const extensionQUICTransportParameters: u16 = 57;
pub(crate) const extensionRenegotiationInfo: u16 = 0xff01;
pub(crate) const extensionEncryptedClientHello: u16 = 0xfe0d;

/// TLS signaling cipher suite values (common.go:136).
pub(crate) const scsvRenegotiation: u16 = 0x00ff;
pub(crate) const TLS_FALLBACK_SCSV: u16 = 0x5600;

/// TLS compression types (common.go:105).
pub(crate) const compressionNone: byte = 0;

// ─── cryptobyte.String (parser) ─────────────────────────────────────
//
// Minimal port of the cryptobyte.String read operations used by
// clientHelloMsg.unmarshal. Every method mirrors the Go method of the
// same (Go-cased) name and returns `false`/`None` on underflow.

pub(crate) struct cbs<'a> {
    s: &'a [byte],
}

impl<'a> cbs<'a> {
    pub(crate) fn new(s: &'a [byte]) -> cbs<'a> {
        cbs { s }
    }

    pub(crate) fn Empty(&self) -> bool {
        self.s.is_empty()
    }

    pub(crate) fn Skip(&mut self, n: usize) -> bool {
        if self.s.len() < n {
            return false;
        }
        self.s = &self.s[n..];
        true
    }

    pub(crate) fn ReadUint8(&mut self, out: &mut u8) -> bool {
        if self.s.is_empty() {
            return false;
        }
        *out = self.s[0];
        self.s = &self.s[1..];
        true
    }

    pub(crate) fn ReadUint16(&mut self, out: &mut u16) -> bool {
        if self.s.len() < 2 {
            return false;
        }
        *out = ((self.s[0] as u16) << 8) | (self.s[1] as u16);
        self.s = &self.s[2..];
        true
    }

    pub(crate) fn ReadUint24(&mut self, out: &mut u32) -> bool {
        if self.s.len() < 3 {
            return false;
        }
        *out = ((self.s[0] as u32) << 16) | ((self.s[1] as u32) << 8) | (self.s[2] as u32);
        self.s = &self.s[3..];
        true
    }

    pub(crate) fn ReadUint32(&mut self, out: &mut u32) -> bool {
        if self.s.len() < 4 {
            return false;
        }
        *out = ((self.s[0] as u32) << 24)
            | ((self.s[1] as u32) << 16)
            | ((self.s[2] as u32) << 8)
            | (self.s[3] as u32);
        self.s = &self.s[4..];
        true
    }

    pub(crate) fn ReadBytes(&mut self, n: usize) -> Option<&'a [byte]> {
        if self.s.len() < n {
            return None;
        }
        let (head, tail) = self.s.split_at(n);
        self.s = tail;
        Some(head)
    }

    pub(crate) fn ReadUint8LengthPrefixed(&mut self) -> Option<cbs<'a>> {
        let mut n: u8 = 0;
        if !self.ReadUint8(&mut n) {
            return None;
        }
        self.ReadBytes(n as usize).map(cbs::new)
    }

    pub(crate) fn ReadUint16LengthPrefixed(&mut self) -> Option<cbs<'a>> {
        let mut n: u16 = 0;
        if !self.ReadUint16(&mut n) {
            return None;
        }
        self.ReadBytes(n as usize).map(cbs::new)
    }

    pub(crate) fn ReadUint24LengthPrefixed(&mut self) -> Option<cbs<'a>> {
        let mut n: u32 = 0;
        if !self.ReadUint24(&mut n) {
            return None;
        }
        self.ReadBytes(n as usize).map(cbs::new)
    }

    pub(crate) fn rest(&self) -> &'a [byte] {
        self.s
    }
}

// ─── cryptobyte.Builder ─────────────────────────────────────────────
//
// Minimal port of the cryptobyte.Builder operations used by the
// marshal functions: AddUint8/16/24, AddBytes, and the closure-based
// length-prefixed groups.

pub(crate) struct builder {
    b: Vec<byte>,
}

impl builder {
    pub(crate) fn new() -> builder {
        builder { b: Vec::new() }
    }

    pub(crate) fn AddUint8(&mut self, v: u8) {
        self.b.push(v);
    }

    pub(crate) fn AddUint16(&mut self, v: u16) {
        self.b.push((v >> 8) as byte);
        self.b.push((v & 0xff) as byte);
    }

    pub(crate) fn AddUint24(&mut self, v: u32) {
        self.b.push(((v >> 16) & 0xff) as byte);
        self.b.push(((v >> 8) & 0xff) as byte);
        self.b.push((v & 0xff) as byte);
    }

    pub(crate) fn AddUint32(&mut self, v: u32) {
        self.b.push(((v >> 24) & 0xff) as byte);
        self.b.push(((v >> 16) & 0xff) as byte);
        self.b.push(((v >> 8) & 0xff) as byte);
        self.b.push((v & 0xff) as byte);
    }

    pub(crate) fn AddBytes(&mut self, v: &[byte]) {
        self.b.extend_from_slice(v);
    }

    pub(crate) fn AddUint8LengthPrefixed(&mut self, f: impl FnOnce(&mut builder)) {
        let at = self.b.len();
        self.b.push(0);
        f(self);
        let n = self.b.len() - at - 1;
        self.b[at] = n as byte;
    }

    pub(crate) fn AddUint16LengthPrefixed(&mut self, f: impl FnOnce(&mut builder)) {
        let at = self.b.len();
        self.b.extend_from_slice(&[0, 0]);
        let n0 = self.b.len();
        f(self);
        let n = self.b.len() - n0;
        self.b[at] = ((n >> 8) & 0xff) as byte;
        self.b[at + 1] = (n & 0xff) as byte;
    }

    pub(crate) fn AddUint24LengthPrefixed(&mut self, f: impl FnOnce(&mut builder)) {
        let at = self.b.len();
        self.b.extend_from_slice(&[0, 0, 0]);
        let n0 = self.b.len();
        f(self);
        let n = self.b.len() - n0;
        self.b[at] = ((n >> 16) & 0xff) as byte;
        self.b[at + 1] = ((n >> 8) & 0xff) as byte;
        self.b[at + 2] = (n & 0xff) as byte;
    }

    pub(crate) fn Bytes(self) -> Vec<byte> {
        self.b
    }
}

// ─── keyShare / pskIdentity (common.go:214, :220) ───────────────────

/// `keyShare` — a TLS 1.3 Key Share (RFC 8446, Section 4.2.8).
#[derive(Clone, Default)]
pub(crate) struct keyShare {
    pub group: u16,
    pub data: Vec<byte>,
}

/// `pskIdentity` — a TLS 1.3 PSK Identity (RFC 8446, Section 4.2.11).
#[derive(Clone, Default)]
pub(crate) struct pskIdentity {
    pub label: Vec<byte>,
    pub obfuscatedTicketAge: u32,
}

// ─── clientHelloMsg (handshake_messages.go:70) ──────────────────────

/// Parsed ClientHello. Field-for-field port of Go's `clientHelloMsg`
/// (minus QUIC/ECH fields, which are out of scope for the Goish
/// server).
#[derive(Clone, Default)]
pub(crate) struct clientHelloMsg {
    pub original: Vec<byte>,
    pub vers: u16,
    pub random: Vec<byte>,
    pub sessionId: Vec<byte>,
    pub cipherSuites: Vec<u16>,
    pub compressionMethods: Vec<byte>,
    pub serverName: String,
    pub ocspStapling: bool,
    pub supportedCurves: Vec<u16>,
    pub supportedPoints: Vec<byte>,
    pub ticketSupported: bool,
    pub sessionTicket: Vec<byte>,
    pub supportedSignatureAlgorithms: Vec<u16>,
    pub supportedSignatureAlgorithmsCert: Vec<u16>,
    pub secureRenegotiationSupported: bool,
    pub secureRenegotiation: Vec<byte>,
    pub extendedMasterSecret: bool,
    pub alpnProtocols: Vec<String>,
    pub scts: bool,
    pub supportedVersions: Vec<u16>,
    pub cookie: Vec<byte>,
    pub keyShares: Vec<keyShare>,
    pub earlyData: bool,
    pub pskModes: Vec<byte>,
    pub pskIdentities: Vec<pskIdentity>,
    pub pskBinders: Vec<Vec<byte>>,
}

impl clientHelloMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:418-680 clientHelloMsg.unmarshal
    /// `(*clientHelloMsg).unmarshal(data)` — handshake_messages.go:418.
    /// `data` is the full handshake message including the 4-byte
    /// type+uint24-length header. Returns false on malformed input.
    pub(crate) fn unmarshal(&mut self, data: &[byte]) -> bool {
        *self = clientHelloMsg::default();
        self.original = data.to_vec();
        let mut s = cbs::new(data);

        // Go: !s.Skip(4) || !s.ReadUint16(&m.vers) || !s.ReadBytes(&m.random, 32) ||
        //     !readUint8LengthPrefixed(&s, &m.sessionId)
        if !s.Skip(4) || !s.ReadUint16(&mut self.vers) {
            return false;
        }
        match s.ReadBytes(32) {
            Some(r) => self.random = r.to_vec(),
            None => return false,
        }
        match s.ReadUint8LengthPrefixed() {
            Some(sid) => self.sessionId = sid.rest().to_vec(),
            None => return false,
        }

        // cipher_suites
        let mut cipherSuites = match s.ReadUint16LengthPrefixed() {
            Some(cs) => cs,
            None => return false,
        };
        self.cipherSuites = Vec::new();
        self.secureRenegotiationSupported = false;
        while !cipherSuites.Empty() {
            let mut suite: u16 = 0;
            if !cipherSuites.ReadUint16(&mut suite) {
                return false;
            }
            if suite == scsvRenegotiation {
                self.secureRenegotiationSupported = true;
            }
            self.cipherSuites.push(suite);
        }

        // compression_methods
        match s.ReadUint8LengthPrefixed() {
            Some(cm) => self.compressionMethods = cm.rest().to_vec(),
            None => return false,
        }

        if s.Empty() {
            // ClientHello is optionally followed by extension data.
            return true;
        }

        let mut extensions = match s.ReadUint16LengthPrefixed() {
            Some(e) => e,
            None => return false,
        };
        if !s.Empty() {
            return false;
        }

        // Go uses a map[uint16]bool to reject duplicate extensions;
        // a sorted Vec works the same in no_std.
        let mut seenExts: Vec<u16> = Vec::new();
        while !extensions.Empty() {
            let mut extension: u16 = 0;
            if !extensions.ReadUint16(&mut extension) {
                return false;
            }
            let mut extData = match extensions.ReadUint16LengthPrefixed() {
                Some(d) => d,
                None => return false,
            };

            if seenExts.contains(&extension) {
                return false;
            }
            seenExts.push(extension);

            match extension {
                extensionServerName => {
                    // RFC 6066, Section 3
                    let mut nameList = match extData.ReadUint16LengthPrefixed() {
                        Some(n) => n,
                        None => return false,
                    };
                    if nameList.Empty() {
                        return false;
                    }
                    while !nameList.Empty() {
                        let mut nameType: u8 = 0;
                        if !nameList.ReadUint8(&mut nameType) {
                            return false;
                        }
                        let serverName = match nameList.ReadUint16LengthPrefixed() {
                            Some(n) => n,
                            None => return false,
                        };
                        if serverName.Empty() {
                            return false;
                        }
                        if nameType != 0 {
                            continue;
                        }
                        if !self.serverName.is_empty() {
                            // Multiple names of the same name_type are prohibited.
                            return false;
                        }
                        self.serverName = match core::str::from_utf8(serverName.rest()) {
                            Ok(v) => String::from(v),
                            Err(_) => return false,
                        };
                        // An SNI value may not include a trailing dot.
                        if self.serverName.ends_with('.') {
                            return false;
                        }
                    }
                }
                extensionStatusRequest => {
                    // RFC 4366, Section 3.6
                    let mut statusType: u8 = 0;
                    if !extData.ReadUint8(&mut statusType)
                        || extData.ReadUint16LengthPrefixed().is_none()
                        || extData.ReadUint16LengthPrefixed().is_none()
                    {
                        return false;
                    }
                    // statusTypeOCSP = 1
                    self.ocspStapling = statusType == 1;
                }
                extensionSupportedCurves => {
                    // RFC 4492, Section 5.1.1 and RFC 8446, Section 4.2.7
                    let mut curves = match extData.ReadUint16LengthPrefixed() {
                        Some(c) => c,
                        None => return false,
                    };
                    if curves.Empty() {
                        return false;
                    }
                    while !curves.Empty() {
                        let mut curve: u16 = 0;
                        if !curves.ReadUint16(&mut curve) {
                            return false;
                        }
                        self.supportedCurves.push(curve);
                    }
                }
                extensionSupportedPoints => {
                    // RFC 4492, Section 5.1.2
                    match extData.ReadUint8LengthPrefixed() {
                        Some(p) => self.supportedPoints = p.rest().to_vec(),
                        None => return false,
                    }
                    if self.supportedPoints.is_empty() {
                        return false;
                    }
                }
                extensionSessionTicket => {
                    // RFC 5077, Section 3.2
                    self.ticketSupported = true;
                    self.sessionTicket = extData.rest().to_vec();
                    let _ = extData.Skip(self.sessionTicket.len());
                }
                extensionSignatureAlgorithms => {
                    // RFC 5246, Section 7.4.1.4.1
                    let mut sigAndAlgs = match extData.ReadUint16LengthPrefixed() {
                        Some(a) => a,
                        None => return false,
                    };
                    if sigAndAlgs.Empty() {
                        return false;
                    }
                    while !sigAndAlgs.Empty() {
                        let mut sigAndAlg: u16 = 0;
                        if !sigAndAlgs.ReadUint16(&mut sigAndAlg) {
                            return false;
                        }
                        self.supportedSignatureAlgorithms.push(sigAndAlg);
                    }
                }
                extensionSignatureAlgorithmsCert => {
                    // RFC 8446, Section 4.2.3
                    let mut sigAndAlgs = match extData.ReadUint16LengthPrefixed() {
                        Some(a) => a,
                        None => return false,
                    };
                    if sigAndAlgs.Empty() {
                        return false;
                    }
                    while !sigAndAlgs.Empty() {
                        let mut sigAndAlg: u16 = 0;
                        if !sigAndAlgs.ReadUint16(&mut sigAndAlg) {
                            return false;
                        }
                        self.supportedSignatureAlgorithmsCert.push(sigAndAlg);
                    }
                }
                extensionRenegotiationInfo => {
                    // RFC 5746, Section 3.2
                    match extData.ReadUint8LengthPrefixed() {
                        Some(r) => self.secureRenegotiation = r.rest().to_vec(),
                        None => return false,
                    }
                    self.secureRenegotiationSupported = true;
                }
                extensionExtendedMasterSecret => {
                    // RFC 7627
                    self.extendedMasterSecret = true;
                }
                extensionALPN => {
                    // RFC 7301, Section 3.1
                    let mut protoList = match extData.ReadUint16LengthPrefixed() {
                        Some(p) => p,
                        None => return false,
                    };
                    if protoList.Empty() {
                        return false;
                    }
                    while !protoList.Empty() {
                        let proto = match protoList.ReadUint8LengthPrefixed() {
                            Some(p) => p,
                            None => return false,
                        };
                        if proto.Empty() {
                            return false;
                        }
                        match core::str::from_utf8(proto.rest()) {
                            Ok(v) => self.alpnProtocols.push(String::from(v)),
                            Err(_) => return false,
                        }
                    }
                }
                extensionSCT => {
                    // RFC 6962, Section 3.3.1
                    self.scts = true;
                }
                extensionSupportedVersions => {
                    // RFC 8446, Section 4.2.1
                    let mut versList = match extData.ReadUint8LengthPrefixed() {
                        Some(v) => v,
                        None => return false,
                    };
                    if versList.Empty() {
                        return false;
                    }
                    while !versList.Empty() {
                        let mut vers: u16 = 0;
                        if !versList.ReadUint16(&mut vers) {
                            return false;
                        }
                        self.supportedVersions.push(vers);
                    }
                }
                extensionCookie => {
                    // RFC 8446, Section 4.2.2
                    match extData.ReadUint16LengthPrefixed() {
                        Some(c) => self.cookie = c.rest().to_vec(),
                        None => return false,
                    }
                    if self.cookie.is_empty() {
                        return false;
                    }
                }
                extensionKeyShare => {
                    // RFC 8446, Section 4.2.8
                    let mut clientShares = match extData.ReadUint16LengthPrefixed() {
                        Some(c) => c,
                        None => return false,
                    };
                    while !clientShares.Empty() {
                        let mut ks = keyShare::default();
                        if !clientShares.ReadUint16(&mut ks.group) {
                            return false;
                        }
                        match clientShares.ReadUint16LengthPrefixed() {
                            Some(d) => ks.data = d.rest().to_vec(),
                            None => return false,
                        }
                        if ks.data.is_empty() {
                            return false;
                        }
                        self.keyShares.push(ks);
                    }
                }
                extensionEarlyData => {
                    // RFC 8446, Section 4.2.10
                    self.earlyData = true;
                }
                extensionPSKModes => {
                    // RFC 8446, Section 4.2.9
                    match extData.ReadUint8LengthPrefixed() {
                        Some(p) => self.pskModes = p.rest().to_vec(),
                        None => return false,
                    }
                }
                extensionPreSharedKey => {
                    // RFC 8446, Section 4.2.11
                    if !extensions.Empty() {
                        return false; // pre_shared_key must be the last extension
                    }
                    let mut identities = match extData.ReadUint16LengthPrefixed() {
                        Some(i) => i,
                        None => return false,
                    };
                    if identities.Empty() {
                        return false;
                    }
                    while !identities.Empty() {
                        let mut psk = pskIdentity::default();
                        match identities.ReadUint16LengthPrefixed() {
                            Some(l) => psk.label = l.rest().to_vec(),
                            None => return false,
                        }
                        if !identities.ReadUint32(&mut psk.obfuscatedTicketAge) {
                            return false;
                        }
                        if psk.label.is_empty() {
                            return false;
                        }
                        self.pskIdentities.push(psk);
                    }
                    let mut binders = match extData.ReadUint16LengthPrefixed() {
                        Some(b) => b,
                        None => return false,
                    };
                    if binders.Empty() {
                        return false;
                    }
                    while !binders.Empty() {
                        let binder = match binders.ReadUint8LengthPrefixed() {
                            Some(b) => b.rest().to_vec(),
                            None => return false,
                        };
                        if binder.is_empty() {
                            return false;
                        }
                        self.pskBinders.push(binder);
                    }
                }
                extensionQUICTransportParameters | extensionEncryptedClientHello => {
                    // Recognized but unsupported by the Goish server;
                    // consume the payload so the trailing extData.Empty()
                    // check passes (Go stores these; we drop them).
                    let n = extData.rest().len();
                    let _ = extData.Skip(n);
                }
                _ => {
                    // Ignore unknown extensions.
                    continue;
                }
            }

            if !extData.Empty() {
                return false;
            }
        }

        true
    }
}

// ─── serverHelloMsg (handshake_messages.go:711) ─────────────────────

/// ServerHello builder state — the TLS 1.3-relevant subset of Go's
/// `serverHelloMsg` (the TLS 1.2-only fields — ocspStapling,
/// ticketSupported, secureRenegotiation, extendedMasterSecret, scts —
/// are omitted; a TLS 1.3 ServerHello never carries them).
#[derive(Clone, Default)]
pub(crate) struct serverHelloMsg {
    pub vers: u16,
    pub random: Vec<byte>,
    pub sessionId: Vec<byte>,
    pub cipherSuite: u16,
    pub compressionMethod: byte,
    pub alpnProtocol: String,
    pub supportedVersion: u16,
    pub serverShare: keyShare,
    pub selectedIdentityPresent: bool,
    pub selectedIdentity: u16,
    pub supportedPoints: Vec<byte>,

    // HelloRetryRequest extensions
    pub cookie: Vec<byte>,
    pub selectedGroup: u16,
}

impl serverHelloMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:746-869 serverHelloMsg.marshal
    /// `(*serverHelloMsg).marshal()` — handshake_messages.go:746.
    /// Emits extensions in the same order as Go.
    pub(crate) fn marshal(&self) -> Vec<byte> {
        let mut exts = builder::new();
        if !self.alpnProtocol.is_empty() {
            exts.AddUint16(extensionALPN);
            let alpn = self.alpnProtocol.as_bytes();
            exts.AddUint16LengthPrefixed(|exts| {
                exts.AddUint16LengthPrefixed(|exts| {
                    exts.AddUint8LengthPrefixed(|exts| {
                        exts.AddBytes(alpn);
                    });
                });
            });
        }
        if self.supportedVersion != 0 {
            exts.AddUint16(extensionSupportedVersions);
            let v = self.supportedVersion;
            exts.AddUint16LengthPrefixed(|exts| {
                exts.AddUint16(v);
            });
        }
        if self.serverShare.group != 0 {
            exts.AddUint16(extensionKeyShare);
            let group = self.serverShare.group;
            let data = &self.serverShare.data;
            exts.AddUint16LengthPrefixed(|exts| {
                exts.AddUint16(group);
                exts.AddUint16LengthPrefixed(|exts| {
                    exts.AddBytes(data);
                });
            });
        }
        if self.selectedIdentityPresent {
            exts.AddUint16(extensionPreSharedKey);
            let id = self.selectedIdentity;
            exts.AddUint16LengthPrefixed(|exts| {
                exts.AddUint16(id);
            });
        }
        if !self.cookie.is_empty() {
            exts.AddUint16(extensionCookie);
            let cookie = &self.cookie;
            exts.AddUint16LengthPrefixed(|exts| {
                exts.AddUint16LengthPrefixed(|exts| {
                    exts.AddBytes(cookie);
                });
            });
        }
        if self.selectedGroup != 0 {
            exts.AddUint16(extensionKeyShare);
            let group = self.selectedGroup;
            exts.AddUint16LengthPrefixed(|exts| {
                exts.AddUint16(group);
            });
        }
        if !self.supportedPoints.is_empty() {
            exts.AddUint16(extensionSupportedPoints);
            let points = &self.supportedPoints;
            exts.AddUint16LengthPrefixed(|exts| {
                exts.AddUint8LengthPrefixed(|exts| {
                    exts.AddBytes(points);
                });
            });
        }
        let extBytes = exts.Bytes();

        let mut b = builder::new();
        b.AddUint8(typeServerHello);
        b.AddUint24LengthPrefixed(|b| {
            b.AddUint16(self.vers);
            // Go: addBytesWithLength(b, m.random, 32)
            b.AddBytes(&self.random);
            b.AddUint8LengthPrefixed(|b| {
                b.AddBytes(&self.sessionId);
            });
            b.AddUint16(self.cipherSuite);
            b.AddUint8(self.compressionMethod);
            if !extBytes.is_empty() {
                b.AddUint16LengthPrefixed(|b| {
                    b.AddBytes(&extBytes);
                });
            }
        });
        b.Bytes()
    }
}

// ─── encryptedExtensionsMsg (handshake_messages.go:1000) ────────────

#[derive(Clone, Default)]
pub(crate) struct encryptedExtensionsMsg {
    pub alpnProtocol: String,
    pub serverNameAck: bool,
}

impl encryptedExtensionsMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1011-1052 encryptedExtensionsMsg.marshal
    /// `(*encryptedExtensionsMsg).marshal()` — handshake_messages.go:1011.
    pub(crate) fn marshal(&self) -> Vec<byte> {
        let mut b = builder::new();
        b.AddUint8(typeEncryptedExtensions);
        b.AddUint24LengthPrefixed(|b| {
            b.AddUint16LengthPrefixed(|b| {
                if !self.alpnProtocol.is_empty() {
                    b.AddUint16(extensionALPN);
                    let alpn = self.alpnProtocol.as_bytes();
                    b.AddUint16LengthPrefixed(|b| {
                        b.AddUint16LengthPrefixed(|b| {
                            b.AddUint8LengthPrefixed(|b| {
                                b.AddBytes(alpn);
                            });
                        });
                    });
                }
                if self.serverNameAck {
                    b.AddUint16(extensionServerName);
                    b.AddUint16(0); // empty extension_data
                }
            });
        });
        b.Bytes()
    }
}

// ─── certificateMsgTLS13 (handshake_messages.go:1459) ───────────────

/// TLS 1.3 Certificate message. Carries the DER chain directly
/// (leaf first) rather than embedding the `tls::Certificate` struct —
/// OCSP staples and SCTs are not supported by the Goish server, so
/// `ocspStapling`/`scts` from Go's struct are omitted.
#[derive(Clone, Default)]
pub(crate) struct certificateMsgTLS13 {
    pub certificate: Vec<Vec<byte>>,
}

impl certificateMsgTLS13 {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1465-1482 certificateMsgTLS13.marshal
    /// `(*certificateMsgTLS13).marshal()` — handshake_messages.go:1465,
    /// with `marshalCertificate` (:1484) inlined (no OCSP/SCT
    /// extensions, so every per-cert extensions block is empty).
    pub(crate) fn marshal(&self) -> Vec<byte> {
        let mut b = builder::new();
        b.AddUint8(typeCertificate);
        b.AddUint24LengthPrefixed(|b| {
            b.AddUint8(0); // certificate_request_context
            b.AddUint24LengthPrefixed(|b| {
                for cert in self.certificate.iter() {
                    b.AddUint24LengthPrefixed(|b| {
                        b.AddBytes(cert);
                    });
                    b.AddUint16LengthPrefixed(|_b| {
                        // no per-certificate extensions
                    });
                }
            });
        });
        b.Bytes()
    }
}

// ─── certificateVerifyMsg (handshake_messages.go:1848) ──────────────

#[derive(Clone, Default)]
pub(crate) struct certificateVerifyMsg {
    pub hasSignatureAlgorithm: bool,
    pub signatureAlgorithm: u16,
    pub signature: Vec<byte>,
}

impl certificateVerifyMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1854-1867 certificateVerifyMsg.marshal
    /// `(*certificateVerifyMsg).marshal()` — handshake_messages.go:1854.
    pub(crate) fn marshal(&self) -> Vec<byte> {
        let mut b = builder::new();
        b.AddUint8(typeCertificateVerify);
        b.AddUint24LengthPrefixed(|b| {
            if self.hasSignatureAlgorithm {
                b.AddUint16(self.signatureAlgorithm);
            }
            b.AddUint16LengthPrefixed(|b| {
                b.AddBytes(&self.signature);
            });
        });
        b.Bytes()
    }
}

// ─── finishedMsg (handshake_messages.go:1692) ───────────────────────

#[derive(Clone, Default)]
pub(crate) struct finishedMsg {
    pub verifyData: Vec<byte>,
}

impl finishedMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1697-1705 finishedMsg.marshal
    /// `(*finishedMsg).marshal()` — handshake_messages.go:1697.
    pub(crate) fn marshal(&self) -> Vec<byte> {
        let mut b = builder::new();
        b.AddUint8(typeFinished);
        b.AddUint24LengthPrefixed(|b| {
            b.AddBytes(&self.verifyData);
        });
        b.Bytes()
    }
}


// ─── Verbatim ports on the real cryptobyte ────────────────────────────
//
// Everything above is the pre-existing hand-written subset, built on the
// private `builder` / `cbs` mini-cryptobyte. Everything below is a
// verbatim port of handshake_messages[go] on the ported
// `crypto/cryptobyte`. Nothing below is wired into the live handshake:
// the two coexist until conn[go] lands and the file can be replaced in
// one piece. See ROADMAP.md.

use crate::crypto::cryptobyte;
// `CBString` rather than `cryptobyte::String`: the bare name reads as
// Rust's `String` to GOISH009, and this is Go's cryptobyte.String — a
// TLS byte-string cursor. Same spelling crypto/x509/parser[rs] uses.
use crate::crypto::cryptobyte::String as CBString;
use crate::error;
use crate::goslice::slice;
use crate::types::uint8;

// The handshake message type bytes this file needs. Go declares the
// full set in common[go] lines 84-102, which lands with the record
// layer; these three are inlined here so this file anchors to exactly
// one Go file (GOISH015).
const typeEndOfEarlyData: uint8 = 5;
const typeCertificateStatus: uint8 = 22;
const typeKeyUpdate: uint8 = 24;

/// `statusTypeOCSP uint8 = 1` in common[go]; see the note above.
const statusTypeOCSP: uint8 = 1;

// go: sdk 1.25.5 crypto/tls/handshake_messages.go:22-24 readUint8LengthPrefixed
/// Go: "readUint8LengthPrefixed acts like s.ReadUint8LengthPrefixed, but
/// targets a []byte instead of a cryptobyte.String."
pub(crate) fn readUint8LengthPrefixed(
    s: &mut CBString,
    out: &mut slice<byte>,
) -> bool {
    // Go: return s.ReadUint8LengthPrefixed((*cryptobyte.String)(out))
    let mut tmp = CBString::New(slice::__from_vec(Vec::new()));
    if !s.ReadUint8LengthPrefixed(&mut tmp) {
        return false;
    }
    *out = tmp.0;
    return true;
}

// go: sdk 1.25.5 crypto/tls/handshake_messages.go:26-28 readUint16LengthPrefixed
/// Go: the uint16 mirror of [`readUint8LengthPrefixed`].
pub(crate) fn readUint16LengthPrefixed(
    s: &mut CBString,
    out: &mut slice<byte>,
) -> bool {
    // Go: return s.ReadUint16LengthPrefixed((*cryptobyte.String)(out))
    let mut tmp = CBString::New(slice::__from_vec(Vec::new()));
    if !s.ReadUint16LengthPrefixed(&mut tmp) {
        return false;
    }
    *out = tmp.0;
    return true;
}

// go: sdk 1.25.5 crypto/tls/handshake_messages.go:30-32 readUint24LengthPrefixed
/// Go: the uint24 mirror of [`readUint8LengthPrefixed`].
pub(crate) fn readUint24LengthPrefixed(
    s: &mut CBString,
    out: &mut slice<byte>,
) -> bool {
    // Go: return s.ReadUint24LengthPrefixed((*cryptobyte.String)(out))
    let mut tmp = CBString::New(slice::__from_vec(Vec::new()));
    if !s.ReadUint24LengthPrefixed(&mut tmp) {
        return false;
    }
    *out = tmp.0;
    return true;
}

// Go: handshake_messages.go — `type keyUpdateMsg struct { updateRequested bool }`
/// RFC 8446 §4.6.3 KeyUpdate.
#[derive(Clone, Default, PartialEq, Debug)]
pub(crate) struct keyUpdateMsg {
    pub updateRequested: bool,
}

impl keyUpdateMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1799-1811 keyUpdateMsg.marshal
    /// Serialize the KeyUpdate message.
    pub(crate) fn marshal(&self) -> (slice<byte>, error) {
        // Go: var b cryptobyte.Builder; b.AddUint8(typeKeyUpdate)
        let mut b = cryptobyte::NewBuilder(slice::__from_vec(Vec::new()));
        b.AddUint8(typeKeyUpdate);
        // Go: b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
        //         if m.updateRequested { b.AddUint8(1) } else { b.AddUint8(0) }
        //     })
        let updateRequested = self.updateRequested;
        b.AddUint24LengthPrefixed(|b: &mut cryptobyte::Builder| {
            if updateRequested {
                b.AddUint8(1);
            } else {
                b.AddUint8(0);
            }
        });
        // Go: return b.Bytes()
        return b.Bytes();
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1813-1831 keyUpdateMsg.unmarshal
    /// Parse a KeyUpdate message. Reports whether it was well-formed.
    pub(crate) fn unmarshal(&mut self, data: slice<byte>) -> bool {
        // Go: s := cryptobyte.String(data)
        let mut s = CBString::New(data);

        // Go: var updateRequested uint8
        //     if !s.Skip(4) || // message type and uint24 length field
        //        !s.ReadUint8(&updateRequested) || !s.Empty() { return false }
        let mut updateRequested: uint8 = 0;
        if !s.Skip(4) || !s.ReadUint8(&mut updateRequested) || !s.Empty() {
            return false;
        }
        // Go: switch updateRequested { case 0: … case 1: … default: return false }
        if updateRequested == 0 {
            self.updateRequested = false;
        } else if updateRequested == 1 {
            self.updateRequested = true;
        } else {
            return false;
        }
        // Go: return true
        return true;
    }
}

// Go: handshake_messages.go — `type endOfEarlyDataMsg struct{}`
/// RFC 8446 §4.5 EndOfEarlyData — an empty message.
#[derive(Clone, Default, PartialEq, Debug)]
pub(crate) struct endOfEarlyDataMsg {}

impl endOfEarlyDataMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1768-1772 endOfEarlyDataMsg.marshal
    /// Serialize: a bare header with a zero-length body.
    pub(crate) fn marshal(&self) -> (slice<byte>, error) {
        // Go: x := make([]byte, 4); x[0] = typeEndOfEarlyData; return x, nil
        let mut x: Vec<byte> = alloc::vec![0u8; 4];
        x[0] = typeEndOfEarlyData;
        return (slice::__from_vec(x), crate::errors::nil);
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1774-1776 endOfEarlyDataMsg.unmarshal
    /// Parse: well-formed exactly when the message is the 4-byte header.
    pub(crate) fn unmarshal(&mut self, data: slice<byte>) -> bool {
        // Go: return len(data) == 4
        return data.Len() == 4;
    }
}

// Go: handshake_messages.go — `type certificateStatusMsg struct { response []byte }`
/// RFC 6066 §8 CertificateStatus, carrying a stapled OCSP response.
#[derive(Clone, Default, PartialEq)]
pub(crate) struct certificateStatusMsg {
    pub response: slice<byte>,
}

impl certificateStatusMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1735-1747 certificateStatusMsg.marshal
    /// Serialize the CertificateStatus message.
    pub(crate) fn marshal(&self) -> (slice<byte>, error) {
        // Go: var b cryptobyte.Builder; b.AddUint8(typeCertificateStatus)
        let mut b = cryptobyte::NewBuilder(slice::__from_vec(Vec::new()));
        b.AddUint8(typeCertificateStatus);
        // Go: b.AddUint24LengthPrefixed(func(b) {
        //         b.AddUint8(statusTypeOCSP)
        //         b.AddUint24LengthPrefixed(func(b) { b.AddBytes(m.response) })
        //     })
        let response = self.response.clone();
        b.AddUint24LengthPrefixed(|b: &mut cryptobyte::Builder| {
            b.AddUint8(statusTypeOCSP);
            b.AddUint24LengthPrefixed(|b: &mut cryptobyte::Builder| {
                b.AddBytes(&response);
            });
        });
        // Go: return b.Bytes()
        return b.Bytes();
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1749-1761 certificateStatusMsg.unmarshal
    /// Parse a CertificateStatus message. Reports whether it was
    /// well-formed; an empty OCSP response is rejected, as Go does.
    pub(crate) fn unmarshal(&mut self, data: slice<byte>) -> bool {
        // Go: s := cryptobyte.String(data)
        let mut s = CBString::New(data);

        // Go: var statusType uint8
        //     if !s.Skip(4) || !s.ReadUint8(&statusType) ||
        //        statusType != statusTypeOCSP ||
        //        !readUint24LengthPrefixed(&s, &m.response) ||
        //        len(m.response) == 0 || !s.Empty() { return false }
        let mut statusType: uint8 = 0;
        if !s.Skip(4)
            || !s.ReadUint8(&mut statusType)
            || statusType != statusTypeOCSP
            || !readUint24LengthPrefixed(&mut s, &mut self.response)
            || self.response.Len() == 0
            || !s.Empty()
        {
            return false;
        }
        // Go: return true
        return true;
    }
}
