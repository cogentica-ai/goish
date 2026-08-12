// goishlint:ignore GOISH018 marshalCertificate — marshalCertificate takes common.go's Certificate, which is not ported yet (mod[rs] declares a hand-written one). Everything else in handshake_messages.go is here. See ROADMAP.md.
// goishlint:ignore GOISH021 certificateMsg, certificateRequestMsg, certificateRequestMsgTLS13, certificateStatusMsg, clientKeyExchangeMsg, endOfEarlyDataMsg, helloRequestMsg, keyUpdateMsg, newSessionTicketMsg, newSessionTicketMsgTLS13, serverKeyExchangeMsg, transcriptHash — the message types the subset does not handle.
// go: file crypto/tls/handshake_messages.go decls: marshalingFunction.Marshal, addBytesWithLength, clientHelloMsg.marshalMsg, clientHelloMsg.marshal, clientHelloMsg.marshalWithoutBinders, clientHelloMsg.updateBinders, clientHelloMsg.originalBytes, clientHelloMsg.clone, serverHelloDoneMsg.marshal, serverHelloDoneMsg.unmarshal, clientHelloMsg.unmarshal, serverHelloMsg.marshal, encryptedExtensionsMsg.marshal, certificateMsgTLS13.marshal, certificateVerifyMsg.marshal, finishedMsg.marshal, keyUpdateMsg.marshal, keyUpdateMsg.unmarshal, endOfEarlyDataMsg.marshal, endOfEarlyDataMsg.unmarshal, certificateStatusMsg.marshal, certificateStatusMsg.unmarshal, readUint8LengthPrefixed, readUint16LengthPrefixed, readUint24LengthPrefixed, addUint64, readUint64, helloRequestMsg.marshal, helloRequestMsg.unmarshal, serverKeyExchangeMsg.marshal, serverKeyExchangeMsg.unmarshal, clientKeyExchangeMsg.marshal, clientKeyExchangeMsg.unmarshal, newSessionTicketMsg.marshal, newSessionTicketMsg.unmarshal, certificateMsg.marshal, certificateMsg.unmarshal, newSessionTicketMsgTLS13.marshal, newSessionTicketMsgTLS13.unmarshal, certificateRequestMsgTLS13.marshal, certificateRequestMsgTLS13.unmarshal, certificateRequestMsg.marshal, certificateRequestMsg.unmarshal, finishedMsg.unmarshal, certificateVerifyMsg.unmarshal, encryptedExtensionsMsg.unmarshal, unmarshalCertificate, marshalCertificate, certificateMsgTLS13.unmarshal, serverHelloMsg.unmarshal, serverHelloMsg.originalBytes, transcriptMsg
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
pub(crate) const typeServerHelloDone: byte = 14;
pub(crate) const typeNewSessionTicket: byte = 4;
pub(crate) const typeServerKeyExchange: byte = 12;
pub(crate) const typeClientKeyExchange: byte = 16;
pub(crate) const typeHelloRequest: byte = 0;
pub(crate) const typeEndOfEarlyData: byte = 5;
pub(crate) const typeCertificateStatus: byte = 22;
pub(crate) const typeKeyUpdate: byte = 24;
pub(crate) const typeEncryptedExtensions: byte = 8;
pub(crate) const typeCertificate: byte = 11;
pub(crate) const typeCertificateRequest: byte = 13;
pub(crate) const typeCertificateVerify: byte = 15;
pub(crate) const typeFinished: byte = 20;
pub(crate) const typeMessageHash: byte = 254; // synthetic message

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
    /// Go: `quicTransportParameters []byte`. Go marshals a zero-length
    /// extension when the field is non-nil but empty, so the nil/empty
    /// distinction is load-bearing and `Option` carries it.
    pub quicTransportParameters: Option<Vec<byte>>,
    pub encryptedClientHello: Vec<byte>,
    /// Go: "extensions are only populated on the server-side of a
    /// handshake" — the IDs in the order the peer sent them, which ECH's
    /// outer-extension compression reads back.
    pub extensions: Vec<u16>,
}

impl clientHelloMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:418-680 clientHelloMsg.unmarshal
    /// `(*clientHelloMsg).unmarshal(data)` — handshake_messages.go:418.
    /// `data` is the full handshake message including the 4-byte
    /// type+uint24-length header. Returns false on malformed input.
    pub(crate) fn unmarshal(&mut self, data: slice<byte>) -> bool {
        *self = clientHelloMsg::default();
        let raw: &[byte] = &data;
        self.original = raw.to_vec();
        let mut s = cbs::new(raw);

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
            // Go: m.extensions = append(m.extensions, extension)
            self.extensions.push(extension);

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
                extensionQUICTransportParameters => {
                    // Go: RFC 9001, Section 8.2
                    //     m.quicTransportParameters = make([]byte, len(extData))
                    //     if !extData.CopyBytes(m.quicTransportParameters) { return false }
                    let n = extData.rest().len();
                    match extData.ReadBytes(n) {
                        Some(v) => self.quicTransportParameters = Some(v.to_vec()),
                        None => return false,
                    }
                }
                extensionEncryptedClientHello => {
                    // Go: echBytes := make([]byte, len(extData))
                    //     if !extData.CopyBytes(echBytes) { return false }
                    //     m.encryptedClientHello = echBytes
                    let n = extData.rest().len();
                    match extData.ReadBytes(n) {
                        Some(v) => self.encryptedClientHello = v.to_vec(),
                        None => return false,
                    }
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

    // Fields `unmarshal` fills that the ported `marshal` does not emit.
    pub original: Vec<byte>,
    pub ocspStapling: bool,
    pub ticketSupported: bool,
    pub secureRenegotiation: Vec<byte>,
    pub secureRenegotiationSupported: bool,
    pub extendedMasterSecret: bool,
    pub scts: Vec<Vec<byte>>,
    pub encryptedClientHello: Vec<byte>,
    pub serverNameAck: bool,
}

impl serverHelloMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:746-869 serverHelloMsg.marshal
    /// `(*serverHelloMsg).marshal()` — handshake_messages.go:746.
    /// Emits extensions in the same order as Go.
    pub(crate) fn marshal(&self) -> (slice<byte>, crate::error) {
        let mut exts = builder::new();
        // Go: if m.ocspStapling { exts.AddUint16(extensionStatusRequest)
        //         exts.AddUint16(0) }
        if self.ocspStapling {
            exts.AddUint16(extensionStatusRequest);
            exts.AddUint16(0); // empty extension_data
        }
        // Go: if m.ticketSupported { exts.AddUint16(extensionSessionTicket)
        //         exts.AddUint16(0) }
        if self.ticketSupported {
            exts.AddUint16(extensionSessionTicket);
            exts.AddUint16(0); // empty extension_data
        }
        // Go: if m.secureRenegotiationSupported {
        //         exts.AddUint16(extensionRenegotiationInfo)
        //         exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
        //             exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
        //                 exts.AddBytes(m.secureRenegotiation) }) }) }
        if self.secureRenegotiationSupported {
            exts.AddUint16(extensionRenegotiationInfo);
            let sr = &self.secureRenegotiation;
            exts.AddUint16LengthPrefixed(|exts| {
                exts.AddUint8LengthPrefixed(|exts| {
                    exts.AddBytes(sr);
                });
            });
        }
        // Go: if m.extendedMasterSecret {
        //         exts.AddUint16(extensionExtendedMasterSecret)
        //         exts.AddUint16(0) }
        if self.extendedMasterSecret {
            exts.AddUint16(extensionExtendedMasterSecret);
            exts.AddUint16(0); // empty extension_data
        }
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
        // Go: if len(m.scts) > 0 { exts.AddUint16(extensionSCT)
        //         exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
        //             exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
        //                 for _, sct := range m.scts {
        //                     exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
        //                         exts.AddBytes(sct) }) } }) }) }
        if !self.scts.is_empty() {
            exts.AddUint16(extensionSCT);
            let scts = &self.scts;
            exts.AddUint16LengthPrefixed(|exts| {
                exts.AddUint16LengthPrefixed(|exts| {
                    for sct in scts.iter() {
                        exts.AddUint16LengthPrefixed(|exts| {
                            exts.AddBytes(sct);
                        });
                    }
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
        // Go: if len(m.encryptedClientHello) > 0 {
        //         exts.AddUint16(extensionEncryptedClientHello)
        //         exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
        //             exts.AddBytes(m.encryptedClientHello) }) }
        if !self.encryptedClientHello.is_empty() {
            exts.AddUint16(extensionEncryptedClientHello);
            let ech = &self.encryptedClientHello;
            exts.AddUint16LengthPrefixed(|exts| {
                exts.AddBytes(ech);
            });
        }
        // Go: if m.serverNameAck { exts.AddUint16(extensionServerName)
        //         exts.AddUint16(0) }
        if self.serverNameAck {
            exts.AddUint16(extensionServerName);
            exts.AddUint16(0);
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
        return (slice::__from_vec(b.Bytes()), crate::errors::nil);
    }
}

// ─── encryptedExtensionsMsg (handshake_messages.go:1000) ────────────

#[derive(Clone, Default)]
pub(crate) struct encryptedExtensionsMsg {
    pub alpnProtocol: String,
    pub quicTransportParameters: Vec<byte>,
    pub earlyData: bool,
    pub echRetryConfigs: Vec<byte>,
    pub serverNameAck: bool,
}

impl encryptedExtensionsMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1011-1052 encryptedExtensionsMsg.marshal
    /// `(*encryptedExtensionsMsg).marshal()` — handshake_messages.go:1011.
    pub(crate) fn marshal(&self) -> (slice<byte>, crate::error) {
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
                // Go: if m.quicTransportParameters != nil {
                //         // marshal zero-length parameters when present
                //         // draft-ietf-quic-tls-32, Section 8.2
                //         b.AddUint16(extensionQUICTransportParameters)
                //         b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
                //             b.AddBytes(m.quicTransportParameters) }) }
                if !self.quicTransportParameters.is_empty() {
                    b.AddUint16(extensionQUICTransportParameters);
                    let qtp = self.quicTransportParameters.as_slice();
                    b.AddUint16LengthPrefixed(|b| {
                        b.AddBytes(qtp);
                    });
                }
                // Go: if m.earlyData { // RFC 8446, Section 4.2.10
                //         b.AddUint16(extensionEarlyData); b.AddUint16(0) }
                if self.earlyData {
                    b.AddUint16(extensionEarlyData);
                    b.AddUint16(0); // empty extension_data
                }
                // Go: if len(m.echRetryConfigs) > 0 {
                //         b.AddUint16(extensionEncryptedClientHello)
                //         b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
                //             b.AddBytes(m.echRetryConfigs) }) }
                if !self.echRetryConfigs.is_empty() {
                    b.AddUint16(extensionEncryptedClientHello);
                    let rc = self.echRetryConfigs.as_slice();
                    b.AddUint16LengthPrefixed(|b| {
                        b.AddBytes(rc);
                    });
                }
                if self.serverNameAck {
                    b.AddUint16(extensionServerName);
                    b.AddUint16(0); // empty extension_data
                }
            });
        });
        return (slice::__from_vec(b.Bytes()), crate::errors::nil);
    }
}

// ─── certificateMsgTLS13 (handshake_messages.go:1459) ───────────────

// Go: handshake_messages.go:1459-1463
//   type certificateMsgTLS13 struct { certificate Certificate
//                                     ocspStapling bool; scts bool }
/// The TLS 1.3 Certificate message.
#[derive(Clone, Default)]
pub(crate) struct certificateMsgTLS13 {
    pub certificate: super::Certificate,
    pub ocspStapling: bool,
    pub scts: bool,
}

impl certificateMsgTLS13 {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1465-1482 certificateMsgTLS13.marshal
    pub(crate) fn marshal(&self) -> (slice<byte>, crate::error) {
        // Go: var b cryptobyte.Builder
        //     b.AddUint8(typeCertificate)
        let mut b = cryptobyte::NewBuilder(slice::__from_vec(Vec::new()));
        b.AddUint8(typeCertificate);
        // Go: certificate := m.certificate
        //     if !m.ocspStapling { certificate.OCSPStaple = nil }
        //     if !m.scts { certificate.SignedCertificateTimestamps = nil }
        let mut certificate = self.certificate.clone();
        if !self.ocspStapling {
            certificate.OCSPStaple = slice::new();
        }
        if !self.scts {
            certificate.SignedCertificateTimestamps = slice::new();
        }
        b.AddUint24LengthPrefixed(|b: &mut cryptobyte::Builder| {
            b.AddUint8(0); // certificate_request_context
            marshalCertificate(b, &certificate);
        });
        // Go: return b.Bytes()
        return b.Bytes();
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1521-1537 certificateMsgTLS13.unmarshal
    pub(crate) fn unmarshal(&mut self, data: slice<byte>) -> bool {
        // Go: *m = certificateMsgTLS13{}
        //     s := cryptobyte.String(data)
        *self = certificateMsgTLS13::default();
        let mut s = CBString::New(data);

        // Go: var context cryptobyte.String
        //     if !s.Skip(4) || !s.ReadUint8LengthPrefixed(&context) ||
        //        !context.Empty() || !unmarshalCertificate(&s, &m.certificate) ||
        //        !s.Empty() { return false }
        let mut context = CBString::New(slice::__from_vec(Vec::new()));
        if !s.Skip(4)
            || !s.ReadUint8LengthPrefixed(&mut context)
            || !context.Empty()
            || !unmarshalCertificate(&mut s, &mut self.certificate)
            || !s.Empty()
        {
            return false;
        }

        // Go: m.scts = m.certificate.SignedCertificateTimestamps != nil
        //     m.ocspStapling = m.certificate.OCSPStaple != nil
        //
        // goish slices carry no nil/empty distinction; `len() > 0` is
        // observably identical here, because unmarshalCertificate
        // rejects an empty staple and an empty SCT entry outright.
        self.scts = certificateMsgTLS13Nonempty(&self.certificate.SignedCertificateTimestamps);
        self.ocspStapling = self.certificate.OCSPStaple.Len() > 0;

        // Go: return true
        return true;
    }
}

// go: none — goish-only: `len(x) > 0` on a slice-of-slices, named so the
// nil-vs-empty deviation above has one place to point at.
fn certificateMsgTLS13Nonempty(v: &slice<slice<byte>>) -> bool {
    return v.Len() > 0;
}

// go: sdk 1.25.5 crypto/tls/handshake_messages.go:1484-1518 marshalCertificate
/// Encode a TLS 1.3 CertificateEntry list. OCSP staples and SCTs are
/// emitted for the LEAF only — Go's comment: "This library only supports
/// OCSP and SCT for leaf certificates."
///
/// Deviation: Go tests `certificate.OCSPStaple != nil`; goish slices
/// carry no nil/empty distinction, so the test is on length. The two
/// differ only for a non-nil zero-length staple, which the matching
/// `unmarshalCertificate` rejects.
pub(crate) fn marshalCertificate(b: &mut cryptobyte::Builder, certificate: &super::Certificate) {
    use super::common::{extensionSCT, extensionStatusRequest};
    let certificate = certificate.clone();
    b.AddUint24LengthPrefixed(|b: &mut cryptobyte::Builder| {
        // Go: for i, cert := range certificate.Certificate {
        for (i, cert) in crate::range!(certificate.Certificate.clone()) {
            let c = cert.clone();
            b.AddUint24LengthPrefixed(|b: &mut cryptobyte::Builder| {
                b.AddBytes(&c);
            });
            let staple = certificate.OCSPStaple.clone();
            let scts = certificate.SignedCertificateTimestamps.clone();
            b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
                // Go: if i > 0 { return } — only the leaf carries these.
                if i > 0 {
                    return;
                }
                // Go: if certificate.OCSPStaple != nil { … }
                if staple.Len() > 0 {
                    b.AddUint16(extensionStatusRequest);
                    b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
                        b.AddUint8(statusTypeOCSP);
                        b.AddUint24LengthPrefixed(|b: &mut cryptobyte::Builder| {
                            b.AddBytes(&staple);
                        });
                    });
                }
                // Go: if certificate.SignedCertificateTimestamps != nil { … }
                if scts.Len() > 0 {
                    b.AddUint16(extensionSCT);
                    b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
                        b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
                            for (_, sct) in crate::range!(scts.clone()) {
                                let s2 = sct.clone();
                                b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
                                    b.AddBytes(&s2);
                                });
                            }
                        });
                    });
                }
            });
        }
    });
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
    pub(crate) fn marshal(&self) -> (slice<byte>, crate::error) {
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
        return (slice::__from_vec(b.Bytes()), crate::errors::nil);
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
    pub(crate) fn marshal(&self) -> (slice<byte>, crate::error) {
        let mut b = builder::new();
        b.AddUint8(typeFinished);
        b.AddUint24LengthPrefixed(|b| {
            b.AddBytes(&self.verifyData);
        });
        return (slice::__from_vec(b.Bytes()), crate::errors::nil);
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

/// `statusTypeOCSP uint8 = 1` in common[go]; see the note above.
const statusTypeOCSP: uint8 = 1;

// go: sdk 1.25.5 crypto/tls/handshake_messages.go:55-57 readUint8LengthPrefixed
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

// go: sdk 1.25.5 crypto/tls/handshake_messages.go:61-63 readUint16LengthPrefixed
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

// go: sdk 1.25.5 crypto/tls/handshake_messages.go:67-69 readUint24LengthPrefixed
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
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1137-1149 keyUpdateMsg.marshal
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

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1151-1168 keyUpdateMsg.unmarshal
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
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1123-1127 endOfEarlyDataMsg.marshal
    /// Serialize: a bare header with a zero-length body.
    pub(crate) fn marshal(&self) -> (slice<byte>, error) {
        // Go: x := make([]byte, 4); x[0] = typeEndOfEarlyData; return x, nil
        let mut x: Vec<byte> = alloc::vec![0u8; 4];
        x[0] = typeEndOfEarlyData;
        return (slice::__from_vec(x), crate::errors::nil);
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1129-1131 endOfEarlyDataMsg.unmarshal
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
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1627-1638 certificateStatusMsg.marshal
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

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1640-1651 certificateStatusMsg.unmarshal
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


// The uint64 helpers Go writes because cryptobyte has no AddUint64 /
// ReadUint64 of its own — it splits into two uint32 halves.

// go: sdk 1.25.5 crypto/tls/handshake_messages.go:37-40 addUint64
/// Append `v` as two big-endian uint32 halves.
pub(crate) fn addUint64(b: &mut cryptobyte::Builder, v: crate::types::uint64) {
    // Go: b.AddUint32(uint32(v >> 32)); b.AddUint32(uint32(v))
    b.AddUint32(crate::uint32(v >> 32));
    b.AddUint32(crate::uint32(v));
}

// go: sdk 1.25.5 crypto/tls/handshake_messages.go:44-51 readUint64
/// Read two big-endian uint32 halves into `out`.
pub(crate) fn readUint64(s: &mut CBString, out: &mut crate::types::uint64) -> bool {
    // Go: var hi, lo uint32
    //     if !s.ReadUint32(&hi) || !s.ReadUint32(&lo) { return false }
    let mut hi: crate::types::uint32 = 0;
    let mut lo: crate::types::uint32 = 0;
    if !s.ReadUint32(&mut hi) || !s.ReadUint32(&mut lo) {
        return false;
    }
    // Go: *out = uint64(hi)<<32 | uint64(lo)
    *out = (crate::uint64(hi) << 32) | crate::uint64(lo);
    // Go: return true
    return true;
}

/// Go: `type helloRequestMsg struct{}` — the TLS 1.2 renegotiation
/// request, which this package never sends.
#[derive(Clone, Default, PartialEq, Debug)]
pub(crate) struct helloRequestMsg {}

impl helloRequestMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1926-1928 helloRequestMsg.marshal
    /// Go: `return []byte{typeHelloRequest, 0, 0, 0}, nil`
    pub(crate) fn marshal(&self) -> (slice<byte>, error) {
        return (
            slice::__from_vec(alloc::vec![typeHelloRequest, 0, 0, 0]),
            crate::errors::nil,
        );
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1930-1932 helloRequestMsg.unmarshal
    /// Go: `return len(data) == 4`
    pub(crate) fn unmarshal(&mut self, data: slice<byte>) -> bool {
        return data.Len() == 4;
    }
}


/// Go: `type serverKeyExchangeMsg struct { key []byte }` — an opaque
/// body whose contents depend on the key-exchange algorithm.
#[derive(Clone, Default, PartialEq)]
pub(crate) struct serverKeyExchangeMsg {
    pub key: slice<byte>,
}

impl serverKeyExchangeMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1603-1613 serverKeyExchangeMsg.marshal
    /// Serialize: a 4-byte header with a uint24 length, then the body.
    pub(crate) fn marshal(&self) -> (slice<byte>, error) {
        // Go: length := len(m.key); x := make([]byte, length+4)
        let length = self.key.Len();
        let mut x: Vec<byte> = alloc::vec![0u8; (length + 4) as usize];
        // Go: x[0] = typeServerKeyExchange; x[1..3] = uint24(length)
        x[0] = typeServerKeyExchange;
        x[1] = crate::uint8(length >> 16);
        x[2] = crate::uint8(length >> 8);
        x[3] = crate::uint8(length);
        // Go: copy(x[4:], m.key)
        let raw: &[byte] = &self.key;
        x[4..].copy_from_slice(raw);
        return (slice::__from_vec(x), crate::errors::nil);
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1615-1621 serverKeyExchangeMsg.unmarshal
    /// Parse. Note Go does NOT check the declared length here — the body
    /// is whatever follows the header — unlike clientKeyExchangeMsg.
    pub(crate) fn unmarshal(&mut self, data: slice<byte>) -> bool {
        // Go: if len(data) < 4 { return false }
        if data.Len() < 4 {
            return false;
        }
        // Go: m.key = data[4:]
        self.key = data.slice(4, data.Len());
        // Go: return true
        return true;
    }
}

/// Go: `type clientKeyExchangeMsg struct { ciphertext []byte }`.
#[derive(Clone, Default, PartialEq)]
pub(crate) struct clientKeyExchangeMsg {
    pub ciphertext: slice<byte>,
}

impl clientKeyExchangeMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1669-1679 clientKeyExchangeMsg.marshal
    /// Serialize: header with uint24 length, then the ciphertext.
    pub(crate) fn marshal(&self) -> (slice<byte>, error) {
        // Go: length := len(m.ciphertext); x := make([]byte, length+4)
        let length = self.ciphertext.Len();
        let mut x: Vec<byte> = alloc::vec![0u8; (length + 4) as usize];
        x[0] = typeClientKeyExchange;
        x[1] = crate::uint8(length >> 16);
        x[2] = crate::uint8(length >> 8);
        x[3] = crate::uint8(length);
        // Go: copy(x[4:], m.ciphertext)
        let raw: &[byte] = &self.ciphertext;
        x[4..].copy_from_slice(raw);
        return (slice::__from_vec(x), crate::errors::nil);
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1681-1691 clientKeyExchangeMsg.unmarshal
    /// Parse. Unlike `serverKeyExchangeMsg`, this one DOES validate the
    /// declared uint24 length against the data that follows.
    pub(crate) fn unmarshal(&mut self, data: slice<byte>) -> bool {
        // Go: if len(data) < 4 { return false }
        if data.Len() < 4 {
            return false;
        }
        // Go: l := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
        //     if l != len(data)-4 { return false }
        let l = (crate::int(data[1]) << 16) | (crate::int(data[2]) << 8) | crate::int(data[3]);
        if l != data.Len() - 4 {
            return false;
        }
        // Go: m.ciphertext = data[4:]
        self.ciphertext = data.slice(4, data.Len());
        return true;
    }
}

/// Go: `type newSessionTicketMsg struct { ticket []byte }` — the TLS 1.2
/// NewSessionTicket of RFC 5077 §3.3.
#[derive(Clone, Default, PartialEq)]
pub(crate) struct newSessionTicketMsg {
    pub ticket: slice<byte>,
}

impl newSessionTicketMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1887-1901 newSessionTicketMsg.marshal
    /// Serialize. The four bytes at x[4..8] are the lifetime hint, left
    /// zero by Go, and x[8..10] is the uint16 ticket length.
    pub(crate) fn marshal(&self) -> (slice<byte>, error) {
        // Go: ticketLen := len(m.ticket); length := 2 + 4 + ticketLen
        //     x := make([]byte, 4+length)
        let ticketLen = self.ticket.Len();
        let length = 2 + 4 + ticketLen;
        let mut x: Vec<byte> = alloc::vec![0u8; (4 + length) as usize];
        x[0] = typeNewSessionTicket;
        x[1] = crate::uint8(length >> 16);
        x[2] = crate::uint8(length >> 8);
        x[3] = crate::uint8(length);
        // Go: x[8] = uint8(ticketLen >> 8); x[9] = uint8(ticketLen)
        x[8] = crate::uint8(ticketLen >> 8);
        x[9] = crate::uint8(ticketLen);
        // Go: copy(x[10:], m.ticket)
        let raw: &[byte] = &self.ticket;
        x[10..].copy_from_slice(raw);
        return (slice::__from_vec(x), crate::errors::nil);
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1903-1921 newSessionTicketMsg.unmarshal
    /// Parse, validating both the uint24 message length and the uint16
    /// ticket length.
    pub(crate) fn unmarshal(&mut self, data: slice<byte>) -> bool {
        // Go: if len(data) < 10 { return false }
        if data.Len() < 10 {
            return false;
        }
        // Go: length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
        //     if uint32(len(data))-4 != length { return false }
        let length = (crate::uint32(data[1]) << 16)
            | (crate::uint32(data[2]) << 8)
            | crate::uint32(data[3]);
        if crate::uint32(data.Len()) - 4 != length {
            return false;
        }
        // Go: ticketLen := int(data[8])<<8 + int(data[9])
        //     if len(data)-10 != ticketLen { return false }
        let ticketLen = (crate::int(data[8]) << 8) + crate::int(data[9]);
        if data.Len() - 10 != ticketLen {
            return false;
        }
        // Go: m.ticket = data[10:]
        self.ticket = data.slice(10, data.Len());
        return true;
    }
}


/// Go: `type certificateMsg struct { certificates [][]byte }` — the
/// TLS 1.2 Certificate message, a uint24-prefixed list of uint24-
/// prefixed DER certificates.
#[derive(Clone, Default, PartialEq)]
pub(crate) struct certificateMsg {
    pub certificates: slice<slice<byte>>,
}

impl certificateMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1393-1421 certificateMsg.marshal
    /// Serialize the chain.
    pub(crate) fn marshal(&self) -> (slice<byte>, error) {
        // Go: var i int; for _, slice := range m.certificates { i += len(slice) }
        let mut i: crate::types::int = 0;
        for (_, c) in crate::range!(self.certificates.clone()) {
            i += c.Len();
        }
        // Go: length := 3 + 3*len(m.certificates) + i
        let length = 3 + 3 * self.certificates.Len() + i;
        // Go: x := make([]byte, 4+length)
        let mut x: Vec<byte> = alloc::vec![0u8; (4 + length) as usize];
        x[0] = typeCertificate;
        x[1] = crate::uint8(length >> 16);
        x[2] = crate::uint8(length >> 8);
        x[3] = crate::uint8(length);

        // Go: certificateOctets := length - 3; x[4..7] = uint24(that)
        let certificateOctets = length - 3;
        x[4] = crate::uint8(certificateOctets >> 16);
        x[5] = crate::uint8(certificateOctets >> 8);
        x[6] = crate::uint8(certificateOctets);

        // Go: y := x[7:]
        //     for _, slice := range m.certificates {
        //         y[0..3] = uint24(len(slice)); copy(y[3:], slice)
        //         y = y[3+len(slice):]
        //     }
        let mut off = 7usize;
        for (_, c) in crate::range!(self.certificates.clone()) {
            let n = c.Len();
            x[off] = crate::uint8(n >> 16);
            x[off + 1] = crate::uint8(n >> 8);
            x[off + 2] = crate::uint8(n);
            let raw: &[byte] = &c;
            x[off + 3..off + 3 + raw.len()].copy_from_slice(raw);
            off += 3 + raw.len();
        }
        return (slice::__from_vec(x), crate::errors::nil);
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1423-1457 certificateMsg.unmarshal
    /// Parse the chain. Go walks the list TWICE — once to count and
    /// validate every length, once to slice the entries out — so a
    /// truncated entry is rejected before any is stored.
    pub(crate) fn unmarshal(&mut self, data: slice<byte>) -> bool {
        // Go: if len(data) < 7 { return false }
        if data.Len() < 7 {
            return false;
        }
        // Go: certsLen := uint32(data[4])<<16 | uint32(data[5])<<8 | uint32(data[6])
        //     if uint32(len(data)) != certsLen+7 { return false }
        let mut certsLen = (crate::uint32(data[4]) << 16)
            | (crate::uint32(data[5]) << 8)
            | crate::uint32(data[6]);
        if crate::uint32(data.Len()) != certsLen + 7 {
            return false;
        }

        // Go: first pass — count and validate.
        let mut numCerts = 0usize;
        let raw: &[byte] = &data;
        let mut d = &raw[7..];
        while certsLen > 0 {
            // Go: if len(d) < 4 { return false }
            if d.len() < 4 {
                return false;
            }
            let certLen = (crate::uint32(d[0]) << 16)
                | (crate::uint32(d[1]) << 8)
                | crate::uint32(d[2]);
            // Go: if uint32(len(d)) < 3+certLen { return false }
            if crate::uint32(d.len() as crate::types::int) < 3 + certLen {
                return false;
            }
            d = &d[(3 + certLen) as usize..];
            certsLen -= 3 + certLen;
            numCerts += 1;
        }

        // Go: second pass — slice them out.
        let mut out: Vec<slice<byte>> = Vec::with_capacity(numCerts);
        let mut d = &raw[7..];
        for _ in 0..numCerts {
            let certLen = ((crate::uint32(d[0]) << 16)
                | (crate::uint32(d[1]) << 8)
                | crate::uint32(d[2])) as usize;
            out.push(slice::__from_vec(d[3..3 + certLen].to_vec()));
            d = &d[3 + certLen..];
        }
        self.certificates = slice::__from_vec(out);
        return true;
    }
}


/// Go: `type newSessionTicketMsgTLS13 struct { … }` — RFC 8446 §4.6.1
/// NewSessionTicket, with the optional early_data extension.
#[derive(Clone, Default, PartialEq)]
pub(crate) struct newSessionTicketMsgTLS13 {
    pub lifetime: crate::types::uint32,
    pub ageAdd: crate::types::uint32,
    pub nonce: slice<byte>,
    pub label: slice<byte>,
    pub maxEarlyData: crate::types::uint32,
}

impl newSessionTicketMsgTLS13 {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1178-1202 newSessionTicketMsgTLS13.marshal
    /// Serialize. The extensions block is always emitted, even when
    /// empty — Go writes the uint16 length unconditionally and only the
    /// early_data body is conditional.
    pub(crate) fn marshal(&self) -> (slice<byte>, error) {
        // Go: var b cryptobyte.Builder; b.AddUint8(typeNewSessionTicket)
        let mut b = cryptobyte::NewBuilder(slice::__from_vec(Vec::new()));
        b.AddUint8(typeNewSessionTicket);
        let (lifetime, ageAdd) = (self.lifetime, self.ageAdd);
        let (nonce, label) = (self.nonce.clone(), self.label.clone());
        let maxEarlyData = self.maxEarlyData;
        // Go: b.AddUint24LengthPrefixed(func(b) { … })
        b.AddUint24LengthPrefixed(|b: &mut cryptobyte::Builder| {
            b.AddUint32(lifetime);
            b.AddUint32(ageAdd);
            // Go: b.AddUint8LengthPrefixed(func(b) { b.AddBytes(m.nonce) })
            b.AddUint8LengthPrefixed(|b: &mut cryptobyte::Builder| {
                b.AddBytes(&nonce);
            });
            // Go: b.AddUint16LengthPrefixed(func(b) { b.AddBytes(m.label) })
            b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
                b.AddBytes(&label);
            });
            // Go: the extensions block — present but possibly empty.
            b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
                if maxEarlyData > 0 {
                    b.AddUint16(super::common::extensionEarlyData);
                    b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
                        b.AddUint32(maxEarlyData);
                    });
                }
            });
        });
        // Go: return b.Bytes()
        return b.Bytes();
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1204-1243 newSessionTicketMsgTLS13.unmarshal
    /// Parse. Unknown extensions are skipped, as Go does; a known one
    /// with trailing bytes is rejected.
    pub(crate) fn unmarshal(&mut self, data: slice<byte>) -> bool {
        // Go: *m = newSessionTicketMsgTLS13{}
        *self = newSessionTicketMsgTLS13::default();
        // Go: s := cryptobyte.String(data)
        let mut s = CBString::New(data);

        // Go: if !s.Skip(4) || !s.ReadUint32(&m.lifetime) || … { return false }
        let mut extensions = CBString::New(slice::__from_vec(Vec::new()));
        if !s.Skip(4)
            || !s.ReadUint32(&mut self.lifetime)
            || !s.ReadUint32(&mut self.ageAdd)
            || !readUint8LengthPrefixed(&mut s, &mut self.nonce)
            || !readUint16LengthPrefixed(&mut s, &mut self.label)
            || !s.ReadUint16LengthPrefixed(&mut extensions)
            || !s.Empty()
        {
            return false;
        }

        // Go: for !extensions.Empty() { … }
        while !extensions.Empty() {
            let mut extension: crate::types::uint16 = 0;
            let mut extData = CBString::New(slice::__from_vec(Vec::new()));
            if !extensions.ReadUint16(&mut extension)
                || !extensions.ReadUint16LengthPrefixed(&mut extData)
            {
                return false;
            }

            // Go: switch extension { case extensionEarlyData: … default: continue }
            if extension == super::common::extensionEarlyData {
                if !extData.ReadUint32(&mut self.maxEarlyData) {
                    return false;
                }
            } else {
                // Go: Ignore unknown extensions.
                continue;
            }

            // Go: if !extData.Empty() { return false }
            if !extData.Empty() {
                return false;
            }
        }
        // Go: return true
        return true;
    }
}


/// Go: `type certificateRequestMsgTLS13 struct { … }` — RFC 8446 §4.3.2
/// CertificateRequest.
#[derive(Clone, Default, PartialEq)]
pub(crate) struct certificateRequestMsgTLS13 {
    pub ocspStapling: bool,
    pub scts: bool,
    pub supportedSignatureAlgorithms: slice<super::common::SignatureScheme>,
    pub supportedSignatureAlgorithmsCert: slice<super::common::SignatureScheme>,
    pub certificateAuthorities: slice<slice<byte>>,
}

impl certificateRequestMsgTLS13 {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1253-1311 certificateRequestMsgTLS13.marshal
    /// Serialize. Every extension is conditional, so an all-default
    /// message is a bare header, an empty context and an empty
    /// extensions list.
    pub(crate) fn marshal(&self) -> (slice<byte>, error) {
        use super::common::{
            extensionCertificateAuthorities, extensionSCT, extensionSignatureAlgorithms,
            extensionSignatureAlgorithmsCert, extensionStatusRequest,
        };
        let mut b = cryptobyte::NewBuilder(slice::__from_vec(Vec::new()));
        b.AddUint8(typeCertificateRequest);
        let (ocspStapling, scts) = (self.ocspStapling, self.scts);
        let sigAlgs = self.supportedSignatureAlgorithms.clone();
        let sigAlgsCert = self.supportedSignatureAlgorithmsCert.clone();
        let cas = self.certificateAuthorities.clone();
        b.AddUint24LengthPrefixed(|b: &mut cryptobyte::Builder| {
            // Go: certificate_request_context (SHALL be zero length
            // unless used for post-handshake authentication)
            b.AddUint8(0);

            b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
                if ocspStapling {
                    b.AddUint16(extensionStatusRequest);
                    b.AddUint16(0); // empty extension_data
                }
                if scts {
                    // Go: RFC 8446 §4.4.2.1 makes no mention of
                    // signed_certificate_timestamp in CertificateRequest,
                    // but extensions in the client's Certificate MUST
                    // correspond to ones here, and it is in the §4.2 table.
                    b.AddUint16(extensionSCT);
                    b.AddUint16(0); // empty extension_data
                }
                if sigAlgs.Len() > 0 {
                    b.AddUint16(extensionSignatureAlgorithms);
                    b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
                        b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
                            for (_, a) in crate::range!(sigAlgs.clone()) {
                                b.AddUint16(a.0);
                            }
                        });
                    });
                }
                if sigAlgsCert.Len() > 0 {
                    b.AddUint16(extensionSignatureAlgorithmsCert);
                    b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
                        b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
                            for (_, a) in crate::range!(sigAlgsCert.clone()) {
                                b.AddUint16(a.0);
                            }
                        });
                    });
                }
                if cas.Len() > 0 {
                    b.AddUint16(extensionCertificateAuthorities);
                    b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
                        b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
                            for (_, ca) in crate::range!(cas.clone()) {
                                b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
                                    b.AddBytes(&ca);
                                });
                            }
                        });
                    });
                }
            });
        });
        return b.Bytes();
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1313-1387 certificateRequestMsgTLS13.unmarshal
    /// Parse. An EMPTY sigalgs or CA list is rejected, and a zero-length
    /// CA entry is rejected — presence of the extension implies content.
    pub(crate) fn unmarshal(&mut self, data: slice<byte>) -> bool {
        use super::common::{
            extensionCertificateAuthorities, extensionSCT, extensionSignatureAlgorithms,
            extensionSignatureAlgorithmsCert, extensionStatusRequest, SignatureScheme,
        };
        *self = certificateRequestMsgTLS13::default();
        let mut s = CBString::New(data);

        // Go: if !s.Skip(4) || !s.ReadUint8LengthPrefixed(&context) ||
        //        !context.Empty() || !s.ReadUint16LengthPrefixed(&extensions) ||
        //        !s.Empty() { return false }
        let mut context = CBString::New(slice::__from_vec(Vec::new()));
        let mut extensions = CBString::New(slice::__from_vec(Vec::new()));
        if !s.Skip(4)
            || !s.ReadUint8LengthPrefixed(&mut context)
            || !context.Empty()
            || !s.ReadUint16LengthPrefixed(&mut extensions)
            || !s.Empty()
        {
            return false;
        }

        while !extensions.Empty() {
            let mut extension: crate::types::uint16 = 0;
            let mut extData = CBString::New(slice::__from_vec(Vec::new()));
            if !extensions.ReadUint16(&mut extension)
                || !extensions.ReadUint16LengthPrefixed(&mut extData)
            {
                return false;
            }

            if extension == extensionStatusRequest {
                self.ocspStapling = true;
            } else if extension == extensionSCT {
                self.scts = true;
            } else if extension == extensionSignatureAlgorithms
                || extension == extensionSignatureAlgorithmsCert
            {
                // Go: two identical arms differing only in the target field.
                let mut sigAndAlgs = CBString::New(slice::__from_vec(Vec::new()));
                if !extData.ReadUint16LengthPrefixed(&mut sigAndAlgs) || sigAndAlgs.Empty() {
                    return false;
                }
                let mut out: Vec<SignatureScheme> = Vec::new();
                while !sigAndAlgs.Empty() {
                    let mut sigAndAlg: crate::types::uint16 = 0;
                    if !sigAndAlgs.ReadUint16(&mut sigAndAlg) {
                        return false;
                    }
                    out.push(SignatureScheme(sigAndAlg));
                }
                if extension == extensionSignatureAlgorithms {
                    self.supportedSignatureAlgorithms = slice::__from_vec(out);
                } else {
                    self.supportedSignatureAlgorithmsCert = slice::__from_vec(out);
                }
            } else if extension == extensionCertificateAuthorities {
                let mut auths = CBString::New(slice::__from_vec(Vec::new()));
                if !extData.ReadUint16LengthPrefixed(&mut auths) || auths.Empty() {
                    return false;
                }
                let mut out: Vec<slice<byte>> = Vec::new();
                while !auths.Empty() {
                    let mut ca: slice<byte> = slice::__from_vec(Vec::new());
                    if !readUint16LengthPrefixed(&mut auths, &mut ca) || ca.Len() == 0 {
                        return false;
                    }
                    out.push(ca);
                }
                self.certificateAuthorities = slice::__from_vec(out);
            } else {
                // Go: Ignore unknown extensions.
                continue;
            }

            if !extData.Empty() {
                return false;
            }
        }
        return true;
    }
}


/// Go: `type certificateRequestMsg struct { … }` — the TLS 1.0-1.2
/// CertificateRequest of RFC 4346 §7.4.4.
///
/// `hasSignatureAlgorithm` is not on the wire: it is set by the caller
/// from the negotiated version (TLS 1.2 added the field) and steers
/// BOTH marshal and unmarshal. Parsing with it wrong misreads the rest
/// of the message.
#[derive(Clone, Default, PartialEq)]
pub(crate) struct certificateRequestMsg {
    pub hasSignatureAlgorithm: bool,
    pub certificateTypes: slice<byte>,
    pub supportedSignatureAlgorithms: slice<super::common::SignatureScheme>,
    pub certificateAuthorities: slice<slice<byte>>,
}

impl certificateRequestMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1724-1772 certificateRequestMsg.marshal
    /// Serialize. See RFC 4346, Section 7.4.4.
    pub(crate) fn marshal(&self) -> (slice<byte>, error) {
        // Go: length := 1 + len(m.certificateTypes) + 2
        let mut length = 1 + self.certificateTypes.Len() + 2;
        // Go: casLength := 0; for _, ca := range … { casLength += 2 + len(ca) }
        let mut casLength: crate::types::int = 0;
        for (_, ca) in crate::range!(self.certificateAuthorities.clone()) {
            casLength += 2 + ca.Len();
        }
        length += casLength;
        // Go: if m.hasSignatureAlgorithm { length += 2 + 2*len(…) }
        if self.hasSignatureAlgorithm {
            length += 2 + 2 * self.supportedSignatureAlgorithms.Len();
        }

        let mut x: Vec<byte> = alloc::vec![0u8; (4 + length) as usize];
        x[0] = typeCertificateRequest;
        x[1] = crate::uint8(length >> 16);
        x[2] = crate::uint8(length >> 8);
        x[3] = crate::uint8(length);
        // Go: x[4] = uint8(len(m.certificateTypes)); copy(x[5:], …)
        x[4] = crate::uint8(self.certificateTypes.Len());
        let ct: &[byte] = &self.certificateTypes;
        x[5..5 + ct.len()].copy_from_slice(ct);

        // Go: y := x[5+len(m.certificateTypes):]
        let mut off = 5 + ct.len();
        if self.hasSignatureAlgorithm {
            // Go: n := len(m.supportedSignatureAlgorithms) * 2
            let n = self.supportedSignatureAlgorithms.Len() * 2;
            x[off] = crate::uint8(n >> 8);
            x[off + 1] = crate::uint8(n);
            off += 2;
            for (_, a) in crate::range!(self.supportedSignatureAlgorithms.clone()) {
                x[off] = crate::uint8(crate::int(a.0 >> 8));
                x[off + 1] = crate::uint8(crate::int(a.0));
                off += 2;
            }
        }
        // Go: y[0..2] = uint16(casLength); then each CA, uint16-prefixed.
        x[off] = crate::uint8(casLength >> 8);
        x[off + 1] = crate::uint8(casLength);
        off += 2;
        for (_, ca) in crate::range!(self.certificateAuthorities.clone()) {
            let raw: &[byte] = &ca;
            x[off] = crate::uint8(ca.Len() >> 8);
            x[off + 1] = crate::uint8(ca.Len());
            off += 2;
            x[off..off + raw.len()].copy_from_slice(raw);
            off += raw.len();
        }
        return (slice::__from_vec(x), crate::errors::nil);
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1774-1846 certificateRequestMsg.unmarshal
    /// Parse. Rejects an empty certificateTypes list, an odd or zero
    /// sigalgs length, and any trailing data.
    pub(crate) fn unmarshal(&mut self, data: slice<byte>) -> bool {
        // Go: if len(data) < 5 { return false }
        if data.Len() < 5 {
            return false;
        }
        let raw: &[byte] = &data;
        // Go: length := uint24(data[1..4]); if uint32(len(data))-4 != length { false }
        let length = (crate::uint32(data[1]) << 16)
            | (crate::uint32(data[2]) << 8)
            | crate::uint32(data[3]);
        if crate::uint32(data.Len()) - 4 != length {
            return false;
        }

        // Go: numCertTypes := int(data[4]); data = data[5:]
        //     if numCertTypes == 0 || len(data) <= numCertTypes { return false }
        let numCertTypes = crate::int(data[4]) as usize;
        let mut d = &raw[5..];
        if numCertTypes == 0 || d.len() <= numCertTypes {
            return false;
        }
        self.certificateTypes = slice::__from_vec(d[..numCertTypes].to_vec());
        d = &d[numCertTypes..];

        // Go: if m.hasSignatureAlgorithm { … }
        if self.hasSignatureAlgorithm {
            if d.len() < 2 {
                return false;
            }
            let sigAndHashLen = ((d[0] as usize) << 8) | (d[1] as usize);
            d = &d[2..];
            // Go: if sigAndHashLen&1 != 0 || sigAndHashLen == 0 { return false }
            if sigAndHashLen & 1 != 0 || sigAndHashLen == 0 {
                return false;
            }
            if d.len() < sigAndHashLen {
                return false;
            }
            let numSigAlgos = sigAndHashLen / 2;
            let mut out: Vec<super::common::SignatureScheme> = Vec::with_capacity(numSigAlgos);
            for _ in 0..numSigAlgos {
                out.push(super::common::SignatureScheme(
                    ((d[0] as crate::types::uint16) << 8) | (d[1] as crate::types::uint16),
                ));
                d = &d[2..];
            }
            self.supportedSignatureAlgorithms = slice::__from_vec(out);
        }

        // Go: casLength := uint16(data[0])<<8 | uint16(data[1])
        if d.len() < 2 {
            return false;
        }
        let casLength = ((d[0] as usize) << 8) | (d[1] as usize);
        d = &d[2..];
        if d.len() < casLength {
            return false;
        }
        let mut cas = &d[..casLength];
        d = &d[casLength..];

        // Go: m.certificateAuthorities = nil; for len(cas) > 0 { … }
        let mut out: Vec<slice<byte>> = Vec::new();
        while !cas.is_empty() {
            if cas.len() < 2 {
                return false;
            }
            let caLen = ((cas[0] as usize) << 8) | (cas[1] as usize);
            cas = &cas[2..];
            if cas.len() < caLen {
                return false;
            }
            out.push(slice::__from_vec(cas[..caLen].to_vec()));
            cas = &cas[caLen..];
        }
        self.certificateAuthorities = slice::__from_vec(out);

        // Go: return len(data) == 0
        return d.is_empty();
    }
}


// The `unmarshal` halves the hand-written subset above never needed:
// it only ever WROTE these two messages. Ported verbatim on the real
// cryptobyte, against the subset's existing structs, so a future
// replacement of the file has both directions already in place.

impl finishedMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1707-1713 finishedMsg.unmarshal
    /// Go: `s.Skip(1) && readUint24LengthPrefixed(&s, &m.verifyData) && s.Empty()`
    ///
    /// Note Go skips only ONE byte here, not four: the uint24 length is
    /// then consumed by `readUint24LengthPrefixed` as the field's own
    /// prefix. Skipping four would silently drop three bytes of body.
    pub(crate) fn unmarshal(&mut self, data: slice<byte>) -> bool {
        let mut s = CBString::New(data);
        let mut verifyData: slice<byte> = slice::__from_vec(Vec::new());
        if !s.Skip(1) || !readUint24LengthPrefixed(&mut s, &mut verifyData) || !s.Empty() {
            return false;
        }
        self.verifyData = verifyData.__into_vec();
        return true;
    }
}

impl certificateVerifyMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1869-1881 certificateVerifyMsg.unmarshal
    /// Parse. `hasSignatureAlgorithm` is set by the caller from the
    /// negotiated version, exactly as in `certificateRequestMsg`, and
    /// decides whether a uint16 algorithm precedes the signature.
    pub(crate) fn unmarshal(&mut self, data: slice<byte>) -> bool {
        let mut s = CBString::New(data);
        // Go: if !s.Skip(4) { return false }  — type + uint24 length
        if !s.Skip(4) {
            return false;
        }
        // Go: if m.hasSignatureAlgorithm { if !s.ReadUint16(…) { return false } }
        if self.hasSignatureAlgorithm {
            let mut alg: crate::types::uint16 = 0;
            if !s.ReadUint16(&mut alg) {
                return false;
            }
            self.signatureAlgorithm = alg;
        }
        // Go: return readUint16LengthPrefixed(&s, &m.signature) && s.Empty()
        let mut sig: slice<byte> = slice::__from_vec(Vec::new());
        if !readUint16LengthPrefixed(&mut s, &mut sig) || !s.Empty() {
            return false;
        }
        self.signature = sig.__into_vec();
        return true;
    }
}


impl encryptedExtensionsMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1054-1119 encryptedExtensionsMsg.unmarshal
    /// Parse. A DUPLICATE extension is rejected outright — Go tracks
    /// what it has seen and fails on a repeat, which no other message
    /// in this file does. Unknown extensions are still skipped.
    pub(crate) fn unmarshal(&mut self, data: slice<byte>) -> bool {
        use super::common::{
            extensionALPN, extensionEarlyData, extensionEncryptedClientHello,
            extensionQUICTransportParameters, extensionServerName,
        };
        // Go: *m = encryptedExtensionsMsg{}
        *self = encryptedExtensionsMsg::default();
        let mut s = CBString::New(data);

        // Go: if !s.Skip(4) || !s.ReadUint16LengthPrefixed(&extensions) ||
        //        !s.Empty() { return false }
        let mut extensions = CBString::New(slice::__from_vec(Vec::new()));
        if !s.Skip(4) || !s.ReadUint16LengthPrefixed(&mut extensions) || !s.Empty() {
            return false;
        }

        // Go: seenExts := make(map[uint16]bool)
        let mut seenExts: Vec<crate::types::uint16> = Vec::new();
        while !extensions.Empty() {
            let mut extension: crate::types::uint16 = 0;
            let mut extData = CBString::New(slice::__from_vec(Vec::new()));
            if !extensions.ReadUint16(&mut extension)
                || !extensions.ReadUint16LengthPrefixed(&mut extData)
            {
                return false;
            }

            // Go: if seenExts[extension] { return false }; seenExts[extension] = true
            if seenExts.contains(&extension) {
                return false;
            }
            seenExts.push(extension);

            if extension == extensionALPN {
                // Go: exactly ONE protocol, non-empty, nothing after it.
                let mut protoList = CBString::New(slice::__from_vec(Vec::new()));
                if !extData.ReadUint16LengthPrefixed(&mut protoList) || protoList.Empty() {
                    return false;
                }
                let mut proto = CBString::New(slice::__from_vec(Vec::new()));
                if !protoList.ReadUint8LengthPrefixed(&mut proto)
                    || proto.Empty()
                    || !protoList.Empty()
                {
                    return false;
                }
                // `from_utf8_lossy(..).into_owned()` drags in an unwinding
                // path that will not link under panic=abort; the fallible
                // form with a default is equivalent for valid UTF-8 and
                // cannot unwind.
                self.alpnProtocol =
                    String::from_utf8(proto.0.clone().__into_vec()).unwrap_or_default();
            } else if extension == extensionQUICTransportParameters {
                self.quicTransportParameters = extData.0.clone().__into_vec();
                extData = CBString::New(slice::__from_vec(Vec::new()));
            } else if extension == extensionEarlyData {
                // Go: RFC 8446, Section 4.2.10
                self.earlyData = true;
            } else if extension == extensionEncryptedClientHello {
                self.echRetryConfigs = extData.0.clone().__into_vec();
                extData = CBString::New(slice::__from_vec(Vec::new()));
            } else if extension == extensionServerName {
                // Go: if len(extData) != 0 { return false }
                if extData.0.Len() != 0 {
                    return false;
                }
                self.serverNameAck = true;
            } else {
                // Go: Ignore unknown extensions.
                continue;
            }

            if !extData.Empty() {
                return false;
            }
        }
        return true;
    }
}


// go: sdk 1.25.5 crypto/tls/handshake_messages.go:1539-1597 unmarshalCertificate
/// Read a TLS 1.3 CertificateEntry list into `certificate`.
///
/// Two rules that are easy to lose: OCSP and SCT extensions are only
/// honoured on the LEAF (Go skips them once more than one certificate
/// has been read), and an empty OCSP staple or SCT entry is rejected.
pub(crate) fn unmarshalCertificate(
    s: &mut CBString,
    certificate: &mut super::Certificate,
) -> bool {
    use super::common::{extensionSCT, extensionStatusRequest};
    // Go: var certList cryptobyte.String
    //     if !s.ReadUint24LengthPrefixed(&certList) { return false }
    let mut certList = CBString::New(slice::__from_vec(Vec::new()));
    if !s.ReadUint24LengthPrefixed(&mut certList) {
        return false;
    }
    let mut chain: Vec<slice<byte>> = certificate.Certificate.clone().__into_vec();
    let mut scts: Vec<slice<byte>> =
        certificate.SignedCertificateTimestamps.clone().__into_vec();
    // Go: for !certList.Empty() { … }
    while !certList.Empty() {
        let mut cert: slice<byte> = slice::__from_vec(Vec::new());
        let mut extensions = CBString::New(slice::__from_vec(Vec::new()));
        if !readUint24LengthPrefixed(&mut certList, &mut cert)
            || !certList.ReadUint16LengthPrefixed(&mut extensions)
        {
            return false;
        }
        // Go: certificate.Certificate = append(certificate.Certificate, cert)
        chain.push(cert);

        while !extensions.Empty() {
            let mut extension: crate::types::uint16 = 0;
            let mut extData = CBString::New(slice::__from_vec(Vec::new()));
            if !extensions.ReadUint16(&mut extension)
                || !extensions.ReadUint16LengthPrefixed(&mut extData)
            {
                return false;
            }
            // Go: if len(certificate.Certificate) > 1 { continue }
            //     "This library only supports OCSP and SCT for leaf
            //      certificates."
            if chain.len() > 1 {
                continue;
            }

            if extension == extensionStatusRequest {
                let mut statusType: uint8 = 0;
                let mut staple: slice<byte> = slice::__from_vec(Vec::new());
                if !extData.ReadUint8(&mut statusType)
                    || statusType != statusTypeOCSP
                    || !readUint24LengthPrefixed(&mut extData, &mut staple)
                    || staple.Len() == 0
                {
                    return false;
                }
                certificate.OCSPStaple = staple;
            } else if extension == extensionSCT {
                let mut sctList = CBString::New(slice::__from_vec(Vec::new()));
                if !extData.ReadUint16LengthPrefixed(&mut sctList) || sctList.Empty() {
                    return false;
                }
                while !sctList.Empty() {
                    let mut sct: slice<byte> = slice::__from_vec(Vec::new());
                    if !readUint16LengthPrefixed(&mut sctList, &mut sct) || sct.Len() == 0 {
                        return false;
                    }
                    scts.push(sct);
                }
            } else {
                // Go: Ignore unknown extensions.
                continue;
            }

            if !extData.Empty() {
                return false;
            }
        }
    }
    certificate.Certificate = slice::__from_vec(chain);
    certificate.SignedCertificateTimestamps = slice::__from_vec(scts);
    return true;
}


// ─── clientHelloMsg encoding ──────────────────────────────────────────
//
// Ported against the real `crypto/cryptobyte` Builder, as Go is: the
// `builder` mini-port above predates that package landing in goish and
// has no `AddValue`, which `addBytesWithLength` needs in order to fail
// the build the way Go does on a wrong-length random.

// Go: handshake_messages.go:16-18
//   type marshalingFunction func(b *cryptobyte.Builder) error
/// An adapter to allow the use of ordinary functions as
/// `cryptobyte.MarshalingValue`.
pub(crate) struct marshalingFunction<F>(pub F)
where
    F: Fn(&mut cryptobyte::Builder) -> crate::error;

impl<F> cryptobyte::MarshalingValue for marshalingFunction<F>
where
    F: Fn(&mut cryptobyte::Builder) -> crate::error,
{
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:20-22 marshalingFunction.Marshal
    fn Marshal(&self, b: &mut cryptobyte::Builder) -> crate::error {
        // Go: return f(b)
        return (self.0)(b);
    }
}

// go: sdk 1.25.5 crypto/tls/handshake_messages.go:26-34 addBytesWithLength
/// Appends a sequence of bytes to the builder. If the length of the
/// sequence is not the value specified, it sets an error on the builder.
pub(crate) fn addBytesWithLength(b: &mut cryptobyte::Builder, v: &[byte], n: crate::types::int) {
    // Go: b.AddValue(marshalingFunction(func(b *cryptobyte.Builder) error {
    //         if len(v) != n { return fmt.Errorf("invalid value length: expected %d, got %d", n, len(v)) }
    //         b.AddBytes(v)
    //         return nil
    //     }))
    b.AddValue(&marshalingFunction(
        |b: &mut cryptobyte::Builder| -> crate::error {
            if v.len() as crate::types::int != n {
                return crate::fmt::Errorf!(
                    "invalid value length: expected %d, got %d",
                    n,
                    v.len() as crate::types::int
                );
            }
            b.AddBytes(&slice::__from_vec(v.to_vec()));
            return crate::errors::nil;
        },
    ));
}

// go: none — goish-only: Go writes `b.AddBytes(v)` on a `[]byte` field
// directly; goish's builder takes `&slice<byte>`, so each call site
// would otherwise repeat the wrap.
fn bs(v: &[byte]) -> slice<byte> {
    return slice::__from_vec(v.to_vec());
}

impl clientHelloMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:104-373 clientHelloMsg.marshalMsg
    /// Encode the ClientHello. With `echInner` set, the extensions that
    /// can be compressed by ECH are replaced by an `ech_outer_extensions`
    /// list and the legacy_session_id is emitted empty — RFC 9180 and
    /// draft-ietf-tls-esni.
    pub(crate) fn marshalMsg(&self, echInner: bool) -> (slice<byte>, crate::error) {
        // Go: var exts cryptobyte.Builder
        let mut exts = cryptobyte::NewBuilder(slice::__from_vec(Vec::new()));
        // Go: if len(m.serverName) > 0 { … } — RFC 6066, Section 3
        if self.serverName.len() > 0 {
            exts.AddUint16(extensionServerName);
            let name = self.serverName.clone();
            exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                    exts.AddUint8(0); // name_type = host_name
                    exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                        exts.AddBytes(&bs(name.as_bytes()));
                    });
                });
            });
        }
        // Go: if len(m.supportedPoints) > 0 && !echInner { … } — RFC 4492, Section 5.1.2
        if self.supportedPoints.len() > 0 && !echInner {
            exts.AddUint16(extensionSupportedPoints);
            let pts = self.supportedPoints.clone();
            exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                exts.AddUint8LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                    exts.AddBytes(&bs(&pts));
                });
            });
        }
        // Go: if m.ticketSupported && !echInner { … } — RFC 5077, Section 3.2
        if self.ticketSupported && !echInner {
            exts.AddUint16(extensionSessionTicket);
            let t = self.sessionTicket.clone();
            exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                exts.AddBytes(&bs(&t));
            });
        }
        // Go: if m.secureRenegotiationSupported && !echInner { … } — RFC 5746, Section 3.2
        if self.secureRenegotiationSupported && !echInner {
            exts.AddUint16(extensionRenegotiationInfo);
            let r = self.secureRenegotiation.clone();
            exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                exts.AddUint8LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                    exts.AddBytes(&bs(&r));
                });
            });
        }
        // Go: if m.extendedMasterSecret && !echInner { … } — RFC 7627
        if self.extendedMasterSecret && !echInner {
            exts.AddUint16(extensionExtendedMasterSecret);
            exts.AddUint16(0); // empty extension_data
        }
        // Go: if m.scts { … } — RFC 6962, Section 3.3.1
        if self.scts {
            exts.AddUint16(extensionSCT);
            exts.AddUint16(0); // empty extension_data
        }
        // Go: if m.earlyData { … } — RFC 8446, Section 4.2.10
        if self.earlyData {
            exts.AddUint16(extensionEarlyData);
            exts.AddUint16(0); // empty extension_data
        }
        // Go: if m.quicTransportParameters != nil { … } — RFC 9001, Section 8.2
        //
        // "marshal zero-length parameters when present": the test is on
        // nil, not on length, which is why the field is an Option.
        if self.quicTransportParameters.is_some() {
            exts.AddUint16(extensionQUICTransportParameters);
            let q = self.quicTransportParameters.clone().unwrap();
            exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                exts.AddBytes(&bs(&q));
            });
        }
        // Go: if len(m.encryptedClientHello) > 0 { … }
        if self.encryptedClientHello.len() > 0 {
            exts.AddUint16(extensionEncryptedClientHello);
            let e = self.encryptedClientHello.clone();
            exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                exts.AddBytes(&bs(&e));
            });
        }
        // Go: Note that any extension that can be compressed during ECH
        // must be contiguous. If any additional extensions are to be
        // compressed they must be added to the following block, so that
        // they can be properly decompressed on the other side.
        // Go: var echOuterExts []uint16
        let mut echOuterExts: Vec<u16> = Vec::new();
        // Go: if m.ocspStapling { … } — RFC 4366, Section 3.6
        if self.ocspStapling {
            if echInner {
                echOuterExts.push(extensionStatusRequest);
            } else {
                exts.AddUint16(extensionStatusRequest);
                exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                    exts.AddUint8(1); // status_type = ocsp
                    exts.AddUint16(0); // empty responder_id_list
                    exts.AddUint16(0); // empty request_extensions
                });
            }
        }
        // Go: if len(m.supportedCurves) > 0 { … } — RFC 4492 §5.1.1, RFC 8446 §4.2.7
        if self.supportedCurves.len() > 0 {
            if echInner {
                echOuterExts.push(extensionSupportedCurves);
            } else {
                exts.AddUint16(extensionSupportedCurves);
                let cs = self.supportedCurves.clone();
                exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                    exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                        for curve in cs.iter() {
                            exts.AddUint16(*curve);
                        }
                    });
                });
            }
        }
        // Go: if len(m.supportedSignatureAlgorithms) > 0 { … } — RFC 5246 §7.4.1.4.1
        if self.supportedSignatureAlgorithms.len() > 0 {
            if echInner {
                echOuterExts.push(extensionSignatureAlgorithms);
            } else {
                exts.AddUint16(extensionSignatureAlgorithms);
                let algs = self.supportedSignatureAlgorithms.clone();
                exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                    exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                        for sigAlgo in algs.iter() {
                            exts.AddUint16(*sigAlgo);
                        }
                    });
                });
            }
        }
        // Go: if len(m.supportedSignatureAlgorithmsCert) > 0 { … } — RFC 8446 §4.2.3
        if self.supportedSignatureAlgorithmsCert.len() > 0 {
            if echInner {
                echOuterExts.push(extensionSignatureAlgorithmsCert);
            } else {
                exts.AddUint16(extensionSignatureAlgorithmsCert);
                let algs = self.supportedSignatureAlgorithmsCert.clone();
                exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                    exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                        for sigAlgo in algs.iter() {
                            exts.AddUint16(*sigAlgo);
                        }
                    });
                });
            }
        }
        // Go: if len(m.alpnProtocols) > 0 { … } — RFC 7301, Section 3.1
        if self.alpnProtocols.len() > 0 {
            if echInner {
                echOuterExts.push(extensionALPN);
            } else {
                exts.AddUint16(extensionALPN);
                let protos = self.alpnProtocols.clone();
                exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                    exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                        for proto in protos.iter() {
                            exts.AddUint8LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                                exts.AddBytes(&bs(proto.as_bytes()));
                            });
                        }
                    });
                });
            }
        }
        // Go: if len(m.supportedVersions) > 0 { … } — RFC 8446, Section 4.2.1
        if self.supportedVersions.len() > 0 {
            if echInner {
                echOuterExts.push(extensionSupportedVersions);
            } else {
                exts.AddUint16(extensionSupportedVersions);
                let vs = self.supportedVersions.clone();
                exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                    exts.AddUint8LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                        for vers in vs.iter() {
                            exts.AddUint16(*vers);
                        }
                    });
                });
            }
        }
        // Go: if len(m.cookie) > 0 { … } — RFC 8446, Section 4.2.2
        if self.cookie.len() > 0 {
            if echInner {
                echOuterExts.push(extensionCookie);
            } else {
                exts.AddUint16(extensionCookie);
                let c = self.cookie.clone();
                exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                    exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                        exts.AddBytes(&bs(&c));
                    });
                });
            }
        }
        // Go: if len(m.keyShares) > 0 { … } — RFC 8446, Section 4.2.8
        if self.keyShares.len() > 0 {
            if echInner {
                echOuterExts.push(extensionKeyShare);
            } else {
                exts.AddUint16(extensionKeyShare);
                let kss = self.keyShares.clone();
                exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                    exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                        for ks in kss.iter() {
                            exts.AddUint16(ks.group);
                            let d = ks.data.clone();
                            exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                                exts.AddBytes(&bs(&d));
                            });
                        }
                    });
                });
            }
        }
        // Go: if len(m.pskModes) > 0 { … } — RFC 8446, Section 4.2.9
        if self.pskModes.len() > 0 {
            if echInner {
                echOuterExts.push(extensionPSKModes);
            } else {
                exts.AddUint16(extensionPSKModes);
                let pm = self.pskModes.clone();
                exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                    exts.AddUint8LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                        exts.AddBytes(&bs(&pm));
                    });
                });
            }
        }
        // Go: if len(echOuterExts) > 0 && echInner { … }
        if echOuterExts.len() > 0 && echInner {
            exts.AddUint16(super::common::extensionECHOuterExtensions);
            let oe = echOuterExts.clone();
            exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                exts.AddUint8LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                    for e in oe.iter() {
                        exts.AddUint16(*e);
                    }
                });
            });
        }
        // Go: if len(m.pskIdentities) > 0 { // pre_shared_key must be the
        //     last extension } — RFC 8446, Section 4.2.11
        if self.pskIdentities.len() > 0 {
            exts.AddUint16(extensionPreSharedKey);
            let ids = self.pskIdentities.clone();
            let binders = self.pskBinders.clone();
            exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                    for psk in ids.iter() {
                        let lab = psk.label.clone();
                        exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                            exts.AddBytes(&bs(&lab));
                        });
                        exts.AddUint32(psk.obfuscatedTicketAge);
                    }
                });
                exts.AddUint16LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                    for binder in binders.iter() {
                        let b2 = binder.clone();
                        exts.AddUint8LengthPrefixed(|exts: &mut cryptobyte::Builder| {
                            exts.AddBytes(&bs(&b2));
                        });
                    }
                });
            });
        }
        // Go: extBytes, err := exts.Bytes(); if err != nil { return nil, err }
        let (extBytes, err) = exts.Bytes();
        if err != crate::errors::nil {
            return (slice::__from_vec(Vec::new()), err);
        }

        // Go: var b cryptobyte.Builder
        //     b.AddUint8(typeClientHello)
        let mut b = cryptobyte::NewBuilder(slice::__from_vec(Vec::new()));
        b.AddUint8(typeClientHello);
        let vers = self.vers;
        let random = self.random.clone();
        let sessionId = self.sessionId.clone();
        let cipherSuites = self.cipherSuites.clone();
        let compressionMethods = self.compressionMethods.clone();
        b.AddUint24LengthPrefixed(|b: &mut cryptobyte::Builder| {
            b.AddUint16(vers);
            addBytesWithLength(b, &random, 32);
            b.AddUint8LengthPrefixed(|b: &mut cryptobyte::Builder| {
                if !echInner {
                    b.AddBytes(&bs(&sessionId));
                }
            });
            b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
                for suite in cipherSuites.iter() {
                    b.AddUint16(*suite);
                }
            });
            b.AddUint8LengthPrefixed(|b: &mut cryptobyte::Builder| {
                b.AddBytes(&bs(&compressionMethods));
            });

            if extBytes.Len() > 0 {
                b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
                    b.AddBytes(&extBytes);
                });
            }
        });

        // Go: return b.Bytes()
        return b.Bytes();
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:374-376 clientHelloMsg.marshal
    pub(crate) fn marshal(&self) -> (slice<byte>, crate::error) {
        // Go: return m.marshalMsg(false)
        return self.marshalMsg(false);
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:382-400 clientHelloMsg.marshalWithoutBinders
    /// The ClientHello through the `PreSharedKeyExtension.identities`
    /// field, per RFC 8446 §4.2.11.2. `m.pskBinders` must already be set
    /// to slices of the correct length.
    pub(crate) fn marshalWithoutBinders(&self) -> (slice<byte>, crate::error) {
        // Go: bindersLen := 2 // uint16 length prefix
        //     for _, binder := range m.pskBinders { bindersLen += 1; bindersLen += len(binder) }
        let mut bindersLen: usize = 2;
        for binder in self.pskBinders.iter() {
            bindersLen += 1; // uint8 length prefix
            bindersLen += binder.len();
        }

        // Go: var fullMessage []byte
        //     if m.original != nil { fullMessage = m.original }
        //     else { fullMessage, err = m.marshal(); if err != nil { return nil, err } }
        let fullMessage: slice<byte>;
        if !self.original.is_empty() {
            fullMessage = slice::__from_vec(self.original.clone());
        } else {
            let (fm, err) = self.marshal();
            if err != crate::errors::nil {
                return (slice::__from_vec(Vec::new()), err);
            }
            fullMessage = fm;
        }
        // Go: return fullMessage[:len(fullMessage)-bindersLen], nil
        let n = fullMessage.Len();
        return (
            fullMessage.slice(0, n - bindersLen as crate::types::int),
            crate::errors::nil,
        );
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:404-416 clientHelloMsg.updateBinders
    /// Update `m.pskBinders`. The supplied binders must have the same
    /// length as the current ones.
    ///
    ///
    /// Go's `[][]byte` is spelled `slice<slice<byte>>` here rather than
    /// the `Vec<Vec<byte>>` the private field uses, because this one
    /// crosses a package boundary.
    pub(crate) fn updateBinders(&mut self, pskBinders: slice<slice<byte>>) -> crate::error {
        // Go: if len(pskBinders) != len(m.pskBinders) { return errors.New(…) }
        if pskBinders.Len() as usize != self.pskBinders.len() {
            return crate::errors::New("tls: internal error: pskBinders length mismatch");
        }
        // Go: for i := range m.pskBinders {
        //         if len(pskBinders[i]) != len(m.pskBinders[i]) { return errors.New(…) }
        //     }
        let mut i: usize = 0;
        while i < self.pskBinders.len() {
            if pskBinders[i].Len() as usize != self.pskBinders[i].len() {
                return crate::errors::New("tls: internal error: pskBinders length mismatch");
            }
            i += 1;
        }
        // Go: m.pskBinders = pskBinders
        let mut next: Vec<Vec<byte>> = Vec::new();
        for (_, b) in crate::range!(pskBinders) {
            let raw: &[byte] = b;
            next.push(raw.to_vec());
        }
        self.pskBinders = next;

        // Go: return nil
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:682-684 clientHelloMsg.originalBytes
    pub(crate) fn originalBytes(&self) -> slice<byte> {
        // Go: return m.original
        return slice::__from_vec(self.original.clone());
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:686-717 clientHelloMsg.clone
    /// A deep copy. Go clones every slice field; the two ECH-related
    /// fields are cloned too, but `extensions` deliberately is not — it
    /// is server-side scratch and Go leaves it nil in the copy.
    pub(crate) fn clone(&self) -> clientHelloMsg {
        return clientHelloMsg {
            original: self.original.clone(),
            vers: self.vers,
            random: self.random.clone(),
            sessionId: self.sessionId.clone(),
            cipherSuites: self.cipherSuites.clone(),
            compressionMethods: self.compressionMethods.clone(),
            serverName: self.serverName.clone(),
            ocspStapling: self.ocspStapling,
            supportedCurves: self.supportedCurves.clone(),
            supportedPoints: self.supportedPoints.clone(),
            ticketSupported: self.ticketSupported,
            sessionTicket: self.sessionTicket.clone(),
            supportedSignatureAlgorithms: self.supportedSignatureAlgorithms.clone(),
            supportedSignatureAlgorithmsCert: self.supportedSignatureAlgorithmsCert.clone(),
            secureRenegotiationSupported: self.secureRenegotiationSupported,
            secureRenegotiation: self.secureRenegotiation.clone(),
            extendedMasterSecret: self.extendedMasterSecret,
            alpnProtocols: self.alpnProtocols.clone(),
            scts: self.scts,
            supportedVersions: self.supportedVersions.clone(),
            cookie: self.cookie.clone(),
            keyShares: self.keyShares.clone(),
            earlyData: self.earlyData,
            pskModes: self.pskModes.clone(),
            pskIdentities: self.pskIdentities.clone(),
            pskBinders: self.pskBinders.clone(),
            quicTransportParameters: self.quicTransportParameters.clone(),
            encryptedClientHello: self.encryptedClientHello.clone(),
            extensions: Vec::new(),
        };
    }
}

// Go: handshake_messages.go:1653
//   type serverHelloDoneMsg struct{}
/// The TLS 1.0-1.2 ServerHelloDone: a bare four-byte header.
#[derive(Clone, Default)]
pub(crate) struct serverHelloDoneMsg {}

impl serverHelloDoneMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1655-1659 serverHelloDoneMsg.marshal
    pub(crate) fn marshal(&self) -> (slice<byte>, crate::error) {
        // Go: x := make([]byte, 4); x[0] = typeServerHelloDone; return x, nil
        let mut x: Vec<byte> = alloc::vec![0u8; 4];
        x[0] = typeServerHelloDone;
        return (slice::__from_vec(x), crate::errors::nil);
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:1661-1663 serverHelloDoneMsg.unmarshal
    pub(crate) fn unmarshal(&mut self, data: slice<byte>) -> bool {
        // Go: return len(data) == 4
        return data.Len() == 4;
    }
}


impl serverHelloMsg {
    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:871-997 serverHelloMsg.unmarshal
    pub(crate) fn unmarshal(&mut self, data: slice<byte>) -> bool {
        // Go: *m = serverHelloMsg{original: data}
        //     s := cryptobyte.String(data)
        *self = serverHelloMsg::default();
        let raw: &[byte] = &data;
        self.original = raw.to_vec();
        let mut s = CBString::New(data);

        // Go: if !s.Skip(4) || // message type and uint24 length field
        //        !s.ReadUint16(&m.vers) || !s.ReadBytes(&m.random, 32) ||
        //        !readUint8LengthPrefixed(&s, &m.sessionId) ||
        //        !s.ReadUint16(&m.cipherSuite) ||
        //        !s.ReadUint8(&m.compressionMethod) { return false }
        let mut random: slice<byte> = slice::new();
        let mut sessionId: slice<byte> = slice::new();
        if !s.Skip(4)
            || !s.ReadUint16(&mut self.vers)
            || !s.ReadBytes(&mut random, 32)
            || !readUint8LengthPrefixed(&mut s, &mut sessionId)
            || !s.ReadUint16(&mut self.cipherSuite)
            || !s.ReadUint8(&mut self.compressionMethod)
        {
            return false;
        }
        self.random = random.__into_vec();
        self.sessionId = sessionId.__into_vec();

        // Go: if s.Empty() {
        //         // ServerHello is optionally followed by extension data
        //         return true }
        if s.Empty() {
            return true;
        }

        // Go: var extensions cryptobyte.String
        //     if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() { return false }
        let mut extensions = CBString::New(slice::new());
        if !s.ReadUint16LengthPrefixed(&mut extensions) || !s.Empty() {
            return false;
        }

        // Go: seenExts := make(map[uint16]bool)
        //     for !extensions.Empty() { … }
        let mut seenExts: Vec<u16> = Vec::new();
        while !extensions.Empty() {
            let mut extension: u16 = 0;
            let mut extData = CBString::New(slice::new());
            if !extensions.ReadUint16(&mut extension)
                || !extensions.ReadUint16LengthPrefixed(&mut extData)
            {
                return false;
            }

            // Go: if seenExts[extension] { return false }
            //     seenExts[extension] = true
            if seenExts.contains(&extension) {
                return false;
            }
            seenExts.push(extension);

            // Go: switch extension { … }
            if extension == extensionStatusRequest {
                self.ocspStapling = true;
            } else if extension == extensionSessionTicket {
                self.ticketSupported = true;
            } else if extension == extensionRenegotiationInfo {
                let mut sr: slice<byte> = slice::new();
                if !readUint8LengthPrefixed(&mut extData, &mut sr) {
                    return false;
                }
                self.secureRenegotiation = sr.__into_vec();
                self.secureRenegotiationSupported = true;
            } else if extension == extensionExtendedMasterSecret {
                self.extendedMasterSecret = true;
            } else if extension == extensionALPN {
                // Go: var protoList cryptobyte.String
                //     if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
                //         return false }
                //     var proto cryptobyte.String
                //     if !protoList.ReadUint8LengthPrefixed(&proto) ||
                //        proto.Empty() || !protoList.Empty() { return false }
                //     m.alpnProtocol = string(proto)
                let mut protoList = CBString::New(slice::new());
                if !extData.ReadUint16LengthPrefixed(&mut protoList) || protoList.Empty() {
                    return false;
                }
                let mut proto = CBString::New(slice::new());
                if !protoList.ReadUint8LengthPrefixed(&mut proto)
                    || proto.Empty()
                    || !protoList.Empty()
                {
                    return false;
                }
                let pb: &[byte] = &proto.0;
                self.alpnProtocol =
                    String::from_utf8(pb.to_vec()).unwrap_or_default();
            } else if extension == extensionSCT {
                // Go: var sctList cryptobyte.String
                //     if !extData.ReadUint16LengthPrefixed(&sctList) || sctList.Empty() {
                //         return false }
                //     for !sctList.Empty() {
                //         var sct []byte
                //         if !readUint16LengthPrefixed(&sctList, &sct) || len(sct) == 0 {
                //             return false }
                //         m.scts = append(m.scts, sct) }
                let mut sctList = CBString::New(slice::new());
                if !extData.ReadUint16LengthPrefixed(&mut sctList) || sctList.Empty() {
                    return false;
                }
                while !sctList.Empty() {
                    let mut sct: slice<byte> = slice::new();
                    if !readUint16LengthPrefixed(&mut sctList, &mut sct) || sct.Len() == 0 {
                        return false;
                    }
                    self.scts.push(sct.__into_vec());
                }
            } else if extension == extensionSupportedVersions {
                if !extData.ReadUint16(&mut self.supportedVersion) {
                    return false;
                }
            } else if extension == extensionCookie {
                let mut cookie: slice<byte> = slice::new();
                if !readUint16LengthPrefixed(&mut extData, &mut cookie) || cookie.Len() == 0 {
                    return false;
                }
                self.cookie = cookie.__into_vec();
            } else if extension == extensionKeyShare {
                // Go: This extension has different formats in SH and HRR,
                // accept either and let the handshake logic decide. See RFC
                // 8446, Section 4.2.8.
                if extData.0.Len() == 2 {
                    if !extData.ReadUint16(&mut self.selectedGroup) {
                        return false;
                    }
                } else {
                    let mut d: slice<byte> = slice::new();
                    if !extData.ReadUint16(&mut self.serverShare.group)
                        || !readUint16LengthPrefixed(&mut extData, &mut d)
                    {
                        return false;
                    }
                    self.serverShare.data = d.__into_vec();
                }
            } else if extension == extensionPreSharedKey {
                self.selectedIdentityPresent = true;
                if !extData.ReadUint16(&mut self.selectedIdentity) {
                    return false;
                }
            } else if extension == extensionSupportedPoints {
                // Go: RFC 4492, Section 5.1.2
                let mut pts: slice<byte> = slice::new();
                if !readUint8LengthPrefixed(&mut extData, &mut pts) || pts.Len() == 0 {
                    return false;
                }
                self.supportedPoints = pts.__into_vec();
            } else if extension == extensionEncryptedClientHello {
                let n = extData.0.Len();
                let mut ech: slice<byte> = slice::new();
                if !extData.ReadBytes(&mut ech, n) {
                    return false;
                }
                self.encryptedClientHello = ech.__into_vec();
            } else if extension == extensionServerName {
                if extData.0.Len() != 0 {
                    return false;
                }
                self.serverNameAck = true;
            } else {
                // Go: default: // Ignore unknown extensions.
                continue;
            }

            // Go: if !extData.Empty() { return false }
            if !extData.Empty() {
                return false;
            }
        }

        // Go: return true
        return true;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_messages.go:999-1001 serverHelloMsg.originalBytes
    pub(crate) fn originalBytes(&self) -> slice<byte> {
        // Go: return m.original
        return slice::__from_vec(self.original.clone());
    }
}

// ── handshakeMessage, for every message type ────────────────────────
//
// Go gets this for free: each message already has `marshal`/`unmarshal`
// with the right shape, so it satisfies `handshakeMessage` implicitly.
// Rust needs the impl spelled out, and every member forwards to the
// inherent method of the same name. `asAny` and `asWithOriginalBytes`
// are the two goish-only members documented on the trait in common.rs.


impl super::common::handshakeMessage for helloRequestMsg {
    // go: none — goish-only: forwards to `helloRequestMsg::marshal`, which Go's
    // implicit interface satisfaction reaches directly.
    fn marshal(&self) -> (slice<byte>, crate::error) {
        return helloRequestMsg::marshal(self);
    }
    // go: none — goish-only: forwards to `helloRequestMsg::unmarshal`, same reason.
    fn unmarshal(&mut self, data: slice<byte>) -> bool {
        return helloRequestMsg::unmarshal(self, data);
    }
    // go: none — goish-only: stands in for the type assertion Go's
    // callers write on the `any` that `readHandshake` returns.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }
}

impl super::common::handshakeMessage for clientHelloMsg {
    // go: none — goish-only: forwards to `clientHelloMsg::marshal`, which Go's
    // implicit interface satisfaction reaches directly.
    fn marshal(&self) -> (slice<byte>, crate::error) {
        return clientHelloMsg::marshal(self);
    }
    // go: none — goish-only: forwards to `clientHelloMsg::unmarshal`, same reason.
    fn unmarshal(&mut self, data: slice<byte>) -> bool {
        return clientHelloMsg::unmarshal(self, data);
    }
    // go: none — goish-only: stands in for the type assertion Go's
    // callers write on the `any` that `readHandshake` returns.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }
    // go: none — goish-only: stands in for Go's
    // `msg.(handshakeMessageWithOriginalBytes)` assertion, which Rust
    // cannot express as a trait-object downcast.
    fn asWithOriginalBytes(&self) -> Option<&dyn super::common::handshakeMessageWithOriginalBytes> {
        return Some(self);
    }
}

impl super::common::handshakeMessageWithOriginalBytes for clientHelloMsg {
    // go: none — goish-only: forwards to `clientHelloMsg::originalBytes`.
    fn originalBytes(&self) -> slice<byte> {
        return clientHelloMsg::originalBytes(self);
    }
}

impl super::common::handshakeMessage for serverHelloMsg {
    // go: none — goish-only: forwards to `serverHelloMsg::marshal`, which Go's
    // implicit interface satisfaction reaches directly.
    fn marshal(&self) -> (slice<byte>, crate::error) {
        return serverHelloMsg::marshal(self);
    }
    // go: none — goish-only: forwards to `serverHelloMsg::unmarshal`, same reason.
    fn unmarshal(&mut self, data: slice<byte>) -> bool {
        return serverHelloMsg::unmarshal(self, data);
    }
    // go: none — goish-only: stands in for the type assertion Go's
    // callers write on the `any` that `readHandshake` returns.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }
    // go: none — goish-only: stands in for Go's
    // `msg.(handshakeMessageWithOriginalBytes)` assertion, which Rust
    // cannot express as a trait-object downcast.
    fn asWithOriginalBytes(&self) -> Option<&dyn super::common::handshakeMessageWithOriginalBytes> {
        return Some(self);
    }
}

impl super::common::handshakeMessageWithOriginalBytes for serverHelloMsg {
    // go: none — goish-only: forwards to `serverHelloMsg::originalBytes`.
    fn originalBytes(&self) -> slice<byte> {
        return serverHelloMsg::originalBytes(self);
    }
}

impl super::common::handshakeMessage for newSessionTicketMsg {
    // go: none — goish-only: forwards to `newSessionTicketMsg::marshal`, which Go's
    // implicit interface satisfaction reaches directly.
    fn marshal(&self) -> (slice<byte>, crate::error) {
        return newSessionTicketMsg::marshal(self);
    }
    // go: none — goish-only: forwards to `newSessionTicketMsg::unmarshal`, same reason.
    fn unmarshal(&mut self, data: slice<byte>) -> bool {
        return newSessionTicketMsg::unmarshal(self, data);
    }
    // go: none — goish-only: stands in for the type assertion Go's
    // callers write on the `any` that `readHandshake` returns.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }
}

impl super::common::handshakeMessage for newSessionTicketMsgTLS13 {
    // go: none — goish-only: forwards to `newSessionTicketMsgTLS13::marshal`, which Go's
    // implicit interface satisfaction reaches directly.
    fn marshal(&self) -> (slice<byte>, crate::error) {
        return newSessionTicketMsgTLS13::marshal(self);
    }
    // go: none — goish-only: forwards to `newSessionTicketMsgTLS13::unmarshal`, same reason.
    fn unmarshal(&mut self, data: slice<byte>) -> bool {
        return newSessionTicketMsgTLS13::unmarshal(self, data);
    }
    // go: none — goish-only: stands in for the type assertion Go's
    // callers write on the `any` that `readHandshake` returns.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }
}

impl super::common::handshakeMessage for certificateMsg {
    // go: none — goish-only: forwards to `certificateMsg::marshal`, which Go's
    // implicit interface satisfaction reaches directly.
    fn marshal(&self) -> (slice<byte>, crate::error) {
        return certificateMsg::marshal(self);
    }
    // go: none — goish-only: forwards to `certificateMsg::unmarshal`, same reason.
    fn unmarshal(&mut self, data: slice<byte>) -> bool {
        return certificateMsg::unmarshal(self, data);
    }
    // go: none — goish-only: stands in for the type assertion Go's
    // callers write on the `any` that `readHandshake` returns.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }
}

impl super::common::handshakeMessage for certificateMsgTLS13 {
    // go: none — goish-only: forwards to `certificateMsgTLS13::marshal`, which Go's
    // implicit interface satisfaction reaches directly.
    fn marshal(&self) -> (slice<byte>, crate::error) {
        return certificateMsgTLS13::marshal(self);
    }
    // go: none — goish-only: forwards to `certificateMsgTLS13::unmarshal`, same reason.
    fn unmarshal(&mut self, data: slice<byte>) -> bool {
        return certificateMsgTLS13::unmarshal(self, data);
    }
    // go: none — goish-only: stands in for the type assertion Go's
    // callers write on the `any` that `readHandshake` returns.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }
}

impl super::common::handshakeMessage for certificateRequestMsg {
    // go: none — goish-only: forwards to `certificateRequestMsg::marshal`, which Go's
    // implicit interface satisfaction reaches directly.
    fn marshal(&self) -> (slice<byte>, crate::error) {
        return certificateRequestMsg::marshal(self);
    }
    // go: none — goish-only: forwards to `certificateRequestMsg::unmarshal`, same reason.
    fn unmarshal(&mut self, data: slice<byte>) -> bool {
        return certificateRequestMsg::unmarshal(self, data);
    }
    // go: none — goish-only: stands in for the type assertion Go's
    // callers write on the `any` that `readHandshake` returns.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }
}

impl super::common::handshakeMessage for certificateRequestMsgTLS13 {
    // go: none — goish-only: forwards to `certificateRequestMsgTLS13::marshal`, which Go's
    // implicit interface satisfaction reaches directly.
    fn marshal(&self) -> (slice<byte>, crate::error) {
        return certificateRequestMsgTLS13::marshal(self);
    }
    // go: none — goish-only: forwards to `certificateRequestMsgTLS13::unmarshal`, same reason.
    fn unmarshal(&mut self, data: slice<byte>) -> bool {
        return certificateRequestMsgTLS13::unmarshal(self, data);
    }
    // go: none — goish-only: stands in for the type assertion Go's
    // callers write on the `any` that `readHandshake` returns.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }
}

impl super::common::handshakeMessage for certificateStatusMsg {
    // go: none — goish-only: forwards to `certificateStatusMsg::marshal`, which Go's
    // implicit interface satisfaction reaches directly.
    fn marshal(&self) -> (slice<byte>, crate::error) {
        return certificateStatusMsg::marshal(self);
    }
    // go: none — goish-only: forwards to `certificateStatusMsg::unmarshal`, same reason.
    fn unmarshal(&mut self, data: slice<byte>) -> bool {
        return certificateStatusMsg::unmarshal(self, data);
    }
    // go: none — goish-only: stands in for the type assertion Go's
    // callers write on the `any` that `readHandshake` returns.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }
}

impl super::common::handshakeMessage for serverKeyExchangeMsg {
    // go: none — goish-only: forwards to `serverKeyExchangeMsg::marshal`, which Go's
    // implicit interface satisfaction reaches directly.
    fn marshal(&self) -> (slice<byte>, crate::error) {
        return serverKeyExchangeMsg::marshal(self);
    }
    // go: none — goish-only: forwards to `serverKeyExchangeMsg::unmarshal`, same reason.
    fn unmarshal(&mut self, data: slice<byte>) -> bool {
        return serverKeyExchangeMsg::unmarshal(self, data);
    }
    // go: none — goish-only: stands in for the type assertion Go's
    // callers write on the `any` that `readHandshake` returns.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }
}

impl super::common::handshakeMessage for serverHelloDoneMsg {
    // go: none — goish-only: forwards to `serverHelloDoneMsg::marshal`, which Go's
    // implicit interface satisfaction reaches directly.
    fn marshal(&self) -> (slice<byte>, crate::error) {
        return serverHelloDoneMsg::marshal(self);
    }
    // go: none — goish-only: forwards to `serverHelloDoneMsg::unmarshal`, same reason.
    fn unmarshal(&mut self, data: slice<byte>) -> bool {
        return serverHelloDoneMsg::unmarshal(self, data);
    }
    // go: none — goish-only: stands in for the type assertion Go's
    // callers write on the `any` that `readHandshake` returns.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }
}

impl super::common::handshakeMessage for clientKeyExchangeMsg {
    // go: none — goish-only: forwards to `clientKeyExchangeMsg::marshal`, which Go's
    // implicit interface satisfaction reaches directly.
    fn marshal(&self) -> (slice<byte>, crate::error) {
        return clientKeyExchangeMsg::marshal(self);
    }
    // go: none — goish-only: forwards to `clientKeyExchangeMsg::unmarshal`, same reason.
    fn unmarshal(&mut self, data: slice<byte>) -> bool {
        return clientKeyExchangeMsg::unmarshal(self, data);
    }
    // go: none — goish-only: stands in for the type assertion Go's
    // callers write on the `any` that `readHandshake` returns.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }
}

impl super::common::handshakeMessage for certificateVerifyMsg {
    // go: none — goish-only: forwards to `certificateVerifyMsg::marshal`, which Go's
    // implicit interface satisfaction reaches directly.
    fn marshal(&self) -> (slice<byte>, crate::error) {
        return certificateVerifyMsg::marshal(self);
    }
    // go: none — goish-only: forwards to `certificateVerifyMsg::unmarshal`, same reason.
    fn unmarshal(&mut self, data: slice<byte>) -> bool {
        return certificateVerifyMsg::unmarshal(self, data);
    }
    // go: none — goish-only: stands in for the type assertion Go's
    // callers write on the `any` that `readHandshake` returns.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }
}

impl super::common::handshakeMessage for finishedMsg {
    // go: none — goish-only: forwards to `finishedMsg::marshal`, which Go's
    // implicit interface satisfaction reaches directly.
    fn marshal(&self) -> (slice<byte>, crate::error) {
        return finishedMsg::marshal(self);
    }
    // go: none — goish-only: forwards to `finishedMsg::unmarshal`, same reason.
    fn unmarshal(&mut self, data: slice<byte>) -> bool {
        return finishedMsg::unmarshal(self, data);
    }
    // go: none — goish-only: stands in for the type assertion Go's
    // callers write on the `any` that `readHandshake` returns.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }
}

impl super::common::handshakeMessage for encryptedExtensionsMsg {
    // go: none — goish-only: forwards to `encryptedExtensionsMsg::marshal`, which Go's
    // implicit interface satisfaction reaches directly.
    fn marshal(&self) -> (slice<byte>, crate::error) {
        return encryptedExtensionsMsg::marshal(self);
    }
    // go: none — goish-only: forwards to `encryptedExtensionsMsg::unmarshal`, same reason.
    fn unmarshal(&mut self, data: slice<byte>) -> bool {
        return encryptedExtensionsMsg::unmarshal(self, data);
    }
    // go: none — goish-only: stands in for the type assertion Go's
    // callers write on the `any` that `readHandshake` returns.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }
}

impl super::common::handshakeMessage for endOfEarlyDataMsg {
    // go: none — goish-only: forwards to `endOfEarlyDataMsg::marshal`, which Go's
    // implicit interface satisfaction reaches directly.
    fn marshal(&self) -> (slice<byte>, crate::error) {
        return endOfEarlyDataMsg::marshal(self);
    }
    // go: none — goish-only: forwards to `endOfEarlyDataMsg::unmarshal`, same reason.
    fn unmarshal(&mut self, data: slice<byte>) -> bool {
        return endOfEarlyDataMsg::unmarshal(self, data);
    }
    // go: none — goish-only: stands in for the type assertion Go's
    // callers write on the `any` that `readHandshake` returns.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }
}

impl super::common::handshakeMessage for keyUpdateMsg {
    // go: none — goish-only: forwards to `keyUpdateMsg::marshal`, which Go's
    // implicit interface satisfaction reaches directly.
    fn marshal(&self) -> (slice<byte>, crate::error) {
        return keyUpdateMsg::marshal(self);
    }
    // go: none — goish-only: forwards to `keyUpdateMsg::unmarshal`, same reason.
    fn unmarshal(&mut self, data: slice<byte>) -> bool {
        return keyUpdateMsg::unmarshal(self, data);
    }
    // go: none — goish-only: stands in for the type assertion Go's
    // callers write on the `any` that `readHandshake` returns.
    fn asAny(&self) -> &dyn core::any::Any {
        return self;
    }
}

// Go: handshake_messages.go:1934-1936
//   type transcriptHash interface { Write([]byte) (int, error) }
/// Go's `transcriptHash` — the write half of a running handshake hash.
/// Any `io::Writer` satisfies it, which is how Go's `hash.Hash` does.
pub(crate) trait transcriptHash {
    /// Go: `Write([]byte) (int, error)`
    fn Write(&mut self, p: slice<byte>) -> (crate::types::int, error);
}

impl<T: crate::io::Writer> transcriptHash for T {
    // go: none — goish-only: in Go a `hash.Hash` satisfies
    // `transcriptHash` structurally, because it embeds `io.Writer`.
    fn Write(&mut self, p: slice<byte>) -> (crate::types::int, error) {
        return crate::io::Writer::Write(self, p);
    }
}

// go: none — goish-only: Go's `hs.transcript` is a `hash.Hash`, an
// interface value that satisfies `transcriptHash` by shape. goish holds
// `Box<dyn hash::Hash>`, and Rust cannot re-coerce one trait object
// into another, so the box is wrapped in this sized carrier. It is the
// same value; only the plumbing differs.
pub(crate) struct transcriptHasher(pub alloc::boxed::Box<dyn crate::hash::Hash + Send + Sync>);

impl crate::io::Writer for transcriptHasher {
    // go: none — goish-only: forwards to the boxed hash.
    fn Write(&mut self, p: slice<byte>) -> (crate::types::int, error) {
        return crate::io::Writer::Write(&mut *self.0, p);
    }
}

// go: sdk 1.25.5 crypto/tls/handshake_messages.go:1949-1962 transcriptMsg
/// Go: "transcriptMsg is a helper used to hash messages which are not
/// hashed when they are read from, or written to, the wire. This is
/// typically the case for messages which are either not sent, or need
/// to be hashed out of order from when they are read/written.
///
/// For most messages, the message is marshalled using their marshal
/// method, since their wire representation is idempotent. For
/// clientHelloMsg and serverHelloMsg, we store the original wire
/// representation of the message and use that for hashing, since
/// unmarshal/marshal are not idempotent due to extension ordering and
/// other malleable fields, which may cause differences between what was
/// received and what we marshal."
pub(crate) fn transcriptMsg(
    msg: &dyn super::common::handshakeMessage,
    h: &mut dyn transcriptHash,
) -> crate::error {
    // Go: if msgWithOrig, ok := msg.(handshakeMessageWithOriginalBytes); ok {
    //         if orig := msgWithOrig.originalBytes(); orig != nil {
    //             h.Write(msgWithOrig.originalBytes()); return nil } }
    if let Some(msgWithOrig) = msg.asWithOriginalBytes() {
        let orig = msgWithOrig.originalBytes();
        if orig.Len() != 0 {
            h.Write(msgWithOrig.originalBytes());
            return crate::errors::nil;
        }
    }

    // Go: data, err := msg.marshal(); if err != nil { return err }
    let (data, err) = msg.marshal();
    if err != crate::errors::nil {
        return err;
    }
    // Go: h.Write(data); return nil
    h.Write(data);
    return crate::errors::nil;
}

// go: none — goish-only: stands in for Go's `%T` on a
// `handshakeMessage`, which `unexpectedMessageError` formats. Rust
// trait objects carry no printable type name, so the concrete type is
// recovered through `asAny` and named explicitly.
pub(crate) fn handshakeMessageTypeName(
    m: &dyn super::common::handshakeMessage,
) -> crate::gostring::string {
    let a = m.asAny();
    if a.is::<helloRequestMsg>() {
        return crate::gostring::string::from_static("*tls.helloRequestMsg");
    } else if a.is::<clientHelloMsg>() {
        return crate::gostring::string::from_static("*tls.clientHelloMsg");
    } else if a.is::<serverHelloMsg>() {
        return crate::gostring::string::from_static("*tls.serverHelloMsg");
    } else if a.is::<newSessionTicketMsg>() {
        return crate::gostring::string::from_static("*tls.newSessionTicketMsg");
    } else if a.is::<newSessionTicketMsgTLS13>() {
        return crate::gostring::string::from_static("*tls.newSessionTicketMsgTLS13");
    } else if a.is::<certificateMsg>() {
        return crate::gostring::string::from_static("*tls.certificateMsg");
    } else if a.is::<certificateMsgTLS13>() {
        return crate::gostring::string::from_static("*tls.certificateMsgTLS13");
    } else if a.is::<certificateRequestMsg>() {
        return crate::gostring::string::from_static("*tls.certificateRequestMsg");
    } else if a.is::<certificateRequestMsgTLS13>() {
        return crate::gostring::string::from_static("*tls.certificateRequestMsgTLS13");
    } else if a.is::<certificateStatusMsg>() {
        return crate::gostring::string::from_static("*tls.certificateStatusMsg");
    } else if a.is::<serverKeyExchangeMsg>() {
        return crate::gostring::string::from_static("*tls.serverKeyExchangeMsg");
    } else if a.is::<serverHelloDoneMsg>() {
        return crate::gostring::string::from_static("*tls.serverHelloDoneMsg");
    } else if a.is::<clientKeyExchangeMsg>() {
        return crate::gostring::string::from_static("*tls.clientKeyExchangeMsg");
    } else if a.is::<certificateVerifyMsg>() {
        return crate::gostring::string::from_static("*tls.certificateVerifyMsg");
    } else if a.is::<finishedMsg>() {
        return crate::gostring::string::from_static("*tls.finishedMsg");
    } else if a.is::<encryptedExtensionsMsg>() {
        return crate::gostring::string::from_static("*tls.encryptedExtensionsMsg");
    } else if a.is::<endOfEarlyDataMsg>() {
        return crate::gostring::string::from_static("*tls.endOfEarlyDataMsg");
    } else if a.is::<keyUpdateMsg>() {
        return crate::gostring::string::from_static("*tls.keyUpdateMsg");
    }
    return crate::gostring::string::from_static("<nil>");
}
