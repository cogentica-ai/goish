// go: file crypto/tls/ticket.go decls: SessionState.Bytes, certificatesToBytesSlice, ParseSessionState, ClientSessionState.ResumptionState, NewResumptionState, Config.EncryptTicket, Config.encryptTicket, Config.DecryptTicket, Config.decryptTicket, Conn.sessionState
//
// crypto/tls — the session-resumption state and its wire encoding.
//
// **Partial port.** What is here is `SessionState` and the two halves of
// its encoding, which depend on nothing but `marshalCertificate` and
// `unmarshalCertificate`. What is not here is the ticket *sealing*:
// `Config.EncryptTicket`/`DecryptTicket` and their unexported halves
// need `Config.ticketKeys`, which is part of the Config record still in
// mod[rs]; and `Conn.sessionState` needs a Conn.
//
//
// One deviation: Go resolves each peer certificate through
// `globalCertCache.newCert`, a `sync.Map` of weak pointers that memoises
// parsing across sessions. goish has no weak pointers (the same reason
// `fips140cache` trades caching for portability), so `ParseSessionState`
// calls `x509.ParseCertificate` directly. Same results, no sharing.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

extern crate alloc;
use alloc::vec::Vec;

use super::common::{Certificate, CurveID, VersionTLS13};
use super::handshake_messages::{
    addUint64, marshalCertificate, readUint24LengthPrefixed, readUint64,
    readUint8LengthPrefixed, unmarshalCertificate,
};
use crate::crypto::cryptobyte;
use crate::crypto::cryptobyte::String as CBString;
use crate::crypto::x509;
use crate::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, uint16, uint32, uint64, uint8};

// Go: ticket.go:26-83
//   type SessionState struct { Extra [][]byte; EarlyData bool
//                              version uint16; isClient bool; cipherSuite uint16
//                              createdAt uint64; secret []byte; extMasterSecret bool
//                              peerCertificates []*x509.Certificate
//                              ocspResponse []byte; scts [][]byte
//                              verifiedChains [][]*x509.Certificate
//                              alpnProtocol string
//                              useBy uint64; ageAdd uint32; ticket []byte
//                              curveID CurveID }
/// Go: "A SessionState is a resumable session."
#[derive(Clone, Default)]
pub struct SessionState {
    /// Go: "Extra is ignored by crypto/tls, but is encoded by
    /// [SessionState.Bytes] and parsed by [ParseSessionState]."
    pub Extra: slice<slice<byte>>,
    /// Go: "EarlyData indicates whether the ticket can be used for 0-RTT
    /// in a QUIC connection."
    pub EarlyData: bool,
    pub(crate) version: uint16,
    pub(crate) isClient: bool,
    pub(crate) cipherSuite: uint16,
    /// Seconds since the UNIX epoch.
    pub(crate) createdAt: uint64,
    /// Master secret for TLS 1.2, or the PSK for TLS 1.3.
    pub(crate) secret: slice<byte>,
    pub(crate) extMasterSecret: bool,
    pub(crate) peerCertificates: slice<x509::Certificate>,
    pub(crate) ocspResponse: slice<byte>,
    pub(crate) scts: slice<slice<byte>>,
    pub(crate) verifiedChains: slice<slice<x509::Certificate>>,
    /// Only set if `EarlyData` is true.
    pub(crate) alpnProtocol: string,
    /// Seconds since the UNIX epoch.
    pub(crate) useBy: uint64,
    pub(crate) ageAdd: uint32,
    pub(crate) ticket: slice<byte>,
    pub(crate) curveID: CurveID,
}

// go: sdk 1.25.5 crypto/tls/ticket.go:85-93 certificatesToBytesSlice
pub(crate) fn certificatesToBytesSlice(certs: slice<x509::Certificate>) -> slice<slice<byte>> {
    // Go: s := make([][]byte, 0, len(certs))
    //     for _, c := range certs { s = append(s, c.Raw) }
    //     return s
    let mut s: Vec<slice<byte>> = Vec::with_capacity(certs.Len() as usize);
    for (_, c) in crate::range!(certs) {
        s.push(c.Raw.clone());
    }
    return slice::__from_vec(s);
}

impl SessionState {
    // go: sdk 1.25.5 crypto/tls/ticket.go:101-176 SessionState.Bytes
    /// Go: "Bytes encodes the session, including any private fields, so
    /// that it can be parsed by [ParseSessionState]. The encoding
    /// contains secret values critical to the security of future and
    /// possibly past sessions. The specific encoding should be
    /// considered opaque and may change incompatibly between Go
    /// versions."
    pub fn Bytes(&self) -> (slice<byte>, error) {
        // Go: var b cryptobyte.Builder
        //     b.AddUint16(s.version)
        //     if s.isClient { b.AddUint8(2) } else { b.AddUint8(1) }
        //     b.AddUint16(s.cipherSuite)
        //     addUint64(&b, s.createdAt)
        let mut b = cryptobyte::NewBuilder(slice::new());
        b.AddUint16(self.version);
        if self.isClient {
            b.AddUint8(2); // client
        } else {
            b.AddUint8(1); // server
        }
        b.AddUint16(self.cipherSuite);
        addUint64(&mut b, self.createdAt);
        // Go: b.AddUint8LengthPrefixed(func(b …) { b.AddBytes(s.secret) })
        let secret = self.secret.clone();
        b.AddUint8LengthPrefixed(|b: &mut cryptobyte::Builder| {
            b.AddBytes(&secret);
        });
        // Go: b.AddUint24LengthPrefixed(func(b …) {
        //         for _, extra := range s.Extra {
        //             b.AddUint24LengthPrefixed(func(b …) { b.AddBytes(extra) }) } })
        let extra = self.Extra.clone();
        b.AddUint24LengthPrefixed(|b: &mut cryptobyte::Builder| {
            for (_, e) in crate::range!(extra.clone()) {
                let e2 = e.clone();
                b.AddUint24LengthPrefixed(|b: &mut cryptobyte::Builder| {
                    b.AddBytes(&e2);
                });
            }
        });
        // Go: if s.extMasterSecret { b.AddUint8(1) } else { b.AddUint8(0) }
        //     if s.EarlyData { b.AddUint8(1) } else { b.AddUint8(0) }
        if self.extMasterSecret {
            b.AddUint8(1);
        } else {
            b.AddUint8(0);
        }
        if self.EarlyData {
            b.AddUint8(1);
        } else {
            b.AddUint8(0);
        }
        // Go: marshalCertificate(&b, Certificate{
        //         Certificate: certificatesToBytesSlice(s.peerCertificates),
        //         OCSPStaple: s.ocspResponse,
        //         SignedCertificateTimestamps: s.scts })
        let mut cert = Certificate::default();
        cert.Certificate = certificatesToBytesSlice(self.peerCertificates.clone());
        cert.OCSPStaple = self.ocspResponse.clone();
        cert.SignedCertificateTimestamps = self.scts.clone();
        marshalCertificate(&mut b, &cert);
        // Go: b.AddUint24LengthPrefixed(func(b …) {
        //         for _, chain := range s.verifiedChains {
        //             b.AddUint24LengthPrefixed(func(b …) {
        //                 // We elide the first certificate because it's always the leaf.
        //                 if len(chain) == 0 {
        //                     b.SetError(errors.New("tls: internal error: empty verified chain"))
        //                     return
        //                 }
        //                 for _, cert := range chain[1:] {
        //                     b.AddUint24LengthPrefixed(func(b …) { b.AddBytes(cert.Raw) }) } }) } })
        let chains = self.verifiedChains.clone();
        b.AddUint24LengthPrefixed(|b: &mut cryptobyte::Builder| {
            for (_, chain) in crate::range!(chains.clone()) {
                let chain2 = chain.clone();
                b.AddUint24LengthPrefixed(|b: &mut cryptobyte::Builder| {
                    if chain2.Len() == 0 {
                        b.SetError(crate::errors::New(
                            "tls: internal error: empty verified chain",
                        ));
                        return;
                    }
                    let rest = chain2.slice(1, chain2.Len());
                    for (_, cert) in crate::range!(rest.clone()) {
                        let raw = cert.Raw.clone();
                        b.AddUint24LengthPrefixed(|b: &mut cryptobyte::Builder| {
                            b.AddBytes(&raw);
                        });
                    }
                });
            }
        });
        // Go: if s.EarlyData {
        //         b.AddUint8LengthPrefixed(func(b …) { b.AddBytes([]byte(s.alpnProtocol)) }) }
        if self.EarlyData {
            let alpn = self.alpnProtocol.clone();
            b.AddUint8LengthPrefixed(|b: &mut cryptobyte::Builder| {
                b.AddBytes(&slice::__from_vec(alpn.as_bytes().to_vec()));
            });
        }
        // Go: if s.version >= VersionTLS13 {
        //         if s.isClient { addUint64(&b, s.useBy); b.AddUint32(s.ageAdd) }
        //     } else {
        //         b.AddUint16(uint16(s.curveID))
        //     }
        if self.version >= VersionTLS13 {
            if self.isClient {
                addUint64(&mut b, self.useBy);
                b.AddUint32(self.ageAdd);
            }
        } else {
            b.AddUint16(self.curveID.0);
        }
        // Go: return b.Bytes()
        return b.Bytes();
    }
}

// go: sdk 1.25.5 crypto/tls/ticket.go:238-347 ParseSessionState
/// Go: "ParseSessionState parses a [SessionState] encoded by
/// [SessionState.Bytes]."
pub fn ParseSessionState(data: slice<byte>) -> (SessionState, error) {
    // Go: ss := &SessionState{}
    //     s := cryptobyte.String(data)
    let mut ss = SessionState::default();
    let mut s = CBString::New(data);
    let mut typ: uint8 = 0;
    let mut extMasterSecret: uint8 = 0;
    let mut earlyData: uint8 = 0;
    let mut cert = Certificate::default();
    let mut extra = CBString::New(slice::new());
    // Go: if !s.ReadUint16(&ss.version) || !s.ReadUint8(&typ) ||
    //        !s.ReadUint16(&ss.cipherSuite) || !readUint64(&s, &ss.createdAt) ||
    //        !readUint8LengthPrefixed(&s, &ss.secret) ||
    //        !s.ReadUint24LengthPrefixed(&extra) ||
    //        !s.ReadUint8(&extMasterSecret) || !s.ReadUint8(&earlyData) ||
    //        len(ss.secret) == 0 || !unmarshalCertificate(&s, &cert) {
    //         return nil, errors.New("tls: invalid session encoding") }
    if !s.ReadUint16(&mut ss.version)
        || !s.ReadUint8(&mut typ)
        || !s.ReadUint16(&mut ss.cipherSuite)
        || !readUint64(&mut s, &mut ss.createdAt)
        || !readUint8LengthPrefixed(&mut s, &mut ss.secret)
        || !s.ReadUint24LengthPrefixed(&mut extra)
        || !s.ReadUint8(&mut extMasterSecret)
        || !s.ReadUint8(&mut earlyData)
        || ss.secret.Len() == 0
        || !unmarshalCertificate(&mut s, &mut cert)
    {
        return (
            SessionState::default(),
            crate::errors::New("tls: invalid session encoding"),
        );
    }
    // Go: for !extra.Empty() {
    //         var e []byte
    //         if !readUint24LengthPrefixed(&extra, &e) { return nil, errors.New(…) }
    //         ss.Extra = append(ss.Extra, e) }
    let mut extras: Vec<slice<byte>> = Vec::new();
    while !extra.Empty() {
        let mut e: slice<byte> = slice::new();
        if !readUint24LengthPrefixed(&mut extra, &mut e) {
            return (
                SessionState::default(),
                crate::errors::New("tls: invalid session encoding"),
            );
        }
        extras.push(e);
    }
    ss.Extra = slice::__from_vec(extras);
    // Go: switch typ { case 1: ss.isClient = false; case 2: ss.isClient = true
    //     default: return nil, errors.New("tls: unknown session encoding") }
    if typ == 1 {
        ss.isClient = false;
    } else if typ == 2 {
        ss.isClient = true;
    } else {
        return (
            SessionState::default(),
            crate::errors::New("tls: unknown session encoding"),
        );
    }
    // Go: switch extMasterSecret { case 0: false; case 1: true
    //     default: return nil, errors.New("tls: invalid session encoding") }
    if extMasterSecret == 0 {
        ss.extMasterSecret = false;
    } else if extMasterSecret == 1 {
        ss.extMasterSecret = true;
    } else {
        return (
            SessionState::default(),
            crate::errors::New("tls: invalid session encoding"),
        );
    }
    // Go: switch earlyData { case 0: false; case 1: true
    //     default: return nil, errors.New("tls: invalid session encoding") }
    if earlyData == 0 {
        ss.EarlyData = false;
    } else if earlyData == 1 {
        ss.EarlyData = true;
    } else {
        return (
            SessionState::default(),
            crate::errors::New("tls: invalid session encoding"),
        );
    }
    // Go: for _, cert := range cert.Certificate {
    //         c, err := globalCertCache.newCert(cert)
    //         if err != nil { return nil, err }
    //         ss.peerCertificates = append(ss.peerCertificates, c) }
    //
    // See the banner: goish parses directly, without the weak-pointer
    // cache Go memoises through.
    let mut peers: Vec<x509::Certificate> = Vec::new();
    for (_, der) in crate::range!(cert.Certificate.clone()) {
        let (c, err) = x509::ParseCertificate(der.clone());
        if err != crate::errors::nil {
            return (SessionState::default(), err);
        }
        peers.push(c);
    }
    ss.peerCertificates = slice::__from_vec(peers);
    // Go: if ss.isClient && len(ss.peerCertificates) == 0 {
    //         return nil, errors.New("tls: no server certificates in client session") }
    if ss.isClient && ss.peerCertificates.Len() == 0 {
        return (
            SessionState::default(),
            crate::errors::New("tls: no server certificates in client session"),
        );
    }
    // Go: ss.ocspResponse = cert.OCSPStaple; ss.scts = cert.SignedCertificateTimestamps
    ss.ocspResponse = cert.OCSPStaple.clone();
    ss.scts = cert.SignedCertificateTimestamps.clone();
    // Go: var chainList cryptobyte.String
    //     if !s.ReadUint24LengthPrefixed(&chainList) { return nil, errors.New(…) }
    let mut chainList = CBString::New(slice::new());
    if !s.ReadUint24LengthPrefixed(&mut chainList) {
        return (
            SessionState::default(),
            crate::errors::New("tls: invalid session encoding"),
        );
    }
    // Go: for !chainList.Empty() { … }
    let mut chains: Vec<slice<x509::Certificate>> = Vec::new();
    while !chainList.Empty() {
        let mut certList = CBString::New(slice::new());
        if !chainList.ReadUint24LengthPrefixed(&mut certList) {
            return (
                SessionState::default(),
                crate::errors::New("tls: invalid session encoding"),
            );
        }
        if ss.peerCertificates.Len() == 0 {
            return (
                SessionState::default(),
                crate::errors::New("tls: invalid session encoding"),
            );
        }
        // Go: chain = append(chain, ss.peerCertificates[0])
        let mut chain: Vec<x509::Certificate> = Vec::new();
        chain.push(ss.peerCertificates[0].clone());
        while !certList.Empty() {
            let mut der: slice<byte> = slice::new();
            if !readUint24LengthPrefixed(&mut certList, &mut der) {
                return (
                    SessionState::default(),
                    crate::errors::New("tls: invalid session encoding"),
                );
            }
            let (c, err) = x509::ParseCertificate(der);
            if err != crate::errors::nil {
                return (SessionState::default(), err);
            }
            chain.push(c);
        }
        chains.push(slice::__from_vec(chain));
    }
    ss.verifiedChains = slice::__from_vec(chains);
    // Go: if ss.EarlyData {
    //         var alpn []byte
    //         if !readUint8LengthPrefixed(&s, &alpn) { return nil, errors.New(…) }
    //         ss.alpnProtocol = string(alpn) }
    if ss.EarlyData {
        let mut alpn: slice<byte> = slice::new();
        if !readUint8LengthPrefixed(&mut s, &mut alpn) {
            return (
                SessionState::default(),
                crate::errors::New("tls: invalid session encoding"),
            );
        }
        ss.alpnProtocol = string::from_bytes(&alpn);
    }
    // Go: if ss.version >= VersionTLS13 {
    //         if ss.isClient {
    //             if !s.ReadUint64(&ss.useBy) || !s.ReadUint32(&ss.ageAdd) {
    //                 return nil, errors.New(…) } }
    //     } else {
    //         if !s.ReadUint16((*uint16)(&ss.curveID)) { return nil, errors.New(…) }
    //     }
    if ss.version >= VersionTLS13 {
        if ss.isClient {
            if !s.ReadUint64(&mut ss.useBy) || !s.ReadUint32(&mut ss.ageAdd) {
                return (
                    SessionState::default(),
                    crate::errors::New("tls: invalid session encoding"),
                );
            }
        }
    } else {
        let mut cid: uint16 = 0;
        if !s.ReadUint16(&mut cid) {
            return (
                SessionState::default(),
                crate::errors::New("tls: invalid session encoding"),
            );
        }
        ss.curveID = CurveID(cid);
    }
    // Go: return ss, nil
    return (ss, crate::errors::nil);
}

// go: none — goish-only: Go's tests are in-package and touch
// SessionState's unexported fields directly. goish examples are external
// crates, so the fields need named accessors. Nothing in the port uses
// them.
impl SessionState {
    // go: none — goish-only: see above.
    #[doc(hidden)]
    pub fn __setVersion(&mut self, v: uint16) { self.version = v; }
    // go: none — goish-only: see above.
    #[doc(hidden)]
    pub fn __setCipherSuite(&mut self, v: uint16) { self.cipherSuite = v; }
    // go: none — goish-only: see above.
    #[doc(hidden)]
    pub fn __setCreatedAt(&mut self, v: uint64) { self.createdAt = v; }
    // go: none — goish-only: see above.
    #[doc(hidden)]
    pub fn __setSecret(&mut self, v: slice<byte>) { self.secret = v; }
    // go: none — goish-only: `SessionState.ticket` is unexported in Go,
    // where the tests are in-package.
    #[doc(hidden)]
    pub fn __setTicket(&mut self, v: slice<byte>) { self.ticket = v; }
    // go: none — goish-only: see above.
    #[doc(hidden)]
    pub fn __setExtMasterSecret(&mut self, v: bool) { self.extMasterSecret = v; }
    // go: none — goish-only: see above.
    #[doc(hidden)]
    pub fn __setAlpnProtocol(&mut self, v: string) { self.alpnProtocol = v; }
    // go: none — goish-only: see above.
    #[doc(hidden)]
    pub fn __setCurveID(&mut self, v: CurveID) { self.curveID = v; }
    // go: none — goish-only: see above.
    #[doc(hidden)]
    pub fn __version(&self) -> uint16 { return self.version; }

    // go: none — goish-only: see `__setVersion`.
    #[doc(hidden)]
    pub fn __peerCertificates(&self) -> slice<x509::Certificate> {
        return self.peerCertificates.clone();
    }
    // go: none — goish-only: see `__setVersion`.
    #[doc(hidden)]
    pub fn __verifiedChains(&self) -> slice<slice<x509::Certificate>> {
        return self.verifiedChains.clone();
    }
    // go: none — goish-only: see `__setVersion`.
    #[doc(hidden)]
    pub fn __ocspResponse(&self) -> slice<byte> { return self.ocspResponse.clone(); }
    // go: none — goish-only: see `__setVersion`.
    #[doc(hidden)]
    pub fn __scts(&self) -> slice<slice<byte>> { return self.scts.clone(); }

    // go: none — goish-only: see above.
    #[doc(hidden)]
    pub fn __cipherSuite(&self) -> uint16 { return self.cipherSuite; }
    // go: none — goish-only: see above.
    #[doc(hidden)]
    pub fn __createdAt(&self) -> uint64 { return self.createdAt; }
    // go: none — goish-only: see above.
    #[doc(hidden)]
    pub fn __secret(&self) -> slice<byte> { return self.secret.clone(); }
    // go: none — goish-only: `SessionState.ticket` is unexported in Go.
    #[doc(hidden)]
    pub fn __ticket(&self) -> slice<byte> { return self.ticket.clone(); }
    // go: none — goish-only: see above.
    #[doc(hidden)]
    pub fn __extMasterSecret(&self) -> bool { return self.extMasterSecret; }
    // go: none — goish-only: see above.
    #[doc(hidden)]
    pub fn __alpnProtocol(&self) -> string { return self.alpnProtocol.clone(); }
    // go: none — goish-only: see above.
    #[doc(hidden)]
    pub fn __curveID(&self) -> CurveID { return self.curveID; }
    // go: none — goish-only: `SessionState.isClient` is unexported in
    // Go, where the tests are in-package.
    #[doc(hidden)]
    pub fn __isClientFlag(&self) -> bool { return self.isClient; }
}


// ─── ClientSessionState ───────────────────────────────────────────────

// Go: ticket.go:349-351
//   type ClientSessionState struct { session *SessionState }
/// Go: "ClientSessionState contains the state needed by a client to
/// resume a previous TLS session."
#[derive(Clone, Default)]
pub struct ClientSessionState {
    pub(crate) session: Option<SessionState>,
}

impl ClientSessionState {
    // go: none — goish-only: Go writes the composite literal
    // `&ClientSessionState{session: session}` in-package; `session` is
    // unexported, so sibling modules need a constructor.
    #[doc(hidden)]
    pub fn __of(session: SessionState) -> ClientSessionState {
        return ClientSessionState { session: Some(session) };
    }

    // go: none — goish-only: see `__of`.
    #[doc(hidden)]
    pub fn __session(&self) -> Option<SessionState> {
        return self.session.clone();
    }

    // go: sdk 1.25.5 crypto/tls/ticket.go:355-360 ClientSessionState.ResumptionState
    /// Go: "ResumptionState returns the session ticket sent by the
    /// server (also known as the session's identity) and the state
    /// necessary to resume this session. It can be called by
    /// [Config.UnwrapSession] to serialize a resumable session."
    ///
    /// Deviation: Go's nil receiver and nil `cs.session` both yield
    /// `(nil, nil, nil)`. goish has no nil receiver; a zero
    /// ClientSessionState has `session == None`, which is the same
    /// state, and the second result becomes an `Option`.
    pub fn ResumptionState(&self) -> (slice<byte>, Option<SessionState>, error) {
        // Go: if cs == nil || cs.session == nil { return nil, nil, nil }
        if self.session.is_none() {
            return (slice::new(), None, crate::errors::nil);
        }
        // Go: return cs.session.ticket, cs.session, nil
        let s = self.session.clone().unwrap();
        return (s.ticket.clone(), Some(s), crate::errors::nil);
    }
}

// go: sdk 1.25.5 crypto/tls/ticket.go:364-371 NewResumptionState
/// Go: "NewResumptionState returns a state value that can be returned by
/// [Config.UnwrapSession] to resume a previous session. state needs to
/// be returned by [ParseSessionState], and the ticket and session state
/// must have been returned by [ClientSessionState.ResumptionState]."
pub fn NewResumptionState(
    ticket: slice<byte>,
    state: SessionState,
) -> (ClientSessionState, error) {
    // Go: state.ticket = ticket
    //     return &ClientSessionState{session: state}, nil
    let mut state = state;
    state.ticket = ticket;
    return (
        ClientSessionState {
            session: Some(state),
        },
        crate::errors::nil,
    );
}


// ─── Session ticket sealing ───────────────────────────────────────────

use super::common::ticketKey;
use super::Config;
use crate::crypto::aes;
use crate::crypto::cipher;
use crate::crypto::hmac;
use crate::crypto::sha256;
use crate::crypto::subtle;
use crate::types::int;

impl Config {
    // go: sdk 1.25.5 crypto/tls/ticket.go:185-192 Config.EncryptTicket
    /// Go: "EncryptTicket encrypts a ticket with the [Config]'s
    /// configured (or default) session ticket keys. It can be used as a
    /// [Config.WrapSession] implementation."
    ///
    /// Deviation: `&mut self`, because `ticketKeys` may rotate the
    /// auto-managed key set. Go hides that behind a mutex.
    pub fn EncryptTicket(
        &mut self,
        _cs: super::common::ConnectionState,
        ss: &SessionState,
    ) -> (slice<byte>, error) {
        // Go: ticketKeys := c.ticketKeys(nil)
        //     stateBytes, err := ss.Bytes()
        //     if err != nil { return nil, err }
        //     return c.encryptTicket(stateBytes, ticketKeys)
        let ticketKeys = self.ticketKeys(None);
        let (stateBytes, err) = ss.Bytes();
        if err != crate::errors::nil {
            return (slice::new(), err);
        }
        return self.encryptTicket(stateBytes, ticketKeys);
    }

    // go: sdk 1.25.5 crypto/tls/ticket.go:194-221 Config.encryptTicket
    pub(crate) fn encryptTicket(
        &self,
        state: slice<byte>,
        ticketKeys: slice<ticketKey>,
    ) -> (slice<byte>, error) {
        // Go: if len(ticketKeys) == 0 {
        //         return nil, errors.New("tls: internal error: session ticket keys unavailable") }
        if ticketKeys.Len() == 0 {
            return (
                slice::new(),
                crate::errors::New("tls: internal error: session ticket keys unavailable"),
            );
        }

        // Go: encrypted := make([]byte, aes.BlockSize+len(state)+sha256.Size)
        //     iv := encrypted[:aes.BlockSize]
        //     ciphertext := encrypted[aes.BlockSize : len(encrypted)-sha256.Size]
        //     authenticated := encrypted[:len(encrypted)-sha256.Size]
        //     macBytes := encrypted[len(encrypted)-sha256.Size:]
        //
        // Go carves four aliasing views of one array; goish slices do
        // not share backing, so the pieces are built and concatenated in
        // the same order instead.
        let blockSize = aes::BlockSize;
        let macSize = sha256::Size;

        // Go: if _, err := io.ReadFull(c.rand(), iv); err != nil { return nil, err }
        let mut iv: slice<byte> = slice::__from_vec(alloc::vec![0u8; blockSize as usize]);
        let mut r = self.rand();
        let (_, err) = crate::io::ReadFull(&mut *r, &mut iv);
        if err != crate::errors::nil {
            return (slice::new(), err);
        }
        // Go: key := ticketKeys[0]
        //     block, err := aes.NewCipher(key.aesKey[:])
        //     if err != nil { return nil, errors.New(
        //         "tls: failed to create cipher while encrypting ticket: " + err.Error()) }
        let key = ticketKeys[0].clone();
        let (block, err) = aes::NewCipher(slice::__from_vec(key.aesKey.to_vec()));
        if err != crate::errors::nil {
            return (
                slice::new(),
                crate::errors::New(
                    string::from("tls: failed to create cipher while encrypting ticket: ")
                        + err.Error(),
                ),
            );
        }
        // Go: cipher.NewCTR(block, iv).XORKeyStream(ciphertext, state)
        let mut ctr = cipher::NewCTR(block.unwrap(), iv.clone());
        let mut ciphertext: slice<byte> =
            slice::__from_vec(alloc::vec![0u8; state.Len() as usize]);
        crate::crypto::cipher::Stream::XORKeyStream(&mut ctr, &mut ciphertext, state);

        // Go: mac := hmac.New(sha256.New, key.hmacKey[:])
        //     mac.Write(authenticated)
        //     mac.Sum(macBytes[:0])
        let mut authenticated: Vec<byte> = Vec::new();
        let ivRaw: &[byte] = &iv;
        let ctRaw: &[byte] = &ciphertext;
        authenticated.extend_from_slice(ivRaw);
        authenticated.extend_from_slice(ctRaw);
        let mut mac = hmac::New(
            sha256::NewHash as fn() -> alloc::boxed::Box<dyn crate::hash::Hash + Send + Sync>,
            slice::__from_vec(key.hmacKey.to_vec()),
        );
        let _ = crate::io::Writer::Write(&mut mac, slice::__from_vec(authenticated.clone()));
        let macBytes = crate::hash::Hash::Sum(&mac, slice::new());

        // Go: return encrypted, nil
        let mut encrypted = authenticated;
        let mRaw: &[byte] = &macBytes;
        encrypted.extend_from_slice(mRaw);
        let _ = macSize;
        return (slice::__from_vec(encrypted), crate::errors::nil);
    }

    // go: sdk 1.25.5 crypto/tls/ticket.go:223-236 Config.DecryptTicket
    /// Go: "DecryptTicket decrypts a ticket encrypted by
    /// [Config.EncryptTicket]. It can be used as a
    /// [Config.UnwrapSession] implementation. If the ticket can't be
    /// decrypted or parsed, DecryptTicket returns (nil, nil)."
    pub fn DecryptTicket(
        &mut self,
        identity: slice<byte>,
        _cs: super::common::ConnectionState,
    ) -> (Option<SessionState>, error) {
        // Go: ticketKeys := c.ticketKeys(nil)
        //     stateBytes := c.decryptTicket(identity, ticketKeys)
        //     if stateBytes == nil { return nil, nil }
        let ticketKeys = self.ticketKeys(None);
        let stateBytes = self.decryptTicket(identity, ticketKeys);
        if stateBytes.is_none() {
            return (None, crate::errors::nil);
        }
        // Go: s, err := ParseSessionState(stateBytes)
        //     if err != nil { return nil, nil } // drop unparsable tickets on the floor
        //     return s, nil
        let (s, err) = ParseSessionState(stateBytes.unwrap());
        if err != crate::errors::nil {
            return (None, crate::errors::nil);
        }
        return (Some(s), crate::errors::nil);
    }

    // go: sdk 1.25.5 crypto/tls/ticket.go:238-267 Config.decryptTicket
    ///
    /// Deviation: Go returns a nil `[]byte` both for "too short" and for
    /// "no key matched"; goish returns `None`, which is the same signal
    /// its one caller tests for.
    pub(crate) fn decryptTicket(
        &self,
        encrypted: slice<byte>,
        ticketKeys: slice<ticketKey>,
    ) -> Option<slice<byte>> {
        // Go: if len(encrypted) < aes.BlockSize+sha256.Size { return nil }
        let blockSize = aes::BlockSize;
        let macSize = sha256::Size;
        if encrypted.Len() < blockSize + macSize {
            return None;
        }

        // Go: iv := encrypted[:aes.BlockSize]
        //     ciphertext := encrypted[aes.BlockSize : len(encrypted)-sha256.Size]
        //     authenticated := encrypted[:len(encrypted)-sha256.Size]
        //     macBytes := encrypted[len(encrypted)-sha256.Size:]
        let n = encrypted.Len();
        let iv = encrypted.slice(0, blockSize);
        let ciphertext = encrypted.slice(blockSize, n - macSize);
        let authenticated = encrypted.slice(0, n - macSize);
        let macBytes = encrypted.slice(n - macSize, n);

        // Go: for _, key := range ticketKeys {
        //         mac := hmac.New(sha256.New, key.hmacKey[:])
        //         mac.Write(authenticated)
        //         expected := mac.Sum(nil)
        //         if subtle.ConstantTimeCompare(macBytes, expected) != 1 { continue }
        //         block, err := aes.NewCipher(key.aesKey[:])
        //         if err != nil { return nil }
        //         plaintext := make([]byte, len(ciphertext))
        //         cipher.NewCTR(block, iv).XORKeyStream(plaintext, ciphertext)
        //         return plaintext }
        for (_, key) in crate::range!(ticketKeys) {
            let mut mac = hmac::New(
                sha256::NewHash as fn() -> alloc::boxed::Box<dyn crate::hash::Hash + Send + Sync>,
                slice::__from_vec(key.hmacKey.to_vec()),
            );
            let _ = crate::io::Writer::Write(&mut mac, authenticated.clone());
            let expected = crate::hash::Hash::Sum(&mac, slice::new());

            if subtle::ConstantTimeCompare(&macBytes, &expected) != 1 {
                continue;
            }

            let (block, err) = aes::NewCipher(slice::__from_vec(key.aesKey.to_vec()));
            if err != crate::errors::nil {
                return None;
            }
            let mut plaintext: slice<byte> =
                slice::__from_vec(alloc::vec![0u8; ciphertext.Len() as usize]);
            let mut ctr = cipher::NewCTR(block.unwrap(), iv.clone());
            crate::crypto::cipher::Stream::XORKeyStream(
                &mut ctr,
                &mut plaintext,
                ciphertext.clone(),
            );

            return Some(plaintext);
        }

        // Go: return nil
        return None;
    }
}

use super::conn::Conn;

impl Conn {
    // go: sdk 1.25.5 crypto/tls/ticket.go:298-312 Conn.sessionState
    /// Go: snapshot the connection's resumable state into a
    /// `SessionState`. The fields a ticket also needs — `secret`,
    /// `useBy`, `ageAdd`, `ticket` — are filled in by the caller.
    pub(crate) fn sessionState(&self) -> SessionState {
        // Go: return &SessionState{version: c.vers, cipherSuite: c.cipherSuite,
        //     createdAt: uint64(c.config.time().Unix()), alpnProtocol: c.clientProtocol,
        //     peerCertificates: c.peerCertificates, ocspResponse: c.ocspResponse,
        //     scts: c.scts, isClient: c.isClient, extMasterSecret: c.extMasterSecret,
        //     verifiedChains: c.verifiedChains, curveID: c.curveID}
        return SessionState {
            version: self.vers,
            cipherSuite: self.cipherSuite,
            createdAt: crate::uint64(self.config.time().Unix()),
            alpnProtocol: self.clientProtocol.clone(),
            peerCertificates: self.peerCertificates.clone(),
            ocspResponse: self.ocspResponse.clone(),
            scts: self.scts.clone(),
            isClient: self.isClient,
            extMasterSecret: self.extMasterSecret,
            verifiedChains: self.verifiedChains.clone(),
            curveID: self.curveID,
            ..SessionState::default()
        };
    }
}
