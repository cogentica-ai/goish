// go: file crypto/tls/quic.go decls: QUICEncryptionLevel.String
//
// crypto/tls — the QUIC transport interface (RFC 9001).
//
// **Partial port.** quic.go is 500 lines. What is here is the public
// enumeration surface, which depends on nothing. `QUICConn` and its
// event loop drive the handshake state machine through a side channel
// instead of a net.Conn, so they land with conn[go]. goish ships no
// QUIC, so nothing here is reachable from a handshake.
//
// goishlint:ignore GOISH018 QUICClient, QUICServer, newQUICConn, Start, NextEvent, Close, HandleData, SendSessionTicket, StoreSession, SetTransportParameters, ConnectionState, quicError, quicReadHandshakeBytes, quicSetReadSecret, quicSetWriteSecret, quicWriteCryptoData, quicSetTransportParameters, quicGetTransportParameters, quicWaitForSignal, quicSignal, quicNextEvent, quicHandshakeComplete, quicResumeSession, quicSetSessionTicket, quicSendSessionTicket, quicRejectedEarlyData, quicWaitForSignalOrError, quicStoreSession — the QUICConn event loop, which needs the handshake state machine; see the banner. ROADMAP.md.
// goishlint:ignore GOISH019 QUICConn, QUICConfig, QUICEvent, QUICSessionTicketOptions, quicState — same.
// goishlint:ignore GOISH021 QUICConn, QUICConfig, QUICEvent, QUICEventKind, QUICSessionTicketOptions, quicState, QUICNoEvent, QUICSetReadSecret, QUICSetWriteSecret, QUICWriteData, QUICTransportParameters, QUICTransportParametersRequired, QUICRejectedEarlyData, QUICHandshakeDone, QUICResumeSession, QUICStoreSession, errCallbackFailed, quicWaitingForData, quicWaitingForTransportParameters, quicClosed, quicRunning — same.

#![allow(non_snake_case, dead_code)]

use crate::gostring::string;
use crate::types::int;

// Go: quic.go:19
//   type QUICEncryptionLevel int
/// `tls.QUICEncryptionLevel` — the encryption level of a QUIC packet,
/// as reported to a QUIC transport by the TLS handshake.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct QUICEncryptionLevel(pub int);

// Go: quic.go:21-26 — `iota`-numbered, so the values are 0..3.
pub const QUICEncryptionLevelInitial: QUICEncryptionLevel = QUICEncryptionLevel(0);
pub const QUICEncryptionLevelEarly: QUICEncryptionLevel = QUICEncryptionLevel(1);
pub const QUICEncryptionLevelHandshake: QUICEncryptionLevel = QUICEncryptionLevel(2);
pub const QUICEncryptionLevelApplication: QUICEncryptionLevel = QUICEncryptionLevel(3);

impl QUICEncryptionLevel {
    // go: sdk 1.25.5 crypto/tls/quic.go:24-37 QUICEncryptionLevel.String
    /// Go: the level's name, or `QUICEncryptionLevel(N)` for an
    /// unrecognised value. Note the fallback uses `%v` on an `int`, so
    /// it prints in DECIMAL — unlike `VersionName`, whose fallback is
    /// `%04X`.
    pub fn String(&self) -> string {
        return match *self {
            QUICEncryptionLevelInitial => string::from_static("Initial"),
            QUICEncryptionLevelEarly => string::from_static("Early"),
            QUICEncryptionLevelHandshake => string::from_static("Handshake"),
            QUICEncryptionLevelApplication => string::from_static("Application"),
            // Go: fmt.Sprintf("QUICEncryptionLevel(%v)", int(l))
            _ => crate::fmt::Sprintf!("QUICEncryptionLevel(%v)", self.0),
        };
    }
}

// ── Waived: the QUICConn event loop and the Conn.quic hooks ──────────
//
// goish ships no QUIC transport: there is no `Conn.quic` field and no
// external QUIC stack to drive a `QUICConn`. Upstream, every one of the
// declarations below is reached ONLY through a `c.quic != nil` arm,
// which is dead on every TLS-over-TCP connection — the only kind goish
// makes. Each such arm in the ported handshake code is already carried
// as an explicit, documented deviation at its site (grep the tree for
// "goish ships no QUIC transport").
//
// These are WAIVED, not remaining work: porting them verbatim would add
// a `Conn.quic` field plus the `QUICConn` machinery (`quicWaitForSignal`
// blocks the handshake goroutine on a condition variable so an external
// QUIC caller can pump it) and would require re-editing ~15 verified
// functions to reinstate their dead arms — untestable code that could
// never execute without a QUIC transport this library does not provide.
// If goish grows a QUIC/HTTP-3 stack, quic.go ports as a unit alongside
// it and these waivers come out. `QUICEncryptionLevel.String` above is
// the one piece with no `c.quic` dependency, so it is ported, not waived.
//
// go: waived QUICClient — goish ships no QUIC transport; see the waiver banner.
// go: waived QUICServer — goish ships no QUIC transport; see the waiver banner.
// go: waived newQUICConn — goish ships no QUIC transport; see the waiver banner.
// go: waived quicError — goish ships no QUIC transport; see the waiver banner.
// go: waived QUICConn.Start — goish ships no QUIC transport; see the waiver banner.
// go: waived QUICConn.NextEvent — goish ships no QUIC transport; see the waiver banner.
// go: waived QUICConn.Close — goish ships no QUIC transport; see the waiver banner.
// go: waived QUICConn.HandleData — goish ships no QUIC transport; see the waiver banner.
// go: waived QUICConn.SendSessionTicket — goish ships no QUIC transport; see the waiver banner.
// go: waived QUICConn.StoreSession — goish ships no QUIC transport; see the waiver banner.
// go: waived QUICConn.ConnectionState — goish ships no QUIC transport; see the waiver banner.
// go: waived QUICConn.SetTransportParameters — goish ships no QUIC transport; see the waiver banner.
// go: waived Conn.quicReadHandshakeBytes — goish ships no QUIC transport; see the waiver banner.
// go: waived Conn.quicSetReadSecret — goish ships no QUIC transport; see the waiver banner.
// go: waived Conn.quicSetWriteSecret — goish ships no QUIC transport; see the waiver banner.
// go: waived Conn.quicWriteCryptoData — goish ships no QUIC transport; see the waiver banner.
// go: waived Conn.quicResumeSession — goish ships no QUIC transport; see the waiver banner.
// go: waived Conn.quicStoreSession — goish ships no QUIC transport; see the waiver banner.
// go: waived Conn.quicSetTransportParameters — goish ships no QUIC transport; see the waiver banner.
// go: waived Conn.quicGetTransportParameters — goish ships no QUIC transport; see the waiver banner.
// go: waived Conn.quicHandshakeComplete — goish ships no QUIC transport; see the waiver banner.
// go: waived Conn.quicRejectedEarlyData — goish ships no QUIC transport; see the waiver banner.
// go: waived Conn.quicWaitForSignal — goish ships no QUIC transport; see the waiver banner.
