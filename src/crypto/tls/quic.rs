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
    // go: sdk 1.25.5 crypto/tls/quic.go:28-41 QUICEncryptionLevel.String
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
