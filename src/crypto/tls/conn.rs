// go: file crypto/tls/conn.go decls: permanentError.Error, permanentError.Unwrap, permanentError.Timeout, permanentError.Temporary, halfConn.setErrorLocked, halfConn.prepareCipherSpec, halfConn.changeCipherSpec, halfConn.setTrafficSecret, halfConn.incSeq, halfConn.explicitNonceLen, extractPadding, roundUp, sliceForAppend, RecordHeaderError.Error
//
// crypto/tls — the record layer's cipher state.
//
// **Partial port.** conn.go is 1700 lines and most of it is `Conn`,
// which owns a `net.Conn` and drives the handshake; that lands with the
// state machines. What is here is `halfConn` — the per-direction cipher
// state — and the free functions the record codec needs, none of which
// touch a `Conn`.
//
// goishlint:ignore GOISH018 Read, SetReadDeadline, SetWriteDeadline, NetConn, decrypt, encrypt, newRecordHeaderError, readRecord, readChangeCipherSpec, readRecordOrCCS, retryReadRecord, readFromUntil, sendAlertLocked, sendAlert, maxPayloadSizeForWrite, flush, writeRecordLocked, writeHandshakeRecord, writeChangeCipherRecord, readHandshakeBytes, readHandshake, unmarshalHandshakeMessage, handleRenegotiation, handlePostHandshakeMessage, handleKeyUpdate, CloseWrite, closeNotify, HandshakeContext, handshakeContext, ConnectionState, connectionStateLocked, OCSPResponse, VerifyHostname, LocalAddr, RemoteAddr, SetDeadline, write, Write, Close, Handshake — Conn and the record read/write loop, which own a net.Conn. halfConn.decrypt and halfConn.encrypt are with them: both rewrite the record buffer in place, aliasing the payload they are decrypting, which needs the Conn-owned scratch buffers to port faithfully. See ROADMAP.md.
// goishlint:ignore GOISH019 Conn, atLeastReader — same.
// goishlint:ignore GOISH021 Conn, atLeastReader, outBufPool, errShutdown, errEarlyCloseWrite, maxUselessBytes, tcpMSSEstimate, recordSizeBoostThreshold, tlsunsafeekm — same; the last three are the dynamic record-sizing knobs and a godebug var, all of which belong to Conn.write.
//
// One deviation: `setErrorLocked` asserts `err.(net.Error)` in Go, to
// wrap a transient network error as permanent. goish's `net` exposes no
// `Error` interface to assert against, so that arm is unreachable and
// the error is stored as-is. `permanentError` is ported regardless —
// it is a declared type with four methods, and the wrap becomes live the
// moment `net.Error` does.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use super::alert::{alert, alertInternalError};
use super::cipher_suites::{aead, cipherSuiteTLS13, mutAEAD};
use super::common::{recordType, VersionTLS11, VersionTLS13};
use super::quic::QUICEncryptionLevel;
use crate::crypto::cipher;
use crate::crypto::rc4;
use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::gostring::string;
use crate::hash::Hash;
use crate::types::{byte, int, uint, uint16, uint8};

// Go: conn.go — `type permanentError struct { err net.Error }`
/// Go: "permanentError is a wrapper around net.Error that makes the
/// error permanent, i.e. non-temporary."
#[derive(Clone)]
pub(crate) struct permanentError {
    pub err: error,
}

impl permanentError {
    // go: sdk 1.25.5 crypto/tls/conn.go:130-130 permanentError.Error
    pub(crate) fn Error(&self) -> string {
        // Go: return e.err.Error()
        return self.err.Error();
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:131-131 permanentError.Unwrap
    pub(crate) fn Unwrap(&self) -> error {
        // Go: return e.err
        return self.err.clone();
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:132-132 permanentError.Timeout
    ///
    /// Deviation: Go forwards to `e.err.Timeout()` on the wrapped
    /// `net.Error`. goish has no `net.Error` interface to forward
    /// through, so this reports false until one exists.
    pub(crate) fn Timeout(&self) -> bool {
        // Go: return e.err.Timeout()
        return false;
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:133-133 permanentError.Temporary
    pub(crate) fn Temporary(&self) -> bool {
        // Go: return false
        return false;
    }
}

// go: none — goish idiom: Go satisfies `error` implicitly through
// `Error() string`, and `errors.Is`/`As` reach the wrapped error through
// an `Unwrap` assertion. goish's `ErrorTrait` carries both.
impl errors::ErrorTrait for permanentError {
    // go: none — goish idiom: forwards to the ported inherent `Error`.
    fn Error(&self) -> string {
        return permanentError::Error(self);
    }
    // go: none — goish idiom: forwards to the ported inherent `Unwrap`.
    fn Unwrap(&self) -> error {
        return permanentError::Unwrap(self);
    }
}

// Go: conn.go — `type cbcMode interface { cipher.BlockMode; SetIV([]byte) }`
/// Go: "cbcMode is an interface for block ciphers using cipher block
/// chaining."
pub(crate) trait cbcMode: cipher::BlockMode {
    fn SetIV(&mut self, iv: slice<byte>);
}

impl<B: cipher::Block + Send + Sync> cbcMode for cipher::CBCEncrypter<B> {
    // go: none — goish-only: Go satisfies `cbcMode` structurally from
    // the concrete CBC modes; goish spells the impl.
    fn SetIV(&mut self, iv: slice<byte>) {
        return cipher::CBCEncrypter::SetIV(self, iv);
    }
}

impl<B: cipher::Block + Send + Sync> cbcMode for cipher::CBCDecrypter<B> {
    // go: none — goish-only: see the encrypter above.
    fn SetIV(&mut self, iv: slice<byte>) {
        return cipher::CBCDecrypter::SetIV(self, iv);
    }
}

// go: none — goish-only: Go's `halfConn.cipher` is an `any` holding one
// of three interfaces, which `decrypt`/`encrypt` recover with a type
// switch. goish's `Any` cannot hand out the `&mut` a stream or block
// mode needs, so the closed set of three is a sum type. `None` is Go's
// nil, the pre-ChangeCipherSpec state.
pub(crate) enum halfConnCipher {
    None,
    Stream(rc4::Cipher),
    AEAD(Box<dyn aead + Send + Sync>),
    CBC(Box<dyn cbcMode + Send + Sync>),
}

// Go: conn.go:139-155
//   type halfConn struct { sync.Mutex; err error; version uint16
//                          cipher any; mac hash.Hash; seq [8]byte
//                          scratchBuf [13]byte
//                          nextCipher any; nextMac hash.Hash
//                          level QUICEncryptionLevel; trafficSecret []byte }
/// Go: "halfConn represents one direction of the record layer
/// connection, either sending or receiving."
pub(crate) struct halfConn {
    /// First permanent error.
    pub err: error,
    /// Protocol version.
    pub version: uint16,
    /// Cipher algorithm.
    pub cipher: halfConnCipher,
    pub mac: Option<Box<dyn Hash + Send + Sync>>,
    /// 64-bit sequence number.
    pub seq: [byte; 8],
    /// Go: "to avoid allocs; interface method args escape".
    pub scratchBuf: [byte; 13],
    /// Next encryption state.
    pub nextCipher: halfConnCipher,
    /// Next MAC algorithm.
    pub nextMac: Option<Box<dyn Hash + Send + Sync>>,
    /// Current QUIC encryption level.
    pub level: QUICEncryptionLevel,
    /// Current TLS 1.3 traffic secret.
    pub trafficSecret: slice<byte>,
}

impl Default for halfConn {
    // go: none — goish idiom: Go's zero value.
    fn default() -> Self {
        return halfConn {
            err: errors::nil,
            version: 0,
            cipher: halfConnCipher::None,
            mac: None,
            seq: [0u8; 8],
            scratchBuf: [0u8; 13],
            nextCipher: halfConnCipher::None,
            nextMac: None,
            level: QUICEncryptionLevel(0),
            trafficSecret: slice::new(),
        };
    }
}

impl halfConn {
    // go: sdk 1.25.5 crypto/tls/conn.go:157-164 halfConn.setErrorLocked
    ///
    /// Deviation: Go's `if e, ok := err.(net.Error); ok` arm is
    /// unreachable here — see the file banner.
    pub(crate) fn setErrorLocked(&mut self, err: error) -> error {
        // Go: if e, ok := err.(net.Error); ok { hc.err = &permanentError{err: e} }
        //     else { hc.err = err }
        self.err = err;
        // Go: return hc.err
        return self.err.clone();
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:168-172 halfConn.prepareCipherSpec
    /// Go: "sets the encryption and MAC states that a subsequent
    /// changeCipherSpec will use."
    pub(crate) fn prepareCipherSpec(
        &mut self,
        version: uint16,
        cipher: halfConnCipher,
        mac: Option<Box<dyn Hash + Send + Sync>>,
    ) {
        // Go: hc.version = version; hc.nextCipher = cipher; hc.nextMac = mac
        self.version = version;
        self.nextCipher = cipher;
        self.nextMac = mac;
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:176-188 halfConn.changeCipherSpec
    /// Go: "changes the encryption and MAC states to the ones previously
    /// passed to prepareCipherSpec."
    pub(crate) fn changeCipherSpec(&mut self) -> Option<alert> {
        // Go: if hc.nextCipher == nil || hc.version == VersionTLS13 {
        //         return alertInternalError }
        if matches!(self.nextCipher, halfConnCipher::None) || self.version == VersionTLS13 {
            return Some(alertInternalError);
        }
        // Go: hc.cipher = hc.nextCipher; hc.mac = hc.nextMac
        //     hc.nextCipher = nil; hc.nextMac = nil
        //     for i := range hc.seq { hc.seq[i] = 0 }
        self.cipher = core::mem::replace(&mut self.nextCipher, halfConnCipher::None);
        self.mac = self.nextMac.take();
        let mut i: usize = 0;
        while i < self.seq.len() {
            self.seq[i] = 0;
            i += 1;
        }
        // Go: return nil
        return None;
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:190-198 halfConn.setTrafficSecret
    pub(crate) fn setTrafficSecret(
        &mut self,
        suite: &'static cipherSuiteTLS13,
        level: QUICEncryptionLevel,
        secret: slice<byte>,
    ) {
        // Go: hc.trafficSecret = secret; hc.level = level
        //     key, iv := suite.trafficKey(secret)
        //     hc.cipher = suite.aead(key, iv)
        //     for i := range hc.seq { hc.seq[i] = 0 }
        self.trafficSecret = secret.clone();
        self.level = level;
        let (key, iv) = suite.trafficKey(secret);
        self.cipher = halfConnCipher::AEAD((suite.aead)(key, iv));
        let mut i: usize = 0;
        while i < self.seq.len() {
            self.seq[i] = 0;
            i += 1;
        }
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:201-212 halfConn.incSeq
    /// Increment the sequence number.
    pub(crate) fn incSeq(&mut self) {
        // Go: for i := 7; i >= 0; i-- { hc.seq[i]++; if hc.seq[i] != 0 { return } }
        let mut i: int = 7;
        while i >= 0 {
            self.seq[i as usize] = self.seq[i as usize].wrapping_add(1);
            if self.seq[i as usize] != 0 {
                return;
            }
            i -= 1;
        }

        // Go: Not allowed to let sequence number wrap. Instead, must
        // renegotiate before it does. Not likely enough to bother.
        panic!("TLS: sequence number wraparound");
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:217-236 halfConn.explicitNonceLen
    /// Go: "returns the number of bytes of explicit nonce or IV included
    /// in each record. Explicit nonces are present only in CBC modes
    /// after TLS 1.0 and in certain AEAD modes in TLS 1.2."
    pub(crate) fn explicitNonceLen(&self) -> int {
        // Go: if hc.cipher == nil { return 0 }
        // Go: switch c := hc.cipher.(type) {
        //     case cipher.Stream: return 0
        //     case aead: return c.explicitNonceLen()
        //     case cbcMode:
        //         // TLS 1.1 introduced a per-record explicit IV to fix the BEAST attack.
        //         if hc.version >= VersionTLS11 { return c.BlockSize() }
        //         return 0
        //     default: panic("unknown cipher type") }
        match &self.cipher {
            halfConnCipher::None => return 0,
            halfConnCipher::Stream(_) => return 0,
            halfConnCipher::AEAD(c) => return c.explicitNonceLen(),
            halfConnCipher::CBC(c) => {
                if self.version >= VersionTLS11 {
                    return c.BlockSize();
                }
                return 0;
            }
        };
    }
}

// go: sdk 1.25.5 crypto/tls/conn.go:241-286 extractPadding
/// Go: "extractPadding returns, in constant time, the length of the
/// padding to remove from the end of payload. It also returns a byte
/// which is equal to 255 if the padding was valid and 0 otherwise. See
/// RFC 2246, Section 6.2.3.2."
pub(crate) fn extractPadding(payload: slice<byte>) -> (int, byte) {
    // Go: if len(payload) < 1 { return 0, 0 }
    if payload.Len() < 1 {
        return (0, 0);
    }

    // Go: paddingLen := payload[len(payload)-1]
    //     t := uint(len(payload)-1) - uint(paddingLen)
    //     // if len(payload) >= (paddingLen - 1) then the MSB of t is zero
    //     good = byte(int32(^t) >> 31)
    let mut paddingLen = payload[(payload.Len() - 1) as usize];
    let t = crate::uint(payload.Len() - 1).wrapping_sub(crate::uint(paddingLen));
    let mut good: byte = crate::byte(crate::int32(!t) >> 31);

    // Go: toCheck := 256 // The maximum possible padding length plus the
    //     actual length field
    //     // The length of the padded data is public, so we can use an if here
    //     if toCheck > len(payload) { toCheck = len(payload) }
    let mut toCheck: int = 256;
    if toCheck > payload.Len() {
        toCheck = payload.Len();
    }

    // Go: for i := 0; i < toCheck; i++ {
    //         t := uint(paddingLen) - uint(i)
    //         // if i <= paddingLen then the MSB of t is zero
    //         mask := byte(int32(^t) >> 31)
    //         b := payload[len(payload)-1-i]
    //         good &^= mask&paddingLen ^ mask&b
    //     }
    let mut i: int = 0;
    while i < toCheck {
        let t = crate::uint(paddingLen).wrapping_sub(crate::uint(i));
        let mask: byte = crate::byte(crate::int32(!t) >> 31);
        let b = payload[(payload.Len() - 1 - i) as usize];
        good &= !((mask & paddingLen) ^ (mask & b));
        i += 1;
    }

    // Go: We AND together the bits of good and replicate the result
    // across all the bits.
    good &= good << 4;
    good &= good << 2;
    good &= good << 1;
    good = crate::byte(crate::int8(good) >> 7);

    // Go: Zero the padding length on error. This ensures any unchecked
    // bytes are included in the MAC. Otherwise, an attacker that could
    // distinguish MAC failures from padding failures could mount an
    // attack similar to POODLE in SSL 3.0: given a good ciphertext that
    // uses a full block's worth of padding, replace the final block with
    // another block. If the MAC check passed but the padding check
    // failed, the last byte of that block decrypted to the block size.
    //
    // See also macAndPaddingGood logic in decrypt.
    paddingLen &= good;

    // Go: toRemove = int(paddingLen) + 1; return
    return (crate::int(paddingLen) + 1, good);
}

// go: sdk 1.25.5 crypto/tls/conn.go:288-290 roundUp
pub(crate) fn roundUp(a: int, b: int) -> int {
    // Go: return a + (b-a%b)%b
    return a + (b - a % b) % b;
}

// go: sdk 1.25.5 crypto/tls/conn.go:928-937 sliceForAppend
/// Go: "sliceForAppend extends the input slice by n bytes. head is the
/// full extended slice, while tail is the appended part. If the original
/// slice has sufficient capacity no allocation is performed."
pub(crate) fn sliceForAppend(in_: slice<byte>, n: int) -> (slice<byte>, slice<byte>) {
    // Go: if total := len(in) + n; cap(in) >= total { head = in[:total] }
    //     else { head = make([]byte, total); copy(head, in) }
    //     tail = head[len(in):]
    let inLen = in_.Len();
    let total = inLen + n;
    let mut head: Vec<byte> = Vec::with_capacity(total as usize);
    let raw: &[byte] = &in_;
    head.extend_from_slice(raw);
    head.resize(total as usize, 0);
    let head = slice::__from_vec(head);
    let tail = head.slice(inLen, total);
    // Go: return
    return (head, tail);
}

// Go: conn.go — `type RecordHeaderError struct { Msg string
//     RecordHeader [5]byte; Conn net.Conn }`
/// Go: "RecordHeaderError is returned when a TLS record header is
/// invalid."
#[derive(Clone, Default)]
pub struct RecordHeaderError {
    /// Go: "Msg contains a human readable string that describes the
    /// error."
    pub Msg: string,
    /// Go: "RecordHeader contains the five bytes of TLS record header
    /// that triggered the error."
    pub RecordHeader: [byte; 5],
}

impl RecordHeaderError {
    // go: sdk 1.25.5 crypto/tls/conn.go:719-719 RecordHeaderError.Error
    pub fn Error(&self) -> string {
        // Go: return "tls: " + e.Msg
        return string::from("tls: ") + self.Msg.clone();
    }
}

// go: none — goish idiom: see `impl ErrorTrait for permanentError`.
impl errors::ErrorTrait for RecordHeaderError {
    // go: none — goish idiom: forwards to the ported inherent `Error`.
    fn Error(&self) -> string {
        return RecordHeaderError::Error(self);
    }
}
