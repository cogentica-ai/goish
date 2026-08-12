// go: file crypto/tls/conn.go decls: permanentError.Error, permanentError.Unwrap, permanentError.Timeout, permanentError.Temporary, halfConn.setErrorLocked, halfConn.prepareCipherSpec, halfConn.changeCipherSpec, halfConn.setTrafficSecret, halfConn.incSeq, halfConn.explicitNonceLen, extractPadding, roundUp, sliceForAppend, RecordHeaderError.Error, atLeastReader.Read, halfConn.decrypt, halfConn.encrypt
//
// crypto/tls — the record layer's cipher state.
//
// **Partial port.** conn.go is 1700 lines and most of it is `Conn`,
// which owns a `net.Conn` and drives the handshake; that lands with the
// state machines. What is here is the whole record codec — `halfConn`,
// its `decrypt`/`encrypt`, `atLeastReader` and the free functions they
// need — none of which touches a `Conn`.
//
// goishlint:ignore GOISH018 SetReadDeadline, SetWriteDeadline, NetConn, newRecordHeaderError, readRecord, readChangeCipherSpec, readRecordOrCCS, retryReadRecord, readFromUntil, sendAlertLocked, sendAlert, maxPayloadSizeForWrite, flush, writeRecordLocked, writeHandshakeRecord, writeChangeCipherRecord, readHandshakeBytes, readHandshake, unmarshalHandshakeMessage, handleRenegotiation, handlePostHandshakeMessage, handleKeyUpdate, CloseWrite, closeNotify, HandshakeContext, handshakeContext, ConnectionState, connectionStateLocked, OCSPResponse, VerifyHostname, LocalAddr, RemoteAddr, SetDeadline, write, Write, Close, Handshake — Conn and the record read/write loop, which own a net.Conn. See ROADMAP.md.
// goishlint:ignore GOISH019 Conn — same.
// goishlint:ignore GOISH021 Conn, outBufPool, errShutdown, errEarlyCloseWrite, maxUselessBytes, tcpMSSEstimate, recordSizeBoostThreshold, tlsunsafeekm — same; the last three are the dynamic record-sizing knobs and a godebug var, all of which belong to Conn.write.
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

use super::alert::{alert, alertBadRecordMAC, alertInternalError, alertRecordOverflow, alertUnexpectedMessage};
use super::cipher_suites::{aead, cipherSuiteTLS13, mutAEAD};
use super::common::{recordHeaderLen, recordType, VersionTLS11, VersionTLS13};
use super::quic::QUICEncryptionLevel;
use crate::crypto::cipher;
use crate::crypto::cipher::Stream as _;
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

// ─── The record codec ─────────────────────────────────────────────────
//
// Go works in place: `payload = payload[explicitNonceLen:]`,
// `c.CryptBlocks(payload, payload)`, `plaintext = payload[:n]` all alias
// one backing array, and `record[3]`/`record[4]` are rewritten through
// it. goish slices do not share backing across handles, so the two
// functions below carry an explicit offset into a single `Vec` instead
// of re-slicing. Same reads, same writes, same order.

// Go: conn.go — `type atLeastReader struct { R io.Reader; N int64 }`
/// Go: "atLeastReader reads from R, stopping with EOF once at least N
/// bytes have been read. It is different from an io.LimitedReader in
/// that it doesn't cut short the last call to Read, and in that it
/// considers an early EOF an error."
pub(crate) struct atLeastReader<'a> {
    pub R: &'a mut (dyn crate::io::Reader + Send + Sync + 'static),
    pub N: crate::types::int64,
}

impl<'a> crate::io::Reader for atLeastReader<'a> {
    // go: sdk 1.25.5 crypto/tls/conn.go:756-770 atLeastReader.Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // Go: if r.N <= 0 { return 0, io.EOF }
        if self.N <= 0 {
            return (0, crate::io::EOF.into());
        }
        // Go: n, err := r.R.Read(p)
        let (n, err) = self.R.Read(p);
        // Go: r.N -= int64(n) // won't underflow unless len(p) >= n > 9223372036854775809
        self.N -= crate::int64(n);
        // Go: if r.N > 0 && err == io.EOF { return n, io.ErrUnexpectedEOF }
        if self.N > 0 && err == crate::io::EOF {
            return (n, crate::io::ErrUnexpectedEOF.into());
        }
        // Go: if r.N <= 0 && err == nil { return n, io.EOF }
        if self.N <= 0 && err == errors::nil {
            return (n, crate::io::EOF.into());
        }
        // Go: return n, err
        return (n, err);
    }
}

impl halfConn {
    // go: sdk 1.25.5 crypto/tls/conn.go:301-406 halfConn.decrypt
    /// Go: "decrypt authenticates and decrypts the record if protection
    /// is active at this stage. The returned plaintext might overlap
    /// with the input."
    ///
    /// Deviation: Go rewrites `record[3]`/`record[4]` in place through
    /// the shared backing array, so the caller sees the corrected
    /// length. goish takes `record` by `&mut` for the same effect.
    pub(crate) fn decrypt(
        &mut self,
        record: &mut slice<byte>,
    ) -> (slice<byte>, recordType, Option<alert>) {
        // Go: var plaintext []byte
        //     typ := recordType(record[0])
        //     payload := record[recordHeaderLen:]
        let mut plaintext: slice<byte> = slice::new();
        let mut typ = recordType(record[0]);
        let mut payload = record.slice(recordHeaderLen, record.Len());

        // Go: In TLS 1.3, change_cipher_spec messages are to be ignored
        // without being decrypted. See RFC 8446, Appendix D.4.
        if self.version == VersionTLS13 && typ == super::common::recordTypeChangeCipherSpec {
            return (payload, typ, None);
        }

        // Go: paddingGood := byte(255); paddingLen := 0
        //     explicitNonceLen := hc.explicitNonceLen()
        let mut paddingGood: byte = 255;
        let mut paddingLen: int = 0;
        let explicitNonceLen = self.explicitNonceLen();

        // Go: if hc.cipher != nil { switch c := hc.cipher.(type) { … } }
        //     else { plaintext = payload }
        if !matches!(self.cipher, halfConnCipher::None) {
            match &mut self.cipher {
                halfConnCipher::Stream(c) => {
                    // Go: c.XORKeyStream(payload, payload)
                    let mut buf = payload.clone();
                    c.XORKeyStream(&mut buf, payload.clone());
                    payload = buf;
                }
                halfConnCipher::AEAD(c) => {
                    // Go: if len(payload) < explicitNonceLen { return nil, 0, alertBadRecordMAC }
                    if payload.Len() < explicitNonceLen {
                        return (slice::new(), recordType(0), Some(alertBadRecordMAC));
                    }
                    // Go: nonce := payload[:explicitNonceLen]
                    //     if len(nonce) == 0 { nonce = hc.seq[:] }
                    //     payload = payload[explicitNonceLen:]
                    let mut nonce = payload.slice(0, explicitNonceLen);
                    if nonce.Len() == 0 {
                        nonce = slice::__from_vec(self.seq.to_vec());
                    }
                    payload = payload.slice(explicitNonceLen, payload.Len());

                    // Go: var additionalData []byte
                    //     if hc.version == VersionTLS13 {
                    //         additionalData = record[:recordHeaderLen]
                    //     } else {
                    //         additionalData = append(hc.scratchBuf[:0], hc.seq[:]...)
                    //         additionalData = append(additionalData, record[:3]...)
                    //         n := len(payload) - c.Overhead()
                    //         additionalData = append(additionalData, byte(n>>8), byte(n))
                    //     }
                    let additionalData: slice<byte>;
                    if self.version == VersionTLS13 {
                        additionalData = record.slice(0, recordHeaderLen);
                    } else {
                        let mut ad: Vec<byte> = Vec::new();
                        ad.extend_from_slice(&self.seq);
                        let rec3 = record.slice(0, 3);
                        let raw: &[byte] = &rec3;
                        ad.extend_from_slice(raw);
                        let n = payload.Len() - c.Overhead();
                        ad.push(crate::byte(n >> 8));
                        ad.push(crate::byte(n));
                        additionalData = slice::__from_vec(ad);
                    }

                    // Go: plaintext, err = c.Open(payload[:0], nonce, payload, additionalData)
                    //     if err != nil { return nil, 0, alertBadRecordMAC }
                    let (out, err) =
                        c.Open(slice::new(), nonce, payload.clone(), additionalData);
                    if err != errors::nil {
                        return (slice::new(), recordType(0), Some(alertBadRecordMAC));
                    }
                    plaintext = out;
                }
                halfConnCipher::CBC(c) => {
                    // Go: blockSize := c.BlockSize()
                    //     minPayload := explicitNonceLen + roundUp(hc.mac.Size()+1, blockSize)
                    //     if len(payload)%blockSize != 0 || len(payload) < minPayload {
                    //         return nil, 0, alertBadRecordMAC }
                    let blockSize = c.BlockSize();
                    let macSize = match &self.mac {
                        Some(m) => m.Size(),
                        None => 0,
                    };
                    let minPayload = explicitNonceLen + roundUp(macSize + 1, blockSize);
                    if payload.Len() % blockSize != 0 || payload.Len() < minPayload {
                        return (slice::new(), recordType(0), Some(alertBadRecordMAC));
                    }

                    // Go: if explicitNonceLen > 0 {
                    //         c.SetIV(payload[:explicitNonceLen])
                    //         payload = payload[explicitNonceLen:] }
                    //     c.CryptBlocks(payload, payload)
                    if explicitNonceLen > 0 {
                        c.SetIV(payload.slice(0, explicitNonceLen));
                        payload = payload.slice(explicitNonceLen, payload.Len());
                    }
                    let mut buf = payload.clone();
                    c.CryptBlocks(&mut buf, payload.clone());
                    payload = buf;

                    // Go: In a limited attempt to protect against CBC padding
                    // oracles like Lucky13, the data past paddingLen (which is
                    // secret) is passed to the MAC function as extra data, to be
                    // fed into the HMAC after computing the digest. This makes
                    // the MAC roughly constant time as long as the digest
                    // computation is constant time and does not affect the
                    // subsequent write, modulo cache effects.
                    // Go: paddingLen, paddingGood = extractPadding(payload)
                    let (pl, pg) = extractPadding(payload.clone());
                    paddingLen = pl;
                    paddingGood = pg;
                }
                halfConnCipher::None => {}
            }

            // Go: if hc.version == VersionTLS13 {
            //         if typ != recordTypeApplicationData { return nil, 0, alertUnexpectedMessage }
            //         if len(plaintext) > maxPlaintext+1 { return nil, 0, alertRecordOverflow }
            //         // Remove padding and find the ContentType scanning from the end.
            //         for i := len(plaintext) - 1; i >= 0; i-- {
            //             if plaintext[i] != 0 { typ = recordType(plaintext[i]);
            //                                    plaintext = plaintext[:i]; break }
            //             if i == 0 { return nil, 0, alertUnexpectedMessage } } }
            if self.version == VersionTLS13 {
                if typ != super::common::recordTypeApplicationData {
                    return (slice::new(), recordType(0), Some(alertUnexpectedMessage));
                }
                if plaintext.Len() > super::common::maxPlaintext + 1 {
                    return (slice::new(), recordType(0), Some(alertRecordOverflow));
                }
                let mut i: int = plaintext.Len() - 1;
                loop {
                    if i < 0 {
                        return (slice::new(), recordType(0), Some(alertUnexpectedMessage));
                    }
                    if plaintext[i as usize] != 0 {
                        typ = recordType(plaintext[i as usize]);
                        plaintext = plaintext.slice(0, i);
                        break;
                    }
                    if i == 0 {
                        return (slice::new(), recordType(0), Some(alertUnexpectedMessage));
                    }
                    i -= 1;
                }
            }
        } else {
            plaintext = payload.clone();
        }

        // Go: if hc.mac != nil { … }
        if self.mac.is_some() {
            // Go: macSize := hc.mac.Size()
            //     if len(payload) < macSize { return nil, 0, alertBadRecordMAC }
            let macSize = self.mac.as_ref().unwrap().Size();
            if payload.Len() < macSize {
                return (slice::new(), recordType(0), Some(alertBadRecordMAC));
            }

            // Go: n := len(payload) - macSize - paddingLen
            //     n = subtle.ConstantTimeSelect(int(uint32(n)>>31), 0, n) // if n < 0 { n = 0 }
            //     record[3] = byte(n >> 8); record[4] = byte(n)
            let mut n = payload.Len() - macSize - paddingLen;
            n = crate::crypto::subtle::ConstantTimeSelect(
                crate::int(crate::uint32(n) >> 31),
                0,
                n,
            );
            record[3] = crate::byte(n >> 8);
            record[4] = crate::byte(n);
            // Go: remoteMAC := payload[n : n+macSize]
            //     localMAC := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:],
            //         record[:recordHeaderLen], payload[:n], payload[n+macSize:])
            let remoteMAC = payload.slice(n, n + macSize);
            let localMAC = super::cipher_suites::tls10MAC(
                &mut **self.mac.as_mut().unwrap(),
                slice::new(),
                slice::__from_vec(self.seq.to_vec()),
                record.slice(0, recordHeaderLen),
                payload.slice(0, n),
                payload.slice(n + macSize, payload.Len()),
            );

            // Go: This is equivalent to checking the MACs and paddingGood
            // separately, but in constant-time to prevent distinguishing
            // padding failures from MAC failures. Depending on what value of
            // paddingLen was returned on bad padding, distinguishing bad MAC
            // from bad padding can lead to an attack.
            //
            // See also the logic at the end of extractPadding.
            // Go: macAndPaddingGood := subtle.ConstantTimeCompare(localMAC, remoteMAC) & int(paddingGood)
            //     if macAndPaddingGood != 1 { return nil, 0, alertBadRecordMAC }
            let macAndPaddingGood =
                crate::crypto::subtle::ConstantTimeCompare(&localMAC, &remoteMAC)
                    & crate::int(paddingGood);
            if macAndPaddingGood != 1 {
                return (slice::new(), recordType(0), Some(alertBadRecordMAC));
            }

            // Go: plaintext = payload[:n]
            plaintext = payload.slice(0, n);
        }

        // Go: hc.incSeq(); return plaintext, typ, nil
        self.incSeq();
        return (plaintext, typ, None);
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:940-1017 halfConn.encrypt
    /// Go: "encrypt encrypts payload, adding the appropriate nonce
    /// and/or MAC, and appends it to record, which must already contain
    /// the record header."
    pub(crate) fn encrypt(
        &mut self,
        record: slice<byte>,
        payload: slice<byte>,
        rand: &mut (dyn crate::io::Reader + Send + Sync + 'static),
    ) -> (slice<byte>, error) {
        // Go: if hc.cipher == nil { return append(record, payload...), nil }
        if matches!(self.cipher, halfConnCipher::None) {
            let mut out: Vec<byte> = Vec::new();
            let r: &[byte] = &record;
            let p: &[byte] = &payload;
            out.extend_from_slice(r);
            out.extend_from_slice(p);
            return (slice::__from_vec(out), errors::nil);
        }

        // Go: var explicitNonce []byte
        //     if explicitNonceLen := hc.explicitNonceLen(); explicitNonceLen > 0 {
        //         record, explicitNonce = sliceForAppend(record, explicitNonceLen)
        //         if _, isCBC := hc.cipher.(cbcMode); !isCBC && explicitNonceLen < 16 {
        //             copy(explicitNonce, hc.seq[:])
        //         } else {
        //             if _, err := io.ReadFull(rand, explicitNonce); err != nil { return nil, err } } }
        let mut rec: Vec<byte> = {
            let r: &[byte] = &record;
            r.to_vec()
        };
        let mut explicitNonce: Vec<byte> = Vec::new();
        let enl = self.explicitNonceLen();
        if enl > 0 {
            let isCBC = matches!(self.cipher, halfConnCipher::CBC(_));
            if !isCBC && enl < 16 {
                // Go: The AES-GCM construction in TLS has an explicit nonce so
                // that the nonce can be random. However, the nonce is only 8
                // bytes which is too small for a secure, random nonce.
                // Therefore we use the sequence number as the nonce. The
                // 3DES-CBC construction also has an 8 bytes nonce but its
                // nonces must be unpredictable (see RFC 5246, Appendix F.3),
                // forcing us to use randomness. That's not 3DES' biggest
                // problem anyway because the birthday bound on block collision
                // is reached first due to its similarly small block size (see
                // the Sweet32 attack).
                explicitNonce = self.seq[..enl as usize].to_vec();
            } else {
                let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; enl as usize]);
                let (_, err) = crate::io::ReadFull(rand, &mut buf);
                if err != errors::nil {
                    return (slice::new(), err);
                }
                let raw: &[byte] = &buf;
                explicitNonce = raw.to_vec();
            }
            rec.extend_from_slice(&explicitNonce);
        }

        // Go: var dst []byte
        //     switch c := hc.cipher.(type) { … }
        let seq = slice::__from_vec(self.seq.to_vec());
        let version = self.version;
        match &mut self.cipher {
            halfConnCipher::Stream(c) => {
                // Go: mac := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:],
                //         record[:recordHeaderLen], payload, nil)
                //     record, dst = sliceForAppend(record, len(payload)+len(mac))
                //     c.XORKeyStream(dst[:len(payload)], payload)
                //     c.XORKeyStream(dst[len(payload):], mac)
                let mac = super::cipher_suites::tls10MAC(
                    &mut **self.mac.as_mut().unwrap(),
                    slice::new(),
                    seq,
                    slice::__from_vec(rec[..recordHeaderLen as usize].to_vec()),
                    payload.clone(),
                    slice::new(),
                );
                let mut head = payload.clone();
                c.XORKeyStream(&mut head, payload.clone());
                let mut tail = mac.clone();
                c.XORKeyStream(&mut tail, mac);
                let h: &[byte] = &head;
                let t: &[byte] = &tail;
                rec.extend_from_slice(h);
                rec.extend_from_slice(t);
            }
            halfConnCipher::AEAD(c) => {
                // Go: nonce := explicitNonce; if len(nonce) == 0 { nonce = hc.seq[:] }
                let nonce = if explicitNonce.is_empty() {
                    seq.clone()
                } else {
                    slice::__from_vec(explicitNonce.clone())
                };

                if version == VersionTLS13 {
                    // Go: record = append(record, payload...)
                    //     // Encrypt the actual ContentType and replace the plaintext one.
                    //     record = append(record, record[0])
                    //     record[0] = byte(recordTypeApplicationData)
                    //     n := len(payload) + 1 + c.Overhead()
                    //     record[3] = byte(n >> 8); record[4] = byte(n)
                    //     record = c.Seal(record[:recordHeaderLen], nonce,
                    //         record[recordHeaderLen:], record[:recordHeaderLen])
                    let p: &[byte] = &payload;
                    rec.extend_from_slice(p);
                    let first = rec[0];
                    rec.push(first);
                    rec[0] = super::common::recordTypeApplicationData.0;
                    let n = payload.Len() + 1 + c.Overhead();
                    rec[3] = crate::byte(n >> 8);
                    rec[4] = crate::byte(n);
                    let header = slice::__from_vec(rec[..recordHeaderLen as usize].to_vec());
                    let body = slice::__from_vec(rec[recordHeaderLen as usize..].to_vec());
                    let sealed = c.Seal(header.clone(), nonce, body, header);
                    let s: &[byte] = &sealed;
                    rec = s.to_vec();
                } else {
                    // Go: additionalData := append(hc.scratchBuf[:0], hc.seq[:]...)
                    //     additionalData = append(additionalData, record[:recordHeaderLen]...)
                    //     record = c.Seal(record, nonce, payload, additionalData)
                    let mut ad: Vec<byte> = Vec::new();
                    let sq: &[byte] = &seq;
                    ad.extend_from_slice(sq);
                    ad.extend_from_slice(&rec[..recordHeaderLen as usize]);
                    let sealed = c.Seal(
                        slice::__from_vec(rec.clone()),
                        nonce,
                        payload.clone(),
                        slice::__from_vec(ad),
                    );
                    let s: &[byte] = &sealed;
                    rec = s.to_vec();
                }
            }
            halfConnCipher::CBC(c) => {
                // Go: mac := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:],
                //         record[:recordHeaderLen], payload, nil)
                //     blockSize := c.BlockSize()
                //     plaintextLen := len(payload) + len(mac)
                //     paddingLen := blockSize - plaintextLen%blockSize
                //     record, dst = sliceForAppend(record, plaintextLen+paddingLen)
                //     copy(dst, payload); copy(dst[len(payload):], mac)
                //     for i := plaintextLen; i < len(dst); i++ { dst[i] = byte(paddingLen - 1) }
                //     if len(explicitNonce) > 0 { c.SetIV(explicitNonce) }
                //     c.CryptBlocks(dst, dst)
                let mac = super::cipher_suites::tls10MAC(
                    &mut **self.mac.as_mut().unwrap(),
                    slice::new(),
                    seq,
                    slice::__from_vec(rec[..recordHeaderLen as usize].to_vec()),
                    payload.clone(),
                    slice::new(),
                );
                let blockSize = c.BlockSize();
                let plaintextLen = payload.Len() + mac.Len();
                let paddingLen = blockSize - plaintextLen % blockSize;
                let mut dst: Vec<byte> = Vec::with_capacity((plaintextLen + paddingLen) as usize);
                let p: &[byte] = &payload;
                let m: &[byte] = &mac;
                dst.extend_from_slice(p);
                dst.extend_from_slice(m);
                while crate::int(dst.len()) < plaintextLen + paddingLen {
                    dst.push(crate::byte(paddingLen - 1));
                }
                if !explicitNonce.is_empty() {
                    c.SetIV(slice::__from_vec(explicitNonce.clone()));
                }
                let src = slice::__from_vec(dst.clone());
                let mut out = src.clone();
                c.CryptBlocks(&mut out, src);
                let o: &[byte] = &out;
                rec.extend_from_slice(o);
            }
            halfConnCipher::None => {}
        }

        // Go: Update length to include nonce, MAC and any block padding needed.
        // Go: n := len(record) - recordHeaderLen
        //     record[3] = byte(n >> 8); record[4] = byte(n)
        //     hc.incSeq()
        let n = crate::int(rec.len()) - recordHeaderLen;
        rec[3] = crate::byte(n >> 8);
        rec[4] = crate::byte(n);
        self.incSeq();

        // Go: return record, nil
        return (slice::__from_vec(rec), errors::nil);
    }
}
