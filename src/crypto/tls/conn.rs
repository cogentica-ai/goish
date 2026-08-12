// go: file crypto/tls/conn.go decls: permanentError.Error, permanentError.Unwrap, permanentError.Timeout, permanentError.Temporary, halfConn.setErrorLocked, halfConn.prepareCipherSpec, halfConn.changeCipherSpec, halfConn.setTrafficSecret, halfConn.incSeq, halfConn.explicitNonceLen, extractPadding, roundUp, sliceForAppend, RecordHeaderError.Error, atLeastReader.Read, halfConn.decrypt, halfConn.encrypt, Conn.LocalAddr, Conn.RemoteAddr, Conn.SetDeadline, Conn.SetReadDeadline, Conn.SetWriteDeadline, Conn.NetConn, Conn.newRecordHeaderError, Conn.maxPayloadSizeForWrite, Conn.OCSPResponse, Conn.VerifyHostname, Conn.ConnectionState, Conn.connectionStateLocked, Conn.flush, Conn.write, Conn.writeRecordLocked, Conn.writeChangeCipherRecord, Conn.sendAlertLocked, Conn.sendAlert, Conn.readFromUntil, Conn.retryReadRecord, Conn.readRecord, Conn.readChangeCipherSpec, Conn.readRecordOrCCS, Conn.closeNotify, Conn.CloseWrite, Conn.readHandshakeBytes, Conn.readHandshake, Conn.unmarshalHandshakeMessage, Conn.writeHandshakeRecord, Conn.handleKeyUpdate, Conn.Handshake, Conn.HandshakeContext, Conn.handshakeContext, Conn.handleRenegotiation, Conn.handlePostHandshakeMessage
//
// crypto/tls — the record layer's cipher state.
//
// **Partial port.** conn.go is 1700 lines and most of it is `Conn`,
// which owns a `net.Conn` and drives the handshake; that lands with the
// state machines. What is here is the whole record codec — `halfConn`,
// its `decrypt`/`encrypt`, `atLeastReader` and the free functions they
// need — none of which touches a `Conn`.
//
// goishlint:ignore GOISH018 handleRenegotiation, HandshakeContext, handshakeContext, Write, Close, Handshake — Conn and the record read/write loop, which own a net.Conn. See ROADMAP.md.
// goishlint:ignore GOISH019  — same.
// goishlint:ignore GOISH021 maxUselessBytes, tlsunsafeekm, outBufPool — same; the last three are the dynamic record-sizing knobs and a godebug var, all of which belong to Conn.write; outBufPool is a sync.Pool whose only purpose is to avoid one allocation per record, which goish does not model.
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
use super::common::{recordHeaderLen, recordType, VersionTLS11, VersionTLS12, VersionTLS13};
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
    // go: sdk 1.25.5 crypto/tls/conn.go:191-191 permanentError.Error
    pub(crate) fn Error(&self) -> string {
        // Go: return e.err.Error()
        return self.err.Error();
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:192-192 permanentError.Unwrap
    pub(crate) fn Unwrap(&self) -> error {
        // Go: return e.err
        return self.err.clone();
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:193-193 permanentError.Timeout
    ///
    /// Deviation: Go forwards to `e.err.Timeout()` on the wrapped
    /// `net.Error`. goish has no `net.Error` interface to forward
    /// through, so this reports false until one exists.
    pub(crate) fn Timeout(&self) -> bool {
        // Go: return e.err.Timeout()
        return false;
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:194-194 permanentError.Temporary
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
    // go: sdk 1.25.5 crypto/tls/conn.go:196-203 halfConn.setErrorLocked
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

    // go: sdk 1.25.5 crypto/tls/conn.go:207-211 halfConn.prepareCipherSpec
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

    // go: sdk 1.25.5 crypto/tls/conn.go:215-227 halfConn.changeCipherSpec
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

    // go: sdk 1.25.5 crypto/tls/conn.go:229-237 halfConn.setTrafficSecret
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

    // go: sdk 1.25.5 crypto/tls/conn.go:240-252 halfConn.incSeq
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

    // go: sdk 1.25.5 crypto/tls/conn.go:257-276 halfConn.explicitNonceLen
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

// go: sdk 1.25.5 crypto/tls/conn.go:281-326 extractPadding
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

// go: sdk 1.25.5 crypto/tls/conn.go:328-330 roundUp
pub(crate) fn roundUp(a: int, b: int) -> int {
    // Go: return a + (b-a%b)%b
    return a + (b - a % b) % b;
}

// go: sdk 1.25.5 crypto/tls/conn.go:467-476 sliceForAppend
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
    // go: sdk 1.25.5 crypto/tls/conn.go:579-579 RecordHeaderError.Error
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
    pub R: &'a mut (dyn crate::io::Reader + 'a),
    pub N: crate::types::int64,
}

impl<'a> crate::io::Reader for atLeastReader<'a> {
    // go: sdk 1.25.5 crypto/tls/conn.go:812-825 atLeastReader.Read
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
    // go: sdk 1.25.5 crypto/tls/conn.go:340-462 halfConn.decrypt
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

    // go: sdk 1.25.5 crypto/tls/conn.go:480-563 halfConn.encrypt
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

// ─── Conn ─────────────────────────────────────────────────────────────
//
// Go's `Conn` record and the methods that read it without driving the
// handshake. Nothing here is reachable from goish's own TLS client yet:
// `tls::Conn` in mod[rs] is a four-field wrapper that delegates to
// record[rs] and handshake_client[rs], and `tls::Dial` returns that one.
// This is the shape it has to become, ported and diffable in the
// meantime — the same arrangement key_agreement[rs] and prf[rs] are in.

// Go: conn.go:43-124
//   type Conn struct { conn net.Conn; isClient bool; handshakeFn …; quic …
//                      isHandshakeComplete atomic.Bool; handshakeMutex sync.Mutex
//                      handshakeErr error; vers uint16; haveVers bool; config *Config
//                      handshakes int; extMasterSecret bool; didResume bool; didHRR bool
//                      cipherSuite uint16; curveID CurveID; peerSigAlg SignatureScheme
//                      ocspResponse []byte; scts [][]byte
//                      peerCertificates []*x509.Certificate
//                      verifiedChains [][]*x509.Certificate; serverName string
//                      secureRenegotiation bool; ekm …; resumptionSecret []byte
//                      echAccepted bool; ticketKeys []ticketKey
//                      clientFinishedIsFirst bool; closeNotifyErr error
//                      closeNotifySent bool; clientFinished, serverFinished [12]byte
//                      clientProtocol string; in, out halfConn; rawInput bytes.Buffer
//                      input bytes.Reader; hand bytes.Buffer; buffering bool
//                      sendBuf []byte; bytesSent, packetsSent int64; retryCount int
//                      activeCall atomic.Int32; tmp [16]byte }
/// Go: "A Conn represents a secured connection. It implements the
/// net.Conn interface."
///
/// Deviations, all structural:
///
///   * `handshakeFn` and `quic` are absent — they arrive with the state
///     machines and the QUIC event loop respectively.
///   * `isHandshakeComplete` is a plain `bool` and `handshakeMutex`,
///     `activeCall` are gone: goish methods take `&mut self`, so the
///     borrow checker gives the exclusion the atomics and the mutex buy.
///   * `rawInput`/`input`/`hand` are `Vec<byte>` with an explicit read
///     offset rather than `bytes.Buffer`/`bytes.Reader`.
pub struct Conn {
    pub(crate) conn: Option<alloc::boxed::Box<dyn crate::net::Conn>>,
    pub(crate) isClient: bool,
    pub(crate) isHandshakeComplete: bool,
    pub(crate) handshakeErr: error,
    /// TLS version.
    pub(crate) vers: uint16,
    /// Version has been negotiated.
    pub(crate) haveVers: bool,
    /// Configuration passed to constructor.
    pub(crate) config: super::Config,
    pub(crate) handshakes: int,
    pub(crate) extMasterSecret: bool,
    /// Whether this connection was a session resumption.
    pub(crate) didResume: bool,
    /// Whether a HelloRetryRequest was sent/received.
    pub(crate) didHRR: bool,
    pub(crate) cipherSuite: uint16,
    pub(crate) curveID: super::common::CurveID,
    pub(crate) peerSigAlg: super::common::SignatureScheme,
    /// Stapled OCSP response.
    pub(crate) ocspResponse: slice<byte>,
    /// Signed certificate timestamps from server.
    pub(crate) scts: slice<slice<byte>>,
    pub(crate) peerCertificates: slice<crate::crypto::x509::Certificate>,
    pub(crate) verifiedChains: slice<slice<crate::crypto::x509::Certificate>>,
    pub(crate) serverName: string,
    pub(crate) secureRenegotiation: bool,
    pub(crate) ekm:
        Option<alloc::sync::Arc<dyn Fn(string, slice<byte>, int) -> (slice<byte>, error) + Send + Sync>>,
    pub(crate) resumptionSecret: slice<byte>,
    pub(crate) echAccepted: bool,
    pub(crate) ticketKeys: slice<super::common::ticketKey>,
    pub(crate) clientFinishedIsFirst: bool,
    pub(crate) closeNotifyErr: error,
    pub(crate) closeNotifySent: bool,
    pub(crate) clientFinished: [byte; 12],
    pub(crate) serverFinished: [byte; 12],
    pub(crate) clientProtocol: string,
    pub(crate) in_: halfConn,
    pub(crate) out: halfConn,
    /// Raw input, starting with a record header.
    pub(crate) rawInput: Vec<byte>,
    /// Application data waiting to be read, from rawInput.Next.
    pub(crate) input: Vec<byte>,
    pub(crate) inputOff: int,
    /// Handshake data waiting to be read.
    pub(crate) hand: Vec<byte>,
    /// Whether records are buffered in sendBuf.
    pub(crate) buffering: bool,
    /// A buffer of records waiting to be sent.
    pub(crate) sendBuf: Vec<byte>,
    pub(crate) bytesSent: crate::types::int64,
    pub(crate) packetsSent: crate::types::int64,
    pub(crate) retryCount: int,
    pub(crate) tmp: [byte; 16],
}

impl Default for Conn {
    // go: none — goish idiom: Go's zero value. `conn` is nil until
    // `tls.Client`/`tls.Server` sets it.
    fn default() -> Self {
        return Conn {
            conn: None,
            isClient: false,
            isHandshakeComplete: false,
            handshakeErr: errors::nil,
            vers: 0,
            haveVers: false,
            config: super::Config::default(),
            handshakes: 0,
            extMasterSecret: false,
            didResume: false,
            didHRR: false,
            cipherSuite: 0,
            curveID: super::common::CurveID(0),
            peerSigAlg: super::common::SignatureScheme(0),
            ocspResponse: slice::new(),
            scts: slice::new(),
            peerCertificates: slice::new(),
            verifiedChains: slice::new(),
            serverName: string::from_static(""),
            secureRenegotiation: false,
            ekm: None,
            resumptionSecret: slice::new(),
            echAccepted: false,
            ticketKeys: slice::new(),
            clientFinishedIsFirst: false,
            closeNotifyErr: errors::nil,
            closeNotifySent: false,
            clientFinished: [0u8; 12],
            serverFinished: [0u8; 12],
            clientProtocol: string::from_static(""),
            in_: halfConn::default(),
            out: halfConn::default(),
            rawInput: Vec::new(),
            input: Vec::new(),
            inputOff: 0,
            hand: Vec::new(),
            buffering: false,
            sendBuf: Vec::new(),
            bytesSent: 0,
            packetsSent: 0,
            retryCount: 0,
            tmp: [0u8; 16],
        };
    }
}

impl Conn {

    // go: none — goish-only: Conn's fields are unexported in Go, where
    // the tests are in-package. goish examples are external crates, so
    // the fields the reference tests set need named setters. Nothing in
    // the port uses them.
    #[doc(hidden)]
    pub fn __setIsClient(&mut self, v: bool) { self.isClient = v; }
    // go: none — goish-only: see `__setIsClient`.
    #[doc(hidden)]
    pub fn __setHandshakeComplete(&mut self, v: bool) { self.isHandshakeComplete = v; }
    // go: none — goish-only: see `__setIsClient`.
    #[doc(hidden)]
    pub fn __setVers(&mut self, v: uint16) { self.vers = v; }
    // go: none — goish-only: see `__setIsClient`.
    #[doc(hidden)]
    pub fn __setBytesSent(&mut self, v: crate::types::int64) { self.bytesSent = v; }
    // go: none — goish-only: see `__setIsClient`.
    #[doc(hidden)]
    pub fn __setDynamicRecordSizingDisabled(&mut self, v: bool) {
        self.config.DynamicRecordSizingDisabled = v;
    }
    // go: none — goish-only: see `__setIsClient`.
    #[doc(hidden)]
    pub fn __setRenegotiation(&mut self, v: super::common::RenegotiationSupport) {
        self.config.Renegotiation = v;
    }
    // go: none — goish-only: see `__setIsClient`.
    #[doc(hidden)]
    pub fn __setRawInput(&mut self, v: slice<byte>) {
        let raw: &[byte] = &v;
        self.rawInput = raw.to_vec();
    }
    // go: none — goish-only: see `__setIsClient`.
    #[doc(hidden)]
    pub fn __setOutTrafficSecret(
        &mut self,
        suite: &'static cipherSuiteTLS13,
        secret: slice<byte>,
    ) {
        self.out
            .setTrafficSecret(suite, QUICEncryptionLevel(0), secret);
    }
    // go: none — goish-only: see `__setIsClient`.
    #[doc(hidden)]
    pub fn __setStateFields(
        &mut self,
        cipherSuite: uint16,
        serverName: string,
        clientProtocol: string,
        curveID: super::common::CurveID,
    ) {
        self.cipherSuite = cipherSuite;
        self.serverName = serverName;
        self.clientProtocol = clientProtocol;
        self.curveID = curveID;
        self.clientFinishedIsFirst = true;
        self.clientFinished = [1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    }


    // go: none — goish-only: an in-memory net::Conn so the reference
    // tests can see what the write path put on the wire. Go's tests are
    // in-package and build one inline.
    #[doc(hidden)]
    pub fn __setMemConn(
        &mut self,
        sink: alloc::sync::Arc<crate::sync::Mutex<slice<byte>>>,
    ) {
        self.conn = Some(alloc::boxed::Box::new(memConn { sink }));
    }
    // go: none — goish-only: see `__setMemConn`.
    #[doc(hidden)]
    pub fn __echAccepted(&self) -> bool { return self.echAccepted; }
    // go: none — goish-only: see `__setMemConn`.
    #[doc(hidden)]
    pub fn __setBuffering(&mut self, v: bool) { self.buffering = v; }
    // go: none — goish-only: see `__setMemConn`.
    #[doc(hidden)]
    pub fn __buffering(&self) -> bool { return self.buffering; }


    // go: none — goish-only: an in-memory net::Conn that yields a fixed
    // byte string, so the reference tests can drive the read path. Go's
    // tests are in-package and build one inline.
    #[doc(hidden)]
    pub fn __setFeedConn(&mut self, data: slice<byte>) {
        let raw: &[byte] = &data;
        self.conn = Some(alloc::boxed::Box::new(feedConn {
            r: raw.to_vec(),
            at: 0,
            sink: None,
        }));
    }
    // go: none — goish-only: like `__setFeedConn`, but writes are
    // recorded into `sink` rather than discarded. A read-path test needs
    // this: `readHandshake` answers a bad message with an alert, and an
    // error return without the alert would look identical to the caller
    // and wrong to the peer.
    #[doc(hidden)]
    pub fn __setDuplexConn(
        &mut self,
        data: slice<byte>,
        sink: alloc::sync::Arc<crate::sync::Mutex<slice<byte>>>,
    ) {
        let raw: &[byte] = &data;
        self.conn = Some(alloc::boxed::Box::new(feedConn {
            r: raw.to_vec(),
            at: 0,
            sink: Some(sink),
        }));
    }
    // go: none — goish-only: see `__setFeedConn`.
    #[doc(hidden)]
    pub fn __setHaveVers(&mut self, v: bool) { self.haveVers = v; }
    // go: none — goish-only: see `__setFeedConn`.
    #[doc(hidden)]
    pub fn __hand(&self) -> slice<byte> { return slice::__from_vec(self.hand.clone()); }
    // go: none — goish-only: see `__setFeedConn`.
    #[doc(hidden)]
    pub fn __retryCount(&self) -> int { return self.retryCount; }


    // go: none — goish-only: `config` is unexported in Go, where the
    // tests and handshake_client.go are in the same package.
    #[doc(hidden)]
    pub fn __configServerName(&self) -> string { return self.config.ServerName.clone(); }


    // go: none — goish-only: `config` is unexported in Go, where the
    // handshake state machines are in the same package.
    #[doc(hidden)]
    pub fn __configSessionTicketsDisabled(&self) -> bool {
        return self.config.SessionTicketsDisabled;
    }
    // go: none — goish-only: see `__configSessionTicketsDisabled`.
    #[doc(hidden)]
    pub fn __configClientAuth(&self) -> super::common::ClientAuthType {
        return self.config.ClientAuth;
    }


    // go: none — goish-only: see `__configSessionTicketsDisabled`.
    #[doc(hidden)]
    pub fn __setConfig(&mut self, cfg: super::Config) { self.config = cfg; }
    // go: none — goish-only: see `__setConfig`.
    #[doc(hidden)]
    pub fn __configClientSessionCache(
        &self,
    ) -> Option<
        alloc::sync::Arc<crate::sync::Mutex<Box<dyn super::common::ClientSessionCache>>>,
    > {
        return self.config.ClientSessionCache.clone();
    }
    // go: none — goish-only: see `__setConfig`.
    #[doc(hidden)]
    pub fn __peerCertificateCount(&self) -> int { return self.peerCertificates.Len(); }
    // go: none — goish-only: see `__setConfig`.
    #[doc(hidden)]
    pub fn __verifiedChainCount(&self) -> int { return self.verifiedChains.Len(); }


    // go: none — goish-only: see `__configSessionTicketsDisabled`.
    #[doc(hidden)]
    pub fn __config(&self) -> super::Config { return self.config.clone(); }
    // go: none — goish-only: see `__configSessionTicketsDisabled`.
    #[doc(hidden)]
    pub fn __vers(&self) -> uint16 { return self.vers; }


    // go: none — goish-only: see `__configSessionTicketsDisabled`.
    #[doc(hidden)]
    pub fn __setCipherSuite(&mut self, id: uint16) { self.cipherSuite = id; }
    // go: none — goish-only: `halfConn.trafficSecret` and the identity
    // fields a SessionState snapshot reads are unexported in Go, where
    // the tests are in-package.
    #[doc(hidden)]
    pub fn __setTrafficSecrets(&mut self, in_: slice<byte>, out: slice<byte>) {
        self.in_.trafficSecret = in_;
        self.out.trafficSecret = out;
    }
    // go: none — goish-only: see `__setTrafficSecrets`.
    #[doc(hidden)]
    pub fn __trafficSecrets(&self) -> (slice<byte>, slice<byte>) {
        return (self.in_.trafficSecret.clone(), self.out.trafficSecret.clone());
    }
    // go: none — goish-only: see `__setTrafficSecrets`.
    #[doc(hidden)]
    pub fn __setSessionIdentity(
        &mut self,
        proto: string,
        ocsp: slice<byte>,
        scts: slice<slice<byte>>,
        extMasterSecret: bool,
        curveID: super::common::CurveID,
    ) {
        self.clientProtocol = proto;
        self.ocspResponse = ocsp;
        self.scts = scts;
        self.extMasterSecret = extMasterSecret;
        self.curveID = curveID;
    }
    // go: none — goish-only: Go writes the four assignments inline in
    // `pickTLSVersion`; the fields are unexported, so goish names them
    // once here.
    #[doc(hidden)]
    pub fn __adoptVersion(&mut self, vers: uint16) {
        self.vers = vers;
        self.haveVers = true;
        self.in_.version = vers;
        self.out.version = vers;
    }


    // go: none — goish-only: see `__configSessionTicketsDisabled`.
    #[doc(hidden)]
    pub fn __inVersion(&self) -> uint16 { return self.in_.version; }
    // go: none — goish-only: see `__configSessionTicketsDisabled`.
    #[doc(hidden)]
    pub fn __cipherSuite(&self) -> uint16 { return self.cipherSuite; }


    // go: none — goish-only: Go calls `c.in.prepareCipherSpec` and
    // `c.out.prepareCipherSpec` directly, because both halves are
    // unexported fields. goish's callers are in sibling modules, so the
    // pair is named once here.
    #[doc(hidden)]
    pub fn __prepareCipherSpecs(
        &mut self,
        vers: uint16,
        inCipher: halfConnCipher,
        inMac: Option<alloc::boxed::Box<dyn Hash + Send + Sync>>,
        outCipher: halfConnCipher,
        outMac: Option<alloc::boxed::Box<dyn Hash + Send + Sync>>,
    ) {
        self.in_.prepareCipherSpec(vers, inCipher, inMac);
        self.out.prepareCipherSpec(vers, outCipher, outMac);
    }
    // go: none — goish-only: see `__prepareCipherSpecs`.
    #[doc(hidden)]
    pub fn __inExplicitNonceLen(&self) -> int { return self.in_.explicitNonceLen(); }
    // go: none — goish-only: see `__prepareCipherSpecs`.
    #[doc(hidden)]
    pub fn __changeCipherSpecs(&mut self) -> bool {
        return self.in_.changeCipherSpec().is_none() && self.out.changeCipherSpec().is_none();
    }


    // go: none — goish-only: see `__configSessionTicketsDisabled`.
    #[doc(hidden)]
    pub fn __ticketKeys(&self) -> slice<super::common::ticketKey> {
        return self.ticketKeys.clone();
    }
    // go: none — goish-only: Go assigns the seven resumed fields inline
    // in `checkForResumption`; they are unexported, so goish names the
    // block once here.
    #[doc(hidden)]
    pub fn __adoptSession(&mut self, ss: &super::ticket::SessionState) {
        self.peerCertificates = ss.__peerCertificates();
        self.ocspResponse = ss.__ocspResponse();
        self.scts = ss.__scts();
        self.verifiedChains = ss.__verifiedChains();
        self.extMasterSecret = ss.__extMasterSecret();
        self.curveID = ss.__curveID();
        self.didResume = true;
    }
    // go: none — goish-only: see `__adoptSession`.
    #[doc(hidden)]
    pub fn __didResume(&self) -> bool { return self.didResume; }
    // go: none — goish-only: see `__didResume`.
    #[doc(hidden)]
    pub fn __ocspResponseLen(&self) -> int { return self.ocspResponse.Len(); }
    // go: none — goish-only: see `__didResume`.
    #[doc(hidden)]
    pub fn __inTrafficSecretOf(&self) -> slice<byte> { return self.in_.trafficSecret.clone(); }
    // go: none — goish-only: see `__didResume`.
    #[doc(hidden)]
    pub fn __resumptionSecret(&self) -> slice<byte> { return self.resumptionSecret.clone(); }
    // go: none — goish-only: see `__didResume`.
    #[doc(hidden)]
    pub fn __hasEkm(&self) -> bool { return self.ekm.is_some(); }
    // go: none — goish-only: see `__adoptSession`.
    #[doc(hidden)]
    pub fn __setTicketKeys(&mut self, k: slice<super::common::ticketKey>) {
        self.ticketKeys = k;
    }


    // go: none — goish-only: see `__configSessionTicketsDisabled`.
    #[doc(hidden)]
    pub fn __handshakes(&self) -> int { return self.handshakes; }
    // go: none — goish-only: see `__configSessionTicketsDisabled`.
    #[doc(hidden)]
    pub fn __secureRenegotiation(&self) -> bool { return self.secureRenegotiation; }
    // go: none — goish-only: see `__configSessionTicketsDisabled`.
    #[doc(hidden)]
    pub fn __setSecureRenegotiation(&mut self, v: bool) { self.secureRenegotiation = v; }
    // go: none — goish-only: Go builds the 24-byte expected value inline
    // from two unexported [12]byte fields; goish names the concatenation.
    #[doc(hidden)]
    pub fn __expectedSecureRenegotiation(&self) -> slice<byte> {
        let mut v: Vec<byte> = Vec::with_capacity(24);
        v.extend_from_slice(&self.clientFinished);
        v.extend_from_slice(&self.serverFinished);
        return slice::__from_vec(v);
    }
    // go: none — goish-only: see `__configSessionTicketsDisabled`.
    #[doc(hidden)]
    pub fn __setClientProtocol(&mut self, p: string) { self.clientProtocol = p; }
    // go: none — goish-only: see `__configSessionTicketsDisabled`.
    #[doc(hidden)]
    pub fn __setSCTs(&mut self, v: slice<slice<byte>>) { self.scts = v; }
    // go: none — goish-only: see `__configSessionTicketsDisabled`.
    #[doc(hidden)]
    pub fn __scts(&self) -> slice<slice<byte>> { return self.scts.clone(); }
    // go: none — goish-only: see `__configSessionTicketsDisabled`.
    #[doc(hidden)]
    pub fn __clientProtocol(&self) -> string { return self.clientProtocol.clone(); }
    // go: none — goish-only: see `__setMemConn`.
    #[doc(hidden)]
    pub fn __curveID(&self) -> super::common::CurveID { return self.curveID; }
    // go: none — goish-only: see `__setMemConn`.
    #[doc(hidden)]
    pub fn __serverName(&self) -> string { return self.serverName.clone(); }


    // go: none — goish-only: `processServerHello` restores the same
    // fields as `checkForResumption` EXCEPT didResume, which the client
    // sets later in `clientHandshake`. Keeping the two apart matters:
    // folding them would mark a connection resumed before the server's
    // Finished has been verified.
    #[doc(hidden)]
    pub fn __restoreSession(&mut self, ss: &super::ticket::SessionState) {
        self.extMasterSecret = ss.__extMasterSecret();
        self.peerCertificates = ss.__peerCertificates();
        self.verifiedChains = ss.__verifiedChains();
        self.ocspResponse = ss.__ocspResponse();
        self.scts = ss.__scts();
        self.curveID = ss.__curveID();
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:131-133 Conn.LocalAddr
    /// Go: "LocalAddr returns the local network address."
    pub fn LocalAddr(&self) -> crate::net::TCPAddr {
        // Go: return c.conn.LocalAddr()
        return self.conn.as_ref().unwrap().LocalAddr();
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:136-138 Conn.RemoteAddr
    /// Go: "RemoteAddr returns the remote network address."
    pub fn RemoteAddr(&self) -> crate::net::TCPAddr {
        // Go: return c.conn.RemoteAddr()
        return self.conn.as_ref().unwrap().RemoteAddr();
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:143-145 Conn.SetDeadline
    /// Go: "SetDeadline sets the read and write deadlines associated
    /// with the connection. A zero value for t means Read and Write will
    /// not time out. After a Write has timed out, the TLS state is
    /// corrupt and all future writes will return the same error."
    pub fn SetDeadline(&self, t: crate::time::Time) -> error {
        // Go: return c.conn.SetDeadline(t)
        return self.conn.as_ref().unwrap().SetDeadline(t);
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:149-151 Conn.SetReadDeadline
    /// Go: "SetReadDeadline sets the read deadline on the underlying
    /// connection. A zero value for t means Read will not time out."
    pub fn SetReadDeadline(&self, t: crate::time::Time) -> error {
        // Go: return c.conn.SetReadDeadline(t)
        return self.conn.as_ref().unwrap().SetReadDeadline(t);
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:156-158 Conn.SetWriteDeadline
    /// Go: "SetWriteDeadline sets the write deadline on the underlying
    /// connection. A zero value for t means Write will not time out.
    /// After a Write has timed out, the TLS state is corrupt and all
    /// future writes will return the same error."
    pub fn SetWriteDeadline(&self, t: crate::time::Time) -> error {
        // Go: return c.conn.SetWriteDeadline(t)
        return self.conn.as_ref().unwrap().SetWriteDeadline(t);
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:163-165 Conn.NetConn
    /// Go: "NetConn returns the underlying connection that is wrapped by
    /// c. Note that writing to or reading from this connection directly
    /// will corrupt the TLS session."
    pub fn NetConn(&self) -> Option<&(dyn crate::net::Conn + 'static)> {
        // Go: return c.conn
        return self.conn.as_deref();
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:581-586 Conn.newRecordHeaderError
    ///
    /// Deviation: Go's `RecordHeaderError.Conn` field holds the
    /// `net.Conn`; goish's record does not carry it, so the parameter is
    /// accepted and dropped rather than stored.
    /// goishlint:ignore GOISH020 newRecordHeaderError — Go's net.Conn parameter has nowhere to go
    pub(crate) fn newRecordHeaderError(&self, msg: string) -> RecordHeaderError {
        // Go: err.Msg = msg; err.Conn = conn
        //     copy(err.RecordHeader[:], c.rawInput.Bytes())
        //     return err
        let mut err = RecordHeaderError::default();
        err.Msg = msg;
        let n = core::cmp::min(err.RecordHeader.len(), self.rawInput.len());
        err.RecordHeader[..n].copy_from_slice(&self.rawInput[..n]);
        return err;
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:902-947 Conn.maxPayloadSizeForWrite
    /// Go: "maxPayloadSizeForWrite returns the maximum TLS payload size
    /// to use for the write of the given record type. It defaults to
    /// [maxPlaintext] but is reduced for the first few records to
    /// improve latency."
    pub(crate) fn maxPayloadSizeForWrite(&mut self, typ: recordType) -> int {
        // Go: if c.config.DynamicRecordSizingDisabled ||
        //        typ != recordTypeApplicationData { return maxPlaintext }
        if self.config.DynamicRecordSizingDisabled
            || typ != super::common::recordTypeApplicationData
        {
            return super::common::maxPlaintext;
        }

        // Go: if c.bytesSent >= recordSizeBoostThreshold { return maxPlaintext }
        if self.bytesSent >= recordSizeBoostThreshold {
            return super::common::maxPlaintext;
        }

        // Go: Subtract TLS overheads to get the maximum payload size.
        // Go: payloadBytes := tcpMSSEstimate - recordHeaderLen - c.out.explicitNonceLen()
        let mut payloadBytes = tcpMSSEstimate - recordHeaderLen - self.out.explicitNonceLen();
        let macSize = match &self.out.mac {
            Some(m) => m.Size(),
            None => 0,
        };
        match &self.out.cipher {
            halfConnCipher::None => {}
            halfConnCipher::Stream(_) => {
                // Go: payloadBytes -= c.out.mac.Size()
                payloadBytes -= macSize;
            }
            halfConnCipher::AEAD(ciph) => {
                // Go: payloadBytes -= ciph.Overhead()
                payloadBytes -= ciph.Overhead();
            }
            halfConnCipher::CBC(ciph) => {
                // Go: blockSize := ciph.BlockSize()
                //     // The payload must fit in a multiple of blockSize, with
                //     // room for at least one padding byte.
                //     payloadBytes = (payloadBytes & ^(blockSize - 1)) - 1
                //     // The MAC is appended before padding so affects the
                //     // payload size directly.
                //     payloadBytes -= c.out.mac.Size()
                let blockSize = ciph.BlockSize();
                payloadBytes = (payloadBytes & !(blockSize - 1)) - 1;
                payloadBytes -= macSize;
            }
        }
        // Go: if c.vers == VersionTLS13 { payloadBytes-- } // encrypted ContentType
        if self.vers == VersionTLS13 {
            payloadBytes -= 1;
        }

        // Go: Allow packet growth in arithmetic progression up to max.
        // Go: pkt := c.packetsSent; c.packetsSent++
        //     if pkt > 1000 { return maxPlaintext } // avoid overflow in multiply below
        let pkt = self.packetsSent;
        self.packetsSent += 1;
        if pkt > 1000 {
            return super::common::maxPlaintext;
        }

        // Go: n := payloadBytes * int(pkt+1)
        //     if n > maxPlaintext { n = maxPlaintext }
        //     return n
        let mut n = payloadBytes * crate::int(pkt + 1);
        if n > super::common::maxPlaintext {
            n = super::common::maxPlaintext;
        }
        return n;
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:1669-1674 Conn.OCSPResponse
    /// Go: "OCSPResponse returns the stapled OCSP response from the TLS
    /// server, if any. (Only valid for client connections.)"
    pub fn OCSPResponse(&self) -> slice<byte> {
        // Go: c.handshakeMutex.Lock(); defer c.handshakeMutex.Unlock()
        //     return c.ocspResponse
        return self.ocspResponse.clone();
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:1679-1692 Conn.VerifyHostname
    /// Go: "VerifyHostname checks that the peer certificate chain is
    /// valid for connecting to host. If so, it returns nil; if not, it
    /// returns an error describing the problem."
    pub fn VerifyHostname(&self, host: string) -> error {
        // Go: if !c.isClient { return errors.New(
        //         "tls: VerifyHostname called on TLS server connection") }
        if !self.isClient {
            return errors::New("tls: VerifyHostname called on TLS server connection");
        }
        // Go: if !c.isHandshakeComplete.Load() { return errors.New(
        //         "tls: handshake has not yet been performed") }
        if !self.isHandshakeComplete {
            return errors::New("tls: handshake has not yet been performed");
        }
        // Go: if len(c.verifiedChains) == 0 { return errors.New(
        //         "tls: handshake did not verify certificate chain") }
        if self.verifiedChains.Len() == 0 {
            return errors::New("tls: handshake did not verify certificate chain");
        }
        // Go: return c.peerCertificates[0].VerifyHostname(host)
        return self.peerCertificates[0].VerifyHostname(host);
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:1619-1623 Conn.ConnectionState
    /// Go: "ConnectionState returns basic TLS details about the
    /// connection."
    pub fn ConnectionState(&self) -> super::common::ConnectionState {
        // Go: c.handshakeMutex.Lock(); defer c.handshakeMutex.Unlock()
        //     return c.connectionStateLocked()
        return self.connectionStateLocked();
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:1627-1665 Conn.connectionStateLocked
    ///
    /// Deviations: Go's two `testingOnly*` fields are absent from
    /// `ConnectionState`, and the `tlsunsafeekm` GODEBUG escape hatch is
    /// not reachable — `internal/godebug` is not ported, so an unset
    /// variable takes `noEKMBecauseNoEMS` exactly as Go does.
    pub(crate) fn connectionStateLocked(&self) -> super::common::ConnectionState {
        // Go: var state ConnectionState
        //     state.HandshakeComplete = c.isHandshakeComplete.Load()
        //     state.Version = c.vers … state.OCSPResponse = c.ocspResponse
        let mut state = super::common::ConnectionState::default();
        state.HandshakeComplete = self.isHandshakeComplete;
        state.Version = self.vers;
        state.NegotiatedProtocol = self.clientProtocol.clone();
        state.DidResume = self.didResume;
        state.CurveID = self.curveID;
        state.NegotiatedProtocolIsMutual = true;
        state.ServerName = self.serverName.clone();
        state.CipherSuite = self.cipherSuite;
        state.PeerCertificates = self.peerCertificates.clone();
        state.VerifiedChains = self.verifiedChains.clone();
        state.SignedCertificateTimestamps = self.scts.clone();
        state.OCSPResponse = self.ocspResponse.clone();
        // Go: if (!c.didResume || c.extMasterSecret) && c.vers != VersionTLS13 {
        //         if c.clientFinishedIsFirst { state.TLSUnique = c.clientFinished[:] }
        //         else { state.TLSUnique = c.serverFinished[:] } }
        if (!self.didResume || self.extMasterSecret) && self.vers != VersionTLS13 {
            if self.clientFinishedIsFirst {
                state.TLSUnique = slice::__from_vec(self.clientFinished.to_vec());
            } else {
                state.TLSUnique = slice::__from_vec(self.serverFinished.to_vec());
            }
        }
        // Go: if c.config.Renegotiation != RenegotiateNever {
        //         state.ekm = noEKMBecauseRenegotiation
        //     } else if c.vers != VersionTLS13 && !c.extMasterSecret {
        //         state.ekm = func(…) { if tlsunsafeekm.Value() == "1" { … }
        //                               return noEKMBecauseNoEMS(…) }
        //     } else { state.ekm = c.ekm }
        if self.config.Renegotiation != super::common::RenegotiateNever {
            state.__setEKM(true);
        } else if self.vers != VersionTLS13 && !self.extMasterSecret {
            state.__setEKM(false);
        } else {
            state.__setEKMHook(self.ekm.clone());
        }
        // Go: state.ECHAccepted = c.echAccepted
        //     return state
        state.ECHAccepted = self.echAccepted;
        return state;
    }
}

// Go: conn.go — `const ( recordSizeBoostThreshold = 128 * 1024
//                        tcpMSSEstimate = 1208 )`
/// Go: "recordSizeBoostThreshold is the number of bytes after which we
/// stop boosting the record size."
pub(crate) const recordSizeBoostThreshold: crate::types::int64 = 128 * 1024;
/// Go: "tcpMSSEstimate is a conservative estimate of the TCP maximum
/// segment size (MSS). A constant is used, rather than querying the
/// kernel for the actual value, to avoid complexity."
pub(crate) const tcpMSSEstimate: int = 1208;

impl Conn {
    // go: sdk 1.25.5 crypto/tls/conn.go:960-970 Conn.flush
    /// Go: "flush sends any pending records currently buffered."
    pub(crate) fn flush(&mut self) -> (int, error) {
        // Go: if len(c.sendBuf) == 0 { return 0, nil }
        if self.sendBuf.len() == 0 {
            return (0, errors::nil);
        }

        // Go: n, err := c.conn.Write(c.sendBuf)
        //     c.bytesSent += int64(n)
        //     c.sendBuf = nil; c.buffering = false
        //     return n, err
        let buf = slice::__from_vec(core::mem::take(&mut self.sendBuf));
        let (n, err) = self.conn.as_mut().unwrap().Write(buf);
        self.bytesSent += crate::int64(n);
        self.sendBuf = Vec::new();
        self.buffering = false;
        return (n, err);
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:949-958 Conn.write
    /// Go: "write buffers data for the record layer, or writes it out
    /// directly if buffering is off."
    pub(crate) fn write(&mut self, data: slice<byte>) -> (int, error) {
        // Go: if c.buffering { c.sendBuf = append(c.sendBuf, data...); return len(data), nil }
        if self.buffering {
            let raw: &[byte] = &data;
            self.sendBuf.extend_from_slice(raw);
            return (data.Len(), errors::nil);
        }

        // Go: n, err := c.conn.Write(data); c.bytesSent += int64(n); return n, err
        let (n, err) = self.conn.as_mut().unwrap().Write(data);
        self.bytesSent += crate::int64(n);
        return (n, err);
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:981-1050 Conn.writeRecordLocked
    ///
    /// Deviations: the `c.quic != nil` branch is absent — goish ships no
    /// QUIC transport, so `c.quic` is always nil and Go's non-QUIC path
    /// is the only reachable one. And `outBufPool` is a `sync.Pool`
    /// whose only purpose is to avoid an allocation per record; goish
    /// allocates, which is observably identical.
    pub(crate) fn writeRecordLocked(
        &mut self,
        typ: recordType,
        data: slice<byte>,
    ) -> (int, error) {
        // Go: var n int
        //     for len(data) > 0 { … }
        let mut n: int = 0;
        let mut data = data;
        while data.Len() > 0 {
            // Go: m := len(data)
            //     if maxPayload := c.maxPayloadSizeForWrite(typ); m > maxPayload { m = maxPayload }
            let mut m = data.Len();
            let maxPayload = self.maxPayloadSizeForWrite(typ);
            if m > maxPayload {
                m = maxPayload;
            }

            // Go: _, outBuf = sliceForAppend(outBuf[:0], recordHeaderLen)
            //     outBuf[0] = byte(typ)
            //     vers := c.vers
            //     if vers == 0 {
            //         // Some TLS servers fail if the record version is
            //         // greater than TLS 1.0 for the initial ClientHello.
            //         vers = VersionTLS10
            //     } else if vers == VersionTLS13 {
            //         // TLS 1.3 froze the record layer version to 1.2.
            //         // See RFC 8446, Section 5.1.
            //         vers = VersionTLS12
            //     }
            //     outBuf[1] = byte(vers >> 8); outBuf[2] = byte(vers)
            //     outBuf[3] = byte(m >> 8); outBuf[4] = byte(m)
            let mut outBuf: Vec<byte> = alloc::vec![0u8; recordHeaderLen as usize];
            outBuf[0] = typ.0;
            let mut vers = self.vers;
            if vers == 0 {
                vers = super::common::VersionTLS10;
            } else if vers == VersionTLS13 {
                vers = super::common::VersionTLS12;
            }
            outBuf[1] = crate::byte(vers >> 8);
            outBuf[2] = crate::byte(vers);
            outBuf[3] = crate::byte(m >> 8);
            outBuf[4] = crate::byte(m);

            // Go: outBuf, err = c.out.encrypt(outBuf, data[:m], c.config.rand())
            //     if err != nil { return n, err }
            let mut rand = self.config.rand();
            let (sealed, err) = self.out.encrypt(
                slice::__from_vec(outBuf),
                data.slice(0, m),
                &mut *rand,
            );
            if err != errors::nil {
                return (n, err);
            }
            // Go: if _, err := c.write(outBuf); err != nil { return n, err }
            let (_, err) = self.write(sealed);
            if err != errors::nil {
                return (n, err);
            }
            // Go: n += m; data = data[m:]
            n += m;
            data = data.slice(m, data.Len());
        }

        // Go: if typ == recordTypeChangeCipherSpec && c.vers != VersionTLS13 {
        //         if err := c.out.changeCipherSpec(); err != nil {
        //             return n, c.sendAlertLocked(err.(alert)) } }
        if typ == super::common::recordTypeChangeCipherSpec && self.vers != VersionTLS13 {
            let a = self.out.changeCipherSpec();
            if a.is_some() {
                return (n, self.sendAlertLocked(a.unwrap()));
            }
        }

        // Go: return n, nil
        return (n, errors::nil);
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:1072-1077 Conn.writeChangeCipherRecord
    pub(crate) fn writeChangeCipherRecord(&mut self) -> error {
        // Go: c.out.Lock(); defer c.out.Unlock()
        //     _, err := c.writeRecordLocked(recordTypeChangeCipherSpec, []byte{1})
        //     return err
        let (_, err) = self.writeRecordLocked(
            super::common::recordTypeChangeCipherSpec,
            slice::__from_vec(alloc::vec![1u8]),
        );
        return err;
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:843-863 Conn.sendAlertLocked
    ///
    /// Deviation: Go wraps the alert in a `*net.OpError{Op: "local
    /// error"}` before storing it as the half-connection's permanent
    /// error. goish's `net` has no `OpError`, so the alert is stored
    /// directly — `halfConn.err` is only ever surfaced through
    /// `Error()`, and the alert's own message is what Go's OpError
    /// prints after the "local error: tls: " prefix.
    pub(crate) fn sendAlertLocked(&mut self, err: alert) -> error {
        // Go: switch err {
        //     case alertNoRenegotiation, alertCloseNotify: c.tmp[0] = alertLevelWarning
        //     default: c.tmp[0] = alertLevelError }
        //     c.tmp[1] = byte(err)
        if err == super::alert::alertNoRenegotiation || err == super::alert::alertCloseNotify {
            self.tmp[0] = crate::byte(super::alert::alertLevelWarning);
        } else {
            self.tmp[0] = crate::byte(super::alert::alertLevelError);
        }
        self.tmp[1] = crate::byte(err.0);

        // Go: _, writeErr := c.writeRecordLocked(recordTypeAlert, c.tmp[0:2])
        let two = slice::__from_vec(self.tmp[0..2].to_vec());
        let (_, writeErr) = self.writeRecordLocked(super::common::recordTypeAlert, two);
        // Go: if err == alertCloseNotify {
        //         // closeNotify is a special case in that it isn't an error.
        //         return writeErr }
        if err == super::alert::alertCloseNotify {
            return writeErr;
        }

        // Go: return c.out.setErrorLocked(&net.OpError{Op: "local error", Err: err})
        return self.out.setErrorLocked(crate::errors::Wrap(err));
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:866-870 Conn.sendAlert
    pub(crate) fn sendAlert(&mut self, err: alert) -> error {
        // Go: c.out.Lock(); defer c.out.Unlock()
        //     return c.sendAlertLocked(err)
        return self.sendAlertLocked(err);
    }
}


// go: none — goish-only: the in-memory net::Conn `__setMemConn`
// installs. Go's tests build one inline; goish examples are external
// crates, so it lives here.
struct memConn {
    sink: alloc::sync::Arc<crate::sync::Mutex<slice<byte>>>,
}

impl crate::net::Conn for memConn {
    // go: none — goish-only: see `memConn`.
    fn Read(&mut self, _p: &mut slice<byte>) -> (int, error) {
        return (0, errors::nil);
    }
    // go: none — goish-only: see `memConn`.
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let raw: &[byte] = &p;
        let mut g = self.sink.Lock();
        let mut v = core::mem::replace(&mut *g, slice::new()).__into_vec();
        v.extend_from_slice(raw);
        *g = slice::__from_vec(v);
        return (p.Len(), errors::nil);
    }
    // go: none — goish-only: see `memConn`.
    fn Close(&mut self) -> error {
        return errors::nil;
    }
    // go: none — goish-only: see `memConn`.
    fn LocalAddr(&self) -> crate::net::TCPAddr {
        return crate::net::TCPAddr { IP: [0, 0, 0, 0], Port: 0 };
    }
    // go: none — goish-only: see `memConn`.
    fn RemoteAddr(&self) -> crate::net::TCPAddr {
        return crate::net::TCPAddr { IP: [0, 0, 0, 0], Port: 0 };
    }
    // go: none — goish-only: see `memConn`.
    fn SetDeadline(&self, _t: crate::time::Time) -> error {
        return errors::nil;
    }
    // go: none — goish-only: see `memConn`.
    fn SetReadDeadline(&self, _t: crate::time::Time) -> error {
        return errors::nil;
    }
    // go: none — goish-only: see `memConn`.
    fn SetWriteDeadline(&self, _t: crate::time::Time) -> error {
        return errors::nil;
    }
}

impl Conn {
    // go: sdk 1.25.5 crypto/tls/conn.go:829-840 Conn.readFromUntil
    /// Go: "readFromUntil reads from r into c.rawInput until c.rawInput
    /// contains at least n bytes or else returns an error."
    ///
    /// Deviation: Go grows `rawInput` by `needs + bytes.MinRead` and
    /// lets `ReadFrom` make a best-effort over-read, so that
    /// `(*Conn).Read` can "predict" closeNotify alerts. goish reads
    /// exactly `needs` bytes through the same `atLeastReader`; the
    /// prediction is an optimisation, not a protocol behaviour.
    ///
    /// goishlint:ignore GOISH020 readFromUntil — Go's `r io.Reader` parameter is always `c.conn`; goish reads it from the receiver, because `net::Conn` is not an `io::Reader` and the borrow cannot be split
    pub(crate) fn readFromUntil(&mut self, n: int) -> error {
        // Go: if c.rawInput.Len() >= n { return nil }
        if crate::int(self.rawInput.len()) >= n {
            return errors::nil;
        }
        // Go: needs := n - c.rawInput.Len()
        let needs = n - crate::int(self.rawInput.len());
        // Go: _, err := c.rawInput.ReadFrom(&atLeastReader{r, int64(needs)})
        //     return err
        let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; needs as usize]);
        let conn = self.conn.as_mut().unwrap();
        let mut adapter = connReader { c: &mut **conn };
        let mut r = atLeastReader {
            R: &mut adapter,
            N: crate::int64(needs),
        };
        let (got, err) = crate::io::ReadFull(&mut r, &mut buf);
        let raw: &[byte] = &buf;
        self.rawInput.extend_from_slice(&raw[..got as usize]);
        return err;
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:795-802 Conn.retryReadRecord
    /// Go: "retryReadRecord recurses into readRecordOrCCS to drop a
    /// non-advancing record, like a warning alert, empty application_data,
    /// or a change_cipher_spec in TLS 1.3."
    pub(crate) fn retryReadRecord(&mut self, expectChangeCipherSpec: bool) -> error {
        // Go: c.retryCount++
        //     if c.retryCount > maxUselessRecords {
        //         c.sendAlert(alertUnexpectedMessage)
        //         return c.in.setErrorLocked(errors.New("tls: too many ignored records")) }
        self.retryCount += 1;
        if self.retryCount > super::common::maxUselessRecords {
            self.sendAlert(alertUnexpectedMessage);
            return self
                .in_
                .setErrorLocked(errors::New("tls: too many ignored records"));
        }
        // Go: return c.readRecordOrCCS(expectChangeCipherSpec)
        return self.readRecordOrCCS(expectChangeCipherSpec);
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:588-590 Conn.readRecord
    /// Go: "readRecord reads the next TLS record from the connection and
    /// updates the record layer state."
    pub(crate) fn readRecord(&mut self) -> error {
        // Go: return c.readRecordOrCCS(false)
        return self.readRecordOrCCS(false);
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:592-594 Conn.readChangeCipherSpec
    pub(crate) fn readChangeCipherSpec(&mut self) -> error {
        // Go: return c.readRecordOrCCS(true)
        return self.readRecordOrCCS(true);
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:610-791 Conn.readRecordOrCCS
    /// Go: "readRecordOrCCS reads one or more TLS records from the
    /// connection and updates the record layer state. Some invariants:
    ///   * c.in must be locked
    ///   * c.input must be empty
    /// During the handshake one and only one of the following will happen:
    ///   - c.hand grows
    ///   - c.in.changeCipherSpec is called
    ///   - an error is returned
    /// After the handshake one and only one of the following will happen:
    ///   - c.hand grows
    ///   - c.input is set
    ///   - an error is returned"
    ///
    /// Deviations: the two `c.quic != nil` branches are absent (goish
    /// ships no QUIC transport); Go's `net.Error` temporary-error test
    /// around `readFromUntil` is absent, because goish's `net` exposes no
    /// `Error` interface — the error is always recorded, which is Go's
    /// behaviour for every non-temporary error; and the remote alert is
    /// stored directly rather than wrapped in a `*net.OpError{Op:
    /// "remote error"}`.
    pub(crate) fn readRecordOrCCS(&mut self, expectChangeCipherSpec: bool) -> error {
        // Go: if c.in.err != nil { return c.in.err }
        if self.in_.err != errors::nil {
            return self.in_.err.clone();
        }
        // Go: handshakeComplete := c.isHandshakeComplete.Load()
        let handshakeComplete = self.isHandshakeComplete;

        // Go: This function modifies c.rawInput, which owns the c.input memory.
        // Go: if c.input.Len() != 0 { return c.in.setErrorLocked(errors.New(
        //         "tls: internal error: attempted to read record with pending application data")) }
        //     c.input.Reset(nil)
        if crate::int(self.input.len()) - self.inputOff != 0 {
            return self.in_.setErrorLocked(errors::New(
                "tls: internal error: attempted to read record with pending application data",
            ));
        }
        self.input = Vec::new();
        self.inputOff = 0;

        // Go: Read header, payload.
        // Go: if err := c.readFromUntil(c.conn, recordHeaderLen); err != nil { … }
        let err = self.readFromUntil(recordHeaderLen);
        if err != errors::nil {
            // Go: RFC 8446, Section 6.1 suggests that EOF without an
            // alertCloseNotify is an error, but popular web sites seem to
            // do this, so we accept it if and only if at the record
            // boundary.
            let mut err = err;
            if err == crate::io::ErrUnexpectedEOF && self.rawInput.len() == 0 {
                err = crate::io::EOF.into();
            }
            self.in_.setErrorLocked(err.clone());
            return err;
        }
        // Go: hdr := c.rawInput.Bytes()[:recordHeaderLen]
        //     typ := recordType(hdr[0])
        let hdr = self.rawInput[..recordHeaderLen as usize].to_vec();
        let typ0 = recordType(hdr[0]);

        // Go: No valid TLS record has a type of 0x80, however SSLv2
        // handshakes start with a uint16 length where the MSB is set and
        // the first record is always < 256 bytes long. Therefore typ ==
        // 0x80 strongly suggests an SSLv2 client.
        if !handshakeComplete && typ0 == recordType(0x80) {
            self.sendAlert(super::alert::alertProtocolVersion);
            let e = self.newRecordHeaderError(string::from_static(
                "unsupported SSLv2 handshake received",
            ));
            return self.in_.setErrorLocked(crate::errors::Wrap(e));
        }

        // Go: vers := uint16(hdr[1])<<8 | uint16(hdr[2])
        //     expectedVers := c.vers
        //     if expectedVers == VersionTLS13 {
        //         // All TLS 1.3 records are expected to have 0x0303 (1.2) after
        //         // the initial hello (RFC 8446 Section 5.1).
        //         expectedVers = VersionTLS12 }
        //     n := int(hdr[3])<<8 | int(hdr[4])
        let vers = (crate::uint16(hdr[1]) << 8) | crate::uint16(hdr[2]);
        let mut expectedVers = self.vers;
        if expectedVers == VersionTLS13 {
            expectedVers = super::common::VersionTLS12;
        }
        let n = (crate::int(hdr[3]) << 8) | crate::int(hdr[4]);
        // Go: if c.haveVers && vers != expectedVers {
        //         c.sendAlert(alertProtocolVersion)
        //         msg := fmt.Sprintf("received record with version %x when expecting version %x", …)
        //         return c.in.setErrorLocked(c.newRecordHeaderError(nil, msg)) }
        if self.haveVers && vers != expectedVers {
            self.sendAlert(super::alert::alertProtocolVersion);
            let msg = crate::fmt::Sprintf!(
                "received record with version %x when expecting version %x",
                vers,
                expectedVers
            );
            let e = self.newRecordHeaderError(msg);
            return self.in_.setErrorLocked(crate::errors::Wrap(e));
        }
        // Go: if !c.haveVers {
        //         // First message, be extra suspicious: this might not be a TLS
        //         // client. Bail out before reading a full 'body', if possible.
        //         // The current max version is 3.3 so if the version is >= 16.0,
        //         // it's probably not real.
        //         if (typ != recordTypeAlert && typ != recordTypeHandshake) || vers >= 0x1000 {
        //             return c.in.setErrorLocked(c.newRecordHeaderError(c.conn,
        //                 "first record does not look like a TLS handshake")) } }
        if !self.haveVers {
            if (typ0 != super::common::recordTypeAlert
                && typ0 != super::common::recordTypeHandshake)
                || vers >= 0x1000
            {
                let e = self.newRecordHeaderError(string::from_static(
                    "first record does not look like a TLS handshake",
                ));
                return self.in_.setErrorLocked(crate::errors::Wrap(e));
            }
        }
        // Go: if c.vers == VersionTLS13 && n > maxCiphertextTLS13 || n > maxCiphertext {
        //         c.sendAlert(alertRecordOverflow)
        //         msg := fmt.Sprintf("oversized record received with length %d", n)
        //         return c.in.setErrorLocked(c.newRecordHeaderError(nil, msg)) }
        if (self.vers == VersionTLS13 && n > super::common::maxCiphertextTLS13)
            || n > super::common::maxCiphertext
        {
            self.sendAlert(alertRecordOverflow);
            let msg = crate::fmt::Sprintf!("oversized record received with length %d", n);
            let e = self.newRecordHeaderError(msg);
            return self.in_.setErrorLocked(crate::errors::Wrap(e));
        }
        // Go: if err := c.readFromUntil(c.conn, recordHeaderLen+n); err != nil { … }
        let err = self.readFromUntil(recordHeaderLen + n);
        if err != errors::nil {
            self.in_.setErrorLocked(err.clone());
            return err;
        }

        // Go: Process message.
        // Go: record := c.rawInput.Next(recordHeaderLen + n)
        //     data, typ, err := c.in.decrypt(record)
        //     if err != nil { return c.in.setErrorLocked(c.sendAlert(err.(alert))) }
        let take = (recordHeaderLen + n) as usize;
        let mut record = slice::__from_vec(self.rawInput[..take].to_vec());
        self.rawInput.drain(..take);
        let (data, typ, alertErr) = self.in_.decrypt(&mut record);
        if alertErr.is_some() {
            let e = self.sendAlert(alertErr.unwrap());
            return self.in_.setErrorLocked(e);
        }
        // Go: if len(data) > maxPlaintext {
        //         return c.in.setErrorLocked(c.sendAlert(alertRecordOverflow)) }
        if data.Len() > super::common::maxPlaintext {
            let e = self.sendAlert(alertRecordOverflow);
            return self.in_.setErrorLocked(e);
        }

        // Go: Application Data messages are always protected.
        if matches!(self.in_.cipher, halfConnCipher::None)
            && typ == super::common::recordTypeApplicationData
        {
            let e = self.sendAlert(alertUnexpectedMessage);
            return self.in_.setErrorLocked(e);
        }

        // Go: if typ != recordTypeAlert && typ != recordTypeChangeCipherSpec && len(data) > 0 {
        //         // This is a state-advancing message: reset the retry count.
        //         c.retryCount = 0 }
        if typ != super::common::recordTypeAlert
            && typ != super::common::recordTypeChangeCipherSpec
            && data.Len() > 0
        {
            self.retryCount = 0;
        }

        // Go: Handshake messages MUST NOT be interleaved with other record
        // types in TLS 1.3.
        if self.vers == VersionTLS13
            && typ != super::common::recordTypeHandshake
            && self.hand.len() > 0
        {
            let e = self.sendAlert(alertUnexpectedMessage);
            return self.in_.setErrorLocked(e);
        }

        // Go: switch typ { … }
        if typ == super::common::recordTypeAlert {
            // Go: if len(data) != 2 { return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage)) }
            if data.Len() != 2 {
                let e = self.sendAlert(alertUnexpectedMessage);
                return self.in_.setErrorLocked(e);
            }
            // Go: if alert(data[1]) == alertCloseNotify {
            //         return c.in.setErrorLocked(io.EOF) }
            if alert(data[1]) == super::alert::alertCloseNotify {
                return self.in_.setErrorLocked(crate::io::EOF.into());
            }
            if self.vers == VersionTLS13 {
                // Go: TLS 1.3 removed warning-level alerts except for
                // alertUserCanceled (RFC 8446, § 6.1). Since at least one
                // major implementation misuses this alert, many TLS stacks
                // now ignore it outright when seen in a TLS 1.3 handshake
                // (e.g. BoringSSL, NSS, Rustls).
                if alert(data[1]) == super::alert::alertUserCanceled {
                    // Go: Like TLS 1.2 alertLevelWarning alerts, we drop the
                    // record and retry.
                    return self.retryReadRecord(expectChangeCipherSpec);
                }
                return self
                    .in_
                    .setErrorLocked(crate::errors::Wrap(alert(data[1])));
            }
            // Go: switch data[0] {
            //     case alertLevelWarning: // Drop the record on the floor and retry.
            //         return c.retryReadRecord(expectChangeCipherSpec)
            //     case alertLevelError:
            //         return c.in.setErrorLocked(&net.OpError{Op: "remote error", Err: alert(data[1])})
            //     default: return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage)) }
            if crate::int(data[0]) == super::alert::alertLevelWarning {
                return self.retryReadRecord(expectChangeCipherSpec);
            }
            if crate::int(data[0]) == super::alert::alertLevelError {
                return self
                    .in_
                    .setErrorLocked(crate::errors::Wrap(alert(data[1])));
            }
            let e = self.sendAlert(alertUnexpectedMessage);
            return self.in_.setErrorLocked(e);
        }

        if typ == super::common::recordTypeChangeCipherSpec {
            // Go: if len(data) != 1 || data[0] != 1 {
            //         return c.in.setErrorLocked(c.sendAlert(alertDecodeError)) }
            if data.Len() != 1 || data[0] != 1 {
                let e = self.sendAlert(super::alert::alertDecodeError);
                return self.in_.setErrorLocked(e);
            }
            // Go: Handshake messages are not allowed to fragment across the CCS.
            if self.hand.len() > 0 {
                let e = self.sendAlert(alertUnexpectedMessage);
                return self.in_.setErrorLocked(e);
            }
            // Go: In TLS 1.3, change_cipher_spec records are ignored until
            // the Finished. See RFC 8446, Appendix D.4. Note that according
            // to Section 5, a server can send a ChangeCipherSpec before its
            // ServerHello, when c.vers is still unset. That's not useful
            // though and suspicious if the server then selects a lower
            // protocol version, so don't allow that.
            if self.vers == VersionTLS13 {
                return self.retryReadRecord(expectChangeCipherSpec);
            }
            if !expectChangeCipherSpec {
                let e = self.sendAlert(alertUnexpectedMessage);
                return self.in_.setErrorLocked(e);
            }
            let a = self.in_.changeCipherSpec();
            if a.is_some() {
                let e = self.sendAlert(a.unwrap());
                return self.in_.setErrorLocked(e);
            }
            return errors::nil;
        }

        if typ == super::common::recordTypeApplicationData {
            // Go: if !handshakeComplete || expectChangeCipherSpec {
            //         return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage)) }
            if !handshakeComplete || expectChangeCipherSpec {
                let e = self.sendAlert(alertUnexpectedMessage);
                return self.in_.setErrorLocked(e);
            }
            // Go: Some OpenSSL servers send empty records in order to
            // randomize the CBC IV. Ignore a limited number of empty records.
            if data.Len() == 0 {
                return self.retryReadRecord(expectChangeCipherSpec);
            }
            // Go: c.input.Reset(data)
            let raw: &[byte] = &data;
            self.input = raw.to_vec();
            self.inputOff = 0;
            return errors::nil;
        }

        if typ == super::common::recordTypeHandshake {
            // Go: if len(data) == 0 || expectChangeCipherSpec {
            //         return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage)) }
            //     c.hand.Write(data)
            if data.Len() == 0 || expectChangeCipherSpec {
                let e = self.sendAlert(alertUnexpectedMessage);
                return self.in_.setErrorLocked(e);
            }
            let raw: &[byte] = &data;
            self.hand.extend_from_slice(raw);
            return errors::nil;
        }

        // Go: default: return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
        let e = self.sendAlert(alertUnexpectedMessage);
        return self.in_.setErrorLocked(e);
    }
}


// go: none — goish-only: Go's `readFromUntil` takes an `io.Reader` and
// is handed `c.conn`, because `net.Conn` embeds `io.Reader`. goish's
// `net::Conn` declares `Read` itself rather than inheriting it, so the
// two traits are unrelated and the connection needs a one-method
// adapter.
struct connReader<'a> {
    c: &'a mut (dyn crate::net::Conn + 'a),
}

impl<'a> crate::io::Reader for connReader<'a> {
    // go: none — goish-only: see `connReader`.
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return self.c.Read(p);
    }
}


// go: none — goish-only: the in-memory net::Conn `__setFeedConn`
// installs. Returns EOF once drained, as a socket at end of stream does.
struct feedConn {
    r: Vec<byte>,
    at: usize,
    /// When set, writes are recorded here instead of discarded, so a
    /// read-path test can also see the alert the failure sent.
    sink: Option<alloc::sync::Arc<crate::sync::Mutex<slice<byte>>>>,
}

impl crate::net::Conn for feedConn {
    // go: none — goish-only: see `feedConn`.
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if self.at >= self.r.len() {
            return (0, crate::io::EOF.into());
        }
        let want = p.Len() as usize;
        let n = core::cmp::min(want, self.r.len() - self.at);
        let mut i = 0usize;
        while i < n {
            p[i] = self.r[self.at + i];
            i += 1;
        }
        self.at += n;
        return (crate::int(n), errors::nil);
    }
    // go: none — goish-only: see `feedConn`.
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        if let Some(sink) = self.sink.as_ref() {
            let raw: &[byte] = &p;
            let mut g = sink.Lock();
            let mut v = g.clone().__into_vec();
            v.extend_from_slice(raw);
            *g = slice::__from_vec(v);
        }
        return (p.Len(), errors::nil);
    }
    // go: none — goish-only: see `feedConn`.
    fn Close(&mut self) -> error { return errors::nil; }
    // go: none — goish-only: see `feedConn`.
    fn LocalAddr(&self) -> crate::net::TCPAddr {
        return crate::net::TCPAddr { IP: [0, 0, 0, 0], Port: 0 };
    }
    // go: none — goish-only: see `feedConn`.
    fn RemoteAddr(&self) -> crate::net::TCPAddr {
        return crate::net::TCPAddr { IP: [0, 0, 0, 0], Port: 0 };
    }
    // go: none — goish-only: see `feedConn`.
    fn SetDeadline(&self, _t: crate::time::Time) -> error { return errors::nil; }
    // go: none — goish-only: see `feedConn`.
    fn SetReadDeadline(&self, _t: crate::time::Time) -> error { return errors::nil; }
    // go: none — goish-only: see `feedConn`.
    fn SetWriteDeadline(&self, _t: crate::time::Time) -> error { return errors::nil; }
}

crate::var! {
    /// Go: `var errEarlyCloseWrite = errors.New(…)`
    pub(crate) errEarlyCloseWrite: error = "tls: CloseWrite called before handshake complete";
    /// Go: `var errShutdown = errors.New(…)`
    pub(crate) errShutdown: error = "tls: protocol is shutdown";
}

impl Conn {
    // go: sdk 1.25.5 crypto/tls/conn.go:1470-1483 Conn.closeNotify
    /// Go: "closeNotify closes the Write side of the connection by
    /// sending a close notify record."
    pub(crate) fn closeNotify(&mut self) -> error {
        // Go: if !c.closeNotifySent {
        //         // Set a Write Deadline to prevent possibly blocking forever.
        //         c.SetWriteDeadline(time.Now().Add(time.Second * 5))
        //         c.closeNotifyErr = c.sendAlertLocked(alertCloseNotify)
        //         c.closeNotifySent = true
        //         // Any subsequent writes will fail.
        //         c.SetWriteDeadline(time.Now()) }
        //     return c.closeNotifyErr
        if !self.closeNotifySent {
            self.SetWriteDeadline(crate::time::Now().Add(crate::time::Second * 5));
            self.closeNotifyErr = self.sendAlertLocked(super::alert::alertCloseNotify);
            self.closeNotifySent = true;
            self.SetWriteDeadline(crate::time::Now());
        }
        return self.closeNotifyErr.clone();
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:1462-1468 Conn.CloseWrite
    /// Go: "CloseWrite shuts down the writing side of the connection. It
    /// should only be called once the handshake has completed and does
    /// not call CloseWrite on the underlying connection. Most callers
    /// should just use Close."
    pub fn CloseWrite(&mut self) -> error {
        // Go: if !c.isHandshakeComplete.Load() { return errEarlyCloseWrite }
        //     return c.closeNotify()
        if !self.isHandshakeComplete {
            return errEarlyCloseWrite.into();
        }
        return self.closeNotify();
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:1080-1090 Conn.readHandshakeBytes
    ///
    /// Deviation: the `c.quic != nil` branch is absent — goish ships no
    /// QUIC transport.
    pub(crate) fn readHandshakeBytes(&mut self, n: int) -> error {
        // Go: for c.hand.Len() < n {
        //         if err := c.readRecord(); err != nil { return err } }
        //     return nil
        while crate::int(self.hand.len()) < n {
            let err = self.readRecord();
            if err != errors::nil {
                return err;
            }
        }
        return errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:1055-1068 Conn.writeHandshakeRecord
    /// Go: marshal one handshake message, feed the transcript hash if
    /// one was passed, and write it out as a handshake record.
    ///
    /// Deviation: `c.out.Lock()`/`Unlock` are absent — `&mut self` is
    /// the lock, as everywhere else on the write path.
    pub(crate) fn writeHandshakeRecord(
        &mut self,
        msg: &dyn super::common::handshakeMessage,
        transcript: Option<&mut dyn super::handshake_messages::transcriptHash>,
    ) -> (int, error) {
        // Go: data, err := msg.marshal(); if err != nil { return 0, err }
        let (data, err) = msg.marshal();
        if err != errors::nil {
            return (0, err);
        }
        // Go: if transcript != nil { transcript.Write(data) }
        if let Some(t) = transcript {
            t.Write(data.clone());
        }
        // Go: return c.writeRecordLocked(recordTypeHandshake, data)
        return self.writeRecordLocked(super::common::recordTypeHandshake, data);
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:1335-1370 Conn.handleKeyUpdate
    /// Go: rotate the read traffic secret, and if the peer asked for it,
    /// send our own KeyUpdate and rotate the write secret too.
    ///
    /// Deviations: the `c.quic != nil` arm is absent — goish ships no
    /// QUIC transport — and `c.out.Lock()`/`Unlock` are elided as above.
    pub(crate) fn handleKeyUpdate(
        &mut self,
        keyUpdate: &super::handshake_messages::keyUpdateMsg,
    ) -> error {
        // Go: cipherSuite := cipherSuiteTLS13ByID(c.cipherSuite)
        //     if cipherSuite == nil {
        //         return c.in.setErrorLocked(c.sendAlert(alertInternalError)) }
        let cipherSuite = match super::cipher_suites::cipherSuiteTLS13ByID(self.cipherSuite) {
            Some(cs) => cs,
            None => {
                let a = self.sendAlert(alertInternalError);
                return self.in_.setErrorLocked(a);
            }
        };

        // Go: newSecret := cipherSuite.nextTrafficSecret(c.in.trafficSecret)
        //     c.in.setTrafficSecret(cipherSuite, QUICEncryptionLevelInitial, newSecret)
        let newSecret = cipherSuite.nextTrafficSecret(self.in_.trafficSecret.clone());
        self.in_
            .setTrafficSecret(cipherSuite, super::quic::QUICEncryptionLevelInitial, newSecret);

        // Go: if keyUpdate.updateRequested { … }
        if keyUpdate.updateRequested {
            // Go: msg := &keyUpdateMsg{}
            //     msgBytes, err := msg.marshal(); if err != nil { return err }
            let msg = super::handshake_messages::keyUpdateMsg::default();
            let (msgBytes, err) = msg.marshal();
            if err != errors::nil {
                return err;
            }
            // Go: _, err = c.writeRecordLocked(recordTypeHandshake, msgBytes)
            let (_, err) = self.writeRecordLocked(super::common::recordTypeHandshake, msgBytes);
            if err != errors::nil {
                // Go: "Surface the error at the next write."
                self.out.setErrorLocked(err);
                return errors::nil;
            }

            // Go: newSecret := cipherSuite.nextTrafficSecret(c.out.trafficSecret)
            //     c.out.setTrafficSecret(cipherSuite, QUICEncryptionLevelInitial, newSecret)
            let newSecret = cipherSuite.nextTrafficSecret(self.out.trafficSecret.clone());
            self.out.setTrafficSecret(
                cipherSuite,
                super::quic::QUICEncryptionLevelInitial,
                newSecret,
            );
        }

        // Go: return nil
        return errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:1095-1122 Conn.readHandshake
    /// Go: read one complete handshake message off `c.hand`, refilling
    /// it from the record layer as needed, and unmarshal it.
    ///
    /// Deviations: Go returns `any` so the caller can type-assert to a
    /// concrete message; goish returns `Box<dyn handshakeMessage>`,
    /// whose `asAny` recovers the same thing. `c.hand` is a `Vec<byte>`
    /// rather than a `bytes.Buffer`, so `Bytes()`/`Next(n)` become a
    /// borrow and a `drain`.
    pub(crate) fn readHandshake(
        &mut self,
        transcript: Option<&mut dyn super::handshake_messages::transcriptHash>,
    ) -> (Option<Box<dyn super::common::handshakeMessage>>, error) {
        // Go: if err := c.readHandshakeBytes(4); err != nil { return nil, err }
        let err = self.readHandshakeBytes(4);
        if err != errors::nil {
            return (None, err);
        }
        // Go: data := c.hand.Bytes()
        let data: &[byte] = &self.hand;

        // Go: maxHandshakeSize := maxHandshake
        let mut maxHandshakeSize = super::common::maxHandshake;
        // Go: "hasVers indicates we're past the first message, forcing
        // someone trying to make us just allocate a large buffer to at
        // least do the initial part of the handshake first."
        if self.haveVers && data[0] == super::handshake_messages::typeCertificate {
            // Go: "Since certificate messages are likely to be the only
            // messages that can be larger than maxHandshake, we use a
            // special limit for just those messages."
            maxHandshakeSize = super::common::maxHandshakeCertificateMsg;
        }

        // Go: n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
        let n = crate::int(data[1]) << 16 | crate::int(data[2]) << 8 | crate::int(data[3]);
        if n > maxHandshakeSize {
            self.sendAlertLocked(alertInternalError);
            // Go: return nil, c.in.setErrorLocked(fmt.Errorf("tls: handshake
            //     message of length %d bytes exceeds maximum of %d bytes", …))
            let e = crate::fmt::Errorf!(
                "tls: handshake message of length %d bytes exceeds maximum of %d bytes",
                n,
                maxHandshakeSize
            );
            let e = self.in_.setErrorLocked(e);
            return (None, e);
        }
        // Go: if err := c.readHandshakeBytes(4 + n); err != nil { return nil, err }
        let err = self.readHandshakeBytes(4 + n);
        if err != errors::nil {
            return (None, err);
        }
        // Go: data = c.hand.Next(4 + n)
        let taken: Vec<byte> = self.hand.drain(..usize::try_from(4 + n).unwrap_or(0)).collect();
        // Go: return c.unmarshalHandshakeMessage(data, transcript)
        return self.unmarshalHandshakeMessage(slice::__from_vec(taken), transcript);
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:1124-1191 Conn.unmarshalHandshakeMessage
    /// Go: pick the concrete message type from the first byte — the
    /// choice depends on `c.vers` for the four types whose shape
    /// changed in TLS 1.3 — then unmarshal into it and, if a transcript
    /// hash was passed, feed it the raw bytes.
    pub(crate) fn unmarshalHandshakeMessage(
        &mut self,
        data: slice<byte>,
        transcript: Option<&mut dyn super::handshake_messages::transcriptHash>,
    ) -> (Option<Box<dyn super::common::handshakeMessage>>, error) {
        use super::handshake_messages as hm;
        // Go: var m handshakeMessage; switch data[0] { … }
        let mut m: Box<dyn super::common::handshakeMessage> = match data[0] {
            hm::typeHelloRequest => Box::new(hm::helloRequestMsg::default()),
            hm::typeClientHello => Box::new(hm::clientHelloMsg::default()),
            hm::typeServerHello => Box::new(hm::serverHelloMsg::default()),
            hm::typeNewSessionTicket => {
                if self.vers == VersionTLS13 {
                    Box::new(hm::newSessionTicketMsgTLS13::default())
                } else {
                    Box::new(hm::newSessionTicketMsg::default())
                }
            }
            hm::typeCertificate => {
                if self.vers == VersionTLS13 {
                    Box::new(hm::certificateMsgTLS13::default())
                } else {
                    Box::new(hm::certificateMsg::default())
                }
            }
            hm::typeCertificateRequest => {
                if self.vers == VersionTLS13 {
                    Box::new(hm::certificateRequestMsgTLS13::default())
                } else {
                    // Go: &certificateRequestMsg{hasSignatureAlgorithm: c.vers >= VersionTLS12}
                    Box::new(hm::certificateRequestMsg {
                        hasSignatureAlgorithm: self.vers >= VersionTLS12,
                        ..Default::default()
                    })
                }
            }
            hm::typeCertificateStatus => Box::new(hm::certificateStatusMsg::default()),
            hm::typeServerKeyExchange => Box::new(hm::serverKeyExchangeMsg::default()),
            hm::typeServerHelloDone => Box::new(hm::serverHelloDoneMsg::default()),
            hm::typeClientKeyExchange => Box::new(hm::clientKeyExchangeMsg::default()),
            hm::typeCertificateVerify => {
                // Go: &certificateVerifyMsg{hasSignatureAlgorithm: c.vers >= VersionTLS12}
                Box::new(hm::certificateVerifyMsg {
                    hasSignatureAlgorithm: self.vers >= VersionTLS12,
                    ..Default::default()
                })
            }
            hm::typeFinished => Box::new(hm::finishedMsg::default()),
            hm::typeEncryptedExtensions => Box::new(hm::encryptedExtensionsMsg::default()),
            hm::typeEndOfEarlyData => Box::new(hm::endOfEarlyDataMsg::default()),
            hm::typeKeyUpdate => Box::new(hm::keyUpdateMsg::default()),
            // Go: default: return nil, c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
            _ => {
                let a = self.sendAlert(alertUnexpectedMessage);
                let e = self.in_.setErrorLocked(a);
                return (None, e);
            }
        };

        // Go: "The handshake message unmarshalers expect to be able to
        // keep references to data, so pass in a fresh copy that won't be
        // overwritten."  Go: data = append([]byte(nil), data...)
        let data: slice<byte> = slice::__from_vec(data.to_vec());

        // Go: if !m.unmarshal(data) {
        //         return nil, c.in.setErrorLocked(c.sendAlert(alertDecodeError)) }
        if !m.unmarshal(data.clone()) {
            let a = self.sendAlert(super::alert::alertDecodeError);
            let e = self.in_.setErrorLocked(a);
            return (None, e);
        }

        // Go: if transcript != nil { transcript.Write(data) }
        if let Some(t) = transcript {
            t.Write(data);
        }

        // Go: return m, nil
        return (Some(m), errors::nil);
    }

}


// go: none — goish-only: Go's `cipherSuite.cipher` returns `any`, and
// `halfConn.cipher` is the same `any` — the record layer asserts it back
// to `cipher.Stream` or `cbcMode`. goish spells the producer's set as
// `anyCipher` and the consumer's as `halfConnCipher`, so the two need
// bridging. Same two cases, and `anyCipher` carries `cbcMode` rather
// than `cipher::BlockMode` precisely so `SetIV` survives the trip.
pub(crate) fn halfConnCipherOf(c: super::cipher_suites::anyCipher) -> halfConnCipher {
    match c {
        super::cipher_suites::anyCipher::Stream(s) => return halfConnCipher::Stream(s),
        super::cipher_suites::anyCipher::BlockMode(m) => return halfConnCipher::CBC(m),
    };
}

impl Conn {
    // go: sdk 1.25.5 crypto/tls/conn.go:1498-1500 Conn.Handshake
    /// Go: run the client or server handshake if it has not yet run.
    /// Reference: the RSA-key-size cap note is enforced downstream in
    /// processCertsFromClient / verifyServerCertificate.
    pub fn Handshake(&mut self) -> error {
        // Go: return c.HandshakeContext(context.Background())
        return self.HandshakeContext();
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:1512-1516 Conn.HandshakeContext
    /// Go: run the handshake if it has not yet run. goish drops the
    /// `ctx context.Context` — there is no cancellation plumbing — so
    /// this simply delegates.
    pub fn HandshakeContext(&mut self) -> error {
        // Go: return c.handshakeContext(ctx)
        return self.handshakeContext();
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:1518-1616 Conn.handshakeContext
    /// Go: the handshake body — fast-path if already complete, run the
    /// client or server handshake, bump the handshake count on success
    /// or flush a pending alert on failure, and enforce the
    /// result/complete invariants.
    ///
    /// Deviations: Go's `ctx` interrupter goroutine (which closes the
    /// conn on context cancellation) is absent — goish has no context
    /// cancellation; `handshakeMutex` and `c.in.Lock()` are gone —
    /// `&mut self` gives the same exclusion; the whole `c.quic != nil`
    /// tail is absent — goish ships no QUIC transport; and `handshakeFn`
    /// is not a field, so the client/server split is dispatched on
    /// `c.isClient`.
    pub(crate) fn handshakeContext(&mut self) -> error {
        // Go: "Fast sync/atomic-based exit […]"
        //     if c.isHandshakeComplete.Load() { return nil }
        if self.isHandshakeComplete {
            return errors::nil;
        }

        // Go: if err := c.handshakeErr; err != nil { return err }
        if self.handshakeErr != errors::nil {
            return self.handshakeErr.clone();
        }
        // Go: if c.isHandshakeComplete.Load() { return nil }
        if self.isHandshakeComplete {
            return errors::nil;
        }

        // Go: c.handshakeErr = c.handshakeFn(handshakeCtx)
        let e = if self.isClient {
            self.clientHandshake()
        } else {
            self.serverHandshake()
        };
        self.handshakeErr = e;
        // Go: if c.handshakeErr == nil { c.handshakes++ } else { c.flush() }
        if self.handshakeErr == errors::nil {
            self.handshakes += 1;
        } else {
            // Go: "If an error occurred during the handshake try to
            // flush the alert that might be left in the buffer."
            self.flush();
        }

        // Go: if c.handshakeErr == nil && !c.isHandshakeComplete.Load() {
        //         c.handshakeErr = errors.New("tls: internal error: handshake should have had a result") }
        if self.handshakeErr == errors::nil && !self.isHandshakeComplete {
            self.handshakeErr = errors::New(
                "tls: internal error: handshake should have had a result",
            );
        }
        // Go: if c.handshakeErr != nil && c.isHandshakeComplete.Load() {
        //         panic("tls: internal error: handshake returned an error but is marked successful") }
        if self.handshakeErr != errors::nil && self.isHandshakeComplete {
            panic!(
                "tls: internal error: handshake returned an error but is marked successful"
            );
        }

        // Go: the `c.quic != nil` tail is absent — goish ships no QUIC
        // transport.

        // Go: return c.handshakeErr
        return self.handshakeErr.clone();
    }

    // go: sdk 1.25.5 crypto/tls/conn.go:1260-1302 Conn.handleRenegotiation
    /// Go: process a HelloRequest — only a client may renegotiate, and
    /// only within the policy `Config.Renegotiation` allows; TLS 1.3
    /// forbids it entirely.
    ///
    /// Deviation: `handshakeMutex` is absent (`&mut self` gives the
    /// exclusion), and `clientHandshake` takes no context.
    pub(crate) fn handleRenegotiation(&mut self) -> error {
        // Go: if c.vers == VersionTLS13 {
        //         return errors.New("tls: internal error: unexpected renegotiation") }
        if self.vers == super::common::VersionTLS13 {
            return errors::New("tls: internal error: unexpected renegotiation");
        }

        // Go: msg, err := c.readHandshake(nil)
        //     if err != nil { return err }
        let (msg, err) = self.readHandshake(None);
        if err != errors::nil {
            return err;
        }
        // Go: helloReq, ok := msg.(*helloRequestMsg)
        //     if !ok { c.sendAlert(alertUnexpectedMessage)
        //         return unexpectedMessageError(helloReq, msg) }
        let msg = match msg {
            Some(m) => m,
            None => return errors::New("tls: internal error: no handshake message"),
        };
        if msg
            .asAny()
            .downcast_ref::<super::handshake_messages::helloRequestMsg>()
            .is_none()
        {
            self.sendAlert(super::alert::alertUnexpectedMessage);
            return super::common::unexpectedMessageError(
                crate::gostring::string::from_static("*tls.helloRequestMsg"),
                super::handshake_messages::handshakeMessageTypeName(&*msg),
            );
        }

        // Go: if !c.isClient { return c.sendAlert(alertNoRenegotiation) }
        if !self.isClient {
            return self.sendAlert(super::alert::alertNoRenegotiation);
        }

        // Go: switch c.config.Renegotiation {
        //     case RenegotiateNever: return c.sendAlert(alertNoRenegotiation)
        //     case RenegotiateOnceAsClient: if c.handshakes > 1 { return c.sendAlert(alertNoRenegotiation) }
        //     case RenegotiateFreelyAsClient: // Ok.
        //     default: c.sendAlert(alertInternalError)
        //         return errors.New("tls: unknown Renegotiation value") }
        let reneg = self.config.Renegotiation;
        if reneg == super::common::RenegotiateNever {
            return self.sendAlert(super::alert::alertNoRenegotiation);
        } else if reneg == super::common::RenegotiateOnceAsClient {
            if self.handshakes > 1 {
                return self.sendAlert(super::alert::alertNoRenegotiation);
            }
        } else if reneg == super::common::RenegotiateFreelyAsClient {
            // Ok.
        } else {
            self.sendAlert(super::alert::alertInternalError);
            return errors::New("tls: unknown Renegotiation value");
        }

        // Go: (handshakeMutex omitted)
        //     c.isHandshakeComplete.Store(false)
        //     if c.handshakeErr = c.clientHandshake(context.Background()); c.handshakeErr == nil {
        //         c.handshakes++ }
        //     return c.handshakeErr
        self.isHandshakeComplete = false;
        let e = self.clientHandshake();
        self.handshakeErr = e;
        if self.handshakeErr == errors::nil {
            self.handshakes += 1;
        }
        return self.handshakeErr.clone();
    }
}

impl Conn {
    // go: sdk 1.25.5 crypto/tls/conn.go:1306-1333 Conn.handlePostHandshakeMessage
    /// Go: dispatch a handshake message that arrives after the
    /// handshake — a renegotiation HelloRequest in TLS 1.2, or a
    /// NewSessionTicket or KeyUpdate in TLS 1.3 — and bound the number
    /// of non-advancing records.
    ///
    /// Deviation: the RFC 9001 QUIC note is retained as commentary only;
    /// goish ships no QUIC transport.
    pub(crate) fn handlePostHandshakeMessage(&mut self) -> error {
        // Go: if c.vers != VersionTLS13 { return c.handleRenegotiation() }
        if self.vers != super::common::VersionTLS13 {
            return self.handleRenegotiation();
        }

        // Go: msg, err := c.readHandshake(nil)
        //     if err != nil { return err }
        let (msg, err) = self.readHandshake(None);
        if err != errors::nil {
            return err;
        }
        // Go: c.retryCount++
        //     if c.retryCount > maxUselessRecords {
        //         c.sendAlert(alertUnexpectedMessage)
        //         return c.in.setErrorLocked(errors.New("tls: too many non-advancing records")) }
        self.retryCount += 1;
        if self.retryCount > super::common::maxUselessRecords {
            self.sendAlert(super::alert::alertUnexpectedMessage);
            let e = errors::New("tls: too many non-advancing records");
            return self.in_.setErrorLocked(e);
        }

        let msg = match msg {
            Some(m) => m,
            None => return errors::New("tls: internal error: no handshake message"),
        };
        // Go: switch msg := msg.(type) {
        //     case *newSessionTicketMsgTLS13: return c.handleNewSessionTicket(msg)
        //     case *keyUpdateMsg: return c.handleKeyUpdate(msg) }
        if let Some(nst) = msg
            .asAny()
            .downcast_ref::<super::handshake_messages::newSessionTicketMsgTLS13>()
        {
            return self.handleNewSessionTicket(nst);
        }
        if let Some(ku) = msg
            .asAny()
            .downcast_ref::<super::handshake_messages::keyUpdateMsg>()
        {
            let ku = ku.clone();
            return self.handleKeyUpdate(&ku);
        }

        // Go: "The QUIC layer is supposed to treat an unexpected
        // post-handshake CertificateRequest as a QUIC-level
        // PROTOCOL_VIOLATION error […]"
        //     c.sendAlert(alertUnexpectedMessage)
        //     return fmt.Errorf("tls: received unexpected handshake message of type %T", msg)
        self.sendAlert(super::alert::alertUnexpectedMessage);
        return crate::fmt::Errorf!(
            "tls: received unexpected handshake message of type %s",
            super::handshake_messages::handshakeMessageTypeName(&*msg)
        );
    }
}
