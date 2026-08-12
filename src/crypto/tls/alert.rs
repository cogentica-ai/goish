// go: file crypto/tls/alert.go decls: AlertError.Error, alert.String, alert.Error
//
// crypto/tls — TLS alert codes (RFC 8446 §6, RFC 5246 §7.2).
//
// Deviations from alert[go] @ Go 1.25.5:
//
//   * Go's `alertText` is a package-level `map[alert]string`. goish has
//     no const map, so the table is a `match` in `String()`. Same
//     entries, same order as Go's literal, and the fallback arm is
//     Go's `"tls: alert(" + strconv.Itoa(int(e)) + ")"` verbatim — a
//     map lookup miss and a match fall-through are the same thing here.
//     goishlint:ignore GOISH021 alertText — the map is a match arm; see above
//   * `alert` and `AlertError` are newtypes over `uint8` rather than Go
//     `type alert uint8`, so that `From`/`PartialEq` can be derived.
//     Go's implicit conversion `alert(e)` in `AlertError.Error` is
//     spelled `alert(e.0)`.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::errors::ErrorTrait;
use crate::gostring::string;
use crate::strconv;
use crate::int;
use crate::types::uint8;

// Go: alert.go:19
//   type alert uint8
/// A TLS alert code.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct alert(pub uint8);

// Go: alert.go:13
//   type AlertError uint8
/// `tls.AlertError` — a TLS alert surfaced as an error.
///
/// When using a QUIC transport, `QUICConn` methods return an error
/// wrapping `AlertError` rather than sending a TLS alert.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct AlertError(pub uint8);

// Go: alert.go:21-25
//   const ( alertLevelWarning = 1; alertLevelError = 2 )
/// Alert level: warning.
pub const alertLevelWarning: int = 1;
/// Alert level: fatal.
pub const alertLevelError: int = 2;

// Go: alert.go:27-61 — the alert codes, in Go's declaration order.
pub const alertCloseNotify: alert = alert(0);
pub const alertUnexpectedMessage: alert = alert(10);
pub const alertBadRecordMAC: alert = alert(20);
pub const alertDecryptionFailed: alert = alert(21);
pub const alertRecordOverflow: alert = alert(22);
pub const alertDecompressionFailure: alert = alert(30);
pub const alertHandshakeFailure: alert = alert(40);
pub const alertBadCertificate: alert = alert(42);
pub const alertUnsupportedCertificate: alert = alert(43);
pub const alertCertificateRevoked: alert = alert(44);
pub const alertCertificateExpired: alert = alert(45);
pub const alertCertificateUnknown: alert = alert(46);
pub const alertIllegalParameter: alert = alert(47);
pub const alertUnknownCA: alert = alert(48);
pub const alertAccessDenied: alert = alert(49);
pub const alertDecodeError: alert = alert(50);
pub const alertDecryptError: alert = alert(51);
pub const alertExportRestriction: alert = alert(60);
pub const alertProtocolVersion: alert = alert(70);
pub const alertInsufficientSecurity: alert = alert(71);
pub const alertInternalError: alert = alert(80);
pub const alertInappropriateFallback: alert = alert(86);
pub const alertUserCanceled: alert = alert(90);
pub const alertNoRenegotiation: alert = alert(100);
pub const alertMissingExtension: alert = alert(109);
pub const alertUnsupportedExtension: alert = alert(110);
pub const alertCertificateUnobtainable: alert = alert(111);
pub const alertUnrecognizedName: alert = alert(112);
pub const alertBadCertificateStatusResponse: alert = alert(113);
pub const alertBadCertificateHashValue: alert = alert(114);
pub const alertUnknownPSKIdentity: alert = alert(115);
pub const alertCertificateRequired: alert = alert(116);
pub const alertNoApplicationProtocol: alert = alert(120);
pub const alertECHRequired: alert = alert(121);

impl alert {
    // go: sdk 1.25.5 crypto/tls/alert.go:101-107 alert.String
    /// Go: `s, ok := alertText[e]; if ok { return "tls: " + s }` and
    /// otherwise `"tls: alert(" + strconv.Itoa(int(e)) + ")"`.
    pub fn String(&self) -> string {
        // Go: alertText — see the deviation note at the head of this file.
        let s: Option<&'static str> = match *self {
            alertCloseNotify => Some("close notify"),
            alertUnexpectedMessage => Some("unexpected message"),
            alertBadRecordMAC => Some("bad record MAC"),
            alertDecryptionFailed => Some("decryption failed"),
            alertRecordOverflow => Some("record overflow"),
            alertDecompressionFailure => Some("decompression failure"),
            alertHandshakeFailure => Some("handshake failure"),
            alertBadCertificate => Some("bad certificate"),
            alertUnsupportedCertificate => Some("unsupported certificate"),
            alertCertificateRevoked => Some("revoked certificate"),
            alertCertificateExpired => Some("expired certificate"),
            alertCertificateUnknown => Some("unknown certificate"),
            alertIllegalParameter => Some("illegal parameter"),
            alertUnknownCA => Some("unknown certificate authority"),
            alertAccessDenied => Some("access denied"),
            alertDecodeError => Some("error decoding message"),
            alertDecryptError => Some("error decrypting message"),
            alertExportRestriction => Some("export restriction"),
            alertProtocolVersion => Some("protocol version not supported"),
            alertInsufficientSecurity => Some("insufficient security level"),
            alertInternalError => Some("internal error"),
            alertInappropriateFallback => Some("inappropriate fallback"),
            alertUserCanceled => Some("user canceled"),
            alertNoRenegotiation => Some("no renegotiation"),
            alertMissingExtension => Some("missing extension"),
            alertUnsupportedExtension => Some("unsupported extension"),
            alertCertificateUnobtainable => Some("certificate unobtainable"),
            alertUnrecognizedName => Some("unrecognized name"),
            alertBadCertificateStatusResponse => Some("bad certificate status response"),
            alertBadCertificateHashValue => Some("bad certificate hash value"),
            alertUnknownPSKIdentity => Some("unknown PSK identity"),
            alertCertificateRequired => Some("certificate required"),
            alertNoApplicationProtocol => Some("no application protocol"),
            alertECHRequired => Some("encrypted client hello required"),
            _ => None,
        };
        // Go: if ok { return "tls: " + s }
        if let Some(s) = s {
            return string::from_static("tls: ") + string::from_static(s);
        }
        // Go: return "tls: alert(" + strconv.Itoa(int(e)) + ")"
        return string::from_static("tls: alert(")
            + strconv::Itoa(int(self.0))
            + string::from_static(")");
    }

    // go: sdk 1.25.5 crypto/tls/alert.go:109-111 alert.Error
    /// Go: `func (e alert) Error() string { return e.String() }`
    pub fn Error(&self) -> string {
        return self.String();
    }
}

impl ErrorTrait for alert {
    // go: none — goish idiom: Go's `alert` satisfies `error` by having
    // an `Error() string` method; goish needs the trait impl spelled.
    fn Error(&self) -> string {
        return alert::Error(self);
    }
}

impl AlertError {
    // go: sdk 1.25.5 crypto/tls/alert.go:15-17 AlertError.Error
    /// Go: `func (e AlertError) Error() string { return alert(e).String() }`
    pub fn Error(&self) -> string {
        // Go: alert(e).String()
        return alert(self.0).String();
    }
}

impl ErrorTrait for AlertError {
    // go: none — goish idiom: see `impl ErrorTrait for alert`.
    fn Error(&self) -> string {
        return AlertError::Error(self);
    }
}
