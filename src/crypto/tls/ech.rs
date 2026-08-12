// go: file crypto/tls/ech.go decls: echConfigErr.Error, parseECHConfig, parseECHConfigList, skipUint8LengthPrefixed, skipUint16LengthPrefixed, validDNSName, ECHRejectionError.Error, parseECHExt, marshalEncryptedClientHelloConfigList, generateOuterECHExt, pickECHCipherSuite, pickECHConfig, extractRawExtensions, encodeInnerClientHello, decodeInnerClientHello, decryptECHPayload, buildRetryConfigList
//
// crypto/tls — Encrypted Client Hello (draft-ietf-tls-esni), config
// parsing.
//
// **Partial port.** ech.go is 668 lines; what is here is the ECHConfig
// wire parser, which depends on nothing but cryptobyte. The rest —
// pickECHConfig, encodeInnerClientHello, the HPKE sealing and the
// retry-config path — hangs on the ClientHello types and the handshake
// state machine. goish ships no ECH support, so nothing here is wired
// into a handshake; it is the parser Go's own tests drive directly.
//
// goishlint:ignore GOISH018 computeAndUpdateOuterECHExtension, decryptECHExtension, encodeOuterExtensions, init, processECHClientHello, sendECHRetryConfigs — the ClientHello-dependent half; see the banner. ROADMAP.md.
// goishlint:ignore GOISH019 echExtension, echConfig, echCipher, echConfigErr, echContext, echServerContext, echClientContext — the parser's shapes are here; the handshake-side ones are not.
// goishlint:ignore GOISH021 echAcceptConfirmationLabel, echClientContext, echContext, echHRRAcceptConfirmationLabel, echServerContext, errIllegalECHExt, errMalformedECHConfigList, sortedSupportedAEADs — same.

#![allow(non_snake_case, dead_code)]

extern crate alloc;
use alloc::vec::Vec;

use super::common::extensionEncryptedClientHello;
use crate::crypto::cryptobyte::String as CBString;
use crate::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, uint16, uint8};

// Go: ech.go — `type echCipher struct { KDFID, AEADID uint16 }`
/// An HPKE symmetric cipher suite offered by an ECHConfig.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub(crate) struct echCipher {
    pub KDFID: uint16,
    pub AEADID: uint16,
}

// Go: ech.go — `type echExtension struct { Type uint16; Data []byte }`
/// An unrecognised ECHConfig extension, kept verbatim.
#[derive(Clone, Default, PartialEq)]
pub(crate) struct echExtension {
    pub Type: uint16,
    pub Data: slice<byte>,
}

// Go: ech.go — `type echConfig struct { … }`
/// A parsed ECHConfig.
#[derive(Clone, Default, PartialEq)]
pub(crate) struct echConfig {
    pub raw: slice<byte>,

    pub Version: uint16,
    pub Length: uint16,

    pub ConfigID: uint8,
    pub KemID: uint16,
    pub PublicKey: slice<byte>,
    pub SymmetricCipherSuite: slice<echCipher>,

    pub MaxNameLength: uint8,
    pub PublicName: slice<byte>,
    pub Extensions: slice<echExtension>,
}

// Go: ech.go — `type echConfigErr struct { field string }`
/// A malformed-ECHConfig error naming the field that failed.
#[derive(Clone, Default, PartialEq)]
pub(crate) struct echConfigErr {
    pub field: string,
}

impl echConfigErr {
    // go: sdk 1.25.5 crypto/tls/ech.go:66-71 echConfigErr.Error
    /// Go: `"tls: malformed ECHConfig"`, or `"…, invalid %s field"`.
    pub(crate) fn Error(&self) -> string {
        // Go: if e.field == "" { return "tls: malformed ECHConfig" }
        if self.field == string::from_static("") {
            return string::from_static("tls: malformed ECHConfig");
        }
        // Go: return fmt.Sprintf("tls: malformed ECHConfig, invalid %s field", e.field)
        return crate::fmt::Sprintf!(
            "tls: malformed ECHConfig, invalid %s field",
            self.field.clone()
        );
    }
}

impl crate::errors::ErrorTrait for echConfigErr {
    // go: none — goish idiom: Go's *echConfigErr satisfies `error` by
    // having an `Error() string` method; goish needs the impl spelled.
    fn Error(&self) -> string {
        return echConfigErr::Error(self);
    }
}

// go: none — goish idiom: Go writes `&echConfigErr{"version"}` inline;
// naming the constructor keeps each site to one line as Go's is.
fn ecErr(field: &'static str) -> error {
    return crate::errors::Wrap(echConfigErr {
        field: string::from_static(field),
    });
}

// go: sdk 1.25.5 crypto/tls/ech.go:73-135 parseECHConfig
/// Parse one ECHConfig from `enc`.
///
/// Returns `(skip, config, err)`. `skip` is true for a config whose
/// version this implementation does not recognise: Go consumes it and
/// reports success with an EMPTY config, so the caller drops it rather
/// than failing the whole list. That is what makes an ECHConfigList
/// forward-compatible, and it is the one behaviour here worth not
/// simplifying.
pub(crate) fn parseECHConfig(enc: slice<byte>) -> (bool, echConfig, error) {
    // Go: s := cryptobyte.String(enc); ec.raw = []byte(enc)
    let mut s = CBString::New(enc.clone());
    let mut ec = echConfig::default();
    ec.raw = enc.clone();
    // Go: if !s.ReadUint16(&ec.Version) { … "version" }
    if !s.ReadUint16(&mut ec.Version) {
        return (false, echConfig::default(), ecErr("version"));
    }
    // Go: if !s.ReadUint16(&ec.Length) { … "length" }
    if !s.ReadUint16(&mut ec.Length) {
        return (false, echConfig::default(), ecErr("length"));
    }
    // Go: if len(ec.raw) < int(ec.Length)+4 { … "length" }
    if ec.raw.Len() < crate::int(ec.Length) + 4 {
        return (false, echConfig::default(), ecErr("length"));
    }
    // Go: ec.raw = ec.raw[:ec.Length+4]
    ec.raw = enc.slice(0, crate::int(ec.Length) + 4);
    // Go: if ec.Version != extensionEncryptedClientHello {
    //         s.Skip(int(ec.Length)); return true, echConfig{}, nil
    //     }
    if ec.Version != extensionEncryptedClientHello {
        s.Skip(crate::int(ec.Length));
        return (true, echConfig::default(), crate::errors::nil);
    }
    // Go: if !s.ReadUint8(&ec.ConfigID) { … "config_id" }
    if !s.ReadUint8(&mut ec.ConfigID) {
        return (false, echConfig::default(), ecErr("config_id"));
    }
    // Go: if !s.ReadUint16(&ec.KemID) { … "kem_id" }
    if !s.ReadUint16(&mut ec.KemID) {
        return (false, echConfig::default(), ecErr("kem_id"));
    }
    // Go: if !readUint16LengthPrefixed(&s, &ec.PublicKey) { … "public_key" }
    if !super::handshake_messages::readUint16LengthPrefixed(&mut s, &mut ec.PublicKey) {
        return (false, echConfig::default(), ecErr("public_key"));
    }
    // Go: var cipherSuites cryptobyte.String
    //     if !s.ReadUint16LengthPrefixed(&cipherSuites) { … "cipher_suites" }
    let mut cipherSuites = CBString::New(slice::__from_vec(Vec::new()));
    if !s.ReadUint16LengthPrefixed(&mut cipherSuites) {
        return (false, echConfig::default(), ecErr("cipher_suites"));
    }
    let mut suites: Vec<echCipher> = Vec::new();
    while !cipherSuites.Empty() {
        let mut c = echCipher::default();
        if !cipherSuites.ReadUint16(&mut c.KDFID) {
            return (false, echConfig::default(), ecErr("cipher_suites kdf_id"));
        }
        if !cipherSuites.ReadUint16(&mut c.AEADID) {
            return (false, echConfig::default(), ecErr("cipher_suites aead_id"));
        }
        suites.push(c);
    }
    ec.SymmetricCipherSuite = slice::__from_vec(suites);
    // Go: if !s.ReadUint8(&ec.MaxNameLength) { … "maximum_name_length" }
    if !s.ReadUint8(&mut ec.MaxNameLength) {
        return (false, echConfig::default(), ecErr("maximum_name_length"));
    }
    // Go: var publicName cryptobyte.String
    //     if !s.ReadUint8LengthPrefixed(&publicName) { … "public_name" }
    let mut publicName = CBString::New(slice::__from_vec(Vec::new()));
    if !s.ReadUint8LengthPrefixed(&mut publicName) {
        return (false, echConfig::default(), ecErr("public_name"));
    }
    ec.PublicName = publicName.0.clone();
    // Go: var extensions cryptobyte.String
    //     if !s.ReadUint16LengthPrefixed(&extensions) { … "extensions" }
    let mut extensions = CBString::New(slice::__from_vec(Vec::new()));
    if !s.ReadUint16LengthPrefixed(&mut extensions) {
        return (false, echConfig::default(), ecErr("extensions"));
    }
    let mut exts: Vec<echExtension> = Vec::new();
    while !extensions.Empty() {
        let mut e = echExtension::default();
        if !extensions.ReadUint16(&mut e.Type) {
            return (false, echConfig::default(), ecErr("extensions type"));
        }
        let mut data = CBString::New(slice::__from_vec(Vec::new()));
        if !extensions.ReadUint16LengthPrefixed(&mut data) {
            return (false, echConfig::default(), ecErr("extensions data"));
        }
        e.Data = data.0.clone();
        exts.push(e);
    }
    ec.Extensions = slice::__from_vec(exts);

    // Go: return false, ec, nil
    return (false, ec, crate::errors::nil);
}

// go: sdk 1.25.5 crypto/tls/ech.go:137-160 parseECHConfigList
/// Parse an ECHConfigList: a uint16 length followed by back-to-back
/// ECHConfigs. Configs whose version is unrecognised are dropped.
pub(crate) fn parseECHConfigList(data: slice<byte>) -> (slice<echConfig>, error) {
    // Go: s := cryptobyte.String(data); var length uint16
    //     if !s.ReadUint16(&length) { return nil, errMalformedECHConfigList }
    let mut s = CBString::New(data.clone());
    let mut length: uint16 = 0;
    if !s.ReadUint16(&mut length) {
        return (
            slice::__from_vec(Vec::new()),
            crate::errors::New("tls: malformed ECHConfigList"),
        );
    }
    // Go: if length != uint16(len(data)-2) { return nil, errMalformedECHConfigList }
    if crate::int(length) != data.Len() - 2 {
        return (
            slice::__from_vec(Vec::new()),
            crate::errors::New("tls: malformed ECHConfigList"),
        );
    }
    // Go: for len(s) > 0 { … }
    let mut configs: Vec<echConfig> = Vec::new();
    let mut rest = data.slice(2, data.Len());
    while rest.Len() > 0 {
        // Go: if len(s) < 4 { return nil, errors.New("tls: malformed ECHConfig") }
        if rest.Len() < 4 {
            return (
                slice::__from_vec(Vec::new()),
                crate::errors::New("tls: malformed ECHConfig"),
            );
        }
        // Go: configLen := uint16(s[2])<<8 | uint16(s[3])
        let configLen = (crate::int(rest[2]) << 8) | crate::int(rest[3]);
        let (skip, ec, err) = parseECHConfig(rest.clone());
        if err != crate::errors::nil {
            return (slice::__from_vec(Vec::new()), err);
        }
        // Go: s = s[configLen+4:]
        if configLen + 4 > rest.Len() {
            return (
                slice::__from_vec(Vec::new()),
                crate::errors::New("tls: malformed ECHConfig"),
            );
        }
        rest = rest.slice(configLen + 4, rest.Len());
        // Go: if !skip { configs = append(configs, ec) }
        if !skip {
            configs.push(ec);
        }
    }
    // Go: return configs, nil
    return (slice::__from_vec(configs), crate::errors::nil);
}


// go: sdk 1.25.5 crypto/tls/ech.go:262-268 skipUint8LengthPrefixed
/// Consume a uint8-prefixed field without keeping it.
pub(crate) fn skipUint8LengthPrefixed(s: &mut CBString) -> bool {
    // Go: var skip uint8; if !s.ReadUint8(&skip) { return false }
    //     return s.Skip(int(skip))
    let mut skip: uint8 = 0;
    if !s.ReadUint8(&mut skip) {
        return false;
    }
    return s.Skip(crate::int(skip));
}

// go: sdk 1.25.5 crypto/tls/ech.go:270-276 skipUint16LengthPrefixed
/// The uint16 mirror of [`skipUint8LengthPrefixed`].
pub(crate) fn skipUint16LengthPrefixed(s: &mut CBString) -> bool {
    // Go: var skip uint16; if !s.ReadUint16(&skip) { return false }
    //     return s.Skip(int(skip))
    let mut skip: uint16 = 0;
    if !s.ReadUint16(&mut skip) {
        return false;
    }
    return s.Skip(crate::int(skip));
}

// go: sdk 1.25.5 crypto/tls/ech.go:640-666 validDNSName
/// Report whether `name` is a syntactically valid DNS name for the ECH
/// public_name field.
///
/// Stricter than a general hostname check, and deliberately so: at least
/// two labels, no empty label, a leading or trailing `-` in ANY label is
/// invalid, and only ASCII alphanumerics and `-` are permitted — no
/// underscore, no trailing dot, no IDN.
pub(crate) fn validDNSName(name: string) -> bool {
    // Go: if len(name) > 253 { return false }
    let raw: &[byte] = name.as_bytes();
    if raw.len() > 253 {
        return false;
    }
    // Go: labels := strings.Split(name, "."); if len(labels) <= 1 { return false }
    let labels: Vec<&[byte]> = raw.split(|c| *c == b'.').collect();
    if labels.len() <= 1 {
        return false;
    }
    // Go: for _, l := range labels { … }
    for l in labels {
        let labelLen = l.len();
        // Go: if labelLen == 0 { return false }
        if labelLen == 0 {
            return false;
        }
        for (i, r) in l.iter().enumerate() {
            let r = *r;
            // Go: if r == '-' && (i == 0 || i == labelLen-1) { return false }
            if r == b'-' && (i == 0 || i == labelLen - 1) {
                return false;
            }
            // Go: only 0-9, a-z, A-Z and '-'.
            if (r < b'0' || r > b'9')
                && (r < b'a' || r > b'z')
                && (r < b'A' || r > b'Z')
                && r != b'-'
            {
                return false;
            }
        }
    }
    return true;
}


// ─── Config selection and the encrypted_client_hello extension ────────

use super::common::EncryptedClientHelloKey;
use super::handshake_messages::{
    clientHelloMsg, readUint16LengthPrefixed,
};
use crate::crypto::cryptobyte;
use crate::crypto::internal::hpke;
use crate::types::int;

// Go: ech.go:506-508
//   type ECHRejectionError struct { RetryConfigList []byte }
/// Go: "ECHRejectionError is the error type returned when ECH is
/// rejected by a remote server. If the server offered a ECHConfigList to
/// use for retries, the RetryConfigList field will contain this list."
#[derive(Clone, Default)]
pub struct ECHRejectionError {
    pub RetryConfigList: slice<byte>,
}

impl ECHRejectionError {
    // go: sdk 1.25.5 crypto/tls/ech.go:510-512 ECHRejectionError.Error
    pub fn Error(&self) -> string {
        // Go: return "tls: server rejected ECH"
        return string::from_static("tls: server rejected ECH");
    }
}

// go: none — goish idiom: Go satisfies `error` implicitly through
// `Error() string`; goish requires the trait wiring.
impl crate::errors::ErrorTrait for ECHRejectionError {
    // go: none — goish idiom: forwards to the ported inherent `Error`.
    fn Error(&self) -> string {
        return ECHRejectionError::Error(self);
    }
}

// Go: ech.go:517-522
//   type echExtType uint8
//   const ( innerECHExt echExtType = 1; outerECHExt echExtType = 0 )
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub(crate) struct echExtType(pub uint8);
pub(crate) const innerECHExt: echExtType = echExtType(1);
pub(crate) const outerECHExt: echExtType = echExtType(0);

crate::var! {
    /// Go: `var errMalformedECHExt = errors.New(…)`
    pub(crate) errMalformedECHExt: error = "tls: malformed encrypted_client_hello extension";
    /// Go: `var errInvalidECHExt = errors.New(…)`
    pub(crate) errInvalidECHExt: error = "tls: client sent invalid encrypted_client_hello extension";
}

// go: sdk 1.25.5 crypto/tls/ech.go:524-569 parseECHExt
/// Parse the `encrypted_client_hello` extension body.
///
/// goishlint:ignore GOISH020 parseECHExt — Go's six named results become one tuple
pub(crate) fn parseECHExt(
    ext: slice<byte>,
) -> (
    echExtType,
    echCipher,
    uint8,
    slice<byte>,
    slice<byte>,
    crate::error,
) {
    // Go: data := make([]byte, len(ext)); copy(data, ext)
    //     s := cryptobyte.String(data)
    let raw: &[byte] = &ext;
    let data = slice::__from_vec(raw.to_vec());
    let mut s = CBString::New(data);
    let mut cs = echCipher::default();
    let mut configID: uint8 = 0;
    let mut encap: slice<byte> = slice::new();
    let mut payload: slice<byte> = slice::new();

    // Go: var echInt uint8
    //     if !s.ReadUint8(&echInt) { err = errMalformedECHExt; return }
    //     echType = echExtType(echInt)
    let mut echInt: uint8 = 0;
    if !s.ReadUint8(&mut echInt) {
        return (
            echExtType(0),
            cs,
            0,
            slice::new(),
            slice::new(),
            errMalformedECHExt.into(),
        );
    }
    let echType = echExtType(echInt);
    // Go: if echType == innerECHExt {
    //         if !s.Empty() { err = errMalformedECHExt; return }
    //         return echType, cs, 0, nil, nil, nil }
    if echType == innerECHExt {
        if !s.Empty() {
            return (
                echType,
                cs,
                0,
                slice::new(),
                slice::new(),
                errMalformedECHExt.into(),
            );
        }
        return (
            echType,
            cs,
            0,
            slice::new(),
            slice::new(),
            crate::errors::nil,
        );
    }
    // Go: if echType != outerECHExt { err = errInvalidECHExt; return }
    if echType != outerECHExt {
        return (
            echType,
            cs,
            0,
            slice::new(),
            slice::new(),
            errInvalidECHExt.into(),
        );
    }
    // Go: if !s.ReadUint16(&cs.KDFID) { err = errMalformedECHExt; return }
    //     if !s.ReadUint16(&cs.AEADID) { … }
    //     if !s.ReadUint8(&configID) { … }
    //     if !readUint16LengthPrefixed(&s, &encap) { … }
    //     if !readUint16LengthPrefixed(&s, &payload) { … }
    if !s.ReadUint16(&mut cs.KDFID)
        || !s.ReadUint16(&mut cs.AEADID)
        || !s.ReadUint8(&mut configID)
        || !readUint16LengthPrefixed(&mut s, &mut encap)
        || !readUint16LengthPrefixed(&mut s, &mut payload)
    {
        return (
            echType,
            cs,
            0,
            slice::new(),
            slice::new(),
            errMalformedECHExt.into(),
        );
    }

    // Go: NOTE: clone encap and payload so that mutating them does not
    // mutate the raw extension bytes.
    let encapRaw: &[byte] = &encap;
    let payloadRaw: &[byte] = &payload;
    return (
        echType,
        cs,
        configID,
        slice::__from_vec(encapRaw.to_vec()),
        slice::__from_vec(payloadRaw.to_vec()),
        crate::errors::nil,
    );
}

// go: sdk 1.25.5 crypto/tls/ech.go:571-579 marshalEncryptedClientHelloConfigList
pub(crate) fn marshalEncryptedClientHelloConfigList(
    configs: slice<EncryptedClientHelloKey>,
) -> (slice<byte>, crate::error) {
    // Go: builder := cryptobyte.NewBuilder(nil)
    //     builder.AddUint16LengthPrefixed(func(builder …) {
    //         for _, c := range configs { builder.AddBytes(c.Config) } })
    //     return builder.Bytes()
    let mut builder = cryptobyte::NewBuilder(slice::new());
    builder.AddUint16LengthPrefixed(|builder: &mut cryptobyte::Builder| {
        for (_, c) in crate::range!(configs.clone()) {
            builder.AddBytes(&c.Config);
        }
    });
    return builder.Bytes();
}

// go: sdk 1.25.5 crypto/tls/ech.go:427-436 generateOuterECHExt
pub(crate) fn generateOuterECHExt(
    id: uint8,
    kdfID: uint16,
    aeadID: uint16,
    encodedKey: slice<byte>,
    payload: slice<byte>,
) -> (slice<byte>, crate::error) {
    // Go: var b cryptobyte.Builder
    //     b.AddUint8(0) // outer
    //     b.AddUint16(kdfID); b.AddUint16(aeadID); b.AddUint8(id)
    //     b.AddUint16LengthPrefixed(func(b …) { b.AddBytes(encodedKey) })
    //     b.AddUint16LengthPrefixed(func(b …) { b.AddBytes(payload) })
    //     return b.Bytes()
    let mut b = cryptobyte::NewBuilder(slice::new());
    b.AddUint8(0); // outer
    b.AddUint16(kdfID);
    b.AddUint16(aeadID);
    b.AddUint8(id);
    b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
        b.AddBytes(&encodedKey);
    });
    b.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
        b.AddBytes(&payload);
    });
    return b.Bytes();
}

// go: sdk 1.25.5 crypto/tls/ech.go:204-218 pickECHCipherSuite
/// Go: "NOTE: all of the supported AEADs and KDFs are fine, rather than
/// imposing some sort of preference here, we just pick the first valid
/// suite."
pub(crate) fn pickECHCipherSuite(suites: slice<echCipher>) -> (echCipher, crate::error) {
    // Go: for _, s := range suites {
    //         if _, ok := hpke.SupportedAEADs[s.AEADID]; !ok { continue }
    //         if _, ok := hpke.SupportedKDFs[s.KDFID]; !ok { continue }
    //         return s, nil }
    for (_, s) in crate::range!(suites) {
        if hpke::SupportedAEADs(s.AEADID).is_none() {
            continue;
        }
        if hpke::SupportedKDFs(s.KDFID).is_none() {
            continue;
        }
        return (*s, crate::errors::nil);
    }
    // Go: return echCipher{}, errors.New("tls: no supported symmetric
    //     ciphersuites for ECH")
    return (
        echCipher::default(),
        crate::errors::New("tls: no supported symmetric ciphersuites for ECH"),
    );
}

// go: sdk 1.25.5 crypto/tls/ech.go:165-202 pickECHConfig
/// The first config in the list this library can actually use.
pub(crate) fn pickECHConfig(list: slice<echConfig>) -> Option<echConfig> {
    // Go: for _, ec := range list {
    for (_, ec) in crate::range!(list) {
        // Go: if _, ok := hpke.SupportedKEMs[ec.KemID]; !ok { continue }
        if hpke::SupportedKEMs(ec.KemID).is_none() {
            continue;
        }
        // Go: var validSCS bool
        //     for _, cs := range ec.SymmetricCipherSuite {
        //         if _, ok := hpke.SupportedAEADs[cs.AEADID]; !ok { continue }
        //         if _, ok := hpke.SupportedKDFs[cs.KDFID]; !ok { continue }
        //         validSCS = true; break }
        //     if !validSCS { continue }
        let mut validSCS = false;
        for (_, cs) in crate::range!(ec.SymmetricCipherSuite.clone()) {
            if hpke::SupportedAEADs(cs.AEADID).is_none() {
                continue;
            }
            if hpke::SupportedKDFs(cs.KDFID).is_none() {
                continue;
            }
            validSCS = true;
            break;
        }
        if !validSCS {
            continue;
        }
        // Go: if !validDNSName(string(ec.PublicName)) { continue }
        if !validDNSName(string::from_bytes(&ec.PublicName)) {
            continue;
        }
        // Go: var unsupportedExt bool
        //     for _, ext := range ec.Extensions {
        //         // If high order bit is set to 1 the extension is mandatory.
        //         // Since we don't support any extensions, if we see a
        //         // mandatory bit, we skip the config.
        //         if ext.Type&uint16(1<<15) != 0 { unsupportedExt = true } }
        //     if unsupportedExt { continue }
        let mut unsupportedExt = false;
        for (_, ext) in crate::range!(ec.Extensions.clone()) {
            if ext.Type & (1u16 << 15) != 0 {
                unsupportedExt = true;
            }
        }
        if unsupportedExt {
            continue;
        }
        // Go: return &ec
        return Some(ec.clone());
    }
    // Go: return nil
    return None;
}

// Go: ech.go:254-257
//   type rawExtension struct { extType uint16; data []byte }
#[derive(Clone, Default)]
pub(crate) struct rawExtension {
    pub extType: uint16,
    pub data: slice<byte>,
}

// go: sdk 1.25.5 crypto/tls/ech.go:259-283 extractRawExtensions
/// Reparse the outer ClientHello's extensions in wire order, which is
/// what ECH's outer-extension decompression needs.
pub(crate) fn extractRawExtensions(
    hello: &clientHelloMsg,
) -> (slice<rawExtension>, crate::error) {
    // Go: s := cryptobyte.String(hello.original)
    //     if !s.Skip(4+2+32) || // header, version, random
    //        !skipUint8LengthPrefixed(&s) || // session ID
    //        !skipUint16LengthPrefixed(&s) || // cipher suites
    //        !skipUint8LengthPrefixed(&s) { // compression methods
    //         return nil, errors.New("tls: malformed outer client hello") }
    let mut s = CBString::New(slice::__from_vec(hello.original.clone()));
    if !s.Skip(4 + 2 + 32)
        || !skipUint8LengthPrefixed(&mut s)
        || !skipUint16LengthPrefixed(&mut s)
        || !skipUint8LengthPrefixed(&mut s)
    {
        return (
            slice::new(),
            crate::errors::New("tls: malformed outer client hello"),
        );
    }
    // Go: var rawExtensions []rawExtension
    //     var extensions cryptobyte.String
    //     if !s.ReadUint16LengthPrefixed(&extensions) {
    //         return nil, errors.New("tls: malformed outer client hello") }
    let mut rawExtensions: Vec<rawExtension> = Vec::new();
    let mut extensions = CBString::New(slice::new());
    if !s.ReadUint16LengthPrefixed(&mut extensions) {
        return (
            slice::new(),
            crate::errors::New("tls: malformed outer client hello"),
        );
    }

    // Go: for !extensions.Empty() {
    //         var extension uint16
    //         var extData cryptobyte.String
    //         if !extensions.ReadUint16(&extension) ||
    //            !extensions.ReadUint16LengthPrefixed(&extData) {
    //             return nil, errors.New("tls: invalid inner client hello") }
    //         rawExtensions = append(rawExtensions, rawExtension{extension, extData}) }
    while !extensions.Empty() {
        let mut extension: uint16 = 0;
        let mut extData = CBString::New(slice::new());
        if !extensions.ReadUint16(&mut extension)
            || !extensions.ReadUint16LengthPrefixed(&mut extData)
        {
            return (
                slice::new(),
                crate::errors::New("tls: invalid inner client hello"),
            );
        }
        rawExtensions.push(rawExtension {
            extType: extension,
            data: extData.0.clone(),
        });
    }
    // Go: return rawExtensions, nil
    return (slice::__from_vec(rawExtensions), crate::errors::nil);
}

// go: sdk 1.25.5 crypto/tls/ech.go:220-236 encodeInnerClientHello
/// The ECH inner ClientHello, padded per draft-ietf-tls-esni §6.1.3.
pub(crate) fn encodeInnerClientHello(
    inner: &clientHelloMsg,
    maxNameLength: int,
) -> (slice<byte>, crate::error) {
    // Go: h, err := inner.marshalMsg(true)
    //     if err != nil { return nil, err }
    //     h = h[4:] // strip four byte prefix
    let (h, err) = inner.marshalMsg(true);
    if err != crate::errors::nil {
        return (slice::new(), err);
    }
    let h = h.slice(4, h.Len());

    // Go: var paddingLen int
    //     if inner.serverName != "" {
    //         paddingLen = max(0, maxNameLength-len(inner.serverName))
    //     } else {
    //         paddingLen = maxNameLength + 9
    //     }
    //     paddingLen = 31 - ((len(h) + paddingLen - 1) % 32)
    let mut paddingLen: int;
    if inner.serverName.len() != 0 {
        paddingLen = maxNameLength - crate::int(inner.serverName.len());
        if paddingLen < 0 {
            paddingLen = 0;
        }
    } else {
        paddingLen = maxNameLength + 9;
    }
    paddingLen = 31 - ((h.Len() + paddingLen - 1) % 32);

    // Go: return append(h, make([]byte, paddingLen)...), nil
    let raw: &[byte] = &h;
    let mut out: Vec<byte> = raw.to_vec();
    out.resize(out.len() + paddingLen as usize, 0);
    return (slice::__from_vec(out), crate::errors::nil);
}


// ─── Inner-hello reconstruction and payload decryption ────────────────

use super::handshake_messages::{readUint8LengthPrefixed, typeClientHello};

// go: sdk 1.25.5 crypto/tls/ech.go:285-416 decodeInnerClientHello
/// Go: "Reconstructing the inner client hello from its encoded form is
/// somewhat complicated. It is missing its header (message type and
/// length), session ID, and the extensions may be compressed. Since we
/// need to put the extensions back in the same order as they were in the
/// raw outer hello, and since we don't store the raw extensions, or the
/// order we parsed them in, we need to reparse the raw extensions from
/// the outer hello in order to properly insert them into the inner
/// hello. This _should_ result in raw bytes which match the hello as it
/// was generated by the client."
pub(crate) fn decodeInnerClientHello(
    outer: &clientHelloMsg,
    encoded: slice<byte>,
) -> (Option<clientHelloMsg>, crate::error) {
    let invalid = || crate::errors::New("tls: invalid inner client hello");

    // Go: innerReader := cryptobyte.String(encoded)
    //     if !innerReader.ReadBytes(&versionAndRandom, 2+32) ||
    //        !readUint8LengthPrefixed(&innerReader, &sessionID) || len(sessionID) != 0 ||
    //        !readUint16LengthPrefixed(&innerReader, &cipherSuites) ||
    //        !readUint8LengthPrefixed(&innerReader, &compressionMethods) ||
    //        !innerReader.ReadUint16LengthPrefixed(&extensions) {
    //         return nil, errors.New("tls: invalid inner client hello") }
    let mut innerReader = CBString::New(encoded);
    let mut versionAndRandom: slice<byte> = slice::new();
    let mut sessionID: slice<byte> = slice::new();
    let mut cipherSuites: slice<byte> = slice::new();
    let mut compressionMethods: slice<byte> = slice::new();
    let mut extensions = CBString::New(slice::new());
    if !innerReader.ReadBytes(&mut versionAndRandom, 2 + 32)
        || !readUint8LengthPrefixed(&mut innerReader, &mut sessionID)
        || sessionID.Len() != 0
        || !readUint16LengthPrefixed(&mut innerReader, &mut cipherSuites)
        || !readUint8LengthPrefixed(&mut innerReader, &mut compressionMethods)
        || !innerReader.ReadUint16LengthPrefixed(&mut extensions)
    {
        return (None, invalid());
    }

    // Go: The specification says we must verify that the trailing padding
    // is all zeros. This is kind of weird for TLS messages, where we
    // generally just throw away any trailing garbage.
    // Go: for _, p := range innerReader { if p != 0 { return nil, errors.New(…) } }
    for (_, p) in crate::range!(innerReader.0.clone()) {
        if *p != 0 {
            return (None, invalid());
        }
    }

    // Go: rawOuterExts, err := extractRawExtensions(outer)
    //     if err != nil { return nil, err }
    let (rawOuterExts, err) = extractRawExtensions(outer);
    if err != crate::errors::nil {
        return (None, err);
    }

    // Go: recon := cryptobyte.NewBuilder(nil)
    //     recon.AddUint8(typeClientHello)
    //     recon.AddUint24LengthPrefixed(func(recon …) { … })
    let mut recon = cryptobyte::NewBuilder(slice::new());
    recon.AddUint8(typeClientHello);
    let sessionId = slice::__from_vec(outer.sessionId.clone());
    recon.AddUint24LengthPrefixed(|recon: &mut cryptobyte::Builder| {
        recon.AddBytes(&versionAndRandom);
        recon.AddUint8LengthPrefixed(|recon: &mut cryptobyte::Builder| {
            recon.AddBytes(&sessionId);
        });
        recon.AddUint16LengthPrefixed(|recon: &mut cryptobyte::Builder| {
            recon.AddBytes(&cipherSuites);
        });
        recon.AddUint8LengthPrefixed(|recon: &mut cryptobyte::Builder| {
            recon.AddBytes(&compressionMethods);
        });
        recon.AddUint16LengthPrefixed(|recon: &mut cryptobyte::Builder| {
            // Go: for !extensions.Empty() { … }
            while !extensions.Empty() {
                let mut extension: uint16 = 0;
                let mut extData = CBString::New(slice::new());
                if !extensions.ReadUint16(&mut extension)
                    || !extensions.ReadUint16LengthPrefixed(&mut extData)
                {
                    recon.SetError(crate::errors::New("tls: invalid inner client hello"));
                    return;
                }
                if extension == super::common::extensionECHOuterExtensions {
                    // Go: if !extData.ReadUint8LengthPrefixed(&extData) { … }
                    let mut list = CBString::New(slice::new());
                    if !extData.ReadUint8LengthPrefixed(&mut list) {
                        recon.SetError(crate::errors::New("tls: invalid inner client hello"));
                        return;
                    }
                    // Go: var i int
                    //     for !extData.Empty() {
                    //         var extType uint16
                    //         if !extData.ReadUint16(&extType) { … }
                    //         if extType == extensionEncryptedClientHello {
                    //             recon.SetError(errors.New("tls: invalid outer extensions")); return }
                    //         for ; i <= len(rawOuterExts); i++ {
                    //             if i == len(rawOuterExts) {
                    //                 recon.SetError(errors.New("tls: invalid outer extensions")); return }
                    //             if rawOuterExts[i].extType == extType { break } }
                    //         recon.AddUint16(rawOuterExts[i].extType)
                    //         recon.AddUint16LengthPrefixed(func(recon …) {
                    //             recon.AddBytes(rawOuterExts[i].data) }) }
                    //
                    // `i` does not reset between iterations: the outer
                    // extensions must appear in the same order the inner
                    // hello lists them, which is what makes the
                    // reconstruction byte-exact.
                    let mut i: int = 0;
                    while !list.Empty() {
                        let mut extType: uint16 = 0;
                        if !list.ReadUint16(&mut extType) {
                            recon.SetError(crate::errors::New("tls: invalid inner client hello"));
                            return;
                        }
                        if extType == extensionEncryptedClientHello {
                            recon.SetError(crate::errors::New("tls: invalid outer extensions"));
                            return;
                        }
                        loop {
                            if i == rawOuterExts.Len() {
                                recon.SetError(crate::errors::New("tls: invalid outer extensions"));
                                return;
                            }
                            if rawOuterExts[i as usize].extType == extType {
                                break;
                            }
                            i += 1;
                        }
                        let found = rawOuterExts[i as usize].clone();
                        recon.AddUint16(found.extType);
                        recon.AddUint16LengthPrefixed(|recon: &mut cryptobyte::Builder| {
                            recon.AddBytes(&found.data);
                        });
                    }
                } else {
                    // Go: recon.AddUint16(extension)
                    //     recon.AddUint16LengthPrefixed(func(recon …) { recon.AddBytes(extData) })
                    recon.AddUint16(extension);
                    let data = extData.0.clone();
                    recon.AddUint16LengthPrefixed(|recon: &mut cryptobyte::Builder| {
                        recon.AddBytes(&data);
                    });
                }
            }
        });
    });

    // Go: reconBytes, err := recon.Bytes()
    //     if err != nil { return nil, err }
    let (reconBytes, err) = recon.Bytes();
    if err != crate::errors::nil {
        return (None, err);
    }
    // Go: inner := &clientHelloMsg{}
    //     if !inner.unmarshal(reconBytes) {
    //         return nil, errors.New("tls: invalid reconstructed inner client hello") }
    let mut inner = clientHelloMsg::default();
    let raw: &[byte] = &reconBytes;
    if !inner.unmarshal(raw) {
        return (
            None,
            crate::errors::New("tls: invalid reconstructed inner client hello"),
        );
    }

    // Go: if !bytes.Equal(inner.encryptedClientHello, []byte{uint8(innerECHExt)}) {
    //         return nil, errInvalidECHExt }
    if inner.encryptedClientHello != alloc::vec![innerECHExt.0] {
        return (None, errInvalidECHExt.into());
    }

    // Go: hasTLS13 := false
    //     for _, v := range inner.supportedVersions { … }
    let mut hasTLS13 = false;
    for v in inner.supportedVersions.iter() {
        // Go: Skip GREASE values (values of the form 0x?A0A). GREASE
        // (Generate Random Extensions And Sustain Extensibility) is a
        // mechanism used by browsers like Chrome to ensure TLS
        // implementations correctly ignore unknown values. GREASE values
        // follow a specific pattern: 0x?A0A, where ? can be any hex
        // digit. These values should be ignored when processing
        // supported TLS versions.
        if *v & 0x0F0F == 0x0A0A && *v & 0xff == *v >> 8 {
            continue;
        }

        // Go: Ensure at least TLS 1.3 is offered.
        if *v == super::common::VersionTLS13 {
            hasTLS13 = true;
        } else if *v < super::common::VersionTLS13 {
            // Go: Reject if any non-GREASE value is below TLS 1.3, as ECH
            // requires TLS 1.3+.
            return (
                None,
                crate::errors::New(
                    "tls: client sent encrypted_client_hello extension with unsupported versions",
                ),
            );
        }
    }

    // Go: if !hasTLS13 { return nil, errors.New("tls: client sent
    //     encrypted_client_hello extension but did not offer TLS 1.3") }
    if !hasTLS13 {
        return (
            None,
            crate::errors::New(
                "tls: client sent encrypted_client_hello extension but did not offer TLS 1.3",
            ),
        );
    }

    // Go: return inner, nil
    return (Some(inner), crate::errors::nil);
}

// go: sdk 1.25.5 crypto/tls/ech.go:422-425 decryptECHPayload
/// Open the ECH payload against the outer ClientHello with the payload
/// itself zeroed — the AAD construction from draft-ietf-tls-esni §6.1.
pub(crate) fn decryptECHPayload(
    context: &mut hpke::Recipient,
    hello: slice<byte>,
    payload: slice<byte>,
) -> (slice<byte>, crate::error) {
    // Go: outerAAD := bytes.Replace(hello[4:], payload, make([]byte, len(payload)), 1)
    //     return context.Open(outerAAD, payload)
    let outerAAD = crate::bytes::Replace(
        hello.slice(4, hello.Len()),
        payload.clone(),
        slice::__from_vec(alloc::vec![0u8; payload.Len() as usize]),
        1,
    );
    return context.Open(&outerAAD, &payload);
}

// go: sdk 1.25.5 crypto/tls/ech.go:600-616 buildRetryConfigList
/// The ECHConfigList to send back when ECH was offered and rejected —
/// only the keys flagged `SendAsRetry`. Returns nil if none are.
pub(crate) fn buildRetryConfigList(
    keys: slice<EncryptedClientHelloKey>,
) -> (slice<byte>, crate::error) {
    // Go: var atLeastOneRetryConfig bool
    //     var retryBuilder cryptobyte.Builder
    //     retryBuilder.AddUint16LengthPrefixed(func(b …) {
    //         for _, c := range keys {
    //             if !c.SendAsRetry { continue }
    //             atLeastOneRetryConfig = true
    //             b.AddBytes(c.Config) } })
    let mut atLeastOneRetryConfig = false;
    for (_, c) in crate::range!(keys.clone()) {
        if c.SendAsRetry {
            atLeastOneRetryConfig = true;
        }
    }
    let mut retryBuilder = cryptobyte::NewBuilder(slice::new());
    retryBuilder.AddUint16LengthPrefixed(|b: &mut cryptobyte::Builder| {
        for (_, c) in crate::range!(keys.clone()) {
            if !c.SendAsRetry {
                continue;
            }
            b.AddBytes(&c.Config);
        }
    });
    // Go: if !atLeastOneRetryConfig { return nil, nil }
    if !atLeastOneRetryConfig {
        return (slice::new(), crate::errors::nil);
    }
    // Go: return retryBuilder.Bytes()
    return retryBuilder.Bytes();
}
