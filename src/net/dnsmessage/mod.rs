// Port of vendor/golang.org/x/net/dns/dnsmessage@go1.26.0
// (message.go + svcb.go combined)
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(unused_imports)]

extern crate alloc;
use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::gostring::string;

// ─── Error sentinels ────────────────────────────────────────────────────────

crate::var! {
    pub ErrNotStarted: error = "parsing/packing of this type isn't available yet";
    pub ErrSectionDone: error = "parsing/packing of this section has completed";
    pub ERR_BASE_LEN: error = "insufficient data for base length type";
    pub ERR_CALC_LEN: error = "insufficient data for calculated length type";
    pub ERR_RESERVED: error = "segment prefix is reserved";
    pub ERR_TOO_MANY_PTR: error = "too many pointers (>10)";
    pub ERR_INVALID_PTR: error = "invalid pointer";
    pub ERR_INVALID_NAME: error = "invalid dns name";
    pub ERR_NIL_RESOURCE_BODY: error = "nil resource body";
    pub ERR_RESOURCE_LEN: error = "insufficient data for resource body length";
    pub ERR_SEG_TOO_LONG: error = "segment length too long";
    pub ERR_NAME_TOO_LONG: error = "name too long";
    pub ERR_ZERO_SEG_LEN: error = "zero length segment";
    pub ERR_RES_TOO_LONG: error = "resource length too long";
    pub ERR_NON_CANONICAL_NAME: error = "name is not in canonical format (it must end with a .)";
    pub ERR_STRING_TOO_LONG: error = "character string exceeds maximum length (255)";
    pub ERR_PARAM_OUT_OF_ORDER: error = "parameter out of order";
    pub ERR_TOO_LONG_SVCB_VALUE: error = "value too long (>65535 bytes)";
}

fn err_base_len() -> error {
    ERR_BASE_LEN.into()
}
fn err_calc_len() -> error {
    ERR_CALC_LEN.into()
}
fn err_reserved() -> error {
    ERR_RESERVED.into()
}
fn err_too_many_ptr() -> error {
    ERR_TOO_MANY_PTR.into()
}
fn err_invalid_ptr() -> error {
    ERR_INVALID_PTR.into()
}
fn err_invalid_name() -> error {
    ERR_INVALID_NAME.into()
}
fn err_resource_len() -> error {
    ERR_RESOURCE_LEN.into()
}
fn err_seg_too_long() -> error {
    ERR_SEG_TOO_LONG.into()
}
fn err_name_too_long() -> error {
    ERR_NAME_TOO_LONG.into()
}
fn err_zero_seg_len() -> error {
    ERR_ZERO_SEG_LEN.into()
}
fn err_res_too_long() -> error {
    ERR_RES_TOO_LONG.into()
}
fn err_non_canonical_name() -> error {
    ERR_NON_CANONICAL_NAME.into()
}
fn err_string_too_long() -> error {
    ERR_STRING_TOO_LONG.into()
}
fn err_param_out_of_order() -> error {
    ERR_PARAM_OUT_OF_ORDER.into()
}
fn err_too_long_svcb_value() -> error {
    ERR_TOO_LONG_SVCB_VALUE.into()
}

fn nested_err<S: AsRef<str>>(s: S, err: error) -> error {
    let s = s.as_ref();
    let msg = err.Error();
    let mut b: Vec<u8> = Vec::with_capacity(s.len() + 2 + msg.Len() as usize);
    b.extend_from_slice(s.as_bytes());
    b.extend_from_slice(b": ");
    b.extend_from_slice(msg.as_bytes());
    errors::New(string::from_bytes(&b))
}

// ─── Type ─────────────────────────────────────────────────────────────────

pub type Type = u16;

pub const TypeA: Type = 1;
pub const TypeNS: Type = 2;
pub const TypeCNAME: Type = 5;
pub const TypeSOA: Type = 6;
pub const TypePTR: Type = 12;
pub const TypeMX: Type = 15;
pub const TypeTXT: Type = 16;
pub const TypeAAAA: Type = 28;
pub const TypeSRV: Type = 33;
pub const TypeOPT: Type = 41;
pub const TypeSVCB: Type = 64;
pub const TypeHTTPS: Type = 65;
pub const TypeWKS: Type = 11;
pub const TypeHINFO: Type = 13;
pub const TypeMINFO: Type = 14;
pub const TypeAXFR: Type = 252;
pub const TypeALL: Type = 255;

// ─── Class ────────────────────────────────────────────────────────────────

pub type Class = u16;

pub const ClassINET: Class = 1;
pub const ClassCSNET: Class = 2;
pub const ClassCHAOS: Class = 3;
pub const ClassHESIOD: Class = 4;
pub const ClassANY: Class = 255;

// ─── OpCode / RCode ───────────────────────────────────────────────────────

pub type OpCode = u16;
pub type RCode = u16;

pub const RCodeSuccess: RCode = 0;
pub const RCodeFormatError: RCode = 1;
pub const RCodeServerFailure: RCode = 2;
pub const RCodeNameError: RCode = 3;
pub const RCodeNotImplemented: RCode = 4;
pub const RCodeRefused: RCode = 5;

// ─── Header ───────────────────────────────────────────────────────────────

#[derive(Clone, Default, Debug)]
pub struct Header {
    pub ID: u16,
    pub Response: bool,
    pub OpCode: OpCode,
    pub Authoritative: bool,
    pub Truncated: bool,
    pub RecursionDesired: bool,
    pub RecursionAvailable: bool,
    pub AuthenticData: bool,
    pub CheckingDisabled: bool,
    pub RCode: RCode,
}

const HEADER_BIT_QR: u16 = 1 << 15;
const HEADER_BIT_AA: u16 = 1 << 10;
const HEADER_BIT_TC: u16 = 1 << 9;
const HEADER_BIT_RD: u16 = 1 << 8;
const HEADER_BIT_RA: u16 = 1 << 7;
const HEADER_BIT_AD: u16 = 1 << 5;
const HEADER_BIT_CD: u16 = 1 << 4;

impl Header {
    fn pack(&self) -> (u16, u16) {
        let id = self.ID;
        let mut bits = ((self.OpCode as u16) << 11) | (self.RCode as u16);
        if self.RecursionAvailable {
            bits |= HEADER_BIT_RA;
        }
        if self.AuthenticData {
            bits |= HEADER_BIT_AD;
        }
        if self.CheckingDisabled {
            bits |= HEADER_BIT_CD;
        }
        if self.RecursionDesired {
            bits |= HEADER_BIT_RD;
        }
        if self.Truncated {
            bits |= HEADER_BIT_TC;
        }
        if self.Authoritative {
            bits |= HEADER_BIT_AA;
        }
        if self.Response {
            bits |= HEADER_BIT_QR;
        }
        (id, bits)
    }
}

// Wire-level header
#[derive(Clone, Default)]
struct WireHeader {
    id: u16,
    bits: u16,
    questions: u16,
    answers: u16,
    authorities: u16,
    additionals: u16,
}

impl WireHeader {
    fn count(&self, sec: Section) -> u16 {
        match sec {
            Section::Questions => self.questions,
            Section::Answers => self.answers,
            Section::Authorities => self.authorities,
            Section::Additionals => self.additionals,
            _ => 0,
        }
    }

    fn pack_into(&self, msg: &mut Vec<u8>, start: usize) {
        msg[start] = (self.id >> 8) as u8;
        msg[start + 1] = self.id as u8;
        msg[start + 2] = (self.bits >> 8) as u8;
        msg[start + 3] = self.bits as u8;
        msg[start + 4] = (self.questions >> 8) as u8;
        msg[start + 5] = self.questions as u8;
        msg[start + 6] = (self.answers >> 8) as u8;
        msg[start + 7] = self.answers as u8;
        msg[start + 8] = (self.authorities >> 8) as u8;
        msg[start + 9] = self.authorities as u8;
        msg[start + 10] = (self.additionals >> 8) as u8;
        msg[start + 11] = self.additionals as u8;
    }

    fn unpack(msg: &[u8], off: usize) -> Result<(WireHeader, usize), error> {
        let mut h = WireHeader::default();
        let mut o = off;
        let (v, no) = unpack_u16(msg, o).map_err(|e| nested_err("id", e))?;
        h.id = v;
        o = no;
        let (v, no) = unpack_u16(msg, o).map_err(|e| nested_err("bits", e))?;
        h.bits = v;
        o = no;
        let (v, no) = unpack_u16(msg, o).map_err(|e| nested_err("questions", e))?;
        h.questions = v;
        o = no;
        let (v, no) = unpack_u16(msg, o).map_err(|e| nested_err("answers", e))?;
        h.answers = v;
        o = no;
        let (v, no) = unpack_u16(msg, o).map_err(|e| nested_err("authorities", e))?;
        h.authorities = v;
        o = no;
        let (v, no) = unpack_u16(msg, o).map_err(|e| nested_err("additionals", e))?;
        h.additionals = v;
        o = no;
        Ok((h, o))
    }

    fn header(&self) -> Header {
        Header {
            ID: self.id,
            Response: (self.bits & HEADER_BIT_QR) != 0,
            OpCode: (self.bits >> 11) & 0xF,
            Authoritative: (self.bits & HEADER_BIT_AA) != 0,
            Truncated: (self.bits & HEADER_BIT_TC) != 0,
            RecursionDesired: (self.bits & HEADER_BIT_RD) != 0,
            RecursionAvailable: (self.bits & HEADER_BIT_RA) != 0,
            AuthenticData: (self.bits & HEADER_BIT_AD) != 0,
            CheckingDisabled: (self.bits & HEADER_BIT_CD) != 0,
            RCode: self.bits & 0xF,
        }
    }
}

// ─── Section ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Section {
    NotStarted = 0,
    Header_ = 1,
    Questions = 2,
    Answers = 3,
    Authorities = 4,
    Additionals = 5,
    Done = 6,
}

impl Default for Section {
    fn default() -> Self {
        Section::NotStarted
    }
}

fn advance_section(sec: Section) -> Section {
    match sec {
        Section::Questions => Section::Answers,
        Section::Answers => Section::Authorities,
        Section::Authorities => Section::Additionals,
        _ => Section::Done,
    }
}

fn section_name(sec: Section) -> &'static str {
    match sec {
        Section::Questions => "Question",
        Section::Answers => "Answer",
        Section::Authorities => "Authority",
        Section::Additionals => "Additional",
        _ => "unknown",
    }
}

// ─── Name ─────────────────────────────────────────────────────────────────

const NON_ENCODED_NAME_MAX: usize = 254;

#[derive(Clone, Debug)]
pub struct Name {
    pub Data: [u8; 255],
    pub Length: u8,
}

impl Default for Name {
    fn default() -> Self {
        Name {
            Data: [0u8; 255],
            Length: 0,
        }
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.Length == other.Length
            && self.Data[..self.Length as usize] == other.Data[..other.Length as usize]
    }
}

impl Name {
    pub fn String(&self) -> string {
        string::from_bytes(&self.Data[..self.Length as usize])
    }

    fn pack(
        &self,
        mut msg: Vec<u8>,
        mut compression: Option<&mut BTreeMap<String, u16>>,
        compression_off: usize,
    ) -> Result<Vec<u8>, error> {
        if self.Length as usize > NON_ENCODED_NAME_MAX {
            return Err(err_name_too_long());
        }
        if self.Length == 0 || self.Data[self.Length as usize - 1] != b'.' {
            return Err(err_non_canonical_name());
        }
        // Root domain
        if self.Data[0] == b'.' && self.Length == 1 {
            msg.push(0);
            return Ok(msg);
        }

        let name_bytes = &self.Data[..self.Length as usize];

        let mut i = 0usize;
        let mut begin = 0usize;
        while i <= self.Length as usize {
            if i == self.Length as usize || name_bytes[i] == b'.' {
                if i == self.Length as usize {
                    // End of name — emit null terminator
                    break;
                }
                let label_len = i - begin;
                if label_len >= 64 {
                    return Err(err_seg_too_long());
                }
                if label_len == 0 {
                    return Err(err_zero_seg_len());
                }

                // Check compression for this suffix (starting at begin)
                if let Some(ref cmap) = compression {
                    let suffix_key = core::str::from_utf8(&name_bytes[begin..])
                        .unwrap_or_default()
                        .to_owned();
                    if let Some(&ptr) = cmap.get(&suffix_key) {
                        msg.push(((ptr >> 8) as u8) | 0xC0);
                        msg.push(ptr as u8);
                        return Ok(msg);
                    }
                }

                // Add to compression table
                if let Some(ref mut cmap) = compression {
                    let new_ptr = (msg.len() - compression_off) as u16;
                    if (new_ptr as usize) <= (u16::MAX as usize >> 2) {
                        let key = core::str::from_utf8(&name_bytes[begin..])
                            .unwrap_or_default()
                            .to_owned();
                        cmap.insert(key, new_ptr);
                    }
                }

                msg.push(label_len as u8);
                msg.extend_from_slice(&name_bytes[begin..i]);
                begin = i + 1;
            }
            i += 1;
        }
        msg.push(0); // null terminator
        Ok(msg)
    }

    fn unpack(&mut self, msg: &[u8], off: usize) -> Result<usize, error> {
        let mut curr_off = off;
        let mut new_off = off;
        let mut ptr_count = 0i32;
        let mut name: Vec<u8> = Vec::with_capacity(64);

        loop {
            if curr_off >= msg.len() {
                return Err(err_base_len());
            }
            let c = msg[curr_off] as usize;
            curr_off += 1;
            match c & 0xC0 {
                0x00 => {
                    if c == 0x00 {
                        break;
                    }
                    let end_off = curr_off + c;
                    if end_off > msg.len() {
                        return Err(err_calc_len());
                    }
                    for &b in &msg[curr_off..end_off] {
                        if b == b'.' {
                            return Err(err_invalid_name());
                        }
                    }
                    name.extend_from_slice(&msg[curr_off..end_off]);
                    name.push(b'.');
                    curr_off = end_off;
                }
                0xC0 => {
                    if curr_off >= msg.len() {
                        return Err(err_invalid_ptr());
                    }
                    let c1 = msg[curr_off];
                    curr_off += 1;
                    if ptr_count == 0 {
                        new_off = curr_off;
                    }
                    ptr_count += 1;
                    if ptr_count > 10 {
                        return Err(err_too_many_ptr());
                    }
                    curr_off = ((c ^ 0xC0) << 8) | c1 as usize;
                }
                _ => return Err(err_reserved()),
            }
        }

        if name.is_empty() {
            name.push(b'.');
        }
        if name.len() > NON_ENCODED_NAME_MAX {
            return Err(err_name_too_long());
        }
        self.Length = name.len() as u8;
        self.Data[..name.len()].copy_from_slice(&name);
        if ptr_count == 0 {
            new_off = curr_off;
        }
        Ok(new_off)
    }
}

fn skip_name(msg: &[u8], off: usize) -> Result<usize, error> {
    let mut new_off = off;
    loop {
        if new_off >= msg.len() {
            return Err(err_base_len());
        }
        let c = msg[new_off] as usize;
        new_off += 1;
        match c & 0xC0 {
            0x00 => {
                if c == 0x00 {
                    break;
                }
                new_off += c;
                if new_off > msg.len() {
                    return Err(err_calc_len());
                }
            }
            0xC0 => {
                new_off += 1;
                break;
            }
            _ => return Err(err_reserved()),
        }
    }
    Ok(new_off)
}

// ─── NewName / MustNewName ────────────────────────────────────────────────

pub fn NewName<S: AsRef<str>>(name: S) -> (Name, error) {
    let b = name.as_ref().as_bytes();
    if b.len() > 255 {
        return (Name::default(), err_calc_len());
    }
    let mut n = Name::default();
    n.Length = b.len() as u8;
    n.Data[..b.len()].copy_from_slice(b);
    (n, crate::errors::nil)
}

pub fn MustNewName<S: AsRef<str>>(name: S) -> Name {
    let (n, err) = NewName(name);
    if err != crate::errors::nil {
        panic!("creating name");
    }
    n
}

// ─── Question ─────────────────────────────────────────────────────────────

#[derive(Clone, Default, Debug)]
pub struct Question {
    pub Name: Name,
    pub Type: Type,
    pub Class: Class,
}

impl Question {
    fn pack(
        &self,
        msg: Vec<u8>,
        compression: Option<&mut BTreeMap<String, u16>>,
        compression_off: usize,
    ) -> Result<Vec<u8>, error> {
        let msg = self
            .Name
            .pack(msg, compression, compression_off)
            .map_err(|e| nested_err("Name", e))?;
        let msg = pack_u16(msg, self.Type);
        let msg = pack_u16(msg, self.Class);
        Ok(msg)
    }
}

// ─── ResourceHeader ───────────────────────────────────────────────────────

#[derive(Clone, Default, Debug)]
pub struct ResourceHeader {
    pub Name: Name,
    pub Type: Type,
    pub Class: Class,
    pub TTL: u32,
    pub Length: u16,
}

const EDNS0_VERSION: u32 = 0;
const EDNS0_DNSSEC_OK: u32 = 0x00008000;
const EDNS_VERSION_MASK: u32 = 0x00ff0000;
const EDNS0_DNSSEC_OK_MASK: u32 = 0x00ff8000;

impl ResourceHeader {
    pub fn SetEDNS0(&mut self, udp_payload_len: usize, ext_rcode: RCode, dnssec_ok: bool) -> error {
        self.Name = MustNewName(".");
        self.Type = TypeOPT;
        self.Class = udp_payload_len as u16;
        self.TTL = (ext_rcode as u32) >> 4 << 24;
        if dnssec_ok {
            self.TTL |= EDNS0_DNSSEC_OK;
        }
        crate::errors::nil
    }

    pub fn DNSSECAllowed(&self) -> bool {
        self.TTL & EDNS0_DNSSEC_OK_MASK == EDNS0_DNSSEC_OK
    }

    pub fn ExtendedRCode(&self, rcode: RCode) -> RCode {
        if self.TTL & EDNS_VERSION_MASK == EDNS0_VERSION {
            return ((self.TTL >> 24 << 4) as u16) | rcode;
        }
        rcode
    }

    fn pack(
        &self,
        msg: Vec<u8>,
        compression: Option<&mut BTreeMap<String, u16>>,
        compression_off: usize,
    ) -> Result<(Vec<u8>, usize), error> {
        let msg = self
            .Name
            .pack(msg, compression, compression_off)
            .map_err(|e| nested_err("Name", e))?;
        let msg = pack_u16(msg, self.Type);
        let msg = pack_u16(msg, self.Class);
        let msg = pack_u32(msg, self.TTL);
        let len_off = msg.len();
        let msg = pack_u16(msg, self.Length);
        Ok((msg, len_off))
    }

    fn unpack(&mut self, msg: &[u8], off: usize) -> Result<usize, error> {
        let mut o = off;
        o = self
            .Name
            .unpack(msg, o)
            .map_err(|e| nested_err("Name", e))?;
        let (t, no) = unpack_u16(msg, o).map_err(|e| nested_err("Type", e))?;
        self.Type = t;
        o = no;
        let (c, no) = unpack_u16(msg, o).map_err(|e| nested_err("Class", e))?;
        self.Class = c;
        o = no;
        let (ttl, no) = unpack_u32(msg, o).map_err(|e| nested_err("TTL", e))?;
        self.TTL = ttl;
        o = no;
        let (len, no) = unpack_u16(msg, o).map_err(|e| nested_err("Length", e))?;
        self.Length = len;
        o = no;
        Ok(o)
    }

    fn fix_len(msg: &mut Vec<u8>, len_off: usize, pre_len: usize) -> Result<(), error> {
        let con_len = msg.len() - pre_len;
        if con_len > u16::MAX as usize {
            return Err(err_res_too_long());
        }
        let v = con_len as u16;
        msg[len_off] = (v >> 8) as u8;
        msg[len_off + 1] = v as u8;
        Ok(())
    }
}

fn skip_resource_wire(msg: &[u8], off: usize) -> Result<usize, error> {
    let off = skip_name(msg, off).map_err(|e| nested_err("Name", e))?;
    let off = skip_u16(msg, off).map_err(|e| nested_err("Type", e))?;
    let off = skip_u16(msg, off).map_err(|e| nested_err("Class", e))?;
    let off = skip_u32(msg, off).map_err(|e| nested_err("TTL", e))?;
    let (length, off) = unpack_u16(msg, off).map_err(|e| nested_err("Length", e))?;
    let off = off + length as usize;
    if off > msg.len() {
        return Err(err_resource_len());
    }
    Ok(off)
}

// ─── ResourceBody trait ───────────────────────────────────────────────────

pub trait ResourceBody: Send + Sync {
    fn pack_body(
        &self,
        msg: Vec<u8>,
        compression: Option<&mut BTreeMap<String, u16>>,
        compression_off: usize,
    ) -> Result<Vec<u8>, error>;
    fn real_type(&self) -> Type;
    fn clone_box(&self) -> Box<dyn ResourceBody>;
}

// ─── Concrete resource record types ──────────────────────────────────────

#[derive(Clone, Default, Debug)]
pub struct AResource {
    pub A: [u8; 4],
}

#[derive(Clone, Default, Debug)]
pub struct AAAAResource {
    pub AAAA: [u8; 16],
}

#[derive(Clone, Default, Debug)]
pub struct CNAMEResource {
    pub CNAME: Name,
}

#[derive(Clone, Default, Debug)]
pub struct NSResource {
    pub NS: Name,
}

#[derive(Clone, Default, Debug)]
pub struct PTRResource {
    pub PTR: Name,
}

#[derive(Clone, Default, Debug)]
pub struct MXResource {
    pub Pref: u16,
    pub MX: Name,
}

#[derive(Clone, Default, Debug)]
pub struct SOAResource {
    pub NS: Name,
    pub MBox: Name,
    pub Serial: u32,
    pub Refresh: u32,
    pub Retry: u32,
    pub Expire: u32,
    pub MinTTL: u32,
}

#[derive(Clone, Default, Debug)]
pub struct TXTResource {
    pub TXT: Vec<String>,
}

#[derive(Clone, Default, Debug)]
pub struct SRVResource {
    pub Priority: u16,
    pub Weight: u16,
    pub Port: u16,
    pub Target: Name,
}

#[derive(Clone, Default, Debug)]
pub struct OPTResource {
    pub Options: Vec<DNSOption>,
}

#[derive(Clone, Default, Debug)]
pub struct DNSOption {
    pub Code: u16,
    pub Data: Vec<u8>,
}

#[derive(Clone, Default, Debug)]
pub struct UnknownResource {
    pub Type: Type,
    pub Data: Vec<u8>,
}

// SVCB / HTTPS
#[derive(Clone, Default, Debug)]
pub struct SVCBResource {
    pub Priority: u16,
    pub Target: Name,
    pub Params: Vec<SVCParam>,
}

#[derive(Clone, Default, Debug)]
pub struct HTTPSResource {
    pub SVCBResource: SVCBResource,
}

#[derive(Clone, Default, Debug)]
pub struct SVCParam {
    pub Key: SVCParamKey,
    pub Value: Vec<u8>,
}

pub type SVCParamKey = u16;
pub const SVCParamMandatory: SVCParamKey = 0;
pub const SVCParamALPN: SVCParamKey = 1;
pub const SVCParamNoDefaultALPN: SVCParamKey = 2;
pub const SVCParamPort: SVCParamKey = 3;
pub const SVCParamIPv4Hint: SVCParamKey = 4;
pub const SVCParamECH: SVCParamKey = 5;
pub const SVCParamIPv6Hint: SVCParamKey = 6;
pub const SVCParamDOHPath: SVCParamKey = 7;
pub const SVCParamOHTTP: SVCParamKey = 8;
pub const SVCParamTLSSupportedGroups: SVCParamKey = 9;

// ─── ResourceBody impls ───────────────────────────────────────────────────

impl ResourceBody for AResource {
    fn pack_body(
        &self,
        mut msg: Vec<u8>,
        _c: Option<&mut BTreeMap<String, u16>>,
        _co: usize,
    ) -> Result<Vec<u8>, error> {
        msg.extend_from_slice(&self.A);
        Ok(msg)
    }
    fn real_type(&self) -> Type {
        TypeA
    }
    fn clone_box(&self) -> Box<dyn ResourceBody> {
        Box::new(self.clone())
    }
}

impl ResourceBody for AAAAResource {
    fn pack_body(
        &self,
        mut msg: Vec<u8>,
        _c: Option<&mut BTreeMap<String, u16>>,
        _co: usize,
    ) -> Result<Vec<u8>, error> {
        msg.extend_from_slice(&self.AAAA);
        Ok(msg)
    }
    fn real_type(&self) -> Type {
        TypeAAAA
    }
    fn clone_box(&self) -> Box<dyn ResourceBody> {
        Box::new(self.clone())
    }
}

impl ResourceBody for CNAMEResource {
    fn pack_body(
        &self,
        msg: Vec<u8>,
        c: Option<&mut BTreeMap<String, u16>>,
        co: usize,
    ) -> Result<Vec<u8>, error> {
        self.CNAME.pack(msg, c, co)
    }
    fn real_type(&self) -> Type {
        TypeCNAME
    }
    fn clone_box(&self) -> Box<dyn ResourceBody> {
        Box::new(self.clone())
    }
}

impl ResourceBody for NSResource {
    fn pack_body(
        &self,
        msg: Vec<u8>,
        c: Option<&mut BTreeMap<String, u16>>,
        co: usize,
    ) -> Result<Vec<u8>, error> {
        self.NS.pack(msg, c, co)
    }
    fn real_type(&self) -> Type {
        TypeNS
    }
    fn clone_box(&self) -> Box<dyn ResourceBody> {
        Box::new(self.clone())
    }
}

impl ResourceBody for PTRResource {
    fn pack_body(
        &self,
        msg: Vec<u8>,
        c: Option<&mut BTreeMap<String, u16>>,
        co: usize,
    ) -> Result<Vec<u8>, error> {
        self.PTR.pack(msg, c, co)
    }
    fn real_type(&self) -> Type {
        TypePTR
    }
    fn clone_box(&self) -> Box<dyn ResourceBody> {
        Box::new(self.clone())
    }
}

impl ResourceBody for MXResource {
    fn pack_body(
        &self,
        mut msg: Vec<u8>,
        c: Option<&mut BTreeMap<String, u16>>,
        co: usize,
    ) -> Result<Vec<u8>, error> {
        msg = pack_u16(msg, self.Pref);
        self.MX
            .pack(msg, c, co)
            .map_err(|e| nested_err("MXResource.MX", e))
    }
    fn real_type(&self) -> Type {
        TypeMX
    }
    fn clone_box(&self) -> Box<dyn ResourceBody> {
        Box::new(self.clone())
    }
}

impl ResourceBody for SOAResource {
    fn pack_body(
        &self,
        msg: Vec<u8>,
        _c: Option<&mut BTreeMap<String, u16>>,
        co: usize,
    ) -> Result<Vec<u8>, error> {
        let msg = self
            .NS
            .pack(msg, None, co)
            .map_err(|e| nested_err("SOAResource.NS", e))?;
        let msg = self
            .MBox
            .pack(msg, None, co)
            .map_err(|e| nested_err("SOAResource.MBox", e))?;
        let msg = pack_u32(msg, self.Serial);
        let msg = pack_u32(msg, self.Refresh);
        let msg = pack_u32(msg, self.Retry);
        let msg = pack_u32(msg, self.Expire);
        Ok(pack_u32(msg, self.MinTTL))
    }
    fn real_type(&self) -> Type {
        TypeSOA
    }
    fn clone_box(&self) -> Box<dyn ResourceBody> {
        Box::new(self.clone())
    }
}

impl ResourceBody for TXTResource {
    fn pack_body(
        &self,
        mut msg: Vec<u8>,
        _c: Option<&mut BTreeMap<String, u16>>,
        _co: usize,
    ) -> Result<Vec<u8>, error> {
        for s in &self.TXT {
            msg = pack_text(msg, s)?;
        }
        Ok(msg)
    }
    fn real_type(&self) -> Type {
        TypeTXT
    }
    fn clone_box(&self) -> Box<dyn ResourceBody> {
        Box::new(self.clone())
    }
}

impl ResourceBody for SRVResource {
    fn pack_body(
        &self,
        mut msg: Vec<u8>,
        _c: Option<&mut BTreeMap<String, u16>>,
        co: usize,
    ) -> Result<Vec<u8>, error> {
        msg = pack_u16(msg, self.Priority);
        msg = pack_u16(msg, self.Weight);
        msg = pack_u16(msg, self.Port);
        self.Target
            .pack(msg, None, co)
            .map_err(|e| nested_err("SRVResource.Target", e))
    }
    fn real_type(&self) -> Type {
        TypeSRV
    }
    fn clone_box(&self) -> Box<dyn ResourceBody> {
        Box::new(self.clone())
    }
}

impl ResourceBody for OPTResource {
    fn pack_body(
        &self,
        mut msg: Vec<u8>,
        _c: Option<&mut BTreeMap<String, u16>>,
        _co: usize,
    ) -> Result<Vec<u8>, error> {
        for opt in &self.Options {
            msg = pack_u16(msg, opt.Code);
            msg = pack_u16(msg, opt.Data.len() as u16);
            msg.extend_from_slice(&opt.Data);
        }
        Ok(msg)
    }
    fn real_type(&self) -> Type {
        TypeOPT
    }
    fn clone_box(&self) -> Box<dyn ResourceBody> {
        Box::new(self.clone())
    }
}

impl ResourceBody for UnknownResource {
    fn pack_body(
        &self,
        mut msg: Vec<u8>,
        _c: Option<&mut BTreeMap<String, u16>>,
        _co: usize,
    ) -> Result<Vec<u8>, error> {
        msg.extend_from_slice(&self.Data);
        Ok(msg)
    }
    fn real_type(&self) -> Type {
        self.Type
    }
    fn clone_box(&self) -> Box<dyn ResourceBody> {
        Box::new(self.clone())
    }
}

impl ResourceBody for SVCBResource {
    fn pack_body(
        &self,
        msg: Vec<u8>,
        _c: Option<&mut BTreeMap<String, u16>>,
        _co: usize,
    ) -> Result<Vec<u8>, error> {
        let mut msg = pack_u16(msg, self.Priority);
        msg = self
            .Target
            .pack(msg, None, 0)
            .map_err(|e| nested_err("SVCBResource.Target", e))?;
        let mut prev_key: Option<u16> = None;
        for param in &self.Params {
            if let Some(pk) = prev_key {
                if param.Key <= pk {
                    return Err(nested_err("SVCBResource.Params", err_param_out_of_order()));
                }
            }
            if param.Value.len() > 65535 {
                return Err(nested_err("SVCBResource.Params", err_too_long_svcb_value()));
            }
            msg = pack_u16(msg, param.Key);
            msg = pack_u16(msg, param.Value.len() as u16);
            msg.extend_from_slice(&param.Value);
            prev_key = Some(param.Key);
        }
        Ok(msg)
    }
    fn real_type(&self) -> Type {
        TypeSVCB
    }
    fn clone_box(&self) -> Box<dyn ResourceBody> {
        Box::new(self.clone())
    }
}

impl ResourceBody for HTTPSResource {
    fn pack_body(
        &self,
        msg: Vec<u8>,
        c: Option<&mut BTreeMap<String, u16>>,
        co: usize,
    ) -> Result<Vec<u8>, error> {
        self.SVCBResource.pack_body(msg, c, co)
    }
    fn real_type(&self) -> Type {
        TypeHTTPS
    }
    fn clone_box(&self) -> Box<dyn ResourceBody> {
        Box::new(self.clone())
    }
}

// ─── Resource ─────────────────────────────────────────────────────────────

pub struct Resource {
    pub Header: ResourceHeader,
    pub Body: Option<Box<dyn ResourceBody>>,
}

impl Clone for Resource {
    fn clone(&self) -> Self {
        Resource {
            Header: self.Header.clone(),
            Body: self.Body.as_ref().map(|b| b.clone_box()),
        }
    }
}

// ─── Unpack helpers ───────────────────────────────────────────────────────

fn unpack_a_resource(msg: &[u8], off: usize) -> Result<AResource, error> {
    let mut a = [0u8; 4];
    if off + 4 > msg.len() {
        return Err(err_base_len());
    }
    a.copy_from_slice(&msg[off..off + 4]);
    Ok(AResource { A: a })
}

fn unpack_aaaa_resource(msg: &[u8], off: usize) -> Result<AAAAResource, error> {
    let mut aaaa = [0u8; 16];
    if off + 16 > msg.len() {
        return Err(err_base_len());
    }
    aaaa.copy_from_slice(&msg[off..off + 16]);
    Ok(AAAAResource { AAAA: aaaa })
}

fn unpack_cname_resource(msg: &[u8], off: usize) -> Result<CNAMEResource, error> {
    let mut cname = Name::default();
    cname.unpack(msg, off)?;
    Ok(CNAMEResource { CNAME: cname })
}

fn unpack_ns_resource(msg: &[u8], off: usize) -> Result<NSResource, error> {
    let mut ns = Name::default();
    ns.unpack(msg, off)?;
    Ok(NSResource { NS: ns })
}

fn unpack_ptr_resource(msg: &[u8], off: usize) -> Result<PTRResource, error> {
    let mut ptr = Name::default();
    ptr.unpack(msg, off)?;
    Ok(PTRResource { PTR: ptr })
}

fn unpack_mx_resource(msg: &[u8], off: usize) -> Result<MXResource, error> {
    let (pref, off) = unpack_u16(msg, off).map_err(|e| nested_err("Pref", e))?;
    let mut mx = Name::default();
    mx.unpack(msg, off).map_err(|e| nested_err("MX", e))?;
    Ok(MXResource { Pref: pref, MX: mx })
}

fn unpack_soa_resource(msg: &[u8], off: usize) -> Result<SOAResource, error> {
    let mut ns = Name::default();
    let off = ns.unpack(msg, off).map_err(|e| nested_err("NS", e))?;
    let mut mbox = Name::default();
    let off = mbox.unpack(msg, off).map_err(|e| nested_err("MBox", e))?;
    let (serial, off) = unpack_u32(msg, off).map_err(|e| nested_err("Serial", e))?;
    let (refresh, off) = unpack_u32(msg, off).map_err(|e| nested_err("Refresh", e))?;
    let (retry, off) = unpack_u32(msg, off).map_err(|e| nested_err("Retry", e))?;
    let (expire, off) = unpack_u32(msg, off).map_err(|e| nested_err("Expire", e))?;
    let (min_ttl, _) = unpack_u32(msg, off).map_err(|e| nested_err("MinTTL", e))?;
    Ok(SOAResource {
        NS: ns,
        MBox: mbox,
        Serial: serial,
        Refresh: refresh,
        Retry: retry,
        Expire: expire,
        MinTTL: min_ttl,
    })
}

fn unpack_txt_resource(msg: &[u8], off: usize, length: u16) -> Result<TXTResource, error> {
    let mut txts = Vec::new();
    let mut n: u16 = 0;
    let mut off = off;
    while n < length {
        let (t, new_off) = unpack_text(msg, off).map_err(|e| nested_err("text", e))?;
        if length - n < t.len() as u16 + 1 {
            return Err(err_calc_len());
        }
        n += t.len() as u16 + 1;
        off = new_off;
        txts.push(t);
    }
    Ok(TXTResource { TXT: txts })
}

fn unpack_srv_resource(msg: &[u8], off: usize) -> Result<SRVResource, error> {
    let (priority, off) = unpack_u16(msg, off).map_err(|e| nested_err("Priority", e))?;
    let (weight, off) = unpack_u16(msg, off).map_err(|e| nested_err("Weight", e))?;
    let (port, off) = unpack_u16(msg, off).map_err(|e| nested_err("Port", e))?;
    let mut target = Name::default();
    target
        .unpack(msg, off)
        .map_err(|e| nested_err("Target", e))?;
    Ok(SRVResource {
        Priority: priority,
        Weight: weight,
        Port: port,
        Target: target,
    })
}

fn unpack_opt_resource(msg: &[u8], off: usize, length: u16) -> Result<OPTResource, error> {
    let mut opts = Vec::new();
    let mut off = off;
    let end = off + length as usize;
    while off < end {
        let (code, no) = unpack_u16(msg, off).map_err(|e| nested_err("Code", e))?;
        let (l, no) = unpack_u16(msg, no).map_err(|e| nested_err("Data", e))?;
        let llen = l as usize;
        if no + llen > msg.len() {
            return Err(nested_err("Data", err_calc_len()));
        }
        let data = msg[no..no + llen].to_vec();
        off = no + llen;
        opts.push(DNSOption {
            Code: code,
            Data: data,
        });
    }
    Ok(OPTResource { Options: opts })
}

fn unpack_unknown_resource(
    rtype: Type,
    msg: &[u8],
    off: usize,
    length: u16,
) -> Result<UnknownResource, error> {
    let llen = length as usize;
    if off + llen > msg.len() {
        return Err(err_base_len());
    }
    Ok(UnknownResource {
        Type: rtype,
        Data: msg[off..off + llen].to_vec(),
    })
}

fn unpack_svcb_resource(msg: &[u8], off: usize, length: u16) -> Result<SVCBResource, error> {
    let body_end = off + length as usize;
    let mut r = SVCBResource::default();
    let (priority, mut params_off) = unpack_u16(msg, off).map_err(|e| nested_err("Priority", e))?;
    r.Priority = priority;
    params_off = r
        .Target
        .unpack(msg, params_off)
        .map_err(|e| nested_err("Target", e))?;

    // First pass: count params
    let mut n = 0usize;
    let mut tmp_off = params_off;
    let mut prev_key: Option<u16> = None;
    while tmp_off < body_end {
        let (key, no) = unpack_u16(msg, tmp_off).map_err(|e| nested_err("Params key", e))?;
        if let Some(pk) = prev_key {
            if key <= pk {
                return Err(nested_err("Params", err_param_out_of_order()));
            }
        }
        prev_key = Some(key);
        let (len, no) = unpack_u16(msg, no).map_err(|e| nested_err("Params value length", e))?;
        if no + len as usize > body_end {
            return Err(err_resource_len());
        }
        tmp_off = no + len as usize;
        n += 1;
    }
    if tmp_off != body_end {
        return Err(err_resource_len());
    }

    // Second pass: fill params
    r.Params = Vec::with_capacity(n);
    let mut off = params_off;
    for _ in 0..n {
        let (key, no) = unpack_u16(msg, off)?;
        let (len, no) = unpack_u16(msg, no)?;
        let llen = len as usize;
        r.Params.push(SVCParam {
            Key: key,
            Value: msg[no..no + llen].to_vec(),
        });
        off = no + llen;
    }
    Ok(r)
}

// ─── Parser ───────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
pub struct Parser {
    msg: Vec<u8>,
    header: WireHeader,
    section: Section,
    off: usize,
    index: usize,
    res_header_valid: bool,
    res_header_offset: usize,
    res_header_type: Type,
    res_header_length: u16,
}

impl Parser {
    pub fn new() -> Self {
        Parser::default()
    }

    pub fn Start(&mut self, msg: Vec<u8>) -> (Header, error) {
        *self = Parser::default();
        self.msg = msg;
        match WireHeader::unpack(&self.msg, 0) {
            Ok((hdr, off)) => {
                self.header = hdr;
                self.off = off;
                self.section = Section::Questions;
                (self.header.header(), crate::errors::nil)
            }
            Err(e) => (Header::default(), nested_err("unpacking header", e)),
        }
    }

    fn check_advance(&mut self, sec: Section) -> error {
        if self.section < sec {
            return ErrNotStarted.clone().into();
        }
        if self.section > sec {
            return ErrSectionDone.clone().into();
        }
        self.res_header_valid = false;
        if self.index == self.header.count(sec) as usize {
            self.index = 0;
            self.section = advance_section(sec);
            return ErrSectionDone.clone().into();
        }
        crate::errors::nil
    }

    fn resource_header_inner(&mut self, sec: Section) -> (ResourceHeader, error) {
        if self.res_header_valid {
            self.off = self.res_header_offset;
        }
        let err = self.check_advance(sec);
        if err != crate::errors::nil {
            return (ResourceHeader::default(), err);
        }
        let mut hdr = ResourceHeader::default();
        match hdr.unpack(&self.msg, self.off) {
            Ok(off) => {
                self.res_header_valid = true;
                self.res_header_offset = self.off;
                self.res_header_type = hdr.Type;
                self.res_header_length = hdr.Length;
                self.off = off;
                (hdr, crate::errors::nil)
            }
            Err(e) => (ResourceHeader::default(), e),
        }
    }

    fn skip_resource_inner(&mut self, sec: Section) -> error {
        if self.res_header_valid && self.section == sec {
            let new_off = self.off + self.res_header_length as usize;
            if new_off > self.msg.len() {
                return err_resource_len();
            }
            self.off = new_off;
            self.res_header_valid = false;
            self.index += 1;
            return crate::errors::nil;
        }
        let err = self.check_advance(sec);
        if err != crate::errors::nil {
            return err;
        }
        let msg = self.msg.clone();
        match skip_resource_wire(&msg, self.off) {
            Ok(off) => {
                self.off = off;
                self.index += 1;
                crate::errors::nil
            }
            Err(e) => {
                let sec_name = section_name(sec);
                let mut name = String::with_capacity(10 + sec_name.len());
                name.push_str("skipping: ");
                name.push_str(sec_name);
                nested_err(&name, e)
            }
        }
    }

    // ── Questions ─────────────────────────────────────────────────────

    pub fn Question(&mut self) -> (Question, error) {
        let err = self.check_advance(Section::Questions);
        if err != crate::errors::nil {
            return (Question::default(), err);
        }
        let mut name = Name::default();
        let off = match name.unpack(&self.msg, self.off) {
            Ok(o) => o,
            Err(e) => {
                return (
                    Question::default(),
                    nested_err("unpacking Question.Name", e),
                )
            }
        };
        let (typ, off) = match unpack_u16(&self.msg, off) {
            Ok(v) => v,
            Err(e) => {
                return (
                    Question::default(),
                    nested_err("unpacking Question.Type", e),
                )
            }
        };
        let (class, off) = match unpack_u16(&self.msg, off) {
            Ok(v) => v,
            Err(e) => {
                return (
                    Question::default(),
                    nested_err("unpacking Question.Class", e),
                )
            }
        };
        self.off = off;
        self.index += 1;
        (
            Question {
                Name: name,
                Type: typ,
                Class: class,
            },
            crate::errors::nil,
        )
    }

    pub fn SkipQuestion(&mut self) -> error {
        let err = self.check_advance(Section::Questions);
        if err != crate::errors::nil {
            return err;
        }
        let msg = self.msg.clone();
        let off = match skip_name(&msg, self.off) {
            Ok(o) => o,
            Err(e) => return nested_err("skipping Question Name", e),
        };
        let off = match skip_u16(&msg, off) {
            Ok(o) => o,
            Err(e) => return nested_err("skipping Question Type", e),
        };
        let off = match skip_u16(&msg, off) {
            Ok(o) => o,
            Err(e) => return nested_err("skipping Question Class", e),
        };
        self.off = off;
        self.index += 1;
        crate::errors::nil
    }

    pub fn SkipAllQuestions(&mut self) -> error {
        loop {
            let e = self.SkipQuestion();
            if e == ErrSectionDone {
                return crate::errors::nil;
            }
            if e != crate::errors::nil {
                return e;
            }
        }
    }

    // ── Answer section ────────────────────────────────────────────────

    pub fn AnswerHeader(&mut self) -> (ResourceHeader, error) {
        self.resource_header_inner(Section::Answers)
    }

    pub fn SkipAnswer(&mut self) -> error {
        self.skip_resource_inner(Section::Answers)
    }

    pub fn SkipAllAnswers(&mut self) -> error {
        loop {
            let e = self.SkipAnswer();
            if e == ErrSectionDone {
                return crate::errors::nil;
            }
            if e != crate::errors::nil {
                return e;
            }
        }
    }

    pub fn AResource(&mut self) -> (AResource, error) {
        if !self.res_header_valid || self.res_header_type != TypeA {
            return (AResource::default(), ErrNotStarted.clone().into());
        }
        match unpack_a_resource(&self.msg, self.off) {
            Ok(r) => {
                self.off += self.res_header_length as usize;
                self.res_header_valid = false;
                self.index += 1;
                (r, crate::errors::nil)
            }
            Err(e) => (AResource::default(), e),
        }
    }

    pub fn AAAAResource(&mut self) -> (AAAAResource, error) {
        if !self.res_header_valid || self.res_header_type != TypeAAAA {
            return (AAAAResource::default(), ErrNotStarted.clone().into());
        }
        match unpack_aaaa_resource(&self.msg, self.off) {
            Ok(r) => {
                self.off += self.res_header_length as usize;
                self.res_header_valid = false;
                self.index += 1;
                (r, crate::errors::nil)
            }
            Err(e) => (AAAAResource::default(), e),
        }
    }

    pub fn CNAMEResource(&mut self) -> (CNAMEResource, error) {
        if !self.res_header_valid || self.res_header_type != TypeCNAME {
            return (CNAMEResource::default(), ErrNotStarted.clone().into());
        }
        match unpack_cname_resource(&self.msg, self.off) {
            Ok(r) => {
                self.off += self.res_header_length as usize;
                self.res_header_valid = false;
                self.index += 1;
                (r, crate::errors::nil)
            }
            Err(e) => (CNAMEResource::default(), e),
        }
    }

    pub fn PTRResource(&mut self) -> (PTRResource, error) {
        if !self.res_header_valid || self.res_header_type != TypePTR {
            return (PTRResource::default(), ErrNotStarted.clone().into());
        }
        match unpack_ptr_resource(&self.msg, self.off) {
            Ok(r) => {
                self.off += self.res_header_length as usize;
                self.res_header_valid = false;
                self.index += 1;
                (r, crate::errors::nil)
            }
            Err(e) => (PTRResource::default(), e),
        }
    }

    pub fn TXTResource(&mut self) -> (TXTResource, error) {
        if !self.res_header_valid || self.res_header_type != TypeTXT {
            return (TXTResource::default(), ErrNotStarted.clone().into());
        }
        let length = self.res_header_length;
        match unpack_txt_resource(&self.msg, self.off, length) {
            Ok(r) => {
                self.off += self.res_header_length as usize;
                self.res_header_valid = false;
                self.index += 1;
                (r, crate::errors::nil)
            }
            Err(e) => (TXTResource::default(), e),
        }
    }

    pub fn MXResource(&mut self) -> (MXResource, error) {
        if !self.res_header_valid || self.res_header_type != TypeMX {
            return (MXResource::default(), ErrNotStarted.clone().into());
        }
        match unpack_mx_resource(&self.msg, self.off) {
            Ok(r) => {
                self.off += self.res_header_length as usize;
                self.res_header_valid = false;
                self.index += 1;
                (r, crate::errors::nil)
            }
            Err(e) => (MXResource::default(), e),
        }
    }

    pub fn NSResource(&mut self) -> (NSResource, error) {
        if !self.res_header_valid || self.res_header_type != TypeNS {
            return (NSResource::default(), ErrNotStarted.clone().into());
        }
        match unpack_ns_resource(&self.msg, self.off) {
            Ok(r) => {
                self.off += self.res_header_length as usize;
                self.res_header_valid = false;
                self.index += 1;
                (r, crate::errors::nil)
            }
            Err(e) => (NSResource::default(), e),
        }
    }

    pub fn SOAResource(&mut self) -> (SOAResource, error) {
        if !self.res_header_valid || self.res_header_type != TypeSOA {
            return (SOAResource::default(), ErrNotStarted.clone().into());
        }
        match unpack_soa_resource(&self.msg, self.off) {
            Ok(r) => {
                self.off += self.res_header_length as usize;
                self.res_header_valid = false;
                self.index += 1;
                (r, crate::errors::nil)
            }
            Err(e) => (SOAResource::default(), e),
        }
    }

    pub fn SRVResource(&mut self) -> (SRVResource, error) {
        if !self.res_header_valid || self.res_header_type != TypeSRV {
            return (SRVResource::default(), ErrNotStarted.clone().into());
        }
        match unpack_srv_resource(&self.msg, self.off) {
            Ok(r) => {
                self.off += self.res_header_length as usize;
                self.res_header_valid = false;
                self.index += 1;
                (r, crate::errors::nil)
            }
            Err(e) => (SRVResource::default(), e),
        }
    }

    pub fn OPTResource(&mut self) -> (OPTResource, error) {
        if !self.res_header_valid || self.res_header_type != TypeOPT {
            return (OPTResource::default(), ErrNotStarted.clone().into());
        }
        let length = self.res_header_length;
        match unpack_opt_resource(&self.msg, self.off, length) {
            Ok(r) => {
                self.off += self.res_header_length as usize;
                self.res_header_valid = false;
                self.index += 1;
                (r, crate::errors::nil)
            }
            Err(e) => (OPTResource::default(), e),
        }
    }

    // ── Authority section ─────────────────────────────────────────────

    pub fn AuthorityHeader(&mut self) -> (ResourceHeader, error) {
        self.resource_header_inner(Section::Authorities)
    }

    pub fn SkipAuthority(&mut self) -> error {
        self.skip_resource_inner(Section::Authorities)
    }

    pub fn SkipAllAuthorities(&mut self) -> error {
        loop {
            let e = self.SkipAuthority();
            if e == ErrSectionDone {
                return crate::errors::nil;
            }
            if e != crate::errors::nil {
                return e;
            }
        }
    }

    // ── Additional section ────────────────────────────────────────────

    pub fn AdditionalHeader(&mut self) -> (ResourceHeader, error) {
        self.resource_header_inner(Section::Additionals)
    }

    pub fn SkipAdditional(&mut self) -> error {
        self.skip_resource_inner(Section::Additionals)
    }

    pub fn SkipAllAdditionals(&mut self) -> error {
        loop {
            let e = self.SkipAdditional();
            if e == ErrSectionDone {
                return crate::errors::nil;
            }
            if e != crate::errors::nil {
                return e;
            }
        }
    }
}

// ─── Builder ──────────────────────────────────────────────────────────────

const PACK_STARTING_CAP: usize = 512;

pub struct Builder {
    msg: Vec<u8>,
    section: Section,
    header: WireHeader,
    start: usize,
    compression: Option<BTreeMap<String, u16>>,
}

pub fn NewBuilder(buf: Vec<u8>, h: Header) -> Builder {
    let mut msg = if buf.is_empty() {
        Vec::with_capacity(PACK_STARTING_CAP)
    } else {
        buf
    };
    let start = msg.len();
    let (id, bits) = h.pack();
    // Reserve 12 bytes for wire header
    msg.extend_from_slice(&[0u8; 12]);
    Builder {
        msg,
        section: Section::Header_,
        header: WireHeader {
            id,
            bits,
            ..Default::default()
        },
        start,
        compression: None,
    }
}

impl Builder {
    pub fn EnableCompression(&mut self) {
        self.compression = Some(BTreeMap::new());
    }

    fn start_check(&self, s: Section) -> error {
        if self.section <= Section::NotStarted {
            return ErrNotStarted.clone().into();
        }
        if self.section > s {
            return ErrSectionDone.clone().into();
        }
        crate::errors::nil
    }

    pub fn StartQuestions(&mut self) -> error {
        let e = self.start_check(Section::Questions);
        if e != crate::errors::nil {
            return e;
        }
        self.section = Section::Questions;
        crate::errors::nil
    }

    pub fn StartAnswers(&mut self) -> error {
        let e = self.start_check(Section::Answers);
        if e != crate::errors::nil {
            return e;
        }
        self.section = Section::Answers;
        crate::errors::nil
    }

    pub fn StartAuthorities(&mut self) -> error {
        let e = self.start_check(Section::Authorities);
        if e != crate::errors::nil {
            return e;
        }
        self.section = Section::Authorities;
        crate::errors::nil
    }

    pub fn StartAdditionals(&mut self) -> error {
        let e = self.start_check(Section::Additionals);
        if e != crate::errors::nil {
            return e;
        }
        self.section = Section::Additionals;
        crate::errors::nil
    }

    fn increment_section_count(&mut self) -> error {
        match self.section {
            Section::Questions => {
                if self.header.questions == u16::MAX {
                    return errors::New("too many Questions to pack (>65535)");
                }
                self.header.questions += 1;
            }
            Section::Answers => {
                if self.header.answers == u16::MAX {
                    return errors::New("too many Answers to pack (>65535)");
                }
                self.header.answers += 1;
            }
            Section::Authorities => {
                if self.header.authorities == u16::MAX {
                    return errors::New("too many Authorities to pack (>65535)");
                }
                self.header.authorities += 1;
            }
            Section::Additionals => {
                if self.header.additionals == u16::MAX {
                    return errors::New("too many Additionals to pack (>65535)");
                }
                self.header.additionals += 1;
            }
            _ => {}
        }
        crate::errors::nil
    }

    pub fn Question(&mut self, q: Question) -> error {
        if self.section < Section::Questions {
            return ErrNotStarted.clone().into();
        }
        if self.section > Section::Questions {
            return ErrSectionDone.clone().into();
        }
        let msg = core::mem::take(&mut self.msg);
        match q.pack(msg, self.compression.as_mut(), self.start) {
            Ok(m) => {
                self.msg = m;
                self.increment_section_count()
            }
            Err(e) => e,
        }
    }

    fn check_resource_section(&self) -> error {
        if self.section < Section::Answers {
            return ErrNotStarted.clone().into();
        }
        if self.section > Section::Additionals {
            return ErrSectionDone.clone().into();
        }
        crate::errors::nil
    }

    fn add_resource<B: ResourceBody>(&mut self, mut hdr: ResourceHeader, body: &B) -> error {
        let e = self.check_resource_section();
        if e != crate::errors::nil {
            return e;
        }
        hdr.Type = body.real_type();
        let msg = core::mem::take(&mut self.msg);
        let (msg, len_off) = match hdr.pack(msg, self.compression.as_mut(), self.start) {
            Ok(v) => v,
            Err(e) => return nested_err("ResourceHeader", e),
        };
        let pre_len = msg.len();
        let msg = match body.pack_body(msg, self.compression.as_mut(), self.start) {
            Ok(m) => m,
            Err(e) => return e,
        };
        let mut msg = msg;
        if let Err(e) = ResourceHeader::fix_len(&mut msg, len_off, pre_len) {
            return e;
        }
        self.msg = msg;
        self.increment_section_count()
    }

    pub fn AResource(&mut self, h: ResourceHeader, r: AResource) -> error {
        self.add_resource(h, &r)
    }
    pub fn AAAAResource(&mut self, h: ResourceHeader, r: AAAAResource) -> error {
        self.add_resource(h, &r)
    }
    pub fn CNAMEResource(&mut self, h: ResourceHeader, r: CNAMEResource) -> error {
        self.add_resource(h, &r)
    }
    pub fn NSResource(&mut self, h: ResourceHeader, r: NSResource) -> error {
        self.add_resource(h, &r)
    }
    pub fn PTRResource(&mut self, h: ResourceHeader, r: PTRResource) -> error {
        self.add_resource(h, &r)
    }
    pub fn MXResource(&mut self, h: ResourceHeader, r: MXResource) -> error {
        self.add_resource(h, &r)
    }
    pub fn SOAResource(&mut self, h: ResourceHeader, r: SOAResource) -> error {
        self.add_resource(h, &r)
    }
    pub fn TXTResource(&mut self, h: ResourceHeader, r: TXTResource) -> error {
        self.add_resource(h, &r)
    }
    pub fn SRVResource(&mut self, h: ResourceHeader, r: SRVResource) -> error {
        self.add_resource(h, &r)
    }
    pub fn OPTResource(&mut self, h: ResourceHeader, r: OPTResource) -> error {
        self.add_resource(h, &r)
    }
    pub fn UnknownResource(&mut self, h: ResourceHeader, r: UnknownResource) -> error {
        self.add_resource(h, &r)
    }
    pub fn SVCBResource(&mut self, h: ResourceHeader, r: SVCBResource) -> error {
        self.add_resource(h, &r)
    }
    pub fn HTTPSResource(&mut self, h: ResourceHeader, r: HTTPSResource) -> error {
        self.add_resource(h, &r)
    }

    pub fn Finish(mut self) -> (Vec<u8>, error) {
        if self.section < Section::Header_ {
            return (Vec::new(), ErrNotStarted.clone().into());
        }
        self.section = Section::Done;
        let start = self.start;
        self.header.pack_into(&mut self.msg, start);
        (self.msg, crate::errors::nil)
    }
}

// ─── Wire-format helpers ──────────────────────────────────────────────────

fn pack_u16(mut msg: Vec<u8>, v: u16) -> Vec<u8> {
    msg.push((v >> 8) as u8);
    msg.push(v as u8);
    msg
}

fn unpack_u16(msg: &[u8], off: usize) -> Result<(u16, usize), error> {
    if off + 2 > msg.len() {
        return Err(err_base_len());
    }
    Ok(((msg[off] as u16) << 8 | msg[off + 1] as u16, off + 2))
}

fn skip_u16(msg: &[u8], off: usize) -> Result<usize, error> {
    if off + 2 > msg.len() {
        return Err(err_base_len());
    }
    Ok(off + 2)
}

fn pack_u32(mut msg: Vec<u8>, v: u32) -> Vec<u8> {
    msg.push((v >> 24) as u8);
    msg.push((v >> 16) as u8);
    msg.push((v >> 8) as u8);
    msg.push(v as u8);
    msg
}

fn unpack_u32(msg: &[u8], off: usize) -> Result<(u32, usize), error> {
    if off + 4 > msg.len() {
        return Err(err_base_len());
    }
    let v = (msg[off] as u32) << 24
        | (msg[off + 1] as u32) << 16
        | (msg[off + 2] as u32) << 8
        | msg[off + 3] as u32;
    Ok((v, off + 4))
}

fn skip_u32(msg: &[u8], off: usize) -> Result<usize, error> {
    if off + 4 > msg.len() {
        return Err(err_base_len());
    }
    Ok(off + 4)
}

fn pack_text(mut msg: Vec<u8>, s: &str) -> Result<Vec<u8>, error> {
    if s.len() > 255 {
        return Err(err_string_too_long());
    }
    msg.push(s.len() as u8);
    msg.extend_from_slice(s.as_bytes());
    Ok(msg)
}

fn unpack_text(msg: &[u8], off: usize) -> Result<(String, usize), error> {
    if off >= msg.len() {
        return Err(err_base_len());
    }
    let begin = off + 1;
    let end = begin + msg[off] as usize;
    if end > msg.len() {
        return Err(err_calc_len());
    }
    let bytes = &msg[begin..end];
    // Replace invalid UTF-8 bytes with '?' (no-std safe, no format!)
    let mut s = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b < 0x80 {
            s.push(b as char);
            i += 1;
        } else {
            // Try to decode a multi-byte UTF-8 sequence
            let width = if b < 0xE0 {
                2
            } else if b < 0xF0 {
                3
            } else {
                4
            };
            if i + width <= bytes.len() {
                match core::str::from_utf8(&bytes[i..i + width]) {
                    Ok(chunk) => {
                        s.push_str(chunk);
                        i += width;
                    }
                    Err(_) => {
                        s.push('\u{FFFD}');
                        i += 1;
                    }
                }
            } else {
                s.push('\u{FFFD}');
                i += 1;
            }
        }
    }
    Ok((s, end))
}
