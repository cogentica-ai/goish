// go: file net/mail/message.go decls: ReadMessage, readHeader, dateLayouts, ParseDate, Header.Get, Header.Date, Header.AddressList, ParseAddress, ParseAddressList, AddressParser.Parse, AddressParser.ParseList, Address.String, addrParser.parseAddressList, addrParser.parseSingleAddress, addrParser.parseAddress, addrParser.consumeGroupList, addrParser.consumeAddrSpec, addrParser.consumePhrase, addrParser.consumeQuotedString, addrParser.consumeAtom, addrParser.consumeDomainLiteral, addrParser.consumeDisplayNameComment, addrParser.consume, addrParser.skipSpace, addrParser.peek, addrParser.empty, addrParser.len, addrParser.skipCFWS, addrParser.consumeComment, addrParser.decodeRFC2047Word, rfc2047Decoder, charsetError.Error, isAtext, isQtext, quoteString, isVchar, isMultibyte, isWSP, isDtext
//
// message.go — RFC 5322 message and address parsing.
//
// The address half of this file is an RFC 5322 lexer wearing a
// four-function API, and it was the part goish did not have: the port
// carried `Message`, `ReadMessage`, `readHeader` and `Header`, and
// stopped there. `ParseAddress`, `ParseAddressList`, `Address.String`,
// `AddressParser`, `ParseDate`, `Header.Date` and `Header.AddressList`
// were all absent — four of thirty-eight functions, and none of the
// ones a caller reaches for.
//
// `ParseDate` in particular could not have worked before now: it hands
// `time.Parse` a layout ending in "-0700" and expects the offset back,
// which a `time.Location` with no offset could not carry. It is
// portable in this tree only because `Location` gained a real name and
// offset first.
//
// goish deviations, all local:
//
//   * `debugT`/`debug.Printf` are omitted — they are `if debug {}`
//     tracing with no behaviour attached.
//   * Go's `addrParser` holds `dec *mime.WordDecoder`, nil meaning
//     "use the package default". goish's is an `Option`, which is the
//     same nil.
//   * `consumeAddrSpec`'s `defer func() { if err != nil { *p = orig } }()`
//     restores the parser on any error exit. Rust has no such defer
//     over a named result, so each error path restores explicitly and
//     is marked; the set of paths is the set Go's defer covers.
//   * Go slices `p.s` with `p.s[i:]`; goish's `string` slices with
//     `.slice(a, b)`, and `utf8::DecodeRune` takes the bytes where
//     Go's `DecodeRuneInString` takes the string. Both are the same
//     decoder over the same bytes.

#![allow(non_snake_case)]
// goishlint:ignore GOISH018 Printf — `debugT.Printf` is `if debug {}` tracing with no behaviour attached; goish drops the whole facility.
// goishlint:ignore GOISH021 debugT, debug — see the GOISH018 waiver above: the type and the package var exist only to carry that tracing.

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::bufio;
use crate::errors::{self, error, nil};
use crate::gomap::map;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::mime;
use crate::net::textproto;
use crate::strings;
use crate::time;
use crate::types::byte;
use crate::unicode::utf8;
use crate::{fmt, int, rune};

// ─── Message (message.go:46) ────────────────────────────────────────

// go: sdk 1.25.5 net/mail/message.go:46-49 Message
/// Go: "A Message represents a parsed mail message."
pub struct Message {
    pub Header: Header,
    pub Body: Box<dyn io::Reader>,
}

// go: sdk 1.25.5 net/mail/message.go:54-66 ReadMessage
/// Go: "ReadMessage reads a message from r. The headers are parsed, and
/// the body of the message will be available for reading from msg.Body."
///
/// goish returns `(Option<Message>, error)` where Go returns a pointer.
pub fn ReadMessage<R: io::Reader + 'static>(r: R) -> (Option<Message>, error) {
    // Go: tp := textproto.NewReader(bufio.NewReader(r))
    let mut tp = textproto::NewReader(bufio::NewReader(r));

    // Go: hdr, err := readHeader(tp)
    let (hdr, err) = readHeader(&mut tp);

    // Go: if err != nil && (err != io.EOF || len(hdr) == 0) { return nil, err }
    if err != nil && (!errors::Is(err.clone(), io::EOF) || hdr.Len() == 0) {
        return (None, err);
    }

    // Go: return &Message{ Header: Header(hdr), Body: tp.R }, nil
    let body: Box<dyn io::Reader> = Box::new(tp.R);
    return (
        Some(Message {
            Header: Header(hdr),
            Body: body,
        }),
        nil,
    );
}

// go: sdk 1.25.5 net/mail/message.go:75-114 readHeader
/// Go: "readHeader reads the message headers from r. This is like
/// textproto.ReadMIMEHeader, but doesn't validate. The fix for issue
/// #53188 tightened up net/textproto to enforce restrictions of RFC
/// 7230. This package implements RFC 5322, which does not have those
/// restrictions."
// goishlint:ignore GOISH023 — Go's `readHeader` ends in `for { … }` with
// every exit a `return` inside the loop; the Rust `loop` is that same
// construct and has no reachable tail value to return.
fn readHeader<R: io::Reader>(r: &mut textproto::Reader<R>) -> (map<string, slice<string>>, error) {
    // Go: m := make(map[string][]string)
    let mut m: map<string, slice<string>> = map::new();

    // Go: if buf, err := r.R.Peek(1); err == nil && (buf[0] == ' ' || buf[0] == '\t')
    {
        let (buf, perr) = r.R.Peek(1);
        if perr == nil && buf.Len() >= 1 && (buf[0] == b' ' || buf[0] == b'\t') {
            // Go: line, err := r.ReadLine()
            let (line, err) = r.ReadLine();
            if err != nil {
                return (m, err);
            }
            // Go: return m, errors.New("malformed initial line: " + line)
            let msg = string::from_static("malformed initial line: ") + line;
            return (m, errors::New(msg));
        }
    }

    loop {
        // Go: kv, err := r.ReadContinuedLine()
        let (kv, err) = r.ReadContinuedLine();
        // Go: if kv == "" { return m, err }
        if kv.Len() == 0 {
            return (m, err);
        }

        // Go: k, v, ok := strings.Cut(kv, ":")
        let (k, v, ok) = strings::Cut(kv.clone(), string::from_static(":"));
        if !ok {
            let msg = string::from_static("malformed header line: ") + kv;
            return (m, errors::New(msg));
        }

        // Go: key := textproto.CanonicalMIMEHeaderKey(k)
        let key = textproto::CanonicalMIMEHeaderKey(k);

        // Go: if key == "" { continue }
        if key.Len() == 0 {
            continue;
        }

        // Go: value := strings.TrimLeft(v, " \t")
        let value = strings::TrimLeft(v, string::from_static(" \t"));

        // Go: m[key] = append(m[key], value)
        let mut cur: Vec<string> = if m.Has(key.clone()) {
            m[key.clone()].clone().__into_vec()
        } else {
            Vec::new()
        };
        cur.push(value);
        m[key] = slice::__from_vec(cur);

        if err != nil {
            return (m, err);
        }
    }
}

// ─── ParseDate (message.go:118) ─────────────────────────────────────

// go: sdk 1.25.5 net/mail/message.go:118-145 dateLayouts
/// Go: "Generate layouts based on RFC 5322, section 3.3."
///
/// Go builds these once with `sync.OnceValue` over five nested loops.
/// goish builds them per call: the product is 48 short strings, and a
/// `OnceValue` here would need a lock for no measured gain. The
/// GENERATION is Go's, loop for loop, so the SET and its ORDER match —
/// and the order matters, because `ParseDate` returns the first layout
/// that parses.
fn dateLayouts() -> Vec<string> {
    // Go: dows := [...]string{"", "Mon, "}
    let dows: [&str; 2] = ["", "Mon, "];
    // Go: days := [...]string{"2", "02"}
    let days: [&str; 2] = ["2", "02"];
    // Go: years := [...]string{"2006", "06"}
    let years: [&str; 2] = ["2006", "06"];
    // Go: seconds := [...]string{":05", ""}
    let seconds: [&str; 2] = [":05", ""];
    // Go: "-0700 (MST)" is not in RFC 5322, but is common.
    let zones: [&str; 3] = ["-0700", "MST", "UT"];

    let mut layouts: Vec<string> = Vec::with_capacity(48);
    for dow in dows {
        for day in days {
            for year in years {
                for second in seconds {
                    for zone in zones {
                        // Go: s := dow + day + " Jan " + year + " 15:04" + second + " " + zone
                        let s = string::from_bytes(dow.as_bytes())
                            + string::from_bytes(day.as_bytes())
                            + string::from_static(" Jan ")
                            + string::from_bytes(year.as_bytes())
                            + string::from_static(" 15:04")
                            + string::from_bytes(second.as_bytes())
                            + string::from_static(" ")
                            + string::from_bytes(zone.as_bytes());
                        layouts.push(s);
                    }
                }
            }
        }
    }
    return layouts;
}

// go: sdk 1.25.5 net/mail/message.go:147-194 ParseDate
/// Go: "ParseDate parses an RFC 5322 date string."
pub fn ParseDate<S: Into<string>>(date: S) -> (time::Time, error) {
    let mut date: string = date.into();
    // Go: CR and LF must match and are tolerated anywhere in the date field.
    date = strings::ReplaceAll(date, string::from_static("\r\n"), string::from_static(""));
    if strings::Contains(date.clone(), string::from_static("\r")) {
        return (
            time::Time::default(),
            errors::New("mail: header has a CR without LF"),
        );
    }
    // Go: Re-using some addrParser methods which support obsolete
    // text, i.e. non-printable ASCII.
    let mut p = addrParser {
        s: date.clone(),
        dec: None,
    };
    p.skipSpace();

    // Go: RFC 5322: zone = (FWS ( "+" / "-" ) 4DIGIT) / obs-zone
    // zone length is always 5 chars unless obsolete (obs-zone)
    let ind = strings::IndexAny(p.s.clone(), string::from_static("+-"));
    if ind != -1 && p.len() >= ind + 5 {
        date = p.s.slice(0, ind + 5);
        p.s = p.s.slice(ind + 5, p.len());
    } else {
        let mut ind = strings::Index(p.s.clone(), string::from_static("T"));
        if ind == 0 {
            // Go: In this case we have the following date formats:
            // * Thu, 20 Nov 1997 09:55:06 MDT
            // * Thu, 20 Nov 1997 09:55:06 MDT (MDT)
            // * Thu, 20 Nov 1997 09:55:06 MDT (This comment)
            ind = strings::Index(p.s.slice(1, p.len()), string::from_static("T"));
            if ind != -1 {
                ind += 1;
            }
        }

        if ind != -1 && p.len() >= ind + 5 {
            // Go: The last letter T of the obsolete time zone is
            // checked when no standard time zone is found. If T is
            // misplaced, the date to parse is garbage.
            date = p.s.slice(0, ind + 1);
            p.s = p.s.slice(ind + 1, p.len());
        }
    }
    if !p.skipCFWS() {
        return (
            time::Time::default(),
            errors::New("mail: misformatted parenthetical comment"),
        );
    }
    for layout in dateLayouts() {
        let (t, err) = time::Parse(layout, date.clone());
        if err == nil {
            return (t, nil);
        }
    }
    return (
        time::Time::default(),
        errors::New("mail: header could not be parsed"),
    );
}

// ─── Header (message.go:196) ────────────────────────────────────────

// go: sdk 1.25.5 net/mail/message.go:196-196 Header
/// Go: "A Header represents the key-value pairs in a mail message
/// header."
///
/// goish wraps the map in a tuple struct so `Get` can hang off it —
/// `MIMEHeader` is a `pub type` alias and cannot carry inherent
/// methods. The field is public, which is Go's "access the map
/// directly" for non-canonical keys.
pub struct Header(pub map<string, slice<string>>);

impl Header {
    // go: sdk 1.25.5 net/mail/message.go:204-206 Header.Get
    /// Go: "Get gets the first value associated with the given key. It
    /// is case insensitive; CanonicalMIMEHeaderKey is used to
    /// canonicalize the provided key. If there are no values associated
    /// with the key, Get returns ""."
    pub fn Get<K: Into<string>>(&self, key: K) -> string {
        let key: string = key.into();
        return textproto::Get(&self.0, key);
    }

    // go: sdk 1.25.5 net/mail/message.go:211-217 Header.Date
    /// Go: "Date parses the Date header field."
    pub fn Date(&self) -> (time::Time, error) {
        // Go: hdr := h.Get("Date")
        let hdr = self.Get("Date");
        // Go: if hdr == "" { return time.Time{}, ErrHeaderNotPresent }
        if hdr.Len() == 0 {
            return (time::Time::default(), ErrHeaderNotPresent.into());
        }
        return ParseDate(hdr);
    }

    // go: sdk 1.25.5 net/mail/message.go:220-226 Header.AddressList
    /// Go: "AddressList parses the named header field as a list of
    /// addresses."
    pub fn AddressList<K: Into<string>>(&self, key: K) -> (Vec<Address>, error) {
        // Go: hdr := h.Get(key)
        let hdr = self.Get(key);
        // Go: if hdr == "" { return nil, ErrHeaderNotPresent }
        if hdr.Len() == 0 {
            return (Vec::new(), ErrHeaderNotPresent.into());
        }
        return ParseAddressList(hdr);
    }

    // go: none — goish idiom: Go writes `len(h)` on the map directly;
    //     goish's Header wraps it, so the length is a method.
    pub fn Len(&self) -> int {
        return self.0.Len();
    }

    // go: none — goish idiom: Go writes `_, ok := h[k]` on the map
    //     directly; goish's Header wraps it.
    pub fn Has<K: Into<string>>(&self, key: K) -> bool {
        let key: string = key.into();
        let k = textproto::CanonicalMIMEHeaderKey(key);
        return self.0.Has(k);
    }
}

// go: sdk 1.25.5 net/mail/message.go:208-208 ErrHeaderNotPresent
crate::var! {
    pub ErrHeaderNotPresent: error = "mail: header not in message";
}

// ─── Address (message.go:231) ───────────────────────────────────────

// go: sdk 1.25.5 net/mail/message.go:231-234 Address
/// Go: "Address represents a single mail address. An address such as
/// "Barry Gibbs <bg@example.com>" is represented as Address{Name: "Barry
/// Gibbs", Address: "bg@example.com"}."
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Address {
    /// Go: "Proper name; may be empty."
    pub Name: string,
    /// Go: "user@domain"
    pub Address: string,
}

// go: sdk 1.25.5 net/mail/message.go:237-239 ParseAddress
/// Go: "ParseAddress parses a single RFC 5322 address, e.g. "Barry Gibbs
/// <bg@example.com>""
pub fn ParseAddress<S: Into<string>>(address: S) -> (Address, error) {
    let mut p = addrParser {
        s: address.into(),
        dec: None,
    };
    return p.parseSingleAddress();
}

// go: sdk 1.25.5 net/mail/message.go:242-244 ParseAddressList
/// Go: "ParseAddressList parses the given string as a list of
/// addresses."
pub fn ParseAddressList<S: Into<string>>(list: S) -> (Vec<Address>, error) {
    let mut p = addrParser {
        s: list.into(),
        dec: None,
    };
    return p.parseAddressList();
}

// go: sdk 1.25.5 net/mail/message.go:247-250 AddressParser
/// Go: "An AddressParser is an RFC 5322 address parser."
#[derive(Default)]
pub struct AddressParser {
    /// Go: "WordDecoder optionally specifies a decoder for RFC 2047
    /// encoded-words."
    pub WordDecoder: Option<mime::WordDecoder>,
}

impl AddressParser {
    // go: sdk 1.25.5 net/mail/message.go:254-256 AddressParser.Parse
    /// Go: "Parse parses a single RFC 5322 address of the form "Gogh Fir
    /// <gf@example.com>" or "foo@example.com"."
    pub fn Parse<S: Into<string>>(&self, address: S) -> (Address, error) {
        let mut p = addrParser {
            s: address.into(),
            dec: self.WordDecoder.clone(),
        };
        return p.parseSingleAddress();
    }

    // go: sdk 1.25.5 net/mail/message.go:260-262 AddressParser.ParseList
    /// Go: "ParseList parses the given string as a list of
    /// comma-separated addresses of the form "Gogh Fir
    /// <gf@example.com>" or "foo@example.com"."
    pub fn ParseList<S: Into<string>>(&self, list: S) -> (Vec<Address>, error) {
        let mut p = addrParser {
            s: list.into(),
            dec: self.WordDecoder.clone(),
        };
        return p.parseAddressList();
    }
}

impl Address {
    // go: sdk 1.25.5 net/mail/message.go:267-327 Address.String
    /// Go: "String formats the address as a valid RFC 5322 address. If
    /// the address's name contains non-ASCII characters the name will be
    /// rendered according to RFC 2047."
    pub fn String(&self) -> string {
        // Go: Format address local@domain
        let at = strings::LastIndex(self.Address.clone(), string::from_static("@"));
        let mut local: string;
        let mut domain = string::from_static("");
        if at < 0 {
            // Go: This is a malformed address ("@" is required in
            // addr-spec); treat the whole address as local-part.
            local = self.Address.clone();
        } else {
            local = self.Address.slice(0, at);
            domain = self.Address.slice(at + 1, self.Address.Len());
        }

        // Go: Add quotes if needed
        let mut quoteLocal = false;
        // Go ranges the STRING, so `i` is a byte offset and `r` a rune.
        let lb = local.as_bytes().to_vec();
        let mut i: int = 0;
        while i < int(lb.len()) {
            let (r, size) = utf8::DecodeRune(&lb[i.unsigned_abs() as usize..]);
            if isAtext(r, false) {
                i += size;
                continue;
            }
            if r == rune('.') {
                // Go: Dots are okay if they are surrounded by atext. We
                // only need to check that the previous byte is not a
                // dot, and this isn't the end of the string.
                if i > 0 && lb[(i - 1).unsigned_abs() as usize] != b'.' && i < int(lb.len()) - 1 {
                    i += size;
                    continue;
                }
            }
            quoteLocal = true;
            break;
        }
        if quoteLocal {
            local = quoteString(local);
        }

        // Go: s := "<" + local + "@" + domain + ">"
        let s = string::from_static("<")
            + local
            + string::from_static("@")
            + domain
            + string::from_static(">");

        // Go: if a.Name == "" { return s }
        if self.Name.Len() == 0 {
            return s;
        }

        // Go: If every character is printable ASCII, quoting is simple.
        let mut allPrintable = true;
        let nb = self.Name.as_bytes().to_vec();
        let mut j: int = 0;
        while j < int(nb.len()) {
            let (r, size) = utf8::DecodeRune(&nb[j.unsigned_abs() as usize..]);
            // Go: isWSP here should actually be isFWS, but we don't
            // support folding yet.
            if !isVchar(r) && !isWSP(r) || isMultibyte(r) {
                allPrintable = false;
                break;
            }
            j += size;
        }
        if allPrintable {
            return quoteString(self.Name.clone()) + string::from_static(" ") + s;
        }

        // Go: Text in an encoded-word in a display-name must not contain
        // certain characters like quotes or parentheses (see RFC 2047
        // section 5.3). When this is the case encode the name using
        // base64 encoding.
        if strings::ContainsAny(
            self.Name.clone(),
            string::from_static("\"#$%&'(),.:;<>@[]^`{|}~"),
        ) {
            return mime::BEncoding.Encode("utf-8", self.Name.clone())
                + string::from_static(" ")
                + s;
        }
        return mime::QEncoding.Encode("utf-8", self.Name.clone()) + string::from_static(" ") + s;
    }
}

// ─── addrParser (message.go:330) ────────────────────────────────────

// go: sdk 1.25.5 net/mail/message.go:330-333 addrParser
/// The RFC 5322 lexer. `dec` is Go's `*mime.WordDecoder`, nil meaning
/// "use the package default".
#[derive(Clone)]
struct addrParser {
    s: string,
    dec: Option<mime::WordDecoder>,
}

impl addrParser {
    // go: sdk 1.25.5 net/mail/message.go:335-369 addrParser.parseAddressList
    fn parseAddressList(&mut self) -> (Vec<Address>, error) {
        // Go: var list []*Address
        let mut list: Vec<Address> = Vec::new();
        loop {
            self.skipSpace();

            // Go: allow skipping empty entries (RFC5322 obs-addr-list)
            if self.consume(b',') {
                continue;
            }

            let (addrs, err) = self.parseAddress(true);
            if err != nil {
                return (Vec::new(), err);
            }
            // Go: list = append(list, addrs...)
            list.extend(addrs);

            if !self.skipCFWS() {
                return (
                    Vec::new(),
                    errors::New("mail: misformatted parenthetical comment"),
                );
            }
            if self.empty() {
                break;
            }
            if self.peek() != b',' {
                return (Vec::new(), errors::New("mail: expected comma"));
            }

            // Go: Skip empty entries for obs-addr-list.
            while self.consume(b',') {
                self.skipSpace();
            }
            if self.empty() {
                break;
            }
        }
        return (list, nil);
    }

    // go: sdk 1.25.5 net/mail/message.go:372-390 addrParser.parseSingleAddress
    fn parseSingleAddress(&mut self) -> (Address, error) {
        let (addrs, err) = self.parseAddress(true);
        if err != nil {
            return (Address::default(), err);
        }
        if !self.skipCFWS() {
            return (
                Address::default(),
                errors::New("mail: misformatted parenthetical comment"),
            );
        }
        if !self.empty() {
            return (
                Address::default(),
                fmt::Errorf!("mail: expected single address, got %q", self.s.clone()),
            );
        }
        if addrs.is_empty() {
            return (Address::default(), errors::New("mail: empty group"));
        }
        if addrs.len() > 1 {
            return (
                Address::default(),
                errors::New("mail: group with multiple addresses"),
            );
        }
        return (addrs[0].clone(), nil);
    }

    // go: sdk 1.25.5 net/mail/message.go:393-473 addrParser.parseAddress
    /// Go: "parseAddress parses a single RFC 5322 address at the start
    /// of p."
    fn parseAddress(&mut self, handleGroup: bool) -> (Vec<Address>, error) {
        self.skipSpace();
        if self.empty() {
            return (Vec::new(), errors::New("mail: no address"));
        }

        // Go: address = mailbox / group
        //     mailbox = name-addr / addr-spec
        //     group = display-name ":" [group-list] ";" [CFWS]
        //
        // Go: addr-spec has a more restricted grammar than name-addr,
        // so try parsing it first, and fallback to name-addr.
        let (spec, err) = self.consumeAddrSpec();
        if err == nil {
            let mut displayName = string::from_static("");
            self.skipSpace();
            if !self.empty() && self.peek() == b'(' {
                let (d, e) = self.consumeDisplayNameComment();
                if e != nil {
                    return (Vec::new(), e);
                }
                displayName = d;
            }

            return (
                alloc::vec![Address {
                    Name: displayName,
                    Address: spec,
                }],
                nil,
            );
        }

        // Go: display-name
        let mut displayName = string::from_static("");
        if self.peek() != b'<' {
            let (d, e) = self.consumePhrase();
            if e != nil {
                return (Vec::new(), e);
            }
            displayName = d;
        }

        self.skipSpace();
        if handleGroup {
            if self.consume(b':') {
                return self.consumeGroupList();
            }
        }
        // Go: angle-addr = "<" addr-spec ">"
        if !self.consume(b'<') {
            let mut atext = true;
            let db = displayName.as_bytes().to_vec();
            let mut i: int = 0;
            while i < int(db.len()) {
                let (r, size) = utf8::DecodeRune(&db[i.unsigned_abs() as usize..]);
                if !isAtext(r, true) {
                    atext = false;
                    break;
                }
                i += size;
            }
            if atext {
                // Go: The input is like "foo.bar"; it's possible the
                // input meant to be "foo.bar@domain", or "foo.bar <...>".
                return (Vec::new(), errors::New("mail: missing '@' or angle-addr"));
            }
            // Go: The input is like "Full Name", which couldn't possibly
            // be a valid email address if followed by "@domain"; the
            // input likely meant to be "Full Name <...>".
            return (Vec::new(), errors::New("mail: no angle-addr"));
        }
        let (spec2, err2) = self.consumeAddrSpec();
        if err2 != nil {
            return (Vec::new(), err2);
        }
        if !self.consume(b'>') {
            return (Vec::new(), errors::New("mail: unclosed angle-addr"));
        }

        return (
            alloc::vec![Address {
                Name: displayName,
                Address: spec2,
            }],
            nil,
        );
    }

    // go: sdk 1.25.5 net/mail/message.go:476-510 addrParser.consumeGroupList
    fn consumeGroupList(&mut self) -> (Vec<Address>, error) {
        let mut group: Vec<Address> = Vec::new();
        // Go: handle empty group.
        self.skipSpace();
        if self.consume(b';') {
            if !self.skipCFWS() {
                return (
                    Vec::new(),
                    errors::New("mail: misformatted parenthetical comment"),
                );
            }
            return (group, nil);
        }

        loop {
            self.skipSpace();
            // Go: embedded groups not allowed.
            let (addrs, err) = self.parseAddress(false);
            if err != nil {
                return (Vec::new(), err);
            }
            group.extend(addrs);

            if !self.skipCFWS() {
                return (
                    Vec::new(),
                    errors::New("mail: misformatted parenthetical comment"),
                );
            }
            if self.consume(b';') {
                if !self.skipCFWS() {
                    return (
                        Vec::new(),
                        errors::New("mail: misformatted parenthetical comment"),
                    );
                }
                break;
            }
            if !self.consume(b',') {
                return (Vec::new(), errors::New("mail: expected comma"));
            }
        }
        return (group, nil);
    }

    // go: sdk 1.25.5 net/mail/message.go:513-572 addrParser.consumeAddrSpec
    /// Go: "consumeAddrSpec parses a single RFC 5322 addr-spec at the
    /// start of p."
    ///
    /// Go restores the parser on any error with
    /// `defer func() { if err != nil { *p = orig } }()`. goish restores
    /// explicitly at each error return — the paths marked RESTORE below
    /// are exactly the ones that defer covers.
    fn consumeAddrSpec(&mut self) -> (string, error) {
        // Go: orig := *p
        let orig = self.clone();

        // Go: local-part = dot-atom / quoted-string
        let localPart: string;
        self.skipSpace();
        if self.empty() {
            *self = orig; // RESTORE
            return (string::from_static(""), errors::New("mail: no addr-spec"));
        }
        let mut err: error;
        if self.peek() == b'"' {
            // Go: quoted-string
            let (lp, e) = self.consumeQuotedString();
            localPart = lp;
            err = e;
            if localPart.Len() == 0 {
                err = errors::New("mail: empty quoted string in addr-spec");
            }
        } else {
            // Go: dot-atom
            let (lp, e) = self.consumeAtom(true, false);
            localPart = lp;
            err = e;
        }
        if err != nil {
            *self = orig; // RESTORE
            return (string::from_static(""), err);
        }

        if !self.consume(b'@') {
            *self = orig; // RESTORE
            return (
                string::from_static(""),
                errors::New("mail: missing @ in addr-spec"),
            );
        }

        // Go: domain = dot-atom / domain-literal
        let domain: string;
        self.skipSpace();
        if self.empty() {
            *self = orig; // RESTORE
            return (
                string::from_static(""),
                errors::New("mail: no domain in addr-spec"),
            );
        }

        if self.peek() == b'[' {
            // Go: domain-literal
            let (d, e) = self.consumeDomainLiteral();
            if e != nil {
                *self = orig; // RESTORE
                return (string::from_static(""), e);
            }
            domain = d;
        } else {
            // Go: dot-atom
            let (d, e) = self.consumeAtom(true, false);
            if e != nil {
                *self = orig; // RESTORE
                return (string::from_static(""), e);
            }
            domain = d;
        }

        return (localPart + string::from_static("@") + domain, nil);
    }

    // go: sdk 1.25.5 net/mail/message.go:575-625 addrParser.consumePhrase
    /// Go: "consumePhrase parses the RFC 5322 phrase at the start of p."
    fn consumePhrase(&mut self) -> (string, error) {
        // Go: phrase = 1*word
        let mut words: Vec<string> = Vec::new();
        let mut isPrevEncoded = false;
        let mut err: error = nil;
        loop {
            // Go: obs-phrase allows CFWS after one word
            if !words.is_empty() {
                if !self.skipCFWS() {
                    return (
                        string::from_static(""),
                        errors::New("mail: misformatted parenthetical comment"),
                    );
                }
            }
            // Go: word = atom / quoted-string
            let mut word: string;
            self.skipSpace();
            if self.empty() {
                break;
            }
            let mut isEncoded = false;
            if self.peek() == b'"' {
                // Go: quoted-string
                let (w, e) = self.consumeQuotedString();
                word = w;
                err = e;
            } else {
                // Go: atom. We actually parse dot-atom here to be more
                // permissive than what RFC 5322 specifies.
                let (w, e) = self.consumeAtom(true, true);
                word = w;
                err = e;
                if err == nil {
                    let (w2, enc, e2) = self.decodeRFC2047Word(word.clone());
                    word = w2;
                    isEncoded = enc;
                    err = e2;
                }
            }

            if err != nil {
                break;
            }
            if isPrevEncoded && isEncoded {
                // Go: words[len(words)-1] += word
                let last = words.len() - 1;
                words[last] = words[last].clone() + word;
            } else {
                words.push(word);
            }
            isPrevEncoded = isEncoded;
        }
        // Go: Ignore any error if we got at least one word.
        if err != nil && words.is_empty() {
            return (
                string::from_static(""),
                fmt::Errorf!("mail: missing word in phrase: %v", err),
            );
        }
        // Go: phrase = strings.Join(words, " ")
        let phrase = strings::Join(slice::__from_vec(words), string::from_static(" "));
        return (phrase, nil);
    }

    // go: sdk 1.25.5 net/mail/message.go:628-679 addrParser.consumeQuotedString
    /// Go: "consumeQuotedString parses the quoted string at the start of
    /// p."
    fn consumeQuotedString(&mut self) -> (string, error) {
        // Go: Assume first byte is '"'.
        let mut i: int = 1;
        let mut qsb: Vec<byte> = Vec::with_capacity(10);
        let mut escaped = false;
        let sb = self.s.as_bytes().to_vec();

        loop {
            let (r, size) = utf8::DecodeRune(&sb[i.unsigned_abs() as usize..]);

            if size == 0 {
                return (
                    string::from_static(""),
                    errors::New("mail: unclosed quoted-string"),
                );
            } else if size == 1 && r == utf8::RuneError {
                return (
                    string::from_static(""),
                    fmt::Errorf!("mail: invalid utf-8 in quoted-string: %q", self.s.clone()),
                );
            } else if escaped {
                // Go: quoted-pair = ("\" (VCHAR / WSP))
                if !isVchar(r) && !isWSP(r) {
                    return (
                        string::from_static(""),
                        fmt::Errorf!("mail: bad character in quoted-string: %q", r),
                    );
                }
                appendRune(&mut qsb, r);
                escaped = false;
            } else if isQtext(r) || isWSP(r) {
                // Go: qtext (printable US-ASCII excluding " and \), or
                // FWS (almost; we're ignoring CRLF)
                appendRune(&mut qsb, r);
            } else if r == rune('"') {
                break;
            } else if r == rune('\\') {
                escaped = true;
            } else {
                return (
                    string::from_static(""),
                    fmt::Errorf!("mail: bad character in quoted-string: %q", r),
                );
            }

            i += size;
        }
        self.s = self.s.slice(i + 1, self.s.Len());
        return (string::__from_vec(qsb), nil);
    }

    // go: sdk 1.25.5 net/mail/message.go:682-716 addrParser.consumeAtom
    /// Go: "consumeAtom parses an RFC 5322 atom at the start of p. If
    /// dot is true, consumeAtom parses an RFC 5322 dot-atom instead. If
    /// permissive is true, consumeAtom will not fail on:
    /// - leading/trailing/double dots in the atom (see
    /// golang.org/issue/4938)"
    fn consumeAtom(&mut self, dot: bool, permissive: bool) -> (string, error) {
        let mut i: int = 0;
        let sb = self.s.as_bytes().to_vec();

        loop {
            let (r, size) = utf8::DecodeRune(&sb[i.unsigned_abs() as usize..]);
            if size == 1 && r == utf8::RuneError {
                return (
                    string::from_static(""),
                    fmt::Errorf!("mail: invalid utf-8 in address: %q", self.s.clone()),
                );
            } else if size == 0 || !isAtext(r, dot) {
                break;
            } else {
                i += size;
            }
        }

        if i == 0 {
            return (string::from_static(""), errors::New("mail: invalid string"));
        }
        // Go: atom, p.s = p.s[:i], p.s[i:]
        let atom = self.s.slice(0, i);
        self.s = self.s.slice(i, self.s.Len());
        if !permissive {
            if strings::HasPrefix(atom.clone(), string::from_static(".")) {
                return (
                    string::from_static(""),
                    errors::New("mail: leading dot in atom"),
                );
            }
            if strings::Contains(atom.clone(), string::from_static("..")) {
                return (
                    string::from_static(""),
                    errors::New("mail: double dot in atom"),
                );
            }
            if strings::HasSuffix(atom.clone(), string::from_static(".")) {
                return (
                    string::from_static(""),
                    errors::New("mail: trailing dot in atom"),
                );
            }
        }
        return (atom, nil);
    }

    // go: sdk 1.25.5 net/mail/message.go:719-760 addrParser.consumeDomainLiteral
    /// Go: "consumeDomainLiteral parses an RFC 5322 domain-literal at
    /// the start of p."
    fn consumeDomainLiteral(&mut self) -> (string, error) {
        // Go: Skip the leading [
        if !self.consume(b'[') {
            return (
                string::from_static(""),
                errors::New("mail: missing \"[\" in domain-literal"),
            );
        }

        // Go: Parse the dtext
        let dtext_all = self.s.clone();
        let mut dtextLen: int = 0;
        loop {
            if self.empty() {
                return (
                    string::from_static(""),
                    errors::New("mail: unclosed domain-literal"),
                );
            }
            if self.peek() == b']' {
                break;
            }

            let (r, size) = utf8::DecodeRune(self.s.as_bytes());
            if size == 1 && r == utf8::RuneError {
                return (
                    string::from_static(""),
                    fmt::Errorf!("mail: invalid utf-8 in domain-literal: %q", self.s.clone()),
                );
            }
            if !isDtext(r) {
                return (
                    string::from_static(""),
                    fmt::Errorf!("mail: bad character in domain-literal: %q", r),
                );
            }

            dtextLen += size;
            self.s = self.s.slice(size, self.s.Len());
        }
        let dtext = dtext_all.slice(0, dtextLen);

        // Go: Skip the trailing ]
        if !self.consume(b']') {
            return (
                string::from_static(""),
                errors::New("mail: unclosed domain-literal"),
            );
        }

        // Go: Check if the domain literal is an IP address
        if crate::net::ParseIP(dtext.clone()).IsNil() {
            return (
                string::from_static(""),
                fmt::Errorf!("mail: invalid IP address in domain-literal: %q", dtext),
            );
        }

        return (
            string::from_static("[") + dtext + string::from_static("]"),
            nil,
        );
    }

    // go: sdk 1.25.5 net/mail/message.go:763-784 addrParser.consumeDisplayNameComment
    fn consumeDisplayNameComment(&mut self) -> (string, error) {
        if !self.consume(b'(') {
            return (
                string::from_static(""),
                errors::New("mail: comment does not start with ("),
            );
        }
        let (comment, ok) = self.consumeComment();
        if !ok {
            return (
                string::from_static(""),
                errors::New("mail: misformatted parenthetical comment"),
            );
        }

        // Go: words := strings.FieldsFunc(comment, func(r rune) bool {
        //         return r == ' ' || r == '\t' })
        let words0 = strings::FieldsFunc(comment, |r: rune| {
            return r == rune(' ') || r == rune('\t');
        });
        let mut words: Vec<string> = words0.__into_vec();
        let mut idx = 0usize;
        while idx < words.len() {
            let (decoded, isEncoded, err) = self.decodeRFC2047Word(words[idx].clone());
            if err != nil {
                return (string::from_static(""), err);
            }
            if isEncoded {
                words[idx] = decoded;
            }
            idx += 1;
        }

        return (
            strings::Join(slice::__from_vec(words), string::from_static(" ")),
            nil,
        );
    }

    // go: sdk 1.25.5 net/mail/message.go:787-793 addrParser.consume
    fn consume(&mut self, c: byte) -> bool {
        if self.empty() || self.peek() != c {
            return false;
        }
        self.s = self.s.slice(1, self.s.Len());
        return true;
    }

    // go: sdk 1.25.5 net/mail/message.go:796-798 addrParser.skipSpace
    /// Go: "skipSpace skips the leading space and tab characters."
    fn skipSpace(&mut self) {
        self.s = strings::TrimLeft(self.s.clone(), string::from_static(" \t"));
    }

    // go: sdk 1.25.5 net/mail/message.go:800-802 addrParser.peek
    fn peek(&self) -> byte {
        return self.s.as_bytes()[0];
    }

    // go: sdk 1.25.5 net/mail/message.go:804-806 addrParser.empty
    fn empty(&self) -> bool {
        return self.len() == 0;
    }

    // go: sdk 1.25.5 net/mail/message.go:808-810 addrParser.len
    fn len(&self) -> int {
        return self.s.Len();
    }

    // go: sdk 1.25.5 net/mail/message.go:813-828 addrParser.skipCFWS
    /// Go: "skipCFWS skips CFWS as defined in RFC5322."
    fn skipCFWS(&mut self) -> bool {
        self.skipSpace();

        loop {
            if !self.consume(b'(') {
                break;
            }

            let (_, ok) = self.consumeComment();
            if !ok {
                return false;
            }

            self.skipSpace();
        }

        return true;
    }

    // go: sdk 1.25.5 net/mail/message.go:831-854 addrParser.consumeComment
    fn consumeComment(&mut self) -> (string, bool) {
        // Go: '(' already consumed.
        let mut depth: int = 1;

        let mut comment = string::from_static("");
        loop {
            if self.empty() || depth == 0 {
                break;
            }

            if self.peek() == b'\\' && self.len() > 1 {
                self.s = self.s.slice(1, self.s.Len());
            } else if self.peek() == b'(' {
                depth += 1;
            } else if self.peek() == b')' {
                depth -= 1;
            }
            if depth > 0 {
                comment = comment + self.s.slice(0, 1);
            }
            self.s = self.s.slice(1, self.s.Len());
        }

        return (comment, depth == 0);
    }

    // go: sdk 1.25.5 net/mail/message.go:857-897 addrParser.decodeRFC2047Word
    /// Go substitutes its own `CharsetReader` so it can tell whether a
    /// `Decode` error came from the charset rather than the encoding,
    /// and reports `isEncoded=true` in that case.
    ///
    /// goish's `WordDecoder.CharsetReader` is an `Option<fn>`, a plain
    /// function pointer with no captured state, so the wrapper closure
    /// Go installs cannot be expressed. The observable rule it
    /// implements is reproduced directly: with no caller-supplied
    /// reader, any charset that is not one of the built-in ones IS the
    /// charset error, which is the `rfc2047Decoder` case.
    fn decodeRFC2047Word(&self, s: string) -> (string, bool, error) {
        let dec = match &self.dec {
            Some(d) => d.clone(),
            // Go: `dec = &rfc2047Decoder` — the package default, whose
            // CharsetReader rejects every charset it is asked about.
            None => rfc2047Decoder(),
        };

        let (word, err) = dec.Decode(s.clone());
        if err == nil {
            return (word, true, nil);
        }

        // Go: If the error came from the character set reader (meaning
        // the character set itself is invalid but the decoding worked
        // fine until then), return the original text and the error,
        // with isEncoded=true.
        if isCharsetError(&err) {
            return (s, true, err);
        }

        // Go: Ignore invalid RFC 2047 encoded-word errors.
        return (s, false, nil);
    }
}

// go: sdk 1.25.5 net/mail/message.go:900-904 rfc2047Decoder
/// Go: `var rfc2047Decoder = mime.WordDecoder{CharsetReader: func(...)
/// { return nil, charsetError(charset) }}` — a decoder that handles the
/// charsets `mime` knows natively and REJECTS every other one, so that
/// an unknown charset is reported rather than silently passed through.
///
/// goish builds it per call rather than as a package var: it holds one
/// `fn` pointer and nothing else, so there is no state to share.
fn rfc2047Decoder() -> mime::WordDecoder {
    return mime::WordDecoder {
        CharsetReader: Some(rejectCharset),
    };
}

// go: none — goish idiom: the closure Go writes inline as
//     `rfc2047Decoder`'s CharsetReader. goish's CharsetReader is a bare
//     `fn` pointer, which cannot be a closure, so it is named.
fn rejectCharset(charset: string, _input: slice<byte>) -> (string, error) {
    return (string::from_static(""), errors::Wrap(charsetError(charset)));
}

// go: none — goish idiom: Go distinguishes a charset failure from an
//     encoding failure by installing its own CharsetReader and setting
//     a flag inside it. goish's CharsetReader is a bare `fn` pointer
//     with nowhere to put that flag, so the same distinction is drawn
//     from the error the decoder returns.
fn isCharsetError(err: &error) -> bool {
    return strings::Contains(err.Error(), string::from_static("charset not supported"));
}

// go: none — goish idiom: Go's `type charsetError string` is a named
//     string type with an Error method; goish spells it a newtype so
//     the method has somewhere to live. The anchor is on the method.
/// Go: `type charsetError string`.
pub struct charsetError(pub string);

impl crate::errors::ErrorTrait for charsetError {
    // go: sdk 1.25.5 net/mail/message.go:908-910 charsetError.Error
    /// Go: `fmt.Sprintf("charset not supported: %q", string(e))`.
    fn Error(&self) -> string {
        return fmt::Sprintf!("charset not supported: %q", self.0.clone());
    }
}

// go: none — goish idiom: Go's `qsb = append(qsb, r)` appends a RUNE to
//     a `[]rune` and `string(qsb)` re-encodes at the end. goish builds
//     the UTF-8 bytes directly, which is the same string.
fn appendRune(b: &mut Vec<byte>, r: rune) {
    let mut buf = [0u8; 4];
    let n = utf8::EncodeRune(&mut buf, r);
    let mut k: int = 0;
    while k < n {
        b.push(buf[k.unsigned_abs() as usize]);
        k += 1;
    }
}

// ─── Character classes (message.go:914) ─────────────────────────────

// go: sdk 1.25.5 net/mail/message.go:912-925 isAtext
/// Go: "isAtext reports whether r is an RFC 5322 atext character. If dot
/// is true, period is included."
fn isAtext(r: rune, dot: bool) -> bool {
    if r == rune('.') {
        return dot;
    }
    // Go: RFC 5322 3.2.3. specials
    if r == rune('(')
        || r == rune(')')
        || r == rune('<')
        || r == rune('>')
        || r == rune('[')
        || r == rune(']')
        || r == rune(':')
        || r == rune(';')
        || r == rune('@')
        || r == rune('\\')
        || r == rune(',')
        || r == rune('"')
    {
        return false;
    }
    return isVchar(r);
}

// go: sdk 1.25.5 net/mail/message.go:927-934 isQtext
/// Go: "isQtext reports whether r is an RFC 5322 qtext character."
fn isQtext(r: rune) -> bool {
    // Go: Printable US-ASCII, excluding backslash or quote.
    if r == rune('\\') || r == rune('"') {
        return false;
    }
    return isVchar(r);
}

// go: sdk 1.25.5 net/mail/message.go:936-950 quoteString
/// Go: "quoteString renders a string as an RFC 5322 quoted-string."
fn quoteString(s: string) -> string {
    let mut b: Vec<byte> = Vec::new();
    b.push(b'"');
    let sb = s.as_bytes().to_vec();
    let mut i: int = 0;
    while i < int(sb.len()) {
        let (r, size) = utf8::DecodeRune(&sb[i.unsigned_abs() as usize..]);
        if isQtext(r) || isWSP(r) {
            appendRune(&mut b, r);
        } else if isVchar(r) {
            b.push(b'\\');
            appendRune(&mut b, r);
        }
        i += size;
    }
    b.push(b'"');
    return string::__from_vec(b);
}

// go: sdk 1.25.5 net/mail/message.go:952-957 isVchar
/// Go: "isVchar reports whether r is an RFC 5322 VCHAR character."
fn isVchar(r: rune) -> bool {
    // Go: Visible (printing) characters.
    return rune('!') <= r && r <= rune('~') || isMultibyte(r);
}

// go: sdk 1.25.5 net/mail/message.go:959-963 isMultibyte
/// Go: "isMultibyte reports whether r is a multi-byte UTF-8 character as
/// supported by RFC 6532."
fn isMultibyte(r: rune) -> bool {
    return r >= rune(utf8::RuneSelf);
}

// go: sdk 1.25.5 net/mail/message.go:965-969 isWSP
/// Go: "isWSP reports whether r is a WSP (white space). WSP is a space
/// or horizontal tab (RFC 5234 Appendix B)."
fn isWSP(r: rune) -> bool {
    return r == rune(' ') || r == rune('\t');
}

// go: sdk 1.25.5 net/mail/message.go:970-976 isDtext
/// Go: "isDtext reports whether r is an RFC 5322 dtext character."
fn isDtext(r: rune) -> bool {
    // Go: Printable US-ASCII, excluding "[", "]", or "\".
    if r == rune('[') || r == rune(']') || r == rune('\\') {
        return false;
    }
    return isVchar(r);
}
