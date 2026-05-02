// net/mail — RFC 5322 mail message parsing (slim).
//
// Line-by-line port of:
//   /nix/store/60z37432vmgkg54krwr1z057bqwp7583-go-1.25.5/share/go/src/
//     net/mail/message.go        (Message, ReadMessage, readHeader, Header)
//
// Slim deviations:
//   * `ParseDate`, `Header.Date`, `Header.AddressList`, `ParseAddress`,
//     `ParseAddressList`, `AddressParser`, `Address` and the entire
//     addrParser machinery are **not ported in v1**. They depend on a
//     ~600-LOC RFC 5322 lexer that is its own future iteration.
//   * `Message.Body` is `Box<dyn io::Reader>` — the boxed bufio reader
//     left over after the textproto reader finished the headers.
//   * `debugT` (logging in debug mode) is omitted entirely.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::bufio;
use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::gomap::map;
use crate::gostring::string;
use crate::io;
use crate::net::textproto;
use crate::strings;
use crate::types::int;

// ─── Message (message.go:46) ────────────────────────────────────────

// Go: message.go:46-49
//   type Message struct {
//       Header Header
//       Body   io.Reader
//   }
pub struct Message {
    pub Header: Header,
    pub Body: Box<dyn io::Reader>,
}

// ─── ReadMessage (message.go:54) ────────────────────────────────────

// Go: message.go:54-66
//   func ReadMessage(r io.Reader) (msg *Message, err error) { ... }
//
// Slim: returns `(Option<Message>, error)` instead of a pointer.
// `R: io::Reader + 'static` is required because the bufio.Reader
// is boxed and stored in `Message.Body`.
pub fn ReadMessage<R: io::Reader + 'static>(r: R) -> (Option<Message>, error) {
    // Go: tp := textproto.NewReader(bufio.NewReader(r))
    let mut tp = textproto::NewReader(bufio::NewReader(r));

    // Go: hdr, err := readHeader(tp)
    let (hdr, err) = readHeader(&mut tp);

    // Go: if err != nil && (err != io.EOF || len(hdr) == 0) { return nil, err }
    if err != nil && (!errors::Is(err.clone(), io::EOF()) || hdr.Len() == 0) {
        return (None, err);
    }

    // Go: return &Message{ Header: Header(hdr), Body: tp.R }, nil
    let body: Box<dyn io::Reader> = Box::new(tp.R);
    (
        Some(Message {
            Header: Header(hdr),
            Body: body,
        }),
        nil,
    )
}

// ─── readHeader (message.go:75) ─────────────────────────────────────

// Go: message.go:75-114
//   func readHeader(r *textproto.Reader) (map[string][]string, error)
//
// "Like textproto.ReadMIMEHeader but doesn't validate" — RFC 5322
// permits non-ASCII bytes in header values (RFC 6532), and net/mail
// does not enforce RFC 7230's restrictions.
fn readHeader<R: io::Reader>(
    r: &mut textproto::Reader<R>,
) -> (map<string, slice<string>>, error) {
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
            let msg = crate::Sprintf!("malformed initial line: {}", line);
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
            let msg = crate::Sprintf!("malformed header line: {}", kv);
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

// ─── Header (message.go:196) ────────────────────────────────────────

// Go: message.go:196
//   type Header map[string][]string
//
// Slim: a tuple-struct wrapper so we can hang `.Get()` off it without
// stomping on `MIMEHeader` (which is a `pub type` alias and can't have
// inherent methods). The inner field is exposed for direct map access
// (matches Go: "access the map directly" for non-canonical keys).
pub struct Header(pub map<string, slice<string>>);

impl Header {
    // Go: message.go:204-206
    //   func (h Header) Get(key string) string {
    //       return textproto.MIMEHeader(h).Get(key)
    //   }
    pub fn Get<K: Into<string>>(&self, key: K) -> string {
        let key: string = key.into();
        textproto::Get(&self.0, key)
    }

    // Convenience: header count. Not in Go but useful for tests since
    // accessing the inner map directly is verbose.
    pub fn Len(&self) -> int {
        self.0.Len()
    }

    // Convenience: existence check (Go does `_, ok := h[k]` directly).
    pub fn Has<K: Into<string>>(&self, key: K) -> bool {
        let key: string = key.into();
        let k = textproto::CanonicalMIMEHeaderKey(key);
        self.0.Has(k)
    }
}

// Go: message.go:208
//   var ErrHeaderNotPresent = errors.New("mail: header not in message")
//
// Cached singleton — every call returns the same Arc so
// `errors::Is(err, ErrHeaderNotPresent())` works.
pub fn ErrHeaderNotPresent() -> error {
    use crate::runtime::spin::SpinLock;
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(errors::New(string::from_static("mail: header not in message")));
    }
    g.as_ref().unwrap().clone()
}
