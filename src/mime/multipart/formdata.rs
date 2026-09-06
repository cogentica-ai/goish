// go: file mime/multipart/formdata.go decls: Form.RemoveAll, FileHeader.Open, Reader.ReadForm, Reader.readForm
//
// mime/multipart/formdata.go — the parsed multipart/form-data form.
//
// goish's multipart Reader is EAGER: `NewReader` takes the whole body
// as bytes and every `Part.Body` is already in memory. That removes
// Go's spill-to-disk half wholesale — `readForm`'s temp file,
// `FileHeader.tmpfile/tmpoff/tmpshared`, and `Form.RemoveAll`'s unlink
// loop have nothing to do here. What is kept is the ACCOUNTING: the
// same memory budget, the same ErrMessageTooLarge, so a caller that
// bounds an upload still gets it bounded.

#![allow(non_snake_case)]

extern crate alloc;

#[allow(unused_imports)] // used by the `var!` expansion below
use crate::errors::error;
use crate::types::int64;

// ─── File / FileHeader (Go 1.25 src/mime/multipart/formdata.go) ───────
//
// `File` is the interface a server-side handler receives for an
// uploaded part. Go composes it from io.{Reader, ReaderAt, Seeker,
// Closer}. Goish models it as a trait that requires the same four
// behaviours; concrete impls (e.g. an `os.File`-backed wrapper) must
// satisfy all four. The interface itself appears in user code mainly
// as a stored field type — `pub Data: File` lowers to `Box<dyn File +
// Send + Sync>` via the boxed-trait field convention.
pub trait File:
    crate::io::Reader + crate::io::ReaderAt + crate::io::Seeker + crate::io::Closer
{
}

// Blanket: any type that already implements all four io traits is a
// `File`. Lets call sites store concrete readers without explicit
// `impl File for MyT {}`.
impl<T> File for T where
    T: crate::io::Reader + crate::io::ReaderAt + crate::io::Seeker + crate::io::Closer
{
}

/// `multipart.Form` (Go 1.25 src/mime/multipart/formdata.go:234) — the
/// parsed multipart form: the plain values, and the file parts keyed by
/// field name.
///
/// Go's `File` is `map[string][]*FileHeader`; goish carries values, the
/// same choice `[]*http.Cookie` gets as `slice<Cookie>` — nothing
/// mutates a FileHeader through the map.
#[derive(Clone, Default)]
pub struct Form {
    /// Go: "Value map[string][]string".
    pub Value:
        crate::gomap::map<crate::gostring::string, crate::goslice::slice<crate::gostring::string>>,
    /// Go: "File map[string][]*FileHeader".
    pub File: crate::gomap::map<crate::gostring::string, crate::goslice::slice<FileHeader>>,
}

impl Form {
    // go: none — goish's FileHeader has no `tmpfile` field yet, so this
    // is Go's body with the only branch it has statically absent. See
    // the doc comment.
    /// `(*Form).RemoveAll()` (formdata.go:240) — Go removes the
    /// temporary files a large upload spilled to disk.
    ///
    /// goish's FileHeader has no `tmpfile` field yet (the private
    /// spill-to-disk members are deferred with the Reader port), so
    /// every part is in memory and there is nothing to unlink. Go's own
    /// body skips a header whose tmpfile is "", which is every header
    /// here — so this returns nil for the same reason Go's would, not
    /// as a stub.
    pub fn RemoveAll(&self) -> crate::error {
        return crate::errors::nil;
    }
}

/// `multipart.FileHeader` (Go 1.25 src/mime/multipart/formdata.go:271)
/// — the metadata for an uploaded file part.
///
/// Go's private trio is `content []byte`, `tmpfile string` and
/// `tmpoff/tmpshared`: a part that fits in the caller's memory budget
/// is kept in `content`, a larger one spills to a temp file. goish
/// carries `content` and NOT the spill, because its multipart Reader
/// is eager — the whole body is already in memory before ReadForm is
/// called, so spilling would write out bytes it is holding anyway.
#[derive(Clone, Default)]
pub struct FileHeader {
    /// Original filename as supplied by the client.
    pub Filename: crate::gostring::string,
    /// Headers attached to this part (Content-Type, Content-Disposition,
    /// etc.). `MIMEHeader` is `map<string, slice<string>>` per
    /// `net/textproto`.
    pub Header: crate::net::textproto::MIMEHeader,
    /// File size in bytes.
    pub Size: i64,
    /// Go's unexported `content []byte`.
    pub(crate) content: crate::goslice::slice<crate::types::byte>,
}

impl FileHeader {
    // go: sdk 1.25.5 mime/multipart/formdata.go:268-282 FileHeader.Open
    /// Go: "Open opens and returns the [FileHeader]'s associated File."
    ///
    /// Go returns the `File` INTERFACE (Reader + ReaderAt + Seeker +
    /// Closer), satisfied by either a `sectionReadCloser` over the
    /// temp file or a `bytes.Reader` over `content`. goish has only the
    /// second case, so it returns that reader concretely; the error is
    /// kept in the signature because Go's has one and the disk case
    /// would need it.
    pub fn Open(&self) -> (crate::bytes::Reader, crate::error) {
        return (
            crate::bytes::NewReader(self.content.clone()),
            crate::errors::nil,
        );
    }
}

// go: none — goish-only: Go's `Part.Header` and `FileHeader.Header`
// are both `textproto.MIMEHeader`; goish's Part carries an
// `http.Header`, which is the same map under a different name. This is
// the copy across.
fn __to_mime_header(h: &crate::net::http::Header) -> crate::net::textproto::MIMEHeader {
    let mut out: crate::net::textproto::MIMEHeader = crate::gomap::map::new();
    for (k, v) in h.__inner().__iter() {
        out.Set(k.clone(), v.clone());
    }
    return out;
}

// go: sdk 1.25.5 mime/multipart/formdata.go:20-20 ErrMessageTooLarge
crate::var! {
    /// Go: "ErrMessageTooLarge is returned by ReadForm if the message
    /// form data is too large to be processed."
    pub ErrMessageTooLarge: error = "multipart: message too large";
}

// go: none — goish-only: Go's `mimeHeaderSize` lives beside readForm
// and sums the header map's key and value lengths plus per-entry
// overhead. Same sum here; it is only ever a budget input.
fn mimeHeaderSize(h: &crate::net::textproto::MIMEHeader) -> int64 {
    // Go: `size := 400` then 200 per entry plus key/value lengths.
    let mut size: int64 = 400;
    let keys = h.Keys();
    for i in 0..keys.len() {
        let k = keys[i].clone();
        size += crate::int64(k.Len()) + 200;
        let (vv, _) = h.Get(k);
        for j in 0..crate::len(&vv) {
            size += crate::int64(vv[j].Len());
        }
    }
    return size;
}

impl super::reader::Reader {
    // go: sdk 1.25.5 mime/multipart/formdata.go:32-34 Reader.ReadForm
    /// Go: "ReadForm parses an entire multipart message whose parts
    /// have a Content-Disposition of 'form-data'. It stores up to
    /// maxMemory bytes + 10MB (reserved for non-file parts) in memory."
    ///
    /// The 10MB slop is Go's, and its own comment calls it
    /// "overly-large and unconfigurable […] but difficult to change
    /// within the constraints of the API as documented". It is
    /// reproduced rather than tidied, because a caller that passes
    /// maxMemory expecting Go's budget would otherwise get a different
    /// one.
    ///
    /// goish stores every part in memory: its Reader already holds the
    /// whole body, so Go's spill-to-disk branch has nothing to spill.
    /// The BUDGET is still enforced — an oversized form is
    /// ErrMessageTooLarge here exactly as there.
    pub fn ReadForm(&mut self, maxMemory: int64) -> (Form, crate::error) {
        return self.readForm(maxMemory);
    }

    // go: sdk 1.25.5 mime/multipart/formdata.go:41-215 Reader.readForm
    fn readForm(&mut self, maxMemory: int64) -> (Form, crate::error) {
        let mut form = Form {
            Value: crate::gomap::map::new(),
            File: crate::gomap::map::new(),
        };
        // Go: maxParts is 1000 unless GODEBUG says otherwise; goish has
        // no godebug, so it is the default.
        let mut maxParts: int64 = 1000;

        // Go: "We reserve an additional 10 MB in maxMemoryBytes for
        // non-file data."
        // Go: `maxFileMemoryBytes := maxMemory; if == MaxInt64 { -- }`.
        // The decrement was missing here; Go backs off by one so the
        // later `>= maxFileMemoryBytes` comparisons cannot be satisfied
        // by the saturated value itself.
        let mut maxFileMemoryBytes = maxMemory;
        if maxFileMemoryBytes == crate::types::int64::MAX {
            maxFileMemoryBytes -= 1;
        }
        // Go: `maxMemoryBytes := maxMemory + int64(10<<20)`, which WRAPS
        // on overflow and is then caught by the `<= 0` guard below —
        // that guard exists precisely to turn the wrapped negative into
        // MaxInt64.
        //
        // Rust's `+` traps instead, so `ReadForm(int64::MAX)` panicked
        // in a debug build before reaching the guard, making the guard
        // dead code for the one input it was written for. e2e builds
        // debug. wrapping_add reproduces Go's arithmetic so the guard
        // does its job.
        let mut maxMemoryBytes = maxMemory.wrapping_add(10 << 20);
        if maxMemoryBytes <= 0 {
            if maxMemory < 0 {
                maxMemoryBytes = 0;
            } else {
                maxMemoryBytes = crate::types::int64::MAX;
            }
        }

        loop {
            let (p, err) = self.NextPart();
            if crate::errors::Is(err.clone(), crate::io::EOF) {
                break;
            }
            if !err.IsNil() {
                return (Form::default(), err);
            }
            if maxParts <= 0 {
                return (Form::default(), ErrMessageTooLarge.into());
            }
            maxParts -= 1;

            let name = p.FormName();
            if name.Len() == 0 {
                continue;
            }
            let filename = p.FileName();

            // Go: "Multiple values for the same key […] are cheaper
            // than the same number of values for different keys, but
            // using a consistent per-value cost for overhead is
            // simpler."
            const mapEntryOverhead: int64 = 200;
            maxMemoryBytes -= crate::int64(name.Len());
            maxMemoryBytes -= mapEntryOverhead;
            if maxMemoryBytes < 0 {
                return (Form::default(), ErrMessageTooLarge.into());
            }

            if filename.Len() == 0 {
                // Go: "value, store as string in memory".
                let n = crate::int64(crate::len(&p.Body));
                if n > maxMemoryBytes {
                    return (Form::default(), ErrMessageTooLarge.into());
                }
                maxMemoryBytes -= n;
                if maxMemoryBytes < 0 {
                    return (Form::default(), ErrMessageTooLarge.into());
                }
                let (mut vv, _) = form.Value.Get(name.clone());
                vv = crate::append!(vv, crate::string::from_bytes(&p.Body));
                form.Value.Set(name, vv);
                continue;
            }

            // Go: "file, store in memory or on disk" — goish, in memory.
            const fileHeaderSize: int64 = 100;
            let hdr = __to_mime_header(&p.Header);
            maxMemoryBytes -= mimeHeaderSize(&hdr);
            maxMemoryBytes -= mapEntryOverhead;
            maxMemoryBytes -= fileHeaderSize;
            if maxMemoryBytes < 0 {
                return (Form::default(), ErrMessageTooLarge.into());
            }
            let n = crate::int64(crate::len(&p.Body));
            // Go spills past maxFileMemoryBytes; with no disk half the
            // only honest answer for an oversized file is the same
            // error an oversized form gets.
            if n > maxFileMemoryBytes {
                return (Form::default(), ErrMessageTooLarge.into());
            }
            maxMemoryBytes -= n;
            if maxMemoryBytes < 0 {
                return (Form::default(), ErrMessageTooLarge.into());
            }
            let fh = FileHeader {
                Filename: filename,
                Header: hdr,
                Size: n,
                content: p.Body.clone(),
            };
            let (mut fhs, _) = form.File.Get(name.clone());
            fhs = crate::append!(fhs, fh);
            form.File.Set(name, fhs);
        }

        return (form, crate::errors::nil);
    }
}
