// go: file log/slog/record.go decls: argsToAttr, Record.Source, Source.group, Source.isEmpty, Record.Clone, Record.NumAttrs, Record.Attrs, Record.AddAttrs, Record.Add
//
// log/slog/record.go — the loose-argument pairing behind the `...any`
// logging form.
//
// The `Record` struct itself is declared in the module root, where the
// rest of the package's shared types live; its methods are ported here.
//
// goishlint:ignore GOISH020 argsToAttr — Go returns the unconsumed
// tail of the slice and takes only the slice; goish takes an index and
// returns how many elements were consumed, so the caller advances
// rather than re-slicing on every iteration. Same walk, no reallocation
// per argument pair.
// goishlint:ignore GOISH018 NewRecord, countAttrs — Record and its methods are hand-written in mod[rs].
// goishlint:ignore GOISH021 Record, Source, nAttrsInline — same.

#![allow(non_snake_case)]

extern crate alloc;

use super::Attr;

// go: sdk 1.25.5 log/slog/record.go:160-160 badKey
/// Go: `const badKey = "!BADKEY"` — the key an unpaired or
/// non-string-keyed argument is filed under.
///
/// Go chooses to *record* the mistake rather than drop it or panic: a
/// stray argument still reaches the handler, tagged so it is obvious in
/// the output. A logging call is the wrong place to fail.
pub const badKey: &str = "!BADKEY";

// go: sdk 1.25.5 log/slog/record.go:168-182 argsToAttr
/// Go: "argsToAttr turns a prefix of the nonempty args slice into an
/// Attr and returns the unconsumed portion of the slice."
///
/// Three cases, and the arithmetic differs in each: a string key with a
/// following value consumes two; a string key at the end of the list
/// consumes one and is filed under badKey; an Attr passed directly, or
/// any non-string, consumes one.
///
/// Deviation: Go returns the remaining slice; goish returns how many
/// elements were consumed, so the caller advances an index rather than
/// re-slicing on every iteration.
pub fn argsToAttr(
    args: &crate::goslice::slice<crate::goany::Any>,
    i: crate::types::int,
) -> (Attr, crate::types::int) {
    let first = args[i].clone();

    // Go: case string:
    if let Some(k) = first.As::<crate::gostring::string>() {
        // Go: if len(args) == 1 { return String(badKey, x), nil }
        if i + 1 >= args.Len() {
            return (
                super::String(crate::gostring::string::from_static(badKey), k.clone()),
                1,
            );
        }
        // Go: return Any(x, args[1]), args[2:]
        return (super::Any(k.clone(), args[i + 1].clone()), 2);
    }

    // Go: case Attr: return x, args[1:]
    if let Some(a) = first.As::<Attr>() {
        return (a.clone(), 1);
    }

    // Go: default: return Any(badKey, x), args[1:]
    return (
        super::Any(crate::gostring::string::from_static(badKey), first),
        1,
    );
}

// ─── Record methods (record.go:87) ──────────────────────────────────
//
// Go's Record splits its attrs across an inline `front [5]Attr` and a
// heap `back []Attr` purely to avoid allocating for the common case.
// goish's Record carries one `slice<Attr>`, which is observably the
// same: the attrs come out in the order they went in, and an empty
// group is skipped on the way in. The one Go behaviour the split
// creates and goish therefore does not reproduce is the "!BUG" attr Go
// appends when it detects AddAttrs called on a copy made without
// Clone — that detection reads the capacity past the end of a shared
// backing array, which is exactly the aliasing goish's single slice
// does not have.

impl super::Record {
    // go: sdk 1.25.5 log/slog/record.go:70-73 Record.Clone
    /// Go: "Clone returns a copy of the record with no shared state.
    /// The original record and the clone can both be modified without
    /// interfering with each other."
    pub fn Clone(&self) -> super::Record {
        let mut r = super::Record {
            Time: self.Time,
            Level: self.Level,
            Message: self.Message.clone(),
            PC: self.PC,
            attrs: crate::goslice::slice::new(),
        };
        // Go: slices.Clip — prevent append from mutating a shared array.
        // goish copies the elements, which is the same guarantee.
        r.attrs = crate::goslice::slice::__from_vec(self.attrs.clone().__into_vec());
        return r;
    }

    // go: sdk 1.25.5 log/slog/record.go:76-78 Record.NumAttrs
    /// Go: "NumAttrs returns the number of attrs in r."
    pub fn NumAttrs(&self) -> crate::types::int {
        return self.attrs.Len();
    }

    // go: sdk 1.25.5 log/slog/record.go:82-93 Record.Attrs
    /// Go: "Attrs calls f on each Attr in the [Record]. Iteration stops
    /// if f returns false."
    pub fn Attrs<F: FnMut(&Attr) -> bool>(&self, mut f: F) {
        let mut i: crate::types::int = 0;
        while i < self.attrs.Len() {
            if !f(&self.attrs[i]) {
                return;
            }
            i += 1;
        }
    }

    // go: sdk 1.25.5 log/slog/record.go:97-124 Record.AddAttrs
    /// Go: "AddAttrs appends the given Attrs to the [Record]'s list of
    /// Attrs. It omits empty groups."
    pub fn AddAttrs(&mut self, attrs: &[Attr]) {
        let mut out = self.attrs.clone().__into_vec();
        for a in attrs {
            // Go: if a.Value.isEmptyGroup() { continue }
            if super::isEmptyGroup(&a.Value) {
                continue;
            }
            out.push(a.clone());
        }
        self.attrs = crate::goslice::slice::__from_vec(out);
    }

    // go: sdk 1.25.5 log/slog/record.go:129-146 Record.Add
    /// Go: "Add converts the args to Attrs as described in
    /// [Logger.Log], then appends the Attrs to the [Record]'s list of
    /// Attrs. It omits empty groups."
    pub fn Add(&mut self, args: crate::goslice::slice<crate::goany::Any>) {
        let mut out = self.attrs.clone().__into_vec();
        let mut i: crate::types::int = 0;
        while i < args.Len() {
            let (a, n) = argsToAttr(&args, i);
            i += n;
            if super::isEmptyGroup(&a.Value) {
                continue;
            }
            out.push(a);
        }
        self.attrs = crate::goslice::slice::__from_vec(out);
    }
}

// ─── Source (record.go:184) ─────────────────────────────────────────

// go: sdk 1.25.5 log/slog/record.go:184-194 Source
/// Go: "Source describes the location of a line of source code."
///
/// This is what `HandlerOptions.AddSource` puts in the output. It was
/// the one part of the handler port left as a stated no-op, because it
/// needs a PC resolved to a function, file and line — and goish has a
/// real symboliser (`runtime::CallersFrames`), so it is portable after
/// all.
#[derive(Clone, Default, PartialEq)]
pub struct Source {
    /// Go: "Function is the package path-qualified function name
    /// containing the source line. … This may be the empty string if
    /// not known."
    pub Function: crate::gostring::string,
    /// Go: "File and Line are the file name and line number (1-based) of
    /// the source line. These may be the empty string and zero,
    /// respectively, if not known."
    pub File: crate::gostring::string,
    pub Line: crate::types::int,
}

impl crate::reflect::Reflect for Source {
    // go: none — goish idiom: minimal descriptor so a `Source` can live
    //     in a `goany::Any`, which requires Reflect. The handlers reach
    //     it by downcast, not by walking it.
    fn __reflect_type() -> crate::reflect::Type {
        return crate::reflect::Type::__new(crate::reflect::Kind::Struct, "Source", &[]);
    }
    // go: none — goish idiom: as `__reflect_type`.
    fn __reflect_value(&self) -> crate::reflect::Value {
        return crate::reflect::Value::Struct {
            ty: <Source as crate::reflect::Reflect>::__reflect_type(),
            fields: alloc::vec![],
        };
    }
}

impl Source {
    // go: sdk 1.25.5 log/slog/record.go:200-212 Source.group
    /// Go: "group returns the non-zero fields of s as a slice of Attrs.
    /// It is similar to a LogValue method, but we don't want Source to
    /// implement LogValuer because it would be resolved before
    /// PC-to-Source translation."
    pub(crate) fn group(&self) -> super::Value {
        let mut as_: alloc::vec::Vec<Attr> = alloc::vec::Vec::new();
        if self.Function.Len() != 0 {
            as_.push(super::String("function", self.Function.clone()));
        }
        if self.File.Len() != 0 {
            as_.push(super::String("file", self.File.clone()));
        }
        if self.Line != 0 {
            as_.push(super::Int("line", self.Line));
        }
        return super::GroupValue(crate::goslice::slice::__from_vec(as_));
    }

    // go: sdk 1.25.5 log/slog/record.go:215-215 Source.isEmpty
    /// Go: `func (s *Source) isEmpty() bool { return s == nil || *s == Source{} }`
    pub(crate) fn isEmpty(&self) -> bool {
        return self.Function.Len() == 0 && self.File.Len() == 0 && self.Line == 0;
    }
}

impl super::Record {
    // go: sdk 1.25.5 log/slog/record.go:220-232 Record.Source
    /// Go: "Source returns a new Source for the log event using r's PC.
    /// If the PC field is zero, meaning the Record was created without
    /// the necessary information or the location is unavailable, then
    /// nil is returned."
    ///
    /// goish returns `Option<Source>` where Go returns a nil-able
    /// pointer.
    pub fn Source(&self) -> Option<Source> {
        if self.PC == 0 {
            return None;
        }
        let mut fs =
            crate::runtime::CallersFrames(crate::goslice::slice::__from_vec(alloc::vec![self.PC]));
        let (f, _) = fs.Next();
        return Some(Source {
            Function: f.Function,
            File: f.File,
            Line: f.Line,
        });
    }
}
