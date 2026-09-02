// go: file log/slog/level.go decls: Level.String, Level.MarshalJSON, Level.UnmarshalJSON, Level.AppendText, Level.MarshalText, Level.UnmarshalText, Level.parse, Level.Level, LevelVar.Level, LevelVar.Set, LevelVar.String, LevelVar.AppendText, LevelVar.MarshalText, LevelVar.UnmarshalText
//
// level.go — the verbosity level, its text form, and the dynamic
// LevelVar.
//
// `Level` and the four constants already existed in this package's
// module root; everything that gives them BEHAVIOUR did not. That is
// the interesting half, because `Level.String` is not a lookup table:
// it renders the nearest named level plus a SIGNED OFFSET, so `Level(1)`
// is "INFO+1" and `Level(-2)` is "DEBUG+2". A port that treats the four
// names as the whole vocabulary answers differently for every level a
// caller actually chooses, and silently, because the four common ones
// all land exactly on names.
//
// `parse` reads that syntax back, and deliberately does NOT round-trip:
// "WARN-1" is level 3, whose String is "INFO+3". Go documents this —
// "It also accepts numeric offsets that would result in a different
// string on output."

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::strconv;
use crate::strings;
use crate::types::byte;
use crate::{fmt, int};

// go: sdk 1.25.5 log/slog/level.go:17-17 Level
/// Go: "A Level is the importance or severity of a log event. The
/// higher the level, the more important or severe the event."
///
/// goish wraps the `int` in a transparent tuple struct so it carries a
/// distinct type identity, which is what goishc emits for a named
/// scalar type.
#[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct Level(pub int);

impl From<int> for Level {
    // go: none — goish idiom: Go writes the conversion `slog.Level(n)`;
    //     Rust needs it spelled as a trait impl.
    fn from(v: int) -> Self {
        return Level(v);
    }
}

// go: sdk 1.25.5 log/slog/level.go:43-51 LevelDebug
/// Go: "Names for common levels."
pub const LevelDebug: Level = Level(-4);
// go: sdk 1.25.5 log/slog/level.go:43-51 LevelInfo
pub const LevelInfo: Level = Level(0);
// go: sdk 1.25.5 log/slog/level.go:43-51 LevelWarn
pub const LevelWarn: Level = Level(4);
// go: sdk 1.25.5 log/slog/level.go:43-51 LevelError
pub const LevelError: Level = Level(8);

// go: none — goish idiom: Go's `String` closes over nothing but its two
//     arguments; Rust closures in a `no_std` trait-free context are
//     simpler as a free fn, and it is used only here.
/// Go's inner `str := func(base string, val Level) string`.
fn levelStr(base: &str, val: Level) -> string {
    if val.0 == 0 {
        return string::from_bytes(base.as_bytes());
    }
    // Go: fmt.Sprintf("%s%+d", base, val) — the `+` flag is what puts
    // the sign on a POSITIVE offset, and it is the whole difference
    // between "INFO+2" and "INFO2".
    return fmt::Sprintf!("%s%+d", string::from_bytes(base.as_bytes()), val.0);
}

impl Level {
    // go: sdk 1.25.5 log/slog/level.go:59-77 Level.String
    /// Go: "String returns a name for the level. If the level has an
    /// attached value, it appends the value to the name."
    ///
    /// Go's examples: `LevelWarn.String() => "WARN"`,
    /// `(LevelInfo+2).String() => "INFO+2"`.
    pub fn String(self) -> string {
        if self < LevelInfo {
            return levelStr("DEBUG", Level(self.0 - LevelDebug.0));
        } else if self < LevelWarn {
            return levelStr("INFO", Level(self.0 - LevelInfo.0));
        } else if self < LevelError {
            return levelStr("WARN", Level(self.0 - LevelWarn.0));
        }
        return levelStr("ERROR", Level(self.0 - LevelError.0));
    }

    // go: sdk 1.25.5 log/slog/level.go:81-86 Level.MarshalJSON
    /// Go: "MarshalJSON implements encoding/json.Marshaler by quoting
    /// the output of Level.String."
    pub fn MarshalJSON(self) -> (slice<byte>, error) {
        // Go: "AppendQuote is sufficient for JSON-encoding all Level
        // strings. They don't contain any runes that would produce
        // invalid JSON when escaped."
        return (strconv::AppendQuote(slice::new(), self.String()), nil);
    }

    // go: sdk 1.25.5 log/slog/level.go:93-99 Level.UnmarshalJSON
    /// Go: "UnmarshalJSON implements encoding/json.Unmarshaler. It
    /// accepts any string produced by Level.MarshalJSON, ignoring case.
    /// It also accepts numeric offsets that would result in a different
    /// string on output. For example, "Error-8" would marshal as
    /// "INFO"."
    pub fn UnmarshalJSON(&mut self, data: slice<byte>) -> error {
        let (s, err) = strconv::Unquote(string::from_bytes(&data.clone().__into_vec()));
        if err != nil {
            return err;
        }
        return self.parse(s);
    }

    // go: sdk 1.25.5 log/slog/level.go:103-105 Level.AppendText
    /// Go: "AppendText implements encoding.TextAppender by calling
    /// Level.String."
    pub fn AppendText(self, b: slice<byte>) -> (slice<byte>, error) {
        let mut out: Vec<byte> = b.clone().__into_vec();
        out.extend_from_slice(self.String().as_bytes());
        return (slice::__from_vec(out), nil);
    }

    // go: sdk 1.25.5 log/slog/level.go:109-111 Level.MarshalText
    /// Go: "MarshalText implements encoding.TextMarshaler by calling
    /// Level.AppendText."
    pub fn MarshalText(self) -> (slice<byte>, error) {
        return self.AppendText(slice::new());
    }

    // go: sdk 1.25.5 log/slog/level.go:118-120 Level.UnmarshalText
    /// Go: "UnmarshalText implements encoding.TextUnmarshaler. It
    /// accepts any string produced by Level.MarshalText, ignoring case."
    pub fn UnmarshalText(&mut self, data: slice<byte>) -> error {
        return self.parse(string::from_bytes(&data.clone().__into_vec()));
    }

    // go: sdk 1.25.5 log/slog/level.go:122-154 Level.parse
    /// Go wraps every failure with
    /// `fmt.Errorf("slog: level string %q: %w", s, err)` in a deferred
    /// closure over the named result. Rust has no such defer, so the
    /// wrap is applied at each error return — the two paths below are
    /// the two the defer covers.
    fn parse<S: Into<string>>(&mut self, s: S) -> error {
        let s: string = s.into();

        let mut name = s.clone();
        let mut offset: int = 0;
        let i = strings::IndexAny(s.clone(), string::from_static("+-"));
        if i >= 0 {
            name = s.slice(0, i);
            let (o, err) = strconv::Atoi(s.slice(i, s.Len()));
            if err != nil {
                // Go: the deferred wrap.
                return fmt::Errorf!("slog: level string %q: %w", s, err);
            }
            offset = o;
        }
        let up = strings::ToUpper(name);
        if up == string::from_static("DEBUG") {
            *self = LevelDebug;
        } else if up == string::from_static("INFO") {
            *self = LevelInfo;
        } else if up == string::from_static("WARN") {
            *self = LevelWarn;
        } else if up == string::from_static("ERROR") {
            *self = LevelError;
        } else {
            // Go: the deferred wrap around errors.New("unknown name").
            return fmt::Errorf!("slog: level string %q: %w", s, errors::New("unknown name"));
        }
        // Go: *l += Level(offset)
        self.0 += offset;
        return nil;
    }

    // go: sdk 1.25.5 log/slog/level.go:156-156 Level.Level
    /// Go: "Level returns the receiver. It implements Leveler."
    pub fn Level(self) -> Level {
        return self;
    }
}

// go: sdk 1.25.5 log/slog/level.go:163-165 LevelVar
/// Go: "A LevelVar is a Level variable, to allow a Handler level to
/// change dynamically. It implements Leveler as well as a Set method,
/// and it is safe for use by multiple goroutines. The zero LevelVar
/// corresponds to LevelInfo."
#[derive(Default)]
pub struct LevelVar {
    val: crate::sync::atomic::Int64,
}

impl LevelVar {
    // go: none — goish idiom: Go writes `var v LevelVar` for the zero
    //     value; Rust needs a constructor for a struct with a private
    //     field. The zero IS LevelInfo, as Go documents.
    pub fn new() -> Self {
        return LevelVar::default();
    }

    // go: sdk 1.25.5 log/slog/level.go:168-170 LevelVar.Level
    /// Go: "Level returns v's level."
    pub fn Level(&self) -> Level {
        return Level(int(self.val.Load()));
    }

    // go: sdk 1.25.5 log/slog/level.go:173-175 LevelVar.Set
    /// Go: "Set sets v's level to l."
    pub fn Set(&self, l: Level) {
        self.val.Store(l.0);
    }

    // go: sdk 1.25.5 log/slog/level.go:177-179 LevelVar.String
    pub fn String(&self) -> string {
        return fmt::Sprintf!("LevelVar(%s)", self.Level().String());
    }

    // go: sdk 1.25.5 log/slog/level.go:183-185 LevelVar.AppendText
    /// Go: "AppendText implements encoding.TextAppender by calling
    /// Level.AppendText."
    pub fn AppendText(&self, b: slice<byte>) -> (slice<byte>, error) {
        return self.Level().AppendText(b);
    }

    // go: sdk 1.25.5 log/slog/level.go:189-191 LevelVar.MarshalText
    /// Go: "MarshalText implements encoding.TextMarshaler by calling
    /// LevelVar.AppendText."
    pub fn MarshalText(&self) -> (slice<byte>, error) {
        return self.AppendText(slice::new());
    }

    // go: sdk 1.25.5 log/slog/level.go:195-202 LevelVar.UnmarshalText
    /// Go: "UnmarshalText implements encoding.TextUnmarshaler by calling
    /// Level.UnmarshalText."
    pub fn UnmarshalText(&self, data: slice<byte>) -> error {
        let mut l = Level(0);
        let err = l.UnmarshalText(data);
        if err != nil {
            return err;
        }
        self.Set(l);
        return nil;
    }
}

// go: sdk 1.25.5 log/slog/level.go:210-212 Leveler
/// Go: "A Leveler provides a Level value. As Level itself implements
/// Leveler, clients typically supply a Level value wherever a Leveler is
/// needed, such as in HandlerOptions."
pub trait Leveler {
    // go: none — goish idiom: the sole method of Go's `Leveler`
    //     interface; the interface itself carries the anchor.
    fn Level(&self) -> Level;
}

impl Leveler for Level {
    // go: none — goish idiom: see the note on `Leveler::Level`.
    fn Level(&self) -> Level {
        return *self;
    }
}

impl Leveler for LevelVar {
    // go: none — goish idiom: see the note on `Leveler::Level`.
    fn Level(&self) -> Level {
        return LevelVar::Level(self);
    }
}
