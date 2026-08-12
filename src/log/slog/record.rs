// go: file log/slog/record.go decls: argsToAttr
//
// log/slog/record.go — the loose-argument pairing behind the `...any`
// logging form.
//
// **Partial port.** `Record` itself and its Add/AddAttrs/Attrs methods
// are hand-written in mod[rs] and predate this file; only the argument
// pairing is anchored here.
//
// goishlint:ignore GOISH020 argsToAttr — Go returns the unconsumed
// tail of the slice and takes only the slice; goish takes an index and
// returns how many elements were consumed, so the caller advances
// rather than re-slicing on every iteration. Same walk, no reallocation
// per argument pair.
// goishlint:ignore GOISH018 Add, AddAttrs, Attrs, Clone, NewRecord, NumAttrs, Source, countAttrs, group, isEmpty — Record and its methods are hand-written in mod[rs].
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
