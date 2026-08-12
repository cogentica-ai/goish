// go: file testing/slogtest/slogtest.go decls: hasKey, missingKey, hasAttr, inGroup, wrapper.Handle, replace.LogValue, replace.String
//
// testing/slogtest — the conformance checks a slog.Handler must pass.
//
// **Partial port.** `TestHandler` and `Run`, which drive the checks,
// are not here. Both walk a ~250-line `cases` table whose entries call
// `l.Info(msg, "k", v, ...)` — Go's variadic `...any` form, which pairs
// loose key/value arguments through `argsToAttrSlice`. goish's Logger
// takes Attrs the caller built (see src/log/slog/logger.rs), so those
// cases cannot be transcribed without inventing a different table, and
// a "conformance suite" that tests different cases than Go's is worth
// less than none.
//
// What is here is every check the table is built out of, which is the
// reusable half: a handler author can assert `hasAttr`, `inGroup` and
// friends against their own output today.
//
// goishlint:ignore GOISH018 TestHandler, Run, withSource — TestHandler and Run need the `cases` table described above; withSource formats a runtime.Caller(1) location into an explanation string and is only used by that table.
// goishlint:ignore GOISH021 check, wrapper, replace, cases, testCase — `cases` and `testCase` come with TestHandler; `check` is a func type, and goish spells it as a closure bound at each helper.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::context;
use crate::errors;
use crate::goany::Any;
use crate::gomap::map;
use crate::gostring::string;
use crate::log::slog;

/// Go: `type check func(map[string]any) string` — returns "" when the
/// property holds, or a description of the problem when it does not.
///
/// goish spells it as a boxed closure so the helpers below can capture
/// their arguments, which is what Go's returned closures do.
pub type check = Box<dyn Fn(&map<string, Any>) -> string>;

// go: sdk 1.25.5 testing/slogtest/slogtest.go:320-327 hasKey
/// Go: the key must be present. Only presence — the value is not
/// examined, which is what makes this composable with `inGroup`.
pub fn hasKey(key: string) -> check {
    return Box::new(move |m: &map<string, Any>| {
        if !m.Has(key.clone()) {
            return crate::fmt::Sprintf!("missing key %q", key.clone());
        }
        return string::from_static("");
    });
}

// go: sdk 1.25.5 testing/slogtest/slogtest.go:329-336 missingKey
/// Go: the key must be absent. The mirror of `hasKey`, and the reason
/// both exist: a handler that emits a `time` key when it was told not
/// to is as wrong as one that omits it.
pub fn missingKey(key: string) -> check {
    return Box::new(move |m: &map<string, Any>| {
        if m.Has(key.clone()) {
            return crate::fmt::Sprintf!("unexpected key %q", key.clone());
        }
        return string::from_static("");
    });
}

// go: sdk 1.25.5 testing/slogtest/slogtest.go:338-349 hasAttr
/// Go: the key must be present AND carry the expected value.
///
/// Note the delegation on the first line: Go runs `hasKey(key)(m)`
/// first and returns its message unchanged if it fails, so a missing
/// key reports "missing key" rather than a confusing value mismatch
/// against a zero. Ported as written.
///
/// Deviation: Go compares with `reflect.DeepEqual`. goish's `Any`
/// carries `PartialEq`, so the comparison is direct — which is
/// stricter in one respect, since DeepEqual would equate two distinct
/// types with identical structure.
pub fn hasAttr(key: string, wantVal: Any) -> check {
    let k = key.clone();
    return Box::new(move |m: &map<string, Any>| {
        // Go: if s := hasKey(key)(m); s != "" { return s }
        let missing = hasKey(k.clone())(m);
        if missing.Len() != 0 {
            return missing;
        }
        let (gotVal, _) = m.Get(k.clone());
        if gotVal != wantVal {
            return crate::fmt::Sprintf!("%q: value mismatch", k.clone());
        }
        return string::from_static("");
    });
}

// go: sdk 1.25.5 testing/slogtest/slogtest.go:351-363 inGroup
/// Go: descend into a named group and apply `c` to its contents.
///
/// Two distinct failures are reported separately — the group being
/// absent, and the group's value not being a map at all. A handler that
/// emitted a group as a flat string would otherwise look like a check
/// failure inside the group rather than a structural error.
pub fn inGroup(name: string, c: check) -> check {
    return Box::new(move |m: &map<string, Any>| {
        let (v, ok) = m.Get(name.clone());
        if !ok {
            return crate::fmt::Sprintf!("missing group %q", name.clone());
        }
        return match v.As::<map<string, Any>>() {
            Some(g) => c(g),
            None => crate::fmt::Sprintf!(
                "value for group %q is not map[string]any",
                name.clone()
            ),
        };
    });
}

// goishlint:ignore GOISH019 wrapper — Go embeds `slog.Handler` in the
// struct and inherits Enabled/WithAttrs/WithGroup for free. Rust has no
// embedding, so the handler is a named field and the three forwarding
// methods are written out; `mod` is spelled `md` because `mod` is a
// Rust keyword.
// go: sdk 1.25.5 testing/slogtest/slogtest.go:365-368 wrapper
/// Go: a Handler that mutates the Record on its way through, so a test
/// case can simulate what a caller cannot construct directly (an empty
/// PC, a zero Time).
pub struct wrapper {
    inner: Arc<dyn slog::Handler + Send + Sync>,
    md: Arc<dyn Fn(&mut slog::Record) + Send + Sync>,
}

impl wrapper {
    // go: none — goish-only: Go embeds `slog.Handler` in the struct and
    // gets the other three methods for free. Rust has no embedding, so
    // the constructor is explicit and the forwarding methods are
    // written out below.
    pub fn new(
        inner: Arc<dyn slog::Handler + Send + Sync>,
        md: Arc<dyn Fn(&mut slog::Record) + Send + Sync>,
    ) -> Self {
        return wrapper { inner: inner, md: md };
    }
}

impl slog::Handler for wrapper {
    // go: sdk 1.25.5 testing/slogtest/slogtest.go:370-373 wrapper.Handle
    /// Go: `h.mod(&r); return h.Handler.Handle(ctx, r)` — mutate, then
    /// forward.
    fn Handle(&self, ctx: &dyn context::Context, record: slog::Record) -> errors::error {
        let mut r = record;
        (self.md)(&mut r);
        return self.inner.Handle(ctx, r);
    }

    // go: none — goish idiom: Go embeds the Handler and inherits these.
    fn Enabled(&self, ctx: &dyn context::Context, level: slog::Level) -> bool {
        return self.inner.Enabled(ctx, level);
    }
    // go: none — goish idiom: as Enabled.
    fn WithAttrs(
        &self,
        attrs: crate::goslice::slice<slog::Attr>,
    ) -> Arc<dyn slog::Handler + Send + Sync> {
        return self.inner.WithAttrs(attrs);
    }
    // go: none — goish idiom: as Enabled.
    fn WithGroup(&self, name: string) -> Arc<dyn slog::Handler + Send + Sync> {
        return self.inner.WithGroup(name);
    }
}

// go: sdk 1.25.5 testing/slogtest/slogtest.go:383-385 replace
/// Go: a value that resolves to something else through `LogValue`, used
/// to check that a handler calls `Resolve` rather than formatting the
/// wrapper.
pub struct replace {
    pub v: Any,
}

impl replace {
    // go: sdk 1.25.5 testing/slogtest/slogtest.go:387-387 replace.LogValue
    /// Go: `func (r *replace) LogValue() slog.Value { return slog.AnyValue(r.v) }`
    pub fn LogValue(&self) -> slog::Value {
        return slog::AnyValue(self.v.clone());
    }

    // go: sdk 1.25.5 testing/slogtest/slogtest.go:389-391 replace.String
    /// Go: `fmt.Sprintf("<replace(%v)>", r.v)` — deliberately distinct
    /// from what LogValue resolves to, so a handler that formatted the
    /// wrapper instead of resolving it is visible in the output.
    pub fn String(&self) -> string {
        return crate::fmt::Sprintf!("<replace(%v)>", self.v.clone());
    }
}
