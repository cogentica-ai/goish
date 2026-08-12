// go: file testing/slogtest/slogtest.go decls: Run, TestHandler, cases, withSource, hasKey, missingKey, hasAttr, inGroup, wrapper.Handle, replace.LogValue, replace.String
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
// goishlint:ignore GOISH018 Run, withSource — TestHandler and Run need the `cases` table described above; withSource formats a runtime.Caller(1) location into an explanation string and is only used by that table.
// goishlint:ignore GOISH021 check, wrapper, replace — `cases` and `testCase` come with TestHandler; `check` is a func type, and goish spells it as a closure bound at each helper.

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
pub type check = Box<dyn Fn(&map<string, Any>) -> string + Send + Sync>;

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

// go: none — goish idiom: Go's `replace` satisfies slog.LogValuer just
// by having a LogValue method. goish needs the `impl Trait for T` block
// written out — an inherent method does not satisfy a trait.
impl slog::LogValuer for replace {
    // go: none — goish idiom: forwards to the inherent method, which is
    // the port.
    fn LogValue(&self) -> slog::Value {
        return replace::LogValue(self);
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

// ─── the case table and its drivers ──────────────────────────────────

// goishlint:ignore GOISH019 testCase — `mod` is spelled `md` because
// `mod` is a Rust keyword, and the closures are boxed because Rust has
// no bare function-typed struct fields. Same five fields, same roles.
// go: sdk 1.25.5 testing/slogtest/slogtest.go:19-34 testCase
/// Go: one conformance case — a name, an explanation of the constraint
/// it enforces, the log call that exercises it, an optional Record
/// mutation, and the checks its output must satisfy.
pub struct testCase {
    /// Go: "Subtest name."
    pub name: string,
    /// Go: "If non-empty, explanation explains the violated
    /// constraint."
    pub explanation: string,
    /// Go: "f executes a single log event using its argument logger."
    pub f: Box<dyn Fn(&slog::Logger) + Send + Sync>,
    /// Go: "If mod is not nil, it is called to modify the Record
    /// generated by the Logger before it is passed to the Handler."
    pub md: Option<Arc<dyn Fn(&mut slog::Record) + Send + Sync>>,
    /// Go: the properties the emitted record must satisfy.
    pub checks: alloc::vec::Vec<check>,
}

// go: none — goish idiom: `slog.Group("G", slog.String(...))` is
// variadic; goish's Group takes a slice, so the call sites below build
// one. Named for brevity because the table uses it seventeen times.
fn g(key: &str, attrs: alloc::vec::Vec<slog::Attr>) -> slog::Attr {
    return slog::Group(sx(key), crate::goslice::slice::__from_vec(attrs));
}

// go: none — goish idiom: `&str` to goish `string`.
fn sx(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: a `...any` argument list.
fn args(xs: alloc::vec::Vec<Any>) -> crate::goslice::slice<Any> {
    return crate::goslice::slice::__from_vec(xs);
}

// go: sdk 1.25.5 testing/slogtest/slogtest.go:36-246 cases
/// Go: "cases is the set of conformance tests a Handler must pass."
///
/// Built as a function rather than a `var` because each entry owns
/// boxed closures, which cannot live in a `const`. Seventeen cases, in
/// Go's order — `TestHandler` matches results to cases positionally, so
/// the order is load-bearing, not cosmetic.
///
/// Deviation: `explanation` is the plain sentence. Go wraps each in
/// `withSource(...)`, which appends the table's own file:line via
/// `runtime.Caller(1)` so a failure points at the case that produced
/// it. That helper is not ported — it would report this file's line,
/// not Go's, and a citation to the wrong file is worse than none.
pub fn cases() -> alloc::vec::Vec<testCase> {
    let mut out: alloc::vec::Vec<testCase> = alloc::vec::Vec::new();

    out.push(testCase {
        name: sx("built-ins"),
        explanation: withSource(sx("this test expects slog.TimeKey, slog.LevelKey and slog.MessageKey")),
        f: Box::new(|l| l.Info(sx("message"), args(alloc::vec![]))),
        md: None,
        checks: alloc::vec![
            hasKey(sx(slog::TimeKey)),
            hasKey(sx(slog::LevelKey)),
            hasAttr(sx(slog::MessageKey), Any::new(sx("message"))),
        ],
    });

    out.push(testCase {
        name: sx("attrs"),
        explanation: withSource(sx("a Handler should output attributes passed to the logging function")),
        f: Box::new(|l| {
            l.Info(sx("message"), args(alloc::vec![Any::new(sx("k")), Any::new(sx("v"))]))
        }),
        md: None,
        checks: alloc::vec![hasAttr(sx("k"), Any::new(sx("v")))],
    });

    out.push(testCase {
        name: sx("empty-attr"),
        explanation: withSource(sx("a Handler should ignore an empty Attr")),
        f: Box::new(|l| {
            l.Info(
                sx("msg"),
                args(alloc::vec![
                    Any::new(sx("a")),
                    Any::new(sx("b")),
                    Any::new(sx("")),
                    Any::new(crate::nilval::nil),
                    Any::new(sx("c")),
                    Any::new(sx("d")),
                ]),
            )
        }),
        md: None,
        checks: alloc::vec![
            hasAttr(sx("a"), Any::new(sx("b"))),
            missingKey(sx("")),
            hasAttr(sx("c"), Any::new(sx("d"))),
        ],
    });

    out.push(testCase {
        name: sx("zero-time"),
        explanation: withSource(sx("a Handler should ignore a zero Record.Time")),
        f: Box::new(|l| {
            l.Info(sx("msg"), args(alloc::vec![Any::new(sx("k")), Any::new(sx("v"))]))
        }),
        md: Some(Arc::new(|r: &mut slog::Record| {
            r.Time = crate::time::Time::default();
        })),
        checks: alloc::vec![missingKey(sx(slog::TimeKey))],
    });

    out.push(testCase {
        name: sx("WithAttrs"),
        explanation: withSource(sx("a Handler should include the attributes from the WithAttrs method")),
        f: Box::new(|l| {
            l.With(args(alloc::vec![Any::new(sx("a")), Any::new(sx("b"))]))
                .Info(sx("msg"), args(alloc::vec![Any::new(sx("k")), Any::new(sx("v"))]))
        }),
        md: None,
        checks: alloc::vec![
            hasAttr(sx("a"), Any::new(sx("b"))),
            hasAttr(sx("k"), Any::new(sx("v"))),
        ],
    });

    out.push(testCase {
        name: sx("groups"),
        explanation: withSource(sx("a Handler should handle Group attributes")),
        f: Box::new(|l| {
            l.Info(
                sx("msg"),
                args(alloc::vec![
                    Any::new(sx("a")),
                    Any::new(sx("b")),
                    Any::new(g("G", alloc::vec![slog::String(sx("c"), sx("d"))])),
                    Any::new(sx("e")),
                    Any::new(sx("f")),
                ]),
            )
        }),
        md: None,
        checks: alloc::vec![
            hasAttr(sx("a"), Any::new(sx("b"))),
            inGroup(sx("G"), hasAttr(sx("c"), Any::new(sx("d")))),
            hasAttr(sx("e"), Any::new(sx("f"))),
        ],
    });

    out.push(testCase {
        name: sx("empty-group"),
        explanation: withSource(sx("a Handler should ignore an empty group")),
        f: Box::new(|l| {
            l.Info(
                sx("msg"),
                args(alloc::vec![
                    Any::new(sx("a")),
                    Any::new(sx("b")),
                    Any::new(g("G", alloc::vec![])),
                    Any::new(sx("e")),
                    Any::new(sx("f")),
                ]),
            )
        }),
        md: None,
        checks: alloc::vec![
            hasAttr(sx("a"), Any::new(sx("b"))),
            missingKey(sx("G")),
            hasAttr(sx("e"), Any::new(sx("f"))),
        ],
    });

    out.push(testCase {
        name: sx("inline-group"),
        explanation: withSource(sx(
            "a Handler should inline the Attrs of a group with an empty key"
        )),
        f: Box::new(|l| {
            l.Info(
                sx("msg"),
                args(alloc::vec![
                    Any::new(sx("a")),
                    Any::new(sx("b")),
                    Any::new(g("", alloc::vec![slog::String(sx("c"), sx("d"))])),
                    Any::new(sx("e")),
                    Any::new(sx("f")),
                ]),
            )
        }),
        md: None,
        checks: alloc::vec![
            hasAttr(sx("a"), Any::new(sx("b"))),
            hasAttr(sx("c"), Any::new(sx("d"))),
            hasAttr(sx("e"), Any::new(sx("f"))),
        ],
    });

    out.push(testCase {
        name: sx("WithGroup"),
        explanation: withSource(sx("a Handler should handle the WithGroup method")),
        f: Box::new(|l| {
            l.WithGroup(sx("G"))
                .Info(sx("msg"), args(alloc::vec![Any::new(sx("a")), Any::new(sx("b"))]))
        }),
        md: None,
        checks: alloc::vec![
            hasKey(sx(slog::TimeKey)),
            hasKey(sx(slog::LevelKey)),
            hasAttr(sx(slog::MessageKey), Any::new(sx("msg"))),
            missingKey(sx("a")),
            inGroup(sx("G"), hasAttr(sx("a"), Any::new(sx("b")))),
        ],
    });

    out.push(testCase {
        name: sx("multi-With"),
        explanation: withSource(sx("a Handler should handle multiple WithGroup and WithAttr calls")),
        f: Box::new(|l| {
            l.With(args(alloc::vec![Any::new(sx("a")), Any::new(sx("b"))]))
                .WithGroup(sx("G"))
                .With(args(alloc::vec![Any::new(sx("c")), Any::new(sx("d"))]))
                .WithGroup(sx("H"))
                .Info(sx("msg"), args(alloc::vec![Any::new(sx("e")), Any::new(sx("f"))]))
        }),
        md: None,
        checks: alloc::vec![
            hasKey(sx(slog::TimeKey)),
            hasKey(sx(slog::LevelKey)),
            hasAttr(sx(slog::MessageKey), Any::new(sx("msg"))),
            hasAttr(sx("a"), Any::new(sx("b"))),
            inGroup(sx("G"), hasAttr(sx("c"), Any::new(sx("d")))),
            inGroup(sx("G"), inGroup(sx("H"), hasAttr(sx("e"), Any::new(sx("f"))))),
        ],
    });

    out.push(testCase {
        name: sx("empty-group-record"),
        explanation: withSource(sx("a Handler should not output groups if there are no attributes")),
        f: Box::new(|l| {
            l.With(args(alloc::vec![Any::new(sx("a")), Any::new(sx("b"))]))
                .WithGroup(sx("G"))
                .With(args(alloc::vec![Any::new(sx("c")), Any::new(sx("d"))]))
                .WithGroup(sx("H"))
                .Info(sx("msg"), args(alloc::vec![]))
        }),
        md: None,
        checks: alloc::vec![
            hasKey(sx(slog::TimeKey)),
            hasKey(sx(slog::LevelKey)),
            hasAttr(sx(slog::MessageKey), Any::new(sx("msg"))),
            hasAttr(sx("a"), Any::new(sx("b"))),
            inGroup(sx("G"), hasAttr(sx("c"), Any::new(sx("d")))),
            inGroup(sx("G"), missingKey(sx("H"))),
        ],
    });

    out.push(testCase {
        name: sx("nested-empty-group-record"),
        explanation: withSource(sx(
            "a Handler should not output nested groups if there are no attributes"
        )),
        f: Box::new(|l| {
            l.With(args(alloc::vec![Any::new(sx("a")), Any::new(sx("b"))]))
                .WithGroup(sx("G"))
                .With(args(alloc::vec![Any::new(sx("c")), Any::new(sx("d"))]))
                .WithGroup(sx("H"))
                .WithGroup(sx("I"))
                .Info(sx("msg"), args(alloc::vec![]))
        }),
        md: None,
        checks: alloc::vec![
            hasKey(sx(slog::TimeKey)),
            hasKey(sx(slog::LevelKey)),
            hasAttr(sx(slog::MessageKey), Any::new(sx("msg"))),
            hasAttr(sx("a"), Any::new(sx("b"))),
            inGroup(sx("G"), hasAttr(sx("c"), Any::new(sx("d")))),
            inGroup(sx("G"), missingKey(sx("H"))),
            inGroup(sx("G"), missingKey(sx("I"))),
        ],
    });

    out.push(testCase {
        name: sx("resolve"),
        explanation: withSource(sx("a Handler should call Resolve on attribute values")),
        f: Box::new(|l| {
            let r: Arc<dyn slog::LogValuer> = Arc::new(replace {
                v: Any::new(sx("replaced")),
            });
            l.LogAttrsAt(
                context::Background().as_ref(),
                slog::LevelInfo,
                sx("msg"),
                crate::goslice::slice::__from_vec(alloc::vec![slog::Attr {
                    Key: sx("k"),
                    Value: slog::LogValuerValue(r),
                }]),
            )
        }),
        md: None,
        checks: alloc::vec![hasAttr(sx("k"), Any::new(sx("replaced")))],
    });

    out.push(testCase {
        name: sx("resolve-groups"),
        explanation: withSource(sx("a Handler should call Resolve on attribute values in groups")),
        f: Box::new(|l| {
            let r: Arc<dyn slog::LogValuer> = Arc::new(replace {
                v: Any::new(sx("v2")),
            });
            l.LogAttrsAt(
                context::Background().as_ref(),
                slog::LevelInfo,
                sx("msg"),
                crate::goslice::slice::__from_vec(alloc::vec![g(
                    "G",
                    alloc::vec![
                        slog::String(sx("a"), sx("v1")),
                        slog::Attr { Key: sx("b"), Value: slog::LogValuerValue(r) },
                    ]
                )]),
            )
        }),
        md: None,
        checks: alloc::vec![
            inGroup(sx("G"), hasAttr(sx("a"), Any::new(sx("v1")))),
            inGroup(sx("G"), hasAttr(sx("b"), Any::new(sx("v2")))),
        ],
    });


    out.push(testCase {
        name: sx("resolve-WithAttrs"),
        explanation: withSource(sx(
            "a Handler should call Resolve on attribute values from WithAttrs"
        )),
        f: Box::new(|l| {
            let r: Arc<dyn slog::LogValuer> = Arc::new(replace {
                v: Any::new(sx("replaced")),
            });
            // Go writes `l.With("k", &replace{…})`, relying on
            // slog.Any to spot the LogValuer. goish's `...any` form
            // accepts a ready-made Attr in the same slot, which is
            // exactly what Go's pairing step builds.
            let l = l.With(args(alloc::vec![Any::new(slog::Attr {
                Key: sx("k"),
                Value: slog::LogValuerValue(r),
            })]));
            l.Info(sx("msg"), args(alloc::vec![]))
        }),
        md: None,
        checks: alloc::vec![hasAttr(sx("k"), Any::new(sx("replaced")))],
    });

    out.push(testCase {
        name: sx("resolve-WithAttrs-groups"),
        explanation: withSource(sx(
            "a Handler should call Resolve on attribute values in groups from WithAttrs"
        )),
        f: Box::new(|l| {
            let r: Arc<dyn slog::LogValuer> = Arc::new(replace {
                v: Any::new(sx("v2")),
            });
            let l = l.With(args(alloc::vec![Any::new(g(
                "G",
                alloc::vec![
                    slog::String(sx("a"), sx("v1")),
                    slog::Attr { Key: sx("b"), Value: slog::LogValuerValue(r) },
                ]
            ))]));
            l.Info(sx("msg"), args(alloc::vec![]))
        }),
        md: None,
        checks: alloc::vec![
            inGroup(sx("G"), hasAttr(sx("a"), Any::new(sx("v1")))),
            inGroup(sx("G"), hasAttr(sx("b"), Any::new(sx("v2")))),
        ],
    });

    out.push(testCase {
        name: sx("empty-PC"),
        explanation: withSource(sx(
            "a Handler should not output SourceKey if the PC is zero"
        )),
        f: Box::new(|l| l.Info(sx("message"), args(alloc::vec![]))),
        md: Some(Arc::new(|r: &mut slog::Record| {
            r.PC = 0;
        })),
        checks: alloc::vec![missingKey(sx(slog::SourceKey))],
    });

    return out;
}

// go: sdk 1.25.5 testing/slogtest/slogtest.go:375-381 withSource
/// Go appends the source position of the *case* to its explanation, so
/// a handler author can jump straight to the constraint that failed.
/// Go calls this from the package-level `cases` literal, so
/// `runtime.Caller(1)` lands on the literal's line; goish calls it from
/// inside `cases()`, which lands on the same line of this file.
fn withSource(s: string) -> string {
    let (_, file, line, ok) = crate::runtime::Caller(1);
    if !ok {
        panic!("runtime.Caller failed");
    }
    return crate::fmt::Sprintf!("%s (%s:%d)", s, file, line);
}

// go: sdk 1.25.5 testing/slogtest/slogtest.go:267-293 TestHandler
/// Go: "TestHandler tests a [slog.Handler]. If TestHandler finds any
/// misbehaviors, it returns an error for each, combined into a single
/// error with [errors.Join].
///
/// TestHandler installs the given Handler in a [slog.Logger] and makes
/// several calls to the Logger's output methods. The results function
/// is invoked after all such calls. It should return a slice of
/// map[string]any, one for each call to a Logger output method."
///
/// Results are matched to cases **positionally**, which is why the
/// table's order is load-bearing and why the length check below comes
/// first: a handler that dropped one record would otherwise report
/// every subsequent case's failures against the wrong explanation.
pub fn TestHandler<F>(h: Arc<dyn slog::Handler + Send + Sync>, results: F) -> errors::error
where
    F: Fn() -> crate::goslice::slice<map<string, Any>>,
{
    let cs = cases();
    // Go: run the handler on the test cases.
    for c in cs.iter() {
        let ht: Arc<dyn slog::Handler + Send + Sync> = match &c.md {
            Some(m) => Arc::new(wrapper::new(h.clone(), m.clone())),
            None => h.clone(),
        };
        let l = slog::New(ht);
        (c.f)(&l);
    }

    // Go: collect and check the results.
    let res = results();
    if res.Len() as usize != cs.len() {
        return errors::New(crate::fmt::Sprintf!(
            "got %d results, want %d",
            res.Len(),
            cs.len() as crate::types::int
        ));
    }
    let mut errs: alloc::vec::Vec<errors::error> = alloc::vec::Vec::new();
    for (i, c) in cs.iter().enumerate() {
        let got = res[i as crate::types::int].clone();
        for chk in c.checks.iter() {
            let problem = chk(&got);
            if problem.Len() != 0 {
                errs.push(errors::New(crate::fmt::Sprintf!(
                    "%s: %s",
                    problem,
                    c.explanation.clone()
                )));
            }
        }
    }
    if errs.len() == 0 {
        return errors::nil;
    }
    return errors::Join(crate::goslice::slice::__from_vec(errs));
}

// go: sdk 1.25.5 testing/slogtest/slogtest.go:299-316 Run
// goishlint:ignore GOISH020 Run — Go's `newHandler`/`result` are plain
// func values; goish takes them as generic parameters so a caller can
// pass a closure without boxing. Same two callbacks, same order.
//
// Go: "Run exercises a [slog.Handler] on the same test cases as
// [TestHandler], but runs each case in a subtest. For each test case, it
// first calls newHandler to get an instance of the handler under test,
// then runs the test case, then calls result to get the result. If the
// test case fails, it calls t.Error."
pub fn Run<NH, RES>(t: &mut crate::testing::T, newHandler: NH, result: RES)
where
    NH: Fn(&mut crate::testing::T) -> Arc<dyn slog::Handler + Send + Sync>
        + Send
        + Sync
        + 'static,
    RES: Fn(&mut crate::testing::T) -> map<string, Any> + Send + Sync + 'static,
{
    // Go passes the two funcs into each subtest closure directly. goish
    // subtests run on their own goroutine, so the callbacks are shared
    // through an Arc rather than copied per iteration.
    let newHandler = Arc::new(newHandler);
    let result = Arc::new(result);

    for c in cases().into_iter() {
        let newHandler = newHandler.clone();
        let result = result.clone();
        let name = c.name.clone();
        t.Run(name, move |t| {
            let h0 = newHandler(t);
            let h: Arc<dyn slog::Handler + Send + Sync> = match &c.md {
                Some(m) => Arc::new(wrapper::new(h0, m.clone())),
                None => h0,
            };
            let l = slog::New(h);
            (c.f)(&l);
            let got = result(t);
            for chk in c.checks.iter() {
                let problem = chk(&got);
                if problem.Len() != 0 {
                    t.Errorf(
                        "%s: %s",
                        crate::goslice::slice::__from_vec(alloc::vec![
                            Any::new(problem),
                            Any::new(c.explanation.clone()),
                        ]),
                    );
                }
            }
        });
    }
}
