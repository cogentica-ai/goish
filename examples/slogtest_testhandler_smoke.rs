// slogtest_testhandler_smoke — slogtest.TestHandler and slogtest.Run
// driving real handlers through the conformance cases.
//
// This is the payoff for the whole slog chain: Logger's emitting
// surface, the ...any pairing form, With/WithGroup, and
// LogValuer/Resolve all had to exist before the case table could be
// written at all.
//
// Each direction is asserted twice, because "a conforming handler
// passes" is also what a harness that checks NOTHING would report. So
// every positive check is paired with a negative one:
//
//   1 conforming handler passes    <->  2 no results at all is caught
//                                  <->  4 right count, groups dropped,
//                                          caught by a CONTENT check
//   5 Run leaves the suite green   <->  6 Run turns it red

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::context;
use goish::gostring::string;
use goish::log::slog;
use goish::sync::Mutex;
use goish::testing;
use goish::testing::slogtest::{self, TestHandler};
use goish::{errors, fmt, map, slice, syscall, Any};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

/// Where every handler below records what it was handed.
///
/// `testing::TestFn` is a bare fn pointer and slogtest::Run's callbacks
/// must be `'static`, so the sink is a static rather than something
/// threaded through captures.
static SINK: Mutex<alloc::vec::Vec<map<string, Any>>> = Mutex::new(alloc::vec::Vec::new());

fn sinkClear() {
    SINK.Lock().clear();
}

fn sinkAll() -> slice<map<string, Any>> {
    return slice::__from_vec(SINK.Lock().clone());
}

/// Run hands each subtest a fresh handler, so the sink is cleared at
/// handler-creation time and `result` returns just that subtest's
/// record.
fn sinkLast() -> map<string, Any> {
    let mut g = SINK.Lock();
    let last = g.last().cloned().unwrap_or_else(map::new);
    g.clear();
    return last;
}

// ─── a conforming handler ────────────────────────────────────────────

/// A tree node built while flattening a Record: leaves are values,
/// branches are groups. Groups are only materialised into the output
/// map if they end up non-empty.
enum Node {
    Leaf(Any),
    Branch(alloc::vec::Vec<(string, Node)>),
}

impl Node {
    fn child(&mut self, name: &string) -> &mut Node {
        if let Node::Branch(kids) = self {
            let mut idx = kids.len();
            for (i, (k, _)) in kids.iter().enumerate() {
                if k == name {
                    idx = i;
                    break;
                }
            }
            if idx == kids.len() {
                kids.push((name.clone(), Node::Branch(alloc::vec::Vec::new())));
            }
            return &mut kids[idx].1;
        }
        unreachable!("child() on a leaf");
    }

    fn set(&mut self, name: &string, v: Node) {
        if let Node::Branch(kids) = self {
            for (k, slot) in kids.iter_mut() {
                if k == name {
                    *slot = v;
                    return;
                }
            }
            kids.push((name.clone(), v));
        }
    }

    /// Collapses to a map, dropping groups that came out empty — Go
    /// requires that a group with no attributes is not emitted at all.
    fn collapse(&self) -> Option<map<string, Any>> {
        if let Node::Branch(kids) = self {
            let mut m: map<string, Any> = map::new();
            for (k, v) in kids.iter() {
                match v {
                    Node::Leaf(a) => m.Set(k.clone(), a.clone()),
                    Node::Branch(_) => {
                        if let Some(sub) = v.collapse() {
                            m.Set(k.clone(), Any::new(sub));
                        }
                    }
                }
            }
            if m.Len() == 0 {
                return None;
            }
            return Some(m);
        }
        return None;
    }
}

/// A minimally-CONFORMING handler.
///
/// Attrs are stored with the group path that was open when they were
/// added, because `WithGroup("a").WithAttrs(x).WithGroup("b")` must put
/// x inside "a" and NOT inside "b". A handler keeping one flat prefix
/// list cannot express that, and Go has a case for exactly it.
struct Recorder {
    prefix: alloc::vec::Vec<(alloc::vec::Vec<string>, slice<slog::Attr>)>,
    groups: alloc::vec::Vec<string>,
}

fn newRecorder() -> Arc<dyn slog::Handler + Send + Sync> {
    return Arc::new(Recorder {
        prefix: alloc::vec::Vec::new(),
        groups: alloc::vec::Vec::new(),
    });
}

impl Recorder {
    /// Places one Attr into the tree at `path`, expanding inline groups.
    fn put(&self, root: &mut Node, path: &[string], a: &slog::Attr) {
        let v = slog::Resolve(&a.Value);

        let mut at = root;
        for p in path.iter() {
            at = at.child(p);
        }

        if v.Kind() == slog::KindGroup {
            if let Some(list) = v.Any().As::<slice<slog::Attr>>() {
                if list.Len() == 0 {
                    return;
                }
                let mut sub = Node::Branch(alloc::vec::Vec::new());
                for i in 0..list.Len() {
                    self.put(&mut sub, &[], &list[i]);
                }
                if let Node::Branch(kids) = &sub {
                    if kids.len() == 0 {
                        return;
                    }
                }
                // A group with an empty NAME is inlined into its parent.
                if a.Key.Len() == 0 {
                    if let Node::Branch(kids) = sub {
                        for (k, n) in kids.into_iter() {
                            at.set(&k, n);
                        }
                    }
                    return;
                }
                at.set(&a.Key, sub);
            }
            return;
        }

        // Go: an Attr with an empty key AND value is elided entirely.
        if a.Key.Len() == 0 && v.Kind() == slog::KindAny && v.Any().IsNil() {
            return;
        }
        at.set(&a.Key, Node::Leaf(v.Any()));
    }

    fn derive(
        &self,
        prefix: alloc::vec::Vec<(alloc::vec::Vec<string>, slice<slog::Attr>)>,
        groups: alloc::vec::Vec<string>,
    ) -> Arc<dyn slog::Handler + Send + Sync> {
        return Arc::new(Recorder { prefix, groups });
    }
}

impl slog::Handler for Recorder {
    fn Enabled(&self, _c: &dyn context::Context, _l: slog::Level) -> bool {
        return true;
    }

    fn Handle(&self, _c: &dyn context::Context, r: slog::Record) -> errors::error {
        let mut root = Node::Branch(alloc::vec::Vec::new());

        // The built-in keys sit at the top level, never inside a group.
        if !r.Time.IsZero() {
            root.set(&s(slog::TimeKey), Node::Leaf(Any::new(r.Time.Unix())));
        }
        root.set(&s(slog::LevelKey), Node::Leaf(Any::new(r.Level.0)));
        root.set(
            &s(slog::MessageKey),
            Node::Leaf(Any::new(r.Message.clone())),
        );

        // Then the accumulated With attrs, each at the path it was
        // added under…
        for (path, attrs) in self.prefix.iter() {
            for i in 0..attrs.Len() {
                self.put(&mut root, path, &attrs[i]);
            }
        }
        // …and finally the Record's own, under whatever groups are open.
        r.Attrs(|a: &slog::Attr| {
            self.put(&mut root, &self.groups, a);
            return true;
        });

        let flat = match root.collapse() {
            Some(m) => m,
            None => map::new(),
        };
        SINK.Lock().push(flat);
        return errors::nil;
    }

    fn WithAttrs(&self, attrs: slice<slog::Attr>) -> Arc<dyn slog::Handler + Send + Sync> {
        if attrs.Len() == 0 {
            return self.derive(self.prefix.clone(), self.groups.clone());
        }
        let mut p = self.prefix.clone();
        p.push((self.groups.clone(), attrs));
        return self.derive(p, self.groups.clone());
    }

    fn WithGroup(&self, name: string) -> Arc<dyn slog::Handler + Send + Sync> {
        if name.Len() == 0 {
            return self.derive(self.prefix.clone(), self.groups.clone());
        }
        let mut g = self.groups.clone();
        g.push(name);
        return self.derive(self.prefix.clone(), g);
    }
}

// ─── a deliberately broken one ───────────────────────────────────────

/// Emits every attribute at the top level, ignoring WithGroup. Produces
/// one record per case, so only a CONTENT check can catch it.
struct Flattener;

fn newFlattener() -> Arc<dyn slog::Handler + Send + Sync> {
    return Arc::new(Flattener);
}

impl slog::Handler for Flattener {
    fn Enabled(&self, _c: &dyn context::Context, _l: slog::Level) -> bool {
        return true;
    }
    fn Handle(&self, _c: &dyn context::Context, r: slog::Record) -> errors::error {
        let mut flat: map<string, Any> = map::new();
        if !r.Time.IsZero() {
            flat.Set(s(slog::TimeKey), Any::new(r.Time.Unix()));
        }
        flat.Set(s(slog::LevelKey), Any::new(r.Level.0));
        flat.Set(s(slog::MessageKey), Any::new(r.Message.clone()));
        r.Attrs(|a: &slog::Attr| {
            flat.Set(a.Key.clone(), slog::Resolve(&a.Value).Any());
            return true;
        });
        SINK.Lock().push(flat);
        return errors::nil;
    }
    fn WithAttrs(&self, _a: slice<slog::Attr>) -> Arc<dyn slog::Handler + Send + Sync> {
        return newFlattener();
    }
    fn WithGroup(&self, _n: string) -> Arc<dyn slog::Handler + Send + Sync> {
        return newFlattener();
    }
}

// ─── the two Run tests ───────────────────────────────────────────────

fn run_conforming(t: &mut testing::T) {
    slogtest::Run(
        t,
        |_t| {
            sinkClear();
            return newRecorder();
        },
        |_t| sinkLast(),
    );
}

fn run_broken(t: &mut testing::T) {
    slogtest::Run(
        t,
        |_t| {
            sinkClear();
            return newFlattener();
        },
        |_t| sinkLast(),
    );
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let want = slogtest::cases().len();

    // 1. A conforming handler passes every case, and produces exactly
    //    one record per case.
    {
        sinkClear();
        let err = TestHandler(newRecorder(), sinkAll);
        let n = SINK.Lock().len();
        if err == errors::nil && n == want {
            fmt::Println!("[ 1] conforming handler passes PASS");
        } else {
            let msg = if err != errors::nil {
                err.Error()
            } else {
                s("")
            };
            fmt::Println!(
                "[ 1] conforming handler passes FAIL n=",
                n as i64,
                " [",
                msg,
                "]"
            );
            failed += 1;
        }
    }

    // 2. A handler that records NOTHING is caught by the result count,
    //    and the message says so — every later case would otherwise be
    //    compared against the wrong explanation.
    {
        sinkClear();
        let err = TestHandler(newRecorder(), || slice::new());
        let m = if err != errors::nil {
            err.Error()
        } else {
            s("")
        };
        let ms: &str = m.as_ref();
        if err != errors::nil && ms.starts_with("got 0 results, want") {
            fmt::Println!("[ 2] empty results caught      PASS");
        } else {
            fmt::Println!("[ 2] empty results caught      FAIL [", m, "]");
            failed += 1;
        }
    }

    // 3. The case table is the size Go's is. Ordering is load-bearing
    //    too, since results are matched to cases positionally.
    {
        if want == 17 {
            fmt::Println!("[ 3] case table populated      PASS");
        } else {
            fmt::Println!("[ 3] case table populated      FAIL got ", want as i64);
            failed += 1;
        }
    }

    // 4. A handler producing the right NUMBER of records but ignoring
    //    WithGroup must still be caught. Without this, a TestHandler
    //    that only counted results would pass checks 1-3 while
    //    inspecting nothing.
    {
        sinkClear();
        let err = TestHandler(newFlattener(), sinkAll);
        let n = SINK.Lock().len();
        let m = if err != errors::nil {
            err.Error()
        } else {
            s("")
        };
        let ms: &str = m.as_ref();
        if err != errors::nil && n == want && !ms.starts_with("got 0 results") {
            fmt::Println!("[ 4] dropped groups caught     PASS");
        } else {
            fmt::Println!(
                "[ 4] dropped groups caught     FAIL n=",
                n as i64,
                " [",
                m,
                "]"
            );
            failed += 1;
        }
    }

    // 5/6. Run drives the same cases through the real test harness, one
    //    subtest per case, reporting through t instead of returning an
    //    error. Both directions again: green for a conforming handler,
    //    red for a broken one.
    {
        fmt::Println!("--- slogtest::Run over a conforming handler:");
        let good = testing::Main(&[("SlogtestRunConforming", run_conforming)]);
        fmt::Println!("--- slogtest::Run over a handler that drops groups");
        fmt::Println!("    (the FAILs below are the expected result):");
        let bad = testing::Main(&[("SlogtestRunBroken", run_broken)]);

        if good == 0 {
            fmt::Println!("[ 5] Run passes conforming     PASS");
        } else {
            fmt::Println!("[ 5] Run passes conforming     FAIL");
            failed += 1;
        }
        if bad != 0 {
            fmt::Println!("[ 6] Run fails on bad handler  PASS");
        } else {
            fmt::Println!("[ 6] Run fails on bad handler  FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
