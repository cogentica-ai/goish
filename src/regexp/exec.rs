// Port of Go 1.25.5 regexp/exec.go — the NFA simulation.
//
// goishlint:ignore GOISH015 — this file also carries `endOfText` from regexp.go, one constant that exec.go's every input step compares against. It moves to a regexp.rs when the public surface is rewired in stage 4b.
// goishlint:ignore GOISH021 inputs, onePassMachine, onePassPool, arrayNoInts — the `input` interface and its three implementations, the onepass machine's pool, and regexp.go's shared empty slice. All belong to code stage 4a does not port; see above.
// goishlint:ignore GOISH020 step — Go's `step` takes runq and nextq as separate pointers. Rust will not hand out two `&mut` into the same struct, so goish passes one bool naming which of `q0`/`q1` is the runq and derives the other. Same two queues, one parameter fewer.
// goishlint:ignore GOISH019 pc, inst, re, pool, inputs, q0, q1, longest, cond, steps — `thread` holds a pc where Go holds `inst *syntax.Inst`, because a borrow of the program cannot live across the mutations `add` and `step` make. `machine` has no `re` (goish passes `longest` and `cond` in), no `pool` (goish's threads are values in the queue) and no `inputs` (goish's regexp takes a string, so the input is its bytes); `steps` is the counter the linear-time bound is asserted with.
// goishlint:ignore GOISH018 alloc — Go's thread-pool allocator. goish's threads are values in the queue's `dense`, so there is nothing to allocate from a pool.
//
// goishlint:ignore GOISH018 match, alloc, inputs, newBytes, newString, newReader, clear, init, newOnePassMachine, freeOnePassMachine, doOnePass, newMachine, freeMachine, doMatch, doExecute, canCheckPrefix, index, context, hasPrefix, step — `match` is anchored twice below but the anchor cannot name the Rust function, which must be `r#match` because `match` is a keyword; `alloc` is Go's thread-pool allocator, and goish's threads are values in the queue so there is nothing to allocate from a pool. The rest is the incremental port (§2c stage 4a). The `input` abstraction is a three-way interface over []byte, string and io.RuneReader; goish's regexp takes a string and this file runs over its bytes directly. `doOnePass` and the onePassMachine pool belong to onepass.go, which is an OPTIMISATION goish does not have — see the file header. The machine pool, the prefix fast path and `doExecute`'s engine choice arrive with the swap in stage 4b.
//
// This is the point of §2c. goish's matcher backtracks over the AST and
// is exponential on `(a+)+$`; this one runs a THREAD LIST over the
// compiled program, and Go's guarantee follows from one property of it:
//
//     `add` refuses to enqueue a pc already on the queue.
//
// So each queue holds at most one entry per instruction, each input
// position does at most O(len(prog)) work, and the whole match is
// O(len(prog) × len(input)). No input can make it blow up, because
// there is nowhere for the blowup to go.
//
// ─── what is NOT ported, and why it is safe ──────────────────────────
//
// Go has THREE engines and picks between them: `onepass` for patterns
// whose automaton never needs to branch, `backtrack` for small programs
// and short inputs, and this NFA for everything else. The first two are
// optimisations — the NFA answers every case correctly, which is why Go
// falls back to it — so goish has only this one. That is slower on some
// patterns and it is not a divergence in RESULT, which is what
// `regexp_exec_ref_smoke` compares.
//
// The sparse-set queue is Russ Cox's, and its trick is worth naming:
// `sparse[pc]` is read WITHOUT being initialised, and the read is only
// trusted when `dense[sparse[pc]].pc == pc` confirms it. That makes
// clearing the queue O(1) — set `dense`'s length to zero — instead of
// O(len(prog)) per position, which for a long input is the difference
// between linear and quadratic.

use alloc::vec::Vec;

use crate::regexp::syntax;
use crate::regexp::syntax::prog::{
    EmptyBeginLine, EmptyBeginText, EmptyEndLine, EmptyEndText, EmptyNoWordBoundary, EmptyOp,
    EmptyWordBoundary, Inst, InstAlt, InstAltMatch, InstCapture, InstEmptyWidth, InstFail,
    InstMatch, InstNop, InstRune, InstRune1, InstRuneAny, InstRuneAnyNotNL, IsWordChar, Prog,
};
use crate::{int, rune};

// go: sdk 1.25.5 regexp/regexp.go:368-368 endOfText
/// The rune `step` returns past the end of the input. `-1` rather than
/// a flag, so `lazyFlag` can hold it in the same field as a real rune.
pub(crate) const endOfText: rune = -1;

// go: sdk 1.25.5 regexp/exec.go:15-18 queue
/// Go: "A queue is a 'sparse array' holding pending threads of
/// execution."
///
/// `sparse` is indexed by pc and read uninitialised; see the file
/// header for why that is sound.
#[allow(non_camel_case_types)] // Go name
#[derive(Default)]
struct queue {
    sparse: Vec<u32>,
    dense: Vec<entry>,
}

// go: sdk 1.25.5 regexp/exec.go:20-27 entry
/// Go: "An entry is an entry on a queue. It holds both the instruction
/// pc and the actual thread. Some queue entries are just place holders
/// so that the machine knows it has considered that pc. Such entries
/// have t == nil."
#[allow(non_camel_case_types)] // Go name
#[derive(Clone, Default)]
struct entry {
    pc: u32,
    /// Go's `t *thread`; `None` is the placeholder.
    t: Option<thread>,
}

// goishlint:ignore GOISH019 inst, pc — Go's `thread` holds `inst
// *syntax.Inst`; goish holds the pc and indexes the program, because a
// borrow of `m.p.Inst[..]` cannot live across the mutations `add` and
// `step` make to the queues.
// go: sdk 1.25.5 regexp/exec.go:29-34 thread
/// Go: "A thread is the state of a single path through the machine: an
/// instruction and a corresponding capture array."
///
/// Go holds `inst *syntax.Inst`; goish holds the pc and indexes the
/// program, because a borrow of `m.p.Inst[..]` cannot live across the
/// mutations `add` and `step` make.
#[allow(non_camel_case_types)] // Go name
#[derive(Clone, Default)]
struct thread {
    pc: u32,
    cap: Vec<int>,
}

// goishlint:ignore GOISH019 re, pool, inputs, q0, q1, longest, cond, steps — no `re` (goish passes `longest` and `cond` in rather than reading them off a Regexp that does not exist yet), no `pool` (goish's threads are values in the queue's `dense`, so there is nothing to recycle), no `inputs` (goish's regexp takes a string, so the input is its bytes). `q0`/`q1` are Go's, spelled separately because Go declares them on one line. `steps` is goish-only: the counter the linear-time bound is asserted with instead of timed.
// go: sdk 1.25.5 regexp/exec.go:38-47 machine
/// Go: "A machine holds all the state during an NFA simulation for p."
///
/// Go's `pool []*thread` recycles thread allocations. goish's threads
/// are values in the queue's `dense`, so there is nothing to recycle
/// and no pool; the observable behaviour is identical because the pool
/// never affects which threads run, only where their memory came from.
#[allow(non_camel_case_types)] // Go name
pub(crate) struct machine<'a> {
    p: &'a Prog,
    /// Go's `q0, q1` — runq and nextq, swapped each step.
    q0: queue,
    q1: queue,
    /// Whether a match was found.
    matched: bool,
    /// Capture information for the match.
    matchcap: Vec<int>,
    /// Go reads these off the `*Regexp`; goish passes them in.
    longest: bool,
    cond: EmptyOp,
    // go: none — goish-only: a count of `add` calls, so the
    //     linear-time guarantee can be ASSERTED rather than timed. A
    //     wall-clock assertion is a flake waiting to happen on shared
    //     CI; this is deterministic and it is the actual property.
    /// How many times `add` has been entered.
    steps: i64,
}

// go: sdk 1.25.5 regexp/exec.go:122-122 lazyFlag
/// Go: "a lazily-evaluated syntax.EmptyOp, for checking zero-width
/// flags like ^ $ \A \z \B \b. It records the pair of relevant runes
/// and does not determine the implied flags until absolutely necessary
/// (most of the time, that means never)."
#[allow(non_camel_case_types)] // Go name
#[derive(Clone, Copy, Default)]
struct lazyFlag(u64);

// go: sdk 1.25.5 regexp/exec.go:124-126 newLazyFlag
/// Pack the rune before and the rune after into one word.
fn newLazyFlag(r1: rune, r2: rune) -> lazyFlag {
    return lazyFlag((crate::uint64(crate::int64(r1)) << 32) | crate::uint64(crate::int64(crate::uint32(r2))));
}

impl lazyFlag {
    // goishlint:ignore GOISH014 — `match` is a Rust keyword, so the method is `r#match`; the anchor names Go's spelling.
    // go: sdk 1.25.5 regexp/exec.go:128-169 lazyFlag.match
    /// Whether the packed pair satisfies every bit of `op`.
    ///
    /// Each satisfied condition is CLEARED and the function returns
    /// early when nothing is left, which is what makes it lazy: the
    /// word-boundary test at the bottom — the only one that costs two
    /// `IsWordChar` calls — usually never runs.
    fn r#match(&self, op: EmptyOp) -> bool {
        let mut op = op;
        if op.0 == 0 {
            return true;
        }
        let r1 = crate::int32(crate::uint32(crate::int64((self.0 >> 32) & 0xffff_ffff)));
        if (op & EmptyBeginLine).0 != 0 {
            if r1 != rune('\n') && r1 >= 0 {
                return false;
            }
            op = EmptyOp(op.0 & !EmptyBeginLine.0);
        }
        if (op & EmptyBeginText).0 != 0 {
            if r1 >= 0 {
                return false;
            }
            op = EmptyOp(op.0 & !EmptyBeginText.0);
        }
        if op.0 == 0 {
            return true;
        }
        let r2 = crate::int32(crate::uint32(crate::int64(self.0 & 0xffff_ffff)));
        if (op & EmptyEndLine).0 != 0 {
            if r2 != rune('\n') && r2 >= 0 {
                return false;
            }
            op = EmptyOp(op.0 & !EmptyEndLine.0);
        }
        if (op & EmptyEndText).0 != 0 {
            if r2 >= 0 {
                return false;
            }
            op = EmptyOp(op.0 & !EmptyEndText.0);
        }
        if op.0 == 0 {
            return true;
        }
        if IsWordChar(r1) != IsWordChar(r2) {
            op = EmptyOp(op.0 & !EmptyWordBoundary.0);
        } else {
            op = EmptyOp(op.0 & !EmptyNoWordBoundary.0);
        }
        return op.0 == 0;
    }
}

// go: none — goish idiom: Go's `input` is an interface over []byte,
//     string and io.RuneReader with a `step` method. goish's regexp
//     takes a string, so the input is its bytes and `step` is a
//     function over them.
/// Decode the rune at `pos`, or `(endOfText, 0)` at the end.
fn inputStep(b: &[u8], pos: usize) -> (rune, usize) {
    if pos >= b.len() {
        return (endOfText, 0);
    }
    let (r, w) = crate::unicode::utf8::DecodeRune(&b[pos..]);
    return (r, crate::int64(w) as usize);
}

// go: none — goish idiom: Go's `input.context`, which the three input
//     kinds each implement. Same computation over bytes.
/// The zero-width context at `pos`: the rune before and the rune after.
fn inputContext(b: &[u8], pos: usize) -> lazyFlag {
    let mut r1: rune = endOfText;
    if pos > 0 && pos <= b.len() {
        let (r, _) = crate::unicode::utf8::DecodeLastRune(&b[..pos]);
        r1 = r;
    }
    let mut r2: rune = endOfText;
    if pos < b.len() {
        let (r, _) = crate::unicode::utf8::DecodeRune(&b[pos..]);
        r2 = r;
    }
    return newLazyFlag(r1, r2);
}

impl<'a> machine<'a> {
    // go: none — goish idiom: Go pools machines per Regexp and calls
    //     `init(ncap)`. goish builds one per execution; the pool is an
    //     allocation strategy, not behaviour.
    /// A machine over `p`, with `ncap` capture slots.
    pub(crate) fn __new(p: &'a Prog, ncap: usize, longest: bool, cond: EmptyOp) -> machine<'a> {
        let n = p.Inst.len();
        let mut m = machine {
            p,
            q0: queue::default(),
            q1: queue::default(),
            matched: false,
            matchcap: Vec::new(),
            longest,
            cond,
            steps: 0,
        };
        m.q0.sparse.resize(n, 0);
        m.q1.sparse.resize(n, 0);
        m.q0.dense.reserve(n);
        m.q1.dense.reserve(n);
        m.matchcap.resize(ncap, -1);
        return m;
    }

    // goishlint:ignore GOISH014 — see the note on `lazyFlag::r#match`.
    // go: sdk 1.25.5 regexp/exec.go:175-243 machine.match
    /// Go: "match runs the machine over the input starting at pos. It
    /// reports whether a match was found. If so, m.matchcap holds the
    /// submatch information."
    ///
    /// Go's prefix fast path — `i.index(m.re, pos)`, which memchrs for
    /// a required literal prefix — is not ported. It only ever SKIPS
    /// positions that cannot match, so omitting it costs time and not
    /// answers.
    pub(crate) fn r#match(&mut self, b: &[u8], pos: usize) -> bool {
        if self.cond == !EmptyOp(0) {
            // Go: impossible.
            return false;
        }
        self.matched = false;
        for i in 0..self.matchcap.len() {
            self.matchcap[i] = -1;
        }
        // Go swaps two queue pointers; goish swaps a bool, because two
        // `&mut` into the same struct is what Rust will not give.
        let mut runq_is_q0 = true;
        let mut pos = pos;
        let (mut r, mut width) = inputStep(b, pos);
        let mut r1: rune = endOfText;
        let mut width1: usize = 0;
        if r != endOfText {
            let (a, w) = inputStep(b, pos + width);
            r1 = a;
            width1 = w;
        }
        let mut flag = if pos == 0 {
            newLazyFlag(-1, r)
        } else {
            inputContext(b, pos)
        };

        loop {
            let runq_len = if runq_is_q0 {
                self.q0.dense.len()
            } else {
                self.q1.dense.len()
            };
            if runq_len == 0 {
                if (self.cond & EmptyBeginText).0 != 0 && pos != 0 {
                    // Go: anchored match, past beginning of text.
                    break;
                }
                if self.matched {
                    // Go: have match; finished exploring alternatives.
                    break;
                }
                // Go's literal-prefix fast search would go here.
            }
            if !self.matched {
                if !self.matchcap.is_empty() {
                    self.matchcap[0] = int::from(crate::int64(pos));
                }
                let start = crate::uint32(crate::int64(self.p.Start));
                let cap = self.matchcap.clone();
                self.add(runq_is_q0, start, pos, &cap, &flag, None);
            }
            flag = newLazyFlag(r, r1);
            self.step(runq_is_q0, pos, pos + width, r, &flag);
            if width == 0 {
                break;
            }
            if self.matchcap.is_empty() && self.matched {
                // Go: "Found a match and not paying attention to where
                // it is, so any match will do."
                break;
            }
            pos += width;
            r = r1;
            width = width1;
            if r != endOfText {
                let (a, w) = inputStep(b, pos + width);
                r1 = a;
                width1 = w;
            }
            runq_is_q0 = !runq_is_q0;
        }
        if runq_is_q0 {
            self.q1.dense.clear();
        } else {
            self.q0.dense.clear();
        }
        return self.matched;
    }

    // go: sdk 1.25.5 regexp/exec.go:260-311 machine.step
    /// Go: "step executes one step of the machine, running each of the
    /// threads on runq and appending new threads to nextq."
    ///
    /// The `InstMatch` arm carries the whole difference between
    /// leftmost-first and leftmost-longest. In first-match mode it
    /// TRUNCATES the queue, cutting off every lower-priority thread —
    /// which is what makes `a|ab` match `a`. In longest mode it keeps
    /// them and only replaces the recorded match when this one ends
    /// later.
    fn step(&mut self, runq_is_q0: bool, pos: usize, nextPos: usize, c: rune, nextCond: &lazyFlag) {
        let longest = self.longest;
        let mut j = 0usize;
        loop {
            let dense_len = if runq_is_q0 {
                self.q0.dense.len()
            } else {
                self.q1.dense.len()
            };
            if j >= dense_len {
                break;
            }
            let t = {
                let d = if runq_is_q0 {
                    &self.q0.dense[j]
                } else {
                    &self.q1.dense[j]
                };
                d.t.clone()
            };
            let t = match t {
                Some(t) => t,
                None => {
                    j += 1;
                    continue;
                }
            };
            if longest && self.matched && !t.cap.is_empty() && self.matchcap[0] < t.cap[0] {
                j += 1;
                continue;
            }
            let i: Inst = self.p.Inst[t.pc as usize].clone();
            let mut add = false;
            if i.Op == InstMatch {
                if !t.cap.is_empty()
                    && (!longest || !self.matched || self.matchcap[1] < int::from(crate::int64(pos)))
                {
                    let mut c2 = t.cap.clone();
                    c2[1] = int::from(crate::int64(pos));
                    for k in 0..self.matchcap.len().min(c2.len()) {
                        self.matchcap[k] = c2[k];
                    }
                }
                if !longest {
                    // Go: "First-match mode: cut off all lower-priority
                    // threads."
                    if runq_is_q0 {
                        self.q0.dense.clear();
                    } else {
                        self.q1.dense.clear();
                    }
                }
                self.matched = true;
            } else if i.Op == InstRune {
                add = i.MatchRune(c);
            } else if i.Op == InstRune1 {
                add = c == i.Rune[0];
            } else if i.Op == InstRuneAny {
                add = true;
            } else if i.Op == InstRuneAnyNotNL {
                add = c != rune('\n');
            } else {
                panic!("bad inst");
            }
            if add {
                let cap = t.cap.clone();
                self.add(!runq_is_q0, i.Out, nextPos, &cap, nextCond, None);
            }
            j += 1;
        }
        if runq_is_q0 {
            self.q0.dense.clear();
        } else {
            self.q1.dense.clear();
        }
    }

    // go: sdk 1.25.5 regexp/exec.go:317-374 machine.add
    /// Go: "add adds an entry to q for pc, unless the q already has
    /// such an entry. It also recursively adds an entry for all
    /// instructions reachable from pc by following empty-width
    /// conditions satisfied by cond."
    ///
    /// THE REFUSAL IN THE FIRST SENTENCE IS THE LINEAR-TIME GUARANTEE.
    /// One entry per pc per position bounds the work at each position
    /// by the program's length, and no input can push past that.
    ///
    /// Go's `goto Again` is a loop here; Go's thread reuse (`t` passed
    /// in and handed back) is an allocation optimisation goish does not
    /// need, so the parameter is kept for shape and always `None`.
    // goishlint:ignore GOISH023 — the body IS the loop that replaces
    //     Go's `goto Again`, and every exit from it is an explicit
    //     `return`. There is no trailing expression to convert.
    fn add(
        &mut self,
        q_is_q0: bool,
        pc: u32,
        pos: usize,
        cap: &[int],
        cond: &lazyFlag,
        t: Option<thread>,
    ) -> Option<thread> {
        self.steps += 1;
        let mut pc = pc;
        let mut cap: Vec<int> = cap.to_vec();
        loop {
            if pc == 0 {
                return t;
            }
            {
                let q = if q_is_q0 { &self.q0 } else { &self.q1 };
                let j = q.sparse[pc as usize];
                if (j as usize) < q.dense.len() && q.dense[j as usize].pc == pc {
                    return t;
                }
            }

            let j = {
                let q = if q_is_q0 {
                    &mut self.q0
                } else {
                    &mut self.q1
                };
                let j = q.dense.len();
                q.dense.push(entry { pc, t: None });
                q.sparse[pc as usize] = crate::uint32(crate::int64(j));
                j
            };

            let i: Inst = self.p.Inst[pc as usize].clone();
            if i.Op == InstFail {
                // Go: nothing
                return t;
            } else if i.Op == InstAlt || i.Op == InstAltMatch {
                self.add(q_is_q0, i.Out, pos, &cap, cond, None);
                pc = i.Arg;
                continue;
            } else if i.Op == InstEmptyWidth {
                if cond.r#match(EmptyOp(crate::uint8(i.Arg))) {
                    pc = i.Out;
                    continue;
                }
                return t;
            } else if i.Op == InstNop {
                pc = i.Out;
                continue;
            } else if i.Op == InstCapture {
                if (i.Arg as usize) < cap.len() {
                    let opos = cap[i.Arg as usize];
                    cap[i.Arg as usize] = int::from(crate::int64(pos));
                    self.add(q_is_q0, i.Out, pos, &cap, cond, None);
                    cap[i.Arg as usize] = opos;
                    return t;
                }
                pc = i.Out;
                continue;
            } else if i.Op == InstMatch
                || i.Op == InstRune
                || i.Op == InstRune1
                || i.Op == InstRuneAny
                || i.Op == InstRuneAnyNotNL
            {
                let q = if q_is_q0 {
                    &mut self.q0
                } else {
                    &mut self.q1
                };
                q.dense[j].t = Some(thread {
                    pc,
                    cap: cap.clone(),
                });
                return None;
            } else {
                panic!("unhandled");
            }
        }
    }

    // go: none — goish idiom: Go's caller reads `m.matchcap` directly.
    /// The capture slots after a successful [`machine::match`].
    pub(crate) fn __matchcap(&self) -> &[int] {
        return &self.matchcap;
    }

    // go: none — goish-only: see the `steps` field.
    /// How many `add` calls this match took.
    pub(crate) fn __steps(&self) -> i64 {
        return self.steps;
    }
}

// go: none — goish-only: the whole pipeline in one call, for
//     `regexp_exec_ref_smoke`. The public `Regexp` is rewired onto the
//     machine in stage 4b; until then this is its only caller.
/// Parse, simplify, compile and run `pattern` against `subject`.
///
/// Returns `None` when there is no match, else the capture slots — the
/// same shape as Go's `FindStringSubmatchIndex`.
#[doc(hidden)]
pub fn __exec(
    pattern: &crate::gostring::string,
    subject: &crate::gostring::string,
    longest: bool,
) -> Option<crate::goslice::slice<int>> {
    let (m, _) = __exec_steps(pattern, subject, longest);
    return m.map(crate::goslice::slice::__from_vec);
}

// go: none — goish-only: [`__exec`] plus the machine's `add` count, so
//     `regexp_exec_ref_smoke` can assert the linear-time bound instead
//     of timing it.
/// `(captures, add-calls)`.
#[doc(hidden)]
pub fn __exec_steps(
    pattern: &crate::gostring::string,
    subject: &crate::gostring::string,
    longest: bool,
) -> (Option<Vec<int>>, i64) {
    let (re, err) = syntax::Parse(pattern.clone(), syntax::Perl);
    if !err.IsNil() {
        return (None, 0);
    }
    let re = re.MustTake();
    let sre = re.Simplify();
    let (prog, _) = syntax::Compile(&sre);
    let ncap = 2 * ((crate::int64(re.MaxCap()) as usize) + 1);
    let cond = prog.StartCond();
    let mut m = machine::__new(&prog, ncap, longest, cond);
    if !m.r#match(subject.as_bytes(), 0) {
        return (None, m.__steps());
    }
    return (Some(m.__matchcap().to_vec()), m.__steps());
}
