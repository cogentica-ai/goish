# Mutation-Effects Analysis Pass — Design Discussion

Status: design draft. Not implemented. Captured at the end of the
2026-05-05 session that shipped the `oklog/ulid/v2` port (187 → 0
errors via T1–T5 transpiler fixes + R1–R4 runtime additions).

This is the design record for an upcoming refactor that unifies the
six ad-hoc mutation visitors in goishc into a single per-function
effect-tagging pass. It is the analogue of `DISCUSSION_VAR.md` for the
mut/non-mut question.

---

## 1. The unifying observation

Every mut/non-mut decision goishc makes is asking the same question
of one named entity (binding, param, receiver, or transitive `*p`
deref):

> **For binding/param/receiver X, which kinds of mutation does the
> body apply, and which kinds do its callers require?**

The current code base has ~6 ad-hoc visitors answering slices of this
question with slightly different rules and no shared state:

| Visitor | Owns | File |
|---|---|---|
| `paramsAssignedInBody` | `let mut x` for params | `decls.go` |
| `pointerParamsWrittenThrough` | `*T → &mut T` promotion | `decls.go` |
| L2 mutating-receiver promotion | `&self → &mut self` | `decls.go` |
| T3 call-site `&x → &mut x` | Call-site borrow choice | `bodies.go::emitArgsForCall` |
| T4 skip auto-clone on user-iface field | Field-read clone elision | `bodies.go::shouldAutoCloneSelector` |
| T5 embedded-field FieldType collection | `FieldTypes` lookup keys | `collect.go::collectFieldTypes` |

Adding T2 (this session) — `(*p)[i] =` and `(*p).f =` write-through
detection — was *another* slice of the same question. The heuristic
surface grows linearly with the patterns we encounter, and patterns
don't compose: T2 only sees `(*p)[i]=`, misses `f(&p.field)` where `f`
needs `&mut F`.

## 2. Effects alphabet

```go
type EffectKind uint16
const (
    EffReassign       EffectKind = 1 << iota  // x = expr   (incl. x++, x--)
    EffDerefWrite                             // *x = expr
    EffFieldWrite                             // x.f = expr (root traced to x)
    EffElemWrite                              // x[i] = expr (root traced to x)
    EffMutMethodCall                          // x.M(…) where M has *T receiver
    EffPassedAsMutPtr                         // f(&x,…) and f's param i requires write-through
    EffAddrTaken                              // &x captured outside (closure / return)
    EffConsumed                               // value moved (last-use, returned)
)

type EffectSet uint16  // bitmap
```

Subtleties:

- **`x.f = expr`** charges `EffFieldWrite` against `x`, not against
  `x.f`. Recursing through `SelectorExpr` finds the root binding.
- **`(*p).f = expr`** is `EffFieldWrite` on `*p`, which means
  `EffDerefWrite | EffFieldWrite` charged against `p` (the pointer)
  — together they imply `*T → &mut T`.
- **`&x` taken in a `func(){…}` literal that escapes** →
  `EffAddrTaken`. Not needed for the immediate goal but it's the seam
  for future closure-capture analysis.

## 3. IR

```go
type FuncSig struct {
    Name     string
    Params   []ParamInfo
    Results  []ParamInfo
    Receiver *ParamInfo  // nil for free functions

    // Per-pos effect set folded over the body. Filled by the effect
    // walk. ParamRequires[i] = effects observed against params[i]
    // inside this function's body.
    ParamRequires    []EffectSet
    ReceiverRequires EffectSet
    LocalEffects     map[string]EffectSet  // declared bindings + named returns
}
```

The existing `ParamInfo.IsMutPointer` field collapses into

```go
ParamRequires[i] & (EffDerefWrite|EffFieldWrite|EffElemWrite) != 0
```

## 4. Type-info dependency

Three things in the alphabet cannot be answered by AST shape alone:

| Effect | Needs |
|---|---|
| `EffMutMethodCall` | Method-set lookup: does `x.M` dispatch to a pointer-receiver method? |
| Chains `x.f.g.h = expr` | Type of `x.f.g` to know if it's a pointer (charges `EffDerefWrite|EffFieldWrite` on `x.f.g`'s root), a struct (`EffFieldWrite`), or a map (`EffElemWrite`). |
| Cross-fn effects on stdlib calls | Signature of `io.ReadFull` etc. — needs to know it takes `*T` written-through. |

So we need **go/types** integrated. Use
`golang.org/x/tools/go/packages` with `LoadAllSyntax` mode — gives us
`*types.Info` keyed by `ast.Expr`. From there:

- `info.ObjectOf(ident)` → resolves to a `*types.Var`, `*types.Func`, etc.
- `info.TypeOf(expr)` → exact type
- `info.Selections[*ast.SelectorExpr]` → method dispatch + implicit
  indirections (Go promotes through embedded fields)

Stdlib effect signatures come from a small **stdlib effects
descriptor** alongside `stdlib.go` — same shape as the existing
`IsTrait` flag.

## 5. The walk (`classifyLHS` core)

Per `*ast.FuncDecl`:

```go
func walkFunc(prog *ProgramInfo, info *types.Info, fn *ast.FuncDecl) {
    e := newFuncEffects(fn)  // params, receiver, locals → 0

    ast.Inspect(fn.Body, func(n ast.Node) bool {
        switch s := n.(type) {
        case *ast.AssignStmt:
            for _, lhs := range s.Lhs {
                root, kinds := classifyLHS(info, lhs)
                if root != "" {
                    e.add(root, kinds)
                }
            }
        case *ast.IncDecStmt:
            root, _ := classifyLHS(info, s.X)
            e.add(root, EffReassign)
        case *ast.CallExpr:
            // 1. Method call x.M(): check receiver type via info.
            if sel, ok := s.Fun.(*ast.SelectorExpr); ok {
                if sig := methodSig(info, sel); sig != nil && sig.PointerReceiver {
                    if root := rootIdent(sel.X); root != "" {
                        e.add(root, EffMutMethodCall)
                    }
                }
            }
            // 2. Arg expressions: each `&ident` matched against
            //    callee's ParamRequires (looked up later in fixpoint;
            //    initially we record "needs callee[i] info").
            for i, arg := range s.Args {
                if u, ok := arg.(*ast.UnaryExpr); ok && u.Op == token.AND {
                    if root := rootIdent(u.X); root != "" {
                        e.recordCallSite(root, calleeName(s.Fun), i)
                    }
                }
            }
        }
        return true
    })
    prog.Effects[funcKey(fn)] = e
}
```

`classifyLHS` returns `(rootName, EffectSet)` for every shape:

| LHS shape | classifyLHS returns |
|---|---|
| `Ident{x}` | `(x, EffReassign)` |
| `StarExpr{X: Ident{p}}` | `(p, EffDerefWrite)` |
| `IndexExpr{X: Ident{x}}` | `(x, EffElemWrite)` |
| `SelectorExpr{X: Ident{x}, Sel: f}` | `(x, EffFieldWrite)` |
| `IndexExpr{X: ParenExpr{StarExpr{X: Ident{p}}}}` | `(p, EffDerefWrite \| EffElemWrite)` |
| `SelectorExpr{X: SelectorExpr{X: Ident{x}}}` | recurse, charge `EffFieldWrite` against `x` (and `EffDerefWrite` on intermediate ptr-typed fields) |

This single function replaces `pointerParamsWrittenThrough` and the
similar walkers entirely.

## 6. Fixpoint (deferred)

```
repeat:
  changed = false
  for each function f:
    for each call site (callee, args, pos) in f.callSites:
      for i, arg in args:
        if arg is &ident x and prog.Effects[callee].ParamRequires[i]
                               has any of (EffDerefWrite | EffFieldWrite
                                | EffElemWrite | EffMutMethodCall):
            if not f.LocalEffects[x] has EffPassedAsMutPtr:
              f.LocalEffects[x] |= EffPassedAsMutPtr
              if x is one of f's params:
                  f.ParamRequires[paramIdxOf(x)] |= EffPassedAsMutPtr
              changed = true
until !changed
```

Settles in 2–3 iterations for typical Go packages. Stdlib effects
seed from the descriptor, never updated by the fixpoint.

**Survey finding (2026-05-05):** in 6 shipped ports, the cross-fn
fixpoint would catch *zero* additional cases. Direct write-through
detection on `*T` params (what `pointerParamsWrittenThrough` already
does, unified through `classifyLHS`) covers 100% of observed needs.
Defer the fixpoint until a port surfaces it.

## 7. Consumers — what existing code becomes

Each ad-hoc visitor collapses into a 1-line query:

| Today's visitor | New query |
|---|---|
| `paramsAssignedInBody` | `LocalEffects[name] & EffReassign != 0` |
| `pointerParamsWrittenThrough` | `ParamRequires[i] & (EffDerefWrite\|EffFieldWrite\|EffElemWrite) != 0` |
| L2 mutating-receiver | `ReceiverRequires & (EffFieldWrite\|EffElemWrite\|EffMutMethodCall\|EffPassedAsMutPtr) != 0` |
| T3 call-site `&x → &mut x` | At call site: look up `prog.Effects[callee].ParamRequires[i]` directly |
| T4 skip auto-clone on user-iface field | Driven by `EffConsumed` (covers the more general "is this binding still live?" question) |
| `shouldAutoCloneSelector` | Same — driven by `EffConsumed` of the binding |

The patterns we currently can't handle become free:

- `f(&p.field)` where f wants `&mut`: `EffPassedAsMutPtr` reaches `p`
  through `SelectorExpr` chain (theoretical — survey shows this
  doesn't appear in real ports yet).
- `(*pp).f = …` (double pointer): `classifyLHS` recurses through `*`
  and `.f`, charging `pp` correctly.
- `*p++`: `IncDecStmt` goes through `classifyLHS`, ends up as
  `EffDerefWrite` on `p`.
- Method value vs method call: distinguished via
  `info.Selections`.

## 8. Survey findings (2026-05-05)

Catalogued mutation patterns across `oklog_ulid_v2`,
`pmezard_go_difflib`, `liggitt_tabwriter`, `uber_multierr`,
`cenkalti_backoff_v5`, `philhofer_fwd`. Findings reorder priorities:

| Category | Hand-rolled count | Real risk |
|---|---|---|
| Over-mutted params (`#[allow(unused_mut)]`) | 40+ sites | Wide — pure noise, but unblocks nothing |
| Redundant `.clone()` chains (loops, slice-assign) | 5+ in 2 ports | Wide — performance leak per port |
| `obj.field[i] = x` cloning the field | 1 confirmed (tabwriter:359), inferred elsewhere | **Codegen, not effects** — but driven by effects info |
| `f(&p.field)` cross-fn write-through | **0** observed | Imagined problem |
| Compositional `(*pp).f`, `*p++` | **0** observed | Imagined problem |
| Trait upcast `&mut dyn A as &mut dyn B` | Working (`uber_multierr:79`) | No work needed |
| IIFE static, runtime type-assert | Hand-edits | Out of scope for this pass |

Crucial detail: the 40+ `#[allow(unused_mut)]` sites are mostly
**named-return slots** from Go's
`func F() (id ULID, err error)` shape, not user-declared params.
The transpiler emits `let mut id; let mut err;` at function entry as
the named-return prelude, then defensively wraps each in
`#[allow(unused_mut)]` because it can't tell at emit time which slots
will be assigned. Effects-driven check fixes this trivially.

## 9. Phasing

**Phase 1 — `classifyLHS` + per-function `EffectSet` table**

No `go/types` integration yet. AST-based effect tagging covering the
cases observed in shipped ports:

- `EffReassign`, `EffDerefWrite`, `EffFieldWrite`, `EffElemWrite`
  from `AssignStmt` LHS / `IncDecStmt`.
- `EffPassedAsMutPtr` from `&Ident` args at calls to functions in
  this file (we already collect their `IsMutPointer` info).
- `EffMutMethodCall` deferred (needs go/types).

Lands as `effects.go`, populated during Pass 2, queried during
Pass 3.

**Phase 2 — Migrate existing visitors to read from the table**

`paramsAssignedInBody`, `pointerParamsWrittenThrough`, L2
receiver-promotion, T4 `IsKnownInterface` test all become 1-line
lookups. Delete the duplicate AST walks.

**Phase 3 — Named-return slot pruning**

When emitting the named-return prelude, check the effects table:

- Slot has *any* effect → `let mut name: T = Default::default();`
- Slot has *no* effect → drop the binding entirely

Drops `#[allow(unused_mut)]` everywhere it currently fires.

**Phase 4 — Liveness sub-pass for clone elimination**

Tracks last-use of each binding. Reads/uses the effects table for
"is this binding ever mutated after this point?". Two specific
codegen fixes from the survey:

- `range!(self.errors.clone())` where the loop body doesn't write
  `self.errors` → drop the clone, range over `&self.errors`.
- `self.maxwidths.append!(self.widths.clone().slice(...))` —
  recognize "single-shot temporary" pattern.

Risky phase; defer until 1–3 stable.

**Phase 5 — `go/types` integration**

Only if/when a port surfaces:
- Cross-function `&mut` propagation that direct-call detection misses
  (survey: 0 cases)
- Method-set lookup for `EffMutMethodCall` (today's heuristics
  already cover this via receiver-promotion paths)

On-demand, not scheduled.

## 10. Open decisions

1. **Stdlib effect descriptors — granularity.** Per-method
   (`io.Reader::Read` requires `&mut self`, `*[]byte` written) is
   precise but verbose. Per-trait (any `*T` param of a stdlib method
   is potentially write-through) is conservative but might over-mut.
   **Recommend:** start per-trait conservative, refine per-method
   only when over-mutting causes a port-side issue.

2. **Where does `Option<Box<dyn Trait>>` lowering live?** It's not a
   mutation question — it's a "this field is nil-compared" question.
   Different effect (`EffNilCompared`?) or separate pass?
   **Recommend:** separate small pass running on the same IR; the
   data-collection skeleton is identical.

3. **Receiver name canonicalization.** Current
   `CurrentReceiver = "r"` vs emitted `self`. Bug-prone (today's
   embedded-field bug touched this). **Recommend:** in the new pass,
   store both names; provide a single accessor `binding(rcvName)`
   that takes either.

4. **`go/packages` vs raw `go/types` + manual loader.**
   `go/packages` is the standard tool and handles modules + vendoring;
   raw `go/types` is faster but you have to feed it parsed
   dependencies yourself. **Recommend:** `go/packages` — the cost is
   one-time and `goishc deps` already pays it.

## 11. First spike

Write `effects.go` with `classifyLHS` + the per-function walk, run in
**shadow mode** alongside the existing `paramsAssignedInBody` and
`pointerParamsWrittenThrough`. At end of compile, assert the new
system gives the same answer as both. If they agree on the 138 e2e +
47 ports, grounds to migrate. If they disagree, the disagreements
*are* the bugs we want to find.

Phase 4 should land in a separate session — clone-elimination needs
careful regression testing.

## 12. Headline takeaways

1. **The cross-function fixpoint isn't worth building yet.** Survey:
   0 observations. Build later as a follow-up if a port forces it.
2. **`go/types` integration isn't worth doing yet.** The remaining
   cases that *would* need it are method dispatch through embedded
   interfaces, exotic in Go-stdlib-shape ports.
3. **The biggest user-visible win is named-return slot pruning,**
   which doesn't even need the cross-pass machinery — just the
   per-function effect set on locals.
