// runtime::symbolize::demangle_v0 — Rust v0 symbol demangler.
//
// go: none — goish-only: Rust's symbol mangling has no Go counterpart.
//
// WHY THIS EXISTS. `demangle.rs` handles the LEGACY mangling
// (`_ZN5goish…17h<hash>E`). This build emits rustc's v0 scheme, so it
// demangled nothing at all, and every backtrace goish printed was raw:
//
//     _RNvNtNtCsc47Z2okxEDo_5goish7runtime5pprof14StopCPUProfile
//
// That is what a SIGSEGV report, a panic trace, `runtime.Callers`
// output and a pprof text profile all showed. One binary in this tree
// defines 19231 v0 symbols and exactly zero of them were readable.
//
// SCOPE, and the rule that keeps it honest: this parses the v0 path and
// type grammar (RFC 2603) — crate roots, nested paths, inherent and
// trait impls, generic arguments, closures, backreferences, the
// primitive types, references, pointers, slices, arrays, tuples, `dyn`
// and fn pointers. Anything it does not model makes it return 0, and a
// caller that gets 0 prints the raw symbol. It never emits a name it is
// unsure of: a WRONG name in a backtrace is worse than a mangled one,
// because a mangled name is obviously mangled.
//
// NO ALLOCATION. It runs in the SIGSEGV handler, so output goes into a
// caller-supplied buffer and the recursion depth is capped.

/// Deepest nesting the parser will follow. Real symbols in this tree
/// reach about 20; the cap exists because this runs on a signal
/// handler's alternate stack, where blowing the stack turns a
/// diagnostic into a second crash.
const MAX_DEPTH: u32 = 64;

struct Demangler<'a> {
    sym: &'a [u8],
    /// Byte offset of the start of the path grammar, which is where
    /// backreferences are measured from.
    base: usize,
    pos: usize,
    out: &'a mut [u8],
    olen: usize,
    depth: u32,
    /// Set on any failure. Checked once at the end rather than
    /// threaded through every call site as a Result, which would
    /// triple the size of this file.
    bad: bool,
    /// How many higher-ranked lifetimes are currently in scope. v0
    /// indexes bound lifetimes de Bruijn style, so a name can only be
    /// recovered by counting binders — `L1_` is `'a` under two binders
    /// and `'b` under one.
    bound_depth: u64,
}

impl<'a> Demangler<'a> {
    /// The single write path. An EMPTY `out` means "parse but discard",
    /// which is how the trailing instantiating-crate path is validated
    /// without printing it.
    ///
    /// That distinction is the whole reason this exists. The first
    /// version bounds-checked against `out.len()` directly, so the
    /// discard pass — handed a zero-length slice — failed on its very
    /// first byte and reported the symbol unparseable. 14363 of 19231
    /// symbols bailed for that one reason, which looked like a grammar
    /// gap and was a buffer check.
    #[inline]
    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    fn putc(&mut self, c: u8) {
        if self.out.is_empty() {
            self.olen += 1;
            return;
        }
        if self.olen >= self.out.len() {
            self.bad = true;
            return;
        }
        self.out[self.olen] = c;
        self.olen += 1;
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    fn emit(&mut self, b: &[u8]) {
        for c in b.iter() {
            self.putc(*c);
            if self.bad {
                return;
            }
        }
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    fn peek(&self) -> u8 {
        if self.pos < self.sym.len() {
            return self.sym[self.pos];
        }
        return 0;
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    fn next(&mut self) -> u8 {
        let c = self.peek();
        if c == 0 {
            self.bad = true;
        } else {
            self.pos += 1;
        }
        return c;
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    fn eat(&mut self, want: u8) {
        if self.peek() == want {
            self.pos += 1;
        } else {
            self.bad = true;
        }
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    /// A base-62 number, as v0 writes disambiguators and backreference
    /// indices: digits then lowercase then uppercase, terminated by
    /// `_`, with the empty string meaning 0 and everything else
    /// meaning value+1.
    fn base62(&mut self) -> u64 {
        if self.peek() == b'_' {
            self.pos += 1;
            return 0;
        }
        let mut v: u64 = 0;
        // Bounded by the symbol length rather than `loop`, so the
        // function ends in an explicit return like every other one
        // here. A `loop` whose only exits are returns reads as a tail
        // expression to the linter, and it is also one unterminated
        // digit run away from spinning.
        while self.pos < self.sym.len() {
            let c = self.next();
            if self.bad {
                return 0;
            }
            let d = match c {
                b'0'..=b'9' => crate::uint64(c - b'0'),
                b'a'..=b'z' => crate::uint64(c - b'a') + 10,
                b'A'..=b'Z' => crate::uint64(c - b'A') + 36,
                b'_' => return v + 1,
                _ => {
                    self.bad = true;
                    return 0;
                }
            };
            v = match v.checked_mul(62).and_then(|x| x.checked_add(d)) {
                Some(x) => x,
                None => {
                    self.bad = true;
                    return 0;
                }
            };
        }
        // Ran off the end without the terminating `_`.
        self.bad = true;
        return 0;
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    /// A decimal length prefix, with v0's LEADING-ZERO rule: a first
    /// digit of `0` ends the number there.
    ///
    /// Reading digits greedily instead is wrong, and it is wrong in a
    /// way that only shows up on nested closures. Two adjacent
    /// zero-length identifiers — which is what `…4POOL00` is, the
    /// empty names of two nested closures — got read as one length
    /// "00", so the second closure's identifier was gone and the
    /// parse hit the instantiating crate where a length should be.
    /// That was every one of the 227 symbols this parser still
    /// refused, out of 19231.
    fn decimal(&mut self) -> usize {
        if !self.peek().is_ascii_digit() {
            self.bad = true;
            return 0;
        }
        let first = (self.next() - b'0') as usize;
        if first == 0 {
            return 0;
        }
        let mut v = first;
        while self.peek().is_ascii_digit() {
            let c = (self.next() - b'0') as usize;
            v = match v.checked_mul(10).and_then(|x| x.checked_add(c)) {
                Some(x) => x,
                None => {
                    self.bad = true;
                    return 0;
                }
            };
        }
        return v;
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    /// `s<base62>_`, or absent. The value is the base-62 number PLUS
    /// ONE, and that `+ 1` is not cosmetic — it is the difference
    /// between `{closure#0}` and `{closure#1}`.
    ///
    /// Read off the corpus rather than guessed: an absent
    /// disambiguator is 0, `s_` is 1, `s0_` is 2, `s1_` is 3, `s2_` is
    /// 4. Without the `+ 1`, 1142 of 19231 symbols named the right
    /// function and the wrong closure inside it — which is exactly the
    /// kind of plausible-but-wrong output this file is supposed to
    /// refuse to produce.
    fn disambiguator(&mut self) -> u64 {
        if self.peek() == b's' {
            self.pos += 1;
            let v = self.base62();
            return v + 1;
        }
        return 0;
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    /// Print a de Bruijn lifetime index as rustc names it: `'_` for 0
    /// (erased), otherwise `'a`, `'b`, … counted from the OUTERMOST
    /// binder in scope.
    ///
    /// Printing `'_` for everything was the first attempt and it is
    /// wrong in a way that matters: `for<'a, 'b> Fn(&'a mut T<'b>)` and
    /// `for<'a, 'b> Fn(&'b mut T<'a>)` are different types and both
    /// came out as `for<'_> Fn(&mut T<'_>)`.
    fn lifetime(&mut self, lt: u64) {
        self.emit(b"'");
        if lt == 0 {
            self.emit(b"_");
            return;
        }
        match self.bound_depth.checked_sub(lt) {
            Some(d) => {
                let c = b'a' + crate::uint8(d % 26);
                self.putc(c);
                if d >= 26 {
                    self.emit_u64(d / 26);
                }
            }
            None => self.bad = true,
        }
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    /// `<len> <bytes>`, WITHOUT a disambiguator — that belongs to the
    /// production containing the identifier, and every caller here
    /// reads it explicitly. Bundling the two is what let the closure
    /// branch read one disambiguator and the ident read a second.
    ///
    /// A leading `u` marks a punycode identifier, which this refuses
    /// rather than mis-decoding — a non-ASCII name is rare and a wrong
    /// one is worse than none.
    fn ident(&mut self, emit: bool) {
        let puny = self.peek() == b'u';
        if puny {
            self.pos += 1;
        }
        let n = self.decimal();
        if self.bad {
            return;
        }
        // v0 allows an optional `_` between the length and the bytes,
        // used when the name would otherwise start with a digit.
        if self.peek() == b'_' {
            self.pos += 1;
        }
        if self.pos + n > self.sym.len() {
            self.bad = true;
            return;
        }
        if puny {
            self.bad = true;
            return;
        }
        let start = self.pos;
        self.pos += n;
        if emit {
            let mut i = 0usize;
            while i < n {
                let c = self.sym[start + i];
                self.putc(c);
                if self.bad {
                    return;
                }
                i += 1;
            }
        }
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    /// Follow a backreference: `B<base62>` names an absolute offset
    /// from `base`. Parsing continues there and then returns here.
    fn backref<F: FnOnce(&mut Self)>(&mut self, f: F) {
        let idx = self.base62();
        if self.bad {
            return;
        }
        let target = self.base + idx as usize;
        if target >= self.sym.len() || target >= self.pos {
            // A backref must point strictly backwards. Anything else
            // would let a crafted symbol loop forever.
            self.bad = true;
            return;
        }
        let save = self.pos;
        self.pos = target;
        f(self);
        self.pos = save;
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    /// `in_value` is rustc's own distinction and it is load-bearing for
    /// ONE thing: a generic list prints as `::<T>` on a value path and as
    /// `<T>` on a type path. Getting it wrong produced
    /// `Vec::<_, _>` where rustc prints `Vec<_, _>` — 24 symbols out of
    /// 19231, all of this shape.
    fn path(&mut self, in_value: bool) {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            self.bad = true;
            return;
        }
        let tag = self.next();
        if self.bad {
            self.depth -= 1;
            return;
        }
        match tag {
            // Crate root: `C <ident>`.
            b'C' => {
                self.disambiguator();
                self.ident(true);
            }
            // Nested path: `N <ns> <path> <ident>`.
            b'N' => {
                let ns = self.next();
                if self.bad {
                    self.depth -= 1;
                    return;
                }
                self.path(in_value);
                if self.bad {
                    self.depth -= 1;
                    return;
                }
                let dis = self.disambiguator();
                match ns {
                    // A closure or an anonymous const/static. rustc
                    // prints `{closure#N}`, or `{closure:name#N}` when
                    // the identifier is non-empty.
                    b'C' | b'S' => {
                        self.emit(b"::{");
                        if ns == b'C' {
                            self.emit(b"closure");
                        } else {
                            self.emit(b"shim");
                        }
                        let before = self.pos;
                        if self.peek() != b'0' {
                            self.emit(b":");
                            self.ident(true);
                        } else {
                            self.ident(false);
                        }
                        if self.pos == before {
                            self.bad = true;
                            self.depth -= 1;
                            return;
                        }
                        self.emit(b"#");
                        self.emit_u64(dis);
                        self.emit(b"}");
                    }
                    _ => {
                        self.emit(b"::");
                        self.ident(true);
                    }
                }
            }
            // Inherent impl: `M <impl-path> <type>` → `<Type>`.
            b'M' => {
                self.impl_path();
                self.emit(b"<");
                self.ty();
                self.emit(b">");
            }
            // Trait impl: `X <impl-path> <type> <trait-path>`.
            b'X' => {
                self.impl_path();
                self.emit(b"<");
                self.ty();
                self.emit(b" as ");
                self.path(false);
                self.emit(b">");
            }
            // Trait definition: `Y <type> <trait-path>`.
            b'Y' => {
                self.emit(b"<");
                self.ty();
                self.emit(b" as ");
                self.path(false);
                self.emit(b">");
            }
            // Generic specialization: `I <path> {generic-arg} E`.
            b'I' => {
                self.path(in_value);
                if self.bad {
                    self.depth -= 1;
                    return;
                }
                if in_value {
                    self.emit(b"::");
                }
                self.emit(b"<");
                let mut first = true;
                while self.peek() != b'E' && !self.bad {
                    if !first {
                        self.emit(b", ");
                    }
                    first = false;
                    self.generic_arg();
                }
                self.eat(b'E');
                self.emit(b">");
            }
            b'B' => {
                self.backref(|s| s.path(in_value));
            }
            _ => self.bad = true,
        }
        self.depth -= 1;
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    /// `impl-path` is a disambiguator plus a path whose NAME rustc does
    /// not print — the impl's defining module is implied by the type.
    fn impl_path(&mut self) {
        self.disambiguator();
        let save_olen = self.olen;
        self.path(false);
        // Discard whatever the module path emitted; rustc-demangle
        // prints only the type for an impl.
        self.olen = save_olen;
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    fn emit_u64(&mut self, mut v: u64) {
        let mut buf = [0u8; 20];
        let mut n = 0usize;
        if v == 0 {
            self.emit(b"0");
            return;
        }
        while v > 0 {
            buf[n] = b'0' + crate::uint8(v % 10);
            v /= 10;
            n += 1;
        }
        let mut i = n;
        while i > 0 {
            i -= 1;
            let c = buf[i];
            self.putc(c);
            if self.bad {
                return;
            }
        }
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    fn generic_arg(&mut self) {
        match self.peek() {
            // A lifetime. rustc-demangle prints nothing for the
            // erased ones that reach a symbol name.
            b'L' => {
                self.pos += 1;
                let lt = self.base62();
                self.lifetime(lt);
            }
            b'K' => {
                self.pos += 1;
                self.konst();
            }
            _ => self.ty(),
        }
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    /// Const generic arguments. Only the integer and bool forms are
    /// modelled; anything else bails.
    fn konst(&mut self) {
        let tag = self.next();
        if self.bad {
            return;
        }
        match tag {
            // Integers: a type letter then hex digits, `n` for
            // negative, terminated by `_`.
            b'a' | b'b' | b'c' | b'd' | b'e' | b'f' | b'h' | b'i' | b'j' | b'l' | b'm' | b'n'
            | b'o' | b's' | b't' | b'u' | b'v' | b'x' | b'y' | b'z' => {
                if self.peek() == b'n' {
                    self.pos += 1;
                    self.emit(b"-");
                }
                let mut v: u64 = 0;
                while self.peek() != b'_' && !self.bad {
                    let c = self.next();
                    let d = match c {
                        b'0'..=b'9' => crate::uint64(c - b'0'),
                        b'a'..=b'f' => crate::uint64(c - b'a') + 10,
                        _ => {
                            self.bad = true;
                            return;
                        }
                    };
                    v = v.wrapping_mul(16).wrapping_add(d);
                }
                self.eat(b'_');
                if tag == b'b' {
                    if v == 0 {
                        self.emit(b"false");
                    } else {
                        self.emit(b"true");
                    }
                } else {
                    self.emit_u64(v);
                }
            }
            b'B' => {
                self.pos -= 1;
                self.pos += 1;
                self.backref(|s| s.konst());
            }
            _ => self.bad = true,
        }
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    fn ty(&mut self) {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            self.bad = true;
            return;
        }
        let c = self.peek();
        let prim: Option<&[u8]> = match c {
            b'a' => Some(b"i8"),
            b'b' => Some(b"bool"),
            b'c' => Some(b"char"),
            b'd' => Some(b"f64"),
            b'e' => Some(b"str"),
            b'f' => Some(b"f32"),
            b'h' => Some(b"u8"),
            b'i' => Some(b"isize"),
            b'j' => Some(b"usize"),
            b'l' => Some(b"i32"),
            b'm' => Some(b"u32"),
            b'n' => Some(b"i128"),
            b'o' => Some(b"u128"),
            b's' => Some(b"i16"),
            b't' => Some(b"u16"),
            b'u' => Some(b"()"),
            b'v' => Some(b"..."),
            b'x' => Some(b"i64"),
            b'y' => Some(b"u64"),
            b'z' => Some(b"!"),
            b'p' => Some(b"_"),
            _ => None,
        };
        if let Some(p) = prim {
            self.pos += 1;
            self.emit(p);
            self.depth -= 1;
            return;
        }
        match c {
            b'A' => {
                self.pos += 1;
                self.emit(b"[");
                self.ty();
                self.emit(b"; ");
                self.konst();
                self.emit(b"]");
            }
            b'S' => {
                self.pos += 1;
                self.emit(b"[");
                self.ty();
                self.emit(b"]");
            }
            b'T' => {
                self.pos += 1;
                self.emit(b"(");
                let mut first = true;
                let mut n = 0usize;
                while self.peek() != b'E' && !self.bad {
                    if !first {
                        self.emit(b", ");
                    }
                    first = false;
                    self.ty();
                    n += 1;
                }
                self.eat(b'E');
                if n == 1 {
                    self.emit(b",");
                }
                self.emit(b")");
            }
            b'R' => {
                self.pos += 1;
                self.emit(b"&");
                self.ref_lifetime();
                self.ty();
            }
            b'Q' => {
                self.pos += 1;
                self.emit(b"&");
                self.ref_lifetime();
                self.emit(b"mut ");
                self.ty();
            }
            b'P' => {
                self.pos += 1;
                self.emit(b"*const ");
                self.ty();
            }
            b'O' => {
                self.pos += 1;
                self.emit(b"*mut ");
                self.ty();
            }
            b'B' => {
                self.pos += 1;
                self.backref(|s| s.ty());
            }
            b'F' => {
                self.pos += 1;
                self.fn_sig();
            }
            b'D' => {
                self.pos += 1;
                self.dyn_bounds();
            }
            _ => self.path(false),
        }
        self.depth -= 1;
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    /// `G <base62>` — a higher-ranked lifetime binder introducing
    /// `base62 + 1` lifetimes. The `+ 1` is the same convention the
    /// disambiguator uses, and getting it wrong printed `for<>`.
    ///
    /// Returns the count so the caller can pop the scope; a binder that
    /// stayed pushed would rename every later lifetime in the symbol.
    fn push_binder(&mut self) -> u64 {
        if self.peek() != b'G' {
            return 0;
        }
        self.pos += 1;
        let n = self.base62() + 1;
        if self.bad {
            return 0;
        }
        self.emit(b"for<");
        let mut i = 0u64;
        while i < n {
            if i > 0 {
                self.emit(b", ");
            }
            self.bound_depth += 1;
            self.lifetime(1);
            i += 1;
        }
        self.emit(b"> ");
        return n;
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    /// A reference's optional lifetime. Printed with a trailing space
    /// only when it is named, because `&'a T` has one and `&T` has
    /// none.
    fn ref_lifetime(&mut self) {
        if self.peek() != b'L' {
            return;
        }
        self.pos += 1;
        let lt = self.base62();
        if lt != 0 {
            self.lifetime(lt);
            self.emit(b" ");
        }
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    /// `F <binder>? U? (K <abi>)? {type} E <ret>`.
    ///
    /// Below `ty`, not above it, so `ty`'s own comment block stays put.
    fn fn_sig(&mut self) {
        let n = self.push_binder();
        if self.peek() == b'U' {
            self.pos += 1;
            self.emit(b"unsafe ");
        }
        if self.peek() == b'K' {
            self.pos += 1;
            self.emit(b"extern \"");
            if self.peek() == b'C' {
                self.pos += 1;
                self.emit(b"C");
            } else {
                // A named ABI is an ident whose `_` stand for `-`.
                let save = self.olen;
                self.ident(true);
                if !self.out.is_empty() {
                    let mut i = save;
                    while i < self.olen && i < self.out.len() {
                        if self.out[i] == b'_' {
                            self.out[i] = b'-';
                        }
                        i += 1;
                    }
                }
            }
            self.emit(b"\" ");
        }
        self.emit(b"fn(");
        let mut first = true;
        while self.peek() != b'E' && !self.bad {
            if !first {
                self.emit(b", ");
            }
            first = false;
            self.ty();
        }
        self.eat(b'E');
        self.emit(b")");
        // The return type is always present; `u` (unit) means rustc
        // prints nothing at all.
        if self.peek() == b'u' {
            self.pos += 1;
        } else {
            self.emit(b" -> ");
            self.ty();
        }
        self.bound_depth -= n;
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    /// `D <binder>? {dyn-trait} E <lifetime>`, where each dyn-trait is
    /// a path followed by zero or more `p <ident> <type>` associated
    /// bindings.
    ///
    /// Below `fn_sig` for the same reason.
    fn dyn_bounds(&mut self) {
        self.emit(b"dyn ");
        let nb = self.push_binder();
        let mut first = true;
        while self.peek() != b'E' && !self.bad {
            if !first {
                self.emit(b" + ");
            }
            first = false;
            // An associated binding JOINS the trait's own generic list
            // — rustc prints `Fn<(A,), Output = ()>`, one list, not
            // `Fn<(A,)><Output = ()>`. So the generic list has to be
            // left open across the bindings.
            let mut open = self.path_open_generics();
            while self.peek() == b'p' && !self.bad {
                self.pos += 1;
                if !open {
                    self.emit(b"<");
                    open = true;
                } else {
                    self.emit(b", ");
                }
                self.ident(true);
                self.emit(b" = ");
                self.ty();
            }
            if open {
                self.emit(b">");
            }
        }
        self.eat(b'E');
        // The trailing lifetime. rustc prints `+ 'a` only for a named
        // one; an erased lifetime (index 0) prints nothing.
        if self.peek() == b'L' {
            self.pos += 1;
            let lt = self.base62();
            if lt != 0 {
                self.emit(b" + ");
                self.lifetime(lt);
            }
        } else {
            self.bad = true;
        }
        self.bound_depth -= nb;
    }

    // go: none — goish-only: v0 demangling has no Go counterpart; see the module header.
    /// Print a path, and if it is a generic specialization leave its
    /// `<` open, returning true. `dyn_bounds` needs that so associated
    /// bindings land inside the same list.
    ///
    /// Below `dyn_bounds` because it exists only for it.
    fn path_open_generics(&mut self) -> bool {
        if self.peek() == b'B' {
            self.pos += 1;
            let idx = self.base62();
            if self.bad {
                return false;
            }
            let target = self.base + idx as usize;
            if target >= self.sym.len() || target >= self.pos {
                self.bad = true;
                return false;
            }
            let save = self.pos;
            self.pos = target;
            let open = self.path_open_generics();
            self.pos = save;
            return open;
        }
        if self.peek() != b'I' {
            self.path(false);
            return false;
        }
        self.pos += 1;
        self.path(false);
        if self.bad {
            return false;
        }
        self.emit(b"<");
        let mut first = true;
        while self.peek() != b'E' && !self.bad {
            if !first {
                self.emit(b", ");
            }
            first = false;
            self.generic_arg();
        }
        self.eat(b'E');
        return true;
    }
}

// go: none — goish-only: see the module header.
/// Demangle a v0 Rust symbol into `out`. Returns the number of bytes
/// written, or 0 if `sym` is not a v0 symbol or uses a construct this
/// parser does not model.
///
/// A 0 return is not an error to report; it means "print the raw
/// symbol", which is what `demangle.rs` already does for a legacy
/// symbol it cannot parse.
pub fn demangle_v0(sym: &[u8], out: &mut [u8]) -> usize {
    if sym.len() < 3 || sym[0] != b'_' || sym[1] != b'R' {
        return 0;
    }
    let mut pos = 2usize;
    // An optional `_` after `_R`, emitted when the symbol would
    // otherwise be ambiguous with a C identifier.
    if sym[pos] == b'_' {
        pos += 1;
    }
    let base = pos;
    let mut d = Demangler {
        sym: sym,
        base: base,
        pos: pos,
        out: out,
        olen: 0,
        depth: 0,
        bad: false,
        bound_depth: 0,
    };
    d.path(true);
    if d.bad {
        return 0;
    }
    // A trailing instantiating-crate path is allowed and not printed.
    // Anything else left over means the parse went wrong.
    if d.pos < d.sym.len() {
        let rest = d.pos;
        let mut probe = Demangler {
            sym: sym,
            base: base,
            pos: rest,
            out: &mut [],
            olen: 0,
            depth: 0,
            bad: false,
            bound_depth: 0,
        };
        probe.path(true);
        if probe.bad || probe.pos != sym.len() {
            return 0;
        }
    }
    return d.olen;
}
