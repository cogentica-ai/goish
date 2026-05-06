// goish-macros — proc-macros for goish v1.
//
// `#[goish::main]` decorates a user's `fn main()` to:
//
//   1. emit the ELF entry point `_start` (assembly stub) which reads
//      argc/argv off the stack and tail-calls into `__goish_rt0`.
//   2. wrap the user's body in `#[no_mangle] extern "C" fn __goish_main`,
//      the symbol the runtime's rt0 hands control to.
//
// `#[goish::reflect]` decorates a struct definition. It re-emits the
// struct verbatim and appends an `impl reflect::Reflect` whose
// `__reflect_type()` returns a static descriptor. Per-field
// `#[tag(r#"json:"name""#)]` attributes are captured verbatim into
// the descriptor's `StructField.Tag`, mirroring Go's backtick tags.
//
// No `syn`/`quote`/`proc-macro2` deps — we work with raw `proc_macro`
// tokens. The user's body is preserved as a `TokenTree::Group` (never
// stringified) so non-ASCII char literals like `'é'` round-trip cleanly.

extern crate proc_macro;

use proc_macro::{Delimiter, TokenStream, TokenTree};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

/// Per-process counter for unique symbol names emitted by `import!`.
/// Each invocation gets a fresh integer, used to disambiguate the
/// `__goish_import_<N>` function and `__GOISH_IMPORT_<N>` static slot
/// within a single crate's symbol table. Collisions across crates
/// are impossible — they each have their own object file.
static IMPORT_COUNTER: AtomicU64 = AtomicU64::new(0);

#[proc_macro_attribute]
pub fn main(_attr: TokenStream, item: TokenStream) -> TokenStream {
    // The body is the last token tree of `fn main(...) [-> T] { ... }` —
    // a brace-delimited Group. Pull it off; the rest (signature) we
    // discard and rewrite to `pub extern "C" fn __goish_main()`.
    let mut tokens: Vec<TokenTree> = item.into_iter().collect();
    let body = match tokens.pop() {
        Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace => g,
        _ => panic!("#[goish::main] must be placed on `fn main() {{ ... }}`"),
    };

    // 1) ELF entry point — assembly stub. Reads argc/argv off the
    //    kernel-supplied stack, aligns rsp to 16 bytes, calls __goish_rt0.
    //    `ud2` is dead code (rt0 is `-> !`); just makes any accidental
    //    return crash loudly.
    let asm: TokenStream = r#"
        ::core::arch::global_asm!(
            ".global _start",
            "_start:",
            "    mov rdi, [rsp]",
            "    lea rsi, [rsp + 8]",
            "    xor rbp, rbp",
            "    and rsp, -16",
            "    call __goish_rt0",
            "    ud2",
        );
    "#
    .parse()
    .expect("goish::main: invalid asm preamble");

    // 2) `#[no_mangle] pub extern "C" fn __goish_main()` — the user's
    //    body, exposed under a stable symbol so __goish_rt0 can call it.
    //    The signature is built as raw text; the body is appended as the
    //    original TokenTree::Group so all literals (including non-ASCII)
    //    are preserved verbatim.
    //
    //    Go's `runtime.main` calls `doInit(runtime_inittasks)` and
    //    walks per-module init lists BEFORE the user `main` body
    //    (proc.go:202, :255-7). We do the equivalent by prepending
    //    `::goish::init()` — the state machine inside makes the call
    //    idempotent so any port whose own `init()` already invokes it
    //    pays nothing on the second pass.
    //
    //    Port-specific init still needs an explicit call at the top
    //    of the user's main body — Cargo dependency graphs aren't
    //    available at proc-macro expansion time, and the goish runtime
    //    has no linker-driven `firstmoduledata` walk equivalent.
    let prefix: TokenStream = r#"
        #[no_mangle]
        pub extern "C" fn __goish_main()
    "#
    .parse()
    .expect("goish::main: invalid fn prefix");

    // Splice the init prelude as the first statements of the user
    // body. Order:
    //
    //   1. `::goish::init()` — bootstrap goish-stdlib state
    //      (crypto registry etc.). Idempotent via PkgInit.
    //
    //   2. `::goish::__run_pkg_inits()` — walk the `.init_array`
    //      section so each `goish::import! { … }` block's port
    //      `init()` runs. Mirrors Go's per-package init walk before
    //      `main` (proc.go:202, :255-7).
    //
    // We rebuild the brace group rather than doing string surgery so
    // any non-ASCII tokens inside body stay untouched.
    let init_call: TokenStream = r#"
        { ::goish::init(); ::goish::__run_pkg_inits(); }
    "#
    .parse()
    .expect("goish::main: invalid init prelude");

    let body_with_init = {
        let mut inner = init_call.into_iter().collect::<Vec<_>>();
        // The single brace group emitted by `{ ::goish::init(); }`.
        let prelude_stream = match inner.pop().expect("init prelude empty") {
            TokenTree::Group(g) if g.delimiter() == Delimiter::Brace => g.stream(),
            _ => panic!("goish::main: init prelude not a brace group"),
        };
        let mut combined = prelude_stream;
        combined.extend(body.stream());
        proc_macro::Group::new(Delimiter::Brace, combined)
    };

    let body_stream: TokenStream = TokenTree::Group(body_with_init).into();

    let mut out = asm;
    out.extend(prefix);
    out.extend(body_stream);
    out
}

// ─── #[goish::init] — package-level init wrapper ─────────────────────
//
// Decorates a port's `fn init() { … }` to wrap the body in the
// `PkgInit::run_once` state machine. Mirrors Go's per-package init
// task — see `goish::runtime::pkginit`.
//
// User writes:
//
//   #[goish::init]
//   fn init() {
//       goish::init();           // bootstrap deps
//       RegisterAlgorithm(…);    // package-level state setup
//   }
//
// Expands to:
//
//   pub fn init() {
//       static __PKG_INIT: ::goish::runtime::pkginit::PkgInit =
//           ::goish::runtime::pkginit::PkgInit::new(env!("CARGO_PKG_NAME"));
//       __PKG_INIT.run_once(|| { /* original body, verbatim */ });
//   }
//
// `env!("CARGO_PKG_NAME")` is a `&'static str` literal at compile
// time, which `PkgInit::new` (a `const fn`) accepts as a static
// initializer. The static slot is private to the function — Rust's
// fn-local-static feature gives it the lifetime of the binary while
// keeping the name out of the public API surface.
//
// Token-level body splicing (rather than stringification) preserves
// non-ASCII char literals and any other source detail, exactly like
// `#[goish::main]` already does.
#[proc_macro_attribute]
pub fn init(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut tokens: Vec<TokenTree> = item.into_iter().collect();
    let body = match tokens.pop() {
        Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace => g,
        _ => panic!("#[goish::init] must be placed on `fn init() {{ ... }}`"),
    };

    // Discard the original signature tokens — we rebuild the prefix.
    // We don't validate the discarded tokens: the proc-macro is
    // documented as "place on `fn init() { … }`", and a malformed
    // signature surfaces as a clear error from rustc on the rebuilt
    // form.

    // `.parse()` rejects unbalanced fragments — every level of
    // delimiter must be opened and closed within the same string.
    // Build the output bottom-up: closure body → closure expr →
    // call's parenthesised arg → fn body braces → outer signature.

    // Closure literal: `|| { user_body }`. The two pipes are
    // separate Punct tokens; `body` is the user's brace Group.
    use proc_macro::{Group, Punct, Spacing};
    let mut closure_inner: TokenStream = TokenStream::new();
    closure_inner.extend(core::iter::once(TokenTree::Punct(Punct::new('|', Spacing::Joint))));
    closure_inner.extend(core::iter::once(TokenTree::Punct(Punct::new('|', Spacing::Alone))));
    closure_inner.extend(core::iter::once(TokenTree::Group(body)));

    // Wrap closure in `( … )` for the run_once call argument.
    let arg_paren: TokenTree =
        TokenTree::Group(Group::new(Delimiter::Parenthesis, closure_inner));

    // Inner fn body prelude. Balanced — declares the static, then
    // names the run_once method (we append the parenthesised arg
    // and a trailing semicolon next).
    let inner_prefix: TokenStream = r#"
        static __PKG_INIT: ::goish::runtime::pkginit::PkgInit =
            ::goish::runtime::pkginit::PkgInit::new(env!("CARGO_PKG_NAME"));
        __PKG_INIT.run_once
    "#
    .parse()
    .expect("goish::init: invalid inner prelude");

    let semi: TokenStream = ";".parse().expect("goish::init: missing semi");

    let mut inner: TokenStream = inner_prefix;
    inner.extend(core::iter::once(arg_paren));
    inner.extend(semi);

    // Outer signature, then fn body Group(Brace, inner).
    let outer_sig: TokenStream = "pub fn init()"
        .parse()
        .expect("goish::init: invalid outer signature");

    let fn_body = TokenTree::Group(Group::new(Delimiter::Brace, inner));

    let mut out = outer_sig;
    out.extend(core::iter::once(fn_body));
    out
}

// ─── goish::var! sentinel-marker emission ────────────────────────────
//
// Internal helper invoked from the `goish::var!` macro_rules! muncher.
// Receives a parsed-down decl in one of two shapes:
//
//   var_emit_error_marker!( vis NAME "literal" )    — string-message arm
//   var_emit_error_marker!( vis NAME { expr } )     — typed-payload arm
//
// Emits the full per-sentinel expansion: ZST marker + const + lazy slot
// + IsTarget/From/PartialEq impls. Identity-stable across all access
// paths (.into(), errors::Is, ==).
//
// Token-level proc-macro (no syn/quote) — matches the rest of this
// crate's posture. macro_rules! drives the per-decl dispatch; this
// only does the ident-concatenation Rust macro_rules! can't do.

#[proc_macro]
pub fn var_emit_error_marker(input: TokenStream) -> TokenStream {
    // macro_rules! `$vis:vis` and `$expr` matchers wrap their captures in an
    // "invisible" `Group` (Delimiter::None). Flatten any such groups at the
    // top level before walking the token stream.
    let flat: Vec<TokenTree> = input
        .into_iter()
        .flat_map(|tt| match tt {
            TokenTree::Group(g) if g.delimiter() == Delimiter::None => {
                g.stream().into_iter().collect::<Vec<_>>()
            }
            other => vec![other],
        })
        .collect();

    let mut iter = flat.into_iter().peekable();

    // Parse optional visibility tokens (pub, pub(crate), pub(super), etc.)
    // until we hit the name ident.
    let mut vis = String::new();
    let name: String;
    loop {
        match iter.peek() {
            Some(TokenTree::Ident(id)) if id.to_string() == "pub" => {
                vis.push_str(&id.to_string());
                vis.push(' ');
                iter.next();
                // Optional `(crate)`, `(super)`, `(in path)` group
                if let Some(TokenTree::Group(g)) = iter.peek() {
                    if g.delimiter() == Delimiter::Parenthesis {
                        vis.push('(');
                        vis.push_str(&g.stream().to_string());
                        vis.push_str(") ");
                        iter.next();
                    }
                }
            }
            Some(TokenTree::Ident(id)) => {
                name = id.to_string();
                iter.next();
                break;
            }
            other => panic!("var_emit_error_marker: expected vis or name, got {:?}", other),
        }
    }

    // Parse the payload — either a string literal or a brace group.
    let payload = iter
        .next()
        .expect("var_emit_error_marker: missing payload after name");

    let init_expr = match &payload {
        TokenTree::Literal(lit) => {
            // String literal — wrap with errors::New
            format!("::goish::errors::New({})", lit)
        }
        TokenTree::Group(g) if g.delimiter() == Delimiter::Brace => {
            // Typed-payload — wrap with errors::Wrap
            format!("::goish::errors::Wrap({{ {} }})", g.stream())
        }
        other => panic!("var_emit_error_marker: payload must be \"literal\" or {{ expr }}, got {:?}", other),
    };

    let marker = format!("__{}Marker", name);
    let slot = format!("__{}_SLOT", name);
    let resolve = format!("__{}_resolve", name);

    let src = format!(
        r#"
        #[doc(hidden)]
        #[derive(::core::marker::Copy, ::core::clone::Clone)]
        {vis}struct {marker};

        #[allow(non_upper_case_globals)]
        {vis}const {name}: {marker} = {marker};

        #[doc(hidden)]
        #[allow(non_upper_case_globals)]
        static {slot}: ::goish::runtime::spin::SpinLock<
            ::core::option::Option<::goish::error>,
        > = ::goish::runtime::spin::SpinLock::new(::core::option::Option::None);

        #[doc(hidden)]
        #[allow(non_snake_case)]
        fn {resolve}() -> ::goish::error {{
            let mut g = {slot}.lock();
            if g.is_none() {{
                *g = ::core::option::Option::Some({init_expr});
            }}
            g.as_ref().unwrap().clone()
        }}

        impl ::goish::errors::IsTarget for {marker} {{
            #[inline]
            fn __resolve(&self) -> ::goish::error {{ {resolve}() }}
        }}

        impl ::core::convert::From<{marker}> for ::goish::error {{
            #[inline]
            fn from(_: {marker}) -> Self {{ {resolve}() }}
        }}

        impl ::core::cmp::PartialEq<{marker}> for ::goish::error {{
            #[inline]
            fn eq(&self, _: &{marker}) -> bool {{
                self.__ptr_eq(&{resolve}())
            }}
        }}

        impl ::core::cmp::PartialEq<::goish::error> for {marker} {{
            #[inline]
            fn eq(&self, e: &::goish::error) -> bool {{ e == self }}
        }}
        "#,
    );

    src.parse().expect("var_emit_error_marker: emitted source failed to parse")
}

// ─── #[goish::reflect] ───────────────────────────────────────────────

/// `#[goish::reflect]` — emit `impl reflect::Reflect` for a struct.
///
/// Captures `#[tag(r#"json:..."#)]` field attributes and bakes the tag
/// strings into the descriptor. The struct itself is re-emitted verbatim
/// (minus the `#[tag(...)]` attributes, which the Rust compiler doesn't
/// recognize on plain fields).
#[proc_macro_attribute]
pub fn reflect(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let parsed = parse_struct(item);

    // Re-emit the struct without the #[tag(...)] attributes (those are
    // private to the goish reflect macro; rustc doesn't know them).
    let mut struct_text = String::new();
    if let Some(vis) = &parsed.vis {
        struct_text.push_str(vis);
        struct_text.push(' ');
    }
    struct_text.push_str("struct ");
    struct_text.push_str(&parsed.name);
    struct_text.push_str(" {\n");
    for f in &parsed.fields {
        if let Some(vis) = &f.vis {
            struct_text.push_str(vis);
            struct_text.push(' ');
        }
        struct_text.push_str(&f.name);
        struct_text.push_str(": ");
        struct_text.push_str(&f.ty);
        struct_text.push_str(",\n");
    }
    struct_text.push_str("}\n");

    // Build the static field array + impl Reflect.
    let mut impl_text = String::new();
    let _ = write!(impl_text, "impl ::goish::reflect::Reflect for {} {{\n", parsed.name);
    impl_text.push_str("    fn __reflect_type() -> ::goish::reflect::Type {\n");
    impl_text.push_str(
        "        static FIELDS: &[::goish::reflect::StructField] = &[\n",
    );
    for f in &parsed.fields {
        // `tag` is the verbatim literal text from the user's source —
        // already a `"..."` or `r#"..."#` string literal — or `""` if
        // the field has no #[tag(...)].
        let tag = f.tag.clone().unwrap_or_else(|| "\"\"".to_string());
        let _ = write!(
            impl_text,
            "            ::goish::reflect::StructField {{\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20Name: \"{}\",\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20Tag: ::goish::reflect::StructTag::__new({}),\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20Type: <{} as ::goish::reflect::Reflect>::__reflect_type,\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20PkgPath: \"\",\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20Anonymous: false,\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20}},\n",
            f.name, tag, f.ty
        );
    }
    impl_text.push_str("        ];\n");
    let _ = write!(
        impl_text,
        "        ::goish::reflect::Type::__new(::goish::reflect::Kind::Struct, \"{}\", FIELDS)\n",
        parsed.name
    );
    impl_text.push_str("    }\n");
    // (close __reflect_type body — __reflect_value continues below)

    // __reflect_value: deep-clone each field into a Value, package as
    // Value::Struct.
    impl_text.push_str(
        "    fn __reflect_value(&self) -> ::goish::reflect::Value {\n",
    );
    impl_text.push_str(
        "        let mut __fields: ::goish::__macro_alloc::Vec<::goish::reflect::Value> = ::goish::__macro_alloc::Vec::new();\n",
    );
    for f in &parsed.fields {
        let _ = write!(
            impl_text,
            "        __fields.push(<{} as ::goish::reflect::Reflect>::__reflect_value(&self.{}));\n",
            f.ty, f.name
        );
    }
    impl_text.push_str(
        "        ::goish::reflect::Value::Struct {\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20ty: <Self as ::goish::reflect::Reflect>::__reflect_type(),\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20fields: __fields,\n\
         \x20\x20\x20\x20\x20\x20\x20\x20}\n",
    );
    impl_text.push_str("    }\n");
    impl_text.push_str("}\n");

    // ── impl Default for the struct ────────────────────────────────
    // Auto-Default mirrors Go's "structs are zero-initializable by
    // default". Every field type must already impl Default (built-in
    // primitives do, slice<T> does, and any nested #[goish::reflect]
    // struct gets one of these from its own attribute). With this in
    // place, FromValue / FromReflectValue / Settable can all rely on
    // `<Self as Default>::default()` for the zero state.
    impl_text.push_str("impl ::core::default::Default for ");
    impl_text.push_str(&parsed.name);
    impl_text.push_str(" {\n");
    impl_text.push_str("    fn default() -> Self {\n");
    impl_text.push_str("        Self {\n");
    for f in &parsed.fields {
        let _ = write!(
            impl_text,
            "            {}: <{} as ::core::default::Default>::default(),\n",
            f.name, f.ty
        );
    }
    impl_text.push_str("        }\n");
    impl_text.push_str("    }\n");
    impl_text.push_str("}\n");

    // ── impl Clone for the struct ──────────────────────────────────
    // Go-faithful: every struct is field-wise copyable. Lets reflect
    // structs flow through `slice<T>`, `map<K,V>`, `Vec<T>` and other
    // containers without the user writing #[derive(Clone)].
    impl_text.push_str("impl ::core::clone::Clone for ");
    impl_text.push_str(&parsed.name);
    impl_text.push_str(" {\n");
    impl_text.push_str("    fn clone(&self) -> Self {\n");
    impl_text.push_str("        Self {\n");
    for f in &parsed.fields {
        let _ = write!(
            impl_text,
            "            {}: <{} as ::core::clone::Clone>::clone(&self.{}),\n",
            f.name, f.ty, f.name
        );
    }
    impl_text.push_str("        }\n");
    impl_text.push_str("    }\n");
    impl_text.push_str("}\n");

    // ── impl json::FromValue for the struct ────────────────────────
    // Walks the parsed json::Value::Object, maps each json key (from
    // Tag.Get("json") or the field name) to the matching field via
    // recursive FromValue dispatch. Missing fields stay at their
    // per-field zero (each field type must impl ::core::default::Default).
    impl_text.push_str("impl ::goish::encoding::json::FromValue for ");
    impl_text.push_str(&parsed.name);
    impl_text.push_str(" {\n");
    impl_text.push_str("    fn from_value(__v: &::goish::encoding::json::Value) -> (Self, ::goish::error) {\n");
    // Helper closure: build a fresh "zero" Self via per-field defaults.
    impl_text.push_str("        let __zero = || -> Self { Self {\n");
    for f in &parsed.fields {
        let _ = write!(
            impl_text,
            "            {}: <{} as ::core::default::Default>::default(),\n",
            f.name, f.ty
        );
    }
    impl_text.push_str("        } };\n");
    impl_text.push_str("        let __obj = match __v {\n");
    impl_text.push_str("            ::goish::encoding::json::Value::Object(o) => o,\n");
    impl_text.push_str("            ::goish::encoding::json::Value::Null => return (__zero(), ::goish::errors::nil),\n");
    impl_text.push_str("            _ => return (__zero(), ::goish::errors::New(\"json: cannot unmarshal into struct\")),\n");
    impl_text.push_str("        };\n");
    impl_text.push_str("        let mut __out = __zero();\n");
    impl_text.push_str("        let __ty = <Self as ::goish::reflect::Reflect>::__reflect_type();\n");
    for (i, f) in parsed.fields.iter().enumerate() {
        impl_text.push_str("        {\n");
        let _ = write!(
            impl_text,
            "            let __field = __ty.Field({} as ::goish::int);\n",
            i
        );
        impl_text.push_str("            let __raw_tag = __field.Tag.Get(\"json\");\n");
        impl_text.push_str("            let (__key_seg, __skip) = ::goish::encoding::json::__parse_json_tag(&__raw_tag);\n");
        impl_text.push_str("            if !__skip {\n");
        impl_text.push_str("                let __key_str: ::goish::string = if __key_seg.Len() == 0 {\n");
        impl_text.push_str("                    ::goish::string::from_static(__field.Name)\n");
        impl_text.push_str("                } else {\n");
        impl_text.push_str("                    __key_seg\n");
        impl_text.push_str("                };\n");
        impl_text.push_str("                let (__sub, __present) = __obj.Get(__key_str);\n");
        impl_text.push_str("                if __present {\n");
        let _ = write!(
            impl_text,
            "                    let (__val, __err) = <{} as ::goish::encoding::json::FromValue>::from_value(&__sub);\n",
            f.ty
        );
        impl_text.push_str("                    if __err != ::goish::errors::nil { return (__out, __err); }\n");
        let _ = write!(impl_text, "                    __out.{} = __val;\n", f.name);
        impl_text.push_str("                }\n");
        impl_text.push_str("            }\n");
        impl_text.push_str("        }\n");
    }
    impl_text.push_str("        (__out, ::goish::errors::nil)\n");
    impl_text.push_str("    }\n");
    impl_text.push_str("}\n");

    // ── impl fmt::Format for the struct ────────────────────────────
    // %v / %+v / %s on this type walks reflect.Value and emits Go-
    // faithful default formatting. Conflicts with a manual impl
    // Stringer for the same type — pick one.
    impl_text.push_str("impl ::goish::fmt::Format for ");
    impl_text.push_str(&parsed.name);
    impl_text.push_str(" {\n");
    impl_text.push_str(
        "    fn fmt(&self, __verb: ::goish::byte, __f: &mut ::goish::fmt::FmtBuf) {\n",
    );
    impl_text.push_str("        ::goish::fmt::reflect_fmt_to(self, __verb, __f);\n");
    impl_text.push_str("    }\n");
    impl_text.push_str("}\n");
    // Borrow form so callers can pass `&p` directly to Printf! without
    // moving — non-Copy structs need this. A blanket `impl Format for &T`
    // would conflict with the Stringer blanket, hence per-type emission.
    impl_text.push_str("impl ::goish::fmt::Format for &");
    impl_text.push_str(&parsed.name);
    impl_text.push_str(" {\n");
    impl_text.push_str(
        "    fn fmt(&self, __verb: ::goish::byte, __f: &mut ::goish::fmt::FmtBuf) {\n",
    );
    impl_text.push_str("        ::goish::fmt::reflect_fmt_to(*self, __verb, __f);\n");
    impl_text.push_str("    }\n");
    impl_text.push_str("}\n");

    // ── impl reflect::FromReflectValue for the struct ─────────────
    // Lets this struct be used as a field type within another reflect
    // struct (nested structs, SetField with a struct payload, etc.).
    // Walks Value::Struct positionally, dispatching FromReflectValue
    // per field.
    impl_text.push_str("impl ::goish::reflect::FromReflectValue for ");
    impl_text.push_str(&parsed.name);
    impl_text.push_str(" {\n");
    impl_text.push_str(
        "    fn from_reflect_value(__v: ::goish::reflect::Value) -> (Self, ::goish::error) {\n",
    );
    // Helper: zero-Self via per-field defaults.
    impl_text.push_str("        let __zero = || -> Self { Self {\n");
    for f in &parsed.fields {
        let _ = write!(
            impl_text,
            "            {}: <{} as ::core::default::Default>::default(),\n",
            f.name, f.ty
        );
    }
    impl_text.push_str("        } };\n");
    impl_text.push_str("        let __fields = match __v {\n");
    impl_text.push_str("            ::goish::reflect::Value::Struct { fields, .. } => fields,\n");
    impl_text.push_str("            _ => return (__zero(), ::goish::errors::New(\"reflect: expected struct\")),\n");
    impl_text.push_str("        };\n");
    let _ = write!(
        impl_text,
        "        if __fields.len() != {} {{\n            return (__zero(), ::goish::errors::New(\"reflect: field count mismatch\"));\n        }}\n",
        parsed.fields.len()
    );
    impl_text.push_str("        let mut __out = __zero();\n");
    for (i, f) in parsed.fields.iter().enumerate() {
        let _ = write!(
            impl_text,
            "        {{\n            let (__val, __err) = <{} as ::goish::reflect::FromReflectValue>::from_reflect_value(__fields[{}].clone());\n            if __err != ::goish::errors::nil {{ return (__zero(), __err); }}\n            __out.{} = __val;\n        }}\n",
            f.ty, i, f.name
        );
    }
    impl_text.push_str("        (__out, ::goish::errors::nil)\n");
    impl_text.push_str("    }\n");
    impl_text.push_str("}\n");

    // ── impl reflect::Settable for the struct ──────────────────────
    // Dispatches index → field write via FromReflectValue. Composite
    // field types must impl FromReflectValue (built-in primitives do;
    // user nested structs now do too via the impl above).
    impl_text.push_str("impl ::goish::reflect::Settable for ");
    impl_text.push_str(&parsed.name);
    impl_text.push_str(" {\n");
    impl_text.push_str(
        "    fn __reflect_set_field(&mut self, __idx: ::goish::int, __v: ::goish::reflect::Value) -> ::goish::error {\n",
    );
    impl_text.push_str("        match __idx {\n");
    for (i, f) in parsed.fields.iter().enumerate() {
        let _ = write!(impl_text, "            {} => {{\n", i);
        let _ = write!(
            impl_text,
            "                let (__val, __err) = <{} as ::goish::reflect::FromReflectValue>::from_reflect_value(__v);\n",
            f.ty
        );
        impl_text.push_str("                if __err != ::goish::errors::nil { return __err; }\n");
        let _ = write!(impl_text, "                self.{} = __val;\n", f.name);
        impl_text.push_str("                ::goish::errors::nil\n");
        impl_text.push_str("            }\n");
    }
    impl_text.push_str("            _ => ::goish::errors::New(\"reflect.SetField: index out of range\"),\n");
    impl_text.push_str("        }\n");
    impl_text.push_str("    }\n");
    impl_text.push_str("}\n");

    let mut out: TokenStream = struct_text
        .parse()
        .expect("goish::reflect: failed to re-emit struct");
    let impl_ts: TokenStream = impl_text
        .parse()
        .expect("goish::reflect: failed to emit impl");
    out.extend(impl_ts);
    out
}

// ─── manual struct parser ────────────────────────────────────────────

struct Parsed {
    vis: Option<String>,
    name: String,
    fields: Vec<ParsedField>,
}

struct ParsedField {
    vis: Option<String>,
    name: String,
    ty: String,
    /// `r#"json:"name""#` literal text, exactly as written by the user.
    /// `None` = no `#[tag(...)]` attribute on this field.
    tag: Option<String>,
}

fn parse_struct(item: TokenStream) -> Parsed {
    let mut iter = item.into_iter().peekable();

    // Skip outer attributes (e.g. doc comments) — `# [ ... ]`.
    loop {
        match iter.peek() {
            Some(TokenTree::Punct(p)) if p.as_char() == '#' => {
                iter.next();
                iter.next(); // bracket group
            }
            _ => break,
        }
    }

    // Optional visibility: `pub`, `pub(crate)`, `pub(super)`, `pub(in path)`.
    let vis = consume_visibility(&mut iter);

    // `struct`
    match iter.next() {
        Some(TokenTree::Ident(i)) if i.to_string() == "struct" => {}
        other => panic!(
            "#[goish::reflect] expects `struct Name {{ ... }}`, got token {:?}",
            other
        ),
    }

    // struct name
    let name = match iter.next() {
        Some(TokenTree::Ident(i)) => i.to_string(),
        _ => panic!("#[goish::reflect]: expected struct name"),
    };

    // body
    let body = match iter.next() {
        Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace => g,
        _ => panic!("#[goish::reflect]: expected struct body `{{ ... }}`"),
    };

    let fields = parse_fields(body.stream());
    Parsed { vis, name, fields }
}

fn consume_visibility<I>(iter: &mut std::iter::Peekable<I>) -> Option<String>
where
    I: Iterator<Item = TokenTree>,
{
    if let Some(TokenTree::Ident(i)) = iter.peek() {
        if i.to_string() == "pub" {
            let mut s = String::from("pub");
            iter.next();
            // optional `(crate)` / `(super)` / `(in path)`
            if let Some(TokenTree::Group(g)) = iter.peek() {
                if g.delimiter() == Delimiter::Parenthesis {
                    s.push('(');
                    s.push_str(&g.stream().to_string());
                    s.push(')');
                    iter.next();
                }
            }
            return Some(s);
        }
    }
    None
}

fn parse_fields(body: TokenStream) -> Vec<ParsedField> {
    let mut fields = Vec::new();
    let mut iter = body.into_iter().peekable();

    loop {
        if iter.peek().is_none() {
            break;
        }

        // Pending attributes — capture #[tag(...)], skip everything else
        // (e.g. doc comments).
        let mut tag: Option<String> = None;
        loop {
            match iter.peek() {
                Some(TokenTree::Punct(p)) if p.as_char() == '#' => {
                    iter.next();
                    let g = match iter.next() {
                        Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Bracket => g,
                        _ => panic!("#[goish::reflect]: malformed field attribute"),
                    };
                    let mut ai = g.stream().into_iter();
                    if let Some(TokenTree::Ident(name)) = ai.next() {
                        if name.to_string() == "tag" {
                            // `tag(<literal>)`
                            if let Some(TokenTree::Group(inner)) = ai.next() {
                                if inner.delimiter() == Delimiter::Parenthesis {
                                    if let Some(TokenTree::Literal(lit)) =
                                        inner.stream().into_iter().next()
                                    {
                                        tag = Some(lit.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
                _ => break,
            }
        }

        // Visibility
        let vis = consume_visibility(&mut iter);

        // Field name
        let name = match iter.next() {
            Some(TokenTree::Ident(i)) => i.to_string(),
            None => break,
            other => panic!("#[goish::reflect]: expected field name, got {:?}", other),
        };

        // Colon
        match iter.next() {
            Some(TokenTree::Punct(p)) if p.as_char() == ':' => {}
            other => panic!(
                "#[goish::reflect]: expected ':' after field {}, got {:?}",
                name, other
            ),
        }

        // Type tokens up to comma at angle-depth 0.
        let mut depth: i32 = 0;
        let mut ty_tokens: Vec<TokenTree> = Vec::new();
        loop {
            match iter.peek() {
                Some(TokenTree::Punct(p)) if p.as_char() == ',' && depth == 0 => {
                    iter.next();
                    break;
                }
                Some(TokenTree::Punct(p)) if p.as_char() == '<' => {
                    depth += 1;
                    ty_tokens.push(iter.next().unwrap());
                }
                Some(TokenTree::Punct(p)) if p.as_char() == '>' => {
                    depth -= 1;
                    ty_tokens.push(iter.next().unwrap());
                }
                None => break,
                _ => ty_tokens.push(iter.next().unwrap()),
            }
        }

        let ts: TokenStream = ty_tokens.into_iter().collect();
        let ty = ts.to_string();

        fields.push(ParsedField { vis, name, ty, tag });
    }

    fields
}

// ─── goish::import! { … } — file-scope side-effect import ────────────
//
// Mirrors Go's `import _ "pkg/path"` — pull in a port, run its
// `init()` before main, and (unlike Go's blank import) also bring
// the path into scope so user code can reference it.
//
// User writes at file scope:
//
//   goish::import! {
//       opencontainers_go_digest as digest,
//       cenkalti_backoff_v5,
//   }
//
// The macro emits:
//
//   1. `use` lines so `digest::FromBytes(...)` resolves at call sites.
//
//   2. An `extern "C" fn __goish_import_<N>()` whose body calls
//      `<path>::init()` for each listed port (in declaration order).
//
//   3. A `#[used] #[link_section = ".init_array"]` static function
//      pointer to that fn. The linker concatenates `.init_array`
//      sections from every translation unit; goish's `__goish_main`
//      prelude walks the section before user code runs.
//
// Each invocation gets a unique `<N>` from a per-process counter, so
// multiple `import!` blocks across files don't collide. Different
// crates each have their own counter (per-process state in the proc-
// macro driver), but their object files have separate symbol tables
// regardless, so no inter-crate collision either.
//
// Path forms:
//
//   - `crate_name`               — `use crate_name; crate_name::init();`
//   - `crate_name as alias`      — `use crate_name as alias; crate_name::init();`
//   - `foo::bar`                 — `use foo::bar; foo::bar::init();`
//   - `foo::bar as baz`          — `use foo::bar as baz; foo::bar::init();`
//
// The init call always uses the original path, never the alias —
// which matches Go's `import _ "pkg/path"` (no alias, just side
// effect) combined with the named-import case `import alias "pkg"`.
#[proc_macro]
pub fn import(input: TokenStream) -> TokenStream {
    let entries = parse_imports(input);

    let n = IMPORT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let fn_name = format!("__goish_import_{}", n);
    let slot_name = format!("__GOISH_IMPORT_{}", n);

    let mut out = String::new();

    // Step 1: emit `use` lines.
    for e in &entries {
        if let Some(alias) = &e.alias {
            let _ = writeln!(out, "#[allow(unused_imports)] use {} as {};", e.path, alias);
        } else {
            let _ = writeln!(out, "#[allow(unused_imports)] use {};", e.path);
        }
    }

    // Step 2: the init dispatcher fn. extern "C" so the .init_array
    // entry's function-pointer type matches the C ABI used by libc
    // and by goish's rt0 walk.
    let _ = writeln!(out, "extern \"C\" fn {}() {{", fn_name);
    for e in &entries {
        let _ = writeln!(out, "    {}::init();", e.path);
    }
    let _ = writeln!(out, "}}");

    // Step 3: register the dispatcher in `.init_array`. The `#[used]`
    // attribute keeps the linker from stripping the static; the
    // `#[link_section = ".init_array"]` puts the fn pointer where
    // goish's __run_pkg_inits walk will find it.
    //
    // `#[allow(non_upper_case_globals)]` — the auto-generated name
    // is conventionally formatted, not user-visible.
    let _ = writeln!(out, "#[used]");
    let _ = writeln!(out, "#[allow(non_upper_case_globals)]");
    let _ = writeln!(out, "#[link_section = \".init_array\"]");
    let _ = writeln!(
        out,
        "static {}: extern \"C\" fn() = {};",
        slot_name, fn_name
    );

    out.parse().expect("goish::import: emitted source failed to parse")
}

// `(path, alias?)` — one entry per comma-separated item in the
// `import!` argument list.
struct ImportEntry {
    path: String,
    alias: Option<String>,
}

fn parse_imports(input: TokenStream) -> Vec<ImportEntry> {
    let tokens: Vec<TokenTree> = input.into_iter().collect();
    let mut iter = tokens.into_iter().peekable();
    let mut out = Vec::new();

    while iter.peek().is_some() {
        // Path: ident (:: ident)*. We greedy-consume idents and `::`
        // pairs until we hit `as`, `,`, or end.
        let mut path = String::new();
        let mut after_segment = false;
        loop {
            match iter.peek() {
                Some(TokenTree::Ident(id)) => {
                    let s = id.to_string();
                    if after_segment && s == "as" {
                        break;
                    }
                    path.push_str(&s);
                    iter.next();
                    after_segment = true;
                }
                Some(TokenTree::Punct(p)) if p.as_char() == ':' => {
                    // Expect `::` — two consecutive ':' Punct tokens.
                    iter.next();
                    match iter.peek() {
                        Some(TokenTree::Punct(p2)) if p2.as_char() == ':' => {
                            iter.next();
                            path.push_str("::");
                            after_segment = false;
                        }
                        other => panic!(
                            "goish::import: expected `::` after `:`, got {:?}",
                            other
                        ),
                    }
                }
                _ => break,
            }
        }

        if path.is_empty() {
            panic!("goish::import: expected an import path");
        }

        // Optional `as <alias>`.
        let alias = if let Some(TokenTree::Ident(id)) = iter.peek() {
            if id.to_string() == "as" {
                iter.next();
                match iter.next() {
                    Some(TokenTree::Ident(a)) => Some(a.to_string()),
                    other => panic!(
                        "goish::import: expected alias ident after `as`, got {:?}",
                        other
                    ),
                }
            } else {
                None
            }
        } else {
            None
        };

        out.push(ImportEntry { path, alias });

        // Optional comma between entries; trailing comma allowed.
        match iter.peek() {
            Some(TokenTree::Punct(p)) if p.as_char() == ',' => {
                iter.next();
            }
            None => {}
            other => panic!("goish::import: expected `,` or end, got {:?}", other),
        }
    }

    out
}

// ─── #[goish::interface] — Go-faithful interface declaration ─────────
//
// Decorate a trait declaration to give it Go-interface semantics:
//
//   1. `: Send + Sync` supertraits — every Goish iface value flows
//      across goroutines.
//   2. Hidden default-method `__is_nil_iface(&self) -> bool` returning
//      `false`. Concrete impls inherit the default unchanged.
//   3. A `__NilT` ZST whose every method panics with a clear
//      "method call on nil T interface" message and whose
//      `__is_nil_iface` returns `true`.
//   4. `Default for Arc<dyn T + Send + Sync>` returning the sentinel —
//      gives Go's `var x T` zero-value semantics. Cascades into
//      `..Default::default()` working on structs that have an
//      interface-typed field.
//   5. `PartialEq<goish::Nil>` (both directions) on
//      `Arc<dyn T + Send + Sync>` — implements Go's `if r == nil`
//      check by dispatching through `__is_nil_iface`.
//
// User pattern:
//
//   #[goish::interface]
//   pub trait Reader {
//       fn Read(&self, p: slice<byte>) -> (int, error);
//   }
//
//   impl Reader for MyFile {
//       fn Read(&self, p: slice<byte>) -> (int, error) { … }
//   }
//
//   pub struct Conn {
//       pub reader: alloc::sync::Arc<dyn Reader + Send + Sync>,
//       // #[derive(Default)] now compiles — was broken without the
//       // attribute because dyn Reader had no Default.
//   }
//
// Token-level parser (no syn/quote, matching the rest of this crate's
// posture). Method signatures are reproduced verbatim from the trait
// declaration into the sentinel impl, with each `;` swapped for
// `{ panic!(…) }`.
//
// Limitations:
//   * Trait must NOT have generics on the trait itself (Go interfaces
//     don't either; emit error if encountered).
//   * Methods must be `;`-terminated signatures, no default bodies
//     (also matches Go interface declarations exactly).
//   * Each method's signature is captured as raw token text and
//     re-emitted; complex generic / where-clause shapes round-trip
//     through `TokenStream::to_string()`.
#[proc_macro_attribute]
pub fn interface(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let parsed = parse_iface(item);
    let name = &parsed.name;
    let nil_name = format!("__Nil{}", name);
    let ref_name = format!("{}Ref", name);
    let vis = parsed.vis.as_deref().unwrap_or("");

    let mut out = String::new();

    // ── (1) Trait redeclaration with supertraits + hidden helper ───
    //
    // `__is_nil_iface` is a default method on the trait itself (NOT a
    // separate supertrait) so concrete impls inherit `false` for free
    // and the nil sentinel overrides to `true`.
    let _ = writeln!(
        out,
        "{vis} trait {name}: ::core::marker::Send + ::core::marker::Sync {{"
    );
    for m in &parsed.methods {
        let _ = writeln!(out, "    {}", m.sig_text);
    }
    out.push_str("    #[doc(hidden)]\n");
    out.push_str("    fn __is_nil_iface(&self) -> bool { false }\n");
    out.push_str("}\n\n");

    // ── (2) Nil sentinel struct ─────────────────────────────────────
    out.push_str("#[doc(hidden)]\n");
    out.push_str("#[allow(non_camel_case_types)]\n");
    let _ = writeln!(out, "pub struct {nil_name};");
    out.push('\n');

    // ── (3) impl Trait for __NilT — every method panics ────────────
    let _ = writeln!(out, "impl {name} for {nil_name} {{");
    for m in &parsed.methods {
        // Strip the trailing `;` and append `{ panic!(...) }`.
        let body_part = m.sig_text.trim_end();
        let stripped = body_part.strip_suffix(';').unwrap_or(body_part);
        let _ = writeln!(
            out,
            "    {} {{ panic!(\"goish: method call on nil {} interface\") }}",
            stripped, name
        );
    }
    out.push_str("    fn __is_nil_iface(&self) -> bool { true }\n");
    out.push_str("}\n\n");

    // ── (4) The canonical iface-value newtype `<Trait>Ref` ──────────
    //
    // `Arc<dyn Trait>` would be the natural representation, but Rust's
    // orphan rule rejects `impl Default for Arc<dyn LocalTrait>` —
    // `Arc` isn't `#[fundamental]`, so the local trait inside doesn't
    // make the outer Arc local. The wrapper newtype (declared in the
    // same crate as the trait) is local, so all impls land cleanly.
    //
    // Provides Default, Clone, Deref<Target = dyn Trait>, PartialEq<Nil>
    // both directions, and `From<T>` for any concrete impl. Use sites
    // see a value-type wrapper that behaves exactly like a Go interface
    // value.
    let _ = writeln!(out,
        "{vis} struct {ref_name}(pub ::alloc::sync::Arc<dyn {name} + ::core::marker::Send + ::core::marker::Sync>);"
    );
    out.push('\n');

    let _ = writeln!(out,
        "impl ::core::default::Default for {ref_name} {{"
    );
    let _ = writeln!(out,
        "    #[inline] fn default() -> Self {{ {ref_name}(::alloc::sync::Arc::new({nil_name})) }}"
    );
    out.push_str("}\n\n");

    let _ = writeln!(out, "impl ::core::clone::Clone for {ref_name} {{");
    let _ = writeln!(out,
        "    #[inline] fn clone(&self) -> Self {{ {ref_name}(::alloc::sync::Arc::clone(&self.0)) }}"
    );
    out.push_str("}\n\n");

    let _ = writeln!(out, "impl ::core::ops::Deref for {ref_name} {{");
    let _ = writeln!(out,
        "    type Target = dyn {name} + ::core::marker::Send + ::core::marker::Sync;"
    );
    out.push_str("    #[inline] fn deref(&self) -> &Self::Target { &*self.0 }\n");
    out.push_str("}\n\n");

    // From<T> for any concrete impl — matches Go's "any type with the
    // method set satisfies the interface" via Rust's `impl T for U`.
    let _ = writeln!(out,
        "impl<__T: {name} + 'static> ::core::convert::From<__T> for {ref_name} {{"
    );
    let _ = writeln!(out,
        "    #[inline] fn from(t: __T) -> Self {{ {ref_name}(::alloc::sync::Arc::new(t)) }}"
    );
    out.push_str("}\n\n");

    // ── (5) PartialEq<Nil> in both directions ──────────────────────
    let _ = writeln!(out,
        "impl ::core::cmp::PartialEq<::goish::Nil> for {ref_name} {{"
    );
    out.push_str("    #[inline] fn eq(&self, _: &::goish::Nil) -> bool { (*self.0).__is_nil_iface() }\n");
    out.push_str("}\n\n");
    let _ = writeln!(out,
        "impl ::core::cmp::PartialEq<{ref_name}> for ::goish::Nil {{"
    );
    let _ = writeln!(out,
        "    #[inline] fn eq(&self, other: &{ref_name}) -> bool {{ (*other.0).__is_nil_iface() }}"
    );
    out.push_str("}\n\n");

    // ── (6) From<Nil> — lets `nil.into()` flow into iface slots ────
    let _ = writeln!(out,
        "impl ::core::convert::From<::goish::Nil> for {ref_name} {{"
    );
    out.push_str("    #[inline] fn from(_: ::goish::Nil) -> Self { <Self as ::core::default::Default>::default() }\n");
    out.push_str("}\n\n");

    out.parse()
        .expect("goish::interface: emitted source failed to parse")
}

struct ParsedIface {
    vis: Option<String>,
    name: String,
    methods: Vec<IfaceMethod>,
}

struct IfaceMethod {
    /// Verbatim signature text including the trailing `;`.
    sig_text: String,
}

fn parse_iface(item: TokenStream) -> ParsedIface {
    let tokens: Vec<TokenTree> = item.into_iter().collect();
    let mut iter = tokens.into_iter().peekable();

    // Skip outer attributes (e.g. doc comments): `# [ ... ]`.
    loop {
        match iter.peek() {
            Some(TokenTree::Punct(p)) if p.as_char() == '#' => {
                iter.next();
                iter.next(); // bracket group
            }
            _ => break,
        }
    }

    // Optional visibility.
    let vis = consume_visibility(&mut iter);

    // `trait` keyword.
    match iter.next() {
        Some(TokenTree::Ident(i)) if i.to_string() == "trait" => {}
        other => panic!(
            "#[goish::interface] expects `trait Name {{ ... }}`, got {:?}",
            other
        ),
    }

    // Trait name.
    let name = match iter.next() {
        Some(TokenTree::Ident(i)) => i.to_string(),
        other => panic!("#[goish::interface]: expected trait name, got {:?}", other),
    };

    // Reject generics on the trait itself — Go interfaces don't
    // have type parameters.
    match iter.peek() {
        Some(TokenTree::Punct(p)) if p.as_char() == '<' => panic!(
            "#[goish::interface]: trait `{}` has generics, which Go interfaces don't support",
            name
        ),
        _ => {}
    }

    // Brace-delimited body.
    let body = match iter.next() {
        Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace => g,
        other => panic!(
            "#[goish::interface]: expected trait body `{{ ... }}`, got {:?}",
            other
        ),
    };

    let methods = parse_iface_methods(body.stream());
    ParsedIface { vis, name, methods }
}

fn parse_iface_methods(body: TokenStream) -> Vec<IfaceMethod> {
    let mut methods = Vec::new();
    let mut current: Vec<TokenTree> = Vec::new();

    for tt in body {
        let is_terminator = matches!(&tt, TokenTree::Punct(p) if p.as_char() == ';');
        let is_brace_body =
            matches!(&tt, TokenTree::Group(g) if g.delimiter() == Delimiter::Brace);

        if is_terminator {
            current.push(tt);
            let sig: TokenStream = current.drain(..).collect();
            methods.push(IfaceMethod { sig_text: sig.to_string() });
        } else if is_brace_body {
            // Default-bodied method — refuse. Go interfaces don't
            // have these; if a user wants one, they should declare
            // a plain `pub trait` instead of using this attribute.
            panic!(
                "#[goish::interface]: default-method bodies are not supported \
                 (Go interfaces don't have them); use a plain `pub trait` instead"
            );
        } else {
            current.push(tt);
        }
    }

    if !current.is_empty() {
        let sig: TokenStream = current.drain(..).collect();
        let leftover = sig.to_string();
        let trimmed = leftover.trim();
        if !trimmed.is_empty() {
            panic!(
                "#[goish::interface]: trailing tokens after last method `{}`",
                trimmed
            );
        }
    }

    methods
}
