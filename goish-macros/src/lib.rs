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
        #[derive(::core::marker::Copy, ::core::clone::Clone, ::core::fmt::Debug)]
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

    // ── impl json/v2 MarshalerTo / UnmarshalerFrom ─────────────────
    // The compile-time equivalent of json/v2's cached reflection
    // codec (encoding/json/v2/arshal_default.go): Go builds a struct
    // codec at runtime from reflect.Type + json tags; here the field
    // list and tags are known at macro time, so the object codec is
    // generated directly. Field names come from the `json:"…"` tag
    // segment (or the field name verbatim, matching v2's default);
    // `-` skips the field; `omitempty` / `omitzero` route through the
    // `v2::JsonOmit` helper trait. Unknown incoming names are skipped
    // (v2 default), and a JSON null resets the struct to its zero
    // value.
    let _ = write!(
        impl_text,
        "impl ::goish::encoding::json::v2::MarshalerTo for {} {{\n\
         \x20   fn MarshalJSONTo(&self, __enc: &mut ::goish::encoding::json::jsontext::Encoder) -> ::goish::error {{\n\
         \x20       let mut __err = __enc.WriteToken(::goish::encoding::json::jsontext::BeginObject);\n\
         \x20       if __err != ::goish::errors::nil {{ return __err; }}\n",
        parsed.name
    );
    for f in &parsed.fields {
        let (key, skip, omitempty, omitzero) = json_tag_parts(f.tag.as_deref(), &f.name);
        if skip {
            continue;
        }
        let key_lit = key.replace('\\', "\\\\").replace('"', "\\\"");
        if omitempty {
            let _ = write!(
                impl_text,
                "        if !::goish::encoding::json::v2::JsonOmit::__json_empty(&self.{}) {{\n",
                f.name
            );
        } else if omitzero {
            let _ = write!(
                impl_text,
                "        if !::goish::encoding::json::v2::JsonOmit::__json_zero(&self.{}) {{\n",
                f.name
            );
        }
        let _ = write!(
            impl_text,
            "        __err = __enc.WriteToken(::goish::encoding::json::jsontext::String(::goish::string::from_static(\"{}\")));\n\
             \x20       if __err != ::goish::errors::nil {{ return __err; }}\n\
             \x20       __err = <{} as ::goish::encoding::json::v2::MarshalerTo>::MarshalJSONTo(&self.{}, __enc);\n\
             \x20       if __err != ::goish::errors::nil {{ return __err; }}\n",
            key_lit, f.ty, f.name
        );
        if omitempty || omitzero {
            impl_text.push_str("        }\n");
        }
    }
    impl_text.push_str(
        "        __enc.WriteToken(::goish::encoding::json::jsontext::EndObject)\n\
         \x20   }\n\
         }\n",
    );

    let _ = write!(
        impl_text,
        "impl ::goish::encoding::json::v2::UnmarshalerFrom for {} {{\n\
         \x20   fn UnmarshalJSONFrom(&mut self, __dec: &mut ::goish::encoding::json::jsontext::Decoder) -> ::goish::error {{\n\
         \x20       if __dec.PeekKind() == 'n' {{\n\
         \x20           let (_, __err) = __dec.ReadToken();\n\
         \x20           *self = <Self as ::core::default::Default>::default();\n\
         \x20           return __err;\n\
         \x20       }}\n\
         \x20       let (__t, __err) = __dec.ReadToken();\n\
         \x20       if __err != ::goish::errors::nil {{ return __err; }}\n\
         \x20       if __t.Kind() != '{{' {{\n\
         \x20           return ::goish::errors::New(\"json: cannot unmarshal non-object into struct\");\n\
         \x20       }}\n\
         \x20       while __dec.PeekKind() != '}}' {{\n\
         \x20           if __dec.PeekKind() == ::goish::encoding::json::jsontext::Kind(0) {{\n\
         \x20               return ::goish::io::ErrUnexpectedEOF.into();\n\
         \x20           }}\n\
         \x20           let (__name_tok, __err) = __dec.ReadToken();\n\
         \x20           if __err != ::goish::errors::nil {{ return __err; }}\n\
         \x20           let __name = __name_tok.String();\n\
         \x20           match __name.as_bytes() {{\n",
        parsed.name
    );
    for f in &parsed.fields {
        let (key, skip, _, _) = json_tag_parts(f.tag.as_deref(), &f.name);
        if skip {
            continue;
        }
        let key_lit = key.replace('\\', "\\\\").replace('"', "\\\"");
        let _ = write!(
            impl_text,
            "                b\"{}\" => {{\n\
             \x20                   let __err = <{} as ::goish::encoding::json::v2::UnmarshalerFrom>::UnmarshalJSONFrom(&mut self.{}, __dec);\n\
             \x20                   if __err != ::goish::errors::nil {{ return __err; }}\n\
             \x20               }}\n",
            key_lit, f.ty, f.name
        );
    }
    impl_text.push_str(
        "                _ => {\n\
         \x20                   let __err = __dec.SkipValue();\n\
         \x20                   if __err != ::goish::errors::nil { return __err; }\n\
         \x20               }\n\
         \x20           }\n\
         \x20       }\n\
         \x20       let (_, __err) = __dec.ReadToken();\n\
         \x20       __err\n\
         \x20   }\n\
         }\n",
    );

    // Struct values are never considered empty/zero for omission
    // purposes (documented v1 simplification; Go v2's omitzero on a
    // struct compares against the zero value).
    let _ = write!(
        impl_text,
        "impl ::goish::encoding::json::v2::JsonOmit for {} {{}}\n",
        parsed.name
    );

    let mut out: TokenStream = struct_text
        .parse()
        .expect("goish::reflect: failed to re-emit struct");
    let impl_ts: TokenStream = impl_text
        .parse()
        .expect("goish::reflect: failed to emit impl");
    out.extend(impl_ts);
    out
}

/// Macro-time parse of a `#[tag(...)]` literal's `json:"…"` segment.
/// Returns `(effective_key, skip, omitempty, omitzero)`. The literal
/// arrives as verbatim source text — either `"json:\"name,opt\""` or
/// `r#"json:"name,opt""#` — so quoting is normalized first. Mirrors
/// the runtime `__parse_json_tag` (and Go's tags.go) semantics:
/// `-` alone skips; empty name falls back to the field name.
fn json_tag_parts(tag_lit: Option<&str>, field_name: &str) -> (String, bool, bool, bool) {
    let fallback = (field_name.to_string(), false, false, false);
    let lit = match tag_lit {
        Some(l) => l,
        None => return fallback,
    };
    // Normalize the literal to its contents.
    let inner = if let Some(stripped) = lit.strip_prefix("r#\"") {
        stripped.strip_suffix("\"#").unwrap_or(stripped).to_string()
    } else if let Some(stripped) = lit.strip_prefix('"') {
        stripped
            .strip_suffix('"')
            .unwrap_or(stripped)
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    } else {
        lit.to_string()
    };
    // Locate the json:"..." segment.
    let seg = match inner.find("json:\"") {
        Some(i) => &inner[i + 6..],
        None => return fallback,
    };
    let body = match seg.find('"') {
        Some(end) => &seg[..end],
        None => seg,
    };
    let mut parts = body.split(',');
    let name = parts.next().unwrap_or("");
    if name == "-" && body == "-" {
        return (String::new(), true, false, false);
    }
    let mut omitempty = false;
    let mut omitzero = false;
    for p in parts {
        match p {
            "omitempty" => omitempty = true,
            "omitzero" => omitzero = true,
            _ => {}
        }
    }
    let key = if name.is_empty() { field_name.to_string() } else { name.to_string() };
    (key, false, omitempty, omitzero)
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
/// Returns true when the supertrait clause contains ONLY `Send`/`Sync`
/// marker traits (or is empty). Returns false when any non-marker
/// supertrait is present — that means the trait is "composite" and we
/// cannot safely auto-emit a nil sentinel struct that impls all the
/// foreign supertraits.
///
/// Recognized trivial tokens (case-sensitive):
///   `Send`, `Sync`,
///   `::core::marker::Send`, `::core::marker::Sync`,
///   `core::marker::Send`, `core::marker::Sync`
///
/// Any other segment — even `io::Writer` or `metav1::Object` — is
/// composite.
fn supertraits_are_trivial(supertraits: &str) -> bool {
    // Strip leading `: ` that parse_iface may have retained.
    let s = supertraits.trim_start_matches(':').trim();
    if s.is_empty() {
        return true;
    }
    s.split('+').map(|x| x.trim()).all(|x| {
        matches!(
            x,
            "Send"
                | "Sync"
                | "::core::marker::Send"
                | "::core::marker::Sync"
                | "core::marker::Send"
                | "core::marker::Sync"
        )
    })
}

#[proc_macro_attribute]
pub fn interface(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let parsed = parse_iface(item);
    let name = &parsed.name;
    let nil_name = format!("__Nil{}", name);
    let vis = parsed.vis.as_deref().unwrap_or("");

    // Determine whether the supertrait clause is trivial (only
    // Send/Sync markers) or composite (includes foreign traits like
    // `metav1::Object`). Composite → skip nil sentinel sections.
    let composite = !supertraits_are_trivial(&parsed.supertraits);

    // Compose the supertrait clause. We always require `Send + Sync`
    // (every Goish iface flows across goroutines); pre-existing
    // user supertraits (like `: io::Writer` for hash::Hash) are
    // preserved by token-capturing them in parse_iface. Rust accepts
    // duplicate trait bounds without warnings, so over-specifying is
    // harmless if the user already wrote `: Send + Sync`.
    //
    // Note: we don't add `core::any::Any` as a supertrait — Any
    // requires `Self: 'static`, which would break common forwarding
    // impls like `impl<R: Reader + ?Sized> Reader for &mut R` where
    // the borrow lifetime is shorter than 'static. Trait-borrow
    // downcast (TRAIT-BORROW-DOWNCAST) instead routes through the
    // per-trait `__as_dyn_any` method that we add below.
    let supertraits = if parsed.supertraits.is_empty() {
        String::from(": ::core::marker::Send + ::core::marker::Sync")
    } else {
        // parsed.supertraits starts with the leading `:` token.
        format!(
            "{} + ::core::marker::Send + ::core::marker::Sync",
            parsed.supertraits
        )
    };

    let mut out = String::new();

    // ── (1) Trait redeclaration with supertraits + hidden helper ───
    //
    // `__is_nil_iface` is a default method on the trait itself (NOT a
    // separate supertrait) so concrete impls inherit `false` for free
    // and the nil sentinel overrides to `true`.
    //
    // `__GOISH_HAS_NIL_SENTINEL` is a doc-hidden associated const
    // that records whether this trait has a nil sentinel at compile
    // time. Trivial supertraits → true; composite → false. The
    // `cast!` macro reads this via `__HasNilSentinel` and produces a
    // clear compile error for composite-trait callers.
    let has_sentinel_val = if composite { "false" } else { "true" };
    let _ = writeln!(
        out,
        "{vis} trait {name}{supertraits} {{"
    );
    for m in &parsed.methods {
        let _ = writeln!(out, "    {}", m.full_text);
    }
    out.push_str("    #[doc(hidden)]\n");
    out.push_str("    fn __is_nil_iface(&self) -> bool { false }\n");
    // `__goish_as_dyn_any` exposes a `&dyn Any` view for trait-borrow
    // downcast (TRAIT-BORROW-DOWNCAST). Default body returns None —
    // forwarding impls and the nil sentinel inherit this. Concrete
    // user impls override to `Some(self)` (the transpiler emits the
    // override at every `impl Trait for Concrete` site). Object-safe
    // since the method has no generic params.
    out.push_str("    #[doc(hidden)]\n");
    out.push_str(
        "    fn __goish_as_dyn_any(&self) \
         -> ::core::option::Option<&(dyn ::core::any::Any \
         + ::core::marker::Send + ::core::marker::Sync)> { ::core::option::Option::None }\n",
    );
    // `__goish_as_dyn_any_mut` — the `&mut` mirror, for `cast!(&mut x, J)`.
    // Default None; concrete impls override to `Some(self)` alongside the
    // `__goish_as_dyn_any` override (emitted at every `impl Trait for C` site).
    out.push_str("    #[doc(hidden)]\n");
    out.push_str(
        "    fn __goish_as_dyn_any_mut(&mut self) \
         -> ::core::option::Option<&mut (dyn ::core::any::Any \
         + ::core::marker::Send + ::core::marker::Sync)> { ::core::option::Option::None }\n",
    );
    out.push_str("}\n\n");

    // Emit __HasNilSentinel impl so cast!() can const-assert on the
    // presence/absence of a nil sentinel. Both trivial and composite
    // traits get this; only the constant VALUE differs.
    let _ = writeln!(
        out,
        "impl ::goish::any::__HasNilSentinel \
         for dyn {name} + ::core::marker::Send + ::core::marker::Sync {{"
    );
    let _ = writeln!(
        out,
        "    const __GOISH_HAS_NIL_SENTINEL: bool = {has_sentinel_val};"
    );
    out.push_str("}\n\n");

    // ── (2) Nil sentinel struct — TRIVIAL only ──────────────────────
    //
    // Skipped for composite traits (supertrait clause contains non-
    // marker types like `metav1::Object`). Emitting the struct + impl
    // would require also emitting `impl ForeignTrait for __NilT` which
    // violates the orphan rule or fails when the foreign trait has
    // non-default methods.
    if !composite {
        out.push_str("#[doc(hidden)]\n");
        out.push_str("#[allow(non_camel_case_types)]\n");
        let _ = writeln!(out, "pub struct {nil_name};");
        out.push('\n');
    }

    // ── (3) impl Trait for __NilT — every method panics (TRIVIAL only)
    if !composite {
        let _ = writeln!(out, "impl {name} for {nil_name} {{");
        for m in &parsed.methods {
            let _ = writeln!(
                out,
                "    {} {{ panic!(\"goish: method call on nil {} interface\") }}",
                m.sig_only.trim(), name
            );
        }
        out.push_str("    fn __is_nil_iface(&self) -> bool { true }\n");
        out.push_str("}\n\n");
    }

    // ── NO PER-TRAIT WRAPPER NEWTYPE ────────────────────────────────
    //
    // Earlier designs emitted `<Trait>Ref(pub Arc<dyn Trait + Send +
    // Sync>)` to host orphan-rule-bound impls. That generated one
    // new top-level type per user trait — visual clutter the Goish
    // project rejects.
    //
    // Convention:
    //   * Function params of interface type lower to
    //     `impl Trait + 'static` (anonymous generic + bound). No
    //     wrapper at the param position.
    //   * Storage positions (struct fields, locals, returns, Hook<T>)
    //     use `Arc<dyn Trait + Send + Sync>` directly.
    //
    // Orphan-rule subtlety: foreign-trait impls on `Arc<dyn LocalTrait>`
    // are allowed IFF the foreign trait has at least one local type
    // argument. Concretely:
    //
    //   * `PartialEq<Nil>` for `Arc<dyn T>` — OK. Nil is local; the
    //     foreign-trait type arg covers Self.
    //   * `From<Nil>` for `Arc<dyn T>` — OK. Same reason.
    //   * `Default` for `Arc<dyn T>` — NOT OK. Default has no type
    //     arguments, so Self alone determines coverage; Arc is
    //     foreign at the outermost position and `dyn T` doesn't lift
    //     covered-ness through Arc per RFC 2451.
    //
    // Sections (6.8) and (7) below emit the two ALLOWED impls so
    // users can write `arc == nil` / `nil.into()` directly. Default
    // is intentionally NOT emitted — structs with `Arc<dyn T>`-typed
    // fields need either an explicit `Default` impl or to drop
    // `#[derive(Default)]`.

    // ── (6.5) Forwarding impl Trait for Hook<dyn T + Send + Sync> ─
    //
    // Lets `goish::var! { pub iface tracer: Tracer; }` users call
    // `tracer.M(args)` directly — no `tracer.call(|h| h.M(args)).unwrap()`
    // closure noise.
    //
    // SKIPPED for composite traits: Hook<dyn T> requires a nil sentinel
    // for the "None" branch panic; composite traits have no sentinel.
    let mut forwarding_impl_ok = !composite && !parsed.methods.is_empty();
    for m in &parsed.methods {
        if m.method_name.is_empty() {
            forwarding_impl_ok = false;
            break;
        }
        if m.receiver == "&mut self" {
            forwarding_impl_ok = false;
            break;
        }
    }
    if forwarding_impl_ok {
        let _ = writeln!(
            out,
            "impl {name} for ::goish::hook::Hook<dyn {name} + ::core::marker::Send + ::core::marker::Sync> {{"
        );
        for m in &parsed.methods {
            let arg_list = m.arg_names.join(", ");
            // `call_or_panic` (defined on Hook<T>) handles the lock +
            // unwrap-or-panic dance, so the forwarding body is a
            // single line. The trait method's `&self` / `&mut self`
            // distinction doesn't matter at this layer — Hook always
            // dispatches through `&mut T` (which auto-deref-coerces
            // to `&T` for `&self` methods).
            let body = format!(
                "{{ self.call_or_panic(\"goish: method call on nil {name} interface\", |__t| __t.{method}({args})) }}",
                name = name,
                method = m.method_name,
                args = arg_list,
            );
            let _ = writeln!(out, "    {} {}", m.sig_only.trim(), body);
        }
        out.push_str("}\n\n");
    }

    // ── (6.6) Forwarding impl Trait for nilable<__T: Trait + ?Sized> ──
    //
    // SKIPPED for composite traits: nilable<T> forwarding panics on nil
    // via Must(), which is fine, but the impl itself requires that
    // __NilT satisfies the supertrait — which it doesn't when the
    // supertrait is foreign with non-default methods.
    let mut nilable_impl_ok = !composite && !parsed.methods.is_empty();
    for m in &parsed.methods {
        if m.method_name.is_empty() || m.receiver == "&mut self" {
            nilable_impl_ok = false;
            break;
        }
    }
    if nilable_impl_ok {
        let _ = writeln!(
            out,
            "impl<__T: {name} + ?::core::marker::Sized> {name} for ::goish::nilable<__T> {{"
        );
        for m in &parsed.methods {
            let arg_list = m.arg_names.join(", ");
            let body = format!(
                "{{ self.Must().{method}({args}) }}",
                method = m.method_name,
                args = arg_list,
            );
            let _ = writeln!(out, "    {} {}", m.sig_only.trim(), body);
        }
        out.push_str("}\n\n");
    }

    // ── (6.7a) Forwarding impl Trait for &T and &mut T blankets ────
    //
    // Rust doesn't auto-derive `impl Trait for &T` or `impl Trait for
    // &mut T` from `impl Trait for T`. Goish-emitted code routinely
    // borrows trait-implementing values into trait-object positions
    // — `let h: &slogHandler = ...; h.Handle(...)` requires
    // `&slogHandler: Handler`. Without these blankets, the borrow
    // forms fail with E0277 even when the owned form satisfies the
    // trait.
    //
    // Emission:
    //   * `&mut T` blanket: ALWAYS emit when the trait's methods can
    //     all be dispatched via auto-deref through `&mut`. Concretely:
    //     `&mut T` derefs to `T`, and method resolution can find any
    //     `&self` or `&mut self` method on T. So forwarding is
    //     unconditional (every method body is `(**self).M(args)`,
    //     which auto-borrows correctly).
    //
    //   * `&T` blanket: emit ONLY when every trait method takes
    //     `&self` (no `&mut self` methods). Otherwise the impl can't
    //     dispatch `&mut self` methods through a `&T` — no way to
    //     promote a shared borrow to an exclusive one.
    //
    // Method bodies use fully-qualified dispatch
    // `<__T as Trait>::M(self, args)` so they don't recurse into the
    // forwarding impl. Skipped (forwarding_impl_ok) when method-shape
    // parsing failed for any method.
    // ── (6.7a) Forwarding impl Trait for &T and &mut T blankets ────
    //
    // SKIPPED for composite traits: the blanket `impl<__T: Composite>
    // Composite for &mut __T` would require `&mut __T: Foreign`, which
    // generally doesn't hold (foreign traits don't impl for &mut T
    // unless they explicitly provide it). Composite-trait callers use
    // the concrete type directly.
    let blanket_methods_ok = !composite
        && !parsed.methods.is_empty()
        && parsed.methods.iter().all(|m| !m.method_name.is_empty());
    let any_mut_self = parsed.methods.iter().any(|m| m.receiver == "&mut self");

    if blanket_methods_ok {
        // &mut T blanket — always valid (every method auto-borrows
        // through &mut). Methods that take `&self` get an &mut → &
        // demotion via auto-deref; methods that take `&mut self`
        // re-borrow through the impl's `self: &mut &mut __T` → `&mut __T`.
        let _ = writeln!(
            out,
            "impl<__T: {name} + ?::core::marker::Sized> {name} for &mut __T {{"
        );
        for m in &parsed.methods {
            let arg_list = m.arg_names.join(", ");
            let body = format!(
                "{{ <__T as {name}>::{method}(self, {args}) }}",
                name = name,
                method = m.method_name,
                args = arg_list,
            );
            let _ = writeln!(out, "    {} {}", m.sig_only.trim(), body);
        }
        out.push_str("}\n\n");

        if !any_mut_self {
            // &T blanket — only valid when no method needs &mut.
            let _ = writeln!(
                out,
                "impl<__T: {name} + ?::core::marker::Sized> {name} for &__T {{"
            );
            for m in &parsed.methods {
                let arg_list = m.arg_names.join(", ");
                let body = format!(
                    "{{ <__T as {name}>::{method}(*self, {args}) }}",
                    name = name,
                    method = m.method_name,
                    args = arg_list,
                );
                let _ = writeln!(out, "    {} {}", m.sig_only.trim(), body);
            }
            out.push_str("}\n\n");
        }
    }

    // ── (6.8) PartialEq<Nil> + From<Nil> for Arc<dyn T + Send + Sync> ──
    //
    // Lets users write `if sink == nil { ... }` and `if sink != nil`
    // against `Arc<dyn Trait>`-typed bindings — Go's idiomatic
    // interface-nil-check, preserved at the source level.
    //
    // Orphan-rule gate: these impls are only valid when `Nil` is local
    // to the calling crate (per RFC 2451's "covered" requirement for
    // `impl ForeignTrait<T_local> for Arc<dyn LocalTrait>`). Inside
    // goish-v1, `::goish::Nil` IS local (`extern crate self as goish`
    // makes it so). In a goishc-emitted port crate, `::goish::Nil` is
    // foreign, and the orphan rule rejects the impl entirely.
    //
    // Detect the goish-v1 *lib* crate via CARGO_CRATE_NAME — the
    // proc-macro reads the env var at expansion time, set to the
    // crate currently being compiled. `Nil` is local only to the
    // goish lib crate itself; it is foreign to a port crate AND to
    // goish's own example crates (which share the `goish` *package*
    // name but are distinct *crates*). CARGO_PKG_NAME would be
    // "goish" for both the lib and its examples, wrongly emitting the
    // orphan-violating impl in examples — CARGO_CRATE_NAME is "goish"
    // for the lib alone.
    //
    // When not the lib crate, the goishc transpiler's nil-check
    // rewrite (which lowers `arc == nil` to `(*arc).__is_nil_iface()`
    // at the call site) is the path that makes user-facing `==` work.
    //
    // Dispatches through the `__is_nil_iface` default method: the
    // private nil sentinel `__NilT` overrides it to return true; any
    // concrete impl inherits the `false` default.
    let inside_goish_runtime = ::std::env::var("CARGO_CRATE_NAME")
        .map(|n| n == "goish")
        .unwrap_or(false);
    if inside_goish_runtime {
        // PartialEq<Nil> dispatches through __is_nil_iface() — safe for
        // both trivial and composite traits (no nil sentinel needed).
        let _ = writeln!(out,
            "impl ::core::cmp::PartialEq<::goish::Nil> \
             for ::alloc::sync::Arc<dyn {name} + ::core::marker::Send + ::core::marker::Sync> {{"
        );
        let _ = writeln!(out,
            "    #[inline] fn eq(&self, _: &::goish::Nil) -> bool {{ (**self).__is_nil_iface() }}"
        );
        out.push_str("}\n\n");
        let _ = writeln!(out,
            "impl ::core::cmp::PartialEq<::alloc::sync::Arc<dyn {name} + ::core::marker::Send + ::core::marker::Sync>> \
             for ::goish::Nil {{"
        );
        let _ = writeln!(out,
            "    #[inline] fn eq(&self, other: &::alloc::sync::Arc<dyn {name} + ::core::marker::Send + ::core::marker::Sync>) -> bool {{ (**other).__is_nil_iface() }}"
        );
        out.push_str("}\n\n");
        // From<Nil> for Arc needs the nil sentinel struct — TRIVIAL only.
        if !composite {
            let _ = writeln!(out,
                "impl ::core::convert::From<::goish::Nil> \
                 for ::alloc::sync::Arc<dyn {name} + ::core::marker::Send + ::core::marker::Sync> {{"
            );
            let _ = writeln!(out,
                "    #[inline] fn from(_: ::goish::Nil) -> Self {{ ::alloc::sync::Arc::new({nil_name}) }}"
            );
            out.push_str("}\n\n");
        }
    }

    // ── (7) Backwards-compat From<Nil> for Box<dyn T> — TRIVIAL only ──
    //
    // Composite traits have no nil sentinel struct, so we cannot
    // construct `Box::new(__NilT)` — skip this section entirely for
    // composite. Trivial traits emit as before.
    if !composite {
        let _ = writeln!(out,
            "impl ::core::convert::From<::goish::Nil> \
             for ::alloc::boxed::Box<dyn {name} + ::core::marker::Send + ::core::marker::Sync> {{"
        );
        let _ = writeln!(out,
            "    #[inline] fn from(_: ::goish::Nil) -> Self {{ ::alloc::boxed::Box::new({nil_name}) }}"
        );
        out.push_str("}\n\n");
    }

    // ── (8) DowncastableFromAny for `dyn Trait` + per-trait registry ─
    //
    // Lets `goish::Any::As::<dyn Trait>()` return `Some(&dyn Trait)`
    // when the wrapped concrete type was registered via the
    // matching `register_<trait>_impl` helper. Drives Go's
    // trait-typed comma-ok type assertion `vv, ok := x.(Trait)`;
    // the transpiler lowers it to `data.As::<dyn Trait>()`.
    //
    // Per-trait static + helper because the cast fn signature is
    // trait-specific (returns `&dyn Trait`, a fat pointer with
    // Trait's vtable). A trait-agnostic registry would lose the
    // vtable on cast.
    //
    // The transpiler emits `register_<trait>_impl::<Concrete>()` at
    // every `impl Trait for Concrete` site (typically inside the
    // crate's `init()` so registration happens before any
    // `As::<dyn Trait>()` call).
    let registry_name = format!("__GOISH_{}_REGISTRY", name.to_uppercase());
    let register_fn = format!("__goish_register_{}_impl", name);

    let _ = writeln!(
        out,
        "#[doc(hidden)]\n\
         pub static {registry_name}: \
         ::goish::runtime::spin::SpinLock<::goish::any::TraitRegistry<\
         dyn {name} + ::core::marker::Send + ::core::marker::Sync>> = \
         ::goish::runtime::spin::SpinLock::new(::goish::any::TraitRegistry::new());"
    );
    out.push('\n');

    let _ = writeln!(
        out,
        "#[doc(hidden)]\n\
         pub fn {register_fn}<__C: 'static + {name} + \
         ::core::marker::Send + ::core::marker::Sync>() {{"
    );
    out.push_str("    fn cast<__C: 'static + ");
    out.push_str(&name);
    out.push_str(" + ::core::marker::Send + ::core::marker::Sync>(\n");
    out.push_str(
        "        any_ref: &(dyn ::core::any::Any + ::core::marker::Send + \
         ::core::marker::Sync),\n",
    );
    // Explicit 'static on the dyn return so the inferred fn-item
    // lifetime matches `TraitProbe.cast`'s `for<'a> fn(&'a _) -> &'a
    // Trait` shape (where Trait carries its own 'static object
    // lifetime). Without the bound, Rust infers the return's dyn-
    // object-lifetime as 'a, narrowing the type beyond the field.
    let _ = writeln!(
        out,
        "    ) -> &(dyn {name} + ::core::marker::Send + ::core::marker::Sync + 'static) {{"
    );
    out.push_str("        any_ref.downcast_ref::<__C>()\n");
    out.push_str(
        "            .expect(\"goish::any: cast invoked with mismatched concrete type\")\n",
    );
    out.push_str("    }\n");
    // Mutable cast mirror — recovers `&mut dyn Trait` from `&mut dyn Any`.
    out.push_str("    fn cast_mut<__C: 'static + ");
    out.push_str(&name);
    out.push_str(" + ::core::marker::Send + ::core::marker::Sync>(\n");
    out.push_str(
        "        any_ref: &mut (dyn ::core::any::Any + ::core::marker::Send + \
         ::core::marker::Sync),\n",
    );
    let _ = writeln!(
        out,
        "    ) -> &mut (dyn {name} + ::core::marker::Send + ::core::marker::Sync + 'static) {{"
    );
    out.push_str("        any_ref.downcast_mut::<__C>()\n");
    out.push_str(
        "            .expect(\"goish::any: cast_mut invoked with mismatched concrete type\")\n",
    );
    out.push_str("    }\n");
    out.push_str(
        "    let probe = ::goish::any::TraitProbe { concrete: \
         ::core::any::TypeId::of::<__C>(), cast: cast::<__C>, cast_mut: cast_mut::<__C> };\n",
    );
    let _ = writeln!(
        out,
        "    ::goish::any::register_with(&{registry_name}, probe);"
    );
    out.push_str("}\n\n");

    let _ = writeln!(
        out,
        "impl ::goish::any::DowncastableFromAny \
         for dyn {name} + ::core::marker::Send + ::core::marker::Sync {{"
    );
    out.push_str(
        "    #[inline]\n    fn from_any(any_ref: &(dyn ::core::any::Any + \
         ::core::marker::Send + ::core::marker::Sync)) -> ::core::option::Option<&Self> {\n",
    );
    let _ = writeln!(
        out,
        "        ::goish::any::lookup_with(&{registry_name}, any_ref)"
    );
    out.push_str("    }\n}\n\n");

    // Mutable mirror of the DowncastableFromAny impl.
    let _ = writeln!(
        out,
        "impl ::goish::any::DowncastableFromAnyMut \
         for dyn {name} + ::core::marker::Send + ::core::marker::Sync {{"
    );
    out.push_str(
        "    #[inline]\n    fn from_any_mut(any_ref: &mut (dyn ::core::any::Any + \
         ::core::marker::Send + ::core::marker::Sync)) -> ::core::option::Option<&mut Self> {\n",
    );
    let _ = writeln!(
        out,
        "        ::goish::any::lookup_with_mut(&{registry_name}, any_ref)"
    );
    out.push_str("    }\n}\n\n");

    // ── (9) HasDynAny for `dyn Trait + Send + Sync` ─────────────────
    //
    // Routes `&dyn Trait`'s "give me an Any view" request through the
    // trait's `__goish_as_dyn_any` method (added in section 1's
    // trait-redecl). Concrete impls override to `Some(self)`; default
    // is `None`. The `AsExt::As<T>` blanket consults HasDynAny, so
    // `rd.As::<Reader>()` on `rd: &dyn Trait` works out-of-the-box
    // for any concrete type that overrode `__goish_as_dyn_any`.
    //
    // Without this impl, `dyn Trait + Send + Sync: !HasDynAny`,
    // because the blanket on Sized + 'static doesn't reach unsized
    // dyn types. Path: TRAIT-BORROW-DOWNCAST.
    let _ = writeln!(
        out,
        "impl ::goish::any::HasDynAny \
         for dyn {name} + ::core::marker::Send + ::core::marker::Sync {{"
    );
    out.push_str(
        "    #[inline]\n    fn __goish_as_dyn_any(&self) \
         -> ::core::option::Option<&(dyn ::core::any::Any + \
         ::core::marker::Send + ::core::marker::Sync)> {\n",
    );
    let _ = writeln!(
        out,
        "        {name}::__goish_as_dyn_any(self)"
    );
    out.push_str("    }\n}\n\n");

    // Mutable mirror — HasDynAnyMut for `dyn Trait + Send + Sync`.
    let _ = writeln!(
        out,
        "impl ::goish::any::HasDynAnyMut \
         for dyn {name} + ::core::marker::Send + ::core::marker::Sync {{"
    );
    out.push_str(
        "    #[inline]\n    fn __goish_as_dyn_any_mut(&mut self) \
         -> ::core::option::Option<&mut (dyn ::core::any::Any + \
         ::core::marker::Send + ::core::marker::Sync)> {\n",
    );
    let _ = writeln!(
        out,
        "        {name}::__goish_as_dyn_any_mut(self)"
    );
    out.push_str("    }\n}\n\n");

    // ── (10) NilDyn for `dyn Trait + Send + Sync` — TRIVIAL only ───────
    //
    // Hands back a `&'static` borrow of the nil sentinel `__NilT`.
    // Skipped for composite traits because __NilT doesn't exist there.
    if !composite {
        let _ = writeln!(
            out,
            "impl ::goish::any::NilDyn \
             for dyn {name} + ::core::marker::Send + ::core::marker::Sync {{"
        );
        let _ = writeln!(
            out,
            "    #[inline]\n    fn __goish_nil_ref() \
             -> &'static (dyn {name} + ::core::marker::Send + ::core::marker::Sync) {{"
        );
        let _ = writeln!(out, "        static __GOISH_NIL: {nil_name} = {nil_name};");
        out.push_str("        &__GOISH_NIL\n");
        out.push_str("    }\n}\n\n");
    }

    out.parse()
        .expect("goish::interface: emitted source failed to parse")
}

struct ParsedIface {
    vis: Option<String>,
    name: String,
    /// Verbatim text of any supertrait clause the user wrote (between
    /// `trait Name` and the body brace), e.g. `: io::Writer` or `:
    /// Send + Sync`. Empty when the user wrote no supertrait clause.
    /// The macro always tacks on `+ Send + Sync` to whatever the user
    /// wrote — Rust accepts duplicate trait bounds without diagnostic
    /// warnings, so over-specifying is harmless.
    supertraits: String,
    methods: Vec<IfaceMethod>,
}

struct IfaceMethod {
    /// Verbatim text for trait redeclaration — may end in `;`
    /// (signature-only) OR a brace group (default-bodied method,
    /// for Goish-specific traits with optional methods like
    /// `context::Context::Value`).
    full_text: String,
    /// Signature-only text WITHOUT the trailing `;` or default body.
    /// Used to build the sentinel impl: `<sig_only> { panic!(…) }`.
    sig_only: String,
    /// Method name (extracted from `fn <name>(…)`). Used by the
    /// Hook-forwarding impl to emit `t.<name>(<args>)`.
    method_name: String,
    /// Argument names in source order, excluding `self` / `&self` /
    /// `&mut self`. Used by the Hook-forwarding impl to thread args
    /// into the inner call. Empty when the method takes only the
    /// receiver (or when parsing failed — caller falls back to the
    /// closure-form rewrite).
    arg_names: Vec<String>,
    /// Receiver shape — either "&self" or "&mut self". The
    /// forwarding impl uses this to lock the SpinLock with `.lock()`
    /// and call through the appropriate guard projection
    /// (`as_ref()` for &self, `as_mut()` for &mut self).
    receiver: String,
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

    // Capture the supertrait clause: every token between the trait
    // name and the body brace group. Typically `: io::Writer + Send +
    // Sync` or empty.
    //
    // We collect into a Vec<TokenTree> and reconstruct via
    // TokenStream so that multi-char tokens like `::` (two Joint
    // Punct tokens) round-trip correctly — iterating and calling
    // tt.to_string() per token would insert spaces between the two
    // `:` chars, producing `metav1 : : Object` instead of
    // `metav1 :: Object`.
    let mut supertrait_tokens: Vec<TokenTree> = Vec::new();
    let body = loop {
        match iter.next() {
            Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace => break g,
            Some(tt) => supertrait_tokens.push(tt),
            None => panic!(
                "#[goish::interface]: expected trait body `{{ ... }}` after supertraits"
            ),
        }
    };
    let supertraits: TokenStream = supertrait_tokens.into_iter().collect();
    let supertraits = supertraits.to_string();

    let methods = parse_iface_methods(body.stream());
    ParsedIface { vis, name, supertraits, methods }
}

fn parse_iface_methods(body: TokenStream) -> Vec<IfaceMethod> {
    let mut methods = Vec::new();
    let mut current: Vec<TokenTree> = Vec::new();

    for tt in body {
        let is_terminator = matches!(&tt, TokenTree::Punct(p) if p.as_char() == ';');
        let is_brace_body =
            matches!(&tt, TokenTree::Group(g) if g.delimiter() == Delimiter::Brace);

        if is_terminator {
            // Signature-only method: `fn name(...) -> ret;`
            let sig_tokens: Vec<TokenTree> = current.drain(..).collect();
            let (method_name, arg_names, receiver) = extract_method_shape(&sig_tokens);
            let sig_only: TokenStream = sig_tokens.into_iter().collect();
            let sig_only_text = sig_only.to_string();
            let full_text = format!("{};", sig_only_text);
            methods.push(IfaceMethod {
                full_text,
                sig_only: sig_only_text,
                method_name,
                arg_names,
                receiver,
            });
        } else if is_brace_body {
            // Default-bodied method: `fn name(...) -> ret { body }`.
            // sig_only excludes the brace body; full_text includes it.
            let sig_tokens: Vec<TokenTree> = current.drain(..).collect();
            let (method_name, arg_names, receiver) = extract_method_shape(&sig_tokens);
            let sig_only: TokenStream = sig_tokens.into_iter().collect();
            let sig_only_text = sig_only.to_string();
            let full_text = format!("{} {}", sig_only_text, tt.to_string());
            methods.push(IfaceMethod {
                full_text,
                sig_only: sig_only_text,
                method_name,
                arg_names,
                receiver,
            });
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

// extract_method_shape parses a method signature's token stream and
// extracts (method_name, arg_names, receiver_form). The signature
// shape is `fn NAME(RECV, NAME: TYPE, …) -> RETURN` where RECV is one
// of `self`, `&self`, `&mut self`. We need:
//
//   * method_name — for `t.<NAME>(args)` in the forwarding impl.
//   * arg_names   — for the comma-separated forward list.
//   * receiver    — to pick `as_ref()` vs `as_mut()` on the lock guard.
//
// Returns ("", vec![], "&self") on parse failure — the Hook-forwarding
// impl-emitter checks for empty method_name and skips when the parse
// can't be trusted.
fn extract_method_shape(sig: &[TokenTree]) -> (String, Vec<String>, String) {
    let mut iter = sig.iter().peekable();

    // Skip optional `pub` (interfaces don't have it but be defensive).
    while let Some(TokenTree::Ident(i)) = iter.peek() {
        let s = i.to_string();
        if s == "pub" {
            iter.next();
            continue;
        }
        break;
    }

    // Expect `fn`.
    match iter.next() {
        Some(TokenTree::Ident(i)) if i.to_string() == "fn" => {}
        _ => return (String::new(), Vec::new(), String::from("&self")),
    }

    // Method name.
    let method_name = match iter.next() {
        Some(TokenTree::Ident(i)) => i.to_string(),
        _ => return (String::new(), Vec::new(), String::from("&self")),
    };

    // Optional generics on the method itself — skip the `<…>` group's
    // tokens until matching `>`. Rare in Goish ifaces but defensive.
    if let Some(TokenTree::Punct(p)) = iter.peek() {
        if p.as_char() == '<' {
            iter.next();
            let mut depth = 1;
            while depth > 0 {
                match iter.next() {
                    Some(TokenTree::Punct(p)) if p.as_char() == '<' => depth += 1,
                    Some(TokenTree::Punct(p)) if p.as_char() == '>' => depth -= 1,
                    Some(_) => {}
                    None => return (method_name, Vec::new(), String::from("&self")),
                }
            }
        }
    }

    // Parameter list — a single Group with parens.
    let params_group = match iter.next() {
        Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis => g.clone(),
        _ => return (method_name, Vec::new(), String::from("&self")),
    };

    // Walk the param tokens, splitting on top-level commas.
    let mut top_level_params: Vec<Vec<TokenTree>> = vec![Vec::new()];
    for tt in params_group.stream() {
        if let TokenTree::Punct(p) = &tt {
            if p.as_char() == ',' {
                top_level_params.push(Vec::new());
                continue;
            }
        }
        top_level_params.last_mut().unwrap().push(tt);
    }

    // Drop trailing-empty (after final comma).
    if top_level_params
        .last()
        .map(|p| p.is_empty())
        .unwrap_or(false)
    {
        top_level_params.pop();
    }
    if top_level_params.is_empty() {
        return (method_name, Vec::new(), String::from("&self"));
    }

    // First param is the receiver. Detect `&mut self`, `&self`, `self`.
    let recv_str = top_level_params[0]
        .iter()
        .map(|t| t.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let receiver = if recv_str.contains("mut") && recv_str.contains("self") {
        "&mut self".to_string()
    } else if recv_str.contains("self") {
        "&self".to_string()
    } else {
        // Atypical — e.g. associated fn with no `self`. Skip forwarding.
        return (String::new(), Vec::new(), String::from("&self"));
    };

    // Each remaining param is `name: type`. Extract the leading ident
    // name. `name` may be preceded by `mut` or `_` patterns; we take
    // the LAST ident before the `:` to handle `mut foo: T`.
    let mut arg_names: Vec<String> = Vec::new();
    for param in top_level_params.iter().skip(1) {
        let mut last_ident: Option<String> = None;
        for tt in param {
            match tt {
                TokenTree::Ident(i) => {
                    let s = i.to_string();
                    // Skip pattern-binding `mut` or `ref` qualifiers.
                    if s == "mut" || s == "ref" {
                        continue;
                    }
                    last_ident = Some(s);
                }
                TokenTree::Punct(p) if p.as_char() == ':' => break,
                _ => break,
            }
        }
        match last_ident {
            Some(name) if name != "_" => arg_names.push(name),
            // Wildcard or unparseable — bail; caller falls back.
            _ => return (String::new(), Vec::new(), receiver),
        }
    }

    (method_name, arg_names, receiver)
}

// ─── goish::embed! — Go's //go:embed directive ──────────────────────
//
// Mirrors the Go declaration shape:
//
//   //go:embed hello.txt                 goish::embed! {
//   var s string                             #[embed("hello.txt")]
//                                            static s: string;
//   //go:embed image/* html/index.html
//   var content embed.FS                     #[embed("image/*", "html/index.html")]
//                                            static content: embed::FS;
//                                        }
//
// Patterns are interpreted relative to the directory of the source
// file containing the declaration (Go: "relative to the package
// directory containing the source file"), resolved at compile time via
// Span::local_file(). Semantics per src/embed/embed.go:
//   * no '.', '..', empty elements; no leading/trailing '/';
//   * a pattern naming a directory embeds the whole subtree,
//     excluding '.'/'_'-prefixed names unless prefixed with `all:`;
//   * glob elements support '*' and '?' (path.Match char classes are
//     rejected with a compile error);
//   * string / slice<byte> variables: exactly one pattern matching
//     exactly one file;
//   * every pattern must match at least one file.
//
// string / slice<byte> statics expand to `goish::lazy::Lazy` cells
// (contents still embedded at compile time via include_bytes!; the
// Lazy only defers the goish-string allocation). embed::FS statics
// are fully const.

#[proc_macro]
pub fn embed(input: TokenStream) -> TokenStream {
    match embed_impl(input) {
        Ok(ts) => ts,
        Err(msg) => format!("compile_error!({msg:?});").parse().unwrap(),
    }
}

fn embed_glob_match(pat: &str, name: &str) -> bool {
    // path.Match subset over a single element: '*' (any run of
    // non-separator chars) and '?' (one char). No char classes.
    let p: Vec<char> = pat.chars().collect();
    let n: Vec<char> = name.chars().collect();
    fn m(p: &[char], n: &[char]) -> bool {
        if p.is_empty() {
            return n.is_empty();
        }
        match p[0] {
            '*' => {
                for skip in 0..=n.len() {
                    if m(&p[1..], &n[skip..]) {
                        return true;
                    }
                }
                false
            }
            '?' => !n.is_empty() && m(&p[1..], &n[1..]),
            c => !n.is_empty() && n[0] == c && m(&p[1..], &n[1..]),
        }
    }
    m(&p, &n)
}

// Walk `dir` recursively, collecting files (rel paths under `rel`).
// Skips '.'/'_'-prefixed names unless `all`.
fn embed_walk(
    dir: &std::path::Path,
    rel: &str,
    all: bool,
    out: &mut Vec<String>,
) -> Result<(), String> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("goish::embed: reading {}: {}", dir.display(), e))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().into_string().map_err(|_| {
            format!("goish::embed: non-UTF-8 file name under {}", dir.display())
        })?;
        if !all && (name.starts_with('.') || name.starts_with('_')) {
            continue;
        }
        let sub_rel = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
        let path = e.path();
        if path.is_dir() {
            embed_walk(&path, &sub_rel, all, out)?;
        } else if path.is_file() {
            out.push(sub_rel);
        }
    }
    Ok(())
}

// Expand one pattern (Go semantics) into matching file rel-paths.
fn embed_expand(base: &std::path::Path, pattern: &str) -> Result<Vec<String>, String> {
    let (all, pat) = match pattern.strip_prefix("all:") {
        Some(rest) => (true, rest),
        None => (false, pattern),
    };
    if pat.is_empty() || pat.starts_with('/') || pat.ends_with('/') {
        return Err(format!("goish::embed: invalid pattern {pattern:?}"));
    }
    for el in pat.split('/') {
        if el.is_empty() || el == "." || el == ".." {
            return Err(format!("goish::embed: invalid pattern {pattern:?}"));
        }
        if el.contains('[') || el.contains(']') || el.contains('\\') {
            return Err(format!(
                "goish::embed: pattern {pattern:?}: character classes are not supported (only * and ?)"
            ));
        }
    }
    // Resolve glob elements level by level.
    let mut cur: Vec<String> = vec![String::new()]; // rel dirs ("" = base)
    let elements: Vec<&str> = pat.split('/').collect();
    for (i, el) in elements.iter().enumerate() {
        let last = i == elements.len() - 1;
        let mut next: Vec<String> = Vec::new();
        for prefix in &cur {
            let dir = if prefix.is_empty() { base.to_path_buf() } else { base.join(prefix) };
            if el.contains('*') || el.contains('?') {
                let mut entries: Vec<_> = std::fs::read_dir(&dir)
                    .map_err(|e| format!("goish::embed: reading {}: {}", dir.display(), e))?
                    .filter_map(|e| e.ok())
                    .collect();
                entries.sort_by_key(|e| e.file_name());
                for e in entries {
                    let Ok(name) = e.file_name().into_string() else { continue };
                    if embed_glob_match(el, &name) {
                        let sub = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
                        next.push(sub);
                    }
                }
            } else {
                let sub = if prefix.is_empty() { (*el).to_string() } else { format!("{prefix}/{el}") };
                if dir.join(el).exists() {
                    next.push(sub);
                }
            }
        }
        cur = next;
        if !last {
            // Intermediate elements must be directories.
            cur.retain(|p| base.join(p).is_dir());
        }
    }
    // Final expansion: files stay; directories embed their subtree.
    // Go: a glob match on a dot/underscore name is kept for the '*'
    // form at the top level but the recursive walk still excludes them.
    let mut out: Vec<String> = Vec::new();
    for p in cur {
        let full = base.join(&p);
        if full.is_dir() {
            embed_walk(&full, &p, all, &mut out)?;
        } else if full.is_file() {
            out.push(p);
        }
    }
    if out.is_empty() {
        return Err(format!("goish::embed: pattern {pattern:?}: no matching files found"));
    }
    Ok(out)
}

fn embed_impl(input: TokenStream) -> Result<TokenStream, String> {
    use proc_macro::TokenTree as TT;

    // local_file() may be relative to rustc's working directory (the
    // package root); canonicalize so emitted include_bytes! paths are
    // unambiguous absolutes.
    let base = proc_macro::Span::call_site()
        .local_file()
        .and_then(|p| std::fs::canonicalize(p).ok())
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .ok_or_else(|| "goish::embed: cannot resolve invoking source file".to_string())?;

    let mut toks = input.into_iter().peekable();
    let mut out = String::new();

    while toks.peek().is_some() {
        // #[embed("pat", ...)]
        match toks.next() {
            Some(TT::Punct(p)) if p.as_char() == '#' => {}
            Some(other) => return Err(format!("goish::embed: expected #[embed(...)], got {other}")),
            None => break,
        }
        let attr = match toks.next() {
            Some(TT::Group(g)) if g.delimiter() == proc_macro::Delimiter::Bracket => g,
            _ => return Err("goish::embed: expected #[embed(...)]".to_string()),
        };
        let mut patterns: Vec<String> = Vec::new();
        {
            let mut it = attr.stream().into_iter();
            match it.next() {
                Some(TT::Ident(id)) if id.to_string() == "embed" => {}
                _ => return Err("goish::embed: attribute must be #[embed(...)]".to_string()),
            }
            let args = match it.next() {
                Some(TT::Group(g)) if g.delimiter() == proc_macro::Delimiter::Parenthesis => g,
                _ => return Err("goish::embed: attribute must be #[embed(\"pattern\", ...)]".to_string()),
            };
            for t in args.stream() {
                match t {
                    TT::Literal(l) => {
                        let s = l.to_string();
                        let Some(stripped) = s.strip_prefix('"').and_then(|s| s.strip_suffix('"'))
                        else {
                            return Err("goish::embed: patterns must be plain string literals".to_string());
                        };
                        patterns.push(stripped.to_string());
                    }
                    TT::Punct(p) if p.as_char() == ',' => {}
                    other => return Err(format!("goish::embed: unexpected token {other} in pattern list")),
                }
            }
        }
        if patterns.is_empty() {
            return Err("goish::embed: at least one pattern required".to_string());
        }

        // [pub] static NAME : TYPE ;
        let mut vis = String::new();
        let mut t = toks.next();
        if let Some(TT::Ident(id)) = &t {
            if id.to_string() == "pub" {
                vis = "pub ".to_string();
                t = toks.next();
                // pub(crate) etc.
                if let Some(TT::Group(g)) = &t {
                    if g.delimiter() == proc_macro::Delimiter::Parenthesis {
                        vis = format!("pub({}) ", g.stream());
                        t = toks.next();
                    }
                }
            }
        }
        match &t {
            Some(TT::Ident(id)) if id.to_string() == "static" => {}
            _ => return Err("goish::embed: expected `static`".to_string()),
        }
        let name = match toks.next() {
            Some(TT::Ident(id)) => id.to_string(),
            _ => return Err("goish::embed: expected variable name".to_string()),
        };
        match toks.next() {
            Some(TT::Punct(p)) if p.as_char() == ':' => {}
            _ => return Err("goish::embed: expected `:` after variable name".to_string()),
        }
        let mut ty = String::new();
        for t in toks.by_ref() {
            if let TT::Punct(p) = &t {
                if p.as_char() == ';' {
                    break;
                }
            }
            ty.push_str(&t.to_string());
        }
        let ty_norm: String = ty.chars().filter(|c| !c.is_whitespace()).collect();

        // Expand patterns.
        let mut files: Vec<String> = Vec::new();
        for pat in &patterns {
            for f in embed_expand(&base, pat)? {
                if !files.contains(&f) {
                    files.push(f);
                }
            }
        }

        match ty_norm.as_str() {
            "string" | "goish::string" | "::goish::string" => {
                if patterns.len() != 1 || files.len() != 1 {
                    return Err(format!(
                        "goish::embed: {name}: string variables take one pattern matching one file"
                    ));
                }
                let abs = base.join(&files[0]);
                out.push_str(&format!(
                    "{vis}static {name}: ::goish::lazy::Lazy<::goish::string> = \
                     ::goish::lazy::Lazy::new(|| ::goish::string::from_bytes(\
                     include_bytes!({:?})));\n",
                    abs.display().to_string(),
                ));
            }
            "slice<byte>" | "slice<u8>" | "goish::slice<byte>" | "::goish::slice<byte>" => {
                if patterns.len() != 1 || files.len() != 1 {
                    return Err(format!(
                        "goish::embed: {name}: slice<byte> variables take one pattern matching one file"
                    ));
                }
                let abs = base.join(&files[0]);
                out.push_str(&format!(
                    "{vis}static {name}: ::goish::lazy::Lazy<::goish::slice<::goish::byte>> = \
                     ::goish::lazy::Lazy::new(|| ::goish::goslice::slice::__from_vec(\
                     include_bytes!({:?}).to_vec()));\n",
                    abs.display().to_string(),
                ));
            }
            "embed::FS" | "FS" | "goish::embed::FS" | "::goish::embed::FS" => {
                // Full entry table: files plus synthesized parent dirs,
                // sorted by (dir, base) like Go's sortedList.
                let mut entries: Vec<(String, bool)> = Vec::new(); // (rel, is_dir)
                for f in &files {
                    entries.push((f.clone(), false));
                    let mut p = f.as_str();
                    while let Some(i) = p.rfind('/') {
                        p = &p[..i];
                        if !entries.iter().any(|(e, d)| *d && e == p) {
                            entries.push((p.to_string(), true));
                        }
                    }
                }
                entries.sort_by(|a, b| {
                    let split = |s: &str| -> (String, String) {
                        match s.rfind('/') {
                            Some(i) => (s[..i].to_string(), s[i + 1..].to_string()),
                            None => (String::new(), s.to_string()),
                        }
                    };
                    split(&a.0).cmp(&split(&b.0))
                });
                let mut table = String::new();
                for (rel, is_dir) in &entries {
                    if *is_dir {
                        table.push_str(&format!(
                            "::goish::embed::__File {{ name: {:?}, data: b\"\" }},\n",
                            format!("{rel}/"),
                        ));
                    } else {
                        let abs = base.join(rel);
                        table.push_str(&format!(
                            "::goish::embed::__File {{ name: {:?}, data: include_bytes!({:?}) }},\n",
                            rel,
                            abs.display().to_string(),
                        ));
                    }
                }
                out.push_str(&format!(
                    "{vis}static {name}: ::goish::embed::FS = \
                     ::goish::embed::FS::__new(&[\n{table}]);\n",
                ));
            }
            other => {
                return Err(format!(
                    "goish::embed: {name}: unsupported type `{other}` \
                     (use string, slice<byte>, or embed::FS)"
                ));
            }
        }
    }

    out.parse()
        .map_err(|e| format!("goish::embed: generated code failed to parse: {e:?}"))
}
