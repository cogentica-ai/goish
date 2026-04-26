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
    let prefix: TokenStream = r#"
        #[no_mangle]
        pub extern "C" fn __goish_main()
    "#
    .parse()
    .expect("goish::main: invalid fn prefix");

    let body_stream: TokenStream = TokenTree::Group(body).into();

    let mut out = asm;
    out.extend(prefix);
    out.extend(body_stream);
    out
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
    impl_text.push_str("            ::goish::encoding::json::Value::Null => return (__zero(), ::goish::nil),\n");
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
        impl_text.push_str("                    if __err != ::goish::nil { return (__out, __err); }\n");
        let _ = write!(impl_text, "                    __out.{} = __val;\n", f.name);
        impl_text.push_str("                }\n");
        impl_text.push_str("            }\n");
        impl_text.push_str("        }\n");
    }
    impl_text.push_str("        (__out, ::goish::nil)\n");
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
            "        {{\n            let (__val, __err) = <{} as ::goish::reflect::FromReflectValue>::from_reflect_value(__fields[{}].clone());\n            if __err != ::goish::nil {{ return (__zero(), __err); }}\n            __out.{} = __val;\n        }}\n",
            f.ty, i, f.name
        );
    }
    impl_text.push_str("        (__out, ::goish::nil)\n");
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
        impl_text.push_str("                if __err != ::goish::nil { return __err; }\n");
        let _ = write!(impl_text, "                self.{} = __val;\n", f.name);
        impl_text.push_str("                ::goish::nil\n");
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
