// goish-macros — proc-macros for goish v1.
//
// `#[goish::main]` decorates a user's `fn main()` to:
//
//   1. emit the ELF entry point `_start` (assembly stub) which reads
//      argc/argv off the stack and tail-calls into `__goish_rt0`.
//   2. wrap the user's body in `#[no_mangle] extern "C" fn __goish_main`,
//      the symbol the runtime's rt0 hands control to.
//
// No `syn`/`quote`/`proc-macro2` deps — we work with raw `proc_macro`
// tokens. The user's body is preserved as a `TokenTree::Group` (never
// stringified) so non-ASCII char literals like `'é'` round-trip cleanly.

extern crate proc_macro;

use proc_macro::{Delimiter, TokenStream, TokenTree};

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
