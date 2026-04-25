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
// tokens and do minimal structural manipulation. The assumption is the
// user writes `fn main() { ... }` (no args, optional `-> ()`).

extern crate proc_macro;

use proc_macro::{Delimiter, TokenStream, TokenTree};

#[proc_macro_attribute]
pub fn main(_attr: TokenStream, item: TokenStream) -> TokenStream {
    // The body is always the last token tree of `fn main(...) [-> T] { ... }`
    // — a brace-delimited Group. Pull it off; the rest (signature) we
    // discard and rewrite to our own.
    let mut tokens: Vec<TokenTree> = item.into_iter().collect();
    let body = match tokens.pop() {
        Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace => g,
        _ => panic!("#[goish::main] must be placed on `fn main() {{ ... }}`"),
    };
    let body_src = body.stream().to_string();

    // The output is two top-level items, plain text → re-parsed as Rust.
    //
    //   1. `_start`: assembly stub. Reads argc/argv off the kernel-supplied
    //      stack, aligns rsp to 16 bytes, and calls `__goish_rt0`. The
    //      `ud2` trap is dead code (rt0 is `-> !`) and just makes any
    //      accidental return crash loudly.
    //
    //   2. `__goish_main`: the user's body, exposed under a stable symbol
    //      so `extern "C" { fn __goish_main(); }` in the runtime resolves.
    let output = format!(
        r#"
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

        #[no_mangle]
        pub extern "C" fn __goish_main() {{
            {body}
        }}
        "#,
        body = body_src,
    );

    output.parse().expect("goish::main: emitted invalid Rust")
}
