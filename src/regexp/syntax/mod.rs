// go: package regexp/syntax
//
// regexp/syntax — Go's `regexp/syntax` package, ported.
//
// Source: go1.25.5/src/regexp/syntax/
//
// Go's `regexp/syntax` is the half of regexp that turns a pattern into
// something an engine can run: `Parse` builds a `Regexp` AST,
// `Simplify` rewrites counted repetition away, and `Compile` lowers
// the AST to a `Prog` — an instruction array. The engines in `regexp`
// itself then run the Prog.
//
// §2c is the reason this exists: goish's matcher backtracks over an
// AST and is exponential on `(a+)+$`, and the fix named in the roadmap
// is this construction. It arrives in stages, and each stage is inert
// until the last one rewires `regexp::mod`.
//
//   stage 1 (here)  prog.rs — the Prog/Inst representation,
//                   parse.rs — the Flags bitset it reads
//   stage 2a (here) regexp.rs, op_string.rs — the AST and Op.String
//   stage 2b        parse.rs — the parser (and Flags moves back to it)
//   stage 3         simplify.rs, compile.rs — AST -> Prog
//   stage 4         regexp/exec.rs — the NFA, and the swap

pub mod op_string;
pub mod parse;
pub mod perl_groups;
pub mod prog;
pub mod regexp;

pub use parse::{
    ClassNL, DotNL, Flags, FoldCase, Literal, MatchNL, NonGreedy, OneLine, POSIX, Perl, PerlX,
    Simple, UnicodeGroups, WasDollar,
};
pub use prog::{
    EmptyBeginLine, EmptyBeginText, EmptyEndLine, EmptyEndText, EmptyNoWordBoundary, EmptyOp,
    EmptyOpContext, EmptyWordBoundary, Inst, InstAlt, InstAltMatch, InstCapture, InstEmptyWidth,
    InstFail, InstMatch, InstNop, InstOp, InstRune, InstRune1, InstRuneAny, InstRuneAnyNotNL,
    IsWordChar, Prog,
};
pub use regexp::{
    Op, OpAlternate, OpAnyChar, OpAnyCharNotNL, OpBeginLine, OpBeginText, OpCapture, OpCharClass,
    OpConcat, OpEmptyMatch, OpEndLine, OpEndText, OpLiteral, OpNoMatch, OpNoWordBoundary, OpPlus,
    OpQuest, OpRepeat, OpStar, OpWordBoundary, Regexp,
};
pub use parse::{Error, ErrorCode, Parse};
