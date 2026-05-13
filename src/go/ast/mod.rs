// go/ast — minimal Goish surface for Go's go/ast package.
//
// 66 stdlib call sites in the reasoner cache carry `Arc<dyn go::ast::Expr>`.
// Implementations (Ident, BasicLit, BinaryExpr, …) live in ports.

#![allow(non_camel_case_types, non_snake_case)]

use crate::types::int;

/// Go's `ast.Node` — the root of every AST class. Every Node has a
/// position span; the rest of the AST surface is the kind-specific
/// methods on Expr/Stmt/Decl.
pub trait Node: Send + Sync {
    fn Pos(&self) -> int;
    fn End(&self) -> int;
}

/// Go's `ast.Expr` — expression-level AST node.
pub trait Expr: Node {
    fn exprNode(&self) {}
}

/// Go's `ast.Stmt` — statement-level AST node.
pub trait Stmt: Node {
    fn stmtNode(&self) {}
}

/// Go's `ast.Decl` — top-level declaration node.
pub trait Decl: Node {
    fn declNode(&self) {}
}
