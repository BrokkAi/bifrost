//! Shared, schema-neutral S-expression concrete syntax.
//!
//! RQL, RQLP, and Rune IR formatting share this byte-spanned parser and
//! formatter. Schema-specific lowering and validation stay in their owning
//! modules.

mod format;
mod syntax;

pub(crate) use format::{DEFAULT_SEXP_LINE_WIDTH, SexpFormatOptions, format_sexp_document};
#[cfg(test)]
pub(crate) use syntax::MAX_SEXP_DEPTH;
pub(crate) use syntax::{
    Expr, ExprKind, ParseError, ParsedSexp, ParsedSexpDocument, parse_sexp, parse_sexp_document,
};
