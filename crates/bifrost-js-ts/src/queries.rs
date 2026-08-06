//! JavaScript's and TypeScript's bundled tree-sitter query assets.
//!
//! The `.scm` files ship inside this crate rather than
//! `brokk-bifrost-analysis/resources/` and are embedded at compile time, so a
//! consumer never resolves them from a runtime path. `brokk-bifrost-analysis`
//! folds [`JS_TS_QUERY_ASSETS`] into the per-language store epoch: the entry
//! paths keep the historical `treesitter/javascript/` and
//! `treesitter/typescript/` prefixes so the epoch's per-language filter is one
//! rule rather than two.
//!
//! These were the last six entries in that crate's `EMBEDDED_QUERIES` table and
//! the last two directories under its `resources/treesitter/`; both are now
//! gone, and every language's query assets live in its own crate.

/// Directory JavaScript's query assets live in, relative to this crate's root.
///
/// Reported by `JavascriptAdapter::query_directory()`. The relocation from the
/// analysis crate is why the JavaScript store-epoch salt bumped: the salted
/// content now comes from this crate's `resources/`, not analysis's.
pub const JAVASCRIPT_QUERY_DIRECTORY: &str = "resources/treesitter/javascript";

/// Directory TypeScript's query assets live in, relative to this crate's root.
///
/// Reported by `TypescriptAdapter::query_directory()`, and the reason the
/// TypeScript store-epoch salt bumped alongside JavaScript's.
pub const TYPESCRIPT_QUERY_DIRECTORY: &str = "resources/treesitter/typescript";

/// Compile-time embedded `.scm` query files as `(relative_path, contents)`.
///
/// One table for two languages, matching everything else in this crate: the two
/// dialects share a module, an edge pass, a structural spec and a config, so
/// splitting the asset table would be the only place they were treated as
/// separate.
pub const JS_TS_QUERY_ASSETS: &[(&str, &str)] = &[
    (
        "treesitter/javascript/definitions.scm",
        include_str!("../resources/treesitter/javascript/definitions.scm"),
    ),
    (
        "treesitter/javascript/imports.scm",
        include_str!("../resources/treesitter/javascript/imports.scm"),
    ),
    (
        "treesitter/javascript/identifiers.scm",
        include_str!("../resources/treesitter/javascript/identifiers.scm"),
    ),
    (
        "treesitter/typescript/definitions.scm",
        include_str!("../resources/treesitter/typescript/definitions.scm"),
    ),
    (
        "treesitter/typescript/imports.scm",
        include_str!("../resources/treesitter/typescript/imports.scm"),
    ),
    (
        "treesitter/typescript/identifiers.scm",
        include_str!("../resources/treesitter/typescript/identifiers.scm"),
    ),
];
