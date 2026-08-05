//! PHP's bundled tree-sitter query assets.
//!
//! The `.scm` files ship inside this crate rather than
//! `brokk-bifrost-analysis/resources/` and are embedded at compile time, so a
//! consumer never resolves them from a runtime path. `brokk-bifrost-analysis`
//! folds [`PHP_QUERY_ASSETS`] into the per-language store epoch exactly as it
//! folds its own `resources/treesitter/<lang>/` files: the entry paths keep the
//! historical `treesitter/php/` prefix so the epoch's per-language filter is one
//! rule rather than two.

/// Directory the query assets live in, relative to this crate's root.
///
/// Reported by `PhpAdapter::query_directory()`. The relocation from the analysis
/// crate is why the PHP store-epoch salt bumped: the salted content now comes
/// from this crate's `resources/`, not analysis's.
pub const PHP_QUERY_DIRECTORY: &str = "resources/treesitter/php";

/// Compile-time embedded `.scm` query files as `(relative_path, contents)`.
///
/// PHP ships no `identifiers.scm`; type identifiers come from the declaration
/// walk in [`crate::declarations`], not from a query.
pub const PHP_QUERY_ASSETS: &[(&str, &str)] = &[
    (
        "treesitter/php/definitions.scm",
        include_str!("../resources/treesitter/php/definitions.scm"),
    ),
    (
        "treesitter/php/imports.scm",
        include_str!("../resources/treesitter/php/imports.scm"),
    ),
];
