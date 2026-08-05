//! C++'s bundled tree-sitter query assets.
//!
//! The `.scm` files ship inside this crate rather than
//! `brokk-bifrost-analysis/resources/` and are embedded at compile time, so a
//! consumer never resolves them from a runtime path. `brokk-bifrost-analysis`
//! folds [`CPP_QUERY_ASSETS`] into the per-language store epoch exactly as it
//! folds its own `resources/treesitter/<lang>/` files: the entry paths keep the
//! historical `treesitter/cpp/` prefix so the epoch's per-language filter is one
//! rule rather than two.

/// Directory the query assets live in, relative to this crate's root.
///
/// Reported by `CppAdapter::query_directory()`. The relocation from the analysis
/// crate is why the C++ store-epoch salt bumped: the salted content now comes
/// from this crate's `resources/`, not analysis's.
pub const CPP_QUERY_DIRECTORY: &str = "resources/treesitter/cpp";

/// Compile-time embedded `.scm` query files as `(relative_path, contents)`.
pub const CPP_QUERY_ASSETS: &[(&str, &str)] = &[
    (
        "treesitter/cpp/definitions.scm",
        include_str!("../resources/treesitter/cpp/definitions.scm"),
    ),
    (
        "treesitter/cpp/imports.scm",
        include_str!("../resources/treesitter/cpp/imports.scm"),
    ),
    (
        "treesitter/cpp/identifiers.scm",
        include_str!("../resources/treesitter/cpp/identifiers.scm"),
    ),
];
