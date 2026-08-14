//! Rust's bundled tree-sitter query assets.
//!
//! The `.scm` files ship inside this crate rather than
//! `brokk-bifrost-analysis/resources/` and are embedded at compile time, so a
//! consumer never resolves them from a runtime path. `brokk-bifrost-analysis`
//! folds [`RUST_QUERY_ASSETS`] into the per-language store epoch exactly as it
//! folds its own `resources/treesitter/<lang>/` files: the entry paths keep the
//! historical `treesitter/rust/` prefix so the epoch's per-language filter is
//! one rule rather than two.

/// Directory the query assets live in, relative to this crate's root.
///
/// Reported by `RustAdapter::query_directory()`. The relocation from the
/// analysis crate is why the Rust store-epoch salt bumped: the salted content
/// now comes from this crate's `resources/`, not analysis's.
pub const RUST_QUERY_DIRECTORY: &str = "resources/treesitter/rust";

/// Compile-time embedded `.scm` query files as `(relative_path, contents)`.
pub const RUST_QUERY_ASSETS: &[(&str, &str)] = &[
    (
        "treesitter/rust/definitions.scm",
        include_str!("../resources/treesitter/rust/definitions.scm"),
    ),
    (
        "treesitter/rust/imports.scm",
        include_str!("../resources/treesitter/rust/imports.scm"),
    ),
];
