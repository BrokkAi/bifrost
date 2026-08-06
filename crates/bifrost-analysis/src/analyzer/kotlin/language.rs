//! The pinned, vendored tree-sitter Kotlin grammar, re-imported from
//! `brokk-bifrost-jvm`.
//!
//! The vendor tree, `build.rs` and the `cc` build-dependency moved with the JVM
//! language crate. This module keeps the historical path so every call site
//! -- including `lexical_definitions.rs`'s `cfg(test)` reach-in -- reads the
//! same constant it always did. The grammar-contract tests moved with the
//! binding.

pub(crate) use brokk_bifrost_jvm::kotlin::language::LANGUAGE;
