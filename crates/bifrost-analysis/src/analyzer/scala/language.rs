//! The vendored tree-sitter Scala grammar, re-imported from `brokk-bifrost-jvm`.
//!
//! The vendor tree, `build.rs` and the `cc` build-dependency moved with the JVM
//! language crate. This module keeps the historical path so every call site
//! -- including `store/epoch.rs`'s `scala_epoch_before_scalachess_fqn_recovery`
//! prior-salt helper and the three `store/mod.rs` blob-eviction tests -- reads
//! the same constant it always did.
//!
//! This is the mirror image of the C++/Ruby situation, where analysis kept a
//! crates.io grammar dependency the language crate also uses. Here the grammar
//! is native source that only the JVM crate can build.

pub(crate) use brokk_bifrost_jvm::scala::language::LANGUAGE;
