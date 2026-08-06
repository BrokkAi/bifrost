//! JVM language knowledge for Bifrost.
//!
//! Internal implementation detail of `brokk-bifrost`; no stability guarantees --
//! depend on `brokk-bifrost` instead.
//!
//! This crate sits between [`brokk_bifrost_core`] and `brokk-bifrost-analysis`.
//! It holds Java, Scala and Kotlin *language knowledge* as plain functions and
//! data, and it ships the two vendored tree-sitter grammars those languages
//! parse with. It depends on no other Bifrost crate than core, so nothing here
//! may name `IAnalyzer`, `TreeSitterAnalyzer`, `JavaAnalyzer`, `ScalaAnalyzer`
//! or `KotlinAnalyzer`.
//!
//! # Why one crate for three languages
//!
//! Java, Scala and Kotlin sources in one workspace compile to one classpath, so
//! a declaration written in any of them can be named from the other two.
//! [`realm::JvmSourceRealm`] is the view that closes that gap, and it makes
//! Kotlin's import, type and hierarchy routes depend on Java's and Scala's
//! declarations; Java's forward scan depends on Scala syntax in the other
//! direction. The three languages also share one
//! [`brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig`]. Splitting them
//! would need a cycle between crates.
//!
//! # The vendored grammars
//!
//! Scala and Kotlin have no crates.io grammar here. `build.rs` compiles
//! `vendor/tree-sitter-{scala,kotlin}/src/{parser.c,scanner.c}` through `cc`
//! under per-grammar `-D` symbol renaming, so the vendored parsers cannot
//! collide with the crates.io `tree-sitter-scala` that `brokk-bifrost-analysis`
//! keeps as a dev-dependency for two deliberately-different-parser call sites.
//! [`scala::language::LANGUAGE`] and [`kotlin::language::LANGUAGE`] bind the
//! renamed entry points; `brokk-bifrost-analysis` re-imports both, because its
//! store-epoch helper and three blob-eviction tests parse with them directly.
//!
//! Where analysis code would reach for an analyzer handle, the functions here
//! take a source trait -- a core
//! [`brokk_bifrost_core::analyzer::CodeUnitIndex`] plus the memoized products
//! the language logic resolves through. `analyzer/{java,scala,kotlin,jvm}/` in
//! `brokk-bifrost-analysis` keeps the shims: the three analyzer structs with
//! their moka caches and `OnceLock` cells, the `CodeUnitIndex` and `IAnalyzer`
//! impls, the three adapter forwarding shells, the three SPI blocks, and the
//! downcasts that produce the arguments -- including the three that build a
//! [`realm::JvmSourceRealm`].

pub mod kotlin;
pub mod queries;
pub mod realm;
pub mod scala;
