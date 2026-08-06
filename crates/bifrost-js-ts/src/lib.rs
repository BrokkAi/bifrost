//! JavaScript and TypeScript language knowledge for Bifrost.
//!
//! Internal implementation detail of `brokk-bifrost`; no stability guarantees --
//! depend on `brokk-bifrost` instead.
//!
//! This crate sits between [`brokk_bifrost_core`] and `brokk-bifrost-analysis`.
//! It holds JS/TS *language knowledge* -- the two declaration walks, ESM and
//! CommonJS import parsing, `tsconfig`/`jsconfig` path-alias resolution, the
//! import binder and lexical binding index, the structural spec, test and clone
//! detection, semantic diagnostics, the type-owner resolution the definition
//! routes ask for, and the whole usage graph -- as plain functions and data. It
//! depends on no other Bifrost crate than core, so nothing here may name
//! `IAnalyzer`, `TreeSitterAnalyzer`, `JavascriptAnalyzer` or
//! `TypescriptAnalyzer`.
//!
//! # One crate, two dialects
//!
//! JavaScript and TypeScript are inseparable here: they share one module, one
//! `EdgePassId`, one usage strategy, one structural spec, one memo-cache type
//! and one `JsTsAnalyzerConfig`. The only per-dialect files are the two
//! declaration walks ([`javascript`] and [`typescript`]), and even those share
//! their model and syntax helpers.
//!
//! # Where the analyzer stayed
//!
//! Where analysis code would reach for an analyzer handle, the functions here
//! take [`providers::JsTsAnalyzerHost`] -- a core
//! [`brokk_bifrost_core::analyzer::CodeUnitIndex`] plus the memoized JS/TS
//! products the language logic resolves through. `analyzer/{js_ts, javascript,
//! typescript}/` in `brokk-bifrost-analysis` keeps the shim: the two analyzer
//! structs with their shared `JsTsMemoCaches` bucket and `AliasResolver`, the
//! moka-backed caching wrappers, both `CodeUnitIndex` and `IAnalyzer` impls,
//! both `LanguageAdapter` shells, both `LanguageSupport` registrations, and the
//! downcasts that produce the arguments.

pub mod clones;
pub mod diagnostics;
pub mod graph;
pub mod hierarchy;
pub mod identifiers;
pub mod imports;
pub mod javascript;
pub mod model;
pub mod parse;
pub mod providers;
pub mod queries;
pub mod structural;
pub mod syntax;
pub mod test_detection;
pub mod ts_owners;
pub mod tsconfig;
pub mod type_text;
pub mod typescript;
