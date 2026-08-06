//! The analyzer-resident products Kotlin's language logic resolves through.
//!
//! `KotlinAnalyzer` owns four moka caches (two of them realm-scoped), three
//! `Arc<OnceLock<..>>` cells and two `PoolSafeMemo`s; every one of them stays
//! in `brokk-bifrost-analysis` because `IAnalyzer::update`/`update_all` rebuild
//! the analyzer wholesale through `Self::from_inner`, and the realm-keyed pairs
//! answer a strictly wider question than their Kotlin-only siblings. What
//! crosses the crate line is [`KotlinSource`], the same idiom `JavaSource`,
//! `ScalaSource` and `RubySource` landed.
//!
//! Two members carry more than their signature.
//! [`KotlinSource::external_index_is_empty`] and
//! [`KotlinSource::external_qualified_name_exists`] are the only two questions
//! Kotlin's resolution ladder asks `JvmExternalDeclarationIndex` -- the
//! classpath-artifact index built out of `analyzer/jvm/`, which is parked in
//! `brokk-bifrost-analysis` with the rest of the `semantic_model` band. The
//! answers are a `bool` each, so they cross where `JvmExternalType` cannot:
//! nothing in this crate ever holds an external type, and
//! [`crate::kotlin::types::KotlinTypeResolution::External`] therefore carries
//! no payload. This is `ScalaSource::simple_type_knownness`'s shape, narrowed
//! -- Kotlin's ladder needs only "does the classpath know this name", never
//! what the classpath knows about it.
//!
//! `KotlinAnalyzer` lives in `brokk-bifrost-analysis`; this crate never names
//! it.

use std::sync::Arc;

use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;
use brokk_bifrost_core::analyzer::{BoundedDefinitionLookup, CodeUnit, CodeUnitIndex, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};

/// The analyzer-resident products Kotlin's language logic resolves through, on
/// top of the two core capability traits it reads declarations and imports
/// with. The analyzer is the only implementor and every method forwards to one
/// of its own accessors or memo cells, so the cells stay where they are and no
/// free function below can reach past this surface.
pub trait KotlinSource: CodeUnitIndex + ImportAnalysisProvider {
    /// The analyzed live file set (`TreeSitterAnalyzer::all_files`).
    ///
    /// `CodeUnitIndex::analyzed_files` is a different query, so this is spelled
    /// out rather than inferred from the supertrait.
    fn all_files(&self) -> Vec<ProjectFile>;

    /// The file's `package` declaration.
    fn package_name_of(&self, file: &ProjectFile) -> Option<String>;

    /// The workspace's usage-definition index, as the bounded lookup contract.
    fn usage_definitions(&self) -> &dyn BoundedDefinitionLookup;

    /// The type identifiers a file spells, from the analyzer's persisted parse.
    fn type_identifiers_of(&self, file: &ProjectFile) -> Option<HashSet<String>>;

    /// The supertype names written on `code_unit`, unresolved.
    fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String>;

    /// The top-level declarations each Kotlin package exports, built once per
    /// analyzer generation. The uncached build is
    /// [`crate::kotlin::imports::build_kotlin_top_level_declarations_by_package`].
    fn top_level_declarations_by_package(&self) -> &HashMap<String, Arc<Vec<CodeUnit>>>;

    /// Whether the shared JVM dependency index holds nothing. See this module's
    /// note: the index behind it stays in `brokk-bifrost-analysis`.
    fn external_index_is_empty(&self) -> bool;

    /// Whether the shared JVM dependency index resolves `fqn` as seen from a
    /// file declaring `access_package`. See [`Self::external_index_is_empty`].
    fn external_qualified_name_exists(&self, fqn: &str, access_package: &str) -> bool;
}
