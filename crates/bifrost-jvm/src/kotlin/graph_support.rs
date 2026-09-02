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
use brokk_bifrost_core::analyzer::model::ImportInfo;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::{BoundedDefinitionLookup, CodeUnit, CodeUnitIndex, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};

use crate::proof::JvmRetainedExternalIndex;
use crate::realm::JvmSourceRealm;

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

    /// Run one synchronous resolution step against a step-local bounded
    /// definition lookup. The callback keeps the lookup owned by the analysis
    /// implementation instead of publishing it as analyzer-generation state.
    fn with_usage_definitions(
        &self,
        token: QueryToken<'_>,
        read: &mut dyn FnMut(&dyn BoundedDefinitionLookup),
    );

    /// The type identifiers a file spells, from the analyzer's persisted parse.
    fn type_identifiers_of(&self, file: &ProjectFile) -> Option<HashSet<String>>;

    /// The supertype names written on `code_unit`, unresolved.
    fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String>;

    /// Resolve one declaration's ancestors from facts the caller already
    /// holds, memoized when the source keeps an ancestor cache.
    ///
    /// The descendant-index build hydrates declaration facts in batches and
    /// then resolves every candidate through `type_by_fqn`. Without this hook
    /// each candidate's resolution bypasses the analyzer's ancestor memo, so
    /// the two scope variants one scan request builds re-derive the whole
    /// workspace's ancestry, and later hierarchy questions start cold (#2868).
    fn resolved_ancestors_from_hydrated_facts(
        &self,
        token: QueryToken<'_>,
        owner: &CodeUnit,
        raw_supertypes: &[String],
        imports: &[ImportInfo],
        _realm: Option<&JvmSourceRealm<'_>>,
        type_by_fqn: &mut dyn FnMut(&str) -> Option<CodeUnit>,
    ) -> Vec<CodeUnit> {
        crate::kotlin::hierarchy::kotlin_resolve_ancestors_from_facts(
            self,
            token,
            owner,
            raw_supertypes,
            imports,
            type_by_fqn,
        )
    }

    /// The top-level declarations each Kotlin package exports, built once per
    /// analyzer generation. The uncached build is
    /// [`crate::kotlin::imports::build_kotlin_top_level_declarations_by_package`].
    fn top_level_declarations_by_package(&self) -> &HashMap<String, Arc<Vec<CodeUnit>>>;

    /// Whether the shared JVM dependency index holds nothing. See this module's
    /// note: the index behind it stays in `brokk-bifrost-analysis`.
    ///
    /// This and [`Self::external_qualified_name_exists`] are the *resolver's*
    /// questions: they build the index on demand to answer. Diagnostics must
    /// not, so they ask the two `retained_` members below instead.
    fn external_index_is_empty(&self) -> bool;

    /// Whether the shared JVM dependency index resolves `fqn` as seen from a
    /// file declaring `access_package`. See [`Self::external_index_is_empty`].
    fn external_qualified_name_exists(&self, fqn: &str, access_package: &str) -> bool;

    /// What the analyzer has retained of the JVM dependency surface, read
    /// without building it. See [`crate::proof`] on why a diagnostic peeks.
    fn retained_external_index(&self) -> JvmRetainedExternalIndex;

    /// [`Self::external_qualified_name_exists`] against the retained index
    /// only. Answers `false` for an unbuilt index, which
    /// [`Self::retained_external_index`] reports separately so the caller can
    /// tell "not there" from "nothing to look in".
    fn retained_external_qualified_name_exists(&self, fqn: &str, access_package: &str) -> bool;
}
