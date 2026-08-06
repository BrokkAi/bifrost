//! The analyzer-resident products Scala's language logic resolves through.
//!
//! `ScalaAnalyzer` owns four moka caches, six `Arc<OnceLock<..>>` cells and two
//! `PoolSafeMemo`s; every one of them stays in `brokk-bifrost-analysis` because
//! `IAnalyzer::update`/`update_all` rebuild the analyzer wholesale through
//! `Self::from_inner`. What crosses the crate line is [`ScalaSource`], which is
//! how a free function reaches back for a memoized product without naming the
//! analyzer type -- the same idiom `RubySource` and `CppAnalysisSource` landed.
//!
//! [`ScalaSource::simple_type_knownness`] and [`ScalaSource::is_known_simple_term`]
//! are load-bearing beyond their signature. Both answer "does the workspace know
//! this bare Scala name", and both consult `JvmExternalDeclarationIndex` -- the
//! classpath-artifact index built out of `analyzer/jvm/`, which is parked in
//! `brokk-bifrost-analysis` with the rest of the `semantic_model` band. That
//! index is why they are trait members rather than moved bodies: the decision
//! they make is Scala's, but one of the facts it reads is not reachable from
//! this crate.
//!
//! The three types beneath the trait are the same story told about indexes
//! rather than about the analyzer. [`ScalaDefinitionIndex`] and
//! [`ScalaCallableFactsIndex`] are the exact slices of the analysis-side
//! `GlobalUsageDefinitionIndex` and `UsageFactsIndex` that the graph reads;
//! lowering either whole would move a genuinely analysis-side product for a
//! handful of questions, so the crate line is drawn at the answers -- the
//! `PhpCallableFacts` precedent. [`ScalaFileFacts`] is the same cut through the
//! analyzer's per-file `FileState`: thirteen fields of the twenty-five it
//! carries, decoded shim-side and handed across, the way Ruby's owner-relation
//! facts cross.

use std::sync::Arc;

use brokk_bifrost_core::analyzer::capabilities::{
    ImportAnalysisProvider, TypeAliasProvider, TypeHierarchyProvider,
};
use brokk_bifrost_core::analyzer::model::{
    CallableFacts, ImportInfo, ScalaExportInfo, SignatureMetadata,
};
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile, Range};
use brokk_bifrost_core::hash::{HashMap, HashSet};

use crate::scala::graph::inverted::ProjectTypes;
use crate::scala::supertypes::ScalaSupertypeLookupPath;

/// What the workspace can prove about a bare Scala type name at a site.
///
/// `Uncertain` is the answer that keeps the semantic-diagnostic pass honest: an
/// unresolved wildcard or aliased import means the name *may* be declared
/// somewhere this analyzer does not index, so reporting it would be a false
/// positive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalaTypeKnownness {
    Known,
    Absent,
    Uncertain,
}

/// The supertype, signature and trait facts a Scala owner's own file state
/// carries, decoded once by the analyzer that holds the state.
#[derive(Debug, Clone)]
pub struct ScalaForwardOwnerFacts {
    pub supertype_lookup_paths: Vec<ScalaSupertypeLookupPath>,
    pub signatures: Vec<String>,
    pub is_trait: bool,
}

pub trait ScalaSource:
    CodeUnitIndex + ImportAnalysisProvider + TypeAliasProvider + TypeHierarchyProvider
{
    /// What the workspace can prove about the bare type name `name` as written
    /// in `file`. See this module's note on why this is not a moved body.
    fn simple_type_knownness(&self, file: &ProjectFile, name: &str) -> ScalaTypeKnownness;

    /// Whether `name` names a value the workspace declares in `file`'s own
    /// package, source-side or on the classpath.
    fn is_known_simple_term(&self, file: &ProjectFile, name: &str) -> bool;

    /// The owner the parser recorded for `code_unit`, without the fq-name
    /// segment-pop fallback [`CodeUnitIndex::parent_of`] layers on top.
    fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit>;

    /// The `export` clauses `owner` declares.
    fn export_infos_for_owner(&self, owner: &CodeUnit) -> Vec<ScalaExportInfo>;

    /// `code_unit`'s own declaration facts, or `None` when its file state does
    /// not declare it or its raw supertypes and structured lookup paths
    /// disagree in length.
    fn forward_owner_facts(&self, code_unit: &CodeUnit) -> Option<ScalaForwardOwnerFacts>;

    /// Whether `code_unit` is a `trait` rather than a `class`/`object`.
    fn is_scala_trait_declaration(&self, code_unit: &CodeUnit) -> bool;

    /// The workspace-wide definition index, in the two shapes the graph asks it
    /// for.
    ///
    /// Not a `&dyn` like [`ScalaDefinitionIndex`] below: the analyzer's handle
    /// is built per call and merges every language's shards, so it can never be
    /// lent out for this crate to hold. Same reason `CppWorkspaceSource` names
    /// its two lookups one at a time.
    fn definitions_by_normalized_fqn(&self, normalized: &str) -> Vec<CodeUnit>;

    /// Types declared in `package` whose simple type name is `simple`. See
    /// [`Self::definitions_by_normalized_fqn`].
    fn types_in_package(&self, package: &str, simple: &str) -> Vec<CodeUnit>;

    /// The analyzer-cached [`ProjectTypes`], built once per analyzer generation.
    ///
    /// The `OnceLock` that caches it stays on the analyzer, because
    /// `IAnalyzer::update`/`update_all` rebuild the analyzer wholesale and the
    /// cell has to be reset with it.
    fn project_types(&self) -> Arc<ProjectTypes>;

    /// Count a targeted query parse against the analyzer's counter.
    ///
    /// Called from production code in [`crate::scala::graph::inverted`], which
    /// is why it is on the trait at all; the counter itself stays on the
    /// analyzer. The default is a no-op because the two gates are not the same
    /// gate: Cargo turns this crate's `test-support` on for the whole build
    /// graph whenever `brokk-bifrost-analysis`'s dev-dependencies are in play,
    /// while the analyzer-side counter is read through `AnalyzerTestHooks` on
    /// *that* crate.
    #[cfg(any(test, feature = "test-support"))]
    fn record_query_parse(&self) {}

    /// Count a targeted query walk. See [`Self::record_query_parse`].
    #[cfg(any(test, feature = "test-support"))]
    fn record_query_walk(&self) {}
}

/// The *dispatching* analyzer's view a targeted find-references scan needs.
///
/// Not [`ScalaSource`]: the query is issued against whatever analyzer the
/// caller holds, which in a mixed workspace is a `MultiAnalyzer` whose
/// definition index merges every language's shards and whose enclosing-unit and
/// range answers cross language boundaries. A Scala class is equally nameable
/// from Java and Kotlin, so collapsing these three onto the Scala analyzer
/// would silently narrow the scan -- the trap the Python pass recorded.
///
/// Three free-standing methods rather than a `CodeUnitIndex` supertrait,
/// because `dyn IAnalyzer` cannot be unsized to another trait object and the
/// shim therefore has to wrap it; wrapping should cost three forwards, not
/// forty.
pub trait ScalaWorkspaceSource {
    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit>;
    fn ranges(&self, code_unit: &CodeUnit) -> Vec<Range>;

    /// See [`ScalaSource::definitions_by_normalized_fqn`]; this one answers
    /// from every language's shard.
    fn definitions_by_normalized_fqn(&self, normalized: &str) -> Vec<CodeUnit>;
}

/// The slice of the workspace declaration index [`ProjectTypes`] holds.
///
/// Eleven questions out of `GlobalUsageDefinitionIndex`'s surface, three of
/// them already spelled by core's `BoundedDefinitionLookup` and the rest the
/// index's own secondary catalogs. The four `&[CodeUnit]` returns borrow on
/// purpose: the whole-workspace scan asks them per reference, and the analysis
/// index answers each from a map it already owns.
pub trait ScalaDefinitionIndex: Send + Sync {
    fn by_fqn(&self, fqn: &str) -> &[CodeUnit];
    fn by_normalized_fqn(&self, normalized: &str) -> &[CodeUnit];
    fn types_in_package(&self, package: &str, simple: &str) -> &[CodeUnit];
    fn identifier(&self, ident: &str) -> &[CodeUnit];
    fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit>;
    fn fqn_exists(&self, fqn: &str) -> bool;
    fn package_exists(&self, package: &str) -> bool;
    fn package_container_exists(&self, package: &str) -> bool;
    fn child_packages(&self, package: &str) -> Vec<String>;

    /// Direct children of `owner_fqn` named `name`, falling back to the
    /// normalized spelling when the exact fq misses. Both spellings are the
    /// caller's because normalization is Scala's `$`-companion rule, which the
    /// index does not know.
    fn members_for_owner_name<'a>(
        &'a self,
        owner_fqn: &str,
        normalized_owner_fqn: &str,
        name: &str,
    ) -> Vec<&'a CodeUnit>;

    /// Every `(package, simple type name) -> declarations` entry the index
    /// catalogs, in the index's own iteration order.
    fn package_types(&self) -> ScalaPackageTypeEntries<'_>;
}

/// The `(package, simple type name) -> declarations` stream
/// [`ScalaDefinitionIndex::package_types`] yields. Boxed rather than `impl
/// Iterator` because the index crosses the crate line as a trait object.
pub type ScalaPackageTypeEntries<'a> =
    Box<dyn Iterator<Item = (&'a (String, String), &'a [CodeUnit])> + 'a>;

/// The one question [`ProjectTypes`] asks the workspace usage-facts index.
pub trait ScalaCallableFactsIndex: Send + Sync {
    fn fact_for_declaration(&self, declaration: &CodeUnit) -> Option<&CallableFacts>;
}

/// The thirteen per-file declaration facts the Scala graph reads out of the
/// analyzer's persisted file state, decoded shim-side.
///
/// The analyzer's `FileState` carries twenty-five, and most of the rest are
/// other languages' columns or store bookkeeping. Handing the decoded record
/// across rather than the state itself is what keeps `tree_sitter_analyzer` out
/// of this crate.
#[derive(Debug, Clone)]
pub struct ScalaFileFacts {
    pub source: String,
    pub package_name: String,
    pub declarations: HashSet<CodeUnit>,
    pub definition_lookup_units: HashSet<CodeUnit>,
    pub imports: Vec<ImportInfo>,
    pub scala_exports: HashMap<CodeUnit, Vec<ScalaExportInfo>>,
    pub supertype_lookup_paths: HashMap<CodeUnit, Vec<String>>,
    pub signatures: HashMap<CodeUnit, Vec<String>>,
    pub signature_metadata: HashMap<CodeUnit, Vec<SignatureMetadata>>,
    pub ranges: HashMap<CodeUnit, Vec<Range>>,
    pub children: HashMap<CodeUnit, Vec<CodeUnit>>,
    pub scala_traits: HashSet<CodeUnit>,
    pub type_aliases: HashSet<CodeUnit>,
}
