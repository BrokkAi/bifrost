//! The analyzer-resident products Scala's language logic resolves through.
//!
//! `ScalaAnalyzer` owns four moka caches, six `Arc<OnceLock<..>>` cells and two
//! `PoolSafeMemo`s; every one of them stays in `brokk-bifrost-analysis` because
//! `IAnalyzer::update`/`update_all` rebuild the analyzer wholesale through
//! `Self::from_inner`. What crosses the crate line is [`ScalaSource`], which is
//! how a free function reaches back for a memoized product without naming the
//! analyzer type -- the same idiom `RubySource` and `CppSource` landed.
//!
//! [`ScalaSource::simple_type_proof`] and [`ScalaSource::simple_term_proof`]
//! are load-bearing beyond their signature. Both answer "what does every
//! retained surface prove about this bare Scala name", and both consult
//! `JvmExternalDeclarationIndex` -- the
//! classpath-artifact index built out of `analyzer/jvm/`, which is parked in
//! `brokk-bifrost-analysis` with the rest of the `semantic_model` band. That
//! index is why they are trait members rather than moved bodies: the decision
//! they make is Scala's, but one of the facts it reads is not reachable from
//! this crate.
//!
//! The types beneath the trait are the same story told about query-shaped
//! data rather than about the analyzer. [`ScalaDefinitionIndex`] and
//! [`ScalaCallableFactsIndex`] expose only the request-local relational answers
//! the graph reads. [`ScalaFileFacts`] is the same cut through the analyzer's
//! per-file `FileState`: thirteen fields of the twenty-five it
//! carries, decoded shim-side and handed across, the way Ruby's owner-relation
//! facts cross. [`ScalaFileFactsRef`] and [`ScalaFileFactsProvider`] are how a
//! targeted query reads those facts one file at a time instead of holding the
//! whole-workspace map (#3142).

use std::sync::Arc;

use brokk_bifrost_core::analyzer::capabilities::{
    ImportAnalysisProvider, TypeAliasProvider, TypeHierarchyProvider,
};
use brokk_bifrost_core::analyzer::fq_name::FqName;
use brokk_bifrost_core::analyzer::model::{ImportInfo, ScalaExportInfo, SignatureMetadata};
use brokk_bifrost_core::analyzer::{
    CodeUnit, CodeUnitIndex, ProjectFile, Range, RelationalCallableFact,
};
use brokk_bifrost_core::hash::{HashMap, HashSet};

use crate::proof::JvmActiveSemanticModel;

use crate::scala::graph::inverted::ProjectTypes;
use crate::scala::supertypes::ScalaSupertypeLookupPath;

/// Every surface a Scala name lookup consults, and what each proved.
///
/// This is [`crate::proof::JvmNameProof`], the vocabulary Java and Kotlin
/// answer in too. It replaces an earlier `Known | Absent | Uncertain`
/// tri-state: `Uncertain` collapsed two different facts -- "an import points
/// somewhere I cannot follow" and "nothing past the workspace is readable" --
/// into one silent suppression, and #1619 requires each to carry its own
/// reason.
pub use crate::proof::JvmNameProof as ScalaNameProof;

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
    /// What every retained surface proves about the bare type name `name` as
    /// written in `file`. See this module's note on why this is not a moved
    /// body: Scala's ladder needs the jar index, the resolved-import set and
    /// the package projection, all of which are analyzer-resident.
    ///
    /// `model` is the dispatching analyzer's active dependency model, passed in
    /// because a language analyzer only knows its own generation. Every tier
    /// reads retained state; see [`crate::proof`] on why a diagnostic may not
    /// build the jar index.
    fn simple_type_proof(
        &self,
        file: &ProjectFile,
        name: &str,
        model: &dyn JvmActiveSemanticModel,
    ) -> ScalaNameProof;

    /// [`Self::simple_type_proof`] for a bare term: a value or `object` name
    /// rather than a type name.
    fn simple_term_proof(
        &self,
        file: &ProjectFile,
        name: &str,
        model: &dyn JvmActiveSemanticModel,
    ) -> ScalaNameProof;

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
    /// from the dispatching workspace.
    fn definitions_by_normalized_fqn(&self, normalized: &str) -> Vec<CodeUnit>;
}

/// The request-local relational definition surface [`ProjectTypes`] reads.
pub trait ScalaDefinitionIndex: Send + Sync {
    fn by_fqn(&self, fqn: &str) -> Vec<CodeUnit>;
    fn by_normalized_fqn(&self, normalized: &str) -> Vec<CodeUnit>;
    fn types_in_package(&self, package: &str, simple: &str) -> Vec<CodeUnit>;
    fn identifier(&self, ident: &str) -> Vec<CodeUnit>;
    fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit>;
    fn fqn_exists(&self, fqn: &str) -> bool;
    fn package_exists(&self, package: &str) -> bool;
    fn package_container_exists(&self, package: &str) -> bool;
    fn child_packages(&self, package: &str) -> Vec<String>;

    /// Direct children of one already-resolved structured owner named `name`.
    /// Callers that hold a `CodeUnit` must use this form so the lookup retains
    /// the declaration's authoritative segment kinds instead of rendering and
    /// reparsing them as an unresolved user path.
    fn members_for_structured_owner(&self, owner: &FqName, name: &str) -> Vec<CodeUnit>;

    /// Direct children of `owner_fqn` named `name`, falling back to the
    /// normalized spelling when the exact fq misses. Both spellings are the
    /// caller's because normalization is Scala's `$`-companion rule, which the
    /// index does not know.
    fn members_for_owner_name(
        &self,
        owner_fqn: &str,
        normalized_owner_fqn: &str,
        name: &str,
    ) -> Vec<CodeUnit>;

    /// Every simple type-name bucket in one exact package.
    fn package_types_in(&self, package: &str) -> Vec<(String, Vec<CodeUnit>)>;
}

/// The one question [`ProjectTypes`] asks the workspace usage-facts index.
pub trait ScalaCallableFactsIndex: Send + Sync {
    fn facts_for_declaration(&self, declaration: &CodeUnit) -> Vec<RelationalCallableFact>;
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

/// One file's [`ScalaFileFacts`], either borrowed from a whole-workspace read
/// or rehydrated on demand. The borrowed arm keeps the eager whole-workspace
/// consumer (the inverted edge build) allocation-free; the owned arm is what a
/// targeted query pays per file it actually touches (#3142).
pub enum ScalaFileFactsRef<'a> {
    Borrowed(&'a ScalaFileFacts),
    Owned(Arc<ScalaFileFacts>),
}

impl std::ops::Deref for ScalaFileFactsRef<'_> {
    type Target = ScalaFileFacts;

    fn deref(&self) -> &ScalaFileFacts {
        match self {
            Self::Borrowed(facts) => facts,
            Self::Owned(facts) => facts,
        }
    }
}

/// The per-file facts source behind a targeted usage query's
/// [`crate::scala::graph::inverted::ProjectTypes`].
///
/// The query's workspace-wide sweep derives the type-namespace structures it
/// needs and drops the rest, so the facts a later lookup reads are rehydrated
/// one file at a time through the analyzer's ordinary store path. The
/// implementation owns the caching policy; a file's facts are immutable for
/// the query's generation, so one hydration per file per query is the
/// contract, exactly as the eager read hydrated once.
pub trait ScalaFileFactsProvider: Send + Sync {
    /// The persisted facts for `file`, or `None` when the analyzer holds no
    /// state for it -- the same answer the eager whole-workspace map gives by
    /// omission, so callers must not fall back to another source on `None`.
    fn file_facts(&self, file: &ProjectFile) -> Option<Arc<ScalaFileFacts>>;

    /// Warm the cells for `files` ahead of the parallel scan, batching what
    /// would otherwise be one hydration per file per first touch.
    fn prefetch_file_facts(&self, files: &[ProjectFile]);
}
