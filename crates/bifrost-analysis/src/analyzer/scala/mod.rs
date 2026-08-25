mod adapter;
mod clones;
pub(crate) mod diagnostics;
mod hierarchy;
pub(crate) mod imports;
pub(crate) mod language;
mod semantic;
mod structural;

use crate::analyzer::Range;
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
/// The Scala declaration walk, structured import/export parsing, raw-supertype
/// extraction and ordered wildcard-import environment now live in
/// [`brokk_bifrost_jvm::scala`]. Re-exporting the modules under their historical
/// names keeps every `crate::analyzer::scala::…` path in this crate pointing at
/// the same items.
pub(crate) use brokk_bifrost_jvm::scala::{declarations, wildcard_imports};

use crate::analyzer::clone_detection::{
    CloneCandidateProfile, detect_structural_clone_smells, refine_clone_similarity_with_ast,
};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::jvm::dependency_discovery::is_jvm_dependency_input;
use crate::analyzer::jvm::external::{JvmExternalDeclarationIndex, JvmExternalDeclarations};
use crate::analyzer::jvm::retained_external_index_state;
use crate::analyzer::languages::{
    BoundedReceiverQuery, DeadCodeBulkEdges, DeadCodeBulkPreflight, DeadCodeBulkProof,
    DeadCodeRouting, DeadCodeSupport, EdgePassId, EdgeSiteScanCtx, EdgeWeightScanCtx,
    LanguageEdgePass, LanguageEdgeSites, LanguageEdgeWeights, LanguageSupport,
    StructuralReceiverResolver, analyzable_file_count, candidate_fqns,
    fqn_has_multiple_function_definitions,
};
use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::type_relations::TypeRelation;
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, resolve_scala_bounded,
};
use crate::analyzer::usages::get_type::{TypeLookupOutcome, resolve_scala_type_bounded};
use crate::analyzer::usages::scala_graph::{
    ScalaDeadCodeBulkContext, ScalaDeadCodeBulkEligibility, ScalaUsageGraphStrategy,
    build_inbound_scala_usage_edges, build_scala_usage_edge_weights, dead_code_bulk_eligibility,
};
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::weighted_cache::{
    build_weighted_cache, weight_code_unit_set, weight_code_unit_vec_by_unit,
    weight_project_file_set,
};
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, BulkFileStateSource, CodeUnit,
    ForwardQueryProvider, IAnalyzer, ImportAnalysisProvider, JvmAnalyzerConfig, Language,
    PoolSafeMemo, Project, ProjectFile, SignatureMetadata, TestAssertionSmell,
    TestAssertionWeights, TestDetectionProvider, TreeSitterAnalyzer, TypeAliasProvider,
    TypeHierarchyProvider, resolve_analyzer,
};
use crate::hash::{HashMap, HashSet};
use crate::{CloneSmell, CloneSmellWeights};
use brokk_bifrost_core::CancellationToken;
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
use brokk_bifrost_core::analyzer::{
    BoundedDefinitionLookup, DefinitionLanguageScope, PackageRelationKind, PackageRelationValue,
    RelationalDefinitionFrontier, RelationalDefinitionLookup, RelationalDefinitionQuery,
    RelationalDefinitionQuestion, RelationalDefinitionValue, RelationalName,
    RelationalPointOutcome,
};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

pub(crate) use crate::analyzer::usages::scala_graph::ScalaProjectTypes;
pub(crate) use crate::analyzer::{ScalaExportInfo, ScalaExportSelector};
pub(crate) use adapter::ScalaAdapter;
pub(crate) use brokk_bifrost_jvm::proof::{
    JvmActiveSemanticModel, JvmModelDisposition, JvmProofGap, model_disposition_over_tiers,
    prove_against_active_model,
};
use brokk_bifrost_jvm::scala::graph::inverted::ScalaProjectTypesSeed;
pub(crate) use brokk_bifrost_jvm::scala::graph_support::{
    ScalaCallableFactsIndex, ScalaDefinitionIndex, ScalaFileFacts, ScalaForwardOwnerFacts,
    ScalaNameProof, ScalaSource,
};
pub(crate) use brokk_bifrost_jvm::scala::imports::{
    scala_enclosing_template_owner_fq_names, scala_lexical_scope_path_at,
    scala_lexical_scope_path_checked,
};
pub(crate) use brokk_bifrost_jvm::scala::supertypes::{
    ScalaSupertypeLookupPath, scala_type_lookup_segments,
};
use brokk_bifrost_jvm::scala::test_detection::detect_scala_test_assertion_smells;
/// Scala's pure name, signature and delimiter helpers. They read and produce
/// strings only, so they moved with the language knowledge they serve.
pub(crate) use brokk_bifrost_jvm::scala::{
    scala_default_type_name, scala_nested_type_candidates, scala_normalize_full_name,
    scala_package_fq_name, scala_simple_type_name,
};
use clones::build_scala_clone_candidate_data;
pub(crate) use wildcard_imports::{
    ScalaWildcardImportEnvironment, ScalaWildcardOwnerFacts,
    resolve_scala_wildcard_import_environment, scala_enclosing_package_root_candidates,
    scala_import_path, scala_import_path_candidates, scala_import_visible_at,
    scala_package_prefixes_at, scala_package_prefixes_at_checked,
};

/// Decode one persisted [`FileState`] into the thirteen per-file facts the
/// Scala graph reads.
///
/// The state's own fields are moved out rather than cloned: this is the one
/// caller, and it owns the map. Everything left behind is another language's
/// column or store bookkeeping.
fn scala_file_facts(state: FileState) -> ScalaFileFacts {
    ScalaFileFacts {
        source: state.source,
        package_name: state.package_name,
        declarations: state.declarations,
        definition_lookup_units: state.definition_lookup_units,
        imports: state.imports,
        scala_exports: state.scala_exports,
        supertype_lookup_paths: state.supertype_lookup_paths,
        signatures: state.signatures,
        signature_metadata: state.signature_metadata,
        ranges: state.ranges,
        children: state.children,
        scala_traits: state.scala_traits,
        type_aliases: state.type_aliases,
    }
}

#[derive(Clone)]
enum ScalaRelationalBackend {
    Store(Box<TreeSitterAnalyzer<ScalaAdapter>>),
    Frontier(Arc<dyn RelationalDefinitionFrontier>),
}

struct ScalaRelationalDefinitionIndex {
    backend: ScalaRelationalBackend,
}

impl ScalaRelationalDefinitionIndex {
    fn definition_query(
        &self,
        name: RelationalName,
        query: RelationalDefinitionQuery,
    ) -> RelationalDefinitionValue {
        let question = RelationalDefinitionQuestion {
            language_scope: DefinitionLanguageScope::Language(Language::Scala),
            name,
            query,
        };
        match &self.backend {
            ScalaRelationalBackend::Frontier(frontier) => frontier.ask(&question),
            ScalaRelationalBackend::Store(inner) => {
                let request = question.request(0);
                match inner.point(&request, &CancellationToken::new()) {
                    RelationalPointOutcome::Complete(result) => result.value,
                    RelationalPointOutcome::Cancelled => {
                        RelationalDefinitionValue::empty_for(&request.query)
                    }
                    RelationalPointOutcome::Failed(error) => {
                        inner.record_query_failure(crate::analyzer::store::StoreError::new(
                            error.message(),
                        ));
                        RelationalDefinitionValue::empty_for(&request.query)
                    }
                }
            }
        }
    }

    fn package_query(
        &self,
        package: &str,
        query: RelationalDefinitionQuery,
    ) -> RelationalDefinitionValue {
        self.definition_query(
            RelationalName::stable(scala_package_fq_name(package)),
            query,
        )
    }

    fn rendered_name_query(
        &self,
        name: &str,
        query: RelationalDefinitionQuery,
    ) -> RelationalDefinitionValue {
        self.structured_name_query(self.rendered_fq(name), query)
    }

    fn rendered_fq(&self, name: &str) -> crate::analyzer::FqName {
        brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
            Language::Scala,
            name,
            crate::analyzer::fq_name::segment_interner(),
        )
    }

    fn terminal_identifier<'a>(&self, name: &'a crate::analyzer::FqName) -> &'a str {
        crate::analyzer::fq_name::segment_interner()
            .resolve(
                name.last()
                    .expect("a Scala definition lookup name is non-empty"),
            )
            .0
    }

    fn structured_name_query(
        &self,
        name: crate::analyzer::FqName,
        query: RelationalDefinitionQuery,
    ) -> RelationalDefinitionValue {
        self.definition_query(RelationalName::stable(name), query)
    }

    fn identifier_query(&self, identifier: &str, file: Option<ProjectFile>) -> Vec<CodeUnit> {
        let mut name = crate::analyzer::FqName::new();
        name.push(
            crate::analyzer::fq_name::segment_interner()
                .intern(identifier, crate::analyzer::fq_name::SegmentKind::Unknown),
        );
        match self.structured_name_query(name, RelationalDefinitionQuery::Identifier { file }) {
            RelationalDefinitionValue::Definitions(units) => units,
            _ => unreachable!("Scala identifier query returned the wrong shape"),
        }
    }
}

impl ScalaDefinitionIndex for ScalaRelationalDefinitionIndex {
    fn by_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        if fqn.is_empty() {
            return Vec::new();
        }
        let structured = self.rendered_fq(fqn);
        let mut candidates = match self
            .structured_name_query(structured.clone(), RelationalDefinitionQuery::ExactName)
        {
            RelationalDefinitionValue::Definitions(units) => units,
            _ => unreachable!("Scala exact-name query returned the wrong shape"),
        };
        candidates.extend(self.identifier_query(self.terminal_identifier(&structured), None));
        candidates.retain(|unit| unit.fq_name() == fqn);
        candidates.sort();
        candidates.dedup();
        candidates
    }

    fn by_normalized_fqn(&self, normalized: &str) -> Vec<CodeUnit> {
        if normalized.is_empty() {
            return Vec::new();
        }
        let mut candidates =
            match self.rendered_name_query(normalized, RelationalDefinitionQuery::NormalizedName) {
                RelationalDefinitionValue::Definitions(units) => units,
                _ => unreachable!("Scala normalized-name query returned the wrong shape"),
            };
        let structured = self.rendered_fq(normalized);
        let terminal = self.terminal_identifier(&structured);
        candidates.extend(self.identifier_query(terminal, None));
        candidates.extend(self.identifier_query(&format!("{terminal}$"), None));
        candidates.retain(|unit| scala_normalize_full_name(&unit.fq_name()) == normalized);
        candidates.sort();
        candidates.dedup();
        candidates
    }

    fn types_in_package(&self, package: &str, simple: &str) -> Vec<CodeUnit> {
        match self.package_query(
            package,
            RelationalDefinitionQuery::PackageTypes {
                simple_name: simple.to_string(),
            },
        ) {
            RelationalDefinitionValue::Definitions(units) => units,
            _ => unreachable!("Scala package-type query returned the wrong shape"),
        }
    }

    fn identifier(&self, ident: &str) -> Vec<CodeUnit> {
        self.identifier_query(ident, None)
    }

    fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit> {
        let mut children =
            match self.rendered_name_query(fqn, RelationalDefinitionQuery::StructuralChildren) {
                RelationalDefinitionValue::Definitions(units) => units,
                _ => unreachable!("Scala structural-children query returned the wrong shape"),
            };
        let normalized = scala_normalize_full_name(fqn);
        let mut owners = ScalaDefinitionIndex::by_fqn(self, fqn);
        if owners.is_empty() {
            owners.extend(ScalaDefinitionIndex::by_normalized_fqn(self, &normalized));
        }
        owners.sort();
        owners.dedup();
        for owner in owners {
            children.extend(
                match self.structured_name_query(
                    owner.fq().clone(),
                    RelationalDefinitionQuery::StructuralChildren,
                ) {
                    RelationalDefinitionValue::Definitions(units) => units,
                    _ => unreachable!("Scala structural-children query returned the wrong shape"),
                },
            );
        }
        children.sort();
        children.dedup();
        children
    }

    fn fqn_exists(&self, fqn: &str) -> bool {
        !ScalaDefinitionIndex::by_fqn(self, fqn).is_empty()
    }

    fn package_exists(&self, package: &str) -> bool {
        matches!(
            self.package_query(
                package,
                RelationalDefinitionQuery::PackageRelation(PackageRelationKind::Exists),
            ),
            RelationalDefinitionValue::PackageRelation(PackageRelationValue::Exists(true))
        )
    }

    fn package_container_exists(&self, package: &str) -> bool {
        ScalaDefinitionIndex::package_exists(self, package)
            || !ScalaDefinitionIndex::child_packages(self, package).is_empty()
    }

    fn child_packages(&self, package: &str) -> Vec<String> {
        match self.package_query(
            package,
            RelationalDefinitionQuery::PackageRelation(PackageRelationKind::Children),
        ) {
            RelationalDefinitionValue::PackageRelation(PackageRelationValue::Packages(
                packages,
            )) => packages,
            _ => unreachable!("Scala child-package query returned the wrong shape"),
        }
    }

    fn members_for_structured_owner(
        &self,
        owner: &crate::analyzer::FqName,
        name: &str,
    ) -> Vec<CodeUnit> {
        match self.structured_name_query(
            owner.clone(),
            RelationalDefinitionQuery::StructuralMembers {
                identifier: name.to_string(),
            },
        ) {
            RelationalDefinitionValue::Definitions(units) => units,
            _ => unreachable!("Scala structured-owner query returned the wrong shape"),
        }
    }

    fn members_for_owner_name(
        &self,
        owner_fqn: &str,
        normalized_owner_fqn: &str,
        name: &str,
    ) -> Vec<CodeUnit> {
        let query = RelationalDefinitionQuery::StructuralMembers {
            identifier: name.to_string(),
        };
        let definitions = |value| match value {
            RelationalDefinitionValue::Definitions(units) => units,
            _ => unreachable!("Scala structural-members query returned the wrong shape"),
        };
        let exact = definitions(self.rendered_name_query(owner_fqn, query.clone()));
        let mut normalized = ScalaDefinitionIndex::by_normalized_fqn(self, normalized_owner_fqn)
            .into_iter()
            .flat_map(
                |owner| match self.structured_name_query(owner.fq().clone(), query.clone()) {
                    RelationalDefinitionValue::Definitions(units) => units,
                    _ => unreachable!("Scala structural-members query returned the wrong shape"),
                },
            )
            .collect::<Vec<_>>();
        normalized.extend(
            self.identifier_query(name, None)
                .into_iter()
                .filter(|unit| {
                    brokk_bifrost_core::analyzer::default_parent_fq_name(unit).is_some_and(
                        |owner| {
                            owner == owner_fqn
                                || scala_normalize_full_name(&owner) == normalized_owner_fqn
                        },
                    )
                }),
        );
        normalized.extend(exact);
        normalized.sort();
        normalized.dedup();
        normalized
    }

    fn package_types_in(&self, package: &str) -> Vec<(String, Vec<CodeUnit>)> {
        let mut grouped: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        let units =
            match self.package_query(package, RelationalDefinitionQuery::PackageTypesInPackage) {
                RelationalDefinitionValue::Definitions(units) => units,
                _ => unreachable!("Scala package-types query returned the wrong shape"),
            };
        for unit in units {
            grouped
                .entry(scala_simple_type_name(&unit))
                .or_default()
                .push(unit);
        }
        let mut grouped = grouped.into_iter().collect::<Vec<_>>();
        grouped.sort_by(|left, right| left.0.cmp(&right.0));
        for (_, units) in &mut grouped {
            units.sort();
            units.dedup();
        }
        grouped
    }
}

impl BoundedDefinitionLookup for ScalaRelationalDefinitionIndex {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        ScalaDefinitionIndex::by_fqn(self, fqn)
    }

    fn fqn_in_language(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
        if language == Language::Scala {
            ScalaDefinitionIndex::by_fqn(self, fqn)
        } else {
            Vec::new()
        }
    }

    fn types_in_package(&self, package: &str, simple: &str) -> Vec<CodeUnit> {
        ScalaDefinitionIndex::types_in_package(self, package, simple)
    }

    fn by_normalized_fqn(&self, normalized: &str) -> Vec<CodeUnit> {
        ScalaDefinitionIndex::by_normalized_fqn(self, normalized)
    }

    fn identifier(&self, ident: &str) -> Vec<CodeUnit> {
        ScalaDefinitionIndex::identifier(self, ident)
    }

    fn members_for_owner_name(
        &self,
        owner_fqn: &str,
        normalized_owner_fqn: &str,
        name: &str,
    ) -> Vec<CodeUnit> {
        ScalaDefinitionIndex::members_for_owner_name(self, owner_fqn, normalized_owner_fqn, name)
    }

    fn file_identifier(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
        self.identifier_query(ident, Some(file.clone()))
    }

    fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit> {
        ScalaDefinitionIndex::fqn_direct_children(self, fqn)
    }

    fn fqn_exists(&self, fqn: &str) -> bool {
        ScalaDefinitionIndex::fqn_exists(self, fqn)
    }

    fn package_exists(&self, package: &str) -> bool {
        ScalaDefinitionIndex::package_exists(self, package)
    }

    fn package_exists_in_language(&self, package: &str, language: Language) -> bool {
        language == Language::Scala && ScalaDefinitionIndex::package_exists(self, package)
    }

    fn fqn_prefix_exists(&self, prefix: &str) -> bool {
        match &self.backend {
            ScalaRelationalBackend::Store(inner) => inner.forward_fqn_prefix_exists(prefix),
            ScalaRelationalBackend::Frontier(_) => false,
        }
    }
}

struct ScalaRelationalCallableFacts {
    backend: ScalaRelationalBackend,
}

impl ScalaCallableFactsIndex for ScalaRelationalCallableFacts {
    fn facts_for_declaration(
        &self,
        declaration: &CodeUnit,
    ) -> Vec<crate::analyzer::RelationalCallableFact> {
        if !declaration.is_function() && !declaration.is_field() {
            return Vec::new();
        }
        let question = RelationalDefinitionQuestion {
            language_scope: DefinitionLanguageScope::Language(Language::Scala),
            name: RelationalName::stable(declaration.fq().clone()),
            query: RelationalDefinitionQuery::CallableFacts,
        };
        match &self.backend {
            ScalaRelationalBackend::Frontier(frontier) => match frontier.ask(&question) {
                RelationalDefinitionValue::CallableFacts(facts) => facts,
                _ => unreachable!("Scala callable-facts query returned the wrong shape"),
            },
            ScalaRelationalBackend::Store(inner) => {
                let request = question.request(0);
                match inner.point(&request, &CancellationToken::new()) {
                    RelationalPointOutcome::Complete(result) => match result.value {
                        RelationalDefinitionValue::CallableFacts(facts) => facts,
                        _ => unreachable!("Scala callable-facts query returned the wrong shape"),
                    },
                    RelationalPointOutcome::Cancelled => Vec::new(),
                    RelationalPointOutcome::Failed(error) => {
                        inner.record_query_failure(crate::analyzer::store::StoreError::new(
                            error.message(),
                        ));
                        Vec::new()
                    }
                }
            }
        }
    }
}

/// Build the crate-side [`ScalaProjectTypes`] out of a bulk file-state read.
/// Definition and callable questions stay store-backed; the bulk facts below
/// are the Scala graph's pre-existing structural state, not replacement lookup
/// indexes.
pub(crate) fn build_scala_project_types(
    inner: TreeSitterAnalyzer<ScalaAdapter>,
    file_states: HashMap<ProjectFile, FileState>,
) -> ScalaProjectTypes {
    let file_states: HashMap<ProjectFile, ScalaFileFacts> = file_states
        .into_iter()
        .map(|(file, state)| (file, scala_file_facts(state)))
        .collect();
    let index = Arc::new(ScalaRelationalDefinitionIndex {
        backend: ScalaRelationalBackend::Store(Box::new(inner.clone())),
    });
    let facts = Arc::new(ScalaRelationalCallableFacts {
        backend: ScalaRelationalBackend::Store(Box::new(inner)),
    });
    ScalaProjectTypes::from_parts(index, facts, file_states)
}

fn scala_project_types_seed(file_states: HashMap<ProjectFile, FileState>) -> ScalaProjectTypesSeed {
    let file_states = file_states
        .into_iter()
        .map(|(file, state)| (file, scala_file_facts(state)))
        .collect();
    ScalaProjectTypes::seed(Arc::new(file_states))
}

fn build_scala_project_types_from_frontier(
    frontier: Arc<dyn RelationalDefinitionFrontier>,
    seed: ScalaProjectTypesSeed,
) -> ScalaProjectTypes {
    let index = Arc::new(ScalaRelationalDefinitionIndex {
        backend: ScalaRelationalBackend::Frontier(frontier.clone()),
    });
    let facts = Arc::new(ScalaRelationalCallableFacts {
        backend: ScalaRelationalBackend::Frontier(frontier),
    });
    ScalaProjectTypes::from_seed(index, facts, seed)
}

#[derive(Clone)]
pub struct ScalaAnalyzer {
    inner: TreeSitterAnalyzer<ScalaAdapter>,
    java_config: JvmAnalyzerConfig,
    external_index: Arc<OnceLock<JvmExternalDeclarationIndex>>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    reverse_import_index: Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    importable_declarations_by_package: Arc<OnceLock<HashMap<String, Arc<Vec<CodeUnit>>>>>,
    package_namespaces: Arc<OnceLock<Vec<String>>>,
    same_package_reference_index:
        Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    lazy_hierarchy_index: Arc<OnceLock<hierarchy::ScalaLazyHierarchyIndex>>,
    /// Analyzer-cached Scala usage/type-resolution support, built once per
    /// analyzer generation and reset on `update`/`update_all`.
    project_types: Arc<OnceLock<Arc<crate::analyzer::usages::scala_graph::ScalaProjectTypes>>>,
    full_usage_edges:
        Cache<Arc<[String]>, Arc<crate::analyzer::usages::inverted_edges::UsageEdges>>,
    project_types_build_count: Arc<AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    scala_query_parse_count: Arc<AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    scala_query_walk_count: Arc<AtomicUsize>,
    #[allow(dead_code)]
    type_relations: Arc<OnceLock<Vec<TypeRelation>>>,
}

crate::analyzer::impl_forward_query_provider!(ScalaAnalyzer);

impl ScalaAnalyzer {
    pub(crate) fn declaration_candidates_by_identifier_limited(
        &self,
        identifier: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> crate::analyzer::store::LimitedQueryRows<CodeUnit> {
        self.inner
            .lookup_declarations_by_identifier_limited(identifier, limit, continue_query)
    }

    pub(crate) fn declaration_candidates_by_fqn_limited(
        &self,
        fqn: &str,
        normalized: bool,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> crate::analyzer::store::LimitedQueryRows<CodeUnit> {
        self.inner.lookup_declarations_by_persisted_fqn_limited(
            fqn,
            normalized,
            limit,
            continue_query,
        )
    }

    pub(crate) fn direct_children_limited(
        &self,
        owner: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<CodeUnit> {
        self.inner.direct_children_limited(owner, limit)
    }

    pub(crate) fn import_info_of_limited(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<crate::analyzer::ImportInfo> {
        self.inner.import_info_of_limited(token, file, limit)
    }

    pub(crate) fn namespace_of_file_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<String> {
        self.inner.file_namespace_hint_limited(file, limit)
    }

    pub(crate) fn workspace_package_exists(&self, package: &str) -> bool {
        self.inner.persisted_package_exists(package)
    }

    pub(crate) fn workspace_fqn_prefix_exists(&self, prefix: &str) -> bool {
        self.inner.forward_fqn_prefix_exists(prefix)
    }

    pub(crate) fn signature_metadata_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<SignatureMetadata> {
        self.inner.signature_metadata_limited(code_unit, limit)
    }

    pub(crate) fn signatures_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<String> {
        self.inner.signatures_limited(code_unit, limit)
    }

    pub(crate) fn ranges_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<crate::analyzer::Range> {
        self.inner.ranges_limited(code_unit, limit)
    }

    pub(crate) fn supertype_lookup_paths_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<String> {
        self.inner.supertype_lookup_paths_limited(code_unit, limit)
    }

    pub(crate) fn raw_supertypes_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<String> {
        self.inner.raw_supertypes_limited(code_unit, limit)
    }

    pub fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }

    pub(crate) fn import_lexical_context_for_unit(
        &self,
        unit: &CodeUnit,
    ) -> Option<(
        Vec<String>,
        Vec<crate::analyzer::StructuredImportScope>,
        usize,
    )> {
        let reference_byte = self
            .ranges(unit)
            .into_iter()
            .map(|range| range.start_byte)
            .min()?;
        let scope = AnalyzerQueryScope::new(self);
        let prepared = self.inner.prepared_syntax(scope.token(), unit.source())?;
        let root = prepared.tree().root_node();
        Some((
            scala_package_prefixes_at(root, prepared.source(), reference_byte),
            scala_lexical_scope_path_at(root, reference_byte),
            reference_byte,
        ))
    }

    pub(crate) fn export_infos_for_owner(&self, owner: &CodeUnit) -> Vec<ScalaExportInfo> {
        self.inner
            .fetch_file_state(owner.source())
            .and_then(|state| state.scala_exports.get(owner).cloned())
            .unwrap_or_default()
    }

    pub(crate) fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner.structural_parent_of(code_unit)
    }

    pub(crate) fn is_full_enum_case_declaration(&self, code_unit: &CodeUnit) -> bool {
        if !code_unit.is_class() {
            return false;
        }
        let Some(range) = self.ranges(code_unit).into_iter().next() else {
            return false;
        };
        let scope = AnalyzerQueryScope::new(self);
        let Some(prepared) = self
            .inner
            .prepared_syntax(scope.token(), code_unit.source())
        else {
            return false;
        };
        prepared
            .tree()
            .root_node()
            .descendant_for_byte_range(range.start_byte, range.end_byte)
            .is_some_and(|node| node.kind() == "full_enum_case")
    }

    pub(crate) fn is_case_class_declaration(&self, code_unit: &CodeUnit) -> bool {
        if !code_unit.is_class() {
            return false;
        }
        let Some(range) = self.ranges(code_unit).into_iter().next() else {
            return false;
        };
        let scope = AnalyzerQueryScope::new(self);
        let Some(prepared) = self
            .inner
            .prepared_syntax(scope.token(), code_unit.source())
        else {
            return false;
        };
        let Some(node) = prepared
            .tree()
            .root_node()
            .descendant_for_byte_range(range.start_byte, range.end_byte)
        else {
            return false;
        };
        node.kind() == "full_enum_case"
            || node.kind() == "class_definition"
                && (0..node.child_count())
                    .filter_map(|index| node.child(index))
                    .any(|child| child.kind() == "case")
    }

    pub(crate) fn forward_owner_facts(
        &self,
        code_unit: &CodeUnit,
    ) -> Option<ScalaForwardOwnerFacts> {
        let state = self.inner.fetch_file_state(code_unit.source())?;
        if !state.declarations.contains(code_unit) {
            return None;
        }
        let raw_supertypes = state
            .raw_supertypes
            .get(code_unit)
            .cloned()
            .unwrap_or_default();
        let supertype_lookup_paths = state
            .supertype_lookup_paths
            .get(code_unit)
            .into_iter()
            .flatten()
            .map(|path| ScalaSupertypeLookupPath::decode(path))
            .collect::<Option<Vec<_>>>()?;
        if raw_supertypes.len() != supertype_lookup_paths.len() {
            return None;
        }
        Some(ScalaForwardOwnerFacts {
            supertype_lookup_paths,
            signatures: state.signatures.get(code_unit).cloned().unwrap_or_default(),
            is_trait: state.scala_traits.contains(code_unit),
        })
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone.external_index = Arc::new(OnceLock::new());
        clone.project_types = Arc::new(OnceLock::new());
        clone.full_usage_edges =
            build_weighted_cache(self.memo_budget / 8, weight_scala_usage_edges);
        clone.project_types_build_count = Arc::new(AtomicUsize::new(0));
        #[cfg(any(test, feature = "test-support"))]
        {
            clone.scala_query_parse_count = Arc::new(AtomicUsize::new(0));
            clone.scala_query_walk_count = Arc::new(AtomicUsize::new(0));
        }
        clone
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let java_config = config.jvm.clone();
        let inner = TreeSitterAnalyzer::new_with_config(project, ScalaAdapter, config);
        Self::from_inner(inner, memo_budget, java_config)
    }

    fn from_inner(
        inner: TreeSitterAnalyzer<ScalaAdapter>,
        memo_budget: u64,
        java_config: JvmAnalyzerConfig,
    ) -> Self {
        Self {
            inner,
            java_config,
            external_index: Arc::new(OnceLock::new()),
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            direct_ancestors: build_weighted_cache(memo_budget / 8, weight_code_unit_vec_by_unit),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            importable_declarations_by_package: Arc::new(OnceLock::new()),
            package_namespaces: Arc::new(OnceLock::new()),
            same_package_reference_index: Arc::new(PoolSafeMemo::new()),
            lazy_hierarchy_index: Arc::new(OnceLock::new()),
            project_types: Arc::new(OnceLock::new()),
            full_usage_edges: build_weighted_cache(memo_budget / 8, weight_scala_usage_edges),
            project_types_build_count: Arc::new(AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            scala_query_parse_count: Arc::new(AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            scala_query_walk_count: Arc::new(AtomicUsize::new(0)),
            type_relations: Arc::new(OnceLock::new()),
        }
    }

    pub(crate) fn project_types(&self) -> Arc<ScalaProjectTypes> {
        self.initialize_project_types(|| {
            self.bulk_file_states(self.analyzed_files(), BulkFileStateSource::Omit)
        })
    }

    pub(crate) fn external_declaration_index(&self) -> &JvmExternalDeclarationIndex {
        self.external_index.get_or_init(|| {
            JvmExternalDeclarationIndex::build_for_project(&self.java_config, self.inner.project())
        })
    }

    /// The external declaration surface Scala resolution reads: the shared
    /// jar-backed index plus the declaration facts the activated semantic packs
    /// publish (#1893).
    ///
    /// `packs` is the *dispatching* analyzer's overlay; see
    /// [`crate::analyzer::JavaAnalyzer::resolve_type_name_with_external`] on
    /// why activation state arrives as a parameter.
    pub(crate) fn external_declarations(
        &self,
        packs: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
    ) -> JvmExternalDeclarations<'_> {
        JvmExternalDeclarations::new(self.external_declaration_index(), packs)
    }

    /// How far a lookup for `name` from `file` could see past the workspace,
    /// and the external type it landed on when it landed on one.
    ///
    /// The JVM half of boundary refinement, mirroring
    /// `JavaAnalyzer::external_boundary_evidence`. The tiers are the external
    /// tiers of [`ScalaSource::simple_type_proof`] -- a written qualified name,
    /// `java.lang`, the file's explicit and wildcard imports, the file's own
    /// package -- read against the built index rather than a peek, because the
    /// trace runs on the resolver path where building is permitted. A hit is
    /// [`BoundaryStatus::ExternalIndexed`] with the resolved external type; a
    /// miss against an index whose producers reported truncation is
    /// [`BoundaryStatus::ExternalDeclaredUnindexed`], because the build
    /// declared artifacts the index never finished reading.
    pub(crate) fn external_boundary_evidence(
        &self,
        token: QueryToken<'_>,
        packs: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
        file: &ProjectFile,
        name: &str,
    ) -> (BoundaryStatus, Option<String>) {
        let external = self.external_declarations(packs.clone());
        let package_name = self.inner.package_name_of(file).unwrap_or_default();
        if let Some(ty) = self.external_type_spelling(token, &external, file, &package_name, name) {
            return (BoundaryStatus::ExternalIndexed, Some(ty.fqn().to_owned()));
        }
        // A member spelling leaves the workspace exactly as its owner type
        // does, so the member tier runs where the type tier found nothing
        // (#1900). A member the surface does not declare changes nothing.
        // One ladder answers here and in the resolver's own boundary gate, so
        // a trace and a definition cannot disagree about a spelling (#2287).
        if let Some(member) = self.resolve_member_name_with_external(token, packs, file, name) {
            return (
                BoundaryStatus::ExternalIndexed,
                Some(member.fqn().to_owned()),
            );
        }
        if self
            .external_declaration_index()
            .production_diagnostic_count()
            > 0
        {
            return (BoundaryStatus::ExternalDeclaredUnindexed, None);
        }
        (BoundaryStatus::ExternalUnknown, None)
    }

    /// The external type a written Scala type spelling names, read through the
    /// external tiers of [`ScalaSource::simple_type_proof`]: a written
    /// qualified name, `java.lang`, the file's explicit and wildcard imports,
    /// and the file's own package, in that order.
    ///
    /// Kept as one function because both the trace's boundary evidence and the
    /// resolver's own member gate must reach a type spelling the same way; two
    /// copies of this ladder would let a trace and a definition disagree.
    fn external_type_spelling(
        &self,
        token: QueryToken<'_>,
        external: &JvmExternalDeclarations<'_>,
        file: &ProjectFile,
        package_name: &str,
        spelling: &str,
    ) -> Option<crate::analyzer::jvm::external::JvmExternalType> {
        if spelling.contains('.')
            && let Some(ty) = external.resolve_qualified_name(spelling, package_name)
        {
            return Some(ty);
        }
        if let Some(ty) = external.resolve_java_lang(spelling) {
            return Some(ty);
        }
        for import in self.inner.import_info_of(token, file) {
            let Some(path) = scala_import_path(&import) else {
                continue;
            };
            if import.is_wildcard {
                if let Some(ty) = external.resolve_wildcard_import(&path, spelling, package_name) {
                    return Some(ty);
                }
            } else if import.local_name() == Some(spelling)
                && let Some(ty) = external.resolve_explicit_import(&path, package_name)
            {
                return Some(ty);
            }
        }
        external.resolve_same_package(package_name, spelling)
    }

    /// Resolve `raw_name` in `file` as a member spelling -- a written
    /// `Owner.member` whose head is a type Scala's import ladder reaches
    /// outside the workspace and whose last segment is a member the external
    /// declaration surface declares (#1900).
    ///
    /// This is the Scala counterpart of
    /// `JavaAnalyzer::resolve_member_name_with_external`, and it is what lets
    /// Scala's own unresolved-receiver paths reach the shared import-boundary
    /// gate (#2287) instead of dying with a plain miss. The owner runs through
    /// [`Self::external_type_spelling`], so a renaming import
    /// (`import a.b.{C => D}`, written `D.member`) reaches the declaration its
    /// local name binds.
    ///
    /// Only the external surface can answer here: a workspace owner's members
    /// are indexed, and the resolver either found them or did not.
    pub(crate) fn resolve_member_name_with_external(
        &self,
        token: QueryToken<'_>,
        packs: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Option<crate::analyzer::jvm::external::JvmExternalMember> {
        let normalized = raw_name.trim();
        if normalized.is_empty() {
            return None;
        }
        let external = self.external_declarations(packs);
        if external.is_empty() {
            return None;
        }
        let package_name = self.inner.package_name_of(file).unwrap_or_default();
        external.resolve_member_spelling(normalized, &package_name, |owner_spelling| {
            self.external_type_spelling(token, &external, file, &package_name, owner_spelling)
        })
    }

    /// Whether a bare Scala type name is declared in `file` itself or anywhere
    /// in `package_name`. The source-declaration half of both
    /// [`ScalaSource::simple_type_proof`] and
    /// [`ScalaSource::simple_term_proof`], which decide whether
    /// `SCALA_UNRECOGNIZED_SYMBOL` fires for a name.
    ///
    /// Two indexed lookups, one per disjunct, in place of one
    /// `all_declarations()` walk per name. The walk cost the whole workspace's
    /// declarations for every bare identifier in a file, which is the product
    /// that made diagnostics on a large Scala checkout quadratic.
    ///
    /// The name test is the same in both halves and is not what either index is
    /// keyed on, so it is re-applied to whatever the index returns:
    ///
    /// * `types_in_package` keys on `scala_simple_type_name`, the *terminal*
    ///   segment of the short name with `$` trimmed, so it answers a bare
    ///   `Inner` with the nested `app.Outer$.Inner$`. The predicate here trims
    ///   only the trailing `$` of the whole short name, so `Outer$.Inner$` has
    ///   never matched `Inner` and must not start to.
    /// * The global usage-definition index also admits definition-lookup-only
    ///   units, which `all_declarations()` excludes. Scala's parser records
    ///   none today, but a candidate is confirmed against its own file's
    ///   declarations rather than against that absence, so the equivalence does
    ///   not depend on a set staying empty.
    ///
    /// The per-file half needs no such repair: `declarations(file)` is exactly
    /// `all_declarations()` restricted to one file, minus file scopes, which
    /// were never `is_class()`.
    fn declares_simple_type(&self, file: &ProjectFile, package_name: &str, name: &str) -> bool {
        let matches_name =
            |unit: &CodeUnit| unit.is_class() && unit.short_name().trim_end_matches('$') == name;
        if self.inner.declarations(file).iter().any(matches_name) {
            return true;
        }
        crate::analyzer::AnalyzerDefinitionLookup::new(self, Language::Scala)
            .types_in_package(package_name, name)
            .iter()
            .any(|unit| {
                matches_name(unit)
                    && unit.package_name() == package_name
                    && self.inner.declarations(unit.source()).contains(unit)
            })
    }

    #[cfg(test)]
    pub(crate) fn full_usage_edges(
        &self,
        nodes: &HashSet<String>,
        build: impl FnOnce() -> crate::analyzer::usages::inverted_edges::UsageEdges,
    ) -> Arc<crate::analyzer::usages::inverted_edges::UsageEdges> {
        let mut sorted_nodes = nodes.iter().cloned().collect::<Vec<_>>();
        sorted_nodes.sort_unstable();
        let key: Arc<[String]> = sorted_nodes.into();
        self.full_usage_edges.get_with(key, || Arc::new(build()))
    }

    #[cfg(any(test, feature = "test-support"))]
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn record_query_parse(&self) {
        self.scala_query_parse_count.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn record_query_walk(&self) {
        self.scala_query_walk_count.fetch_add(1, Ordering::Relaxed);
    }

    fn project_types_from_file_states(
        &self,
        file_states: HashMap<ProjectFile, FileState>,
    ) -> Arc<ScalaProjectTypes> {
        self.initialize_project_types(|| file_states)
    }

    pub(crate) fn build_project_types_from_file_states(
        &self,
        file_states: HashMap<ProjectFile, FileState>,
    ) -> ScalaProjectTypes {
        build_scala_project_types(self.inner.clone(), file_states)
    }

    pub(crate) fn project_types_seed_from_file_states(
        &self,
        file_states: HashMap<ProjectFile, FileState>,
    ) -> ScalaProjectTypesSeed {
        scala_project_types_seed(file_states)
    }

    pub(crate) fn build_project_types_from_frontier(
        &self,
        frontier: Arc<dyn RelationalDefinitionFrontier>,
        seed: ScalaProjectTypesSeed,
    ) -> ScalaProjectTypes {
        build_scala_project_types_from_frontier(frontier, seed)
    }

    fn initialize_project_types<F>(&self, file_states: F) -> Arc<ScalaProjectTypes>
    where
        F: FnOnce() -> HashMap<ProjectFile, FileState>,
    {
        self.project_types
            .get_or_init(|| {
                self.project_types_build_count
                    .fetch_add(1, Ordering::Relaxed);
                Arc::new(build_scala_project_types(self.inner.clone(), file_states()))
            })
            .clone()
    }

    pub(crate) fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, crate::analyzer::store::StoreError> {
        let memo_budget = config.memo_cache_budget_bytes();
        let java_config = config.jvm.clone();
        let inner = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            ScalaAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self::from_inner(inner, memo_budget, java_config))
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub(crate) fn bulk_file_states(
        &self,
        files: impl IntoIterator<Item = ProjectFile>,
        source_mode: BulkFileStateSource,
    ) -> HashMap<ProjectFile, FileState> {
        self.inner.bulk_file_states(files, source_mode)
    }

    pub(crate) fn bulk_import_infos(
        &self,
        files: impl IntoIterator<Item = ProjectFile>,
    ) -> HashMap<ProjectFile, Vec<crate::analyzer::ImportInfo>> {
        self.inner.bulk_import_infos(files)
    }

    #[doc(hidden)]
    pub fn reset_full_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    #[doc(hidden)]
    pub fn full_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test()
    }

    #[doc(hidden)]
    pub fn bulk_hydration_count_for_test(&self) -> usize {
        self.inner.bulk_hydration_count_for_test()
    }
}

fn weight_scala_usage_edges(
    key: &Arc<[String]>,
    edges: &Arc<crate::analyzer::usages::inverted_edges::UsageEdges>,
) -> u32 {
    use std::mem::size_of;

    let key_bytes = size_of::<Arc<[String]>>()
        + key
            .iter()
            .map(|item| size_of::<String>() + item.len())
            .sum::<usize>();
    let edge_bytes = edges
        .edges
        .iter()
        .map(|((caller, callee), sites)| {
            caller.len()
                + callee.len()
                + sites
                    .iter()
                    .map(|site| {
                        size_of::<crate::analyzer::usages::inverted_edges::CallSite>()
                            + site.path.len()
                    })
                    .sum::<usize>()
        })
        .sum::<usize>();
    let summary_bytes = edges
        .truncated
        .keys()
        .chain(edges.unproven_inbound.keys())
        .map(|name| size_of::<String>() + name.len() + size_of::<usize>())
        .sum::<usize>();
    (key_bytes + edge_bytes + summary_bytes).clamp(1, u32::MAX as usize) as u32
}

/// A tier that stopped Scala's ladder because an import could bind the name and
/// this analyzer cannot follow it to a declaration set.
///
/// `UnsupportedSemantics`, not a dependency-state reason: nothing is missing
/// from the dependency surface, and pointing at the classpath would send a
/// reader to fix the wrong thing. The gap is in this resolver -- it does not
/// enumerate a wildcard import's members, and it cannot follow an import target
/// that no retained surface holds -- so the reason names that.
fn unfollowable_scala_import(spelling: &str) -> ScalaNameProof {
    ScalaNameProof::Incomplete(JvmProofGap::Unsupported {
        detail: format!("Scala {spelling} cannot be followed to a declaration set"),
    })
}

/// What a published dependency model proves about one fully-qualified Scala
/// spelling, or `None` when it does not hold that spelling at all.
fn model_proof(model: &dyn JvmActiveSemanticModel, fqn: &str) -> Option<ScalaNameProof> {
    match model.qualified_name_disposition(fqn) {
        JvmModelDisposition::Absent => model
            .extraction_gap(fqn)
            .map(|gap| ScalaNameProof::Incomplete(JvmProofGap::PackExtraction(gap))),
        JvmModelDisposition::Unique => Some(ScalaNameProof::ExternalIndexed),
        JvmModelDisposition::Conflicting { declarations } => Some(ScalaNameProof::Ambiguous {
            boundaries: vec![BoundaryStatus::ExternalIndexed; declarations],
        }),
    }
}

fn qualify_scala_name(package_name: &str, name: &str) -> String {
    if package_name.is_empty() {
        name.to_string()
    } else {
        format!("{package_name}.{name}")
    }
}

impl ScalaSource for ScalaAnalyzer {
    /// Scala's type-name ladder, read-only (#1619).
    ///
    /// Every tier peeks: `self.external_index.get()` rather than
    /// `external_declaration_index()`, because building that index reads jars
    /// and a diagnostic request may not. An unbuilt index simply cannot answer,
    /// which is `Incomplete`, never `Absent`.
    ///
    /// The tiers are, in order: `scala_default_type_name`, this file's and this
    /// package's declarations, `java.lang`, the file's imports, and finally the
    /// package projection of the external surfaces. An import that cannot be
    /// followed to a declaration set stops the ladder with the exact import
    /// spelling, because that import may be what binds the name.
    fn simple_type_proof(
        &self,
        file: &ProjectFile,
        name: &str,
        model: &dyn JvmActiveSemanticModel,
    ) -> ScalaNameProof {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        if name.is_empty() || scala_default_type_name(name) {
            // A name on Scala's built-in list is known by construction. It
            // denotes a stdlib declaration, so the boundary is external.
            return ScalaNameProof::ExternalIndexed;
        }

        let package_name = self.inner.package_name_of(file).unwrap_or_default();
        if self.declares_simple_type(file, &package_name, name) {
            return ScalaNameProof::Workspace;
        }

        let imports = self.inner.import_info_of(token, file);
        let imported = self.imported_code_units_of(file);
        let retained = self.external_index.get();
        let declares_name = |declaration: &CodeUnit| {
            declaration.is_class() && declaration.short_name().trim_end_matches('$') == name
        };
        if retained.is_some_and(|external| external.resolve_java_lang(name).is_some()) {
            return ScalaNameProof::ExternalIndexed;
        }
        for import in &imports {
            let Some(path) = scala_import_path(import) else {
                return unfollowable_scala_import("an import with no structured path");
            };
            if import.is_wildcard {
                if imported.iter().any(declares_name) {
                    return ScalaNameProof::Workspace;
                }
                if retained.is_some_and(|external| {
                    external
                        .resolve_wildcard_import(&path, name, &package_name)
                        .is_some()
                }) {
                    return ScalaNameProof::ExternalIndexed;
                }
                if let Some(proof) = model_proof(model, &format!("{path}.{name}")) {
                    return proof;
                }
                // The members of a wildcard import this analyzer cannot
                // enumerate are exactly the names it cannot rule out.
                return unfollowable_scala_import(&format!("wildcard import `{path}`"));
            }

            if import.local_name() != Some(name) {
                continue;
            }
            if imported.iter().any(declares_name) {
                return ScalaNameProof::Workspace;
            }
            if retained.is_some_and(|external| {
                external
                    .resolve_explicit_import(&path, &package_name)
                    .is_some()
            }) {
                return ScalaNameProof::ExternalIndexed;
            }
            if let Some(proof) = model_proof(model, &path) {
                return proof;
            }
            // An explicit import binds this spelling to something no retained
            // surface holds. The import is the answer; it just cannot be
            // followed, so the name must not be called absent.
            return unfollowable_scala_import(&format!("import `{path}`"));
        }

        if retained
            .is_some_and(|external| external.resolve_same_package(&package_name, name).is_some())
        {
            return ScalaNameProof::ExternalIndexed;
        }
        let spellings = [
            qualify_scala_name(&package_name, name),
            format!("java.lang.{name}"),
        ];
        prove_against_active_model(retained_external_index_state(retained), model, || {
            model_disposition_over_tiers(model, spellings.iter().map(String::as_str))
        })
    }

    /// Scala's term ladder, read-only. See [`Self::simple_type_proof`].
    ///
    /// A term is looked for among this file's and this package's declarations
    /// only. Any import that could bind the spelling stops the ladder: Scala
    /// imports terms as readily as types, and this analyzer does not follow an
    /// import to its term members.
    fn simple_term_proof(
        &self,
        file: &ProjectFile,
        name: &str,
        model: &dyn JvmActiveSemanticModel,
    ) -> ScalaNameProof {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        let package_name = self.inner.package_name_of(file).unwrap_or_default();
        if self.declares_simple_type(file, &package_name, name) {
            return ScalaNameProof::Workspace;
        }
        let retained = self.external_index.get();
        if retained
            .is_some_and(|external| external.resolve_same_package(&package_name, name).is_some())
        {
            return ScalaNameProof::ExternalIndexed;
        }
        let imports = self.inner.import_info_of(token, file);
        if let Some(import) = imports
            .iter()
            .find(|import| import.is_wildcard || import.local_name() == Some(name))
        {
            let spelling = scala_import_path(import).unwrap_or_else(|| name.to_string());
            return unfollowable_scala_import(&if import.is_wildcard {
                format!("wildcard import `{spelling}`")
            } else {
                format!("import `{spelling}`")
            });
        }
        let spelling = qualify_scala_name(&package_name, name);
        prove_against_active_model(retained_external_index_state(retained), model, || {
            model_disposition_over_tiers(model, std::iter::once(spelling.as_str()))
        })
    }

    fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        ScalaAnalyzer::structural_parent_of(self, code_unit)
    }

    fn export_infos_for_owner(&self, owner: &CodeUnit) -> Vec<ScalaExportInfo> {
        ScalaAnalyzer::export_infos_for_owner(self, owner)
    }

    fn forward_owner_facts(&self, code_unit: &CodeUnit) -> Option<ScalaForwardOwnerFacts> {
        ScalaAnalyzer::forward_owner_facts(self, code_unit)
    }

    fn is_scala_trait_declaration(&self, code_unit: &CodeUnit) -> bool {
        ScalaAnalyzer::is_scala_trait_declaration(self, code_unit)
    }

    fn definitions_by_normalized_fqn(&self, normalized: &str) -> Vec<CodeUnit> {
        crate::analyzer::AnalyzerDefinitionLookup::new(self, Language::Scala)
            .by_normalized_fqn(normalized)
    }

    fn types_in_package(&self, package: &str, simple: &str) -> Vec<CodeUnit> {
        crate::analyzer::AnalyzerDefinitionLookup::new(self, Language::Scala)
            .types_in_package(package, simple)
    }

    fn project_types(&self) -> Arc<ScalaProjectTypes> {
        ScalaAnalyzer::project_types(self)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn record_query_parse(&self) {
        ScalaAnalyzer::record_query_parse(self);
    }

    #[cfg(any(test, feature = "test-support"))]
    fn record_query_walk(&self) {
        ScalaAnalyzer::record_query_walk(self);
    }
}

/// The declaration-index questions the Scala graph asks, answered by the
/// analyzer's own workspace index. Nothing narrows or reorders: each member is
/// the identically named inherent accessor or `BoundedDefinitionLookup` method.
impl TestDetectionProvider for ScalaAnalyzer {}

impl TypeAliasProvider for ScalaAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }
}

use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for ScalaAnalyzer {
    fn enclosing_code_unit(
        &self,
        file: &ProjectFile,
        range: &crate::analyzer::Range,
    ) -> Option<CodeUnit> {
        self.inner.enclosing_code_unit(file, range)
    }

    fn enclosing_code_unit_for_lines(
        &self,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit> {
        self.inner
            .enclosing_code_unit_for_lines(file, start_line, end_line)
    }

    fn top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        self.inner.top_level_declarations(file)
    }

    fn summary_file_projection(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::SummaryFileProjection>> {
        let mut projection = (*self.inner.summary_file_projection(file)?).clone();
        for children in projection.children.values_mut() {
            children.retain(|child| !child.is_synthetic());
        }
        Some(Arc::new(projection))
    }

    fn analyzed_files(&self) -> Vec<ProjectFile> {
        self.inner.analyzed_files()
    }

    fn indexed_source(&self, file: &ProjectFile) -> Option<String> {
        self.inner.indexed_source(file)
    }

    fn location_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.inner.location_declarations(file)
    }

    fn location_ranges(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range> {
        self.inner.location_ranges(code_unit)
    }

    fn indexed_source_matches(&self, file: &ProjectFile, source: &str) -> bool {
        self.inner.indexed_source_matches(file, source)
    }

    fn is_analyzed(&self, file: &ProjectFile) -> bool {
        self.inner.is_analyzed(file)
    }

    fn retain_analyzed(&self, candidates: &[ProjectFile]) -> Vec<ProjectFile> {
        self.inner.retain_analyzed(candidates)
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.all_declarations()
    }

    fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.inner.declarations(file)
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.definitions(fq_name)
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner
            .direct_children(code_unit)
            .into_iter()
            .filter(|child| !child.is_synthetic())
            .collect()
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.structural_parent_of(code_unit)
            .or_else(|| CodeUnitIndex::parent_of(&self.inner, code_unit))
    }

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range> {
        self.inner.ranges(code_unit)
    }

    fn ranges_with_limit(
        &self,
        code_unit: &CodeUnit,
        max_ranges: usize,
        cancellation: &crate::CancellationToken,
    ) -> (Vec<crate::analyzer::Range>, usize, bool) {
        self.inner
            .ranges_with_limit(code_unit, max_ranges, cancellation)
    }

    fn signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.forward_owner_facts(code_unit)
            .map(|facts| facts.signatures)
            .unwrap_or_else(|| self.inner.signatures(code_unit))
    }

    fn signature_metadata(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        self.inner.signature_metadata(code_unit)
    }

    fn get_analyzed_files(&self) -> BTreeSet<ProjectFile> {
        self.inner.get_analyzed_files()
    }

    fn languages(&self) -> BTreeSet<Language> {
        self.inner.languages()
    }

    fn project(&self) -> &dyn Project {
        self.inner.project()
    }

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.inner.get_all_declarations()
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        self.inner.get_definitions(fq_name)
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        let rendered = crate::analyzer::common::render_skeleton(self, code_unit, false);
        (!rendered.is_empty()).then(|| rendered.trim_end().to_string())
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        let rendered = crate::analyzer::common::render_skeleton(self, code_unit, true);
        (!rendered.is_empty()).then(|| rendered.trim_end().to_string())
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        self.inner.get_source(code_unit, include_comments)
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        self.inner.get_sources(code_unit, include_comments)
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        self.inner.search_definitions(pattern, auto_quote)
    }

    fn search_definitions_by_suffix_pattern(
        &self,
        pattern: &str,
        terminal_identifiers: &[String],
        language: Language,
    ) -> BTreeSet<CodeUnit> {
        self.inner
            .search_definitions_by_suffix_pattern(pattern, terminal_identifiers, language)
    }

    fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_candidates_by_short_name(symbol)
    }

    fn has_complete_symbol_lookup_index(&self) -> bool {
        self.inner.has_complete_symbol_lookup_index()
    }

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_declarations_by_identifier(identifier)
    }
}

impl IAnalyzer for ScalaAnalyzer {
    crate::analyzer::i_analyzer::forward_relational_definition_batch!();

    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn crate::analyzer::AnalyzerTestHooks {
        self
    }

    fn invalidate_cached_file_identities(&self) {
        self.inner.invalidate_cached_file_identities();
    }

    fn working_tree_identity(&self) -> Option<std::sync::Arc<crate::gitblob::WorkingTreeIdentity>> {
        self.inner.working_tree_identity()
    }

    fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.begin_query(context);
    }

    fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.end_query(context);
    }

    fn record_query_failure(&self, error: crate::analyzer::store::StoreError) {
        self.inner.record_query_failure(error);
    }

    fn begin_streaming_file_read(&self, file: &ProjectFile) {
        self.inner.begin_streaming_file_read(file);
    }

    fn end_streaming_file_read(&self, file: &ProjectFile) {
        self.inner.end_streaming_file_read(file);
    }

    fn release_streaming_readers(&self) {
        self.inner.release_streaming_readers();
    }

    fn workspace_file_index_cell(&self) -> Option<crate::analyzer::WorkspaceFileIndexCell> {
        self.inner.workspace_file_index_cell()
    }

    fn structural_fact_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralFactProvider> {
        self.inner.structural_fact_providers()
    }

    fn snapshot_caches(&self) -> Option<&crate::analyzer::AnalyzerSnapshotCaches> {
        Some(self.inner.snapshot_caches())
    }

    fn workspace_content_identities(
        &self,
    ) -> Option<crate::analyzer::content_identity::WorkspaceContentIdentities> {
        self.inner.workspace_content_identities()
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements(file)
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> crate::analyzer::SemanticDiagnosticReport {
        diagnostics::collect_scala_semantic_diagnostics(self, file, source)
    }

    /// Build the jar-backed external declaration index off the request path.
    /// See `JavaAnalyzer::warm_query_indexes`; the three JVM analyzers share
    /// one dependency universe and one reason not to build it under a
    /// diagnostic.
    fn warm_query_indexes(&self) {
        self.external_declaration_index();
    }

    fn query_indexes_warm(&self) -> bool {
        self.external_index.get().is_some()
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let external_index = if changed_files.iter().any(is_jvm_dependency_input) {
            Arc::new(OnceLock::new())
        } else {
            self.external_index.clone()
        };
        let mut updated = Self::from_inner(
            self.inner.update(changed_files),
            self.memo_budget,
            self.java_config.clone(),
        );
        updated.external_index = external_index;
        updated
    }

    fn update_all(&self) -> Self {
        Self::from_inner(
            self.inner.update_all(),
            self.memo_budget,
            self.java_config.clone(),
        )
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
        Some(self)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.inner.extract_call_receiver(reference)
    }

    fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool {
        self.inner.is_access_expression(file, start_byte, end_byte)
    }

    fn find_nearest_declaration(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        ident: &str,
    ) -> Option<crate::analyzer::DeclarationInfo> {
        self.inner
            .find_nearest_declaration(file, start_byte, end_byte, ident)
    }

    fn search_symbol_candidates(
        &self,
        patterns: &crate::analyzer::SearchSymbolPatternBatch,
        cancellation: Option<&crate::CancellationToken>,
    ) -> crate::analyzer::SearchSymbolCandidates {
        self.inner.search_symbol_candidates(patterns, cancellation)
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }

    fn in_test_region(&self, code_unit: &crate::analyzer::CodeUnit) -> bool {
        self.inner.in_test_region(code_unit)
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        if !self.contains_tests(file) || file_language(file) != Language::Scala {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_scala_test_assertion_smells(file, &source, &weights)
    }

    fn find_structural_clone_smells(
        &self,
        file: &ProjectFile,
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        self.find_structural_clone_smells_for_files(std::slice::from_ref(file), weights)
    }

    fn find_structural_clone_smells_for_files(
        &self,
        files: &[ProjectFile],
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        let requested_files: Vec<ProjectFile> = files
            .iter()
            .filter(|file| file_language(file) == Language::Scala)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }

        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function() && file_language(code_unit.source()) == Language::Scala
            })
            .filter_map(|code_unit| build_scala_clone_candidate_data(self, &code_unit, weights))
            .map(|candidate| CloneCandidateProfile::create(candidate, weights))
            .collect();
        if all_candidates.is_empty() {
            return Vec::new();
        }

        detect_structural_clone_smells(
            &requested_files,
            all_candidates,
            weights,
            refine_clone_similarity_with_ast,
        )
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for ScalaAnalyzer {
    fn reset_full_declaration_scan_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_full_declaration_scan_count_for_test();
    }

    fn full_declaration_scan_count_for_test(&self) -> usize {
        self.inner
            .test_hooks()
            .full_declaration_scan_count_for_test()
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    fn candidate_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test() + self.inner.bulk_hydration_count_for_test()
    }

    fn reset_workspace_path_scan_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_workspace_path_scan_count_for_test();
    }

    fn workspace_path_scan_count_for_test(&self) -> usize {
        self.inner.test_hooks().workspace_path_scan_count_for_test()
    }

    fn reset_scala_project_types_build_count_for_test(&self) {
        self.project_types_build_count.store(0, Ordering::Relaxed);
    }

    fn scala_project_types_build_count_for_test(&self) -> usize {
        self.project_types_build_count.load(Ordering::Relaxed)
    }

    fn reset_scala_query_scan_counts_for_test(&self) {
        self.scala_query_parse_count.store(0, Ordering::Relaxed);
        self.scala_query_walk_count.store(0, Ordering::Relaxed);
    }

    fn scala_query_parse_count_for_test(&self) -> usize {
        self.scala_query_parse_count.load(Ordering::Relaxed)
    }

    fn scala_query_walk_count_for_test(&self) -> usize {
        self.scala_query_walk_count.load(Ordering::Relaxed)
    }
}

static SCALA_USAGE_STRATEGY: ScalaUsageGraphStrategy = ScalaUsageGraphStrategy::new();

pub(crate) struct ScalaSupport;

impl LanguageSupport for ScalaSupport {
    fn language(&self) -> Language {
        Language::Scala
    }

    /// The trailing `$` marks a companion object in the indexed name and is not part of
    /// how anyone writes or reads the type.
    fn display_symbol_name(&self, symbol: &str) -> String {
        symbol
            .split('.')
            .map(|segment| segment.trim_end_matches('$'))
            .collect::<Vec<_>>()
            .join(".")
    }

    /// The same decoration, read off a single identifier: an object is indexed
    /// as `Name$` but declared as `Name`. Without this override the
    /// seek-then-verify lookup of a source-spelled object name fails
    /// verification against the persisted identifier (#2419).
    fn source_identifier<'s>(&self, identifier: &'s str) -> &'s str {
        identifier.strip_suffix('$').unwrap_or(identifier)
    }

    fn signature_metadata_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<SignatureMetadata>> {
        resolve_analyzer::<ScalaAnalyzer>(analyzer)
            .map(|scala| scala.signature_metadata_limited(unit, limit))
    }

    fn signatures_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<String>> {
        resolve_analyzer::<ScalaAnalyzer>(analyzer)
            .map(|scala| scala.signatures_limited(unit, limit))
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        resolve_analyzer::<ScalaAnalyzer>(analyzer).map(|scala| scala.ranges_limited(unit, limit))
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        resolve_analyzer::<ScalaAnalyzer>(analyzer).map(|value| value as _)
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Jvm
    }

    fn reference_plugin(&self) -> crate::analyzer::languages::ReferenceLanguagePlugin {
        crate::analyzer::languages::ReferenceLanguagePlugin::new(
            &SCALA_USAGE_STRATEGY,
            &ScalaEdgePass,
        )
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&SCALA_USAGE_STRATEGY),
            bulk: Some(&ScalaDeadCodeBulk),
        }
    }

    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        Some(&ScalaSupport)
    }

    fn parser_language(&self, _flavor: crate::analyzer::ParserFlavor) -> tree_sitter::Language {
        language::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn crate::analyzer::structural::StructuralSpec {
        &brokk_bifrost_jvm::scala::structural::SCALA_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(brokk_bifrost_jvm::queries::SCALA_HIGHLIGHTS_QUERY)
    }
}

/// One of three distinct JVM passes. Java, Scala and Kotlin resolve over the same
/// candidate space but scan only files of their own language, so the three passes cover
/// disjoint call sites and merge without double counting.
struct ScalaEdgePass;

impl LanguageEdgePass for ScalaEdgePass {
    fn id(&self) -> EdgePassId {
        EdgePassId::Scala
    }

    fn permits_logical_family_targets(&self) -> bool {
        true
    }

    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites> {
        let scope = AnalyzerQueryScope::new(ctx.analyzer);
        let token = scope.token();
        crate::analyzer::usages::scala_graph::build_rooted_scala_usage_edges(
            ctx.analyzer,
            token,
            ctx.fqns,
            ctx.keep_file,
        )
        .map(LanguageEdgeSites::Fqn)
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        let scope = AnalyzerQueryScope::new(ctx.analyzer);
        let token = scope.token();
        build_scala_usage_edge_weights(ctx.analyzer, token, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeWeights::Fqn)
    }
}

impl StructuralReceiverResolver for ScalaSupport {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        let scope = AnalyzerQueryScope::new(query.analyzer);
        let token = scope.token();
        resolve_scala_type_bounded(
            query.analyzer,
            token,
            query.file,
            query.source,
            query.tree,
            query.site,
            query.budget,
            query.cancellation,
        )
    }

    fn resolve_definition_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        let scope = AnalyzerQueryScope::new(query.analyzer);
        let token = scope.token();
        resolve_scala_bounded(
            query.analyzer,
            token,
            query.file,
            query.source,
            query.tree,
            query.site,
            query.budget,
            query.cancellation,
        )
    }
}

#[cfg(test)]
mod overlay_usage_tests {
    use super::*;
    use crate::analyzer::usages::{UsageFinder, scala_graph::build_scala_usage_edges};
    use crate::analyzer::{OverlayProject, TestProject};

    #[test]
    fn cloned_overlay_rebuilds_scala_source_facts_for_targeted_and_inverted_ranges() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "app/Calls.scala");
        std::fs::create_dir_all(file.abs_path().parent().expect("source parent"))
            .expect("source directory");
        file.write(
            r#"package app
class Api { def choose(value: Int): Int = value }
class Use(api: Api) { def call(): Int = api.choose(1) }
"#,
        )
        .expect("disk Scala source");

        let disk_project: Arc<dyn Project> =
            Arc::new(TestProject::new(root.clone(), Language::Scala));
        let disk = ScalaAnalyzer::new(Arc::clone(&disk_project));
        let disk_target = disk
            .get_definitions("app.Api.choose")
            .into_iter()
            .next()
            .expect("disk target");
        let disk_hits = UsageFinder::new()
            .find_usages_default(&disk, std::slice::from_ref(&disk_target))
            .into_either()
            .expect("disk usages");
        assert!(
            disk_hits
                .iter()
                .any(|hit| hit.snippet.contains("api.choose(1)"))
        );
        assert!(
            disk.project_types.get().is_some(),
            "disk cache should be warm"
        );

        let overlay_source = r#"package app
// This overlay shifts every exact declaration range and changes the callable shape.
class Api { def choose(value: Int)(label: String): Int = value }
class Use(api: Api) { def call(): Int = api.choose(1)("overlay") }
"#;
        let overlay = Arc::new(OverlayProject::new(Arc::clone(&disk_project)));
        assert!(overlay.set(file.abs_path(), overlay_source.to_string()));
        let snapshot = disk.clone_with_project(Arc::clone(&overlay) as Arc<dyn Project>);
        assert!(
            snapshot.project_types.get().is_none(),
            "an overlay clone needs an independent source-facts generation"
        );
        let overlay_target = snapshot
            .get_definitions("app.Api.choose")
            .into_iter()
            .next()
            .expect("overlay target");
        let overlay_hits = UsageFinder::new()
            .find_usages_default(&snapshot, std::slice::from_ref(&overlay_target))
            .into_either()
            .expect("overlay usages");
        assert!(
            overlay_hits
                .iter()
                .any(|hit| hit.snippet.contains("api.choose(1)(\"overlay\")")),
            "targeted lookup must use overlay ranges and callable facts: {overlay_hits:#?}"
        );

        let nodes = snapshot
            .get_all_declarations()
            .into_iter()
            .map(|unit| unit.fq_name())
            .collect();
        let scope = AnalyzerQueryScope::new(&disk);
        let token = scope.token();
        let edges = build_scala_usage_edges(&snapshot, token, &nodes, |_| true)
            .expect("Scala inverted edge build");
        assert!(
            edges
                .edges
                .keys()
                .any(|(caller, callee)| caller == "app.Use.call" && callee == "app.Api.choose"),
            "inverted lookup must use overlay ranges and callable facts: {:?}",
            edges.edges.keys().collect::<Vec<_>>()
        );
    }
}

/// The answers [`ScalaSource::simple_type_proof`] and
/// [`ScalaSource::simple_term_proof`] give for a bare name, pinned on a
/// fixture that separates every disjunct of the declaration test.
///
/// These two decide whether `SCALA_UNRECOGNIZED_SYMBOL` fires, so a changed
/// answer is a changed diagnostic and nothing else reports it. The cases below
/// existed before the indexed lookups replaced the whole-workspace
/// `all_declarations()` scan and read identically after, which is the whole
/// point of writing them as one table.
///
/// Since #1619 the table records *proofs* rather than a `Known`/`Absent`
/// boolean. A name the workspace does not declare is no longer absent by
/// default: with no retained jar index and no published dependency model,
/// nothing past the workspace has been read, so the honest answer is
/// `Incomplete`. Only the published-model case below can reach `Absent`.
#[cfg(test)]
mod knownness_tests {
    use super::*;
    use crate::analyzer::TestProject;

    /// A dependency model holding exactly the fully-qualified names it is given.
    struct FakeActiveModel {
        published: bool,
        names: Vec<&'static str>,
    }

    impl FakeActiveModel {
        fn unpublished() -> Self {
            Self {
                published: false,
                names: Vec::new(),
            }
        }

        fn publishing(names: &[&'static str]) -> Self {
            Self {
                published: true,
                names: names.to_vec(),
            }
        }
    }

    impl JvmActiveSemanticModel for FakeActiveModel {
        fn is_published(&self) -> bool {
            self.published
        }

        fn qualified_name_disposition(&self, fqn: &str) -> JvmModelDisposition {
            match self.names.iter().filter(|name| **name == fqn).count() {
                0 => JvmModelDisposition::Absent,
                1 => JvmModelDisposition::Unique,
                declarations => JvmModelDisposition::Conflicting { declarations },
            }
        }
    }

    /// What every name below answers when nothing past the workspace is
    /// readable: the jar index was never built and no model is published.
    fn unreadable_beyond_workspace() -> ScalaNameProof {
        ScalaNameProof::Incomplete(JvmProofGap::ExternalBoundary {
            boundary: BoundaryStatus::ExternalUnknown,
        })
    }

    /// `app/Consumer.scala` declares `nested.FileLocal` in a second package
    /// clause, so that unit is same-file but *not* same-package: it isolates
    /// the `source() == file` disjunct from the `package_name()` one.
    ///
    /// `app/Companion.scala` carries the `$` shapes: a lone `object`
    /// (`app.Lonely$`), a class/companion pair (`app.Paired` and
    /// `app.Paired$`), and an object nested in an object
    /// (`app.Outer$.Inner$`), whose short name is `Outer$.Inner$` and so has
    /// never answered a bare `Inner`.
    fn fixture() -> (tempfile::TempDir, ScalaAnalyzer, ProjectFile) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        for (path, source) in [
            (
                "app/Consumer.scala",
                "package app\nclass Consumer\npackage nested { class FileLocal }\n",
            ),
            (
                "app/Companion.scala",
                "package app\nclass Paired\nobject Paired\nobject Lonely\nobject Outer { object Inner }\n",
            ),
            ("app/Sibling.scala", "package app\nclass Sibling\n"),
            ("other/Far.scala", "package other\nclass Far\n"),
        ] {
            let file = ProjectFile::new(root.clone(), path);
            std::fs::create_dir_all(file.abs_path().parent().expect("source parent"))
                .expect("source directory");
            file.write(source).expect("scala source");
        }
        let analyzer = ScalaAnalyzer::new(
            Arc::new(TestProject::new(root.clone(), Language::Scala)) as Arc<dyn Project>,
        );
        let consumer = ProjectFile::new(root, "app/Consumer.scala");
        (temp, analyzer, consumer)
    }

    #[test]
    fn simple_type_proof_answers_each_declaration_shape() {
        let (_temp, analyzer, consumer) = fixture();
        let model = FakeActiveModel::unpublished();
        for (name, expected) in [
            // Same package, another file: the plain class.
            ("Sibling", ScalaNameProof::Workspace),
            // Same package, class and companion object under one name.
            ("Paired", ScalaNameProof::Workspace),
            // Same package, companion object with no class: the only unit is
            // `app.Lonely$`, matched with its trailing `$` trimmed.
            ("Lonely", ScalaNameProof::Workspace),
            ("Outer", ScalaNameProof::Workspace),
            // The `$`-carrying spelling is not a Scala type name, and trimming
            // the declaration's `$` must not make it one.
            ("Lonely$", unreadable_beyond_workspace()),
            // Nested object: short name `Outer$.Inner$`, so a bare `Inner` has
            // never matched it even though the type exists in the package.
            ("Inner", unreadable_beyond_workspace()),
            // Same file, different package.
            ("FileLocal", ScalaNameProof::Workspace),
            // Another package entirely, and no import to reach it.
            ("Far", unreadable_beyond_workspace()),
            ("Missing", unreadable_beyond_workspace()),
        ] {
            assert_eq!(
                expected,
                ScalaSource::simple_type_proof(&analyzer, &consumer, name, &model),
                "type proof of `{name}`"
            );
        }
    }

    #[test]
    fn simple_term_proof_answers_each_declaration_shape() {
        let (_temp, analyzer, consumer) = fixture();
        let model = FakeActiveModel::unpublished();
        for (name, expected) in [
            ("Sibling", ScalaNameProof::Workspace),
            ("Paired", ScalaNameProof::Workspace),
            ("Lonely", ScalaNameProof::Workspace),
            ("Outer", ScalaNameProof::Workspace),
            ("Lonely$", unreadable_beyond_workspace()),
            ("Inner", unreadable_beyond_workspace()),
            ("FileLocal", ScalaNameProof::Workspace),
            ("Far", unreadable_beyond_workspace()),
            ("Missing", unreadable_beyond_workspace()),
        ] {
            assert_eq!(
                expected,
                ScalaSource::simple_term_proof(&analyzer, &consumer, name, &model),
                "term proof of `{name}`"
            );
        }
    }

    /// The one state in which a bare Scala name is provably absent: a published
    /// dependency model that does not hold it. Everything else in this module
    /// stops at `Incomplete`, and this is what separates the two.
    #[test]
    fn a_published_model_decides_between_absent_and_externally_indexed() {
        let (_temp, analyzer, consumer) = fixture();

        let empty = FakeActiveModel::publishing(&[]);
        assert_eq!(
            ScalaNameProof::Absent {
                boundary: BoundaryStatus::ExternalIndexed,
            },
            ScalaSource::simple_type_proof(&analyzer, &consumer, "Missing", &empty),
            "a published model that misses the name proves it absent"
        );

        // The model is consulted at the spelling Scala's own package tier
        // produces, so the same simple name under another package must not
        // silence the error.
        let elsewhere = FakeActiveModel::publishing(&["other.Missing"]);
        assert_eq!(
            ScalaNameProof::Absent {
                boundary: BoundaryStatus::ExternalIndexed,
            },
            ScalaSource::simple_type_proof(&analyzer, &consumer, "Missing", &elsewhere),
            "a same-named type in an unrelated package is not this reference"
        );

        let holding = FakeActiveModel::publishing(&["app.Missing"]);
        assert_eq!(
            ScalaNameProof::ExternalIndexed,
            ScalaSource::simple_type_proof(&analyzer, &consumer, "Missing", &holding),
            "the model holds the name at the file's own package"
        );

        let conflicted = FakeActiveModel::publishing(&["app.Missing", "app.Missing"]);
        assert_eq!(
            ScalaNameProof::Ambiguous {
                boundaries: vec![BoundaryStatus::ExternalIndexed; 2],
            },
            ScalaSource::simple_type_proof(&analyzer, &consumer, "Missing", &conflicted),
            "two published declarations of one name is ambiguity, not absence"
        );
    }

    /// A diagnostic must never build the jar-backed external index: reading
    /// jars is package I/O, which #1615 forbids inside a request.
    #[test]
    fn a_name_proof_never_builds_the_external_declaration_index() {
        let (_temp, analyzer, consumer) = fixture();
        let model = FakeActiveModel::unpublished();
        for name in ["Sibling", "Missing", "Far", "Inner"] {
            ScalaSource::simple_type_proof(&analyzer, &consumer, name, &model);
            ScalaSource::simple_term_proof(&analyzer, &consumer, name, &model);
        }
        assert!(
            analyzer.external_index.get().is_none(),
            "answering a bare Scala name must not build the classpath index"
        );
    }

    /// The reason the two proofs above stopped calling `all_declarations()`.
    ///
    /// Without this the swap to indexed lookups is unobservable: every
    /// assertion in this module passes just as well against a whole-workspace
    /// scan, which is exactly what made the scan survive this long.
    #[test]
    fn a_name_proof_never_scans_every_workspace_declaration() {
        let (_temp, analyzer, consumer) = fixture();
        let model = FakeActiveModel::unpublished();
        // Warm the indexes first: building one is allowed to scan, answering a
        // name is not.
        ScalaSource::simple_type_proof(&analyzer, &consumer, "Sibling", &model);
        analyzer.inner.reset_full_declaration_scan_count_for_test();
        for name in [
            "Sibling",
            "Paired",
            "Lonely",
            "Inner",
            "FileLocal",
            "Missing",
        ] {
            ScalaSource::simple_type_proof(&analyzer, &consumer, name, &model);
            ScalaSource::simple_term_proof(&analyzer, &consumer, name, &model);
        }
        assert_eq!(
            0,
            analyzer.inner.full_declaration_scan_count_for_test(),
            "answering a bare Scala name must not walk every declaration in the workspace"
        );
    }
}

#[derive(Default)]
struct ScalaDeadCodeMemo {
    file_count: Option<usize>,
    overloaded_fqns: HashMap<String, bool>,
    bulk_context: Option<Option<ScalaDeadCodeBulkContext>>,
}

struct ScalaDeadCodeBulk;

impl DeadCodeBulkProof for ScalaDeadCodeBulk {
    fn id(&self) -> EdgePassId {
        EdgePassId::Scala
    }

    fn new_memo(&self) -> Box<dyn std::any::Any + Send> {
        Box::new(ScalaDeadCodeMemo::default())
    }

    /// Inverted cap polarity, deliberately: past the file cap a Scala candidate goes
    /// *into* the bulk bucket, where the shared cap check reports it once for the whole
    /// bucket, rather than falling through to a per-symbol scan that would pay the cost
    /// the cap exists to avoid.
    fn needs_precise_scan(&self, routing: DeadCodeRouting<'_>) -> bool {
        let scope = AnalyzerQueryScope::new(routing.analyzer);
        let token = scope.token();
        let DeadCodeRouting {
            analyzer,
            candidate,
            file_cap,
            memo,
        } = routing;
        let ScalaDeadCodeMemo {
            file_count,
            overloaded_fqns,
            bulk_context,
        } = memo.downcast_mut().expect("Scala bulk memo");
        if *file_count.get_or_insert_with(|| analyzable_file_count(analyzer, Language::Scala))
            > file_cap
        {
            return false;
        }

        let mut overloads = HashSet::default();
        if candidate.is_function() {
            let fqn = candidate.fq_name();
            if *overloaded_fqns.entry(fqn.clone()).or_insert_with(|| {
                fqn_has_multiple_function_definitions(analyzer, Language::Scala, &fqn)
            }) {
                overloads.insert(fqn);
            }
        }
        let Some(context) = bulk_context
            .get_or_insert_with(|| ScalaDeadCodeBulkContext::from_analyzer(analyzer))
            .as_ref()
        else {
            return true;
        };

        matches!(
            dead_code_bulk_eligibility(analyzer, token, candidate, &overloads, context),
            ScalaDeadCodeBulkEligibility::NeedsPrecise
        )
    }

    fn supports_precise_inbound_preflight(&self, routing: DeadCodeRouting<'_>) -> bool {
        let ScalaDeadCodeMemo {
            overloaded_fqns, ..
        } = routing.memo.downcast_mut().expect("Scala bulk memo");
        if !routing.candidate.is_function() {
            return false;
        }
        let fqn = routing.candidate.fq_name();
        *overloaded_fqns.entry(fqn.clone()).or_insert_with(|| {
            fqn_has_multiple_function_definitions(routing.analyzer, Language::Scala, &fqn)
        })
    }

    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight {
        DeadCodeBulkPreflight::Ready {
            label: "Scala",
            files: analyzable_file_count(analyzer, Language::Scala),
        }
    }

    /// The full builder, not the workspace one every sibling uses: it has no `keep_file`
    /// predicate, and its result is the analyzer-cached whole-project edge set.
    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let callees = candidate_fqns(candidates);
        build_inbound_scala_usage_edges(analyzer, token, &callees).map(DeadCodeBulkEdges::Fqn)
    }
}
