#[doc(hidden)]
pub mod adapter;
mod call_conversion;
mod clones;
pub(crate) mod diagnostics;
mod hierarchy;
pub(crate) mod imports;
#[doc(hidden)]
pub mod language;
mod scalar;
mod semantic;
mod semantic_adaptation;
mod source_facts;
pub(crate) mod source_publication;
#[doc(hidden)]
pub mod source_storage;
mod structural;
mod syntax;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::delegate_inner_test_hook_methods;
use brokk_bifrost_analysis::{
    delegate_inner_methods, delegate_inner_procedure_fact_methods,
    forward_file_identity_invalidation, forward_relational_definition_batch,
    impl_forward_query_provider,
};

use crate::analyzer::scala::source_facts::ScalaSourceFacts;

pub use crate::analyzer::scala::scalar::scala_declared_scalar_types;

use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::package_exists_value;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::analyzer::query_token::QueryToken;

pub(crate) fn scala_package_exists_in_language(
    language: brokk_bifrost_core::analyzer::model::Language,
    package: &str,
    lookup: impl FnOnce(&str) -> bool,
) -> bool {
    language == brokk_bifrost_core::analyzer::model::Language::Scala && lookup(package)
}

pub(crate) fn case_block_is_partial_function(node: tree_sitter::Node<'_>) -> bool {
    !node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "match_expression" | "catch_clause" | "try_expression"
        )
    })
}

use brokk_bifrost_analysis::analyzer::clone_detection::detect_language_structural_clone_smells;

use brokk_bifrost_core::analyzer::common::language_for_file as file_language;

use crate::analyzer::jvm::dependency_discovery::is_jvm_dependency_input;

use crate::analyzer::jvm::external::JvmExternalDeclarationIndex;

use crate::analyzer::jvm::external::JvmExternalDeclarations;

use crate::analyzer::jvm::retained_external_index_state;
mod call_applicability;

use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;

use brokk_bifrost_analysis::analyzer::languages::DeadCodeBulkEdges;

use brokk_bifrost_analysis::analyzer::languages::DeadCodeBulkPreflight;

use brokk_bifrost_analysis::analyzer::languages::DeadCodeBulkProof;

use brokk_bifrost_analysis::analyzer::languages::DeadCodeRouting;

use brokk_bifrost_analysis::analyzer::languages::DeadCodeSupport;

use brokk_bifrost_analysis::analyzer::languages::EdgePassId;

use brokk_bifrost_analysis::analyzer::languages::EdgeSiteScanCtx;

use brokk_bifrost_analysis::analyzer::languages::EdgeWeightScanCtx;

use brokk_bifrost_analysis::analyzer::languages::LanguageEdgePass;

use brokk_bifrost_analysis::analyzer::languages::LanguageEdgeSites;

use brokk_bifrost_analysis::analyzer::languages::LanguageEdgeWeights;

use brokk_bifrost_analysis::analyzer::languages::LanguageSupport;

use brokk_bifrost_analysis::analyzer::languages::StructuralReceiverResolver;

use brokk_bifrost_analysis::analyzer::languages::analyzable_file_count;

use brokk_bifrost_analysis::analyzer::languages::fqn_has_multiple_function_definitions;

use brokk_bifrost_analysis::analyzer::languages::ready_preflight;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState;

use brokk_bifrost_core::analyzer::type_relations::TypeRelation;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome;

use crate::analyzer::usages::get_definition::scala::resolve_scala_bounded;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupOutcome;

use crate::analyzer::usages::get_type::resolve_scala_type_bounded;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::UsageEdgesCache;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::weight_usage_edges;

use crate::analyzer::usages::scala_graph::ScalaDeadCodeBulkContext;

use crate::analyzer::usages::scala_graph::ScalaDeadCodeBulkEligibility;

use crate::analyzer::usages::scala_graph::ScalaUsageGraphStrategy;

use crate::analyzer::usages::scala_graph::build_inbound_scala_usage_edges_with_completeness;

use crate::analyzer::usages::scala_graph::build_scala_usage_edge_weights;

use crate::analyzer::usages::scala_graph::dead_code_bulk_eligibility;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

use brokk_bifrost_core::analyzer::weighted_cache::build_weighted_cache;

use brokk_bifrost_core::analyzer::weighted_cache::weight_code_unit_set;

use brokk_bifrost_core::analyzer::weighted_cache::weight_code_unit_vec_by_unit;

use brokk_bifrost_core::analyzer::weighted_cache::weight_project_file_set;

use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::AnalyzerStoreContext;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BulkFileStateSource;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::ForwardQueryProvider;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;

use brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::pool_memo::PoolSafeMemo;

use brokk_bifrost_core::analyzer::project::Project;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::SignatureMetadata;

use brokk_bifrost_core::analyzer::model::TestAssertionSmell;

use brokk_bifrost_core::analyzer::model::TestAssertionWeights;

use brokk_bifrost_core::analyzer::capabilities::TestDetectionProvider;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

use brokk_bifrost_core::analyzer::capabilities::TypeAliasProvider;

use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;

use brokk_bifrost_core::analyzer::model::CloneSmell;

use brokk_bifrost_core::CancellationToken;
use brokk_bifrost_core::analyzer::fq_name::{SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::model::CloneSmellWeights;
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
use std::sync::{Arc, Mutex, OnceLock};

pub(crate) use brokk_bifrost_jvm::scala::graph::inverted::ProjectTypes as ScalaProjectTypes;

pub(crate) use brokk_bifrost_core::analyzer::model::ScalaExportInfo;

pub(crate) use crate::analyzer::scala::adapter::ScalaAdapter;
pub(crate) use brokk_bifrost_jvm::proof::{
    JvmActiveSemanticModel, JvmModelDisposition, JvmProofGap, model_disposition_over_tiers,
    prove_against_active_model,
};
use brokk_bifrost_jvm::scala::graph::inverted::{
    ScalaProjectTypesSeed, ScalaProjectTypesSweep, ScalaSourceFactsCache,
    new_scala_source_facts_cache,
};
pub(crate) use brokk_bifrost_jvm::scala::graph_support::{
    ScalaCallableFactsIndex, ScalaDefinitionIndex, ScalaFileFacts, ScalaFileFactsProvider,
    ScalaForwardOwnerFacts, ScalaNameProof, ScalaSource,
};

pub(crate) use brokk_bifrost_jvm::scala::supertypes::ScalaSupertypeLookupPath;
use brokk_bifrost_jvm::scala::test_detection::detect_scala_test_assertion_smells;
#[doc = " Scala's pure name, signature and delimiter helpers. They read and produce"]
#[doc = " strings only, so they moved with the language knowledge they serve."]
pub(crate) use brokk_bifrost_jvm::scala::{
    scala_default_type_name, scala_normalize_full_name, scala_package_fq_name,
};

use crate::analyzer::scala::clones::build_scala_clone_candidate_data;

pub(crate) use brokk_bifrost_jvm::scala::wildcard_imports::scala_enclosing_package_root_candidates;

pub(crate) use brokk_bifrost_jvm::scala::wildcard_imports::scala_import_path;

pub(crate) use brokk_bifrost_jvm::scala::wildcard_imports::scala_import_path_candidates;

pub(crate) use brokk_bifrost_jvm::scala::wildcard_imports::scala_import_visible_at;

/// Whether `unit` is the code unit Scala declaration extraction publishes for a
/// compiler-synthesized companion object: the `X$` beside a `case class X` that
/// has no authored companion. No source writes it.
///
/// The persisted synthetic flag plus the structured [`SegmentKind::Companion`]
/// kind distinguish these from written anonymous templates and primary
/// constructors, whose identities the graph must retain.
pub(crate) fn scala_generated_companion_owner(unit: &CodeUnit) -> bool {
    unit.is_class()
        && unit.is_synthetic()
        && unit
            .fq()
            .last()
            .is_some_and(|segment| segment_interner().resolve(segment).1 == SegmentKind::Companion)
}

fn scala_usage_graph_declaration(unit: &CodeUnit) -> bool {
    // Generated companion owners have no authored graph declaration. Generated
    // members already alias their primary constructors rather than publishing
    // separate CodeUnits.
    !scala_generated_companion_owner(unit)
}

/// Decode one persisted [`FileState`] into the thirteen per-file facts the
/// Scala graph reads.
///
/// The state's own fields are moved out rather than cloned: this is the one
/// caller, and it owns the map. Everything left behind is another language's
/// column or store bookkeeping.
fn scala_file_facts(mut state: FileState) -> ScalaFileFacts {
    state.declarations.retain(scala_usage_graph_declaration);
    state
        .definition_lookup_units
        .retain(scala_usage_graph_declaration);
    state
        .scala_exports
        .retain(|owner, _| scala_usage_graph_declaration(owner));
    state
        .supertype_lookup_paths
        .retain(|owner, _| scala_usage_graph_declaration(owner));
    state
        .signatures
        .retain(|unit, _| scala_usage_graph_declaration(unit));
    state
        .signature_metadata
        .retain(|unit, _| scala_usage_graph_declaration(unit));
    state
        .ranges
        .retain(|unit, _| scala_usage_graph_declaration(unit));
    state.children.retain(|owner, children| {
        children.retain(scala_usage_graph_declaration);
        scala_usage_graph_declaration(owner)
    });
    state.scala_traits.retain(scala_usage_graph_declaration);
    state.type_aliases.retain(scala_usage_graph_declaration);
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
        let mut value = match &self.backend {
            ScalaRelationalBackend::Frontier(frontier) => frontier.ask(&question),
            ScalaRelationalBackend::Store(inner) => {
                let request = question.request(0);
                match inner.point(&request, &CancellationToken::new()) {
                    RelationalPointOutcome::Complete(result) => result.value,
                    RelationalPointOutcome::Cancelled => {
                        RelationalDefinitionValue::empty_for(&request.query)
                    }
                    RelationalPointOutcome::Failed(error) => {
                        inner.record_query_failure(
                            brokk_bifrost_analysis::analyzer::store::StoreError::new(
                                error.message(),
                            ),
                        );
                        RelationalDefinitionValue::empty_for(&request.query)
                    }
                }
            }
        };
        if let RelationalDefinitionValue::Definitions(units) = &mut value {
            units.retain(scala_usage_graph_declaration);
        }
        value
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

    fn rendered_fq(&self, name: &str) -> brokk_bifrost_core::analyzer::fq_name::FqName {
        brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
            Language::Scala,
            name,
            brokk_bifrost_core::analyzer::fq_name::segment_interner(),
        )
    }

    /// The terminal identifier of an already-rendered qualified name.
    ///
    /// A rendered name is joined by `.`, and a Scala member may be spelled
    /// with any of the *selector* splitter's other delimiters: `::` names the
    /// cons cell, and `+` and `/` are ordinary method names. Routing a
    /// rendered name through `parse_symbol_path` therefore reads
    /// `scala.collection.immutable.::` as the package and, for a name that is
    /// nothing but delimiters, produces no segment at all. So the terminal
    /// comes from the rendered-name helper, which splits on `.` with the same
    /// backtick rule (#3032).
    fn terminal_identifier<'a>(&self, name: &'a str) -> &'a str {
        brokk_bifrost_core::analyzer::symbol_path::rendered_terminal_segment(Language::Scala, name)
    }

    fn structured_name_query(
        &self,
        name: brokk_bifrost_core::analyzer::fq_name::FqName,
        query: RelationalDefinitionQuery,
    ) -> RelationalDefinitionValue {
        self.definition_query(RelationalName::stable(name), query)
    }

    fn identifier_query(&self, identifier: &str, file: Option<ProjectFile>) -> Vec<CodeUnit> {
        let mut name = brokk_bifrost_core::analyzer::fq_name::FqName::new();
        name.push(
            brokk_bifrost_core::analyzer::fq_name::segment_interner().intern(
                identifier,
                brokk_bifrost_core::analyzer::fq_name::SegmentKind::Unknown,
            ),
        );
        match self.structured_name_query(name, RelationalDefinitionQuery::Identifier { file }) {
            RelationalDefinitionValue::Definitions(units) => units,
            _ => unreachable!("Scala identifier query returned the wrong shape"),
        }
    }
}

impl ScalaDefinitionIndex for ScalaRelationalDefinitionIndex {
    fn by_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        // A name with no terminal identifier names no declaration; the empty
        // string and a malformed trailing separator are the same answer.
        let terminal = self.terminal_identifier(fqn);
        if terminal.is_empty() {
            return Vec::new();
        }
        // The exact-name query needs the whole name as segments, which only
        // the selector splitter produces; a name it cannot segment at all
        // (`::`) is answered by the identifier query on the terminal alone.
        let structured = self.rendered_fq(fqn);
        let mut candidates = if structured.is_empty() {
            Vec::new()
        } else {
            match self.structured_name_query(structured, RelationalDefinitionQuery::ExactName) {
                RelationalDefinitionValue::Definitions(units) => units,
                _ => unreachable!("Scala exact-name query returned the wrong shape"),
            }
        };
        candidates.extend(self.identifier_query(terminal, None));
        candidates.retain(|unit| unit.fq_name() == fqn);
        candidates.sort();
        candidates.dedup();
        candidates
    }

    fn by_normalized_fqn(&self, normalized: &str) -> Vec<CodeUnit> {
        let terminal = self.terminal_identifier(normalized);
        if terminal.is_empty() {
            return Vec::new();
        }
        let structured = self.rendered_fq(normalized);
        let mut candidates = if structured.is_empty() {
            Vec::new()
        } else {
            match self.structured_name_query(structured, RelationalDefinitionQuery::NormalizedName)
            {
                RelationalDefinitionValue::Definitions(units) => units,
                _ => unreachable!("Scala normalized-name query returned the wrong shape"),
            }
        };
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
        package_exists_value(&self.package_query(
            package,
            RelationalDefinitionQuery::PackageRelation(PackageRelationKind::Exists),
        ))
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
        owner: &brokk_bifrost_core::analyzer::fq_name::FqName,
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
        let units =
            match self.package_query(package, RelationalDefinitionQuery::PackageTypesInPackage) {
                RelationalDefinitionValue::Definitions(units) => units,
                _ => unreachable!("Scala package-types query returned the wrong shape"),
            };
        let mut grouped =
            brokk_bifrost_jvm::scala::scala_group_package_types(package, units.iter());
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
            self.fqn(fqn)
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
        scala_package_exists_in_language(language, package, |package| {
            ScalaDefinitionIndex::package_exists(self, package)
        })
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
    ) -> Vec<brokk_bifrost_core::analyzer::definition_lookup::RelationalCallableFact> {
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
                        inner.record_query_failure(
                            brokk_bifrost_analysis::analyzer::store::StoreError::new(
                                error.message(),
                            ),
                        );
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
    let (index, facts) = scala_store_backed_indexes(inner);
    ScalaProjectTypes::from_parts(index, facts, file_states)
}

/// The analyzer-cached [`ScalaProjectTypes`] from a seed whose hierarchy was
/// already resolved on the relational frontier. Definition and callable
/// questions stay store-backed as in [`build_scala_project_types`]; what this
/// avoids is resolving the whole workspace's supertypes one synchronous store
/// read at a time, which held every worker of a candidate-discovery pass on
/// akka (2,656 Scala files) past the fuzzer's probe cap.
fn build_scala_project_types_from_seed(
    inner: TreeSitterAnalyzer<ScalaAdapter>,
    seed: ScalaProjectTypesSeed,
) -> ScalaProjectTypes {
    let (index, facts) = scala_store_backed_indexes(inner);
    ScalaProjectTypes::from_seed(index, facts, seed)
}

fn scala_store_backed_indexes(
    inner: TreeSitterAnalyzer<ScalaAdapter>,
) -> (
    Arc<ScalaRelationalDefinitionIndex>,
    Arc<ScalaRelationalCallableFacts>,
) {
    let index = Arc::new(ScalaRelationalDefinitionIndex {
        backend: ScalaRelationalBackend::Store(Box::new(inner.clone())),
    });
    let facts = Arc::new(ScalaRelationalCallableFacts {
        backend: ScalaRelationalBackend::Store(Box::new(inner)),
    });
    (index, facts)
}

/// The per-generation resolved seed plus the frontier answers its hierarchy
/// pass batched, so a later request's session starts with them instead of
/// re-asking the same workspace-derived questions.
struct ScalaResolvedQuerySeed {
    seed: ScalaProjectTypesSeed,
    answers: brokk_bifrost_analysis::analyzer::relational_frontier::FrontierAnswers,
}

/// How one request obtained the workspace's resolved Scala seed.
pub(crate) enum ScalaResolvedSeedOutcome {
    Ready(ScalaProjectTypesSeed),
    Cancelled,
    Failed(&'static str),
}

/// One file's lazily hydrated facts cell in [`ScalaQueryFileFactsProvider`].
type ScalaQueryFileFactsCell = Arc<OnceLock<Option<Arc<ScalaFileFacts>>>>;

/// The per-file facts source a targeted Scala usage query resolves through
/// (#3142).
///
/// One `OnceLock` cell per touched file pins a single hydration, exactly as
/// the eager whole-workspace read hydrated each file once; the cells outlive
/// the frontier's provisional rebuilds because a file's persisted facts are
/// not a provisional relational answer. A file the store cannot hydrate
/// caches `None`, the same answer its absence from the eager map gave.
struct ScalaQueryFileFactsProvider {
    inner: TreeSitterAnalyzer<ScalaAdapter>,
    cells: Mutex<HashMap<ProjectFile, ScalaQueryFileFactsCell>>,
    touched: Arc<AtomicUsize>,
}

impl ScalaQueryFileFactsProvider {
    /// The file's cell, creating it empty on first touch. Cell creation is
    /// the query's touched-file count: every created cell hydrates once and
    /// stays for the rest of the query.
    fn cell_for(
        &self,
        cells: &mut HashMap<ProjectFile, ScalaQueryFileFactsCell>,
        file: &ProjectFile,
    ) -> ScalaQueryFileFactsCell {
        match cells.entry(file.clone()) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.get().clone(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                self.touched.fetch_add(1, Ordering::Relaxed);
                entry.insert(Arc::new(OnceLock::new())).clone()
            }
        }
    }
}

impl ScalaFileFactsProvider for ScalaQueryFileFactsProvider {
    fn file_facts(&self, file: &ProjectFile) -> Option<Arc<ScalaFileFacts>> {
        let cell = {
            let mut guard = self
                .cells
                .lock()
                .expect("Scala query file-facts cache poisoned");
            self.cell_for(&mut guard, file)
        };
        cell.get_or_init(|| {
            self.inner
                .bulk_file_states([file.clone()], BulkFileStateSource::Omit)
                .remove(file)
                .map(|state| Arc::new(scala_file_facts(state)))
        })
        .clone()
    }

    fn prefetch_file_facts(&self, files: &[ProjectFile]) {
        let pending: Vec<(ProjectFile, ScalaQueryFileFactsCell)> = {
            let mut guard = self
                .cells
                .lock()
                .expect("Scala query file-facts cache poisoned");
            files
                .iter()
                .map(|file| (file.clone(), self.cell_for(&mut guard, file)))
                .filter(|(_, cell)| cell.get().is_none())
                .collect()
        };
        for chunk in pending.chunks(SCALA_QUERY_SWEEP_CHUNK_FILES) {
            let mut states = self.inner.bulk_file_states(
                chunk.iter().map(|(file, _)| file.clone()),
                BulkFileStateSource::Omit,
            );
            for (file, cell) in chunk {
                cell.get_or_init(|| {
                    states
                        .remove(file)
                        .map(|state| Arc::new(scala_file_facts(state)))
                });
            }
        }
    }
}

/// The files one sweep batch hydrates at a time.
///
/// The sweep keeps only the seed's derived structures and the lean hierarchy
/// inputs, so this bounds the live fat per-file records during the
/// whole-workspace pass to one chunk instead of the workspace (#3142).
const SCALA_QUERY_SWEEP_CHUNK_FILES: usize = 64;

/// The targeted usage query's seed: the workspace-wide type-namespace
/// structures derived in a chunked sweep, plus a lazily rehydrated per-file
/// facts source for the files resolution actually touches. Unlike
/// [`build_scala_project_types`], no whole-workspace map of thirteen-field
/// per-file records is materialized or retained.
fn scala_query_file_facts_provider(
    inner: &TreeSitterAnalyzer<ScalaAdapter>,
    touched: Arc<AtomicUsize>,
) -> Arc<dyn ScalaFileFactsProvider> {
    Arc::new(ScalaQueryFileFactsProvider {
        inner: inner.clone(),
        cells: Mutex::new(HashMap::default()),
        touched,
    })
}

fn scala_project_types_query_seed(
    inner: &TreeSitterAnalyzer<ScalaAdapter>,
    touched: Arc<AtomicUsize>,
    files: &[ProjectFile],
) -> ScalaProjectTypesSeed {
    let provider = scala_query_file_facts_provider(inner, touched);
    let mut sweep = ScalaProjectTypesSweep::default();
    for chunk in files.chunks(SCALA_QUERY_SWEEP_CHUNK_FILES) {
        let states = inner.bulk_file_states(chunk.iter().cloned(), BulkFileStateSource::Omit);
        for (file, state) in states {
            sweep.fold_file(file, scala_file_facts(state));
        }
    }
    sweep.into_seed(provider)
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
    external_index: Arc<OnceLock<Arc<JvmExternalDeclarationIndex>>>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    source_facts: Cache<
        (
            brokk_bifrost_analysis::analyzer::store::GenerationId,
            git2::Oid,
            ProjectFile,
        ),
        Arc<brokk_bifrost_jvm::scala::source_facts::ScalaFileSourceFacts>,
    >,
    reverse_import_index: Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    file_dependency_index: Arc<OnceLock<imports::ScalaFileDependencyIndex>>,
    importable_declarations_by_package: Arc<OnceLock<HashMap<String, Arc<Vec<CodeUnit>>>>>,
    package_namespaces: Arc<OnceLock<Vec<String>>>,
    same_package_reference_index:
        Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    lazy_hierarchy_index: Arc<OnceLock<hierarchy::ScalaLazyHierarchyIndex>>,
    /// Analyzer-cached Scala usage/type-resolution support, built once per
    /// analyzer generation and reset on `update`/`update_all`.
    project_types: Arc<OnceLock<Arc<brokk_bifrost_jvm::scala::graph::inverted::ProjectTypes>>>,
    /// The workspace's Scala seed with its hierarchy resolved on the
    /// relational frontier, built once per analyzer generation. Every
    /// targeted usage query and the analyzer-cached `project_types` build
    /// start from it instead of re-sweeping the workspace.
    resolved_query_seed: Arc<OnceLock<ScalaResolvedQuerySeed>>,
    pub(crate) dead_code_usage_edges: UsageEdgesCache,
    project_types_build_count: Arc<AtomicUsize>,
    /// Files whose full per-file facts the current analyzer generation's
    /// targeted usage queries materialized through the lazy provider (#3142).
    scala_query_file_facts_touched: Arc<AtomicUsize>,
    /// Per-generation source-facts parse cache shared by every targeted
    /// usage query's `ProjectTypes` (see `ScalaSourceFactsCache`).
    scala_source_facts_by_file: ScalaSourceFactsCache,
    #[cfg(any(test, feature = "test-support"))]
    scala_query_parse_count: Arc<AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    scala_query_walk_count: Arc<AtomicUsize>,
    #[allow(dead_code)]
    type_relations: Arc<OnceLock<Vec<TypeRelation>>>,
}

impl_forward_query_provider!(ScalaAnalyzer);

impl ScalaAnalyzer {
    pub(crate) fn tree_sitter_analyzer(&self) -> &TreeSitterAnalyzer<ScalaAdapter> {
        &self.inner
    }

    pub(crate) fn update_all_with_progress(
        &self,
        progress: Option<brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress>,
    ) -> Self {
        Self::from_inner(
            self.inner.update_all_with_progress(progress),
            self.memo_budget,
            self.java_config.clone(),
        )
    }

    pub(crate) fn declaration_candidates_by_identifier_limited(
        &self,
        identifier: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows<CodeUnit> {
        self.inner
            .lookup_declarations_by_identifier_limited(identifier, limit, continue_query)
    }

    pub(crate) fn declaration_candidates_by_fqn_limited(
        &self,
        fqn: &str,
        normalized: bool,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows<CodeUnit> {
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
    ) -> brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows<CodeUnit> {
        self.inner.direct_children_limited(owner, limit)
    }

    pub(crate) fn import_info_of_limited(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        limit: usize,
    ) -> brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows<
        brokk_bifrost_core::analyzer::model::ImportInfo,
    > {
        self.inner.import_info_of_limited(token, file, limit)
    }

    pub(crate) fn namespace_of_file_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
    ) -> brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows<String> {
        self.inner.file_namespace_hint_limited(file, limit)
    }

    pub(crate) fn workspace_package_exists(&self, package: &str) -> bool {
        self.inner.persisted_package_exists(package)
    }

    pub(crate) fn workspace_fqn_prefix_exists(&self, prefix: &str) -> bool {
        self.inner.forward_fqn_prefix_exists(prefix)
    }

    delegate_inner_methods! {
        pub(crate) fn signature_metadata_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows<SignatureMetadata>;
    }

    pub(crate) fn signatures_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows<String> {
        self.inner.signatures_limited(code_unit, limit)
    }

    pub(crate) fn ranges_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows<
        brokk_bifrost_core::analyzer::model::Range,
    > {
        self.inner.ranges_limited(code_unit, limit)
    }

    pub(crate) fn supertype_lookup_paths_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows<String> {
        self.inner.supertype_lookup_paths_limited(code_unit, limit)
    }

    delegate_inner_methods! {
        pub(crate) fn raw_supertypes_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows<String>;
    }

    pub fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }

    pub(crate) fn canonical_source_facts(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_jvm::scala::source_facts::ScalaFileSourceFacts>> {
        if file_language(file) != Language::Scala {
            return None;
        }
        self.inner
            .canonical_scala_source_facts(file, &self.source_facts)
    }

    pub(crate) fn import_lexical_context_for_unit(
        &self,
        unit: &CodeUnit,
    ) -> Option<(
        Vec<String>,
        Vec<brokk_bifrost_core::analyzer::model::StructuredImportScope>,
        usize,
    )> {
        let bundle = self.canonical_source_facts(unit.source())?;
        let fact = bundle.for_unit(unit).min_by_key(|fact| {
            bundle
                .source
                .occurrence(bundle.source.declaration(fact.declaration).occurrence)
                .range
                .start_byte
        })?;
        let scopes = fact
            .lexical_scopes
            .iter()
            .map(|scope| {
                let range = bundle.source.occurrence(*scope).range;
                brokk_bifrost_core::analyzer::model::StructuredImportScope {
                    start_byte: range.start_byte,
                    end_byte: range.end_byte,
                }
            })
            .collect();
        let start = bundle
            .source
            .occurrence(bundle.source.declaration(fact.declaration).occurrence)
            .range
            .start_byte;
        Some((fact.lexical_prefixes.clone(), scopes, start))
    }

    pub(crate) fn export_infos_for_owner(&self, owner: &CodeUnit) -> Vec<ScalaExportInfo> {
        self.inner
            .fetch_file_state(owner.source())
            .map(|state| {
                brokk_bifrost_jvm::scala::scala_export_infos_for_owner(&state.scala_exports, owner)
            })
            .unwrap_or_default()
    }

    pub(crate) fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner.structural_parent_of(code_unit)
    }

    pub(crate) fn is_full_enum_case_declaration(&self, code_unit: &CodeUnit) -> bool {
        code_unit.is_class()
            && self
                .canonical_source_facts(code_unit.source())
                .is_some_and(|bundle| {
                    bundle
                        .for_unit(code_unit)
                        .any(|fact| fact.is_full_enum_case)
                })
    }

    pub(crate) fn is_case_class_declaration(&self, code_unit: &CodeUnit) -> bool {
        code_unit.is_class()
            && self
                .canonical_source_facts(code_unit.source())
                .is_some_and(|bundle| bundle.for_unit(code_unit).any(|fact| fact.is_case_class))
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
        clone.file_dependency_index = Arc::new(OnceLock::new());
        clone.project_types = Arc::new(OnceLock::new());
        clone.resolved_query_seed = Arc::new(OnceLock::new());
        clone.dead_code_usage_edges =
            build_weighted_cache(self.memo_budget / 8, weight_usage_edges);
        clone.project_types_build_count = Arc::new(AtomicUsize::new(0));
        clone.scala_query_file_facts_touched = Arc::new(AtomicUsize::new(0));
        clone.scala_source_facts_by_file = new_scala_source_facts_cache(self.memo_budget / 8);
        #[cfg(any(test, feature = "test-support"))]
        {
            clone.scala_query_parse_count = Arc::new(AtomicUsize::new(0));
            clone.scala_query_walk_count = Arc::new(AtomicUsize::new(0));
        }
        clone
    }

    pub(crate) fn clone_for_index_warm(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let java_config = config.jvm.clone();
        TreeSitterAnalyzer::wrap_with_config(
            config,
            |config| TreeSitterAnalyzer::new_with_config(project, ScalaAdapter, config),
            |inner, memo_budget| Self::from_inner(inner, memo_budget, java_config),
        )
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
            source_facts: build_weighted_cache(
                memo_budget / 8,
                |_, facts: &Arc<brokk_bifrost_jvm::scala::source_facts::ScalaFileSourceFacts>| {
                    u32::try_from(facts.estimated_retained_bytes()).unwrap_or(u32::MAX)
                },
            ),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            file_dependency_index: Arc::new(OnceLock::new()),
            importable_declarations_by_package: Arc::new(OnceLock::new()),
            package_namespaces: Arc::new(OnceLock::new()),
            same_package_reference_index: Arc::new(PoolSafeMemo::new()),
            lazy_hierarchy_index: Arc::new(OnceLock::new()),
            project_types: Arc::new(OnceLock::new()),
            resolved_query_seed: Arc::new(OnceLock::new()),
            dead_code_usage_edges: build_weighted_cache(memo_budget / 8, weight_usage_edges),
            project_types_build_count: Arc::new(AtomicUsize::new(0)),
            scala_query_file_facts_touched: Arc::new(AtomicUsize::new(0)),
            scala_source_facts_by_file: new_scala_source_facts_cache(memo_budget / 8),
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

    /// The workspace's resolved seed for one request, on that request's
    /// relational session: the cached per-generation seed with a fresh
    /// per-query facts provider (the session adopts the hierarchy answers the
    /// first request batched), or, on first use, the chunked workspace sweep
    /// (#3142) plus one hierarchy pass on `session`.
    pub(crate) fn resolved_query_seed(
        &self,
        session: &brokk_bifrost_analysis::analyzer::relational_frontier::RelationalFrontierSession<
            '_,
        >,
    ) -> ScalaResolvedSeedOutcome {
        if let Some(seed) = self.cached_resolved_query_seed(session) {
            return ScalaResolvedSeedOutcome::Ready(seed);
        }
        let workspace_files = match self.inner.project().analyzable_files(Language::Scala) {
            Ok(files) => files.into_iter().collect::<Vec<_>>(),
            Err(_) => {
                return ScalaResolvedSeedOutcome::Failed(
                    "the Scala workspace file set is unavailable",
                );
            }
        };
        let unresolved_seed = self.project_types_query_seed(&workspace_files);
        self.resolve_query_seed(session, &unresolved_seed)
    }

    fn cached_resolved_query_seed(
        &self,
        session: &brokk_bifrost_analysis::analyzer::relational_frontier::RelationalFrontierSession<
            '_,
        >,
    ) -> Option<ScalaProjectTypesSeed> {
        let cached = self.resolved_query_seed.get()?;
        session.adopt_answers(&cached.answers);
        Some(
            cached
                .seed
                .clone()
                .with_file_facts_provider(scala_query_file_facts_provider(
                    &self.inner,
                    Arc::clone(&self.scala_query_file_facts_touched),
                )),
        )
    }

    /// Resolve one already-built workspace seed and publish its hierarchy for
    /// the analyzer generation. Eager callers keep their original file-facts
    /// map and targeted callers replace it with a fresh per-query provider.
    fn resolve_query_seed(
        &self,
        session: &brokk_bifrost_analysis::analyzer::relational_frontier::RelationalFrontierSession<
            '_,
        >,
        unresolved_seed: &ScalaProjectTypesSeed,
    ) -> ScalaResolvedSeedOutcome {
        let fresh_provider = || {
            scala_query_file_facts_provider(
                &self.inner,
                Arc::clone(&self.scala_query_file_facts_touched),
            )
        };
        if let Some(seed) = self.cached_resolved_query_seed(session) {
            return ScalaResolvedSeedOutcome::Ready(seed);
        }
        let resolved_seed = match session.resolve_owned("scala_hierarchy", |frontier| {
            self.build_project_types_from_frontier(frontier, unresolved_seed.clone())
                .resolved_seed()
        }) {
            brokk_bifrost_core::analyzer::definition_lookup::RelationalFrontierOutcome::Complete(seed) => seed,
            brokk_bifrost_core::analyzer::definition_lookup::RelationalFrontierOutcome::Cancelled => {
                return ScalaResolvedSeedOutcome::Cancelled;
            }
            brokk_bifrost_core::analyzer::definition_lookup::RelationalFrontierOutcome::Failed(_) => {
                return ScalaResolvedSeedOutcome::Failed("the Scala hierarchy frontier failed");
            }
        };
        // The cached copy carries a provider nothing hydrates through, so no
        // query's touched facts outlive it; each request gets its own.
        let cached = self
            .resolved_query_seed
            .get_or_init(|| ScalaResolvedQuerySeed {
                seed: resolved_seed
                    .clone()
                    .with_file_facts_provider(fresh_provider()),
                answers: session.answer_snapshot(),
            });
        // A concurrent resolver may have published the winning seed. Its
        // hierarchy and recorded answers must travel together in this session.
        session.adopt_answers(&cached.answers);
        ScalaResolvedSeedOutcome::Ready(
            cached
                .seed
                .clone()
                .with_file_facts_provider(fresh_provider()),
        )
    }

    pub(crate) fn external_declaration_index(&self) -> &JvmExternalDeclarationIndex {
        crate::analyzer::jvm::external::get_or_build_external_declaration_index(
            self,
            &self.external_index,
            &self.java_config,
            self.inner.project(),
            self.inner.analyzer_store(),
        )
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
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
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
    #[doc(hidden)]
    pub fn external_boundary_evidence(
        &self,
        token: QueryToken<'_>,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        file: &ProjectFile,
        name: &str,
    ) -> (BoundaryStatus, Option<String>) {
        let type_evidence = self
            .external_type_name(token, packs.clone(), file, name)
            .map(|fqn| brokk_bifrost_analysis::analyzer::languages::ExternalTypeBoundaryEvidence::Indexed(Some(fqn)))
            .unwrap_or(brokk_bifrost_analysis::analyzer::languages::ExternalTypeBoundaryEvidence::Unresolved);
        // A member spelling leaves the workspace exactly as its owner type
        // does, so the member tier runs where the type tier found nothing
        // (#1900). A member the surface does not declare changes nothing.
        // One ladder answers here and in the resolver's own boundary gate, so
        // a trace and a definition cannot disagree about a spelling (#2287).
        brokk_bifrost_analysis::analyzer::languages::classify_jvm_external_boundary_evidence(
            type_evidence,
            || {
                self.resolve_member_name_with_external(token, packs, file, name)
                    .map(|member| member.fqn().to_owned())
            },
            || {
                self.external_declaration_index()
                    .production_diagnostic_count()
                    > 0
            },
        )
    }

    /// The fully-qualified name of the external type a written Scala type
    /// spelling names, or `None` when the shared surface names none (#3454).
    ///
    /// This is [`Self::external_type_spelling`] alone -- the same ladder the
    /// boundary evidence and the member gate read -- exposed to callers that
    /// need the external *type* rather than a boundary classification. The
    /// receiver-typing path uses it for a written annotation whose workspace
    /// resolution declined because an explicit import binds the name outside
    /// the indexed workspace (`import java.net.URL`; `url: URL`), so the
    /// receiver's owner is the imported type and its members are reached
    /// through the external member route. Keeping this the one ladder means a
    /// typed receiver and a trace row cannot disagree about a spelling.
    pub(crate) fn external_type_name(
        &self,
        token: QueryToken<'_>,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        file: &ProjectFile,
        spelling: &str,
    ) -> Option<String> {
        let external = self.external_declarations(packs);
        let package_name = self.inner.package_name_of(file).unwrap_or_default();
        self.external_type_spelling(token, &external, file, &package_name, spelling)
            .map(|ty| ty.fqn().to_owned())
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
        let imports = self.inner.import_info_of(token, file);
        Self::external_type_spelling_in(external, package_name, spelling, &imports)
    }

    /// [`Self::external_type_spelling`] over a caller-supplied import set.
    ///
    /// The hierarchy walk reads the imports the parser recorded at the
    /// declaration whose supertypes it lands (#3454), rather than re-reading
    /// the file, so the one ladder is spelled once and both callers agree
    /// about which declaration a spelling names.
    fn external_type_spelling_in(
        external: &JvmExternalDeclarations<'_>,
        package_name: &str,
        spelling: &str,
        imports: &[brokk_bifrost_core::analyzer::model::ImportInfo],
    ) -> Option<crate::analyzer::jvm::external::JvmExternalType> {
        if spelling.contains('.')
            && let Some(ty) = external.resolve_qualified_name(spelling, package_name)
        {
            return Some(ty);
        }
        if let Some(ty) = external.resolve_java_lang(spelling) {
            return Some(ty);
        }
        for import in imports {
            let Some(path) = scala_import_path(import) else {
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
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
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
        brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup::new(
            self,
            Language::Scala,
        )
        .types_in_package(package_name, name)
        .iter()
        .any(|unit| {
            matches_name(unit)
                && unit.package_name() == package_name
                && self.inner.declarations(unit.source()).contains(unit)
        })
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

    pub(crate) fn project_types_query_seed(&self, files: &[ProjectFile]) -> ScalaProjectTypesSeed {
        scala_project_types_query_seed(
            &self.inner,
            Arc::clone(&self.scala_query_file_facts_touched),
            files,
        )
        .with_source_facts_cache(self.scala_source_facts_by_file.clone())
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
            .get_or_init(|| brokk_bifrost_analysis::analyzer::common::persistent_cache_fill(self, "scala.project_types", || {
                self.project_types_build_count
                    .fetch_add(1, Ordering::Relaxed);
                let file_states: HashMap<ProjectFile, ScalaFileFacts> = file_states()
                    .into_iter()
                    .map(|(file, state)| (file, scala_file_facts(state)))
                    .collect();
                let file_states = Arc::new(file_states);
                let unresolved_seed = ScalaProjectTypes::seed(Arc::clone(&file_states))
                    .with_source_facts_cache(self.scala_source_facts_by_file.clone());
                let uncancelled = brokk_bifrost_core::cancellation::CancellationToken::new();
                let session = brokk_bifrost_analysis::analyzer::relational_frontier::RelationalFrontierSession::new(
                    self,
                    &uncancelled,
                );
                let types = match self.resolve_query_seed(&session, &unresolved_seed) {
                    ScalaResolvedSeedOutcome::Ready(seed) => build_scala_project_types_from_seed(
                        self.inner.clone(),
                        seed.with_eager_file_facts(file_states),
                    ),
                    // The frontier read failed part-way; the same eager seed
                    // resolves through the store backend and reports its own
                    // errors without reading any file twice.
                    ScalaResolvedSeedOutcome::Cancelled | ScalaResolvedSeedOutcome::Failed(_) => {
                        self.record_degraded_persistent_fill("scala.project_types", "frontier_fallback");
                        build_scala_project_types_from_seed(self.inner.clone(), unresolved_seed)
                    }
                };
                Arc::new(types)
            }))
            .clone()
    }

    pub(crate) fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, brokk_bifrost_analysis::analyzer::store::StoreError> {
        let java_config = config.jvm.clone();
        TreeSitterAnalyzer::try_wrap_with_config(
            config,
            |config| {
                TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
                    project,
                    ScalaAdapter,
                    config,
                    store_context,
                    progress,
                )
            },
            |inner, memo_budget| Self::from_inner(inner, memo_budget, java_config),
        )
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
    ) -> HashMap<ProjectFile, Vec<brokk_bifrost_core::analyzer::model::ImportInfo>> {
        self.inner.bulk_import_infos(files)
    }

    delegate_inner_methods! {
        #[doc(hidden)]
        pub fn reset_full_hydration_count_for_test(&self);
    }

    delegate_inner_methods! {
        #[doc(hidden)]
        pub fn full_hydration_count_for_test(&self) -> usize;
    }

    #[doc(hidden)]
    pub fn bulk_hydration_count_for_test(&self) -> usize {
        self.inner.bulk_hydration_count_for_test()
    }

    #[cfg(test)]
    pub(crate) fn clear_retained_file_states_for_test(&mut self) {
        self.inner.clear_retained_file_states_for_test();
    }
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
    brokk_bifrost_core::analyzer::common::qualify_dotted_name(package_name, name)
}

impl ScalaSource for ScalaAnalyzer {
    fn canonical_source_facts(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_jvm::scala::source_facts::ScalaFileSourceFacts>> {
        ScalaAnalyzer::canonical_source_facts(self, file)
    }

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
        let retained = self.external_index.get().map(Arc::as_ref);
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
        let retained = self.external_index.get().map(Arc::as_ref);
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
        brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup::new(
            self,
            Language::Scala,
        )
        .by_normalized_fqn(normalized)
    }

    fn types_in_package(&self, package: &str, simple: &str) -> Vec<CodeUnit> {
        brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup::new(
            self,
            Language::Scala,
        )
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

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

impl CodeUnitIndex for ScalaAnalyzer {
    delegate_inner_methods! {
        /// Forwarded so the request-scoped memo on the inner analyzer answers
        /// (#2679); the trait default would rebuild uncached per call.
        fn class_range_index(
        &self,
        file: &ProjectFile,
    ) -> std::sync::Arc<brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex>;
    }

    delegate_inner_methods! {
        fn enclosing_code_unit(
        &self,
        file: &ProjectFile,
        range: &brokk_bifrost_analysis::analyzer::Range,
    ) -> Option<CodeUnit>;
    }

    delegate_inner_methods! {
        fn enclosing_code_unit_for_lines(
            &self,
            file: &ProjectFile,
            start_line: usize,
            end_line: usize,
        ) -> Option<CodeUnit>;
    }

    delegate_inner_methods! {
        fn top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit>;
    }

    fn summary_file_projection(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_core::analyzer::model::SummaryFileProjection>> {
        self.inner
            .summary_file_projection(file)
            .map(brokk_bifrost_analysis::analyzer::common::non_synthetic_summary_projection)
    }

    delegate_inner_methods! {
        fn analyzed_files(&self) -> Vec<ProjectFile>;
    }

    delegate_inner_methods! {
        fn indexed_source(&self, file: &ProjectFile) -> Option<String>;
    }

    delegate_inner_methods! {
        fn indexed_blob_oid(&self, file: &ProjectFile) -> Option<brokk_bifrost_analysis::analyzer::Oid>;
    }

    delegate_inner_methods! {
        fn location_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit>;
    }

    delegate_inner_methods! {
        fn location_ranges(&self, code_unit: &CodeUnit) -> Vec<brokk_bifrost_analysis::analyzer::Range>;
    }

    delegate_inner_methods! {
        fn indexed_source_matches(&self, file: &ProjectFile, source: &str) -> bool;
    }

    delegate_inner_methods! {
        fn is_analyzed(&self, file: &ProjectFile) -> bool;
    }

    delegate_inner_methods! {
        fn retain_analyzed(&self, candidates: &[ProjectFile]) -> Vec<ProjectFile>;
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.all_declarations()
    }

    delegate_inner_methods! {
        fn declarations_sharing_name(&self, unit: &CodeUnit) -> Vec<CodeUnit>;
    }

    delegate_inner_methods! {
        fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit>;
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.definitions(fq_name)
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        brokk_bifrost_analysis::analyzer::common::non_synthetic_children(
            self.inner.direct_children(code_unit),
        )
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.structural_parent_of(code_unit)
            .or_else(|| CodeUnitIndex::parent_of(&self.inner, code_unit))
    }

    delegate_inner_methods! {
        fn ranges(&self, code_unit: &CodeUnit) -> Vec<brokk_bifrost_analysis::analyzer::Range>;
    }

    fn ranges_with_limit(
        &self,
        code_unit: &CodeUnit,
        max_ranges: usize,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> (Vec<brokk_bifrost_core::analyzer::model::Range>, usize, bool) {
        self.inner
            .ranges_with_limit(code_unit, max_ranges, cancellation)
    }

    fn signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.forward_owner_facts(code_unit)
            .map(|facts| facts.signatures)
            .unwrap_or_else(|| self.inner.signatures(code_unit))
    }

    delegate_inner_methods! {
        fn signature_metadata(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata>;
    }

    delegate_inner_methods! {
        fn languages(&self) -> BTreeSet<Language>;
    }

    delegate_inner_methods! {
        fn project(&self) -> &dyn Project;
    }

    delegate_inner_methods! {
        fn get_all_declarations(&self) -> Vec<CodeUnit>;
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        let rendered =
            brokk_bifrost_analysis::analyzer::common::render_skeleton(self, code_unit, false);
        brokk_bifrost_analysis::analyzer::common::normalize_skeleton(rendered)
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        let rendered =
            brokk_bifrost_analysis::analyzer::common::render_skeleton(self, code_unit, true);
        brokk_bifrost_analysis::analyzer::common::normalize_skeleton(rendered)
    }

    delegate_inner_methods! {
        fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String>;
    }

    delegate_inner_methods! {
        fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String>;
    }

    delegate_inner_methods! {
        fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit>;
    }

    delegate_inner_methods! {
        fn search_definitions_by_suffix_pattern(
        &self,
        pattern: &str,
        terminal_identifiers: &[String],
        language: Language,
    ) -> BTreeSet<CodeUnit>;
    }

    delegate_inner_methods! {
        fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit>;
    }

    delegate_inner_methods! {
        fn has_complete_symbol_lookup_index(&self) -> bool;
    }

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_declarations_by_identifier(identifier)
    }
}

impl IAnalyzer for ScalaAnalyzer {
    delegate_inner_procedure_fact_methods!();

    forward_relational_definition_batch!();

    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerTestHooks {
        self
    }

    forward_file_identity_invalidation!();

    fn working_tree_identity(
        &self,
    ) -> Option<std::sync::Arc<brokk_bifrost_core::gitblob::WorkingTreeIdentity>> {
        self.inner.working_tree_identity()
    }

    brokk_bifrost_analysis::forward_query_read_ledger!();

    fn begin_query(
        &self,
        context: &Arc<brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext>,
    ) {
        self.inner.begin_query(context);
    }

    fn end_query(
        &self,
        context: &Arc<brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext>,
    ) {
        self.inner.end_query(context);
    }

    delegate_inner_methods! {
        fn prefetch_definitions(&self, fq_names: &[String]);
    }

    delegate_inner_methods! {
        fn record_query_failure(&self, error: brokk_bifrost_analysis::analyzer::store::StoreError);
    }

    delegate_inner_methods! {
        fn workspace_file_index_cell(&self) -> Option<brokk_bifrost_analysis::analyzer::WorkspaceFileIndexCell>;
    }

    delegate_inner_methods! {
        fn definition_lookup_memo(
        &self,
    ) -> Option<std::sync::Arc<brokk_bifrost_analysis::analyzer::DefinitionLookupMemo>>;
    }

    delegate_inner_methods! {
        fn structural_fact_providers(
        &self,
    ) -> Vec<&dyn brokk_bifrost_analysis::analyzer::structural::StructuralFactProvider>;
    }

    fn snapshot_caches(
        &self,
    ) -> Option<&brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerSnapshotCaches> {
        Some(self.inner.snapshot_caches())
    }

    delegate_inner_methods! {
        fn workspace_content_identities(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::content_identity::WorkspaceContentIdentities>;
    }

    delegate_inner_methods! {
        fn workspace_fact_indexes(
        &self,
    ) -> Vec<&dyn brokk_bifrost_analysis::analyzer::read_verification::WorkspaceFactIndex>;
    }

    delegate_inner_methods! {
        fn import_statements(&self, file: &ProjectFile) -> Vec<String>;
    }

    delegate_inner_methods! {
        fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)>;
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport {
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

    fn external_dispatch_behavior_identity(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::semantic::StableDigest> {
        Some(
            self.external_declaration_index()
                .dispatch_behavior_identity(),
        )
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let external_index = brokk_bifrost_analysis::analyzer::updated_external_index(
            &self.external_index,
            changed_files,
            is_jvm_dependency_input,
        );
        let mut updated = Self::from_inner(
            self.inner.update(changed_files),
            self.memo_budget,
            self.java_config.clone(),
        );
        updated.external_index = external_index;
        if Arc::ptr_eq(&self.external_index, &updated.external_index)
            && self.degraded_persistent_fills() > 0
        {
            updated.record_degraded_persistent_fill(
                "retained_external_index",
                "inherited_degraded_owner",
            );
        }
        updated
    }

    fn update_all(&self) -> Self {
        self.update_all_with_progress(None)
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

    fn member_family_provider(
        &self,
    ) -> Option<&dyn brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyProvider>
    {
        Some(self)
    }

    fn parse_errors(
        &self,
        file: &ProjectFile,
    ) -> Option<Vec<brokk_bifrost_core::analyzer::model::ParseError>> {
        self.inner.parse_errors(file)
    }

    delegate_inner_methods! {
        fn extract_call_receiver(&self, reference: &str) -> Option<String>;
    }

    delegate_inner_methods! {
        fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool;
    }

    delegate_inner_methods! {
        fn find_nearest_declaration(
            &self,
            file: &ProjectFile,
            start_byte: usize,
            end_byte: usize,
            ident: &str,
        ) -> Option<brokk_bifrost_analysis::analyzer::DeclarationInfo>;
    }

    fn search_symbol_candidates(
        &self,
        patterns: &brokk_bifrost_analysis::analyzer::i_analyzer::SearchSymbolPatternBatch,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> brokk_bifrost_analysis::analyzer::i_analyzer::SearchSymbolCandidates {
        self.inner.search_symbol_candidates(patterns, cancellation)
    }

    delegate_inner_methods! {
        fn contains_tests(&self, file: &ProjectFile) -> bool;
    }

    fn in_test_region(&self, code_unit: &brokk_bifrost_core::analyzer::model::CodeUnit) -> bool {
        self.inner.in_test_region(code_unit)
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        brokk_bifrost_analysis::analyzer::test_assertion_smells_for_file(
            self,
            file,
            Language::Scala,
            |source| detect_scala_test_assertion_smells(file, source, &weights),
        )
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
        detect_language_structural_clone_smells(
            self,
            files,
            weights,
            Language::Scala,
            |code_unit| build_scala_clone_candidate_data(self, code_unit, weights),
        )
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }
}

/// Scala joins the #1721 nominal-family rollout.
///
/// Scala makes `override` mandatory only when redefining a concrete member, so
/// the keyword cannot gate the relation; structure decides, as in Java, and the
/// recorded keyword is corroborating evidence. The relation follows trait-ness,
/// which the Scala declaration walk records on the template itself, so a member
/// found on a trait is `implements` and one found on a class is `overrides` --
/// the same split `ScalaAnalyzer::relation_kind` applies to type relations.
///
/// `self` is the declaration source here, but the multi-analyzer overrides the
/// hierarchy argument with its own realm-aware walk: a Scala class can extend a
/// Java class, and only the composite resolves that ancestor edge.
impl brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyProvider
    for ScalaAnalyzer
{
    fn member_family_capability(
        &self,
        member: &CodeUnit,
    ) -> brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyCapability {
        brokk_bifrost_analysis::analyzer::usages::member_family::scala_member_family_capability(
            self, member,
        )
    }

    fn member_family(
        &self,
        member: &CodeUnit,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyAnswer {
        brokk_bifrost_analysis::analyzer::usages::member_family::scala_member_family(
            self,
            self,
            member,
            cancellation,
        )
    }

    fn external_member_family(
        &self,
        identity: &brokk_bifrost_jvm::realm::JvmExternalMemberIdentity,
        max_visits: usize,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyAnswer {
        self.resolve_external_member_family(self, identity, max_visits, cancellation)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerTestHooks for ScalaAnalyzer {
    delegate_inner_test_hook_methods! {
        fn reset_relational_definition_batch_call_count_for_test(&self);
    }

    delegate_inner_test_hook_methods! {
        fn relational_definition_batch_call_count_for_test(&self) -> usize;
    }

    delegate_inner_test_hook_methods! {
        fn reset_definition_candidates_query_count_for_test(&self);
    }

    delegate_inner_test_hook_methods! {
        fn definition_candidates_query_count_for_test(&self) -> usize;
    }

    delegate_inner_test_hook_methods! {
        fn reset_definition_prefetch_batch_count_for_test(&self);
    }

    delegate_inner_test_hook_methods! {
        fn definition_prefetch_batch_count_for_test(&self) -> usize;
    }

    delegate_inner_test_hook_methods! {
        fn reset_full_declaration_scan_count_for_test(&self);
    }

    delegate_inner_test_hook_methods! {
        fn full_declaration_scan_count_for_test(&self) -> usize;
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    delegate_inner_test_hook_methods! {
        fn full_candidate_hydration_count_for_test(&self) -> usize;
    }

    delegate_inner_test_hook_methods! {
        fn bulk_candidate_hydration_count_for_test(&self) -> usize;
    }

    delegate_inner_test_hook_methods! {
        fn reset_workspace_path_scan_count_for_test(&self);
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

    fn reset_scala_query_file_facts_touched_for_test(&self) {
        self.scala_query_file_facts_touched
            .store(0, Ordering::Relaxed);
    }

    fn scala_query_file_facts_touched_for_test(&self) -> usize {
        self.scala_query_file_facts_touched.load(Ordering::Relaxed)
    }
}

static SCALA_USAGE_STRATEGY: ScalaUsageGraphStrategy = ScalaUsageGraphStrategy::new();

impl brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer for ScalaAnalyzer {
    fn analyzer(&self) -> &dyn IAnalyzer {
        self
    }

    fn program_semantics_provider(
        &self,
    ) -> &dyn brokk_bifrost_analysis::analyzer::semantic::ProgramSemanticsProvider {
        self
    }

    fn clone_with_project(
        &self,
        project: Arc<dyn Project>,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(ScalaAnalyzer::clone_with_project(self, project))
    }

    fn clone_for_index_warm(
        &self,
        project: Arc<dyn Project>,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(ScalaAnalyzer::clone_for_index_warm(self, project))
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        IAnalyzer::import_analysis_provider(self)
    }

    fn type_hierarchy_provider(
        &self,
    ) -> Option<&dyn brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider> {
        IAnalyzer::type_hierarchy_provider(self)
    }

    fn type_alias_provider(
        &self,
    ) -> Option<&dyn brokk_bifrost_core::analyzer::capabilities::TypeAliasProvider> {
        IAnalyzer::type_alias_provider(self)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }

    fn update(
        &self,
        changed_files: &BTreeSet<ProjectFile>,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(IAnalyzer::update(self, changed_files))
    }

    fn update_all_with_progress(
        &self,
        progress: Option<BuildProgress>,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(ScalaAnalyzer::update_all_with_progress(self, progress))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn clone_box(
        &self,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(Clone::clone(self))
    }
}

#[doc(hidden)]
pub struct ScalaSupport;

impl LanguageSupport for ScalaSupport {
    fn supports_selected_resolution_overlays(&self) -> bool {
        true
    }

    #[cfg(any(test, feature = "test-support"))]
    fn probe_assignment_value(
        &self,
        query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
        _request: &brokk_bifrost_core::analyzer::usages::reference_site::SourceLocationRequest,
        _cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<
        Option<
            brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution<
                brokk_bifrost_analysis::analyzer::native_points::NativeAssignmentValueProbe,
            >,
        >,
        String,
    > {
        use brokk_bifrost_analysis::analyzer::native_points::probe_jvm_assignment_value;

        use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
        let analyzer = query.analyzer;

        Ok(Some(probe_jvm_assignment_value(
            resolve_analyzer::<crate::analyzer::scala::ScalaAnalyzer>(analyzer)
                .ok_or("assignment-value probe has no Scala analyzer")?
                .tree_sitter_analyzer(),
            query,
        )))
    }

    #[cfg(any(test, feature = "test-support"))]
    fn selected_reverse_reference_file<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
        _target_analyzer: &'a dyn IAnalyzer,
        file: &ProjectFile,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        brokk_bifrost_analysis::analyzer::structural::reference_edges::SelectedReferenceFileProjection<'a>,
    >{
        let caller = resolve_analyzer::<ScalaAnalyzer>(analyzer).ok_or_else(|| {
            brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                "selected reverse caller analyzer is unavailable: {file}"
            ))
        })?;
        brokk_bifrost_analysis::analyzer::structural::reference_edges::SelectedReferenceFileProjection::new(
            caller,
            analyzer,
            file,
            |source| {
                caller
                    .inner
                    .source_matches_selected_native_content(file, source)
            },
        )
    }

    fn workspace_external_member_family(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        identity: &brokk_bifrost_jvm::realm::JvmExternalMemberIdentity,
        max_visits: usize,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyAnswer {
        if let Some(language) = [Language::Java, Language::Kotlin]
            .into_iter()
            .find(|language| workspace.languages().contains(language))
        {
            return brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyAnswer::incomplete(
                brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyIncompleteReason::MixedJvmRealmUnsupported(
                    language,
                ),
                0,
            );
        }
        let Some(scala) = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
            ScalaAnalyzer,
        >(workspace) else {
            return brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyAnswer::unsupported();
        };
        scala.resolve_external_member_family(workspace, identity, max_visits, cancellation)
    }

    fn workspace_semantic_diagnostics(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        _token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        file: &ProjectFile,
        source: &str,
    ) -> Option<brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport> {
        // Scala's own ladder is delegate-resident, but the active dependency
        // model it must not claim absence past is published on the dispatcher.
        Some(diagnostics::collect_scala_semantic_diagnostics(
            workspace, file, source,
        ))
    }

    fn knowledge(
        &self,
    ) -> &'static dyn brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge {
        &brokk_bifrost_jvm::ScalaKnowledge
    }

    fn build_analyzer(
        &self,
        project: Arc<dyn brokk_bifrost_core::analyzer::project::Project>,
        config: brokk_bifrost_core::analyzer::config::AnalyzerConfig,
        store_context: brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::AnalyzerStoreContext,
        progress: Option<brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress>,
    ) -> Result<
        brokk_bifrost_analysis::analyzer::multi_analyzer::AnalyzerDelegate,
        brokk_bifrost_analysis::analyzer::store::StoreError,
    > {
        Ok(
            brokk_bifrost_analysis::analyzer::multi_analyzer::AnalyzerDelegate::new(
                ScalaAnalyzer::new_with_config_store_context(
                    project,
                    config,
                    store_context,
                    progress,
                )?,
            ),
        )
    }

    fn is_configuration_input(&self, file: &ProjectFile) -> bool {
        crate::analyzer::jvm::dependency_discovery::is_jvm_dependency_input(file)
    }

    fn workspace_member_family_capability(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        member: &CodeUnit,
    ) -> brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyCapability {
        brokk_bifrost_analysis::analyzer::usages::member_family::scala_member_family_capability(
            workspace, member,
        )
    }

    fn workspace_member_family(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        member: &CodeUnit,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyAnswer {
        brokk_bifrost_analysis::analyzer::usages::member_family::scala_member_family(
            workspace,
            workspace,
            member,
            cancellation,
        )
    }

    fn native_member_attribution(
        &self,
        context: &brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::ProjectedNativeMemberContext,
        _outcome: brokk_bifrost_core::analyzer::structural::resolution::CandidateOutcome,
    ) -> Option<brokk_bifrost_analysis::analyzer::languages::NativeMemberAttribution> {
        Some(crate::analyzer::jvm::native_member_attribution(context))
    }

    fn native_non_reference_site(&self, node: tree_sitter::Node<'_>) -> bool {
        crate::analyzer::jvm::native_points::scala_non_reference_site(node)
    }

    fn external_inventory_providers(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
    ) -> Vec<String> {
        crate::analyzer::jvm::external::scala_inventory_providers(analyzer)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn native_rollout_points(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::languages::StructuralReceiverResolver>
    {
        Some(&crate::analyzer::jvm::native_points::JVM_NATIVE_ROLLOUT_POINTS)
    }

    fn explicit_import_model_target(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        file: &brokk_bifrost_core::analyzer::model::ProjectFile,
        reference: &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
    ) -> Option<String> {
        crate::analyzer::jvm::import_routes::explicit_import_model_route(
            analyzer, token, file, reference,
        )
        .map(|route| route.target)
    }

    fn procedure_syntax_roles(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::languages::ProcedureSyntaxRoles> {
        Some(semantic::PROCEDURE_SYNTAX_ROLES)
    }

    fn call_argument_conversion_prover(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::usages::call_conversion::CallArgumentConversionProver>
{
        Some(&call_conversion::CALL_ARGUMENT_CONVERSION_PROVER)
    }

    fn signature_metadata_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<SignatureMetadata>> {
        brokk_bifrost_analysis::analyzer::languages::with_resolved_analyzer::<ScalaAnalyzer, _>(
            analyzer,
            |scala| scala.signature_metadata_limited(unit, limit),
        )
    }

    fn signatures_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<String>> {
        brokk_bifrost_analysis::analyzer::languages::with_resolved_analyzer::<ScalaAnalyzer, _>(
            analyzer,
            |scala| scala.signatures_limited(unit, limit),
        )
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        brokk_bifrost_analysis::analyzer::languages::with_resolved_analyzer::<ScalaAnalyzer, _>(
            analyzer,
            |scala| scala.ranges_limited(unit, limit),
        )
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        brokk_bifrost_analysis::analyzer::multi_analyzer::forward_query_provider::<ScalaAnalyzer>(
            analyzer,
        )
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Jvm
    }

    fn reference_usage_strategy(
        &self,
    ) -> &'static dyn brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer {
        &SCALA_USAGE_STRATEGY
    }

    fn reference_graph_backend(
        &self,
    ) -> brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend {
        if super::jvm::native_graph::native_jvm_graph_selected() {
            brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend::Native(
                &super::jvm::native_graph::JVM_NATIVE_GRAPH,
            )
        } else {
            brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend::Legacy(
                &ScalaEdgePass,
            )
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_definition_dispatch<'a>(
        &self,
        analyzer: &'a dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        context: &mut brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionBatchContext<'a, '_>,
        request: &brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest,
        source: &std::sync::Arc<str>,
        tree: &Option<tree_sitter::Tree>,
        site: &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
        operation: Option<brokk_bifrost_analysis::navigation::NavigationOperation>,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
        go_session: Option<
            &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
        >,
    ) -> std::ops::ControlFlow<
        brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolution,
        brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolution,
    > {
        crate::analyzer::usages::get_definition::scala::resolve_definition_dispatch(
            analyzer,
            token,
            context,
            request,
            source,
            tree,
            site,
            operation,
            cancellation,
            go_session,
        )
    }

    fn definition_call_reference_candidate(&self, node: tree_sitter::Node<'_>) -> bool {
        crate::analyzer::usages::get_definition::scala::scala_call_reference_candidate(node)
    }

    fn definition_call_callee<'tree>(
        &self,
        node: tree_sitter::Node<'tree>,
    ) -> Option<tree_sitter::Node<'tree>> {
        crate::analyzer::usages::get_definition::scala::scala_callee_node_for_call(node)
    }

    fn definition_call_signature_context(
        &self,
        node: tree_sitter::Node<'_>,
        byte_offset: usize,
    ) -> Option<
        brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::CallSignatureContext,
    > {
        crate::analyzer::usages::get_definition::scala::scala_call_signature_context_for_node(
            node,
            byte_offset,
        )
    }

    fn definition_nested_callable(&self, node: tree_sitter::Node<'_>) -> bool {
        node.kind() == "given_definition"
            || (node.kind() == "case_block" && case_block_is_partial_function(node))
    }

    fn definition_boundary_evidence(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        file: &brokk_bifrost_core::analyzer::model::ProjectFile,
        name: &str,
    ) -> Option<(
        brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus,
        Option<String>,
    )> {
        use crate::analyzer::ScalaAnalyzer;

        use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
        resolve_analyzer::<ScalaAnalyzer>(analyzer).map(|scala| {
            scala.external_boundary_evidence(token, analyzer.semantic_model_overlay(), file, name)
        })
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
}
impl brokk_bifrost_analysis::analyzer::store::StoreLanguageSupport for ScalaSupport {
    fn root_source_horizon_follows_provenance(&self) -> bool {
        // Local identities stay in their host mount, including nonshared stage
        // allocations. Selected root and JVM bridges cannot classify as Import
        // or Reference source halves in another mount.
        true
    }

    fn is_configuration_input_path(&self, path: &std::path::Path) -> bool {
        crate::analyzer::jvm::is_jvm_configuration_input_path(path)
    }
fn call_applicability_adapter(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::CallApplicabilityAdapter>{
        Some(&call_applicability::SCALA_CALL_APPLICABILITY_ADAPTER)
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
        brokk_bifrost_analysis::analyzer::languages::fqn_edge_sites(ctx, |token| {
            crate::analyzer::usages::scala_graph::build_rooted_scala_usage_edges(
                ctx.analyzer,
                token,
                ctx.fqns,
                ctx.keep_file,
            )
        })
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        brokk_bifrost_analysis::analyzer::languages::fqn_edge_weights(ctx, |token| {
            build_scala_usage_edge_weights(ctx.analyzer, token, ctx.fqns, ctx.keep_file)
        })
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
        brokk_bifrost_analysis::analyzer::languages::with_bounded_receiver_query(
            query,
            |query, token| {
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
            },
        )
    }
}

#[cfg(test)]
mod overlay_usage_tests {

    use crate::analyzer::scala::*;

    use brokk_bifrost_analysis::analyzer::usages::finder::UsageFinder;

    use crate::analyzer::usages::scala_graph::build_scala_usage_edges;

    use brokk_bifrost_core::analyzer::project::OverlayProject;

    use brokk_bifrost_core::analyzer::project::TestProject;

    /// The producer/SQLite boundary preserves written parent order, including
    /// swapped mixins. Read SQL ordinals as well as rehydrated source facts.
    #[test]
    fn scala_written_parent_order_survives_source_publication() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Scala)
            .file("Parents.scala", "class C[A] extends Base[A] with Left[A] with Right[A]\nclass D[A] extends Base[A] with Right[A] with Left[A]\n")
            .build();
        let analyzer = ScalaAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("Parents.scala");
        let facts = analyzer.canonical_source_facts(&file).unwrap();
        let mut expected = Vec::new();
        for (name, parents) in [
            ("C", ["Base", "Left", "Right"]),
            ("D", ["Base", "Right", "Left"]),
        ] {
            let unit = analyzer
                .get_definitions(name)
                .into_iter()
                .find(|unit| unit.is_class())
                .unwrap();
            let declaration = facts
                .for_unit(&unit)
                .find(|fact| fact.generic_owner.is_some())
                .unwrap();
            let actual = declaration
                .generic_owner
                .as_ref()
                .unwrap()
                .supertypes
                .iter()
                .map(|parent| parent.segments.join("."))
                .collect::<Vec<_>>();
            assert_eq!(actual, parents, "{name}");
            for (ordinal, parent) in parents.into_iter().enumerate() {
                expected.push((declaration.declaration.index(), ordinal, parent.to_string()));
            }
        }
        expected.sort();
        let conn = analyzer.inner.store_context.store.read_conn().unwrap();
        let mut stmt = conn.prepare(
            "SELECT p.declaration_id, p.ordinal, s.segment FROM source_scala_generic_supertypes p
             JOIN source_scala_type_expression_segments s
               ON s.blob_id=p.blob_id AND s.expression_id=p.expression_id
             WHERE s.ordinal=0 ORDER BY p.declaration_id,p.ordinal"
        ).unwrap();
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, usize>(0)?,
                    row.get::<_, usize>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(rows, expected);
    }

    #[test]
    fn canonical_declaration_properties_follow_overlay_content_without_mutating_disk_snapshot() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Scala)
            .file("Types.scala", "package app\ncase class Shape(value: Int)\nobject Api { def build(value: Int): Shape = Shape(value) }\n")
            .build();
        let file = fixture.file("Types.scala");
        let disk = ScalaAnalyzer::new(fixture.project_dyn());
        let shape = disk
            .get_definitions("app.Shape")
            .into_iter()
            .next()
            .expect("disk shape");
        assert!(disk.is_case_class_declaration(&shape));
        let before = disk
            .canonical_source_facts(&file)
            .expect("disk canonical publication");
        assert!(Arc::ptr_eq(
            &before,
            &disk
                .canonical_source_facts(&file)
                .expect("memoized disk publication")
        ));
        let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(file.abs_path(), "package app\nclass Shape(value: Int)\nobject Api { def build(value: Int)(label: String): Shape = new Shape(value) }\n".to_string()));
        let snapshot = disk.clone_with_project(overlay);
        let overlay_shape = snapshot
            .get_definitions("app.Shape")
            .into_iter()
            .next()
            .expect("overlay shape");
        assert!(!snapshot.is_case_class_declaration(&overlay_shape));
        let after = snapshot
            .canonical_source_facts(&file)
            .expect("overlay canonical publication");
        let build = snapshot
            .get_definitions("app.Api$.build")
            .into_iter()
            .next()
            .expect("overlay build");
        assert!(
            after
                .for_unit(&build)
                .filter_map(|fact| fact.callable.as_ref())
                .any(|callable| callable.shape.len() == 2)
        );
        assert!(disk.is_case_class_declaration(&shape));
        assert_eq!(
            before.facts,
            disk.canonical_source_facts(&file)
                .expect("unchanged disk publication")
                .facts
        );
    }

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
        disk.prefetch_file_dependency_targets(
            &disk.analyzed_files(),
            None,
            &brokk_bifrost_core::cancellation::CancellationToken::new(),
        );
        assert!(
            disk.file_dependency_index.get().is_some(),
            "disk file-dependency index should be warm"
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
        assert!(
            snapshot.file_dependency_index.get().is_none(),
            "an overlay clone needs an independent file-dependency index"
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

    use crate::analyzer::scala::*;

    use brokk_bifrost_core::analyzer::project::TestProject;

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

        fn discovery_truncated(&self) -> bool {
            false
        }

        fn qualified_name_disposition(&self, fqn: &str) -> JvmModelDisposition {
            match self.names.iter().filter(|name| **name == fqn).count() {
                0 => JvmModelDisposition::Absent,
                1 => JvmModelDisposition::Unique,
                declarations => JvmModelDisposition::Conflicting { declarations },
            }
        }
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
        ready_preflight(analyzer, Language::Scala, "Scala")
    }

    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        let scala = resolve_analyzer::<ScalaAnalyzer>(analyzer)?;
        brokk_bifrost_analysis::analyzer::languages::build_fqn_dead_code_edges(
            analyzer,
            &scala.dead_code_usage_edges,
            candidates,
            |token, callees| {
                build_inbound_scala_usage_edges_with_completeness(analyzer, token, callees)
            },
        )
    }
}

#[cfg(test)]
mod dead_code_cache_tests {

    use crate::analyzer::scala::*;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2844: update paths retained stale dead-code usage graphs"
    )]
    fn update_all_update_and_overlay_clone_start_with_empty_dead_code_caches() {
        let fixture = InlineTestProject::with_language(Language::Scala)
            .file("A.scala", "class A")
            .build();
        let analyzer = ScalaAnalyzer::from_project(fixture.project().clone());
        let key: Arc<[String]> = vec!["A".to_string()].into();
        analyzer
            .dead_code_usage_edges
            .insert(key.clone(), Arc::new(UsageEdges::default()));

        let updated = analyzer.update(&BTreeSet::new());
        assert!(updated.dead_code_usage_edges.get(&key).is_none());
        let rebuilt = analyzer.update_all();
        assert!(rebuilt.dead_code_usage_edges.get(&key).is_none());
        let overlay = analyzer.clone_with_project(fixture.project_dyn());
        assert!(overlay.dead_code_usage_edges.get(&key).is_none());
    }
}

#[cfg(test)]
mod project_types_seed_tests {

    use crate::analyzer::scala::*;
    use crate::inline_project::InlineTestProject;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "00ad7f265a5b: Scala hierarchy reused stale providers and rehydrated every query"
    )]
    fn eager_hierarchy_reads_once_and_targeted_queries_keep_fresh_facts() {
        let fixture = InlineTestProject::with_language(Language::Scala)
            .file("Base.scala", "package sample\nclass Base\n")
            .file("Child.scala", "package sample\nclass Child extends Base\n")
            .build();
        let analyzer = ScalaAnalyzer::from_project(fixture.project().clone());
        let files = analyzer.analyzed_files();
        analyzer.reset_full_hydration_count_for_test();
        let before = analyzer.bulk_hydration_count_for_test();
        let types = analyzer.project_types();
        assert_eq!(analyzer.bulk_hydration_count_for_test() - before, 2);

        for query in 1..=2 {
            let token = brokk_bifrost_core::cancellation::CancellationToken::new();
            let session = brokk_bifrost_analysis::analyzer::relational_frontier::RelationalFrontierSession::new(
                &analyzer, &token,
            );
            let ScalaResolvedSeedOutcome::Ready(seed) = analyzer.resolved_query_seed(&session)
            else {
                panic!("the fixture hierarchy resolves completely");
            };
            seed.prefetch_file_facts(&files);
            assert_eq!(
                analyzer.bulk_hydration_count_for_test() - before,
                2 + query * 2,
                "each query owns its file facts while reusing the resolved hierarchy",
            );
        }
        assert!(Arc::ptr_eq(&types, &analyzer.project_types()));
        assert_eq!(analyzer.full_hydration_count_for_test(), 0);
    }
}
