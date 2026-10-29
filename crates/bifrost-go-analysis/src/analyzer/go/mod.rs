use brokk_bifrost_analysis::{
    delegate_inner_methods, delegate_inner_procedure_fact_methods,
    forward_relational_definition_batch, impl_forward_query_provider,
};
#[doc(hidden)]
pub mod adapter;
mod artifact;
pub(crate) mod build_evidence;
mod cache;
mod clones;
#[doc(hidden)]
pub mod dependency_discovery;
pub(crate) mod diagnostics;
mod external_field_memory;
mod failure_handlers;
mod handler_dispatch;
mod imports;
pub(super) mod native_call_relations;
#[doc(hidden)]
pub mod native_graph;
pub(super) mod native_outgoing;
#[doc(hidden)]
pub mod native_points;
/// Go's declared receiver rule and the independently established operand
/// shape select one preparation. Missing addressability never creates a borrow.
pub(crate) fn go_method_receiver_preparation(
    pointer_receiver: bool,
    pointer_operand: bool,
    addressable: bool,
) -> Option<brokk_bifrost_analysis::analyzer::semantic::MemberReceiverPreparation> {
    use brokk_bifrost_analysis::analyzer::semantic::MemberReceiverPreparation as Preparation;
    match (pointer_receiver, pointer_operand) {
        (true, true) => Some(Preparation::Reference),
        (true, false) => addressable.then_some(Preparation::AddressOfPlace),
        (false, true) => Some(Preparation::CopyPointee),
        (false, false) => Some(Preparation::CopyValue),
    }
}

impl brokk_bifrost_analysis::analyzer::store::StoreLanguageSupport for GoSupport {
    fn supports_direct_type_shapes(&self) -> bool {
        true
    }

    fn selected_definition_module_anchor(
        &self,
        selection: &brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventory<'_>,
        mount: brokk_bifrost_analysis::analyzer::resolution::SelectedResolutionMountOrdinal,
        _project: &dyn brokk_bifrost_analysis::analyzer::Project,
        _file: &brokk_bifrost_analysis::analyzer::ProjectFile,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        Option<brokk_bifrost_core::analyzer::fq_name::FqName>,
    > {
        brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::go_definition_module_anchor(selection, mount)
    }

    fn callable_results_instantiate_nested_generic_projections(&self) -> bool {
        true
    }

    fn go_member_definition_namespaces(
        &self,
        kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind,
    ) -> Option<brokk_bifrost_analysis::analyzer::resolution::GoDefinitionNamespaces> {
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind;
        let bits = match kind {
            ResolutionMemberKind::Field => 2,
            ResolutionMemberKind::Method => 2 | 4,
            _ => return None,
        };
        Some(brokk_bifrost_analysis::analyzer::resolution::GoDefinitionNamespaces::member(bits))
    }

    fn is_configuration_input_path(&self, path: &std::path::Path) -> bool {
        matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("go.mod" | "go.sum" | "go.work" | "go.work.sum")
        ) || path.ends_with(std::path::Path::new("vendor/modules.txt"))
    }
    fn root_source_horizon_follows_provenance(&self) -> bool {
        true
    }
    fn call_applicability_adapter(
        &self,
    ) -> Option<
        &'static dyn brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::CallApplicabilityAdapter,
    >
{
        Some(&call_applicability::GO_CALL_APPLICABILITY_ADAPTER)
    }
    fn type_component_projection(
        &self,
        transfer: brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeTransferKind,
        constructor: Option<
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeConstructorKind,
        >,
        intrinsic: Option<brokk_bifrost_analysis::analyzer::resolution::universe::UniverseEntry>,
        operand: brokk_bifrost_analysis::analyzer::resolution::ResolutionSlotValue,
    ) -> Option<brokk_bifrost_analysis::analyzer::languages::TypeComponentProjection> {
        use brokk_bifrost_analysis::analyzer::languages::{
            TypeComponentProjection, TypeComponentSelection as Selection,
        };
        use brokk_bifrost_analysis::analyzer::resolution::universe::GoRangeType;
        use brokk_bifrost_core::analyzer::resolution_facts::{
            ResolutionTypeComponentKind as Component, ResolutionTypeConstructorKind as Constructor,
            ResolutionTypeTransferKind as Transfer,
        };

        let pointer = operand.ty().indirection();
        if pointer != 0 && !(pointer == 1 && constructor == Some(Constructor::Array)) {
            return None;
        }
        let mut addressable = None;
        let selection = match transfer {
            Transfer::ComponentIndex => {
                addressable = Some(match constructor {
                    Some(Constructor::Slice) => true,
                    Some(Constructor::Array) => pointer == 1 || operand.addressable() == Some(true),
                    _ => false,
                });
                match constructor {
                    Some(Constructor::Array | Constructor::Slice) => {
                        Selection::Component(Component::Element)
                    }
                    Some(Constructor::Map) => Selection::Component(Component::Value),
                    None if intrinsic
                        .is_some_and(|entry| entry.range_type == Some(GoRangeType::String)) =>
                    {
                        Selection::Intrinsic("byte")
                    }
                    _ => return None,
                }
            }
            Transfer::ComponentCommaOkValue if constructor == Some(Constructor::Map) => {
                addressable = Some(false);
                Selection::Component(Component::Value)
            }
            Transfer::ComponentCommaOkValue => return None,
            Transfer::ComponentIndexOk if constructor == Some(Constructor::Map) => {
                Selection::Intrinsic("bool")
            }
            Transfer::ComponentIndexOk => return None,
            Transfer::ComponentSlice => match constructor {
                Some(Constructor::Slice) => Selection::Operand,
                Some(Constructor::Array) if pointer == 1 || operand.addressable() == Some(true) => {
                    Selection::Constructed
                }
                None if intrinsic.is_some_and(|entry| entry.spelling == "untyped string") => {
                    Selection::Intrinsic("string")
                }
                None if intrinsic
                    .is_some_and(|entry| entry.range_type == Some(GoRangeType::String)) =>
                {
                    Selection::Operand
                }
                _ => return None,
            },
            Transfer::ComponentKey => match constructor {
                Some(Constructor::Array | Constructor::Slice | Constructor::Sequence) => {
                    Selection::Intrinsic("int")
                }
                Some(Constructor::Map) => Selection::Component(Component::Key),
                Some(Constructor::Channel) => Selection::Component(Component::Element),
                None => match intrinsic.and_then(|entry| entry.range_type) {
                    Some(GoRangeType::String) => Selection::Intrinsic("int"),
                    Some(GoRangeType::Integer) => Selection::Operand,
                    _ => return None,
                },
            },
            Transfer::ComponentValue => match constructor {
                Some(
                    Constructor::Array
                    | Constructor::Slice
                    | Constructor::Sequence
                    | Constructor::Channel,
                ) => Selection::Component(Component::Element),
                Some(Constructor::Map) => Selection::Component(Component::Value),
                None if intrinsic
                    .is_some_and(|entry| entry.range_type == Some(GoRangeType::String)) =>
                {
                    Selection::Intrinsic("rune")
                }
                _ => return None,
            },
            Transfer::ComponentElement => Selection::Component(Component::Element),
            _ => unreachable!("only component transfers reach component selection"),
        };
        Some(TypeComponentProjection {
            selection,
            addressable,
        })
    }
}

#[cfg(test)]
mod native_qualifier_tests;
pub(super) mod native_rename;
pub(super) mod native_usages;
pub(crate) mod package_function_value;
#[doc(hidden)]
pub mod package_identity;
#[doc(hidden)]
pub mod selected_reverse;
mod semantic;
mod source_identity;
pub(crate) mod source_publication;
#[doc(hidden)]
pub mod source_storage;
pub(crate) mod type_identity_proof;
mod value_type_barriers;

use crate::analyzer::go::semantic::GoCallableMaterialization;

use brokk_bifrost_core::analyzer::model::Range;

use crate::analyzer::go::source_storage::CanonicalGoSourceFacts;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::analyzer::query_token::QueryToken;

use brokk_bifrost_analysis::analyzer::clone_detection::detect_language_structural_clone_smells;

use brokk_bifrost_core::analyzer::common::language_for_file as file_language;
mod call_applicability;

use brokk_bifrost_analysis::analyzer::languages::DeadCodeSupport;

use brokk_bifrost_analysis::analyzer::languages::LanguageSupport;

use brokk_bifrost_analysis::analyzer::languages::ModeledExternalPackageIdentity;

use brokk_bifrost_analysis::analyzer::languages::PredeclaredBuiltinQueryStep;

use brokk_bifrost_analysis::analyzer::languages::StablePackageFunctionValueProof;

use brokk_bifrost_analysis::analyzer::languages::StructuralReceiverResolver;

use brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows;
#[cfg(test)]
use brokk_bifrost_core::analyzer::type_relations::TypeRelationKind;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::AnalyzerStoreContext;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress;

use brokk_bifrost_core::analyzer::model::CloneSmell;

use brokk_bifrost_core::analyzer::model::CloneSmellWeights;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::ForwardQueryProvider;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;

use brokk_bifrost_core::analyzer::model::Language;

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
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;

pub(crate) use crate::analyzer::go::adapter::GoAdapter;

pub use crate::analyzer::go::artifact::GoDependencyPackAdapter;

pub use crate::analyzer::go::artifact::GoModulePackProducer;

pub use artifact::GoPinnedPackage;
pub use brokk_bifrost_go::structural::{GoCallResultUseIndex, go_call_result_use};

pub use crate::analyzer::go::external_field_memory::GoAggregateOperand;

pub use crate::analyzer::go::external_field_memory::GoAggregateSourceBinding;

pub use crate::analyzer::go::external_field_memory::GoExternalField;

pub use crate::analyzer::go::external_field_memory::GoExternalFieldGap;

pub use crate::analyzer::go::external_field_memory::GoExternalFieldMemory;

pub use crate::analyzer::go::external_field_memory::GoExternalFieldQuery;

pub use crate::analyzer::go::external_field_memory::GoFieldReplayRoute;

pub use crate::analyzer::go::external_field_memory::bind_go_aggregate_operand_source;

pub use crate::analyzer::go::external_field_memory::bind_go_external_field_source;

pub use crate::analyzer::go::external_field_memory::go_aggregate_object_is_singleton;

pub use crate::analyzer::go::external_field_memory::observe_go_aggregate_object;

pub use crate::analyzer::go::external_field_memory::resolve_go_external_field;

pub use crate::analyzer::go::failure_handlers::{
    go_failure_handler_body_shapes, go_failure_handler_file_body_shapes,
};

pub use crate::analyzer::go::handler_dispatch::GoHttpHandlerDispatch;

pub use crate::analyzer::go::handler_dispatch::GoHttpHandlerOpenReason;

pub use crate::analyzer::go::handler_dispatch::go_http_handler_dispatch;

pub use crate::analyzer::go::source_identity::GoAnonymousCallableIdentityBindingError;

pub use crate::analyzer::go::source_identity::GoArtifactCallableTarget;

pub use crate::analyzer::go::source_identity::GoBoundAnonymousCallableIdentity;

pub use crate::analyzer::go::source_identity::GoCatalogAnonymousCallableBindingError;

pub use crate::analyzer::go::source_identity::GoDeclaredTypeShape;

pub use crate::analyzer::go::source_identity::GoDeclaredTypeUnknown;

pub use crate::analyzer::go::source_identity::GoFunctionParameterShape;

pub use crate::analyzer::go::source_identity::GoFunctionTypeShape;

pub use crate::analyzer::go::source_identity::GoOuterTypeShape;

pub use crate::analyzer::go::source_identity::GoReceiverOwnerUnknown;

pub use crate::analyzer::go::source_identity::GoReceiverTypeOwner;

pub use crate::analyzer::go::source_identity::GoSourceAnchor;

pub use crate::analyzer::go::source_identity::GoSourceByteRange;

pub use crate::analyzer::go::source_identity::GoSourceDeclarationIdentity;

pub use crate::analyzer::go::source_identity::GoSourceDeclarationKind;

pub use crate::analyzer::go::source_identity::GoSourceIdentityAnalysis;

pub use crate::analyzer::go::source_identity::GoSourceIdentityGap;

pub use crate::analyzer::go::source_identity::GoSourceIdentityGapKind;

pub use crate::analyzer::go::source_identity::GoSourceName;

pub use crate::analyzer::go::source_identity::GoSourceTypeNode;

pub use crate::analyzer::go::source_identity::GoStructFieldIdentity;

pub use crate::analyzer::go::source_identity::analyze_go_package_source_identities;

pub use crate::analyzer::go::source_identity::bind_catalog_go_anonymous_callable_target;

pub use crate::analyzer::go::source_identity::bind_go_anonymous_callable_identity;
// The Go declaration walk lives in the go crate; the rest of analysis (artifact,
// semantic) still reaches its helpers through `super::declarations::`.
pub(crate) use brokk_bifrost_go::declarations;
use brokk_bifrost_go::graph::resolver::GoEdgeIndex;
use brokk_bifrost_go::graph::resolver::{
    GoGraphBuildError, GoGraphSource, GoPackageClauseProvider, GoWorkspaceIndexes,
    build_go_workspace_indexes,
};
use brokk_bifrost_go::hierarchy::GoHierarchyIndex;
pub(crate) use brokk_bifrost_go::packages;
pub(crate) use brokk_bifrost_go::packages::GO_MODULE_SCOPE_SEGMENT;
use brokk_bifrost_go::packages::invalidate_nearest_go_module_cache;
use brokk_bifrost_go::test_detection::detect_go_test_assertion_smells;

use crate::analyzer::go::cache::GoMemoCaches;

use crate::analyzer::go::clones::build_go_clone_candidate_data;

pub use crate::analyzer::go::dependency_discovery::resolve_go_semantic_pack_dependencies;

pub use crate::analyzer::go::semantic::GoCallableCaptureBindingError;

pub use crate::analyzer::go::semantic::GoCaptureSlot;

pub use crate::analyzer::go::semantic::GoCaptureSlotPlan;

pub use crate::analyzer::go::semantic::GoMaterializedAnonymousCallable;

pub use crate::analyzer::go::semantic::materialize_go_anonymous_callable;

pub use crate::analyzer::go::semantic::reference_assertion_payload_type_is_exact;

pub use crate::analyzer::go::semantic::workspace_reference_assertion_accepts_payload;

pub use crate::analyzer::go::type_identity_proof::GO_MODELED_RESULT_BINDING_TYPE_PROOF_MAX_SOURCE_BYTES;

pub use crate::analyzer::go::type_identity_proof::GO_MODELED_RESULT_BINDING_TYPE_PROOF_MAX_STEPS;

pub use crate::analyzer::go::type_identity_proof::go_modeled_result_binding_type_identity_is_exact;

pub use crate::analyzer::go::type_identity_proof::go_modeled_result_binding_type_identity_proof_work;

pub use crate::analyzer::go::type_identity_proof::go_native_error_function_value_obligation;

pub use crate::analyzer::go::type_identity_proof::go_native_error_result_obligation;

pub use crate::analyzer::go::type_identity_proof::go_native_obligation_exclusion;

pub struct GoAnalyzer {
    inner: TreeSitterAnalyzer<GoAdapter>,
    memo_caches: GoMemoCaches,
    #[doc(hidden)]
    pub active_base_profile: std::sync::RwLock<Option<[u8; 32]>>,
    #[doc(hidden)]
    pub build_selection_error: std::sync::RwLock<String>,
}

pub(crate) fn go_import_binding_pairs(
    root: tree_sitter::Node<'_>,
    source: &str,
    mut package_name: impl FnMut(&str) -> Option<String>,
) -> Vec<(String, String)> {
    declarations::collect_go_import_infos(root, source)
        .into_iter()
        .filter_map(|info| {
            let path = info.path.as_ref()?.render_segments("/");
            if path.is_empty() {
                return None;
            }
            let local = info
                .alias
                .or_else(|| package_name(&path))
                .or(info.identifier)?;
            (!matches!(local.as_str(), "_" | ".")).then_some((local, path))
        })
        .collect()
}

#[cfg(test)]
fn activate_go_tool_context_for_test(
    fixture: &crate::inline_project::BuiltInlineTestProject,
    analyzer: &GoAnalyzer,
) -> i64 {
    use brokk_bifrost_analysis::analyzer::store::go_package_context::GoContextPublicationOutcome;
    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::store::go_package_context::GoInputObservationOutcome;

    use brokk_bifrost_analysis::analyzer::store::go_package_context::profile_digest;

    let snapshot = analyzer.selected_snapshot_for_test().unwrap();
    let store = analyzer.inner.analyzer_store();
    let cancellation = CancellationToken::new();
    let GoInputObservationOutcome::Ready(before) = store
        .observe_go_context_inputs(&snapshot, analyzer.project(), &cancellation)
        .unwrap()
    else {
        panic!("fixture Go inputs must be selected");
    };
    let mut discovery = crate::analyzer::go::dependency_discovery::discover_go_packages(
        &analyzer.inner.analyzer_config().go,
        analyzer.project(),
        &brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits::default(),
        Some(&cancellation),
    )
    .canonical
    .expect("Go tool discovery must publish the fixture context");
    // The root convenience discovery omits domain metadata; publication
    // needs the exact main modules just as production reconciliation does.
    discovery.domain = brokk_bifrost_go::package_discovery::go_discovery_domains(
        fixture.root(),
        &[(
            std::path::PathBuf::from("go.mod"),
            std::fs::read_to_string(fixture.root().join("go.mod")).unwrap(),
        )],
    )
    .unwrap()
    .pop()
    .expect("one fixture domain");
    let profile = profile_digest(&discovery);
    let GoInputObservationOutcome::Ready(after) = store
        .observe_go_context_inputs(&snapshot, analyzer.project(), &cancellation)
        .unwrap()
    else {
        panic!("fixture Go inputs must remain selected");
    };
    let GoContextPublicationOutcome::Published(context) = store
        .publish_go_package_context(
            snapshot.clone(),
            fixture.root().to_path_buf(),
            None,
            &before,
            &after,
            discovery,
            &cancellation,
        )
        .unwrap()
    else {
        panic!("Go tool publication must succeed");
    };
    assert!(analyzer.activate_native_context_profile(&snapshot, profile));
    reconcile_go_summaries_for_test(analyzer, context.context_id);
    context.context_id
}

#[cfg(test)]
fn reconcile_go_summaries_for_test(analyzer: &GoAnalyzer, context_id: i64) {
    let snapshot = analyzer
        .selected_snapshot_for_test()
        .expect("selected Go snapshot");
    let profile = analyzer
        .context_profile_for_test()
        .expect("selected Go native context profile");
    let report = analyzer
        .inner
        .analyzer_store()
        .reconcile_unit_summaries(
            &snapshot,
            brokk_bifrost_analysis::analyzer::store::go_unit_summaries::GoUnitSummaries {
                context_id,
                profile,
            },
            &brokk_bifrost_core::cancellation::CancellationToken::new(),
        )
        .expect("reconcile summaries for the selected Go native context");
    assert!(
        report.failed.is_empty(),
        "selected Go native summary derivation must succeed: {:?}",
        report.failed
    );
}

#[cfg(test)]
fn build_constrained_sibling_fixture_for_test(
    caller_source: &str,
) -> Option<(crate::inline_project::BuiltInlineTestProject, GoAnalyzer)> {
    if !std::process::Command::new("go")
        .arg("version")
        .output()
        .is_ok_and(|output| output.status.success())
    {
        eprintln!("build-constrained sibling regression requires Go discovery");
        return None;
    }
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/workerprofile\n\ngo 1.22\n")
        .file("service.go", caller_source)
        .file("service_linux.go", "package workerprofile\n\ntype Service struct{}\nfunc (s *Service) Run() { active() }\nfunc active() {}\n")
        .file("service_windows.go", "package workerprofile\n\ntype Service struct{}\nfunc (s *Service) Run() { ignored() }\nfunc ignored() {}\n")
        .build();
    let mut config = AnalyzerConfig::default();
    config.go.dependency_discovery.goos = Some("linux".into());
    config.go.dependency_discovery.goarch = Some("amd64".into());
    let analyzer = GoAnalyzer::new_with_config(fixture.project_dyn(), config);
    persist_live_go_sources_for_test(&analyzer);
    let context_id = activate_go_tool_context_for_test(&fixture, &analyzer);
    let roles = analyzer
        .inner
        .analyzer_store()
        .read_conn()
        .unwrap()
        .prepare("SELECT DISTINCT files.source_role FROM go_package_files files JOIN go_package_instances packages USING(package_id) WHERE packages.context_id=?1 AND files.rel_path=?2")
        .unwrap()
        .query_map(rusqlite::params![context_id, "service_windows.go"], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        roles,
        ["ignored"],
        "Go discovery excluded the sibling: {roles:?}"
    );
    for path in ["service_linux.go", "service_windows.go"] {
        assert!(
            analyzer
                .declarations(&fixture.file(path))
                .iter()
                .any(|unit| unit.identifier() == "Run"),
            "both sibling declarations must exist in the source inventory: {path}"
        );
    }
    Some((fixture, analyzer))
}

/// Reproduce a complete package publication containing an unselected saved sibling.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn mark_go_package_complete_for_test(analyzer: &GoAnalyzer, import_path: &'static str) {
    let snapshot = analyzer
        .selected_snapshot_for_test()
        .expect("selected Go snapshot");
    let profile = analyzer
        .context_profile_for_test()
        .expect("selected Go profile");
    let store = analyzer.inner.analyzer_store();
    let context = store
        .selected_go_context(&snapshot, &profile)
        .expect("read selected Go context")
        .expect("selected Go context");
    brokk_bifrost_analysis::analyzer::store::resolution_operation::go_reverse_rows::mark_go_package_complete_for_test(
        store, context.context_id, import_path,
    ).expect("mark selected package complete");
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn persist_live_go_sources_for_test(analyzer: &GoAnalyzer) {
    for file in analyzer.get_analyzed_files() {
        assert!(
            analyzer
                .inner
                .write_live_file_to_store_for_test(&file)
                .is_some(),
            "persist selected Go source facts for {file}"
        );
    }
    // Re-persistence withdraws summaries that depended on the replaced blobs.
    // Reconcile under the same selected snapshot and profile as production.
    let snapshots = analyzer.inner.selected_workspace_snapshots();
    let snapshot = snapshots.get("go").expect("selected Go snapshot");
    let base = analyzer
        .native_context_base_profile()
        .expect("selected Go base profile");
    let store = analyzer.inner.analyzer_store();
    let mut contexts = std::collections::BTreeMap::new();
    for file in analyzer.get_analyzed_files() {
        let path = brokk_bifrost_core::path_utils::rel_path_string(&file);
        for (context, profile) in store
            .go_contexts_for_file(snapshot, &base, &path)
            .expect("selected Go contexts")
        {
            contexts.insert(context.context_id, profile);
        }
    }
    for (context_id, profile) in contexts {
        let report = store
            .reconcile_unit_summaries(
                snapshot,
                brokk_bifrost_analysis::analyzer::store::go_unit_summaries::GoUnitSummaries {
                    context_id,
                    profile,
                },
                &brokk_bifrost_core::cancellation::CancellationToken::new(),
            )
            .expect("reconcile summaries after persisting selected Go sources");
        assert!(
            report.failed.is_empty(),
            "selected Go summary reconciliation failed: {:?}",
            report.failed
        );
    }
}

impl Clone for GoAnalyzer {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            memo_caches: self.memo_caches.clone(),
            active_base_profile: std::sync::RwLock::new(
                *self
                    .active_base_profile
                    .read()
                    .expect("Go base profile lock poisoned"),
            ),
            build_selection_error: std::sync::RwLock::new(
                self.build_selection_error().unwrap_or_default(),
            ),
        }
    }
}

impl_forward_query_provider!(GoAnalyzer);

impl brokk_bifrost_go::source_facts::GoSourceFactProvider for GoAnalyzer {
    fn go_source_facts(
        &self,
        _token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_go::source_facts::GoFileSourceFacts>> {
        self.inner
            .canonical_go_source_facts(file, &self.memo_caches.source_facts)
    }
}

impl GoAnalyzer {
    #[doc(hidden)]
    pub fn build_selection_error(&self) -> Option<String> {
        if self.inner.analyzer_config().go.dependency_discovery.mode
            == brokk_bifrost_core::analyzer::config::GoDependencyDiscoveryMode::Disabled
        {
            return Some("Go dependency discovery is disabled".into());
        }
        let error = self
            .build_selection_error
            .read()
            .expect("Go build selection lock poisoned");
        (!error.is_empty()).then(|| error.clone())
    }

    #[doc(hidden)]
    pub fn record_build_selection(
        &self,
        outcome: &dependency_discovery::GoDiscoveryOutcome,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<()> {
        let error = if self.inner.analyzer_config().go.dependency_discovery.mode
            == brokk_bifrost_core::analyzer::config::GoDependencyDiscoveryMode::Disabled
        {
            "Go dependency discovery is disabled".to_owned()
        } else if outcome.canonical.is_none()
            || outcome
                .semantic_packs
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "go.list_failed")
        {
            outcome
                .semantic_packs
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == "go.list_failed")
                .or_else(|| outcome.semantic_packs.diagnostics.first())
                .map(|diagnostic| diagnostic.message.clone())
                .unwrap_or_else(|| "Go discovery did not produce a selected build context".into())
        } else {
            String::new()
        };
        *self
            .build_selection_error
            .write()
            .expect("Go build selection lock poisoned") = error;
        if outcome.canonical.is_none() {
            // A failed discovery must not keep a previous tool profile active.
            *self
                .active_base_profile
                .write()
                .expect("Go profile lock poisoned") = None;
            self.refresh_source_inventory()?;
        }
        Ok(())
    }

    pub(crate) fn fallback_graph_exclusion(
        &self,
        file: &ProjectFile,
        _modules: &[brokk_bifrost_go::packages::GoModuleRoot],
    ) -> Option<brokk_bifrost_analysis::analyzer::store::resolution_operation::graph_stage::GraphFileSkipReason>
{
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::graph_stage::GraphFileSkipReason;
        let build = self.selected_build_configuration();
        if !brokk_bifrost_go::packages::source_filename_matches_target(
            file,
            &build.goos,
            &build.goarch,
        ) {
            return Some(GraphFileSkipReason::ExcludedBuildSelection);
        }
        if let Some(root) = self.workspace_path_index().unnamed_module_root(file) {
            return Some(GraphFileSkipReason::OutsideSelectedModules {
                module_path: brokk_bifrost_core::path_utils::workspace_relative_slash_path(root),
            });
        }
        None
    }

    #[doc(hidden)]
    pub fn selected_build_configuration(
        &self,
    ) -> brokk_bifrost_go::package_discovery::GoBuildConfiguration {
        brokk_bifrost_go::package_discovery::host_build_configuration(
            &self.inner.analyzer_config().go.dependency_discovery,
        )
    }

    pub(crate) fn update_all_with_progress(
        &self,
        progress: Option<brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress>,
    ) -> Self {
        invalidate_nearest_go_module_cache();
        let inner = self.inner.update_all_with_progress(progress);
        Self {
            inner,
            memo_caches: GoMemoCaches::new(self.memo_caches.budget_bytes()),
            active_base_profile: std::sync::RwLock::new(
                *self
                    .active_base_profile
                    .read()
                    .expect("Go base profile lock poisoned"),
            ),
            build_selection_error: std::sync::RwLock::new(
                self.build_selection_error().unwrap_or_default(),
            ),
        }
        .with_source_inventory()
    }

    /// The selected Go snapshot the unit-summary differential test reads.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn selected_snapshot_for_test(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId> {
        self.inner.selected_workspace_snapshots().get("go").cloned()
    }

    #[doc(hidden)]
    pub fn native_context_base_profile(&self) -> Option<[u8; 32]> {
        *self
            .active_base_profile
            .read()
            .expect("Go base profile lock poisoned")
    }

    #[doc(hidden)]
    pub fn context_profile_for_file(&self, path: &str) -> Option<[u8; 32]> {
        let base = self.native_context_base_profile()?;
        let snapshots = self.inner.selected_workspace_snapshots();
        let snapshot = snapshots.get("go")?;
        match self
            .inner
            .analyzer_store()
            .go_owner_context_for_file(snapshot, &base, path)
        {
            Ok(mut contexts) => {
                assert!(
                    contexts.len() <= 1,
                    "one workspace source belongs to one domain: {contexts:?}"
                );
                contexts.pop().map(|(_, profile)| profile)
            }
            Err(error) => {
                self.inner.record_store_error(error);
                None
            }
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn context_profile_for_test(&self) -> Option<[u8; 32]> {
        self.get_analyzed_files().iter().find_map(|file| {
            self.context_profile_for_file(&brokk_bifrost_core::path_utils::rel_path_string(file))
        })
    }

    #[doc(hidden)]
    pub fn activate_native_context_profile(
        &self,
        snapshot: &brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId,
        profile: [u8; 32],
    ) -> bool {
        if self.inner.selected_workspace_snapshots().get("go") != Some(snapshot) {
            return false;
        }
        let base=self.inner.analyzer_store().read_conn().and_then(|conn| {
            conn.query_row("SELECT base_profile_digest FROM go_context_selections WHERE workspace_id=?1 AND generation=?2 AND profile_digest=?3",
                rusqlite::params![snapshot.workspace_id.as_str(),snapshot.generation.get(),profile],
                |row|Ok(row.get::<_,Vec<u8>>(0)?.try_into().expect("schema checks base profile width"))).map_err(Into::into)
        });
        let base = match base {
            Ok(base) => base,
            Err(error) => {
                self.inner.record_store_error(error);
                return false;
            }
        };
        *self
            .active_base_profile
            .write()
            .expect("Go base profile lock poisoned") = Some(base);
        true
    }

    fn refresh_source_inventory(&self) -> brokk_bifrost_analysis::analyzer::store::Result<()> {
        use brokk_bifrost_analysis::analyzer::store::go_package_context::GoContextPublicationOutcome;

        use brokk_bifrost_analysis::analyzer::store::go_package_context::source_inventory_profile;
        let profile = source_inventory_profile();
        if self
            .native_context_base_profile()
            .is_some_and(|active| active != profile)
        {
            return Ok(());
        }
        let Some(snapshot) = self.inner.selected_workspace_snapshots().get("go").cloned() else {
            return Ok(());
        };
        match self.inner.analyzer_store().publish_go_source_context(
            snapshot.clone(),
            self.inner.project().root(),
            &brokk_bifrost_core::cancellation::CancellationToken::new(),
        )? {
            GoContextPublicationOutcome::Published(identity) => {
                assert!(self.activate_native_context_profile(&snapshot, profile));
                // The summaries of this publication's units, after the head is
                // published and before any request reads them.
                // Optional by design: a failure leaves readers on their fallback
                // and must not fail the publication that already succeeded.
                let timing = brokk_bifrost_core::profiling::scope(
                    "go.unit_summaries.reconcile.source_inventory",
                );
                let reconciliation = self.inner.analyzer_store().reconcile_unit_summaries(
                    &snapshot,
                    brokk_bifrost_analysis::analyzer::store::go_unit_summaries::GoUnitSummaries {
                        context_id: identity.context_id,
                        profile,
                    },
                    &brokk_bifrost_core::cancellation::CancellationToken::new(),
                );
                drop(timing);
                brokk_bifrost_core::profiling::note_with(|| {
                    format!("go.unit_summaries source_inventory reconciled={reconciliation:?}")
                });
                match &reconciliation {
                    Ok(reconciliation) if reconciliation.failed.is_empty() => {}
                    Ok(reconciliation) => eprintln!(
                        "go.unit_summary_failed: Go unit summaries were not published for {:?}",
                        reconciliation.failed
                    ),
                    Err(error) => eprintln!(
                        "go.unit_summary_failed: Go unit summaries were not reconciled: {error}"
                    ),
                }
            }
            GoContextPublicationOutcome::InputsChanged | GoContextPublicationOutcome::Cancelled => {
            }
        }
        Ok(())
    }

    fn with_source_inventory(self) -> Self {
        if let Err(error) = self.refresh_source_inventory() {
            eprintln!("Go source inventory publication unavailable: {error}");
        }
        self
    }

    #[doc(hidden)]
    pub fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        Self {
            inner: self.inner.clone_with_project(project),
            memo_caches: GoMemoCaches::new(self.memo_caches.budget_bytes()),
            active_base_profile: std::sync::RwLock::new(
                *self
                    .active_base_profile
                    .read()
                    .expect("Go base profile lock poisoned"),
            ),
            build_selection_error: std::sync::RwLock::new(
                self.build_selection_error().unwrap_or_default(),
            ),
        }
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        invalidate_nearest_go_module_cache();
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, GoAdapter, config),
            memo_caches: GoMemoCaches::new(memo_budget),
            active_base_profile: std::sync::RwLock::new(None),
            build_selection_error: std::sync::RwLock::new(
                "Go build selection discovery has not run".into(),
            ),
        }
        .with_source_inventory()
    }

    #[doc(hidden)]
    pub fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, brokk_bifrost_analysis::analyzer::store::StoreError> {
        let analyzer = TreeSitterAnalyzer::try_wrap_with_config(
            config,
            |config| {
                invalidate_nearest_go_module_cache();
                TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
                    project,
                    GoAdapter,
                    config,
                    store_context,
                    progress,
                )
            },
            |inner, memo_budget| Self {
                inner,
                memo_caches: GoMemoCaches::new(memo_budget),
                active_base_profile: std::sync::RwLock::new(None),
                build_selection_error: std::sync::RwLock::new(
                    "Go build selection discovery has not run".into(),
                ),
            },
        )?;
        analyzer.refresh_source_inventory()?;
        Ok(analyzer)
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub(crate) fn declaration_candidates_by_fqn_limited(
        &self,
        fqn: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        self.inner
            .lookup_declarations_by_fqn_limited(fqn, limit, continue_query)
    }

    pub(crate) fn member_candidates_for_owner_limited(
        &self,
        owner_fqn: &str,
        name: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        let exact_fqn = format!("{owner_fqn}.{name}");
        self.inner
            .lookup_declarations_by_fqn_limited(&exact_fqn, limit, continue_query)
    }

    pub(crate) fn import_info_limited(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<brokk_bifrost_core::analyzer::model::ImportInfo> {
        self.inner.import_info_of_limited(token, file, limit)
    }

    delegate_inner_methods! {
        pub(crate) fn signature_metadata_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<SignatureMetadata>;
    }

    delegate_inner_methods! {
        pub(crate) fn signatures_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<String>;
    }

    pub(crate) fn ranges_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<brokk_bifrost_core::analyzer::model::Range> {
        self.inner.ranges_limited(code_unit, limit)
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

    pub(crate) fn package_clause_of(&self, file: &ProjectFile) -> Option<String> {
        self.inner.content_qualifier_of(file)
    }

    pub(crate) fn workspace_path_index(&self) -> &packages::GoWorkspacePathIndex {
        self.memo_caches.workspace_path_index.get_or_init(|| {
            brokk_bifrost_analysis::analyzer::common::persistent_cache_fill(
                self,
                "go.workspace_path_index",
                || {
                    self.memo_caches
                        .workspace_path_index_build_count
                        .fetch_add(1, Ordering::Relaxed);
                    // Without the recorded refusals, a refused file is an unexplained
                    // missing clause and the index stays incomplete.
                    let refused = self
                        .inner
                        .selected_source_admission_refusals()
                        .unwrap_or_else(|error| {
                            self.inner.record_store_error(error);
                            Vec::new()
                        })
                        .into_iter()
                        .map(|(file, _)| file)
                        .collect();
                    packages::GoWorkspacePathIndex::build(
                        self.project(),
                        |file| self.package_clause_of(file),
                        &refused,
                    )
                },
            )
        })
    }

    pub(crate) fn same_module(&self, left: &ProjectFile, right: &ProjectFile) -> bool {
        self.workspace_path_index().same_module(left, right)
    }

    pub(crate) fn workspace_package_inventory_complete(&self) -> bool {
        self.inner.workspace_package_inventory_complete()
    }

    pub(crate) fn workspace_declaration_identities_authoritative(&self) -> bool {
        self.inner.workspace_declaration_identities_authoritative()
    }

    /// Whether an indexed Go package-scope declaration shadows a predeclared
    /// builtin, returning `None` when the declaration index cannot prove an
    /// answer. The lookup is bounded and hydrates only rows for `name`.
    /// Check whether a same-package declaration shadows a predeclared builtin.
    ///
    /// `None` means the bounded declaration lookup could not prove absence or
    /// presence. `continue_query` lets workspace consumers charge and cancel
    /// candidate visits using their own query budget.
    pub fn predeclared_builtin_shadow_status_limited(
        &self,
        relative_path: &str,
        name: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> Option<bool> {
        if !self.workspace_declaration_identities_authoritative() {
            return None;
        }
        let file = self
            .inner
            .project()
            .file_by_rel_path(Path::new(relative_path))?;
        let declared_package = self.package_clause_of(&file)?;
        let package = self
            .workspace_path_index()
            .canonical_package_name(&file, &declared_package);
        let candidates =
            self.inner
                .lookup_declarations_by_identifier_limited(name, limit, continue_query);
        let has_package_declaration = candidates.rows.iter().any(|candidate| {
            if candidate.terminal_name() != name || candidate.package_name() != package {
                return false;
            }
            let top_level_function =
                candidate.is_function() && candidate.declaration_segment_count() == 1;
            let top_level_type = candidate.is_class() && candidate.declaration_segment_count() == 1;
            let package_variable_or_type = (candidate.is_field() || candidate.is_class())
                && candidate.declaration_segment_count() == 2
                && candidate
                    .fq_segment_texts()
                    .get(candidate.package_segment_count())
                    .is_some_and(|segment| segment == GO_MODULE_SCOPE_SEGMENT);
            top_level_function || top_level_type || package_variable_or_type
        });
        if has_package_declaration {
            Some(true)
        } else if candidates.complete {
            Some(false)
        } else {
            None
        }
    }

    /// Go sources that source admission refused at the selected revision,
    /// with the recorded reason. [`Self::graph_inventory_complete`] accepts
    /// them as explained exclusions, so a consumer that claims completeness
    /// or proves absence of references must account for them.
    pub(crate) fn graph_source_exclusions(
        &self,
    ) -> Result<Vec<(ProjectFile, String)>, brokk_bifrost_analysis::analyzer::store::StoreError>
    {
        self.inner.selected_source_admission_refusals()
    }

    #[doc(hidden)]
    pub fn graph_inventory_complete(&self) -> bool {
        self.workspace_path_index().is_complete()
            && self.inner.indexed_source_inventory_complete()
            && self.workspace_declaration_identities_authoritative()
    }

    #[doc(hidden)]
    pub fn workspace_path_index_build_count_for_test(&self) -> usize {
        self.memo_caches.workspace_path_index_build_count()
    }

    fn workspace_indexes(&self) -> Result<Arc<GoWorkspaceIndexes>, GoGraphBuildError> {
        // Completeness is a cheap readiness check and must still guard a warm
        // memo: an unavailable publication must not make an earlier index look
        // authoritative. Enumerate files only to describe that failure.
        if !self.graph_inventory_complete() {
            let files: Vec<_> = self
                .get_analyzed_files()
                .into_iter()
                .filter(|file| file_language(file) == Language::Go)
                .collect();
            return Err(GoGraphBuildError::from_files(files));
        }
        self.memo_caches
            .workspace_indexes
            .get_or_try_build_on_dedicated_pool(|| {
                // Keep workspace enumeration and its whole-language read on
                // the cold build path. A warm root only borrows the shared
                // canonical index; repeating `get_analyzed_files` here would
                // record a broad Scope read in every root and invalidate roots
                // for an edit to an unrelated Go file.
                let files: Vec<_> = self
                    .get_analyzed_files()
                    .into_iter()
                    .filter(|file| file_language(file) == Language::Go)
                    .collect();
                let scope = AnalyzerQueryScope::new(self);
                let source = GoGraphSource {
                    token: scope.token(),
                    index: self,
                    imports: self,
                    type_aliases: self,
                    workspace_paths: self.workspace_path_index(),
                    package_clauses: self,
                    source_facts: self,
                };
                self.memo_caches
                    .workspace_indexes_build_count
                    .fetch_add(1, Ordering::Relaxed);
                let result = build_go_workspace_indexes(source, &files);
                if scope.store_error().is_some() {
                    Err(GoGraphBuildError::from_files(files.clone()))
                } else {
                    if result.is_ok() {
                        self.memo_caches
                            .workspace_source_fact_load_count
                            .fetch_add(files.len(), Ordering::Relaxed);
                    }
                    result
                }
            })
    }

    #[doc(hidden)]
    pub fn usage_edge_index(&self) -> Result<Arc<GoEdgeIndex>, GoGraphBuildError> {
        self.workspace_indexes()
            .map(|indexes| Arc::clone(&indexes.edges))
    }

    /// Build count for the shared source-authoritative hierarchy/edge product.
    /// Both repeated inverse requests and hierarchy lookups reuse this one
    /// memoized workspace build.
    #[doc(hidden)]
    pub fn workspace_indexes_build_count_for_test(&self) -> usize {
        self.memo_caches.workspace_indexes_build_count()
    }

    /// Canonical Go fact files consumed by completed shared workspace builds.
    /// Workspace indexes use persisted source facts and do not perform a
    /// parser pass, so this replaces the old parse-count assertion honestly.
    #[doc(hidden)]
    pub fn workspace_source_fact_load_count_for_test(&self) -> usize {
        self.memo_caches.workspace_source_fact_load_count()
    }

    pub fn format_test_module(path: impl AsRef<Path>) -> String {
        let path = path.as_ref();
        let normalized = path
            .to_string_lossy()
            .replace('\\', "/")
            .trim()
            .trim_start_matches('/')
            .trim_end_matches('/')
            .trim_matches('.')
            .trim_matches('/')
            .to_string();
        if normalized.is_empty() {
            ".".to_string()
        } else {
            format!("./{normalized}")
        }
    }

    pub fn get_test_modules_static(files: &[ProjectFile]) -> Vec<String> {
        let mut modules: Vec<_> = files
            .iter()
            .map(|file| {
                Self::format_test_module(file.rel_path().parent().unwrap_or_else(|| Path::new(".")))
            })
            .collect();
        modules.sort();
        modules.dedup();
        modules
    }
}

impl GoPackageClauseProvider for GoAnalyzer {
    fn package_clause_of(&self, file: &ProjectFile) -> Option<String> {
        GoAnalyzer::package_clause_of(self, file)
    }
}

impl TypeAliasProvider for GoAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }
}

impl GoAnalyzer {
    /// Cache successful hierarchy builds; unavailable source publications are
    /// retried so a transient store failure cannot become a permanent proof.
    fn hierarchy_index(&self) -> Result<Arc<GoHierarchyIndex>, GoGraphBuildError> {
        self.workspace_indexes()
            .map(|indexes| Arc::clone(&indexes.hierarchy))
    }
}

impl TypeHierarchyProvider for GoAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.hierarchy_index()
            .map(|index| index.direct_ancestors(code_unit))
            .unwrap_or_default()
    }

    fn get_direct_descendants(
        &self,
        code_unit: &CodeUnit,
    ) -> brokk_bifrost_core::hash::HashSet<CodeUnit> {
        self.hierarchy_index()
            .map(|index| index.direct_descendants(code_unit))
            .unwrap_or_default()
    }

    fn supports_type_hierarchy(&self, code_unit: &CodeUnit) -> bool {
        self.hierarchy_index()
            .is_ok_and(|index| index.supports(code_unit))
    }
}

/// Go's method family: structural interface satisfaction (#1721, and the CHA
/// lever ICFG dispatch consumes at
/// `workspace_oracle::dispatch::virtual_dispatch_implementor_targets`).
///
/// Go has no override chains and writes nothing at either declaration site: a
/// type satisfies an interface exactly when its method set covers the
/// interface's. So `Overrides`/`OverriddenBy` never appear here, and the only
/// edges are `Implements` and its bounded inversion `ImplementedBy`, both read
/// out of the one satisfaction pass `GoHierarchyIndex` already runs. That pass
/// compares whole method keys -- each method's name, qualified by package when
/// the name is unexported, plus its parameter and result type tokens resolved
/// through the file's imports and type aliases -- so an edge exists only where
/// two declarations agree on structure, never where two names merely agree.
///
/// Only a method with a body joins a family as an implementor. An interface
/// method whose signature happens to match another interface's declares no
/// body, so it supplies nothing to implement and gets no `Implements` edge --
/// which is also why an interface method's own family is exactly its
/// implementors. Go's one real interface-to-interface relation is embedding,
/// and a promoted method has no declaration of its own to relate: the edge
/// lands on the interface that declares it.
///
/// `proven` therefore means "exhaustive over the indexed workspace": every Go
/// file parsed, the satisfaction pass ran within its pair cap, and neither end
/// of the answer touches an interface the pass skips. Anything else is
/// `incomplete`, and dispatch treats an unproven family as contributing no
/// target at all.
impl brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyProvider for GoAnalyzer {
    fn member_family_capability(
        &self,
        member: &CodeUnit,
    ) -> brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyCapability {
        go_member_family_capability(member)
    }

    fn member_family(
        &self,
        member: &CodeUnit,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyAnswer {
        match self.hierarchy_index() {
            Ok(index) => go_member_family(self, &index, member, cancellation),
            Err(_) => brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyAnswer::incomplete(
                go_member_family_capability(member),
                brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyReason::HierarchyTruncated,
            ),
        }
    }
}

/// What a Go declaration's own recorded structure can discriminate.
///
/// `ParameterTypeSpellings` is the measured level: the satisfaction pass reads
/// each parameter's and result's declared type node and resolves it through
/// the file's imports and aliases where it can, falling back to the written
/// token where it cannot. That is a strictly stronger discriminator than a
/// bare spelling but is not proof of type identity, so it must not claim
/// erasure.
pub fn go_member_family_capability(
    member: &CodeUnit,
) -> brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyCapability {
    use brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyCapability;
    if file_language(member.source()) != Language::Go {
        return MemberFamilyCapability::Unsupported;
    }
    MemberFamilyCapability::ParameterTypeSpellings
}

/// One Go member's family, read out of the workspace satisfaction index.
pub fn go_member_family(
    analyzer: &dyn IAnalyzer,
    index: &GoHierarchyIndex,
    member: &CodeUnit,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
) -> brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyAnswer {
    use brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyCapability;

    use brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyReason;

    use brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyAnswer;
    use brokk_bifrost_go::hierarchy::{GoMemberFamily, GoMemberFamilyEdge};

    let capability = go_member_family_capability(member);
    if capability == MemberFamilyCapability::Unsupported {
        return MemberFamilyAnswer::unsupported_answer();
    }
    if cancellation.is_some_and(brokk_bifrost_core::cancellation::CancellationToken::is_cancelled) {
        return MemberFamilyAnswer::incomplete(capability, MemberFamilyReason::HierarchyTruncated);
    }
    if !member.is_function() {
        return MemberFamilyAnswer::no_family(capability, MemberFamilyReason::NotAMethod);
    }
    let (implements, implemented_by) = match index.member_family(member) {
        GoMemberFamily::Proven {
            implements,
            implemented_by,
        } => (implements, implemented_by),
        GoMemberFamily::NotEnumerable => {
            return MemberFamilyAnswer::incomplete(
                capability,
                MemberFamilyReason::HierarchyTruncated,
            );
        }
        // A top-level Go function owns no type and joins no method family;
        // that is a complete answer. A function the index did not record while
        // its owner is a type is a fact the index is missing, not an exclusion.
        GoMemberFamily::NotTracked => {
            return match analyzer.parent_of(member) {
                Some(parent) if parent.is_class() => {
                    MemberFamilyAnswer::incomplete(capability, MemberFamilyReason::OwnerUnknown)
                }
                _ => MemberFamilyAnswer::no_family(capability, MemberFamilyReason::NotAMethod),
            };
        }
    };

    // Go promotion and satisfaction match whole method keys, and Go has no
    // overloading, so a member is singled out by structure alone.
    brokk_bifrost_analysis::analyzer::usages::member_family::proven_member_family_answer(
        capability,
        member,
        implements
            .into_iter()
            .map(|edge: GoMemberFamilyEdge| (edge.member, edge.owner)),
        implemented_by
            .into_iter()
            .map(|edge: GoMemberFamilyEdge| (edge.member, edge.owner)),
    )
}

impl TestDetectionProvider for GoAnalyzer {}

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

impl CodeUnitIndex for GoAnalyzer {
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

    delegate_inner_methods! {
        fn summary_file_projection(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_analysis::analyzer::SummaryFileProjection>>;
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

    fn declarations_of_files(
        &self,
        files: &[ProjectFile],
    ) -> brokk_bifrost_core::hash::HashMap<ProjectFile, BTreeSet<CodeUnit>> {
        self.inner.declarations_of_files(files)
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

    delegate_inner_methods! {
        fn prefetch_definitions(&self, fq_names: &[String]);
    }

    delegate_inner_methods! {
        fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit>;
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
        self.inner.signatures(code_unit)
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
        self.inner
            .get_skeleton(code_unit)
            .map(|skeleton| go_type_skeleton(code_unit, skeleton))
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        self.inner
            .get_skeleton_header(code_unit)
            .map(|skeleton| go_type_skeleton(code_unit, skeleton))
    }

    fn render_source_fragment(
        &self,
        code_unit: &CodeUnit,
        mut source: String,
        declaration_start: usize,
    ) -> String {
        let Some(declaration) = source.get(declaration_start..) else {
            return source;
        };
        let declaration_has_type_keyword = declaration.trim_start().starts_with("type ")
            || source
                .get(..declaration_start)
                .is_some_and(|prefix| prefix.trim_end().ends_with("type"));
        if code_unit.is_class() && !declaration_has_type_keyword {
            source.insert_str(declaration_start, "type ");
        }
        source
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        if !code_unit.is_class() {
            return self.inner.get_sources(code_unit, include_comments);
        }

        let Some(content) = self.inner.indexed_source(code_unit.source()) else {
            return BTreeSet::new();
        };
        let mut ranges = self.inner.ranges(code_unit);
        ranges.sort_by_key(|range| range.start_byte);

        ranges
            .into_iter()
            .filter_map(|range| {
                let start_byte = if include_comments {
                    brokk_bifrost_core::analyzer::tree_walk::expanded_comment_start(
                        Language::Go,
                        &content,
                        range.start_byte,
                    )
                } else {
                    range.start_byte
                };
                let source = content.get(start_byte..range.end_byte)?.to_string();
                Some(self.render_source_fragment(
                    code_unit,
                    source,
                    range.start_byte.saturating_sub(start_byte),
                ))
            })
            .collect()
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

impl IAnalyzer for GoAnalyzer {
    delegate_inner_procedure_fact_methods!();

    forward_relational_definition_batch!();

    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerTestHooks {
        self
    }

    fn invalidate_cached_file_identities(&self) {
        self.inner.invalidate_cached_file_identities();
        invalidate_nearest_go_module_cache();
    }

    fn invalidate_cached_file_identities_for(&self, changed_files: &BTreeSet<ProjectFile>) {
        self.inner
            .invalidate_cached_file_identities_for(changed_files);
    }

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
        fn import_statements(&self, file: &ProjectFile) -> Vec<String>;
    }

    delegate_inner_methods! {
        fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)>;
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        // Package facts are keyed by import path. A module-path change
        // therefore rekeys every Go file below this manifest, including files
        // absent from `changed_files`, and the inner update rebuilds for it
        // (see `GoAdapter::workspace_package_identity_digest`). Invalidate
        // first so neither path can reuse the old nearest-module answer.
        invalidate_nearest_go_module_cache();
        Self {
            inner: self.inner.update(changed_files),
            memo_caches: GoMemoCaches::new(self.memo_caches.budget_bytes()),
            active_base_profile: std::sync::RwLock::new(
                *self
                    .active_base_profile
                    .read()
                    .expect("Go base profile lock poisoned"),
            ),
            build_selection_error: std::sync::RwLock::new(
                self.build_selection_error().unwrap_or_default(),
            ),
        }
        .with_source_inventory()
    }

    fn update_all(&self) -> Self {
        self.update_all_with_progress(None)
    }

    fn parse_errors(
        &self,
        file: &ProjectFile,
    ) -> Option<Vec<brokk_bifrost_core::analyzer::model::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        // The Go collector builds the complete report itself: it is the only
        // caller that knows which of its lookups checked a workspace lexical
        // scope, an indexed external package surface, or nothing at all.
        diagnostics::collect_go_semantic_diagnostics(self, token, file, source)
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

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
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
        fn contains_tests(&self, file: &ProjectFile) -> bool;
    }

    fn in_test_region(&self, code_unit: &brokk_bifrost_core::analyzer::model::CodeUnit) -> bool {
        self.inner.in_test_region(code_unit)
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
        detect_language_structural_clone_smells(self, files, weights, Language::Go, |code_unit| {
            build_go_clone_candidate_data(self, code_unit, weights)
        })
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        if !self.contains_tests(file) || file_language(file) != Language::Go {
            return Vec::new();
        }
        let Some(source) = self.inner.file_source(file) else {
            return Vec::new();
        };
        let imports = self.inner.import_info_of(token, file);
        detect_go_test_assertion_smells(file, &source, &imports, &weights)
    }

    fn get_test_modules(&self, files: &[ProjectFile]) -> Vec<String> {
        Self::get_test_modules_static(files)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerTestHooks for GoAnalyzer {
    fn arm_selector_continuation_semantic_cache_invalidation_for_test(&self) {
        self.inner
            .test_hooks()
            .arm_selector_continuation_semantic_cache_invalidation_for_test();
    }

    fn invalidate_selector_continuation_semantic_cache_if_armed_for_test(&self) {
        self.inner
            .test_hooks()
            .invalidate_selector_continuation_semantic_cache_if_armed_for_test();
    }

    fn selector_continuation_semantic_cache_revival_census_for_test(
        &self,
    ) -> brokk_bifrost_semantic::analyzer::semantic::service::SemanticCacheRevivalCensus {
        self.inner
            .test_hooks()
            .selector_continuation_semantic_cache_revival_census_for_test()
    }

    fn arm_evaluation_root_continuation_semantic_cache_invalidation_for_test(&self) {
        self.inner
            .test_hooks()
            .arm_evaluation_root_continuation_semantic_cache_invalidation_for_test();
    }

    fn invalidate_evaluation_root_continuation_semantic_cache_if_armed_for_test(&self) {
        self.inner
            .test_hooks()
            .invalidate_evaluation_root_continuation_semantic_cache_if_armed_for_test();
    }

    fn evaluation_root_continuation_semantic_cache_revival_census_for_test(
        &self,
    ) -> brokk_bifrost_semantic::analyzer::semantic::service::SemanticCacheRevivalCensus {
        self.inner
            .test_hooks()
            .evaluation_root_continuation_semantic_cache_revival_census_for_test()
    }

    fn semantic_materialization_census_for_test(
        &self,
    ) -> Vec<(
        brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath,
        brokk_bifrost_semantic::analyzer::semantic::service::SemanticMaterializationCensus,
    )> {
        self.inner
            .test_hooks()
            .semantic_materialization_census_for_test()
    }

    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn reset_relational_definition_batch_call_count_for_test(&self);
    }

    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn relational_definition_batch_call_count_for_test(&self) -> usize;
    }

    fn record_resolve_definition_batch_with_source_call_for_test(&self) {
        self.inner
            .test_hooks()
            .record_resolve_definition_batch_with_source_call_for_test();
    }

    fn reset_resolve_definition_batch_with_source_call_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_resolve_definition_batch_with_source_call_count_for_test();
    }

    fn resolve_definition_batch_with_source_call_count_for_test(&self) -> usize {
        self.inner
            .test_hooks()
            .resolve_definition_batch_with_source_call_count_for_test()
    }

    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn reset_definition_candidates_query_count_for_test(&self);
    }

    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn definition_candidates_query_count_for_test(&self) -> usize;
    }

    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn reset_definition_prefetch_batch_count_for_test(&self);
    }

    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn definition_prefetch_batch_count_for_test(&self) -> usize;
    }

    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn reset_full_declaration_scan_count_for_test(&self);
    }

    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn full_declaration_scan_count_for_test(&self) -> usize;
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn full_candidate_hydration_count_for_test(&self) -> usize;
    }

    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn bulk_candidate_hydration_count_for_test(&self) -> usize;
    }
}

static GO_NATIVE_USAGE_STRATEGY: native_usages::GoNativeUsageStrategy =
    native_usages::GoNativeUsageStrategy::new();

impl brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer for GoAnalyzer {
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
        Box::new(GoAnalyzer::clone_with_project(self, project))
    }

    fn clone_for_index_warm(
        &self,
        project: Arc<dyn Project>,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(GoAnalyzer::clone_with_project(self, project))
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
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
        Box::new(GoAnalyzer::update_all_with_progress(self, progress))
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
pub struct GoSupport;

fn go_type_skeleton(code_unit: &CodeUnit, skeleton: String) -> String {
    if code_unit.is_class() && !skeleton.trim_start().starts_with("type ") {
        format!("type {skeleton}")
    } else {
        skeleton
    }
}

fn go_branch_reference_site(
    node: tree_sitter::Node<'_>,
) -> Option<brokk_bifrost_analysis::analyzer::structural::branch_relations::BranchReferenceSite> {
    use brokk_bifrost_analysis::analyzer::structural::branch_relations::{
        BranchReferenceKind, BranchReferenceSite,
    };
    let (focus, kind) = match node.kind() {
        "call_expression" => {
            let function = node.child_by_field_name("function")?;
            if function.kind() != "identifier" {
                return None;
            }
            (function, BranchReferenceKind::Method)
        }
        "identifier"
            if node.parent().is_some_and(|parent| {
                parent.kind() == "call_expression"
                    && parent.child_by_field_name("function") == Some(node)
            }) =>
        {
            return None;
        }
        "identifier" => (node, BranchReferenceKind::Field),
        _ => return None,
    };
    Some(BranchReferenceSite {
        range: (focus.start_byte(), focus.end_byte()),
        kind,
    })
}

impl LanguageSupport for GoSupport {
    fn lexical_definitions_are_authoritative(&self) -> bool {
        false
    }

    fn branch_body_reference_site(
        &self,
        node: tree_sitter::Node<'_>,
        _source: &str,
    ) -> Option<brokk_bifrost_analysis::analyzer::structural::branch_relations::BranchReferenceSite>
    {
        go_branch_reference_site(node)
    }

    fn branch_condition_reference_site(
        &self,
        node: tree_sitter::Node<'_>,
        _source: &str,
    ) -> Option<brokk_bifrost_analysis::analyzer::structural::branch_relations::BranchReferenceSite>
    {
        go_branch_reference_site(node)
    }

    fn supports_selected_resolution_overlays(&self) -> bool {
        true
    }

    fn closed_receiver_summary_closes_external_body(&self) -> bool {
        true
    }

    fn call_argument_partition_is_complete(
        &self,
        analyzer: &dyn IAnalyzer,
        shape: &brokk_bifrost_analysis::analyzer::usages::call_shape::CallShapeReport,
        cancellation: Option<&brokk_bifrost_analysis::analyzer::semantic::CancellationToken>,
    ) -> bool {
        crate::analyzer::usages::get_definition::go::go_call_argument_partition_is_complete(
            analyzer,
            shape,
            cancellation,
        )
    }

    fn value_type_barrier_context<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
        _cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<
        Option<Box<dyn brokk_bifrost_analysis::analyzer::semantic::ValueTypeBarrierContext + 'a>>,
        brokk_bifrost_analysis::analyzer::semantic::SemanticProviderError,
    > {
        Ok(Some(value_type_barriers::open(analyzer)))
    }

    fn value_type_barrier(
        &self,
        _analyzer: &dyn IAnalyzer,
        observation: &brokk_bifrost_analysis::analyzer::semantic::BarrierObservation,
        predicate: brokk_bifrost_analysis::analyzer::semantic::ValueTypePredicate,
        request: &mut brokk_bifrost_analysis::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        brokk_bifrost_analysis::analyzer::semantic::ValueTypeBarrierDecision,
        brokk_bifrost_analysis::analyzer::semantic::SemanticProviderError,
    > {
        use brokk_bifrost_analysis::analyzer::semantic::{
            ValueTypeBarrierDecision, ValueTypeBarrierReason,
        };
        let Some(context) = request.value_type_barrier_context() else {
            return Ok(ValueTypeBarrierDecision::Undecided(
                ValueTypeBarrierReason::UnavailableObservation,
            ));
        };
        context.classify(observation, predicate, request)
    }

    fn observed_value_type(
        &self,
        _analyzer: &dyn IAnalyzer,
        observation: &brokk_bifrost_analysis::analyzer::semantic::BarrierObservation,
        request: &mut brokk_bifrost_analysis::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        brokk_bifrost_analysis::analyzer::semantic::ObservedValueType,
        brokk_bifrost_analysis::analyzer::semantic::SemanticProviderError,
    > {
        use brokk_bifrost_analysis::analyzer::semantic::{
            ObservedValueType, ValueTypeBarrierReason,
        };
        let Some(context) = request.value_type_barrier_context() else {
            return Ok(ObservedValueType::Undecided(
                ValueTypeBarrierReason::UnavailableObservation,
            ));
        };
        context.observed_type(observation, request)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn probe_assignment_value(
        &self,
        query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
        request: &brokk_bifrost_core::analyzer::usages::reference_site::SourceLocationRequest,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<
        Option<
            brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution<
                brokk_bifrost_analysis::analyzer::native_points::NativeAssignmentValueProbe,
            >,
        >,
        String,
    > {
        use brokk_bifrost_analysis::analyzer::native_points::adapt_assignment_value_probe;

        use brokk_bifrost_analysis::analyzer::native_points::map_bounded;

        use brokk_bifrost_analysis::analyzer::native_points::unavailable_assignment_value_probe;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedSemanticLocator;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionLocated;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

        use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

        use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;
        use brokk_bifrost_core::path_utils::rel_path_string;
        let analyzer = query.analyzer;
        let site = query.site;
        let budget = query.budget;
        let language = Language::Go;

        use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

        use crate::analyzer::go::native_points::GoNativePointRequest;

        use crate::analyzer::go::native_points::GoNativePointRequestOpen;
        let go = resolve_analyzer::<crate::analyzer::go::GoAnalyzer>(analyzer)
            .ok_or("assignment-value probe has no Go analyzer")?;
        let mut go_request =
            match GoNativePointRequest::open_for_file(go, query.file, None, cancellation)
                .map_err(|error| error.to_string())?
            {
                GoNativePointRequestOpen::Ready(request) => request,
                GoNativePointRequestOpen::Unavailable { kind, message } => {
                    return Ok(Some(BoundedResolution::Complete {
                        value: unavailable_assignment_value_probe(site, kind, message),
                        work: ReceiverAnalysisWork::default(),
                    }));
                }
                GoNativePointRequestOpen::Cancelled => {
                    return Ok(Some(BoundedResolution::Cancelled {
                        work: ReceiverAnalysisWork::default(),
                    }));
                }
            };
        let locator = SelectedSemanticLocator::for_reference_range(
            "go",
            rel_path_string(&request.file),
            site.focus_start_byte,
            site.focus_end_byte,
        );
        let Some(answer) = go_request
            .resolve_assignment_value_bounded(
                &rel_path_string(&request.file),
                &locator,
                budget,
                cancellation,
            )
            .map_err(|error| error.to_string())?
        else {
            return Ok(Some(BoundedResolution::Complete {
                value: unavailable_assignment_value_probe(
                    site,
                    "native_context_unavailable",
                    "selected Go file import/demand context is unavailable".into(),
                ),
                work: ReceiverAnalysisWork::default(),
            }));
        };
        Ok(Some(map_bounded(answer, |outcome| match outcome {
            SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                answer,
            )) => adapt_assignment_value_probe(site, language, answer),
            SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Missing) => {
                unavailable_assignment_value_probe(
                    site,
                    "native_reference_unavailable",
                    "assignment-value probe has no exact selected reference".into(),
                )
            }
            SelectedResolutionOperationOutcome::Unavailable(reason) => {
                unavailable_assignment_value_probe(
                    site,
                    "native_unavailable",
                    format!("{reason:?}"),
                )
            }
            SelectedResolutionOperationOutcome::Stale(reason) => {
                unavailable_assignment_value_probe(site, "native_stale", format!("{reason:?}"))
            }
            SelectedResolutionOperationOutcome::Cancelled(completion) => {
                unavailable_assignment_value_probe(
                    site,
                    "native_cancelled",
                    format!("{completion:?}"),
                )
            }
        })))
    }

    fn workspace_semantic_diagnostics(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        file: &ProjectFile,
        source: &str,
    ) -> Option<brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport> {
        // Go classifies references that leave the workspace against the
        // activated exact API packs (#1623), and the semantic-model overlay
        // and the retained Go module graph belong to the dispatching analyzer,
        // not to the delegate. Passing `workspace` is what lets a Go file's import
        // of an indexed module resolve instead of reporting nothing known.
        Some(diagnostics::collect_go_semantic_diagnostics(
            workspace, token, file, source,
        ))
    }

    fn knowledge(
        &self,
    ) -> &'static dyn brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge {
        &brokk_bifrost_go::GoKnowledge
    }

    fn call_relation_target_is_conversion(
        &self,
        site_kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind,
        namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
        target: &CodeUnit,
    ) -> bool {
        site_kind
            == brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::CallableReference
            && namespace
                == brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::TypeOrValue
            && target.is_class()
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
                GoAnalyzer::new_with_config_store_context(
                    project,
                    config,
                    store_context,
                    progress,
                )?,
            ),
        )
    }

    fn is_configuration_input(&self, file: &ProjectFile) -> bool {
        matches!(
            file.rel_path().file_name().and_then(|name| name.to_str()),
            Some("go.mod" | "go.sum")
        )
    }

    fn native_member_attribution(
        &self,
        context: &brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::ProjectedNativeMemberContext,
        outcome: brokk_bifrost_core::analyzer::structural::resolution::CandidateOutcome,
    ) -> Option<brokk_bifrost_analysis::analyzer::languages::NativeMemberAttribution> {
        use brokk_bifrost_core::analyzer::structural::resolution::HierarchyRelation;

        use brokk_bifrost_core::analyzer::structural::resolution::MemberDispatchTier;

        use brokk_bifrost_core::analyzer::structural::resolution::PrecedenceTier;
        // Go's existing callable-applicability rows carry no member route;
        // member-selection and wrong-declaration-space rows retain theirs.
        if matches!(
            outcome,
            brokk_bifrost_core::analyzer::structural::resolution::CandidateOutcome::Rejected(
                brokk_bifrost_core::analyzer::structural::resolution::RejectionReason::CallableApplicabilityDeferred
            )
        ) {
            return None;
        }
        let interface_owner = context.go_interface_owner?;
        let depth = context.owner_path.len() - 1;
        Some(
            brokk_bifrost_analysis::analyzer::languages::NativeMemberAttribution {
                dispatch_tier: if interface_owner {
                    MemberDispatchTier::TraitOrInterface
                } else if depth == 0 {
                    MemberDispatchTier::InherentOrDirect
                } else {
                    MemberDispatchTier::InheritedOrPromoted
                },
                relation: HierarchyRelation::Embedded,
                precedence_tier: if depth == 0 {
                    PrecedenceTier::OwnMember
                } else {
                    PrecedenceTier::InheritedMember
                },
            },
        )
    }

    fn modeled_external_package_identity(
        &self,
        overlay: &brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay,
        import_path: &str,
    ) -> Option<ModeledExternalPackageIdentity> {
        let identity = package_identity::GoOverlayPackages::new(Some(overlay))
            .modeled_package_identity(import_path)?;
        Some(ModeledExternalPackageIdentity {
            package_name: identity.package_name,
            symbol_id: identity.symbol_id,
            pack_id: identity.pack_id,
            pack_digest: identity.pack_digest,
            record_id: identity.record_id,
        })
    }

    fn materialize_callable_factory(
        &self,
        oracle: &brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::WorkspaceSemanticOracle<'_>,
        call: &brokk_bifrost_semantic::analyzer::semantic::ir::CallSiteHandle,
        proof: &brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof,
        request: &mut brokk_bifrost_analysis::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        Option<
            brokk_bifrost_analysis::analyzer::semantic::SemanticOutcome<
                brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::DispatchResult,
            >,
        >,
        brokk_bifrost_analysis::analyzer::semantic::SemanticProviderError,
    > {
        oracle.materialize_go_callable_factory(call, proof, request)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn native_rollout_points(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::languages::StructuralReceiverResolver>
    {
        Some(&native_points::GoNativeRolloutPoints)
    }

    fn selected_graph_fallback_active(&self, analyzer: &dyn IAnalyzer) -> bool {
        resolve_analyzer::<GoAnalyzer>(analyzer)
            .expect("Go stage has a Go analyzer")
            .build_selection_error()
            .is_some()
    }

    fn selected_graph_fallback_exclusion(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        modules: &[brokk_bifrost_go::packages::GoModuleRoot],
    ) -> Option<brokk_bifrost_analysis::analyzer::store::resolution_operation::graph_stage::GraphFileSkipReason>{
        resolve_analyzer::<GoAnalyzer>(analyzer)
            .expect("Go stage has a Go analyzer")
            .fallback_graph_exclusion(file, modules)
    }

    fn unnamed_module_root_for_file(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
    ) -> Option<std::path::PathBuf> {
        resolve_analyzer::<GoAnalyzer>(analyzer)?
            .workspace_path_index()
            .unnamed_module_root(file)
            .map(std::path::Path::to_path_buf)
    }

    fn stable_package_function_value_proof(
        &self,
        analyzer: &dyn IAnalyzer,
        variable: &CodeUnit,
        declaring_source: &str,
    ) -> Option<Result<StablePackageFunctionValueProof, String>> {
        package_function_value::prove_stable_package_function_value(
            analyzer,
            variable,
            declaring_source,
        )
        .map(|proof| {
            proof.map(|proof| StablePackageFunctionValueProof {
                initializer_start: proof.initializer_start,
                initializer_end: proof.initializer_end,
                references: proof.references,
                scope: proof.scope,
            })
        })
    }

    fn virtual_dispatch_target_is_applicable(
        &self,
        analyzer: &dyn IAnalyzer,
        declaration: &CodeUnit,
        target_file: &ProjectFile,
    ) -> bool {
        resolve_analyzer::<GoAnalyzer>(analyzer)
            .is_some_and(|go| go.same_module(declaration.source(), target_file))
    }

    fn predeclared_builtin_shadow_status_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        relative_path: &str,
        name: &str,
        limit: usize,
        query_step: &mut dyn FnMut(PredeclaredBuiltinQueryStep) -> bool,
    ) -> Option<bool> {
        let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
        if !query_step(PredeclaredBuiltinQueryStep::BeginLookup) {
            return None;
        }
        go.predeclared_builtin_shadow_status_limited(relative_path, name, limit, || {
            query_step(PredeclaredBuiltinQueryStep::VisitCandidate)
        })
    }

    fn procedure_syntax_roles(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::languages::ProcedureSyntaxRoles> {
        Some(semantic::PROCEDURE_SYNTAX_ROLES)
    }

    fn signature_metadata_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<SignatureMetadata>> {
        brokk_bifrost_analysis::analyzer::languages::with_resolved_analyzer::<GoAnalyzer, _>(
            analyzer,
            |go| go.signature_metadata_limited(unit, limit),
        )
    }

    fn signatures_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<String>> {
        resolve_analyzer::<GoAnalyzer>(analyzer).map(|go| go.signatures_limited(unit, limit))
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        brokk_bifrost_analysis::analyzer::languages::with_resolved_analyzer::<GoAnalyzer, _>(
            analyzer,
            |go| go.ranges_limited(unit, limit),
        )
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        resolve_analyzer::<GoAnalyzer>(analyzer).map(|value| value as _)
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Go
    }

    fn dependency_pack_resolver(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyResolver>{
        Some(&dependency_packs::GoDependencyResolver)
    }

    fn reconcile_workspace_build_context(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer,
        changed: Option<&BTreeSet<ProjectFile>>,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<()> {
        let Some(go) = resolve_analyzer::<GoAnalyzer>(workspace.analyzer()) else {
            return Ok(());
        };
        if let Some(changed)=changed && !changed.iter().any(|file| file.rel_path().extension().is_some_and(|extension|extension=="go")
            || <Self as brokk_bifrost_analysis::analyzer::store::StoreLanguageSupport>::is_configuration_input_path(self,file.rel_path())) {return Ok(());}
        let limits =
            brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits::default();
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
        if changed.is_some() {
            dependency_packs::reconcile_go_dependencies_after_edit(
                workspace,
                go.inner.analyzer_config(),
                &limits,
                &cancellation,
            )?;
        } else {
            dependency_packs::reconcile_selected_go_domains(
                workspace,
                go.inner.analyzer_config(),
                &limits,
                &cancellation,
                dependency_packs::GoReconciliationTrigger::ExplicitRefresh,
            )?;
        }
        Ok(())
    }

    fn refresh_updated_workspace_context(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer,
        changed_files: &BTreeSet<ProjectFile>,
        config: &brokk_bifrost_core::analyzer::config::AnalyzerConfig,
        limits: &brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<()> {
        if !changed_files.iter().any(|file| {
            Language::from_path(file.rel_path()) == Language::Go
                || self.is_file_dependency_input(file.rel_path())
        }) {
            return Ok(());
        }
        dependency_packs::reconcile_go_dependencies_after_edit(
            workspace,
            config,
            limits,
            cancellation,
        )?;
        Ok(())
    }

    fn resolve_workspace_dependencies(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        config: &brokk_bifrost_core::analyzer::config::AnalyzerConfig,
        limits: &brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::semantic_model::DependencyDiscoveryOutcome {
        match dependency_packs::resolve_selected_go_dependencies(
            workspace,
            config,
            limits,
            cancellation,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                let mut outcome =
                    brokk_bifrost_analysis::analyzer::semantic_model::DependencyDiscoveryOutcome::complete(
                        Vec::new(),
                    );
                outcome.complete = false;
                outcome.cancelled = cancellation.is_cancelled();
                outcome.diagnostics.push(brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackDiagnostic {
                    severity: brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackDiagnosticSeverity::Error,
                    code: "go.native_context_store_failure".into(), dependency_id: None, location: None,
                    message: error.to_string(),
                });
                outcome
            }
        }
    }

    fn reference_usage_strategy(
        &self,
    ) -> &'static dyn brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer {
        &GO_NATIVE_USAGE_STRATEGY
    }

    fn reference_graph_backend(
        &self,
    ) -> brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend {
        brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend::Native(
            &native_graph::GoNativeWorkspaceGraphProvider,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn definition_allocation_selector_method(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        file: &brokk_bifrost_core::analyzer::model::ProjectFile,
        source: &str,
        root: tree_sitter::Node<'_>,
        allocation: tree_sitter::Node<'_>,
        member: &str,
        byte: usize,
        budget: brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution<
        Option<brokk_bifrost_core::analyzer::model::CodeUnit>,
    > {
        crate::analyzer::usages::get_definition::go::go_allocation_selector_method(
            analyzer,
            token,
            file,
            source,
            root,
            allocation,
            member,
            byte,
            budget,
            cancellation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_definition_call_target_batch(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        requests: Vec<
            brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest,
        >,
        file: brokk_bifrost_core::analyzer::model::ProjectFile,
        source: std::sync::Arc<str>,
        _primary_tree: Option<tree_sitter::Tree>,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> Vec<brokk_bifrost_analysis::analyzer::usages::get_definition::CallTargetLookupOutcome>
    {
        crate::analyzer::usages::get_definition::go::resolve_definition_call_target_batch(
            analyzer,
            token,
            requests,
            file,
            source,
            cancellation,
        )
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
        crate::analyzer::usages::get_definition::go::resolve_definition_dispatch(
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
        crate::analyzer::usages::get_definition::go::go_call_reference_candidate(node)
    }

    fn definition_boundary_evidence(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
        _token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        _file: &brokk_bifrost_core::analyzer::model::ProjectFile,
        name: &str,
    ) -> Option<(
        brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus,
        Option<String>,
    )> {
        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
        Some((|| {
            // Go's boundary evidence is the same pair the Python and JS/TS arm
            // reads, resolved through the shared Go package identity so a
            // trace, a definition, and a diagnostic classify one import path
            // identically. Import paths are slash-separated, so the declared
            // check walks them by segment rather than by dot.
            let overlay = analyzer.semantic_model_overlay();
            let packages =
                crate::analyzer::go::package_identity::GoOverlayPackages::new(overlay.as_deref());
            if let Some(symbol) = packages.unique_symbol(name) {
                return (BoundaryStatus::ExternalIndexed, Some(symbol.id.clone()));
            }
            let declared = analyzer
                .dependency_discovery_evidence(Language::Go)
                .is_some_and(|evidence| {
                    evidence.truncated() || evidence.declares_go_import_path(name)
                });
            if declared {
                (BoundaryStatus::ExternalDeclaredUnindexed, None)
            } else {
                (BoundaryStatus::ExternalUnknown, None)
            }
        })())
    }

    fn allocation_binds_by_reference_at_offset(
        &self,
        file: &ProjectFile,
        source: &str,
        offset: usize,
    ) -> Option<bool> {
        crate::analyzer::usages::get_definition::go::allocation_binds_by_reference_at_offset(
            file, source, offset,
        )
    }

    fn allocation_boxes_reference_payload_at_offset(
        &self,
        file: &ProjectFile,
        source: &str,
        offset: usize,
    ) -> Option<bool> {
        crate::analyzer::usages::get_definition::go::allocation_boxes_reference_payload_at_offset(
            file, source, offset,
        )
    }

    fn result_binds_by_reference_at_ordinal(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
        declaration: &CodeUnit,
        ordinal: usize,
    ) -> Option<bool> {
        crate::analyzer::usages::get_definition::go::result_binds_by_reference_at_ordinal(
            analyzer,
            file,
            source,
            declaration,
            ordinal,
        )
    }

    fn parameter_binds_by_reference_at_span(
        &self,
        file: &ProjectFile,
        source: &str,
        start: usize,
        end: usize,
        ordinal: usize,
    ) -> Option<bool> {
        crate::analyzer::usages::get_definition::go::parameter_binds_by_reference_at_span(
            file, source, start, end, ordinal,
        )
    }

    fn parameter_preserves_backing_at_span(
        &self,
        file: &ProjectFile,
        source: &str,
        start: usize,
        end: usize,
        ordinal: usize,
    ) -> Option<bool> {
        crate::analyzer::usages::get_definition::go::parameter_preserves_backing_at_span(
            file, source, start, end, ordinal,
        )
    }

    fn parameter_boxes_reference_payload_at_span(
        &self,
        file: &ProjectFile,
        source: &str,
        start: usize,
        end: usize,
        ordinal: usize,
    ) -> Option<bool> {
        crate::analyzer::usages::get_definition::go::parameter_boxes_reference_payload_at_span(
            file, source, start, end, ordinal,
        )
    }

    fn parameter_is_reference_free_at_ordinal(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
        declaration: &CodeUnit,
        ordinal: usize,
    ) -> Option<bool> {
        crate::analyzer::usages::get_definition::go::parameter_is_reference_free_at_ordinal(
            analyzer,
            file,
            source,
            declaration,
            ordinal,
        )
    }

    fn modeled_method_selection_at_offset(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
        offset: usize,
    ) -> Option<String> {
        crate::analyzer::usages::get_definition::go::modeled_method_selection_at_offset(
            analyzer, file, source, offset,
        )
    }

    fn lexical_binding_repeats_at_offset(
        &self,
        file: &ProjectFile,
        source: &str,
        offset: usize,
    ) -> Option<bool> {
        crate::analyzer::usages::get_definition::go::lexical_binding_repeats_at_offset(
            file, source, offset,
        )
    }

    fn declaration_site_at_offset(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
        offset: usize,
    ) -> Option<CodeUnit> {
        crate::analyzer::usages::get_definition::go::field_declaration_at_offset(
            analyzer, file, source, offset,
        )
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&GO_NATIVE_USAGE_STRATEGY),
            bulk: None,
        }
    }

    fn dead_code_outside_build_files(
        &self,
        analyzer: &dyn IAnalyzer,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        brokk_bifrost_core::hash::HashSet<ProjectFile>,
    > {
        use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
        use brokk_bifrost_analysis::analyzer::store::StoreError;
        let go = resolve_analyzer::<GoAnalyzer>(analyzer)
            .ok_or_else(|| StoreError::new("outside-build files: no Go analyzer"))?;
        let snapshots = go.inner.selected_workspace_snapshots();
        let snapshot = snapshots
            .get("go")
            .ok_or_else(|| StoreError::new("outside-build files: no selected Go snapshot"))?;
        let base = go
            .native_context_base_profile()
            .ok_or_else(|| StoreError::new("outside-build files: no selected Go build"))?;
        let paths = go
            .inner
            .analyzer_store()
            .go_files_outside_selected_build(snapshot, &base)?;
        Ok(paths
            .into_iter()
            .map(|path| ProjectFile::new(go.project().root().to_path_buf(), path))
            .collect())
    }

    fn dead_code_needs_precise_scan(
        &self,
        _analyzer: &dyn IAnalyzer,
        _candidate: &CodeUnit,
    ) -> bool {
        // Every Go candidate uses native inverse search. An interface call x.M()
        // resolves to the interface method, leaving the concrete T.M without a
        // forward inbound edge, and inverse search handles interface families and
        // promoted members. For functions and top-level types the shared graph
        // projection would also be correct, but it projects the whole workspace:
        // on cli/cli one function candidate cost 556 prepared contexts, while
        // seven inverse searches together prepared 128.
        true
    }

    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        Some(&native_points::GoNativeRolloutPoints)
    }

    fn imported_package_at_range(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
        start_byte: usize,
        end_byte: usize,
    ) -> Option<String> {
        crate::analyzer::usages::get_definition::go::go_imported_package_at_range(
            analyzer, file, source, start_byte, end_byte,
        )
    }

    fn refine_selector_call_target(
        &self,
        lookup: &mut brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchLookup,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        file: &ProjectFile,
        source: &str,
        tree: &tree_sitter::Tree,
        callee_range: &Range,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) {
        selector_calls::apply_go_typed_selector_target_at_call(
            lookup,
            analyzer,
            token,
            file,
            source,
            tree,
            callee_range,
            cancellation,
        );
    }

    fn parse_tree_for_type_lookup(
        &self,
        _file: &ProjectFile,
        _language: Language,
        source: &str,
    ) -> Option<tree_sitter::Tree> {
        brokk_bifrost_go::parse::parse_go(source)
    }

    fn open_receiver_request<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Option<Box<dyn brokk_bifrost_analysis::analyzer::languages::ReceiverRequest + 'a>> {
        let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
        if let Ok(native_points::GoNativePointRequestOpen::Ready(opened)) =
            native_points::GoNativePointRequest::open(
                go,
                analyzer.semantic_model_overlay(),
                cancellation,
            )
        {
            Some(opened)
        } else {
            None
        }
    }

    fn call_relation_provider(
        &self,
    ) -> Option<
        &'static dyn brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationProvider,
    > {
        Some(&native_call_relations::GoNativeCallRelations)
    }

    fn rename_provider(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::rename::RenameProvider> {
        Some(&native_rename::GoNativeRenameProvider)
    }

    fn selected_inverse_reference_provider(
        &self,
    ) -> Option<
        &'static dyn brokk_bifrost_analysis::analyzer::structural::reference_edges::SelectedInverseReferenceProvider,
    >{
        Some(&selected_reverse::GoNativeSelectedInverseProvider)
    }
}

mod dependency_packs {
    use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyDiscoveryOutcome;

    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackAdapter;

    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits;

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyResolver;

    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyResolverBounds;

    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackPreparationOutcome;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_compatible_installed_semantic_packs;

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_dependency_semantic_packs;

    use brokk_bifrost_analysis::analyzer::workspace::build_tool_dependency_resolver_bounds;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_core::analyzer::config::GoDependencyDiscoveryMode;

    use crate::analyzer::GoDependencyPackAdapter;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

    use crate::analyzer::resolve_go_semantic_pack_dependencies;
    pub(crate) struct GoDependencyResolver;

    impl DependencyResolver for GoDependencyResolver {
        fn adapter(&self) -> &'static dyn DependencyPackAdapter {
            &GoDependencyPackAdapter
        }

        fn dependency_inputs(&self) -> &'static [&'static str] {
            &["go.mod", "go.sum", "go.work", "go.work.sum", "modules.txt"]
        }

        fn bounds(&self, config: &AnalyzerConfig) -> DependencyResolverBounds {
            let discovery = &config.go.dependency_discovery;
            let runs_tools = discovery.mode != GoDependencyDiscoveryMode::Disabled;
            // `go list` under the bounded-process runner, with a cleared
            // environment and the module cache the configuration names.
            build_tool_dependency_resolver_bounds(runs_tools.then_some(discovery.timeout), None)
        }

        fn prepare(
            &self,
            config: &AnalyzerConfig,
            catalog: &SemanticPackCatalog,
            dependencies: &[brokk_bifrost_analysis::analyzer::semantic_model::ResolvedDependency],
            limits: &DependencyPackLimits,
            cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
        ) -> DependencyPackPreparationOutcome {
            if config.go.dependency_discovery.mode == GoDependencyDiscoveryMode::CuratedPackEvidence
            {
                prepare_compatible_installed_semantic_packs(
                    catalog,
                    dependencies,
                    limits,
                    cancellation,
                )
            } else {
                prepare_dependency_semantic_packs(
                    catalog,
                    self.adapter(),
                    dependencies,
                    limits,
                    cancellation,
                )
            }
        }

        fn resolve(
            &self,
            config: &AnalyzerConfig,
            project: &dyn Project,
            limits: &DependencyPackLimits,
            cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
        ) -> DependencyDiscoveryOutcome {
            resolve_go_semantic_pack_dependencies(&config.go, project, limits, cancellation)
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum GoReconciliationTrigger {
        DependencyActivation,
        SourceChange,
        ExplicitRefresh,
    }

    pub(crate) fn resolve_selected_go_dependencies(
        workspace: &WorkspaceAnalyzer,
        config: &AnalyzerConfig,
        limits: &DependencyPackLimits,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<DependencyDiscoveryOutcome> {
        reconcile_selected_go_domains(
            workspace,
            config,
            limits,
            cancellation,
            GoReconciliationTrigger::DependencyActivation,
        )
    }

    pub(super) fn reconcile_go_dependencies_after_edit(
        workspace: &WorkspaceAnalyzer,
        config: &AnalyzerConfig,
        limits: &DependencyPackLimits,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<DependencyDiscoveryOutcome> {
        reconcile_selected_go_domains(
            workspace,
            config,
            limits,
            cancellation,
            GoReconciliationTrigger::SourceChange,
        )
    }

    pub(super) fn reconcile_selected_go_domains(
        workspace: &WorkspaceAnalyzer,
        config: &AnalyzerConfig,
        limits: &DependencyPackLimits,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
        trigger: GoReconciliationTrigger,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<DependencyDiscoveryOutcome> {
        use brokk_bifrost_analysis::analyzer::store::go_package_context::GoContextPublicationOutcome;

        use brokk_bifrost_analysis::analyzer::store::go_package_context::GoInputObservationOutcome;

        use brokk_bifrost_analysis::analyzer::store::go_package_context::profile_digest;
        use rusqlite::OptionalExtension;
        let project = workspace.analyzer().project();
        let Some(store) = workspace.store() else {
            return Ok(
                crate::analyzer::go::dependency_discovery::discover_go_packages(
                    &config.go,
                    project,
                    limits,
                    Some(cancellation),
                )
                .semantic_packs,
            );
        };
        let workspace_id =
            brokk_bifrost_analysis::analyzer::store::WorkspaceId::for_root(project.root());
        let snapshot = {
            let conn = store.read_conn()?;
            conn.query_row(
                "SELECT h.workspace_id,h.generation,h.revision FROM workspace_heads h
                 JOIN analysis_epochs e ON e.lang=h.lang AND e.generation=h.generation
                 WHERE h.workspace_id=?1 AND h.lang='go'",
                [workspace_id.as_str()],
                |row| {
                    Ok(brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId {
                        workspace_id: workspace_id.clone(),
                        lang: "go".into(),
                        generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                            row.get(1)?,
                        ),
                        revision: row.get(2)?,
                    })
                },
            )
            .optional()?
        };
        let overlays = brokk_bifrost_analysis::analyzer::store::go_package_context::GoOverlaySnapshot::capture(project)?;
        let before = snapshot
            .as_ref()
            .map(|snapshot| {
                store.observe_go_context_inputs_with_overlay(
                    snapshot,
                    project,
                    cancellation,
                    &overlays,
                )
            })
            .transpose()?;
        // Keep only this query's result through discovery: the canonical profile
        // is known after go env, but CAS must use the head before go list ran.
        let prior_heads = if let Some(snapshot) = snapshot.as_ref() {
            let conn = store.read_conn()?;
            let mut query = conn.prepare_cached(
                brokk_bifrost_analysis::analyzer::store::go_package_context::PRIOR_HEADS_SQL,
            )?;
            query.query_map(rusqlite::params![snapshot.workspace_id.as_str(),snapshot.generation.get(),snapshot.revision,
                brokk_bifrost_analysis::analyzer::store::go_package_context::DERIVATION_VERSION], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?.try_into().expect("schema checks profile digest width"),
                        brokk_bifrost_analysis::analyzer::store::go_package_context::GoContextIdentity {
                            revision: snapshot.revision,
                            selection_id:row.get(1)?,context_id:row.get(2)?,
                            publication_digest:row.get::<_, Vec<u8>>(3)?.try_into().expect("schema checks publication digest width"),
                        }))
                })?.collect::<std::result::Result<Vec<([u8;32],brokk_bifrost_analysis::analyzer::store::go_package_context::GoContextIdentity)>,_>>()?
        } else {
            Vec::new()
        };
        let Some(selected) = snapshot.as_ref() else {
            return Ok(DependencyDiscoveryOutcome::complete(Vec::new()));
        };
        if config.go.dependency_discovery.mode == GoDependencyDiscoveryMode::Disabled {
            let discovered = crate::analyzer::go::dependency_discovery::discover_go_packages(
                &config.go,
                project,
                limits,
                Some(cancellation),
            );
            if let Some(go) = resolve_analyzer::<crate::analyzer::GoAnalyzer>(workspace.analyzer())
            {
                go.record_build_selection(&discovered)?;
            }
            return Ok(discovered.semantic_packs);
        }
        let domains = store.go_discovery_domain_inputs(selected, project.root())?;
        let base_environment = crate::analyzer::go::dependency_discovery::domain_environment(
            &config.go,
            project,
            &Default::default(),
            cancellation,
        );
        let base_environment = match base_environment {
            Ok(environment) => environment,
            Err(_) => {
                let discovered = crate::analyzer::go::dependency_discovery::discover_go_packages(
                    &config.go,
                    project,
                    limits,
                    Some(cancellation),
                );
                if let Some(go) = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                    crate::analyzer::GoAnalyzer,
                >(workspace.analyzer())
                {
                    go.record_build_selection(&discovered)?;
                }
                return Ok(discovered.semantic_packs);
            }
        };
        let root_key = domains
            .iter()
            .filter(|(domain, _)| domain.directory.is_empty())
            .max_by_key(|(domain, _)| !domain.gowork_path.is_empty())
            .map(|(domain, _)| (domain.directory.clone(), domain.gowork_path.clone()));
        let base_template = crate::analyzer::go::dependency_discovery::GoPackageDiscovery {
            domain: Default::default(),
            input_digest: None,
            failure: None,
            packages: Vec::new(),
            build_configuration:
                crate::analyzer::go::dependency_discovery::selected_build_configuration(
                    &config.go.dependency_discovery,
                    &base_environment.goos,
                    &base_environment.goarch,
                ),
            environment: base_environment.clone(),
            workspace_patterns: config.go.dependency_discovery.workspace_patterns.clone(),
            vendor: false,
        };
        store.close_absent_go_domains(
            selected,
            brokk_bifrost_analysis::analyzer::store::go_package_context::base_profile_digest(
                &base_template,
            ),
            &domains,
        )?;
        if domains.is_empty() {
            if let Some(go) = resolve_analyzer::<crate::analyzer::GoAnalyzer>(workspace.analyzer())
            {
                *go.active_base_profile
                    .write()
                    .expect("Go base profile lock poisoned") = None;
                go.refresh_source_inventory()?;
            }
            return Ok(if trigger == GoReconciliationTrigger::SourceChange {
                DependencyDiscoveryOutcome::complete(Vec::new())
            } else {
                crate::analyzer::go::dependency_discovery::discover_go_packages(
                    &config.go,
                    project,
                    limits,
                    Some(cancellation),
                )
                .semantic_packs
            });
        }
        if let Some(go) = resolve_analyzer::<crate::analyzer::GoAnalyzer>(workspace.analyzer()) {
            *go.active_base_profile
                .write()
                .expect("Go base profile lock poisoned") = Some(
                brokk_bifrost_analysis::analyzer::store::go_package_context::base_profile_digest(
                    &base_template,
                ),
            );
            go.build_selection_error
                .write()
                .expect("Go build selection lock poisoned")
                .clear();
        }
        let width = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .min(8);
        let mut aggregate = DependencyDiscoveryOutcome::complete(Vec::new());
        let mut worker_failures = Vec::new();
        for chunk in domains.chunks(width) {
            let outcomes = std::thread::scope(|scope| {
                let handles=chunk.iter().map(|(domain,input_digest)| {
                    let base_environment=base_environment.clone();
                    let root_key=&root_key;
                    let overlays=&overlays;
                    scope.spawn(move || -> brokk_bifrost_analysis::analyzer::store::Result<_> {
                        use crate::analyzer::go::dependency_discovery::{domain_environment, discover_domain, GoPackageDiscovery};
                        let mut environment=base_environment;
                        environment.gowork=if domain.gowork_path.is_empty(){"off".into()}else{project.root().join(&domain.gowork_path).to_string_lossy().into_owned()};
                        let mut canonical=GoPackageDiscovery {
                            domain:domain.clone(),input_digest:Some(*input_digest),failure:None,packages:Vec::new(),
                            build_configuration:crate::analyzer::go::dependency_discovery::selected_build_configuration(
                                &config.go.dependency_discovery,&environment.goos,&environment.goarch),
                            environment,
                            workspace_patterns:config.go.dependency_discovery.workspace_patterns.clone(),vendor:false,
                        };
                        let profile=profile_digest(&canonical);
                        let changed_membership;
                        if let Some(context)=store.go_context_for_reconciliation(selected,&profile)? {
                            let conn=store.read_conn()?;
                            let (digest,complete):(Vec<u8>,bool)=conn.query_row("SELECT input_digest,complete FROM go_context_publications WHERE context_id=?1",[context.context_id],|row|Ok((row.get(0)?,row.get(1)?)))?;
                            drop(conn);
                            let root=root_key.as_ref().is_some_and(|key|key.0==domain.directory && key.1==domain.gowork_path);
                            let force=trigger==GoReconciliationTrigger::ExplicitRefresh
                                || (trigger==GoReconciliationTrigger::DependencyActivation && (root || !complete));
                            if digest.as_slice()==input_digest && !force {
                                return Ok((domain.clone(),None,Some((context,profile))));
                            }
                            // Equal membership digests prove that transient placement
                            // keeps build constraints (both forms), package name, cgo
                            // and imports. Body-only buffers need no new tool evidence.
                            // File-name membership (_test.go, _linux.go, leading _ or .)
                            // changes only on disk and is outside this overlay trigger.
                            let placement = store.go_overlay_placement(selected, project.root(), Some(context.context_id), domain, overlays)?;
                            changed_membership = placement.changed_membership;
                            if placement.reuse_context && !force {
                                return Ok((domain.clone(),None,Some((context,profile))));
                            }
                        } else {
                            changed_membership = store.go_overlay_placement(selected, project.root(), None, domain, overlays)?.changed_membership;
                        }
                        // Body-only buffers are overlaid only when some buffer
                        // changed membership. Disk-only discovery needs no replacements:
                        // equal membership digests give the same go list answer.
                        let disk_only = Default::default();
                        let discovery_overlays = if changed_membership { overlays } else { &disk_only };
                        let mut discovered=match domain_environment(&config.go,project,domain,cancellation) {
                            Ok(environment)=>discover_domain(&config.go,project,limits,cancellation,domain,environment,discovery_overlays),
                            Err(error)=>{
                                canonical.failure=Some(error.clone());
                                let mut semantic_packs=DependencyDiscoveryOutcome::complete(Vec::new());
                                semantic_packs.complete=false;
                                semantic_packs.diagnostics.push(brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackDiagnostic {
                                    severity:brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackDiagnosticSeverity::Error,
                                    code:"go.env_failed".into(),dependency_id:None,location:None,message:error,
                                });
                                crate::analyzer::go::dependency_discovery::GoDiscoveryOutcome {canonical:Some(canonical.clone()),semantic_packs}
                            }
                        };
                        if discovered.canonical.is_none() && !cancellation.is_cancelled() {
                            canonical.failure=Some(discovered.semantic_packs.diagnostics.first().map(|diagnostic|diagnostic.message.clone()).unwrap_or_else(||"Go domain discovery unavailable".into()));
                            discovered.canonical=Some(canonical);
                        }
                        if let Some(canonical)=discovered.canonical.as_mut() {
                            canonical.input_digest=Some(*input_digest);
                            if let Some(error)=discovered.semantic_packs.diagnostics.iter().find(|diagnostic|diagnostic.code=="go.list_failed") {
                                canonical.failure=Some(error.message.clone());
                            }
                        }
                        Ok((domain.clone(),Some(discovered),None))
                    })
                }).collect::<Vec<_>>();
                // Join every scoped worker even when a sibling fails or panics.
                handles
                    .into_iter()
                    .map(|handle| match handle.join() {
                        Ok(result) => result,
                        Err(panic) => Err(
                            brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                                "Go domain worker in {chunk:?} panicked: {}",
                                panic
                                    .downcast_ref::<String>()
                                    .map(String::as_str)
                                    .or_else(|| panic.downcast_ref::<&str>().copied())
                                    .map(str::to_owned)
                                    .unwrap_or_else(|| format!("{panic:?}"))
                            )),
                        ),
                    })
                    .collect::<Vec<_>>()
            });
            for outcome in outcomes {
                let (domain, discovered, reused) = match outcome {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        worker_failures.push(error.to_string());
                        continue;
                    }
                };
                if let Some((identity, profile)) = reused {
                    match store.reconcile_unit_summaries(selected,brokk_bifrost_analysis::analyzer::store::go_unit_summaries::GoUnitSummaries{context_id:identity.context_id,profile},cancellation) {
                        Ok(report) if report.failed.is_empty()=>{},
                        report=>eprintln!("go.unit_summary_failed: domain {domain:?}, reconciliation {report:?}"),
                    }
                    if root_key
                        .as_ref()
                        .is_some_and(|key| key.0 == domain.directory && key.1 == domain.gowork_path)
                        && let Some(go) =
                            brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                                crate::analyzer::GoAnalyzer,
                            >(workspace.analyzer())
                    {
                        go.activate_native_context_profile(selected, profile);
                    }
                    continue;
                }
                let mut discovered = discovered.expect("a domain was reused or discovered");
                let Some(canonical) = discovered.canonical.take() else {
                    aggregate.complete &= discovered.semantic_packs.complete;
                    continue;
                };
                let selected_snapshot = snapshot.clone();
                let profile = profile_digest(&canonical);
                let mut input_change = None;
                let publication =
                    match (snapshot.clone(), before.clone()) {
                        (Some(snapshot), Some(GoInputObservationOutcome::Ready(before))) => {
                            let expected = prior_heads.iter().cloned().find_map(
                                |(prior_profile, identity)| {
                                    (prior_profile == profile).then_some(identity)
                                },
                            );
                            match store.observe_go_context_inputs_with_overlay(
                                &snapshot,
                                project,
                                cancellation,
                                &overlays,
                            )? {
                                GoInputObservationOutcome::Ready(after) => store
                                    .publish_go_package_context(
                                        snapshot,
                                        project.root().to_path_buf(),
                                        expected,
                                        &before,
                                        &after,
                                        canonical,
                                        cancellation,
                                    )?,
                                GoInputObservationOutcome::InputsChanged(change) => {
                                    input_change = Some(change);
                                    GoContextPublicationOutcome::InputsChanged
                                }
                                GoInputObservationOutcome::Cancelled => {
                                    GoContextPublicationOutcome::Cancelled
                                }
                            }
                        }
                        (_, Some(GoInputObservationOutcome::Cancelled)) => {
                            GoContextPublicationOutcome::Cancelled
                        }
                        (_, Some(GoInputObservationOutcome::InputsChanged(change))) => {
                            input_change = Some(change);
                            GoContextPublicationOutcome::InputsChanged
                        }
                        _ => GoContextPublicationOutcome::InputsChanged,
                    };
                let publication = match publication {
                    GoContextPublicationOutcome::Published(identity) => {
                        let activated = !root_key.as_ref().is_some_and(|key| {
                            key.0 == domain.directory && key.1 == domain.gowork_path
                        }) || selected_snapshot.as_ref().is_some_and(|snapshot| {
                            brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                                crate::analyzer::GoAnalyzer,
                            >(workspace.analyzer())
                            .is_some_and(|go| go.activate_native_context_profile(snapshot, profile))
                        });
                        if activated {
                            GoContextPublicationOutcome::Published(identity)
                        } else {
                            GoContextPublicationOutcome::InputsChanged
                        }
                    }
                    other => other,
                };
                match publication {
                    GoContextPublicationOutcome::Published(identity) => {
                        brokk_bifrost_core::profiling::note_with(|| {
                            format!("go.native_context published={identity:?}")
                        });
                        // The head is the membership authority the unit summaries are
                        // derived from, so they are reconciled after it and never before.
                        let snapshot = selected_snapshot
                            .as_ref()
                            .expect("a published Go context was selected at a snapshot");
                        // The summaries are optional (readers fall back), so a store error
                        // here is a diagnostic, not a failure of the activation whose head
                        // was already published.
                        let timing =
                            brokk_bifrost_core::profiling::scope("go.unit_summaries.reconcile");
                        let reconciliation = store.reconcile_unit_summaries(
                    snapshot,
                    brokk_bifrost_analysis::analyzer::store::go_unit_summaries::GoUnitSummaries {
                        context_id: identity.context_id,
                        profile,
                    },
                    cancellation,
                );
                        drop(timing);
                        brokk_bifrost_core::profiling::note_with(|| {
                            format!("go.unit_summaries reconciled={reconciliation:?}")
                        });
                        let failure = match &reconciliation {
                            Ok(reconciliation) if reconciliation.failed.is_empty() => None,
                            Ok(reconciliation) => Some(format!(
                                "Go unit summaries were not published for {:?}",
                                reconciliation.failed
                            )),
                            Err(error) => {
                                Some(format!("Go unit summaries were not reconciled: {error}"))
                            }
                        };
                        if let Some(message) = failure {
                            discovered.semantic_packs.diagnostics.push(brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackDiagnostic {
                        severity: brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackDiagnosticSeverity::Warning,
                        code: "go.unit_summary_failed".into(), dependency_id: None, location: None,
                        message,
                    });
                        }
                    }
                    GoContextPublicationOutcome::Cancelled => {
                        discovered.semantic_packs.cancelled = true;
                        discovered.semantic_packs.complete = false;
                    }
                    GoContextPublicationOutcome::InputsChanged => {
                        // Without the first disagreement, the refusal was the
                        // before/after comparison or the publication's head check.
                        let message = format!(
                            "Go source or configuration no longer matches the selected revision ({}); native package context was not published",
                            input_change.map_or_else(
                                || "inputs changed while discovery ran".to_owned(),
                                |change| format!("{change:?}")
                            )
                        );
                        eprintln!("go.native_context_inputs_changed: domain {domain:?}: {message}");
                        discovered.semantic_packs.complete = false;
                        discovered.semantic_packs.diagnostics.push(brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackDiagnostic {
                    severity: brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackDiagnosticSeverity::Warning,
                    code: "go.native_context_inputs_changed".into(), dependency_id:None, location:None,
                    message,
                });
                    }
                }
                if root_key
                    .as_ref()
                    .is_some_and(|key| key.0 == domain.directory && key.1 == domain.gowork_path)
                {
                    aggregate = discovered.semantic_packs;
                }
            }
        }
        if root_key.is_none() && trigger != GoReconciliationTrigger::SourceChange {
            aggregate = crate::analyzer::go::dependency_discovery::discover_go_packages(
                &config.go,
                project,
                limits,
                Some(cancellation),
            )
            .semantic_packs;
        }
        if !worker_failures.is_empty() {
            return Err(brokk_bifrost_analysis::analyzer::store::StoreError::new(
                format!("Go domain workers failed: {worker_failures:?}"),
            ));
        }
        Ok(aggregate)
    }
}

#[cfg(test)]
mod hierarchy_tests {
    //! Lives here rather than beside the builder in `brokk-bifrost-go`: the
    //! fixture needs a real `GoAnalyzer` to supply the `CodeUnitIndex` and
    //! `ImportAnalysisProvider` the hierarchy is built from.

    use crate::analyzer::go::*;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use crate::inline_project::InlineTestProject;
    use std::fs;
    use tempfile::tempdir;

    fn status(analyzer: &GoAnalyzer, path: &str, name: &str) -> Option<bool> {
        analyzer.predeclared_builtin_shadow_status_limited(path, name, 64, || true)
    }

    fn analyzer(files: &[(&str, &str)]) -> GoAnalyzer {
        let temp = tempdir().unwrap();
        let root = temp.keep();
        fs::write(root.join("go.mod"), "module example.com/app\n\ngo 1.22\n").unwrap();
        for (path, source) in files {
            let path = root.join(path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, source).unwrap();
        }
        GoAnalyzer::from_project(TestProject::new(root, Language::Go))
    }

    #[test]
    fn canonical_method_sets_preserve_array_lengths_channels_and_repeated_parameters() {
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/app\n\ngo 1.24\n")
            .file("types.go", "package app\n\
                type Contract interface { Run(a,b [4]int, tail ...chan<- int) (int,error) }\n\
                type Exact struct{}\n\
                type DifferentLength struct{}\n\
                type DifferentDirection struct{}\n\
                func (Exact) Run(a,b [4]int, tail ...chan<- int) (int,error) { return 0,nil }\n\
                func (DifferentLength) Run(a,b [5]int, tail ...chan<- int) (int,error) { return 0,nil }\n\
                func (DifferentDirection) Run(a,b [4]int, tail ...<-chan int) (int,error) { return 0,nil }\n")
            .build();
        let analyzer = GoAnalyzer::new(project.project_dyn());
        let index = analyzer.hierarchy_index().unwrap();
        let contract = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.is_class() && unit.identifier() == "Contract")
            .unwrap();
        let descendants = index.direct_descendants(&contract);
        assert!(
            descendants.iter().any(|unit| unit.identifier() == "Exact"),
            "{descendants:?}"
        );
        assert!(
            !descendants
                .iter()
                .any(|unit| matches!(unit.identifier(), "DifferentLength" | "DifferentDirection")),
            "distinct source method sets must not compare equal: {descendants:?}"
        );
    }

    #[test]
    fn graph_index_reports_a_missing_canonical_package_clause() {
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/app\n\ngo 1.24\n")
            .file("broken.go", "// no package clause\nfunc Broken() {}\n")
            .build();
        let analyzer = GoAnalyzer::new(project.project_dyn());
        let error = match analyzer.usage_edge_index() {
            Ok(_) => panic!("a missing package clause must not produce a complete graph"),
            Err(error) => error,
        };
        assert!(
            error.unavailable_files.contains(&project.file("broken.go")),
            "missing package clause must identify the unavailable file: {error:?}"
        );
        for _ in 0..2 {
            assert!(
                analyzer.hierarchy_index().is_err(),
                "unavailable canonical input must not cache an empty hierarchy"
            );
        }
    }

    #[test]
    fn usage_graph_keeps_cross_file_receiver_method_in_canonical_inventory() {
        use brokk_bifrost_analysis::analyzer::usages::traits::UsageAnalyzer;

        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/app\n\ngo 1.24\n")
            .file(
                "api/types.go",
                "package api\n\ntype Worker struct{}\n",
            )
            .file(
                "api/method.go",
                "package api\n\nfunc (Worker) Run() {}\n",
            )
            .file(
                "caller.go",
                "package main\n\nimport \"example.com/app/api\"\n\nfunc call(worker api.Worker) { worker.Run() }\n",
            )
            .build();
        let analyzer = GoAnalyzer::new(project.project_dyn());
        let target = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.fq_name() == "example.com/app/api.Worker.Run")
            .expect("receiver method should be indexed in its defining file");
        let candidates = analyzer.get_analyzed_files().into_iter().collect();
        let hits = GO_NATIVE_USAGE_STRATEGY
            .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 100)
            .into_either()
            .expect("cross-file receiver method should have a complete graph");

        assert_eq!(hits.len(), 1, "expected one caller: {hits:#?}");
        let hit = hits.first().expect("one caller hit");
        assert_eq!(hit.file, project.file("caller.go"));
        assert_eq!(hit.enclosing.identifier(), "call");
    }

    #[test]
    fn structural_relation_records_satisfied_interface() {
        let analyzer = analyzer(&[(
            "service.go",
            "package app\ntype Runner interface { Run() error }\ntype Worker struct{}\nfunc (Worker) Run() error { return nil }\n",
        )]);
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let index = GoHierarchyIndex::build(GoGraphSource {
            token,
            index: &analyzer,
            imports: &analyzer,
            type_aliases: &analyzer,
            workspace_paths: analyzer.workspace_path_index(),
            package_clauses: &analyzer,
            source_facts: &analyzer,
        })
        .unwrap();
        assert!(index.relations().iter().any(|relation| {
            relation.kind == TypeRelationKind::StructuralSatisfaction
                && relation.from.identifier() == "Worker"
                && relation.to.identifier() == "Runner"
        }));
    }

    /// The member of `owner` named `identifier`, by exact declaration identity.
    fn member(analyzer: &GoAnalyzer, owner: &str, identifier: &str) -> CodeUnit {
        analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| {
                unit.is_function()
                    && unit.identifier() == identifier
                    && unit.owner_identifier() == Some(owner)
            })
            .unwrap_or_else(|| panic!("no declaration {owner}.{identifier}"))
    }

    /// The members the family answer says implement `member`, by short name.
    fn implementors(analyzer: &GoAnalyzer, member: &CodeUnit) -> Vec<String> {
        use brokk_bifrost_core::analyzer::structural::resolution::MethodFamilyRelation;

        use brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyProvider;
        let answer = analyzer.member_family(member, None);
        assert!(
            answer.is_proven(),
            "family for {} is not proven: {:?} {:?}",
            member.fq_name(),
            answer.outcome,
            answer.reason
        );
        let mut names: Vec<_> = answer
            .edges
            .iter()
            .filter(|edge| edge.relation == MethodFamilyRelation::ImplementedBy)
            .map(|edge| edge.target.short_name().to_string())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn interface_method_resolves_to_its_implementors() {
        let analyzer = analyzer(&[(
            "service.go",
            "package app\n\
             type Runner interface { Run(id int) error }\n\
             type Worker struct{}\n\
             func (Worker) Run(id int) error { return nil }\n\
             type Pointer struct{}\n\
             func (*Pointer) Run(id int) error { return nil }\n",
        )]);
        let declaration = member(&analyzer, "Runner", "Run");
        assert_eq!(
            implementors(&analyzer, &declaration),
            vec!["Pointer.Run".to_string(), "Worker.Run".to_string()],
            "a pointer receiver implements the interface for *Pointer, and its \
             body is still the code that runs"
        );
    }

    #[test]
    fn repeated_inline_interface_projections_keep_their_own_members() {
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/app\n\ngo 1.24\n")
            .file(
                "service.go",
                "package app\n\
                 type Outer struct {\n\
                     A, B interface { Run() error }\n\
                 }\n\
                 type Worker struct{}\n\
                 func (Worker) Run() error { return nil }\n",
            )
            .build();
        let analyzer = GoAnalyzer::new(project.project_dyn());

        assert_eq!(
            implementors(&analyzer, &member(&analyzer, "A", "Run")),
            vec!["Worker.Run".to_string()]
        );
        assert_eq!(
            implementors(&analyzer, &member(&analyzer, "B", "Run")),
            vec!["Worker.Run".to_string()]
        );
    }

    #[test]
    fn non_nominal_aliases_do_not_become_element_type_relations_or_poison_peers() {
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/app\n\ngo 1.24\n")
            .file(
                "service.go",
                "package app\n\
                 type Runner interface { Run() error }\n\
                 type Worker struct{}\n\
                 func (Worker) Run() error { return nil }\n\
                 type SliceAlias = []Worker\n\
                 type TextAlias = string\n",
            )
            .build();
        let analyzer = GoAnalyzer::new(project.project_dyn());
        let index = analyzer.hierarchy_index().unwrap();
        let slice_alias = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.is_field() && unit.identifier() == "SliceAlias")
            .expect("slice alias declaration");
        assert!(
            index.direct_ancestors(&slice_alias).is_empty(),
            "a slice alias must not inherit the element type's interface relations"
        );
        assert_eq!(
            implementors(&analyzer, &member(&analyzer, "Runner", "Run")),
            vec!["Worker.Run".to_string()],
            "valid predeclared and non-nominal aliases must not make unrelated families incomplete"
        );
    }

    #[test]
    fn missing_workspace_alias_target_is_not_complete_empty_evidence() {
        use brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyOutcome;

        use brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyProvider;
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/app\n\ngo 1.24\n")
            .file("dep/types.go", "package dep\ntype Present struct{}\n")
            .file(
                "service.go",
                "package app\nimport \"example.com/app/dep\"\n\
                type Alias = dep.Missing\n\
                type Runner interface { Run() }\n\
                type Worker struct{}\nfunc (Worker) Run() {}\n",
            )
            .build();
        let analyzer = GoAnalyzer::new(project.project_dyn());
        let answer = analyzer.member_family(&member(&analyzer, "Runner", "Run"), None);
        assert_eq!(
            answer.outcome,
            MemberFamilyOutcome::Incomplete,
            "{answer:?}"
        );
    }

    #[test]
    fn a_type_that_satisfies_an_interface_by_embedding_reports_the_embedded_method() {
        let analyzer = analyzer(&[(
            "service.go",
            "package app\n\
             type Runner interface { Run(id int) error }\n\
             type Base struct{}\n\
             func (Base) Run(id int) error { return nil }\n\
             type Derived struct{ Base }\n",
        )]);
        let declaration = member(&analyzer, "Runner", "Run");
        assert_eq!(
            implementors(&analyzer, &declaration),
            vec!["Base.Run".to_string()],
            "Derived satisfies Runner through promotion, and the declaration \
             that runs is Base's"
        );
    }

    #[test]
    fn an_embedded_interfaces_method_keeps_its_own_declaration_as_the_family_root() {
        let analyzer = analyzer(&[(
            "service.go",
            "package app\n\
             type Starter interface { Start() error }\n\
             type Runner interface { Starter; Run() error }\n\
             type Worker struct{}\n\
             func (Worker) Start() error { return nil }\n\
             func (Worker) Run() error { return nil }\n",
        )]);
        assert_eq!(
            implementors(&analyzer, &member(&analyzer, "Starter", "Start")),
            vec!["Worker.Start".to_string()]
        );
        assert_eq!(
            implementors(&analyzer, &member(&analyzer, "Runner", "Run")),
            vec!["Worker.Run".to_string()]
        );
    }

    #[test]
    fn the_forward_and_inverse_directions_name_the_same_pair() {
        use brokk_bifrost_core::analyzer::structural::resolution::MethodFamilyRelation;

        use brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyProvider;
        let analyzer = analyzer(&[(
            "service.go",
            "package app\n\
             type Runner interface { Run() error }\n\
             type Worker struct{}\n\
             func (Worker) Run() error { return nil }\n",
        )]);
        let declaration = member(&analyzer, "Runner", "Run");
        let implementor = member(&analyzer, "Worker", "Run");
        let forward = analyzer.member_family(&implementor, None);
        assert!(forward.is_proven());
        assert_eq!(
            forward
                .edges
                .iter()
                .filter(|edge| edge.relation == MethodFamilyRelation::Implements)
                .map(|edge| edge.target.clone())
                .collect::<Vec<_>>(),
            vec![declaration.clone()]
        );
        assert_eq!(forward.roots, vec![declaration.clone()]);
        let inverse = analyzer.member_family(&declaration, None);
        assert_eq!(
            inverse
                .edges
                .iter()
                .filter(|edge| edge.relation == MethodFamilyRelation::ImplementedBy)
                .map(|edge| edge.target.clone())
                .collect::<Vec<_>>(),
            vec![implementor]
        );
        assert_eq!(inverse.roots, vec![declaration]);
    }

    #[test]
    fn an_interface_with_type_terms_leaves_both_ends_of_its_family_incomplete() {
        use brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyOutcome;

        use brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyReason;

        use brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyProvider;
        let analyzer = analyzer(&[(
            "service.go",
            "package app\n\
             type Labelled interface { ~int | ~int64; Label() string }\n\
             type Counter struct{}\n\
             func (Counter) Label() string { return \"counter\" }\n\
             type Plain interface { Run() error }\n\
             type Worker struct{}\n\
             func (Worker) Run() error { return nil }\n",
        )]);
        for unit in [
            member(&analyzer, "Labelled", "Label"),
            member(&analyzer, "Counter", "Label"),
        ] {
            let answer = analyzer.member_family(&unit, None);
            assert_eq!(
                answer.outcome,
                MemberFamilyOutcome::Incomplete,
                "the satisfaction pass skips an interface carrying type terms, \
                 so neither end of {} may claim an exhaustive family",
                unit.fq_name()
            );
            assert_eq!(answer.reason, Some(MemberFamilyReason::HierarchyTruncated));
            assert!(answer.edges.is_empty());
        }
        assert_eq!(
            implementors(&analyzer, &member(&analyzer, "Plain", "Run")),
            vec!["Worker.Run".to_string()],
            "an unrelated interface in the same workspace still answers"
        );
    }

    #[test]
    fn package_scope_lookup_finds_sibling_functions_variables_and_types() {
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/app\n\ngo 1.24\n")
            .file(
                "main.go",
                "package app\nfunc Run() { _ = max(1, 2); _ = min(1, 2); _ = len([]int{}) }\n",
            )
            .file(
                "util.go",
                "package app\nfunc max(a, b int) int { return a }\nvar min func(int, int) int\ntype len []int\n",
            )
            .build();
        let analyzer = GoAnalyzer::new(project.project_dyn());

        assert_eq!(status(&analyzer, "main.go", "max"), Some(true));
        assert_eq!(status(&analyzer, "main.go", "min"), Some(true));
        assert_eq!(status(&analyzer, "main.go", "len"), Some(true));
    }

    #[test]
    fn package_scope_lookup_proves_absence_for_a_single_file_package() {
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/app\n\ngo 1.24\n")
            .file(
                "main.go",
                "package app\nfunc Run() { _ = max(1, 2); _ = min(1, 2); _ = len([]int{}) }\n",
            )
            .build();
        let analyzer = GoAnalyzer::new(project.project_dyn());

        assert_eq!(status(&analyzer, "main.go", "max"), Some(false));
        assert_eq!(status(&analyzer, "main.go", "min"), Some(false));
        assert_eq!(status(&analyzer, "main.go", "len"), Some(false));
    }
}

mod selector_calls {

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ResolverOwnedExternalCalleeIdentity;

    use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

    use brokk_bifrost_core::analyzer::usages::model::UsageProof;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchBoundaryKind;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchLookup;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchTarget;

    use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::CallApplicationKind;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

    use crate::analyzer::usages::get_definition::go::GoTypedSelectorTarget;

    use crate::analyzer::usages::get_definition::go::go_typed_selector_target;

    use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::model::Range;
    use brokk_bifrost_core::analyzer::query_token::QueryToken;
    fn go_selector_call_parts<'tree>(
        tree: &'tree tree_sitter::Tree,
        callee_range: &Range,
        source: &str,
    ) -> Option<(tree_sitter::Node<'tree>, tree_sitter::Node<'tree>, String)> {
        let root = tree.root_node();
        let mut node =
            root.descendant_for_byte_range(callee_range.start_byte, callee_range.end_byte)?;
        let (selector, member) = loop {
            if node.kind() == "selector_expression"
                && let Some(field) = node.child_by_field_name("field")
                && callee_range.start_byte <= field.start_byte()
                && field.end_byte() <= callee_range.end_byte
            {
                break (node, field);
            }
            node = node.parent()?;
        };
        let call = selector.parent()?;
        if call.kind() != "call_expression"
            || !call
                .child_by_field_name("function")
                .is_some_and(|function| function.id() == selector.id())
        {
            return None;
        }
        let receiver = selector.child_by_field_name("operand")?;
        let member_name = source.get(member.byte_range())?.to_owned();
        Some((receiver, selector, member_name))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply_go_typed_selector_target_at_call(
        lookup: &mut CallDispatchLookup,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        file: &ProjectFile,
        source: &str,
        tree: &tree_sitter::Tree,
        callee_range: &Range,
        cancellation: Option<&CancellationToken>,
    ) {
        let Some((receiver, callable, member)) = go_selector_call_parts(tree, callee_range, source)
        else {
            return;
        };
        match go_typed_selector_target(
            analyzer,
            token,
            file,
            source,
            tree.root_node(),
            receiver,
            callable,
            &member,
            receiver.start_byte(),
            brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget::default(),
            cancellation,
        ) {
            BoundedResolution::Complete {
                value: Some(target),
                work: receiver_work,
            } => {
                lookup.work.examined_candidates = lookup
                    .work
                    .examined_candidates
                    .saturating_add(receiver_work.setup_nodes)
                    .saturating_add(receiver_work.scope_nodes)
                    .saturating_add(receiver_work.summary_expansions);
                // A function-valued field is loaded by the callable-value
                // path; it is not a method merely because its name is unique.
                if let Some(anchor) = target.field_anchor {
                    lookup.member_field_anchor = Some(anchor);
                    return;
                }
                apply_go_typed_selector_target(lookup, target);
            }
            BoundedResolution::Complete {
                value: None,
                work: receiver_work,
            }
            | BoundedResolution::Exceeded {
                work: receiver_work,
                ..
            } => {
                lookup.work.examined_candidates = lookup
                    .work
                    .examined_candidates
                    .saturating_add(receiver_work.setup_nodes)
                    .saturating_add(receiver_work.scope_nodes)
                    .saturating_add(receiver_work.summary_expansions);
            }
            BoundedResolution::Cancelled { .. } => lookup.cancelled = true,
        }
    }

    fn apply_go_typed_selector_target(
        lookup: &mut CallDispatchLookup,
        target: GoTypedSelectorTarget,
    ) {
        lookup.targets.clear();
        lookup.boundaries.clear();
        lookup.adjudicated_no_target = false;
        lookup.adjudicated_non_callable = false;
        lookup.truncated = false;
        lookup.budget_exhausted = false;
        lookup.exact_external_call = None;
        lookup.boundary = None;
        lookup.dispatch_extensibility = None;
        lookup.go_interface_receiver = target.receiver_is_interface;
        lookup.go_selector_member = Some(target.member.clone());
        lookup.member_receiver_preparation = target.receiver_preparation;
        if !target.workspace_methods.is_empty() {
            let ambiguous = target.workspace_methods.len() > 1;
            lookup
                .targets
                .extend(
                    target
                        .workspace_methods
                        .into_iter()
                        .map(|method| CallDispatchTarget {
                            definition: method,
                            proof: if ambiguous {
                                UsageProof::Unproven
                            } else {
                                UsageProof::Proven
                            },
                            native_incomplete_source_reason: None,
                        }),
                );
            lookup.status = Some(if ambiguous {
                DefinitionLookupStatus::Ambiguous
            } else {
                DefinitionLookupStatus::Resolved
            });
            lookup.call_application = CallApplicationKind::BoundReceiver;
            if ambiguous {
                lookup
                    .boundaries
                    .push(CallDispatchBoundaryKind::UnresolvedReason(
                        "Go method selection retains multiple promoted declarations".into(),
                    ));
            }
            if target.receiver_is_interface {
                lookup
                    .boundaries
                    .push(CallDispatchBoundaryKind::UnresolvedReason(
                        "Go interface implementations are not closed by the analyzed module".into(),
                    ));
            }
            return;
        }
        let Some(callee) = target.external_callee else {
            return;
        };
        let Some(external_call) = target.external_call else {
            return;
        };
        lookup.status = Some(DefinitionLookupStatus::UnresolvableImportBoundary);
        lookup.boundary = Some(BoundaryStatus::ExternalIndexed);
        lookup.call_application = external_call.call_application();
        lookup.dispatch_extensibility = external_call.dispatch_extensibility();
        lookup.exact_external_call = Some(external_call);
        lookup.boundaries.push(CallDispatchBoundaryKind::External {
            callee_text: Some(callee.into_boxed_str()),
            normalized_static_owner: None,
            external_callee_identity: target.external_concrete_owner_fqn.map(|owner| {
                ResolverOwnedExternalCalleeIdentity::new(Language::Go, owner, target.member.clone())
            }),
        });
        if target.receiver_is_interface {
            lookup
                .boundaries
                .push(CallDispatchBoundaryKind::UnresolvedReason(
                    "Go interface implementations are not closed by the analyzed module".into(),
                ));
        }
    }
}

/// Classify Go's runtime/test entry points from the persisted package clause.
/// Only a function named `main` needs that fact; the Go crate owns the pure shape and
/// test-file rules, while this shim supplies the analyzer's structured property.
#[doc(hidden)]
pub fn go_implicit_entry_point(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> Option<bool> {
    let package_clause = (candidate.is_function() && candidate.identifier() == "main")
        .then(|| {
            resolve_analyzer::<GoAnalyzer>(analyzer)
                .and_then(|go| go.package_clause_of(candidate.source()))
        })
        .flatten();
    brokk_bifrost_go::entry_point::go_implicit_entry_point(candidate, package_clause.as_deref())
}

/// The Go crate takes its analyzer facts as core capability traits plus the Go
/// workspace path index; this is the one place the concrete analyzer is
/// unpacked into them.
pub(crate) fn go_graph_source<'a>(go: &'a GoAnalyzer, token: QueryToken<'a>) -> GoGraphSource<'a> {
    GoGraphSource {
        token,
        index: go,
        imports: go,
        type_aliases: go,
        workspace_paths: go.workspace_path_index(),
        package_clauses: go,
        source_facts: go,
    }
}
