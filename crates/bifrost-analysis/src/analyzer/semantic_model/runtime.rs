use crate::CancellationToken;

use brokk_bifrost_core::budgeted_value_cache::{BudgetedValueAcquisition, BudgetedValueCache};
use brokk_bifrost_core::retention_budget::{AllocationCharge, RetentionBudget, SharedAllocation};

use crate::analyzer::IAnalyzer;
use crate::analyzer::Language;
use crate::analyzer::semantic_model::PayloadKind;
use crate::analyzer::semantic_model::SemanticModelOverlay;
use crate::analyzer::semantic_model::SemanticModelOverlayBuildError;
use crate::analyzer::semantic_model::SemanticPackCatalog;
use crate::analyzer::semantic_model::SemanticPackSelectorQuery;
use crate::analyzer::semantic_model::{ApproximationReason, ApproximationReasons};
use crate::analyzer::semantic_model::{CatalogCoordinate, CatalogMiss, CatalogPackSourceKind};
use crate::analyzer::store::active_models::ActivationExclusions;
pub use crate::analyzer::store::active_models::{
    ActivatedProcedureSummary, ActivatedSemanticModelRecord, ActiveSemanticModelShard,
    EffectiveProcedureClaims, MatcherIndexes, ProcedureSummaryMatch, ResolvedActiveSemanticModels,
    ReviewedObligationTarget, SemanticModelActivationExplanation, SemanticModelActivationReport,
    SemanticModelMatch, absorb_procedure_posting, build_normal_continuation_absence_candidates,
    empty_procedure_match, indexed_procedure_summary, insert_rule_trigger,
    procedure_match_proves_normal_continuation_absent, procedure_summary_actual_to_formal,
    python_artifact_applies_to_target, python_shard_requires_distribution_artifact,
    resolve_applicable_procedure_postings, resolve_applicable_procedure_postings_where,
    resolve_applicable_procedure_postings_where_for_counts, resolve_exact_procedure_postings,
    resolve_posting, resolve_procedure_postings, resolve_procedure_postings_where,
};
use crate::analyzer::store::{
    AnalyzerStore, SemanticPackActivationSourceKind, SemanticPackActiveReference,
};
use crate::hash::{HashMap, HashSet, map_with_capacity};
use brokk_bifrost_core::util::elapsed_ns;

pub use brokk_bifrost_semantic::analyzer::semantic_model::runtime::*;

use semver::Version;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// #10189 lifts this hold after Match and Assertion have per-lookup OPEN.
/// Installed includes a user-supplied local bundle; it is visibly refused
/// under the interim rule rather than treated as an unmarked exact model.
const APPROXIMATE_DISTRIBUTED_SHARDS_ALLOWED: bool = false;

fn is_distributed_pack_source(kind: CatalogPackSourceKind) -> bool {
    matches!(
        kind,
        CatalogPackSourceKind::Installed
            | CatalogPackSourceKind::PreShipped
            | CatalogPackSourceKind::Embedded
    )
}

/// Effective query overlay, after applying the query's frozen override.
#[derive(Debug, Clone)]
pub enum SemanticModelOverlayRead {
    Published(Arc<SemanticModelOverlay>),
    Pending(crate::analyzer::QueryReadIncomplete),
    NotSelected,
}

impl SemanticModelOverlayRead {
    /// Read model facts while preserving missing-publication evidence in all
    /// carried query contexts. Only NotSelected proves legitimate absence.
    pub fn published(self) -> Option<Arc<SemanticModelOverlay>> {
        match self {
            Self::Published(overlay) => Some(overlay),
            Self::Pending(reason) => {
                crate::analyzer::i_analyzer::record_query_incomplete_on_current_contexts(reason);
                None
            }
            Self::NotSelected => None,
        }
    }
}

/// One immutable semantic-model publication captured under the runtime's
/// publication lock.
///
/// The declaration overlay is derived from `active_models`. Keeping the pair
/// in one owned value prevents a request from combining one activation's
/// procedure summaries with a later activation's declaration resolver.
#[derive(Debug, Clone)]
pub struct ActiveSemanticModelSnapshot {
    active_models: Arc<ResolvedActiveSemanticModels>,
    summary_endpoint_admission: Option<Arc<super::endpoint_projections::SummaryEndpointAdmission>>,
    rust_cargo_graph: Option<Arc<super::RustSelectedCargoGraph>>,
    semantic_model_overlay: Option<Arc<SemanticModelOverlay>>,
    overlay_measurement: Option<SemanticModelOverlayMeasurement>,
    jdk_artifacts_by_configured_home: Arc<HashMap<PathBuf, SemanticModelActivationEvidence>>,
    #[doc(hidden)]
    pub python_runtime:
        Option<crate::analyzer::store::python_runtime::PythonRuntimeProviderPublication>,
}

struct OverlayActivation<'a> {
    request: &'a SemanticModelActivationRequest,
    rust_cargo_graph: Option<&'a super::RustSelectedCargoGraph>,
}

impl ActiveSemanticModelSnapshot {
    fn new(
        active_models: Arc<ResolvedActiveSemanticModels>,
        rust_cargo_graph: Option<Arc<super::RustSelectedCargoGraph>>,
        semantic_model_overlay: Option<Arc<SemanticModelOverlay>>,
        overlay_measurement: Option<SemanticModelOverlayMeasurement>,
        jdk_artifacts_by_configured_home: Arc<HashMap<PathBuf, SemanticModelActivationEvidence>>,
        python_runtime: Option<
            crate::analyzer::store::python_runtime::PythonRuntimeProviderPublication,
        >,
    ) -> Self {
        debug_assert_eq!(
            semantic_model_overlay.is_some(),
            overlay_measurement.is_some(),
            "a semantic-model overlay and its measurement are published atomically"
        );
        Self {
            summary_endpoint_admission: Default::default(),
            active_models,
            rust_cargo_graph,
            semantic_model_overlay,
            overlay_measurement,
            jdk_artifacts_by_configured_home,
            python_runtime,
        }
    }

    pub fn jvm_dependency_gaps(
        &self,
    ) -> Result<
        Vec<brokk_bifrost_semantic::analyzer::semantic_model::dependency::JvmDependencyGap>,
        super::FamilyOpen,
    > {
        super::overlay::active_jvm_dependency_gaps(&self.active_models)
    }

    /// Whether this immutable publication admitted any transfer component
    /// paths. Computed once during admission; this getter performs no lookup.
    pub fn summary_endpoint_projections_enabled(&self) -> bool {
        self.summary_endpoint_admission
            .as_ref()
            .is_some_and(|admission| admission.endpoint_projections_enabled())
    }

    pub fn summary_endpoint_projection_diagnostics(
        &self,
    ) -> &[super::endpoint_projections::SummaryEndpointProjectionDiagnostic] {
        self.summary_endpoint_admission
            .as_ref()
            .map_or(&[], |admission| admission.diagnostics())
    }

    pub fn admit_procedure_summary(
        &self,
        shard: &ActiveSemanticModelShard,
        record: &Arc<crate::analyzer::semantic_model::CompiledProcedureSummary>,
    ) -> Arc<crate::analyzer::semantic_model::CompiledProcedureSummary> {
        match self.summary_endpoint_admission.as_ref() {
            Some(admission) => admission.apply_record(shard, record),
            None => super::endpoint_projections::refuse_unvalidated_summary_record(shard, record),
        }
    }

    pub fn admit_procedure_summary_match(
        &self,
        matched: ProcedureSummaryMatch,
    ) -> ProcedureSummaryMatch {
        match self.summary_endpoint_admission.as_ref() {
            Some(admission) => admission.apply_match(matched),
            None => super::endpoint_projections::refuse_unvalidated_summary_match(matched),
        }
    }

    pub fn procedure_summaries_for_external_target(
        &self,
        target: &crate::analyzer::semantic::UnmaterializedExternalTarget,
    ) -> ProcedureSummaryMatch {
        self.admit_procedure_summary_match(
            self.active_models
                .procedure_summaries_for_external_target(target),
        )
    }

    pub fn procedure_summaries_for(
        &self,
        target: crate::analyzer::semantic_model::ProcedureSummaryTargetKey<'_>,
    ) -> ProcedureSummaryMatch {
        self.admit_procedure_summary_match(self.active_models.procedure_summaries_for(target))
    }

    /// Test-only late catalog read failures keep the same selected declaration
    /// overlay and model identity. The extra owner supplies no healthy rows;
    /// it does not replace the real reader or publish a different selection.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_with_question_reader(
        &self,
        reader: Arc<dyn crate::analyzer::store::model_catalog::CatalogRowReader + Send + Sync>,
    ) -> Arc<Self> {
        let mut snapshot = self.clone();
        snapshot.active_models = Arc::new(self.active_models.test_with_question_reader(reader));
        Arc::new(snapshot)
    }

    pub fn active_models(&self) -> &Arc<ResolvedActiveSemanticModels> {
        &self.active_models
    }

    pub fn rust_cargo_graph(&self) -> Option<&super::RustSelectedCargoGraph> {
        self.rust_cargo_graph.as_deref()
    }

    pub fn semantic_model_overlay(&self) -> Option<&Arc<SemanticModelOverlay>> {
        self.semantic_model_overlay.as_ref()
    }

    /// Whether this snapshot publishes a complete declaration surface for a
    /// language. Consumers that make absence claims must use this predicate
    /// rather than treating any overlay as complete coverage.
    pub fn publishes_complete_declaration_surface_for(&self, language: &str) -> bool {
        self.semantic_model_overlay
            .as_ref()
            .is_some_and(|overlay| overlay.publishes_complete_declaration_surface_for(language))
    }

    pub(crate) fn overlay(&self) -> Option<Arc<SemanticModelOverlay>> {
        self.semantic_model_overlay.as_ref().map(Arc::clone)
    }

    pub fn overlay_measurement(&self) -> Option<SemanticModelOverlayMeasurement> {
        self.overlay_measurement
    }

    #[doc(hidden)]
    pub fn python_runtime(
        &self,
    ) -> Option<&crate::analyzer::store::python_runtime::PythonRuntimeProviderPublication> {
        self.python_runtime.as_ref()
    }

    #[doc(hidden)]
    /// Exact prepared JDK artifact selected by a configured source binding in
    /// this same model publication. A missing home supplies no applicability
    /// proof, even if a model for its release version is globally active.
    pub fn jdk_artifact_for_home(
        &self,
        configured_home: &Path,
    ) -> Option<&SemanticModelActivationEvidence> {
        self.jdk_artifacts_by_configured_home.get(configured_home)
    }
}

#[derive(Debug)]
pub enum SemanticModelResolutionOutcome {
    Ready(ResolvedActiveSemanticModels),
    Incomplete {
        usable: Option<ResolvedActiveSemanticModels>,
        report: SemanticModelActivationReport,
    },
    Cancelled(SemanticModelActivationReport),
    Unavailable(SemanticModelActivationReport),
}

#[derive(Debug, Clone)]
pub enum SemanticModelRuntimeOutcome {
    Ready {
        active: Arc<ResolvedActiveSemanticModels>,
        snapshot: Arc<ActiveSemanticModelSnapshot>,
        lifecycle: SemanticModelRuntimeLifecycle,
    },
    Incomplete {
        usable: Option<Arc<ResolvedActiveSemanticModels>>,
        report: SemanticModelActivationReport,
    },
    Cancelled(SemanticModelActivationReport),
    Unavailable(SemanticModelActivationReport),
}

impl SemanticModelRuntimeOutcome {
    /// Convert an existing activation result into diagnostic suppression
    /// reasons. This method performs no activation, discovery, or package I/O.
    pub fn semantic_diagnostic_incomplete_reasons(
        &self,
    ) -> Vec<crate::analyzer::SemanticDiagnosticIncompleteReason> {
        use crate::analyzer::SemanticDiagnosticIncompleteReason;

        match self {
            Self::Ready { .. } => Vec::new(),
            Self::Incomplete { report, .. } => {
                vec![SemanticDiagnosticIncompleteReason::RuntimeUnavailable {
                    detail: format!("incomplete activation: {report:?}"),
                }]
            }
            Self::Cancelled(_) => vec![SemanticDiagnosticIncompleteReason::Cancelled],
            Self::Unavailable(report) => {
                vec![SemanticDiagnosticIncompleteReason::RuntimeUnavailable {
                    detail: format!("unavailable activation: {report:?}"),
                }]
            }
        }
    }
}

#[doc(hidden)]
pub fn degrade_pack_gap_absences(
    analyzer: &dyn IAnalyzer,
    mut report: crate::analyzer::SemanticDiagnosticReport,
) -> crate::analyzer::SemanticDiagnosticReport {
    use crate::analyzer::{SemanticDiagnosticDomain, SemanticDiagnosticIncompleteReason};

    let Some(overlay) = analyzer.semantic_model_overlay_read().published() else {
        return report;
    };
    report.degrade_absences(|domain| {
        let gap = match domain {
            SemanticDiagnosticDomain::Type { name }
            | SemanticDiagnosticDomain::Module { name }
            | SemanticDiagnosticDomain::Package { name } => overlay.gapped(name),
            SemanticDiagnosticDomain::MemberSurface { owner, member } => {
                overlay.gapped_member_surface(owner, member)
            }
            SemanticDiagnosticDomain::LexicalScope { .. } => None,
        }?;
        Some(SemanticDiagnosticIncompleteReason::PackExtractionGap {
            pack_id: gap.pack_id.clone(),
            declaration: gap.declaration.clone(),
        })
    });
    report
}

pub(crate) struct SemanticModelRuntimeCache {
    host_activation: std::sync::OnceLock<Arc<super::HostActivationContext>>,
    values: BudgetedValueCache<String, SharedAllocation<ResolvedActiveSemanticModels>>,
    budget: RetentionBudget,
    published: Mutex<PublishedSemanticModelState>,
    inventory_store: std::sync::OnceLock<std::sync::Weak<AnalyzerStore>>,
    graph_identities: Mutex<VecDeque<GraphIdentityMemo>>,
}

impl Drop for SemanticModelRuntimeCache {
    fn drop(&mut self) {
        // The shared budget retains cached activations independently of this
        // snapshot. Their request sources can own the store and budget, so
        // release this cache's entries before dropping its budget reference.
        // Live callers keep their own activation references until they finish.
        self.values.invalidate_all();
        self.values.region().run_pending_tasks();
    }
}

/// How many Cargo-graph identities one analyzer snapshot remembers. Each entry
/// is two short strings; the bound keeps a long-lived process from collecting
/// one per request it ever served.
const GRAPH_IDENTITY_MEMO_ENTRIES: usize = 8;

/// The computed facade identity of one Cargo activation, keyed by the inputs
/// that determine it, so a repeat activation can look up its snapshot-cache
/// key without resolving the catalog again. It holds a budget charge; an
/// entry the budget refuses is not kept.
struct GraphIdentityMemo {
    key: String,
    identity: String,
    _charge: AllocationCharge,
}

#[derive(Default)]
pub(crate) struct PublishedSemanticModelState {
    snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    models_selected: bool,
    dependency_evidence:
        HashMap<Language, Arc<crate::analyzer::semantic_model::DependencyDiscoveryEvidence>>,
    stale_dependency_ecosystems: Vec<crate::analyzer::DependencyPackEcosystem>,
    activated_dependency_ecosystems: Option<Vec<crate::analyzer::DependencyPackEcosystem>>,
    requires_whole_dependency_refresh: bool,
    captured_dependency_discoveries: HashMap<
        crate::analyzer::DependencyPackEcosystem,
        crate::analyzer::semantic_model::CapturedDependencyDiscovery,
    >,
    activation_request: Option<ActivationInputs>,
    dependency_request_evidence:
        HashMap<crate::analyzer::DependencyPackEcosystem, DependencyRequestEvidence>,
    prepared_dependency_evidence: Option<(Vec<SemanticModelActivationEvidence>, AllocationCharge)>,
    /// The finalized key for cross-generation carry, the optional pre-discovery
    /// key for same-generation reuse, the retained outcome and its charge.
    completed_dependency_activation: Option<(
        DependencyActivationKey,
        Option<DependencyActivationKey>,
        crate::analyzer::DependencyPackActivationOutcome,
        AllocationCharge,
    )>,
}

/// One atomic predecessor for an installed-stage pending substitution.
pub(crate) struct PendingDependencyPublication {
    pub(crate) snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    pub(crate) inputs: Option<ActivationInputs>,
    evidence: HashMap<Language, Arc<crate::analyzer::semantic_model::DependencyDiscoveryEvidence>>,
    pub(crate) contributions:
        HashMap<crate::analyzer::DependencyPackEcosystem, DependencyRequestEvidence>,
}

impl PendingDependencyPublication {
    pub(crate) fn can_substitute(&self, language: Language) -> bool {
        self.snapshot.is_some()
            && self.evidence.contains_key(&language)
            && self.contributions.iter().any(|(ecosystem, record)| {
                ecosystem.languages().contains(&language)
                    && self.inputs.as_ref().is_some_and(|inputs| {
                        record
                            .evidence
                            .iter()
                            .all(|entry| inputs.request.evidence.contains(entry))
                    })
            })
    }
}

/// In-process contribution and from-scratch publication eligibility.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DependencyRequestEvidence {
    pub evidence: Vec<SemanticModelActivationEvidence>,
    pub publication_eligible: bool,
}

/// Identity of a full activation retained by the generation's publication owner.
#[derive(PartialEq, Eq)]
pub(crate) struct DependencyActivationKey {
    config: crate::analyzer::AnalyzerConfig,
    ecosystems: Vec<crate::analyzer::DependencyPackEcosystem>,
    limits: super::DependencyPackLimits,
    request: String,
    graph: Option<String>,
    reexport_graph: String,
    catalog: super::SemanticPackCatalogCacheIdentity,
    persistence: Option<(String, usize)>,
}

impl DependencyActivationKey {
    pub(crate) fn new(
        config: &crate::analyzer::AnalyzerConfig,
        ecosystems: &[crate::analyzer::DependencyPackEcosystem],
        context: &crate::analyzer::DependencyPackWorkspaceContext<'_>,
        inputs: &ActivationInputs,
        cache: &SemanticModelRuntimeCache,
    ) -> Option<Self> {
        // Runtime provider verification reads are not in discovery's external
        // capture yet. Re-run verification on every configured-runtime request.
        if !config.python.runtime_environments.is_empty() {
            return None;
        }
        let request = runtime_request_key(&inputs.request).ok()?;
        let graph = inputs
            .rust_cargo_graph
            .as_ref()
            .map(|graph| cargo_graph_digest(graph, &inputs.request));
        let catalog = context.catalog.cache_identity().ok()?;
        let reexport_graph = match &graph {
            Some(graph) => cache.remembered_graph_identity(&graph_identity_memo_key(
                &request, "", &catalog, graph,
            ))?,
            None => String::new(),
        };
        Some(Self {
            config: config.clone(),
            ecosystems: {
                let mut selected = ecosystems.to_vec();
                selected.extend(inputs.request.evidence.iter().filter_map(|entry| {
                    crate::analyzer::DependencyPackEcosystem::from_label(&entry.ecosystem)
                }));
                selected.extend(
                    inputs
                        .request
                        .approximate_standard_libraries
                        .iter()
                        .filter_map(|entry| {
                            crate::analyzer::DependencyPackEcosystem::from_label(&entry.ecosystem)
                        }),
                );
                selected.sort();
                selected.dedup();
                selected
            },
            limits: context.limits,
            request,
            graph,
            reexport_graph,
            catalog,
            persistence: context.persistence.map(|persistence| {
                (
                    persistence.scope_id.to_owned(),
                    std::ptr::from_ref(persistence.store) as usize,
                )
            }),
        })
    }
}

fn dependency_activation_key_retained_bytes(key: &DependencyActivationKey) -> usize {
    std::mem::size_of::<DependencyActivationKey>()
        + format!("{:?}", key.config).len().saturating_mul(8)
        + brokk_bifrost_core::hash::allocated_vec_slot_bytes(&key.ecosystems)
        + brokk_bifrost_core::allocation_size::allocation_size(key.request.capacity())
        + brokk_bifrost_core::allocation_size::allocation_size(key.reexport_graph.capacity())
        + key.graph.as_ref().map_or(0, |graph| {
            brokk_bifrost_core::allocation_size::allocation_size(graph.capacity())
        })
        + key.persistence.as_ref().map_or(0, |(scope, _)| {
            brokk_bifrost_core::allocation_size::allocation_size(scope.capacity())
        })
}

/// Inputs retained together across partial refresh and publication.
#[derive(Clone, Debug)]
pub struct ActivationInputs {
    pub preparation_failures: Vec<
        brokk_bifrost_semantic::analyzer::semantic_model::dependency::RecordedPreparationFailure,
    >,
    pub request: SemanticModelActivationRequest,
    pub rust_cargo_graph: Option<super::RustSelectedCargoGraph>,
}

fn three_copy_graph_retained_bytes(overlay_bytes: u64, graph_copy_bytes: usize) -> u64 {
    overlay_bytes.saturating_add(
        u64::try_from(graph_copy_bytes)
            .unwrap_or(u64::MAX)
            .saturating_mul(2),
    )
}

impl ActivationInputs {
    pub(crate) fn finalize_request(&mut self) {
        self.request.evidence.sort();
        self.request.evidence.dedup();
        self.request.approximate_standard_libraries.sort();
        self.request.approximate_standard_libraries.dedup();
        if let Some(graph) = &mut self.rust_cargo_graph {
            graph.retain_evidence(&self.request.evidence);
        }
        debug_assert!(
            self.rust_cargo_graph
                .as_ref()
                .is_none_or(|graph| graph.validate_evidence(&self.request.evidence).is_ok())
        );
    }
}

impl From<SemanticModelActivationRequest> for ActivationInputs {
    fn from(request: SemanticModelActivationRequest) -> Self {
        Self {
            request,
            rust_cargo_graph: None,
            preparation_failures: Vec::new(),
        }
    }
}

#[cfg(test)]
mod carry_request_tests {
    use super::*;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12435: invalidating the only selected ecosystem reported no models selected"
    )]
    fn stale_ecosystem_is_removed_from_carried_request() {
        let evidence =
            |ecosystem: crate::analyzer::DependencyPackEcosystem| SemanticModelActivationEvidence {
                language: ecosystem.languages()[0].config_label().to_owned(),
                ecosystem: ecosystem.label().to_owned(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                production_input_digest: None,
                verified_raw_artifacts: Vec::new(),
            };
        let request = SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            bifrost_version: Version::new(0, 15, 1),
            approximate_standard_libraries: [
                crate::analyzer::DependencyPackEcosystem::Cargo,
                crate::analyzer::DependencyPackEcosystem::Npm,
            ]
            .into_iter()
            .map(|ecosystem| ApproximateSemanticModelExpectation { reasons: brokk_bifrost_semantic::analyzer::semantic_model::ApproximationReasons::only(brokk_bifrost_semantic::analyzer::semantic_model::ApproximationReason::TargetUnknown),
                toolchain: None,
                language: ecosystem.languages()[0].config_label().to_owned(),
                ecosystem: ecosystem.label().to_owned(),
                selection: ApproximateStandardLibrarySelection::Pack(format!(
                    "{}-stdlib",
                    ecosystem.label()
                )),
            })
            .collect(),
            evidence: [
                crate::analyzer::DependencyPackEcosystem::Cargo,
                crate::analyzer::DependencyPackEcosystem::Npm,
            ]
            .into_iter()
            .map(evidence)
            .collect(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let cache = SemanticModelRuntimeCache::default();
        cache.install_carried_dependency_evidence(
            false,
            Vec::new(),
            vec![crate::analyzer::DependencyPackEcosystem::Cargo],
            Some(request.into()),
            Some(vec![
                crate::analyzer::DependencyPackEcosystem::Cargo,
                crate::analyzer::DependencyPackEcosystem::Npm,
            ]),
            Default::default(),
        );
        let carried = cache.carried_activation_request().unwrap();
        assert_eq!(carried.evidence.len(), 1);
        assert_eq!(
            carried.evidence[0].ecosystem,
            crate::analyzer::DependencyPackEcosystem::Npm.label()
        );
        assert_eq!(carried.approximate_standard_libraries.len(), 1);
        assert_eq!(
            carried.approximate_standard_libraries[0].ecosystem,
            crate::analyzer::DependencyPackEcosystem::Npm.label()
        );
        let emptied = SemanticModelRuntimeCache::default();
        emptied.install_carried_dependency_evidence(
            false,
            Vec::new(),
            vec![crate::analyzer::DependencyPackEcosystem::Npm],
            Some(carried.into()),
            Some(vec![crate::analyzer::DependencyPackEcosystem::Npm]),
            Default::default(),
        );
        assert!(
            emptied
                .carried_activation_request()
                .unwrap()
                .evidence
                .is_empty()
        );
        assert!(matches!(
            emptied.overlay_read(None),
            SemanticModelOverlayRead::Pending(_)
        ));
        let next = SemanticModelRuntimeCache::default();
        next.install_carried_dependency_evidence(
            emptied.models_selected(),
            Vec::new(),
            Vec::new(),
            emptied.carried_activation_inputs(),
            Some(Vec::new()),
            emptied.dependency_request_evidence(),
        );
        assert!(matches!(
            next.overlay_read(None),
            SemanticModelOverlayRead::Pending(_)
        ));
    }

    #[test]
    fn verified_partial_refresh_carries_cargo_graph() {
        let request = SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            bifrost_version: Version::new(0, 15, 1),
            approximate_standard_libraries: Vec::new(),
            evidence: Vec::new(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let graph = super::super::RustSelectedCargoGraph::from_cargo_resolve(
            super::super::CargoResolveView::from_rows(Vec::new(), Vec::new()),
        )
        .unwrap();
        let cache = SemanticModelRuntimeCache::default();
        cache.install_carried_dependency_evidence(
            false,
            Vec::new(),
            Vec::new(),
            Some(ActivationInputs {
                request,
                rust_cargo_graph: Some(graph.clone()),
                preparation_failures: Vec::new(),
            }),
            Some(Vec::new()),
            Default::default(),
        );
        assert_eq!(
            cache.carried_activation_inputs().unwrap().rust_cargo_graph,
            Some(graph)
        );
    }
}

#[derive(Clone, Copy)]
pub struct SemanticModelActivationPersistence<'a> {
    pub scope_id: &'a str,
    pub store: &'a AnalyzerStore,
}

#[cfg(any(test, feature = "test-support"))]
impl Default for SemanticModelRuntimeCache {
    fn default() -> Self {
        Self::new(&RetentionBudget::for_tests())
    }
}

impl SemanticModelRuntimeCache {
    pub(crate) fn host_activation(&self) -> Option<Arc<super::HostActivationContext>> {
        self.host_activation.get().cloned()
    }
    pub(crate) fn bind_host_activation(
        &self,
        host: Arc<super::HostActivationContext>,
    ) -> Result<(), String> {
        let wanted = host.identity();
        match self.host_activation.set(host) {
            Ok(()) => Ok(()),
            Err(_) if self.host_activation.get().is_some_and(|pinned| pinned.identity() == wanted) => Ok(()),
            Err(_) => Err("analyzer activation context is immutable; construct a new analyzer for another approval authority".into()),
        }
    }

    pub(crate) fn clear_dependency_activation(&self) {
        self.published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .completed_dependency_activation = None;
    }

    /// Reuse the complete activation retained on this analyzer generation when
    /// the pre-discovery inputs, every recorded external read and the published
    /// snapshot still agree. Discovery may then return exactly the retained
    /// result, so it does not need to run again.
    pub(crate) fn reuse_dependency_activation(
        &self,
        key: Option<&DependencyActivationKey>,
        cancellation: &CancellationToken,
        analyzer: &dyn IAnalyzer,
        catalog: &SemanticPackCatalog,
        ecosystems: &[crate::analyzer::DependencyPackEcosystem],
        finish: impl FnOnce(
            crate::analyzer::DependencyPackActivationOutcome,
        ) -> crate::analyzer::DependencyPackActivationOutcome,
    ) -> Option<crate::analyzer::DependencyPackActivationOutcome> {
        let published = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        let (_, previous, outcome, _) = published.completed_dependency_activation.as_ref()?;
        let previous = previous.as_ref()?;
        // Project membership and project reads belong to this immutable analyzer
        // generation. Same-generation reuse therefore revalidates only the
        // external reads and the inputs keyed above.
        if cancellation.is_cancelled()
            || key != Some(previous)
            || !outcome
                .ecosystems
                .iter()
                .map(|outcome| outcome.ecosystem)
                .eq(ecosystems.iter().copied())
            || !published.captured_dependency_discoveries.is_empty()
            || !outcome.complete()
            || !outcome.ecosystems.iter().all(|ecosystem| {
                ecosystem.ecosystem.languages().iter().all(|language| {
                    published
                        .dependency_evidence
                        .get(language)
                        .is_some_and(|evidence| {
                            crate::analyzer::workspace::dependency_external_reads_unchanged(
                                evidence,
                            )
                        })
                })
            })
            || !matches!(&outcome.runtime, Some(SemanticModelRuntimeOutcome::Ready { snapshot, .. })
                if published.snapshot.as_ref().is_some_and(|current| Arc::ptr_eq(current, snapshot)))
        {
            return None;
        }
        if published
            .snapshot
            .as_ref()?
            .active_models()
            .report
            .publication_diagnostics
            .lock()
            .expect("publication diagnostics lock")
            .is_empty()
        {
            for evidence in published.dependency_evidence.values() {
                analyzer.record_read_receipt(&evidence.project_read_keys);
            }
            // The publication mutex stays held from proof through republication.
            // Catalog methods used by finish take their own writer locks, so
            // validate on both sides instead of recursively acquiring them.
            if !catalog
                .with_cache_identity(|identity| identity == previous.catalog)
                .ok()?
            {
                return None;
            }
            let outcome = finish(outcome.clone());
            let (_, expected) = catalog.activation_publication_identity()?;
            catalog
                .with_cache_identity(|identity| (Some(identity) == expected).then_some(outcome))
                .ok()?
        } else {
            None
        }
    }

    pub(crate) fn prepared_dependency_evidence(
        &self,
    ) -> Option<Vec<SemanticModelActivationEvidence>> {
        self.published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .prepared_dependency_evidence
            .as_ref()
            .map(|(evidence, _)| evidence.clone())
    }

    pub(crate) fn record_prepared_dependency_evidence(
        &self,
        mut evidence: Vec<SemanticModelActivationEvidence>,
    ) {
        evidence.sort();
        evidence.dedup();
        let charge = AllocationCharge::acquire(
            &self.budget,
            std::mem::size_of_val(&evidence) + format!("{evidence:?}").len().saturating_mul(8),
        );
        self.published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .prepared_dependency_evidence = charge.is_charged().then_some((evidence, charge));
    }

    pub(crate) fn carry_prepared_dependency_evidence_to(&self, next: &Self) {
        if let Some(mut evidence) = self.prepared_dependency_evidence() {
            let stale = next.stale_dependency_ecosystems();
            evidence.retain(|entry| {
                !stale
                    .iter()
                    .any(|ecosystem| entry.ecosystem == ecosystem.label())
            });
            next.record_prepared_dependency_evidence(evidence);
        }
    }

    /// Carry only when model inputs and every affected source-locator binding
    /// still match. Uncertified paths and incomplete reads refuse carry.
    pub(crate) fn publication_files_unchanged(
        &self,
        changed: &brokk_bifrost_core::analyzer::changed_paths::ChangedPaths,
        analyzer: &dyn crate::analyzer::IAnalyzer,
    ) -> bool {
        let published = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        let Some(snapshot) = &published.snapshot else {
            return false;
        };
        !changed.touches(Path::new(super::WORKSPACE_SEMANTIC_MODEL_DIRECTORY))
            && snapshot
                .semantic_model_overlay()
                .is_none_or(|overlay| overlay.source_bindings_unchanged(analyzer, changed))
    }

    pub(crate) fn republish_matching_activation(
        &self,
        next: &Self,
        key: Option<DependencyActivationKey>,
        inputs: ActivationInputs,
    ) {
        let Some(key) = key else { return };
        let previous = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        let Some((old_key, _, outcome, charge)) = &previous.completed_dependency_activation else {
            return;
        };
        if old_key != &key {
            return;
        }
        let Some(snapshot) = &previous.snapshot else {
            return;
        };
        if !matches!(&outcome.runtime, Some(SemanticModelRuntimeOutcome::Ready { snapshot: active, .. }) if Arc::ptr_eq(snapshot, active))
        {
            return;
        }
        let charge = AllocationCharge::acquire(
            &next.budget,
            charge
                .bytes()
                .try_into()
                .expect("retained metadata fits usize"),
        );
        if !charge.is_charged() {
            return;
        }
        if let Some(graph) = &key.graph {
            next.remember_graph_identity(
                graph_identity_memo_key(&key.request, "", &key.catalog, graph),
                key.reexport_graph.clone(),
            );
        }
        let mut published = next
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        published.snapshot = Some(Arc::clone(snapshot));
        published.models_selected = previous.models_selected;
        published.activation_request = Some(inputs);
        published.completed_dependency_activation = Some((key, None, outcome.clone(), charge));
    }

    /// Keep the reuse proof and its publication under the same mutex.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn retain_dependency_activation(
        &self,
        same_generation_key: Option<DependencyActivationKey>,
        finalized_key: Option<DependencyActivationKey>,
        outcome: &crate::analyzer::DependencyPackActivationOutcome,
        catalog: &SemanticPackCatalog,
        publication_catalog: Option<&super::SemanticPackCatalogCacheIdentity>,
    ) {
        if !matches!(
            &outcome.runtime,
            Some(SemanticModelRuntimeOutcome::Ready { .. })
        ) || outcome.ecosystems.iter().any(|ecosystem| {
            ecosystem.discovery.cancelled
                || ecosystem
                    .preparation
                    .as_ref()
                    .is_some_and(|preparation| preparation.cancelled)
        }) {
            return;
        }
        let Some(finalized_key) = finalized_key else {
            return;
        };
        let (initial, expected) = match catalog.activation_publication_identity() {
            Some(receipt) => receipt,
            None => {
                let Some(identity) = publication_catalog else {
                    return;
                };
                (*identity, Some(*identity))
            }
        };
        let Some(identity) = expected else {
            return;
        };
        if finalized_key.catalog != identity {
            return;
        }
        let same_generation_key = if outcome.complete() {
            same_generation_key.and_then(|mut key| {
                if key.catalog != initial {
                    return None;
                }
                key.catalog = identity;
                Some(key)
            })
        } else {
            None
        };
        // Estimate the owned metadata as the existing model/receipt caches do:
        // Debug expands strings and nested collections. Allow eight bytes per
        // rendered byte for inline elements of short-string/path collections.
        // Runtime Ready's Arc backings are already charged by the publication
        // and are not copied.
        let retained_bytes = dependency_activation_key_retained_bytes(&finalized_key)
            + same_generation_key
                .as_ref()
                .map_or(0, dependency_activation_key_retained_bytes)
            + std::mem::size_of_val(outcome)
            + brokk_bifrost_core::allocation_size::allocation_size(std::mem::size_of_val(
                outcome.ecosystems.as_slice(),
            ))
            + format!("{:?}", outcome.ecosystems).len().saturating_mul(8);
        let charge = AllocationCharge::acquire(&self.budget, retained_bytes);
        if !charge.is_charged() {
            return;
        }
        let mut published = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        let Ok(()) = catalog.with_cache_identity(|identity| {
            if finalized_key.catalog == identity {
                published.completed_dependency_activation =
                    Some((finalized_key, same_generation_key, outcome.clone(), charge));
            }
        }) else {
            return;
        };
    }

    pub(crate) fn models_selected(&self) -> bool {
        self.published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .models_selected
    }

    pub(crate) fn install_carried_dependency_evidence(
        &self,
        models_selected: bool,
        evidence: Vec<(
            Language,
            Arc<crate::analyzer::semantic_model::DependencyDiscoveryEvidence>,
        )>,
        mut stale: Vec<crate::analyzer::DependencyPackEcosystem>,
        old_request: Option<ActivationInputs>,
        activated: Option<Vec<crate::analyzer::DependencyPackEcosystem>>,
        request_evidence: HashMap<
            crate::analyzer::DependencyPackEcosystem,
            DependencyRequestEvidence,
        >,
    ) {
        let mut published = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        for (language, value) in evidence {
            published
                .dependency_evidence
                .entry(language)
                .or_insert(value);
        }
        stale.retain(|ecosystem| {
            !ecosystem
                .languages()
                .iter()
                .all(|language| published.dependency_evidence.contains_key(language))
        });
        for (ecosystem, evidence) in request_evidence {
            if !stale.contains(&ecosystem)
                && ecosystem
                    .languages()
                    .iter()
                    .all(|language| published.dependency_evidence.contains_key(language))
            {
                published
                    .dependency_request_evidence
                    .entry(ecosystem)
                    .or_insert(evidence);
            }
        }
        // Selection survives invalidation; only reusable evidence is filtered.
        let models_selected = models_selected
            || old_request
                .as_ref()
                .is_some_and(|inputs| request_selects_semantic_models(&inputs.request));
        let carried_request = old_request.map(|mut inputs| {
            inputs.preparation_failures.retain(|failure| {
                !stale.iter().any(|ecosystem| {
                    ecosystem.languages().iter().any(|language| {
                        language.config_label() == failure.dependency.evidence.language
                    })
                })
            });
            inputs.request.evidence.retain(|entry| {
                !stale
                    .iter()
                    .any(|ecosystem| ecosystem.label() == entry.ecosystem)
            });
            inputs
                .request
                .approximate_standard_libraries
                .retain(|entry| {
                    !stale
                        .iter()
                        .any(|ecosystem| ecosystem.label() == entry.ecosystem)
                });
            if stale.contains(&crate::analyzer::DependencyPackEcosystem::Cargo) {
                inputs.rust_cargo_graph = None;
            }
            inputs
        });
        if published.activation_request.is_none() {
            published.models_selected = models_selected;
            published.activation_request = carried_request;
        }
        published.stale_dependency_ecosystems = stale;
        published.requires_whole_dependency_refresh = activated.is_none();
        published.activated_dependency_ecosystems = activated;
    }

    pub(crate) fn carried_activation_request(&self) -> Option<SemanticModelActivationRequest> {
        self.published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .activation_request
            .clone()
            .map(|inputs| inputs.request)
    }

    pub(crate) fn capture_pending_publication(&self) -> PendingDependencyPublication {
        let published = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        PendingDependencyPublication {
            snapshot: published.snapshot.clone(),
            inputs: published.activation_request.clone(),
            evidence: published.dependency_evidence.clone(),
            contributions: published.dependency_request_evidence.clone(),
        }
    }

    pub(crate) fn dependency_request_evidence(
        &self,
    ) -> HashMap<crate::analyzer::DependencyPackEcosystem, DependencyRequestEvidence> {
        self.published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .dependency_request_evidence
            .clone()
    }

    pub(crate) fn carried_activation_inputs(&self) -> Option<ActivationInputs> {
        self.published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .activation_request
            .clone()
    }

    pub(crate) fn store_captured_dependency_discovery(
        &self,
        ecosystem: crate::analyzer::DependencyPackEcosystem,
        discovery: crate::analyzer::semantic_model::CapturedDependencyDiscovery,
    ) {
        assert!(!discovery.outcome.cancelled);
        self.published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .captured_dependency_discoveries
            .insert(ecosystem, discovery);
    }

    /// Whether a finished, uncancelled discovery of this ecosystem is waiting
    /// for the activation stage to take it.
    pub(crate) fn captured_dependency_discovery_is_complete(
        &self,
        ecosystem: crate::analyzer::DependencyPackEcosystem,
    ) -> bool {
        self.published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .captured_dependency_discoveries
            .get(&ecosystem)
            .is_some_and(|captured| captured.outcome.complete && !captured.outcome.cancelled)
    }

    pub(crate) fn take_captured_dependency_discovery(
        &self,
        ecosystem: crate::analyzer::DependencyPackEcosystem,
    ) -> Option<crate::analyzer::semantic_model::CapturedDependencyDiscovery> {
        self.published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .captured_dependency_discoveries
            .remove(&ecosystem)
    }

    pub(crate) fn activated_dependency_ecosystems(
        &self,
    ) -> Option<Vec<crate::analyzer::DependencyPackEcosystem>> {
        self.published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .activated_dependency_ecosystems
            .clone()
    }

    pub(crate) fn requires_whole_dependency_refresh(&self) -> bool {
        self.published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .requires_whole_dependency_refresh
    }

    pub(crate) fn stale_dependency_ecosystems(
        &self,
    ) -> Vec<crate::analyzer::DependencyPackEcosystem> {
        self.published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .stale_dependency_ecosystems
            .clone()
    }

    pub(crate) fn new(budget: &RetentionBudget) -> Self {
        Self::new_with_host_binding(budget, std::sync::OnceLock::new())
    }

    fn new_with_host_binding(
        budget: &RetentionBudget,
        host_activation: std::sync::OnceLock<Arc<super::HostActivationContext>>,
    ) -> Self {
        Self {
            host_activation,
            values: BudgetedValueCache::new(budget.region("semantic_models", None)),
            budget: budget.clone(),
            published: Mutex::new(PublishedSemanticModelState::default()),
            inventory_store: std::sync::OnceLock::new(),
            graph_identities: Mutex::new(VecDeque::new()),
        }
    }

    /// Publications are generation-local; immutable host authority belongs
    /// to the entire analyzer lifetime, including a generation with no models.
    pub(crate) fn new_for_updated_snapshot(&self, budget: &RetentionBudget) -> Self {
        Self::new_with_host_binding(budget, self.host_activation.clone())
    }

    fn remembered_graph_identity(&self, key: &str) -> Option<String> {
        self.graph_identities
            .lock()
            .expect("graph identity memo mutex poisoned")
            .iter()
            .find(|entry| entry.key == key)
            .map(|entry| entry.identity.clone())
    }

    fn remember_graph_identity(&self, key: String, identity: String) {
        let charge = AllocationCharge::acquire(
            &self.budget,
            std::mem::size_of::<GraphIdentityMemo>()
                + brokk_bifrost_core::allocation_size::allocation_size(key.capacity())
                + brokk_bifrost_core::allocation_size::allocation_size(identity.capacity()),
        );
        if !charge.is_charged() {
            return;
        }
        let mut memo = self
            .graph_identities
            .lock()
            .expect("graph identity memo mutex poisoned");
        if memo.iter().any(|entry| entry.key == key) {
            return;
        }
        if memo.len() == GRAPH_IDENTITY_MEMO_ENTRIES {
            memo.pop_front();
        }
        memo.push_back(GraphIdentityMemo {
            key,
            identity,
            _charge: charge,
        });
    }

    pub(crate) fn bind_inventory_store(&self, store: &Arc<AnalyzerStore>) {
        let bound = self.inventory_store.get_or_init(|| Arc::downgrade(store));
        assert!(
            std::sync::Weak::ptr_eq(bound, &Arc::downgrade(store)),
            "one analyzer snapshot cache belongs to one native store"
        );
    }

    pub(crate) fn native_inventory_store(&self) -> Option<Arc<AnalyzerStore>> {
        self.inventory_store
            .get()
            .and_then(std::sync::Weak::upgrade)
    }

    /// Retain discovery evidence for trace tests without invoking discovery
    /// from the query path.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn retain_dependency_discovery_evidence(
        &self,
        languages: &[Language],
        evidence: crate::analyzer::semantic_model::DependencyDiscoveryEvidence,
    ) {
        let evidence = Arc::new(evidence);
        let mut published = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        for language in languages {
            published
                .dependency_evidence
                .insert(*language, Arc::clone(&evidence));
        }
    }
    pub(crate) fn dependency_discovery_evidence(
        &self,
        language: Language,
    ) -> Option<Arc<crate::analyzer::semantic_model::DependencyDiscoveryEvidence>> {
        self.published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .dependency_evidence
            .get(&language)
            .cloned()
    }

    /// The retained status of every ecosystem whose published discovery
    /// evidence carries one.
    pub(crate) fn retained_ecosystem_statuses(
        &self,
    ) -> Vec<(
        crate::analyzer::DependencyPackEcosystem,
        Arc<crate::analyzer::semantic_model::RetainedEcosystemStatus>,
    )> {
        let published = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        crate::analyzer::DependencyPackEcosystem::ALL
            .iter()
            .filter_map(|ecosystem| {
                let evidence = published
                    .dependency_evidence
                    .get(ecosystem.languages().first()?)?;
                Some((*ecosystem, evidence.retained_status.clone()?))
            })
            .collect()
    }

    pub(crate) fn invalidate_dependency_pack_state(&self, languages: &[Language]) -> bool {
        let mut published = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        let mut evidence_changed = false;
        for language in languages {
            evidence_changed |= published.dependency_evidence.remove(language).is_some();
        }
        published
            .dependency_request_evidence
            .retain(|ecosystem, _| {
                !ecosystem
                    .languages()
                    .iter()
                    .any(|language| languages.contains(language))
            });
        if let Some(inputs) = &mut published.activation_request {
            inputs.preparation_failures.retain(|failure| {
                !languages
                    .iter()
                    .any(|language| language.config_label() == failure.dependency.evidence.language)
            });
        }
        let snapshot_changed = published.snapshot.take().is_some();
        evidence_changed || snapshot_changed
    }

    pub(crate) fn snapshot(&self) -> Option<Arc<ActiveSemanticModelSnapshot>> {
        self.published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .snapshot
            .as_ref()
            .map(Arc::clone)
    }

    pub(crate) fn overlay_read(
        &self,
        query_override: Option<Option<Arc<SemanticModelOverlay>>>,
    ) -> SemanticModelOverlayRead {
        let published = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        let overlay = query_override.unwrap_or_else(|| {
            published
                .snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.overlay())
        });
        if let Some(overlay) = overlay {
            SemanticModelOverlayRead::Published(overlay)
        } else if published.models_selected {
            SemanticModelOverlayRead::Pending(
                crate::analyzer::QueryReadIncomplete::SemanticModelsPending,
            )
        } else {
            SemanticModelOverlayRead::NotSelected
        }
    }

    fn publish_overlay(
        &self,
        analyzer: &dyn IAnalyzer,
        activation: OverlayActivation<'_>,
        active: &Arc<ResolvedActiveSemanticModels>,
        dependency_evidence: Option<&[DependencyEvidencePublication]>,
        runtime_artifacts: RuntimeArtifactPublication<'_>,
        cancellation: &CancellationToken,
    ) -> Result<Arc<ActiveSemanticModelSnapshot>, SemanticModelOverlayBuildError> {
        let OverlayActivation {
            request,
            rust_cargo_graph,
        } = activation;
        let RuntimeArtifactPublication {
            publication_kind,
            pending_languages,
            activated_ecosystems,
            pending_previous,
            jdk_artifacts_by_configured_home,
            python_runtime,
            withdrawn_dependency_languages,
            dependency_request_evidence,
        } = runtime_artifacts;
        let _scope = crate::profiling::scope("semantic_pack.publish_overlay");
        {
            let mut published = self
                .published
                .lock()
                .expect("semantic-model publication mutex poisoned");
            // Every publication invalidates the retained Full activation. The Full
            // activation that owns this publication may retain its result afterward.
            published.completed_dependency_activation = None;
            if dependency_request_evidence.is_none()
                && withdrawn_dependency_languages.is_empty()
                && dependency_evidence.is_none()
                && jdk_artifacts_by_configured_home.is_none()
                && python_runtime.is_none()
                && let Some(snapshot) = published.snapshot.as_ref()
                && Arc::ptr_eq(snapshot.active_models(), active)
                && snapshot.rust_cargo_graph() == rust_cargo_graph
            {
                let snapshot = Arc::clone(snapshot);
                published.activation_request = Some(ActivationInputs {
                    request: request.clone(),
                    rust_cargo_graph: rust_cargo_graph.cloned(),
                    preparation_failures: active.preparation_failures.clone(),
                });
                return Ok(snapshot);
            }
        }
        let overlay_started = Instant::now();
        let mut overlay = SemanticModelOverlay::build_with_rust_graph(
            analyzer,
            active,
            rust_cargo_graph,
            cancellation,
            request.limits.max_retained_bytes,
            &self.budget,
        )?;
        // Library callers have no executor: their first request fills search
        // inputs. The service warms the final snapshot after publishing Ready.
        let summary_endpoint_admission =
            super::endpoint_projections::SummaryEndpointAdmission::build(
                &overlay,
                active,
                cancellation,
            )?;
        let summary_endpoint_admission =
            (!summary_endpoint_admission.is_empty()).then(|| Arc::new(summary_endpoint_admission));
        // The overlay owns one graph copy; publication retains two more in
        // the snapshot and carried activation inputs.
        let graph_copy_bytes =
            rust_cargo_graph.map_or(0, super::RustSelectedCargoGraph::retained_bytes_lower_bound);
        let retained_bytes =
            three_copy_graph_retained_bytes(overlay.retained_bytes_lower_bound(), graph_copy_bytes)
                .saturating_add(summary_endpoint_admission.as_ref().map_or(0, |admission| {
                    admission
                        .retained_bytes()
                        .saturating_add(2 * std::mem::size_of::<usize>() as u64)
                }));
        if active.retained_bytes().saturating_add(retained_bytes)
            > request.limits.max_retained_bytes
        {
            return Err(SemanticModelOverlayBuildError::RetainedBytesExceeded(
                crate::analyzer::semantic_model::SemanticModelOverlayBudgetExceeded {
                    loaded_records: active.activation_report().loaded_records,
                    models_retained_bytes: active.retained_bytes(),
                    overlay_working_bytes: retained_bytes,
                    combined_budget_bytes: request.limits.max_retained_bytes,
                },
            ));
        }
        // The published snapshot keeps the overlay across requests as part of
        // the analyzer's selected state, so it owns a required charge too.
        overlay.charge = AllocationCharge::acquire_required(
            &self.budget,
            retained_bytes.try_into().unwrap_or(usize::MAX),
        );
        let overlay = Arc::new(overlay);
        let mut published = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        if dependency_request_evidence.is_none()
            && withdrawn_dependency_languages.is_empty()
            && dependency_evidence.is_none()
            && jdk_artifacts_by_configured_home.is_none()
            && python_runtime.is_none()
            && let Some(current) = published.snapshot.as_ref()
            && Arc::ptr_eq(current.active_models(), active)
            && current.rust_cargo_graph() == rust_cargo_graph
        {
            let current = Arc::clone(current);
            published.activation_request = Some(ActivationInputs {
                request: request.clone(),
                rust_cargo_graph: rust_cargo_graph.cloned(),
                preparation_failures: active.preparation_failures.clone(),
            });
            return Ok(current);
        }
        if let Some(previous) = pending_previous
            && !pending_languages.is_empty()
            && !published
                .snapshot
                .as_ref()
                .zip(previous.snapshot.as_ref())
                .is_some_and(|(current, prior)| Arc::ptr_eq(current, prior))
        {
            return Err(SemanticModelOverlayBuildError::Cancelled);
        }
        if let Some(evidence) = dependency_request_evidence {
            published.dependency_request_evidence = evidence.clone();
        }
        if publication_kind == Some(crate::analyzer::workspace::DependencyPackPublicationKind::Full)
        {
            published
                .dependency_evidence
                .retain(|language, _| pending_languages.contains(language));
        }
        if let Some(kind) = publication_kind {
            match kind {
                crate::analyzer::workspace::DependencyPackPublicationKind::Full => {
                    published.activated_dependency_ecosystems = Some(activated_ecosystems.to_vec());
                    published.stale_dependency_ecosystems.clear();
                    published.requires_whole_dependency_refresh = false;
                }
                crate::analyzer::workspace::DependencyPackPublicationKind::Subset => {
                    if let Some(activated) = &mut published.activated_dependency_ecosystems {
                        for ecosystem in activated_ecosystems {
                            if !activated.contains(ecosystem) {
                                activated.push(*ecosystem);
                            }
                        }
                    }
                    published
                        .stale_dependency_ecosystems
                        .retain(|ecosystem| !activated_ecosystems.contains(ecosystem));
                }
            }
        }
        for language in withdrawn_dependency_languages {
            published.dependency_evidence.remove(language);
        }
        if let Some(evidence) = dependency_evidence {
            for (languages, value) in evidence {
                let value = Arc::new(value.clone());
                for language in languages {
                    published
                        .dependency_evidence
                        .insert(*language, Arc::clone(&value));
                }
            }
        }
        let overlay_measurement = SemanticModelOverlayMeasurement {
            publication_nanos: overlay_started
                .elapsed()
                .as_nanos()
                .try_into()
                .unwrap_or(u64::MAX),
            retained_bytes,
        };
        let jdk_artifacts_by_configured_home = jdk_artifacts_by_configured_home
            .map(|artifacts| Arc::new(artifacts.clone()))
            .or_else(|| {
                if publication_kind
                    == Some(crate::analyzer::workspace::DependencyPackPublicationKind::Full)
                    && !pending_languages.contains(&Language::Java)
                {
                    return None;
                }
                published
                    .snapshot
                    .as_ref()
                    .map(|snapshot| Arc::clone(&snapshot.jdk_artifacts_by_configured_home))
            })
            .unwrap_or_default();
        let omit_overlay = dependency_request_evidence.is_some()
            && !published
                .dependency_request_evidence
                .values()
                .any(|record| record.publication_eligible)
            && request.evidence.is_empty()
            && request.approximate_standard_libraries.is_empty();
        let mut snapshot = ActiveSemanticModelSnapshot::new(
            Arc::clone(active),
            rust_cargo_graph.cloned().map(Arc::new),
            (!omit_overlay).then_some(overlay),
            (!omit_overlay).then_some(overlay_measurement),
            jdk_artifacts_by_configured_home,
            python_runtime.cloned().or_else(|| {
                if publication_kind
                    == Some(crate::analyzer::workspace::DependencyPackPublicationKind::Full)
                    && !pending_languages.contains(&Language::Python)
                {
                    return None;
                }
                published
                    .snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.python_runtime.clone())
            }),
        );
        snapshot.summary_endpoint_admission = summary_endpoint_admission;
        let snapshot = Arc::new(snapshot);
        published.snapshot = Some(Arc::clone(&snapshot));
        published.activation_request = Some(ActivationInputs {
            request: request.clone(),
            rust_cargo_graph: rust_cargo_graph.cloned(),
            preparation_failures: active.preparation_failures.clone(),
        });
        Ok(snapshot)
    }
}

#[derive(Debug)]
pub(crate) struct CandidateSelection {
    active: ActiveSemanticModelShard,
    semantic_sha256: String,
    payload_kind: PayloadKind,
    evidence_rank: EvidenceRank,
    /// The version requirements this candidate satisfied, so the activation
    /// explanation can name them (#3465).
    matched_requirements: Vec<MatchedVersionRequirement>,
    source_rank: u8,
    /// The exact artifact extraction this candidate's extraction defers to
    /// (#9474), so the activation explanation can name it.
    extraction_deferred_to: Option<(CatalogPackSourceKind, String)>,
}

pub fn resolve_active_semantic_models(
    catalog: &SemanticPackCatalog,
    request: &SemanticModelActivationRequest,
    cancellation: &CancellationToken,
) -> SemanticModelResolutionOutcome {
    resolve_active_semantic_models_with_loader(catalog, request, None, cancellation, |candidate| {
        catalog.load(candidate)
    })
}

/// Test-only per-language backing choice. Every selected shard of a language
/// uses the same backing; product activation uses each language's catalog-row capability.
#[cfg(any(test, feature = "test-support"))]
pub fn resolve_row_backed_semantic_models_for_test(
    catalog: &SemanticPackCatalog,
    request: &SemanticModelActivationRequest,
    cancellation: &CancellationToken,
    languages: &[&str],
) -> SemanticModelResolutionOutcome {
    for language in languages {
        assert!(
            row_backing_language_supported_in_m2(language),
            "M3 owns the remaining eager derivations for {language}; M2 tests cannot row-back that language"
        );
    }
    resolve_active_semantic_models_with_loader(catalog, request, None, cancellation, |candidate| {
        let loaded = catalog.load_metadata_only_for_test(candidate)?;
        if languages.contains(&loaded.manifest.language.as_str()) {
            Ok(loaded)
        } else {
            catalog.load_decoded_for_test(candidate)
        }
    })
}

/// M3 owns the language-wide derived surfaces that cannot yet come from rows.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn row_backing_language_supported_in_m2(language: &str) -> bool {
    !matches!(language, "go" | "python" | "c" | "c++" | "cpp")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CloseMatchVersionAdmission {
    Covered,
    MissingEvidence,
}

fn close_match_version_admission(
    claim: &crate::analyzer::semantic_model::RustArtifactApproximation,
    evidence: &[SemanticModelActivationEvidence],
    language: &str,
    ecosystem: &str,
    package_name: &str,
) -> CloseMatchVersionAdmission {
    if evidence.iter().any(|row| {
        row.language == language
            && row.ecosystem == ecosystem
            && row.package.as_ref().is_some_and(|package| {
                package.name == package_name
                    && package
                        .version
                        .as_ref()
                        .is_none_or(|version| claim.activation_reason(version).is_err())
            })
    }) {
        CloseMatchVersionAdmission::MissingEvidence
    } else {
        CloseMatchVersionAdmission::Covered
    }
}

fn retain_pack_winners(
    selected: &mut Vec<CandidateSelection>,
    report: &mut SemanticModelActivationReport,
    limits: SemanticModelRuntimeLimits,
    excluded_shards: &mut std::collections::BTreeSet<(String, String)>,
) {
    // One active version per authored pack_id (#8405): two versions of one
    // pack are one provider, not two, so model lookups must not see both. The
    // higher-precedence source wins, then the newer version. Manifests that
    // tie on both but differ in content are a genuine conflict, not versions
    // of each other, so all of them stay active and composition reports the
    // conflict; the manifest digest only picks which winner a Shadowed reason
    // names. The same manifest from several sources survives here and meets
    // the equivalent-shard rule below.
    // Generated and workspace-produced packs are exact output for one
    // dependency or source set: their pack_id names the producer family (for
    // example bifrost.external.go) and their version is the engine's, so they
    // are not versions of one pack and strict activation already selects them.
    // Bounded by max_catalog_candidates and retained only for this activation.
    let authored = |selection: &CandidateSelection| {
        !matches!(
            selection.active.source_kind,
            CatalogPackSourceKind::Generated | CatalogPackSourceKind::WorkspaceProduced
        )
    };
    let pack_keys = selected
        .iter()
        .map(|selection| {
            (
                !selection.active.approximate(),
                selection.source_rank,
                Version::parse(&selection.active.manifest.version)
                    .expect("validated manifest version is semver"),
                selection.active.manifest.content_sha256.as_str(),
            )
        })
        .collect::<Vec<_>>();
    let mut pack_winners = HashMap::<&str, usize>::default();
    for (index, selection) in selected.iter().enumerate() {
        if !authored(selection) {
            continue;
        }
        let winner = pack_winners
            .entry(selection.active.manifest.pack_id.as_str())
            .or_insert(index);
        if pack_keys[index] > pack_keys[*winner] {
            *winner = index;
        }
    }
    let pack_winners = pack_winners
        .into_iter()
        .map(|(pack_id, index)| {
            let winner = &selected[index].active;
            (
                pack_id.to_owned(),
                (
                    (
                        (pack_keys[index].0, pack_keys[index].1),
                        pack_keys[index].2.clone(),
                    ),
                    winner.manifest.content_sha256.clone(),
                    winner.source_kind,
                    winner.source_id.clone(),
                ),
            )
        })
        .collect::<HashMap<_, _>>();
    let pack_ranks = pack_keys
        .into_iter()
        .map(|(exact, rank, version, _)| ((exact, rank), version))
        .collect::<Vec<_>>();
    let mut position = 0;
    selected.retain(|selection| {
        let rank = &pack_ranks[position];
        position += 1;
        if !authored(selection) {
            return true;
        }
        let manifest = &selection.active.manifest;
        let (winner_rank, digest, source_kind, source_id) = &pack_winners[&manifest.pack_id];
        if rank == winner_rank || *digest == manifest.content_sha256 {
            return true;
        }
        excluded_shards.insert(ActivationExclusions::key(manifest, &selection.active.descriptor));
        push_explanation(
            report,
            limits,
            SemanticModelActivationExplanation {
                manifest_digest: manifest.content_sha256.clone(),
                pack_id: Some(manifest.pack_id.clone()),
                shard_id: selection.active.descriptor.shard_id.as_str().to_owned(),
                source_kind: selection.active.source_kind,
                source_id: selection.active.source_id.clone(),
                status: SemanticModelActivationStatus::Shadowed,
                reason: format!(
                    "pack {} keeps one active version: version {} from {} source {source_id} takes precedence over version {}",
                    manifest.pack_id,
                    winner_rank.1,
                    source_kind.as_str(),
                    manifest.version
                ),
            },
        );
        false
    });
    debug_assert_eq!(
        position,
        pack_ranks.len(),
        "retain visits every selection once, in order"
    );
}

fn supplies_rust_assumption(
    request: &SemanticModelActivationRequest,
    manifest: &crate::analyzer::semantic_model::CompiledPackManifest,
) -> bool {
    request
        .approximate_standard_libraries
        .iter()
        .any(|expectation| {
            expectation.toolchain.as_deref() == Some("rust")
                && expectation.language == "rust"
                && manifest.language == "rust"
                && expectation.ecosystem == manifest.ecosystem
                && expectation.selection
                    == ApproximateStandardLibrarySelection::Pack(manifest.pack_id.clone())
        })
}

fn assumed_rust_toolchain<'a>(
    request: &SemanticModelActivationRequest,
    shards: impl IntoIterator<Item = &'a ActiveSemanticModelShard>,
) -> Result<Version, String> {
    let stdlib = shards
        .into_iter()
        .filter(|shard| shard.approximate() && supplies_rust_assumption(request, &shard.manifest))
        .collect::<Vec<_>>();
    let mut versions = std::collections::BTreeSet::new();
    let mut non_exact = false;
    let mut missing_version = false;
    for shard in &stdlib {
        for selector in shard.selectors.iter() {
            if let Some(toolchain) = &selector.toolchain
                && toolchain.name == "rust"
            {
                match toolchain.version.as_deref() {
                    Some(requirement) => {
                        // A semver equality requires all three components. A
                        // bare version means caret compatibility, not equality.
                        let exact = requirement
                            .strip_prefix('=')
                            .and_then(|version| Version::parse(version.trim()).ok());
                        match exact {
                            Some(version) => {
                                versions.insert(version);
                            }
                            None => non_exact = true,
                        }
                    }
                    None => missing_version = true,
                }
            } else {
                // Selectors are alternatives; an unconstrained alternative
                // cannot justify assuming one exact Rust version.
                missing_version = true;
            }
        }
    }
    let source = stdlib
        .iter()
        .map(|shard| format!("{}@{}", shard.manifest.pack_id, shard.manifest.version))
        .collect::<std::collections::BTreeSet<_>>();
    if stdlib.is_empty() {
        Err("no approximately selected Rust standard-library pack".to_owned())
    } else if non_exact {
        Err(format!(
            "winning stdlib {source:?} has a non-exact Rust selector range"
        ))
    } else if missing_version || versions.is_empty() {
        Err(format!(
            "winning stdlib {source:?} names no exact Rust toolchain version"
        ))
    } else if versions.len() != 1 {
        Err(format!(
            "winning stdlib {source:?} names several Rust toolchain versions: {versions:?}"
        ))
    } else {
        Ok(versions.into_iter().next().expect("one version"))
    }
}

fn resolve_active_semantic_models_with_loader(
    catalog: &SemanticPackCatalog,
    request: &SemanticModelActivationRequest,
    rust_cargo_graph: Option<&super::RustSelectedCargoGraph>,
    cancellation: &CancellationToken,
    load: impl Fn(
        &crate::analyzer::semantic_model::catalog::CatalogCandidate,
    )
        -> Result<crate::analyzer::semantic_model::catalog::LoadedCatalogShard, CatalogMiss>,
) -> SemanticModelResolutionOutcome {
    let _scope = crate::profiling::scope("semantic_pack.resolve_active");
    let mut report = SemanticModelActivationReport {
        host_activation: request.host_activation.metadata().map(Box::new),
        ..Default::default()
    };
    let mut excluded_shards = std::collections::BTreeSet::new();
    let activation_sql_start = catalog.sql_statement_count();
    let selection_started = Instant::now();
    let CanonicalActivationEvidence {
        evidence,
        approximate_standard_libraries,
    } = match validate_and_canonicalize_request(request) {
        Ok(canonical) => canonical,
        Err(reason) => {
            push_request_explanation(&mut report, request.limits, reason);
            return SemanticModelResolutionOutcome::Unavailable(report);
        }
    };
    if cancellation.is_cancelled() {
        return SemanticModelResolutionOutcome::Cancelled(report);
    }

    let mut incomplete = false;
    // A retained obsolete production is a gap until a selected exact current
    // generation covers the same evidence and producer family. Report indices
    // remain stable until the final explanation sort.
    let mut stale_dependencies = BTreeMap::<(usize, String), Vec<usize>>::new();
    let mut candidates = BTreeMap::new();
    for (row_index, row) in evidence.iter().enumerate() {
        if cancellation.is_cancelled() {
            return SemanticModelResolutionOutcome::Cancelled(report);
        }
        let query = evidence_query(row, request.bifrost_version.clone());
        let discovered = match catalog.activation_candidates_bounded(&query, usize::MAX) {
            Ok((discovered, refusals)) => {
                for (digest, reason) in refusals {
                    let super::catalog::CatalogError::StaleGeneratedSelector { producer } = &reason
                    else {
                        unreachable!("activation discovery returns only stale refusals");
                    };
                    let indices = stale_dependencies
                        .entry((row_index, producer.name.clone()))
                        .or_default();
                    let index = report.explanations.len();
                    push_explanation(
                        &mut report,
                        request.limits,
                        SemanticModelActivationExplanation {
                            manifest_digest: digest.clone(),
                            pack_id: None,
                            shard_id: String::new(),
                            source_kind: CatalogPackSourceKind::Generated,
                            source_id: String::new(),
                            status: SemanticModelActivationStatus::Unavailable,
                            reason: format!("catalog refused manifest {digest}: {reason}"),
                        },
                    );
                    if report.explanations.len() > index {
                        indices.push(index);
                    }
                }
                discovered
            }
            Err(error) => {
                push_request_explanation(
                    &mut report,
                    request.limits,
                    format!("catalog candidate discovery failed: {error}"),
                );
                return SemanticModelResolutionOutcome::Unavailable(report);
            }
        };
        for candidate in discovered {
            let key = (
                candidate.manifest_digest().to_owned(),
                candidate.shard_id().to_owned(),
                candidate.source_kind(),
                candidate.source_id().to_owned(),
            );
            candidates.entry(key).or_insert(candidate);
            if candidates.len() > request.limits.max_catalog_candidates {
                push_request_explanation(
                    &mut report,
                    request.limits,
                    "semantic-model catalog candidate budget exceeded".to_owned(),
                );
                return SemanticModelResolutionOutcome::Unavailable(report);
            }
        }
    }
    let mut language_ecosystems = evidence
        .iter()
        .map(|row| {
            (
                semantic_pack_language(&row.language).to_owned(),
                row.ecosystem.clone(),
            )
        })
        .collect::<Vec<_>>();
    language_ecosystems.extend(approximate_standard_libraries.iter().map(|expectation| {
        (
            semantic_pack_language(&expectation.language).to_owned(),
            expectation.pack_ecosystem().to_owned(),
        )
    }));
    language_ecosystems.sort();
    language_ecosystems.dedup();
    for (language, ecosystem) in language_ecosystems {
        if cancellation.is_cancelled() {
            return SemanticModelResolutionOutcome::Cancelled(report);
        }
        let query = SemanticPackSelectorQuery {
            verified_raw_artifacts: Vec::new(),
            production_input_digest: None,
            language,
            ecosystem,
            package: None,
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: None,
            bifrost_version: request.bifrost_version.clone(),
        };
        // Evidence-targeted lookups above report applicable stale producers.
        // This broad pass also discovers version near misses and unrelated
        // dependencies; their obsolete metadata cannot make this request open.
        let discovered = match catalog.candidates_bounded(
            &query,
            request.limits.max_catalog_candidates.saturating_add(1),
        ) {
            Ok(discovered) => discovered,
            Err(error) => {
                push_request_explanation(
                    &mut report,
                    request.limits,
                    format!("catalog candidate evaluation failed: {error}"),
                );
                return SemanticModelResolutionOutcome::Unavailable(report);
            }
        };
        for candidate in discovered {
            let key = (
                candidate.manifest_digest().to_owned(),
                candidate.shard_id().to_owned(),
                candidate.source_kind(),
                candidate.source_id().to_owned(),
            );
            candidates.entry(key).or_insert(candidate);
            if candidates.len() > request.limits.max_catalog_candidates {
                push_request_explanation(
                    &mut report,
                    request.limits,
                    "semantic-model catalog candidate budget exceeded".to_owned(),
                );
                return SemanticModelResolutionOutcome::Unavailable(report);
            }
        }
    }
    report.catalog_candidates = candidates.len();
    report.phase_measurements.selection_nanos = elapsed_ns(selection_started);

    let mut selected = Vec::<CandidateSelection>::new();
    let mut generated_manifests = std::collections::BTreeSet::new();
    let mut decode_hydration_nanos = 0u64;
    let sharing_rust = request
        .approximate_standard_libraries
        .iter()
        .any(|expectation| {
            expectation.language == "rust" && expectation.toolchain.as_deref() == Some("rust")
        })
        && !evidence.iter().any(|row| {
            row.language == "rust"
                && row.toolchain.as_ref().is_some_and(|coordinate| {
                    coordinate.name == "rust" && coordinate.version.is_some()
                })
        });
    let mut pending = VecDeque::new();
    let mut catalog_candidates = candidates.into_values();
    let mut catalog_done = false;
    let mut assumed_toolchain = None;
    loop {
        if cancellation.is_cancelled() {
            return SemanticModelResolutionOutcome::Cancelled(report);
        }
        let (candidate, loaded, from_pending) = if let Some(candidate) = catalog_candidates.next() {
            let load_started = Instant::now();
            let loaded = match load(&candidate) {
                Ok(loaded) => loaded,
                Err(miss) => {
                    let reconciliation_required =
                        matches!(miss, CatalogMiss::IndexReconciliationRequired { .. });
                    incomplete = true;
                    push_explanation(
                        &mut report,
                        request.limits,
                        SemanticModelActivationExplanation {
                            manifest_digest: candidate.manifest_digest().to_owned(),
                            pack_id: None,
                            shard_id: candidate.shard_id().to_owned(),
                            source_kind: candidate.source_kind(),
                            source_id: candidate.source_id().to_owned(),
                            status: SemanticModelActivationStatus::Unavailable,
                            reason: catalog_miss_reason(&miss),
                        },
                    );
                    if reconciliation_required {
                        return SemanticModelResolutionOutcome::Unavailable(report);
                    }
                    continue;
                }
            };
            if loaded.origin == crate::analyzer::semantic_model::SemanticPackOrigin::Generated {
                generated_manifests.insert(loaded.manifest.content_sha256.clone());
            }
            decode_hydration_nanos =
                decode_hydration_nanos.saturating_add(elapsed_ns(load_started));
            report.loaded_shards = report.loaded_shards.saturating_add(1);
            report.loaded_records = report.loaded_records.saturating_add(
                usize::try_from(loaded.descriptor.record_count)
                    .expect("validated record count fits usize"),
            );
            if report.loaded_shards > request.limits.max_loaded_shards
                || report.loaded_records > request.limits.max_records
            {
                push_request_explanation(
                    &mut report,
                    request.limits,
                    "semantic-model decoded shard budget exceeded".to_owned(),
                );
                return SemanticModelResolutionOutcome::Unavailable(report);
            }

            (candidate, loaded, false)
        } else {
            if !catalog_done {
                catalog_done = true;
                if !pending.is_empty() {
                    // Keep the stdlib's ordinary authored-pack precedence, but
                    // do not build indexes or source readers to learn its version.
                    let (mut stdlib, others): (Vec<_>, Vec<_>) =
                        selected.drain(..).partition(|selection| {
                            selection.active.approximate()
                                && supplies_rust_assumption(request, &selection.active.manifest)
                        });
                    retain_pack_winners(
                        &mut stdlib,
                        &mut report,
                        request.limits,
                        &mut excluded_shards,
                    );
                    assumed_toolchain = Some(if incomplete {
                        Err("the stdlib selection is incomplete".to_owned())
                    } else {
                        assumed_rust_toolchain(
                            request,
                            stdlib.iter().map(|selection| &selection.active),
                        )
                    });
                    selected = others;
                    selected.extend(stdlib);
                }
            }
            let Some((candidate, loaded)) = pending.pop_front() else {
                break;
            };
            (candidate, loaded, true)
        };
        let assumption = assumed_toolchain.as_ref();
        // The reasons discovery gave for requesting this pack approximately.
        let requested_reasons = approximate_standard_libraries
            .iter()
            .filter(|expectation| {
                expectation.selection
                    == ApproximateStandardLibrarySelection::Pack(loaded.manifest.pack_id.clone())
                    && semantic_pack_language(&expectation.language) == loaded.manifest.language
                    && expectation.ecosystem == loaded.manifest.ecosystem
            })
            .map(|expectation| expectation.reasons)
            .reduce(ApproximationReasons::union);
        let approximate_stdlib_requested = requested_reasons.is_some();
        let pinned_stdlib_rows = evidence
            .iter()
            .filter(|row| {
                row.language == "rust"
                    && row.ecosystem == loaded.manifest.ecosystem
                    && row.package.is_none()
                    && row.module.is_none()
                    && row.toolchain.as_ref().is_some_and(|coordinate| {
                        coordinate.name == "rust" && coordinate.version.is_some()
                    })
            })
            .cloned()
            .collect::<Vec<_>>();
        let exact_match = ((!approximate_stdlib_requested || !pinned_stdlib_rows.is_empty())
            && !from_pending)
            .then(|| {
                strict_activation_match(
                    &loaded.manifest,
                    &loaded.selectors,
                    &evidence,
                    &request.bifrost_version,
                    loaded.origin,
                )
            })
            .flatten();
        // A known plain pin preserves strict target-free activation. Approximate
        // fallback is allowed only if removing a missing target constraint makes
        // the exact same version row match; mismatches never become assumptions.
        let approximate_stdlib = approximate_stdlib_requested
            && exact_match.is_none()
            && (pinned_stdlib_rows.is_empty() || {
                let missing_target_rows = pinned_stdlib_rows
                    .iter()
                    .filter(|row| row.target.is_none())
                    .cloned()
                    .collect::<Vec<_>>();
                let mut selectors = loaded
                    .selectors
                    .iter()
                    .filter(|selector| !selector.targets.is_empty())
                    .cloned()
                    .collect::<Vec<_>>();
                for selector in &mut selectors {
                    selector.targets.clear();
                }
                !missing_target_rows.is_empty()
                    && strict_activation_match(
                        &loaded.manifest,
                        &selectors,
                        &missing_target_rows,
                        &request.bifrost_version,
                        loaded.origin,
                    )
                    .is_some()
            });
        // An observed toolchain outranks a declared floor, so the floor only
        // selects a pack that no evidence row selects. A toolchain-floor
        // expectation is never a pack-ID request, so `!approximate_stdlib`
        // holds for every shard it can select.
        let floor_match = (!approximate_stdlib && !from_pending && exact_match.is_none())
            .then(|| {
                approximate_standard_libraries
                    .iter()
                    .find_map(|expectation| match &expectation.selection {
                        ApproximateStandardLibrarySelection::ToolchainFloor {
                            pack_ecosystem,
                            toolchain,
                            floor,
                            ceiling,
                        } if semantic_pack_language(&expectation.language)
                            == loaded.manifest.language
                            && *pack_ecosystem == loaded.manifest.ecosystem =>
                        {
                            toolchain_floor_activation_match(
                                &loaded.manifest,
                                &loaded.selectors,
                                toolchain,
                                floor,
                                ceiling,
                                &request.bifrost_version,
                            )
                        }
                        _ => None,
                    })
            })
            .flatten();
        let floor_selected = floor_match.is_some();
        let exact_match = exact_match.or(floor_match);
        let uses_assumption = !approximate_stdlib
            && exact_match.is_none()
            && loaded.manifest.language == "rust"
            && (loaded
                .manifest
                .compatibility
                .toolchains
                .iter()
                .any(|constraint| constraint.name == "rust")
                || loaded.selectors.iter().any(|selector| {
                    selector
                        .toolchain
                        .as_ref()
                        .is_some_and(|coordinate| coordinate.name == "rust")
                }));
        if uses_assumption && sharing_rust && !catalog_done {
            pending.push_back((candidate, loaded));
            continue;
        }
        let mut assumed_evidence = Vec::new();
        if uses_assumption && let Some(Ok(version)) = assumption {
            assumed_evidence = evidence
                .iter()
                .filter(|row| row.language == "rust" && row.ecosystem == loaded.manifest.ecosystem)
                .cloned()
                .collect();
            assumed_evidence.push(SemanticModelActivationEvidence {
                language: "rust".into(),
                ecosystem: loaded.manifest.ecosystem.clone(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                production_input_digest: None,
                verified_raw_artifacts: Vec::new(),
            });
            for row in &mut assumed_evidence {
                row.toolchain = Some(CatalogCoordinate {
                    name: "rust".into(),
                    version: Some(version.clone()),
                });
            }
        }
        let activation_match = if approximate_stdlib {
            // An expectation requests a pack; it does not prove any of that
            // pack's toolchain coordinates or artifact digests exist locally.
            // Catalog discovery already checked engine compatibility.
            let row = SemanticModelActivationEvidence {
                language: loaded.manifest.language.clone(),
                ecosystem: loaded.manifest.ecosystem.clone(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                production_input_digest: None,
                verified_raw_artifacts: Vec::new(),
            };
            Some(StrictActivationMatch {
                evidence_rank: EvidenceRank::Language,
                matched_evidence: row,
                matching_evidence: Vec::new(),
                matched_requirements: Vec::new(),
            })
        } else {
            exact_match.or_else(|| {
                if assumed_evidence.is_empty() {
                    return None;
                }
                strict_activation_match(
                    &loaded.manifest,
                    &loaded.selectors,
                    &assumed_evidence,
                    &request.bifrost_version,
                    loaded.origin,
                )
            })
        };
        let Some(StrictActivationMatch {
            evidence_rank,
            matched_evidence,
            matching_evidence,
            matched_requirements,
        }) = activation_match
        else {
            excluded_shards.insert(ActivationExclusions::key(
                &loaded.manifest,
                &loaded.descriptor,
            ));
            // Classification still excludes the shard, but a suppressed
            // explanation must not scan or format activation evidence.
            if report.explanations.len() >= request.limits.max_explanations {
                report.suppressed_explanations = report.suppressed_explanations.saturating_add(1);
                continue;
            }
            let excluded = loaded
                .manifest
                .provenance
                .rust_artifact_approximation
                .as_ref()
                .is_some_and(|record| {
                    loaded.selectors.iter().any(|selector| {
                        selector.package.as_ref().is_some_and(|package| {
                            close_match_version_admission(
                                record,
                                &evidence,
                                &loaded.manifest.language,
                                &loaded.manifest.ecosystem,
                                &package.name,
                            ) == CloseMatchVersionAdmission::MissingEvidence
                        })
                    })
                });
            let mut reason = if excluded {
                "close-match claim excludes this resolved version".to_owned()
            } else {
                strict_activation_mismatch_reason(
                    &loaded.manifest,
                    &loaded.selectors,
                    &evidence,
                    loaded.origin,
                )
            };
            if uses_assumption && let Some(assumption) = assumption {
                match assumption {
                    Ok(version) => reason.push_str(&format!(
                        "; selector rejects assumed Rust toolchain {version}"
                    )),
                    Err(reason_missing) => {
                        reason.push_str(&format!("; no assumed Rust toolchain: {reason_missing}"))
                    }
                }
            }
            for expectation in &approximate_standard_libraries {
                if let ApproximateStandardLibrarySelection::ToolchainFloor {
                    pack_ecosystem,
                    toolchain,
                    floor,
                    ceiling,
                } = &expectation.selection
                    && semantic_pack_language(&expectation.language) == loaded.manifest.language
                    && *pack_ecosystem == loaded.manifest.ecosystem
                {
                    reason.push_str(&format!(
                        "; the requirement does not admit every {toolchain} release from the declared floor {floor} below {ceiling}"
                    ));
                }
            }
            push_loaded_explanation(
                &mut report,
                request.limits,
                &loaded,
                SemanticModelActivationStatus::Incompatible,
                &reason,
            );
            continue;
        };
        let approximate_record = loaded
            .manifest
            .provenance
            .rust_artifact_approximation
            .as_ref();
        if let Some(record) = approximate_record {
            // Rust overlay lookups are keyed by crate spelling, not Cargo package
            // ID (rust/crate_identity.rs). A second resolved version of the same
            // crate cannot safely be separated from the selected shard here.
            let excluded_version = matched_evidence.package.as_ref().is_some_and(|package| {
                close_match_version_admission(
                    record,
                    &evidence,
                    &matched_evidence.language,
                    &matched_evidence.ecosystem,
                    &package.name,
                ) == CloseMatchVersionAdmission::MissingEvidence
            });
            if excluded_version {
                excluded_shards.insert(ActivationExclusions::key(
                    &loaded.manifest,
                    &loaded.descriptor,
                ));
                push_loaded_explanation(
                    &mut report,
                    request.limits,
                    &loaded,
                    SemanticModelActivationStatus::Incompatible,
                    "close-match claim excludes this resolved version",
                );
                continue;
            }
            let reason = matched_evidence
                .package
                .as_ref()
                .and_then(|package| package.version.as_ref())
                .ok_or_else(|| {
                    "approximate Rust dependency pack requires a matched Cargo package version"
                        .to_owned()
                })
                .and_then(|version| record.activation_reason(version))
                .and_then(|_| {
                    (matched_evidence.target.as_deref() == Some(record.target.as_str()))
                        .then_some(())
                        .ok_or_else(|| {
                            "approximate Rust artifact target differs from matched Cargo target"
                                .to_owned()
                        })
                });
            if let Err(reason) = reason {
                excluded_shards.insert(ActivationExclusions::key(
                    &loaded.manifest,
                    &loaded.descriptor,
                ));
                push_loaded_explanation(
                    &mut report,
                    request.limits,
                    &loaded,
                    SemanticModelActivationStatus::Incompatible,
                    &reason,
                );
                continue;
            }
        }
        let approximate_dependency = approximate_record.is_some();
        // The union of the typed reasons of every route that made this
        // activation approximate; `None` is an exact activation.
        let approximation = [
            requested_reasons.filter(|_| approximate_stdlib),
            approximate_dependency.then_some(ApproximationReasons::only(
                ApproximationReason::DependencyVersionApproximate,
            )),
            (floor_selected || !assumed_evidence.is_empty()).then_some(ApproximationReasons::only(
                ApproximationReason::ToolchainVersionUnknown,
            )),
        ]
        .into_iter()
        .flatten()
        .reduce(ApproximationReasons::union);
        let control = match effective_control(&loaded.manifest, &request.controls) {
            Ok(control) => control,
            Err(reason) => {
                push_loaded_explanation(
                    &mut report,
                    request.limits,
                    &loaded,
                    SemanticModelActivationStatus::Conflict,
                    &reason,
                );
                incomplete = true;
                continue;
            }
        };
        if control == Some(SemanticModelControlAction::Disable) {
            excluded_shards.insert(ActivationExclusions::key(
                &loaded.manifest,
                &loaded.descriptor,
            ));
            push_loaded_explanation(
                &mut report,
                request.limits,
                &loaded,
                SemanticModelActivationStatus::Disabled,
                "a compatible activation control disables this pack",
            );
            continue;
        }
        if loaded.manifest.safety.review_required
            && !request
                .host_activation
                .approves_validated_manifest(&loaded.manifest)
            && control != Some(SemanticModelControlAction::Enable)
        {
            // A shipped language-wide pack is an optional capability, not a
            // rejected dependency decision for every workspace in that
            // language. Keep it dormant and silent until a workspace names
            // it. A named stdlib expectation is already such a request, so its
            // installed-but-unenabled state must not become a missing pack.
            // Coordinate-specific review gates remain visible because
            // their matching evidence proves that the pack is relevant to a
            // discovered dependency or toolchain.
            if !approximate_stdlib_requested
                && evidence_rank == EvidenceRank::Language
                && matches!(
                    loaded.source_kind,
                    CatalogPackSourceKind::PreShipped | CatalogPackSourceKind::Embedded
                )
            {
                excluded_shards.insert(ActivationExclusions::key(
                    &loaded.manifest,
                    &loaded.descriptor,
                ));
                continue;
            }
            excluded_shards.insert(ActivationExclusions::key(
                &loaded.manifest,
                &loaded.descriptor,
            ));
            push_loaded_explanation(
                &mut report,
                request.limits,
                &loaded,
                SemanticModelActivationStatus::ReviewRequired,
                if approximate_stdlib_requested {
                    "the installed standard-library pack requires an explicit compatible enable control"
                } else {
                    "the pack requires an explicit compatible enable control"
                },
            );
            continue;
        }

        let descriptor = candidate.descriptor();
        selected.push(CandidateSelection {
            semantic_sha256: descriptor.semantic_sha256.clone(),
            payload_kind: descriptor.payload_kind,
            evidence_rank,
            matched_requirements,
            source_rank: loaded.source_kind.precedence(),
            extraction_deferred_to: None,
            active: {
                let has_callable_values = loaded.has_callable_values;
                ActiveSemanticModelShard {
                    metadata: std::sync::Arc::new(
                        crate::analyzer::store::active_models::ActiveSemanticModelShardMetadata {
                            assumed_rust_toolchain: !assumed_evidence.is_empty(),
                            approximation,
                            manifest: loaded.manifest,
                            descriptor: loaded.descriptor,
                            selectors: loaded.selectors,
                            row_store: None,
                            has_callable_values,
                            source_kind: loaded.source_kind,
                            source_id: loaded.source_id,
                            matched_evidence,
                            matching_evidence,
                            evidence_rank,
                            source_rank: loaded.source_kind.precedence(),
                            extraction_deferred: false,
                        },
                    ),
                    decoded: loaded.shard,
                }
            },
        });
    }

    retain_pack_winners(
        &mut selected,
        &mut report,
        request.limits,
        &mut excluded_shards,
    );
    // An extraction selected by coordinates defers to an extraction of the
    // exact artifact behind the same coordinates (#9474). A released JDK pack
    // extracted from src.zip matches any JDK 21 toolchain, while the
    // production generated from the workspace's jmods matches that JDK's
    // digest. Both claim extraction authority over every JDK owner, and two
    // producers' facts never agree structurally, so two authorities left every
    // owner ambiguous. The exact artifact is what the workspace compiles
    // against, so it keeps the authority and the coordinate pack stays active
    // as a curated contributor. A coordinate pack keeps its authority while
    // any row it matched has no exact extraction.
    let extracted_declarations = |selection: &CandidateSelection| {
        selection.active.manifest.extraction.is_some()
            && selection.payload_kind == PayloadKind::DeclarationFacts
    };
    let coordinates = |row: &SemanticModelActivationEvidence| SemanticModelActivationEvidence {
        production_input_digest: None,
        verified_raw_artifacts: Vec::new(),
        ..row.clone()
    };
    let mut exact_extractions =
        HashMap::<SemanticModelActivationEvidence, (CatalogPackSourceKind, String)>::default();
    for selection in selected.iter().filter(|selection| {
        extracted_declarations(selection) && selection.evidence_rank == EvidenceRank::ExactArtifact
    }) {
        let source = (
            selection.active.source_kind,
            selection.active.source_id.clone(),
        );
        for row in &selection.active.matching_evidence {
            let named = exact_extractions
                .entry(coordinates(row))
                .or_insert_with(|| source.clone());
            if source < *named {
                named.clone_from(&source);
            }
        }
    }
    for selection in &mut selected {
        if !extracted_declarations(selection)
            || selection.evidence_rank == EvidenceRank::ExactArtifact
            || selection.active.matching_evidence.is_empty()
        {
            continue;
        }
        let Some(exact) = selection
            .active
            .matching_evidence
            .iter()
            .map(|row| exact_extractions.get(&coordinates(row)))
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        selection.extraction_deferred_to = exact.into_iter().min().cloned();
        Arc::get_mut(&mut selection.active.metadata)
            .expect("a candidate owns its shard metadata until activation publishes it")
            .extraction_deferred = true;
    }
    selected.sort_by(compare_selection);
    let mut active = Vec::new();
    let mut by_semantic_shard = BTreeMap::<(String, PayloadKind), usize>::new();
    for selection in selected.into_iter().rev() {
        let key = (selection.semantic_sha256.clone(), selection.payload_kind);
        if let Some(&winner) = by_semantic_shard.get(&key) {
            excluded_shards.insert(ActivationExclusions::key(
                &selection.active.manifest,
                &selection.active.descriptor,
            ));
            let active_winner: &CandidateSelection = &active[winner];
            push_explanation(
                &mut report,
                request.limits,
                SemanticModelActivationExplanation {
                    manifest_digest: selection.active.manifest.content_sha256.clone(),
                    pack_id: Some(selection.active.manifest.pack_id.clone()),
                    shard_id: selection.active.descriptor.shard_id.as_str().to_owned(),
                    source_kind: selection.active.source_kind,
                    source_id: selection.active.source_id.clone(),
                    status: SemanticModelActivationStatus::Shadowed,
                    reason: format!(
                        "equivalent semantic shard is supplied by higher-precedence source {}",
                        active_winner.active.source_id
                    ),
                },
            );
            continue;
        }
        by_semantic_shard.insert(key, active.len());
        active.push(selection);
    }
    active.sort_by(|left, right| {
        left.active
            .manifest
            .pack_id
            .cmp(&right.active.manifest.pack_id)
            .then_with(|| {
                left.active
                    .descriptor
                    .shard_id
                    .as_str()
                    .cmp(right.active.descriptor.shard_id.as_str())
            })
            .then_with(|| left.semantic_sha256.cmp(&right.semantic_sha256))
    });

    // Only a shard that survived controls and both precedence passes can
    // affect this request. Dormant distributed candidates stay Disabled or
    // Shadowed in the activation report without opening a false gap.
    active.retain(|selection| {
        if !selection.active.manifest.provenance.is_close_match_approximation()
            || !is_distributed_pack_source(selection.active.source_kind)
            || APPROXIMATE_DISTRIBUTED_SHARDS_ALLOWED
        {
            return true;
        }
        incomplete = true;
        push_explanation(
            &mut report,
            request.limits,
            SemanticModelActivationExplanation {
                manifest_digest: selection.active.manifest.content_sha256.clone(),
                pack_id: Some(selection.active.manifest.pack_id.clone()),
                shard_id: selection.active.descriptor.shard_id.as_str().to_owned(),
                source_kind: selection.active.source_kind,
                source_id: selection.active.source_id.clone(),
                status: SemanticModelActivationStatus::ApproximateDistributedBlocked,
                reason: "approximate Rust dependency artifact from a distributed source is held until causal attribution is available for every consuming family (#10189, #10198, #10212); Installed includes user-supplied local bundles".to_owned(),
            },
        );
        false
    });

    // The current production's own extraction gaps remain authoritative;
    // historical generator metadata adds no gap once its exact replacement
    // survives controls and precedence for this evidence.
    for ((row_index, producer), indices) in stale_dependencies {
        let replacement = active.iter().find(|selection| {
            let shard = &selection.active;
            generated_manifests.contains(&shard.manifest.content_sha256)
                && shard.manifest.producer.name == producer
                && shard.manifest.producer.has_current_dependency_revision()
                && !shard.approximate()
                && selection.evidence_rank == EvidenceRank::ExactArtifact
                && shard.matching_evidence.contains(&evidence[row_index])
        });
        if let Some(replacement) = replacement {
            for index in indices {
                let explanation = &mut report.explanations[index];
                explanation.status = SemanticModelActivationStatus::Shadowed;
                explanation.reason.push_str(&format!(
                    "; superseded by exact current generated manifest {}",
                    replacement.active.manifest.content_sha256
                ));
            }
        } else {
            incomplete = true;
        }
    }

    if let Some(Ok(expected_version)) = assumed_toolchain.as_ref() {
        let final_assumption = if incomplete {
            Err("the final stdlib selection is incomplete".to_owned())
        } else {
            assumed_rust_toolchain(request, active.iter().map(|selection| &selection.active))
        };
        if final_assumption.as_ref().ok() != Some(expected_version) {
            let reason = format!(
                "no stable assumed Rust toolchain: expected {expected_version}, final selection: {final_assumption:?}"
            );
            active.retain(|selection| {
                let shard = &selection.active;
                let assumed_companion = selection.active.assumed_rust_toolchain;
                if assumed_companion {
                    excluded_shards.insert(ActivationExclusions::key(
                        &shard.manifest,
                        &shard.descriptor,
                    ));
                    push_explanation(
                        &mut report,
                        request.limits,
                        SemanticModelActivationExplanation {
                            manifest_digest: shard.manifest.content_sha256.clone(),
                            pack_id: Some(shard.manifest.pack_id.clone()),
                            shard_id: shard.descriptor.shard_id.as_str().to_owned(),
                            source_kind: shard.source_kind,
                            source_id: shard.source_id.clone(),
                            status: SemanticModelActivationStatus::Incompatible,
                            reason: reason.clone(),
                        },
                    );
                }
                !assumed_companion
            });
        }
    }

    for selection in &active {
        // A review-gated pack reaches this push through host approval or an
        // explicit compatible enable. Preserve which authority admitted it.
        let mut reason = if selection.active.approximate() {
            "approximate activation: the project's toolchain is unpinned; std facts are approximate"
        } else if selection.active.manifest.safety.review_required
            && request
                .host_activation
                .approves_validated_manifest(&selection.active.manifest)
        {
            "strict activation evidence and verified host inventory approval selected this shard"
        } else if selection.active.manifest.safety.review_required {
            "strict activation evidence and an explicit enable control selected this shard"
        } else {
            "strict activation evidence and controls selected this shard"
        }
        .to_owned();
        // A pack whose requirement is a compatible range rather than an exact
        // build has to say which range admitted this workspace, and which
        // build the surface it serves was extracted from, so an
        // `external_indexed` answer stays attributable to a stated
        // requirement instead of to an unnamed match (#3465). The pack
        // version is that extraction identity; it is the provenance the
        // requirement no longer carries.
        if selection.active.approximate() || !selection.matched_requirements.is_empty() {
            reason.push_str("; pack version ");
            reason.push_str(&selection.active.manifest.version);
            for matched in &selection.matched_requirements {
                reason.push_str("; ");
                reason.push_str(&matched.describe());
            }
        }
        if selection.active.assumed_rust_toolchain
            && let Some(toolchain) = &selection.active.matched_evidence.toolchain
            && let Some(version) = &toolchain.version
        {
            reason.push_str(&format!("; assumed {} toolchain {version}", toolchain.name));
        }
        // Only a toolchain floor gives an approximate stdlib shard a toolchain
        // version of its own; a pack-ID expectation matches without one.
        if selection.active.approximate()
            && !selection.active.assumed_rust_toolchain
            && selection
                .active
                .manifest
                .provenance
                .rust_artifact_approximation
                .is_none()
            && let Some(toolchain) = &selection.active.matched_evidence.toolchain
            && let Some(version) = &toolchain.version
        {
            reason.push_str(&format!(
                "; no {} toolchain was observed; the pack admits every release from the declared floor {version}",
                toolchain.name
            ));
        }
        if let Some((source_kind, source_id)) = &selection.extraction_deferred_to {
            reason.push_str(&format!(
                "; extraction authority defers to the exact artifact extraction from {} source {source_id}",
                source_kind.as_str()
            ));
        }
        if let Some(record) = &selection
            .active
            .manifest
            .provenance
            .rust_artifact_approximation
            && let Some(resolved) = selection
                .active
                .matched_evidence
                .package
                .as_ref()
                .and_then(|package| package.version.as_ref())
            && let Ok(approximation_reason) = record.activation_reason(resolved)
        {
            reason.push_str("; ");
            reason.push_str(&approximation_reason);
        }
        push_explanation(
            &mut report,
            request.limits,
            SemanticModelActivationExplanation {
                manifest_digest: selection.active.manifest.content_sha256.clone(),
                pack_id: Some(selection.active.manifest.pack_id.clone()),
                shard_id: selection.active.descriptor.shard_id.as_str().to_owned(),
                source_kind: selection.active.source_kind,
                source_id: selection.active.source_id.clone(),
                status: SemanticModelActivationStatus::Active,
                reason,
            },
        );
    }
    report.explanations.sort_by(|left, right| {
        left.manifest_digest
            .cmp(&right.manifest_digest)
            .then_with(|| left.shard_id.cmp(&right.shard_id))
            .then_with(|| left.source_kind.cmp(&right.source_kind))
            .then_with(|| left.source_id.cmp(&right.source_id))
            .then_with(|| left.status.cmp(&right.status))
    });

    let active_packs = active
        .iter()
        .map(|selection| {
            let manifest = &selection.active.manifest;
            (
                manifest.content_sha256.clone(),
                (
                    manifest.pack_id.clone(),
                    manifest.semantic_sha256.clone(),
                    manifest.completeness,
                    // A deferred extraction's authority is withdrawn in favour
                    // of the exact one it defers to (#9474).
                    manifest.extraction.is_some() && !selection.active.extraction_deferred,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut extraction_gaps = Vec::new();
    let mut extraction_gap_counts = BTreeMap::new();
    let mut packs_naming_every_loss = HashSet::default();
    for (manifest_digest, (pack_id, semantic_digest, completeness, extracted)) in active_packs {
        let extraction = match catalog.extraction_accounting(&manifest_digest) {
            Ok(extraction) => extraction,
            Err(error) => {
                push_request_explanation(
                    &mut report,
                    request.limits,
                    format!("read extraction gaps for active pack {pack_id}: {error}"),
                );
                return SemanticModelResolutionOutcome::Unavailable(report);
            }
        };
        // Accounting covers only what an extractor rejected. A pack it names every
        // loss of must be an artifact extraction (an authored pack may omit
        // declarations on purpose and report no reject), and every reject must
        // name a declaration: a rejected source entry is a whole file no
        // declaration-scoped gap covers (#14133).
        if extracted
            && crate::analyzer::semantic_model::pack_is_activation_ready(
                completeness,
                extraction.as_ref(),
            )
            && extraction
                .as_ref()
                .is_none_or(|extraction| extraction.source_entries.is_empty())
        {
            packs_naming_every_loss.insert(semantic_digest);
        }
        if let Some(extraction) = extraction {
            extraction_gap_counts.insert(manifest_digest, extraction.gaps.len());
            extraction_gaps.extend(extraction.gaps.into_iter().map(|gap| {
                ActivePackExtractionGap {
                    pack_id: pack_id.clone(),
                    declaration: gap.declaration,
                    reason: gap.reason,
                }
            }));
        } else {
            extraction_gap_counts.insert(manifest_digest, 0);
        }
    }
    for explanation in &mut report.explanations {
        if explanation.status == SemanticModelActivationStatus::Active
            && let Some(gaps) = extraction_gap_counts.get(&explanation.manifest_digest)
        {
            explanation.reason = format!("{}; gaps: {gaps}", explanation.reason);
        }
    }
    extraction_gaps.sort_by(|left, right| {
        left.declaration
            .cmp(&right.declaration)
            .then_with(|| left.pack_id.cmp(&right.pack_id))
            .then_with(|| left.reason.cmp(&right.reason))
    });
    let extraction_gaps = extraction_gaps
        .into_iter()
        .map(Arc::new)
        .collect::<Vec<_>>();
    let mut extraction_gaps_by_declaration = map_with_capacity(extraction_gaps.len());
    for (index, gap) in extraction_gaps.iter().enumerate() {
        extraction_gaps_by_declaration
            .entry(gap.declaration.clone())
            .or_insert_with(Vec::new)
            .push(index);
    }
    report.extraction_gaps = extraction_gaps.len();

    let active_model_set_hash = hash_active_models_in_host_context(
        &active,
        &extraction_gaps,
        &packs_naming_every_loss,
        rust_cargo_graph,
        request.host_activation.identity(),
    );
    let mut shards = active
        .into_iter()
        .map(|selection| std::sync::Arc::new(selection.active))
        .collect::<Vec<_>>();
    report.phase_measurements.decode_hydration_nanos = decode_hydration_nanos;
    let matcher_started = Instant::now();
    let indexes = match MatcherIndexes::build(&shards, request.limits, cancellation, &mut report) {
        Ok(indexes) => indexes,
        Err(reason) => {
            push_request_explanation(&mut report, request.limits, reason);
            return if cancellation.is_cancelled() {
                SemanticModelResolutionOutcome::Cancelled(report)
            } else {
                SemanticModelResolutionOutcome::Unavailable(report)
            };
        }
    };
    report.phase_measurements.matcher_construction_nanos = elapsed_ns(matcher_started);
    report.retained_bytes =
        report
            .retained_bytes
            .saturating_add(report.host_activation.as_ref().map_or(0, |host| {
                (std::mem::size_of_val(host.as_ref())
                    + host.inventory_sha256.capacity()
                    + host.approval_identity.capacity()) as u64
            }));
    // The index build checked the shards and indexes; the exclusion record is
    // retained with them, so the activation's limit covers it too.
    let excluded_shards = ActivationExclusions::new(excluded_shards);
    if report
        .retained_bytes
        .saturating_add(excluded_shards.retained_bytes())
        > request.limits.max_retained_bytes
    {
        push_request_explanation(
            &mut report,
            request.limits,
            "semantic-model retained-byte budget exceeded".to_owned(),
        );
        return SemanticModelResolutionOutcome::Unavailable(report);
    }
    report.phase_measurements.catalog_sql_statements = catalog
        .sql_statement_count()
        .saturating_sub(activation_sql_start);
    crate::profiling::note_with(|| {
        format!(
            "semantic_pack.activation_phases {:?}",
            report.phase_measurements
        )
    });
    let (source_reader, row_identities) =
        match catalog.runtime_source_reader_with_shard_keys(shards.iter().map(|shard| {
            (
                shard.manifest.content_sha256.as_str(),
                shard.descriptor.shard_id.as_str(),
                shard.source_kind,
            )
        })) {
            Ok(reader) => reader,
            Err(error) => {
                push_request_explanation(&mut report, request.limits, error.to_string());
                return SemanticModelResolutionOutcome::Unavailable(report);
            }
        };
    for (shard, identity) in shards.iter_mut().zip(row_identities) {
        debug_assert_eq!(
            (&source_reader as &dyn crate::analyzer::store::model_catalog::CatalogRowReader)
                .callable_values_presence(identity)
                .expect("selected shard marker exists"),
            shard.has_callable_values,
        );
        let shard = Arc::get_mut(shard).expect("active shard has not been published");
        Arc::get_mut(&mut shard.metadata)
            .expect("shard metadata has not been published")
            .row_store = Some(identity);
    }
    let source_reader = Arc::new(source_reader);
    let request_source = Arc::new(
        crate::analyzer::store::model_catalog::ActivationRowReaderSource::new(
            Arc::clone(&source_reader),
            &active_model_set_hash,
        ),
    );
    let mut resolved = ResolvedActiveSemanticModels::new(
        active_model_set_hash,
        Some(source_reader),
        shards,
        indexes,
        extraction_gaps,
        extraction_gaps_by_declaration,
        excluded_shards,
        report.clone(),
    )
    .with_host_activation(Arc::clone(&request.host_activation));
    resolved.packs_naming_every_loss = packs_naming_every_loss;
    resolved
        .install_request_source(Some(request_source))
        .expect("activation source retains its reader");
    if incomplete {
        SemanticModelResolutionOutcome::Incomplete {
            usable: (!resolved.shards.is_empty()).then_some(resolved),
            report,
        }
    } else {
        SemanticModelResolutionOutcome::Ready(resolved)
    }
}

pub fn acquire_active_semantic_models(
    analyzer: &dyn IAnalyzer,
    catalog: &SemanticPackCatalog,
    persistence: Option<SemanticModelActivationPersistence<'_>>,
    request: &SemanticModelActivationRequest,
    cancellation: &CancellationToken,
) -> SemanticModelRuntimeOutcome {
    acquire_active_semantic_models_with_evidence(
        analyzer,
        catalog,
        persistence,
        request,
        None,
        cancellation,
    )
}

fn resolve_against_snapshot<T: Eq, R>(
    snapshot: &T,
    current: impl FnOnce() -> T,
    resolve: impl FnOnce() -> R,
) -> Result<R, R> {
    let outcome = resolve();
    if &current() == snapshot {
        Ok(outcome)
    } else {
        Err(outcome)
    }
}

/// Acquire and atomically publish one generation's overlay and discovery evidence.
/// A failed acquisition leaves the previously complete publication unchanged.
pub fn acquire_active_semantic_models_with_evidence(
    analyzer: &dyn IAnalyzer,
    catalog: &SemanticPackCatalog,
    persistence: Option<SemanticModelActivationPersistence<'_>>,
    request: &SemanticModelActivationRequest,
    dependency_evidence: Option<&[DependencyEvidencePublication]>,
    cancellation: &CancellationToken,
) -> SemanticModelRuntimeOutcome {
    acquire_active_semantic_models_with_runtime_artifacts(
        analyzer,
        catalog,
        persistence,
        request,
        dependency_evidence,
        RuntimeArtifactPublication::default(),
        cancellation,
    )
}

/// Borrowed runtime-artifact evidence committed with one model publication.
/// Neither ecosystem can be updated independently of that publication boundary.
#[derive(Clone, Copy, Default)]
pub(crate) struct RuntimeArtifactPublication<'a> {
    pub(crate) publication_kind: Option<crate::analyzer::workspace::DependencyPackPublicationKind>,
    pub(crate) pending_languages: &'a [Language],
    pub(crate) activated_ecosystems: &'a [crate::analyzer::DependencyPackEcosystem],
    pub(crate) pending_previous: Option<&'a PendingDependencyPublication>,
    pub(crate) dependency_request_evidence:
        Option<&'a HashMap<crate::analyzer::DependencyPackEcosystem, DependencyRequestEvidence>>,
    pub(crate) withdrawn_dependency_languages: &'a [Language],
    pub(crate) jdk_artifacts_by_configured_home:
        Option<&'a HashMap<PathBuf, SemanticModelActivationEvidence>>,
    pub(crate) python_runtime:
        Option<&'a crate::analyzer::store::python_runtime::PythonRuntimeProviderPublication>,
}

/// Publish runtime source-binding evidence with the activated models. Ordinary
/// acquisition preserves existing evidence when publishing another ecosystem.
pub(crate) fn acquire_active_semantic_models_with_runtime_artifacts(
    analyzer: &dyn IAnalyzer,
    catalog: &SemanticPackCatalog,
    persistence: Option<SemanticModelActivationPersistence<'_>>,
    request: &SemanticModelActivationRequest,
    dependency_evidence: Option<&[DependencyEvidencePublication]>,
    runtime_artifacts: RuntimeArtifactPublication<'_>,
    cancellation: &CancellationToken,
) -> SemanticModelRuntimeOutcome {
    acquire_active_semantic_models_with_inputs(
        analyzer,
        catalog,
        persistence,
        &ActivationInputs::from(request.clone()),
        dependency_evidence,
        runtime_artifacts,
        cancellation,
    )
}

pub(crate) fn request_row_reader_source(
    analyzer: &dyn IAnalyzer,
    catalog: &SemanticPackCatalog,
) -> Option<Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>> {
    analyzer
        .snapshot_caches()
        .and_then(|caches| caches.semantic_models().native_inventory_store())
        .and_then(|store| {
            analyzer.request_row_reader_source(&catalog.pinned_catalog_source(&store.cache_budget))
        })
}

pub(crate) fn acquire_active_semantic_models_with_inputs(
    analyzer: &dyn IAnalyzer,
    catalog: &SemanticPackCatalog,
    persistence: Option<SemanticModelActivationPersistence<'_>>,
    inputs: &ActivationInputs,
    dependency_evidence: Option<&[DependencyEvidencePublication]>,
    runtime_artifacts: RuntimeArtifactPublication<'_>,
    cancellation: &CancellationToken,
) -> SemanticModelRuntimeOutcome {
    let request = &inputs.request;
    acquire_with_resolution(
        analyzer,
        catalog,
        persistence,
        request,
        inputs.rust_cargo_graph.as_ref(),
        dependency_evidence,
        runtime_artifacts,
        &inputs.preparation_failures,
        cancellation,
        request_row_reader_source(analyzer, catalog),
        || {
            resolve_active_semantic_models_with_loader(
                catalog,
                request,
                inputs.rust_cargo_graph.as_ref(),
                cancellation,
                |candidate| catalog.load(candidate),
            )
        },
    )
}

/// Exercise the pre-row activation path through the same publication and limits.
#[cfg(any(test, feature = "test-support"))]
pub fn acquire_eager_semantic_models_for_test(
    analyzer: &dyn IAnalyzer,
    catalog: &SemanticPackCatalog,
    request: &SemanticModelActivationRequest,
    cancellation: &CancellationToken,
) -> SemanticModelRuntimeOutcome {
    acquire_with_resolution(
        analyzer,
        catalog,
        None,
        request,
        None,
        None,
        RuntimeArtifactPublication::default(),
        &[],
        cancellation,
        None,
        || {
            resolve_active_semantic_models_with_loader(
                catalog,
                request,
                None,
                cancellation,
                |candidate| catalog.load_decoded_for_test(candidate),
            )
        },
    )
}

fn request_selects_semantic_models(request: &SemanticModelActivationRequest) -> bool {
    !request.evidence.is_empty()
        || !request.approximate_standard_libraries.is_empty()
        || request
            .controls
            .iter()
            .any(|control| control.action == super::SemanticModelControlAction::Enable)
}

#[allow(clippy::too_many_arguments)]
fn acquire_with_resolution(
    analyzer: &dyn IAnalyzer,
    catalog: &SemanticPackCatalog,
    persistence: Option<SemanticModelActivationPersistence<'_>>,
    request: &SemanticModelActivationRequest,
    rust_cargo_graph: Option<&super::RustSelectedCargoGraph>,
    dependency_evidence: Option<&[DependencyEvidencePublication]>,
    runtime_artifacts: RuntimeArtifactPublication<'_>,
    preparation_failures: &[brokk_bifrost_semantic::analyzer::semantic_model::dependency::RecordedPreparationFailure],
    cancellation: &CancellationToken,
    request_source: Option<Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>>,
    resolve: impl Fn() -> SemanticModelResolutionOutcome,
) -> SemanticModelRuntimeOutcome {
    debug_assert!(
        !crate::analyzer::workspace_authority::memo_attribution(analyzer).is_capturing(),
        "model acquisition precedes captured reads of the published Models key"
    );

    if let Err(reason) = analyzer.bind_host_activation_context(Arc::clone(&request.host_activation))
    {
        let mut report = SemanticModelActivationReport {
            host_activation: request.host_activation.metadata().map(Box::new),
            ..Default::default()
        };
        push_request_explanation(&mut report, request.limits, reason);
        return SemanticModelRuntimeOutcome::Unavailable(report);
    }
    let resolve = || {
        let mut outcome = resolve();
        match &mut outcome {
            SemanticModelResolutionOutcome::Ready(active)
            | SemanticModelResolutionOutcome::Incomplete {
                usable: Some(active),
                ..
            } => {
                active.preparation_failures = preparation_failures.to_vec();
                if active.retained_bytes() > request.limits.max_retained_bytes {
                    let mut report = active.report.clone();
                    push_request_explanation(
                        &mut report,
                        request.limits,
                        "semantic-model retained-byte budget exceeded by preparation failures"
                            .to_owned(),
                    );
                    return SemanticModelResolutionOutcome::Unavailable(report);
                }
            }
            _ => {}
        }
        outcome
    };
    // Record selection before a failed or cancelled first activation. Keep
    // only a scalar here: retaining the Cargo graph before admission would
    // escape the publication's memory budget.
    if let Some(caches) = analyzer.snapshot_caches() {
        caches
            .semantic_models()
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .models_selected = request_selects_semantic_models(request);
    }
    let RuntimeArtifactPublication {
        jdk_artifacts_by_configured_home,
        python_runtime,
        ..
    } = runtime_artifacts;
    let request_key = match runtime_request_key(request) {
        Ok(key) => key,
        Err(reason) => {
            let mut report = SemanticModelActivationReport::default();
            push_request_explanation(&mut report, request.limits, reason);
            return SemanticModelRuntimeOutcome::Unavailable(report);
        }
    };
    let request_key = format!(
        "{request_key}:{}",
        preparation_failures_digest(preparation_failures)
    );
    if let Some(persistence) = persistence
        && let Err(error) =
            catalog.reconcile_workspace_active_set(persistence.scope_id, persistence.store)
    {
        return catalog_lifecycle_error(request.limits, "reconcile", error);
    }
    let catalog_identity = match catalog.cache_identity() {
        Ok(identity) => identity,
        Err(error) => return catalog_lifecycle_error(request.limits, "identify", error),
    };
    let provider_identity = python_runtime
        .map(|publication| {
            crate::analyzer::canonical_hash::lower_hex_string(&publication.evidence_digest)
        })
        .unwrap_or_default();
    let caches = analyzer.snapshot_caches();
    // Selection decides whether reexports are active, and only a reexport-bearing
    // Rust shard puts the Cargo graph into the cache key. The first activation
    // for a graph therefore resolves before the lookup and reuses that result on
    // a miss. The identity it computes is remembered under the inputs that
    // determine it, so a repeat activation looks up the snapshot without
    // resolving: the catalog identity covers the packs, the request key the
    // evidence and limits, the provider identity the Python publication, and the
    // graph digest the graph.
    let snapshot_content = analyzer.workspace_content_identity();
    let content_is_current = || analyzer.workspace_content_identity() == snapshot_content;
    let mut graph_resolved = None;
    let graph_identity = match (caches, rust_cargo_graph) {
        (Some(caches), Some(graph)) => {
            let memo_key = graph_identity_memo_key(
                &request_key,
                &provider_identity,
                &catalog_identity,
                &cargo_graph_digest(graph, request),
            );
            match caches
                .semantic_models()
                .remembered_graph_identity(&memo_key)
            {
                Some(identity) => identity,
                None => {
                    let mut outcome = match resolve_against_snapshot(
                        &snapshot_content,
                        || analyzer.workspace_content_identity(),
                        || with_python_provider_identity(resolve(), python_runtime),
                    ) {
                        Ok(outcome) => outcome,
                        Err(_) => return stale_generation_outcome(request.limits),
                    };
                    if let Some(source) = &request_source {
                        match &mut outcome {
                            SemanticModelResolutionOutcome::Ready(active)
                            | SemanticModelResolutionOutcome::Incomplete {
                                usable: Some(active),
                                ..
                            } => {
                                if let Err(error) =
                                    active.install_request_source(Some(Arc::clone(source)))
                                {
                                    return catalog_lifecycle_error(
                                        request.limits,
                                        "install request source",
                                        error,
                                    );
                                }
                            }
                            _ => {}
                        }
                    }
                    let identity = reexport_graph_identity(&outcome);
                    // A cancelled or unavailable resolution says nothing about
                    // what the inputs select.
                    if matches!(outcome, SemanticModelResolutionOutcome::Ready(_)) {
                        caches
                            .semantic_models()
                            .remember_graph_identity(memo_key, identity.clone());
                    }
                    graph_resolved = Some(outcome);
                    identity
                }
            }
        }
        _ => String::new(),
    };
    let source_identity = request_source.as_ref().and_then(|source| source.identity());
    let source_suffix = source_identity
        .map(|identity| {
            format!(
                ":{}",
                crate::analyzer::canonical_hash::lower_hex_string(&identity)
            )
        })
        .unwrap_or_default();
    let key = format!(
        "{request_key}:{provider_identity}:{graph_identity}:{}:{}:{}{source_suffix}",
        catalog_identity.instance_identity,
        catalog_identity.mutation_generation,
        catalog_identity.sqlite_data_version
    );
    // The activation guard asks whether the analyzer snapshot moved underneath
    // this resolution. Comparing the whole optional identity keeps an analyzer
    // that states none (an empty workspace) on its previous behavior instead of
    // reporting a permanent mismatch.
    let Some(caches) = caches else {
        let mut outcome = graph_resolved
            .take()
            .unwrap_or_else(|| with_python_provider_identity(resolve(), python_runtime));
        if let Some(source) = &request_source {
            match &mut outcome {
                SemanticModelResolutionOutcome::Ready(active) => {
                    if let Err(error) = active.install_request_source(Some(Arc::clone(source))) {
                        return catalog_lifecycle_error(
                            request.limits,
                            "install request source",
                            error,
                        );
                    }
                }
                SemanticModelResolutionOutcome::Incomplete {
                    usable: Some(active),
                    ..
                } => {
                    if let Err(error) = active.install_request_source(Some(Arc::clone(source))) {
                        return catalog_lifecycle_error(
                            request.limits,
                            "install request source",
                            error,
                        );
                    }
                }
                _ => {}
            }
        }
        if !content_is_current() {
            return stale_generation_outcome(request.limits);
        }
        if let SemanticModelResolutionOutcome::Ready(active) = &outcome
            && let Err(error) =
                publish_active_models(analyzer, catalog, persistence, active, cancellation)
        {
            return catalog_lifecycle_error(request.limits, "publish", error);
        }
        return runtime_outcome(
            outcome,
            SemanticModelRuntimeLifecycle::Uncached,
            jdk_artifacts_by_configured_home,
            python_runtime,
        );
    };
    let (acquisition, _) = caches.semantic_models().values.acquire(&key, cancellation);
    match acquisition {
        BudgetedValueAcquisition::Cached { value } => {
            let value = Arc::clone(value.arc());
            if !content_is_current() {
                return stale_generation_outcome(request.limits);
            }
            if let Err(error) =
                publish_active_models(analyzer, catalog, persistence, &value, cancellation)
            {
                return catalog_lifecycle_error(request.limits, "publish", error);
            }
            let snapshot = match caches.semantic_models().publish_overlay(
                analyzer,
                OverlayActivation {
                    request,
                    rust_cargo_graph,
                },
                &value,
                dependency_evidence,
                runtime_artifacts,
                cancellation,
            ) {
                Ok(snapshot) => snapshot,
                Err(error) => return overlay_build_outcome(&value, error, request.limits),
            };
            SemanticModelRuntimeOutcome::Ready {
                active: value,
                snapshot,
                lifecycle: SemanticModelRuntimeLifecycle::Cached,
            }
        }
        BudgetedValueAcquisition::Leader { permit } => {
            let mut outcome = graph_resolved
                .take()
                .unwrap_or_else(|| with_python_provider_identity(resolve(), python_runtime));
            if let Some(source) = &request_source {
                match &mut outcome {
                    SemanticModelResolutionOutcome::Ready(active) => {
                        if let Err(error) = active.install_request_source(Some(Arc::clone(source)))
                        {
                            return catalog_lifecycle_error(
                                request.limits,
                                "install request source",
                                error,
                            );
                        }
                    }
                    SemanticModelResolutionOutcome::Incomplete {
                        usable: Some(active),
                        ..
                    } => {
                        if let Err(error) = active.install_request_source(Some(Arc::clone(source)))
                        {
                            return catalog_lifecycle_error(
                                request.limits,
                                "install request source",
                                error,
                            );
                        }
                    }
                    _ => {}
                }
            }
            debug_assert!(
                rust_cargo_graph.is_none()
                    || !matches!(outcome, SemanticModelResolutionOutcome::Ready(_))
                    || reexport_graph_identity(&outcome) == graph_identity,
                "the remembered graph identity must equal the resolved one"
            );
            let SemanticModelResolutionOutcome::Ready(active) = outcome else {
                return runtime_outcome(
                    outcome,
                    SemanticModelRuntimeLifecycle::Built,
                    jdk_artifacts_by_configured_home,
                    python_runtime,
                );
            };
            if !content_is_current() {
                return stale_generation_outcome(request.limits);
            }
            let mut active = active;
            // The active models are the analyzer's selected state, published
            // in its snapshot, not an optional cache: their charge cannot be
            // refused (the construction limit already bounds them).
            active.charge = AllocationCharge::acquire_required(
                &caches.semantic_models().budget,
                active.retained_bytes().try_into().unwrap_or(usize::MAX),
            );
            let active = Arc::new(active);
            if let Err(error) =
                publish_active_models(analyzer, catalog, persistence, &active, cancellation)
            {
                return catalog_lifecycle_error(request.limits, "publish", error);
            }
            let snapshot = match caches.semantic_models().publish_overlay(
                analyzer,
                OverlayActivation {
                    request,
                    rust_cargo_graph,
                },
                &active,
                dependency_evidence,
                runtime_artifacts,
                cancellation,
            ) {
                Ok(snapshot) => snapshot,
                Err(error) => return overlay_build_outcome(&active, error, request.limits),
            };
            permit.publish_complete(SharedAllocation::new(Arc::clone(&active)));
            SemanticModelRuntimeOutcome::Ready {
                active,
                snapshot,
                lifecycle: SemanticModelRuntimeLifecycle::Built,
            }
        }
        BudgetedValueAcquisition::Cancelled => {
            SemanticModelRuntimeOutcome::Cancelled(SemanticModelActivationReport::default())
        }
        BudgetedValueAcquisition::Rejected => {
            unreachable!("semantic-model runtime cache never publishes deterministic rejections")
        }
    }
}

pub(crate) fn overlay_build_outcome(
    active: &ResolvedActiveSemanticModels,
    error: SemanticModelOverlayBuildError,
    limits: SemanticModelRuntimeLimits,
) -> SemanticModelRuntimeOutcome {
    let mut report = active.activation_report().clone();
    match error {
        SemanticModelOverlayBuildError::Cancelled | SemanticModelOverlayBuildError::Open(_) => {
            SemanticModelRuntimeOutcome::Cancelled(report)
        }
        SemanticModelOverlayBuildError::RetainedBytesExceeded(measurements) => {
            report.overlay_budget_exceeded = Some(measurements);
            push_request_explanation(
                &mut report,
                limits,
                "semantic-model overlay exceeds the combined retained-byte budget".to_string(),
            );
            SemanticModelRuntimeOutcome::Unavailable(report)
        }
        SemanticModelOverlayBuildError::GoSurfaceTraversalExceeded => {
            push_request_explanation(
                &mut report,
                limits,
                "semantic-model Go promotion or interface traversal exceeds its bounded work limit"
                    .to_string(),
            );
            SemanticModelRuntimeOutcome::Unavailable(report)
        }
    }
}

pub(crate) fn publish_active_models(
    analyzer: &dyn IAnalyzer,
    catalog: &SemanticPackCatalog,
    persistence: Option<SemanticModelActivationPersistence<'_>>,
    active: &ResolvedActiveSemanticModels,
    cancellation: &CancellationToken,
) -> Result<(), crate::analyzer::semantic_model::CatalogError> {
    let _scope = crate::profiling::scope("semantic_pack.publish_active_set");
    if let Some(source) = active.request_source() {
        source.publish_activation(active, cancellation)?;
    }

    let native_store = analyzer
        .snapshot_caches()
        .and_then(|caches| caches.semantic_models().inventory_store.get())
        .and_then(std::sync::Weak::upgrade);
    if let Some(store) = native_store.as_ref() {
        publish_jvm_inventory_rows(store, active)?;
    }
    let Some(persistence) = persistence else {
        return Ok(());
    };
    if native_store
        .as_ref()
        .is_none_or(|store| !std::ptr::eq(store.as_ref(), persistence.store))
    {
        publish_jvm_inventory_rows(persistence.store, active)?;
    }
    let mut members = active
        .shards
        .iter()
        .map(|shard| SemanticPackActiveReference {
            manifest_digest: shard.manifest.content_sha256.clone(),
            source_kind: activation_source_kind(shard.source_kind),
            source_id: shard.source_id.clone(),
            workspace_produced: shard.source_kind == CatalogPackSourceKind::WorkspaceProduced,
        })
        .collect::<Vec<_>>();
    members.sort();
    members.dedup();
    catalog
        .replace_workspace_active_set(persistence.scope_id, persistence.store, &members)
        .map(|_| ())
}

pub(crate) fn publish_jvm_inventory_rows(
    store: &AnalyzerStore,
    active: &ResolvedActiveSemanticModels,
) -> Result<(), crate::analyzer::semantic_model::CatalogError> {
    for shard in &active.shards {
        if shard.request_owned()
            || shard.descriptor.payload_kind
                != crate::analyzer::semantic_model::PayloadKind::DeclarationFacts
        {
            continue;
        }
        store
            .publish_jvm_external_owner_inventory_from_activation(shard, active)
            .map_err(|error| {
                crate::analyzer::semantic_model::CatalogError::Integrity(format!(
                    "JVM external owner publication failed: {error}"
                ))
            })?;
    }
    Ok(())
}

pub(crate) fn activation_source_kind(
    kind: CatalogPackSourceKind,
) -> SemanticPackActivationSourceKind {
    match kind {
        CatalogPackSourceKind::Installed => SemanticPackActivationSourceKind::Installed,
        CatalogPackSourceKind::Generated => SemanticPackActivationSourceKind::Generated,
        CatalogPackSourceKind::PreShipped => SemanticPackActivationSourceKind::PreShipped,
        CatalogPackSourceKind::WorkspaceProduced => {
            SemanticPackActivationSourceKind::WorkspaceProduced
        }
        CatalogPackSourceKind::Embedded => SemanticPackActivationSourceKind::Embedded,
        CatalogPackSourceKind::EphemeralWorkspace => {
            SemanticPackActivationSourceKind::EphemeralWorkspace
        }
    }
}

pub(crate) fn catalog_lifecycle_error(
    limits: SemanticModelRuntimeLimits,
    operation: &str,
    error: crate::analyzer::semantic_model::CatalogError,
) -> SemanticModelRuntimeOutcome {
    if matches!(
        error,
        crate::analyzer::semantic_model::CatalogError::Cancelled
    ) {
        return SemanticModelRuntimeOutcome::Cancelled(SemanticModelActivationReport::default());
    }
    let mut report = SemanticModelActivationReport::default();
    push_request_explanation(
        &mut report,
        limits,
        format!("semantic-model active-set {operation} failed: {error}"),
    );
    SemanticModelRuntimeOutcome::Unavailable(report)
}

pub(crate) fn with_python_provider_identity(
    mut outcome: SemanticModelResolutionOutcome,
    publication: Option<&crate::analyzer::store::python_runtime::PythonRuntimeProviderPublication>,
) -> SemanticModelResolutionOutcome {
    if let Some(publication) = publication {
        let active = match &mut outcome {
            SemanticModelResolutionOutcome::Ready(active) => Some(active),
            SemanticModelResolutionOutcome::Incomplete { usable, .. } => usable.as_mut(),
            _ => None,
        };
        if let Some(active) = active {
            let mut hasher = Sha256::new();
            hasher.update(b"bifrost.python-runtime-active-set.v1\0");
            hasher.update(active.active_model_set_hash.as_bytes());
            hasher.update(publication.evidence_digest);
            active.active_model_set_hash =
                crate::analyzer::canonical_hash::lower_hex_string(&hasher.finalize().into());
        }
    }
    outcome
}

pub(crate) fn runtime_outcome(
    outcome: SemanticModelResolutionOutcome,
    lifecycle: SemanticModelRuntimeLifecycle,
    jdk_artifacts_by_configured_home: Option<&HashMap<PathBuf, SemanticModelActivationEvidence>>,
    python_runtime: Option<
        &crate::analyzer::store::python_runtime::PythonRuntimeProviderPublication,
    >,
) -> SemanticModelRuntimeOutcome {
    match outcome {
        SemanticModelResolutionOutcome::Ready(active) => {
            let active = Arc::new(active);
            let snapshot = Arc::new(ActiveSemanticModelSnapshot::new(
                Arc::clone(&active),
                None,
                None,
                None,
                Arc::new(
                    jdk_artifacts_by_configured_home
                        .cloned()
                        .unwrap_or_default(),
                ),
                python_runtime.cloned(),
            ));
            SemanticModelRuntimeOutcome::Ready {
                active,
                snapshot,
                lifecycle,
            }
        }
        SemanticModelResolutionOutcome::Incomplete { usable, report } => {
            SemanticModelRuntimeOutcome::Incomplete {
                usable: usable.map(Arc::new),
                report,
            }
        }
        SemanticModelResolutionOutcome::Cancelled(report) => {
            SemanticModelRuntimeOutcome::Cancelled(report)
        }
        SemanticModelResolutionOutcome::Unavailable(report) => {
            SemanticModelRuntimeOutcome::Unavailable(report)
        }
    }
}

pub(crate) fn stale_generation_outcome(
    limits: SemanticModelRuntimeLimits,
) -> SemanticModelRuntimeOutcome {
    let mut report = SemanticModelActivationReport::default();
    push_request_explanation(
        &mut report,
        limits,
        "analyzer generation changed during semantic-model activation".to_owned(),
    );
    SemanticModelRuntimeOutcome::Unavailable(report)
}

pub(crate) fn compare_selection(left: &CandidateSelection, right: &CandidateSelection) -> Ordering {
    right
        .active
        .approximate()
        .cmp(&left.active.approximate())
        .then_with(|| left.evidence_rank.cmp(&right.evidence_rank))
        .then_with(|| left.source_rank.cmp(&right.source_rank))
        .then_with(|| left.semantic_sha256.cmp(&right.semantic_sha256))
        .then_with(|| {
            left.active
                .manifest
                .content_sha256
                .cmp(&right.active.manifest.content_sha256)
        })
        .then_with(|| left.active.source_id.cmp(&right.active.source_id))
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn active_model_set_hash(
    active: &[CandidateSelection],
    extraction_gaps: &[Arc<ActivePackExtractionGap>],
    packs_naming_every_loss: &HashSet<String>,
) -> String {
    active_model_set_hash_with_cargo_graph(active, extraction_gaps, packs_naming_every_loss, None)
}

#[cfg(any(test, feature = "test-support"))]
fn active_model_set_hash_with_cargo_graph(
    active: &[CandidateSelection],
    extraction_gaps: &[Arc<ActivePackExtractionGap>],
    packs_naming_every_loss: &HashSet<String>,
    rust_cargo_graph: Option<&super::RustSelectedCargoGraph>,
) -> String {
    hash_active_models_in_host_context(
        active,
        extraction_gaps,
        packs_naming_every_loss,
        rust_cargo_graph,
        super::LIBRARY_NONE_APPROVAL_IDENTITY,
    )
}

fn hash_active_models_in_host_context(
    active: &[CandidateSelection],
    extraction_gaps: &[Arc<ActivePackExtractionGap>],
    packs_naming_every_loss: &HashSet<String>,
    rust_cargo_graph: Option<&super::RustSelectedCargoGraph>,
    approval: crate::analyzer::semantic::StableDigest,
) -> String {
    // Rows key on the shard identity (content digest plus audit revision), so
    // packs that differ only in revision do not share model-set identity.
    let mut rows = active
        .iter()
        .map(|selection| (selection.active.identity(), selection))
        .collect::<Vec<_>>();
    rows.sort_unstable_by(|(left_identity, left), (right_identity, right)| {
        left_identity
            .cmp(right_identity)
            .then_with(|| left.payload_kind.cmp(&right.payload_kind))
            .then_with(|| left.evidence_rank.cmp(&right.evidence_rank))
            .then_with(|| left.source_rank.cmp(&right.source_rank))
            .then_with(|| {
                left.active
                    .matched_evidence
                    .cmp(&right.active.matched_evidence)
            })
            .then_with(|| {
                left.active
                    .matching_evidence
                    .cmp(&right.active.matching_evidence)
            })
    });
    let mut gaps = extraction_gaps.iter().collect::<Vec<_>>();
    gaps.sort_unstable_by(|left, right| {
        left.declaration
            .cmp(&right.declaration)
            .then_with(|| left.pack_id.cmp(&right.pack_id))
            .then_with(|| left.reason.cmp(&right.reason))
    });
    let mut hasher = Sha256::new();
    hasher.update(b"bifrost.semantic-model.active-set.v4\0");
    hasher.update(approval.as_bytes());
    hasher.update(SEMANTIC_MODEL_RUNTIME_REPRESENTATION_VERSION.to_be_bytes());
    hasher.update((rows.len() as u64).to_be_bytes());
    for (identity, selection) in rows {
        if let Some(reasons) = selection.active.approximation {
            hasher.update(b"approximate\0");
            // Distinct reason sets select different composition answers.
            hasher.update([reasons.bits()]);
        }
        if selection.active.assumed_rust_toolchain {
            // Keep both approximation causes in identity even when artifact
            // provenance already set the general approximate bit.
            hasher.update(b"assumed-rust-toolchain\0");
        }
        if let Some(claim) = &selection
            .active
            .manifest
            .provenance
            .rust_artifact_approximation
        {
            // The pack digest covers facts. Activation attribution also depends
            // on the selected X/selection rule, so keep it in this active-set
            // component. Exact-pack hash bytes stay unchanged.
            hash_key_part(
                &mut hasher,
                &serde_json::to_string(claim).expect("validated claim serializes"),
            );
        }
        if selection.active.extraction_deferred {
            hasher.update(b"extraction_deferred\0");
        }
        // A partial pack whose accounting names every loss proves absence for
        // the declarations no gap names (#14133), so its accounting is part of
        // the answer. Complete packs keep their identity bytes.
        if selection.active.manifest.completeness
            != crate::analyzer::semantic_model::Completeness::Complete
            && packs_naming_every_loss.contains(&selection.active.manifest.semantic_sha256)
        {
            hasher.update(b"names-every-loss\0");
        }
        hash_key_part(&mut hasher, &identity);
        if !selection.active.manifest.rust_external_reexports.is_empty()
            || selection.active.manifest.rust_external_reexports_truncated
            || selection
                .active
                .manifest
                .rust_external_reexports_glob_incomplete
        {
            // The shard digest covers declarations, while these routes live
            // in the manifest and change caller-visible binding answers.
            let routes = serde_json::to_vec(&selection.active.manifest.rust_external_reexports)
                .expect("validated reexport carrier serializes");
            hasher.update((routes.len() as u64).to_be_bytes());
            hasher.update(&routes);
            hasher.update([u8::from(
                selection.active.manifest.rust_external_reexports_truncated,
            )]);
            hasher.update([u8::from(
                selection
                    .active
                    .manifest
                    .rust_external_reexports_glob_incomplete,
            )]);
        }
        hasher.update([match selection.payload_kind {
            PayloadKind::DeclarationFacts => 0,
            PayloadKind::GeneratorRules => 1,
            PayloadKind::ProcedureSummaries => 2,
        }]);
        hasher.update([match selection.evidence_rank {
            EvidenceRank::Language => 0,
            EvidenceRank::NamedCoordinate => 1,
            EvidenceRank::VersionedCoordinate => 2,
            EvidenceRank::ExactArtifact => 3,
        }]);
        hasher.update([selection.source_rank]);
        hash_activation_evidence(&mut hasher, &selection.active.matched_evidence);
        hasher.update((selection.active.matching_evidence.len() as u64).to_be_bytes());
        for evidence in &selection.active.matching_evidence {
            hash_activation_evidence(&mut hasher, evidence);
        }
    }
    hasher.update((gaps.len() as u64).to_be_bytes());
    for gap in gaps {
        hash_key_part(&mut hasher, &gap.declaration);
        hash_key_part(&mut hasher, &gap.pack_id);
        hash_key_part(&mut hasher, &gap.reason);
    }
    if active.iter().any(|selection| {
        selection.active.manifest.language == "rust"
            && (!selection.active.manifest.rust_external_reexports.is_empty()
                || selection.active.manifest.rust_external_reexports_truncated
                || selection
                    .active
                    .manifest
                    .rust_external_reexports_glob_incomplete)
    }) {
        hasher.update(b"bifrost.rust-cargo-reexports.v1\0");
        match rust_cargo_graph {
            Some(graph) => hash_cargo_graph_packages(
                &mut hasher,
                graph,
                active
                    .iter()
                    .filter(|selection| selection.active.manifest.language == "rust")
                    .flat_map(|selection| {
                        std::iter::once(&selection.active.matched_evidence)
                            .chain(&selection.active.matching_evidence)
                    }),
            ),
            None => hasher.update(b"missing-cargo-graph"),
        }
    }
    crate::analyzer::canonical_hash::lower_hex_string(&hasher.finalize().into())
}

/// Hash the selected packages that `evidence` maps to in `graph`: identity,
/// scope, admission tuple and scoped edges. The active-set identity and the
/// graph digest below share this encoding, so a graph field the identity
/// reads cannot be missing from the digest that stands in for it.
fn hash_cargo_graph_packages<'a>(
    hasher: &mut Sha256,
    graph: &super::RustSelectedCargoGraph,
    evidence: impl Iterator<Item = &'a SemanticModelActivationEvidence>,
) {
    let mut packages = evidence
        .filter_map(|evidence| graph.package_for_evidence(evidence).cloned())
        .collect::<Vec<_>>();
    packages.sort();
    packages.dedup();
    hasher.update((packages.len() as u64).to_be_bytes());
    let mut edges = graph.scoped_edge_names().peekable();
    for package in packages {
        hash_key_part(hasher, package.as_str());
        for scope in [&package.configuration, &package.target] {
            match scope {
                Some(value) => {
                    hasher.update([1]);
                    hash_key_part(hasher, value);
                }
                None => hasher.update([0]),
            }
        }
        // Serialize the admission tuple itself. A field added to
        // the tuple cannot silently be omitted from identity.
        if let Some(tuple) = graph.artifact_tuple(&package) {
            let tuple_bytes =
                serde_json::to_vec(tuple).expect("typed Cargo artifact tuple serializes");
            hasher.update((tuple_bytes.len() as u64).to_be_bytes());
            hasher.update(tuple_bytes);
        }
        let mut package_edges = Vec::new();
        while let Some((source, _, _, _)) = edges.peek() {
            match source.cmp(&&package) {
                Ordering::Less => {
                    edges.next();
                }
                Ordering::Greater => break,
                Ordering::Equal => package_edges.push(edges.next().expect("peeked edge")),
            }
        }
        hasher.update((package_edges.len() as u64).to_be_bytes());
        for (source, dependency_name, target, crate_name) in package_edges {
            hash_key_part(hasher, source.as_str());
            hash_key_part(hasher, dependency_name);
            hash_key_part(hasher, target);
            match crate_name {
                Some(name) => {
                    hasher.update([1]);
                    hash_key_part(hasher, name);
                }
                None => hasher.update([0]),
            }
        }
    }
}

/// Digest of everything in `graph` that the facade identity can read for an
/// activation with this `request`: the graph's data for every package the
/// request's evidence selects. Selection only ever maps evidence rows of the
/// request (the workspace retains the graph to exactly that evidence), so a
/// graph change that could move the identity moves this digest.
fn cargo_graph_digest(
    graph: &super::RustSelectedCargoGraph,
    request: &SemanticModelActivationRequest,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"bifrost.rust-cargo-graph-digest.v1\0");
    hash_cargo_graph_packages(&mut hasher, graph, request.evidence.iter());
    crate::analyzer::canonical_hash::lower_hex_string(&hasher.finalize().into())
}

fn graph_identity_memo_key(
    request: &str,
    provider: &str,
    catalog: &super::SemanticPackCatalogCacheIdentity,
    graph: &str,
) -> String {
    format!(
        "{request}:{provider}:{}:{}:{}:{graph}",
        catalog.instance_identity, catalog.mutation_generation, catalog.sqlite_data_version
    )
}

/// The active-set identity of `outcome` when it depends on the Cargo graph,
/// else empty: graph data enters the identity only for a reexport-bearing
/// Rust shard.
fn reexport_graph_identity(outcome: &SemanticModelResolutionOutcome) -> String {
    let active = match outcome {
        SemanticModelResolutionOutcome::Ready(active) => Some(active),
        SemanticModelResolutionOutcome::Incomplete { usable, .. } => usable.as_ref(),
        _ => None,
    };
    active
        .filter(|active| {
            active.shards().iter().any(|shard| {
                shard.manifest.language == "rust"
                    && (!shard.manifest.rust_external_reexports.is_empty()
                        || shard.manifest.rust_external_reexports_truncated
                        || shard.manifest.rust_external_reexports_glob_incomplete)
            })
        })
        .map(|active| active.active_model_set_hash().to_owned())
        .unwrap_or_default()
}

pub(crate) fn push_request_explanation(
    report: &mut SemanticModelActivationReport,
    limits: SemanticModelRuntimeLimits,
    reason: String,
) {
    push_explanation(
        report,
        limits,
        SemanticModelActivationExplanation {
            manifest_digest: String::new(),
            pack_id: None,
            shard_id: String::new(),
            source_kind: CatalogPackSourceKind::Embedded,
            source_id: String::new(),
            status: SemanticModelActivationStatus::Unavailable,
            reason,
        },
    );
}

pub(crate) fn push_loaded_explanation(
    report: &mut SemanticModelActivationReport,
    limits: SemanticModelRuntimeLimits,
    loaded: &crate::analyzer::semantic_model::LoadedCatalogShard,
    status: SemanticModelActivationStatus,
    reason: &str,
) {
    push_explanation(
        report,
        limits,
        SemanticModelActivationExplanation {
            manifest_digest: loaded.manifest.content_sha256.clone(),
            pack_id: Some(loaded.manifest.pack_id.clone()),
            shard_id: loaded.descriptor.shard_id.as_str().to_owned(),
            source_kind: loaded.source_kind,
            source_id: loaded.source_id.clone(),
            status,
            reason: reason.to_owned(),
        },
    );
}

pub(crate) fn push_explanation(
    report: &mut SemanticModelActivationReport,
    limits: SemanticModelRuntimeLimits,
    explanation: SemanticModelActivationExplanation,
) {
    if report.explanations.len() < limits.max_explanations {
        report.explanations.push(explanation);
    } else {
        report.suppressed_explanations = report.suppressed_explanations.saturating_add(1);
    }
}

/// An active model set published without a declaration overlay, as the
/// uncached activation path can publish it.
#[cfg(test)]
pub(crate) fn snapshot_without_overlay_fixture(name: &str) -> Arc<ActiveSemanticModelSnapshot> {
    Arc::new(ActiveSemanticModelSnapshot::new(
        Arc::new(resolved_active_models_fixture(name, vec![])),
        None,
        None,
        None,
        Arc::new(HashMap::default()),
        None,
    ))
}

#[cfg(any(test, feature = "test-support"))]
#[track_caller]
pub(crate) fn resolved_active_models_fixture(
    active_model_set_hash: impl Into<String>,
    shards: Vec<Arc<ActiveSemanticModelShard>>,
) -> ResolvedActiveSemanticModels {
    let mut report = SemanticModelActivationReport::default();
    let indexes = MatcherIndexes::build(
        &shards,
        SemanticModelRuntimeLimits::default(),
        &CancellationToken::default(),
        &mut report,
    )
    .expect("active-model fixture matcher builds");
    ResolvedActiveSemanticModels::new(
        active_model_set_hash.into(),
        None,
        shards,
        indexes,
        Vec::new(),
        HashMap::default(),
        Default::default(),
        report,
    )
}

/// Minimal source-absent publication for policy tests of an already selected
/// shard. It deliberately bypasses activation; activation tests cover their
/// own admission rules before publishing a snapshot.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn test_snapshot_from_compiled_pack(
    compiled: crate::analyzer::semantic_model::CompiledSemanticModelPack,
    matched_evidence: SemanticModelActivationEvidence,
    source_kind: CatalogPackSourceKind,
) -> Arc<ActiveSemanticModelSnapshot> {
    test_snapshot_from_compiled_pack_with_evidences(compiled, vec![matched_evidence], source_kind)
}

/// Publish the same compiled shard with all matching resolved package tuples.
/// This matches normal activation's one-shard/many-evidence shape and proves
/// attribution retains every matched Y for one selected record.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn test_snapshot_from_compiled_pack_with_evidences(
    compiled: crate::analyzer::semantic_model::CompiledSemanticModelPack,
    matched_evidences: Vec<SemanticModelActivationEvidence>,
    source_kind: CatalogPackSourceKind,
) -> Arc<ActiveSemanticModelSnapshot> {
    test_snapshot_from_compiled_packs(vec![(compiled, matched_evidences, source_kind)])
}

/// Publish multiple selected compiled packs in one source-absent test snapshot.
/// Each pack keeps its own manifest digest while each evidence tuple keeps its
/// own resolved Cargo version.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn test_snapshot_from_compiled_packs(
    packs: Vec<(
        crate::analyzer::semantic_model::CompiledSemanticModelPack,
        Vec<SemanticModelActivationEvidence>,
        CatalogPackSourceKind,
    )>,
) -> Arc<ActiveSemanticModelSnapshot> {
    assert!(!packs.is_empty(), "test snapshot needs a compiled pack");
    let mut shards = Vec::new();
    let mut selections = Vec::new();
    for (pack_index, (compiled, matched_evidences, source_kind)) in packs.into_iter().enumerate() {
        assert!(
            !matched_evidences.is_empty(),
            "test snapshot needs evidence"
        );
        let manifest = Arc::new(compiled.manifest);
        for (artifact_index, artifact) in compiled.shards.into_iter().enumerate() {
            let matched_evidence = &matched_evidences[0];
            let decoded = crate::analyzer::semantic_model::decode_shard(
                &artifact.descriptor,
                &artifact.bytes,
                &crate::analyzer::semantic_model::DecodeLimits::default(),
            )
            .expect("test pack shard decodes");
            let metadata = Arc::new(
                crate::analyzer::store::active_models::ActiveSemanticModelShardMetadata {
                    assumed_rust_toolchain: false,
                    approximation: manifest
                        .provenance
                        .is_close_match_approximation()
                        .then_some(ApproximationReasons::only(
                            ApproximationReason::DependencyVersionApproximate,
                        )),
                    descriptor: artifact.descriptor.clone(),
                    selectors: decoded.activation().to_vec(),
                    row_store: None,
                    has_callable_values: decoded.callable_values().is_some(),
                    manifest: Arc::clone(&manifest),
                    source_kind,
                    source_id: format!(
                        "test:close-match-active-shard:{pack_index}:{artifact_index}"
                    ),
                    matched_evidence: matched_evidence.clone(),
                    matching_evidence: matched_evidences.clone(),
                    evidence_rank: EvidenceRank::VersionedCoordinate,
                    source_rank: 0,
                    extraction_deferred: false,
                },
            );
            selections.push(CandidateSelection {
                active: ActiveSemanticModelShard {
                    metadata: Arc::clone(&metadata),
                    decoded: None,
                },
                semantic_sha256: artifact.descriptor.semantic_sha256.clone(),
                payload_kind: artifact.descriptor.payload_kind,
                evidence_rank: EvidenceRank::VersionedCoordinate,
                matched_requirements: Vec::new(),
                source_rank: 0,
                extraction_deferred_to: None,
            });
            shards.push(Arc::new(ActiveSemanticModelShard {
                metadata,
                decoded: Some(decoded),
            }));
        }
    }
    // The production hash is the single owner of active-set identity; a
    // test-only digest here could mask a defect in it (#14077).
    let active = Arc::new(resolved_active_models_fixture(
        active_model_set_hash(&selections, &[], &HashSet::default()),
        shards,
    ));
    Arc::new(ActiveSemanticModelSnapshot::new(
        active,
        None,
        None,
        None,
        Arc::new(HashMap::default()),
        None,
    ))
}

#[cfg(test)]
pub(crate) mod unmaterialized_call_shape_binding_tests {

    use super::resolved_active_models_fixture;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::ActivatedProcedureSummary;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::ActiveSemanticModelShard;

    use std::sync::Arc;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCoordinate;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogPackSourceKind;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::EvidenceRank;

    use brokk_bifrost_core::hash::HashMap;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::MatcherIndexes;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::ProcedureSummaryApplicability;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::ProcedureSummaryMemberKey;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::ResolvedActiveSemanticModels;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SemanticLocator;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelActivationEvidence;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelActivationReport;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelMatchDisposition;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelRuntimeLimits;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::UnmaterializedExternalTarget;

    use semver::Version;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::procedure_summary_actual_to_formal;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::strict_activation_match;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::strict_activation_mismatch_reason;

    use brokk_bifrost_analysis::analyzer::semantic::ids::DeclarationLocator;

    use brokk_bifrost_analysis::analyzer::semantic::ids::DeclarationSegment;

    use brokk_bifrost_analysis::analyzer::semantic::ids::DeclarationSegmentKind;

    use brokk_bifrost_core::analyzer::model::LanguageDialect as SemanticLanguage;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SemanticRole;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SourceAnchor;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SourcePosition;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SourceSpan;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::unmaterialized_external_mount;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::unmaterialized_external_path;

    use brokk_bifrost_analysis::analyzer::semantic_model::compiler::CompilerOptions;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::DecodeLimits;

    use brokk_bifrost_analysis::analyzer::semantic_model::source::SourceFormat;

    use brokk_bifrost_analysis::analyzer::semantic_model::compiler::compile_source;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::decode_shard;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#10258: three retained Cargo graph copies must fit the publication budget")]
    fn carried_graph_copies_are_in_the_publication_limit() {
        let active_bytes = 10;
        let overlay_with_one_graph = 50;
        let graph_copy = 40;
        let limit = 100;
        assert!(active_bytes + overlay_with_one_graph <= limit);
        let publication =
            super::three_copy_graph_retained_bytes(overlay_with_one_graph, graph_copy);
        assert!(active_bytes + publication > limit);
    }

    #[test]
    #[hardwon("#10258: graph resolution changing workspace generation cannot publish its outcome")]
    fn graph_resolution_rejects_generation_bump() {
        let generation = std::cell::Cell::new(7u64);
        let captured = generation.get();
        let result = super::resolve_against_snapshot(
            &captured,
            || generation.get(),
            || {
                generation.set(8);
                "selected graph"
            },
        );
        assert_eq!(result, Err("selected graph"));
    }

    const PACK: &[u8] = br#"{
      "schema_version": 2,
      "pack_id": "test.call-shape",
      "version": "1.0.0",
      "producer": {"name": "test", "version": "1.0.0"},
      "language": "java",
      "ecosystem": "maven",
      "compatibility": {"bifrost": ">=0.8.0, <1.0.0"},
      "provenance": {"source": "https://example.invalid/call-shape"},
      "license": "Apache-2.0",
      "completeness": "complete",
      "safety": {"generated_code_only": false, "review_required": false},
      "shards": [{
        "id": "summaries",
        "activation": [{}],
        "payload": {
          "kind": "procedure_summaries",
          "summaries": [{
            "id": "summary.fixed",
            "target": {
              "path": "com/acme/Fixed.class",
              "symbol": "com.acme.Api.fixed(first, second, third)",
              "has_receiver": false,
              "parameter_count": 3
            },
            "completeness": "complete",
            "transfers": [{
              "input": {"kind": "parameter", "ordinal": 0},
              "exit_kind": "normal",
              "output": {"kind": "normal_return"}
            }]
          }, {
            "id": "summary.variadic",
            "target": {
              "path": "com/acme/Variadic.class",
              "symbol": "com.acme.Api.variadic(first, second, rest)",
              "has_receiver": false,
              "variadic": true,
              "parameter_count": 3
            },
            "completeness": "complete",
            "transfers": [{
              "input": {"kind": "parameter", "ordinal": 0},
              "exit_kind": "normal",
              "output": {"kind": "normal_return"}
            }]
          }]
        }
      }]
    }"#;

    fn target(member: &str, arity: u32) -> UnmaterializedExternalTarget {
        target_for_language(
            brokk_bifrost_core::analyzer::model::Language::Java,
            "com.acme.Api",
            member,
            arity,
        )
    }

    fn target_for_language(
        language: brokk_bifrost_core::analyzer::model::Language,
        owner: &str,
        member: &str,
        arity: u32,
    ) -> UnmaterializedExternalTarget {
        let position = SourcePosition::new(0, 0, 0);
        let anchor = SourceAnchor::new(
            SourceSpan::new(position, position).expect("fixture span is ordered"),
            0,
        );
        let declaration = DeclarationLocator::new(vec![
            DeclarationSegment::named(DeclarationSegmentKind::Function, member, anchor, arity)
                .expect("fixture member is named"),
        ])
        .expect("fixture declaration is non-empty");
        let locator = SemanticLocator::new(
            unmaterialized_external_mount(),
            unmaterialized_external_path(),
            SemanticLanguage::Standard(language),
            declaration,
            SemanticRole::Procedure,
            anchor,
        );
        UnmaterializedExternalTarget::new(owner, member, arity, false, locator)
    }

    fn python_evidence(digest_byte: char) -> SemanticModelActivationEvidence {
        SemanticModelActivationEvidence {
            language: "python".to_owned(),
            ecosystem: "python".to_owned(),
            package: Some(CatalogCoordinate {
                name: "pkg:pypi/example@1.2.3".to_owned(),
                version: None,
            }),
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            production_input_digest: None,
verified_raw_artifacts: (Some(std::iter::repeat_n(digest_byte, 64).collect())).into_iter().map(|sha256: String| brokk_bifrost_semantic::analyzer::semantic_model::runtime::VerifiedRawArtifact::from_sha256(brokk_bifrost_semantic::analyzer::semantic_model::dependency::DependencyArtifactRole::Reference, brokk_bifrost_semantic::analyzer::semantic_model::ExternalArtifactKind::PythonSource, &sha256)).collect(),
        }
    }

    fn compile_python_fixture_shard(
        source: serde_json::Value,
        evidence: SemanticModelActivationEvidence,
        source_id: String,
        evidence_rank: EvidenceRank,
        source_rank: u8,
    ) -> ActiveSemanticModelShard {
        let compiled = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .expect("Python fixture compiles");
        let decoded = decode_shard(
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("Python fixture decodes");
        let manifest = Arc::new(compiled.manifest);
        let has_callable_values = decoded.callable_values().is_some();
        let descriptor = manifest
            .shards
            .iter()
            .find(|descriptor| descriptor.shard_id == decoded.shard_id())
            .expect("fixture descriptor exists")
            .clone();
        ActiveSemanticModelShard {
            metadata: std::sync::Arc::new(
                crate::analyzer::store::active_models::ActiveSemanticModelShardMetadata {
                    assumed_rust_toolchain: false,
                    descriptor,
                    selectors: decoded.activation().to_vec(),
                    row_store: None,
                    has_callable_values,
                    manifest,
                    approximation: None,
                    source_kind: CatalogPackSourceKind::Embedded,
                    source_id,
                    matched_evidence: evidence.clone(),
                    matching_evidence: vec![evidence],
                    evidence_rank,
                    source_rank,
                    extraction_deferred: false,
                },
            ),
            decoded: Some(decoded),
        }
    }

    fn python_artifact_shard(
        evidence: &SemanticModelActivationEvidence,
        source_rank: u8,
    ) -> ActiveSemanticModelShard {
        let mut source: serde_json::Value = serde_json::from_slice(PACK).unwrap();
        source["language"] = "python".into();
        source["ecosystem"] = "python".into();
        source["shards"][0]["activation"] = serde_json::json!([{
            "package": {"name": evidence.package.as_ref().unwrap().name.clone()},
            "artifact_sha256": evidence.single_raw_sha256().as_ref().unwrap().clone(),
        }]);
        compile_python_fixture_shard(
            source,
            evidence.clone(),
            format!(
                "test:pypi:{}",
                evidence.single_raw_sha256().as_deref().unwrap()
            ),
            EvidenceRank::ExactArtifact,
            source_rank,
        )
    }

    fn python_pypi_wildcard_shard(
        evidence: &SemanticModelActivationEvidence,
        source_rank: u8,
    ) -> ActiveSemanticModelShard {
        let mut source: serde_json::Value = serde_json::from_slice(PACK).unwrap();
        source["language"] = "python".into();
        source["ecosystem"] = "python".into();
        source["shards"][0]["activation"] = serde_json::json!([{
            "package": {"name": evidence.package.as_ref().unwrap().name.clone()},
        }]);
        compile_python_fixture_shard(
            source,
            evidence.clone(),
            "test:pypi-wildcard".to_owned(),
            EvidenceRank::NamedCoordinate,
            source_rank,
        )
    }

    fn python_generic_shard() -> ActiveSemanticModelShard {
        let mut source: serde_json::Value = serde_json::from_slice(PACK).unwrap();
        source["language"] = "python".into();
        source["ecosystem"] = "python".into();
        source["shards"][0]["activation"] = serde_json::json!([{}]);
        let evidence = SemanticModelActivationEvidence {
            language: "python".to_owned(),
            ecosystem: "python".to_owned(),
            package: None,
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            production_input_digest: None,
            verified_raw_artifacts: Vec::new(),
        };
        compile_python_fixture_shard(
            source,
            evidence,
            "test:generic-python".to_owned(),
            EvidenceRank::Language,
            0,
        )
    }

    #[test]
    fn structured_variadic_summary_binds_both_rest_domains_and_uses_required_arity() {
        let source = serde_json::json!({
            "schema_version": 14,
            "pack_id": "test.variadic-formals",
            "version": "1.0.0",
            "producer": {"name": "test", "version": "1.0.0"},
            "language": "java",
            "ecosystem": "maven",
            "compatibility": {"toolchains": []},
            "provenance": {"source": "test:variadic-formals"},
            "license": "Apache-2.0",
            "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [{
                "id": "summaries",
                "activation": [{}],
                "payload": {"kind": "procedure_summaries", "summaries": [{
                    "id": "summary.variadic",
                    "target": {
                        "path": "com/acme/Variadic.class",
                        "symbol": "com.acme.Api.variadic(first, args, flag, kwargs)",
                        "has_receiver": false,
                        "variadic": true,
                        "parameter_count": 4,
                        "formals": [
                            {"name": "first"},
                            {
                                "name": "args",
                                "passing_mode": "positional_only",
                                "variadic_kind": "positional"
                            },
                            {
                                "name": "flag",
                                "optional": true,
                                "passing_mode": "named_only"
                            },
                            {
                                "name": "kwargs",
                                "passing_mode": "named_only",
                                "variadic_kind": "keyword"
                            }
                        ]
                    },
                    "completeness": "complete",
                    "transfers": [{
                        "input": {"kind": "parameter", "ordinal": 0},
                        "exit_kind": "normal",
                        "output": {"kind": "normal_return"}
                    }]
                }]}
            }]
        });
        let compiled = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .expect("schema-14 variadic summary compiles");
        let shard = decode_shard(
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("schema-14 summary decodes");
        let evidence = SemanticModelActivationEvidence {
            language: "java".to_owned(),
            ecosystem: "maven".to_owned(),
            package: None,
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            production_input_digest: None,
            verified_raw_artifacts: Vec::new(),
        };
        let active_shard = {
            let decoded = shard;
            let manifest = Arc::new(compiled.manifest);
            let has_callable_values = decoded.callable_values().is_some();
            ActiveSemanticModelShard {
                metadata: std::sync::Arc::new(
                    crate::analyzer::store::active_models::ActiveSemanticModelShardMetadata {
                        assumed_rust_toolchain: false,
                        descriptor: manifest
                            .shards
                            .iter()
                            .find(|descriptor| descriptor.shard_id == decoded.shard_id())
                            .expect("fixture descriptor exists")
                            .clone(),
                        selectors: decoded.activation().to_vec(),
                        row_store: None,
                        has_callable_values,
                        manifest,
                        approximation: None,
                        source_kind: CatalogPackSourceKind::Embedded,
                        source_id: "test:variadic-formals".to_owned(),
                        matched_evidence: evidence.clone(),
                        matching_evidence: vec![evidence],
                        evidence_rank: EvidenceRank::Language,
                        source_rank: 0,
                        extraction_deferred: false,
                    },
                ),
                decoded: Some(decoded),
            }
        };
        let mut report = SemanticModelActivationReport::default();
        let active_shard = Arc::new(active_shard);
        let indexes = MatcherIndexes::build(
            std::slice::from_ref(&active_shard),
            SemanticModelRuntimeLimits::default(),
            &CancellationToken::default(),
            &mut report,
        )
        .expect("variadic summary indexes");
        let active = ResolvedActiveSemanticModels::new(
            "test:variadic-formals".to_owned(),
            None,
            vec![active_shard],
            indexes,
            Vec::new(),
            HashMap::default(),
            Default::default(),
            report,
        );
        let direct = |id| {
            brokk_bifrost_analysis::analyzer::semantic::SemanticCallArgument::direct(
                brokk_bifrost_analysis::analyzer::semantic::ValueId::new(id),
                brokk_bifrost_analysis::analyzer::semantic::ArgumentDomain::Positional,
            )
        };
        let keyword = |id, name| {
            brokk_bifrost_analysis::analyzer::semantic::SemanticCallArgument::keyword(
                brokk_bifrost_analysis::analyzer::semantic::ValueId::new(id),
                name,
            )
        };
        let arguments = [
            direct(0),
            direct(1),
            direct(2),
            keyword(3, "flag"),
            keyword(4, "trace"),
            keyword(5, "context"),
        ];
        let target = target_for_language(
            brokk_bifrost_core::analyzer::model::Language::Java,
            "com.acme.Api",
            "variadic",
            arguments.len() as u32,
        )
        .with_call_arguments(&arguments);
        let matched = active.procedure_summaries_for_external_target(&target);
        assert_eq!(matched.disposition, SemanticModelMatchDisposition::Unique);
        let binding = matched.records[0]
            .bind_unmaterialized_call_shape(&target)
            .expect("both direct rest domains bind exactly");
        assert_eq!(
            binding.actual_to_formal(),
            Some([0, 1, 1, 2, 3, 3].as_slice())
        );

        let only_required = [direct(6)];
        let target = target_for_language(
            brokk_bifrost_core::analyzer::model::Language::Java,
            "com.acme.Api",
            "variadic",
            only_required.len() as u32,
        )
        .with_call_arguments(&only_required);
        let matched = active.procedure_summaries_for_external_target(&target);
        assert_eq!(matched.disposition, SemanticModelMatchDisposition::Unique);
        let binding = matched.records[0]
            .bind_unmaterialized_call_shape(&target)
            .expect("empty rest collections and defaulted fixed formals are exact");
        assert_eq!(binding.actual_to_formal(), Some([0].as_slice()));

        let no_required = [];
        let target = target_for_language(
            brokk_bifrost_core::analyzer::model::Language::Java,
            "com.acme.Api",
            "variadic",
            0,
        )
        .with_call_arguments(&no_required);
        assert_eq!(
            active
                .procedure_summaries_for_external_target(&target)
                .disposition,
            SemanticModelMatchDisposition::Empty,
            "the summary is not a candidate below its fixed-formal minimum"
        );
    }

    #[test]
    fn equal_version_jdk_artifacts_remain_distinct_after_activation() {
        let source = std::str::from_utf8(PACK)
            .expect("fixture is UTF-8")
            .replace("\"ecosystem\": \"maven\"", "\"ecosystem\": \"jdk\"");
        let compiled = compile_source(
            SourceFormat::Json,
            source.as_bytes(),
            &CompilerOptions::default(),
        )
        .expect("JDK fixture compiles");
        let shard = decode_shard(
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("JDK fixture decodes");
        let evidence = |digest: &str| {
            SemanticModelActivationEvidence {
            language: "java".to_owned(),
            ecosystem: "jdk".to_owned(),
            package: None,
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: "jdk".to_owned(),
                version: Some(Version::parse("21.0.8").expect("valid JDK version")),
            }),
            target: Some("jvm".to_owned()),
            configuration: None,
            production_input_digest: None,
verified_raw_artifacts: (Some(digest.repeat(64))).into_iter().map(|sha256: String| brokk_bifrost_semantic::analyzer::semantic_model::runtime::VerifiedRawArtifact::from_sha256(brokk_bifrost_semantic::analyzer::semantic_model::dependency::DependencyArtifactRole::Reference, brokk_bifrost_semantic::analyzer::semantic_model::ExternalArtifactKind::JavaClassJar, &sha256)).collect(),
        }
        };
        let first = evidence("1");
        let second = evidence("2");
        let matched = strict_activation_match(
            &compiled.manifest,
            shard.activation(),
            &[first.clone(), second.clone()],
            &Version::parse("0.9.0").expect("valid runtime version"),
            brokk_bifrost_analysis::analyzer::semantic_model::model::SemanticPackOrigin::Authored,
        )
        .expect("both JDK artifacts activate this shard");
        assert_eq!(matched.matching_evidence, vec![first, second]);
        assert_eq!(matched.matched_evidence, matched.matching_evidence[1]);
    }

    #[test]
    #[hardwon("#3464: activation omitted JDK artifacts that matched the declared toolchain range")]
    fn jdk_compatibility_is_checked_against_each_matching_artifact() {
        let source = std::str::from_utf8(PACK)
            .expect("fixture is UTF-8")
            .replace("\"ecosystem\": \"maven\"", "\"ecosystem\": \"jdk\"")
            .replace(
                "\"compatibility\": {\"bifrost\": \">=0.8.0, <1.0.0\"}",
                "\"compatibility\": {\"bifrost\": \">=0.8.0, <1.0.0\", \"toolchains\": [{\"name\": \"jdk\", \"requirement\": \">=21.0.0, <22.0.0\"}]}",
            );
        let compiled = compile_source(
            SourceFormat::Json,
            source.as_bytes(),
            &CompilerOptions::default(),
        )
        .expect("version-constrained JDK fixture compiles");
        let shard = decode_shard(
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("JDK fixture decodes");
        let row = |version: &str, digest: &str| {
            SemanticModelActivationEvidence {
            language: "java".to_owned(),
            ecosystem: "jdk".to_owned(),
            package: None,
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: "jdk".to_owned(),
                version: Some(Version::parse(version).expect("valid JDK version")),
            }),
            target: Some("jvm".to_owned()),
            configuration: None,
            production_input_digest: None,
verified_raw_artifacts: (Some(digest.repeat(64))).into_iter().map(|sha256: String| brokk_bifrost_semantic::analyzer::semantic_model::runtime::VerifiedRawArtifact::from_sha256(brokk_bifrost_semantic::analyzer::semantic_model::dependency::DependencyArtifactRole::Reference, brokk_bifrost_semantic::analyzer::semantic_model::ExternalArtifactKind::JavaClassJar, &sha256)).collect(),
        }
        };
        let java21 = row("21.0.8", "1");
        let java22 = row("22.0.1", "2");
        let matched = strict_activation_match(
            &compiled.manifest,
            shard.activation(),
            &[java21.clone(), java22],
            &Version::parse("0.9.0").expect("valid runtime version"),
            brokk_bifrost_analysis::analyzer::semantic_model::model::SemanticPackOrigin::Authored,
        )
        .expect("the JDK 21 artifact activates the shard");
        assert_eq!(matched.matching_evidence, vec![java21]);
    }

    /// A declared toolchain names the coordinate of a pack whose selector also
    /// binds the exact artifact it was produced from. The rejection names that
    /// unmet digest rather than the generic statement (#3464).
    #[test]
    #[hardwon(
        "#3464: artifact-bound selection reported a toolchain name instead of the missing digest"
    )]
    fn a_named_coordinate_without_the_bound_artifact_names_the_missing_digest() {
        let digest = "a".repeat(64);
        let source = std::str::from_utf8(PACK)
            .expect("fixture is UTF-8")
            .replace("\"ecosystem\": \"maven\"", "\"ecosystem\": \"jdk\"")
            .replace(
                "\"compatibility\": {\"bifrost\": \">=0.8.0, <1.0.0\"}",
                "\"compatibility\": {\"bifrost\": \">=0.8.0, <1.0.0\", \"toolchains\": [{\"name\": \"jdk\", \"requirement\": \">=21.0.0, <22.0.0\"}]}",
            )
            .replace(
                "\"activation\": [{}]",
                &format!(
                    "\"activation\": [{{\"toolchain\": {{\"name\": \"jdk\"}}, \
                     \"artifact_sha256\": \"{digest}\"}}]"
                ),
            );
        let compiled = compile_source(
            SourceFormat::Json,
            source.as_bytes(),
            &CompilerOptions::default(),
        )
        .expect("artifact-bound fixture compiles");
        let shard = decode_shard(
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("artifact-bound fixture decodes");
        let declared = SemanticModelActivationEvidence {
            language: "java".to_owned(),
            ecosystem: "jdk".to_owned(),
            package: None,
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: "jdk".to_owned(),
                version: Some(Version::parse("21.0.8").expect("valid JDK version")),
            }),
            target: None,
            configuration: None,
            production_input_digest: None,
            verified_raw_artifacts: Vec::new(),
        };
        assert_eq!(
            strict_activation_mismatch_reason(
                &compiled.manifest,
                shard.activation(),
                std::slice::from_ref(&declared)
            ,brokk_bifrost_analysis::analyzer::semantic_model::model::SemanticPackOrigin::Authored,),
            format!(
                "activation evidence names toolchain jdk, but the shard selector also requires \
                 artifact sha256 {digest}"
            )
        );
    }

    #[test]
    #[hardwon("#3815: schema-8 activation applied the legacy engine-version gate")]
    fn schema8_activation_is_engine_independent_but_keeps_toolchain_and_artifact_checks() {
        let artifact_sha256 = "a".repeat(64);
        let mut source: serde_json::Value = serde_json::from_slice(PACK).unwrap();
        source["schema_version"] = 8.into();
        source["ecosystem"] = "jdk".into();
        source["compatibility"] = serde_json::json!({
            "toolchains": [{
                "name": "jdk",
                "requirement": ">=21.0.0, <22.0.0"
            }]
        });
        source["completeness"] = "partial".into();
        for summary in source["shards"][0]["payload"]["summaries"]
            .as_array_mut()
            .expect("fixture summaries are an array")
        {
            summary["completeness"] = "partial".into();
        }
        source["shards"][0]["activation"] = serde_json::json!([{
            "toolchain": {"name": "jdk", "version": "=21.0.8"},
            "artifact_sha256": artifact_sha256
        }]);

        let compiled = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .expect("schema 8 fixture compiles");
        assert_eq!(compiled.manifest.schema_version, 8);
        assert_eq!(
            compiled.manifest.completeness,
            brokk_bifrost_analysis::analyzer::semantic_model::Completeness::Partial
        );
        assert!(compiled.manifest.compatibility.bifrost.is_none());
        let shard = decode_shard(
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("schema 8 fixture decodes");
        let brokk_bifrost_analysis::analyzer::semantic_model::artifact::CompiledPayload::ProcedureSummaries { summaries } =
            shard.payload()
        else {
            panic!("schema 8 fixture carries procedure summaries");
        };
        assert!(summaries.iter().all(|summary| {
            summary.completeness
                != brokk_bifrost_analysis::analyzer::semantic_model::Completeness::Complete
        }));
        let evidence = |jdk_version: &str, digest: &str| {
            SemanticModelActivationEvidence {
            language: "java".to_owned(),
            ecosystem: "jdk".to_owned(),
            package: None,
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: "jdk".to_owned(),
                version: Some(Version::parse(jdk_version).expect("valid JDK version")),
            }),
            target: Some("jvm".to_owned()),
            configuration: None,
            production_input_digest: None,
verified_raw_artifacts: (Some(digest.to_owned())).into_iter().map(|sha256: String| brokk_bifrost_semantic::analyzer::semantic_model::runtime::VerifiedRawArtifact::from_sha256(brokk_bifrost_semantic::analyzer::semantic_model::dependency::DependencyArtifactRole::Reference, brokk_bifrost_semantic::analyzer::semantic_model::ExternalArtifactKind::JavaClassJar, &sha256)).collect(),
        }
        };

        let matching = evidence("21.0.8", &artifact_sha256);
        assert!(
            strict_activation_match(
                &compiled.manifest,
                shard.activation(),
                std::slice::from_ref(&matching),
                &Version::parse("99.0.0").expect("valid cross-engine version"),
            brokk_bifrost_analysis::analyzer::semantic_model::model::SemanticPackOrigin::Authored,)
            .is_some()
        );
        assert!(
            strict_activation_match(
                &compiled.manifest,
                shard.activation(),
                &[evidence("22.0.1", &artifact_sha256)],
                &Version::parse("99.0.0").expect("valid cross-engine version"),
            brokk_bifrost_analysis::analyzer::semantic_model::model::SemanticPackOrigin::Authored,)
            .is_none()
        );
        assert!(
            strict_activation_match(
                &compiled.manifest,
                shard.activation(),
                &[evidence("21.0.8", &"b".repeat(64))],
                &Version::parse("99.0.0").expect("valid cross-engine version"),
            brokk_bifrost_analysis::analyzer::semantic_model::model::SemanticPackOrigin::Authored,)
            .is_none()
        );

        let mut unknown_schema = compiled.manifest.clone();
        unknown_schema.schema_version =
            brokk_bifrost_analysis::analyzer::semantic_model::model::SEMANTIC_MODEL_SCHEMA_VERSION
                + 1;
        assert!(
            strict_activation_match(
                &unknown_schema,
                shard.activation(),
                std::slice::from_ref(&matching),
                &Version::parse("99.0.0").expect("valid cross-engine version"),
            brokk_bifrost_analysis::analyzer::semantic_model::model::SemanticPackOrigin::Authored,)
            .is_none()
        );
    }

    #[test]
    #[hardwon("74238a905cc7: reviewed JDK fixture omitted the matched call locator")]
    fn reviewed_jdk_result_obligation_requires_the_exact_selected_artifact_and_call_shape() {
        let mut source: serde_json::Value = serde_json::from_slice(PACK).unwrap();
        source["schema_version"] = 5.into();
        source["ecosystem"] = "jdk".into();
        let fixed = &mut source["shards"][0]["payload"]["summaries"][0];
        fixed["ordinary_heap_unchanged"] = true.into();
        fixed["normal_result_count"] = 1.into();
        fixed["result_use_obligations"] = serde_json::json!([{
            "result_ordinal": 0,
            "kind": "pure_transformation_value"
        }]);
        let compiled = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .expect("reviewed JDK obligation compiles");
        let shard = decode_shard(
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("reviewed JDK obligation decodes");
        let evidence = |version: &str, digest: &str| {
            SemanticModelActivationEvidence {
            language: "java".to_owned(),
            ecosystem: "jdk".to_owned(),
            package: None,
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: "jdk".to_owned(),
                version: Some(Version::parse(version).unwrap()),
            }),
            target: Some("jvm".to_owned()),
            configuration: None,
            production_input_digest: None,
verified_raw_artifacts: (Some(digest.repeat(64))).into_iter().map(|sha256: String| brokk_bifrost_semantic::analyzer::semantic_model::runtime::VerifiedRawArtifact::from_sha256(brokk_bifrost_semantic::analyzer::semantic_model::dependency::DependencyArtifactRole::Reference, brokk_bifrost_semantic::analyzer::semantic_model::ExternalArtifactKind::JavaClassJar, &sha256)).collect(),
        }
        };
        let first = evidence("21.0.8", "1");
        let second = evidence("21.0.8", "2");
        let active = {
            let decoded = shard;
            let manifest = Arc::new(compiled.manifest);
            let has_callable_values = decoded.callable_values().is_some();
            ActiveSemanticModelShard {
                metadata: std::sync::Arc::new(
                    crate::analyzer::store::active_models::ActiveSemanticModelShardMetadata {
                        assumed_rust_toolchain: false,
                        descriptor: manifest
                            .shards
                            .iter()
                            .find(|descriptor| descriptor.shard_id == decoded.shard_id())
                            .expect("fixture descriptor exists")
                            .clone(),
                        selectors: decoded.activation().to_vec(),
                        row_store: None,
                        has_callable_values,
                        manifest,
                        approximation: None,
                        source_kind: CatalogPackSourceKind::Embedded,
                        source_id: "test:reviewed-jdk-obligation".to_owned(),
                        matched_evidence: second.clone(),
                        matching_evidence: vec![first.clone(), second.clone()],
                        evidence_rank: EvidenceRank::Language,
                        source_rank: 0,
                        extraction_deferred: false,
                    },
                ),
                decoded: Some(decoded),
            }
        };
        let active = Arc::new(active);
        let payload = active.decoded().payload().procedure_summaries().unwrap();
        let reviewed = ActivatedProcedureSummary {
            record: Arc::clone(&payload[0]),
            shard: Arc::clone(&active),
            actual_to_formal: None,
            matched_owner_identity: None,
            matched_target_locator: Some(target("fixed", 3).locator().clone()),
            matched_call_arguments: None,
        };
        assert_eq!(
            reviewed
                .bind_reviewed_jdk_result_use_obligations(
                    &target("fixed", 3).with_selected_jdk_for_test(first.clone())
                )
                .map(|obligations| obligations.len()),
            Some(1),
            "the non-representative matching artifact is still applicable"
        );
        assert!(
            reviewed
                .bind_reviewed_jdk_result_use_obligations(
                    &target("fixed", 3).with_selected_jdk_for_test(second.clone())
                )
                .is_some()
        );
        for mismatched in [evidence("21.0.8", "3"), evidence("22.0.1", "1")] {
            assert!(
                reviewed
                    .bind_reviewed_jdk_result_use_obligations(
                        &target("fixed", 3).with_selected_jdk_for_test(mismatched)
                    )
                    .is_none(),
                "an unselected digest or a different version has no obligation"
            );
        }
        assert!(
            reviewed
                .bind_reviewed_jdk_result_use_obligations(&target("fixed", 3))
                .is_none(),
            "a name-only target has no resolver-owned JDK artifact"
        );
        assert!(
            reviewed
                .bind_reviewed_jdk_result_use_obligations(
                    &target("fixed", 4).with_selected_jdk_for_test(first.clone())
                )
                .is_none(),
            "artifact equality cannot rescue an inapplicable arity"
        );

        let mut separate = [first.clone(), second.clone()]
            .into_iter()
            .map(|evidence| {
                let decoded = active.decoded().clone();
                let manifest = Arc::clone(&active.manifest);
                let has_callable_values = decoded.callable_values().is_some();
                ActiveSemanticModelShard {
                    metadata: std::sync::Arc::new(
                        crate::analyzer::store::active_models::ActiveSemanticModelShardMetadata {
                            assumed_rust_toolchain: false,
                            descriptor: manifest
                                .shards
                                .iter()
                                .find(|descriptor| descriptor.shard_id == decoded.shard_id())
                                .expect("fixture descriptor exists")
                                .clone(),
                            selectors: decoded.activation().to_vec(),
                            row_store: None,
                            has_callable_values,
                            manifest,
                            approximation: None,
                            source_kind: CatalogPackSourceKind::Embedded,
                            source_id: format!(
                                "test:artifact-{}",
                                evidence.single_raw_sha256().as_deref().unwrap()
                            ),
                            matched_evidence: evidence.clone(),
                            matching_evidence: vec![evidence],
                            evidence_rank: EvidenceRank::Language,
                            source_rank: 0,
                            extraction_deferred: false,
                        },
                    ),
                    decoded: Some(decoded),
                }
            })
            .collect::<Vec<_>>();
        let mut bare_source = source.clone();
        bare_source["shards"][0]["payload"]["summaries"][0]["result_use_obligations"] =
            serde_json::json!([]);
        let bare_compiled = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&bare_source).unwrap(),
            &CompilerOptions::default(),
        )
        .expect("ordinary model without an obligation compiles");
        separate.push({
            let decoded = decode_shard(
                &bare_compiled.shards[0].descriptor,
                &bare_compiled.shards[0].bytes,
                &DecodeLimits::default(),
            )
            .unwrap();
            let manifest = Arc::new(bare_compiled.manifest);
            let has_callable_values = decoded.callable_values().is_some();
            ActiveSemanticModelShard {
                metadata: std::sync::Arc::new(
                    crate::analyzer::store::active_models::ActiveSemanticModelShardMetadata {
                        assumed_rust_toolchain: false,
                        descriptor: manifest
                            .shards
                            .iter()
                            .find(|descriptor| descriptor.shard_id == decoded.shard_id())
                            .expect("fixture descriptor exists")
                            .clone(),
                        selectors: decoded.activation().to_vec(),
                        row_store: None,
                        has_callable_values,
                        manifest,
                        approximation: None,
                        source_kind: CatalogPackSourceKind::Embedded,
                        source_id: "test:higher-rank-unannotated-jdk-summary".to_owned(),
                        matched_evidence: second.clone(),
                        matching_evidence: vec![second.clone()],
                        evidence_rank: EvidenceRank::Language,
                        source_rank: 1,
                        extraction_deferred: false,
                    },
                ),
                decoded: Some(decoded),
            }
        });
        let mut report = SemanticModelActivationReport::default();
        let separate = separate.into_iter().map(Arc::new).collect::<Vec<_>>();
        let indexes = MatcherIndexes::build(
            &separate,
            SemanticModelRuntimeLimits::default(),
            &CancellationToken::default(),
            &mut report,
        )
        .expect("two equal-summary JDK shards index");
        let active_set = ResolvedActiveSemanticModels::new(
            "test:two-jdk-artifacts".to_owned(),
            None,
            separate,
            indexes,
            Vec::new(),
            HashMap::default(),
            Default::default(),
            report,
        );
        let selected = target("fixed", 3).with_selected_jdk_for_test(second.clone());
        let matched = active_set.procedure_summaries_for_selected_jdk_artifact(&selected);
        assert_eq!(matched.disposition, SemanticModelMatchDisposition::Unique);
        assert_eq!(matched.records.len(), 1);
        assert_eq!(matched.records[0].shard.matched_evidence, second);
        assert_eq!(matched.records[0].shard.source_rank, 0);
        assert!(
            matched.records[0]
                .bind_reviewed_jdk_result_use_obligations(&selected)
                .is_some()
        );
        assert_eq!(
            active_set
                .procedure_summaries_for_selected_jdk_artifact(
                    &target("fixed", 3).with_selected_jdk_for_test(evidence("21.0.8", "3"))
                )
                .disposition,
            SemanticModelMatchDisposition::Empty
        );
    }

    #[test]
    fn python_exact_pypi_binding_requires_the_selected_artifact_before_ranking() {
        let selected_evidence = python_evidence('a');
        let other_evidence = python_evidence('b');
        let higher_rank_other_artifact = python_artifact_shard(&other_evidence, 1);
        let lower_rank_selected_artifact = python_artifact_shard(&selected_evidence, 0);
        let shards = vec![higher_rank_other_artifact, lower_rank_selected_artifact];
        let shards = shards.into_iter().map(Arc::new).collect::<Vec<_>>();
        let active = resolved_active_models_fixture("test:two-python-artifacts", shards);
        let selected_target = target_for_language(
            brokk_bifrost_core::analyzer::model::Language::Python,
            "com.acme.Api",
            "fixed",
            3,
        )
        .with_selected_python_for_test(selected_evidence.clone())
        .with_python_model_manifest_for_test(&active.shards[1].manifest.content_sha256);

        let different_model = selected_target
            .clone()
            .with_python_model_manifest_for_test(&"f".repeat(64));
        let rejected = active.procedure_summaries_for_external_target(&different_model);
        assert_eq!(rejected.disposition, SemanticModelMatchDisposition::Empty);
        assert_eq!(
            rejected.applicability,
            ProcedureSummaryApplicability::Incomplete
        );
        let matched = active.procedure_summaries_for_external_target(&selected_target);
        assert_eq!(matched.disposition, SemanticModelMatchDisposition::Unique);
        assert_eq!(matched.records.len(), 1);
        assert_eq!(matched.records[0].shard.matched_evidence, selected_evidence);
        assert_eq!(
            matched.records[0].shard.source_rank, 0,
            "a higher-ranked same-spelling summary for another digest is filtered first"
        );
        assert!(
            matched.records[0]
                .bind_unmaterialized_call_shape(&selected_target)
                .is_some()
        );

        let selected_shard = active
            .shards
            .iter()
            .find(|shard| shard.matched_evidence == selected_evidence)
            .unwrap();
        let payload = selected_shard
            .decoded()
            .payload()
            .procedure_summaries()
            .unwrap();
        let selected_summary = ActivatedProcedureSummary {
            record: Arc::clone(&payload[0]),
            shard: Arc::clone(selected_shard),
            actual_to_formal: None,
            matched_owner_identity: None,
            matched_target_locator: None,
            matched_call_arguments: None,
        };
        let missing_target = target_for_language(
            brokk_bifrost_core::analyzer::model::Language::Python,
            "com.acme.Api",
            "fixed",
            3,
        );
        assert_eq!(
            active
                .procedure_summaries_for_external_target(&missing_target)
                .disposition,
            SemanticModelMatchDisposition::Empty,
            "an exact PyPI shard is not applicable without selected provider evidence"
        );
        assert_ne!(
            active
                .procedure_summaries_for_member(ProcedureSummaryMemberKey::new(
                    "python",
                    "com.acme.Api",
                    "fixed",
                    false,
                    3,
                ))
                .disposition,
            SemanticModelMatchDisposition::Empty,
            "shape-only discovery still sees the active model"
        );
        assert!(
            selected_summary
                .bind_unmaterialized_call_shape(&missing_target)
                .is_none()
        );

        let different_digest_target = target_for_language(
            brokk_bifrost_core::analyzer::model::Language::Python,
            "com.acme.Api",
            "fixed",
            3,
        )
        .with_selected_python_for_test(python_evidence('c'));
        assert_eq!(
            active
                .procedure_summaries_for_external_target(&different_digest_target)
                .disposition,
            SemanticModelMatchDisposition::Empty,
            "same distribution name and version with a different digest is not applicable"
        );
        assert_ne!(
            active
                .procedure_summaries_for_member(ProcedureSummaryMemberKey::new(
                    "python",
                    "com.acme.Api",
                    "fixed",
                    false,
                    3,
                ))
                .disposition,
            SemanticModelMatchDisposition::Empty,
            "a wrong artifact remains distinct from model absence"
        );
        assert!(
            selected_summary
                .bind_unmaterialized_call_shape(&different_digest_target)
                .is_none()
        );
        let other_shard = active
            .shards
            .iter()
            .find(|shard| shard.matched_evidence == other_evidence)
            .unwrap();
        let other_payload = other_shard
            .decoded()
            .payload()
            .procedure_summaries()
            .unwrap();
        let other_summary = ActivatedProcedureSummary {
            record: Arc::clone(&other_payload[0]),
            shard: Arc::clone(other_shard),
            actual_to_formal: None,
            matched_owner_identity: None,
            matched_target_locator: None,
            matched_call_arguments: None,
        };
        assert!(
            other_summary
                .bind_unmaterialized_call_shape(&selected_target)
                .is_none()
        );

        let generic_shard = python_generic_shard();
        let generic_shard = Arc::new(generic_shard);
        let generic_active =
            resolved_active_models_fixture("test:generic-python", vec![generic_shard]);
        let generic_target = target_for_language(
            brokk_bifrost_core::analyzer::model::Language::Python,
            "com.acme.Api",
            "fixed",
            3,
        );
        let generic_match = generic_active.procedure_summaries_for_external_target(&generic_target);
        assert_eq!(
            generic_match.disposition,
            SemanticModelMatchDisposition::Unique
        );
        assert!(
            generic_match.records[0]
                .bind_unmaterialized_call_shape(&generic_target)
                .is_some()
        );
        let generic_target_with_selected_distribution = target_for_language(
            brokk_bifrost_core::analyzer::model::Language::Python,
            "com.acme.Api",
            "fixed",
            3,
        )
        .with_selected_python_for_test(python_evidence('d'));
        let generic_match = generic_active
            .procedure_summaries_for_external_target(&generic_target_with_selected_distribution);
        assert_eq!(
            generic_match.disposition,
            SemanticModelMatchDisposition::Unique
        );
        assert!(
            generic_match.records[0]
                .bind_unmaterialized_call_shape(&generic_target_with_selected_distribution)
                .is_some()
        );
    }

    #[test]
    fn python_same_artifact_requires_the_selected_model_applicability() {
        let evidence = python_evidence('a');
        let compatible = python_artifact_shard(&evidence, 0);

        let mut source: serde_json::Value = serde_json::from_slice(PACK).unwrap();
        source["language"] = "python".into();
        source["ecosystem"] = "python".into();
        source["shards"][0]["activation"] = serde_json::json!([{
            "package": {"name": evidence.package.as_ref().unwrap().name.clone()},
            "artifact_sha256": evidence.single_raw_sha256().as_ref().unwrap().clone(),
        }]);
        source["shards"][0]["payload"]["summaries"][0]["target"]["variadic"] = true.into();
        let incompatible_compiled = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .expect("same-artifact variadic model compiles");
        let incompatible = {
            let decoded = decode_shard(
                &incompatible_compiled.shards[0].descriptor,
                &incompatible_compiled.shards[0].bytes,
                &DecodeLimits::default(),
            )
            .expect("same-artifact variadic model decodes");
            let manifest = Arc::new(incompatible_compiled.manifest);
            let has_callable_values = decoded.callable_values().is_some();
            ActiveSemanticModelShard {
                metadata: std::sync::Arc::new(
                    crate::analyzer::store::active_models::ActiveSemanticModelShardMetadata {
                        assumed_rust_toolchain: false,
                        descriptor: manifest
                            .shards
                            .iter()
                            .find(|descriptor| descriptor.shard_id == decoded.shard_id())
                            .expect("fixture descriptor exists")
                            .clone(),
                        selectors: decoded.activation().to_vec(),
                        row_store: None,
                        has_callable_values,
                        manifest,
                        approximation: None,
                        source_kind: CatalogPackSourceKind::Embedded,
                        source_id: "test:pypi:variadic-model".to_owned(),
                        matched_evidence: evidence.clone(),
                        matching_evidence: vec![evidence.clone()],
                        evidence_rank: EvidenceRank::ExactArtifact,
                        source_rank: 1,
                        extraction_deferred: false,
                    },
                ),
                decoded: Some(decoded),
            }
        };
        assert_eq!(compatible.matching_evidence, incompatible.matching_evidence);
        assert_ne!(
            compatible.manifest.content_sha256, incompatible.manifest.content_sha256,
            "independently compiled payload applicability must identify distinct models"
        );

        let shards = vec![compatible, incompatible];
        let mut report = SemanticModelActivationReport::default();
        let shards = shards.into_iter().map(Arc::new).collect::<Vec<_>>();
        let indexes = MatcherIndexes::build(
            &shards,
            SemanticModelRuntimeLimits::default(),
            &CancellationToken::default(),
            &mut report,
        )
        .expect("same-artifact Python models index");
        let active = ResolvedActiveSemanticModels::new(
            "test:same-python-artifact-two-models".to_owned(),
            None,
            shards,
            indexes,
            Vec::new(),
            HashMap::default(),
            Default::default(),
            report,
        );
        let target_for_model = |manifest: &str| {
            target_for_language(
                brokk_bifrost_core::analyzer::model::Language::Python,
                "com.acme.Api",
                "fixed",
                3,
            )
            .with_selected_python_for_test(evidence.clone())
            .with_python_model_manifest_for_test(manifest)
        };

        let compatible_target = target_for_model(&active.shards[0].manifest.content_sha256);
        let compatible_match = active.procedure_summaries_for_external_target(&compatible_target);
        assert_eq!(
            compatible_match.applicability,
            ProcedureSummaryApplicability::Complete
        );
        assert_eq!(
            compatible_match.disposition,
            SemanticModelMatchDisposition::Unique
        );
        assert_eq!(compatible_match.records.len(), 1);
        assert_eq!(
            compatible_match.records[0].shard.manifest.content_sha256,
            active.shards[0].manifest.content_sha256
        );
        assert!(
            compatible_match.records[0]
                .bind_unmaterialized_call_shape(&compatible_target)
                .is_some()
        );

        let incompatible_target = target_for_model(&active.shards[1].manifest.content_sha256);
        let incompatible_match =
            active.procedure_summaries_for_external_target(&incompatible_target);
        assert_eq!(
            incompatible_match.applicability,
            ProcedureSummaryApplicability::Incomplete
        );
        assert_eq!(
            incompatible_match.disposition,
            SemanticModelMatchDisposition::Empty,
            "the compatible model cannot authorize the same artifact's incompatible model"
        );
        assert!(incompatible_match.records.is_empty());
    }

    #[test]
    fn python_pypi_wildcard_selector_requires_selected_artifact_evidence() {
        let evidence = python_evidence('a');
        let shard = python_pypi_wildcard_shard(&evidence, 0);
        let shard = Arc::new(shard);
        let active = resolved_active_models_fixture("test:pypi-wildcard", vec![shard]);
        let target = target_for_language(
            brokk_bifrost_core::analyzer::model::Language::Python,
            "com.acme.Api",
            "fixed",
            3,
        );

        assert_eq!(
            active
                .procedure_summaries_for_external_target(&target)
                .disposition,
            SemanticModelMatchDisposition::Empty,
            "a package-only PyPI selector cannot bind without selected artifact proof"
        );
        assert_ne!(
            active
                .procedure_summaries_for_member(ProcedureSummaryMemberKey::new(
                    "python",
                    "com.acme.Api",
                    "fixed",
                    false,
                    3,
                ))
                .disposition,
            SemanticModelMatchDisposition::Empty,
            "the active model remains discoverable; only this boundary lacks proof"
        );

        let selected_target = target
            .with_selected_python_for_test(evidence)
            .with_python_model_manifest_for_test(&active.shards[0].manifest.content_sha256);
        assert_eq!(
            active
                .procedure_summaries_for_external_target(&selected_target)
                .disposition,
            SemanticModelMatchDisposition::Unique,
            "the same selector applies once an exact artifact is selected"
        );
    }

    #[test]
    #[hardwon(
        "1a59441d70d0: identity Python argument mappings were rejected when fixed-arity summaries omitted formal rows"
    )]
    fn python_argument_permutations_have_distinct_aliases_and_checked_formals() {
        let evidence = python_evidence('a');
        let shard = python_artifact_shard(&evidence, 0);
        let manifest_sha256 = shard.manifest.content_sha256.clone();
        let mut report = SemanticModelActivationReport::default();
        let shard = Arc::new(shard);
        let indexes = MatcherIndexes::build(
            std::slice::from_ref(&shard),
            SemanticModelRuntimeLimits::default(),
            &CancellationToken::default(),
            &mut report,
        )
        .expect("exact Python summary indexes");
        let active = ResolvedActiveSemanticModels::new(
            "test:python-argument-permutations".to_owned(),
            None,
            vec![shard],
            indexes,
            Vec::new(),
            HashMap::default(),
            Default::default(),
            report,
        );
        let target = || {
            target_for_language(
                brokk_bifrost_core::analyzer::model::Language::Python,
                "com.acme.Api",
                "fixed",
                3,
            )
            .with_selected_python_for_test(evidence.clone())
            .with_python_model_manifest_for_test(&manifest_sha256)
        };
        let positional = target().with_python_mapping_for_test(Some(vec![0, 1, 2]));
        let reordered = target().with_python_mapping_for_test(Some(vec![2, 0, 1]));
        assert_ne!(positional.locator(), reordered.locator());
        let positional_match = active.procedure_summaries_for_external_target(&positional);
        let reordered_match = active.procedure_summaries_for_external_target(&reordered);
        assert_eq!(
            positional_match.disposition,
            SemanticModelMatchDisposition::Unique
        );
        assert_eq!(
            reordered_match.disposition,
            SemanticModelMatchDisposition::Unique
        );
        let positional_binding = positional_match.records[0]
            .bind_unmaterialized_call_shape(&positional)
            .unwrap();
        let reordered_binding = reordered_match.records[0]
            .bind_unmaterialized_call_shape(&reordered)
            .unwrap();
        assert_eq!(
            positional_binding.formal_locator(),
            reordered_binding.formal_locator()
        );
        assert_eq!(
            reordered_binding.actual_to_formal(),
            Some([2, 0, 1].as_slice())
        );
        for mapping in [
            None,
            Some(vec![0, 0, 2]),
            Some(vec![0, 1]),
            Some(vec![0, 1, 3]),
        ] {
            let invalid = target().with_python_mapping_for_test(mapping);
            assert_eq!(
                active
                    .procedure_summaries_for_external_target(&invalid)
                    .disposition,
                SemanticModelMatchDisposition::Empty
            );
        }
        let payload = active.shards[0]
            .decoded()
            .payload()
            .procedure_summaries()
            .unwrap();
        let mut unsupported = payload[0].as_ref().clone();
        unsupported.ordinary_heap_unchanged = true;
        unsupported.preconditions = Some(vec![brokk_bifrost_analysis::analyzer::semantic_model::artifact::CompiledOperationPrecondition {
            input: brokk_bifrost_analysis::analyzer::semantic_model::artifact::CompiledSummaryInput::Parameter { ordinal: 0, path: None },
            predicate: brokk_bifrost_analysis::analyzer::semantic_model::artifact::CompiledResultPredicate::NonNull,
        }]);
        assert!(
            procedure_summary_actual_to_formal(&active.shards[0], &unsupported, &reordered)
                .is_none()
        );
        assert!(
            procedure_summary_actual_to_formal(&active.shards[0], &unsupported, &positional)
                .is_some()
        );
    }

    #[test]
    #[hardwon(
        "d6d760cab6de: Python omitted-default calls must not bind legacy exact-arity summaries"
    )]
    fn python_omitted_default_boundary_is_incomplete_but_full_positional_call_binds() {
        let evidence = python_evidence('a');
        let shard = python_artifact_shard(&evidence, 0);
        let mut report = SemanticModelActivationReport::default();
        let shard = Arc::new(shard);
        let indexes = MatcherIndexes::build(
            std::slice::from_ref(&shard),
            SemanticModelRuntimeLimits::default(),
            &CancellationToken::default(),
            &mut report,
        )
        .expect("exact Python summary indexes");
        let active = ResolvedActiveSemanticModels::new(
            "test:python-formal-shape".to_owned(),
            None,
            vec![shard],
            indexes,
            Vec::new(),
            HashMap::default(),
            Default::default(),
            report,
        );

        let omitted_default = target_for_language(
            brokk_bifrost_core::analyzer::model::Language::Python,
            "com.acme.Api",
            "fixed",
            2,
        )
        .with_python_formal_shape_for_test(evidence.clone(), 3, 2)
        .with_python_model_manifest_for_test(&active.shards[0].manifest.content_sha256);
        assert_eq!(
            active
                .procedure_summaries_for_external_target(&omitted_default)
                .applicability,
            ProcedureSummaryApplicability::Incomplete,
        );
        assert_eq!(
            active
                .procedure_summaries_for_external_target(&omitted_default)
                .disposition,
            SemanticModelMatchDisposition::Empty,
            "the default-omitting call stays an incomplete boundary while the kernel is positional"
        );
        assert_ne!(
            active
                .procedure_summaries_for_member(ProcedureSummaryMemberKey::new(
                    "python",
                    "com.acme.Api",
                    "fixed",
                    false,
                    3,
                ))
                .disposition,
            SemanticModelMatchDisposition::Empty,
            "the activated summary is present and must not be diagnosed as unused"
        );

        let full_positional = target_for_language(
            brokk_bifrost_core::analyzer::model::Language::Python,
            "com.acme.Api",
            "fixed",
            3,
        )
        .with_python_formal_shape_for_test(evidence, 3, 2)
        .with_python_model_manifest_for_test(&active.shards[0].manifest.content_sha256);
        let matched = active.procedure_summaries_for_external_target(&full_positional);
        assert_eq!(matched.disposition, SemanticModelMatchDisposition::Unique);
        assert!(
            matched.records[0]
                .bind_unmaterialized_call_shape(&full_positional)
                .is_some()
        );
    }

    #[test]
    fn call_shape_binding_proves_fixed_and_variadic_applicability() {
        let compiled = compile_source(SourceFormat::Json, PACK, &CompilerOptions::default())
            .expect("the call-shape fixture compiles");
        let artifact = &compiled.shards[0];
        let shard = decode_shard(
            &artifact.descriptor,
            &artifact.bytes,
            &DecodeLimits::default(),
        )
        .expect("the compiled call-shape shard decodes");
        let matched_evidence = SemanticModelActivationEvidence {
            language: "java".to_owned(),
            ecosystem: "maven".to_owned(),
            package: None,
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            production_input_digest: None,
            verified_raw_artifacts: Vec::new(),
        };
        let active_shard = {
            let decoded = shard;
            let manifest = std::sync::Arc::new(compiled.manifest);
            let has_callable_values = decoded.callable_values().is_some();
            ActiveSemanticModelShard {
                metadata: std::sync::Arc::new(
                    crate::analyzer::store::active_models::ActiveSemanticModelShardMetadata {
                        assumed_rust_toolchain: false,
                        descriptor: manifest
                            .shards
                            .iter()
                            .find(|descriptor| descriptor.shard_id == decoded.shard_id())
                            .expect("fixture descriptor exists")
                            .clone(),
                        selectors: decoded.activation().to_vec(),
                        row_store: None,
                        has_callable_values,
                        manifest,
                        approximation: None,
                        source_kind: CatalogPackSourceKind::Embedded,
                        source_id: "test:call-shape".to_owned(),
                        matching_evidence: vec![matched_evidence.clone()],
                        matched_evidence,
                        evidence_rank: EvidenceRank::Language,
                        source_rank: 0,
                        extraction_deferred: false,
                    },
                ),
                decoded: Some(decoded),
            }
        };
        let mut report = SemanticModelActivationReport::default();
        let active_shard = Arc::new(active_shard);
        let indexes = MatcherIndexes::build(
            std::slice::from_ref(&active_shard),
            SemanticModelRuntimeLimits::default(),
            &CancellationToken::default(),
            &mut report,
        )
        .expect("call-shape summary indexes");
        let active = ResolvedActiveSemanticModels::new(
            "test:call-shape".to_owned(),
            None,
            vec![active_shard],
            indexes,
            Vec::new(),
            HashMap::default(),
            Default::default(),
            report,
        );
        let fixed_target = target("fixed", 3);
        let fixed_match = active.procedure_summaries_for_external_target(&fixed_target);
        assert_eq!(
            fixed_match.disposition,
            SemanticModelMatchDisposition::Unique
        );
        let fixed = &fixed_match.records[0];
        assert!(
            fixed
                .bind_unmaterialized_call_shape(&fixed_target)
                .is_some(),
            "a fixed summary proves only its exact actual arity"
        );
        let too_many_fixed_actuals = target("fixed", 4);
        let too_many_match =
            active.procedure_summaries_for_external_target(&too_many_fixed_actuals);
        assert_eq!(
            too_many_match.disposition,
            SemanticModelMatchDisposition::Empty
        );
        assert!(
            fixed
                .bind_unmaterialized_call_shape(&too_many_fixed_actuals)
                .is_none(),
            "an opaque proof cannot be minted to relabel a fixed summary"
        );

        let below_minimum = target("variadic", 1);
        let variadic_low_match = active.procedure_summaries_for_external_target(&below_minimum);
        assert_eq!(
            variadic_low_match.disposition,
            SemanticModelMatchDisposition::Empty
        );
        assert!(
            variadic_low_match.records.is_empty(),
            "an actual arity below the variadic minimum has no proof"
        );
        for arity in [2, 3, 4] {
            let actual = target("variadic", arity);
            let matched = active.procedure_summaries_for_external_target(&actual);
            assert_eq!(matched.disposition, SemanticModelMatchDisposition::Unique);
            let variadic = &matched.records[0];
            let binding = variadic
                .bind_unmaterialized_call_shape(&actual)
                .unwrap_or_else(|| panic!("variadic actual arity {arity} is applicable"));
            assert_eq!(binding.actual_locator(), actual.locator());
            assert_eq!(binding.formal_locator(), &actual.locator_for_arity(3));
            assert_eq!(binding.model_id(), "test.call-shape#summary.variadic");
            assert_eq!(
                binding.content().to_string(),
                variadic.record.content_sha256,
                "the proof binds the exact activated authored body"
            );
            assert_eq!(binding.contract_version(), 1);
            assert!(!binding.covers_overrides());
        }
    }
}

/// The active-set identity is a behavior key, not just a set of semantic
/// payload digests. Two activation contexts can retain the same payloads while
/// assigning their conflicting records opposite matcher precedence.
#[cfg(test)]
pub(crate) mod active_model_set_identity_tests {
    use super::{APPROXIMATE_DISTRIBUTED_SHARDS_ALLOWED, is_distributed_pack_source};

    use crate::analyzer::store::active_models::matcher_posting_admission;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::ActiveSemanticModelShard;
    use sha2::Digest;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::CandidateSelection;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogPackSourceKind;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::EvidenceRank;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::PayloadKind;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::ProcedureSummaryMemberKey;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::ResolvedActiveSemanticModels;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SEMANTIC_MODEL_RUNTIME_REPRESENTATION_VERSION;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelActivationEvidence;

    use sha2::Sha256;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::active_model_set_hash;
    use brokk_bifrost_semantic::analyzer::semantic_model::{
        CatalogCoordinate, RustArtifactApproximation, RustArtifactMismatchKind,
    };

    use brokk_bifrost_analysis::analyzer::semantic_model::compiler::CompilerOptions;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::DecodeLimits;

    use brokk_bifrost_analysis::analyzer::semantic_model::source::SourceFormat;

    use brokk_bifrost_analysis::analyzer::semantic_model::compiler::compile_source;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::decode_shard;

    pub(super) fn procedure_selection(
        pack_id: &str,
        normal_continuation_absent: bool,
        evidence_rank: EvidenceRank,
    ) -> CandidateSelection {
        procedure_selection_at_revision(
            pack_id,
            normal_continuation_absent,
            evidence_rank,
            "reviewed",
        )
    }

    fn procedure_selection_at_revision(
        pack_id: &str,
        normal_continuation_absent: bool,
        evidence_rank: EvidenceRank,
        revision: &str,
    ) -> CandidateSelection {
        let source = serde_json::to_vec(&serde_json::json!({
            "schema_version": 2,
            "pack_id": pack_id,
            "version": "1.0.0",
            "producer": {"name": "active-set-identity-test", "version": "1.0.0"},
            "language": "go",
            "ecosystem": "go",
            "compatibility": {"bifrost": ">=0.10.5, <1.0.0", "toolchains": []},
            "provenance": {"source": "test:active-set-identity", "revision": revision},
            "license": "Apache-2.0",
            "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [{
                "id": "summaries",
                "activation": [{}],
                "payload": {
                    "kind": "procedure_summaries",
                    "summaries": [{
                        "id": format!("{pack_id}.exit"),
                        "target": {
                            "path": "src/os/proc.go",
                            "symbol": "os.Exit(code int)",
                            "has_receiver": false,
                            "parameter_count": 1
                        },
                        "completeness": "complete",
                        "normal_continuation_absent": normal_continuation_absent,
                        "transfers": [],
                        "effects": [{
                            "kind": "unknown_call_boundary",
                            "event": "test.identity.exit-boundary"
                        }]
                    }]
                }
            }]
        }))
        .expect("identity fixture serializes");
        let compiled = compile_source(SourceFormat::Json, &source, &CompilerOptions::default())
            .unwrap_or_else(|diagnostics| panic!("identity fixture failed: {diagnostics:#?}"));
        let descriptor = compiled.shards[0].descriptor.clone();
        let shard = decode_shard(
            &descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("identity fixture decodes");
        let matched_evidence = SemanticModelActivationEvidence {
            language: "go".to_owned(),
            ecosystem: "go".to_owned(),
            package: None,
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            production_input_digest: None,
verified_raw_artifacts: ((evidence_rank == EvidenceRank::ExactArtifact)
                .then(|| "11".repeat(32))).into_iter().map(|sha256: String| brokk_bifrost_semantic::analyzer::semantic_model::runtime::VerifiedRawArtifact::from_sha256(brokk_bifrost_semantic::analyzer::semantic_model::dependency::DependencyArtifactRole::Reference, brokk_bifrost_semantic::analyzer::semantic_model::ExternalArtifactKind::GoSourceSet, &sha256)).collect(),
        };
        CandidateSelection {
            semantic_sha256: descriptor.semantic_sha256,
            payload_kind: descriptor.payload_kind,
            evidence_rank,
            matched_requirements: Vec::new(),
            source_rank: 0,
            extraction_deferred_to: None,
            active: {
                let decoded = shard;
                let manifest = std::sync::Arc::new(compiled.manifest);
                let has_callable_values = decoded.callable_values().is_some();
                ActiveSemanticModelShard {
                    metadata: std::sync::Arc::new(
                        crate::analyzer::store::active_models::ActiveSemanticModelShardMetadata {
                            assumed_rust_toolchain: false,
                            descriptor: manifest
                                .shards
                                .iter()
                                .find(|descriptor| descriptor.shard_id == decoded.shard_id())
                                .expect("fixture descriptor exists")
                                .clone(),
                            selectors: decoded.activation().to_vec(),
                            row_store: None,
                            has_callable_values,
                            manifest,
                            approximation: None,
                            source_kind: CatalogPackSourceKind::Embedded,
                            source_id: format!("test:{pack_id}"),
                            matching_evidence: vec![matched_evidence.clone()],
                            matched_evidence,
                            evidence_rank,
                            source_rank: 0,
                            extraction_deferred: false,
                        },
                    ),
                    decoded: Some(decoded),
                }
            },
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#14077: audit revision rotates the active-set hash and identity keys; the content digest is unchanged"
    )]
    fn audit_revision_rotates_identity_not_content_digest() {
        let at = |revision: &str| {
            procedure_selection_at_revision(
                "test.audit-revision",
                false,
                EvidenceRank::VersionedCoordinate,
                revision,
            )
        };
        let (first, second) = (at("audit-1"), at("audit-2"));
        // Descriptors pin and loading verifies the content digest.
        assert_eq!(first.semantic_sha256, second.semantic_sha256);
        assert_ne!(first.active.identity(), second.active.identity());
        let none = crate::hash::HashSet::default();
        // The policy unit key, class-set keys, ICFG provider identity and
        // Models receipts all derive from this value.
        assert_ne!(
            active_model_set_hash(&[first], &[], &none),
            active_model_set_hash(&[second], &[], &none)
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13674: approximate activations with different typed reasons compose different answers and need different identities"
    )]
    fn active_set_hash_binds_approximation_reasons() {
        use brokk_bifrost_semantic::analyzer::semantic_model::{
            ApproximationReason::{TargetUnknown, ToolchainVersionUnknown},
            ApproximationReasons,
        };
        let hash = |reasons: Option<ApproximationReasons>| {
            let mut selection = procedure_selection(
                "test.approximate-stdlib",
                false,
                EvidenceRank::VersionedCoordinate,
            );
            std::sync::Arc::make_mut(&mut selection.active.metadata).approximation = reasons;
            active_model_set_hash(&[selection], &[], &crate::hash::HashSet::default())
        };
        let exact = hash(None);
        let target = hash(Some(ApproximationReasons::only(TargetUnknown)));
        let both = hash(Some(
            ApproximationReasons::only(TargetUnknown).with(ToolchainVersionUnknown),
        ));
        assert_ne!(exact, target);
        assert_ne!(target, both);
        assert_ne!(exact, both);
        assert_eq!(
            target,
            hash(Some(ApproximationReasons::only(TargetUnknown)))
        );
    }

    #[test]
    fn verified_slots_and_production_digest_change_active_identity() {
        let make_selection = |sha: &str, production: Option<&str>| {
            let mut selection =
                procedure_selection("test.raw-inputs", false, EvidenceRank::ExactArtifact);
            let metadata = std::sync::Arc::make_mut(&mut selection.active.metadata);
            metadata.matched_evidence.verified_raw_artifacts =
                vec![brokk_bifrost_semantic::analyzer::semantic_model::runtime::VerifiedRawArtifact::from_sha256(
                    crate::analyzer::semantic_model::dependency::DependencyArtifactRole::Sources,
                    crate::analyzer::semantic_model::ExternalArtifactKind::GoSourceSet,
                    sha,
                )];
            metadata.matched_evidence.production_input_digest = production.map(str::to_owned);
            metadata.matching_evidence = vec![metadata.matched_evidence.clone()];
            selection
        };
        let hash = |sha: &str, production| {
            active_model_set_hash(
                &[make_selection(sha, production)],
                &[],
                &crate::hash::HashSet::default(),
            )
        };
        assert_ne!(hash(&"a".repeat(64), None), hash(&"b".repeat(64), None));
        assert_ne!(
            hash(&"a".repeat(64), None),
            hash(&"a".repeat(64), Some(&"c".repeat(64)))
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#14133: certified accounting was keyed by the shard digest, so it never reached the active identity"
    )]
    fn partial_pack_accounting_that_names_every_loss_changes_active_identity() {
        let mut partial =
            procedure_selection("test.partial-jdk", false, EvidenceRank::VersionedCoordinate);
        std::sync::Arc::make_mut(
            &mut std::sync::Arc::make_mut(&mut partial.active.metadata).manifest,
        )
        .completeness = crate::analyzer::semantic_model::Completeness::Partial;
        let certified = std::iter::once(partial.active.manifest.semantic_sha256.clone())
            .collect::<crate::hash::HashSet<_>>();
        assert_ne!(
            active_model_set_hash(std::slice::from_ref(&partial), &[], &Default::default()),
            active_model_set_hash(std::slice::from_ref(&partial), &[], &certified),
        );
        let complete = procedure_selection(
            "test.complete-jdk",
            false,
            EvidenceRank::VersionedCoordinate,
        );
        let certified = std::iter::once(complete.active.manifest.semantic_sha256.clone())
            .collect::<crate::hash::HashSet<_>>();
        assert_eq!(
            active_model_set_hash(std::slice::from_ref(&complete), &[], &Default::default()),
            active_model_set_hash(std::slice::from_ref(&complete), &[], &certified),
            "a complete pack keeps its identity bytes",
        );
    }

    #[test]
    fn approximate_artifact_resolved_version_changes_active_identity() {
        assert_eq!(
            active_model_set_hash(
                &[procedure_selection(
                    "test.exact-rust-artifact",
                    false,
                    EvidenceRank::VersionedCoordinate,
                )],
                &[],
                &crate::hash::HashSet::default(),
            ),
            "66fab5f996817c7473c667420348b554a4104aefbdc72e5b390b6a01ad4ba3a4",
            "the exact active set binds the explicit library-none authority",
        );
        let make_selection = |version: &str| {
            let mut selection = procedure_selection(
                "test.approximate-rust-artifact",
                false,
                EvidenceRank::VersionedCoordinate,
            );
            let metadata = std::sync::Arc::make_mut(&mut selection.active.metadata);
            metadata.approximation = Some(brokk_bifrost_semantic::analyzer::semantic_model::ApproximationReasons::only(
                brokk_bifrost_semantic::analyzer::semantic_model::ApproximationReason::DependencyVersionApproximate,
            ));
            std::sync::Arc::make_mut(&mut metadata.manifest)
                .provenance
                .rust_artifact_approximation = Some(RustArtifactApproximation {
                built_from_version: "0.4.23".to_owned(),
                built_from_features: vec!["std".to_owned()],
                built_from_cfgs: vec!["docsrs".to_owned()],
                target: "x86_64-unknown-linux-gnu".to_owned(),
                format_version: 61,
                toolchain: "nightly-2026-08-24".to_owned(),
                docsrs_build: true,
                original_sha256: "11".repeat(32),
                produced_sha256: "11".repeat(32),
                activation_version_requirement: ">=0.4.0, <0.5.0".to_owned(),
                mismatch_kinds: vec![RustArtifactMismatchKind::VersionNearby],
                selection_rule_id: "cargo-compatible-nearest".to_owned(),
                selection_rule_version: 1,
            });
            metadata.matched_evidence.package = Some(CatalogCoordinate {
                name: "widget".to_owned(),
                version: Some(semver::Version::parse(version).unwrap()),
            });
            metadata.matching_evidence = vec![metadata.matched_evidence.clone()];
            selection
        };
        let warm = make_selection("0.4.25");
        let cold = make_selection("0.4.25");
        let changed = make_selection("0.4.26");
        assert_eq!(
            active_model_set_hash(&[warm], &[], &crate::hash::HashSet::default()),
            active_model_set_hash(&[cold], &[], &crate::hash::HashSet::default())
        );
        assert_ne!(
            active_model_set_hash(
                &[make_selection("0.4.25")],
                &[],
                &crate::hash::HashSet::default()
            ),
            active_model_set_hash(&[changed], &[], &crate::hash::HashSet::default()),
        );
        let with_toolchain_claim = |assumed| {
            let mut selection = make_selection("0.4.25");
            let metadata = std::sync::Arc::make_mut(&mut selection.active.metadata);
            metadata.assumed_rust_toolchain = assumed;
            metadata.matched_evidence.toolchain = Some(CatalogCoordinate {
                name: "rust".into(),
                version: Some(semver::Version::parse("1.100.0-nightly").unwrap()),
            });
            metadata.matching_evidence = vec![metadata.matched_evidence.clone()];
            selection
        };
        assert_ne!(
            active_model_set_hash(
                &[with_toolchain_claim(false)],
                &[],
                &crate::hash::HashSet::default()
            ),
            active_model_set_hash(
                &[with_toolchain_claim(true)],
                &[],
                &crate::hash::HashSet::default()
            ),
            "the assumed-toolchain claim is distinct even when artifact approximation already set approximate"
        );
        let baseline = active_model_set_hash(
            &[make_selection("0.4.25")],
            &[],
            &crate::hash::HashSet::default(),
        );
        for edit in 0..4 {
            let mut changed_claim = make_selection("0.4.25");
            let claim = std::sync::Arc::make_mut(
                &mut std::sync::Arc::make_mut(&mut changed_claim.active.metadata).manifest,
            )
            .provenance
            .rust_artifact_approximation
            .as_mut()
            .unwrap();
            match edit {
                0 => claim.built_from_version = "0.4.24".into(),
                1 => claim
                    .mismatch_kinds
                    .push(RustArtifactMismatchKind::FormatConverted),
                2 => claim.selection_rule_id = "another-rule".into(),
                3 => claim.selection_rule_version = 2,
                _ => unreachable!(),
            }
            assert_ne!(
                baseline,
                active_model_set_hash(&[changed_claim], &[], &crate::hash::HashSet::default())
            );
        }
    }

    #[test]
    fn approximate_distributed_source_hold_classifies_every_catalog_source() {
        use CatalogPackSourceKind as Kind;
        const { assert!(!APPROXIMATE_DISTRIBUTED_SHARDS_ALLOWED) };
        for kind in [Kind::Installed, Kind::PreShipped, Kind::Embedded] {
            assert!(is_distributed_pack_source(kind), "{}", kind.as_str());
        }
        for kind in [
            Kind::Generated,
            Kind::WorkspaceProduced,
            Kind::EphemeralWorkspace,
        ] {
            assert!(!is_distributed_pack_source(kind), "{}", kind.as_str());
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10258: conditional facade hash tracks the selected scoped graph"
    )]
    fn cargo_graph_changes_hash_only_for_reexport_schema() {
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            CargoPackageId, CargoResolveEdge, CargoResolveView, CargoSelectedPackage,
            RustCargoArtifactTuple, RustSelectedCargoGraph,
        };
        let graph = |target: &str, unrelated: bool| {
            let mut evidence =
                procedure_selection("test.cargo-hash", false, EvidenceRank::VersionedCoordinate)
                    .active
                    .matched_evidence
                    .clone();
            evidence.language = "rust".into();
            RustSelectedCargoGraph::from_cargo_resolve(CargoResolveView::from_rows(
                vec![CargoSelectedPackage {
                    evidence,
                    package_id: CargoPackageId("facade".into()),
                    artifact: RustCargoArtifactTuple {
                        version: "1.0.0".into(),
                        resolved_features: Vec::new(),
                        artifact_features: Vec::new(),
                        target: "test-target".into(),
                        toolchain: "test-toolchain".into(),
                        format_version: 61,
                        sha256: "11".repeat(32),
                        exact: true,
                    },
                }],
                [CargoResolveEdge {
                    source: CargoPackageId("facade".into()),
                    dependency_name: "sqlx".into(),
                    target: CargoPackageId(target.into()),
                }]
                .into_iter()
                .chain(unrelated.then(|| CargoResolveEdge {
                    source: CargoPackageId("facade".into()),
                    dependency_name: "other".into(),
                    target: CargoPackageId("unrelated".into()),
                }))
                .collect(),
            ))
            .unwrap()
        };
        let first = graph("sqlx-core@1", false);
        let second = graph("sqlx-core@2", false);
        let unrelated = graph("sqlx-core@1", true);
        let ordinary =
            || procedure_selection("test.cargo-hash", false, EvidenceRank::VersionedCoordinate);
        assert_eq!(
            super::active_model_set_hash_with_cargo_graph(
                &[ordinary()],
                &[],
                &crate::hash::HashSet::default(),
                Some(&first)
            ),
            super::active_model_set_hash_with_cargo_graph(
                &[ordinary()],
                &[],
                &crate::hash::HashSet::default(),
                Some(&second)
            )
        );
        assert_eq!(
            active_model_set_hash(&[ordinary()], &[], &crate::hash::HashSet::default()),
            super::active_model_set_hash_with_cargo_graph(
                &[ordinary()],
                &[],
                &crate::hash::HashSet::default(),
                Some(&first)
            ),
        );
        let no_reexports = || {
            let mut selected = ordinary();
            let metadata = std::sync::Arc::make_mut(&mut selected.active.metadata);
            let manifest = std::sync::Arc::make_mut(&mut metadata.manifest);
            manifest.schema_version = 29;
            manifest.language = "rust".into();
            selected
        };
        let feature_changed =
            RustSelectedCargoGraph::from_cargo_resolve(CargoResolveView::from_rows(
                vec![CargoSelectedPackage {
                    evidence: {
                        let mut evidence = no_reexports().active.matched_evidence.clone();
                        evidence.language = "rust".into();
                        evidence
                    },
                    package_id: CargoPackageId("facade".into()),
                    artifact: RustCargoArtifactTuple {
                        version: "1.0.0".into(),
                        resolved_features: vec!["extra".into()],
                        artifact_features: Vec::new(),
                        target: "test-target".into(),
                        toolchain: "test-toolchain".into(),
                        format_version: 61,
                        sha256: "11".repeat(32),
                        exact: true,
                    },
                }],
                vec![CargoResolveEdge {
                    source: CargoPackageId("facade".into()),
                    dependency_name: "sqlx".into(),
                    target: CargoPackageId("sqlx-core@1".into()),
                }],
            ))
            .unwrap();
        assert_eq!(
            super::active_model_set_hash_with_cargo_graph(
                &[no_reexports()],
                &[],
                &crate::hash::HashSet::default(),
                Some(&first)
            ),
            super::active_model_set_hash_with_cargo_graph(
                &[no_reexports()],
                &[],
                &crate::hash::HashSet::default(),
                Some(&second)
            ),
        );
        assert_eq!(
            active_model_set_hash(&[no_reexports()], &[], &crate::hash::HashSet::default()),
            super::active_model_set_hash_with_cargo_graph(
                &[no_reexports()],
                &[],
                &crate::hash::HashSet::default(),
                Some(&first)
            ),
            "no-reexport active identity keeps the pre-graph bytes",
        );
        assert_eq!(
            super::active_model_set_hash_with_cargo_graph(
                &[no_reexports()],
                &[],
                &crate::hash::HashSet::default(),
                Some(&first)
            ),
            super::active_model_set_hash_with_cargo_graph(
                &[no_reexports()],
                &[],
                &crate::hash::HashSet::default(),
                Some(&unrelated)
            ),
        );
        assert_eq!(
            super::active_model_set_hash_with_cargo_graph(
                &[no_reexports()],
                &[],
                &crate::hash::HashSet::default(),
                Some(&first)
            ),
            super::active_model_set_hash_with_cargo_graph(
                &[no_reexports()],
                &[],
                &crate::hash::HashSet::default(),
                Some(&feature_changed)
            ),
            "no-reexport hash must remain byte-identical when Cargo features change",
        );
        let reexport = || {
            let mut selected = no_reexports();
            let metadata = std::sync::Arc::make_mut(&mut selected.active.metadata);
            let manifest = std::sync::Arc::make_mut(&mut metadata.manifest);
            manifest.rust_external_reexports.push(
                brokk_bifrost_semantic::analyzer::semantic_model::RustExternalReexport::ExplicitUse {
                    facade_path: "sqlx::query".into(),
                    use_item_id: 1,
                    target: brokk_bifrost_semantic::analyzer::semantic_model::RustExternalReexportTarget {
                        namespace: None,
                        external_crate_id: 1,
                        external_crate_name: "sqlx_core".into(),
                        item_id: 2,
                        path: vec!["sqlx_core".into(), "query".into()],
                    },
                },
            );
            metadata.matched_evidence.language = "rust".into();
            selected
        };
        assert_ne!(
            super::active_model_set_hash_with_cargo_graph(
                &[reexport()],
                &[],
                &crate::hash::HashSet::default(),
                Some(&first)
            ),
            super::active_model_set_hash_with_cargo_graph(
                &[reexport()],
                &[],
                &crate::hash::HashSet::default(),
                Some(&second)
            )
        );
        assert_ne!(
            super::active_model_set_hash_with_cargo_graph(
                &[reexport()],
                &[],
                &crate::hash::HashSet::default(),
                Some(&first)
            ),
            super::active_model_set_hash_with_cargo_graph(
                &[reexport()],
                &[],
                &crate::hash::HashSet::default(),
                Some(&unrelated)
            ),
            "the conditional hash reads unrelated edges from the same scoped graph",
        );
        let mut truncated = reexport();
        std::sync::Arc::make_mut(
            &mut std::sync::Arc::make_mut(&mut truncated.active.metadata).manifest,
        )
        .rust_external_reexports_truncated = true;
        assert_ne!(
            super::active_model_set_hash_with_cargo_graph(
                &[reexport()],
                &[],
                &crate::hash::HashSet::default(),
                Some(&first)
            ),
            super::active_model_set_hash_with_cargo_graph(
                &[truncated],
                &[],
                &crate::hash::HashSet::default(),
                Some(&first)
            ),
            "the marker changes the active identity even when retained routes stay the same",
        );
        let mut changed_route = reexport();
        let metadata = std::sync::Arc::make_mut(&mut changed_route.active.metadata);
        let manifest = std::sync::Arc::make_mut(&mut metadata.manifest);
        if let brokk_bifrost_semantic::analyzer::semantic_model::RustExternalReexport::ExplicitUse {
            facade_path,
            ..
        } = &mut manifest.rust_external_reexports[0]
        {
            *facade_path = "sqlx::raw_sql".into();
        }
        assert_ne!(
            super::active_model_set_hash_with_cargo_graph(
                &[reexport()],
                &[],
                &crate::hash::HashSet::default(),
                Some(&first)
            ),
            super::active_model_set_hash_with_cargo_graph(
                &[changed_route],
                &[],
                &crate::hash::HashSet::default(),
                Some(&first)
            ),
            "manifest-only route changes must change the active identity"
        );
        let cache = super::SemanticModelRuntimeCache::default();
        cache.install_carried_dependency_evidence(
            false,
            Vec::new(),
            Vec::new(),
            Some(super::ActivationInputs {
                request: super::SemanticModelActivationRequest {
                    host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
                    bifrost_version: semver::Version::new(0, 15, 1),
                    approximate_standard_libraries: Vec::new(),
                    evidence: Vec::new(),
                    controls: Vec::new(),
                    limits: super::SemanticModelRuntimeLimits::default(),
                },
                rust_cargo_graph: Some(first.clone()),
                preparation_failures: Vec::new(),
            }),
            Some(Vec::new()),
            Default::default(),
        );
        let carried = cache
            .carried_activation_inputs()
            .unwrap()
            .rust_cargo_graph
            .unwrap();
        assert_eq!(carried, first);
        assert_eq!(carried.canonical_edges(), first.canonical_edges());
        assert_eq!(
            super::active_model_set_hash_with_cargo_graph(
                &[reexport()],
                &[],
                &crate::hash::HashSet::default(),
                Some(&first)
            ),
            super::active_model_set_hash_with_cargo_graph(
                &[reexport()],
                &[],
                &crate::hash::HashSet::default(),
                Some(&carried)
            ),
        );
    }

    #[test]
    fn exact_model_selection_precedes_approximate_with_equal_evidence_rank() {
        let exact =
            procedure_selection("test.exact-wins", false, EvidenceRank::VersionedCoordinate);
        let mut approximate =
            procedure_selection("test.exact-wins", false, EvidenceRank::VersionedCoordinate);
        std::sync::Arc::make_mut(&mut approximate.active.metadata).approximation = Some(brokk_bifrost_semantic::analyzer::semantic_model::ApproximationReasons::only(
            brokk_bifrost_semantic::analyzer::semantic_model::ApproximationReason::DependencyVersionApproximate,
        ));
        assert_eq!(
            super::compare_selection(&exact, &approximate),
            std::cmp::Ordering::Greater,
        );
    }

    fn legacy_payload_only_hash(active: &[CandidateSelection]) -> String {
        let mut rows = active
            .iter()
            .map(|selection| {
                (
                    selection.semantic_sha256.as_str(),
                    match selection.payload_kind {
                        PayloadKind::DeclarationFacts => 0u8,
                        PayloadKind::GeneratorRules => 1u8,
                        PayloadKind::ProcedureSummaries => 2u8,
                    },
                )
            })
            .collect::<Vec<_>>();
        rows.sort_unstable();
        let mut hasher = Sha256::new();
        hasher.update(b"bifrost.semantic-model.active-set.v1\0");
        hasher.update(SEMANTIC_MODEL_RUNTIME_REPRESENTATION_VERSION.to_be_bytes());
        hasher.update((rows.len() as u64).to_be_bytes());
        for (digest, kind) in rows {
            hasher.update((digest.len() as u64).to_be_bytes());
            hasher.update(digest.as_bytes());
            hasher.update([kind]);
        }
        crate::analyzer::canonical_hash::lower_hex_string(&hasher.finalize().into())
    }

    #[track_caller]
    fn resolved(active: Vec<CandidateSelection>) -> ResolvedActiveSemanticModels {
        let active_model_set_hash =
            active_model_set_hash(&active, &[], &crate::hash::HashSet::default());
        let shards = active
            .into_iter()
            .map(|selection| std::sync::Arc::new(selection.active))
            .collect::<Vec<_>>();
        super::resolved_active_models_fixture(active_model_set_hash, shards)
    }

    #[test]
    fn matcher_posting_admission_tracks_guard_evidence_and_shard_order() {
        fn shards() -> Vec<std::sync::Arc<ActiveSemanticModelShard>> {
            ["test.admission_a", "test.admission_b"]
                .into_iter()
                .map(|id| {
                    std::sync::Arc::new(
                        procedure_selection(id, true, EvidenceRank::Language).active,
                    )
                })
                .collect()
        }

        let original = shards();
        let baseline = matcher_posting_admission(&original);
        let rebuilt = shards();
        let again = matcher_posting_admission(&rebuilt);
        assert_eq!(baseline, again);
        assert!(baseline.agrees_with(again));

        let mut changed_version = shards();
        let metadata = std::sync::Arc::make_mut(
            &mut std::sync::Arc::get_mut(&mut changed_version[0])
                .unwrap()
                .metadata,
        );
        metadata.matched_evidence.toolchain = Some(
            brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCoordinate {
                name: "jdk".to_owned(),
                version: Some("21.0.1".parse().unwrap()),
            },
        );
        let version = matcher_posting_admission(&changed_version);
        assert_ne!(baseline.all, version.all);
        assert!(!baseline.agrees_with(version));

        let mut changed_target = shards();
        let metadata = std::sync::Arc::make_mut(
            &mut std::sync::Arc::get_mut(&mut changed_target[0])
                .unwrap()
                .metadata,
        );
        metadata.matched_evidence.target = Some("linux-x86_64".to_owned());
        let target = matcher_posting_admission(&changed_target);
        assert_ne!(baseline.all, target.all);
        assert!(!baseline.agrees_with(target));

        let mut reordered = shards();
        reordered.swap(0, 1);
        assert_ne!(baseline.all, matcher_posting_admission(&reordered).all);
    }

    #[test]
    fn matcher_posting_admission_curated_part_ignores_generated_shards() {
        fn shards() -> Vec<std::sync::Arc<ActiveSemanticModelShard>> {
            let curated = procedure_selection("test.curated", true, EvidenceRank::Language).active;
            let mut generated =
                procedure_selection("test.generated", true, EvidenceRank::Language).active;
            std::sync::Arc::make_mut(&mut generated.metadata).source_kind =
                CatalogPackSourceKind::Generated;
            vec![std::sync::Arc::new(curated), std::sync::Arc::new(generated)]
        }

        let baseline = matcher_posting_admission(&shards());
        assert_eq!(
            baseline.curated,
            matcher_posting_admission(&shards()).curated
        );

        let mut changed_curated = shards();
        std::sync::Arc::make_mut(
            &mut std::sync::Arc::get_mut(&mut changed_curated[0])
                .unwrap()
                .metadata,
        )
        .matched_evidence
        .target = Some("linux-x86_64".to_owned());
        assert_ne!(
            baseline.curated,
            matcher_posting_admission(&changed_curated).curated
        );

        let mut changed_generated = shards();
        std::sync::Arc::make_mut(
            &mut std::sync::Arc::get_mut(&mut changed_generated[1])
                .unwrap()
                .metadata,
        )
        .matched_evidence
        .target = Some("linux-x86_64".to_owned());
        let changed = matcher_posting_admission(&changed_generated);
        assert_eq!(baseline.curated, changed.curated);
        assert_ne!(baseline.all, changed.all);
    }

    #[test]
    fn value_semantics_schema_rotates_active_set_identity() {
        assert_eq!(SEMANTIC_MODEL_RUNTIME_REPRESENTATION_VERSION, 11);
        let mut previous = Sha256::new();
        previous.update(b"bifrost.semantic-model.active-set.v2\0");
        previous.update(2u32.to_be_bytes());
        previous.update(0u64.to_be_bytes());
        previous.update(0u64.to_be_bytes());
        let previous =
            crate::analyzer::canonical_hash::lower_hex_string(&previous.finalize().into());

        assert_ne!(
            active_model_set_hash(&[], &[], &crate::hash::HashSet::default()),
            previous,
            "schema-v2 value semantics must not reuse the prior runtime identity"
        );
    }

    #[test]
    fn receipt_free_runtime_does_not_reuse_review_receipt_identity() {
        // The previous runtime encoded a receipt byte on each selected shard.
        // Even an empty set, with no such bytes, must miss the old identity.
        let mut previous = Sha256::new();
        previous.update(b"bifrost.semantic-model.active-set.v3\0");
        previous.update(10u32.to_be_bytes());
        previous.update(0u64.to_be_bytes());
        previous.update(0u64.to_be_bytes());
        assert_ne!(
            active_model_set_hash(&[], &[], &crate::hash::HashSet::default()),
            crate::analyzer::canonical_hash::lower_hex_string(&previous.finalize().into())
        );
    }

    #[test]
    fn matcher_precedence_that_reverses_a_proof_changes_active_set_identity() {
        let returning_low = procedure_selection("test.returning", false, EvidenceRank::Language);
        let nonreturn_high =
            procedure_selection("test.nonreturn", true, EvidenceRank::ExactArtifact);
        let returning_high =
            procedure_selection("test.returning", false, EvidenceRank::ExactArtifact);
        let nonreturn_low = procedure_selection("test.nonreturn", true, EvidenceRank::Language);
        let first = vec![returning_low, nonreturn_high];
        let second = vec![returning_high, nonreturn_low];

        assert_eq!(
            legacy_payload_only_hash(&first),
            legacy_payload_only_hash(&second),
            "the v1 payload-only identity misses matcher precedence"
        );
        assert_ne!(
            active_model_set_hash(&first, &[], &crate::hash::HashSet::default()),
            active_model_set_hash(&second, &[], &crate::hash::HashSet::default()),
            "effective activation inputs must distinguish opposite winners"
        );

        let target = ProcedureSummaryMemberKey::new("go", "os", "Exit", false, 1);
        assert!(
            resolved(first).proves_normal_continuation_absent(target),
            "the exact-artifact non-return record wins in the first context"
        );
        assert!(
            !resolved(second).proves_normal_continuation_absent(target),
            "the exact-artifact returning record wins in the second context"
        );
    }
}

#[cfg(test)]
mod model_read_attribution_tests {
    use super::*;
    use crate::analyzer::semantic::StableDigest;
    use crate::analyzer::{AnalyzerQueryScope, MultiAnalyzer, ReadKey, capture_query_reads};
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn published_models_record_the_model_key_on_every_snapshot_hit() {
        let analyzer = MultiAnalyzer::default();
        let caches = analyzer.snapshot_caches().unwrap();
        let mut report = SemanticModelActivationReport::default();
        let indexes = MatcherIndexes::build(
            &[],
            SemanticModelRuntimeLimits::default(),
            &CancellationToken::default(),
            &mut report,
        )
        .unwrap();
        let active = Arc::new(ResolvedActiveSemanticModels::new(
            "test:published-model-key".to_owned(),
            None,
            Vec::new(),
            indexes,
            Vec::new(),
            HashMap::default(),
            Default::default(),
            report,
        ));
        let snapshot = Arc::new(ActiveSemanticModelSnapshot::new(
            active.clone(),
            None,
            None,
            None,
            Arc::new(HashMap::default()),
            None,
        ));
        caches.semantic_models().published.lock().unwrap().snapshot = Some(snapshot.clone());
        for _ in 0..2 {
            let (selected, reads) =
                capture_query_reads(&analyzer, || analyzer.active_semantic_model_snapshot());
            assert!(Arc::ptr_eq(&selected.unwrap(), &snapshot));
            assert_eq!(
                reads.keys(),
                vec![ReadKey::Models(StableDigest::sha256(
                    active.active_model_set_hash()
                ))]
            );
            assert_eq!(reads.unattributed_reads(), 0);
        }
    }

    #[test]
    #[hardwon("#9163: a selected operation mixed a republished model set with its captured set")]
    fn selected_model_scope_keeps_one_publication_and_respects_outer_overrides() {
        let analyzer = MultiAnalyzer::default();
        let caches = analyzer.snapshot_caches().unwrap();
        let make_snapshot = |hash: &str| {
            let mut report = SemanticModelActivationReport::default();
            let indexes = MatcherIndexes::build(
                &[],
                SemanticModelRuntimeLimits::default(),
                &CancellationToken::default(),
                &mut report,
            )
            .unwrap();
            let active = Arc::new(ResolvedActiveSemanticModels::new(
                hash.to_owned(),
                None,
                Vec::new(),
                indexes,
                Vec::new(),
                HashMap::default(),
                Default::default(),
                report,
            ));
            let overlay = Arc::new(
                SemanticModelOverlay::build(
                    &analyzer,
                    &active,
                    &CancellationToken::default(),
                    u64::MAX,
                    &RetentionBudget::for_tests(),
                )
                .unwrap(),
            );
            Arc::new(ActiveSemanticModelSnapshot::new(
                active,
                None,
                Some(overlay),
                Some(SemanticModelOverlayMeasurement::default()),
                Arc::new(HashMap::default()),
                None,
            ))
        };
        let first = make_snapshot("test:one-model-set");
        let second = make_snapshot("test:one-model-set");
        let third = make_snapshot("test:next-model-set");
        let first_overlay = first.semantic_model_overlay().unwrap().clone();
        assert_eq!(
            first.active_models().active_model_set_hash(),
            second.active_models().active_model_set_hash()
        );

        let (_, reads) = capture_query_reads(&analyzer, || {
            let _outer = AnalyzerQueryScope::with_semantic_model_overlay(&analyzer, None);
            let _pin = AnalyzerQueryScope::pin_selected_model_snapshot(&analyzer).unwrap();
        });
        assert!(
            reads.keys().is_empty(),
            "capture and an early exit read no models"
        );

        caches.semantic_models().published.lock().unwrap().snapshot = Some(first.clone());
        let (selected, reads) = capture_query_reads(&analyzer, || {
            let _pin = AnalyzerQueryScope::pin_selected_model_snapshot(&analyzer).unwrap();
            caches.semantic_models().published.lock().unwrap().snapshot = Some(second.clone());
            analyzer.semantic_model_overlay_read().published().unwrap()
        });
        assert!(Arc::ptr_eq(&selected, &first_overlay));
        assert_eq!(
            reads.keys(),
            vec![ReadKey::Models(StableDigest::sha256(
                first.active_models().active_model_set_hash()
            ))]
        );

        caches.semantic_models().published.lock().unwrap().snapshot = Some(first.clone());
        let _outer =
            AnalyzerQueryScope::with_semantic_model_overlay(&analyzer, Some(first_overlay.clone()));
        let _matching = AnalyzerQueryScope::pin_selected_model_snapshot(&analyzer).unwrap();
        assert!(Arc::ptr_eq(
            &analyzer.semantic_model_overlay_read().published().unwrap(),
            &first_overlay
        ));
        drop(_matching);
        caches.semantic_models().published.lock().unwrap().snapshot = Some(second);
        assert!(AnalyzerQueryScope::pin_selected_model_snapshot(&analyzer).is_err());
        drop(_outer);

        let _outer_none = AnalyzerQueryScope::with_semantic_model_overlay(&analyzer, None);
        assert!(AnalyzerQueryScope::pin_selected_model_snapshot(&analyzer).is_err());
        drop(_outer_none);

        let _outer_snapshot =
            AnalyzerQueryScope::with_active_semantic_model_snapshot(&analyzer, None);
        assert!(
            AnalyzerQueryScope::pin_selected_model_snapshot(&analyzer)
                .unwrap()
                .is_none()
        );
        let (selected, reads) =
            capture_query_reads(&analyzer, || analyzer.active_semantic_model_snapshot());
        assert!(selected.is_none());
        assert_eq!(
            reads.keys(),
            vec![ReadKey::Models(
                crate::analyzer::i_analyzer::current_model_set_digest(None)
            )]
        );
        drop(_outer_snapshot);

        caches.semantic_models().published.lock().unwrap().snapshot = Some(third.clone());
        let (selected, reads) = capture_query_reads(&analyzer, || {
            let _pin = AnalyzerQueryScope::pin_selected_model_snapshot(&analyzer).unwrap();
            analyzer.semantic_model_overlay_read().published().unwrap()
        });
        assert!(Arc::ptr_eq(
            &selected,
            third.semantic_model_overlay().unwrap()
        ));
        assert_eq!(
            reads.keys(),
            vec![ReadKey::Models(StableDigest::sha256(
                third.active_models().active_model_set_hash()
            ))],
            "a later operation reads the newly published set"
        );
    }

    #[test]
    fn native_inventory_store_cell_returns_the_bound_capability_on_hits() {
        let analyzer = MultiAnalyzer::default();
        let cache = SemanticModelRuntimeCache::default();
        let store = Arc::new(AnalyzerStore::open_ephemeral().unwrap());
        cache.bind_inventory_store(&store);
        for _ in 0..2 {
            let (selected, reads) =
                capture_query_reads(&analyzer, || cache.native_inventory_store());
            assert!(Arc::ptr_eq(&selected.unwrap(), &store));
            assert!(
                reads.keys().is_empty(),
                "a store capability has no derived answer"
            );
        }
    }
}

#[cfg(test)]
mod graph_identity_memo_tests {
    use super::active_model_set_identity_tests::procedure_selection;
    use super::*;
    use crate::analyzer::MultiAnalyzer;
    use crate::analyzer::semantic_model::{
        CargoPackageId, CargoResolveEdge, CargoResolveView, CargoSelectedPackage, CatalogOptions,
        RustCargoArtifactTuple, RustExternalReexport, RustExternalReexportTarget,
        RustSelectedCargoGraph,
    };
    use brokk_bifrost_test_macros::hardwon;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    fn evidence() -> SemanticModelActivationEvidence {
        let mut evidence =
            procedure_selection("test.graph-memo", false, EvidenceRank::VersionedCoordinate)
                .active
                .matched_evidence
                .clone();
        evidence.language = "rust".into();
        evidence
    }

    fn request(evidence: Vec<SemanticModelActivationEvidence>) -> SemanticModelActivationRequest {
        SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            bifrost_version: Version::new(0, 15, 1),
            approximate_standard_libraries: Vec::new(),
            evidence,
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        }
    }

    #[test]
    #[hardwon(
        "#12435: a later unrelated update must not revive a publication invalidated by a model edit"
    )]
    fn semantic_model_overlay_pending_does_not_revive_after_later_edit() {
        use crate::analyzer::packs_document::{
            WorkspaceActivationSources, WorkspaceActivationUpdateSource,
        };
        use crate::analyzer::{AnalyzerConfig, DependencyPackWorkspaceContext, ProjectFile};
        use std::collections::BTreeSet;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("unrelated.txt"), "before").unwrap();
        let _language =
            crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[Language::Java]);
        std::fs::write(root.join("Main.java"), "class Main {}\n").unwrap();
        let config = AnalyzerConfig::default();
        let packs_config = crate::analyzer::packs_document::parse_workspace_packs_config(
            r#"{"schema_version":1,"ecosystems":[]}"#,
        )
        .unwrap();
        let workspace = crate::analyzer::packs_document::tests::workspace_at(&root, config.clone());
        let catalog =
            Arc::new(SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap());
        let cancellation = CancellationToken::default();
        let mut request = request(vec![evidence()]);
        request.bifrost_version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
        let outcome = workspace.activate_dependency_packs(
            &config,
            &[],
            DependencyPackWorkspaceContext {
                catalog: &catalog,
                persistence: None,
                activation: &request,
                limits: Default::default(),
                cancellation: &cancellation,
            },
        );
        assert!(outcome.complete(), "{outcome:?}");
        // Explicit selection may publish an empty declaration surface.
        assert!(matches!(
            workspace.analyzer().semantic_model_overlay_read(),
            SemanticModelOverlayRead::Published(_)
        ));
        let original = workspace
            .analyzer()
            .active_semantic_model_snapshot()
            .unwrap();
        let source = WorkspaceActivationUpdateSource::new(
            catalog,
            Vec::new(),
            Some(&packs_config),
            workspace.retention_budget(),
        )
        .unwrap();
        let context = || {
            source.context(
                &config,
                WorkspaceActivationSources {
                    catalog_root: &root,
                    workspace_model_root: None,
                    config: Some(&packs_config),
                    intrinsic_shipped_models: false,
                },
                &request.evidence,
                &cancellation,
            )
        };
        std::fs::write(root.join("unrelated.txt"), "after").unwrap();
        let unchanged = workspace.update_with_activation_context(
            &BTreeSet::from([ProjectFile::new(root.clone(), "unrelated.txt")]),
            context(),
        );
        assert!(Arc::ptr_eq(
            &original,
            &unchanged
                .analyzer()
                .active_semantic_model_snapshot()
                .unwrap()
        ));
        std::fs::create_dir_all(root.join(".bifrost/semantic-models")).unwrap();
        std::fs::write(root.join(".bifrost/semantic-models/model.json"), "changed").unwrap();
        let pending = unchanged.update_with_activation_context(
            &BTreeSet::from([ProjectFile::new(
                root.clone(),
                ".bifrost/semantic-models/model.json",
            )]),
            context(),
        );
        assert!(matches!(
            pending.analyzer().semantic_model_overlay_read(),
            SemanticModelOverlayRead::Pending(_)
        ));
        std::fs::write(root.join("unrelated.txt"), "later").unwrap();
        let still_pending = pending.update_with_activation_context(
            &BTreeSet::from([ProjectFile::new(root.clone(), "unrelated.txt")]),
            context(),
        );
        assert!(matches!(
            still_pending.analyzer().semantic_model_overlay_read(),
            SemanticModelOverlayRead::Pending(_)
        ));
    }

    #[test]
    #[hardwon("#12435: failed first activation was reported as no models selected")]
    fn semantic_model_overlay_first_cancelled_activation_stays_pending() {
        let analyzer = MultiAnalyzer::default();
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let outcome = acquire_active_semantic_models(
            &analyzer,
            &catalog,
            None,
            &request(vec![evidence()]),
            &cancellation,
        );
        assert!(
            matches!(
                analyzer.semantic_model_overlay_read(),
                SemanticModelOverlayRead::Pending(_)
            ),
            "{outcome:?}"
        );
    }

    #[test]
    #[hardwon("#12435: selected models with no publication silently read as absent")]
    fn semantic_model_overlay_pending_records_carried_contexts_and_frozen_absence() {
        use crate::analyzer::{AnalyzerQueryScope, QueryReadIncomplete};
        let analyzer = MultiAnalyzer::default();
        assert!(matches!(
            analyzer.semantic_model_overlay_read(),
            SemanticModelOverlayRead::NotSelected
        ));
        let caches = analyzer.snapshot_caches().unwrap();
        let frozen_empty = AnalyzerQueryScope::with_semantic_model_overlay(&analyzer, None);

        caches
            .semantic_models()
            .published
            .lock()
            .unwrap()
            .activation_request = Some(request(vec![evidence()]).into());
        caches
            .semantic_models()
            .published
            .lock()
            .unwrap()
            .models_selected = true;
        assert!(matches!(
            analyzer.semantic_model_overlay_read(),
            SemanticModelOverlayRead::NotSelected
        ));
        drop(frozen_empty);
        let outer = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
        let inner = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
        let _frozen = AnalyzerQueryScope::with_semantic_model_overlay(&analyzer, None);
        caches
            .semantic_models()
            .published
            .lock()
            .unwrap()
            .activation_request = None;

        assert!(analyzer.semantic_model_overlay_read().published().is_none());
        assert_eq!(
            inner.read_completion(),
            Err(QueryReadIncomplete::SemanticModelsPending)
        );
        assert_eq!(
            outer.read_completion(),
            Err(QueryReadIncomplete::SemanticModelsPending)
        );
        assert_eq!(
            QueryReadIncomplete::SemanticModelsPending.label(),
            "semantic_models_pending"
        );
        assert!(
            QueryReadIncomplete::SemanticModelsPending
                .stable_replay_reason()
                .is_none()
        );
    }

    #[test]
    #[hardwon(
        "#12825: a local catalog writer between key capture and retention could certify stale Full models"
    )]
    fn local_catalog_write_refuses_retention_and_recomputes_full_activation() {
        use super::super::catalog::{DurablePackSource, DurablePackSourceKind};
        use crate::analyzer::{AnalyzerConfig, DependencyPackWorkspaceContext, WorkspaceAnalyzer};
        let root = tempfile::tempdir().unwrap();
        let delegate = crate::analyzer::packs_document::tests::CatalogWorkspace {
            project: Arc::new(crate::TestProject::new(root.path(), Language::Java)),
            language: Language::Java,
            index: None,
            definitions: Vec::new(),
            complete_symbol_index: false,
        };
        let workspace = WorkspaceAnalyzer::Multi(Box::new(MultiAnalyzer::new(
            std::collections::BTreeMap::from([(
                Language::Java,
                crate::analyzer::multi_analyzer::AnalyzerDelegate::new(delegate),
            )]),
        )));
        let (catalog, _) = super::super::catalog::go_extraction_support_22::install_fixture();
        let config = AnalyzerConfig::default();
        let request = request(Vec::new());
        let cancellation = CancellationToken::default();
        let context = || DependencyPackWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &request,
            limits: Default::default(),
            cancellation: &cancellation,
        };
        let first = workspace.activate_dependency_packs(&config, &[], context());
        assert!(first.complete());
        let original = workspace
            .analyzer()
            .active_semantic_model_snapshot()
            .unwrap();
        let cache = workspace
            .analyzer()
            .snapshot_caches()
            .unwrap()
            .semantic_models();
        let inputs = ActivationInputs::from(request.clone());
        let key = DependencyActivationKey::new(&config, &[], &context(), &inputs, cache).unwrap();
        assert!(
            cache
                .reuse_dependency_activation(
                    Some(&key),
                    &cancellation,
                    workspace.analyzer(),
                    &catalog,
                    &[crate::analyzer::DependencyPackEcosystem::Jvm],
                    |_| panic!(
                        "matching normalized keys cannot authorize different discovery work"
                    ),
                )
                .is_none()
        );
        let before = catalog.cache_identity().unwrap();
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    assert!(
                        catalog
                            .remove_source(&DurablePackSource {
                                kind: DurablePackSourceKind::Installed,
                                source_id: "callable-values-fixture-second".to_owned(),
                            })
                            .unwrap()
                    );
                })
                .join()
                .unwrap();
        });
        let after = catalog.cache_identity().unwrap();
        assert_eq!(before.sqlite_data_version, after.sqlite_data_version);
        assert!(before.mutation_generation < after.mutation_generation);
        assert!(
            cache
                .reuse_dependency_activation(
                    Some(&key),
                    &cancellation,
                    workspace.analyzer(),
                    &catalog,
                    &[],
                    |_| panic!("a stale key must not reach republication"),
                )
                .is_none()
        );
        cache
            .published
            .lock()
            .unwrap()
            .completed_dependency_activation = None;
        cache.retain_dependency_activation(None, Some(key), &first, &catalog, Some(&before));
        assert!(
            cache
                .published
                .lock()
                .unwrap()
                .completed_dependency_activation
                .is_none()
        );
        assert!(
            workspace
                .activate_dependency_packs(&config, &[], context())
                .complete()
        );
        let recomputed = workspace
            .analyzer()
            .active_semantic_model_snapshot()
            .unwrap();
        assert!(!Arc::ptr_eq(&original, &recomputed));
        assert!(
            workspace
                .activate_dependency_packs(&config, &[], context())
                .complete()
        );
        assert!(Arc::ptr_eq(
            &recomputed,
            &workspace
                .analyzer()
                .active_semantic_model_snapshot()
                .unwrap()
        ));
        let warm = workspace.activate_dependency_packs(&config, &[], context());
        assert!(matches!(
            warm.runtime,
            Some(SemanticModelRuntimeOutcome::Ready {
                lifecycle: SemanticModelRuntimeLifecycle::Cached,
                ..
            })
        ));
    }

    #[test]
    #[hardwon(
        "#12825: a local catalog writer between key capture and retention could certify stale Full models"
    )]
    fn own_publication_then_local_writer_refuses_retention_and_recomputes_full_activation() {
        use super::super::catalog::{DurablePackSource, DurablePackSourceKind};
        use crate::analyzer::{AnalyzerConfig, DependencyPackWorkspaceContext, WorkspaceAnalyzer};
        let root = tempfile::tempdir().unwrap();
        let delegate = crate::analyzer::packs_document::tests::CatalogWorkspace {
            project: Arc::new(crate::TestProject::new(root.path(), Language::Java)),
            language: Language::Java,
            index: None,
            definitions: Vec::new(),
            complete_symbol_index: false,
        };
        let workspace = WorkspaceAnalyzer::Multi(Box::new(MultiAnalyzer::new(
            std::collections::BTreeMap::from([(
                Language::Java,
                crate::analyzer::multi_analyzer::AnalyzerDelegate::new(delegate),
            )]),
        )));
        let (catalog, _) = super::super::catalog::go_extraction_support_22::install_fixture();
        let config = AnalyzerConfig::default();
        let request = request(Vec::new());
        let cancellation = CancellationToken::default();
        let context = || DependencyPackWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &request,
            limits: Default::default(),
            cancellation: &cancellation,
        };
        let first = workspace.activate_dependency_packs(&config, &[], context());
        assert!(first.complete());
        let original = workspace
            .analyzer()
            .active_semantic_model_snapshot()
            .unwrap();
        let cache = workspace
            .analyzer()
            .snapshot_caches()
            .unwrap()
            .semantic_models();
        let inputs = ActivationInputs::from(request.clone());
        catalog.with_activation_publication(|| {
            assert!(
                catalog
                    .remove_source(&DurablePackSource {
                        kind: DurablePackSourceKind::Installed,
                        source_id: "callable-values-fixture".to_owned(),
                    })
                    .unwrap()
            );
            let (_, expected) = catalog.activation_publication_identity().unwrap();
            assert_eq!(expected, Some(catalog.cache_identity().unwrap()));
            let key =
                DependencyActivationKey::new(&config, &[], &context(), &inputs, cache).unwrap();
            let before = catalog.cache_identity().unwrap();
            cache
                .published
                .lock()
                .unwrap()
                .completed_dependency_activation = None;
            std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        assert!(
                            catalog
                                .remove_source(&DurablePackSource {
                                    kind: DurablePackSourceKind::Installed,
                                    source_id: "callable-values-fixture-second".to_owned(),
                                })
                                .unwrap()
                        );
                    })
                    .join()
                    .unwrap();
            });
            let after = catalog.cache_identity().unwrap();
            assert_eq!(before.sqlite_data_version, after.sqlite_data_version);
            assert!(before.mutation_generation < after.mutation_generation);
            cache.retain_dependency_activation(None, Some(key), &first, &catalog, Some(&before));
            assert!(
                cache
                    .published
                    .lock()
                    .unwrap()
                    .completed_dependency_activation
                    .is_none()
            );
        });
        assert!(
            workspace
                .activate_dependency_packs(&config, &[], context())
                .complete()
        );
        let recomputed = workspace
            .analyzer()
            .active_semantic_model_snapshot()
            .unwrap();
        assert!(!Arc::ptr_eq(&original, &recomputed));
        assert!(
            workspace
                .activate_dependency_packs(&config, &[], context())
                .complete()
        );
        assert!(Arc::ptr_eq(
            &recomputed,
            &workspace
                .analyzer()
                .active_semantic_model_snapshot()
                .unwrap()
        ));
    }

    #[test]
    #[hardwon("#11890: retained complete activation results bypassed the memory budget")]
    fn dependency_activation_outcome_obeys_budget_and_releases_its_charge() {
        use crate::analyzer::{
            AnalyzerConfig, DependencyPackActivationOutcome, DependencyPackWorkspaceContext,
        };
        let analyzer = MultiAnalyzer::default();
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let request = request(Vec::new());
        let cancellation = CancellationToken::default();
        let outcome = DependencyPackActivationOutcome {
            ecosystems: Vec::new(),
            runtime: Some(acquire_active_semantic_models(
                &analyzer,
                &catalog,
                None,
                &request,
                &cancellation,
            )),
            diagnostic_refresh_required: true,
        };
        assert!(outcome.complete());
        let context = DependencyPackWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &request,
            limits: super::super::DependencyPackLimits::default(),
            cancellation: &cancellation,
        };
        let inputs = ActivationInputs::from(request.clone());
        for capacity in [0, 1024 * 1024] {
            let budget = RetentionBudget::for_test_capacity(capacity);
            let cache = SemanticModelRuntimeCache::new(&budget);
            let key = || {
                DependencyActivationKey::new(
                    &AnalyzerConfig::default(),
                    &[],
                    &context,
                    &inputs,
                    &cache,
                )
            };
            cache.retain_dependency_activation(
                key(),
                key(),
                &outcome,
                &catalog,
                catalog.cache_identity().ok().as_ref(),
            );
            assert_eq!(
                cache
                    .published
                    .lock()
                    .unwrap()
                    .completed_dependency_activation
                    .is_some(),
                capacity > 0
            );
            assert_eq!(
                cache
                    .published
                    .lock()
                    .unwrap()
                    .completed_dependency_activation
                    .as_ref()
                    .is_some_and(|(_, same_generation, _, _)| same_generation.is_some()),
                capacity > 0
            );
            assert_eq!(budget.occupied_bytes() > 0, capacity > 0);
            cache.clear_dependency_activation();
            assert_eq!(budget.occupied_bytes(), 0);
        }
    }

    fn graph(core: &str) -> RustSelectedCargoGraph {
        RustSelectedCargoGraph::from_cargo_resolve(CargoResolveView::from_rows(
            vec![CargoSelectedPackage {
                evidence: evidence(),
                package_id: CargoPackageId("facade".into()),
                artifact: RustCargoArtifactTuple {
                    version: "1.0.0".into(),
                    resolved_features: Vec::new(),
                    artifact_features: Vec::new(),
                    target: "test-target".into(),
                    toolchain: "test-toolchain".into(),
                    format_version: 61,
                    sha256: "11".repeat(32),
                    exact: true,
                },
            }],
            vec![CargoResolveEdge {
                source: CargoPackageId("facade".into()),
                dependency_name: "sqlx".into(),
                target: CargoPackageId(core.into()),
            }],
        ))
        .unwrap()
    }

    fn reexport_selection() -> CandidateSelection {
        let mut selected =
            procedure_selection("test.graph-memo", false, EvidenceRank::VersionedCoordinate);
        let metadata = Arc::make_mut(&mut selected.active.metadata);
        let manifest = Arc::make_mut(&mut metadata.manifest);
        manifest.schema_version = 29;
        manifest.language = "rust".into();
        manifest
            .rust_external_reexports
            .push(RustExternalReexport::ExplicitUse {
                facade_path: "sqlx::query".into(),
                use_item_id: 1,
                target: RustExternalReexportTarget {
                    namespace: None,
                    external_crate_id: 1,
                    external_crate_name: "sqlx_core".into(),
                    item_id: 2,
                    path: vec!["sqlx_core".into(), "query".into()],
                },
            });
        metadata.matched_evidence.language = "rust".into();
        selected
    }

    /// A resolution that selects one reexport-bearing Rust shard, so the
    /// active-set identity reads `graph`, and counts how often it runs.
    fn acquire(
        analyzer: &MultiAnalyzer,
        catalog: &SemanticPackCatalog,
        request: &SemanticModelActivationRequest,
        graph: &RustSelectedCargoGraph,
        resolves: &AtomicUsize,
    ) -> String {
        let outcome = acquire_with_resolution(
            analyzer,
            catalog,
            None,
            request,
            Some(graph),
            None,
            RuntimeArtifactPublication::default(),
            &[],
            &CancellationToken::default(),
            None,
            || {
                resolves.fetch_add(1, AtomicOrdering::SeqCst);
                let selection = reexport_selection();
                let hash = active_model_set_hash_with_cargo_graph(
                    std::slice::from_ref(&selection),
                    &[],
                    &crate::hash::HashSet::default(),
                    Some(graph),
                );
                SemanticModelResolutionOutcome::Ready(resolved_active_models_fixture(
                    hash,
                    vec![Arc::new(selection.active)],
                ))
            },
        );
        let SemanticModelRuntimeOutcome::Ready { active, .. } = outcome else {
            panic!("activation must be ready: {outcome:?}");
        };
        active.active_model_set_hash().to_owned()
    }

    #[test]
    #[hardwon(
        "#10258: a Cargo activation resolved before every snapshot-cache lookup, even on a hit"
    )]
    fn repeat_cargo_activation_does_not_resolve_and_input_changes_do() {
        let analyzer = MultiAnalyzer::default();
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let resolves = AtomicUsize::new(0);
        let first = graph("sqlx-core@1");
        let second = graph("sqlx-core@2");
        let request = request(vec![evidence()]);

        let first_hash = acquire(&analyzer, &catalog, &request, &first, &resolves);
        assert_eq!(resolves.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(
            acquire(&analyzer, &catalog, &request, &first, &resolves),
            first_hash
        );
        assert_eq!(
            resolves.load(AtomicOrdering::SeqCst),
            1,
            "identical inputs must not resolve again"
        );

        // A different graph is a different identity and must resolve.
        let second_hash = acquire(&analyzer, &catalog, &request, &second, &resolves);
        assert_eq!(resolves.load(AtomicOrdering::SeqCst), 2);
        assert_ne!(second_hash, first_hash);
        assert_eq!(
            acquire(&analyzer, &catalog, &request, &first, &resolves),
            first_hash,
            "the first graph's identity is still remembered"
        );
        assert_eq!(resolves.load(AtomicOrdering::SeqCst), 2);

        // Different evidence is a different request.
        let mut other = evidence();
        other.target = Some("other-target".into());
        let other_request = request_with_extra(&request, other);
        acquire(&analyzer, &catalog, &other_request, &first, &resolves);
        assert_eq!(resolves.load(AtomicOrdering::SeqCst), 3);
    }

    fn request_with_extra(
        base: &SemanticModelActivationRequest,
        extra: SemanticModelActivationEvidence,
    ) -> SemanticModelActivationRequest {
        let mut evidence = base.evidence.clone();
        evidence.push(extra);
        request(evidence)
    }

    #[test]
    fn unfinished_resolution_is_not_remembered() {
        let analyzer = MultiAnalyzer::default();
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let resolves = AtomicUsize::new(0);
        let graph = graph("sqlx-core@1");
        let request = request(vec![evidence()]);
        for expected in 1..=2 {
            let outcome = acquire_with_resolution(
                &analyzer,
                &catalog,
                None,
                &request,
                Some(&graph),
                None,
                RuntimeArtifactPublication::default(),
                &[],
                &CancellationToken::default(),
                None,
                || {
                    resolves.fetch_add(1, AtomicOrdering::SeqCst);
                    SemanticModelResolutionOutcome::Cancelled(
                        SemanticModelActivationReport::default(),
                    )
                },
            );
            assert!(matches!(outcome, SemanticModelRuntimeOutcome::Cancelled(_)));
            assert_eq!(resolves.load(AtomicOrdering::SeqCst), expected);
        }
    }

    #[test]
    #[hardwon(
        "#9559: preparation failure records and carried copies exceeded activation memory limits"
    )]
    fn preparation_failures_respect_activation_memory_limit() {
        use brokk_bifrost_semantic::analyzer::semantic_model::dependency::{
            DependencyPreparationFailureCause, RecordedPreparationFailure, ResolvedDependency,
        };
        let analyzer = MultiAnalyzer::default();
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let mut request = request(vec![]);
        request.limits.max_retained_bytes = 1024;
        let failure = RecordedPreparationFailure {
            dependency: ResolvedDependency::undeclared_scope(
                "dependency".repeat(1024),
                evidence(),
                vec![],
                vec![],
            ),
            cause: DependencyPreparationFailureCause::ProducerFailed,
            inputs: brokk_bifrost_semantic::analyzer::semantic_model::dependency::PreparationFailureInputs::Bound(vec![]),
        };
        let outcome = acquire_with_resolution(
            &analyzer,
            &catalog,
            None,
            &request,
            None,
            None,
            RuntimeArtifactPublication::default(),
            &[failure],
            &CancellationToken::default(),
            None,
            || {
                SemanticModelResolutionOutcome::Ready(resolved_active_models_fixture(
                    "same-active-set",
                    vec![],
                ))
            },
        );
        assert!(
            matches!(outcome, SemanticModelRuntimeOutcome::Unavailable(_)),
            "{outcome:?}"
        );
    }

    #[test]
    #[hardwon("#9559: repaired preparation must miss the activation cache and clear old failures")]
    fn repaired_preparation_misses_activation_cache() {
        use brokk_bifrost_semantic::analyzer::semantic_model::dependency::{
            DependencyPreparationFailureCause, RecordedPreparationFailure, ResolvedDependency,
        };
        let analyzer = MultiAnalyzer::default();
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let request = request(vec![]);
        let failure = RecordedPreparationFailure {
            dependency: ResolvedDependency::undeclared_scope(
                "dependency".into(),
                evidence(),
                vec![],
                vec![],
            ),
            cause: DependencyPreparationFailureCause::ProducerFailed,
            inputs: brokk_bifrost_semantic::analyzer::semantic_model::dependency::PreparationFailureInputs::Bound(vec![]),
        };
        let resolves = AtomicUsize::new(0);
        for (failures, expected_resolves) in [(vec![failure], 1), (vec![], 2), (vec![], 2)] {
            let outcome = acquire_with_resolution(
                &analyzer,
                &catalog,
                None,
                &request,
                None,
                None,
                RuntimeArtifactPublication::default(),
                &failures,
                &CancellationToken::default(),
                None,
                || {
                    resolves.fetch_add(1, AtomicOrdering::SeqCst);
                    SemanticModelResolutionOutcome::Ready(resolved_active_models_fixture(
                        "same-active-set",
                        vec![],
                    ))
                },
            );
            let SemanticModelRuntimeOutcome::Ready { active, .. } = outcome else {
                panic!("activation must be ready: {outcome:?}");
            };
            assert_eq!(active.preparation_failures, failures);
            assert_eq!(active.active_model_set_hash(), "same-active-set");
            assert_eq!(resolves.load(AtomicOrdering::SeqCst), expected_resolves);
        }
    }

    #[test]
    fn graph_digest_follows_the_graph_data_the_identity_reads() {
        let request = request(vec![evidence()]);
        let digest = |graph: &RustSelectedCargoGraph| cargo_graph_digest(graph, &request);
        assert_eq!(digest(&graph("sqlx-core@1")), digest(&graph("sqlx-core@1")));
        assert_ne!(digest(&graph("sqlx-core@1")), digest(&graph("sqlx-core@2")));
    }

    #[test]
    #[hardwon("#13182: a stored no_models status hid active models from an earlier publication")]
    fn a_stored_complete_status_must_match_the_served_publication() {
        use crate::analyzer::AnalyzerQueryScope;
        use crate::analyzer::semantic_model::{
            SemanticModelActivationInput, SemanticModelActivationRead, SemanticModelOverlayStatus,
        };
        let stored = |status: &SemanticModelOverlayStatus, analyzer: &dyn IAnalyzer| {
            SemanticModelActivationRead::reduce(SemanticModelActivationInput::Stored {
                status,
                analyzer,
            })
        };
        let analyzer = MultiAnalyzer::default();

        // An analyzer that serves no publication.
        let read = stored(&SemanticModelOverlayStatus::Ready, &analyzer);
        assert!(
            matches!(
                read.status(),
                SemanticModelOverlayStatus::Unavailable { .. }
            ),
            "{:?}",
            read.status()
        );
        let read = stored(&SemanticModelOverlayStatus::NoModels, &analyzer);
        assert_eq!(read.status(), &SemanticModelOverlayStatus::NoModels);

        // The analyzer still serves an earlier publication with active models,
        // and a later activation that published nothing stored `no_models`.
        let selection = procedure_selection(
            "test.stored-status",
            false,
            EvidenceRank::VersionedCoordinate,
        );
        let served = Arc::new(ActiveSemanticModelSnapshot::new(
            Arc::new(resolved_active_models_fixture(
                "test:stored-status",
                vec![Arc::new(selection.active)],
            )),
            None,
            None,
            None,
            Arc::new(HashMap::default()),
            None,
        ));
        let _served = AnalyzerQueryScope::with_active_semantic_model_snapshot(
            &analyzer,
            Some(Arc::clone(&served)),
        );
        let read = stored(&SemanticModelOverlayStatus::NoModels, &analyzer);
        assert!(
            matches!(
                read.status(),
                SemanticModelOverlayStatus::Unavailable { .. }
            ),
            "{:?}",
            read.status()
        );
        assert!(!read.is_model_complete());
        assert!(
            read.snapshot()
                .is_some_and(|snapshot| Arc::ptr_eq(snapshot, &served)),
            "the answer keeps the publication the analyzer serves"
        );
        let read = stored(&SemanticModelOverlayStatus::Ready, &analyzer);
        assert_eq!(read.status(), &SemanticModelOverlayStatus::Ready);
    }
}

#[cfg(test)]
mod assumed_toolchain_tests {
    use super::*;
    use crate::analyzer::semantic_model::*;
    use brokk_bifrost_test_macros::hardwon;
    use serde_json::json;
    use std::cell::{Cell, RefCell};

    fn pack(id: &str, version: &str, activation: serde_json::Value) -> serde_json::Value {
        json!({
            "schema_version": 2, "pack_id": id, "version": version,
            "producer": {"name": "test-only", "version": "1.0.0"},
            "language": "rust", "ecosystem": "cargo", "compatibility": {"bifrost":"*", "toolchains":[{"name":"rust", "requirement":"=1.100.0-nightly"}]},
            "provenance": {"source": "test-only shared toolchain review regression"},
            "license": "NOASSERTION", "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [{"id": "main", "activation": activation, "payload": {
                "kind": "declaration_facts", "types": [{
                    "id": format!("{id}.marker"), "name": format!("{id}.Marker"),
                    "type_kind": "struct", "visibility": "public",
                    "locator": {"kind":"artifact", "path":"fixture.json", "symbol":id}
                }], "members": [], "relations": []
            }}]
        })
    }

    /// This inventory is deliberately test-only: a host pin, not a pack label,
    /// supplies its authority. No fixture is added to a product catalog.
    fn approval_for(
        pack: &artifact::CompiledSemanticModelPack,
    ) -> (tempfile::TempDir, Arc<HostActivationContext>) {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().canonicalize().unwrap();
        let inventory = FirstPartyReleaseInventoryDocument::new(vec![FirstPartyApprovedRelease {
            channel: FirstPartyReleaseChannel::PublicSemanticPacks,
            repository: FirstPartyReleaseChannel::PublicSemanticPacks
                .repository()
                .into(),
            tag: "test-only/14134".into(),
            archive_sha256: "a".repeat(64),
            manifests: vec![FirstPartyApprovedManifest {
                object_sha256: artifact::content_digest(&pack.manifest_bytes),
                content_sha256: pack.manifest.content_sha256.clone(),
                semantic_sha256: pack.manifest.semantic_sha256.clone(),
                shards: pack
                    .manifest
                    .shards
                    .iter()
                    .map(|shard| FirstPartyApprovedShard {
                        shard_id: shard.shard_id.clone(),
                        stored_sha256: shard.stored_sha256.clone(),
                        content_sha256: shard.content_sha256.clone(),
                        semantic_sha256: shard.semantic_sha256.clone(),
                    })
                    .collect(),
            }],
        }])
        .unwrap();
        let bytes = serde_json::to_vec(&inventory).unwrap();
        let path = root.join("inventory.json");
        std::fs::write(&path, &bytes).unwrap();
        let verified = VerifiedFirstPartyReleaseInventory::load_host_pinned_unbound(
            &path,
            &artifact::content_digest(&bytes),
        )
        .unwrap();
        let host = HostActivationContext::from_inventory(
            verified,
            &crate::retention_budget::RetentionBudget::for_tests(),
        )
        .unwrap();
        (scratch, host)
    }

    #[test]
    fn first_party_approval_requires_exact_content_and_preserves_disable_and_applicability() {
        let mut source = pack(
            "test.first-party",
            "1.0.0",
            json!([{"toolchain":{"name":"rust","version":"=1.100.0-nightly"}}]),
        );
        source["safety"]["review_required"] = true.into();
        let compiled = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let (_authority, approved) = approval_for(&compiled);
        assert!(approved.approves_validated_manifest(&compiled.manifest));
        let copy = compiled.clone();
        assert!(
            approved.approves_validated_manifest(&copy.manifest),
            "byte-identical copies have the same publication content"
        );
        source["shards"][0]["payload"]["types"][0]["name"] = "test.first-party.Changed".into();
        let changed = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        assert!(
            !approved.approves_validated_manifest(&changed.manifest),
            "a first-party-looking name or source cannot approve changed payload"
        );
        let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
        catalog
            .register_session_pack(
                &compiled,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test-only-untrusted-label".into(),
                },
            )
            .unwrap();
        let control = |action| SemanticModelActivationControl {
            scope: SemanticModelControlScope::Workspace,
            action,
            selector: SemanticModelPackSelector {
                pack_id: "test.first-party".into(),
                version: None,
                manifest_digest: None,
            },
        };
        let mut request = SemanticModelActivationRequest {
            host_activation: HostActivationContext::library_none(),
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            evidence: vec![SemanticModelActivationEvidence {
                language: "rust".into(),
                ecosystem: "cargo".into(),
                toolchain: Some(CatalogCoordinate {
                    name: "rust".into(),
                    version: Some(Version::parse("1.100.0-nightly").unwrap()),
                }),
                package: None,
                module: None,
                target: None,
                configuration: None,
                production_input_digest: None,
                verified_raw_artifacts: Vec::new(),
            }],
            approximate_standard_libraries: Vec::new(),
            controls: Vec::new(),
            limits: Default::default(),
        };
        let resolve =
            |request: &SemanticModelActivationRequest| match resolve_active_semantic_models(
                &catalog,
                request,
                &CancellationToken::default(),
            ) {
                SemanticModelResolutionOutcome::Ready(active) => active,
                other => panic!("expected complete resolution: {other:?}"),
            };
        let dormant = resolve(&request);
        assert!(dormant.shards().is_empty());
        assert!(
            dormant
                .activation_report()
                .explanations
                .iter()
                .any(|row| row.status == SemanticModelActivationStatus::ReviewRequired)
        );
        request
            .controls
            .push(control(SemanticModelControlAction::Enable));
        let explicit = resolve(&request);
        assert_eq!(explicit.shards().len(), 1);
        request.host_activation = Arc::clone(&approved);
        request.controls.clear();
        let active = resolve(&request);
        assert_eq!(active.shards().len(), 1);
        assert_ne!(
            explicit.active_model_set_hash(),
            active.active_model_set_hash(),
            "same selected models still bind distinct host authority"
        );
        assert_eq!(
            active.activation_report().host_activation.as_deref(),
            approved.metadata().as_ref()
        );
        assert!(
            active
                .activation_report()
                .explanations
                .iter()
                .any(|row| row.reason.contains("verified host inventory approval"))
        );
        let default_limits = request.limits;
        request.limits.max_retained_bytes = explicit.retained_bytes();
        assert!(
            matches!(
                resolve_active_semantic_models(&catalog, &request, &CancellationToken::default()),
                SemanticModelResolutionOutcome::Unavailable(_)
            ),
            "the authority diagnostic's retained bytes must fit before Ready is returned"
        );
        request.limits = default_limits;
        request
            .controls
            .push(control(SemanticModelControlAction::Disable));
        let disabled = resolve(&request);
        assert!(
            disabled.shards().is_empty(),
            "host authority cannot override explicit disable"
        );
        assert_ne!(
            dormant.active_model_set_hash(),
            disabled.active_model_set_hash(),
            "even the empty active set binds A"
        );
        request.controls.clear();
        request.evidence[0].toolchain.as_mut().unwrap().version =
            Some(Version::parse("1.99.1").unwrap());
        assert!(
            resolve(&request).shards().is_empty(),
            "approval cannot bypass exact toolchain compatibility"
        );
        // Shared #13869(d) guard: a specifically requested but uncovered std
        // capability reports installed/review-required under an unpinned
        // toolchain; an unrequested optional pack remains dormant and silent.
        let mut optional = pack("test.optional", "1.0.0", json!([{}]));
        optional["compatibility"] = json!({"bifrost":"*"});
        optional["safety"]["review_required"] = true.into();
        let optional = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&optional).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        catalog
            .register_session_pack(
                &optional,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test-only optional".into(),
                },
            )
            .unwrap();
        request.host_activation = HostActivationContext::library_none();
        request.evidence[0].toolchain = None;
        request
            .approximate_standard_libraries
            .push(ApproximateSemanticModelExpectation {
                reasons: ApproximationReasons::only(ApproximationReason::ToolchainVersionUnknown),
                language: "rust".into(),
                ecosystem: "cargo".into(),
                selection: ApproximateStandardLibrarySelection::Pack("test.first-party".into()),
                toolchain: Some("rust".into()),
            });
        let uncovered = resolve(&request);
        assert!(uncovered.shards().is_empty());
        let report = uncovered.activation_report();
        assert!(
            report
                .explanations
                .iter()
                .any(|row| row.pack_id.as_deref() == Some("test.first-party")
                    && row.status == SemanticModelActivationStatus::ReviewRequired)
        );
        assert!(
            report
                .explanations
                .iter()
                .all(|row| row.pack_id.as_deref() != Some("test.optional"))
        );
    }

    #[test]
    #[hardwon(
        "#12360: plain pins need strict target-free activation and only missing-target approximation"
    )]
    fn plain_pin_preserves_strict_activation_and_bounds_approximation() {
        for (bound, version, target, expected) in [
            (false, "1.100.0-nightly", None, Some(false)),
            (true, "1.100.0-nightly", None, Some(true)),
            (true, "1.99.0", None, None),
            (
                true,
                "1.100.0-nightly",
                Some("aarch64-unknown-linux-gnu"),
                None,
            ),
            (
                true,
                "1.100.0-nightly",
                Some("x86_64-unknown-linux-gnu"),
                Some(false),
            ),
        ] {
            let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
            let mut selector = json!({"toolchain":{"name":"rust", "version":"=1.100.0-nightly"}});
            if bound {
                selector["targets"] = json!(["x86_64-unknown-linux-gnu"]);
            }
            let source = pack("test.stdlib", "1.0.0", json!([selector]));
            let compiled = compile_source(
                SourceFormat::Json,
                &serde_json::to_vec(&source).unwrap(),
                &CompilerOptions::default(),
            )
            .unwrap();
            catalog
                .register_session_pack(
                    &compiled,
                    &SessionPackSource {
                        kind: SessionPackSourceKind::Embedded,
                        source_id: "test-only-stdlib".into(),
                    },
                )
                .unwrap();
            let mut request = SemanticModelActivationRequest {
                host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
                bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "rust".into(),
                    ecosystem: "cargo".into(),
                    package: None,
                    module: None,
                    toolchain: Some(CatalogCoordinate {
                        name: "rust".into(),
                        version: Some(Version::parse(version).unwrap()),
                    }),
                    target: target.map(str::to_owned),
                    configuration: None,
                    production_input_digest: None,
                    verified_raw_artifacts: Vec::new(),
                }],
                approximate_standard_libraries: vec![ApproximateSemanticModelExpectation { reasons: brokk_bifrost_semantic::analyzer::semantic_model::ApproximationReasons::only(brokk_bifrost_semantic::analyzer::semantic_model::ApproximationReason::TargetUnknown),
                    language: "rust".into(),
                    ecosystem: "cargo".into(),
                    selection: ApproximateStandardLibrarySelection::Pack("test.stdlib".into()),
                    toolchain: Some("rust".into()),
                }],
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            };
            let outcome =
                resolve_active_semantic_models(&catalog, &request, &CancellationToken::new());
            let active = match &outcome {
                SemanticModelResolutionOutcome::Ready(active) => Some(active),
                SemanticModelResolutionOutcome::Incomplete { usable, .. } => usable.as_ref(),
                _ => None,
            };
            let selected =
                active.and_then(|active| active.shards().first().map(|shard| shard.approximate()));
            assert_eq!(
                selected, expected,
                "bound={bound}, version={version}, target={target:?}: {outcome:#?}"
            );
            if expected == Some(true) {
                // The typed reasons are exactly the expectation's: the
                // runtime carries discovery's decision and adds none.
                assert_eq!(
                    active.and_then(|active| active.shards().first().map(|shard| shard.approximation)),
                    Some(Some(
                        brokk_bifrost_semantic::analyzer::semantic_model::ApproximationReasons::only(
                            brokk_bifrost_semantic::analyzer::semantic_model::ApproximationReason::TargetUnknown,
                        )
                    )),
                    "bound={bound}, version={version}, target={target:?}"
                );
            }
            if !bound {
                request.approximate_standard_libraries.clear();
                let SemanticModelResolutionOutcome::Ready(baseline) =
                    resolve_active_semantic_models(&catalog, &request, &CancellationToken::new())
                else {
                    panic!("target-free baseline must be ready")
                };
                assert_eq!(
                    active.unwrap().active_model_set_hash(),
                    baseline.active_model_set_hash()
                );
            }
        }
    }

    fn artifact_model(id: &str, toolchain_keyed: bool) -> serde_json::Value {
        let mut artifact = pack(id, "9.8.7", json!([{"package":{"name":"widget"}}]));
        artifact["schema_version"] = 28.into();
        artifact["compatibility"] = json!({"toolchains":[]});
        artifact["provenance"]["rust_artifact_approximation"] =
            serde_json::to_value(RustArtifactApproximation {
                built_from_version: "1.0.1".into(),
                built_from_features: vec!["std".into()],
                built_from_cfgs: vec!["docsrs".into()],
                target: "x86_64-unknown-linux-gnu".into(),
                format_version: 61,
                toolchain: "nightly-2026-08-24".into(),
                docsrs_build: true,
                original_sha256: "11".repeat(32),
                produced_sha256: "11".repeat(32),
                activation_version_requirement: ">=1.0.0, <2.0.0".into(),
                mismatch_kinds: vec![RustArtifactMismatchKind::VersionNearby],
                selection_rule_id: "cargo-compatible-nearest".into(),
                selection_rule_version: 1,
            })
            .unwrap();
        if toolchain_keyed {
            artifact["compatibility"]["toolchains"] =
                json!([{"name":"rust","requirement":"=1.100.0-nightly"}]);
            artifact["shards"][0]["activation"][0]["toolchain"] =
                json!({"name":"rust","version":"=1.100.0-nightly"});
        }
        artifact
    }

    #[test]
    #[hardwon(
        "#11114: partial stdlib selection admitted a toolchain assumption; manifest constraints and exact alternatives were mishandled"
    )]
    fn shared_toolchain_requires_complete_selection_and_preserves_exact_alternatives() {
        for case in [
            "transient-load",
            "single-load",
            "manifest",
            "versionless",
            "independent-artifact",
            "independent-artifact-pinned",
            "dual-artifact",
            "no-stdlib",
            "no-companion",
            "exact-pinned-alternative",
        ] {
            let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
            let mut stdlib = pack(
                "test.stdlib",
                "9.8.7",
                json!([{"toolchain":{"name":"rust","version":"=1.100.0-nightly"}}]),
            );
            if matches!(case, "transient-load" | "single-load") {
                let mut other = stdlib["shards"][0].clone();
                other["id"] = "other".into();
                other["activation"][0]["toolchain"]["version"] = if case == "transient-load" {
                    "=1.99.0"
                } else {
                    "=1.100.0-nightly"
                }
                .into();
                other["payload"]["types"][0]["id"] = "other.marker".into();
                other["payload"]["types"][0]["name"] = "other.Marker".into();
                stdlib["shards"].as_array_mut().unwrap().push(other);
            }
            let mut companion = pack(
                "test.companion",
                "9.8.7",
                json!([{"toolchain":{"name":"rust","version":"=1.100.0-nightly"}}]),
            );
            if case == "manifest" {
                companion["compatibility"]["toolchains"] =
                    json!([{"name":"rust","requirement":"=1.100.0-nightly"}]);
                companion["shards"][0]["activation"] = json!([{}]);
            } else if case == "exact-pinned-alternative" {
                companion["shards"][0]["activation"] = json!([
                    {"package":{"name":"widget","version":"=1.0.0"}},
                    {"toolchain":{"name":"rust","version":"=1.99.0"}}
                ]);
            }
            let mut models = Vec::new();
            if case != "no-stdlib" {
                models.push(stdlib);
            }
            if case != "no-companion" {
                models.push(companion);
            }
            if case == "exact-pinned-alternative" {
                models.push(pack("test.companion", "8.0.0", json!([{}])));
            }
            if case.starts_with("independent-artifact") {
                for id in ["test.independent-artifact", "test.blocked-artifact"] {
                    let artifact = artifact_model(id, false);
                    models.push(artifact);
                }
            }
            if case == "dual-artifact" {
                models.push(artifact_model("test.dual-artifact", true));
            }
            for model in models {
                let compiled = compile_source(
                    SourceFormat::Json,
                    &serde_json::to_vec(&model).unwrap(),
                    &CompilerOptions::default(),
                )
                .unwrap();
                catalog
                    .register_session_pack(
                        &compiled,
                        &SessionPackSource {
                            kind: if matches!(
                                compiled.manifest.pack_id.as_str(),
                                "test.independent-artifact" | "test.dual-artifact"
                            ) {
                                SessionPackSourceKind::EphemeralWorkspace
                            } else {
                                SessionPackSourceKind::Embedded
                            },
                            source_id: format!(
                                "{}@{}",
                                compiled.manifest.pack_id, compiled.manifest.version
                            ),
                        },
                    )
                    .unwrap();
            }
            let request = SemanticModelActivationRequest {
                host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
                bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
                approximate_standard_libraries: vec![ApproximateSemanticModelExpectation { reasons: brokk_bifrost_semantic::analyzer::semantic_model::ApproximationReasons::only(brokk_bifrost_semantic::analyzer::semantic_model::ApproximationReason::TargetUnknown),
                    language: "rust".into(),
                    ecosystem: "cargo".into(),
                    selection: ApproximateStandardLibrarySelection::Pack("test.stdlib".into()),
                    toolchain: Some("rust".into()),
                }],
                evidence: vec![SemanticModelActivationEvidence {
                    language: "rust".into(),
                    ecosystem: "cargo".into(),
                    package: Some(CatalogCoordinate {
                        name: "widget".into(),
                        version: Some(Version::new(1, 0, 0)),
                    }),
                    module: None,
                    toolchain: matches!(
                        case,
                        "exact-pinned-alternative"
                            | "versionless"
                            | "independent-artifact"
                            | "independent-artifact-pinned"
                            | "dual-artifact"
                    )
                    .then(|| CatalogCoordinate {
                        name: "rust".into(),
                        version: matches!(
                            case,
                            "exact-pinned-alternative" | "independent-artifact-pinned"
                        )
                        .then(|| Version::parse("1.100.0-nightly").unwrap()),
                    }),
                    target: (case.starts_with("independent-artifact") || case == "dual-artifact")
                        .then(|| "x86_64-unknown-linux-gnu".into()),
                    configuration: None,
                    production_input_digest: None,
                    verified_raw_artifacts: Vec::new(),
                }],
                controls: ["test.stdlib", "test.companion"]
                    .into_iter()
                    .map(|pack_id| SemanticModelActivationControl {
                        scope: SemanticModelControlScope::Workspace,
                        action: SemanticModelControlAction::Enable,
                        selector: SemanticModelPackSelector {
                            pack_id: pack_id.into(),
                            version: None,
                            manifest_digest: None,
                        },
                    })
                    .collect(),
                limits: SemanticModelRuntimeLimits::default(),
            };
            let missing_loads = Cell::new(0);
            let load_counts = RefCell::new(BTreeMap::new());
            let sql_start = catalog.sql_statement_count();
            let result = resolve_active_semantic_models_with_loader(
                &catalog,
                &request,
                None,
                &CancellationToken::default(),
                |candidate| {
                    let key = (
                        candidate.manifest_digest().to_owned(),
                        candidate.shard_id().to_owned(),
                        candidate.source_kind(),
                        candidate.source_id().to_owned(),
                    );
                    let mut counts = load_counts.borrow_mut();
                    let count = counts.entry(key).or_insert(0usize);
                    *count += 1;
                    assert_eq!(
                        *count, 1,
                        "each candidate is hydrated once, including stdlib and missing/unused companions"
                    );
                    drop(counts);
                    if candidate.shard_id() == "other" {
                        missing_loads.set(missing_loads.get() + 1);
                        if case == "transient-load" && missing_loads.get() == 1 {
                            return Err(CatalogMiss::NotFound);
                        }
                    }
                    catalog.load_decoded_for_test(candidate)
                },
            );
            let active = match &result {
                SemanticModelResolutionOutcome::Ready(active) => active,
                SemanticModelResolutionOutcome::Incomplete {
                    usable: Some(active),
                    ..
                } => active,
                _ => panic!("{case}: {result:#?}"),
            };
            assert_eq!(
                active.report.phase_measurements.catalog_sql_statements,
                catalog.sql_statement_count().saturating_sub(sql_start),
                "all catalog work must be reported, including choosing the stdlib assumption"
            );
            let shards = active.shards();
            let companion = shards
                .iter()
                .find(|shard| shard.manifest.pack_id == "test.companion");
            assert_eq!(
                active.report.loaded_shards,
                load_counts.borrow().values().sum::<usize>()
                    - usize::from(case == "transient-load"),
                "the report accounts for every successful hydration"
            );
            if let Some(companion) = companion {
                assert_eq!(
                    companion.assumed_rust_toolchain,
                    case != "exact-pinned-alternative" && case != "independent-artifact-pinned"
                );
            }
            if case == "dual-artifact" {
                let dual = shards
                    .iter()
                    .find(|shard| shard.manifest.pack_id == "test.dual-artifact")
                    .unwrap();
                assert!(dual.assumed_rust_toolchain && dual.approximate());
                assert!(
                    dual.manifest
                        .provenance
                        .rust_artifact_approximation
                        .is_some()
                );
                assert_eq!(
                    dual.matched_evidence
                        .toolchain
                        .as_ref()
                        .unwrap()
                        .version
                        .as_ref()
                        .unwrap()
                        .to_string(),
                    "1.100.0-nightly"
                );
            }
            if case == "transient-load" {
                assert!(
                    matches!(result, SemanticModelResolutionOutcome::Incomplete { .. }),
                    "{result:#?}"
                );
                assert_eq!(
                    missing_loads.get(),
                    1,
                    "an incomplete preselection must not be retried using a partial assumption"
                );
                assert!(companion.is_none(), "{result:#?}");
            } else if case.starts_with("independent-artifact") {
                assert!(
                    matches!(result, SemanticModelResolutionOutcome::Incomplete { .. }),
                    "{result:#?}"
                );
                assert_eq!(
                    companion.is_some(),
                    case == "independent-artifact-pinned",
                    "only the shared assumption was withdrawn"
                );
                let independent = shards
                    .iter()
                    .find(|shard| shard.manifest.pack_id == "test.independent-artifact")
                    .unwrap_or_else(|| {
                        panic!("independent package match was removed: {result:#?}")
                    });
                assert!(independent.approximate());
                assert!(!independent.assumed_rust_toolchain);
                assert_eq!(
                    independent
                        .matched_evidence
                        .toolchain
                        .as_ref()
                        .unwrap()
                        .version
                        .is_some(),
                    case == "independent-artifact-pinned"
                );
                assert!(
                    active
                        .report
                        .explanations
                        .iter()
                        .filter(|explanation| explanation.pack_id.as_deref()
                            == Some("test.independent-artifact")
                            && explanation.status == SemanticModelActivationStatus::Active)
                        .all(|explanation| !explanation.reason.contains("assumed rust toolchain")),
                    "independent attribution must not claim a shared assumption"
                );
                assert!(
                    independent
                        .manifest
                        .provenance
                        .rust_artifact_approximation
                        .is_some()
                );
                assert!(active.report.explanations.iter().any(|explanation| {
                    explanation.pack_id.as_deref() == Some("test.blocked-artifact")
                        && explanation.status
                            == SemanticModelActivationStatus::ApproximateDistributedBlocked
                }));
            } else if matches!(case, "no-stdlib" | "no-companion") {
                assert!(companion.is_none(), "{case}: {result:#?}");
            } else {
                let companion = companion.unwrap_or_else(|| panic!("{case}: {result:#?}"));
                assert_eq!(companion.manifest.version, "9.8.7", "{case}");
                assert_eq!(
                    companion.approximate(),
                    case != "exact-pinned-alternative",
                    "{case}"
                );
            }
        }
    }
}

fn preparation_failures_digest(
    failures: &[brokk_bifrost_semantic::analyzer::semantic_model::dependency::RecordedPreparationFailure],
) -> String {
    crate::analyzer::canonical_hash::lower_hex_string(
        &brokk_bifrost_semantic::analyzer::semantic_model::dependency::preparation_failures_digest(
            failures,
        ),
    )
}

#[cfg(test)]
mod activation_read_tests {
    use super::*;
    use crate::analyzer::semantic_model::{
        DependencyDiscoveryOutcome, SemanticModelActivationInput, SemanticModelActivationRead,
        SemanticModelOverlayStatus, SemanticModelWarmStage,
    };
    use crate::analyzer::{
        AnalyzerConfig, DependencyPackEcosystem, DependencyPackEcosystemOutcome,
    };

    fn ecosystem_outcome(discovery: DependencyDiscoveryOutcome) -> DependencyPackEcosystemOutcome {
        DependencyPackEcosystemOutcome {
            ecosystem: DependencyPackEcosystem::Npm,
            discovery,
            preparation: None,
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13182: failed preparation with no runtime was reported as no models"
    )]
    fn a_missing_runtime_with_failed_preparation_is_unavailable() {
        use crate::analyzer::semantic_model::dependency::{
            DependencyPackPreparationOutcome, DependencyPreparationFailure,
            DependencyPreparationFailureCause,
        };
        let mut outcome = ecosystem_outcome(DependencyDiscoveryOutcome::complete(Vec::new()));
        outcome.preparation = Some(DependencyPackPreparationOutcome {
            failures: vec![DependencyPreparationFailure {
                dependency_id: "declared".to_owned(),
                cause: DependencyPreparationFailureCause::ProducerFailed,
            }],
            packs: Vec::new(),
            installed_packs: Vec::new(),
            evidence: Vec::new(),
            diagnostics: Vec::new(),
            suppressed_diagnostics: Default::default(),
            complete: false,
            cancelled: false,
            profile: Default::default(),
        });
        let read = SemanticModelActivationRead::reduce(SemanticModelActivationInput::Runtime {
            ecosystems: &[outcome],
            runtime: None,
        });
        assert!(
            matches!(read.status(), SemanticModelOverlayStatus::Unavailable { reason, .. } if reason.contains("npm preparation") && reason.contains("ProducerFailed"))
        );
    }

    /// `publish_dependency_pack_activation` returns no runtime both when
    /// discovery finished with nothing to publish and when discovery was cut
    /// short, because both leave the dependency set empty. Only the first is
    /// "no models".
    #[test]
    fn a_missing_runtime_is_no_models_only_when_discovery_finished() {
        let status = |outcome: DependencyDiscoveryOutcome| {
            SemanticModelActivationRead::reduce(SemanticModelActivationInput::Runtime {
                ecosystems: &[ecosystem_outcome(outcome)],
                runtime: None,
            })
            .into_parts()
            .1
        };
        assert_eq!(
            status(DependencyDiscoveryOutcome::complete(Vec::new())),
            SemanticModelOverlayStatus::NoModels
        );
        let incomplete = status(DependencyDiscoveryOutcome::generation_listing_unavailable(
            &CancellationToken::default(),
        ));
        let SemanticModelOverlayStatus::Unavailable { reason, .. } = incomplete else {
            panic!("incomplete discovery is not NoModels: {incomplete:?}");
        };
        assert!(
            reason.contains("npm") && reason.contains("GenerationListingUnavailable"),
            "{reason}"
        );
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        let cancelled_status = status(DependencyDiscoveryOutcome::generation_listing_unavailable(
            &cancelled,
        ));
        assert!(
            matches!(&cancelled_status, SemanticModelOverlayStatus::Unavailable { reason, .. } if reason.contains("cancelled")),
            "{cancelled_status:?}"
        );
    }

    /// An absent publication is `NoModels` only when the analyzer proves no
    /// models were selected; selected-but-unpublished stays pending.
    #[test]
    fn a_detached_capture_never_turns_pending_into_no_models() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let _language = crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::Java,
        ]);
        std::fs::write(root.join("Main.java"), "class Main {}\n").unwrap();
        let workspace =
            crate::analyzer::packs_document::tests::workspace_at(&root, AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        let control = SemanticModelActivationRead::capture(analyzer);
        assert_eq!(control.status(), &SemanticModelOverlayStatus::NoModels);
        assert!(control.snapshot().is_none());

        analyzer
            .snapshot_caches()
            .unwrap()
            .semantic_models()
            .published
            .lock()
            .unwrap()
            .models_selected = true;
        let pending = SemanticModelActivationRead::capture(analyzer);
        assert!(
            matches!(
                pending.status(),
                SemanticModelOverlayStatus::Pending {
                    stage: SemanticModelWarmStage::SelectedNotPublished,
                    ..
                }
            ),
            "{:?}",
            pending.status()
        );
        assert!(!pending.is_model_complete());
        assert!(pending.snapshot().is_none());
    }
}
