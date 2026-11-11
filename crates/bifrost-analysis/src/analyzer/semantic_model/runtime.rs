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
use crate::hash::{HashMap, map_with_capacity};
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

/// One immutable semantic-model publication captured under the runtime's
/// publication lock.
///
/// The declaration overlay is derived from `active_models`. Keeping the pair
/// in one owned value prevents a request from combining one activation's
/// procedure summaries with a later activation's declaration resolver.
#[derive(Debug, Clone)]
pub struct ActiveSemanticModelSnapshot {
    active_models: Arc<ResolvedActiveSemanticModels>,
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
            active_models,
            rust_cargo_graph,
            semantic_model_overlay,
            overlay_measurement,
            jdk_artifacts_by_configured_home,
            python_runtime,
        }
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

#[derive(Debug)]
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

    let Some(overlay) = analyzer.semantic_model_overlay() else {
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
    values: BudgetedValueCache<String, SharedAllocation<ResolvedActiveSemanticModels>>,
    budget: RetentionBudget,
    published: Mutex<PublishedSemanticModelState>,
    inventory_store: std::sync::OnceLock<std::sync::Weak<AnalyzerStore>>,
    graph_identities: Mutex<VecDeque<GraphIdentityMemo>>,
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
}

/// Inputs retained together across partial refresh and publication.
#[derive(Clone, Debug)]
pub struct ActivationInputs {
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

impl From<SemanticModelActivationRequest> for ActivationInputs {
    fn from(request: SemanticModelActivationRequest) -> Self {
        Self {
            request,
            rust_cargo_graph: None,
        }
    }
}

#[cfg(test)]
mod carry_request_tests {
    use super::*;

    #[test]
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
                artifact_sha256: None,
            };
        let request = SemanticModelActivationRequest {
            bifrost_version: Version::new(0, 15, 1),
            approximate_standard_libraries: [
                crate::analyzer::DependencyPackEcosystem::Cargo,
                crate::analyzer::DependencyPackEcosystem::Npm,
            ]
            .into_iter()
            .map(|ecosystem| ApproximateSemanticModelExpectation {
                toolchain: None,
                language: ecosystem.languages()[0].config_label().to_owned(),
                ecosystem: ecosystem.label().to_owned(),
                pack_id: format!("{}-stdlib", ecosystem.label()),
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
            Vec::new(),
            vec![crate::analyzer::DependencyPackEcosystem::Cargo],
            Some(request.into()),
            Some(vec![
                crate::analyzer::DependencyPackEcosystem::Cargo,
                crate::analyzer::DependencyPackEcosystem::Npm,
            ]),
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
    }

    #[test]
    fn verified_partial_refresh_carries_cargo_graph() {
        let request = SemanticModelActivationRequest {
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
            Vec::new(),
            Vec::new(),
            Some(ActivationInputs {
                request,
                rust_cargo_graph: Some(graph.clone()),
            }),
            Some(Vec::new()),
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
    pub(crate) fn install_carried_dependency_evidence(
        &self,
        evidence: Vec<(
            Language,
            Arc<crate::analyzer::semantic_model::DependencyDiscoveryEvidence>,
        )>,
        mut stale: Vec<crate::analyzer::DependencyPackEcosystem>,
        old_request: Option<ActivationInputs>,
        activated: Option<Vec<crate::analyzer::DependencyPackEcosystem>>,
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
        let carried_request = old_request.map(|mut inputs| {
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

    pub(crate) fn record_activated_dependency_ecosystems(
        &self,
        ecosystems: &[crate::analyzer::DependencyPackEcosystem],
    ) {
        let mut published = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        let activated = published
            .activated_dependency_ecosystems
            .get_or_insert_with(Vec::new);
        for ecosystem in ecosystems {
            if !activated.contains(ecosystem) {
                activated.push(*ecosystem);
            }
        }
        published.requires_whole_dependency_refresh = false;
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
        Self {
            values: BudgetedValueCache::new(budget.region("semantic_models", None)),
            budget: budget.clone(),
            published: Mutex::new(PublishedSemanticModelState::default()),
            inventory_store: std::sync::OnceLock::new(),
            graph_identities: Mutex::new(VecDeque::new()),
        }
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
            std::mem::size_of::<GraphIdentityMemo>() + key.len() + identity.len(),
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

    pub(crate) fn invalidate_dependency_pack_state(&self, languages: &[Language]) -> bool {
        let mut published = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        let mut evidence_changed = false;
        for language in languages {
            evidence_changed |= published.dependency_evidence.remove(language).is_some();
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

    pub(crate) fn overlay(&self) -> Option<Arc<SemanticModelOverlay>> {
        self.snapshot().and_then(|snapshot| snapshot.overlay())
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
            jdk_artifacts_by_configured_home,
            python_runtime,
        } = runtime_artifacts;
        let _scope = crate::profiling::scope("semantic_pack.publish_overlay");
        {
            let mut published = self
                .published
                .lock()
                .expect("semantic-model publication mutex poisoned");
            if dependency_evidence.is_none()
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
        // The overlay owns one graph copy; publication retains two more in
        // the snapshot and carried activation inputs.
        let graph_copy_bytes =
            rust_cargo_graph.map_or(0, super::RustSelectedCargoGraph::retained_bytes_lower_bound);
        let retained_bytes =
            three_copy_graph_retained_bytes(overlay.retained_bytes_lower_bound(), graph_copy_bytes);
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
        if dependency_evidence.is_none()
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
            });
            return Ok(current);
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
                published
                    .snapshot
                    .as_ref()
                    .map(|snapshot| Arc::clone(&snapshot.jdk_artifacts_by_configured_home))
            })
            .unwrap_or_default();
        let snapshot = Arc::new(ActiveSemanticModelSnapshot::new(
            Arc::clone(active),
            rust_cargo_graph.cloned().map(Arc::new),
            Some(overlay),
            Some(overlay_measurement),
            jdk_artifacts_by_configured_home,
            python_runtime.cloned().or_else(|| {
                published
                    .snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.python_runtime.clone())
            }),
        ));
        published.snapshot = Some(Arc::clone(&snapshot));
        published.activation_request = Some(ActivationInputs {
            request: request.clone(),
            rust_cargo_graph: rust_cargo_graph.cloned(),
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
    !matches!(
        language,
        "go" | "jvm" | "java" | "kotlin" | "scala" | "python" | "c" | "c++" | "cpp"
    )
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
                !selection.active.approximate,
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
                && expectation.pack_id == manifest.pack_id
        })
}

fn assumed_rust_toolchain<'a>(
    request: &SemanticModelActivationRequest,
    shards: impl IntoIterator<Item = &'a ActiveSemanticModelShard>,
) -> Result<Version, String> {
    let stdlib = shards
        .into_iter()
        .filter(|shard| shard.approximate && supplies_rust_assumption(request, &shard.manifest))
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
    let mut report = SemanticModelActivationReport::default();
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

    let mut candidates = BTreeMap::new();
    for row in &evidence {
        if cancellation.is_cancelled() {
            return SemanticModelResolutionOutcome::Cancelled(report);
        }
        let query = evidence_query(row, request.bifrost_version.clone());
        let discovered = match catalog.candidates(&query) {
            Ok(discovered) => discovered,
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
            expectation.ecosystem.clone(),
        )
    }));
    language_ecosystems.sort();
    language_ecosystems.dedup();
    for (language, ecosystem) in language_ecosystems {
        if cancellation.is_cancelled() {
            return SemanticModelResolutionOutcome::Cancelled(report);
        }
        let query = SemanticPackSelectorQuery {
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
    let mut incomplete = false;
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
                            selection.active.approximate
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
        let approximate_stdlib = approximate_standard_libraries.iter().any(|expectation| {
            expectation.pack_id == loaded.manifest.pack_id
                && semantic_pack_language(&expectation.language) == loaded.manifest.language
                && expectation.ecosystem == loaded.manifest.ecosystem
        });
        let exact_match = (!approximate_stdlib && !from_pending)
            .then(|| {
                strict_activation_match(
                    &loaded.manifest,
                    &loaded.selectors,
                    &evidence,
                    &request.bifrost_version,
                )
            })
            .flatten();
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
                artifact_sha256: None,
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
                artifact_sha256: None,
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
                strict_activation_mismatch_reason(&loaded.manifest, &loaded.selectors, &evidence)
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
        let approximate =
            approximate_stdlib || approximate_dependency || !assumed_evidence.is_empty();
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
            && control != Some(SemanticModelControlAction::Enable)
        {
            // A shipped language-wide pack is an optional capability, not a
            // rejected dependency decision for every workspace in that
            // language. Keep it dormant and silent until a workspace names
            // it. Coordinate-specific review gates remain visible because
            // their matching evidence proves that the pack is relevant to a
            // discovered dependency or toolchain.
            if evidence_rank == EvidenceRank::Language
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
                "the pack requires an explicit compatible enable control",
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
                            approximate,
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
        artifact_sha256: None,
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
        // A review-gated pack reaches this push only through an explicit
        // compatible enable control, so the report retains that user
        // authorization decision rather than merely implying it.
        let mut reason = if selection.active.approximate {
            "approximate activation: the project's toolchain is unpinned; std facts are approximate"
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
        if selection.active.approximate || !selection.matched_requirements.is_empty() {
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
            (
                selection.active.manifest.content_sha256.clone(),
                selection.active.manifest.pack_id.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut extraction_gaps = Vec::new();
    let mut extraction_gap_counts = BTreeMap::new();
    for (manifest_digest, pack_id) in active_packs {
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

    let active_model_set_hash = match rust_cargo_graph {
        Some(graph) => {
            active_model_set_hash_with_cargo_graph(&active, &extraction_gaps, Some(graph))
        }
        None => active_model_set_hash(&active, &extraction_gaps),
    };
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
    );
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
        cancellation,
        false,
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
    acquire_eager_semantic_models_with_request_owner_for_test(
        analyzer,
        catalog,
        request,
        cancellation,
        false,
    )
}

#[cfg(any(test, feature = "test-support"))]
pub fn acquire_eager_semantic_models_with_request_owner_for_test(
    analyzer: &dyn IAnalyzer,
    catalog: &SemanticPackCatalog,
    request: &SemanticModelActivationRequest,
    cancellation: &CancellationToken,
    request_owner: bool,
) -> SemanticModelRuntimeOutcome {
    acquire_with_resolution(
        analyzer,
        catalog,
        None,
        request,
        None,
        None,
        RuntimeArtifactPublication::default(),
        cancellation,
        request_owner,
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

#[allow(clippy::too_many_arguments)]
fn acquire_with_resolution(
    analyzer: &dyn IAnalyzer,
    catalog: &SemanticPackCatalog,
    persistence: Option<SemanticModelActivationPersistence<'_>>,
    request: &SemanticModelActivationRequest,
    rust_cargo_graph: Option<&super::RustSelectedCargoGraph>,
    dependency_evidence: Option<&[DependencyEvidencePublication]>,
    runtime_artifacts: RuntimeArtifactPublication<'_>,
    cancellation: &CancellationToken,
    request_owner: bool,
    resolve: impl Fn() -> SemanticModelResolutionOutcome,
) -> SemanticModelRuntimeOutcome {
    debug_assert!(
        !crate::analyzer::workspace_authority::memo_attribution(analyzer).is_capturing(),
        "model acquisition precedes captured reads of the published Models key"
    );

    let RuntimeArtifactPublication {
        jdk_artifacts_by_configured_home,
        python_runtime,
    } = runtime_artifacts;
    let request_key = match runtime_request_key(request) {
        Ok(key) => key,
        Err(reason) => {
            let mut report = SemanticModelActivationReport::default();
            push_request_explanation(&mut report, request.limits, reason);
            return SemanticModelRuntimeOutcome::Unavailable(report);
        }
    };
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
            let memo_key = format!(
                "{request_key}:{provider_identity}:{}:{}:{}:{}",
                catalog_identity.instance_identity,
                catalog_identity.mutation_generation,
                catalog_identity.sqlite_data_version,
                cargo_graph_digest(graph, request)
            );
            match caches
                .semantic_models()
                .remembered_graph_identity(&memo_key)
            {
                Some(identity) => identity,
                None => {
                    let outcome = match resolve_against_snapshot(
                        &snapshot_content,
                        || analyzer.workspace_content_identity(),
                        || with_python_provider_identity(resolve(), python_runtime),
                    ) {
                        Ok(outcome) => outcome,
                        Err(_) => return stale_generation_outcome(request.limits),
                    };
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
    // #9559: the real JVM request owner is reachable only from tests until
    // step 3d. It is authoritative only with JVM row composition, and the
    // switched-on path still has open items (generator-rule ownership,
    // membership reconciliation, incomplete search). Production always
    // installs the placeholder.
    let request_source = if request_owner {
        analyzer
            .snapshot_caches()
            .and_then(|caches| caches.semantic_models().native_inventory_store())
            .and_then(|store| {
                analyzer
                    .request_row_reader_source(&catalog.pinned_catalog_source(&store.cache_budget))
            })
    } else {
        None
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
            && let Err(error) = publish_active_models(analyzer, catalog, persistence, active)
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
            if let Err(error) = publish_active_models(analyzer, catalog, persistence, &value) {
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
            if let Err(error) = publish_active_models(analyzer, catalog, persistence, &active) {
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
) -> Result<(), crate::analyzer::semantic_model::CatalogError> {
    let _scope = crate::profiling::scope("semantic_pack.publish_active_set");
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
        store
            .publish_jvm_external_owner_inventory(shard)
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
        .approximate
        .cmp(&left.active.approximate)
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

pub(crate) fn active_model_set_hash(
    active: &[CandidateSelection],
    extraction_gaps: &[Arc<ActivePackExtractionGap>],
) -> String {
    active_model_set_hash_with_cargo_graph(active, extraction_gaps, None)
}

fn active_model_set_hash_with_cargo_graph(
    active: &[CandidateSelection],
    extraction_gaps: &[Arc<ActivePackExtractionGap>],
    rust_cargo_graph: Option<&super::RustSelectedCargoGraph>,
) -> String {
    let mut rows = active.iter().collect::<Vec<_>>();
    rows.sort_unstable_by(|left, right| {
        left.semantic_sha256
            .cmp(&right.semantic_sha256)
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
    hasher.update(b"bifrost.semantic-model.active-set.v3\0");
    hasher.update(SEMANTIC_MODEL_RUNTIME_REPRESENTATION_VERSION.to_be_bytes());
    hasher.update((rows.len() as u64).to_be_bytes());
    for selection in rows {
        if selection.active.approximate {
            hasher.update(b"approximate\0");
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
        hash_key_part(&mut hasher, &selection.semantic_sha256);
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
    let mut identity_rows = Vec::new();
    for (pack_index, (compiled, matched_evidences, source_kind)) in packs.into_iter().enumerate() {
        assert!(
            !matched_evidences.is_empty(),
            "test snapshot needs evidence"
        );
        let manifest = Arc::new(compiled.manifest);
        for (artifact_index, artifact) in compiled.shards.into_iter().enumerate() {
            let matched_evidence = &matched_evidences[0];
            for evidence in &matched_evidences {
                identity_rows.push(format!(
                    "{}:{}:{}:{}:{evidence:?}",
                    manifest.semantic_sha256,
                    manifest.content_sha256,
                    manifest.provenance.is_close_match_approximation(),
                    artifact.descriptor.shard_id
                ));
            }
            let decoded = crate::analyzer::semantic_model::decode_shard(
                &artifact.descriptor,
                &artifact.bytes,
                &crate::analyzer::semantic_model::DecodeLimits::default(),
            )
            .expect("test pack shard decodes");
            shards.push(Arc::new(ActiveSemanticModelShard {
                metadata: Arc::new(
                    crate::analyzer::store::active_models::ActiveSemanticModelShardMetadata {
                        assumed_rust_toolchain: false,
                        approximate: manifest.provenance.is_close_match_approximation(),
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
                ),
                decoded: Some(decoded),
            }));
        }
    }
    identity_rows.sort();
    let mut hasher = Sha256::new();
    hasher.update(b"bifrost.test.semantic-model-active-set.v1\0");
    for row in identity_rows {
        hash_key_part(&mut hasher, &row);
    }
    let active = Arc::new(resolved_active_models_fixture(
        crate::analyzer::canonical_hash::lower_hex_string(&hasher.finalize().into()),
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
            artifact_sha256: Some(std::iter::repeat_n(digest_byte, 64).collect()),
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
                    approximate: false,
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
            "artifact_sha256": evidence.artifact_sha256.as_ref().unwrap().clone(),
        }]);
        compile_python_fixture_shard(
            source,
            evidence.clone(),
            format!("test:pypi:{}", evidence.artifact_sha256.as_deref().unwrap()),
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
            artifact_sha256: None,
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
            artifact_sha256: None,
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
                        approximate: false,
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
        let evidence = |digest: &str| SemanticModelActivationEvidence {
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
            artifact_sha256: Some(digest.repeat(64)),
        };
        let first = evidence("1");
        let second = evidence("2");
        let matched = strict_activation_match(
            &compiled.manifest,
            shard.activation(),
            &[first.clone(), second.clone()],
            &Version::parse("0.9.0").expect("valid runtime version"),
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
        let row = |version: &str, digest: &str| SemanticModelActivationEvidence {
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
            artifact_sha256: Some(digest.repeat(64)),
        };
        let java21 = row("21.0.8", "1");
        let java22 = row("22.0.1", "2");
        let matched = strict_activation_match(
            &compiled.manifest,
            shard.activation(),
            &[java21.clone(), java22],
            &Version::parse("0.9.0").expect("valid runtime version"),
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
            artifact_sha256: None,
        };
        assert_eq!(
            strict_activation_mismatch_reason(
                &compiled.manifest,
                shard.activation(),
                std::slice::from_ref(&declared)
            ),
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
        let evidence = |jdk_version: &str, digest: &str| SemanticModelActivationEvidence {
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
            artifact_sha256: Some(digest.to_owned()),
        };

        let matching = evidence("21.0.8", &artifact_sha256);
        assert!(
            strict_activation_match(
                &compiled.manifest,
                shard.activation(),
                std::slice::from_ref(&matching),
                &Version::parse("99.0.0").expect("valid cross-engine version"),
            )
            .is_some()
        );
        assert!(
            strict_activation_match(
                &compiled.manifest,
                shard.activation(),
                &[evidence("22.0.1", &artifact_sha256)],
                &Version::parse("99.0.0").expect("valid cross-engine version"),
            )
            .is_none()
        );
        assert!(
            strict_activation_match(
                &compiled.manifest,
                shard.activation(),
                &[evidence("21.0.8", &"b".repeat(64))],
                &Version::parse("99.0.0").expect("valid cross-engine version"),
            )
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
            )
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
        let evidence = |version: &str, digest: &str| SemanticModelActivationEvidence {
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
            artifact_sha256: Some(digest.repeat(64)),
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
                        approximate: false,
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
                            approximate: false,
                            source_kind: CatalogPackSourceKind::Embedded,
                            source_id: format!(
                                "test:artifact-{}",
                                evidence.artifact_sha256.as_deref().unwrap()
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
                        approximate: false,
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
            "artifact_sha256": evidence.artifact_sha256.as_ref().unwrap().clone(),
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
                        approximate: false,
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
            input: brokk_bifrost_analysis::analyzer::semantic_model::artifact::CompiledSummaryInput::Parameter { ordinal: 0 },
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
            artifact_sha256: None,
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
                        approximate: false,
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
        let source = serde_json::to_vec(&serde_json::json!({
            "schema_version": 2,
            "pack_id": pack_id,
            "version": "1.0.0",
            "producer": {"name": "active-set-identity-test", "version": "1.0.0"},
            "language": "go",
            "ecosystem": "go",
            "compatibility": {"bifrost": ">=0.10.5, <1.0.0", "toolchains": []},
            "provenance": {"source": "test:active-set-identity", "revision": "reviewed"},
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
            artifact_sha256: (evidence_rank == EvidenceRank::ExactArtifact)
                .then(|| "11".repeat(32)),
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
                            approximate: false,
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
    fn approximate_artifact_resolved_version_changes_active_identity() {
        assert_eq!(
            active_model_set_hash(
                &[procedure_selection(
                    "test.exact-rust-artifact",
                    false,
                    EvidenceRank::VersionedCoordinate,
                )],
                &[],
            ),
            "bdae8d0a64d99845005280bdaa217928e688092823dc8551574c1116b838ef1c",
            "exact-pack active-set bytes remain unchanged",
        );
        let make_selection = |version: &str| {
            let mut selection = procedure_selection(
                "test.approximate-rust-artifact",
                false,
                EvidenceRank::VersionedCoordinate,
            );
            let metadata = std::sync::Arc::make_mut(&mut selection.active.metadata);
            metadata.approximate = true;
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
            active_model_set_hash(&[warm], &[]),
            active_model_set_hash(&[cold], &[])
        );
        assert_ne!(
            active_model_set_hash(&[make_selection("0.4.25")], &[]),
            active_model_set_hash(&[changed], &[]),
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
            active_model_set_hash(&[with_toolchain_claim(false)], &[]),
            active_model_set_hash(&[with_toolchain_claim(true)], &[]),
            "the assumed-toolchain claim is distinct even when artifact approximation already set approximate"
        );
        let baseline = active_model_set_hash(&[make_selection("0.4.25")], &[]);
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
            assert_ne!(baseline, active_model_set_hash(&[changed_claim], &[]));
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
            super::active_model_set_hash_with_cargo_graph(&[ordinary()], &[], Some(&first)),
            super::active_model_set_hash_with_cargo_graph(&[ordinary()], &[], Some(&second))
        );
        assert_eq!(
            active_model_set_hash(&[ordinary()], &[]),
            super::active_model_set_hash_with_cargo_graph(&[ordinary()], &[], Some(&first)),
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
            super::active_model_set_hash_with_cargo_graph(&[no_reexports()], &[], Some(&first)),
            super::active_model_set_hash_with_cargo_graph(&[no_reexports()], &[], Some(&second)),
        );
        assert_eq!(
            active_model_set_hash(&[no_reexports()], &[]),
            super::active_model_set_hash_with_cargo_graph(&[no_reexports()], &[], Some(&first)),
            "no-reexport active identity keeps the pre-graph bytes",
        );
        assert_eq!(
            super::active_model_set_hash_with_cargo_graph(&[no_reexports()], &[], Some(&first)),
            super::active_model_set_hash_with_cargo_graph(&[no_reexports()], &[], Some(&unrelated)),
        );
        assert_eq!(
            super::active_model_set_hash_with_cargo_graph(&[no_reexports()], &[], Some(&first)),
            super::active_model_set_hash_with_cargo_graph(
                &[no_reexports()],
                &[],
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
            super::active_model_set_hash_with_cargo_graph(&[reexport()], &[], Some(&first)),
            super::active_model_set_hash_with_cargo_graph(&[reexport()], &[], Some(&second))
        );
        assert_ne!(
            super::active_model_set_hash_with_cargo_graph(&[reexport()], &[], Some(&first)),
            super::active_model_set_hash_with_cargo_graph(&[reexport()], &[], Some(&unrelated)),
            "the conditional hash reads unrelated edges from the same scoped graph",
        );
        let mut truncated = reexport();
        std::sync::Arc::make_mut(
            &mut std::sync::Arc::make_mut(&mut truncated.active.metadata).manifest,
        )
        .rust_external_reexports_truncated = true;
        assert_ne!(
            super::active_model_set_hash_with_cargo_graph(&[reexport()], &[], Some(&first)),
            super::active_model_set_hash_with_cargo_graph(&[truncated], &[], Some(&first)),
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
            super::active_model_set_hash_with_cargo_graph(&[reexport()], &[], Some(&first)),
            super::active_model_set_hash_with_cargo_graph(&[changed_route], &[], Some(&first)),
            "manifest-only route changes must change the active identity"
        );
        let cache = super::SemanticModelRuntimeCache::default();
        cache.install_carried_dependency_evidence(
            Vec::new(),
            Vec::new(),
            Some(super::ActivationInputs {
                request: super::SemanticModelActivationRequest {
                    bifrost_version: semver::Version::new(0, 15, 1),
                    approximate_standard_libraries: Vec::new(),
                    evidence: Vec::new(),
                    controls: Vec::new(),
                    limits: super::SemanticModelRuntimeLimits::default(),
                },
                rust_cargo_graph: Some(first.clone()),
            }),
            Some(Vec::new()),
        );
        let carried = cache
            .carried_activation_inputs()
            .unwrap()
            .rust_cargo_graph
            .unwrap();
        assert_eq!(carried, first);
        assert_eq!(carried.canonical_edges(), first.canonical_edges());
        assert_eq!(
            super::active_model_set_hash_with_cargo_graph(&[reexport()], &[], Some(&first)),
            super::active_model_set_hash_with_cargo_graph(&[reexport()], &[], Some(&carried)),
        );
    }

    #[test]
    fn exact_model_selection_precedes_approximate_with_equal_evidence_rank() {
        let exact =
            procedure_selection("test.exact-wins", false, EvidenceRank::VersionedCoordinate);
        let mut approximate =
            procedure_selection("test.exact-wins", false, EvidenceRank::VersionedCoordinate);
        std::sync::Arc::make_mut(&mut approximate.active.metadata).approximate = true;
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
        let active_model_set_hash = active_model_set_hash(&active, &[]);
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
            active_model_set_hash(&[], &[]),
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
            active_model_set_hash(&[], &[]),
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
            active_model_set_hash(&first, &[]),
            active_model_set_hash(&second, &[]),
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
            analyzer.semantic_model_overlay().unwrap()
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
            &analyzer.semantic_model_overlay().unwrap(),
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
            analyzer.semantic_model_overlay().unwrap()
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
            bifrost_version: Version::new(0, 15, 1),
            approximate_standard_libraries: Vec::new(),
            evidence,
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
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
            &CancellationToken::default(),
            false,
            || {
                resolves.fetch_add(1, AtomicOrdering::SeqCst);
                let selection = reexport_selection();
                let hash = active_model_set_hash_with_cargo_graph(
                    std::slice::from_ref(&selection),
                    &[],
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
                &CancellationToken::default(),
                false,
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
    fn graph_digest_follows_the_graph_data_the_identity_reads() {
        let request = request(vec![evidence()]);
        let digest = |graph: &RustSelectedCargoGraph| cargo_graph_digest(graph, &request);
        assert_eq!(digest(&graph("sqlx-core@1")), digest(&graph("sqlx-core@1")));
        assert_ne!(digest(&graph("sqlx-core@1")), digest(&graph("sqlx-core@2")));
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
                bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
                approximate_standard_libraries: vec![ApproximateSemanticModelExpectation {
                    language: "rust".into(),
                    ecosystem: "cargo".into(),
                    pack_id: "test.stdlib".into(),
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
                    artifact_sha256: None,
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
                assert!(dual.assumed_rust_toolchain && dual.approximate);
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
                assert!(independent.approximate);
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
                    companion.approximate,
                    case != "exact-pinned-alternative",
                    "{case}"
                );
            }
        }
    }
}
