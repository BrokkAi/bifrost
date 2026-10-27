use crate::CancellationToken;

use crate::analyzer::complete_value_cache::{CompleteValueAcquisition, CompleteValueCache};

use crate::analyzer::IAnalyzer;
use crate::analyzer::Language;
use crate::analyzer::semantic_model::PayloadKind;
use crate::analyzer::semantic_model::SemanticModelOverlay;
use crate::analyzer::semantic_model::SemanticModelOverlayBuildError;
use crate::analyzer::semantic_model::SemanticPackCatalog;
use crate::analyzer::semantic_model::SemanticPackSelectorQuery;
use crate::analyzer::semantic_model::{CatalogMiss, CatalogPackSourceKind};
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
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// One immutable semantic-model publication captured under the runtime's
/// publication lock.
///
/// The declaration overlay is derived from `active_models`. Keeping the pair
/// in one owned value prevents a request from combining one activation's
/// procedure summaries with a later activation's declaration resolver.
#[derive(Debug)]
pub struct ActiveSemanticModelSnapshot {
    active_models: Arc<ResolvedActiveSemanticModels>,
    semantic_model_overlay: Option<Arc<SemanticModelOverlay>>,
    overlay_measurement: Option<SemanticModelOverlayMeasurement>,
    jdk_artifacts_by_configured_home: Arc<HashMap<PathBuf, SemanticModelActivationEvidence>>,
    #[doc(hidden)]
    pub python_runtime:
        Option<crate::analyzer::store::python_runtime::PythonRuntimeProviderPublication>,
}

impl ActiveSemanticModelSnapshot {
    fn new(
        active_models: Arc<ResolvedActiveSemanticModels>,
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
            semantic_model_overlay,
            overlay_measurement,
            jdk_artifacts_by_configured_home,
            python_runtime,
        }
    }

    pub fn active_models(&self) -> &Arc<ResolvedActiveSemanticModels> {
        &self.active_models
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
    values: CompleteValueCache<String, ResolvedActiveSemanticModels>,
    published: Mutex<PublishedSemanticModelState>,
    inventory_store: std::sync::OnceLock<std::sync::Weak<AnalyzerStore>>,
}

#[derive(Default)]
pub(crate) struct PublishedSemanticModelState {
    snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    dependency_evidence:
        HashMap<Language, Arc<crate::analyzer::semantic_model::DependencyDiscoveryEvidence>>,
}

#[derive(Clone, Copy)]
pub struct SemanticModelActivationPersistence<'a> {
    pub scope_id: &'a str,
    pub store: &'a AnalyzerStore,
}

impl Default for SemanticModelRuntimeCache {
    fn default() -> Self {
        Self::new(1)
    }
}

impl SemanticModelRuntimeCache {
    pub(crate) fn new(max_retained_bytes: u64) -> Self {
        Self {
            values: CompleteValueCache::<String, ResolvedActiveSemanticModels>::new(
                max_retained_bytes,
                |_, active| u32::try_from(active.retained_bytes()).unwrap_or(u32::MAX),
            ),
            published: Mutex::new(PublishedSemanticModelState::default()),
            inventory_store: std::sync::OnceLock::new(),
        }
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
        active: &Arc<ResolvedActiveSemanticModels>,
        dependency_evidence: Option<&[DependencyEvidencePublication]>,
        runtime_artifacts: RuntimeArtifactPublication<'_>,
        cancellation: &CancellationToken,
        max_combined_retained_bytes: u64,
    ) -> Result<Arc<ActiveSemanticModelSnapshot>, SemanticModelOverlayBuildError> {
        let RuntimeArtifactPublication {
            jdk_artifacts_by_configured_home,
            python_runtime,
        } = runtime_artifacts;
        let _scope = crate::profiling::scope("semantic_pack.publish_overlay");
        {
            let published = self
                .published
                .lock()
                .expect("semantic-model publication mutex poisoned");
            if dependency_evidence.is_none()
                && jdk_artifacts_by_configured_home.is_none()
                && python_runtime.is_none()
                && let Some(snapshot) = published.snapshot.as_ref()
                && Arc::ptr_eq(snapshot.active_models(), active)
            {
                return Ok(Arc::clone(snapshot));
            }
        }
        let overlay_started = Instant::now();
        let overlay = Arc::new(SemanticModelOverlay::build(
            analyzer,
            active,
            cancellation,
            max_combined_retained_bytes,
        )?);
        let retained_bytes = overlay.retained_bytes_lower_bound();
        let mut published = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        if dependency_evidence.is_none()
            && jdk_artifacts_by_configured_home.is_none()
            && python_runtime.is_none()
            && let Some(current) = published.snapshot.as_ref()
            && Arc::ptr_eq(current.active_models(), active)
        {
            return Ok(Arc::clone(current));
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
}

pub fn resolve_active_semantic_models(
    catalog: &SemanticPackCatalog,
    request: &SemanticModelActivationRequest,
    cancellation: &CancellationToken,
) -> SemanticModelResolutionOutcome {
    resolve_active_semantic_models_with_loader(catalog, request, cancellation, |candidate| {
        catalog.load(candidate)
    })
}

/// Test-only per-language backing choice. Every selected shard of a language
/// uses the same backing; product activation selects rows for Rust only.
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
    resolve_active_semantic_models_with_loader(catalog, request, cancellation, |candidate| {
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

fn resolve_active_semantic_models_with_loader(
    catalog: &SemanticPackCatalog,
    request: &SemanticModelActivationRequest,
    cancellation: &CancellationToken,
    load: impl Fn(
        &crate::analyzer::semantic_model::catalog::CatalogCandidate,
    )
        -> Result<crate::analyzer::semantic_model::catalog::LoadedCatalogShard, CatalogMiss>,
) -> SemanticModelResolutionOutcome {
    let _scope = crate::profiling::scope("semantic_pack.resolve_active");
    let mut report = SemanticModelActivationReport::default();
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
    // Bounded by max_catalog_candidates and retained only for this activation.
    let mut newest_approximate_versions = HashMap::<String, Version>::default();
    let mut incomplete = false;
    let mut decode_hydration_nanos = 0u64;
    for candidate in candidates.into_values() {
        if cancellation.is_cancelled() {
            return SemanticModelResolutionOutcome::Cancelled(report);
        }
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
        decode_hydration_nanos = decode_hydration_nanos.saturating_add(elapsed_ns(load_started));
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

        let approximate = approximate_standard_libraries.iter().any(|expectation| {
            expectation.pack_id == loaded.manifest.pack_id
                && semantic_pack_language(&expectation.language) == loaded.manifest.language
                && expectation.ecosystem == loaded.manifest.ecosystem
        });
        let activation_match = if approximate {
            // An expectation requests a pack; it does not prove any of that
            // pack's toolchain coordinates or artifact digests exist locally.
            // Catalog discovery already checked engine compatibility.
            let version = Version::parse(&loaded.manifest.version)
                .expect("validated manifest version is semver");
            newest_approximate_versions
                .entry(loaded.manifest.pack_id.clone())
                .and_modify(|newest| *newest = newest.clone().max(version.clone()))
                .or_insert(version);
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
            strict_activation_match(
                &loaded.manifest,
                &loaded.selectors,
                &evidence,
                &request.bifrost_version,
            )
        };
        let Some(StrictActivationMatch {
            evidence_rank,
            matched_evidence,
            matching_evidence,
            matched_requirements,
        }) = activation_match
        else {
            let reason =
                strict_activation_mismatch_reason(&loaded.manifest, &loaded.selectors, &evidence);
            push_loaded_explanation(
                &mut report,
                request.limits,
                &loaded,
                SemanticModelActivationStatus::Incompatible,
                &reason,
            );
            continue;
        };
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
                continue;
            }
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
            active: {
                let has_callable_values = loaded.has_callable_values;
                ActiveSemanticModelShard {
                    metadata: std::sync::Arc::new(
                        crate::analyzer::store::active_models::ActiveSemanticModelShardMetadata {
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
                        },
                    ),
                    decoded: loaded.shard,
                }
            },
        });
    }

    selected.retain(|selection| {
        !selection.active.approximate
            || newest_approximate_versions
                .get(&selection.active.manifest.pack_id)
                .is_some_and(|newest| newest.to_string() == selection.active.manifest.version)
    });
    selected.sort_by(compare_selection);
    let mut active = Vec::new();
    let mut by_semantic_shard = BTreeMap::<(String, PayloadKind), usize>::new();
    for selection in selected.into_iter().rev() {
        let key = (selection.semantic_sha256.clone(), selection.payload_kind);
        if let Some(&winner) = by_semantic_shard.get(&key) {
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

    let active_model_set_hash = active_model_set_hash(&active, &extraction_gaps);
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
            source_reader
                .callable_values_presence(identity)
                .expect("selected shard marker exists"),
            shard.has_callable_values,
        );
        let shard = Arc::get_mut(shard).expect("active shard has not been published");
        Arc::get_mut(&mut shard.metadata)
            .expect("shard metadata has not been published")
            .row_store = Some(identity);
    }
    let resolved = ResolvedActiveSemanticModels {
        source_reader: Some(source_reader),
        active_model_set_hash,
        shards,
        indexes,
        extraction_gaps,
        extraction_gaps_by_declaration,
        report: report.clone(),
    };
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
    let key = format!(
        "{request_key}:{provider_identity}:{}:{}:{}",
        catalog_identity.instance_identity,
        catalog_identity.mutation_generation,
        catalog_identity.sqlite_data_version
    );
    // The activation guard asks whether the analyzer snapshot moved underneath
    // this resolution. Comparing the whole optional identity keeps an analyzer
    // that states none (an empty workspace) on its previous behavior instead of
    // reporting a permanent mismatch.
    let snapshot_content = analyzer.workspace_content_identity();
    let content_is_current = || analyzer.workspace_content_identity() == snapshot_content;
    let Some(caches) = analyzer.snapshot_caches() else {
        let outcome = with_python_provider_identity(
            resolve_active_semantic_models(catalog, request, cancellation),
            python_runtime,
        );
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
        CompleteValueAcquisition::Cached { value } => {
            if !content_is_current() {
                return stale_generation_outcome(request.limits);
            }
            if let Err(error) = publish_active_models(analyzer, catalog, persistence, &value) {
                return catalog_lifecycle_error(request.limits, "publish", error);
            }
            let snapshot = match caches.semantic_models().publish_overlay(
                analyzer,
                &value,
                dependency_evidence,
                runtime_artifacts,
                cancellation,
                request.limits.max_retained_bytes,
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
        CompleteValueAcquisition::Leader { permit } => {
            let outcome = with_python_provider_identity(
                resolve_active_semantic_models(catalog, request, cancellation),
                python_runtime,
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
            let active = Arc::new(active);
            if let Err(error) = publish_active_models(analyzer, catalog, persistence, &active) {
                return catalog_lifecycle_error(request.limits, "publish", error);
            }
            let snapshot = match caches.semantic_models().publish_overlay(
                analyzer,
                &active,
                dependency_evidence,
                runtime_artifacts,
                cancellation,
                request.limits.max_retained_bytes,
            ) {
                Ok(snapshot) => snapshot,
                Err(error) => return overlay_build_outcome(&active, error, request.limits),
            };
            permit.publish_complete(Arc::clone(&active));
            SemanticModelRuntimeOutcome::Ready {
                active,
                snapshot,
                lifecycle: SemanticModelRuntimeLifecycle::Built,
            }
        }
        CompleteValueAcquisition::Cancelled => {
            SemanticModelRuntimeOutcome::Cancelled(SemanticModelActivationReport::default())
        }
        CompleteValueAcquisition::Rejected => {
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
        SemanticModelOverlayBuildError::Cancelled => SemanticModelRuntimeOutcome::Cancelled(report),
        SemanticModelOverlayBuildError::RetainedBytesExceeded => {
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
            active.active_model_set_hash = format!("{:x}", hasher.finalize());
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
    left.evidence_rank
        .cmp(&right.evidence_rank)
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
        hash_key_part(&mut hasher, &selection.semantic_sha256);
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
    format!("{:x}", hasher.finalize())
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

#[cfg(test)]
pub(crate) mod unmaterialized_call_shape_binding_tests {

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
        let compiled = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .expect("exact-PyPI fixture compiles");
        let shard = decode_shard(
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("exact-PyPI fixture decodes");
        {
            let decoded = shard;
            let manifest = Arc::new(compiled.manifest);
            let has_callable_values = decoded.callable_values().is_some();
            ActiveSemanticModelShard {
                metadata: std::sync::Arc::new(
                    crate::analyzer::store::active_models::ActiveSemanticModelShardMetadata {
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
                            "test:pypi:{}",
                            evidence.artifact_sha256.as_deref().unwrap()
                        ),
                        matched_evidence: evidence.clone(),
                        matching_evidence: vec![evidence.clone()],
                        evidence_rank: EvidenceRank::ExactArtifact,
                        source_rank,
                    },
                ),
                decoded: Some(decoded),
            }
        }
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
        let compiled = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .expect("PyPI wildcard fixture compiles");
        let shard = decode_shard(
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("PyPI wildcard fixture decodes");
        {
            let decoded = shard;
            let manifest = Arc::new(compiled.manifest);
            let has_callable_values = decoded.callable_values().is_some();
            ActiveSemanticModelShard {
                metadata: std::sync::Arc::new(
                    crate::analyzer::store::active_models::ActiveSemanticModelShardMetadata {
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
                        source_id: "test:pypi-wildcard".to_owned(),
                        matched_evidence: evidence.clone(),
                        matching_evidence: vec![evidence.clone()],
                        evidence_rank: EvidenceRank::NamedCoordinate,
                        source_rank,
                    },
                ),
                decoded: Some(decoded),
            }
        }
    }

    fn python_generic_shard() -> ActiveSemanticModelShard {
        let mut source: serde_json::Value = serde_json::from_slice(PACK).unwrap();
        source["language"] = "python".into();
        source["ecosystem"] = "python".into();
        source["shards"][0]["activation"] = serde_json::json!([{}]);
        let compiled = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .expect("generic Python fixture compiles");
        let shard = decode_shard(
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("generic Python fixture decodes");
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
        {
            let decoded = shard;
            let manifest = Arc::new(compiled.manifest);
            let has_callable_values = decoded.callable_values().is_some();
            ActiveSemanticModelShard {
                metadata: std::sync::Arc::new(
                    crate::analyzer::store::active_models::ActiveSemanticModelShardMetadata {
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
                        source_id: "test:generic-python".to_owned(),
                        matched_evidence: evidence.clone(),
                        matching_evidence: vec![evidence],
                        evidence_rank: EvidenceRank::Language,
                        source_rank: 0,
                    },
                ),
                decoded: Some(decoded),
            }
        }
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
        let active = ResolvedActiveSemanticModels {
            source_reader: None,
            active_model_set_hash: "test:variadic-formals".to_owned(),
            shards: vec![active_shard],
            indexes,
            extraction_gaps: Vec::new(),
            extraction_gaps_by_declaration: HashMap::default(),
            report,
        };
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
                == brokk_bifrost_analysis::analyzer::semantic_model::Completeness::Partial
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
        let active_set = ResolvedActiveSemanticModels {
            source_reader: None,
            active_model_set_hash: "test:two-jdk-artifacts".to_owned(),
            shards: separate,
            indexes,
            extraction_gaps: Vec::new(),
            extraction_gaps_by_declaration: HashMap::default(),
            report,
        };
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
        let mut report = SemanticModelActivationReport::default();
        let shards = shards.into_iter().map(Arc::new).collect::<Vec<_>>();
        let indexes = MatcherIndexes::build(
            &shards,
            SemanticModelRuntimeLimits::default(),
            &CancellationToken::default(),
            &mut report,
        )
        .expect("same-spelling Python artifact shards index");
        let active = ResolvedActiveSemanticModels {
            source_reader: None,
            active_model_set_hash: "test:two-python-artifacts".to_owned(),
            shards,
            indexes,
            extraction_gaps: Vec::new(),
            extraction_gaps_by_declaration: HashMap::default(),
            report,
        };
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
        let mut generic_report = SemanticModelActivationReport::default();
        let generic_shard = Arc::new(generic_shard);
        let generic_indexes = MatcherIndexes::build(
            std::slice::from_ref(&generic_shard),
            SemanticModelRuntimeLimits::default(),
            &CancellationToken::default(),
            &mut generic_report,
        )
        .expect("generic Python summary indexes");
        let generic_active = ResolvedActiveSemanticModels {
            source_reader: None,
            active_model_set_hash: "test:generic-python".to_owned(),
            shards: vec![generic_shard],
            indexes: generic_indexes,
            extraction_gaps: Vec::new(),
            extraction_gaps_by_declaration: HashMap::default(),
            report: generic_report,
        };
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
        let active = ResolvedActiveSemanticModels {
            source_reader: None,
            active_model_set_hash: "test:same-python-artifact-two-models".to_owned(),
            shards,
            indexes,
            extraction_gaps: Vec::new(),
            extraction_gaps_by_declaration: HashMap::default(),
            report,
        };
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
        let mut report = SemanticModelActivationReport::default();
        let shard = Arc::new(shard);
        let indexes = MatcherIndexes::build(
            std::slice::from_ref(&shard),
            SemanticModelRuntimeLimits::default(),
            &CancellationToken::default(),
            &mut report,
        )
        .expect("PyPI wildcard summary indexes");
        let active = ResolvedActiveSemanticModels {
            source_reader: None,
            active_model_set_hash: "test:pypi-wildcard".to_owned(),
            shards: vec![shard],
            indexes,
            extraction_gaps: Vec::new(),
            extraction_gaps_by_declaration: HashMap::default(),
            report,
        };
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
        let active = ResolvedActiveSemanticModels {
            source_reader: None,
            active_model_set_hash: "test:python-argument-permutations".to_owned(),
            shards: vec![shard],
            indexes,
            extraction_gaps: Vec::new(),
            extraction_gaps_by_declaration: HashMap::default(),
            report,
        };
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
        let active = ResolvedActiveSemanticModels {
            source_reader: None,
            active_model_set_hash: "test:python-formal-shape".to_owned(),
            shards: vec![shard],
            indexes,
            extraction_gaps: Vec::new(),
            extraction_gaps_by_declaration: HashMap::default(),
            report,
        };

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
        let active = ResolvedActiveSemanticModels {
            source_reader: None,
            active_model_set_hash: "test:call-shape".to_owned(),
            shards: vec![active_shard],
            indexes,
            extraction_gaps: Vec::new(),
            extraction_gaps_by_declaration: HashMap::default(),
            report,
        };
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

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::ActiveSemanticModelShard;
    use sha2::Digest;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::CandidateSelection;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogPackSourceKind;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::EvidenceRank;

    use brokk_bifrost_core::hash::HashMap;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::MatcherIndexes;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::PayloadKind;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::ProcedureSummaryMemberKey;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::ResolvedActiveSemanticModels;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SEMANTIC_MODEL_RUNTIME_REPRESENTATION_VERSION;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelActivationEvidence;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelActivationReport;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelRuntimeLimits;

    use sha2::Sha256;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::active_model_set_hash;

    use brokk_bifrost_analysis::analyzer::semantic_model::compiler::CompilerOptions;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::DecodeLimits;

    use brokk_bifrost_analysis::analyzer::semantic_model::source::SourceFormat;

    use brokk_bifrost_analysis::analyzer::semantic_model::compiler::compile_source;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::decode_shard;

    fn procedure_selection(
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
            active: {
                let decoded = shard;
                let manifest = std::sync::Arc::new(compiled.manifest);
                let has_callable_values = decoded.callable_values().is_some();
                ActiveSemanticModelShard {
                    metadata: std::sync::Arc::new(
                        crate::analyzer::store::active_models::ActiveSemanticModelShardMetadata {
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
                        },
                    ),
                    decoded: Some(decoded),
                }
            },
        }
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
        format!("{:x}", hasher.finalize())
    }

    fn resolved(active: Vec<CandidateSelection>) -> ResolvedActiveSemanticModels {
        let active_model_set_hash = active_model_set_hash(&active, &[]);
        let shards = active
            .into_iter()
            .map(|selection| std::sync::Arc::new(selection.active))
            .collect::<Vec<_>>();
        let mut report = SemanticModelActivationReport::default();
        let indexes = MatcherIndexes::build(
            &shards,
            SemanticModelRuntimeLimits::default(),
            &CancellationToken::default(),
            &mut report,
        )
        .expect("identity fixture matcher builds");
        ResolvedActiveSemanticModels {
            source_reader: None,
            active_model_set_hash,
            shards,
            indexes,
            extraction_gaps: Vec::new(),
            extraction_gaps_by_declaration: HashMap::default(),
            report,
        }
    }

    #[test]
    fn value_semantics_schema_rotates_active_set_identity() {
        assert_eq!(SEMANTIC_MODEL_RUNTIME_REPRESENTATION_VERSION, 11);
        let mut previous = Sha256::new();
        previous.update(b"bifrost.semantic-model.active-set.v2\0");
        previous.update(2u32.to_be_bytes());
        previous.update(0u64.to_be_bytes());
        previous.update(0u64.to_be_bytes());
        let previous = format!("{:x}", previous.finalize());

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
            format!("{:x}", previous.finalize())
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
