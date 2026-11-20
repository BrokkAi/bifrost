use crate::analyzer::Language;
#[cfg(test)]
use crate::policy::{
    PolicyExecutionStage, PolicyExecutionTermination, PolicyReportDiagnosticCode,
    PolicySuppressionDocumentState,
};
#[cfg(test)]
use crate::searchtools::get_symbol_sources;
use crate::{
    AnalyzerConfig, CancellationToken, FilesystemProject, Project, ProjectChangeWatcher,
    ProjectFile, WorkspaceAnalyzer, WorkspaceFileListingCache,
    analyzer::IndexWarmer,
    analyzer::packs_document::{
        ReleaseCoverage, WORKSPACE_PACKS_DOCUMENT_PATH, WorkspaceActivationSources,
        WorkspaceActivationUpdateSource, WorkspacePacksConfig,
        activate_selected_installed_workspace_semantic_sources_in_catalog,
        activate_selected_workspace_semantic_sources_in_catalog_with_handoff,
        bootstrap_semantic_model_catalog,
        install_semantic_model_catalog_bootstrap as install_shared_semantic_model_catalog_bootstrap,
        intrinsic_language_evidence, load_workspace_packs_config_at, node_runtime_evidence,
        open_ambient_semantic_pack_catalog, python_process_input_evidence, release_coverage,
        shipped_semantic_packs_pending, workspace_pack_ecosystems,
    },
    analyzer::semantic::WorkspaceRelativePath,
    analyzer::semantic_model::{
        CatalogCoordinate, CatalogOpenMode, CatalogOptions, HostActivationContext,
        SemanticModelActivationEvidence, SemanticModelActivationRequest,
        SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome, SemanticPackCatalog,
        WorkspaceSemanticModelOptions, acquire_active_semantic_models,
        register_workspace_semantic_models, workspace_semantic_models_not_active,
    },
    blast_radius::{
        BlastRadiusParams, MissingTestsParams, blast_radius_at_root, missing_tests_at_root,
    },
    code_intelligence::CodeIntelligenceRuntime,
    code_quality::{
        analyze_git_hotspots, compute_cognitive_complexity, compute_cyclomatic_complexity,
        report_comment_density_for_code_unit, report_comment_density_for_files,
        report_dead_code_and_unused_abstraction_smells, report_exception_handling_smells,
        report_long_method_and_god_object_smells, report_secret_like_code,
        report_structural_clone_smells, report_test_assertion_smells,
    },
    cyclomatic_complexity_diff::{CyclomaticComplexityParams, cyclomatic_complexity_at_root},
    diff_analysis::{AnalyzeDiffParams, DiffAnalysisOptions, analyze_diff_at_root},
    diff_scoring::{DiffScoringSession, ScoreDiffParams},
    file_tools::{find_files_containing, get_file_contents, search_file_contents},
    panic_report::reported_panic,
    path_normalization::NormalizePath,
    policy::{
        BuiltInPolicySelection, ExplainError, ExplanationCandidate, ExplanationGeneration,
        ExplanationLimits, ExplanationTarget, FlowExplanationCandidate, NearMissCandidates,
        PolicyBaselineOptions, PolicyBaselineSource, PolicyBatchOutcome, PolicyEvaluationDate,
        PolicyEvaluationInput, PolicyEvaluationOptions, PolicyExplanation, PolicyFailOn,
        PolicyFindingId, PolicyId, PolicyNearMissRanking, PolicyRangeRequest, PolicyReportDocument,
        PolicyRun, PolicyScopeOptions, PolicyScopeSource, PolicyStageTiming,
        PolicySuppressionOptions, PolicySuppressionSource, built_in_policy_catalog,
        explain_policy_inputs_with_semantic_models, policy_bundles,
        rank_policy_near_misses_with_semantic_models,
        workspace_snapshot_deadline_outcome_with_preflight,
    },
    profiling,
    searchtools::{
        ActivateWorkspaceParams, ActiveWorkspaceResult, GetActiveWorkspaceParams,
        MostRelevantFilesParams, PendingSemanticPackAcquisition, RefreshParams,
        SemanticModelOverlayStatus, SemanticModelWarmStage, SymbolLookupParams,
        SymbolSourcesResult, classify_test_files, get_declarations_by_location_with_cancellation,
        get_definitions_by_location_with_cancellation,
        get_definitions_by_reference_with_cancellation, get_summaries_with_cancellation,
        get_symbol_ancestors, get_symbol_locations_with_cancellation,
        get_symbol_sources_with_source_budget, get_type_by_location, list_symbols,
        most_relevant_files_with_cancellation, refresh_result, rename_symbol,
        scan_usages_by_location_with_cancellation, scan_usages_by_reference_with_cancellation,
        search_symbols_with_cancellation, session_subset, symbol_source_candidate_files,
        usage_graph_with_cancellation,
    },
    searchtools_render::{RenderOptions, RenderText},
    workspace_document::{WorkspaceDocumentError, WorkspaceRoot, read_workspace_document},
};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const SEMANTIC_PACK_CATALOG_ENV: &str = "BIFROST_SEMANTIC_PACK_CATALOG";
const SEMANTIC_PACK_EVIDENCE_ENV: &str = "BIFROST_SEMANTIC_PACK_EVIDENCE";
const WORKSPACE_SEMANTIC_MODELS_ENV: &str = "BIFROST_WORKSPACE_SEMANTIC_MODELS";

/// Transport-side request delays measured by the MCP host and carried into
/// profiled tool responses. The aggregate queue wait remains distinct from
/// its readiness and analyzer-admission components for attribution.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TransportTimings {
    pub(crate) transport_queue_wait: Duration,
    pub(crate) workspace_readiness_wait: Duration,
    pub(crate) analyzer_admission_wait: Duration,
}

impl TransportTimings {
    fn with_queue_wait(transport_queue_wait: Duration) -> Self {
        Self {
            transport_queue_wait,
            ..Self::default()
        }
    }
}

/// Configure the downstream shipped-pack provider once for this process.
pub fn install_semantic_model_catalog_bootstrap(
    bootstrap: crate::analyzer::packs_document::SemanticModelCatalogBootstrap,
) -> Result<(), &'static str> {
    install_shared_semantic_model_catalog_bootstrap(bootstrap)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfiguredSemanticModelEvidence {
    language: String,
    ecosystem: String,
    #[serde(default)]
    package: Option<ConfiguredCatalogCoordinate>,
    #[serde(default)]
    module: Option<ConfiguredCatalogCoordinate>,
    #[serde(default)]
    toolchain: Option<ConfiguredCatalogCoordinate>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    configuration: Option<String>,
    #[serde(default)]
    artifact_sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfiguredCatalogCoordinate {
    name: String,
    #[serde(default)]
    version: Option<String>,
}

#[derive(Debug, Clone)]
struct ConfiguredSemanticModels {
    catalog_root: Option<PathBuf>,
    evidence: Vec<ConfiguredSemanticModelEvidence>,
    workspace_models: bool,
}

impl ConfiguredCatalogCoordinate {
    fn parse(self) -> Result<CatalogCoordinate, String> {
        Ok(CatalogCoordinate {
            name: self.name,
            version: self
                .version
                .map(|version| {
                    Version::parse(&version).map_err(|error| {
                        format!("invalid configured semantic-pack version {version}: {error}")
                    })
                })
                .transpose()?,
        })
    }
}

impl ConfiguredSemanticModelEvidence {
    fn parse(self) -> Result<SemanticModelActivationEvidence, String> {
        if self.artifact_sha256.as_deref().is_some_and(|digest| {
            !brokk_bifrost_core::analyzer::canonical_hash::is_lower_sha256(digest)
        }) {
            return Err("activation evidence artifact digest must be lowercase SHA-256".to_owned());
        }
        Ok(SemanticModelActivationEvidence {
            language: self.language,
            ecosystem: self.ecosystem,
            package: self
                .package
                .map(ConfiguredCatalogCoordinate::parse)
                .transpose()?,
            module: self
                .module
                .map(ConfiguredCatalogCoordinate::parse)
                .transpose()?,
            toolchain: self
                .toolchain
                .map(ConfiguredCatalogCoordinate::parse)
                .transpose()?,
            target: self.target,
            configuration: self.configuration,
            production_input_digest: None,
verified_raw_artifacts: (self.artifact_sha256).into_iter().map(|sha256: String| brokk_bifrost_analysis::analyzer::semantic_model::runtime::VerifiedRawArtifact::from_sha256(brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyArtifactRole::Reference, brokk_bifrost_analysis::analyzer::semantic_model::ExternalArtifactKind::JavaClassJar, &sha256)).collect(),
        })
    }
}

fn configured_semantic_models() -> Result<Option<ConfiguredSemanticModels>, String> {
    let catalog_root = std::env::var_os(SEMANTIC_PACK_CATALOG_ENV).map(PathBuf::from);
    let evidence = std::env::var(SEMANTIC_PACK_EVIDENCE_ENV).ok();
    let workspace_models = parse_workspace_semantic_models_setting(
        std::env::var_os(WORKSPACE_SEMANTIC_MODELS_ENV).as_deref(),
    )?;
    let (catalog_root, evidence) = match (catalog_root, evidence) {
        (None, None) => (None, Vec::new()),
        (Some(_), None) => Err(format!(
            "{SEMANTIC_PACK_CATALOG_ENV} requires {SEMANTIC_PACK_EVIDENCE_ENV}"
        ))?,
        (None, Some(_)) => Err(format!(
            "{SEMANTIC_PACK_EVIDENCE_ENV} requires {SEMANTIC_PACK_CATALOG_ENV}"
        ))?,
        (Some(catalog_root), Some(evidence)) => {
            let evidence = serde_json::from_str::<Vec<ConfiguredSemanticModelEvidence>>(&evidence)
                .map_err(|error| format!("invalid {SEMANTIC_PACK_EVIDENCE_ENV}: {error}"))?;
            if evidence.is_empty() {
                return Err(format!("{SEMANTIC_PACK_EVIDENCE_ENV} must not be empty"));
            }
            (Some(catalog_root), evidence)
        }
    };
    if catalog_root.is_none() && !workspace_models {
        return Ok(None);
    }
    Ok(Some(ConfiguredSemanticModels {
        catalog_root,
        evidence,
        workspace_models,
    }))
}

fn parse_workspace_semantic_models_setting(
    value: Option<&std::ffi::OsStr>,
) -> Result<bool, String> {
    let Some(value) = value else {
        return Ok(false);
    };
    match value.to_str() {
        Some("on" | "1" | "enabled") => Ok(true),
        Some("off" | "0" | "disabled") => Ok(false),
        Some(value) => Err(format!(
            "invalid {WORKSPACE_SEMANTIC_MODELS_ENV} value {value:?}; use on or off"
        )),
        None => Err(format!(
            "{WORKSPACE_SEMANTIC_MODELS_ENV} must contain valid UTF-8"
        )),
    }
}

#[derive(Debug)]
struct WorkspacePackActivationState {
    config: Option<Arc<WorkspacePacksConfig>>,
    update_source: Option<Arc<WorkspaceActivationUpdateSource>>,
    ecosystems: Vec<crate::analyzer::DependencyPackEcosystem>,
    failure: Option<String>,
    overlay: SemanticModelOverlayStatus,
    /// Dependencies whose exact acquisition the expensive stage of the warm
    /// still owes. Non-empty only on an interim, installed-stage state, so a
    /// query holding it can say which packs its answer could still gain
    /// (issue #3401). A settled state always has this empty.
    pending_acquisitions: Vec<crate::analyzer::semantic_model::PendingDependencyPackAcquisition>,
    /// The host's shipped-pack acquisition the expensive stage still waits
    /// for, by the host's own description. Like `pending_acquisitions`, set
    /// only on an interim installed-stage state (#11030).
    shipped_pack_acquisition_pending: Option<String>,
    /// The release coverage the ordinary route pinned; `None` on the legacy
    /// host-supplied route and on states that never reached bootstrap.
    coverage: Option<PinnedPackCoverage>,
}

/// The release coverage one activation pinned (#6397 Part B), computed from
/// the selected snapshot's languages, the packs configuration and the
/// bootstrap evidence. Publication is fenced by pointer replacement: every
/// coverage input changes only through a refresh that replaces the session's
/// pack state. Configured MCP evidence and Python process settings come from
/// the process environment and are constant for a session; the release bundle
/// is read once per activation, so a changed bundle on disk takes effect only
/// through a new activation (a refresh or a restart).
#[derive(Debug, Clone, PartialEq, Eq)]
struct PinnedPackCoverage {
    coverage: ReleaseCoverage,
    evidence: Vec<SemanticModelActivationEvidence>,
}

impl PinnedPackCoverage {
    /// Whether this pin still reaches every release entry `snapshot` can
    /// demand under the pinned configuration. The snapshot's intrinsic
    /// language evidence is recomputed in memory, because a new language adds
    /// an intrinsic pair even when it leaves the kept ecosystems unchanged
    /// (for example a C++ file under a packs document narrowed to JVM). Node
    /// and Python evidence come from files and settings whose changes refresh
    /// the pack state, so the pinned values stand for them.
    fn covers(&self, snapshot: &WorkspaceAnalyzer, config: Option<&WorkspacePacksConfig>) -> bool {
        let mut evidence = self.evidence.clone();
        evidence.extend(intrinsic_language_evidence(snapshot));
        self.coverage.contains(&release_coverage(
            &snapshot.analyzer().languages(),
            config,
            &evidence,
        ))
    }
}

impl WorkspacePackActivationState {
    fn unavailable(
        config: Option<Arc<WorkspacePacksConfig>>,
        ecosystems: Vec<crate::analyzer::DependencyPackEcosystem>,
        reason: String,
    ) -> Self {
        Self {
            update_source: None,
            config,
            ecosystems,
            failure: Some(reason.clone()),
            overlay: SemanticModelOverlayStatus::Unavailable {
                reason,
                budget: None,
            },
            pending_acquisitions: Vec::new(),
            shipped_pack_acquisition_pending: None,
            coverage: None,
        }
    }

    fn set_runtime_outcome(
        &mut self,
        ecosystems: &[crate::analyzer::DependencyPackEcosystemOutcome],
        outcome: Option<&SemanticModelRuntimeOutcome>,
    ) {
        let (_, status) = crate::analyzer::semantic_model::SemanticModelActivationRead::reduce(
            crate::analyzer::semantic_model::SemanticModelActivationInput::Runtime {
                ecosystems,
                runtime: outcome,
            },
        )
        .into_parts();
        self.failure = match &status {
            SemanticModelOverlayStatus::Unavailable { reason, .. } => Some(reason.clone()),
            _ => None,
        };
        self.overlay = status;
    }
}

/// The installed-pack stage's answer for one session: either the final
/// activation, when nothing expensive is outstanding, or the interim
/// activation whose pending acquisitions the warm thread still owes.
enum InstalledPackStageOutcome {
    Settled(WorkspacePackActivationState),
    AcquisitionPending(
        WorkspacePackActivationState,
        Option<crate::analyzer::StagedDependencyDiscoveryHandoff>,
    ),
}

fn activate_configured_semantic_models(
    workspace_root: &Path,
    workspace: &WorkspaceAnalyzer,
    configured: Option<ConfiguredSemanticModels>,
) -> Result<WorkspacePackActivationState, String> {
    activate_configured_semantic_models_selected(
        workspace_root,
        workspace,
        configured,
        &crate::analyzer::DependencyPackEcosystem::ALL,
        None,
    )
}

fn activate_configured_semantic_models_selected(
    workspace_root: &Path,
    workspace: &WorkspaceAnalyzer,
    configured: Option<ConfiguredSemanticModels>,
    selected: &[crate::analyzer::DependencyPackEcosystem],
    discovery_handoff: Option<crate::analyzer::StagedDependencyDiscoveryHandoff>,
) -> Result<WorkspacePackActivationState, String> {
    let _scope = profiling::scope("semantic_pack.activate_configured");
    let packs_config = load_workspace_packs_config_at(workspace_root)
        .map_err(|error| format!("failed to load workspace packs document: {error}"))?
        .map(Arc::new);
    if configured_explicit_legacy(&configured) {
        return activate_legacy_configured_semantic_models(
            workspace_root,
            workspace,
            configured,
            packs_config,
        );
    }
    // This is the ordinary MCP path. Bootstrap alone is not a legacy
    // override: it contributes reviewed records to the same catalog and
    // one shared transaction as the ambient/default dependency route.
    let SessionPackCatalogPrelude {
        workspace_models,
        ecosystems,
        catalog,
        additional_evidence,
        leases,
        coverage,
    } = match open_session_pack_catalog(workspace_root, workspace, &configured, &packs_config) {
        Ok(prelude) => prelude,
        Err(failure_state) => return Ok(*failure_state),
    };
    // The activation publishes its models onto the session analyzer, which is
    // what the session's tools read. Policy evaluation activates its own
    // workspace (#3735), so nothing reads the transaction's own record.
    let activation_config = workspace_activation_config(workspace);
    let activation = activate_selected_workspace_semantic_sources_in_catalog_with_handoff(
        workspace,
        &activation_config,
        &catalog,
        WorkspaceActivationSources {
            catalog_root: workspace_root,
            workspace_model_root: workspace_models.then_some(workspace_root),
            config: packs_config.as_deref(),
            intrinsic_shipped_models: false,
        },
        &additional_evidence,
        &CancellationToken::default(),
        selected,
        discovery_handoff,
    )
    .map_err(|error| format!("workspace semantic-pack activation failed: {error}"));
    catalog
        .release_leases(&leases)
        .map_err(|error| error.to_string())?;
    let update_source = activation
        .as_ref()
        .ok()
        .and_then(|activation| activation.as_ref())
        .map(|activation| {
            WorkspaceActivationUpdateSource::new(
                Arc::clone(&catalog),
                activation.registration_evidence.clone(),
                packs_config.as_deref(),
                workspace.retention_budget(),
            )
            .map(Arc::new)
        })
        .transpose()
        .map_err(|error| error.to_string())?;
    let mut state = WorkspacePackActivationState {
        update_source,
        config: packs_config,
        ecosystems,
        failure: activation.as_ref().err().cloned(),
        overlay: SemanticModelOverlayStatus::NoModels,
        pending_acquisitions: Vec::new(),
        shipped_pack_acquisition_pending: None,
        coverage: Some(coverage),
    };
    match activation {
        Ok(activation) => state.set_runtime_outcome(
            &workspace.ecosystem_statuses_with_carried(
                activation
                    .as_ref()
                    .map_or(&[][..], |activation| &activation.outcome.ecosystems),
            ),
            activation
                .as_ref()
                .and_then(|activation| activation.outcome.runtime.as_ref()),
        ),
        Err(reason) => {
            state.overlay = SemanticModelOverlayStatus::Unavailable {
                reason,
                budget: None,
            }
        }
    }
    Ok(state)
}

/// The installed-pack stage of [`activate_configured_semantic_models`]: the
/// same document load, catalog open, bootstrap, and discovery, but dependency
/// preparation resolves only against packs already installed in the catalog.
/// Nothing is fetched, verified, extracted, read as a dependency artifact, or
/// generated from a local toolchain; the acquisitions that remain come back
/// named on the interim state (issue #3401, the #3372 family).
fn activate_configured_semantic_models_installed_stage_selected(
    workspace_root: &Path,
    workspace: &WorkspaceAnalyzer,
    configured: Option<ConfiguredSemanticModels>,
    selected: &[crate::analyzer::DependencyPackEcosystem],
) -> Result<InstalledPackStageOutcome, String> {
    let _scope = profiling::scope("semantic_pack.activate_installed");
    let packs_config = load_workspace_packs_config_at(workspace_root)
        .map_err(|error| format!("failed to load workspace packs document: {error}"))?
        .map(Arc::new);
    if let Some(acquisition) = shipped_semantic_packs_pending() {
        // Registering the shipped packs would wait for the host's network
        // acquisition, which this stage must never do: every query awaits it
        // (#11030). The expensive stage registers them and activates the
        // whole set; until it publishes, answers carry the pending marker.
        let ecosystems = workspace_pack_ecosystems(workspace, packs_config.as_deref());
        return Ok(InstalledPackStageOutcome::AcquisitionPending(
            WorkspacePackActivationState {
                update_source: None,
                config: packs_config,
                ecosystems,
                failure: None,
                overlay: SemanticModelOverlayStatus::NoModels,
                pending_acquisitions: Vec::new(),
                shipped_pack_acquisition_pending: Some(acquisition),
                coverage: None,
            },
            None,
        ));
    }
    if configured_explicit_legacy(&configured) {
        // The legacy host-supplied route only ever reads local catalogs and
        // host-supplied evidence, so it is whole in the installed stage by
        // construction.
        return activate_legacy_configured_semantic_models(
            workspace_root,
            workspace,
            configured,
            packs_config,
        )
        .map(InstalledPackStageOutcome::Settled);
    }
    let SessionPackCatalogPrelude {
        workspace_models,
        ecosystems,
        catalog,
        additional_evidence,
        leases,
        coverage,
    } = match open_session_pack_catalog(workspace_root, workspace, &configured, &packs_config) {
        Ok(prelude) => prelude,
        Err(failure_state) => return Ok(InstalledPackStageOutcome::Settled(*failure_state)),
    };
    let activation_config = workspace_activation_config(workspace);
    let activation = activate_selected_installed_workspace_semantic_sources_in_catalog(
        workspace,
        &activation_config,
        &catalog,
        WorkspaceActivationSources {
            catalog_root: workspace_root,
            workspace_model_root: workspace_models.then_some(workspace_root),
            config: packs_config.as_deref(),
            intrinsic_shipped_models: false,
        },
        &additional_evidence,
        &CancellationToken::default(),
        selected,
    );
    catalog
        .release_leases(&leases)
        .map_err(|error| error.to_string())?;
    match activation {
        Ok(Some(installed)) => {
            let update_source = Some(Arc::new(
                WorkspaceActivationUpdateSource::new(
                    Arc::clone(&catalog),
                    installed.activation.registration_evidence.clone(),
                    packs_config.as_deref(),
                    workspace.retention_budget(),
                )
                .map_err(|error| error.to_string())?,
            ));
            let mut state = WorkspacePackActivationState {
                update_source,
                config: packs_config,
                ecosystems,
                failure: None,
                overlay: SemanticModelOverlayStatus::NoModels,
                pending_acquisitions: installed.pending,
                shipped_pack_acquisition_pending: None,
                coverage: Some(coverage),
            };
            state.set_runtime_outcome(
                &workspace
                    .ecosystem_statuses_with_carried(&installed.activation.outcome.ecosystems),
                installed.activation.outcome.runtime.as_ref(),
            );
            if state.pending_acquisitions.is_empty() {
                Ok(InstalledPackStageOutcome::Settled(state))
            } else {
                Ok(InstalledPackStageOutcome::AcquisitionPending(
                    state,
                    installed.discovery_handoff,
                ))
            }
        }
        Ok(None) => Ok(InstalledPackStageOutcome::Settled(
            WorkspacePackActivationState {
                update_source: None,
                config: packs_config,
                ecosystems,
                failure: None,
                overlay: SemanticModelOverlayStatus::NoModels,
                pending_acquisitions: Vec::new(),
                shipped_pack_acquisition_pending: None,
                coverage: Some(coverage),
            },
        )),
        Err(error) => Ok(InstalledPackStageOutcome::Settled(
            WorkspacePackActivationState::unavailable(
                packs_config,
                ecosystems,
                format!("workspace semantic-pack activation failed: {error}"),
            ),
        )),
    }
}

fn configured_explicit_legacy(configured: &Option<ConfiguredSemanticModels>) -> bool {
    configured.as_ref().is_some_and(|configured| {
        configured.catalog_root.is_some() || !configured.evidence.is_empty()
    })
}

/// The catalog handle and bootstrap evidence both activation stages start
/// from. Opening the catalog and running its bootstrap are local work --
/// neither fetches, verifies, extracts, or generates anything -- so the
/// installed-pack stage awaits them (issue #3401).
struct SessionPackCatalogPrelude {
    workspace_models: bool,
    ecosystems: Vec<crate::analyzer::DependencyPackEcosystem>,
    catalog: Arc<SemanticPackCatalog>,
    additional_evidence: Vec<SemanticModelActivationEvidence>,
    leases: Vec<crate::analyzer::semantic_model::CatalogLeaseToken>,
    coverage: PinnedPackCoverage,
}

fn append_intrinsic_semantic_evidence(
    workspace: &WorkspaceAnalyzer,
    evidence: &mut Vec<SemanticModelActivationEvidence>,
) {
    evidence.extend(intrinsic_language_evidence(workspace));
    evidence.extend(node_runtime_evidence(workspace));
    evidence.extend(python_process_input_evidence(workspace));
}

/// The release entries this session can demand. Only a workspace whose project
/// exposes the whole workspace has an authoritative language set; a
/// `--sources` file set (and an overlay over one) installs the whole release.
fn session_release_coverage(
    workspace: &WorkspaceAnalyzer,
    packs_config: Option<&WorkspacePacksConfig>,
    evidence: &[SemanticModelActivationEvidence],
) -> ReleaseCoverage {
    match workspace.analyzer().project().coverage() {
        brokk_bifrost_analysis::ProjectCoverage::Whole => {
            release_coverage(&workspace.analyzer().languages(), packs_config, evidence)
        }
        brokk_bifrost_analysis::ProjectCoverage::Subset(_) => ReleaseCoverage::WholeRelease,
    }
}

fn open_session_pack_catalog(
    workspace_root: &Path,
    workspace: &WorkspaceAnalyzer,
    configured: &Option<ConfiguredSemanticModels>,
    packs_config: &Option<Arc<WorkspacePacksConfig>>,
) -> Result<SessionPackCatalogPrelude, Box<WorkspacePackActivationState>> {
    let workspace_models = configured
        .as_ref()
        .is_some_and(|configured| configured.workspace_models);
    let ecosystems = workspace_pack_ecosystems(workspace, packs_config.as_deref());
    // Intrinsic shipped packs are independent of the dependency and
    // workspace-local routes, so even an explicit empty ecosystem list
    // must reach the shared bootstrap below.
    let catalog = {
        let _scope = profiling::scope("semantic_pack.open_catalog");
        match packs_config.as_ref().and_then(|config| config.catalog()) {
            Some(relative) => match SemanticPackCatalog::open(
                &workspace_root.join(relative),
                CatalogOpenMode::ReadWrite,
                CatalogOptions::default(),
            ) {
                Ok(catalog) => catalog,
                Err(error) => {
                    return Err(Box::new(WorkspacePackActivationState::unavailable(
                        packs_config.clone(),
                        ecosystems,
                        format!("failed to open workspace semantic-pack catalog: {error}"),
                    )));
                }
            },
            None => match open_ambient_semantic_pack_catalog(
                workspace,
                workspace_root,
                CatalogOptions::default(),
            ) {
                Ok(catalog) => catalog,
                Err(error) => {
                    return Err(Box::new(WorkspacePackActivationState::unavailable(
                        packs_config.clone(),
                        ecosystems,
                        format!("failed to open generated semantic-pack catalog: {error}"),
                    )));
                }
            },
        }
    };
    // The evidence that selects shipped packs is computed once: it defines the
    // release coverage before bootstrap and joins activation after it.
    let mut bootstrap_evidence = Vec::new();
    append_intrinsic_semantic_evidence(workspace, &mut bootstrap_evidence);
    let release = session_release_coverage(workspace, packs_config.as_deref(), &bootstrap_evidence);
    let (additional_evidence, leases) = match bootstrap_semantic_model_catalog(&catalog, &release) {
        Ok(Some(leases)) => (bootstrap_evidence.clone(), leases),
        Ok(None) => (Vec::new(), Vec::new()),
        Err(error) => {
            return Err(Box::new(WorkspacePackActivationState::unavailable(
                packs_config.clone(),
                ecosystems,
                format!("failed to register the MCP semantic-pack catalog bootstrap: {error}"),
            )));
        }
    };
    Ok(SessionPackCatalogPrelude {
        workspace_models,
        ecosystems,
        catalog: Arc::new(catalog),
        additional_evidence,
        leases,
        coverage: PinnedPackCoverage {
            coverage: release,
            evidence: bootstrap_evidence,
        },
    })
}

/// Dependency discovery runs under this configuration, so a build target the
/// host selected (for example a Go `goos`/`goarch` pair) must reach semantic
/// activation rather than being replaced by the defaults. A workspace assembled
/// without a build context has no configuration and behaves as the defaults
/// describe.
fn workspace_activation_config(workspace: &WorkspaceAnalyzer) -> AnalyzerConfig {
    workspace.config().cloned().unwrap_or_default()
}

fn activate_legacy_configured_semantic_models(
    workspace_root: &Path,
    workspace: &WorkspaceAnalyzer,
    configured: Option<ConfiguredSemanticModels>,
    packs_config: Option<Arc<WorkspacePacksConfig>>,
) -> Result<WorkspacePackActivationState, String> {
    activate_legacy_configured_semantic_models_with_limits(
        workspace_root,
        workspace,
        configured,
        packs_config,
        SemanticModelRuntimeLimits::default(),
    )
}

fn activate_legacy_configured_semantic_models_with_limits(
    workspace_root: &Path,
    workspace: &WorkspaceAnalyzer,
    configured: Option<ConfiguredSemanticModels>,
    packs_config: Option<Arc<WorkspacePacksConfig>>,
    limits: SemanticModelRuntimeLimits,
) -> Result<WorkspacePackActivationState, String> {
    activate_legacy_configured_semantic_models_with_bootstrap(
        workspace_root,
        workspace,
        configured,
        packs_config,
        limits,
        |catalog| {
            // The legacy host-supplied route keeps installing the whole release.
            Ok(
                match bootstrap_semantic_model_catalog(catalog, &ReleaseCoverage::WholeRelease)? {
                    Some(leases) => (true, leases),
                    None => (false, Vec::new()),
                },
            )
        },
    )
}

fn activate_legacy_configured_semantic_models_with_bootstrap(
    workspace_root: &Path,
    workspace: &WorkspaceAnalyzer,
    configured: Option<ConfiguredSemanticModels>,
    packs_config: Option<Arc<WorkspacePacksConfig>>,
    limits: SemanticModelRuntimeLimits,
    bootstrap: impl FnOnce(
        &SemanticPackCatalog,
    ) -> Result<
        (
            bool,
            Vec<crate::analyzer::semantic_model::CatalogLeaseToken>,
        ),
        String,
    >,
) -> Result<WorkspacePackActivationState, String> {
    if packs_config.is_some() {
        let ecosystems = workspace_pack_ecosystems(workspace, packs_config.as_deref());
        return Ok(WorkspacePackActivationState::unavailable(
            packs_config, ecosystems,
            "workspace packs document cannot be combined with legacy semantic-pack environment configuration".to_owned(),
        ));
    }
    let configured = configured.unwrap_or(ConfiguredSemanticModels {
        catalog_root: None,
        evidence: Vec::new(),
        workspace_models: false,
    });
    let catalog = {
        let _scope = profiling::scope("semantic_pack.open_catalog");
        match &configured.catalog_root {
            Some(catalog_root) => SemanticPackCatalog::open(
                catalog_root,
                CatalogOpenMode::ReadOnly,
                CatalogOptions::default(),
            )
            .map_err(|error| {
                format!(
                    "failed to open configured semantic-pack catalog {}: {error}",
                    catalog_root.display()
                )
            })?,
            None => open_ambient_semantic_pack_catalog(
                workspace,
                workspace_root,
                CatalogOptions::default(),
            )
            .map_err(|error| format!("failed to open generated semantic-pack catalog: {error}"))?,
        }
    };
    let mut evidence = configured
        .evidence
        .into_iter()
        .map(ConfiguredSemanticModelEvidence::parse)
        .collect::<Result<Vec<_>, _>>()?;
    let (shipped, leases) = bootstrap(&catalog)?;
    if shipped {
        {
            let _scope = profiling::scope("semantic_pack.intrinsic_evidence");
            append_intrinsic_semantic_evidence(workspace, &mut evidence);
        }
    }
    // The reviewed workspace-local route is the shared analysis helper, the
    // same one the CLI policy coordinator drives through its pack-activation
    // transaction (#2493). Registration is loud: a checked-in model this host
    // cannot read, compile, or register fails the bind rather than being
    // skipped.
    let workspace_models = if configured.workspace_models {
        let registration = register_workspace_semantic_models(
            workspace_root,
            &catalog,
            WorkspaceSemanticModelOptions::default(),
        );
        let registration = match registration {
            Ok(registration) => registration,
            Err(error) => {
                catalog
                    .release_leases(&leases)
                    .map_err(|release_error| release_error.to_string())?;
                return Err(error.to_string());
            }
        };
        evidence.extend(registration.evidence);
        registration.models
    } else {
        Vec::new()
    };
    evidence.sort();
    evidence.dedup();
    let request = SemanticModelActivationRequest {
        host_activation: workspace
            .analyzer()
            .host_activation_context()
            .unwrap_or_else(HostActivationContext::library_none),
        approximate_standard_libraries: Vec::new(),
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION"))
            .expect("crate version must be valid semver"),
        evidence,
        controls: Vec::new(),
        limits,
    };
    let outcome = {
        let _scope = profiling::scope("semantic_pack.acquire_active");
        acquire_active_semantic_models(
            workspace.analyzer(),
            &catalog,
            None,
            &request,
            &CancellationToken::default(),
        )
    };
    catalog
        .release_leases(&leases)
        .map_err(|error| error.to_string())?;
    if let SemanticModelRuntimeOutcome::Ready { active, .. } = &outcome {
        // Post-activation proof: a registered model that never reaches the
        // active set is invisible, and an invisible model decides answers
        // by its absence. MCP treats every such case, review gate
        // included, as a hard bind error.
        if let Some(inactive) =
            workspace_semantic_models_not_active(&workspace_models, active).first()
        {
            return Err(format!(
                "workspace semantic model {} did not activate: {:?}",
                inactive.model.path,
                active.activation_report()
            ));
        }
        eprintln!(
            "bifrost: semantic-pack activation active_set={} shards={} records={}",
            active.active_model_set_hash(),
            active.shards().len(),
            active.activation_report().loaded_records
        );
        if active.shards().is_empty() {
            eprintln!(
                "bifrost: semantic-pack activation selected no shards: {:?}",
                active.activation_report()
            );
        }
    }
    let mut state = WorkspacePackActivationState {
        update_source: None,
        config: None,
        ecosystems: Vec::new(),
        failure: None,
        overlay: SemanticModelOverlayStatus::NoModels,
        pending_acquisitions: Vec::new(),
        shipped_pack_acquisition_pending: None,
        coverage: None,
    };
    state.set_runtime_outcome(&[], Some(&outcome));
    Ok(state)
}

#[cfg(test)]
mod workspace_semantic_model_configuration_tests {
    use super::*;
    use crate::analyzer::semantic_model::SemanticModelOverlayDisposition;
    use crate::path_normalization::NormalizePath;

    const WORKSPACE_PACK: &str = r#"{
  "schema_version": 2,
  "pack_id": "workspace.job-maker",
  "version": "1.0.0",
  "producer": { "name": "workspace", "version": "1.0.0" },
  "language": "rust",
  "ecosystem": "cargo",
  "compatibility": { "bifrost": ">=0.8.0, <1.0.0", "toolchains": [] },
  "provenance": { "source": "workspace:.bifrost/semantic-models/job-maker.json" },
  "license": "MIT",
  "completeness": "partial",
  "safety": { "generated_code_only": true, "review_required": false },
  "shards": [{
    "id": "workspace.job-maker.declarations",
    "activation": [{ "targets": [], "configurations": [] }],
    "payload": {
      "kind": "declaration_facts",
      "types": [{
        "id": "workspace.type.generated-job-maker",
        "name": "workspace.GeneratedJobMaker",
        "type_kind": "struct",
        "visibility": "public",
        "type_parameters": [],
        "hierarchy": [],
        "aliases": [],
        "extension_surfaces": [],
        "locator": {
          "kind": "artifact",
          "path": "workspace/job_maker.rs",
          "symbol": "GeneratedJobMaker"
        }
      }],
      "members": [],
      "relations": []
    }
  }]
}"#;

    /// Bootstrap registration is process-wide. Run `test_name` again in a child
    /// process so its provider cannot collide with the recording provider of
    /// release_coverage_tests, including when libtest runs both in one process.
    /// Returns true in the parent, which has then already checked the child.
    fn rerun_in_isolated_bootstrap_child(test_name: &str) -> bool {
        const CHILD: &str = "BIFROST_TEST_ISOLATED_BOOTSTRAP_CHILD";
        if std::env::var_os(CHILD).is_some() {
            return false;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!(
                    "searchtools_service::workspace_semantic_model_configuration_tests::{test_name}"
                ),
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("run graph activation with an isolated bootstrap");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed"),
            "{test_name} child did not pass exactly one test: stdout={stdout} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        true
    }

    /// A real MCP session over a durable test catalog whose pack the workspace
    /// activation published. With `authored_source`, the pack's type is
    /// anchored to the declaration `Anchored` in `src/lib.rs`, so the published
    /// overlay is row-backed and carries a workspace-authored path.
    struct GraphFixture {
        _temp: tempfile::TempDir,
        root: PathBuf,
        catalog: SemanticPackCatalog,
        source: crate::analyzer::semantic_model::DurablePackSource,
        model: serde_json::Value,
        service: SearchToolsService,
    }

    fn graph_fixture(authored_source: bool) -> GraphFixture {
        use crate::analyzer::semantic_model::{
            CompilerOptions, DurablePackSource, DurablePackSourceKind, SourceFormat, compile_source,
        };
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        std::fs::write(root.join("lib.rs"), "pub struct Local;\n").unwrap();
        std::fs::create_dir_all(root.join(".bifrost")).unwrap();
        std::fs::write(
            root.join(".bifrost/packs.json"),
            r#"{"schema_version":1,"catalog":".bifrost/catalog","ecosystems":[]}"#,
        )
        .unwrap();
        let catalog = SemanticPackCatalog::open(
            &root.join(".bifrost/catalog"),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let source = DurablePackSource {
            kind: DurablePackSourceKind::PreShipped,
            source_id: "test:reexport-graph".into(),
        };
        let mut model: serde_json::Value = serde_json::from_str(WORKSPACE_PACK).unwrap();
        model["schema_version"] = serde_json::json!(29);
        model["compatibility"]
            .as_object_mut()
            .unwrap()
            .remove("bifrost");
        model["rust_external_reexports"] = serde_json::json!([{
            "kind": "explicit_use", "facade_path": "facade::first", "use_item_id": 1,
            "target": {"external_crate_id": 1, "external_crate_name": "core",
                       "item_id": 2, "path": ["core", "item"]}
        }]);
        if authored_source {
            std::fs::create_dir_all(root.join("src")).unwrap();
            std::fs::write(root.join("src/lib.rs"), "pub struct Anchored;\n").unwrap();
            model["shards"][0]["payload"]["types"][0]["locator"] = serde_json::json!({
                "kind": "source", "path": "src/lib.rs", "symbol": "Anchored"
            });
        }
        let first = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&model).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        catalog.install(&first, &source).unwrap();
        // Enable the host's intrinsic-evidence route without registering any
        // product packs. The durable test pack above is the entire catalog.
        install_semantic_model_catalog_bootstrap(|_, _| Ok(Vec::new())).unwrap();
        let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        GraphFixture {
            _temp: temp,
            root,
            catalog,
            source,
            model,
            service,
        }
    }

    /// The published overlay and the warm worker that produced it.
    fn wait_for_graph_publication(
        service: &SearchToolsService,
    ) -> (
        Arc<crate::analyzer::semantic_model::SemanticModelOverlay>,
        Arc<SemanticPackWarm>,
    ) {
        use crate::analyzer::semantic_model::SemanticModelOverlayRead;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let status = service
                .call_tool_value("get_active_workspace", serde_json::json!({}))
                .unwrap();
            let guard = service.session.read().unwrap();
            let session = guard.as_ref().unwrap();
            if status["semantic_packs_ready"] == true
                && let SemanticModelOverlayRead::Published(overlay) =
                    session.snapshot.analyzer().semantic_model_overlay_read()
            {
                assert_eq!(
                    overlay
                        .symbols_named("workspace.GeneratedJobMaker")
                        .disposition,
                    SemanticModelOverlayDisposition::Unique
                );
                return (overlay, Arc::clone(&session.semantic_packs));
            }
            assert!(
                Instant::now() < deadline,
                "activation never published: {status}"
            );
            drop(guard);
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn reexport_graph_change_schedules_warm_and_republishes() {
        if rerun_in_isolated_bootstrap_child("reexport_graph_change_schedules_warm_and_republishes")
        {
            return;
        }
        use crate::analyzer::semantic_model::{
            CompilerOptions, SemanticModelOverlayRead, SourceFormat, compile_source,
        };
        let GraphFixture {
            _temp,
            root,
            catalog,
            source,
            mut model,
            service,
        } = graph_fixture(false);
        let wait_for_publication = || wait_for_graph_publication(&service);
        let (before, worker) = wait_for_publication();
        // Change only the pack's re-export graph. Workspace files and pack
        // declarations are byte-identical; a no-op source notification asks
        // the host to compare fresh activation inputs.
        model["rust_external_reexports"][0]["facade_path"] = serde_json::json!("facade::second");
        let second = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&model).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        assert!(catalog.remove_source(&source).unwrap());
        catalog.install(&second, &source).unwrap();
        {
            let mut guard = service.session.write().unwrap();
            let session = guard.as_mut().unwrap();
            let changes = BTreeSet::from([ProjectFile::new(root.clone(), "lib.rs")]);
            // Observe the update decision before a warm can publish onto its
            // cache. A second notification must retain Pending and schedule.
            session.snapshot = Arc::new(SearchToolsService::update_session_snapshot(
                session,
                Some(&changes),
                None,
            ));
            assert!(matches!(
                session.snapshot.analyzer().semantic_model_overlay_read(),
                SemanticModelOverlayRead::Pending(_)
            ));
            SearchToolsService::apply_changed_files(session, changes, None).unwrap();
            assert!(!Arc::ptr_eq(&worker, &session.semantic_packs));
        }
        let (after, _) = wait_for_publication();
        assert_ne!(
            before.active_model_set_hash(),
            after.active_model_set_hash()
        );
        assert_eq!(
            std::fs::read_to_string(root.join("lib.rs")).unwrap(),
            "pub struct Local;\n"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12435: a directory-only or alias change event carried a stale published overlay and the pack warm never ran"
    )]
    fn directory_and_alias_changes_refuse_publication_carry_through_the_update_path() {
        if rerun_in_isolated_bootstrap_child(
            "directory_and_alias_changes_refuse_publication_carry_through_the_update_path",
        ) {
            return;
        }
        use crate::analyzer::semantic_model::SemanticModelOverlayRead;
        let GraphFixture {
            _temp,
            root,
            service,
            ..
        } = graph_fixture(true);
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("docs/readme.md"), "unrelated\n").unwrap();
        let (mut overlay, mut worker) = wait_for_graph_publication(&service);
        // The row-backed overlay was authored from this workspace path.
        assert!(
            overlay.any_authored_path(|path| path == "src/lib.rs"),
            "{:?}",
            overlay.symbols_named("workspace.GeneratedJobMaker").records
        );
        let cases: [(&str, bool); 6] = [
            // An unrelated sibling carries, and so do spellings that only
            // share a string prefix with a protected path.
            ("docs/readme.md", true),
            ("docs/deleted-since.md", true),
            (".bifrost2", true),
            ("src2", true),
            // A directory event names only the directory.
            (".bifrost", false),
            ("src", false),
        ];
        for (path, carries) in cases {
            let mut guard = service.session.write().unwrap();
            let session = guard.as_mut().unwrap();
            let changes = BTreeSet::from([ProjectFile::new(root.clone(), path)]);
            session.snapshot = Arc::new(SearchToolsService::update_session_snapshot(
                session,
                Some(&changes),
                None,
            ));
            let read = session.snapshot.analyzer().semantic_model_overlay_read();
            if carries {
                let SemanticModelOverlayRead::Published(carried) = read else {
                    panic!("{path} must carry the published overlay");
                };
                assert!(Arc::ptr_eq(&overlay, &carried), "{path}");
                SearchToolsService::apply_changed_files(session, changes, None).unwrap();
                assert!(
                    Arc::ptr_eq(&worker, &session.semantic_packs),
                    "{path} must not schedule a warm"
                );
            } else {
                assert!(
                    matches!(read, SemanticModelOverlayRead::Pending(_)),
                    "{path} must leave the overlay Pending"
                );
                SearchToolsService::apply_changed_files(session, changes, None).unwrap();
                assert!(
                    !Arc::ptr_eq(&worker, &session.semantic_packs),
                    "{path} must schedule the warm"
                );
                drop(guard);
                (overlay, worker) = wait_for_graph_publication(&service);
            }
        }
        // An alias spelling that no listing certifies, such as another case
        // for a path that no longer exists, could name the authored file.
        let mut guard = service.session.write().unwrap();
        let session = guard.as_mut().unwrap();
        let changes = BTreeSet::from([ProjectFile::new(root.clone(), "SRC/Lib.rs")]);
        session.snapshot = Arc::new(SearchToolsService::update_session_snapshot(
            session,
            Some(&changes),
            None,
        ));
        assert!(matches!(
            session.snapshot.analyzer().semantic_model_overlay_read(),
            SemanticModelOverlayRead::Pending(_)
        ));
        SearchToolsService::apply_changed_files(session, changes, None).unwrap();
        assert!(!Arc::ptr_eq(&worker, &session.semantic_packs));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13500: a fallback model locator kept its old binding when its file gained the declaration"
    )]
    fn fallback_model_locators_rebind_when_declarations_appear() {
        use crate::analyzer::packs_document::{
            activate_workspace_semantic_sources_in_catalog, parse_workspace_packs_config,
        };
        let mut differences = Vec::new();
        for carried_sources in [serde_json::json!([]), serde_json::json!(["src/late.rs"])] {
            let mut model: serde_json::Value = serde_json::from_str(WORKSPACE_PACK).unwrap();
            model["schema_version"] = serde_json::json!(29);
            model["compatibility"]
                .as_object_mut()
                .unwrap()
                .remove("bifrost");
            model["carried_sources"] = carried_sources.clone();
            model["shards"][0]["payload"]["types"][0]["locator"] = serde_json::json!({
                "kind": "source", "path": "src/late.rs", "symbol": "late.Late"
            });
            let (_temp, analyzer) = workspace(&model.to_string());
            let root = analyzer.analyzer().project().root().to_path_buf();
            let config = workspace_activation_config(&analyzer);
            let packs =
                parse_workspace_packs_config(r#"{"schema_version":1,"ecosystems":[]}"#).unwrap();
            let cancellation = CancellationToken::default();
            let sources = WorkspaceActivationSources {
                catalog_root: &root,
                workspace_model_root: Some(&root),
                config: Some(&packs),
                intrinsic_shipped_models: false,
            };
            let catalog =
                Arc::new(SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap());
            let activation = activate_workspace_semantic_sources_in_catalog(
                &analyzer,
                &config,
                &catalog,
                sources,
                &[],
                &cancellation,
            )
            .unwrap()
            .unwrap();
            assert!(activation.outcome.complete(), "{:?}", activation.outcome);
            let original = analyzer
                .analyzer()
                .semantic_model_overlay_read()
                .published()
                .unwrap();
            let initial_paths = original.symbols_at_authored_path("src/late.rs");
            assert_eq!(
                initial_paths.records.len(),
                carried_sources.as_array().unwrap().len()
            );
            let source = WorkspaceActivationUpdateSource::new(
                Arc::clone(&catalog),
                activation.registration_evidence,
                Some(&packs),
                analyzer.retention_budget(),
            )
            .unwrap();
            std::fs::write(root.join("src/lib.rs"), "pub struct Unrelated;\n").unwrap();
            let unrelated = BTreeSet::from([ProjectFile::new(root.clone(), "src/lib.rs")]);
            let analyzer = analyzer.update_with_activation_context(
                &unrelated,
                source.context(&config, sources, &[], &cancellation),
            );
            let carried = analyzer
                .analyzer()
                .semantic_model_overlay_read()
                .published()
                .unwrap();
            assert!(
                Arc::ptr_eq(&original, &carried),
                "an ordinary unrelated save must carry the publication"
            );
            assert_eq!(
                carried
                    .symbols_at_authored_path("src/late.rs")
                    .records
                    .len(),
                initial_paths.records.len()
            );
            std::fs::write(root.join("src/late.rs"), "pub struct Unrelated;\n").unwrap();
            let locator_change = BTreeSet::from([ProjectFile::new(root.clone(), "src/late.rs")]);
            let analyzer = analyzer.update_with_activation_context(
                &locator_change,
                source.context(&config, sources, &[], &cancellation),
            );
            let same_binding = analyzer
                .analyzer()
                .semantic_model_overlay_read()
                .published()
                .unwrap();
            assert!(
                Arc::ptr_eq(&original, &same_binding),
                "an unrelated declaration at a locator path must preserve its binding"
            );
            assert_eq!(
                same_binding
                    .symbols_at_authored_path("src/late.rs")
                    .records
                    .len(),
                initial_paths.records.len()
            );
            std::fs::write(root.join("src/late.rs"), "pub struct Late;\n").unwrap();
            let changed = BTreeSet::from([ProjectFile::new(root.clone(), "src/late.rs")]);
            let updated = analyzer.update_with_activation_context(
                &changed,
                source.context(&config, sources, &[], &cancellation),
            );
            let cold_project: Arc<dyn Project> =
                Arc::new(FilesystemProject::new(root.clone()).unwrap());
            let cold =
                WorkspaceAnalyzer::build_ephemeral_footgun(cold_project, AnalyzerConfig::default())
                    .unwrap();
            let cold_catalog =
                Arc::new(SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap());
            let activation = activate_workspace_semantic_sources_in_catalog(
                &cold,
                &config,
                &cold_catalog,
                sources,
                &[],
                &cancellation,
            )
            .unwrap()
            .unwrap();
            assert!(activation.outcome.complete(), "{:?}", activation.outcome);
            let cold_overlay = cold
                .analyzer()
                .semantic_model_overlay_read()
                .published()
                .unwrap();
            let expected = cold_overlay
                .symbols_named("workspace.GeneratedJobMaker")
                .records[0]
                .location
                .clone();
            assert!(
                matches!(&expected, crate::analyzer::semantic_model::SemanticModelLocation::Authored(anchor) if anchor.range.end_byte > 0),
                "cold must bind the new declaration: {expected:?}"
            );
            // An invalidated publication waits for the ordinary activation warm.
            if updated
                .analyzer()
                .semantic_model_overlay_read()
                .published()
                .is_none()
            {
                let warm_catalog = Arc::new(
                    SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap(),
                );
                let activation = activate_workspace_semantic_sources_in_catalog(
                    &updated,
                    &config,
                    &warm_catalog,
                    sources,
                    &[],
                    &cancellation,
                )
                .unwrap()
                .unwrap();
                assert!(activation.outcome.complete(), "{:?}", activation.outcome);
            }
            let overlay = updated
                .analyzer()
                .semantic_model_overlay_read()
                .published()
                .unwrap();
            let actual = overlay.symbols_named("workspace.GeneratedJobMaker").records[0]
                .location
                .clone();
            if actual != expected {
                differences.push(format!(
                    "carried_sources={carried_sources}: incremental={actual:?}, cold={expected:?}"
                ));
            }
        }
        assert!(differences.is_empty(), "{differences:#?}");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13500: a fallback model locator kept its old binding when its file gained the declaration"
    )]
    fn fallback_model_locator_rebinds_persisted_go_policy_products() {
        use crate::analyzer::packs_document::{
            activate_workspace_semantic_sources_in_catalog, parse_workspace_packs_config,
        };
        use crate::analyzer::semantic_model::*;
        use brokk_bifrost_go_analysis::analyzer::{GoModulePackProducer, GoPinnedPackage};
        use brokk_bifrost_policy::{
            PolicyHostActivationContext, PolicySourceIdentity,
            evaluate_policy_inputs_with_analyzer_and_host_activation,
        };
        use brokk_bifrost_rql::{CodeQuery, execute_workspace};

        // Test-only library: a direct field is provable only while the owner's
        // promoted-member inventory is exact. Rebinding Extra to source makes
        // that inventory open, so the nilness policy must retain uncertainty.
        let artifact_root = tempfile::tempdir().unwrap();
        std::fs::write(artifact_root.path().join("registry.go"), "package registry\ntype Base struct { Extra string }\ntype FieldResult struct { *Base; Name string }\nfunc PointerField() (*FieldResult, bool) { return nil, false }\n").unwrap();
        let artifact = read_exact_source_set(
            artifact_root.path(),
            &["registry.go".into()],
            1,
            1,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();
        let request = ArtifactProductionRequest {
            path: artifact_root.path().to_path_buf(),
            artifact_kind: ExternalArtifactKind::GoSourceSet,
            pack_id: "test.locator-bindings".into(),
            pack_version: "1.0.0".into(),
            ecosystem: "go".into(),
            compatibility: Compatibility {
                bifrost: None,
                toolchains: Vec::new(),
            },
            activation: vec![ActivationSelector {
                package: None,
                module: None,
                toolchain: None,
                targets: Vec::new(),
                configurations: Vec::new(),
                artifact_sha256: None,
                production_input_digest: None,
            }],
            provenance: Provenance {
                source: "test:locator-bindings".into(),
                revision: None,
                rust_artifact_approximation: None,
            },
            license: "MIT".into(),
            safety: Safety {
                generated_code_only: false,
                review_required: false,
            },
        };
        let production = GoModulePackProducer.produce_loaded_source_set(
            &request,
            &ArtifactProducerLimits::default(),
            None,
            &artifact,
            &[GoPinnedPackage {
                import_path: "example.com/result/registry".into(),
                name: "registry".into(),
                files: vec!["registry.go".into()],
            }],
        );
        assert!(
            production.diagnostics.is_empty(),
            "{:?}",
            production.diagnostics
        );
        let mut model = serde_json::to_value(production.pack.unwrap()).unwrap();
        model["compatibility"]
            .as_object_mut()
            .unwrap()
            .remove("bifrost");
        let mut extra_id = None;
        for shard in model["shards"].as_array_mut().unwrap() {
            for selector in shard["activation"].as_array_mut().unwrap() {
                selector.as_object_mut().unwrap().remove("artifact_sha256");
            }
            if let Some(members) = shard["payload"]["members"].as_array_mut() {
                for member in members {
                    if member["name"] == "Extra" {
                        member["locator"] = serde_json::json!({"kind":"source","path":"late/late.go","symbol":"late.Late.Extra"});
                        extra_id = Some(member["id"].as_str().unwrap().to_owned());
                    }
                }
            }
        }
        let extra_id = extra_id.expect("the fixture publishes Base.Extra");
        model["shards"].as_array_mut().unwrap().push(serde_json::json!({
            "id":"result-contract", "activation":[{}], "payload": {
                "kind":"procedure_summaries", "summaries":[{
                    "id":"pointer-result", "target":{"path":"registry.go","symbol":"example.com/result/registry.PointerField()","has_receiver":false,"variadic":false,"parameter_count":0},
                    "completeness":"complete", "normal_result_count":2,"transfers":[],"effects":[],
                    "result_contracts":[{"result_ordinal":0,"condition_result_ordinal":1,"predicate":"true","result_success_predicate":"non_null","member_contracts":[]}]
                }]
            }
        }));
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let model_path = ".bifrost/semantic-models/locator.json";
        std::fs::create_dir_all(root.join(".bifrost/semantic-models")).unwrap();
        std::fs::write(root.join(model_path), serde_json::to_vec(&model).unwrap()).unwrap();
        std::fs::write(root.join("main.go"), "package main\nimport registry \"example.com/result/registry\"\nfunc use() { value, _ := registry.PointerField(); _ = value.Name }\n").unwrap();
        std::fs::create_dir_all(root.join("late")).unwrap();
        std::fs::write(root.join("late/late.go"), "package late\n").unwrap();
        let repo = git2::Repository::init(&root).unwrap();
        let commit = |files: &[&str]| {
            let mut index = repo.index().unwrap();
            for path in files {
                index.add_path(Path::new(path)).unwrap();
            }
            let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
            index.write().unwrap();
            let parent = repo.head().ok().map(|head| head.peel_to_commit().unwrap());
            let parents = parent.iter().collect::<Vec<_>>();
            let signature = git2::Signature::now("Fixture", "fixture@example.test").unwrap();
            repo.commit(
                Some("HEAD"),
                &signature,
                &signature,
                "fixture",
                &tree,
                &parents,
            )
            .unwrap();
        };
        commit(&["main.go", model_path, "late/late.go"]);
        let stores = tempfile::tempdir().unwrap();
        let build = |database: &str| {
            let project: Arc<dyn Project> = Arc::new(FilesystemProject::new(root.clone()).unwrap());
            let store = crate::analyzer::store::AnalyzerStore::open_persistent(
                &stores.path().join(database),
            )
            .unwrap();
            let context = crate::analyzer::tree_sitter_analyzer::store_context_from_store(
                project.as_ref(),
                store,
                false,
            );
            WorkspaceAnalyzer::build_with_store_context_for_test(
                project,
                AnalyzerConfig::default(),
                context,
            )
            .unwrap()
        };
        let initial = build("incremental.db");
        let config = workspace_activation_config(&initial);
        let packs =
            parse_workspace_packs_config(r#"{"schema_version":1,"ecosystems":[]}"#).unwrap();
        let cancellation = CancellationToken::default();
        let sources = WorkspaceActivationSources {
            catalog_root: &root,
            workspace_model_root: Some(&root),
            config: Some(&packs),
            intrinsic_shipped_models: false,
        };
        let activate = |workspace: &WorkspaceAnalyzer, catalog: &SemanticPackCatalog| {
            let activation = activate_workspace_semantic_sources_in_catalog(
                workspace,
                &config,
                catalog,
                sources,
                &[],
                &cancellation,
            )
            .unwrap()
            .unwrap();
            assert!(activation.outcome.complete(), "{:?}", activation.outcome);
            activation
        };
        let query = CodeQuery::from_json(&serde_json::json!({
            "languages":["go"],"match":{"kind":"call","callee":{"name":"PointerField"}},
            "steps":[{"op":"call_shape"},{"op":"call_result_contracts"},{"op":"result_contract_uses"}],"result_detail":"full"
        })).unwrap();
        let products =
            |workspace: &WorkspaceAnalyzer,
             activation: &crate::analyzer::packs_document::WorkspacePacksActivation| {
                let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
                let rows =
                    serde_json::to_value(execute_workspace(workspace, &flow, &query)).unwrap();
                assert_eq!(rows["results"].as_array().unwrap().len(), 1, "{rows:#}");
                let policy = [PolicyEvaluationInput::embedded(
                    PolicySourceIdentity::new("test:locator-nilness"),
                    include_str!(
                        "../../bifrost-policy/policy-packs/bifrost.code-smells/policies/go-nil-dereference.rqlp"
                    ),
                )];
                let outcome = evaluate_policy_inputs_with_analyzer_and_host_activation(
                    &root,
                    &policy,
                    workspace,
                    &flow,
                    &PolicyEvaluationOptions::new(
                        PolicyEvaluationDate::from_ymd(2026, 11, 16).unwrap(),
                    ),
                    PolicyHostActivationContext::new(Some(&packs), Some(activation), &[], None),
                    None,
                    workspace.retention_budget(),
                )
                .unwrap();
                (
                    rows["results"].clone(),
                    serde_json::to_value(outcome.report().runs()).unwrap(),
                )
            };
        let catalog =
            Arc::new(SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap());
        let activation = activate(&initial, &catalog);
        let before = products(&initial, &activation);
        assert_eq!(before.0[0]["use_validation"], "violated", "{before:#?}");
        let source = WorkspaceActivationUpdateSource::new(
            Arc::clone(&catalog),
            activation.registration_evidence.clone(),
            Some(&packs),
            initial.retention_budget(),
        )
        .unwrap();
        std::fs::create_dir_all(root.join("late")).unwrap();
        std::fs::write(
            root.join("late/late.go"),
            "package late\ntype Late struct { Extra string }\n",
        )
        .unwrap();
        commit(&["late/late.go"]);
        let changes = BTreeSet::from([ProjectFile::new(root.clone(), "late/late.go")]);
        let updated = initial.update_with_activation_context(
            &changes,
            source.context(&config, sources, &[], &cancellation),
        );
        let warm_catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let updated_activation = if updated
            .analyzer()
            .semantic_model_overlay_read()
            .published()
            .is_none()
        {
            activate(&updated, &warm_catalog)
        } else {
            activation
        };
        let incremental = products(&updated, &updated_activation);
        let cold = build("cold.db");
        let cold_catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let cold_activation = activate(&cold, &cold_catalog);
        let cold_overlay = cold
            .analyzer()
            .semantic_model_overlay_read()
            .published()
            .unwrap();
        let cold_location = &cold_overlay.symbols_with_id(&extra_id).records[0].location;
        assert!(
            matches!(cold_location, SemanticModelLocation::Authored(anchor) if anchor.range.end_byte > 0),
            "{cold_location:?}"
        );
        let expected = products(&cold, &cold_activation);
        assert_eq!(expected.0[0]["use_validation"], "unknown", "{expected:#?}");
        assert_ne!(
            before.0, expected.0,
            "rebinding must change the modeled member proof"
        );
        let read_units = |database: &str, workspace: &WorkspaceAnalyzer| {
            let conn = rusqlite::Connection::open(stores.path().join(database)).unwrap();
            let snapshot = workspace.analyzer().workspace_content_identity().unwrap();
            conn.prepare("SELECT partition_kind, json(product) FROM policy_units JOIN policy_unit_snapshots USING(unit_id) WHERE seed_rel_path='main.go' AND content_identity=?1 ORDER BY partition_kind, root_locator, selector_digest").unwrap()
                .query_map([snapshot.as_bytes().as_slice()], |row| Ok((row.get::<_,String>(0)?, row.get::<_,String>(1)?))).unwrap()
                .collect::<Result<Vec<_>,_>>().unwrap()
        };
        let incremental_units = read_units("incremental.db", &updated);
        let cold_units = read_units("cold.db", &cold);
        assert!(!cold_units.is_empty(), "the policy must publish units");
        assert_eq!(
            incremental_units, cold_units,
            "incremental={incremental:#?}, cold={expected:#?}"
        );
        let tree = repo
            .head()
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .tree_id()
            .to_string();
        let read_evaluations = |database: &str| {
            let conn = rusqlite::Connection::open(stores.path().join(database)).unwrap();
            conn.prepare("SELECT json_object('completion',p.completion,'detail',json(p.completion_detail),'qualified',p.qualified,'qualification_detail',p.qualification_detail,'diagnostics',json(p.diagnostics),'unreliable',e.aggregate_unreliable) FROM policy_evaluation_policies p JOIN policy_evaluations e USING(evaluation_id) WHERE e.base_tree_oid=?1 ORDER BY policy_id").unwrap()
                .query_map([&tree], |row| row.get::<_,String>(0)).unwrap().collect::<Result<Vec<_>,_>>().unwrap()
        };
        let cold_evaluations = read_evaluations("cold.db");
        assert!(
            !cold_evaluations.is_empty(),
            "the committed snapshot must publish an evaluation"
        );
        assert_eq!(read_evaluations("incremental.db"), cold_evaluations);
        assert_eq!(incremental, expected);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11573: a refreshed snapshot lost the semantic-model overlay and get_symbol_sources reported a complete not_found"
    )]
    fn real_workspace_models_republish_only_unchanged_inputs() {
        use crate::analyzer::packs_document::{
            activate_workspace_semantic_sources_in_catalog, parse_workspace_packs_config,
        };
        use crate::analyzer::semantic_model::SemanticModelOverlayRead;
        let mut external_model: serde_json::Value = serde_json::from_str(WORKSPACE_PACK).unwrap();
        external_model["schema_version"] = serde_json::json!(29);
        external_model["compatibility"]
            .as_object_mut()
            .unwrap()
            .remove("bifrost");
        external_model["carried_sources"] = serde_json::json!(["dependency/generated.rs"]);
        external_model["shards"][0]["payload"]["types"][0]["locator"] = serde_json::json!({
            "kind": "source", "path": "dependency/generated.rs", "symbol": "workspace.GeneratedJobMaker"
        });
        let (temp, analyzer) = workspace(&external_model.to_string());
        let root = analyzer.analyzer().project().root().to_path_buf();
        let config = workspace_activation_config(&analyzer);
        let packs =
            parse_workspace_packs_config(r#"{"schema_version":1,"ecosystems":[]}"#).unwrap();
        let catalog =
            Arc::new(SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap());
        let cancellation = CancellationToken::default();
        let sources = WorkspaceActivationSources {
            catalog_root: &root,
            workspace_model_root: Some(&root),
            config: Some(&packs),
            intrinsic_shipped_models: false,
        };
        let activation = activate_workspace_semantic_sources_in_catalog(
            &analyzer,
            &config,
            &catalog,
            sources,
            &[],
            &cancellation,
        )
        .unwrap()
        .unwrap();
        assert!(activation.outcome.complete(), "{:?}", activation.outcome);
        let original = analyzer
            .analyzer()
            .semantic_model_overlay_read()
            .published()
            .unwrap();
        assert_eq!(
            original
                .symbols_named("workspace.GeneratedJobMaker")
                .disposition,
            SemanticModelOverlayDisposition::Unique
        );
        let source = WorkspaceActivationUpdateSource::new(
            Arc::clone(&catalog),
            activation.registration_evidence,
            Some(&packs),
            analyzer.retention_budget(),
        )
        .unwrap();
        let context = || source.context(&config, sources, &[], &cancellation);
        std::fs::write(root.join("src/lib.rs"), "pub struct Changed;\n").unwrap();
        // The pack's carried locator is not an indexed workspace definition.
        // An unrelated local file at that archive-entry path must not make
        // its typed model description refresh the workspace.
        std::fs::create_dir_all(root.join("dependency")).unwrap();
        std::fs::write(
            root.join("dependency/generated.rs"),
            "pub struct Unrelated;\n",
        )
        .unwrap();
        let mut service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        service.update_strategy = UpdateStrategy::WatchFiles;
        let query = |snapshot: &WorkspaceAnalyzer| {
            let published = Arc::new(snapshot.clone());
            {
                let mut guard = service.session.write().unwrap();
                guard.as_mut().unwrap().snapshot = Arc::clone(&published);
            }
            let answer = service
                .call_tool_value(
                    "get_symbol_sources",
                    serde_json::json!({
                        "symbols": ["workspace.GeneratedJobMaker"]
                    }),
                )
                .unwrap();
            let guard = service.session.read().unwrap();
            assert!(
                Arc::ptr_eq(&published, &guard.as_ref().unwrap().snapshot),
                "model source blocks must not refresh the workspace"
            );
            answer
        };
        let before = query(&analyzer);
        assert_eq!(before["not_found"], serde_json::json!([]), "{before}");
        assert!(
            before["sources"].as_array().unwrap().iter().any(|source| {
                source["presentation"] == "semantic_model"
                    && source["path"] == "dependency/generated.rs"
            }),
            "{before}"
        );
        let changed = BTreeSet::from([ProjectFile::new(root.clone(), "src/lib.rs")]);
        let updated = analyzer.update_with_activation_context(&changed, context());
        let after = query(&updated);
        assert_eq!(before["sources"], after["sources"]);
        assert_eq!(after["not_found"], serde_json::json!([]), "{after}");
        let carried = updated
            .analyzer()
            .semantic_model_overlay_read()
            .published()
            .unwrap();
        assert!(Arc::ptr_eq(&original, &carried));
        std::fs::write(
            temp.path().join(".bifrost/semantic-models/job-maker.json"),
            WORKSPACE_PACK.replace("GeneratedJobMaker", "Replacement"),
        )
        .unwrap();
        let model_changed = BTreeSet::from([ProjectFile::new(
            root.clone(),
            ".bifrost/semantic-models/job-maker.json",
        )]);
        let pending = updated.update_with_activation_context(&model_changed, context());
        assert!(matches!(
            pending.analyzer().semantic_model_overlay_read(),
            SemanticModelOverlayRead::Pending(_)
        ));
        std::fs::write(root.join("src/lib.rs"), "pub struct Later;\n").unwrap();
        let pending = pending.update_with_activation_context(&changed, context());
        assert!(matches!(
            pending.analyzer().semantic_model_overlay_read(),
            SemanticModelOverlayRead::Pending(_)
        ));
        let incomplete = query(&pending);
        assert_eq!(incomplete["complete"], false, "{incomplete}");
        assert!(
            incomplete.to_string().contains("SemanticModelsPending"),
            "{incomplete}"
        );
        // A host warm opens a fresh ephemeral catalog; prior session-only
        // registrations belong to its previous activation.
        let catalog =
            Arc::new(SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap());
        let activation = activate_workspace_semantic_sources_in_catalog(
            &pending,
            &config,
            &catalog,
            sources,
            &[],
            &cancellation,
        )
        .unwrap()
        .unwrap();
        assert!(activation.outcome.complete(), "{:?}", activation.outcome);
        let republished = pending
            .analyzer()
            .semantic_model_overlay_read()
            .published()
            .unwrap();
        assert_eq!(
            republished
                .symbols_named("workspace.Replacement")
                .disposition,
            SemanticModelOverlayDisposition::Unique
        );
        // Bind a model locator to a real parsed declaration, then invalidate
        // only that declaration's source while all activation inputs stay put.
        let mut anchored: serde_json::Value = serde_json::from_str(WORKSPACE_PACK).unwrap();
        anchored["shards"][0]["payload"]["types"][0]["locator"] = serde_json::json!({
            "kind": "source", "path": "src/lib.rs", "symbol": "Later"
        });
        std::fs::write(
            root.join(".bifrost/semantic-models/job-maker.json"),
            serde_json::to_vec(&anchored).unwrap(),
        )
        .unwrap();
        // A host warm opens a fresh ephemeral catalog; prior session-only
        // registrations belong to its previous activation.
        let catalog =
            Arc::new(SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap());
        let activation = activate_workspace_semantic_sources_in_catalog(
            &pending,
            &config,
            &catalog,
            sources,
            &[],
            &cancellation,
        )
        .unwrap()
        .unwrap();
        assert!(activation.outcome.complete(), "{:?}", activation.outcome);
        let overlay = pending
            .analyzer()
            .semantic_model_overlay_read()
            .published()
            .unwrap();
        assert!(matches!(
            overlay.symbols_named("workspace.GeneratedJobMaker").records[0].location,
            crate::analyzer::semantic_model::SemanticModelLocation::Authored(_)
        ));
        let anchor_source = WorkspaceActivationUpdateSource::new(
            Arc::clone(&catalog),
            activation.registration_evidence,
            Some(&packs),
            pending.retention_budget(),
        )
        .unwrap();
        let workspace_source = get_symbol_sources(
            pending.analyzer(),
            SymbolLookupParams {
                symbols: vec!["workspace.GeneratedJobMaker".into()],
            },
        );
        assert!(!workspace_source.sources.is_empty());
        assert!(workspace_source.sources.iter().all(|source| {
            source.origin == brokk_bifrost_tools::searchtools::SourceOrigin::Workspace
        }));
        std::fs::write(root.join("src/lib.rs"), "pub struct Rebound;\n").unwrap();
        let candidates = symbol_source_candidate_files(pending.analyzer(), &workspace_source);
        assert_eq!(
            stale_symbol_source_files(pending.analyzer(), candidates).unwrap(),
            changed
        );
        let invalidated = pending.update_with_activation_context(
            &changed,
            anchor_source.context(&config, sources, &[], &cancellation),
        );
        assert!(matches!(
            invalidated.analyzer().semantic_model_overlay_read(),
            SemanticModelOverlayRead::Pending(_)
        ));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12435: a directory-only or alias change event carried a stale published overlay"
    )]
    fn workspace_models_refuse_carry_for_directory_and_alias_changes() {
        use crate::analyzer::packs_document::{
            activate_workspace_semantic_sources_in_catalog, parse_workspace_packs_config,
        };
        use crate::analyzer::semantic_model::SemanticModelOverlayRead;
        let mut anchored: serde_json::Value = serde_json::from_str(WORKSPACE_PACK).unwrap();
        anchored["shards"][0]["payload"]["types"][0]["locator"] = serde_json::json!({
            "kind": "source", "path": "src/lib.rs", "symbol": "Local"
        });
        let (_temp, analyzer) = workspace(&anchored.to_string());
        let root = analyzer.analyzer().project().root().to_path_buf();
        let config = workspace_activation_config(&analyzer);
        let packs =
            parse_workspace_packs_config(r#"{"schema_version":1,"ecosystems":[]}"#).unwrap();
        let catalog =
            Arc::new(SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap());
        let cancellation = CancellationToken::default();
        let sources = WorkspaceActivationSources {
            catalog_root: &root,
            workspace_model_root: Some(&root),
            config: Some(&packs),
            intrinsic_shipped_models: false,
        };
        let activation = activate_workspace_semantic_sources_in_catalog(
            &analyzer,
            &config,
            &catalog,
            sources,
            &[],
            &cancellation,
        )
        .unwrap()
        .unwrap();
        assert!(activation.outcome.complete(), "{:?}", activation.outcome);
        let original = analyzer
            .analyzer()
            .semantic_model_overlay_read()
            .published()
            .unwrap();
        assert!(original.any_authored_path(|path| path == "src/lib.rs"));
        let source = WorkspaceActivationUpdateSource::new(
            Arc::clone(&catalog),
            activation.registration_evidence,
            Some(&packs),
            analyzer.retention_budget(),
        )
        .unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("docs/readme.md"), "unrelated\n").unwrap();
        let carries = |paths: &[&str]| {
            let changed = paths
                .iter()
                .map(|path| ProjectFile::new(root.clone(), *path))
                .collect::<BTreeSet<_>>();
            let updated = analyzer.update_with_activation_context(
                &changed,
                source.context(&config, sources, &[], &cancellation),
            );
            match updated.analyzer().semantic_model_overlay_read() {
                SemanticModelOverlayRead::Published(overlay) => Arc::ptr_eq(&overlay, &original),
                SemanticModelOverlayRead::Pending(_) => false,
                other => panic!("{paths:?}: unexpected overlay read {other:?}"),
            }
        };
        // Unrelated siblings carry: an existing file, a deleted one, and
        // spellings that only share a string prefix with a protected path.
        assert!(carries(&["docs/readme.md"]));
        assert!(carries(&["docs/deleted-since.md"]));
        assert!(carries(&[".bifrost2"]));
        assert!(carries(&["src2"]));
        // A directory event may name only the directory that holds a model
        // source, the model directory, or the directory above it.
        assert!(!carries(&[".bifrost"]));
        assert!(!carries(&[".bifrost/semantic-models"]));
        assert!(!carries(&["src"]));
        // An uncertified alias spelling may name a protected path.
        assert!(!carries(&["SRC/LIB.RS"]));
        // Spellings with `.` and `..` components name the authored file too.
        assert!(!carries(&["./src/lib.rs"]));
        assert!(!carries(&["docs/../src/lib.rs"]));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("src"), root.join("linked")).unwrap();
            assert!(!carries(&["linked/lib.rs"]));
            assert!(!carries(&["docs/readme.md", "linked/lib.rs"]));
        }
        // A real rename of the authored source's directory.
        std::fs::rename(root.join("src"), root.join("moved")).unwrap();
        assert!(!carries(&["src"]));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12752: an unreported addition rebuilt the workspace and dropped the published semantic overlay"
    )]
    fn unreported_additions_update_incrementally_and_keep_the_published_overlay() {
        use crate::analyzer::packs_document::{
            activate_workspace_semantic_sources_in_catalog, parse_workspace_packs_config,
        };
        use crate::analyzer::semantic_model::SemanticModelOverlayRead;
        let (_temp, analyzer) = workspace(WORKSPACE_PACK);
        let root = analyzer.analyzer().project().root().to_path_buf();
        let config = workspace_activation_config(&analyzer);
        let packs =
            parse_workspace_packs_config(r#"{"schema_version":1,"ecosystems":[]}"#).unwrap();
        let catalog =
            Arc::new(SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap());
        let cancellation = CancellationToken::default();
        let sources = WorkspaceActivationSources {
            catalog_root: &root,
            workspace_model_root: Some(&root),
            config: Some(&packs),
            intrinsic_shipped_models: false,
        };
        let activation = activate_workspace_semantic_sources_in_catalog(
            &analyzer,
            &config,
            &catalog,
            sources,
            &[],
            &cancellation,
        )
        .unwrap()
        .unwrap();
        assert!(activation.outcome.complete(), "{:?}", activation.outcome);
        let original = analyzer
            .analyzer()
            .semantic_model_overlay_read()
            .published()
            .unwrap();
        let source = WorkspaceActivationUpdateSource::new(
            Arc::clone(&catalog),
            activation.registration_evidence,
            Some(&packs),
            analyzer.retention_budget(),
        )
        .unwrap();
        let update = |paths: &[&str]| {
            let changed = paths
                .iter()
                .map(|path| ProjectFile::new(root.clone(), *path))
                .collect::<BTreeSet<_>>();
            analyzer.update_with_activation_context(
                &changed,
                source.context(&config, sources, &[], &cancellation),
            )
        };
        // The save reports only src/lib.rs; src/extra.rs appeared unreported.
        std::fs::write(root.join("src/lib.rs"), "pub struct Changed;\n").unwrap();
        std::fs::write(root.join("src/extra.rs"), "pub struct Extra;\n").unwrap();
        let updated = update(&["src/lib.rs"]);
        let cold = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(FilesystemProject::new(root.clone()).unwrap()),
            AnalyzerConfig::default(),
        )
        .unwrap();
        for path in ["src/lib.rs", "src/extra.rs"] {
            let file = ProjectFile::new(root.clone(), path);
            assert_eq!(
                updated.analyzer().get_declarations(&file),
                cold.analyzer().get_declarations(&file),
                "{path}"
            );
        }
        assert!(
            !updated
                .analyzer()
                .get_declarations(&ProjectFile::new(root.clone(), "src/extra.rs"))
                .is_empty()
        );
        match updated.analyzer().semantic_model_overlay_read() {
            SemanticModelOverlayRead::Published(overlay) => {
                assert!(Arc::ptr_eq(&overlay, &original))
            }
            other => panic!("the published overlay was dropped: {other:?}"),
        }
        // A model file that appears unreported under the model directory
        // invalidates the overlay, even though the update carries it as a
        // discovered addition.
        std::fs::write(root.join(".bifrost/semantic-models/late.json"), "{}\n").unwrap();
        let updated = update(&["src/lib.rs"]);
        assert!(
            matches!(
                updated.analyzer().semantic_model_overlay_read(),
                SemanticModelOverlayRead::Pending(_)
            ),
            "an unreported addition under the model directory must refuse the carry"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13077: an unreported addition of a model's source locator kept the stale overlay"
    )]
    fn unreported_addition_of_a_model_source_invalidates_the_published_overlay() {
        use crate::analyzer::packs_document::{
            activate_workspace_semantic_sources_in_catalog, parse_workspace_packs_config,
        };
        use crate::analyzer::semantic_model::SemanticModelOverlayRead;
        let mut model: serde_json::Value = serde_json::from_str(WORKSPACE_PACK).unwrap();
        model["schema_version"] = serde_json::json!(29);
        model["compatibility"]
            .as_object_mut()
            .unwrap()
            .remove("bifrost");
        model["shards"][0]["payload"]["types"][0]["locator"] = serde_json::json!({
            "kind": "source", "path": "src/late.rs", "symbol": "late.Late"
        });
        let (_temp, analyzer) = workspace(&model.to_string());
        let root = analyzer.analyzer().project().root().to_path_buf();
        let config = workspace_activation_config(&analyzer);
        let packs =
            parse_workspace_packs_config(r#"{"schema_version":1,"ecosystems":[]}"#).unwrap();
        let catalog =
            Arc::new(SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap());
        let cancellation = CancellationToken::default();
        let sources = WorkspaceActivationSources {
            catalog_root: &root,
            workspace_model_root: Some(&root),
            config: Some(&packs),
            intrinsic_shipped_models: false,
        };
        let activation = activate_workspace_semantic_sources_in_catalog(
            &analyzer,
            &config,
            &catalog,
            sources,
            &[],
            &cancellation,
        )
        .unwrap()
        .unwrap();
        assert!(activation.outcome.complete(), "{:?}", activation.outcome);
        let source = WorkspaceActivationUpdateSource::new(
            Arc::clone(&catalog),
            activation.registration_evidence,
            Some(&packs),
            analyzer.retention_budget(),
        )
        .unwrap();
        let update = |paths: &[&str]| {
            let changed = paths
                .iter()
                .map(|path| ProjectFile::new(root.clone(), *path))
                .collect::<BTreeSet<_>>();
            analyzer.update_with_activation_context(
                &changed,
                source.context(&config, sources, &[], &cancellation),
            )
        };
        // The save reports only src/lib.rs; the file named by the model's
        // source locator appeared unreported.
        std::fs::write(root.join("src/lib.rs"), "pub struct Changed;\n").unwrap();
        std::fs::write(root.join("src/late.rs"), "pub struct Late;\n").unwrap();
        let updated = update(&["src/lib.rs"]);
        assert!(
            matches!(
                updated.analyzer().semantic_model_overlay_read(),
                SemanticModelOverlayRead::Pending(_)
            ),
            "a folded addition of a path the model names must refuse the carry"
        );
    }

    #[test]
    fn semantic_model_update_without_activation_context_is_pending() {
        use crate::analyzer::semantic_model::SemanticModelOverlayRead;
        let (temp, analyzer) = workspace(WORKSPACE_PACK);
        let state = activate_configured_semantic_models(
            temp.path(),
            &analyzer,
            Some(workspace_configuration()),
        )
        .unwrap();
        assert!(state.failure.is_none(), "{:?}", state.failure);
        assert!(matches!(
            analyzer.analyzer().semantic_model_overlay_read(),
            SemanticModelOverlayRead::Published(_)
        ));
        std::fs::write(temp.path().join("src/lib.rs"), "pub struct Changed;\n").unwrap();
        let changed = BTreeSet::from([ProjectFile::new(
            analyzer.analyzer().project().root().to_path_buf(),
            "src/lib.rs",
        )]);
        let updated = analyzer.update(&changed);
        assert!(matches!(
            updated.analyzer().semantic_model_overlay_read(),
            SemanticModelOverlayRead::Pending(_)
        ));
    }

    #[test]
    fn pending_overlay_status_serializes_warm_stage_and_acquisitions() {
        let warm = SemanticPackWarm::pending();
        assert_eq!(
            serde_json::to_value(warm.overlay_status()).unwrap(),
            serde_json::json!({"state":"pending", "stage":"activating_installed_packs"})
        );
        let mut interim =
            WorkspacePackActivationState::unavailable(None, Vec::new(), "pending".into());
        interim.pending_acquisitions.push(
            crate::analyzer::semantic_model::PendingDependencyPackAcquisition {
                ecosystem: crate::analyzer::DependencyPackEcosystem::Jvm,
                dependency_id: "example:library:1".into(),
            },
        );
        warm.publish_acquisition_pending(Arc::new(interim));
        let pending = serde_json::to_value(warm.overlay_status()).unwrap();
        assert_eq!(pending["stage"], "acquisition_pending");
        assert_eq!(
            pending["pending_acquisitions"][0]["dependency_id"],
            "example:library:1"
        );
        assert_eq!(pending["pending_acquisitions"][0]["ecosystem"], "jvm");
        warm.begin_configured_activation();
        let configured = serde_json::to_value(warm.overlay_status()).unwrap();
        assert_eq!(configured["stage"], "activating_configured_packs");
        assert_eq!(
            configured["pending_acquisitions"],
            pending["pending_acquisitions"]
        );
    }

    fn workspace(source: &str) -> (tempfile::TempDir, WorkspaceAnalyzer) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(temp.path().join("src/lib.rs"), "pub struct Local;\n").unwrap();
        let model_root = temp.path().join(".bifrost/semantic-models");
        std::fs::create_dir_all(&model_root).unwrap();
        std::fs::write(model_root.join("job-maker.json"), source).unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        let project: Arc<dyn Project> = Arc::new(FilesystemProject::new(root).unwrap());
        let analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("ephemeral test workspace should build");
        (temp, analyzer)
    }

    fn workspace_configuration() -> ConfiguredSemanticModels {
        ConfiguredSemanticModels {
            catalog_root: None,
            evidence: Vec::new(),
            workspace_models: true,
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6397: malformed workspace model leaked bootstrap catalog leases"
    )]
    fn legacy_registration_error_releases_bootstrap_leases() {
        use crate::analyzer::semantic_model::{
            CompilerOptions, DurablePackSource, DurablePackSourceKind, SourceFormat, compile_source,
        };

        let (temp, analyzer) = workspace("{ invalid json");
        let catalog_connection = std::cell::RefCell::new(None);
        let result = activate_legacy_configured_semantic_models_with_bootstrap(
            temp.path(),
            &analyzer,
            Some(workspace_configuration()),
            None,
            SemanticModelRuntimeLimits::default(),
            |catalog| {
                *catalog_connection.borrow_mut() = Some(Arc::clone(&catalog.connection));
                let pack = compile_source(
                    SourceFormat::Json,
                    WORKSPACE_PACK.as_bytes(),
                    &CompilerOptions::default(),
                )
                .expect("fixture pack compiles");
                catalog
                    .install(
                        &pack,
                        &DurablePackSource {
                            kind: DurablePackSourceKind::PreShipped,
                            source_id: "test:legacy-lease".to_owned(),
                        },
                    )
                    .map_err(|error| error.to_string())?;
                let lease = catalog
                    .lease(
                        &pack.manifest.content_sha256,
                        "legacy-registration-test",
                        Duration::from_secs(300),
                    )
                    .map_err(|error| error.to_string())?
                    .into_token(pack.manifest.content_sha256.clone());
                Ok((true, vec![lease]))
            },
        );
        assert!(result.is_err(), "malformed workspace model must fail");
        let connection = catalog_connection.into_inner().expect("bootstrap ran");
        let held: i64 = connection
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM catalog_leases", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            held, 0,
            "registration failure must release bootstrap leases"
        );
    }

    #[test]
    fn packs_document_activates_for_a_bound_workspace_without_environment_configuration() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(temp.path().join("src/lib.rs"), "pub struct Local;\n").unwrap();
        std::fs::create_dir_all(temp.path().join(".bifrost")).unwrap();
        std::fs::write(
            temp.path().join(".bifrost/packs.json"),
            r#"{ "schema_version": 1, "ecosystems": ["cargo"] }"#,
        )
        .unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        let project: Arc<dyn Project> = Arc::new(FilesystemProject::new(root.clone()).unwrap());
        let analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("ephemeral test workspace should build");

        // No environment variables, no host options: the document alone is
        // the opt-in, so a bound MCP session activates the same packs the LSP
        // and the CLI would (#1868).
        let activation = activate_configured_semantic_models(&root, &analyzer, None).unwrap();
        assert!(activation.config.is_some());
        assert!(activation.failure.is_none());

        assert!(
            analyzer
                .analyzer()
                .dependency_discovery_evidence(Language::Rust)
                .is_some(),
            "the packs document must drive dependency activation on workspace bind"
        );
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "3f170fdac386: Commit 3f170fdac386 fixed absent pack configuration failing to use bound workspace defaults"
    )]
    fn absent_packs_document_uses_bound_workspace_defaults() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(temp.path().join("src/lib.rs"), "pub struct Local;\n").unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        let project: Arc<dyn Project> = Arc::new(FilesystemProject::new(root.clone()).unwrap());
        let analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("ephemeral test workspace should build");

        let state = activate_configured_semantic_models(&root, &analyzer, None).unwrap();
        assert!(state.config.is_none());
        assert_eq!(
            state.ecosystems,
            [crate::analyzer::DependencyPackEcosystem::Cargo]
        );
        assert!(state.failure.is_none());
    }

    #[test]
    fn workspace_pack_registration_is_deterministic_and_reports_workspace_provenance() {
        let (first_root, first) = workspace(WORKSPACE_PACK);
        activate_configured_semantic_models(
            first_root.path(),
            &first,
            Some(workspace_configuration()),
        )
        .unwrap();
        let first_overlay = first
            .analyzer()
            .semantic_model_overlay_read()
            .published()
            .expect("workspace activation publishes an overlay");
        let first_match = first_overlay.symbols_named("workspace.GeneratedJobMaker");
        assert_eq!(
            first_match.disposition,
            SemanticModelOverlayDisposition::Unique
        );
        let first_symbol = &first_match.records[0];
        assert_eq!(
            first_symbol.provenance.activation.source_kind,
            "ephemeral_workspace"
        );
        assert!(
            first_symbol
                .provenance
                .activation
                .source_id
                .starts_with("workspace:.bifrost/semantic-models/job-maker.json#sha256=")
        );

        let (second_root, second) = workspace(WORKSPACE_PACK);
        activate_configured_semantic_models(
            second_root.path(),
            &second,
            Some(workspace_configuration()),
        )
        .unwrap();
        let second_overlay = second
            .analyzer()
            .semantic_model_overlay_read()
            .published()
            .expect("repeated workspace activation publishes an overlay");
        let second_symbol = std::sync::Arc::clone(
            &second_overlay
                .symbols_named("workspace.GeneratedJobMaker")
                .records[0],
        );
        assert_eq!(
            first_symbol.provenance.activation.source_id,
            second_symbol.provenance.activation.source_id
        );
        assert_eq!(
            first_overlay.active_model_set_hash(),
            second_overlay.active_model_set_hash()
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#7563: MCP reported semantic packs ready while the overlay was unavailable"
    )]
    fn active_workspace_reports_overlay_budget_rejection_after_warm_settles() {
        let (temp, _) = workspace(WORKSPACE_PACK);
        let root = temp.path().canonicalize().unwrap();
        let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        let models_bytes = {
            let guard = service.session.read().unwrap();
            let session = guard.as_ref().unwrap();
            let ready = activate_configured_semantic_models(
                &root,
                &session.snapshot,
                Some(workspace_configuration()),
            )
            .unwrap();
            assert!(ready.failure.is_none(), "{ready:?}");
            session.semantic_packs.publish_final(Some(Arc::new(ready)));
            session
                .snapshot
                .analyzer()
                .active_semantic_model_snapshot()
                .unwrap()
                .active_models()
                .retained_bytes()
        };
        let ready = service
            .call_tool_value("get_active_workspace", serde_json::json!({}))
            .unwrap();
        assert_eq!(ready["semantic_packs_ready"], true);
        assert_eq!(ready["semantic_model_overlay"]["state"], "ready");
        {
            let guard = service.session.read().unwrap();
            let session = guard.as_ref().unwrap();
            let snapshot = session
                .snapshot
                .analyzer()
                .active_semantic_model_snapshot()
                .unwrap();
            let mut report = snapshot.active_models().report.clone();
            report.explanations.push(
                crate::analyzer::semantic_model::SemanticModelActivationExplanation {
                    manifest_digest: String::new(),
                    pack_id: None,
                    shard_id: String::new(),
                    source_kind: crate::analyzer::semantic_model::CatalogPackSourceKind::Embedded,
                    source_id: String::new(),
                    status:
                        crate::analyzer::semantic_model::SemanticModelActivationStatus::Unavailable,
                    reason: "one model could not be activated".to_owned(),
                },
            );
            let outcome = SemanticModelRuntimeOutcome::Incomplete {
                usable: Some(Arc::clone(snapshot.active_models())),
                report,
            };
            let mut partial = WorkspacePackActivationState {
                update_source: None,
                config: None,
                ecosystems: Vec::new(),
                failure: None,
                overlay: SemanticModelOverlayStatus::NoModels,
                pending_acquisitions: Vec::new(),
                shipped_pack_acquisition_pending: None,
                coverage: None,
            };
            partial.set_runtime_outcome(&[], Some(&outcome));
            assert!(partial.failure.is_none(), "{partial:?}");
            session
                .semantic_packs
                .publish_final(Some(Arc::new(partial)));
        }
        let partial = service
            .call_tool_value("get_active_workspace", serde_json::json!({}))
            .unwrap();
        assert_eq!(partial["semantic_packs_ready"], true);
        assert_eq!(partial["semantic_model_overlay"]["state"], "partial");
        assert_eq!(
            partial["semantic_model_overlay"]["reasons"][0],
            "one model could not be activated"
        );
        let service = service.with_limits(SemanticModelRuntimeLimits {
            max_retained_bytes: models_bytes,
            ..Default::default()
        });
        {
            let guard = service.session.read().unwrap();
            let session = guard.as_ref().unwrap();
            // Hydration fits exactly; the added overlay must exceed the combined budget.
            let unavailable = activate_legacy_configured_semantic_models_with_limits(
                &root,
                &session.snapshot,
                Some(workspace_configuration()),
                None,
                service.semantic_model_runtime_limits,
            )
            .unwrap();
            assert!(unavailable.failure.is_some(), "{unavailable:?}");
            session
                .semantic_packs
                .publish_final(Some(Arc::new(unavailable)));
        }
        let result = service
            .call_tool_value("get_active_workspace", serde_json::json!({}))
            .unwrap();
        assert_eq!(result["semantic_packs_ready"], true);
        let overlay = &result["semantic_model_overlay"];
        assert_eq!(overlay["state"], "unavailable");
        assert_eq!(
            overlay["reason"],
            "semantic-model overlay exceeds the combined retained-byte budget"
        );
        assert!(overlay["loaded_records"].as_u64().unwrap() > 0);
        assert_eq!(overlay["models_retained_bytes"], models_bytes);
        assert!(overlay["overlay_working_bytes"].as_u64().unwrap() > 0);
        assert_eq!(overlay["combined_budget_bytes"], models_bytes);
        let validator = jsonschema::validator_for(
            &crate::output_schemas::output_schema_for("get_active_workspace").unwrap(),
        )
        .unwrap();
        assert!(validator.is_valid(&result), "{result}");
    }

    #[test]
    fn invalid_workspace_pack_stops_activation_with_the_source_path() {
        let (root, analyzer) = workspace("{}");
        let state = activate_configured_semantic_models(
            root.path(),
            &analyzer,
            Some(workspace_configuration()),
        )
        .unwrap();
        let error = state.failure.expect("the failed activation is retained");
        assert!(error.contains("workspace semantic-model discovery failed"));
        assert!(error.contains(".bifrost/semantic-models/job-maker.json"));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchToolsServiceErrorCode {
    WorkspaceUnavailable,
    InvalidParams,
    /// The caller pinned a workspace snapshot this request cannot answer.
    StaleWorkspaceGeneration {
        requested: ExplanationGeneration,
        current: Option<ExplanationGeneration>,
    },
    UnknownTool,
    DeadlineExceeded,
    Internal,
}

#[cfg(test)]
mod issue_1228_response_budget_tests {
    use super::*;
    use crate::searchtools::{
        SourceBlock, SymbolSourcesIncomplete, SymbolSourcesIncompleteReason, SymbolSourcesResult,
    };

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1255: large symbol-source responses regressed MCP code-intelligence latency"
    )]
    fn oversized_symbol_source_response_is_rejected_before_rendering() {
        let result = SymbolSourcesResult {
            sources: vec![SourceBlock {
                origin: brokk_bifrost_tools::searchtools::SourceOrigin::Workspace,
                label: "large".to_string(),
                path: "large.rs".to_string(),
                start_line: 1,
                end_line: 1,
                text: "x".repeat(GET_SYMBOL_SOURCES_RESPONSE_BUDGET_BYTES + 1),
                canonical_selector: None,
                occurrence_role: None,
                presentation: None,
                note: None,
                semantic_model: None,
                inside_unclosed_construct: None,
            }],
            not_found: Vec::new(),
            ambiguous: Vec::new(),
            ambiguous_paths: Vec::new(),
            too_broad: Vec::new(),
            complete: true,
            incomplete: Vec::new(),
        };

        let error = SearchToolsService::symbol_sources_output(result, RenderOptions::default())
            .expect_err("oversized response must be rejected");

        assert_eq!(error.code, SearchToolsServiceErrorCode::InvalidParams);
        assert!(
            error.message.contains("response budget"),
            "{}",
            error.message
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "83d39edefb3d: cancelled symbol-source batches discarded completed sibling results"
    )]
    fn partial_symbol_source_response_keeps_completed_sources_and_typed_cancellation() {
        let result = SymbolSourcesResult {
            sources: vec![SourceBlock {
                origin: brokk_bifrost_tools::searchtools::SourceOrigin::Workspace,
                label: "ready".to_string(),
                path: "ready.rs".to_string(),
                start_line: 1,
                end_line: 1,
                text: "fn ready() {}".to_string(),
                canonical_selector: None,
                occurrence_role: None,
                presentation: None,
                note: None,
                semantic_model: None,
                inside_unclosed_construct: None,
            }],
            not_found: Vec::new(),
            ambiguous: Vec::new(),
            ambiguous_paths: Vec::new(),
            too_broad: Vec::new(),
            complete: false,
            incomplete: vec![SymbolSourcesIncomplete {
                target: "slow".to_string(),
                reason: SymbolSourcesIncompleteReason::Cancelled,
                detail: None,
            }],
        };

        let output = SearchToolsService::symbol_sources_output(result, RenderOptions::default())
            .expect("partial responses remain valid tool output");
        let ToolOutput::Structured {
            structured,
            rendered_text,
        } = output
        else {
            panic!("expected structured symbol source output");
        };

        assert_eq!(structured["complete"], false);
        assert_eq!(structured["incomplete"][0]["target"], "slow");
        assert_eq!(structured["incomplete"][0]["reason"], "cancelled");
        assert!(rendered_text.unwrap_or_default().contains("ready"));
    }
}

const MAX_QUERY_FILE_BYTES: u64 = 64 * 1024;
const GET_SYMBOL_SOURCES_RESPONSE_BUDGET_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunPolicyParams {
    #[serde(default)]
    sources: Vec<String>,
    inline_suppression_prefix: Option<String>,
    #[serde(default)]
    policy_files: Vec<String>,
    #[serde(default)]
    policy_packs: Vec<String>,
    #[serde(default)]
    policy_categories: Vec<String>,
    #[serde(default)]
    policy_ids: Vec<String>,
    suppression_file: Option<String>,
    scope_file: Option<String>,
    baseline_file: Option<String>,
    evaluation_date: PolicyEvaluationDate,
    #[serde(default)]
    fail_on: RunPolicyFailOn,
    diff_base: Option<String>,
    /// Scope taint sink procedures to changed hunks from `diff_base`. Requires
    /// `diff_base` and incremental reuse.
    #[serde(default)]
    diff_scoped: bool,
    /// Whether this run may publish complete units and reuse verified ones.
    /// Absent means yes. `false` forces full evaluation without policy-unit
    /// cache access when diagnosing a difference.
    incremental: Option<bool>,
    /// Opt-in wall-clock stage attribution (#2611). Adds a `stage_timings`
    /// sibling and each run's `evaluation.elapsed_ms` work metric.
    #[serde(default)]
    include_stage_timings: bool,
    /// Advisory dispatch order only; leaves the report unchanged.
    #[serde(default)]
    policy_cost_hints: crate::policy::PolicyCostHints,
    /// Per-policy time limits; a policy past its own ends inconclusive with
    /// `rule_deadline_exceeded` while the others continue (#7557).
    #[serde(default)]
    policy_deadlines_ms: crate::policy::PolicyDeadlines,
    /// Send each policy's run as a progress notification when it finishes,
    /// for a caller that supplied a progress token (#7557).
    #[serde(default)]
    stream_runs: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RunPolicyFailOn {
    Never,
    Finding,
    Note,
    #[default]
    Warning,
    Error,
}

impl From<RunPolicyFailOn> for PolicyFailOn {
    fn from(value: RunPolicyFailOn) -> Self {
        match value {
            RunPolicyFailOn::Never => Self::Never,
            RunPolicyFailOn::Finding => Self::Finding,
            RunPolicyFailOn::Note => Self::Note,
            RunPolicyFailOn::Warning => Self::Warning,
            RunPolicyFailOn::Error => Self::Error,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct RunPolicyToolResult {
    status: &'static str,
    exit_status: u8,
    /// Added when the caller passes `include_stage_timings`; each run also
    /// gains an `evaluation.elapsed_ms` work metric in the report.
    #[serde(skip_serializing_if = "Option::is_none")]
    stage_timings: Option<Vec<PolicyStageTiming>>,
    report: PolicyReportDocument,
}

pub(crate) enum RunPolicyPreflight {
    Valid(PreparedRunPolicyPreflight),
    Invalid(ToolOutput),
}

pub(crate) struct PreparedRunPolicyPreflight {
    suppression_preflight: crate::policy::PolicySuppressionPreflight,
    selection_elapsed: Duration,
    suppression_preflight_elapsed: Duration,
}

struct DecodedRunPolicy {
    sources: Vec<String>,
    inline_suppression_prefix: Option<String>,
    policy_inputs: Vec<PolicyEvaluationInput>,
    selected_policy_ids: Vec<PolicyId>,
    options: PolicyEvaluationOptions,
    include_stage_timings: bool,
}

/// `explain_policy` arguments.
///
/// The policy selection is `run_policy`'s, narrowed to exactly one resolved
/// policy: a finding identity belongs to one run and a candidate is tested
/// against one plan, so explaining a batch is not a question that has an
/// answer. The target is exactly one of `finding_id` (why) or `candidate`
/// (why-not); the schema states the exclusion and the handler enforces it.
///
/// `workspace_generation` is the optional pin: an agent that read a finding id
/// under one workspace states that workspace here, and a request that arrives
/// after the snapshot moved is refused rather than answered about a different
/// run.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainPolicyParams {
    #[serde(default)]
    policy_files: Vec<String>,
    #[serde(default)]
    policy_packs: Vec<String>,
    #[serde(default)]
    policy_categories: Vec<String>,
    #[serde(default)]
    policy_ids: Vec<String>,
    finding_id: Option<String>,
    candidate: Option<ExplainPolicyCandidate>,
    /// For a flow or taint policy, the origin (source) position; `candidate`
    /// is then the observation (sink) position (issue 3686).
    candidate_source: Option<ExplainPolicyCandidate>,
    near_misses: Option<ExplainPolicyNearMisses>,
    workspace_generation: Option<String>,
}

/// One explicit source position a caller believes should have matched.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainPolicyCandidate {
    path: String,
    byte_start: u64,
    /// Omitted means a point candidate at `byte_start`.
    byte_end: Option<u64>,
}

/// The near-miss request form: where the candidates come from, and the two
/// bounds the ranking honours.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainPolicyNearMisses {
    /// Rank exactly these positions. Nothing is searched for.
    candidates: Option<Vec<ExplainPolicyCandidate>>,
    /// Search inside the policy's own seed scope instead.
    enumerate_from_policy_seed: Option<bool>,
    max_candidates: Option<usize>,
    max_executions: Option<usize>,
}

/// The `explain_policy` result: the structured answer and nothing else.
///
/// An explanation is a query about a policy, not a gate, so this result
/// carries no status and no exit code. Everything a caller needs -- the
/// question, the outcome, the node tree or the ranked entries, the truncation
/// record -- is inside the versioned document.
///
/// Both documents are boxed: they are large, they are built once per request,
/// and the enum is moved several times on the way to the transport, so the
/// indirection is cheaper than carrying the wider variant everywhere.
#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum ExplainPolicyToolResult {
    Explanation {
        explanation: Box<PolicyExplanation>,
    },
    NearMiss {
        near_miss_ranking: Box<PolicyNearMissRanking>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct WorkspaceIncomplete {
    pub reason: &'static str,
    pub phase: String,
    pub retiring_workspaces: Vec<brokk_bifrost_tools::searchtools::RetiringWorkspace>,
}

#[derive(Debug, Clone)]
pub struct SearchToolsServiceError {
    pub(crate) workspace_incomplete: Option<Box<WorkspaceIncomplete>>,
    pub code: SearchToolsServiceErrorCode,
    pub message: String,
    pub(crate) retryable_stale_generation: bool,
}

impl SearchToolsServiceError {
    fn workspace_unavailable(
        reason: &'static str,
        phase: &str,
        retiring_workspaces: Vec<brokk_bifrost_tools::searchtools::RetiringWorkspace>,
    ) -> Self {
        Self {
            code: SearchToolsServiceErrorCode::WorkspaceUnavailable,
            message: format!("{phase}; retiring workspaces: {retiring_workspaces:?}; retry"),
            workspace_incomplete: Some(Box::new(WorkspaceIncomplete {
                reason,
                phase: phase.to_owned(),
                retiring_workspaces,
            })),
            retryable_stale_generation: false,
        }
    }

    fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            code: SearchToolsServiceErrorCode::InvalidParams,
            message: message.into(),
            workspace_incomplete: None,
            retryable_stale_generation: false,
        }
    }

    fn unknown_tool(message: impl Into<String>) -> Self {
        Self {
            code: SearchToolsServiceErrorCode::UnknownTool,
            message: message.into(),
            workspace_incomplete: None,
            retryable_stale_generation: false,
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: SearchToolsServiceErrorCode::Internal,
            message: message.into(),
            workspace_incomplete: None,
            retryable_stale_generation: false,
        }
    }

    fn deadline_exceeded(message: impl Into<String>) -> Self {
        Self {
            code: SearchToolsServiceErrorCode::DeadlineExceeded,
            message: message.into(),
            workspace_incomplete: None,
            retryable_stale_generation: false,
        }
    }

    fn stale_analyzer_generation(message: impl Into<String>) -> Self {
        Self {
            code: SearchToolsServiceErrorCode::Internal,
            message: message.into(),
            workspace_incomplete: None,
            retryable_stale_generation: true,
        }
    }

    fn is_stale_analyzer_generation(&self) -> bool {
        self.retryable_stale_generation
    }
}

impl fmt::Display for SearchToolsServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// Error message for a request whose time budget expired while the deferred
/// initial workspace build was still running. Also matched by the repository
/// benchmark's prewarm loop to keep polling until the build completes.
pub const WORKSPACE_SNAPSHOT_NOT_READY_MESSAGE: &str = "workspace snapshot was not ready within the request-wide time budget; retry after workspace initialization completes";

impl std::error::Error for SearchToolsServiceError {}

#[derive(Debug, Clone)]
pub enum ToolOutput {
    /// Admitted query backing stays typed until a transport requests a copy.
    QueryResponse(Arc<crate::rql::CodeQueryResponse>),
    Text(String),
    Structured {
        structured: Value,
        rendered_text: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize)]
struct PythonToolPayload {
    structured: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    rendered_text: Option<String>,
}

impl ToolOutput {
    /// MCP/Python handoff: these plain wire copies do not carry the engine's
    /// admitted backing lifetime. The CLI borrows QueryResponse directly.
    pub fn into_compat_output(self) -> Self {
        match self {
            Self::QueryResponse(response) => Self::Structured {
                structured: serde_json::to_value(response.as_ref())
                    .expect("the public CodeQuery response is serializable"),
                rendered_text: Some(response.render_text()),
            },
            output => output,
        }
    }

    pub fn into_value(self) -> Value {
        match self {
            Self::Text(text) => Value::String(text),
            Self::QueryResponse(response) => serde_json::to_value(response.as_ref())
                .expect("the public CodeQuery response is serializable"),
            Self::Structured { structured, .. } => structured,
        }
    }

    pub fn into_python_payload(self) -> Value {
        match self.into_compat_output() {
            Self::QueryResponse(_) => unreachable!("compatibility conversion erases typed queries"),
            Self::Text(text) => Value::String(text),
            Self::Structured {
                structured,
                rendered_text,
            } => serde_json::to_value(PythonToolPayload {
                structured,
                rendered_text,
            })
            .expect("the Python tool payload contains valid JSON values"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateStrategy {
    WatchFiles,
    /// No background file watcher; the caller drives updates explicitly via the
    /// incremental `update_paths` tool. Used by batch consumers (e.g. the localizer
    /// embedding pipeline) that check out successive revisions into one worktree and
    /// know exactly which files changed -- avoiding a whole-tree watcher and a full
    /// re-analysis per revision.
    Manual,
}

type WatcherStarter = Arc<
    dyn Fn(Arc<dyn Project>, &[ProjectFile]) -> Result<ProjectChangeWatcher, String>
        + Send
        + Sync
        + 'static,
>;
type PendingWorkspaceBuild = JoinHandle<Result<(u64, PathBuf, WorkspaceSession), String>>;

/// Which workspace a service is bound to and how far its analyzer session has
/// got. One lock holds the whole lifecycle, so the root, the build handle, the
/// build failure and the listing cache cannot disagree with each other.
///
/// The session itself stays in [`SearchToolsService::session`], because a
/// query holds that lock for its whole run. `session` is `Some` exactly when
/// the bound build is [`WorkspaceBuild::Installed`]. Lock order: `session`
/// before `phase`, so binding and installation publish one consistent root
/// and session without joining an unfinished build.
///
/// Decisions this type encodes:
/// - The phase lock is short-held. No transition holds it across a build,
///   across a join of an unfinished build thread, or across analysis; a
///   request that needs the session polls until the build thread finishes.
///   `active_workspace_root` and the readiness probes therefore never wait
///   behind a build. #1388 kept the listing cache outside the session lock
///   for a listing reader that must not wait behind re-analysis; that reader
///   (`find_filenames`) was removed for #1493, and the remaining readers (a
///   lazy first build and the stale-snapshot reload) hold no session lock, so
///   the listing lives in the bound phase.
/// - Rebinding cancels and queues the previous build for tracked retirement.
///   Its lifetime slot remains reserved until the build and its warms drain.
///   A build in the phase always carries the current generation and root,
///   and installing it asserts that.
/// - Rebinding an installed session queues its teardown on the service's one
///   retirement worker. Explicit close and shutdown join that worker; activation
///   never joins the superseded session's optional warms on the request.
/// - Nothing that can panic runs while the phase lock is held, so a poisoned
///   phase lock is a bug, and every access asserts that it is not poisoned.
enum WorkspacePhase {
    Unbound,
    Bound(BoundWorkspace),
}

struct BoundWorkspace {
    lifetime: Option<Arc<WorkspaceLifetime>>,
    root: PathBuf,
    /// Watcher-invalidated cache of the workspace's file listing (#1401):
    /// `Some` for a `WatchFiles` root and for a one-shot process. The session
    /// project shares the same handle, so every `all_files` consumer answers
    /// from one listing.
    listing: Option<Arc<WorkspaceFileListingCache>>,
    build: WorkspaceBuild,
}

enum WorkspacePreparation {
    Ready,
    Preparing,
    Finished,
}

enum WorkspaceBuild {
    /// A lazily constructed service: the first request that needs the
    /// session starts the build.
    NotStarted,
    /// The result carries the binding generation and root, which installation
    /// asserts against the phase.
    Building(PendingWorkspaceBuild),
    Installed,
    /// Every request after the failure reports it, instead of hanging or
    /// querying a workspace that was never installed (#2771), until a rebind.
    Failed(String),
    /// `close` dropped the session.
    Closed,
}

impl WorkspacePhase {
    fn bound(
        root: PathBuf,
        listing: Option<Arc<WorkspaceFileListingCache>>,
        build: WorkspaceBuild,
    ) -> Self {
        Self::Bound(BoundWorkspace {
            lifetime: None,
            root,
            listing,
            build,
        })
    }

    #[cfg(test)]
    fn bound_mut_for_test(&mut self) -> &mut BoundWorkspace {
        match self {
            Self::Bound(bound) => bound,
            Self::Unbound => panic!("the test service is bound"),
        }
    }

    fn running_build(&self) -> Option<&PendingWorkspaceBuild> {
        match self {
            Self::Bound(BoundWorkspace {
                build: WorkspaceBuild::Building(handle),
                ..
            }) => Some(handle),
            _ => None,
        }
    }
}

fn production_watcher_starter() -> WatcherStarter {
    Arc::new(ProjectChangeWatcher::start_with_claimed_files)
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum SnapshotAcquisitionPoint {
    BeforeInstalledWait,
    AfterSettle,
}

#[cfg(test)]
type SnapshotAcquisitionObserver = Arc<dyn Fn(SnapshotAcquisitionPoint) + Send + Sync>;

pub struct SearchToolsService {
    #[cfg(test)]
    snapshot_acquisition_observer: Mutex<Option<SnapshotAcquisitionObserver>>,
    retention_budget: brokk_bifrost_core::retention_budget::RetentionBudget,
    /// The host's approval authority, handed in by the entry point and bound
    /// to every analyzer this service builds before any pack activation.
    /// Immutable for the service's life; never part of `AnalyzerConfig`, never
    /// read from the environment or the repository, and no tool argument can
    /// supply or replace it.
    host_activation: Arc<HostActivationContext>,
    phase: Mutex<WorkspacePhase>,
    session: Arc<RwLock<Option<WorkspaceSession>>>,
    retired_sessions: Mutex<WorkspaceSessionRetirement>,
    lifetimes: Arc<WorkspaceLifetimes>,
    workspace_generation: AtomicU64,
    flow_state: crate::flow::FlowWorkspaceState,
    query_protocols: RwLock<crate::rql::ProtocolRegistrationSet>,
    query_value_flows: RwLock<crate::rql::ValueFlowPlanRegistrationSet>,
    query_taint_results: RwLock<crate::rql::TaintResultRegistrationSet>,
    build_progress: Arc<crate::workspace_progress::WorkspaceBuildProgress>,
    update_strategy: UpdateStrategy,
    startup_index_warm: StartupIndexWarm,
    watcher_starter: WatcherStarter,
    diff_snapshot_object_dir: Option<PathBuf>,
    diff_scoring: DiffScoringSession,
    /// Whether `query_code` may spend the source-volume-scaled budget policy
    /// evaluation uses instead of the interactive defaults. Host configuration
    /// for a trusted whole-workspace caller, never a tool argument: a query
    /// document must not be able to raise its own limits.
    workspace_scaled_query_limits: bool,
    #[cfg(any(test, feature = "test-support"))]
    semantic_model_runtime_limits: SemanticModelRuntimeLimits,
}

/// Calls `get_symbol_sources` and decodes its JSON response for tests that
/// exercise the service through its public tool surface.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn symbol_sources_json(service: &SearchToolsService, arguments_json: &str) -> Value {
    let payload = service
        .call_tool_json("get_symbol_sources", arguments_json)
        .unwrap();
    serde_json::from_str(&payload).unwrap()
}

/// When a session pays for the expensive per-generation index builds.
///
/// The distinction is the process, not the workspace: the same Firefox root
/// costs minutes and gigabytes to index either way, but only one of these two
/// kinds of process is still around to spend it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StartupIndexWarm {
    /// A long-lived MCP server, built through the deferred or unbound
    /// constructors. Start the builds after the first tool call, so an
    /// unrelated cold request is not delayed by optional index construction;
    /// later requests that need one still wait for a build already in flight
    /// instead of running it inside their own budget (#1757).
    AtStartup,
    /// A synchronously constructed service: a one-shot `--tool` invocation, an
    /// embedded host, a test fixture. It can exit seconds later, so it must not
    /// spend minutes and gigabytes up front on an index it may never query
    /// (#1758). These sessions keep the lazy build on first need.
    OnDemand,
}

/// The semantic-pack activation a session performs once, published in two
/// stages.
///
/// Activation resolves the workspace's dependency evidence against the pack
/// catalog. The full transaction can read a local toolchain, download and
/// verify a release bundle, produce a generated pack, and decode whole packs
/// into the active model set, so it is measured in seconds to minutes on a
/// JVM workspace with a local JDK while the analyzer snapshot itself is ready
/// in hundreds of milliseconds.
///
/// It is therefore a warm-up for the session, not part of publishing its
/// analyzer: a deferred build starts it on its own thread and reports the
/// workspace ready as soon as the analyzer is installed (issue #3372, the
/// #2377 family). The warm's first, installed stage is the cheap part --
/// opening the catalog and resolving the packs already installed for this
/// workspace, never fetching, verifying, extracting, or generating -- and it
/// is what the query path awaits, so a resolution answer is deterministic
/// instead of whichever side of the warm it landed on (issue #3401). When
/// that stage leaves acquisitions outstanding the warm continues to the full
/// activation on the same thread and publishes its result over the interim
/// one. The consumers that hand the exact final activation to the runtime --
/// policy evaluation and a scope refresh -- wait for that settle. A session
/// assembled synchronously starts settled, so a one-shot invocation and a
/// test fixture keep the previous behavior exactly.
struct SemanticPackWarm {
    search_warm_cancellation: CancellationToken,
    state: Mutex<PackWarmState>,
    settled: Condvar,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    installed_snapshot: Mutex<Option<(Weak<WorkspaceAnalyzer>, Arc<WorkspaceAnalyzer>)>>,
    started_at: Instant,
    settled_ns: AtomicU64,
    worker_exited: AtomicBool,
    /// Parks the worker before it touches the catalog, so a test can prove the
    /// readiness barrier does not cover it without racing the real activation.
    #[cfg(test)]
    hold: Option<Arc<PackWarmHold>>,
}

enum PackWarmState {
    Pending,
    AcquisitionPending(Arc<WorkspacePackActivationState>),
    ConfiguredPending(Arc<WorkspacePackActivationState>),
    Settled(Option<Arc<WorkspacePackActivationState>>),
    Failed(String),
}

/// The session's pack activation as one query snapshot observes it (issue
/// #3401). The two non-settled states are what a `query_code` answer marks
/// with the pending-acquisition diagnostic.
#[derive(Clone)]
enum SessionPackActivation {
    /// The warm finished, successfully or with a stated failure: nothing an
    /// answer could still gain is outstanding. The published state, when
    /// there is one, carries the failure a `query_code` answer must name
    /// (#10002).
    Settled(Option<Arc<WorkspacePackActivationState>>),
    /// The installed stage settled and the snapshot awaited it; the expensive
    /// stage is still running, so the active set can still gain the pending
    /// acquisitions this state names.
    AcquisitionPending(Arc<WorkspacePackActivationState>),
    /// The configured-pack stage of the warm is still running. Query
    /// diagnostics treat it exactly as `AcquisitionPending`; it is distinct
    /// only so the reported overlay stage stays exact.
    ConfiguredPending(Arc<WorkspacePackActivationState>),
    /// The current snapshot's installed stage has not settled. Query
    /// acquisition waits for this state to change or returns a typed stop.
    WarmPending,
    Failed(String),
}

impl SessionPackActivation {
    /// The semantic-model activation one query snapshot observed, as the
    /// neutral read the policy explanation tools consume. `analyzer` must be
    /// the snapshot this activation was captured with, so the stored status and
    /// the publication describe one generation.
    fn semantic_model_read(
        &self,
        analyzer: &dyn crate::analyzer::IAnalyzer,
    ) -> crate::analyzer::semantic_model::SemanticModelActivationRead {
        use crate::analyzer::semantic_model::{
            SemanticModelActivationInput as Input, SemanticModelActivationRead as Read,
        };
        let pending = |stage, state: &WorkspacePackActivationState| {
            Read::reduce(Input::Pending {
                analyzer,
                stage,
                pending_acquisitions: &state.pending_acquisitions,
                shipped_pack_acquisition: state.shipped_pack_acquisition_pending.as_deref(),
            })
        };
        match self {
            Self::Settled(Some(state)) => Read::reduce(Input::Stored {
                status: &state.overlay,
                analyzer,
            }),
            Self::Settled(None) => Read::reduce(Input::NoPublishedOutcome(analyzer)),
            Self::Failed(cause) => Read::reduce(Input::WarmFailed { analyzer, cause }),
            Self::AcquisitionPending(state) => {
                pending(SemanticModelWarmStage::AcquisitionPending, state)
            }
            Self::ConfiguredPending(state) => {
                pending(SemanticModelWarmStage::ActivatingConfiguredPacks, state)
            }
            Self::WarmPending => Read::reduce(Input::Pending {
                analyzer,
                stage: SemanticModelWarmStage::ActivatingInstalledPacks,
                pending_acquisitions: &[],
                shipped_pack_acquisition: None,
            }),
        }
    }
}

fn check_snapshot_cancellation(
    cancellation: Option<&CancellationToken>,
) -> Result<(), SearchToolsServiceError> {
    if let Some(token) = cancellation
        && token.is_cancelled()
    {
        return Err(if token.is_timed_out() {
            SearchToolsServiceError::deadline_exceeded(
                "workspace snapshot acquisition deadline exceeded",
            )
        } else {
            SearchToolsServiceError::internal("workspace snapshot acquisition was cancelled")
        });
    }
    Ok(())
}

impl SemanticPackWarm {
    fn settled(state: Option<Arc<WorkspacePackActivationState>>) -> Self {
        Self::new(PackWarmState::Settled(state))
    }

    fn pending() -> Self {
        Self::new(PackWarmState::Pending)
    }

    fn new(state: PackWarmState) -> Self {
        Self {
            search_warm_cancellation: CancellationToken::new(),
            state: Mutex::new(state),
            settled: Condvar::new(),
            worker: Mutex::new(None),
            installed_snapshot: Mutex::new(None),
            started_at: Instant::now(),
            settled_ns: AtomicU64::new(0),
            worker_exited: AtomicBool::new(false),
            #[cfg(test)]
            hold: None,
        }
    }

    /// Start the staged activation on its own thread and publish what it
    /// returns.
    fn spawn(project_root: PathBuf, analyzer: Arc<WorkspaceAnalyzer>) -> Result<Arc<Self>, String> {
        Self::start_worker(
            Arc::new(Self::pending()),
            project_root,
            analyzer,
            crate::analyzer::DependencyPackEcosystem::ALL.to_vec(),
        )
    }

    fn start_worker(
        warm: Arc<Self>,
        project_root: PathBuf,
        analyzer: Arc<WorkspaceAnalyzer>,
        selected: Vec<crate::analyzer::DependencyPackEcosystem>,
    ) -> Result<Arc<Self>, String> {
        let worker = start_pack_warm_worker(Arc::clone(&warm), project_root, analyzer, selected)?;
        *warm
            .worker
            .lock()
            .expect("semantic-pack warm mutex poisoned") = Some(worker);
        Ok(warm)
    }

    /// [`Self::spawn`] with the worker parked until `hold` releases it, so a
    /// test can hold the activation open and observe what the readiness barrier
    /// does while it is still running.
    #[cfg(test)]
    fn spawn_held(
        project_root: PathBuf,
        analyzer: Arc<WorkspaceAnalyzer>,
        hold: Arc<PackWarmHold>,
    ) -> Result<Arc<Self>, String> {
        let warm = Arc::new(Self {
            hold: Some(hold),
            ..Self::pending()
        });
        Self::start_worker(
            warm,
            project_root,
            analyzer,
            crate::analyzer::DependencyPackEcosystem::ALL.to_vec(),
        )
    }

    fn spawn_selected(
        project_root: PathBuf,
        analyzer: Arc<WorkspaceAnalyzer>,
        selected: Vec<crate::analyzer::DependencyPackEcosystem>,
    ) -> Result<Arc<Self>, String> {
        Self::start_worker(Arc::new(Self::pending()), project_root, analyzer, selected)
    }

    /// Join the worker if it has already exited; whether no worker remains.
    fn reap_finished_worker(&self) -> bool {
        let mut worker = self
            .worker
            .lock()
            .expect("semantic-pack warm worker mutex poisoned");
        if !self.worker_exited.load(Ordering::Acquire)
            && worker.as_ref().is_some_and(|worker| !worker.is_finished())
        {
            return false;
        }
        if let Some(worker) = worker.take()
            && let Err(panic) = worker.join()
        {
            eprintln!("{}", reported_panic("semantic-pack warm thread", panic));
        }
        true
    }

    /// Join activation before the session releases its analyzer snapshot.
    /// The worker owns an analyzer clone, so waiting only for publication would
    /// not prove that its SQLite store handles have been dropped.
    fn wait_for_worker(&self) {
        self.search_warm_cancellation.cancel();
        let worker = self
            .worker
            .lock()
            .expect("semantic-pack warm worker mutex poisoned")
            .take();
        if let Some(worker) = worker {
            #[cfg(test)]
            if let Some(hold) = &self.hold {
                hold.mark_teardown_waiting();
            }
            if let Err(panic) = worker.join() {
                eprintln!("{}", reported_panic("semantic-pack warm thread", panic));
            }
        }
    }

    /// The activation as a query snapshot observes it right now.
    fn snapshot_phase(&self) -> SessionPackActivation {
        match &*self
            .state
            .lock()
            .expect("semantic-pack warm mutex poisoned")
        {
            PackWarmState::Pending => SessionPackActivation::WarmPending,
            PackWarmState::AcquisitionPending(state) => {
                SessionPackActivation::AcquisitionPending(Arc::clone(state))
            }
            PackWarmState::ConfiguredPending(state) => {
                SessionPackActivation::ConfiguredPending(Arc::clone(state))
            }
            PackWarmState::Settled(state) => SessionPackActivation::Settled(state.clone()),
            PackWarmState::Failed(cause) => SessionPackActivation::Failed(cause.clone()),
        }
    }

    /// The best-known activation state, for scope-change detection that only
    /// reads the attempted-ecosystem set: the interim state when that is all
    /// the warm has published.
    fn best_known_state(&self) -> Option<Arc<WorkspacePackActivationState>> {
        match &*self
            .state
            .lock()
            .expect("semantic-pack warm mutex poisoned")
        {
            PackWarmState::Pending | PackWarmState::Failed(_) => None,
            PackWarmState::AcquisitionPending(state) | PackWarmState::ConfiguredPending(state) => {
                Some(Arc::clone(state))
            }
            PackWarmState::Settled(state) => state.clone(),
        }
    }

    /// Whether the warm has fully settled, expensive stage included. This is
    /// what `get_active_workspace` reports as `semantic_packs_ready`;
    /// `semantic_model_overlay` tells whether models are active.
    fn is_ready(&self) -> bool {
        matches!(
            *self
                .state
                .lock()
                .expect("semantic-pack warm mutex poisoned"),
            PackWarmState::Settled(_) | PackWarmState::Failed(_)
        )
    }

    fn overlay_status(&self) -> SemanticModelOverlayStatus {
        match &*self
            .state
            .lock()
            .expect("semantic-pack warm mutex poisoned")
        {
            PackWarmState::Pending => SemanticModelOverlayStatus::Pending {
                stage: SemanticModelWarmStage::ActivatingInstalledPacks,
                pending_acquisitions: Vec::new(),
                shipped_pack_acquisition: None,
            },
            PackWarmState::AcquisitionPending(state) => SemanticModelOverlayStatus::Pending {
                stage: SemanticModelWarmStage::AcquisitionPending,
                pending_acquisitions: state
                    .pending_acquisitions
                    .iter()
                    .map(|pending| PendingSemanticPackAcquisition {
                        ecosystem: pending.ecosystem.label().to_owned(),
                        dependency_id: pending.dependency_id.clone(),
                    })
                    .collect(),
                shipped_pack_acquisition: state.shipped_pack_acquisition_pending.clone(),
            },
            PackWarmState::ConfiguredPending(state) => SemanticModelOverlayStatus::Pending {
                stage: SemanticModelWarmStage::ActivatingConfiguredPacks,
                pending_acquisitions: state
                    .pending_acquisitions
                    .iter()
                    .map(|pending| PendingSemanticPackAcquisition {
                        ecosystem: pending.ecosystem.label().to_owned(),
                        dependency_id: pending.dependency_id.clone(),
                    })
                    .collect(),
                shipped_pack_acquisition: state.shipped_pack_acquisition_pending.clone(),
            },
            PackWarmState::Failed(cause) => SemanticModelOverlayStatus::Unavailable {
                reason: cause.clone(),
                budget: None,
            },
            PackWarmState::Settled(Some(state)) => state.overlay.clone(),
            PackWarmState::Settled(None) => SemanticModelOverlayStatus::Unavailable {
                reason: "semantic-pack warm failed before publishing an activation outcome"
                    .to_owned(),
                budget: None,
            },
        }
    }

    /// How long the warm ran, or `None` while it is pending.
    fn duration(&self) -> Option<Duration> {
        let settled_ns = self.settled_ns.load(Ordering::Relaxed);
        (settled_ns != 0).then(|| Duration::from_nanos(settled_ns))
    }

    /// Block until the installed stage has published. Returning says nothing
    /// about the expensive stage; callers that need the exact final set use
    /// [`Self::wait`].
    fn wait_for_installed_stage(
        &self,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), SearchToolsServiceError> {
        let mut state = self
            .state
            .lock()
            .expect("semantic-pack warm mutex poisoned");
        while matches!(*state, PackWarmState::Pending) {
            state = self.wait_for_progress(state, cancellation)?;
        }
        Ok(())
    }

    /// Wait for the worker slot needed by a deferred installed stage. The
    /// exit guard publishes under the state mutex so a notification cannot
    /// be lost between observing the predicate and entering the wait.
    fn wait_for_worker_exit(
        &self,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), SearchToolsServiceError> {
        let mut state = self
            .state
            .lock()
            .expect("semantic-pack warm mutex poisoned");
        while !self.worker_exited.load(Ordering::Acquire) {
            state = self.wait_for_progress(state, cancellation)?;
        }
        Ok(())
    }

    fn wait_for_progress<'a>(
        &self,
        state: std::sync::MutexGuard<'a, PackWarmState>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<std::sync::MutexGuard<'a, PackWarmState>, SearchToolsServiceError> {
        check_snapshot_cancellation(cancellation)?;
        // CancellationToken has no notification registration. This timeout
        // only polls cancellation; successful readiness always uses state.
        Ok(match cancellation {
            Some(token) => {
                self.settled
                    .wait_timeout(
                        state,
                        token
                            .remaining_time()
                            .unwrap_or(Duration::from_millis(25))
                            .min(Duration::from_millis(25)),
                    )
                    .expect("semantic-pack warm mutex poisoned")
                    .0
            }
            None => self
                .settled
                .wait(state)
                .expect("semantic-pack warm mutex poisoned"),
        })
    }

    /// Test-only wait for the warm's final state. Queries use the installed
    /// stage fence, first awaiting the worker slot when a refresh is deferred.
    #[cfg(test)]
    fn wait(&self) -> Option<Arc<WorkspacePackActivationState>> {
        let mut state = self
            .state
            .lock()
            .expect("semantic-pack warm mutex poisoned");
        loop {
            match &*state {
                PackWarmState::Settled(state) => return state.clone(),
                PackWarmState::Failed(_) => return None,
                _ => {
                    state = self
                        .settled
                        .wait(state)
                        .expect("semantic-pack warm mutex poisoned");
                }
            }
        }
    }

    /// Publish the installed stage's interim activation: queries that awaited
    /// it proceed from here while the expensive stage keeps running.
    fn publish_acquisition_pending(&self, state: Arc<WorkspacePackActivationState>) {
        debug_assert!(
            !state.pending_acquisitions.is_empty()
                || state.shipped_pack_acquisition_pending.is_some(),
            "an acquisition-pending warm state must name its outstanding acquisitions"
        );
        *self
            .state
            .lock()
            .expect("semantic-pack warm mutex poisoned") = PackWarmState::AcquisitionPending(state);
        self.settled.notify_all();
    }

    fn begin_configured_activation(&self) {
        let mut state = self
            .state
            .lock()
            .expect("semantic-pack warm mutex poisoned");
        if let PackWarmState::AcquisitionPending(interim) = &*state {
            *state = PackWarmState::ConfiguredPending(Arc::clone(interim));
        }
    }

    #[cfg(test)]
    fn publish_final(&self, state: Option<Arc<WorkspacePackActivationState>>) {
        drop(PackWarmPublication {
            warm: self,
            outcome: PackWarmState::Settled(state),
        });
    }

    fn publish_terminal(&self, state: PackWarmState) {
        assert!(matches!(
            state,
            PackWarmState::Settled(_) | PackWarmState::Failed(_)
        ));
        if let PackWarmState::Settled(Some(state)) = &state {
            debug_assert!(
                state.pending_acquisitions.is_empty()
                    && state.shipped_pack_acquisition_pending.is_none(),
                "a settled warm state cannot keep pending acquisitions"
            );
        }
        self.settled_ns
            .store(duration_ns(self.started_at.elapsed()), Ordering::Relaxed);
        *self
            .state
            .lock()
            .expect("semantic-pack warm mutex poisoned") = state;
        self.settled.notify_all();
        // The readiness barrier deliberately excludes this work, so a profile
        // has to name it from here or the cost moves off the reported path
        // without ever being visible (issue #3372).
        if let Some(duration) = self.duration() {
            profiling::note_with(|| {
                format!(
                    "semantic_pack.warm settled off the readiness path after {:.1} ms",
                    duration.as_secs_f64() * 1000.0
                )
            });
        }
    }
}

/// Owns terminal publication even when activation unwinds or returns early.
struct PackWarmPublication<'a> {
    warm: &'a SemanticPackWarm,
    outcome: PackWarmState,
}

impl Drop for PackWarmPublication<'_> {
    fn drop(&mut self) {
        self.warm.publish_terminal(std::mem::replace(
            &mut self.outcome,
            PackWarmState::Failed("semantic-pack warm worker exited without an outcome".to_owned()),
        ));
    }
}

fn start_pack_warm_worker(
    warm: Arc<SemanticPackWarm>,
    project_root: PathBuf,
    analyzer: Arc<WorkspaceAnalyzer>,
    selected: Vec<crate::analyzer::DependencyPackEcosystem>,
) -> Result<std::thread::JoinHandle<()>, String> {
    struct PublishWorkerExit(Arc<SemanticPackWarm>);
    impl Drop for PublishWorkerExit {
        fn drop(&mut self) {
            let _state = self
                .0
                .state
                .lock()
                .expect("semantic-pack warm mutex poisoned");
            self.0.worker_exited.store(true, Ordering::Release);
            self.0.settled.notify_all();
        }
    }
    // Background work counts as activity for the idle heap release (#12661): taken before the spawn, held until the thread ends.
    let heap_activity = brokk_bifrost_core::heap_release::IdleHeapRelease::process().warm();
    std::thread::Builder::new()
        .name("bifrost-semantic-pack-warm".to_string())
        .spawn(move || {
            let _exit = PublishWorkerExit(Arc::clone(&warm));
            let _heap_activity = heap_activity;
            let mut publication = Some(PackWarmPublication {
                warm: &warm,
                outcome: PackWarmState::Failed("semantic-pack warm worker panicked".to_owned()),
            });
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                brokk_bifrost_analysis::analyzer::without_project_reads(|| {
                    #[cfg(test)]
                    if let Some(hold) = &warm.hold {
                        hold.park_until_released();
                        if hold.panic_after_release {
                            panic!("injected semantic-pack warm failure");
                        }
                    }
                    // The installed stage is what the query path awaits: catalog open
                    // and the packs already installed for this workspace, with nothing
                    // fetched, verified, extracted, or generated. Only when that stage
                    // leaves acquisitions outstanding does the warm continue to the
                    // full activation (issue #3401).
                    let source_snapshot = analyzer;
                    let analyzer = source_snapshot.as_ref().clone();
                    let installed = activate_session_pack_stage(
                        &project_root,
                        &analyzer,
                        |root, workspace, configured| {
                            activate_configured_semantic_models_installed_stage_selected(
                                root, workspace, configured, &selected,
                            )
                        },
                        InstalledPackStageOutcome::Settled,
                    );
                    // Publish an immutable activated snapshot before releasing the
                    // installed-stage barrier. Later acquisition works on its own clone.
                    *warm
                        .installed_snapshot
                        .lock()
                        .expect("semantic-pack snapshot mutex poisoned") =
                        Some((Arc::downgrade(&source_snapshot), Arc::new(analyzer.clone())));
                    let outcome = match installed {
                        None => None,
                        Some(InstalledPackStageOutcome::Settled(state)) => Some(Arc::new(state)),
                        Some(InstalledPackStageOutcome::AcquisitionPending(
                            state,
                            discovery_handoff,
                        )) => {
                            warm.publish_acquisition_pending(Arc::new(state));
                            #[cfg(test)]
                            if let Some(hold) = &warm.hold {
                                hold.park_expensive_stage_until_released();
                            }
                            warm.begin_configured_activation();
                            let mut discovery_handoff = Some(discovery_handoff);
                            activate_session_pack_stage(
                                &project_root,
                                &analyzer,
                                |root, workspace, configured| {
                                    activate_configured_semantic_models_selected(
                                        root,
                                        workspace,
                                        configured,
                                        &selected,
                                        discovery_handoff
                                            .take()
                                            .expect("configured stage runs once"),
                                    )
                                },
                                |state| state,
                            )
                            .map(Arc::new)
                        }
                    };
                    let mut completed = publication.take().expect("worker owns publication");
                    completed.outcome = PackWarmState::Settled(outcome);
                    drop(completed);
                    // The final activation is already visible as Ready. Reuse this
                    // worker for optional warming; requests join its normal fill.
                    let search_warm_started = Instant::now();
                    if std::env::var_os("BIFROST_TIMING").is_some() {
                        eprintln!("semantic-pack search warm-up started");
                    }
                    if let Some(snapshot) = analyzer.analyzer().active_semantic_model_snapshot()
                        && let Some(overlay) = snapshot.semantic_model_overlay()
                        && let Err(error) = overlay.prefill_search_inputs(
                            analyzer.analyzer(),
                            &warm.search_warm_cancellation,
                        )
                        && !warm.search_warm_cancellation.is_cancelled()
                    {
                        eprintln!("semantic-pack search warm-up failed: {error:?}");
                    }
                    if std::env::var_os("BIFROST_TIMING").is_some() {
                        eprintln!(
                            "semantic-pack search warm-up finished in {:?}; cancelled={}",
                            search_warm_started.elapsed(),
                            warm.search_warm_cancellation.is_cancelled()
                        );
                    }
                })
            }));
            if let Err(payload) = result {
                if let Some(publication) = &mut publication {
                    publication.outcome = PackWarmState::Failed(format!(
                        "semantic-pack warm worker panicked: {}",
                        brokk_bifrost_core::panic_report::panic_payload_message(payload.as_ref()),
                    ));
                }
                std::panic::resume_unwind(payload);
            }
        })
        .map_err(|error| format!("Failed to spawn semantic-pack warm thread: {error}"))
}

/// Hang guard for tests that park or release a semantic-pack warm.
///
/// These tests assert lifecycle ordering; they do not budget how long
/// workspace activation may take. A focused run settles in a few seconds, but
/// a full `brokk-bifrost-mcp` run on a loaded 32-CPU validation host delayed
/// the guarded events past 30 s (#14097). Keep the guard well above observed
/// load latency and below nextest's 600 s terminate-after, so a genuine hang
/// still fails with the guard's own message. Production deadlines are
/// unchanged.
#[cfg(test)]
const PACK_WARM_TEST_HANG_GUARD: Duration = Duration::from_secs(180);

/// Test-only latch that parks a semantic-pack warm before it starts.
#[cfg(test)]
struct PackWarmHold {
    released: Mutex<bool>,
    progress: Condvar,
    worker_parked: Mutex<bool>,
    worker_parked_changed: Condvar,
    teardown_waiting: Mutex<bool>,
    teardown_waiting_changed: Condvar,
    panic_after_release: bool,
    /// When set, parks the warm again between its installed stage and the
    /// expensive acquisition stage, so a test can observe a query answered
    /// against the interim activation with production still outstanding.
    expensive_stage: Option<Arc<ExpensiveStageHold>>,
}

/// The second latch of a [`PackWarmHold`]: parks the warm's expensive stage.
#[cfg(test)]
struct ExpensiveStageHold {
    released: Mutex<bool>,
    progress: Condvar,
}

#[cfg(test)]
fn new_release_latch() -> (Mutex<bool>, Condvar) {
    (Mutex::new(false), Condvar::new())
}

#[cfg(test)]
fn park_on_release(released: &Mutex<bool>, progress: &Condvar, poison_message: &str) {
    let mut released = released.lock().expect(poison_message);
    while !*released {
        released = progress.wait(released).expect(poison_message);
    }
}

#[cfg(test)]
fn release_latch(released: &Mutex<bool>, progress: &Condvar, poison_message: &str) {
    *released.lock().expect(poison_message) = true;
    progress.notify_all();
}

#[cfg(test)]
impl ExpensiveStageHold {
    fn new() -> Self {
        let (released, progress) = new_release_latch();
        Self { released, progress }
    }

    fn park_until_released(&self) {
        park_on_release(
            &self.released,
            &self.progress,
            "expensive-stage hold mutex poisoned",
        );
    }

    fn release(&self) {
        release_latch(
            &self.released,
            &self.progress,
            "expensive-stage hold mutex poisoned",
        );
    }
}

#[cfg(test)]
impl PackWarmHold {
    fn new() -> Self {
        let (released, progress) = new_release_latch();
        Self {
            released,
            progress,
            worker_parked: Mutex::new(false),
            worker_parked_changed: Condvar::new(),
            teardown_waiting: Mutex::new(false),
            teardown_waiting_changed: Condvar::new(),
            panic_after_release: false,
            expensive_stage: None,
        }
    }

    fn new_panicking() -> Self {
        Self {
            panic_after_release: true,
            ..Self::new()
        }
    }

    fn new_holding_expensive_stage() -> (Self, Arc<ExpensiveStageHold>) {
        let expensive_stage = Arc::new(ExpensiveStageHold::new());
        let hold = Self {
            expensive_stage: Some(Arc::clone(&expensive_stage)),
            ..Self::new()
        };
        (hold, expensive_stage)
    }

    fn park_until_released(&self) {
        *self
            .worker_parked
            .lock()
            .expect("pack warm parked mutex poisoned") = true;
        self.worker_parked_changed.notify_all();
        park_on_release(
            &self.released,
            &self.progress,
            "pack warm hold mutex poisoned",
        );
    }

    fn park_expensive_stage_until_released(&self) {
        if let Some(expensive_stage) = &self.expensive_stage {
            expensive_stage.park_until_released();
        }
    }

    fn release(&self) {
        release_latch(
            &self.released,
            &self.progress,
            "pack warm hold mutex poisoned",
        );
    }

    fn release_all(&self) {
        self.release();
        if let Some(expensive_stage) = &self.expensive_stage {
            expensive_stage.release();
        }
    }

    fn mark_teardown_waiting(&self) {
        *self
            .teardown_waiting
            .lock()
            .expect("pack warm teardown mutex poisoned") = true;
        self.teardown_waiting_changed.notify_all();
    }

    fn wait_for_worker_parked(&self) {
        let state = self
            .worker_parked
            .lock()
            .expect("pack warm parked mutex poisoned");
        let (state, _) = self
            .worker_parked_changed
            .wait_timeout_while(state, PACK_WARM_TEST_HANG_GUARD, |state| !*state)
            .expect("pack warm parked mutex poisoned while waiting");
        assert!(*state, "semantic-pack warm worker did not reach its hold");
    }

    fn wait_for_teardown_waiting(&self) {
        let state = self
            .teardown_waiting
            .lock()
            .expect("pack warm teardown mutex poisoned");
        let (state, _) = self
            .teardown_waiting_changed
            .wait_timeout_while(state, PACK_WARM_TEST_HANG_GUARD, |state| !*state)
            .expect("pack warm teardown mutex poisoned while waiting");
        assert!(
            *state,
            "session teardown did not wait for semantic-pack warm"
        );
    }
}

#[cfg(test)]
struct ReleasePackWarmOnDrop(Arc<PackWarmHold>);

#[cfg(test)]
impl Drop for ReleasePackWarmOnDrop {
    fn drop(&mut self) {
        self.0.release_all();
    }
}

struct WorkspaceSession {
    snapshot: Arc<WorkspaceAnalyzer>,
    document_root: Arc<WorkspaceRoot>,
    /// Read through [`WorkspaceSession::pack_activation`]; the warm is settled
    /// for a synchronously assembled session and may still be running for a
    /// deferred one.
    semantic_packs: Arc<SemanticPackWarm>,
    /// Warms a pack refresh replaced while their workers were still running.
    /// Their results can no longer match `semantic_packs`, so they are never
    /// published, but each worker owns an analyzer clone and is joined when the
    /// session drops.
    retired_pack_warms: Vec<Arc<SemanticPackWarm>>,
    refresh: PackRefresh,
    watcher: SessionWatcher,
    usage_index_warm: Option<JoinHandle<()>>,
    index_warmer: Arc<IndexWarmer>,
    // Last field: the slot outlives every session-owned worker and snapshot.
    lifetime: Option<Arc<WorkspaceLifetime>>,
}

/// A pack refresh that could not start because the current warm's worker had
/// not exited. `settle_pack_stage` starts it once the worker is reaped. A whole
/// refresh absorbs any later ecosystem refresh; the stale ecosystems are read
/// from the snapshot when the refresh starts, so none are stored here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PackRefresh {
    Idle,
    DeferredEcosystems,
    DeferredWhole,
}

enum SessionWatcher {
    Disabled,
    Active(Box<ProjectChangeWatcher>),
}

/// Owns one workspace snapshot and its request-scoped analyzer memoization.
///
/// Returning this from `snapshot_for_query` makes the cleanup obligation part
/// of the type, including for direct callers such as the code-query REPL.
struct WorkspaceQueryScope {
    source_snapshot: Arc<WorkspaceAnalyzer>,
    snapshot: Arc<WorkspaceAnalyzer>,
    document_root: Arc<WorkspaceRoot>,
    pack_activation: SessionPackActivation,
    context: Arc<crate::analyzer::AnalyzerQueryContext>,
}

pub(crate) struct PreparedQueryCode {
    snapshot: WorkspaceQueryScope,
    arguments: Value,
    request_timing: PreparedQueryCodeTiming,
    workspace_generation: u64,
    query_protocols: crate::rql::ProtocolRegistrationSet,
    query_value_flows: crate::rql::ValueFlowPlanRegistrationSet,
    query_taint_results: crate::rql::TaintResultRegistrationSet,
}

#[derive(Debug, Clone, Copy)]
struct PreparedQueryCodeTiming {
    started: Instant,
    workspace_ready_ns: u64,
    preparation_ns: u64,
}

#[derive(Debug, Clone, Copy)]
struct QueryCodeExecutionTiming {
    input_decode_ns: u64,
    query_execution_ns: u64,
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// Which question `explain_policy` was asked, and the bounds it carries.
pub(crate) enum ExplainPolicyQuestion {
    /// Why, or why-not, about one exact subject.
    Explanation(ExplanationTarget),
    /// Which subjects came closest, over a bounded candidate set.
    NearMiss(NearMissCandidates, ExplanationLimits),
}

fn explain_policy_candidate(
    candidate: &ExplainPolicyCandidate,
) -> Result<ExplanationCandidate, SearchToolsServiceError> {
    match candidate.byte_end {
        Some(byte_end) => {
            ExplanationCandidate::in_range(&candidate.path, candidate.byte_start, byte_end)
        }
        None => ExplanationCandidate::at_offset(&candidate.path, candidate.byte_start),
    }
    .map_err(|error| {
        SearchToolsServiceError::invalid_params(format!(
            "invalid explain_policy candidate: {error}"
        ))
    })
}

/// Resolve the request into exactly one question.
///
/// Exactly one of the three targets must be present: a request with more than
/// one would have more than one answer, and a request with none has no
/// question. The schema states the exclusion and this enforces it.
/// The workspace generation the request pins, if it pinned one.
fn explain_policy_generation(
    params: &ExplainPolicyParams,
) -> Result<Option<ExplanationGeneration>, SearchToolsServiceError> {
    params
        .workspace_generation
        .as_deref()
        .map(|value| {
            value.parse::<ExplanationGeneration>().map_err(|error| {
                SearchToolsServiceError::invalid_params(format!(
                    "invalid explain_policy workspace_generation `{value}`: {error}"
                ))
            })
        })
        .transpose()
}

fn explain_policy_question(
    params: &ExplainPolicyParams,
) -> Result<ExplainPolicyQuestion, SearchToolsServiceError> {
    let asked = usize::from(params.finding_id.is_some())
        + usize::from(params.candidate.is_some())
        + usize::from(params.near_misses.is_some());
    if asked > 1 {
        return Err(SearchToolsServiceError::invalid_params(
            "explain_policy accepts exactly one of finding_id, candidate, or near_misses"
                .to_string(),
        ));
    }
    if params.candidate_source.is_some() && params.candidate.is_none() {
        return Err(SearchToolsServiceError::invalid_params(
            "explain_policy candidate_source is the source half of a flow or taint candidate \
             and requires candidate"
                .to_string(),
        ));
    }
    if let Some(finding_id) = &params.finding_id {
        let parsed = finding_id.parse::<PolicyFindingId>().map_err(|error| {
            SearchToolsServiceError::invalid_params(format!(
                "invalid explain_policy finding_id `{finding_id}`: {error}"
            ))
        })?;
        return Ok(ExplainPolicyQuestion::Explanation(
            ExplanationTarget::Finding(parsed),
        ));
    }
    if let Some(candidate) = &params.candidate {
        let observation = explain_policy_candidate(candidate)?;
        return Ok(ExplainPolicyQuestion::Explanation(
            match &params.candidate_source {
                Some(source) => ExplanationTarget::FlowCandidate(FlowExplanationCandidate::new(
                    explain_policy_candidate(source)?,
                    observation,
                )),
                None => ExplanationTarget::Candidate(observation),
            },
        ));
    }
    let Some(near_misses) = &params.near_misses else {
        return Err(SearchToolsServiceError::invalid_params(
            "explain_policy requires finding_id (why), candidate (why-not), or near_misses \
             (which came closest)"
                .to_string(),
        ));
    };

    let candidates = match (
        &near_misses.candidates,
        near_misses.enumerate_from_policy_seed,
    ) {
        (Some(_), Some(_)) => {
            return Err(SearchToolsServiceError::invalid_params(
                "explain_policy near_misses accepts candidates or enumerate_from_policy_seed, \
                 not both"
                    .to_string(),
            ));
        }
        (None, None) | (None, Some(false)) => {
            return Err(SearchToolsServiceError::invalid_params(
                "explain_policy near_misses requires either candidates or \
                 enumerate_from_policy_seed: candidates are never scanned for by default"
                    .to_string(),
            ));
        }
        (Some(candidates), None) => {
            if candidates.is_empty()
                || candidates.len() > crate::mcp_extended::MAX_EXPLAIN_POLICY_NEAR_MISS_CANDIDATES
            {
                return Err(SearchToolsServiceError::invalid_params(format!(
                    "explain_policy near_misses candidates must contain between 1 and {} entries",
                    crate::mcp_extended::MAX_EXPLAIN_POLICY_NEAR_MISS_CANDIDATES
                )));
            }
            NearMissCandidates::Supplied(
                candidates
                    .iter()
                    .map(explain_policy_candidate)
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
        (None, Some(true)) => NearMissCandidates::PolicySeedSearch,
    };

    let mut limits = ExplanationLimits::default();
    if let Some(max_candidates) = near_misses.max_candidates {
        if max_candidates == 0
            || max_candidates > crate::mcp_extended::MAX_EXPLAIN_POLICY_NEAR_MISS_CANDIDATES
        {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "explain_policy near_misses max_candidates must be between 1 and {}",
                crate::mcp_extended::MAX_EXPLAIN_POLICY_NEAR_MISS_CANDIDATES
            )));
        }
        limits = limits.with_max_near_miss_candidates(max_candidates);
    }
    if let Some(max_executions) = near_misses.max_executions {
        if max_executions == 0
            || max_executions > crate::mcp_extended::MAX_EXPLAIN_POLICY_NEAR_MISS_EXECUTIONS
        {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "explain_policy near_misses max_executions must be between 1 and {}",
                crate::mcp_extended::MAX_EXPLAIN_POLICY_NEAR_MISS_EXECUTIONS
            )));
        }
        limits = limits.with_max_near_miss_executions(max_executions);
    }
    Ok(ExplainPolicyQuestion::NearMiss(candidates, limits))
}

/// Resolve `explain_policy`'s policy selection into exactly one policy input.
///
/// The bounds are `run_policy`'s -- the same path, selector, and extension
/// rules -- narrowed to one policy, because an explanation is about one.
fn explain_policy_inputs_from(
    params: &ExplainPolicyParams,
) -> Result<Vec<PolicyEvaluationInput>, SearchToolsServiceError> {
    for (label, values) in [
        ("policy_packs", &params.policy_packs),
        ("policy_categories", &params.policy_categories),
        ("policy_ids", &params.policy_ids),
    ] {
        for value in values {
            if value.is_empty() || value.len() > crate::mcp_extended::MAX_RUN_POLICY_SELECTOR_BYTES
            {
                return Err(SearchToolsServiceError::invalid_params(format!(
                    "explain_policy {label} entries must contain between 1 and {} bytes",
                    crate::mcp_extended::MAX_RUN_POLICY_SELECTOR_BYTES
                )));
            }
        }
    }
    let mut inputs = Vec::new();
    for raw_path in &params.policy_files {
        if raw_path.len() > crate::mcp_extended::MAX_RUN_POLICY_PATH_BYTES {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "explain_policy policy path exceeds {} bytes",
                crate::mcp_extended::MAX_RUN_POLICY_PATH_BYTES
            )));
        }
        let path = WorkspaceRelativePath::new(raw_path).map_err(|error| {
            SearchToolsServiceError::invalid_params(format!(
                "invalid explain_policy policy path `{raw_path}`: {error}"
            ))
        })?;
        if Path::new(path.as_str())
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("rqlp")
        {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "explain_policy policy path `{}` must use the .rqlp extension",
                path.as_str()
            )));
        }
        inputs.push(PolicyEvaluationInput::workspace_file(path.as_str()));
    }

    let mut selection = BuiltInPolicySelection {
        packs: params.policy_packs.clone(),
        categories: params.policy_categories.clone(),
        policy_ids: params.policy_ids.clone(),
        excluded_policy_ids: Vec::new(),
    };
    let mut bundle_inputs = policy_bundles()
        .and_then(|bundles| bundles.take_selected(&mut selection))
        .map_err(|error| SearchToolsServiceError::invalid_params(error.to_string()))?;
    let selected = built_in_policy_catalog()
        .map_err(|error| {
            SearchToolsServiceError::internal(format!(
                "failed to load built-in policy catalog: {error}"
            ))
        })?
        .select(&selection)
        .map_err(|error| SearchToolsServiceError::invalid_params(error.to_string()))?;
    let mut built_in = selected
        .into_iter()
        .map(PolicyEvaluationInput::selected_builtin)
        .collect::<Vec<_>>();
    built_in.append(&mut bundle_inputs);
    built_in.append(&mut inputs);
    if built_in.len() != 1 {
        return Err(SearchToolsServiceError::invalid_params(format!(
            "explain_policy explains one policy, but the selection resolved to {}",
            built_in.len()
        )));
    }
    Ok(built_in)
}

/// Map one explanation condition onto the transport's error vocabulary.
///
/// Every condition the caller can fix -- a policy that does not load, an
/// adapter that does not exist for the policy's family, a finding identity the
/// run does not carry -- is an invalid-parameter error carrying the library's
/// own message, so an agent reads one stated condition rather than a stack of
/// wrappers.
fn explain_error_to_service_error(error: ExplainError) -> SearchToolsServiceError {
    match error {
        ExplainError::StaleWorkspaceGeneration { requested, current } => SearchToolsServiceError {
            code: SearchToolsServiceErrorCode::StaleWorkspaceGeneration { requested, current },
            message: format!("explain_policy could not answer: {error}"),
            // Reloading the current snapshot cannot restore an obsolete caller pin.
            workspace_incomplete: None,
            retryable_stale_generation: false,
        },
        _ => SearchToolsServiceError::invalid_params(format!(
            "explain_policy could not answer: {error}"
        )),
    }
}

/// Wire-level coverage for `explain_policy` (issue 2439 slice 3).
///
/// Every assertion here reads the tool's structured result, never rendered
/// text: the whole point of the tool is that an authoring agent does not parse
/// prose.
#[cfg(test)]
mod explain_policy_tests {
    use super::*;
    use crate::path_normalization::NormalizePath;
    use serde_json::json;

    const MATCH_POLICY: &str = r#"(policy
  :id "test.explain.mcp.match"
  :name "Widget"
  :message "Widget is reported"
  :severity warning
  :analysis (analysis :type match :selector (rql (class :name "Widget"))))"#;

    const RELATIONAL_POLICY: &str = r#"(policy
  :id "test.explain.mcp.relational"
  :name "No value reads"
  :message "value reads are forbidden in this fixture"
  :severity warning
  :analysis (analysis
    :type assertion
    (bind :name read :query (rql (occurrences :role [value_reference])))
    (group :name by-read :by (read.ast_id)
      (aggregate :name reads :op count))
    (assert :group by-read :value reads :cardinality (exactly 0))))"#;

    const TAINT_POLICY: &str = r#"(policy
  :id "test.explain.mcp.taint"
  :name "Taint"
  :message (generated-message :relation can-reach)
  :severity warning
  :analysis (analysis
    :type taint
    :mode may
    :sources (endpoint-set :entries [
      (source :id alpha :display-name "user input" :categories [input.user]
        :selector (rql (name "alpha")) :bind return-value :labels [untrusted])])
    :sinks (endpoint-set :entries [
      (sink :id store :display-name "sensitive store" :categories [data.sensitive]
        :selector (rql (name "store")) :dangerous-operand matched-value
        :accepts [untrusted])])))"#;

    /// Two classes, so a near-miss ranking has a subject at distance 0 and a
    /// subject the selector's one declared predicate drops.
    const SOURCE: &str = "class Widget {\n  int render() { return 1; }\n}\nclass Gadget {\n  int render() { return 2; }\n}\n";

    fn service() -> (tempfile::TempDir, SearchToolsService) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("Widget.java"), SOURCE).unwrap();
        std::fs::create_dir_all(temp.path().join("policies")).unwrap();
        for (name, source) in [
            ("match.rqlp", MATCH_POLICY),
            ("relational.rqlp", RELATIONAL_POLICY),
            ("taint.rqlp", TAINT_POLICY),
        ] {
            std::fs::write(temp.path().join("policies").join(name), source).unwrap();
        }
        let root = temp.path().canonicalize().unwrap().normalize();
        let service =
            SearchToolsService::new_manual_ephemeral(root).expect("manual service should start");
        (temp, service)
    }

    fn byte_offset(needle: &str) -> u64 {
        u64::try_from(SOURCE.find(needle).expect("the fixture holds the needle")).unwrap()
    }

    /// The near-miss form never means "search the repository": one of the two
    /// enumeration routes must be chosen explicitly.
    #[test]
    fn explain_policy_near_misses_requires_an_explicit_enumeration_route() {
        let (_temp, service) = service();
        for (arguments, expected) in [
            (
                json!({}),
                "requires either candidates or enumerate_from_policy_seed",
            ),
            (
                json!({ "enumerate_from_policy_seed": false }),
                "requires either candidates or enumerate_from_policy_seed",
            ),
            (
                json!({
                    "candidates": [{ "path": "Widget.java", "byte_start": 0 }],
                    "enumerate_from_policy_seed": true
                }),
                "not both",
            ),
            (
                json!({ "enumerate_from_policy_seed": true, "max_candidates": 0 }),
                "max_candidates must be between 1 and",
            ),
            (
                json!({ "enumerate_from_policy_seed": true, "max_executions": 0 }),
                "max_executions must be between 1 and",
            ),
            (
                json!({ "candidates": [] }),
                "candidates must contain between 1 and",
            ),
        ] {
            let error = service
                .call_tool_value(
                    "explain_policy",
                    json!({
                        "policy_files": ["policies/match.rqlp"],
                        "near_misses": arguments
                    }),
                )
                .expect_err("a near-miss request states where its candidates come from");
            assert_eq!(error.code, SearchToolsServiceErrorCode::InvalidParams);
            assert!(error.message.contains(expected), "{}", error.message);
        }
    }

    /// A taint candidate is a source position and a sink position (issue
    /// 3686), so each half of a mismatched candidate shape is a stated
    /// condition on the wire. A family with no adapter for a question is one
    /// too, and the message names the families that do have one.
    #[test]
    fn explain_policy_states_the_candidate_shape_and_the_supported_families() {
        let (_temp, service) = service();
        let position = json!({ "path": "Widget.java", "byte_start": 0 });
        for (arguments, expected) in [
            (
                json!({ "policy_files": ["policies/taint.rqlp"], "candidate": position }),
                "supply candidate_source",
            ),
            (
                json!({ "policy_files": ["policies/match.rqlp"], "candidate_source": position }),
                "requires candidate",
            ),
            (
                json!({
                    "policy_files": ["policies/match.rqlp"],
                    "finding_id": "0".repeat(64),
                    "candidate_source": position
                }),
                "requires candidate",
            ),
            (
                json!({
                    "policy_files": ["policies/match.rqlp"],
                    "candidate": position,
                    "candidate_source": position
                }),
                "applies only to flow and taint policies",
            ),
            (
                json!({
                    "policy_files": ["policies/taint.rqlp"],
                    "near_misses": { "enumerate_from_policy_seed": true }
                }),
                "supported analysis types: match, assertion",
            ),
        ] {
            let error = service
                .call_tool_value("explain_policy", arguments.clone())
                .expect_err("a mismatched question is refused");
            assert_eq!(
                error.code,
                SearchToolsServiceErrorCode::InvalidParams,
                "{arguments}"
            );
            assert!(
                error.message.contains(expected),
                "{arguments}: {}",
                error.message
            );
        }
    }

    /// Issue 3207 item 1. An agent that read a finding id under one workspace
    /// snapshot can state that snapshot, and a request that arrives after the
    /// workspace moved is refused rather than answered about a different run.
    #[test]
    fn explain_policy_refuses_a_pinned_generation_the_workspace_no_longer_has() {
        let (_temp, service) = service();
        let arguments = json!({
            "policy_files": ["policies/match.rqlp"],
            "candidate": { "path": "Widget.java", "byte_start": byte_offset("Widget") }
        });
        let unpinned = service
            .call_tool_value("explain_policy", arguments.clone())
            .expect("an unpinned answer");
        let current = unpinned["explanation"]["workspace_generation"]
            .as_str()
            .unwrap_or_else(|| panic!("every answer states its generation: {unpinned:#}"))
            .to_owned();

        let mut pinned_arguments = arguments.clone();
        pinned_arguments["workspace_generation"] = json!(current);
        let pinned = service
            .call_tool_value("explain_policy", pinned_arguments)
            .expect("the current generation is accepted");
        assert_eq!(
            serde_json::to_string(&pinned).unwrap(),
            serde_json::to_string(&unpinned).unwrap()
        );

        let mut stale_arguments = arguments;
        stale_arguments["workspace_generation"] = json!("0".repeat(64));
        let stale = service
            .call_tool_value("explain_policy", stale_arguments)
            .expect_err("a workspace that moved must not be silently explained");
        assert!(
            matches!(
                stale.code,
                SearchToolsServiceErrorCode::StaleWorkspaceGeneration { .. }
            ),
            "{stale:?}"
        );
        assert!(
            stale.message.contains("pinned workspace generation")
                && stale.message.contains(&current),
            "{}",
            stale.message
        );
    }

    #[test]
    fn stale_explanation_pin_does_not_reload_workspace() {
        let (_temp, service) = service();
        let generation = service.workspace_generation();
        let error = service
            .call_tool_value(
                "explain_policy",
                json!({
                    "policy_files": ["policies/match.rqlp"],
                    "candidate": { "path": "Widget.java", "byte_start": byte_offset("Widget") },
                    "workspace_generation": "0".repeat(64)
                }),
            )
            .expect_err("a stale pin must fail");
        assert!(matches!(
            error.code,
            SearchToolsServiceErrorCode::StaleWorkspaceGeneration { .. }
        ));
        assert_eq!(service.workspace_generation(), generation);
    }

    #[test]
    fn query_code_projects_registered_taint_result() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        std::fs::write(
            root.join("Foo.java"),
            "class Foo { static String userInput() { return \"input\"; } static String relay(String value) { return value; } static void eval(String code) {} static void unsafe() { eval(relay(userInput())); } }\n",
        )
        .unwrap();
        let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        let input = [PolicyEvaluationInput::embedded(
            crate::policy::PolicySourceIdentity::new("test:registered-taint.rqlp"),
            r#"(policy
              :schema-version 1
              :id "test.registered.taint"
              :name "Registered taint"
              :message "untrusted input reaches eval"
              :severity warning
              :analysis (analysis
                :type taint
                :mode may
                :call-modeling (call-modeling :unmodeled optimistic)
                :sources (endpoint-set :entries [
                  (source :id input :display-name "user input" :categories [input.user]
                    :selector (rql :schema-version 1
                      (language java (call :callee (name "userInput"))))
                    :bind return-value :labels [untrusted])])
                :sinks (endpoint-set :entries [
                  (sink :id eval :display-name "eval sink" :categories [code.execution]
                    :selector (rql :schema-version 1
                      (language java (call :callee (name "eval"))))
                    :dangerous-operand (argument :index 0) :accepts [untrusted])]))
              :classification (classification
                :fallback (classification-id :taxonomy "Test" :id "BROAD-TAINT")))"#,
        )];
        let options =
            PolicyEvaluationOptions::new(PolicyEvaluationDate::from_ymd(2026, 9, 3).unwrap());
        let outcome = service
            .evaluate_policy_inputs(&root, &input, &options, &Default::default())
            .unwrap();
        assert_eq!(
            outcome.taint_findings().len(),
            1,
            "{:?}",
            outcome.report().diagnostics()
        );
        let taint_ref = crate::rql::TaintResultRef::new("test", "registered").unwrap();
        service
            .register_query_taint_outcome(taint_ref, &outcome)
            .unwrap();
        let answer = service
            .call_tool_value(
                "query_code",
                json!({
                    "schema_version": 1,
                    "match": {"kind": "method", "name": "unsafe"},
                    "steps": [
                        {"op": "procedure_of"},
                        {"op": "taint", "taint_ref": "test:registered"}
                    ]
                }),
            )
            .unwrap();
        assert_eq!(
            answer["results"].as_array().map(Vec::len),
            Some(1),
            "{answer}"
        );
        assert_eq!(answer["results"][0]["result_type"], "taint_finding");
    }

    #[test]
    fn query_code_projects_registered_composed_output_rows() {
        // Rust sinks in a blob with rows select the composition engine, so
        // the outcome carries Output rows and no live ICFG analysis. The
        // workspace is written here because this test ships with the public
        // crate and must not read the private root fixture corpus.
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        std::fs::create_dir(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/main.rs"),
            r#"mod apis {
    pub fn query_value(key: &str) -> &'static str {
        ""
    }

    pub fn execute(sql: &str) {}
}

use crate::apis::{execute, query_value};

fn search(term: &str) {
    execute(term);
}

pub fn handle() {
    search(query_value("q"));
}
"#,
        )
        .unwrap();
        let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        let input = [PolicyEvaluationInput::embedded(
            crate::policy::PolicySourceIdentity::new("test:composed-output.rqlp"),
            r#"(policy
              :schema-version 1
              :id "test.composed.output"
              :name "Composed output"
              :message "request value reaches execute"
              :severity warning
              :analysis (analysis
                :type taint
                :mode may
                :call-modeling (call-modeling :unmodeled require-model)
                :sources (endpoint-set :entries [
                  (source :id request :display-name "request value" :categories [input.user]
                    :selector (rql :schema-version 1
                      (language rust
                        (call-sites-to :proof proven
                          (enclosing-decl
                            (inside-decl (module :name "apis") (function :name "query_value"))))))
                    :bind return-value :labels [untrusted])])
                :sinks (endpoint-set :entries [
                  (sink :id execute :display-name "SQL execute" :categories [sql.structure]
                    :selector (rql :schema-version 1
                      (language rust
                        (call-sites-to :proof proven
                          (enclosing-decl
                            (inside-decl (module :name "apis") (function :name "execute"))))))
                    :dangerous-operand (argument :index 0) :accepts [untrusted])]))
              :classification (classification
                :fallback (classification-id :taxonomy "Test" :id "COMPOSED-OUTPUT")))"#,
        )];
        let options =
            PolicyEvaluationOptions::new(PolicyEvaluationDate::from_ymd(2026, 9, 16).unwrap());
        let outcome = service
            .evaluate_policy_inputs(&root, &input, &options, &Default::default())
            .unwrap();
        assert!(!outcome.taint_output_rows().is_empty());
        assert!(outcome.taint_analysis_results().is_empty());
        let taint_ref = crate::rql::TaintResultRef::new("test", "composed").unwrap();
        service
            .register_query_taint_outcome(taint_ref, &outcome)
            .unwrap();
        let answer = service
            .call_tool_value(
                "query_code",
                json!({
                    "schema_version": 1,
                    "languages": ["rust"],
                    "match": {"kind": "function", "name": "search"},
                    "steps": [
                        {"op": "procedure_of"},
                        {"op": "taint", "taint_ref": "test:composed"}
                    ]
                }),
            )
            .unwrap();
        assert_eq!(
            answer["results"].as_array().map(Vec::len),
            Some(1),
            "{answer}"
        );
        assert_eq!(answer["results"][0]["result_type"], "taint_finding");
    }

    /// A composed Output result that lists a budget-stopped anchor answers a
    /// query as incomplete with the budget cause, instead of reporting the
    /// findings it has as the whole answer (#10403).
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10403: a query over a result with a budget-stopped unit reported success without that unit's flows"
    )]
    fn query_code_reports_a_budget_stopped_output_anchor_as_incomplete() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        std::fs::create_dir(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/main.rs"),
            "mod apis {\n    pub fn query_value(key: &str) -> &'static str {\n        \"\"\n    }\n\n    pub fn execute(sql: &str) {}\n}\n\nuse crate::apis::{execute, query_value};\n\nfn search(term: &str) {\n    execute(term);\n}\n\npub fn handle() {\n    search(query_value(\"q\"));\n}\n",
        )
        .unwrap();
        let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        let input = [PolicyEvaluationInput::embedded(
            crate::policy::PolicySourceIdentity::new("test:stopped-output.rqlp"),
            r#"(policy
              :schema-version 1
              :id "test.stopped.output"
              :name "Stopped output"
              :message "request value reaches execute"
              :severity warning
              :analysis (analysis
                :type taint
                :mode may
                :call-modeling (call-modeling :unmodeled require-model)
                :sources (endpoint-set :entries [
                  (source :id request :display-name "request value" :categories [input.user]
                    :selector (rql :schema-version 1
                      (language rust
                        (call-sites-to :proof proven
                          (enclosing-decl
                            (inside-decl (module :name "apis") (function :name "query_value"))))))
                    :bind return-value :labels [untrusted])])
                :sinks (endpoint-set :entries [
                  (sink :id execute :display-name "SQL execute" :categories [sql.structure]
                    :selector (rql :schema-version 1
                      (language rust
                        (call-sites-to :proof proven
                          (enclosing-decl
                            (inside-decl (module :name "apis") (function :name "execute"))))))
                    :dangerous-operand (argument :index 0) :accepts [untrusted])]))
              :classification (classification
                :fallback (classification-id :taxonomy "Test" :id "STOPPED-OUTPUT")))"#,
        )];
        let options =
            PolicyEvaluationOptions::new(PolicyEvaluationDate::from_ymd(2026, 11, 7).unwrap());
        let outcome = service
            .evaluate_policy_inputs(&root, &input, &options, &Default::default())
            .unwrap();
        let query = json!({
            "schema_version": 1,
            "languages": ["rust"],
            "match": {"kind": "function", "name": "search"},
            "steps": [
                {"op": "procedure_of"},
                {"op": "taint", "taint_ref": "test:stopped"}
            ]
        });
        // The same registered rows answer completely when no anchor is stopped.
        let rows = outcome.taint_output_rows().to_vec();
        assert!(rows.iter().all(|output| output.budget_stops.is_empty()));
        service
            .register_query_taint_results_with_output(
                crate::rql::TaintResultRef::new("test", "stopped").unwrap(),
                Vec::new(),
                rows.clone(),
            )
            .unwrap();
        let complete = service
            .call_tool_value("query_code", query.clone())
            .unwrap();
        assert_eq!(
            complete["results"].as_array().map(Vec::len),
            Some(1),
            "{complete}"
        );
        let incomplete = |answer: &serde_json::Value| {
            answer["diagnostics"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|diagnostic| diagnostic["impact"] == "incomplete")
        };
        assert!(!incomplete(&complete), "{complete}");
        assert!(
            !complete.to_string().contains("budget"),
            "no stop is reported: {complete}"
        );

        // List the anchor as stopped by each budget in turn: the answer is
        // incomplete and says which limit stopped it and where.
        use crate::rql::TaintBudgetStopLane as Lane;
        for (lane, code, limit, consequence) in [
            (
                Lane::Semantic,
                "semantic_budget_exhausted",
                "semantic budget",
                "not in this result",
            ),
            (
                Lane::CompositionProcedures,
                "semantic_analysis_partial",
                "taint composition procedure limit",
                "not in this result",
            ),
            (
                Lane::CompositionHops,
                "semantic_analysis_partial",
                "taint composition hop limit",
                "not in this result",
            ),
            (
                Lane::CompositionCallersPerProcedure,
                "semantic_analysis_partial",
                "taint composition callers-per-procedure limit",
                "not in this result",
            ),
            // The limits on the rows themselves: a row that omitted findings or
            // truncated a witness is a partial finding set, never a complete one.
            (
                Lane::FindingLimit,
                "taint_finding_truncated",
                "taint finding limit",
                "lacks the omitted findings",
            ),
            (
                Lane::WitnessLimit,
                "taint_finding_truncated",
                "taint witness and attribution limit",
                "witnesses or attribution of those anchors are partial",
            ),
            (
                Lane::BarrierUndecided,
                "semantic_analysis_partial",
                "taint barrier check limit",
                "barrier decisions of those anchors are incomplete",
            ),
            // A provider failure is not a budget: it has its own code and cause,
            // names the failure and tells the user nothing about a limit to raise.
            (
                Lane::ProviderFailed,
                "semantic_provider_failed",
                "semantic provider",
                "workspace snapshot changed",
            ),
        ] {
            let mut stopped = rows.clone();
            let anchor = stopped[0].rows[0].anchor.clone();
            let detail = if lane == Lane::ProviderFailed {
                "semantic provider unavailable: workspace snapshot changed".to_owned()
            } else {
                String::new()
            };
            stopped[0].budget_stops = vec![crate::rql::TaintBudgetStop {
                anchor,
                lane,
                detail,
            }];
            let name = format!("stopped_{lane:?}").to_lowercase();
            service
                .register_query_taint_results_with_output(
                    crate::rql::TaintResultRef::new("test", &name).unwrap(),
                    Vec::new(),
                    stopped,
                )
                .unwrap();
            let mut stopped_query = query.clone();
            stopped_query["steps"][1]["taint_ref"] = json!(format!("test:{name}"));
            let answer = service
                .call_tool_value("query_code", stopped_query)
                .unwrap();
            let text = answer.to_string();
            assert!(text.contains(code), "{lane:?}: {answer}");
            assert!(text.contains(limit), "{lane:?}: {answer}");
            assert!(text.contains("src/main.rs@"), "{lane:?}: {answer}");
            assert!(
                text.contains(consequence),
                "{lane:?}: the answer says what may be missing: {answer}"
            );
            assert!(
                incomplete(&answer),
                "{lane:?}: the answer is incomplete: {answer}"
            );
            // The other codes are not used for this lane.
            for other in [
                "semantic_budget_exhausted",
                "semantic_analysis_partial",
                "taint_finding_truncated",
                "semantic_provider_failed",
            ] {
                assert_eq!(text.contains(other), other == code, "{lane:?}: {answer}");
            }
        }
    }

    /// A malformed pin is a stated parameter error, never a silent no-op.
    #[test]
    fn explain_policy_rejects_a_malformed_workspace_generation() {
        let (_temp, service) = service();
        let error = service
            .call_tool_value(
                "explain_policy",
                json!({
                    "policy_files": ["policies/match.rqlp"],
                    "candidate": { "path": "Widget.java", "byte_start": 0 },
                    "workspace_generation": "not-a-generation"
                }),
            )
            .expect_err("a malformed generation is refused");
        assert!(
            error.message.contains("workspace_generation"),
            "{}",
            error.message
        );
    }

    /// Determinism on the wire: two calls over one immutable snapshot
    /// serialize byte-identically.
    #[test]
    fn explain_policy_is_deterministic_across_calls() {
        let (_temp, service) = service();
        let arguments = json!({
            "policy_files": ["policies/match.rqlp"],
            "candidate": { "path": "Widget.java", "byte_start": byte_offset("render") }
        });
        let first = service
            .call_tool_value("explain_policy", arguments.clone())
            .expect("first answer");
        let second = service
            .call_tool_value("explain_policy", arguments)
            .expect("second answer");
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
    }
}
pub(crate) struct PreparedRunPolicy {
    sources: Vec<String>,
    workspace_generation: u64,
    snapshot: WorkspaceQueryScope,
    root: PathBuf,
    policy_inputs: Vec<PolicyEvaluationInput>,
    options: PolicyEvaluationOptions,
    selection_elapsed: Duration,
    suppression_preflight: Option<crate::policy::PolicySuppressionPreflight>,
    suppression_preflight_elapsed: Duration,
    snapshot_elapsed: Duration,
    include_stage_timings: bool,
}

struct RunPolicySnapshotPreparation {
    sources: Vec<String>,
    policy_inputs: Vec<PolicyEvaluationInput>,
    selected_policy_ids: Vec<PolicyId>,
    options: PolicyEvaluationOptions,
    suppression_preflight: crate::policy::PolicySuppressionPreflight,
    selection_elapsed: Duration,
    suppression_preflight_elapsed: Duration,
    snapshot_started: Instant,
    include_stage_timings: bool,
}

pub(crate) enum RunPolicyPreparation {
    Ready(Box<PreparedRunPolicy>),
    PreflightFailure(Box<RunPolicyToolResult>),
    // Boxed: the ready payload is a slim handle while the deadline payload
    // carries a whole report document.
    Deadline(Box<RunPolicyToolResult>),
}

impl WorkspaceQueryScope {
    fn new(
        source_snapshot: Arc<WorkspaceAnalyzer>,
        document_root: Arc<WorkspaceRoot>,
        pack_activation: SessionPackActivation,
    ) -> Self {
        let context = Arc::new(crate::analyzer::AnalyzerQueryContext::root());
        Self::with_context(source_snapshot, document_root, pack_activation, context)
    }

    fn with_context(
        source_snapshot: Arc<WorkspaceAnalyzer>,
        document_root: Arc<WorkspaceRoot>,
        pack_activation: SessionPackActivation,
        context: Arc<crate::analyzer::AnalyzerQueryContext>,
    ) -> Self {
        let snapshot = Arc::new(source_snapshot.as_ref().clone());
        {
            let _attribution = context.enter();
            snapshot.begin_query(&context);
        }
        Self {
            source_snapshot,
            snapshot,
            document_root,
            pack_activation,
            context,
        }
    }

    /// Enter on the worker executing this operation. The retained handle can
    /// cross threads; only this entered view exposes analyzer operations.
    fn enter(&self) -> WorkspaceQueryEntry<'_> {
        WorkspaceQueryEntry {
            scope: self,
            _attribution: self.context.enter(),
        }
    }

    fn has_source(&self, source: &Arc<WorkspaceAnalyzer>) -> bool {
        Arc::ptr_eq(&self.source_snapshot, source)
    }

    fn scope_snapshot(&self, source_snapshot: Arc<WorkspaceAnalyzer>) -> Self {
        // Activation metadata must describe the replacement analyzer's owner,
        // rather than a settled publication from the previous generation.
        let pack_activation = match source_snapshot.analyzer().semantic_model_overlay_read() {
            crate::analyzer::semantic_model::SemanticModelOverlayRead::Pending(_) => {
                SessionPackActivation::WarmPending
            }
            _ => self.pack_activation.clone(),
        };
        Self::with_context(
            source_snapshot,
            Arc::clone(&self.document_root),
            pack_activation,
            Arc::clone(&self.context),
        )
    }

    fn document_root(&self) -> &WorkspaceRoot {
        &self.document_root
    }

    fn finish<T>(
        self,
        operation: &str,
        result: Result<T, SearchToolsServiceError>,
    ) -> Result<T, SearchToolsServiceError> {
        match result {
            Err(error) => Err(error),
            Ok(value) => match self.context.unacknowledged_store_error() {
                Some(error) => {
                    let message =
                        format!("Analyzer store failure while running `{operation}`: {error}");
                    if error.is_stale_generation() {
                        Err(SearchToolsServiceError::stale_analyzer_generation(message))
                    } else {
                        Err(SearchToolsServiceError::internal(message))
                    }
                }
                None => Ok(value),
            },
        }
    }
}

struct WorkspaceQueryEntry<'a> {
    scope: &'a WorkspaceQueryScope,
    _attribution: crate::analyzer::i_analyzer::ReadAttributionGuard,
}

impl Deref for WorkspaceQueryEntry<'_> {
    type Target = WorkspaceAnalyzer;

    fn deref(&self) -> &Self::Target {
        self.scope.snapshot.as_ref()
    }
}

impl Drop for WorkspaceQueryScope {
    fn drop(&mut self) {
        self.snapshot.end_query(&self.context);
    }
}

/// Attach the session's pack-activation marker to a `query_code` response:
/// acquisition still pending (issue #3401), or activation settled with a
/// stated failure (#10002).
///
/// A failed activation publishes no models at all, so one rejected workspace
/// model also removes the dependency and intrinsic models every other answer
/// relied on. Without this marker those answers read `unknown` with nothing
/// naming the cause; the failure was visible only in `get_active_workspace`.
///
/// The marker fires exactly when the answer could have used the packs the
/// session is still acquiring: the decoded plan may depend on semantic packs, and
/// the query's selected languages -- or the workspace's, when the query does
/// not select -- must intersect the languages the pending acquisitions serve.
/// A `WarmPending` snapshot has the same dependency requirement because a query
/// that cannot consume semantic packs also cannot gain rows when the warm's
/// state is unknown. The diagnostic's impact is `incomplete`, so the
/// envelope's own completion derives `incomplete`: an answer produced without
/// the packs it could have used is never reported as complete. After the
/// diagnostic lands, the flow-status cap re-derives so no retained flow row
/// presents a clean complete negative under it.
fn mark_pack_activation_incomplete(
    pack_activation: &SessionPackActivation,
    query: &crate::rql::CodeQuery,
    query_languages: Option<&Value>,
    workspace_languages: &std::collections::BTreeSet<Language>,
    response: &mut crate::rql::CodeQueryResponse,
) {
    if !query.may_use_semantic_packs() {
        return;
    }
    let (code, message) = match pack_activation {
        SessionPackActivation::Settled(state) => {
            let Some(failure) = state.as_ref().and_then(|state| state.failure.as_ref()) else {
                return;
            };
            (
                crate::rql::CodeQueryDiagnosticCode::SemanticPackActivationFailed,
                format!(
                    "semantic-pack activation failed, so this answer can be missing rows or \
                     read unknown wherever it needed a semantic model, including models \
                     unrelated to the failure: {failure}"
                ),
            )
        }
        SessionPackActivation::AcquisitionPending(state)
        | SessionPackActivation::ConfiguredPending(state)
            if state.shipped_pack_acquisition_pending.is_some() =>
        {
            // The shipped release covers every workspace language, so no
            // language selection escapes it.
            (
                crate::rql::CodeQueryDiagnosticCode::SemanticPackAcquisitionPending,
                format!(
                    "the host is still acquiring its shipped semantic packs ({}), so this \
                     answer used no semantic packs and may be missing every row they add; \
                     get_active_workspace reports semantic_packs_ready when the set is final",
                    state
                        .shipped_pack_acquisition_pending
                        .as_deref()
                        .expect("the guard requires a pending shipped-pack acquisition")
                ),
            )
        }
        SessionPackActivation::AcquisitionPending(state)
        | SessionPackActivation::ConfiguredPending(state) => {
            let selected: Vec<Language> = match query_languages {
                Some(Value::Array(labels)) => labels
                    .iter()
                    .filter_map(Value::as_str)
                    .filter_map(Language::from_config_label)
                    .collect(),
                _ => workspace_languages.iter().copied().collect(),
            };
            if selected.is_empty()
                || !state.pending_acquisitions.iter().any(|pending| {
                    pending
                        .ecosystem
                        .languages()
                        .iter()
                        .any(|language| selected.contains(language))
                })
            {
                return;
            }
            (
                crate::rql::CodeQueryDiagnosticCode::SemanticPackAcquisitionPending,
                pack_acquisition_pending_message(&state.pending_acquisitions),
            )
        }
        SessionPackActivation::Failed(cause) => (
            crate::rql::CodeQueryDiagnosticCode::SemanticPackActivationFailed,
            format!(
                "semantic-pack activation failed, so this answer may be missing semantic models: {cause}"
            ),
        ),
        SessionPackActivation::WarmPending => (
            crate::rql::CodeQueryDiagnosticCode::SemanticPackAcquisitionPending,
            "the session's semantic-pack warm has not published its installed stage and this \
             request did not wait for it, so this answer may be missing every row semantic \
             packs would add; get_active_workspace reports semantic_packs_ready when \
             activation settles"
                .to_owned(),
        ),
    };
    let Some(result) = response.result_mut() else {
        return;
    };
    result
        .diagnostics
        .push(crate::rql::CodeQueryDiagnostic::new(
            crate::rql::CodeQueryDiagnostic {
                has_non_utf8_refusal: false,
                refusal_sites: Default::default(),
                call_relation_facts: None,
                uses_omissions: Vec::new(),
                incompleteness: brokk_bifrost_rql::Incompleteness::Operational(
                    brokk_bifrost_rql::DiagnosticExecutionCause::Provider,
                ),
                related: Vec::new(),
                source: None,
                code,
                impact: crate::rql::CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: "workspace",
                message,
                exhausted_roots: Vec::new(),
                withheld_rows_path: None,
                step_index: None,
                step_op: None,
                no_rows_reason: None,
                cause_codes: Vec::new(),
            },
        ));
    result.cap_flow_status_by_run();
}

/// Warn a `query_code` caller that the workspace's reviewed models were not
/// loaded (#8304).
///
/// `SearchToolsService` sessions register `.bifrost/semantic-models/` only when
/// `BIFROST_WORKSPACE_SEMANTIC_MODELS` is on, while CLI policy runs always read
/// it. Without this marker, a query over a modeled member answered `unknown`
/// with nothing saying a model sat unloaded beside it. An explicit `off` is a
/// stated choice and stays quiet. The impact is advisory: the session is
/// working as configured, and the opt-out must not mark every answer
/// incomplete.
fn mark_workspace_semantic_models_not_loaded(
    workspace_root: &Path,
    query: &crate::rql::CodeQuery,
    response: &mut crate::rql::CodeQueryResponse,
) {
    if !query.may_use_semantic_packs()
        || std::env::var_os(WORKSPACE_SEMANTIC_MODELS_ENV).is_some()
        || std::fs::symlink_metadata(
            workspace_root
                .join(crate::analyzer::semantic_model::WORKSPACE_SEMANTIC_MODEL_DIRECTORY),
        )
        .is_err()
    {
        return;
    }
    let Some(result) = response.result_mut() else {
        return;
    };
    result
        .diagnostics
        .push(crate::rql::CodeQueryDiagnostic::new(
            crate::rql::CodeQueryDiagnostic {
                has_non_utf8_refusal: false,
                refusal_sites: Default::default(),
                call_relation_facts: None,
                uses_omissions: Vec::new(),
                incompleteness: brokk_bifrost_rql::Incompleteness::Content,
                related: Vec::new(),
                source: None,
                code: crate::rql::CodeQueryDiagnosticCode::WorkspaceSemanticModelsNotLoaded,
                impact: crate::rql::CodeQueryDiagnosticImpact::Advisory,
                branch: Vec::new(),
                language: "workspace",
                message: format!(
                    "{dir}/ exists, but this session did not load it because \
                     {WORKSPACE_SEMANTIC_MODELS_ENV} is unset; answers that need those models \
                     can be missing or unknown. Set {WORKSPACE_SEMANTIC_MODELS_ENV}=on to load \
                     them or =off to silence this warning. Policy runs load {dir}/ either way.",
                    dir = crate::analyzer::semantic_model::WORKSPACE_SEMANTIC_MODEL_DIRECTORY,
                ),
                exhausted_roots: Vec::new(),
                withheld_rows_path: None,
                step_index: None,
                step_op: None,
                no_rows_reason: None,
                cause_codes: Vec::new(),
            },
        ));
}

/// The pending-state message: which ecosystems still owe acquisitions, the
/// dependencies behind them, and what the answer's reader should do about it.
fn pack_acquisition_pending_message(
    pending: &[crate::analyzer::semantic_model::PendingDependencyPackAcquisition],
) -> String {
    const MAX_NAMED_DEPENDENCIES: usize = 5;
    let mut ecosystems: Vec<&'static str> = pending
        .iter()
        .map(|entry| entry.ecosystem.label())
        .collect();
    ecosystems.sort_unstable();
    ecosystems.dedup();
    let mut message = format!(
        "semantic-pack acquisition is still running for {}",
        ecosystems.join(", ")
    );
    let named: Vec<&str> = pending
        .iter()
        .take(MAX_NAMED_DEPENDENCIES)
        .map(|entry| entry.dependency_id.as_str())
        .collect();
    if pending.len() > MAX_NAMED_DEPENDENCIES {
        message.push_str(&format!(
            " ({} and {} more)",
            named.join(", "),
            pending.len() - named.len()
        ));
    } else if !named.is_empty() {
        message.push_str(&format!(" ({})", named.join(", ")));
    }
    message.push_str(
        "; this answer used only the packs already installed in the workspace catalog and may \
         be missing rows those packs add; get_active_workspace reports semantic_packs_ready \
         when the set is final",
    );
    message
}

#[cfg(test)]
mod pack_acquisition_pending_tests {
    use super::*;
    use serde_json::json;

    fn pending_state(entries: &[(&str, &str)]) -> Arc<WorkspacePackActivationState> {
        Arc::new(WorkspacePackActivationState {
            update_source: None,
            config: None,
            ecosystems: Vec::new(),
            failure: None,
            overlay: SemanticModelOverlayStatus::NoModels,
            pending_acquisitions: entries
                .iter()
                .map(|(ecosystem, dependency_id)| {
                    crate::analyzer::semantic_model::PendingDependencyPackAcquisition {
                        ecosystem: crate::analyzer::DependencyPackEcosystem::from_label(ecosystem)
                            .expect("a known ecosystem label"),
                        dependency_id: (*dependency_id).to_owned(),
                    }
                })
                .collect(),
            shipped_pack_acquisition_pending: None,
            coverage: None,
        })
    }

    fn marked_codes(
        response: &crate::rql::CodeQueryResponse,
    ) -> Vec<crate::rql::CodeQueryDiagnosticCode> {
        response
            .result()
            .map(|result| {
                result
                    .diagnostics
                    .iter()
                    .map(|diagnostic| diagnostic.code())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn mark(
        pack_activation: &SessionPackActivation,
        query_languages: Option<&Value>,
        workspace_languages: &[Language],
        query: &crate::rql::CodeQuery,
    ) -> crate::rql::CodeQueryResponse {
        let mut response =
            crate::rql::CodeQueryResponse::Results(crate::rql::CodeQueryResult::default());
        mark_pack_activation_incomplete(
            pack_activation,
            query,
            query_languages,
            &workspace_languages.iter().copied().collect(),
            &mut response,
        );
        response
    }

    fn parsed_query(query: serde_json::Value) -> crate::rql::CodeQuery {
        crate::rql::CodeQuery::from_json(&query).expect("a valid pending-marker query")
    }

    fn gson_class_selector() -> Value {
        json!({
            "languages": ["java"],
            "where": ["Gson.java"],
            "match": { "kind": "class", "name": "Gson" }
        })
    }

    fn gson_class_query(steps: Value) -> Value {
        let mut query = gson_class_selector();
        query["steps"] = steps;
        query
    }

    fn pure_structural_query() -> crate::rql::CodeQuery {
        parsed_query(gson_class_selector())
    }

    fn semantic_query() -> crate::rql::CodeQuery {
        parsed_query(gson_class_query(json!([{ "op": "procedure_of" }])))
    }

    fn nested_pure_query() -> crate::rql::CodeQuery {
        let query = gson_class_query(json!([{ "op": "file_of" }]));
        parsed_query(json!({ "union": [query.clone(), query] }))
    }

    fn nested_semantic_query() -> crate::rql::CodeQuery {
        let query = gson_class_query(json!([{ "op": "procedure_of" }]));
        parsed_query(json!({ "union": [query.clone(), query] }))
    }

    fn nested_mixed_query() -> crate::rql::CodeQuery {
        parsed_query(json!({
            "union": [
                gson_class_query(json!([{ "op": "file_of" }])),
                gson_class_query(json!([{ "op": "enclosing_decl" }, { "op": "file_of" }]))
            ]
        }))
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3433: Issue #3433 fixed a semantic query over a pending language losing its typed pending state"
    )]
    fn a_semantic_query_over_a_pending_language_carries_the_typed_pending_state() {
        let phase = SessionPackActivation::AcquisitionPending(pending_state(&[
            ("jvm", "jdk:25.0.4.1"),
            ("npm", "lodash"),
        ]));
        let response = mark(
            &phase,
            Some(&json!(["java"])),
            &[Language::Java, Language::JavaScript],
            &semantic_query(),
        );
        let result = response.result().expect("results response");
        let diagnostic = result
            .diagnostics
            .iter()
            .find(|diagnostic| {
                diagnostic.code()
                    == crate::rql::CodeQueryDiagnosticCode::SemanticPackAcquisitionPending
            })
            .expect("the pending acquisition must be named: {result:?}");
        assert_eq!(
            diagnostic.impact(),
            crate::rql::CodeQueryDiagnosticImpact::Incomplete
        );
        assert_eq!(diagnostic.language(), "workspace");
        assert!(
            diagnostic.message().contains("jvm")
                && diagnostic.message().contains("jdk:25.0.4.1")
                && diagnostic.message().contains("npm")
                && diagnostic.message().contains("lodash"),
            "the message names the pending ecosystems and dependencies: {}",
            diagnostic.message()
        );
        assert_eq!(
            result.completion(),
            crate::rql::CodeQueryCompletion::Incomplete {
                codes: vec![crate::rql::CodeQueryDiagnosticCode::SemanticPackAcquisitionPending],
            },
            "an answer produced without the packs it could have used is never complete"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3433: model-dependent near misses including unscoped enclosing_decl lost pending coverage"
    )]
    fn model_dependent_near_misses_keep_pending_coverage() {
        let queries = [
            json!({"languages": ["java"], "match": {"kind": "class", "name": "External"}}),
            json!({"languages": ["java"], "match": {"kind": "class", "name": "External"},
                "steps": [{"op": "enclosing_decl"}]}),
            json!({"languages": ["java"], "match": {"kind": "class", "name": "Gson"},
                "steps": [{"op": "enclosing_decl"}]}),
            json!({"languages": ["java"], "where": ["App.java"],
                "match": {"kind": "call", "callee": {"name": "trim"}}}),
            json!({"languages": ["java"], "where": ["App.java"],
                "match": {"kind": "call", "receiver": {"name": "value"}}}),
            json!({"languages": ["java"], "where": ["App.java"],
                "match": {"kind": "class", "name": "App"},
                "steps": [{"op": "enclosing_decl"}, {"op": "members"}]}),
            json!({"union": [
                {"languages": ["java"], "where": ["App.java"],
                    "match": {"kind": "class", "name": "App"}},
                {"languages": ["java"], "match": {"kind": "class", "name": "External"}}
            ]}),
        ];
        let phase = SessionPackActivation::AcquisitionPending(pending_state(&[("jvm", "jdk")]));
        for json in queries {
            let query = parsed_query(json.clone());
            let response = mark(&phase, Some(&json!(["java"])), &[Language::Java], &query);
            assert!(
                marked_codes(&response)
                    .contains(&crate::rql::CodeQueryDiagnosticCode::SemanticPackAcquisitionPending),
                "model-dependent query lost its coverage marker: {json}"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3433: Issue #3433 fixed file-scoped callee and receiver constraints being treated as a workspace-wide semantic query"
    )]
    fn file_scoped_callee_and_receiver_constraints_remain_conservative() {
        let phase = SessionPackActivation::AcquisitionPending(pending_state(&[("jvm", "jdk")]));
        for query in [
            parsed_query(json!({
                "languages": ["java"],
                "where": ["Gson.java"],
                "match": { "kind": "call", "callee": { "name": "trim" } }
            })),
            parsed_query(json!({
                "languages": ["java"],
                "where": ["Gson.java"],
                "match": { "kind": "call", "receiver": { "name": "service" } }
            })),
        ] {
            let response = mark(&phase, Some(&json!(["java"])), &[Language::Java], &query);
            assert!(
                marked_codes(&response)
                    .contains(&crate::rql::CodeQueryDiagnosticCode::SemanticPackAcquisitionPending),
                "a file-scoped role constraint remains conservatively pending"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3433: Issue #3433 fixed file and import-graph steps losing scoped pending state"
    )]
    fn file_and_import_graph_steps_are_safe_for_scoped_declarations() {
        let phase = SessionPackActivation::AcquisitionPending(pending_state(&[("jvm", "jdk")]));
        let query = parsed_query(json!({
            "languages": ["java"],
            "where": ["Gson.java"],
            "match": { "kind": "class", "name": "Gson" },
            "steps": [
                { "op": "file_of" },
                { "op": "imports_of" },
                { "op": "importers_of" }
            ]
        }));
        let response = mark(&phase, Some(&json!(["java"])), &[Language::Java], &query);
        assert!(marked_codes(&response).is_empty());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3433: Issue #3433 fixed an unsupported step falsely discharging pending semantic coverage"
    )]
    fn disallowed_steps_remain_pending() {
        let phase = SessionPackActivation::AcquisitionPending(pending_state(&[("jvm", "jdk")]));
        for step in [
            json!({ "op": "enclosing_decl" }),
            json!({ "op": "procedure_of" }),
        ] {
            let query = parsed_query(json!({
                "languages": ["java"],
                "where": ["Gson.java"],
                "match": { "kind": "class", "name": "Gson" },
                "steps": [step]
            }));
            let response = mark(&phase, Some(&json!(["java"])), &[Language::Java], &query);
            assert!(
                marked_codes(&response)
                    .contains(&crate::rql::CodeQueryDiagnosticCode::SemanticPackAcquisitionPending),
                "non-structural step remains conservatively pending"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3433: Issue #3433 fixed one disallowed nested semantic branch failing to mark the combined query pending"
    )]
    fn a_mixed_nested_query_marks_when_one_branch_is_disallowed() {
        let phase = SessionPackActivation::AcquisitionPending(pending_state(&[("jvm", "jdk")]));
        let response = mark(
            &phase,
            Some(&json!(["java"])),
            &[Language::Java],
            &nested_mixed_query(),
        );
        assert!(
            marked_codes(&response)
                .contains(&crate::rql::CodeQueryDiagnosticCode::SemanticPackAcquisitionPending)
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3433: Issue #3433 fixed a semantic query in a language outside the pending set being marked pending"
    )]
    fn a_semantic_query_outside_the_pending_languages_is_unmarked() {
        let phase = SessionPackActivation::AcquisitionPending(pending_state(&[("jvm", "jdk:25")]));
        let response = mark(
            &phase,
            Some(&json!(["rust"])),
            &[Language::Java, Language::Rust],
            &semantic_query(),
        );
        assert!(
            !marked_codes(&response)
                .contains(&crate::rql::CodeQueryDiagnosticCode::SemanticPackAcquisitionPending),
            "a rust-only query cannot have used the pending jdk pack"
        );

        // The same holds for an unfiltered query on a workspace with no
        // pending language.
        let response = mark(&phase, None, &[Language::Rust], &semantic_query());
        assert!(marked_codes(&response).is_empty());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3433: Issue #3433 fixed an unfiltered semantic query ignoring a pending language present in the workspace"
    )]
    fn an_unfiltered_semantic_query_marks_when_the_workspace_uses_a_pending_language() {
        let phase = SessionPackActivation::AcquisitionPending(pending_state(&[("npm", "lodash")]));
        let response = mark(
            &phase,
            None,
            &[Language::JavaScript, Language::Rust],
            &semantic_query(),
        );
        assert!(
            marked_codes(&response)
                .contains(&crate::rql::CodeQueryDiagnosticCode::SemanticPackAcquisitionPending)
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3433: Issue #3433 fixed nested pure structural branches inheriting unrelated pending model state"
    )]
    fn nested_pure_structural_branches_do_not_mark() {
        let phase = SessionPackActivation::AcquisitionPending(pending_state(&[("jvm", "jdk")]));
        let response = mark(
            &phase,
            Some(&json!(["java"])),
            &[Language::Java],
            &nested_pure_query(),
        );
        assert!(marked_codes(&response).is_empty());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3433: Issue #3433 fixed nested semantic branches losing the typed pending state"
    )]
    fn a_nested_semantic_branch_carries_the_typed_pending_state() {
        let phase = SessionPackActivation::AcquisitionPending(pending_state(&[("jvm", "jdk")]));
        let response = mark(
            &phase,
            Some(&json!(["java"])),
            &[Language::Java],
            &nested_semantic_query(),
        );
        assert!(
            marked_codes(&response)
                .contains(&crate::rql::CodeQueryDiagnosticCode::SemanticPackAcquisitionPending)
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3433: pending semantic queries were unmarked or pure structural queries were marked"
    )]
    fn pending_semantic_queries_are_marked_while_pure_queries_are_unmarked() {
        let response = mark(
            &SessionPackActivation::WarmPending,
            Some(&json!(["rust"])),
            &[Language::Rust],
            &semantic_query(),
        );
        assert!(
            marked_codes(&response)
                .contains(&crate::rql::CodeQueryDiagnosticCode::SemanticPackAcquisitionPending),
            "an answer whose pack state is unknown is never reported as complete"
        );

        let pure = mark(
            &SessionPackActivation::WarmPending,
            Some(&json!(["rust"])),
            &[Language::Rust],
            &pure_structural_query(),
        );
        assert!(marked_codes(&pure).is_empty());

        let acquisition_pure = mark(
            &SessionPackActivation::AcquisitionPending(pending_state(&[("jvm", "jdk")])),
            Some(&json!(["java"])),
            &[Language::Java],
            &pure_structural_query(),
        );
        assert!(marked_codes(&acquisition_pure).is_empty());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3372: settled semantic-pack activation still marked query results incomplete"
    )]
    fn a_settled_session_never_marks() {
        let settled = mark(
            &SessionPackActivation::Settled(None),
            Some(&json!(["java"])),
            &[Language::Java],
            &semantic_query(),
        );
        assert!(marked_codes(&settled).is_empty());
    }
}

enum ObservedSource {
    Present(String),
    Missing,
}

fn classify_source_read(
    file: &ProjectFile,
    result: io::Result<String>,
) -> Result<ObservedSource, SearchToolsServiceError> {
    match result {
        Ok(source) => Ok(ObservedSource::Present(source)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(ObservedSource::Missing),
        Err(err) => Err(SearchToolsServiceError::internal(format!(
            "Failed to verify source freshness for {}: {err}",
            file.rel_path().display()
        ))),
    }
}

fn stale_symbol_source_files(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    candidate_files: BTreeSet<ProjectFile>,
) -> Result<BTreeSet<ProjectFile>, SearchToolsServiceError> {
    candidate_files
        .into_iter()
        .filter_map(|file| {
            let current = analyzer.project().read_source(&file);
            match classify_source_read(&file, current) {
                Ok(ObservedSource::Present(current))
                    if analyzer.indexed_source_matches(&file, &current) =>
                {
                    None
                }
                Ok(_) => Some(Ok(file)),
                Err(err) => Some(Err(err)),
            }
        })
        .collect()
}

impl WorkspaceSession {
    /// The pack activation as a query snapshot observes it: the settled exact
    /// state, the installed stage the expensive warm still supplements, or a
    /// warm that has not published even its installed stage (issue #3401).
    fn pack_activation(&self) -> SessionPackActivation {
        if self.refresh != PackRefresh::Idle {
            return SessionPackActivation::WarmPending;
        }
        let phase = self.semantic_packs.snapshot_phase();
        if matches!(phase, SessionPackActivation::WarmPending) {
            return phase;
        }
        // A request answers under its snapshot's activation only when the
        // pinned release coverage still reaches that snapshot's own demand
        // (#6397). A miss is transient: the snapshot moved while a warm ran.
        // Query acquisition settles the refresh before cloning its scope;
        // status polling may still report pending until activation publishes.
        let covered = self.semantic_packs.best_known_state().is_none_or(|state| {
            state
                .coverage
                .as_ref()
                .is_none_or(|pinned| pinned.covers(&self.snapshot, state.config.as_deref()))
        });
        if covered {
            phase
        } else {
            SessionPackActivation::WarmPending
        }
    }

    /// Whether the snapshot's pack demand moved past its activation: the kept
    /// ecosystems changed, or its demand escaped the pinned release coverage
    /// (#6397).
    fn pack_activation_scope_changed(&self) -> bool {
        self.semantic_packs
            .best_known_state()
            .as_ref()
            .is_some_and(|state| {
                workspace_pack_ecosystems(&self.snapshot, state.config.as_deref())
                    != state.ecosystems
                    || state.coverage.as_ref().is_some_and(|pinned| {
                        !pinned.covers(&self.snapshot, state.config.as_deref())
                    })
            })
    }

    fn refresh_updated_contexts(
        &self,
        changed_files: &BTreeSet<ProjectFile>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), SearchToolsServiceError> {
        brokk_bifrost_analysis::analyzer::without_project_reads(|| {
            let uncancelled = CancellationToken::default();
            self.snapshot
                .refresh_updated_workspace_contexts(
                    changed_files,
                    &crate::analyzer::semantic_model::DependencyPackLimits::default(),
                    cancellation.unwrap_or(&uncancelled),
                )
                .map_err(|error| SearchToolsServiceError::internal(error.to_string()))
        })
    }

    /// Re-run activation after dependency inputs, the workspace pack document
    /// or the pack scope change. Invalidation happens first so a failed
    /// replacement cannot leave proof from an older workspace generation.
    ///
    /// A running warm is superseded by invalidation, but remains the only
    /// worker until it exits. The next query starts one warm for the latest
    /// snapshot; no superseded installed-stage result may be published.
    fn refresh_pack_activation(&mut self) {
        brokk_bifrost_analysis::analyzer::without_project_reads(|| {
            self.semantic_packs.search_warm_cancellation.cancel();
            self.snapshot
                .invalidate_dependency_pack_state(&crate::analyzer::DependencyPackEcosystem::ALL);
            if !self.semantic_packs.reap_finished_worker() {
                self.refresh = PackRefresh::DeferredWhole;
                return;
            }
            self.refresh = PackRefresh::Idle;
            let root = self.snapshot.analyzer().project().root().to_path_buf();
            let replacement = SemanticPackWarm::spawn(root, Arc::clone(&self.snapshot))
                .unwrap_or_else(|error| {
                    Arc::new(SemanticPackWarm::settled(Some(Arc::new(
                        WorkspacePackActivationState::unavailable(None, Vec::new(), error),
                    ))))
                });
            self.semantic_packs = replacement;
            self.retired_pack_warms
                .retain(|warm| !warm.reap_finished_worker());
        })
    }

    fn refresh_dependency_ecosystems(
        &mut self,
        ecosystems: &[crate::analyzer::DependencyPackEcosystem],
    ) {
        if ecosystems.is_empty() {
            return;
        }
        brokk_bifrost_analysis::analyzer::without_project_reads(|| {
            self.semantic_packs.search_warm_cancellation.cancel();
            self.snapshot.invalidate_dependency_pack_state(ecosystems);
            if !self.semantic_packs.reap_finished_worker() {
                if self.refresh == PackRefresh::Idle {
                    self.refresh = PackRefresh::DeferredEcosystems;
                }
                return;
            }
            self.refresh = PackRefresh::Idle;
            let root = self.snapshot.analyzer().project().root().to_path_buf();
            self.semantic_packs = SemanticPackWarm::spawn_selected(
                root,
                Arc::clone(&self.snapshot),
                ecosystems.to_vec(),
            )
            .unwrap_or_else(|error| {
                Arc::new(SemanticPackWarm::settled(Some(Arc::new(
                    WorkspacePackActivationState::unavailable(None, Vec::new(), error),
                ))))
            });
            self.retired_pack_warms
                .retain(|warm| !warm.reap_finished_worker());
        });
    }

    fn settle_pack_stage(&mut self, semantic_packs: &Arc<SemanticPackWarm>) {
        if !Arc::ptr_eq(&self.semantic_packs, semantic_packs) {
            return;
        }
        if self.refresh != PackRefresh::Idle {
            if semantic_packs.reap_finished_worker() {
                if self.refresh == PackRefresh::DeferredWhole
                    || self.snapshot.requires_whole_dependency_refresh()
                {
                    self.refresh_pack_activation();
                } else {
                    let stale = self.snapshot.stale_dependency_ecosystems();
                    if stale.is_empty() {
                        self.refresh = PackRefresh::Idle;
                    } else {
                        self.refresh_dependency_ecosystems(&stale);
                    }
                }
            }
            return;
        }
        if let Some((source, activated)) = semantic_packs
            .installed_snapshot
            .lock()
            .expect("semantic-pack snapshot mutex poisoned")
            .take()
        {
            if source.ptr_eq(&Arc::downgrade(&self.snapshot)) {
                self.snapshot = activated;
            } else if self.pack_activation_scope_changed()
                || self.snapshot.requires_whole_dependency_refresh()
            {
                self.refresh_pack_activation();
            } else {
                let stale = self.snapshot.stale_dependency_ecosystems();
                self.refresh_dependency_ecosystems(&stale);
            }
        }
    }

    /// Queue a background warm of the current snapshot's lazy query indexes.
    /// Free when the snapshot is already warm (incremental updates whose
    /// sources were unchanged share the previous generation's indexes).
    fn schedule_index_warm(&self) {
        self.index_warmer.schedule(Arc::clone(&self.snapshot));
    }

    /// Whether a caller can ask a usage question without waiting behind the
    /// startup warm.
    ///
    /// A session with no startup warm is ready by construction: `OnDemand`
    /// leaves the build to the first query that needs it, under the same memo,
    /// so nothing is outstanding. A session that started one is ready once that
    /// thread has finished. This is what `get_active_workspace` reports as
    /// `usage_index_ready`.
    fn usage_index_ready(&self) -> bool {
        self.usage_index_warm
            .as_ref()
            .is_none_or(JoinHandle::is_finished)
    }
}

/// A directory event can name only the directory, so a change refreshes the
/// global pack inputs when it equals, contains or lies inside the packs
/// document or the workspace model directory. The relation is the one the
/// publication carry proof uses; a spelling it cannot certify leaves the
/// overlay Pending there, and the Pending branch of `apply_changed_files`
/// refreshes the activation.
fn changed_files_refresh_global_pack_inputs(changed_files: &BTreeSet<ProjectFile>) -> bool {
    let changed = brokk_bifrost_core::analyzer::changed_paths::ChangedPaths::literal(
        changed_files.iter().map(ProjectFile::rel_path),
    );
    changed.touches(Path::new(WORKSPACE_PACKS_DOCUMENT_PATH))
        || changed.touches(Path::new(
            crate::analyzer::semantic_model::WORKSPACE_SEMANTIC_MODEL_DIRECTORY,
        ))
        || changed_files.iter().any(|file| {
            matches!(
                file.rel_path().to_str(),
                Some(".nvmrc" | ".node-version" | "package.json")
            )
        })
}

#[cfg(test)]
mod release_coverage_tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::packs_document::CoveredRelease;
    use brokk_bifrost_test_macros::hardwon;
    use serde_json::json;

    static BOOTSTRAPS: Mutex<Vec<ReleaseCoverage>> = Mutex::new(Vec::new());

    fn recording_bootstrap(
        _catalog: &SemanticPackCatalog,
        coverage: &ReleaseCoverage,
    ) -> Result<Vec<crate::analyzer::semantic_model::CatalogLeaseToken>, String> {
        BOOTSTRAPS.lock().unwrap().push(coverage.clone());
        Ok(Vec::new())
    }

    fn workspace_with(files: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        for (name, text) in files {
            std::fs::write(root.join(name), text).unwrap();
        }
        (temp, root)
    }

    fn pinned(service: &SearchToolsService) -> PinnedPackCoverage {
        let guard = service.session.read().unwrap();
        let session = guard.as_ref().unwrap();
        // The synchronous constructors already ran the ordinary activation
        // route eagerly. Read the coverage it pinned instead of running a
        // second full activation per workspace: six catalog opens and SQLite
        // initializations made this test a load multiplier (#14097).
        session
            .semantic_packs
            .best_known_state()
            .and_then(|state| state.coverage.clone())
            .expect("the ordinary route pins its release coverage")
    }

    fn languages(coverage: &ReleaseCoverage) -> BTreeSet<String> {
        match coverage {
            ReleaseCoverage::Covered(CoveredRelease { languages, .. }) => languages.clone(),
            ReleaseCoverage::WholeRelease => panic!("expected a scoped coverage"),
        }
    }

    /// One test, because the bootstrap hook is installed once per process.
    #[test]
    fn activation_pins_the_release_coverage_it_bootstraps_with() {
        install_semantic_model_catalog_bootstrap(recording_bootstrap).unwrap();

        let (_java, root) = workspace_with(&[("A.java", "class A {}\n")]);
        let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        let java = pinned(&service);
        assert!(
            BOOTSTRAPS.lock().unwrap().contains(&java.coverage),
            "bootstrap received a different coverage than activation pinned: {java:?}"
        );
        let java_languages = languages(&java.coverage);
        assert!(java_languages.contains("java"), "{java_languages:?}");
        assert!(!java_languages.contains("python"), "{java_languages:?}");

        let (_both, root) = workspace_with(&[("A.java", "class A {}\n"), ("b.py", "x = 1\n")]);
        let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        let grown = pinned(&service);
        let grown_languages = languages(&grown.coverage);
        assert!(
            java_languages.is_subset(&grown_languages),
            "{grown_languages:?}"
        );
        assert!(grown_languages.contains("python"), "{grown_languages:?}");
        assert!(grown.coverage.contains(&java.coverage));

        // A --sources file set has no authoritative language set.
        let scoped = crate::scoped_project::create_scoped_service(
            root.clone(),
            &["A.java".to_owned()],
            None,
        )
        .unwrap();
        assert_eq!(pinned(&scoped).coverage, ReleaseCoverage::WholeRelease);
    }

    #[test]
    #[hardwon(
        "#6397: a language outside a narrowed packs document escaped the pinned release coverage without a refresh"
    )]
    fn a_new_language_under_a_narrowed_packs_document_refreshes_its_coverage() {
        let (_temp, root) = workspace_with(&[("A.java", "class A {}\n")]);
        std::fs::create_dir_all(root.join(".bifrost")).unwrap();
        std::fs::write(
            root.join(".bifrost/packs.json"),
            r#"{ "schema_version": 1, "ecosystems": ["jvm"] }"#,
        )
        .unwrap();
        let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        // C++ adds an intrinsic (cpp, language) pair while the kept ecosystems
        // stay [jvm].
        std::fs::write(root.join("b.cpp"), "int f() { return 1; }\n").unwrap();
        service
            .call_tool_value("update_paths", json!({"paths": ["b.cpp"]}))
            .unwrap();
        service.snapshot_for_query_with_cancellation(None).unwrap();
        let guard = service.session.read().unwrap();
        let session = guard.as_ref().unwrap();
        session.semantic_packs.wait();
        let pinned = session
            .semantic_packs
            .best_known_state()
            .and_then(|state| state.coverage.clone())
            .expect("the refreshed activation pins its coverage");
        assert!(
            pinned.coverage.covers_entry("cpp", "language"),
            "{pinned:?}"
        );
        assert!(matches!(
            session.pack_activation(),
            SessionPackActivation::Settled(_)
        ));
    }

    fn session_pinned_to(languages: &[&str]) -> (tempfile::TempDir, SearchToolsService) {
        let (temp, root) = workspace_with(&[("A.java", "class A {}\n")]);
        let service = SearchToolsService::new_manual_ephemeral(root).unwrap();
        {
            let guard = service.session.read().unwrap();
            let session = guard.as_ref().unwrap();
            session
                .semantic_packs
                .publish_final(Some(Arc::new(WorkspacePackActivationState {
                    update_source: None,
                    config: None,
                    ecosystems: Vec::new(),
                    failure: None,
                    overlay: SemanticModelOverlayStatus::NoModels,
                    pending_acquisitions: Vec::new(),
                    shipped_pack_acquisition_pending: None,
                    coverage: Some(PinnedPackCoverage {
                        coverage: ReleaseCoverage::Covered(CoveredRelease {
                            languages: languages
                                .iter()
                                .map(|&language| language.to_owned())
                                .collect(),
                            ..CoveredRelease::default()
                        }),
                        evidence: Vec::new(),
                    }),
                })));
        }
        (temp, service)
    }

    fn activation(service: &SearchToolsService) -> SessionPackActivation {
        service
            .session
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .pack_activation()
    }

    #[test]
    fn a_snapshot_inside_its_pinned_coverage_is_ready() {
        let (_temp, service) = session_pinned_to(&["java", "kotlin", "scala"]);
        assert!(matches!(
            activation(&service),
            SessionPackActivation::Settled(_)
        ));
    }

    #[test]
    fn a_snapshot_outside_its_pinned_coverage_is_not_ready() {
        let (_temp, service) = session_pinned_to(&["python"]);
        assert!(matches!(
            activation(&service),
            SessionPackActivation::WarmPending
        ));
    }
}

#[cfg(test)]
mod pack_input_change_tests {
    use super::*;
    use serde_json::json;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12435: malformed packs configuration blocked source updates before activation could report it"
    )]
    fn malformed_packs_document_does_not_block_source_updates() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        std::fs::write(root.join("app.ts"), "export const value = 1;\n").unwrap();
        let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        std::fs::create_dir_all(root.join(".bifrost")).unwrap();
        std::fs::write(root.join(".bifrost/packs.json"), "{").unwrap();
        for value in [2, 3] {
            let source = format!("export const value = {value};\n");
            std::fs::write(root.join("app.ts"), &source).unwrap();
            service
                .call_tool_value(
                    "update_paths",
                    json!({"paths": ["app.ts", ".bifrost/packs.json"]}),
                )
                .unwrap();
            let guard = service.session.read().unwrap();
            assert!(
                guard
                    .as_ref()
                    .unwrap()
                    .snapshot
                    .analyzer()
                    .indexed_source_matches(&ProjectFile::new(root.clone(), "app.ts"), &source,)
            );
        }
    }

    fn mixed_dependency_workspace() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("workspace");
        std::fs::create_dir_all(root.join("src")).unwrap();
        let root = root.canonicalize().unwrap().normalize();
        git2::Repository::init(&root).unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub fn value() -> i32 { 1 }\n").unwrap();
        write_cargo_version(&root, "0.1.0");
        std::fs::write(root.join("app.ts"), "export const value = 1;\n").unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"example","version":"1.0.0"}"#,
        )
        .unwrap();
        (temp, root)
    }

    fn write_cargo_version(root: &Path, version: &str) {
        std::fs::write(
            root.join("Cargo.toml"),
            format!("[package]\nname = \"example\"\nversion = \"{version}\"\n"),
        )
        .unwrap();
    }

    fn dependency_proof(
        service: &SearchToolsService,
        language: Language,
    ) -> Arc<crate::analyzer::semantic_model::DependencyDiscoveryEvidence> {
        service.snapshot_for_query_with_cancellation(None).unwrap();
        let guard = service.session.read().unwrap();
        guard
            .as_ref()
            .unwrap()
            .snapshot
            .analyzer()
            .dependency_discovery_evidence(language)
            .expect("ecosystem proof")
    }

    fn assert_dependency_evidence_matches_cold(service: &SearchToolsService, root: &Path) {
        let cold = SearchToolsService::new_manual_ephemeral(root.to_path_buf()).unwrap();
        cold.snapshot_for_query_with_cancellation(None).unwrap();
        let cold_guard = cold.session.read().unwrap();
        let warm_guard = service.session.read().unwrap();
        let cold_request = cold_guard
            .as_ref()
            .unwrap()
            .snapshot
            .carried_activation_request()
            .unwrap();
        let warm_request = warm_guard
            .as_ref()
            .unwrap()
            .snapshot
            .carried_activation_request()
            .unwrap();
        assert_eq!(warm_request.evidence, cold_request.evidence);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9840: a refresh scoped to one ecosystem must not erase its siblings"
    )]
    fn cargo_refresh_carries_npm() {
        let (_temp, root) = mixed_dependency_workspace();
        brokk_bifrost_core::analyzer::project::age_ignore_test_inputs(&root);
        let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        let npm = dependency_proof(&service, Language::TypeScript);
        let cargo = dependency_proof(&service, Language::Rust);
        for version in ["0.2.0", "0.3.0"] {
            write_cargo_version(&root, version);
            service
                .call_tool_value("update_paths", json!({"paths": ["Cargo.toml"]}))
                .unwrap();
            assert!(Arc::ptr_eq(
                &npm,
                &dependency_proof(&service, Language::TypeScript)
            ));
            assert!(!Arc::ptr_eq(
                &cargo,
                &dependency_proof(&service, Language::Rust)
            ));
        }
        assert_dependency_evidence_matches_cold(&service, &root);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#14051: unrelated source membership invalidated npm discovery"
    )]
    fn cargo_refresh_carries_npm_across_rust_membership() {
        let (_temp, root) = mixed_dependency_workspace();
        brokk_bifrost_core::analyzer::project::age_ignore_test_inputs(&root);
        let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        let npm = dependency_proof(&service, Language::TypeScript);
        write_cargo_version(&root, "0.2.0");
        std::fs::create_dir(root.join("src/new_mod")).unwrap();
        std::fs::write(root.join("src/new_mod/lib.rs"), "pub fn added() {}\n").unwrap();
        std::thread::sleep(Duration::from_millis(2100));
        service
            .call_tool_value(
                "update_paths",
                json!({"paths": ["Cargo.toml", "src/new_mod/lib.rs"]}),
            )
            .unwrap();
        assert!(Arc::ptr_eq(
            &npm,
            &dependency_proof(&service, Language::TypeScript)
        ));
        // Its receipt still names the original inventory after this carry.
        write_cargo_version(&root, "0.3.0");
        service
            .call_tool_value("update_paths", json!({"paths": ["Cargo.toml"]}))
            .unwrap();
        assert!(Arc::ptr_eq(
            &npm,
            &dependency_proof(&service, Language::TypeScript)
        ));
        assert_dependency_evidence_matches_cold(&service, &root);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#14051: npm membership beneath Rust directories must invalidate scoped discovery"
    )]
    fn npm_membership_changes_replace_dependency_proof() {
        let (_temp, root) = mixed_dependency_workspace();
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"example","workspaces":["src/*"]}"#,
        )
        .unwrap();
        std::fs::create_dir(root.join("src/base")).unwrap();
        std::fs::write(root.join("src/base/package.json"), r#"{"name":"base"}"#).unwrap();
        std::fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\nimporters:\n  src/base: {}\n  src/new_mod:\n    dependencies:\n      lodash: {specifier: 1.0.0, version: 1.0.0}\npackages:\n  lodash@1.0.0: {}\nsnapshots:\n  lodash@1.0.0: {}\n",
        )
        .unwrap();
        brokk_bifrost_core::analyzer::project::age_ignore_test_inputs(&root);
        let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        let before = dependency_proof(&service, Language::TypeScript);
        assert!(!before.declares_module_path("lodash"), "{before:?}");
        std::fs::create_dir(root.join("src/new_mod")).unwrap();
        std::fs::write(
            root.join("src/new_mod/package.json"),
            r#"{"name":"new-member","dependencies":{"lodash":"1.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(root.join("src/new_mod/lib.rs"), "pub fn added() {}\n").unwrap();
        std::thread::sleep(Duration::from_millis(2100));
        service
            .call_tool_value("update_paths", json!({"paths": ["src/new_mod"]}))
            .unwrap();
        let added = dependency_proof(&service, Language::TypeScript);
        assert!(!Arc::ptr_eq(&before, &added));
        assert!(added.declares_module_path("lodash"), "{added:?}");
        assert_dependency_evidence_matches_cold(&service, &root);
        std::fs::remove_dir_all(root.join("src/new_mod")).unwrap();
        service
            .call_tool_value("update_paths", json!({"paths": ["src/new_mod"]}))
            .unwrap();
        let removed = dependency_proof(&service, Language::TypeScript);
        assert!(!Arc::ptr_eq(&added, &removed));
        assert!(!removed.declares_module_path("lodash"), "{removed:?}");
        assert_dependency_evidence_matches_cold(&service, &root);

        // Alternate lockfiles are inputs even though dependency_inputs lists
        // only the npm filenames used by the host's direct refresh routing.
        std::fs::remove_file(root.join("pnpm-lock.yaml")).unwrap();
        service
            .call_tool_value("update_paths", json!({"paths": ["pnpm-lock.yaml"]}))
            .unwrap();
        for (name, contents) in [
            (
                "pnpm-lock.yaml",
                "lockfileVersion: '9.0'\nimporters: {}\npackages: {}\nsnapshots: {}\n",
            ),
            ("yarn.lock", "__metadata:\n  version: 8\n"),
        ] {
            let before = dependency_proof(&service, Language::TypeScript);
            std::fs::write(root.join(name), contents).unwrap();
            std::thread::sleep(Duration::from_millis(2100));
            service
                .call_tool_value("update_paths", json!({"paths": [name]}))
                .unwrap();
            assert!(
                !Arc::ptr_eq(&before, &dependency_proof(&service, Language::TypeScript)),
                "{name}"
            );
            assert_dependency_evidence_matches_cold(&service, &root);
        }
    }

    #[test]
    fn unrelated_edit_carries_ecosystems_without_worker() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub fn value() -> i32 { 1 }\n").unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"example\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(root.join("app.ts"), "export const value = 1;\n").unwrap();
        std::fs::write(
            root.join("package.json"),
            "{\"name\":\"example\",\"version\":\"1.0.0\"}",
        )
        .unwrap();
        let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        let proof = |language| {
            service.snapshot_for_query_with_cancellation(None).unwrap();
            let guard = service.session.read().unwrap();
            guard
                .as_ref()
                .unwrap()
                .snapshot
                .analyzer()
                .dependency_discovery_evidence(language)
                .expect("ecosystem proof")
        };
        let npm = proof(Language::TypeScript);
        let cargo = proof(Language::Rust);
        std::fs::write(root.join("src/lib.rs"), "pub fn value() -> i32 { 2 }\n").unwrap();
        let before_worker = {
            let guard = service.session.read().unwrap();
            Arc::clone(&guard.as_ref().unwrap().semantic_packs)
        };
        service
            .call_tool_value("update_paths", json!({"paths": ["src/lib.rs"]}))
            .unwrap();
        let after_worker = {
            let guard = service.session.read().unwrap();
            Arc::clone(&guard.as_ref().unwrap().semantic_packs)
        };
        assert!(Arc::ptr_eq(&before_worker, &after_worker));
        assert!(Arc::ptr_eq(&npm, &proof(Language::TypeScript)));
        assert!(Arc::ptr_eq(&cargo, &proof(Language::Rust)));
    }

    #[test]
    fn superseded_scoped_stage_cannot_replace_current_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        std::fs::write(root.join("app.ts"), "export const value = 1;\n").unwrap();
        let service = SearchToolsService::new_manual_ephemeral(root).unwrap();
        let mut guard = service.session.write().unwrap();
        let session = guard.as_mut().unwrap();
        let obsolete = Arc::clone(&session.snapshot);
        let current = Arc::new(obsolete.as_ref().clone());
        session.snapshot = Arc::clone(&current);
        let warm = Arc::new(SemanticPackWarm::settled(None));
        *warm.installed_snapshot.lock().unwrap() = Some((Arc::downgrade(&obsolete), obsolete));
        session.semantic_packs = Arc::clone(&warm);
        session.settle_pack_stage(&warm);
        assert!(Arc::ptr_eq(&session.snapshot, &current));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#14051: real npm edits batched with unrelated Rust membership must replace discovery"
    )]
    fn package_manifest_edit_replaces_dependency_proof() {
        let (_temp, root) = mixed_dependency_workspace();
        std::fs::write(
            root.join("app.ts"),
            "import { x } from 'lodash';\nexport { x };\n",
        )
        .unwrap();
        for name in ["lodash", "underscore"] {
            std::fs::create_dir_all(root.join("node_modules").join(name)).unwrap();
            std::fs::write(
                root.join("node_modules").join(name).join("package.json"),
                format!(r#"{{"name":"{name}","version":"1.0.0","main":"index.js"}}"#),
            )
            .unwrap();
            std::fs::write(
                root.join("node_modules").join(name).join("index.js"),
                "module.exports = {};\n",
            )
            .unwrap();
            std::fs::write(
                root.join("node_modules").join(name).join("index.d.ts"),
                "export declare const x: number;\n",
            )
            .unwrap();
        }
        let manifest = |name: &str| {
            format!(r#"{{"name":"app","version":"1.0.0","dependencies":{{"{name}":"1.0.0"}}}}"#)
        };
        let lock = |name: &str| {
            format!(
                r#"{{"name":"app","version":"1.0.0","lockfileVersion":3,"packages":{{"":{{"name":"app","version":"1.0.0","dependencies":{{"{name}":"1.0.0"}}}},"node_modules/{name}":{{"version":"1.0.0"}}}}}}"#
            )
        };
        std::fs::write(root.join("package.json"), manifest("lodash")).unwrap();
        std::fs::write(root.join("package-lock.json"), lock("lodash")).unwrap();
        brokk_bifrost_core::analyzer::project::age_ignore_test_inputs(&root);
        let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        let evidence = || {
            // A pack refresh publishes through the next query's settle, and the
            // dependency proof through the warm's final stage (#6397).
            service.snapshot_for_query_with_cancellation(None).unwrap();
            service
                .session
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .semantic_packs
                .wait();
            let guard = service.session.read().unwrap();
            guard
                .as_ref()
                .unwrap()
                .snapshot
                .analyzer()
                .dependency_discovery_evidence(Language::TypeScript)
        };
        let before = evidence().expect("initial npm dependency proof is published");
        assert!(before.declares_module_path("lodash"), "{before:?}");
        std::fs::write(root.join("package.json"), manifest("underscore")).unwrap();
        std::fs::write(root.join("package-lock.json"), lock("underscore")).unwrap();
        write_cargo_version(&root, "0.2.0");
        std::fs::create_dir(root.join("src/new_mod")).unwrap();
        std::fs::write(root.join("src/new_mod/lib.rs"), "pub fn added() {}\n").unwrap();
        std::thread::sleep(Duration::from_millis(2100));
        service
            .call_tool_value(
                "update_paths",
                json!({"paths": ["package.json", "package-lock.json", "Cargo.toml", "src/new_mod/lib.rs"]}),
            )
            .expect("refresh dependency inputs");
        let after = evidence().expect("edited npm dependency proof is published");
        assert!(!Arc::ptr_eq(&before, &after));
        assert_dependency_evidence_matches_cold(&service, &root);
        assert!(after.declares_module_path("underscore"), "{after:?}");
        assert!(!after.declares_module_path("lodash"), "{after:?}");
        std::fs::create_dir_all(root.join(".bifrost")).unwrap();
        std::fs::write(root.join(".bifrost/packs.json"), "{").unwrap();
        service
            .call_tool_value("update_paths", json!({"paths": [".bifrost/packs.json"]}))
            .expect("publish failed replacement activation");
        assert!(
            evidence().is_none(),
            "failed replacement must withdraw the prior dependency proof: {:?}",
            evidence()
        );
    }

    #[test]
    fn new_language_refreshes_settled_pack_scope() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        std::fs::write(root.join("app.js"), "const value = 1;\n").unwrap();
        let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        let ecosystems = || {
            // A pack refresh publishes through the next query's settle (#6397).
            service.snapshot_for_query_with_cancellation(None).unwrap();
            service
                .session
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .semantic_packs
                .wait();
            let guard = service.session.read().unwrap();
            guard
                .as_ref()
                .unwrap()
                .semantic_packs
                .best_known_state()
                .expect("settled pack activation has a scope")
                .ecosystems
                .clone()
        };
        assert!(ecosystems().contains(&crate::analyzer::DependencyPackEcosystem::Npm));
        std::fs::write(root.join("app.py"), "value = 1\n").unwrap();
        service
            .call_tool_value("update_paths", json!({"paths": ["app.py"]}))
            .expect("publish new language");
        assert!(
            ecosystems().contains(&crate::analyzer::DependencyPackEcosystem::Python),
            "the activated pack scope must include the newly introduced language"
        );
    }

    /// `Cargo.lock` and `rust-toolchain.toml` reach Rust analysis only through
    /// dependency and standard-library packs, so this refresh is what keeps
    /// them current: the Rust delegate is not routed either file (#3756).
    /// `.cargo/config.toml` is the reverse: the Rust delegate reads it for crate
    /// cfg sets and routes, and pack discovery does not (#3768).
    #[test]
    fn rust_pack_inputs_use_scoped_refresh() {
        let root = std::env::temp_dir();
        let refreshes = |path: &str| {
            changed_files_refresh_global_pack_inputs(&BTreeSet::from([ProjectFile::new(
                root.clone(),
                path,
            )]))
        };
        assert!(!refreshes("Cargo.lock"));
        assert!(!refreshes("rust-toolchain.toml"));
        assert!(!refreshes("crates/member/Cargo.toml"));
        assert!(!refreshes(".cargo/config.toml"));
        assert!(!refreshes("src/lib.rs"));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12435: a directory event or a case alias of the packs document or model directory skipped the global pack refresh"
    )]
    fn directory_and_alias_events_refresh_global_pack_inputs() {
        let root = std::env::temp_dir();
        let refreshes = |path: &str| {
            changed_files_refresh_global_pack_inputs(&BTreeSet::from([ProjectFile::new(
                root.clone(),
                path,
            )]))
        };
        for path in [
            ".bifrost",
            ".bifrost/packs.json",
            ".bifrost/semantic-models",
            ".bifrost/semantic-models/pack.json",
            ".BIFROST/PACKS.JSON",
            ".Bifrost/Semantic-Models/pack.json",
        ] {
            assert!(refreshes(path), "{path}");
        }
        for path in [".bifrost2", ".bifrost2/packs.json", "bifrost/packs.json"] {
            assert!(!refreshes(path), "{path}");
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6397: Node declaration edits left the published pack activation stale"
    )]
    fn node_runtime_declarations_invalidate_pack_activation() {
        let root = std::env::temp_dir();
        for path in [".nvmrc", ".node-version", "package.json"] {
            assert!(
                changed_files_refresh_global_pack_inputs(&BTreeSet::from([ProjectFile::new(
                    root.clone(),
                    path
                ),])),
                "{path}"
            );
        }
    }
}

/// Like the semantic-pack worker, this dispatcher runs on a named thread.
/// The bounded channel keeps request callbacks free of workspace locks.
fn install_toolchain_wake(
    shared: &Arc<RwLock<Option<WorkspaceSession>>>,
    session: &WorkspaceSession,
) {
    let Some(store) = session.snapshot.store() else {
        return;
    };
    let records = Arc::downgrade(&store.toolchain_verifications());
    let callback_records = records.clone();
    let document_root = Arc::downgrade(&session.document_root);
    let shared = Arc::downgrade(shared);
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name("bifrost-jvm-refresh".into())
        .spawn(move || {
            loop {
                match receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(()) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if document_root.strong_count() == 0 {
                            break;
                        }
                        continue;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
                let Some(records) = records.upgrade() else {
                    break;
                };
                struct Finished(
                    Arc<brokk_bifrost_core::analyzer::external_selection::ToolchainVerifications>,
                );
                impl Drop for Finished {
                    fn drop(&mut self) {
                        self.0.refresh_finished();
                    }
                }
                let _finished = Finished(Arc::clone(&records));
                let mut started = false;
                loop {
                    let Some(shared) = shared.upgrade() else {
                        break;
                    };
                    {
                        let mut guard = shared.write().expect("session lock poisoned");
                        let Some(session) = guard.as_mut() else { break };
                        if !document_root.ptr_eq(&Arc::downgrade(&session.document_root))
                            || !session.snapshot.store().is_some_and(|store| {
                                Arc::ptr_eq(&store.toolchain_verifications(), &records)
                            })
                        {
                            break;
                        }
                        if !started {
                            session.refresh_dependency_ecosystems(&[
                                crate::analyzer::DependencyPackEcosystem::Jvm,
                            ]);
                            started = true;
                        }
                        let warm = Arc::clone(&session.semantic_packs);
                        if warm.reap_finished_worker() {
                            session.settle_pack_stage(&warm);
                            if session.refresh == PackRefresh::Idle
                                && session.semantic_packs.reap_finished_worker()
                            {
                                break;
                            }
                        }
                    }
                    drop(shared);
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        });
    match worker {
        Ok(_) => store
            .toolchain_verifications()
            .set_refresh_callback(Arc::new(move || match sender.try_send(()) {
                Ok(()) | Err(std::sync::mpsc::TrySendError::Full(())) => {}
                Err(std::sync::mpsc::TrySendError::Disconnected(())) => {
                    if let Some(records) = callback_records.upgrade() {
                        records.refresh_finished();
                    }
                    eprintln!("JVM refresh dispatcher disconnected");
                }
            })),
        Err(error) => eprintln!("Failed to spawn JVM refresh dispatcher: {error}"),
    }
}

/// Per binding: the installed session plus one replacement in flight:
/// one serialized replacement decision. A slot is held through actual drain.
#[derive(Default)]
struct WorkspaceLifetimes {
    slots: Mutex<[Weak<WorkspaceLifetime>; 2]>,
}

struct WorkspaceLifetime {
    root: PathBuf,
    generation: u64,
    retiring: std::sync::atomic::AtomicBool,
    phase: Mutex<&'static str>,
    build_cancellation: Mutex<Option<CancellationToken>>,
}

impl WorkspaceLifetimes {
    fn reserve(&self, root: PathBuf, generation: u64) -> Option<Arc<WorkspaceLifetime>> {
        let mut slots = self
            .slots
            .lock()
            .expect("workspace lifetime slots poisoned");
        let slot = slots.iter_mut().find(|slot| slot.strong_count() == 0)?;
        let lifetime = Arc::new(WorkspaceLifetime {
            root,
            generation,
            retiring: std::sync::atomic::AtomicBool::new(false),
            phase: Mutex::new("workspace build"),
            build_cancellation: Mutex::new(None),
        });
        *slot = Arc::downgrade(&lifetime);
        Some(lifetime)
    }

    fn retiring(&self) -> Vec<brokk_bifrost_tools::searchtools::RetiringWorkspace> {
        self.slots
            .lock()
            .expect("workspace lifetime slots poisoned")
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|life| life.retiring.load(Ordering::Acquire))
            .map(|life| life.observation())
            .collect()
    }

    #[cfg(test)]
    fn count(&self) -> usize {
        self.slots
            .lock()
            .unwrap()
            .iter()
            .filter(|slot| slot.strong_count() != 0)
            .count()
    }
}

impl WorkspaceLifetime {
    fn set_phase(&self, phase: &'static str) {
        *self
            .phase
            .lock()
            .expect("workspace lifetime phase poisoned") = phase;
    }

    fn retire(&self) {
        self.retiring.store(true, Ordering::Release);
        if let Some(token) = self
            .build_cancellation
            .lock()
            .expect("workspace build cancellation poisoned")
            .as_ref()
        {
            token.cancel();
        }
    }

    fn observation(&self) -> brokk_bifrost_tools::searchtools::RetiringWorkspace {
        let phase = *self
            .phase
            .lock()
            .expect("workspace lifetime phase poisoned");
        let phase = if phase == "workspace build" {
            self.build_cancellation
                .lock()
                .expect("workspace build cancellation poisoned")
                .as_ref()
                .and_then(CancellationToken::phase)
                .unwrap_or_else(|| phase.to_owned())
        } else {
            phase.to_owned()
        };
        brokk_bifrost_tools::searchtools::RetiringWorkspace {
            root: self.root.display().to_string(),
            generation: self.generation,
            phase,
        }
    }
}

enum RetiredWorkspaceWork {
    Session(Box<WorkspaceSession>),
    Build(PendingWorkspaceBuild),
}

struct RetiredWorkspace {
    lifetime: Arc<WorkspaceLifetime>,
    work: RetiredWorkspaceWork,
}

/// A tracked, ordered teardown worker. The fixed lifetime slots bound its queue,
/// and close/shutdown join it. A work item owns its lease until all warm-owned
/// analyzer clones have drained, not merely until the session is dequeued.
#[derive(Default)]
struct WorkspaceSessionRetirement {
    sender: Option<std::sync::mpsc::Sender<RetiredWorkspace>>,
    worker: Option<JoinHandle<()>>,
    // A failed handoff must retain ownership rather than dropping warm-owned
    // analyzers on the request. Lifetime slots bound this queue to two items.
    pending: std::collections::VecDeque<RetiredWorkspace>,
    #[cfg(test)]
    fail_next_start: bool,
}

impl WorkspaceSessionRetirement {
    fn teardown(RetiredWorkspace { lifetime, work }: RetiredWorkspace) {
        let context = format!(
            "retired workspace {} generation {}",
            lifetime.root.display(),
            lifetime.generation
        );
        if let Err(panic) = crate::panic_report::report_panics(context, || match work {
            RetiredWorkspaceWork::Session(session) => drop(session),
            RetiredWorkspaceWork::Build(handle) => match handle.join() {
                Ok(Ok((_, _, session))) => {
                    session.cancel_warms();
                    drop(session);
                }
                Ok(Err(error)) => eprintln!("Retired workspace build stopped: {error}"),
                Err(panic) => eprintln!("{}", reported_panic("retired workspace build", panic)),
            },
        }) {
            eprintln!("{panic}");
        }
        lifetime.set_phase("releasing workspace resources");
        drop(lifetime);
    }

    // Fallible preparation happens before publishing a replacement or starting
    // its build. Nothing from the preceding binding has moved at this point.
    fn prepare(&mut self) -> Result<(), SearchToolsServiceError> {
        if self.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            drop(self.sender.take());
            if let Err(panic) = self.worker.take().unwrap().join() {
                eprintln!(
                    "{}",
                    reported_panic("workspace session retirement worker", panic)
                );
            }
        }
        if self.worker.is_none() {
            #[cfg(test)]
            if std::mem::take(&mut self.fail_next_start) {
                return Err(SearchToolsServiceError::internal(
                    "injected retirement worker startup failure",
                ));
            }
            let (sender, receiver) = std::sync::mpsc::channel::<RetiredWorkspace>();
            let worker = std::thread::Builder::new()
                .name("bifrost-session-retirement".to_owned())
                .spawn(move || {
                    for retired in receiver {
                        Self::teardown(retired);
                    }
                })
                .map_err(|error| {
                    SearchToolsServiceError::internal(format!(
                        "Failed to start workspace session retirement: {error}"
                    ))
                })?;
            self.sender = Some(sender);
            self.worker = Some(worker);
        }
        while let Some(retired) = self.pending.pop_front() {
            retired.lifetime.set_phase(match &retired.work {
                RetiredWorkspaceWork::Session(_) => "queued session retirement",
                RetiredWorkspaceWork::Build(_) => "workspace build",
            });
            if let Err(error) = self
                .sender
                .as_ref()
                .expect("a retirement worker has a sender")
                .send(retired)
            {
                self.pending.push_front(error.0);
                return Err(SearchToolsServiceError::internal(
                    "Workspace retirement worker stopped before handoff",
                ));
            }
        }
        Ok(())
    }

    // Publication has already succeeded. Handoff failure cannot turn it into
    // an apparent failed activation, or make revocation join old warms inline.
    fn retire(&mut self, retired: RetiredWorkspace) {
        self.pending.push_back(retired);
        if let Err(error) = self.prepare() {
            for retired in &self.pending {
                retired.lifetime.set_phase("waiting for retirement worker");
            }
            eprintln!(
                "{}; retired work retained until retirement retries or close",
                error.message
            );
        }
    }

    fn finish(&mut self) -> Result<(), SearchToolsServiceError> {
        drop(self.sender.take());
        let result = self.worker.take().map_or(Ok(()), |worker| {
            worker.join().map_err(|panic| {
                SearchToolsServiceError::internal(
                    reported_panic("workspace session retirement worker", panic).to_string(),
                )
            })
        });
        // Explicit close/shutdown may drain inline when the OS could not start
        // the worker. Older channel work is joined first to preserve ordering.
        while let Some(retired) = self.pending.pop_front() {
            Self::teardown(retired);
        }
        result
    }
}

impl Drop for WorkspaceSessionRetirement {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            eprintln!("{}", error.message);
        }
    }
}

impl WorkspaceSession {
    fn cancel_warms(&self) {
        self.semantic_packs.search_warm_cancellation.cancel();
        for warm in &self.retired_pack_warms {
            warm.search_warm_cancellation.cancel();
        }
    }
    fn teardown_phase(&self, phase: &'static str) {
        // Index and usage warms cannot yet be cancelled; #13507 tracks that
        // follow-up. Keep naming the phase and holding the slot until they drain.
        if let Some(lifetime) = &self.lifetime {
            lifetime.set_phase(phase);
        }
    }
}

impl Drop for WorkspaceSession {
    fn drop(&mut self) {
        if let Some(store) = self.snapshot.store() {
            store
                .toolchain_verifications()
                .set_refresh_callback(Arc::new(|| {}));
            store.toolchain_verifications().refresh_finished();
        }
        // The warmer owns the snapshot while its thread runs. Wait for it
        // before the session drops the project and its SQLite connections.
        self.cancel_warms();
        self.teardown_phase("index warm");
        self.index_warmer.wait_until_idle();
        self.teardown_phase("activation");
        // Semantic-pack activation owns a cloned analyzer until its worker
        // exits, so joining state publication alone would still let its SQLite
        // handles outlive the session.
        self.semantic_packs.wait_for_worker();
        for warm in &self.retired_pack_warms {
            warm.wait_for_worker();
        }
        self.teardown_phase("usage warm");
        let Some(handle) = self.usage_index_warm.take() else {
            self.teardown_phase("releasing workspace resources");
            return;
        };
        if let Err(panic) = handle.join() {
            // The payload's own `Debug` is `Any { .. }`. A warm that failed
            // leaves its index unpublished and the next query rebuilds it, so
            // this is a diagnostic rather than a request failure -- but it is
            // only a diagnostic if it says what happened.
            eprintln!("{}", reported_panic("usage-index warm thread", panic));
        }
        self.teardown_phase("releasing workspace resources");
    }
}

fn decode_run_policy_arguments(
    arguments: Value,
) -> Result<DecodedRunPolicy, SearchToolsServiceError> {
    let params = serde_json::from_value::<RunPolicyParams>(arguments).map_err(|error| {
        SearchToolsServiceError::invalid_params(format!("Invalid run_policy arguments: {error}"))
    })?;
    let max_policy_files = crate::policy::PolicyBatchBudget::default().max_policies();
    if params.policy_files.len() > max_policy_files {
        return Err(SearchToolsServiceError::invalid_params(format!(
            "run_policy accepts at most {max_policy_files} policy_files entries"
        )));
    }
    for (label, values) in [
        ("policy_packs", &params.policy_packs),
        ("policy_categories", &params.policy_categories),
        ("policy_ids", &params.policy_ids),
    ] {
        if values.len() > max_policy_files {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "run_policy accepts at most {max_policy_files} {label} entries"
            )));
        }
        let mut unique = BTreeSet::new();
        for value in values {
            if value.is_empty() || value.len() > crate::mcp_extended::MAX_RUN_POLICY_SELECTOR_BYTES
            {
                return Err(SearchToolsServiceError::invalid_params(format!(
                    "run_policy {label} entries must contain between 1 and {} bytes",
                    crate::mcp_extended::MAX_RUN_POLICY_SELECTOR_BYTES
                )));
            }
            if !unique.insert(value.as_str()) {
                return Err(SearchToolsServiceError::invalid_params(format!(
                    "run_policy {label} entry `{value}` is duplicated"
                )));
            }
        }
    }
    if params.policy_files.is_empty()
        && params.policy_packs.is_empty()
        && params.policy_categories.is_empty()
        && params.policy_ids.is_empty()
    {
        return Err(SearchToolsServiceError::invalid_params(
            "run_policy requires at least one policy file or built-in selector".to_string(),
        ));
    }

    let mut unique_paths = BTreeSet::new();
    let mut policy_inputs = Vec::with_capacity(params.policy_files.len());
    for raw_path in params.policy_files {
        if raw_path.len() > crate::mcp_extended::MAX_RUN_POLICY_PATH_BYTES {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "run_policy policy path exceeds {} bytes",
                crate::mcp_extended::MAX_RUN_POLICY_PATH_BYTES
            )));
        }
        let path = WorkspaceRelativePath::new(&raw_path).map_err(|error| {
            SearchToolsServiceError::invalid_params(format!(
                "invalid run_policy policy path `{raw_path}`: {error}"
            ))
        })?;
        if Path::new(path.as_str())
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("rqlp")
        {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "run_policy policy path `{}` must use the .rqlp extension",
                path.as_str()
            )));
        }
        if !unique_paths.insert(path.as_str().to_owned()) {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "run_policy policy path `{}` is duplicated",
                path.as_str()
            )));
        }
        policy_inputs.push(PolicyEvaluationInput::workspace_file(path.as_str()));
    }

    let mut selection = BuiltInPolicySelection {
        packs: params.policy_packs,
        categories: params.policy_categories,
        policy_ids: params.policy_ids,
        excluded_policy_ids: Vec::new(),
    };
    let bundle_ids = selection.policy_ids.clone();
    let mut bundle_inputs = policy_bundles()
        .and_then(|bundles| bundles.take_selected(&mut selection))
        .map_err(|error| SearchToolsServiceError::invalid_params(error.to_string()))?;
    let bundle_ids = bundle_ids
        .into_iter()
        .filter(|id| !selection.policy_ids.contains(id))
        .map(|id| PolicyId::new(&id).expect("policy-bundle IDs are validated"))
        .collect::<Vec<_>>();
    let catalog = built_in_policy_catalog().map_err(|error| {
        SearchToolsServiceError::internal(format!(
            "failed to load built-in policy catalog: {error}"
        ))
    })?;
    let selected = catalog
        .select(&selection)
        .map_err(|error| SearchToolsServiceError::invalid_params(error.to_string()))?;
    // A run that selects no built-in policy reads nothing from the catalog,
    // so it reports none of the catalog's rejected packs.
    let builtin_pack_rejections = if selection.is_empty() {
        Vec::new()
    } else {
        catalog.rejection_notices(&selection)
    };
    let mut selected_policy_ids = selected
        .iter()
        .map(|policy| {
            PolicyId::new(&policy.manifest().id).expect("built-in policy IDs are validated")
        })
        .collect::<Vec<_>>();
    selected_policy_ids.extend(bundle_ids);
    let mut built_in_inputs = selected
        .into_iter()
        .map(PolicyEvaluationInput::selected_builtin)
        .collect::<Vec<_>>();
    built_in_inputs.append(&mut bundle_inputs);
    built_in_inputs.append(&mut policy_inputs);
    let policy_inputs = built_in_inputs;
    if policy_inputs.len() > max_policy_files {
        return Err(SearchToolsServiceError::invalid_params(format!(
            "run_policy resolves to {} policies but accepts at most {max_policy_files}",
            policy_inputs.len()
        )));
    }

    let suppressions = params
        .suppression_file
        .map(PolicySuppressionSource::explicit_portable)
        .transpose()
        .map_err(|error| {
            SearchToolsServiceError::invalid_params(format!(
                "invalid run_policy suppression_file: {error}"
            ))
        })?
        .map_or_else(
            PolicySuppressionOptions::default,
            PolicySuppressionOptions::new,
        );
    let scope = params
        .scope_file
        .map(PolicyScopeSource::explicit_portable)
        .transpose()
        .map_err(|error| {
            SearchToolsServiceError::invalid_params(format!(
                "invalid run_policy scope_file: {error}"
            ))
        })?
        .map_or_else(PolicyScopeOptions::default, PolicyScopeOptions::new);
    let baseline = params
        .baseline_file
        .map(PolicyBaselineSource::explicit_portable)
        .transpose()
        .map_err(|error| {
            SearchToolsServiceError::invalid_params(format!(
                "invalid run_policy baseline_file: {error}"
            ))
        })?
        .map_or_else(PolicyBaselineOptions::default, PolicyBaselineOptions::new);
    let fail_on = PolicyFailOn::from(params.fail_on);
    let mut options =
        PolicyEvaluationOptions::with_suppressions(params.evaluation_date, suppressions)
            .with_scope(scope)
            .with_baseline(baseline)
            .with_fail_on(fail_on)
            .with_incremental(params.incremental.unwrap_or(true))
            .with_policy_timings(params.include_stage_timings)
            .with_policy_cost_hints(params.policy_cost_hints)
            .with_policy_deadlines(params.policy_deadlines_ms)
            .with_run_streaming(params.stream_runs)
            .with_builtin_pack_rejections(builtin_pack_rejections);
    if let Some(revision) = params.diff_base {
        if revision.is_empty()
            || revision.len() > crate::mcp_extended::MAX_RUN_POLICY_DIFF_BASE_BYTES
        {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "run_policy diff_base must contain between 1 and {} bytes",
                crate::mcp_extended::MAX_RUN_POLICY_DIFF_BASE_BYTES
            )));
        }
        options = options.with_diff_base(revision);
    }
    if params.diff_scoped {
        if options.diff_base().is_none() {
            return Err(SearchToolsServiceError::invalid_params(
                "run_policy diff_scoped requires diff_base",
            ));
        }
        if !params.incremental.unwrap_or(true) {
            return Err(SearchToolsServiceError::invalid_params(
                "run_policy diff_scoped cannot be combined with incremental: false",
            ));
        }
        options = options.with_range(PolicyRangeRequest::DiffBase);
    }
    Ok(DecodedRunPolicy {
        sources: params.sources,
        inline_suppression_prefix: params.inline_suppression_prefix,
        policy_inputs,
        selected_policy_ids,
        options,
        include_stage_timings: params.include_stage_timings,
    })
}

impl SearchToolsService {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn with_limits(mut self, limits: SemanticModelRuntimeLimits) -> Self {
        self.semantic_model_runtime_limits = limits;
        self
    }

    /// Configure trusted Git objects that immutable `analyze_diff` endpoints
    /// may resolve. This is host configuration, never a tool argument.
    #[must_use]
    pub fn with_diff_snapshot_object_dir(mut self, dir: PathBuf) -> Self {
        self.diff_snapshot_object_dir = Some(dir);
        self
    }

    /// Let `query_code` scale its execution limits to the analyzed source
    /// volume, exactly as policy evaluation does.
    ///
    /// The interactive defaults size one bounded request over an unknown
    /// workspace. A whole-repository question asked by a trusted host -- the
    /// one-shot CLI, or the private correctness corpus -- needs the audited
    /// workspace's own budget instead, or it stops on a limit that describes
    /// the request shape rather than the repository. This is host
    /// configuration, never a tool argument.
    #[must_use]
    pub fn with_workspace_scaled_query_limits(mut self) -> Self {
        self.workspace_scaled_query_limits = true;
        self
    }

    /// The host activation context every analyzer of this service is bound to.
    pub fn host_activation_context(&self) -> &Arc<HostActivationContext> {
        &self.host_activation
    }

    pub fn new(root: PathBuf) -> Result<Self, String> {
        Self::new_with_host_activation_context(root, HostActivationContext::library_none())
    }

    pub fn new_with_host_activation_context(
        root: PathBuf,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        Self::new_with_strategy(root, UpdateStrategy::WatchFiles, host)
    }

    pub fn new_for_python(root: PathBuf) -> Result<Self, String> {
        Self::new_for_python_with_host_activation_context(
            root,
            HostActivationContext::library_none(),
        )
    }

    pub fn new_for_python_with_host_activation_context(
        root: PathBuf,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        Self::new_lazy_with_strategy(root, UpdateStrategy::WatchFiles, host)
    }

    /// Construct with no file watcher and ephemeral analyzer and semantic-pack
    /// caches, for immutable short-lived workspaces such as inline fixtures.
    /// An explicit catalog or cache environment override still opts into
    /// persistence outside this constructor's default.
    ///
    /// Test-only, and gated so it cannot become production API by accident: it
    /// had no production caller, and a service over a live root should build the
    /// persisted cache that [`Self::new_manual_persisted`] gives it. A
    /// `cfg(test)` item is invisible across a crate boundary and the integration
    /// suites under the workspace root need this one, so they reach it through
    /// this crate's `test-support` feature, the same gate `brokk-bifrost-core`
    /// uses for `gitblob::test_repo`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn new_manual_ephemeral(root: PathBuf) -> Result<Self, String> {
        Self::new_manual_ephemeral_with_host_activation_context(
            root,
            HostActivationContext::library_none(),
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn new_manual_ephemeral_with_host_activation_context(
        root: PathBuf,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        Self::new_ephemeral_with_strategy(root, UpdateStrategy::Manual, host)
    }

    /// Construct with persisted analyzer storage and no watcher. The caller
    /// publishes changes explicitly through `update_paths`.
    pub fn new_manual_persisted(root: PathBuf) -> Result<Self, String> {
        Self::new_manual_persisted_with_host_activation_context(
            root,
            HostActivationContext::library_none(),
        )
    }

    pub fn new_manual_persisted_with_host_activation_context(
        root: PathBuf,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        Self::new_with_strategy(root, UpdateStrategy::Manual, host)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn score_diff_target_build_count_for_test(&self) -> usize {
        self.diff_scoring.target_build_count_for_test()
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn score_diff_reference_scan_count_for_test(&self) -> usize {
        self.diff_scoring.reference_scan_count_for_test()
    }

    /// Whether a tool's answer is a pure function of its Git endpoints and
    /// never reads the live workspace analyzer.
    ///
    /// Immutable diff endpoints use revision images. `score_diff` reuses its
    /// retained immutable target, while a worktree target reads the service's
    /// current workspace snapshot and therefore requires workspace readiness.
    ///
    /// Independent means "does not read the live workspace", not "writes
    /// nothing". An immutable endpoint's revision image publishes the blobs it
    /// parses into the repository's shared content-addressed analyzer cache,
    /// which is the point: the next consumer of those blobs, revision or
    /// worktree, reads them instead of parsing them. What the image does not
    /// leave behind is an orphaned workspace projection: the image's lease
    /// removes those rows when its last retained reader releases the image.
    pub fn tool_is_workspace_independent(name: &str, arguments: &Value) -> bool {
        if name == "score_diff" {
            return arguments
                .get("target")
                .and_then(Value::as_str)
                .is_some_and(|target| !target.trim().is_empty());
        }
        matches!(
            name,
            "analyze_diff"
                | "blast_radius"
                | "cyclomatic_complexity"
                | "missing_tests"
                | "report_secret_like_code"
        )
    }

    /// Lazy, watcher-less service for a one-shot `--tool` process whose tool is
    /// [workspace-independent](Self::tool_is_workspace_independent): the
    /// deferred `session` (`None`) is never materialized unless a query forces
    /// it, so no whole-repo analyzer is built. What this saves is parsing the
    /// whole repository to answer a question scoped to one diff; the tool's own
    /// revision-image analyzers may still warm the shared cache with the blobs
    /// they parse.
    ///
    /// It carries a listing cache for the same reason
    /// [`Self::new_one_shot`] does, and only because it is one-shot: a process
    /// that exits cannot observe a change it would need to invalidate for, so
    /// one walk serves every consumer. That reasoning does not extend to a
    /// long-lived `Manual` service (the stdio server under
    /// `BIFROST_MCP_FILE_WATCHER=off`), which has no watcher to invalidate a
    /// cache and must keep answering listing-backed tools from a fresh walk --
    /// hence [`listing_cache_for`] still refuses one there.
    ///
    /// The cache is not academic on this path. A worktree endpoint forces the
    /// lazy build after all, and with no cache `FilesystemProject::all_files`
    /// re-walks the tree per call: on Godot the C++ claim round's ignore probe
    /// alone re-walked 129 times and cost 9.3 seconds.
    pub fn new_one_shot_workspace_independent(root: PathBuf) -> Result<Self, String> {
        Self::new_one_shot_workspace_independent_with_host_activation_context(
            root,
            HostActivationContext::library_none(),
        )
    }

    pub fn new_one_shot_workspace_independent_with_host_activation_context(
        root: PathBuf,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        Self::new_one_shot_workspace_independent_with_watcher_starter(
            root,
            production_watcher_starter(),
            host,
        )
    }

    fn new_one_shot_workspace_independent_with_watcher_starter(
        root: PathBuf,
        watcher_starter: WatcherStarter,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        let (canonical, file_listing) = canonical_one_shot_root_and_listing_cache(root)?;
        Ok(Self::lazy(
            canonical,
            file_listing,
            UpdateStrategy::Manual,
            watcher_starter,
            host,
        ))
    }

    /// Construct a manual service over `project` with an ephemeral
    /// (non-persisted) analyzer cache and a caller-supplied analyzer config.
    ///
    /// Named a footgun because it usually is one: an ephemeral cache is deleted
    /// when the service drops, so every run re-parses and re-persists the whole
    /// workspace from nothing.
    /// [`Self::new_manual_persisted_for_project`] instead reuses
    /// content-addressed blobs across runs, and over a project with no
    /// persistence root it errors rather than quietly opening the store this
    /// constructor opens, so an ephemeral cache is always an explicit choice.
    /// See [`WorkspaceAnalyzer::build_ephemeral_footgun`] for the full rule.
    ///
    /// One-shot audit drivers (the MCP
    /// property fuzzer) get two things at once: absent an explicit catalog or
    /// cache override, nothing is written into the target checkout, which
    /// matters when the operator does not own it, and
    /// because every file is parsed fresh, session-only evidence such as
    /// tree-sitter ERROR nodes (`IAnalyzer::parse_errors`) is available for the
    /// whole workspace rather than only for the blobs that missed the cache.
    /// Scoped sessions use [`Self::new_manual_scoped_persisted_for_project`]
    /// to reuse persistent facts through an isolated session projection.
    pub fn new_manual_ephemeral_footgun_for_project(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, String> {
        Self::new_manual_ephemeral_footgun_for_project_with_host_activation_context(
            project,
            config,
            HostActivationContext::library_none(),
        )
    }

    /// [`Self::new_manual_ephemeral_footgun_for_project`] under the host's
    /// activation authority.
    pub fn new_manual_ephemeral_footgun_for_project_with_host_activation_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        // A manual service is its own budget owner.
        let budget = brokk_bifrost_core::retention_budget::RetentionBudget::new(
            config.retention_budget_bytes(),
        );
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun_with_budget(
            Arc::clone(&project),
            config,
            &budget,
        )
        .map_err(|error| format!("Failed to build ephemeral workspace: {error}"))?;
        Self::new_manual_from_workspace(project, workspace, host)
    }

    /// Construct a manual scoped service that shares the root's persistent
    /// blob facts while owning an isolated, session-lived file projection.
    pub fn new_manual_scoped_persisted_for_project(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, String> {
        Self::new_manual_scoped_persisted_for_project_with_host_activation_context(
            project,
            config,
            HostActivationContext::library_none(),
        )
    }

    /// [`Self::new_manual_scoped_persisted_for_project`] under the host's
    /// activation authority.
    pub fn new_manual_scoped_persisted_for_project_with_host_activation_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        // A manual service is its own budget owner.
        let budget = brokk_bifrost_core::retention_budget::RetentionBudget::new(
            config.retention_budget_bytes(),
        );
        let workspace = WorkspaceAnalyzer::build_scoped_persisted_with_budget(
            Arc::clone(&project),
            config,
            &budget,
        )
        .map_err(|error| format!("Failed to build scoped persisted workspace: {error}"))?;
        Self::new_manual_from_workspace(project, workspace, host)
    }

    /// Persisted-cache sibling of [`Self::new_manual_ephemeral_footgun_for_project`]
    /// for warmed, resumable campaigns. Session-only evidence (tree-sitter
    /// ERROR nodes) is unavailable for files served from the warm cache.
    pub fn new_manual_persisted_for_project(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, String> {
        Self::new_manual_persisted_for_project_with_host_activation_context(
            project,
            config,
            HostActivationContext::library_none(),
        )
    }

    /// [`Self::new_manual_persisted_for_project`] under the host's activation
    /// authority.
    pub fn new_manual_persisted_for_project_with_host_activation_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        // A manual service is its own budget owner.
        let budget = brokk_bifrost_core::retention_budget::RetentionBudget::new(
            config.retention_budget_bytes(),
        );
        Self::new_manual_from_persisted_build_result(
            Arc::clone(&project),
            WorkspaceAnalyzer::build_persisted_without_automatic_gc_with_budget(
                Arc::clone(&project),
                config,
                &budget,
            ),
            host,
        )
    }

    /// Progress-reporting sibling of [`Self::new_manual_persisted_for_project`].
    pub fn new_manual_persisted_with_progress_for_project<F>(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        progress: F,
    ) -> Result<Self, String>
    where
        F: Fn(crate::analyzer::BuildProgressEvent) + Send + Sync + 'static,
    {
        Self::new_manual_persisted_with_progress_for_project_with_host_activation_context(
            project,
            config,
            progress,
            HostActivationContext::library_none(),
        )
    }

    /// [`Self::new_manual_persisted_with_progress_for_project`] under the
    /// host's activation authority.
    pub fn new_manual_persisted_with_progress_for_project_with_host_activation_context<F>(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        progress: F,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String>
    where
        F: Fn(crate::analyzer::BuildProgressEvent) + Send + Sync + 'static,
    {
        // A manual service is its own budget owner.
        let budget = brokk_bifrost_core::retention_budget::RetentionBudget::new(
            config.retention_budget_bytes(),
        );
        Self::new_manual_from_persisted_build_result(
            Arc::clone(&project),
            WorkspaceAnalyzer::build_persisted_without_automatic_gc_with_budget_and_progress(
                Arc::clone(&project),
                config,
                &budget,
                progress,
                CancellationToken::default(),
            ),
            host,
        )
    }

    fn new_manual_from_persisted_build_result<E: std::fmt::Display>(
        project: Arc<dyn Project>,
        result: Result<WorkspaceAnalyzer, E>,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        let workspace =
            result.map_err(|error| format!("Failed to build persisted workspace: {error}"))?;
        Self::new_manual_from_workspace(project, workspace, host)
    }

    fn new_manual_from_workspace(
        project: Arc<dyn Project>,
        workspace: WorkspaceAnalyzer,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        let workspace = HostBoundWorkspace::bind(workspace, &host)?;
        let root = project.root().to_path_buf();
        let budget = workspace
            .0
            .store()
            .expect("a built manual workspace has an analyzer store")
            .retention_budget()
            .clone();
        let watcher_starter = production_watcher_starter();
        let session = assemble_session(
            project,
            workspace,
            UpdateStrategy::Manual,
            StartupIndexWarm::OnDemand,
            &watcher_starter,
        )?;
        Ok(Self::with_session_state_and_budget(
            root,
            Some(session),
            None,
            UpdateStrategy::Manual,
            watcher_starter,
            budget,
            host,
        ))
    }

    /// Clone the active session's workspace analyzer for read-only use.
    /// In-process drivers that derive their inputs from the same index the
    /// service serves (the MCP property fuzzer's probe generator) use this
    /// instead of building a second analyzer over the same root.
    pub fn analyzer_snapshot(&self) -> Result<Arc<WorkspaceAnalyzer>, String> {
        let session = self
            .session
            .read()
            .map_err(|_| "workspace session lock poisoned".to_string())?;
        session
            .as_ref()
            .map(|session| Arc::clone(&session.snapshot))
            .ok_or_else(|| "no active workspace session".to_string())
    }

    /// Settle background indexes before observing deterministic test counters.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn wait_for_index_warm_for_test(&self) -> Result<(), String> {
        let (warmer, startup) = {
            let mut guard = self.session.write().map_err(|_| "session lock poisoned")?;
            let session = guard.as_mut().ok_or("no active workspace session")?;
            (
                Arc::clone(&session.index_warmer),
                session.usage_index_warm.take(),
            )
        };
        // Workers own only an Arc<WorkspaceAnalyzer>, never the service or its
        // session lock. Release that lock anyway before joining either worker.
        if let Some(startup) = startup {
            startup
                .join()
                .map_err(|panic| format!("startup index warm panicked: {panic:?}"))?;
        }
        warmer.wait_until_idle_within(std::time::Duration::from_secs(30));
        Ok(())
    }

    /// Explicit, invocation-scoped measurement outside the timed request phase.
    /// The harness must exclude concurrent requests and edits. This does not
    /// activate a workspace, publish pending packs, apply watcher changes, or
    /// fill caches. Generation and watcher checks refuse an unstable sample.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn retention_census_for_test(&self) -> Result<Value, String> {
        use brokk_bifrost_core::retention_census::{
            FamilyLifetime, ResidentWeightUnit, RetentionCensus, UnknownKind,
        };

        let unavailable = |reason: &str| {
            serde_json::json!({
                "status": "unavailable", "reason": reason,
            })
        };
        let generation = self.workspace_generation();
        let (snapshot, packs, retired_packs, listing) = {
            let guard = self.session.read().map_err(|_| "session lock poisoned")?;
            let Some(session) = guard.as_ref() else {
                return Ok(unavailable("workspace_not_ready"));
            };
            if let Err(reason) = self.retention_census_current_for_test(generation, session, None) {
                return Ok(unavailable(reason));
            }
            let phase = self
                .phase
                .lock()
                .map_err(|_| "workspace phase lock poisoned")?;
            let listing = match &*phase {
                WorkspacePhase::Bound(bound) => bound.listing.clone(),
                WorkspacePhase::Unbound => None,
            };
            (
                Arc::clone(&session.snapshot),
                Arc::clone(&session.semantic_packs),
                session.retired_pack_warms.clone(),
                listing,
            )
        };
        // Capture only immutable handles under the session lock. Join workers
        // after releasing it, following the existing M5a index-warm barrier.
        packs.wait_for_worker();
        for warm in retired_packs {
            warm.wait_for_worker();
        }
        self.wait_for_index_warm_for_test()?;
        {
            let guard = self.session.read().map_err(|_| "session lock poisoned")?;
            let Some(session) = guard.as_ref() else {
                return Ok(unavailable("workspace_closed_during_capture"));
            };
            if let Err(reason) =
                self.retention_census_current_for_test(generation, session, Some(&snapshot))
            {
                return Ok(unavailable(reason));
            }
            if !session.usage_index_ready() {
                return Ok(unavailable("usage_index_not_ready"));
            }
        }

        // This is deliberately a SETTLED budget sample, distinct from the
        // passive structural traversal below. It is never added to its totals.
        let settled = self.retention_budget.snapshot();
        let mut census = RetentionCensus::new();
        snapshot.retention_census_for_test(&mut census);
        self.flow_state.retention_census_for_test(&mut census);
        if let Some(listing) = listing {
            listing.retention_census_for_test(&mut census);
        } else {
            census.record_unknown(
                "cached_workspace_file_listing",
                FamilyLifetime::Persistent,
                UnknownKind::Coverage,
                "no_service_listing_handle",
            );
        }
        // These O(1) counters describe residency, not structural capacity. No
        // payload estimator or cache fill is run by this service boundary.
        {
            let protocols = self
                .query_protocols
                .read()
                .map_err(|_| "protocol lock poisoned")?;
            for (family, bytes) in [
                (
                    "query_protocols.protocols",
                    protocols.retained_protocol_bytes(),
                ),
                (
                    "query_protocols.plans",
                    protocols.retained_binding_plan_bytes(),
                ),
                (
                    "query_protocols.artifacts",
                    protocols.retained_artifact_bytes(),
                ),
            ] {
                census.record_resident_reading(
                    family,
                    FamilyLifetime::Persistent,
                    protocols.registration_count() as u64,
                    bytes as u64,
                    ResidentWeightUnit::BytesEstimate,
                );
                census.record_unknown(
                    family,
                    FamilyLifetime::Persistent,
                    UnknownKind::Coverage,
                    "structural_capacity_not_yet_walked",
                );
            }
        }
        {
            let plans = self
                .query_value_flows
                .read()
                .map_err(|_| "value-flow lock poisoned")?;
            for (family, bytes) in [
                ("query_value_flows.plans", plans.retained_plan_bytes()),
                (
                    "query_value_flows.artifacts",
                    plans.retained_artifact_bytes(),
                ),
            ] {
                census.record_resident_reading(
                    family,
                    FamilyLifetime::Persistent,
                    plans.registration_count() as u64,
                    bytes as u64,
                    ResidentWeightUnit::BytesEstimate,
                );
                census.record_unknown(
                    family,
                    FamilyLifetime::Persistent,
                    UnknownKind::Coverage,
                    "structural_capacity_not_yet_walked",
                );
            }
        }
        {
            let results = self
                .query_taint_results
                .read()
                .map_err(|_| "taint lock poisoned")?;
            for (family, bytes) in [
                ("query_taint_results.plans", results.retained_plan_bytes()),
                (
                    "query_taint_results.reports_and_outputs",
                    results.retained_report_bytes(),
                ),
                (
                    "query_taint_results.artifacts",
                    results.retained_artifact_bytes(),
                ),
            ] {
                census.record_resident_reading(
                    family,
                    FamilyLifetime::Persistent,
                    results.registration_count() as u64,
                    bytes as u64,
                    ResidentWeightUnit::BytesEstimate,
                );
                census.record_unknown(
                    family,
                    FamilyLifetime::Persistent,
                    UnknownKind::Coverage,
                    "structural_capacity_not_yet_walked",
                );
            }
        }
        for family in ["query_protocols.outputs", "query_value_flows.outputs"] {
            census.record_unknown(
                family,
                FamilyLifetime::Persistent,
                UnknownKind::Coverage,
                "actual_outputs_have_no_service_residency_or_structural_visitor",
            );
        }
        census.record_unknown(
            "diff_scoring_reference_cache",
            FamilyLifetime::Persistent,
            UnknownKind::Coverage,
            "no_passive_residency_or_structural_visitor",
        );
        census.record_unknown(
            "ordinary_query_read_cache",
            FamilyLifetime::RequestOnly,
            UnknownKind::Coverage,
            "operation_only_excluded_by_quiescent_harness",
        );
        census.record_unknown(
            "prepared_dispatch_pool",
            FamilyLifetime::ProviderOnly,
            UnknownKind::Coverage,
            "operation_only_excluded_by_quiescent_harness",
        );
        let census = census.finish();
        {
            let guard = self.session.read().map_err(|_| "session lock poisoned")?;
            let Some(session) = guard.as_ref() else {
                return Ok(unavailable("workspace_closed_during_traversal"));
            };
            if let Err(reason) =
                self.retention_census_current_for_test(generation, session, Some(&snapshot))
            {
                return Ok(unavailable(reason));
            }
            if !session.usage_index_ready() {
                return Ok(unavailable("usage_index_not_ready"));
            }
        }
        Ok(serde_json::json!({
            "status": "available", "workspace_generation": generation,
            "assumption": "no_in_flight_requests_or_edits",
            "settled_retention_budget": {
                "owner_id": settled.owner_id, "sample_sequence": settled.sample_sequence,
                "capacity_bytes": settled.capacity_bytes, "accounted_bytes": settled.accounted_bytes,
                "process_required_owner_id": settled.process_required_owner_id,
                "process_required_bytes": settled.process_required_bytes,
                "occupied_bytes": settled.occupied_bytes,
                "regions": settled.regions.iter().map(|region| serde_json::json!({
                    "name": region.name, "namespace": region.namespace,
                    "entries": region.stats.entries, "accounted_bytes": region.stats.accounted_bytes,
                    "deferred_bytes": region.stats.deferred_bytes, "evictions": region.stats.evictions,
                    "refused_admissions": region.stats.refused_admissions, "revivals": region.stats.revivals,
                })).collect::<Vec<_>>(),
            },
            "passive_outside_census": census,
        }))
    }

    #[cfg(feature = "test-support")]
    fn retention_census_current_for_test(
        &self,
        generation: u64,
        session: &WorkspaceSession,
        snapshot: Option<&Arc<WorkspaceAnalyzer>>,
    ) -> Result<(), &'static str> {
        if self.workspace_generation() != generation {
            return Err("workspace_generation_changed");
        }
        if Self::session_watcher_has_pending(session) {
            return Err("pending_watcher_changes");
        }
        if snapshot.is_some_and(|snapshot| !Arc::ptr_eq(snapshot, &session.snapshot)) {
            return Err("workspace_snapshot_changed");
        }
        if !session.semantic_packs.is_ready() || session.refresh != PackRefresh::Idle {
            return Err("semantic_packs_not_ready");
        }
        if session
            .retired_pack_warms
            .iter()
            .any(|warm| !warm.is_ready())
        {
            return Err("retired_semantic_packs_not_ready");
        }
        if session
            .semantic_packs
            .installed_snapshot
            .lock()
            .map_err(|_| "semantic_pack_snapshot_lock_poisoned")?
            .is_some()
        {
            return Err("semantic_pack_publication_pending");
        }
        Ok(())
    }

    /// Evaluate a policy batch against this service's immutable workspace
    /// snapshot. Scoped one-shot CLI runs use this seam so their partial
    /// `FileSetProject` is the only analyzer constructed.
    pub fn evaluate_policy_inputs(
        &self,
        root: &Path,
        policy_inputs: &[PolicyEvaluationInput],
        options: &PolicyEvaluationOptions,
        cancellation: &CancellationToken,
    ) -> Result<PolicyBatchOutcome, String> {
        loop {
            let generation = self.workspace_generation();
            let snapshot = self
                .snapshot_for_query_with_cancellation(Some(cancellation))
                .map_err(|error| error.to_string())?;
            if generation != self.workspace_generation() {
                continue;
            }
            let result = {
                let snapshot = snapshot.enter();
                // The coordinator analyzes this session's project under the
                // policy configuration and activates the policy's semantic
                // sources itself, as every entry point does (#3735).
                let runtime =
                    CodeIntelligenceRuntime::new(&snapshot, &self.flow_state, Some(cancellation));
                runtime
                    .evaluate_policy_inputs(root, policy_inputs, options, &self.retention_budget)
                    .map_err(|error| SearchToolsServiceError::internal(error.to_string()))
            };
            return snapshot
                .finish("evaluate_policy_inputs", result)
                .map_err(|error| error.to_string());
        }
    }

    /// Evaluate one canonical policy batch and observe each finalized run.
    ///
    /// The observer runs only after the normal batch has finished constructing
    /// its canonical report, so it sees the same retained findings,
    /// suppressions, completion state, and truncation decisions as every other
    /// report consumer. An observer cannot alter evaluation behavior.
    pub fn evaluate_policy_inputs_with_observer(
        &self,
        root: &Path,
        policy_inputs: &[PolicyEvaluationInput],
        options: &PolicyEvaluationOptions,
        mut observer: impl FnMut(&PolicyRun),
    ) -> Result<PolicyBatchOutcome, String> {
        let outcome =
            self.evaluate_policy_inputs(root, policy_inputs, options, &Default::default())?;
        for run in outcome.report().runs() {
            observer(run);
        }
        Ok(outcome)
    }

    /// Register one already-compiled protocol and pre-resolved binding plan for
    /// in-process CodeQuery callers. Semantic handles remain host-owned and are
    /// never accepted by an MCP/LSP wire request.
    pub fn register_query_protocol(
        &self,
        protocol_ref: crate::rql::ProtocolRef,
        expected_root: crate::analyzer::semantic::ProcedureHandle,
        protocol: Arc<crate::flow::typestate::CompiledProtocol>,
        bindings: Arc<crate::flow::typestate::TypestateBindingPlan>,
    ) -> Result<crate::rql::ProtocolRegistrationOutcome, SearchToolsServiceError> {
        let session = self.read_session()?;
        session.as_ref().ok_or_else(Self::closed_error)?;
        let workspace_generation = self.workspace_generation();

        let registration = crate::rql::ProtocolRegistration::new(
            workspace_generation,
            expected_root,
            protocol,
            bindings,
        )
        .map_err(|error| SearchToolsServiceError::invalid_params(error.to_string()))?;
        let outcome = self
            .query_protocols
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?
            .register(protocol_ref, registration)
            .map_err(|error| SearchToolsServiceError::invalid_params(error.to_string()))?;
        drop(session);
        Ok(outcome)
    }

    /// Remove one host-defined protocol alias. Prepared requests keep their
    /// immutable snapshot, while later requests observe the removal.
    pub fn unregister_query_protocol(
        &self,
        protocol_ref: &crate::rql::ProtocolRef,
    ) -> Result<bool, SearchToolsServiceError> {
        Ok(self
            .query_protocols
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?
            .unregister(protocol_ref))
    }

    /// Register one already-compiled value-flow plan for in-process CodeQuery callers.
    pub fn register_query_value_flow_plan(
        &self,
        plan_ref: crate::rql::ValueFlowPlanRef,
        plan: Arc<crate::flow::value_flow::ValueFlowPlan>,
    ) -> Result<crate::rql::ValueFlowPlanRegistrationOutcome, SearchToolsServiceError> {
        let workspace_generation = {
            let session = self.read_session()?;
            session.as_ref().ok_or_else(Self::closed_error)?;
            self.workspace_generation()
        };
        let registration = crate::rql::ValueFlowPlanRegistration::new(workspace_generation, plan);
        let session = self.read_session()?;
        session.as_ref().ok_or_else(Self::closed_error)?;
        if self.workspace_generation() != workspace_generation {
            return Err(SearchToolsServiceError::invalid_params(
                "workspace generation changed while preparing the value-flow registration",
            ));
        }
        let outcome = self
            .query_value_flows
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?
            .register(plan_ref, registration)
            .map_err(|error| SearchToolsServiceError::invalid_params(error.to_string()))?;
        drop(session);
        Ok(outcome)
    }

    /// Remove one host-defined value-flow plan alias.
    pub fn unregister_query_value_flow_plan(
        &self,
        plan_ref: &crate::rql::ValueFlowPlanRef,
    ) -> Result<bool, SearchToolsServiceError> {
        Ok(self
            .query_value_flows
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?
            .unregister(plan_ref))
    }

    /// Register retained production taint results for in-process CodeQuery callers.
    pub fn register_query_taint_results(
        &self,
        taint_ref: crate::rql::TaintResultRef,
        results: Vec<Arc<crate::policy::ProductionTaintAnalysisResult>>,
    ) -> Result<crate::rql::TaintResultRegistrationOutcome, SearchToolsServiceError> {
        self.register_query_taint_results_with_output(taint_ref, results, Vec::new())
    }

    /// Register both live ICFG results and stable composed Output rows from a
    /// policy outcome. Fresh and reused composed anchors share this path.
    pub fn register_query_taint_outcome(
        &self,
        taint_ref: crate::rql::TaintResultRef,
        outcome: &crate::policy::PolicyBatchOutcome,
    ) -> Result<crate::rql::TaintResultRegistrationOutcome, SearchToolsServiceError> {
        self.register_query_taint_results_with_output(
            taint_ref,
            outcome.taint_analysis_results().to_vec(),
            outcome.taint_output_rows().to_vec(),
        )
    }

    fn register_query_taint_results_with_output(
        &self,
        taint_ref: crate::rql::TaintResultRef,
        results: Vec<Arc<crate::policy::ProductionTaintAnalysisResult>>,
        output: Vec<crate::rql::TaintOutputRows>,
    ) -> Result<crate::rql::TaintResultRegistrationOutcome, SearchToolsServiceError> {
        let workspace_generation = {
            let session = self.read_session()?;
            session.as_ref().ok_or_else(Self::closed_error)?;
            self.workspace_generation()
        };
        let registration = crate::rql::TaintResultRegistration::new_with_output(
            workspace_generation,
            results,
            output,
        )
        .map_err(|error| SearchToolsServiceError::invalid_params(error.to_string()))?;
        let session = self.read_session()?;
        session.as_ref().ok_or_else(Self::closed_error)?;
        if self.workspace_generation() != workspace_generation {
            return Err(SearchToolsServiceError::invalid_params(
                "workspace generation changed while preparing the taint result registration",
            ));
        }
        let outcome = self
            .query_taint_results
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?
            .register(taint_ref, registration)
            .map_err(|error| SearchToolsServiceError::invalid_params(error.to_string()))?;
        drop(session);
        Ok(outcome)
    }

    /// Remove one host-defined retained taint-result alias.
    pub fn unregister_query_taint_results(
        &self,
        taint_ref: &crate::rql::TaintResultRef,
    ) -> Result<bool, SearchToolsServiceError> {
        Ok(self
            .query_taint_results
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?
            .unregister(taint_ref))
    }

    pub fn call_tool_json(
        &self,
        name: &str,
        arguments_json: &str,
    ) -> Result<String, SearchToolsServiceError> {
        let arguments = serde_json::from_str::<Value>(arguments_json).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!("Invalid JSON arguments: {err}"))
        })?;
        let result = self.call_tool_value(name, arguments)?;
        serde_json::to_string(&result).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })
    }

    pub fn call_tool_payload_json(
        &self,
        name: &str,
        arguments_json: &str,
        render_options: RenderOptions,
    ) -> Result<String, SearchToolsServiceError> {
        let arguments = serde_json::from_str::<Value>(arguments_json).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!("Invalid JSON arguments: {err}"))
        })?;
        let result = self.call_tool_output(name, arguments, render_options)?;
        serde_json::to_string(&result.into_python_payload()).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool payload: {err}"))
        })
    }

    pub fn call_tool_value(
        &self,
        name: &str,
        arguments: Value,
    ) -> Result<Value, SearchToolsServiceError> {
        Ok(self
            .call_tool_output(name, arguments, RenderOptions::default())?
            .into_value())
    }

    pub fn call_tool_output(
        &self,
        name: &str,
        arguments: Value,
        render_options: RenderOptions,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        self.call_tool_output_with_cancellation(name, arguments, render_options, None)
    }

    /// [`Self::call_tool_output`] with a caller-driven cancellation token.
    ///
    /// The one-shot CLI uses this so an orphaned `--tool` run can be
    /// cancelled when its parent process dies (public issue #11); MCP hosts
    /// reach the same plumbing through the transport-timing wrappers below.
    pub fn call_tool_output_with_cancellation(
        &self,
        name: &str,
        arguments: Value,
        render_options: RenderOptions,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        #[cfg(feature = "test-support")]
        if name == "__bifrost_retention_census" {
            if !arguments
                .as_object()
                .is_some_and(|object| object.is_empty())
            {
                return Err(SearchToolsServiceError::invalid_params(
                    "retention census arguments must be an empty object",
                ));
            }
            return Self::structured_only(
                self.retention_census_for_test()
                    .map_err(SearchToolsServiceError::internal)?,
            );
        }
        self.call_tool_output_with_transport_queue_wait(
            name,
            arguments,
            render_options,
            cancellation,
            Duration::ZERO,
        )
    }

    /// Execute a tool after an MCP host waited for analyzer capacity.
    ///
    /// The host measures this phase before it enters the synchronous service.
    /// Profiled `query_code` responses retain the delay as request timing.
    pub(crate) fn call_tool_output_with_transport_queue_wait(
        &self,
        name: &str,
        arguments: Value,
        render_options: RenderOptions,
        cancellation: Option<&CancellationToken>,
        transport_queue_wait: Duration,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        self.call_tool_output_with_transport_timings(
            name,
            arguments,
            render_options,
            cancellation,
            TransportTimings::with_queue_wait(transport_queue_wait),
        )
    }

    /// Execute a tool after an MCP host measured the transport queue and its
    /// two request-admission components.
    ///
    /// `transport_queue_wait` remains the historical accepted-to-admitted
    /// aggregate. The component durations are additive diagnostics for
    /// profiled `query_code` responses; callers that do not have the split can
    /// use [`Self::call_tool_output_with_transport_queue_wait`].
    pub(crate) fn call_tool_output_with_transport_timings(
        &self,
        name: &str,
        arguments: Value,
        render_options: RenderOptions,
        cancellation: Option<&CancellationToken>,
        transport_timings: TransportTimings,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        // Declared first so it drops last: a release starts only after the
        // index warm this request schedules at its end has been registered.
        let _heap_activity = brokk_bifrost_core::heap_release::IdleHeapRelease::process().request();
        let _retention =
            profiling::retention_scope(&self.retention_budget, "service_request", name);
        let retry_arguments = arguments.clone();
        let _product_entry = brokk_bifrost_analysis::analyzer::enter_product_entry();
        let workspace_generation = self.workspace_generation();
        let result = self.call_tool_output_with_transport_queue_wait_inner(
            name,
            arguments,
            render_options,
            cancellation,
            transport_timings,
            None,
        );
        let result = match result {
            Err(error)
                if error.is_stale_analyzer_generation()
                    && !cancellation.is_some_and(CancellationToken::is_cancelled) =>
            {
                self.reload_stale_workspace_snapshot(workspace_generation)?;
                self.call_tool_output_with_transport_queue_wait_inner(
                    name,
                    retry_arguments,
                    render_options,
                    cancellation,
                    transport_timings,
                    None,
                )
            }
            result => result,
        };
        self.schedule_index_warm_after_tool_call();
        result
    }

    pub(crate) fn call_tool_output_with_transport_timings_and_preflight(
        &self,
        name: &str,
        arguments: Value,
        render_options: RenderOptions,
        cancellation: Option<&CancellationToken>,
        transport_timings: TransportTimings,
        suppression_preflight: Option<PreparedRunPolicyPreflight>,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        // Declared first so it drops last: a release starts only after the
        // index warm this request schedules at its end has been registered.
        let _heap_activity = brokk_bifrost_core::heap_release::IdleHeapRelease::process().request();
        let _retention =
            profiling::retention_scope(&self.retention_budget, "service_request", name);
        let retry_arguments = arguments.clone();
        let workspace_generation = self.workspace_generation();
        let result = self.call_tool_output_with_transport_queue_wait_inner(
            name,
            arguments,
            render_options,
            cancellation,
            transport_timings,
            suppression_preflight,
        );
        let result = match result {
            Err(error)
                if error.is_stale_analyzer_generation()
                    && !cancellation.is_some_and(CancellationToken::is_cancelled) =>
            {
                self.reload_stale_workspace_snapshot(workspace_generation)?;
                let retry_preflight = if name == "run_policy" {
                    match self.preflight_run_policy(&retry_arguments)? {
                        RunPolicyPreflight::Valid(preflight) => Some(preflight),
                        RunPolicyPreflight::Invalid(output) => return Ok(output),
                    }
                } else {
                    None
                };
                self.call_tool_output_with_transport_queue_wait_inner(
                    name,
                    retry_arguments,
                    render_options,
                    cancellation,
                    transport_timings,
                    retry_preflight,
                )
            }
            result => result,
        };
        self.schedule_index_warm_after_tool_call();
        result
    }

    fn call_tool_output_with_transport_queue_wait_inner(
        &self,
        name: &str,
        arguments: Value,
        render_options: RenderOptions,
        cancellation: Option<&CancellationToken>,
        transport_timings: TransportTimings,
        suppression_preflight: Option<PreparedRunPolicyPreflight>,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        // Lifecycle tools bypass watcher delta application: refresh rebuilds
        // explicitly, activate replaces the whole workspace, and get is cheap.
        match name {
            "refresh" => return self.handle_refresh(arguments),
            "update_paths" => return self.handle_update_paths(arguments, cancellation),
            "activate_workspace" => return self.handle_activate_workspace(arguments),
            "get_active_workspace" => return self.handle_get_active_workspace(arguments),
            _ => {}
        }

        if name == "report_secret_like_code" {
            // This scan owns Git failure diagnostics and reads no live source
            // selection. A failed analyzer listing must not replace its report.
            let root = self.service_root()?;
            check_snapshot_cancellation(cancellation)?;
            let params = Self::decode_tool_params(arguments)?;
            let result = report_secret_like_code(&root, params);
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err(SearchToolsServiceError::internal(format!(
                    "{name} was cancelled or exceeded its request-wide time budget"
                )));
            }
            return Self::structured_only(result);
        }

        if name == "analyze_diff" {
            let params = serde_json::from_value::<AnalyzeDiffParams>(arguments).map_err(|err| {
                SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
            })?;
            let root = self.service_root()?;
            let uncancelled = CancellationToken::default();
            return Self::structured_only(
                analyze_diff_at_root(
                    &root,
                    params,
                    &DiffAnalysisOptions {
                        snapshot_object_dir: self.diff_snapshot_object_dir.clone(),
                    },
                    cancellation.unwrap_or(&uncancelled),
                    &self.retention_budget,
                )
                .map_err(SearchToolsServiceError::internal)?,
            );
        }
        if name == "cyclomatic_complexity" {
            let params =
                serde_json::from_value::<CyclomaticComplexityParams>(arguments).map_err(|err| {
                    SearchToolsServiceError::invalid_params(format!(
                        "Invalid tool arguments: {err}"
                    ))
                })?;
            let root = self.service_root()?;
            let uncancelled = CancellationToken::default();
            let result = cyclomatic_complexity_at_root(
                &root,
                params,
                &DiffAnalysisOptions {
                    snapshot_object_dir: self.diff_snapshot_object_dir.clone(),
                },
                cancellation.unwrap_or(&uncancelled),
                &self.retention_budget,
            )
            .map_err(SearchToolsServiceError::internal)?;
            return Self::rendered_structured(result, render_options);
        }
        if name == "blast_radius"
            && arguments
                .get("target")
                .and_then(Value::as_str)
                .is_some_and(|target| !target.trim().is_empty())
        {
            let params = serde_json::from_value::<BlastRadiusParams>(arguments).map_err(|err| {
                SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
            })?;
            params
                .validate()
                .map_err(SearchToolsServiceError::invalid_params)?;
            let root = self.service_root()?;
            let uncancelled = CancellationToken::default();
            let result = blast_radius_at_root(
                &root,
                None,
                params,
                &DiffAnalysisOptions {
                    snapshot_object_dir: self.diff_snapshot_object_dir.clone(),
                },
                cancellation.unwrap_or(&uncancelled),
                &self.retention_budget,
            )
            .map_err(SearchToolsServiceError::internal)?;
            return Self::rendered_structured(result, render_options);
        }
        if name == "missing_tests"
            && arguments
                .get("target")
                .and_then(Value::as_str)
                .is_some_and(|target| !target.trim().is_empty())
        {
            let params =
                serde_json::from_value::<MissingTestsParams>(arguments).map_err(|err| {
                    SearchToolsServiceError::invalid_params(format!(
                        "Invalid tool arguments: {err}"
                    ))
                })?;
            let root = self.service_root()?;
            let uncancelled = CancellationToken::default();
            let result = missing_tests_at_root(
                &root,
                None,
                params,
                &DiffAnalysisOptions {
                    snapshot_object_dir: self.diff_snapshot_object_dir.clone(),
                },
                cancellation.unwrap_or(&uncancelled),
                &self.retention_budget,
            )
            .map_err(SearchToolsServiceError::internal)?;
            return Self::rendered_structured(result, render_options);
        }
        if name == "score_diff" {
            let params = serde_json::from_value::<ScoreDiffParams>(arguments).map_err(|err| {
                SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
            })?;
            let root = self.service_root()?;
            let uncancelled = CancellationToken::default();
            let token = cancellation.unwrap_or(&uncancelled);
            let options = DiffAnalysisOptions {
                snapshot_object_dir: self.diff_snapshot_object_dir.clone(),
            };
            if params.targets_worktree() {
                let snapshot = self.snapshot_for_query_with_cancellation(cancellation)?;
                let result = self
                    .diff_scoring
                    .score_worktree(
                        &snapshot.enter(),
                        params,
                        &options,
                        token,
                        &self.retention_budget,
                    )
                    .map_err(SearchToolsServiceError::internal);
                return snapshot.finish("score_diff", result.and_then(Self::structured_only));
            }
            return Self::structured_only(
                self.diff_scoring
                    .score_at_root(&root, params, &options, token, &self.retention_budget)
                    .map_err(SearchToolsServiceError::internal)?,
            );
        }
        if name == "query_code" {
            let prepared = self.prepare_query_code(arguments, cancellation)?;
            return self.execute_prepared_query_code_with_transport_timings(
                prepared,
                cancellation,
                transport_timings,
            );
        }
        if name == "list_policies" {
            let catalog = built_in_policy_catalog().map_err(|error| {
                SearchToolsServiceError::internal(format!(
                    "failed to load built-in policy catalog: {error}"
                ))
            })?;
            return Self::structured_only(catalog.document());
        }
        if name == "run_policy" {
            return match self.prepare_run_policy_with_cancellation_and_preflight(
                arguments,
                cancellation,
                suppression_preflight,
            )? {
                RunPolicyPreparation::Ready(prepared) => {
                    self.execute_prepared_run_policy(*prepared, cancellation)
                }
                RunPolicyPreparation::Deadline(result) => Self::structured_only(result),
                RunPolicyPreparation::PreflightFailure(result) => Self::structured_only(result),
            };
        }
        if name == "explain_policy" {
            return self.handle_explain_policy(arguments, cancellation);
        }
        if name == "flow_query" {
            return self.handle_flow_query(arguments, cancellation);
        }

        let arguments =
            self.normalize_arguments_for_current_workspace(name, arguments, cancellation)?;
        if name == "get_symbol_sources" {
            return self.handle_get_symbol_sources(arguments, render_options, cancellation);
        }
        let snapshot = {
            let _scope = profiling::scope("SearchToolsService::snapshot_for_query");
            // Deadline-aware: a request whose budget expires while the deferred
            // initial build is still running gets an explicit retry error within
            // its budget, instead of blocking through the whole build and then
            // reporting a misleading zero-result "cancelled/partial" payload
            // (#1199).
            let snapshot = self.snapshot_for_query_with_cancellation(cancellation)?;
            let named = crate::tool_arguments::tool_named_files(name, &arguments);
            if self.apply_stale_named_files(&named, cancellation)? {
                self.snapshot_for_query_with_cancellation(cancellation)?
            } else {
                snapshot
            }
        };
        if cancellation.is_some_and(CancellationToken::is_cancelled)
            && !matches!(
                name,
                "search_symbols"
                    | "most_relevant_files"
                    | "blast_radius"
                    | "missing_tests"
                    | "scan_usages_by_reference"
                    | "scan_usages_by_location"
            )
        {
            return Err(SearchToolsServiceError::internal(
                "analyzer request was cancelled or exceeded its request-wide time budget",
            ));
        }
        let request = snapshot;
        let snapshot = request.enter();
        let result = (|| match name {
            "search_symbols" => Self::decode_render_and_run(
                &snapshot,
                arguments,
                render_options,
                |workspace, params| {
                    search_symbols_with_cancellation(workspace.analyzer(), params, cancellation)
                },
            ),
            "get_symbol_locations" => Self::decode_render_and_run(
                &snapshot,
                arguments,
                render_options,
                |workspace, params| {
                    get_symbol_locations_with_cancellation(
                        workspace.analyzer(),
                        params,
                        cancellation,
                    )
                },
            ),
            "get_symbol_ancestors" => Self::decode_render_and_run(
                &snapshot,
                arguments,
                render_options,
                |workspace, params| get_symbol_ancestors(workspace.analyzer(), params),
            ),
            "get_summaries" => Self::decode_render_and_run(
                &snapshot,
                arguments,
                render_options,
                |workspace, params| {
                    get_summaries_with_cancellation(workspace.analyzer(), params, cancellation)
                },
            ),
            "list_symbols" => Self::decode_render_and_run(
                &snapshot,
                arguments,
                render_options,
                |workspace, params| list_symbols(workspace.analyzer(), params),
            ),
            "list_function_sources" => {
                let params = serde_json::from_value::<
                    brokk_bifrost_tools::function_sources::ListFunctionSourcesParams,
                >(arguments)
                .map_err(|err| {
                    SearchToolsServiceError::invalid_params(format!(
                        "Invalid tool arguments: {err}"
                    ))
                })?;
                Self::structured_only(
                    brokk_bifrost_tools::function_sources::list_function_sources(
                        snapshot.analyzer(),
                        params,
                    ),
                )
            }
            "classify_test_files" => {
                let params = Self::decode_tool_params(arguments)?;
                let result = classify_test_files(snapshot.analyzer(), params)
                    .map_err(SearchToolsServiceError::internal)?;
                Self::structured_only(result)
            }
            "most_relevant_files" => Self::decode_render_and_try_run(
                &snapshot,
                arguments,
                render_options,
                |workspace, params: MostRelevantFilesParams| {
                    let uncancelled = CancellationToken::default();
                    most_relevant_files_with_cancellation(
                        workspace.analyzer(),
                        params,
                        cancellation.unwrap_or(&uncancelled),
                    )
                },
            )
            .map_err(|error| {
                if cancellation.is_some_and(CancellationToken::is_cancelled)
                    && error.code == SearchToolsServiceErrorCode::InvalidParams
                {
                    SearchToolsServiceError::internal(error.message)
                } else {
                    error
                }
            }),
            "blast_radius" => Self::decode_render_and_try_run(
                &snapshot,
                arguments,
                render_options,
                |workspace, params: BlastRadiusParams| {
                    params.validate()?;
                    let uncancelled = CancellationToken::default();
                    blast_radius_at_root(
                        workspace.analyzer().project().root(),
                        Some(workspace.analyzer()),
                        params,
                        &DiffAnalysisOptions {
                            snapshot_object_dir: self.diff_snapshot_object_dir.clone(),
                        },
                        cancellation.unwrap_or(&uncancelled),
                        &self.retention_budget,
                    )
                },
            ),
            "missing_tests" => Self::decode_render_and_try_run(
                &snapshot,
                arguments,
                render_options,
                |workspace, params: MissingTestsParams| {
                    let uncancelled = CancellationToken::default();
                    missing_tests_at_root(
                        workspace.analyzer().project().root(),
                        Some(workspace.analyzer()),
                        params,
                        &DiffAnalysisOptions {
                            snapshot_object_dir: self.diff_snapshot_object_dir.clone(),
                        },
                        cancellation.unwrap_or(&uncancelled),
                        &self.retention_budget,
                    )
                },
            ),
            "scan_usages_by_reference" => {
                Self::validate_scan_usages_by_reference_arguments(&arguments)?;
                Self::decode_render_and_run(
                    &snapshot,
                    arguments,
                    render_options,
                    |workspace, params| {
                        let _scan_scope =
                            crate::profiling::scope("searchtools.scan_usages_backend");
                        scan_usages_by_reference_with_cancellation(
                            workspace.analyzer(),
                            params,
                            cancellation.cloned().unwrap_or_default(),
                        )
                    },
                )
            }
            "scan_usages_by_location" => {
                Self::validate_scan_usages_by_location_arguments(&arguments)?;
                Self::decode_render_and_run(
                    &snapshot,
                    arguments,
                    render_options,
                    |workspace, params| {
                        let _scan_scope =
                            crate::profiling::scope("searchtools.scan_usages_backend");
                        scan_usages_by_location_with_cancellation(
                            workspace.analyzer(),
                            params,
                            cancellation.cloned().unwrap_or_default(),
                        )
                    },
                )
            }
            "get_definitions_by_location" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    get_definitions_by_location_with_cancellation(
                        workspace.analyzer(),
                        params,
                        cancellation,
                    )
                })
            }
            "get_declarations_by_location" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    get_declarations_by_location_with_cancellation(
                        workspace.analyzer(),
                        params,
                        cancellation,
                    )
                })
            }
            "get_definitions_by_reference" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    get_definitions_by_reference_with_cancellation(
                        workspace.analyzer(),
                        params,
                        cancellation,
                    )
                })
            }
            "get_type_by_location" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    get_type_by_location(workspace.analyzer(), params)
                })
            }
            "rename_symbol" => Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                rename_symbol(workspace.analyzer(), params)
            }),
            "usage_graph" => Self::decode_render_and_run(
                &snapshot,
                arguments,
                render_options,
                |workspace, params| {
                    usage_graph_with_cancellation(
                        workspace.analyzer(),
                        params,
                        cancellation.cloned().unwrap_or_default(),
                    )
                },
            ),
            "get_file_contents" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    get_file_contents(workspace.analyzer(), params)
                })
            }
            "find_files_containing" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    find_files_containing(workspace.analyzer(), params)
                })
            }
            "search_file_contents" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    search_file_contents(workspace.analyzer(), params)
                })
            }
            "compute_cyclomatic_complexity" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    compute_cyclomatic_complexity(workspace.analyzer(), params)
                })
            }
            "compute_cognitive_complexity" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    compute_cognitive_complexity(workspace.analyzer(), params)
                })
            }
            "report_comment_density_for_code_unit" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    report_comment_density_for_code_unit(workspace.analyzer(), params)
                })
            }
            "report_comment_density_for_files" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    report_comment_density_for_files(workspace.analyzer(), params)
                })
            }
            "report_exception_handling_smells" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    report_exception_handling_smells(workspace.analyzer(), params)
                })
            }
            "report_test_assertion_smells" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    report_test_assertion_smells(workspace.analyzer(), params)
                })
            }
            "report_structural_clone_smells" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    report_structural_clone_smells(workspace.analyzer(), params)
                })
            }
            "report_long_method_and_god_object_smells" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    report_long_method_and_god_object_smells(workspace.analyzer(), params)
                })
            }
            "report_dead_code_and_unused_abstraction_smells" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    report_dead_code_and_unused_abstraction_smells(workspace.analyzer(), params)
                })
            }
            "analyze_git_hotspots" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    analyze_git_hotspots(workspace.analyzer(), params)
                })
            }
            _ => Err(SearchToolsServiceError::unknown_tool(format!(
                "Unknown tool: {name}"
            ))),
        })();
        let result = if cancellation.is_some_and(CancellationToken::is_cancelled)
            && !matches!(
                name,
                "search_symbols"
                    | "most_relevant_files"
                    | "scan_usages_by_reference"
                    | "scan_usages_by_location"
            ) {
            Err(SearchToolsServiceError::internal(format!(
                "{name} was cancelled or exceeded its request-wide time budget"
            )))
        } else {
            result
        };
        drop(snapshot);
        request.finish(name, result)
    }

    pub fn query_code_result(
        &self,
        arguments: Value,
    ) -> Result<crate::rql::CodeQueryResponse, SearchToolsServiceError> {
        let PreparedQueryCode {
            snapshot,
            arguments,
            request_timing,
            workspace_generation,
            query_protocols,
            query_value_flows,
            query_taint_results,
        } = self.prepare_query_code(arguments, None)?;
        let result = self
            .query_code_result_for_snapshot(
                &snapshot,
                arguments,
                None,
                workspace_generation,
                &query_protocols,
                &query_value_flows,
                &query_taint_results,
            )
            .map(|(mut response, execution_timing)| {
                Self::attach_query_code_request_timing(
                    &mut response,
                    request_timing,
                    execution_timing,
                    0,
                    TransportTimings::default(),
                );
                response
            });
        snapshot.finish("query_code", result)
    }

    pub(crate) fn prepare_query_code(
        &self,
        arguments: Value,
        cancellation: Option<&CancellationToken>,
    ) -> Result<PreparedQueryCode, SearchToolsServiceError> {
        let started = Instant::now();
        let mut workspace_ready = Duration::ZERO;
        loop {
            let generation = self.workspace_generation();
            let snapshot_started = Instant::now();
            let snapshot = self.snapshot_for_query_with_cancellation(cancellation)?;
            workspace_ready = workspace_ready.saturating_add(snapshot_started.elapsed());
            let query_protocols = self.query_protocol_snapshot()?;
            let query_value_flows = self.query_value_flow_snapshot()?;
            let query_taint_results = self.query_taint_result_snapshot()?;
            if generation != self.workspace_generation() {
                continue;
            }
            let arguments = {
                let snapshot = snapshot.enter();
                crate::tool_arguments::normalize_tool_arguments(
                    "query_code",
                    arguments,
                    snapshot.analyzer().project().root(),
                )
                .map_err(SearchToolsServiceError::invalid_params)?
            };
            return Ok(PreparedQueryCode {
                snapshot,
                arguments,
                request_timing: PreparedQueryCodeTiming {
                    started,
                    workspace_ready_ns: duration_ns(workspace_ready),
                    preparation_ns: duration_ns(started.elapsed().saturating_sub(workspace_ready)),
                },
                workspace_generation: generation,
                query_protocols,
                query_value_flows,
                query_taint_results,
            });
        }
    }

    #[cfg(test)]
    pub(crate) fn execute_prepared_query_code(
        &self,
        prepared: PreparedQueryCode,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        self.execute_prepared_query_code_with_transport_queue_wait(
            prepared,
            cancellation,
            Duration::ZERO,
        )
    }

    #[cfg(test)]
    pub(crate) fn execute_prepared_query_code_with_transport_queue_wait(
        &self,
        prepared: PreparedQueryCode,
        cancellation: Option<&CancellationToken>,
        transport_queue_wait: Duration,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        self.execute_prepared_query_code_with_transport_timings(
            prepared,
            cancellation,
            TransportTimings::with_queue_wait(transport_queue_wait),
        )
    }

    pub(crate) fn execute_prepared_query_code_with_transport_timings(
        &self,
        prepared: PreparedQueryCode,
        cancellation: Option<&CancellationToken>,
        transport_timings: TransportTimings,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let PreparedQueryCode {
            snapshot,
            arguments,
            request_timing,
            workspace_generation,
            query_protocols,
            query_value_flows,
            query_taint_results,
        } = prepared;
        let result = (|| {
            let (mut output, execution_timing) = self.query_code_result_for_snapshot(
                &snapshot,
                arguments,
                cancellation,
                workspace_generation,
                &query_protocols,
                &query_value_flows,
                &query_taint_results,
            )?;
            let serialization_ns = if matches!(&output, crate::rql::CodeQueryResponse::Profile(_)) {
                let serialization_started = Instant::now();
                // Measure serialization without retaining a wire copy. This probe
                // excludes transport conversion and the CLI's actual final write.
                serde_json::to_writer(std::io::sink(), &output)
                    .expect("the public CodeQuery response is serializable");
                duration_ns(serialization_started.elapsed())
            } else {
                0
            };
            Self::attach_query_code_request_timing(
                &mut output,
                request_timing,
                execution_timing,
                serialization_ns,
                transport_timings,
            );
            Ok(ToolOutput::QueryResponse(Arc::new(output)))
        })();
        snapshot.finish("query_code", result)
    }

    #[allow(clippy::too_many_arguments)]
    fn query_code_result_for_snapshot(
        &self,
        snapshot: &WorkspaceQueryScope,
        arguments: Value,
        cancellation: Option<&CancellationToken>,
        workspace_generation: u64,
        query_protocols: &crate::rql::ProtocolRegistrationSet,
        query_value_flows: &crate::rql::ValueFlowPlanRegistrationSet,
        query_taint_results: &crate::rql::TaintResultRegistrationSet,
    ) -> Result<(crate::rql::CodeQueryResponse, QueryCodeExecutionTiming), SearchToolsServiceError>
    {
        let entered = snapshot.enter();
        let input_decode_started = Instant::now();
        let query_languages = arguments.get("languages").cloned();
        let query = Self::decode_query_code_input(&entered, arguments)?;
        let input_decode_ns = duration_ns(input_decode_started.elapsed());
        let query_execution_started = Instant::now();
        let mut response = CodeIntelligenceRuntime::new(&entered, &self.flow_state, cancellation)
            .execute_query_with_all_analysis_registrations(
                workspace_generation,
                query_protocols,
                query_value_flows,
                query_taint_results,
                &query,
                self.query_execution_limits(&entered),
            );
        mark_pack_activation_incomplete(
            &snapshot.pack_activation,
            &query,
            query_languages.as_ref(),
            &entered.analyzer().languages(),
            &mut response,
        );
        mark_workspace_semantic_models_not_loaded(
            entered.analyzer().project().root(),
            &query,
            &mut response,
        );
        Ok((
            response,
            QueryCodeExecutionTiming {
                input_decode_ns,
                query_execution_ns: duration_ns(query_execution_started.elapsed()),
            },
        ))
    }

    /// The execution limits one `query_code` request runs under.
    ///
    /// Interactive callers keep the fixed defaults. A host that opted into
    /// [`Self::with_workspace_scaled_query_limits`] gets the same
    /// source-volume scaling policy evaluation computes, from this snapshot's
    /// own analyzed files.
    fn query_execution_limits(
        &self,
        snapshot: &WorkspaceAnalyzer,
    ) -> crate::rql::CodeQueryExecutionLimits {
        if self.workspace_scaled_query_limits {
            brokk_bifrost_policy::workspace_scaled_query_limits(snapshot)
        } else {
            crate::rql::CodeQueryExecutionLimits::default()
        }
    }

    fn attach_query_code_request_timing(
        response: &mut crate::rql::CodeQueryResponse,
        prepared: PreparedQueryCodeTiming,
        execution: QueryCodeExecutionTiming,
        rendering_serialization_ns: u64,
        transport_timings: TransportTimings,
    ) {
        let crate::rql::CodeQueryResponse::Profile(profile) = response else {
            return;
        };
        profile.request_timings_ns = crate::rql::CodeQueryProfileRequestTimings {
            transport_queue_wait: duration_ns(transport_timings.transport_queue_wait),
            workspace_readiness_wait: duration_ns(transport_timings.workspace_readiness_wait),
            analyzer_admission_wait: duration_ns(transport_timings.analyzer_admission_wait),
            workspace_ready: prepared.workspace_ready_ns,
            preparation: prepared.preparation_ns,
            input_decode: execution.input_decode_ns,
            query_execution: execution.query_execution_ns,
            rendering_serialization: rendering_serialization_ns,
            total: duration_ns(prepared.started.elapsed())
                .saturating_add(duration_ns(transport_timings.transport_queue_wait)),
        };
    }

    fn decode_query_code_input(
        snapshot: &WorkspaceQueryEntry<'_>,
        arguments: Value,
    ) -> Result<crate::rql::CodeQuery, SearchToolsServiceError> {
        let Some(query_file) = arguments.get("query_file") else {
            return crate::rql::CodeQuery::from_json(&arguments)
                .map_err(|error| SearchToolsServiceError::invalid_params(error.to_string()));
        };

        let object = arguments.as_object().ok_or_else(|| {
            SearchToolsServiceError::invalid_params("query_code arguments must be an object")
        })?;
        if object.len() != 1 {
            return Err(SearchToolsServiceError::invalid_params(
                "query_file is exclusive; put the complete query in the referenced file",
            ));
        }
        let query_file = query_file.as_str().ok_or_else(|| {
            SearchToolsServiceError::invalid_params("query_file must be a string path")
        })?;
        let root = snapshot.analyzer().project().root();
        let path = Path::new(query_file);
        let extension = match path.extension().and_then(|extension| extension.to_str()) {
            Some("rql") | Some("json") => path.extension().and_then(|extension| extension.to_str()),
            Some(extension) => {
                return Err(SearchToolsServiceError::invalid_params(format!(
                    "unsupported query file extension `.{extension}` for `{query_file}`; expected .rql or .json"
                )));
            }
            None => {
                return Err(SearchToolsServiceError::invalid_params(format!(
                    "query file `{query_file}` has no extension; expected .rql or .json"
                )));
            }
        };
        let contents = read_workspace_document(
            snapshot.scope.document_root(),
            path,
            &["rql", "json"],
            MAX_QUERY_FILE_BYTES,
        )
        .map_err(|error| Self::query_file_read_error(query_file, error))?;
        let value = match extension {
            Some("rql") => {
                brokk_bifrost_rql::query::sexp::sexp_to_json(contents.source()).map_err(|error| {
                    SearchToolsServiceError::invalid_params(format!(
                        "failed to parse RQL query file `{query_file}`: {error}"
                    ))
                })
            }
            Some("json") => serde_json::from_str::<Value>(contents.source()).map_err(|error| {
                SearchToolsServiceError::invalid_params(format!(
                    "failed to parse JSON query file `{query_file}`: {error}"
                ))
            }),
            _ => unreachable!("query file extension was validated before reading"),
        }?;
        let value = crate::tool_arguments::normalize_tool_arguments("query_code", value, root)
            .map_err(SearchToolsServiceError::invalid_params)?;
        crate::rql::CodeQuery::from_json(&value).map_err(|error| {
            SearchToolsServiceError::invalid_params(format!(
                "invalid CodeQuery in `{query_file}`: {error}"
            ))
        })
    }

    fn query_file_read_error(
        query_file: &str,
        error: WorkspaceDocumentError,
    ) -> SearchToolsServiceError {
        let message = match error {
            WorkspaceDocumentError::NotRegularFile { .. } => {
                format!("query file `{query_file}` must be a regular file")
            }
            WorkspaceDocumentError::TooLarge {
                bytes: Some(bytes),
                max_bytes,
                ..
            } => {
                format!("query file `{query_file}` is too large: {bytes} bytes exceeds {max_bytes}")
            }
            WorkspaceDocumentError::TooLarge {
                bytes: None,
                max_bytes,
                ..
            } => format!("query file `{query_file}` is too large: more than {max_bytes} bytes"),
            WorkspaceDocumentError::SymlinkNotAllowed { .. } => format!(
                "failed to read query file `{query_file}`: query file path resolves outside active workspace or traverses a symbolic link"
            ),
            WorkspaceDocumentError::PathEscapesWorkspace { .. } => {
                format!(
                    "failed to read query file `{query_file}`: query file path resolves outside active workspace"
                )
            }
            error => format!("failed to read query file `{query_file}`: {error}"),
        };
        SearchToolsServiceError::invalid_params(message)
    }

    pub fn active_workspace_root(&self) -> Option<PathBuf> {
        match &*self.lock_phase() {
            WorkspacePhase::Unbound => None,
            WorkspacePhase::Bound(bound) => Some(bound.root.clone()),
        }
    }

    fn lock_phase(&self) -> std::sync::MutexGuard<'_, WorkspacePhase> {
        self.phase
            .lock()
            .expect("nothing that can panic runs under the workspace phase lock")
    }

    /// The bound root and its listing cache, read without waiting for a build.
    fn bound_root_and_listing(
        &self,
    ) -> Result<(PathBuf, Option<Arc<WorkspaceFileListingCache>>), SearchToolsServiceError> {
        match &*self.lock_phase() {
            WorkspacePhase::Unbound => Err(Self::unbound_error()),
            WorkspacePhase::Bound(bound) => Ok((bound.root.clone(), bound.listing.clone())),
        }
    }

    pub(crate) fn workspace_generation(&self) -> u64 {
        self.workspace_generation.load(Ordering::Acquire)
    }

    fn query_protocol_snapshot(
        &self,
    ) -> Result<crate::rql::ProtocolRegistrationSet, SearchToolsServiceError> {
        self.query_protocols
            .read()
            .map(|registrations| registrations.clone())
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))
    }

    fn query_value_flow_snapshot(
        &self,
    ) -> Result<crate::rql::ValueFlowPlanRegistrationSet, SearchToolsServiceError> {
        self.query_value_flows
            .read()
            .map(|registrations| registrations.clone())
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))
    }

    fn query_taint_result_snapshot(
        &self,
    ) -> Result<crate::rql::TaintResultRegistrationSet, SearchToolsServiceError> {
        self.query_taint_results
            .read()
            .map(|registrations| registrations.clone())
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))
    }

    /// Retire every live registration and move to the next generation.
    ///
    /// The typestate summary repository is deliberately not rotated here. Its
    /// entries are keyed by `ProcedureSummaryKey`, which names the procedure's
    /// exact artifact content, so an update cannot make a retained entry wrong;
    /// rotating would only throw away every unchanged procedure's summary. The
    /// registrations below are different: they are caller-minted handles into
    /// one immutable workspace snapshot, and they do not survive it.
    fn advance_workspace_generation(&self) {
        self.query_protocols
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.query_value_flows
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.query_taint_results
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.workspace_generation.fetch_add(1, Ordering::AcqRel);
    }

    // Note: `--root` and `new_for_python` take the path as-given (canonicalized
    // by `FilesystemProject::new`) without git-root normalization, while
    // `activate_workspace` normalizes to the nearest enclosing git root. As a
    // result, calling `activate_workspace` with the same path that was passed
    // at construction may rebuild the index when the path is a subdirectory of
    // a git repository. The construction path is intentionally precise; hosts
    // that want git-root semantics should call `activate_workspace` after
    // start.
    fn new_with_strategy(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        Self::new_with_strategy_and_watcher_starter(
            root,
            update_strategy,
            production_watcher_starter(),
            host,
        )
    }

    /// A one-shot `--tool` process: build the workspace, answer one call, exit.
    ///
    /// No file watcher. Nothing in the process consumes a watch event before it
    /// exits. Starting a watcher also invalidates the listing the build just
    /// filled, forcing a second whole-workspace walk with no benefit to a
    /// process that exits after one call.
    ///
    /// The listing cache stays, which is the part that is not about watching: a
    /// process that exits cannot observe a change it would need to invalidate
    /// for, so one walk serves every consumer. `Manual` is the honest strategy
    /// here for the same reason the scoped one-shot constructors already use it
    /// -- nothing updates this workspace after construction.
    pub fn new_one_shot(root: PathBuf) -> Result<Self, String> {
        Self::new_one_shot_with_host_activation_context(root, HostActivationContext::library_none())
    }

    pub fn new_one_shot_with_host_activation_context(
        root: PathBuf,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        Self::new_one_shot_with_watcher_starter(root, production_watcher_starter(), host)
    }

    fn new_one_shot_with_watcher_starter(
        root: PathBuf,
        watcher_starter: WatcherStarter,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        let (canonical, file_listing) = canonical_one_shot_root_and_listing_cache(root)?;
        Self::new_synchronous(
            canonical,
            file_listing,
            UpdateStrategy::Manual,
            watcher_starter,
            host,
        )
    }

    fn new_with_strategy_and_watcher_starter(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        watcher_starter: WatcherStarter,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        let (canonical, file_listing) = canonical_root_and_listing_cache(root, update_strategy)?;
        Self::new_synchronous(
            canonical,
            file_listing,
            update_strategy,
            watcher_starter,
            host,
        )
    }

    /// Build a persisted workspace and its session synchronously. The listing
    /// cache is a parameter rather than a function of `update_strategy`: a
    /// one-shot process wants the cache without the watcher that normally
    /// invalidates it.
    fn new_synchronous(
        canonical: PathBuf,
        file_listing: Option<Arc<WorkspaceFileListingCache>>,
        update_strategy: UpdateStrategy,
        watcher_starter: WatcherStarter,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        let budget = brokk_bifrost_core::retention_budget::RetentionBudget::new(
            AnalyzerConfig::default().retention_budget_bytes(),
        );
        let (project, workspace) = build_persisted_workspace_with_budget(
            canonical,
            file_listing.clone(),
            update_strategy,
            &budget,
            &host,
        )?;
        let root = project.root().to_path_buf();
        let session = assemble_session(
            project,
            workspace,
            update_strategy,
            StartupIndexWarm::OnDemand,
            &watcher_starter,
        )?;
        Ok(Self::with_session_state_and_budget(
            root,
            Some(session),
            file_listing,
            update_strategy,
            watcher_starter,
            budget,
            host,
        ))
    }

    #[cfg(any(test, feature = "test-support"))]
    fn new_ephemeral_with_strategy(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        Self::new_ephemeral_with_strategy_and_watcher_starter(
            root,
            update_strategy,
            production_watcher_starter(),
            host,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    fn new_ephemeral_with_strategy_and_watcher_starter(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        watcher_starter: WatcherStarter,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        let canonical = canonical_service_root(root)?;
        let file_listing = listing_cache_for(update_strategy, &canonical);
        let (project, workspace) =
            build_ephemeral_workspace(canonical, file_listing.clone(), &host)?;
        let root = project.root().to_path_buf();
        let session = assemble_session(
            project,
            workspace,
            update_strategy,
            StartupIndexWarm::OnDemand,
            &watcher_starter,
        )?;
        Ok(Self::with_session_state(
            root,
            Some(session),
            file_listing,
            update_strategy,
            watcher_starter,
            host,
        ))
    }

    fn new_lazy_with_strategy(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        Self::new_lazy_with_strategy_and_watcher_starter(
            root,
            update_strategy,
            production_watcher_starter(),
            host,
        )
    }

    fn new_lazy_with_strategy_and_watcher_starter(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        watcher_starter: WatcherStarter,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        let (canonical, file_listing) = canonical_root_and_listing_cache(root, update_strategy)?;
        Ok(Self::lazy(
            canonical,
            file_listing,
            update_strategy,
            watcher_starter,
            host,
        ))
    }

    /// A service with no session yet, whose listing cache is a parameter rather
    /// than a function of `update_strategy` -- the same split
    /// [`Self::new_synchronous`] makes, and for the same reason: a one-shot
    /// process wants the cache without the watcher that normally invalidates
    /// it.
    fn lazy(
        canonical: PathBuf,
        file_listing: Option<Arc<WorkspaceFileListingCache>>,
        update_strategy: UpdateStrategy,
        watcher_starter: WatcherStarter,
        host: Arc<HostActivationContext>,
    ) -> Self {
        Self::with_session_state(
            canonical,
            None,
            file_listing,
            update_strategy,
            watcher_starter,
            host,
        )
    }

    fn with_session_state(
        root: PathBuf,
        session: Option<WorkspaceSession>,
        file_listing: Option<Arc<WorkspaceFileListingCache>>,
        update_strategy: UpdateStrategy,
        watcher_starter: WatcherStarter,
        host: Arc<HostActivationContext>,
    ) -> Self {
        let budget = brokk_bifrost_core::retention_budget::RetentionBudget::new(
            AnalyzerConfig::default().retention_budget_bytes(),
        );
        Self::with_session_state_and_budget(
            root,
            session,
            file_listing,
            update_strategy,
            watcher_starter,
            budget,
            host,
        )
    }

    fn session_with_toolchain_wake(
        session: Option<WorkspaceSession>,
    ) -> Arc<RwLock<Option<WorkspaceSession>>> {
        let shared = Arc::new(RwLock::new(session));
        if let Some(session) = shared.read().expect("session lock poisoned").as_ref() {
            install_toolchain_wake(&shared, session);
        }
        shared
    }

    fn install_toolchain_wake(&self, session: &WorkspaceSession) {
        install_toolchain_wake(&self.session, session);
    }

    fn with_session_state_and_budget(
        root: PathBuf,
        mut session: Option<WorkspaceSession>,
        file_listing: Option<Arc<WorkspaceFileListingCache>>,
        update_strategy: UpdateStrategy,
        watcher_starter: WatcherStarter,
        budget: brokk_bifrost_core::retention_budget::RetentionBudget,
        host: Arc<HostActivationContext>,
    ) -> Self {
        let build = if session.is_some() {
            WorkspaceBuild::Installed
        } else {
            WorkspaceBuild::NotStarted
        };
        let lifetimes = Arc::new(WorkspaceLifetimes::default());
        let lifetime = session.as_mut().map(|session| {
            let lifetime = lifetimes
                .reserve(root.clone(), 1)
                .expect("a new binding has a free slot");
            session.lifetime = Some(Arc::clone(&lifetime));
            lifetime
        });
        let mut phase = WorkspacePhase::bound(root, file_listing, build);
        if let WorkspacePhase::Bound(bound) = &mut phase {
            bound.lifetime = lifetime;
        }
        Self {
            retention_budget: budget,
            host_activation: host,
            phase: Mutex::new(phase),
            session: Self::session_with_toolchain_wake(session),
            retired_sessions: Mutex::new(Default::default()),
            lifetimes,
            workspace_generation: AtomicU64::new(1),
            flow_state: crate::flow::FlowWorkspaceState::new(),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            build_progress: Arc::new(Default::default()),
            update_strategy,
            startup_index_warm: StartupIndexWarm::OnDemand,
            watcher_starter,
            diff_snapshot_object_dir: None,
            diff_scoring: DiffScoringSession::default(),
            workspace_scaled_query_limits: false,
            #[cfg(any(test, feature = "test-support"))]
            semantic_model_runtime_limits: SemanticModelRuntimeLimits::default(),
            #[cfg(test)]
            snapshot_acquisition_observer: Mutex::new(None),
        }
    }

    /// Construct the searchtools service without blocking on the initial
    /// workspace build. The expensive declaration index is built on a
    /// background thread, so the MCP `initialize` handshake can be answered
    /// immediately while indexing proceeds. The first tool call blocks (via
    /// `ensure_ready`) only for whatever build time has not already elapsed.
    ///
    /// Used by the long-lived stdio server. Only a cheap, O(1) root check
    /// (canonicalize + is-dir) runs synchronously so an invalid `--root` still
    /// fails fast. Everything that touches the tree -- file discovery
    /// (`FilesystemProject::new` -> `detect_languages`), parsing, and the file
    /// watcher -- is deferred to the build thread, so the MCP `initialize`
    /// handshake is answered instantly even when the workspace is enormous or on
    /// a slow filesystem (a tree of thousands of repo clones, a WSL `/mnt/c`
    /// mount, etc.). Without this, the discovery walk alone could exceed an MCP
    /// client's startup timeout.
    pub fn new_deferred(root: PathBuf) -> Result<Self, String> {
        Self::new_deferred_with_host_activation_context(root, HostActivationContext::library_none())
    }

    pub fn new_deferred_with_host_activation_context(
        root: PathBuf,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        Self::new_deferred_with_watcher_starter(root, production_watcher_starter(), host)
    }

    /// Construct a deferred, persisted service for an immutable workspace.
    /// Queries never poll a file watcher; callers must use `refresh` when they
    /// intentionally change the workspace after construction.
    pub fn new_deferred_manual(root: PathBuf) -> Result<Self, String> {
        Self::new_deferred_manual_with_host_activation_context(
            root,
            HostActivationContext::library_none(),
        )
    }

    pub fn new_deferred_manual_with_host_activation_context(
        root: PathBuf,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        Self::new_deferred_with_strategy_and_watcher_starter(
            root,
            UpdateStrategy::Manual,
            production_watcher_starter(),
            host,
        )
    }

    /// Construct an MCP service that has not yet been bound to a client-approved
    /// workspace root. Analyzer-backed tools return an actionable error until a
    /// later roots response or negotiated host metadata installs a workspace.
    pub fn new_unbound() -> Self {
        Self::new_unbound_with_host_activation_context(HostActivationContext::library_none())
    }

    pub fn new_unbound_with_host_activation_context(host: Arc<HostActivationContext>) -> Self {
        Self::new_unbound_with_strategy(UpdateStrategy::WatchFiles, host)
    }

    /// Construct an unbound MCP service whose eventual client-selected
    /// workspace is updated only by explicit refresh requests.
    pub fn new_unbound_manual() -> Self {
        Self::new_unbound_manual_with_host_activation_context(HostActivationContext::library_none())
    }

    pub fn new_unbound_manual_with_host_activation_context(
        host: Arc<HostActivationContext>,
    ) -> Self {
        Self::new_unbound_with_strategy(UpdateStrategy::Manual, host)
    }

    fn new_unbound_with_strategy(
        update_strategy: UpdateStrategy,
        host: Arc<HostActivationContext>,
    ) -> Self {
        Self {
            retention_budget: brokk_bifrost_core::retention_budget::RetentionBudget::new(
                AnalyzerConfig::default().retention_budget_bytes(),
            ),
            host_activation: host,
            phase: Mutex::new(WorkspacePhase::Unbound),
            session: Arc::new(RwLock::new(None)),
            retired_sessions: Mutex::new(Default::default()),
            lifetimes: Arc::new(Default::default()),
            workspace_generation: AtomicU64::new(0),
            flow_state: crate::flow::FlowWorkspaceState::new(),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            build_progress: Arc::new(Default::default()),
            update_strategy,
            startup_index_warm: StartupIndexWarm::AtStartup,
            watcher_starter: production_watcher_starter(),
            diff_snapshot_object_dir: None,
            diff_scoring: DiffScoringSession::default(),
            workspace_scaled_query_limits: false,
            #[cfg(any(test, feature = "test-support"))]
            semantic_model_runtime_limits: SemanticModelRuntimeLimits::default(),
            #[cfg(test)]
            snapshot_acquisition_observer: Mutex::new(None),
        }
    }

    /// Bind a rootless MCP service to an exact filesystem root supplied by the
    /// client through roots or negotiated host metadata. Unlike the user-facing
    /// activation tool, this deliberately does not promote a nested directory to
    /// an enclosing Git repository: the client-provided boundary is authoritative
    /// for what the workspace *contains*. It is not a boundary for derived data:
    /// the cache resolves to the primary repository root like every other entry
    /// point, and results stay scoped by reconciliation against the bound root's
    /// current blob oids (issue #1544).
    /// The persisted analyzer builds in the background so workspace negotiation
    /// cannot consume an admitted tool request's interactive latency budget.
    pub fn bind_client_workspace(&self, root: PathBuf) -> Result<PathBuf, SearchToolsServiceError> {
        self.bind_client_workspace_with_result(root)
            .map(|(root, _)| root)
    }

    fn bind_client_workspace_with_result(
        &self,
        root: PathBuf,
    ) -> Result<(PathBuf, ToolOutput), SearchToolsServiceError> {
        let _scope = profiling::scope("mcp_cold.workspace_binding");
        let canonical = Self::canonical_client_workspace(root)?;
        let mut session = self
            .session
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?;
        let mut phase = self.lock_phase();
        let mut retirement = self
            .retired_sessions
            .lock()
            .expect("session retirement lock poisoned");
        self.bind_client_workspace_locked(canonical, &mut session, &mut phase, &mut retirement)
    }

    fn canonical_client_workspace(root: PathBuf) -> Result<PathBuf, SearchToolsServiceError> {
        let canonical = root
            .canonicalize()
            .map_err(|err| {
                SearchToolsServiceError::invalid_params(format!(
                    "Failed to resolve client workspace root {}: {err}",
                    root.display()
                ))
            })?
            .normalize();
        if !canonical.is_dir() {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "Client workspace root is not a directory: {}",
                canonical.display()
            )));
        }

        Ok(canonical)
    }

    fn bind_client_workspace_locked(
        &self,
        canonical: PathBuf,
        session: &mut Option<WorkspaceSession>,
        phase: &mut WorkspacePhase,
        retirement: &mut WorkspaceSessionRetirement,
    ) -> Result<(PathBuf, ToolOutput), SearchToolsServiceError> {
        let replaces_live_binding = matches!(&*phase, WorkspacePhase::Bound(bound)
            if bound.root != canonical && matches!(bound.build, WorkspaceBuild::Installed | WorkspaceBuild::Building(_)));
        if replaces_live_binding || !retirement.pending.is_empty() {
            retirement.prepare()?;
        }
        if matches!(&*phase, WorkspacePhase::Bound(bound) if bound.root == canonical) {
            // Explicit activation of Failed resets it to NotStarted first.
            // Preserve retained failures for ordinary binding/observations.
            if !matches!(&*phase, WorkspacePhase::Bound(bound) if matches!(bound.build, WorkspaceBuild::Failed(_)))
            {
                self.observe_workspace_phase(phase)?;
            }
            let WorkspacePhase::Bound(bound) = &*phase else {
                unreachable!()
            };
            return self
                .active_workspace_output(bound, session.as_ref())
                .map(|output| (canonical, output));
        }

        let generation = self.workspace_generation().wrapping_add(1);
        let lifetime = self
            .lifetimes
            .reserve(canonical.clone(), generation)
            .ok_or_else(|| self.workspace_activation_not_ready())?;
        // Created before the deferred build so the build and the session share
        // one listing; installed below alongside the root.
        let file_listing = listing_cache_for(self.update_strategy, &canonical);
        let observation = self.build_progress.begin(generation);
        let handle = self
            .spawn_workspace_build(
                generation,
                canonical.clone(),
                file_listing.clone(),
                Some(observation),
                Arc::clone(&lifetime),
            )
            .map_err(|error| {
                SearchToolsServiceError::internal(format!(
                    "Failed to start client workspace build for {}: {error}",
                    canonical.display()
                ))
            })?;

        self.advance_workspace_generation();
        debug_assert_eq!(self.workspace_generation(), generation);
        // Publish the replacement, then retire the preceding build or session
        // without joining its work on this request.
        let old_phase = std::mem::replace(
            phase,
            WorkspacePhase::bound(
                canonical.clone(),
                file_listing,
                WorkspaceBuild::Building(handle),
            ),
        );
        if let WorkspacePhase::Bound(bound) = phase {
            bound.lifetime = Some(lifetime);
        }
        let old_session = session.take();
        self.retire_workspace(old_phase, old_session, retirement);
        let WorkspacePhase::Bound(bound) = &*phase else {
            unreachable!()
        };
        // Capture the accepted binding while holding its publication locks.
        // A later probe may be busy; that must not turn an applied activation
        // into an apparent refusal.
        let output = self.active_workspace_output(bound, session.as_ref())?;
        Ok((canonical, output))
    }

    pub(crate) fn workspace_busy(&self, phase: &str) -> SearchToolsServiceError {
        SearchToolsServiceError::workspace_unavailable("busy", phase, self.lifetimes.retiring())
    }

    fn workspace_try_lock_error<T>(
        &self,
        error: std::sync::TryLockError<T>,
        lock: &str,
    ) -> SearchToolsServiceError {
        match error {
            std::sync::TryLockError::WouldBlock => self.workspace_busy(&format!("{lock} is busy")),
            std::sync::TryLockError::Poisoned(_) => {
                SearchToolsServiceError::internal(format!("{lock} poisoned"))
            }
        }
    }

    pub(crate) fn try_active_workspace_root(
        &self,
    ) -> Result<Option<PathBuf>, SearchToolsServiceError> {
        let phase = self
            .phase
            .try_lock()
            .map_err(|error| self.workspace_try_lock_error(error, "workspace lifecycle lock"))?;
        Ok(match &*phase {
            WorkspacePhase::Bound(bound) => Some(bound.root.clone()),
            WorkspacePhase::Unbound => None,
        })
    }

    pub(crate) fn try_bind_client_workspace(
        &self,
        root: PathBuf,
    ) -> Result<PathBuf, SearchToolsServiceError> {
        let _scope = profiling::scope("mcp_cold.workspace_binding");
        let canonical = Self::canonical_client_workspace(root)?;
        let mut session = self
            .session
            .try_write()
            .map_err(|error| self.workspace_try_lock_error(error, "workspace session lock"))?;
        let mut phase = self
            .phase
            .try_lock()
            .map_err(|error| self.workspace_try_lock_error(error, "workspace lifecycle lock"))?;
        let mut retirement = self
            .retired_sessions
            .try_lock()
            .map_err(|error| self.workspace_try_lock_error(error, "workspace retirement lock"))?;
        self.bind_client_workspace_locked(canonical, &mut session, &mut phase, &mut retirement)
            .map(|(root, _)| root)
    }

    pub(crate) fn try_unbind_client_workspace(&self) -> Result<(), SearchToolsServiceError> {
        let mut session = self
            .session
            .try_write()
            .map_err(|error| self.workspace_try_lock_error(error, "workspace session lock"))?;
        let mut phase = self
            .phase
            .try_lock()
            .map_err(|error| self.workspace_try_lock_error(error, "workspace lifecycle lock"))?;
        let mut retirement = self
            .retired_sessions
            .try_lock()
            .map_err(|error| self.workspace_try_lock_error(error, "workspace retirement lock"))?;
        self.unbind_client_workspace_locked(&mut session, &mut phase, &mut retirement);
        Ok(())
    }

    pub(crate) fn workspace_activation_not_ready(&self) -> SearchToolsServiceError {
        SearchToolsServiceError::workspace_unavailable(
            "workspace_not_ready",
            "workspace activation is waiting for preceding sessions to release",
            self.lifetimes.retiring(),
        )
    }

    pub(crate) fn workspace_binding_capacity_exhausted(&self) -> bool {
        self.lifetimes
            .slots
            .lock()
            .expect("workspace lifetime slots poisoned")
            .iter()
            .all(|slot| slot.strong_count() != 0)
    }

    fn retire_workspace(
        &self,
        old_phase: WorkspacePhase,
        old_session: Option<WorkspaceSession>,
        retirement: &mut WorkspaceSessionRetirement,
    ) {
        let WorkspacePhase::Bound(mut bound) = old_phase else {
            debug_assert!(old_session.is_none());
            return;
        };
        let work = match bound.build {
            WorkspaceBuild::Building(handle) => RetiredWorkspaceWork::Build(handle),
            WorkspaceBuild::Installed => {
                let session = old_session.expect("an installed binding owns its session");
                session.cancel_warms();
                RetiredWorkspaceWork::Session(Box::new(session))
            }
            _ => {
                debug_assert!(old_session.is_none());
                return;
            }
        };
        let lifetime = bound
            .lifetime
            .take()
            .expect("a live binding owns its reserved slot");
        lifetime.retire();
        if matches!(work, RetiredWorkspaceWork::Session(_)) {
            lifetime.set_phase("queued session retirement");
        }
        retirement.retire(RetiredWorkspace { lifetime, work })
    }

    /// Start building the session for `root` on its own thread. The build
    /// returns `generation` and `root` so installation can assert that it is
    /// still the bound build.
    fn spawn_workspace_build(
        &self,
        generation: u64,
        root: PathBuf,
        file_listing: Option<Arc<WorkspaceFileListingCache>>,
        observation: Option<crate::workspace_progress::BuildObservation>,
        lifetime: Arc<WorkspaceLifetime>,
    ) -> std::io::Result<PendingWorkspaceBuild> {
        *lifetime
            .build_cancellation
            .lock()
            .expect("workspace build cancellation poisoned") = observation
            .as_ref()
            .map(|observation| observation.cancellation.clone());
        let update_strategy = self.update_strategy;
        let startup_index_warm = self.startup_index_warm;
        let watcher_starter = Arc::clone(&self.watcher_starter);
        let budget = self.retention_budget.clone();
        let host = Arc::clone(&self.host_activation);
        // Background work counts as activity for the idle heap release (#12661): taken before the spawn, held until the thread ends.
        let heap_activity = brokk_bifrost_core::heap_release::IdleHeapRelease::process().warm();
        std::thread::Builder::new()
            .name("bifrost-index-build".to_string())
            .spawn(
                move || -> Result<(u64, PathBuf, WorkspaceSession), String> {
                    let _heap_activity = heap_activity;
                    // Cache resolution is the same one every other entry point
                    // uses (`gitblob::cache_db_path`): a linked worktree shares
                    // the primary checkout's oid-keyed database, so a client
                    // bind neither copies nor forks it (issue #1544).
                    let (project, workspace) = build_persisted_workspace_reporting_with_budget(
                        root.clone(),
                        file_listing,
                        update_strategy,
                        observation.as_ref(),
                        &budget,
                        &host,
                    )?;
                    if lifetime.retiring.load(Ordering::Acquire) {
                        return Err("workspace preparation was revoked".to_owned());
                    }
                    lifetime.set_phase("activation");
                    let mut session = assemble_session_deferred(
                        project,
                        workspace,
                        update_strategy,
                        startup_index_warm,
                        &watcher_starter,
                    )?;
                    session.lifetime = Some(Arc::clone(&lifetime));
                    if lifetime.retiring.load(Ordering::Acquire) {
                        session.cancel_warms();
                    }
                    if let Some(observation) = observation {
                        observation.complete();
                    }
                    Ok((generation, root, session))
                },
            )
    }

    /// Remove a workspace previously supplied through MCP roots or negotiated
    /// host metadata, so revoked scope never remains queryable.
    pub fn unbind_client_workspace(&self) -> Result<(), SearchToolsServiceError> {
        let mut session = self
            .session
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?;
        let mut phase = self.lock_phase();
        let mut retirement = self
            .retired_sessions
            .lock()
            .expect("session retirement lock poisoned");
        self.unbind_client_workspace_locked(&mut session, &mut phase, &mut retirement);
        Ok(())
    }

    fn unbind_client_workspace_locked(
        &self,
        session: &mut Option<WorkspaceSession>,
        phase: &mut WorkspacePhase,
        retirement: &mut WorkspaceSessionRetirement,
    ) {
        let old_phase = std::mem::replace(phase, WorkspacePhase::Unbound);
        if matches!(old_phase, WorkspacePhase::Bound(_)) {
            self.advance_workspace_generation();
        }
        let old_session = session.take();
        self.retire_workspace(old_phase, old_session, retirement);
    }

    fn new_deferred_with_watcher_starter(
        root: PathBuf,
        watcher_starter: WatcherStarter,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        Self::new_deferred_with_strategy_and_watcher_starter(
            root,
            UpdateStrategy::WatchFiles,
            watcher_starter,
            host,
        )
    }

    fn new_deferred_with_strategy_and_watcher_starter(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        watcher_starter: WatcherStarter,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        let _scope = profiling::scope("mcp_cold.workspace_binding");
        let canonical = canonical_service_root(root)?;
        // Created before the deferred build so listing-backed fast paths
        // (`find_filenames`, #1388) can fill it while indexing is pending.
        let file_listing = listing_cache_for(update_strategy, &canonical);
        // Warm the commit-history relevance cache alongside the deferred build (#2327). Every
        // interactive navigation tool carries a cancellation token, so its ranking reads that
        // cache warm-only and never fills it; without a warm scheduled here, a session that
        // only navigates ranks without the history tier for its whole life. The walk is a
        // `git rev-list`/`git log` pair that takes seconds on a large repository, so it gets
        // its own thread and no request waits for it.
        match brokk_bifrost_tools::relevance::spawn_commit_history_warm(canonical.clone()) {
            // Detached deliberately: nothing in the service ever joins the warm, and the
            // thread reports its own failures.
            Ok(_warm) => {}
            Err(error) => {
                eprintln!("Failed to spawn commit-history warm thread: {error}");
            }
        }
        let budget = brokk_bifrost_core::retention_budget::RetentionBudget::new(
            AnalyzerConfig::default().retention_budget_bytes(),
        );
        let mut service = Self::with_session_state_and_budget(
            canonical,
            None,
            file_listing,
            update_strategy,
            watcher_starter,
            budget,
            host,
        );
        service.startup_index_warm = StartupIndexWarm::AtStartup;
        service
            .observe_or_start_workspace()
            .map_err(|error| error.message)?;
        Ok(service)
    }

    /// Block until the bound workspace's session is installed, starting the
    /// build of a lazily constructed service. A no-op once the session is
    /// installed. Safe under concurrency: every caller polls the phase, and the
    /// first to find the build thread finished installs its session.
    ///
    /// A session installed here may still be running its semantic-pack warm;
    /// that is deliberate (issue #3372) and `get_active_workspace` reports it
    /// as `semantic_packs_ready`; `semantic_model_overlay` tells whether models are active.
    fn ensure_ready(&self) -> Result<(), SearchToolsServiceError> {
        self.ensure_ready_unless(&|| None)
    }

    /// [`Self::ensure_ready`], abandoning the wait with the error `stop`
    /// returns while the build is still running.
    fn ensure_ready_unless(
        &self,
        stop: &dyn Fn() -> Option<SearchToolsServiceError>,
    ) -> Result<(), SearchToolsServiceError> {
        loop {
            if self.observe_or_start_workspace()? {
                return Ok(());
            }
            if let Some(error) = stop() {
                return Err(error);
            }
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }

    /// One phase/start algorithm shared by blocking callers and the polling
    /// probe. It never joins an unfinished build or acquires the session lock.
    fn observe_workspace_phase(
        &self,
        phase: &mut WorkspacePhase,
    ) -> Result<WorkspacePreparation, SearchToolsServiceError> {
        let WorkspacePhase::Bound(bound) = phase else {
            return Err(Self::unbound_error());
        };
        match &bound.build {
            WorkspaceBuild::Installed => Ok(WorkspacePreparation::Ready),
            WorkspaceBuild::Failed(error) => Err(SearchToolsServiceError::internal(error.clone())),
            WorkspaceBuild::Closed => Err(Self::closed_error()),
            WorkspaceBuild::NotStarted => {
                if bound.lifetime.is_none() {
                    bound.lifetime = Some(
                        self.lifetimes
                            .reserve(bound.root.clone(), self.workspace_generation())
                            .ok_or_else(|| self.workspace_activation_not_ready())?,
                    );
                }
                let observation = self.build_progress.begin(self.workspace_generation());
                let handle = self.spawn_workspace_build(
                    self.workspace_generation(),
                    bound.root.clone(),
                    bound.listing.clone(),
                    Some(observation),
                    Arc::clone(bound.lifetime.as_ref().unwrap()),
                );
                match handle {
                    Ok(handle) => {
                        bound.build = WorkspaceBuild::Building(handle);
                        Ok(WorkspacePreparation::Preparing)
                    }
                    Err(error) => {
                        let message = format!("Failed to spawn index build thread: {error}");
                        bound.build = WorkspaceBuild::Failed(message.clone());
                        bound.lifetime.take();
                        Err(SearchToolsServiceError::internal(message))
                    }
                }
            }
            WorkspaceBuild::Building(handle) => Ok(if handle.is_finished() {
                WorkspacePreparation::Finished
            } else {
                WorkspacePreparation::Preparing
            }),
        }
    }

    /// Host and embedded callers retain the existing blocking installation
    /// path. The probe supplies already-acquired guards to the same install core.
    pub(crate) fn observe_or_start_workspace(&self) -> Result<bool, SearchToolsServiceError> {
        loop {
            let observed = self.observe_workspace_phase(&mut self.lock_phase())?;
            match observed {
                WorkspacePreparation::Ready => return Ok(true),
                WorkspacePreparation::Preparing => return Ok(false),
                WorkspacePreparation::Finished => {
                    if let Some(installed) = self.install_finished_build() {
                        return installed.map(|()| true);
                    }
                }
            }
        }
    }

    /// Install the session of a build thread that has finished, or record its
    /// failure. Takes `session` before `phase`, per the lock order, so the
    /// phase is checked again: another caller may have installed it, or a
    /// rebind may have replaced it, in between. `None` asks the caller to read
    /// the phase again.
    fn install_finished_build(&self) -> Option<Result<(), SearchToolsServiceError>> {
        let mut session = match self.session.write() {
            Ok(session) => session,
            Err(_) => {
                return Some(Err(SearchToolsServiceError::internal(
                    "SearchToolsService lock poisoned",
                )));
            }
        };
        let mut phase = self.lock_phase();
        self.install_finished_build_locked(&mut session, &mut phase)
    }

    fn install_finished_build_locked(
        &self,
        session: &mut Option<WorkspaceSession>,
        phase: &mut WorkspacePhase,
    ) -> Option<Result<(), SearchToolsServiceError>> {
        let WorkspacePhase::Bound(bound) = &mut *phase else {
            return None;
        };
        let handle = match std::mem::replace(&mut bound.build, WorkspaceBuild::Installed) {
            WorkspaceBuild::Building(handle) if handle.is_finished() => handle,
            other => {
                bound.build = other;
                return None;
            }
        };
        // A panicked build is this request's failure, and the panic's own
        // message is the only description of it the caller will get: the
        // build thread is gone and nothing else knows why it stopped.
        // Record it the way a returned build error is recorded so a later
        // request reports the same failure instead of querying a workspace
        // that was never installed (issue #2771).
        let built = handle.join().unwrap_or_else(|payload| {
            Err(reported_panic("index build thread", payload).to_string())
        });
        match built {
            Ok((generation, root, mut built_session)) => {
                assert_eq!(
                    (generation, &root),
                    (self.workspace_generation(), &bound.root),
                    "a rebind replaces the build in the phase, so the build there is current"
                );
                debug_assert!(session.is_none());
                built_session.lifetime = bound.lifetime.clone();
                self.install_toolchain_wake(&built_session);
                *session = Some(built_session);
                Some(Ok(()))
            }
            Err(error) => {
                bound.build = WorkspaceBuild::Failed(error.clone());
                bound.lifetime.take();
                Some(Err(SearchToolsServiceError::internal(error)))
            }
        }
    }

    /// Blocking preparation for embedded users and durable Task workers.
    /// Synchronous MCP calls observe preparation and return not-ready instead.
    /// Preparation owns its lifetime independently of the waiting request;
    /// cancellation stops this waiter, never the shared build. The optional
    /// semantic warm can continue after the analyzer has been installed.
    pub fn wait_workspace_ready(
        &self,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), SearchToolsServiceError> {
        self.wait_workspace_ready_until(cancelled, None)
    }

    pub(crate) fn initial_workspace_build_uninstalled(&self) -> bool {
        self.lock_phase().running_build().is_some()
    }

    pub(crate) fn workspace_build_progress(
        &self,
        generation: u64,
    ) -> Option<crate::workspace_progress::BuildSnapshot> {
        self.build_progress.snapshot(generation)
    }

    /// Whether a bound build thread is still running. The phase lock is short-held,
    /// so the probe never waits behind the build itself.
    pub fn workspace_build_pending(&self) -> bool {
        self.lock_phase()
            .running_build()
            .is_some_and(|handle| !handle.is_finished())
    }

    pub fn wait_workspace_ready_until(
        &self,
        cancelled: &dyn Fn() -> bool,
        deadline: Option<Instant>,
    ) -> Result<(), SearchToolsServiceError> {
        let _scope = profiling::scope("mcp_cold.workspace_readiness_wait");
        loop {
            if self.observe_or_start_workspace()? {
                return Ok(());
            }
            if cancelled() {
                return Err(SearchToolsServiceError::internal(
                    "the tool call was cancelled while waiting for the workspace snapshot",
                ));
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(SearchToolsServiceError::deadline_exceeded(
                    self.workspace_snapshot_not_ready_message(),
                ));
            }
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }

    fn workspace_snapshot_not_ready_message(&self) -> String {
        let phase = self
            .workspace_build_progress(self.workspace_generation())
            .and_then(|snapshot| snapshot.phase);
        match phase {
            Some(phase) => {
                format!("{WORKSPACE_SNAPSHOT_NOT_READY_MESSAGE}; the workspace build is {phase}")
            }
            None => WORKSPACE_SNAPSHOT_NOT_READY_MESSAGE.to_owned(),
        }
    }

    fn ensure_ready_with_cancellation(
        &self,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), SearchToolsServiceError> {
        let Some(cancellation) = cancellation else {
            return self.ensure_ready();
        };
        self.ensure_ready_unless(&|| {
            if !cancellation.is_cancelled() {
                return None;
            }
            Some(if cancellation.is_timed_out() {
                SearchToolsServiceError::deadline_exceeded(
                    self.workspace_snapshot_not_ready_message(),
                )
            } else {
                SearchToolsServiceError::internal("workspace snapshot acquisition was cancelled")
            })
        })
    }

    /// Drop the session. Closing a lazily constructed service builds it first,
    /// so the session's teardown (automatic cache GC) still runs. Closing a
    /// closed service does nothing.
    pub fn close(&self) -> Result<(), SearchToolsServiceError> {
        if let Err(error) = self.ensure_ready() {
            self.retired_sessions
                .lock()
                .expect("session retirement lock poisoned")
                .finish()?;
            return if self.is_closed() { Ok(()) } else { Err(error) };
        }
        let mut guard = self
            .session
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?;
        let mut phase = self.lock_phase();
        let (session, lifetime) = match &mut *phase {
            WorkspacePhase::Bound(bound) if matches!(bound.build, WorkspaceBuild::Installed) => {
                bound.build = WorkspaceBuild::Closed;
                self.advance_workspace_generation();
                let lifetime = bound.lifetime.take();
                if let Some(lifetime) = &lifetime {
                    lifetime.retire();
                }
                (guard.take(), lifetime)
            }
            // A concurrent close or rebind got there first.
            _ => (None, None),
        };
        drop(phase);
        drop(guard);
        drop(session);
        drop(lifetime);
        self.retired_sessions
            .lock()
            .expect("session retirement lock poisoned")
            .finish()
    }

    fn is_closed(&self) -> bool {
        matches!(
            &*self.lock_phase(),
            WorkspacePhase::Bound(BoundWorkspace {
                build: WorkspaceBuild::Closed,
                ..
            })
        )
    }

    /// Replace a session whose persisted language generations were advanced
    /// by another analyzer process (for example, while a client switched
    /// branches). Incremental updates retain the snapshot's captured
    /// generations, so they cannot repair this condition; a fresh persisted
    /// build must capture the store's current immutable generation map.
    fn reload_stale_workspace_snapshot(
        &self,
        expected_workspace_generation: u64,
    ) -> Result<(), SearchToolsServiceError> {
        let (root, file_listing) = self.bound_root_and_listing()?;
        if let Some(file_listing) = &file_listing {
            file_listing.invalidate();
        }
        let mut session_guard = self.write_session()?;
        if self.workspace_generation() != expected_workspace_generation {
            return Ok(());
        }
        session_guard.as_ref().ok_or_else(Self::closed_error)?;
        let (project, workspace) = build_persisted_workspace_with_budget(
            root,
            file_listing,
            self.update_strategy,
            &self.retention_budget,
            &self.host_activation,
        )
        .map_err(|error| {
            SearchToolsServiceError::internal(format!(
                "Failed to reload workspace after stale analyzer generation: {error}"
            ))
        })?;
        let mut new_session = assemble_session(
            project,
            workspace,
            self.update_strategy,
            self.startup_index_warm,
            &self.watcher_starter,
        )
        .map_err(|error| {
            SearchToolsServiceError::internal(format!(
                "Failed to assemble workspace after stale analyzer generation: {error}"
            ))
        })?;
        new_session.lifetime = session_guard
            .as_ref()
            .and_then(|session| session.lifetime.clone());
        self.advance_workspace_generation();
        let old_session = session_guard
            .replace(new_session)
            .ok_or_else(Self::closed_error)?;
        drop(session_guard);
        drop(old_session);
        if let Some(session) = self.session.read().expect("session lock poisoned").as_ref() {
            self.install_toolchain_wake(session);
        }
        Ok(())
    }

    /// Run a forced git-reachability GC on the analyzer cache
    /// and block until it completes. The session lock is released before blocking.
    pub fn request_cache_gc(&self) -> Result<(), SearchToolsServiceError> {
        self.ensure_ready()?;
        let (root, db_path) = {
            let guard = self.session.read().map_err(|_| {
                SearchToolsServiceError::internal("workspace session lock poisoned")
            })?;
            let session = guard.as_ref().ok_or_else(Self::closed_error)?;
            let db_path = session.snapshot.persisted_store_path().ok_or_else(|| {
                SearchToolsServiceError::invalid_params("cache GC requires a persisted workspace")
            })?;
            (
                session.snapshot.analyzer().project().root().to_path_buf(),
                db_path,
            )
        };
        let repo = crate::gitblob::discover(&root).ok_or_else(|| {
            SearchToolsServiceError::invalid_params("cache GC requires a Git repository")
        })?;
        crate::cache_gc::force_gc_for_path(&db_path, &repo, &root)
            .map(|_| ())
            .map_err(SearchToolsServiceError::internal)
    }

    fn handle_refresh(&self, arguments: Value) -> Result<ToolOutput, SearchToolsServiceError> {
        brokk_bifrost_analysis::analyzer::without_project_reads(|| {
            let _params = serde_json::from_value::<RefreshParams>(arguments).map_err(|err| {
                SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
            })?;
            let mut guard = self.write_session()?;
            let session = guard.as_mut().ok_or_else(Self::closed_error)?;
            // `refresh` promises a from-disk rebuild: drop the cached workspace
            // listing so `update_all`'s file discovery re-walks the tree and
            // re-unions the git index instead of reusing a cached listing.
            session
                .snapshot
                .analyzer()
                .project()
                .invalidate_cached_file_listing();
            let observation = self.build_progress.begin(self.workspace_generation());
            let next = session
                .snapshot
                .update_all_with_progress(observation.sink());
            session.snapshot = Arc::new(next);
            observation.complete();
            session.refresh_pack_activation();
            session.schedule_index_warm();
            Self::structured_only(refresh_result(session.snapshot.analyzer()))
        })
    }

    /// Incrementally re-analyze exactly the given project-relative paths, reusing the
    /// existing analysis for every other file. Unlike `refresh` (which rebuilds the
    /// whole project), this is O(changed files) and is how a caller that knows what
    /// changed (e.g. between two checked-out revisions) drives updates cheaply.
    fn handle_update_paths(
        &self,
        arguments: Value,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        brokk_bifrost_analysis::analyzer::without_project_reads(|| {
            let paths: Vec<String> = arguments
                .get("paths")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let mut guard = self.write_session()?;
            let session = guard.as_mut().ok_or_else(Self::closed_error)?;
            let root = session.snapshot.analyzer().project().root().to_path_buf();
            let changed: BTreeSet<ProjectFile> = paths
                .iter()
                .map(|rel| ProjectFile::new(root.clone(), rel.as_str()))
                .collect();
            // Explicit edits and watcher deltas use the same publication path.
            session
                .snapshot
                .analyzer()
                .project()
                .invalidate_cached_file_listing();
            Self::apply_changed_files(session, changed, cancellation)?;
            Self::structured_only(refresh_result(session.snapshot.analyzer()))
        })
    }

    fn handle_activate_workspace(
        &self,
        arguments: Value,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let params =
            serde_json::from_value::<ActivateWorkspaceParams>(arguments).map_err(|err| {
                SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
            })?;

        let raw = PathBuf::from(&params.workspace_path);
        if !raw.is_absolute() {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "workspace_path must be absolute, got: {}",
                params.workspace_path
            )));
        }

        let resolved = resolve_workspace_root(&raw).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!(
                "Failed to resolve workspace path {}: {err}",
                raw.display()
            ))
        })?;

        {
            let session = self.session.write().map_err(|_| {
                SearchToolsServiceError::internal("SearchToolsService lock poisoned")
            })?;
            let mut phase = self.lock_phase();
            if let WorkspacePhase::Bound(bound) = &mut *phase
                && bound.root == resolved
                && matches!(bound.build, WorkspaceBuild::Failed(_))
            {
                // Only explicit activation retries a failed binding. Ordinary
                // observations retain its failure, and an in-flight or installed
                // binding is never restarted. A fresh generation fences old work.
                debug_assert!(session.is_none());
                // A failed-binding retry also publishes a new generation.
                // Resume any retained retirement before changing that state.
                let mut retirement = self
                    .retired_sessions
                    .lock()
                    .expect("session retirement lock poisoned");
                if !retirement.pending.is_empty() {
                    retirement.prepare()?;
                }
                let lifetime = self
                    .lifetimes
                    .reserve(
                        resolved.clone(),
                        self.workspace_generation().wrapping_add(1),
                    )
                    .ok_or_else(|| self.workspace_activation_not_ready())?;
                self.advance_workspace_generation();
                bound.lifetime = Some(lifetime);
                bound.listing = listing_cache_for(self.update_strategy, &resolved);
                bound.build = WorkspaceBuild::NotStarted;
            }
        }
        self.bind_client_workspace_with_result(resolved)
            .map(|(_, output)| output)
    }

    fn handle_get_active_workspace(
        &self,
        arguments: Value,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let _params =
            serde_json::from_value::<GetActiveWorkspaceParams>(arguments).map_err(|err| {
                SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
            })?;
        enum ProbeGuard<'a> {
            Write(std::sync::RwLockWriteGuard<'a, Option<WorkspaceSession>>),
            Read(std::sync::RwLockReadGuard<'a, Option<WorkspaceSession>>),
        }
        let busy = || {
            SearchToolsServiceError::workspace_unavailable(
                "busy",
                "workspace session lock is busy",
                self.lifetimes.retiring(),
            )
        };
        // This is std::sync::RwLock: writer preference depends on the platform.
        // A queued writer can deny try_read even while readers still hold it;
        // the poll then returns busy, never waiting behind readers or writers.
        let mut guard = match self.session.try_write() {
            Ok(guard) => ProbeGuard::Write(guard),
            Err(std::sync::TryLockError::WouldBlock) => match self.session.try_read() {
                Ok(guard) => ProbeGuard::Read(guard),
                Err(std::sync::TryLockError::WouldBlock) => return Err(busy()),
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(SearchToolsServiceError::internal(
                        "SearchToolsService lock poisoned",
                    ));
                }
            },
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(SearchToolsServiceError::internal(
                    "SearchToolsService lock poisoned",
                ));
            }
        };
        // Session before phase, held together through observation and rendering:
        // an error or snapshot from a prior binding can never cross a rebind.
        let mut phase = match self.phase.try_lock() {
            Ok(phase) => phase,
            Err(std::sync::TryLockError::WouldBlock) => return Err(busy()),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(SearchToolsServiceError::internal(
                    "workspace phase lock poisoned",
                ));
            }
        };
        if matches!(*phase, WorkspacePhase::Unbound) && self.workspace_binding_capacity_exhausted()
        {
            return Err(self.workspace_activation_not_ready());
        }
        let mut observed = self.observe_workspace_phase(&mut phase);
        if let ProbeGuard::Write(session) = &mut guard {
            if matches!(observed, Ok(WorkspacePreparation::Finished))
                && let Some(installed) = self.install_finished_build_locked(session, &mut phase)
            {
                observed = installed.map(|()| WorkspacePreparation::Ready);
            }
            if let Some(session) = session.as_mut() {
                let semantic_packs = Arc::clone(&session.semantic_packs);
                if semantic_packs.reap_finished_worker() {
                    session.settle_pack_stage(&semantic_packs);
                }
            }
        }
        let WorkspacePhase::Bound(bound) = &*phase else {
            return Err(Self::unbound_error());
        };
        if !matches!(bound.build, WorkspaceBuild::Failed(_)) {
            observed?;
        }
        let session = match &guard {
            ProbeGuard::Read(session) => session.as_ref(),
            ProbeGuard::Write(session) => session.as_ref(),
        };
        self.active_workspace_output(bound, session)
    }

    fn active_workspace_output(
        &self,
        bound: &BoundWorkspace,
        session: Option<&WorkspaceSession>,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let error = match &bound.build {
            WorkspaceBuild::Failed(error) => Some(error.clone()),
            _ => None,
        };
        let snapshot = self.workspace_build_progress(self.workspace_generation());
        let workspace_build = brokk_bifrost_tools::searchtools::WorkspaceBuildStatus {
            status: snapshot
                .as_ref()
                .map(|s| match s.status {
                    crate::workspace_progress::BuildStatus::Running => "running",
                    crate::workspace_progress::BuildStatus::Completed => "completed",
                    crate::workspace_progress::BuildStatus::Failed => "failed",
                })
                .unwrap_or("completed")
                .to_owned(),
            generation: snapshot
                .as_ref()
                .map_or(self.workspace_generation(), |s| s.generation),
            phase: snapshot.and_then(|s| s.phase),
            error,
        };
        let retiring = self.lifetimes.retiring();
        if let Some(session) = session {
            debug_assert!(matches!(bound.build, WorkspaceBuild::Installed));
            active_workspace_result_for_session(&bound.root, session, workspace_build, retiring)
        } else {
            active_workspace_result(ActiveWorkspaceResult {
                workspace_path: bound.root.display().to_string(),
                usage_index_ready: false,
                semantic_packs_ready: false,
                semantic_model_overlay: SemanticModelOverlayStatus::Pending {
                    stage: SemanticModelWarmStage::ActivatingInstalledPacks,
                    pending_acquisitions: Vec::new(),
                    shipped_pack_acquisition: None,
                },
                session_subset: None,
                analyzer_ready: false,
                workspace_build,
                retiring_workspaces: retiring,
            })
        }
    }

    /// Read-first snapshot acquisition: the exclusive session lock is only
    /// worth taking when the watcher actually has something to apply. Under
    /// `WatchFiles`, peek `ProjectChangeWatcher::has_pending` while holding
    /// only a read lock (reached through the session, since the watcher lives
    /// inside it); if nothing is pending, clone the two `Arc`s under that same
    /// read lock and return without ever taking the write lock. If something
    /// is pending, drop the read guard and take the write lock to apply the
    /// delta as before. A watcher event landing between the peek and the
    /// read-locked clone is picked up at the next call boundary — the same
    /// call-boundary consistency the previous always-write-locked code had
    /// (an event landing right after `apply_watcher_delta` already missed the
    /// current call). Under `Manual`, the watcher is always `Disabled` and
    /// this path never mutates the snapshot, so a read lock always suffices.
    #[cfg(test)]
    fn snapshot_for_query(&self) -> Result<WorkspaceQueryScope, SearchToolsServiceError> {
        self.snapshot_after_updates(None)
    }

    #[cfg(test)]
    fn snapshot_after_updates(
        &self,
        cancellation: Option<&CancellationToken>,
    ) -> Result<WorkspaceQueryScope, SearchToolsServiceError> {
        self.apply_pending_watcher_delta(cancellation)?;
        let guard = self.read_session()?;
        let session = guard.as_ref().ok_or_else(Self::closed_error)?;
        Ok(WorkspaceQueryScope::new(
            Arc::clone(&session.snapshot),
            Arc::clone(&session.document_root),
            session.pack_activation(),
        ))
    }

    /// Apply the watcher's pending delta, taking the write lock only when
    /// there is one. Manual sessions never mutate the snapshot from this path
    /// (no watcher, no implicit updates driven by this call), so they never
    /// take the write lock at all.
    fn apply_pending_watcher_delta(
        &self,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), SearchToolsServiceError> {
        if self.update_strategy == UpdateStrategy::Manual {
            return Ok(());
        }
        {
            let guard = self.read_session()?;
            let session = guard.as_ref().ok_or_else(Self::closed_error)?;
            if !Self::session_watcher_has_pending(session) {
                return Ok(());
            }
        }
        let mut guard = self.write_session()?;
        let session = guard.as_mut().ok_or_else(Self::closed_error)?;
        Self::apply_watcher_delta(session, cancellation)
    }

    /// Settle this snapshot's installed stage without holding the session
    /// lock while waiting. A deferred refresh first waits for the single
    /// worker slot, then its replacement's installed stage. Ordinary expensive
    /// acquisition remains asynchronous. Library callers without a token have
    /// no deadline, including while waiting for that slot.
    fn settle_installed_pack_stage(
        &self,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(Arc<WorkspaceAnalyzer>, Arc<SemanticPackWarm>), SearchToolsServiceError> {
        loop {
            check_snapshot_cancellation(cancellation)?;
            let (semantic_packs, deferred) = {
                let guard = self.read_session()?;
                let session = guard.as_ref().ok_or_else(Self::closed_error)?;
                (
                    Arc::clone(&session.semantic_packs),
                    session.refresh != PackRefresh::Idle,
                )
            };
            #[cfg(test)]
            self.observe_snapshot_acquisition(SnapshotAcquisitionPoint::BeforeInstalledWait);
            if deferred {
                semantic_packs.wait_for_worker_exit(cancellation)?;
            } else {
                semantic_packs.wait_for_installed_stage(cancellation)?;
            }
            check_snapshot_cancellation(cancellation)?;
            let mut guard = self.write_session()?;
            let session = guard.as_mut().ok_or_else(Self::closed_error)?;
            session.settle_pack_stage(&semantic_packs);
            if Arc::ptr_eq(&session.semantic_packs, &semantic_packs)
                && session.refresh == PackRefresh::Idle
            {
                return Ok((Arc::clone(&session.snapshot), semantic_packs));
            }
        }
    }

    /// Apply delivered watcher deltas and settle the snapshot actually cloned
    /// by the query. Success is observed and cloned under one read guard:
    /// no pending delta and the same snapshot and installed stage as settled.
    /// Continuous edits can delay unbudgeted library calls indefinitely.
    fn snapshot_for_query_with_cancellation(
        &self,
        cancellation: Option<&CancellationToken>,
    ) -> Result<WorkspaceQueryScope, SearchToolsServiceError> {
        self.ensure_ready_with_cancellation(cancellation)?;
        loop {
            check_snapshot_cancellation(cancellation)?;
            self.apply_pending_watcher_delta(cancellation)?;
            let (snapshot, semantic_packs) = self.settle_installed_pack_stage(cancellation)?;
            #[cfg(test)]
            self.observe_snapshot_acquisition(SnapshotAcquisitionPoint::AfterSettle);
            let guard = self.read_session()?;
            let session = guard.as_ref().ok_or_else(Self::closed_error)?;
            check_snapshot_cancellation(cancellation)?;
            if Self::session_watcher_has_pending(session)
                || !Arc::ptr_eq(&snapshot, &session.snapshot)
                || !Arc::ptr_eq(&semantic_packs, &session.semantic_packs)
                || session.refresh != PackRefresh::Idle
            {
                continue;
            }
            let activation = session.pack_activation();
            debug_assert!(
                !matches!(activation, SessionPackActivation::WarmPending),
                "a settled query snapshot must not answer from a pending overlay (#13331)"
            );
            return Ok(WorkspaceQueryScope::new(
                Arc::clone(&session.snapshot),
                Arc::clone(&session.document_root),
                activation,
            ));
        }
    }

    #[cfg(test)]
    fn observe_snapshot_acquisition(&self, point: SnapshotAcquisitionPoint) {
        let observer = self.snapshot_acquisition_observer.lock().unwrap().clone();
        if let Some(observer) = observer {
            observer(point);
        }
    }

    /// Whether `session`'s watcher (if active) currently has a delta that a
    /// call to `apply_watcher_delta` would act on. `Manual` sessions always
    /// carry `SessionWatcher::Disabled`, so this is `false` for them too.
    fn session_watcher_has_pending(session: &WorkspaceSession) -> bool {
        match &session.watcher {
            SessionWatcher::Disabled => false,
            SessionWatcher::Active(watcher) => watcher.has_pending(),
        }
    }

    fn handle_get_symbol_sources(
        &self,
        arguments: Value,
        render_options: RenderOptions,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let params = serde_json::from_value::<SymbolLookupParams>(arguments).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
        })?;
        let initial_snapshot = self.snapshot_for_query_with_cancellation(cancellation)?;
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(SearchToolsServiceError::internal(
                "get_symbol_sources was cancelled or exceeded its request-wide time budget",
            ));
        }
        let mut result = get_symbol_sources_with_source_budget(
            initial_snapshot.enter().analyzer(),
            params.clone(),
            GET_SYMBOL_SOURCES_RESPONSE_BUDGET_BYTES,
            cancellation,
        )
        .map_err(Self::symbol_sources_budget_error)?;
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            result.complete = false;
            let output = Self::symbol_sources_output(result, render_options);
            return initial_snapshot.finish("get_symbol_sources", output);
        }
        if self.update_strategy == UpdateStrategy::WatchFiles {
            let candidate_files =
                symbol_source_candidate_files(initial_snapshot.enter().analyzer(), &result);

            // Compute the stale set from a read-locked snapshot; the disk
            // reads inside `stale_symbol_source_files` happen with no session
            // lock held at all. Only take the write lock when there is
            // something to apply.
            let peek_snapshot = {
                let guard = self.read_session()?;
                let session = guard.as_ref().ok_or_else(Self::closed_error)?;
                Arc::clone(&session.snapshot)
            };
            let stale_files = stale_symbol_source_files(peek_snapshot.analyzer(), candidate_files)?;
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                result.complete = false;
                let output = Self::symbol_sources_output(result, render_options);
                return initial_snapshot.finish("get_symbol_sources", output);
            }

            let final_snapshot = if stale_files.is_empty() {
                None
            } else {
                let mut guard = self.write_session()?;
                let session = guard.as_mut().ok_or_else(Self::closed_error)?;
                Self::apply_watcher_delta(session, cancellation)?;
                // Re-validate under the write lock: another thread may have
                // applied a watcher delta between the read-locked peek above
                // and now, which can make a file the peek considered stale
                // fresh again (or vice versa), so recompute against the
                // now-current session snapshot rather than trusting the peek.
                let analyzer = session.snapshot.analyzer();
                let stale_files = stale_symbol_source_files(analyzer, stale_files)?;
                Self::apply_changed_files(session, stale_files, cancellation)?;
                Some(Arc::clone(&session.snapshot))
            };

            if let Some(final_snapshot) =
                final_snapshot.filter(|snapshot| !initial_snapshot.has_source(snapshot))
            {
                let final_snapshot = initial_snapshot.scope_snapshot(final_snapshot);
                result = get_symbol_sources_with_source_budget(
                    final_snapshot.enter().analyzer(),
                    params,
                    GET_SYMBOL_SOURCES_RESPONSE_BUDGET_BYTES,
                    cancellation,
                )
                .map_err(Self::symbol_sources_budget_error)?;
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    result.complete = false;
                }
                let output = Self::symbol_sources_output(result, render_options);
                return final_snapshot.finish("get_symbol_sources", output);
            }
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            result.complete = false;
        }
        let output = Self::symbol_sources_output(result, render_options);
        initial_snapshot.finish("get_symbol_sources", output)
    }

    fn symbol_sources_output(
        result: SymbolSourcesResult,
        render_options: RenderOptions,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let source_bytes = result
            .sources
            .iter()
            .map(|source| source.text.len())
            .sum::<usize>();
        if source_bytes > GET_SYMBOL_SOURCES_RESPONSE_BUDGET_BYTES {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "get_symbol_sources resolved {source_bytes} bytes of source, exceeding the {GET_SYMBOL_SOURCES_RESPONSE_BUDGET_BYTES}-byte response budget; re-call with fewer or narrower symbols"
            )));
        }
        let rendered_text = {
            let _render_scope = profiling::scope("searchtools.get_symbol_sources.mcp_rendering");
            result.render_text(render_options)
        };
        let structured = serde_json::to_value(result).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })?;
        Ok(ToolOutput::Structured {
            structured,
            rendered_text: Some(rendered_text),
        })
    }

    fn symbol_sources_budget_error(
        exceeded: brokk_bifrost_tools::searchtools::SymbolSourcesBudgetExceeded,
    ) -> SearchToolsServiceError {
        SearchToolsServiceError::invalid_params(format!(
            "get_symbol_sources exceeded the {}-byte response budget while resolving source; re-call with fewer or narrower symbols",
            exceeded.max_source_bytes()
        ))
    }

    /// Bring the files a request names up to date when the watcher has not
    /// delivered their change yet, and report whether the snapshot moved.
    ///
    /// A request must observe the current content of every file it names, and
    /// an editor's request routinely arrives before the watcher's event for
    /// the save it follows. Checking the named files directly (a read and a
    /// comparison with the indexed source each) costs what the request names,
    /// not what the worktree holds. Other files stay as fresh as the watcher
    /// has made them, exactly as before.
    fn apply_stale_named_files(
        &self,
        named: &[String],
        cancellation: Option<&CancellationToken>,
    ) -> Result<bool, SearchToolsServiceError> {
        brokk_bifrost_analysis::analyzer::without_project_reads(|| {
            if self.update_strategy != UpdateStrategy::WatchFiles || named.is_empty() {
                return Ok(false);
            }
            let _scope = profiling::scope("SearchToolsService::apply_stale_named_files");
            let peek_snapshot = {
                let guard = self.read_session()?;
                let session = guard.as_ref().ok_or_else(Self::closed_error)?;
                Arc::clone(&session.snapshot)
            };
            let root = peek_snapshot.analyzer().project().root().to_path_buf();
            let candidates = named
                .iter()
                .map(|path| ProjectFile::new(root.clone(), PathBuf::from(path)))
                .filter(|file| file.abs_path().is_file())
                .collect::<BTreeSet<_>>();
            let stale = stale_symbol_source_files(peek_snapshot.analyzer(), candidates)?;
            if stale.is_empty() {
                return Ok(false);
            }
            let mut guard = self.write_session()?;
            let session = guard.as_mut().ok_or_else(Self::closed_error)?;
            Self::apply_watcher_delta(session, cancellation)?;
            // Another thread may have applied the change between the peek and the
            // write lock; recompute against the now-current snapshot.
            let stale = stale_symbol_source_files(session.snapshot.analyzer(), stale)?;
            Self::apply_changed_files(session, stale, cancellation)?;
            Ok(true)
        })
    }

    fn apply_watcher_delta(
        session: &mut WorkspaceSession,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), SearchToolsServiceError> {
        brokk_bifrost_analysis::analyzer::without_project_reads(|| {
            let _scope = profiling::scope("SearchToolsService::apply_watcher_delta");
            let watcher = match &mut session.watcher {
                SessionWatcher::Disabled => return Ok(()),
                SessionWatcher::Active(watcher) => watcher,
            };

            let delta = {
                let _scope = profiling::scope("SearchToolsService::take_changed_files");
                watcher
                    .rearm_exclude_watch()
                    .map_err(SearchToolsServiceError::internal)?;
                watcher.take_changed_files()
            };
            if profiling::enabled() {
                profiling::note(format!(
                    "watcher_delta files={} full_refresh={}",
                    delta.files.len(),
                    delta.requires_full_refresh
                ));
            }
            if delta.requires_full_refresh {
                session.snapshot = Arc::new({
                    let _scope = profiling::scope("SearchToolsService::snapshot_update_all");
                    Self::update_session_snapshot(session, None, cancellation)
                });
                session.refresh_pack_activation();
                session.schedule_index_warm();
                return Ok(());
            }

            // An event can name content the snapshot already indexed: an edit
            // that `refresh` or `update_paths` read before the watcher
            // reported it. Applying it would build an identical snapshot and
            // restart pack activation for nothing, leaving the next answer
            // pending on that warm (#12441). Unindexed inputs such as
            // manifests and deleted files never match, so they always apply.
            let changed_files = stale_symbol_source_files(
                session.snapshot.analyzer(),
                delta.files.into_iter().collect(),
            )?;
            if delta.revalidate_listing {
                if changed_files.is_empty() {
                    let project = session.snapshot.analyzer().project();
                    // Structural Unknown inputs already require a walk on each
                    // real update. Keep the pre-#13071 behavior for index-only
                    // churn there; the next real update observes its membership.
                    // An ignore-rule edit (info/exclude) always revalidates, as
                    // it did before #13071.
                    if !delta.ignore_input_changed && project.listing_receipt_structurally_unknown()
                    {
                        return Ok(());
                    }
                    match session.snapshot.revalidate_listing_membership() {
                        Ok(false) => return Ok(()),
                        Ok(true) => {}
                        Err(error) => {
                            // The normal update publishes the failure and
                            // keeps retry obligations visible to readers.
                            tracing::warn!(%error, "watcher listing revalidation failed");
                        }
                    }
                }
                Self::apply_snapshot_update(session, changed_files, cancellation)
            } else {
                Self::apply_changed_files(session, changed_files, cancellation)
            }
        })
    }

    fn update_session_snapshot(
        session: &WorkspaceSession,
        changed_files: Option<&BTreeSet<ProjectFile>>,
        cancellation: Option<&CancellationToken>,
    ) -> WorkspaceAnalyzer {
        let root = session.snapshot.analyzer().project().root();
        let prospective = load_workspace_packs_config_at(root)
            .map_err(|error| error.to_string())
            .and_then(|packs| configured_semantic_models().map(|configured| (packs, configured)));
        let prospective = match prospective {
            Ok(inputs) => Some(inputs),
            Err(error) => {
                // Missing fresh authority disallows reuse, but the source
                // update still proceeds. Activation reports the input error.
                tracing::warn!(%error, "semantic-model reuse proof unavailable; updating workspace with Pending models");
                None
            }
        };
        let state = session.semantic_packs.best_known_state();
        let source = state
            .as_ref()
            .and_then(|state| state.update_source.as_ref());
        let config = workspace_activation_config(&session.snapshot);
        let uncancelled = CancellationToken::default();
        let context = source.and_then(|source| {
            let (packs_config, configured) = prospective.as_ref()?;
            source.context(
                &config,
                WorkspaceActivationSources {
                    catalog_root: root,
                    workspace_model_root: configured
                        .as_ref()
                        .is_some_and(|config| config.workspace_models)
                        .then_some(root),
                    config: packs_config.as_ref(),
                    intrinsic_shipped_models: crate::analyzer::packs_document::semantic_model_catalog_bootstrap_configured(),
                },
                &[],
                cancellation.unwrap_or(&uncancelled),
            )
        });
        match changed_files {
            Some(changed) => session
                .snapshot
                .update_with_activation_context(changed, context),
            None => session.snapshot.update_all_with_activation_context(context),
        }
    }

    fn apply_changed_files(
        session: &mut WorkspaceSession,
        changed_files: BTreeSet<ProjectFile>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), SearchToolsServiceError> {
        brokk_bifrost_analysis::analyzer::without_project_reads(|| {
            if changed_files.is_empty() {
                return Ok(());
            }
            Self::apply_snapshot_update(session, changed_files, cancellation)
        })
    }

    fn apply_snapshot_update(
        session: &mut WorkspaceSession,
        changed_files: BTreeSet<ProjectFile>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), SearchToolsServiceError> {
        brokk_bifrost_analysis::analyzer::without_project_reads(|| {
            if profiling::enabled() {
                profiling::note(format!("snapshot_changed_files={}", changed_files.len()));
            }
            let refresh_global_inputs = changed_files_refresh_global_pack_inputs(&changed_files);
            session.snapshot = Arc::new({
                let _scope = profiling::scope("SearchToolsService::snapshot_update");
                Self::update_session_snapshot(session, Some(&changed_files), cancellation)
            });
            let refresh_packs = refresh_global_inputs || session.pack_activation_scope_changed();
            let stale = session.snapshot.stale_dependency_ecosystems();
            if !refresh_packs {
                session.refresh_updated_contexts(&changed_files, cancellation)?;
            }
            if refresh_packs || session.snapshot.requires_whole_dependency_refresh() {
                // Activation already rediscovers tool contexts for this snapshot.
                session.refresh_pack_activation();
            } else if !stale.is_empty() {
                session.refresh_dependency_ecosystems(&stale);
            } else if matches!(
                session.snapshot.analyzer().semantic_model_overlay_read(),
                crate::analyzer::semantic_model::SemanticModelOverlayRead::Pending(_)
            ) {
                // Scoped dependency refreshes preserve sibling evidence. Only
                // model-only invalidation needs the whole activation path.
                // That path coalesces with an already running warm.
                session.refresh_pack_activation();
            }
            session.schedule_index_warm();
            Ok(())
        })
    }

    fn decode_and_run<P, R>(
        workspace: &WorkspaceAnalyzer,
        arguments: Value,
        handler: impl FnOnce(&WorkspaceAnalyzer, P) -> R,
    ) -> Result<ToolOutput, SearchToolsServiceError>
    where
        P: serde::de::DeserializeOwned,
        R: Serialize,
    {
        let params = Self::decode_tool_params(arguments)?;
        let result = handler(workspace, params);
        let structured = serde_json::to_value(result).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })?;
        Ok(ToolOutput::Structured {
            structured,
            rendered_text: None,
        })
    }

    fn validate_scan_usages_by_reference_arguments(
        arguments: &Value,
    ) -> Result<(), SearchToolsServiceError> {
        let valid_symbols = arguments
            .get("symbols")
            .and_then(Value::as_array)
            .is_some_and(|symbols| {
                !symbols.is_empty()
                    && symbols.iter().all(|symbol| {
                        symbol
                            .as_str()
                            .is_some_and(|value| !value.trim().is_empty())
                    })
            });

        if !valid_symbols {
            return Err(SearchToolsServiceError::invalid_params(
                "scan_usages_by_reference requires a non-empty `symbols` array of non-blank strings",
            ));
        }
        Self::validate_scan_usages_scope_arguments(arguments, "scan_usages_by_reference")
    }

    fn validate_scan_usages_by_location_arguments(
        arguments: &Value,
    ) -> Result<(), SearchToolsServiceError> {
        let targets = arguments
            .get("targets")
            .and_then(Value::as_array)
            .filter(|targets| !targets.is_empty())
            .ok_or_else(|| {
                SearchToolsServiceError::invalid_params(
                    "scan_usages_by_location requires a non-empty `targets` array",
                )
            })?;
        for (index, target) in targets.iter().enumerate() {
            let valid = target.as_object().is_some_and(|target| {
                target
                    .get("path")
                    .and_then(Value::as_str)
                    .is_some_and(|path| !path.trim().is_empty())
                    && target
                        .get("line")
                        .and_then(Value::as_u64)
                        .is_some_and(|line| line > 0)
                    && target
                        .get("column")
                        .is_none_or(|column| column.as_u64().is_some_and(|column| column > 0))
                    && target.get("symbol").is_none_or(|symbol| {
                        symbol
                            .as_str()
                            .is_some_and(|symbol| !symbol.trim().is_empty())
                    })
            });
            if !valid {
                return Err(SearchToolsServiceError::invalid_params(format!(
                    "scan_usages_by_location target {} requires a non-blank `path`, a positive 1-based `line`, an optional positive 1-based `column`, and an optional non-blank `symbol`",
                    index + 1
                )));
            }
        }
        Self::validate_scan_usages_scope_arguments(arguments, "scan_usages_by_location")
    }

    fn validate_scan_usages_scope_arguments(
        arguments: &Value,
        tool_name: &str,
    ) -> Result<(), SearchToolsServiceError> {
        if arguments.get("max_duration_secs").is_some() {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "{tool_name} does not accept `max_duration_secs`; deadline policy belongs to the frontend"
            )));
        }
        if arguments
            .get("include_tests")
            .is_some_and(|value| !value.is_boolean())
        {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "{tool_name} requires `include_tests` to be a boolean"
            )));
        }
        if arguments
            .get("include_same_owner")
            .is_some_and(|value| !value.is_boolean())
        {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "{tool_name} requires `include_same_owner` to be a boolean"
            )));
        }
        if arguments.get("paths").is_some_and(|paths| {
            !paths
                .as_array()
                .is_some_and(|paths| paths.iter().all(Value::is_string))
        }) {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "{tool_name} requires `paths` to be an array of strings"
            )));
        }
        Ok(())
    }

    fn decode_render_and_run<P, R>(
        workspace: &WorkspaceAnalyzer,
        arguments: Value,
        render_options: RenderOptions,
        handler: impl FnOnce(&WorkspaceAnalyzer, P) -> R,
    ) -> Result<ToolOutput, SearchToolsServiceError>
    where
        P: serde::de::DeserializeOwned,
        R: Serialize + RenderText,
    {
        Self::decode_render_and_try_run(
            workspace,
            arguments,
            render_options,
            |workspace, params| Ok(handler(workspace, params)),
        )
    }

    fn decode_render_and_try_run<P, R>(
        workspace: &WorkspaceAnalyzer,
        arguments: Value,
        render_options: RenderOptions,
        handler: impl FnOnce(&WorkspaceAnalyzer, P) -> Result<R, String>,
    ) -> Result<ToolOutput, SearchToolsServiceError>
    where
        P: serde::de::DeserializeOwned,
        R: Serialize + RenderText,
    {
        let params = Self::decode_tool_params(arguments)?;
        let result = handler(workspace, params).map_err(SearchToolsServiceError::invalid_params)?;
        let rendered_text = result.render_text(render_options);
        let structured = serde_json::to_value(result).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })?;
        Ok(ToolOutput::Structured {
            structured,
            rendered_text: Some(rendered_text),
        })
    }

    fn decode_tool_params<P: serde::de::DeserializeOwned>(
        arguments: Value,
    ) -> Result<P, SearchToolsServiceError> {
        serde_json::from_value::<P>(arguments).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
        })
    }

    fn policy_suppression_preflight(
        &self,
        options: &PolicyEvaluationOptions,
    ) -> Result<crate::policy::PolicySuppressionPreflight, SearchToolsServiceError> {
        let root = self.service_root()?;
        crate::policy::preflight_policy_suppressions(&root, options).map_err(|error| {
            SearchToolsServiceError::internal(format!(
                "run_policy suppression preflight failed: {error}"
            ))
        })
    }

    pub(crate) fn preflight_run_policy(
        &self,
        arguments: &Value,
    ) -> Result<RunPolicyPreflight, SearchToolsServiceError> {
        let selection_started = Instant::now();
        let decoded = decode_run_policy_arguments(arguments.clone())?;
        let selection_elapsed = selection_started.elapsed();
        let preflight_started = Instant::now();
        let preflight = self.policy_suppression_preflight(&decoded.options)?;
        let preflight_elapsed = preflight_started.elapsed();
        if preflight.is_valid() {
            return Ok(RunPolicyPreflight::Valid(PreparedRunPolicyPreflight {
                suppression_preflight: preflight,
                selection_elapsed,
                suppression_preflight_elapsed: preflight_elapsed,
            }));
        }
        let outcome = crate::policy::suppression_preflight_failure_outcome(
            &decoded.options,
            preflight,
            selection_elapsed,
            preflight_elapsed,
        )
        .map_err(|error| {
            SearchToolsServiceError::internal(format!(
                "failed to construct suppression preflight policy report: {error}"
            ))
        })?;
        Ok(RunPolicyPreflight::Invalid(Self::structured_only(
            RunPolicyToolResult {
                status: "unreliable",
                exit_status: outcome.exit_status(),
                stage_timings: decoded
                    .include_stage_timings
                    .then(|| outcome.stage_attribution().to_vec()),
                report: outcome.into_report(),
            },
        )?))
    }

    #[cfg(test)]
    pub(crate) fn prepare_run_policy_with_cancellation(
        &self,
        arguments: Value,
        cancellation: Option<&CancellationToken>,
    ) -> Result<RunPolicyPreparation, SearchToolsServiceError> {
        self.prepare_run_policy_with_cancellation_and_preflight(arguments, cancellation, None)
    }

    pub(crate) fn prepare_run_policy_with_cancellation_and_preflight(
        &self,
        arguments: Value,
        cancellation: Option<&CancellationToken>,
        supplied_preflight: Option<PreparedRunPolicyPreflight>,
    ) -> Result<RunPolicyPreparation, SearchToolsServiceError> {
        let preparation_started = Instant::now();
        let decoded = decode_run_policy_arguments(arguments)?;
        let decode_selection_elapsed = preparation_started.elapsed();
        let DecodedRunPolicy {
            sources,
            inline_suppression_prefix,
            policy_inputs,
            selected_policy_ids,
            options,
            include_stage_timings,
        } = decoded;
        let root = self.service_root()?;
        let (sources, options) = crate::scoped_project::prepare_policy_source_request(
            &root,
            &sources,
            inline_suppression_prefix.as_deref(),
            options,
        )
        .map_err(SearchToolsServiceError::invalid_params)?;
        let (suppression_preflight, selection_elapsed, suppression_preflight_elapsed) =
            match supplied_preflight {
                Some(preflight) => (
                    preflight.suppression_preflight,
                    preflight
                        .selection_elapsed
                        .saturating_add(decode_selection_elapsed),
                    preflight.suppression_preflight_elapsed,
                ),
                None => {
                    let preflight_started = Instant::now();
                    let preflight = self.policy_suppression_preflight(&options)?;
                    (
                        preflight,
                        decode_selection_elapsed,
                        preflight_started.elapsed(),
                    )
                }
            };
        if suppression_preflight.is_valid() {
            let preparation = RunPolicySnapshotPreparation {
                sources,
                policy_inputs,
                selected_policy_ids,
                options,
                suppression_preflight,
                selection_elapsed,
                suppression_preflight_elapsed,
                snapshot_started: Instant::now(),
                include_stage_timings,
            };
            return self.prepare_run_policy_after_preflight(preparation, cancellation);
        }
        let outcome = crate::policy::suppression_preflight_failure_outcome(
            &options,
            suppression_preflight,
            selection_elapsed,
            suppression_preflight_elapsed,
        )
        .map_err(|error| {
            SearchToolsServiceError::internal(format!(
                "failed to construct suppression preflight policy report: {error}"
            ))
        })?;
        Ok(RunPolicyPreparation::PreflightFailure(Box::new(
            RunPolicyToolResult {
                status: "unreliable",
                exit_status: outcome.exit_status(),
                stage_timings: include_stage_timings.then(|| outcome.stage_attribution().to_vec()),
                report: outcome.into_report(),
            },
        )))
    }

    fn prepare_run_policy_after_preflight(
        &self,
        preparation: RunPolicySnapshotPreparation,
        cancellation: Option<&CancellationToken>,
    ) -> Result<RunPolicyPreparation, SearchToolsServiceError> {
        let RunPolicySnapshotPreparation {
            sources,
            policy_inputs,
            selected_policy_ids,
            options,
            suppression_preflight,
            selection_elapsed,
            suppression_preflight_elapsed,
            snapshot_started,
            include_stage_timings,
        } = preparation;
        loop {
            let workspace_generation = self.workspace_generation();
            let snapshot_result = {
                let _scope = profiling::scope("run_policy.snapshot_for_query");
                self.snapshot_for_query_with_cancellation(cancellation)
            };
            let snapshot = match snapshot_result {
                Ok(snapshot) => snapshot,
                Err(error)
                    if error.code == SearchToolsServiceErrorCode::DeadlineExceeded
                        && cancellation.is_some_and(CancellationToken::is_timed_out) =>
                {
                    let outcome = workspace_snapshot_deadline_outcome_with_preflight(
                        &options,
                        selected_policy_ids,
                        selection_elapsed,
                        &suppression_preflight,
                        suppression_preflight_elapsed,
                        snapshot_started.elapsed(),
                    )
                    .map_err(|error| {
                        SearchToolsServiceError::internal(format!(
                            "failed to construct workspace deadline policy report: {error}"
                        ))
                    })?;
                    let result = RunPolicyToolResult {
                        status: "unreliable",
                        exit_status: outcome.exit_status(),
                        stage_timings: include_stage_timings
                            .then(|| outcome.stage_attribution().to_vec()),
                        report: outcome.into_report(),
                    };
                    return Ok(RunPolicyPreparation::Deadline(Box::new(result)));
                }
                Err(error) => return Err(error),
            };
            if workspace_generation != self.workspace_generation() {
                continue;
            }
            let root = snapshot.enter().analyzer().project().root().to_path_buf();
            return Ok(RunPolicyPreparation::Ready(Box::new(PreparedRunPolicy {
                sources,
                workspace_generation,
                snapshot,
                root,
                policy_inputs,
                options,
                selection_elapsed,
                suppression_preflight: Some(suppression_preflight),
                suppression_preflight_elapsed,
                snapshot_elapsed: snapshot_started.elapsed(),
                include_stage_timings,
            })));
        }
    }

    /// `flow_query`: a flow or reachability question between selected points
    /// (#13213). The host's request deadline wraps this call like every tool;
    /// a cold workspace returns the typed not-ready result from the snapshot
    /// wait, never from here.
    pub(crate) fn handle_flow_query(
        &self,
        arguments: Value,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let params = serde_json::from_value::<crate::flow_query::FlowQueryParams>(arguments)
            .map_err(|error| {
                SearchToolsServiceError::invalid_params(format!(
                    "Invalid flow_query arguments: {error}"
                ))
            })?;
        let snapshot = self.snapshot_for_query_with_cancellation(cancellation)?;
        let uncancelled = CancellationToken::default();
        let result = (|| {
            let entered = snapshot.enter();
            let answer = crate::flow_query::run_flow_query(
                &entered,
                &self.flow_state,
                &params,
                cancellation.unwrap_or(&uncancelled),
            )
            .map_err(|error| match error {
                crate::flow_query::FlowQueryError::Invalid(message) => {
                    SearchToolsServiceError::invalid_params(message)
                }
                crate::flow_query::FlowQueryError::Internal(message) => {
                    SearchToolsServiceError::internal(message)
                }
                crate::flow_query::FlowQueryError::PresentationRefused(cause) => {
                    SearchToolsServiceError::internal(format!(
                        "flow_query result presentation refused: {cause:?}"
                    ))
                }
            })?;
            Self::structured_only(answer)
        })();
        snapshot.finish("flow_query", result)
    }

    /// Answer one bounded `why` or `why-not` question about one policy.
    ///
    /// This reuses the same immutable workspace snapshot `run_policy` uses, so
    /// an explanation describes the generation the caller is already querying.
    /// It loads no suppressions, scope, or baseline and computes no exit
    /// status: an explanation is a query, not a gate.
    pub(crate) fn handle_explain_policy(
        &self,
        arguments: Value,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let params = serde_json::from_value::<ExplainPolicyParams>(arguments).map_err(|error| {
            SearchToolsServiceError::invalid_params(format!(
                "Invalid explain_policy arguments: {error}"
            ))
        })?;
        let question = explain_policy_question(&params)?;
        let generation = explain_policy_generation(&params)?;
        let policy_inputs = explain_policy_inputs_from(&params)?;

        loop {
            let workspace_generation = self.workspace_generation();
            let snapshot = {
                let _scope = profiling::scope("explain_policy.snapshot_for_query");
                self.snapshot_for_query_with_cancellation(cancellation)?
            };
            if workspace_generation != self.workspace_generation() {
                continue;
            }
            let root = snapshot.enter().analyzer().project().root().to_path_buf();
            let result = (|| {
                // One generation: the session's activation and the analyzer
                // publication of this same query snapshot.
                let pack_activation = &snapshot.pack_activation;
                let snapshot = snapshot.enter();
                let semantic_models = pack_activation.semantic_model_read(snapshot.analyzer());
                let _scope = profiling::scope("explain_policy.explain_policy_inputs");
                let answer = match &question {
                    ExplainPolicyQuestion::Explanation(target) => {
                        ExplainPolicyToolResult::Explanation {
                            explanation: Box::new(
                                explain_policy_inputs_with_semantic_models(
                                    &root,
                                    &policy_inputs,
                                    target,
                                    generation,
                                    Some(&snapshot),
                                    Some(semantic_models),
                                    Some(&self.flow_state),
                                    cancellation,
                                    &ExplanationLimits::default(),
                                    &self.retention_budget,
                                )
                                .map_err(explain_error_to_service_error)?,
                            ),
                        }
                    }
                    ExplainPolicyQuestion::NearMiss(candidates, limits) => {
                        ExplainPolicyToolResult::NearMiss {
                            near_miss_ranking: Box::new(
                                rank_policy_near_misses_with_semantic_models(
                                    &root,
                                    &policy_inputs,
                                    candidates,
                                    generation,
                                    Some(&snapshot),
                                    Some(semantic_models),
                                    Some(&self.flow_state),
                                    cancellation,
                                    limits,
                                    &self.retention_budget,
                                )
                                .map_err(explain_error_to_service_error)?,
                            ),
                        }
                    }
                };
                Self::structured_only(answer)
            })();
            return snapshot.finish("explain_policy", result);
        }
    }

    pub(crate) fn execute_prepared_run_policy(
        &self,
        prepared: PreparedRunPolicy,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let PreparedRunPolicy {
            sources,
            workspace_generation,
            snapshot,
            root,
            policy_inputs,
            options,
            selection_elapsed,
            suppression_preflight,
            suppression_preflight_elapsed,
            snapshot_elapsed,
            include_stage_timings,
        } = prepared;
        let refuse_stale_sources = |message: String| SearchToolsServiceError {
            code: ExplanationGeneration::of(snapshot.enter().analyzer())
                .map(
                    |requested| SearchToolsServiceErrorCode::StaleWorkspaceGeneration {
                        requested,
                        current: None,
                    },
                )
                .unwrap_or(SearchToolsServiceErrorCode::Internal),
            message,
            // A server-side reload would silently publish unreported edits.
            workspace_incomplete: None,
            retryable_stale_generation: false,
        };
        // This is the publication lock used by update_paths and watcher application.
        // Keep it until scoped consumption finishes, including snapshot validation.
        let publication_guard = if sources.is_empty() {
            None
        } else {
            Some(self.write_session()?)
        };
        if publication_guard
            .as_ref()
            .is_some_and(|guard| guard.is_some())
            && workspace_generation != self.workspace_generation()
        {
            return Err(refuse_stale_sources(
                "workspace changed before scoped policy evaluation; update_paths and retry"
                    .to_owned(),
            ));
        }
        let mut resident_members = std::collections::BTreeSet::new();
        if publication_guard
            .as_ref()
            .is_some_and(|guard| guard.is_some())
        {
            let resident = snapshot.enter();
            let inventory = resident.analyzer().indexed_source_files();
            if !inventory.complete {
                return Err(refuse_stale_sources(
                    "resident indexed membership is incomplete; update_paths and retry".to_owned(),
                ));
            }
            let paths: Vec<String> = inventory
                .rows
                .iter()
                .map(|file| file.rel_path().to_string_lossy().replace('\\', "/"))
                .collect();
            for source in &sources {
                if source.trim().is_empty() {
                    continue;
                }
                let expected =
                    crate::scoped_project::resident_source_members(&root, source, &paths)
                        .map_err(SearchToolsServiceError::invalid_params)?;
                resident_members.extend(expected.iter().cloned());
                let live =
                    crate::scoped_project::resolve_sources(&root, std::slice::from_ref(source));
                match live {
                    Ok(live)
                        if owned_policy_source_paths(resident.analyzer(), &root, &live)
                            == expected => {}
                    Err(error) if expected.is_empty() => {
                        return Err(SearchToolsServiceError::invalid_params(error));
                    }
                    _ => {
                        return Err(refuse_stale_sources(format!(
                            "source membership differs from resident snapshot: {source}; update_paths and retry"
                        )));
                    }
                }
            }
        }
        let scoped_service = if sources.is_empty() {
            None
        } else {
            Some(
                crate::scoped_project::create_scoped_service_with_options(
                    root.clone(),
                    &sources,
                    None,
                    crate::scoped_project::ScopedProjectOptions::default()
                        .with_host_activation_context(Arc::clone(self.host_activation_context())),
                )
                .map_err(SearchToolsServiceError::invalid_params)?,
            )
        };
        let snapshot = if let Some(scoped) = &scoped_service {
            let scoped_snapshot = scoped.snapshot_for_query_with_cancellation(cancellation)?;
            if publication_guard
                .as_ref()
                .is_some_and(|guard| guard.is_some())
            {
                let resident = snapshot.enter();
                let selected = scoped_snapshot.enter();
                let selected_paths: std::collections::BTreeSet<_> = selected
                    .analyzer()
                    .project()
                    .all_files()
                    .map_err(|error| SearchToolsServiceError::internal(error.to_string()))?
                    .iter()
                    .filter(|file| resident.analyzer().owns_source_file(file))
                    .map(|file| file.rel_path().to_path_buf())
                    .collect();
                if selected_paths != resident_members {
                    return Err(refuse_stale_sources("source membership changed during scoped construction; update_paths and retry".to_owned()));
                }
                for file in selected
                    .analyzer()
                    .project()
                    .all_files()
                    .map_err(|error| SearchToolsServiceError::internal(error.to_string()))?
                    .iter()
                {
                    if !resident.analyzer().owns_source_file(file) {
                        continue;
                    }
                    let oid = selected.analyzer().indexed_blob_oid(file);
                    if oid.is_none() || oid != resident.analyzer().indexed_blob_oid(file) {
                        return Err(refuse_stale_sources(format!(
                            "scoped source differs from resident snapshot: {file:?}; update_paths and retry"
                        )));
                    }
                }
            }
            snapshot.finish("run_policy.source_fence", Ok(()))?;
            scoped_snapshot
        } else {
            snapshot
        };
        let result = (|| {
            let snapshot = snapshot.enter();
            let _scope = profiling::scope("run_policy.evaluate_policy_inputs");
            // The coordinator analyzes this session's project under the policy
            // configuration and activates the policy's semantic sources itself,
            // as every entry point does (#3735).
            let policy_service = scoped_service.as_ref().unwrap_or(self);
            let runtime =
                CodeIntelligenceRuntime::new(&snapshot, &policy_service.flow_state, cancellation);
            // The head evaluation is the other long stretch of a policy
            // request: name it so a budgeted host reports the phase that spent
            // the budget rather than the tool (issue #3170).
            let mut outcome = {
                let _phase = cancellation.map(|cancellation| {
                    cancellation.enter_phase(format!(
                        "evaluating {} policies against the workspace snapshot",
                        policy_inputs.len()
                    ))
                });
                match suppression_preflight {
                    Some(preflight) => runtime.evaluate_policy_inputs_with_suppression_preflight(
                        &root,
                        &policy_inputs,
                        &options,
                        preflight,
                        &policy_service.retention_budget,
                    ),
                    None => runtime.evaluate_policy_inputs(
                        &root,
                        &policy_inputs,
                        &options,
                        &policy_service.retention_budget,
                    ),
                }
                .map_err(|error| {
                    SearchToolsServiceError::internal(format!(
                        "run_policy evaluation failed: {error}"
                    ))
                })?
            };
            outcome.record_preparation_timings(
                selection_elapsed,
                suppression_preflight_elapsed,
                snapshot_elapsed,
            );
            let exit_status = outcome.exit_status();
            let status = outcome.status().label();
            Self::structured_only(RunPolicyToolResult {
                status,
                exit_status,
                stage_timings: include_stage_timings.then(|| outcome.stage_attribution().to_vec()),
                report: outcome.into_report(),
            })
        })();
        snapshot.finish("run_policy", result)
    }

    fn structured_only<R: Serialize>(result: R) -> Result<ToolOutput, SearchToolsServiceError> {
        Self::structured_output(result, None)
    }

    fn structured_output<R: Serialize>(
        result: R,
        rendered_text: Option<String>,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let structured = serde_json::to_value(result).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })?;
        Ok(ToolOutput::Structured {
            structured,
            rendered_text,
        })
    }

    fn rendered_structured<R: Serialize + RenderText>(
        result: R,
        render_options: RenderOptions,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let rendered_text = result.render_text(render_options);
        Self::structured_output(result, Some(rendered_text))
    }

    fn read_session(
        &self,
    ) -> Result<std::sync::RwLockReadGuard<'_, Option<WorkspaceSession>>, SearchToolsServiceError>
    {
        self.ensure_ready()?;
        self.session
            .read()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))
    }

    /// Start the long-lived session's optional query-index warm after a tool
    /// call has finished. Initial workspace installation deliberately leaves
    /// this unscheduled so unrelated cold requests retain priority.
    ///
    /// Every completed call, not only the first: a structural query makes its
    /// provider's posting index outstanding, so the warm that builds it can
    /// only be scheduled after that query returns (#2879). The warmer itself
    /// returns immediately when nothing is outstanding, so the repeats cost a
    /// pair of predicate calls.
    fn schedule_index_warm_after_tool_call(&self) {
        if self.startup_index_warm != StartupIndexWarm::AtStartup {
            return;
        }
        // Optional acceleration must not queue behind publication after a
        // completed call, especially a readiness probe already returning busy.
        // The writer or a later call will schedule its newer snapshot instead.
        let guard = match self.session.try_read() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
        };
        if let Some(session) = guard.as_ref() {
            session.schedule_index_warm();
        }
    }

    fn service_root(&self) -> Result<PathBuf, SearchToolsServiceError> {
        self.active_workspace_root().ok_or_else(Self::unbound_error)
    }

    fn normalize_arguments_for_current_workspace(
        &self,
        name: &str,
        arguments: Value,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Value, SearchToolsServiceError> {
        // Deadline-aware: this runs before the snapshot acquisition on the
        // generic tool path, so a blocking ensure_ready here would defeat the
        // request-wide budget while the deferred initial build runs (#1199).
        self.ensure_ready_with_cancellation(cancellation)?;
        let root = {
            let guard = self.read_session()?;
            let session = guard.as_ref().ok_or_else(Self::closed_error)?;
            session.snapshot.analyzer().project().root().to_path_buf()
        };
        crate::tool_arguments::normalize_tool_arguments(name, arguments, &root)
            .map_err(SearchToolsServiceError::invalid_params)
    }

    fn write_session(
        &self,
    ) -> Result<std::sync::RwLockWriteGuard<'_, Option<WorkspaceSession>>, SearchToolsServiceError>
    {
        self.ensure_ready()?;
        #[cfg(test)]
        crate::scoped_project::SESSION_LOCK_BLOCKED_HOOK.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                assert!(self.session.try_write().is_err());
                hook();
            }
        });
        self.session
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))
    }

    fn closed_error() -> SearchToolsServiceError {
        SearchToolsServiceError::internal("SearchToolsService is closed")
    }

    fn unbound_error() -> SearchToolsServiceError {
        SearchToolsServiceError::internal(
            "Bifrost is not bound to a workspace. The MCP client must provide an approved filesystem root via roots/list, or the server must be started with --root <path>. activate_workspace cannot bind an unbound server.",
        )
    }
}

impl Drop for SearchToolsService {
    fn drop(&mut self) {
        // If a deferred build is still in flight, join it rather than detach it.
        if let Ok(WorkspacePhase::Bound(bound)) = self.phase.get_mut()
            && let WorkspaceBuild::Building(handle) =
                std::mem::replace(&mut bound.build, WorkspaceBuild::NotStarted)
            && let Ok(Ok((_, _, _session))) = handle.join()
        {
            return;
        }
        let Ok(mut session) = self.session.write() else {
            return;
        };
        session.take();
    }
}

/// The shared workspace file listing cache for a root about to be bound, or
/// `None` under `Manual`: manual sessions have no watcher to invalidate a
/// cache, so they keep answering listing-backed tools from a fresh walk.
///
/// A one-shot process is the exception and does not come through here: it
/// constructs its own cache ([`SearchToolsService::new_one_shot`],
/// [`SearchToolsService::new_one_shot_workspace_independent`]) because it
/// exits before any change could need invalidating.
fn listing_cache_for(
    update_strategy: UpdateStrategy,
    root: &Path,
) -> Option<Arc<WorkspaceFileListingCache>> {
    match update_strategy {
        UpdateStrategy::WatchFiles => {
            Some(Arc::new(WorkspaceFileListingCache::new(root.to_path_buf())))
        }
        UpdateStrategy::Manual => None,
    }
}

/// Canonicalize and validate a service root eagerly, so a listing cache
/// created before the project build carries exactly the root the built
/// `FilesystemProject` will canonicalize to.
fn canonical_service_root(root: PathBuf) -> Result<PathBuf, String> {
    let canonical = root
        .canonicalize()
        .map_err(|err| format!("Failed to resolve project root {}: {err}", root.display()))?
        .normalize();
    if !canonical.is_dir() {
        return Err(format!(
            "project root is not a directory: {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn canonical_root_and_listing_cache(
    root: PathBuf,
    update_strategy: UpdateStrategy,
) -> Result<(PathBuf, Option<Arc<WorkspaceFileListingCache>>), String> {
    let canonical = canonical_service_root(root)?;
    let file_listing = listing_cache_for(update_strategy, &canonical);
    Ok((canonical, file_listing))
}

fn canonical_one_shot_root_and_listing_cache(
    root: PathBuf,
) -> Result<(PathBuf, Option<Arc<WorkspaceFileListingCache>>), String> {
    let canonical = canonical_service_root(root)?;
    let file_listing = Arc::new(WorkspaceFileListingCache::new(canonical.clone()));
    Ok((canonical, Some(file_listing)))
}

/// A workspace analyzer already pinned to the host's activation context.
///
/// Session assembly accepts only this type, and the only way to make one is
/// [`Self::bind`], so no analyzer that can reach pack activation was built
/// without the host (or with a different one): the invariant is structural.
/// The context is the host's, handed in by the entry point; it is never part
/// of `AnalyzerConfig`, never read from the environment or the repository, and
/// no tool argument reaches it.
pub(crate) struct HostBoundWorkspace(WorkspaceAnalyzer);

impl HostBoundWorkspace {
    fn bind(
        workspace: WorkspaceAnalyzer,
        host: &Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        workspace.bind_host_activation_context(Arc::clone(host))?;
        Ok(Self(workspace))
    }
}

impl std::ops::Deref for HostBoundWorkspace {
    type Target = WorkspaceAnalyzer;

    fn deref(&self) -> &WorkspaceAnalyzer {
        &self.0
    }
}

fn build_project(
    root: PathBuf,
    listing: Option<Arc<WorkspaceFileListingCache>>,
) -> Result<Arc<dyn Project>, String> {
    let project = match listing {
        Some(listing) => FilesystemProject::with_cached_listing(root, listing),
        None => FilesystemProject::new(root),
    }
    .map_err(|err| format!("Failed to initialize project root: {err}"))?;
    Ok(Arc::new(project))
}

#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
fn build_persisted_workspace(
    root: PathBuf,
    listing: Option<Arc<WorkspaceFileListingCache>>,
    update_strategy: UpdateStrategy,
    host: &Arc<HostActivationContext>,
) -> Result<(Arc<dyn Project>, HostBoundWorkspace), String> {
    build_persisted_workspace_reporting(root, listing, update_strategy, None, host)
}

fn build_persisted_workspace_with_budget(
    root: PathBuf,
    listing: Option<Arc<WorkspaceFileListingCache>>,
    update_strategy: UpdateStrategy,
    budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
    host: &Arc<HostActivationContext>,
) -> Result<(Arc<dyn Project>, HostBoundWorkspace), String> {
    build_persisted_workspace_reporting_with_budget(
        root,
        listing,
        update_strategy,
        None,
        budget,
        host,
    )
}

#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
fn build_persisted_workspace_reporting(
    root: PathBuf,
    listing: Option<Arc<WorkspaceFileListingCache>>,
    update_strategy: UpdateStrategy,
    observation: Option<&crate::workspace_progress::BuildObservation>,
    host: &Arc<HostActivationContext>,
) -> Result<(Arc<dyn Project>, HostBoundWorkspace), String> {
    let budget = brokk_bifrost_core::retention_budget::RetentionBudget::for_test_capacity(
        AnalyzerConfig::default().retention_budget_bytes(),
    );
    build_persisted_workspace_reporting_with_budget(
        root,
        listing,
        update_strategy,
        observation,
        &budget,
        host,
    )
}

fn build_persisted_workspace_reporting_with_budget(
    root: PathBuf,
    listing: Option<Arc<WorkspaceFileListingCache>>,
    update_strategy: UpdateStrategy,
    observation: Option<&crate::workspace_progress::BuildObservation>,
    budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
    host: &Arc<HostActivationContext>,
) -> Result<(Arc<dyn Project>, HostBoundWorkspace), String> {
    let _scope = profiling::scope("mcp_cold.analyzer_construction");
    let cache_path = crate::gitblob::cache_db_path(&root);
    crate::cache_db::validate_writable_cache_filesystem(&cache_path)
        .map_err(|error| format!("Failed to initialize persistent cache: {error}"))?;
    let project = build_project(root, listing)?;
    let workspace = build_persisted_analyzer_with_budget(
        Arc::clone(&project),
        AnalyzerConfig::default(),
        update_strategy,
        observation,
        budget,
    )
    .map_err(|error| format!("Failed to build persisted workspace: {error}"))?;
    Ok((project, HostBoundWorkspace::bind(workspace, host)?))
}

#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
fn build_persisted_analyzer(
    project: Arc<dyn Project>,
    config: AnalyzerConfig,
    update_strategy: UpdateStrategy,
    observation: Option<&crate::workspace_progress::BuildObservation>,
    host: &Arc<HostActivationContext>,
) -> Result<HostBoundWorkspace, String> {
    let budget = brokk_bifrost_core::retention_budget::RetentionBudget::for_test_capacity(
        config.retention_budget_bytes(),
    );
    let workspace = build_persisted_analyzer_with_budget(
        project,
        config,
        update_strategy,
        observation,
        &budget,
    )
    .map_err(|error| error.to_string())?;
    HostBoundWorkspace::bind(workspace, host)
}

fn build_persisted_analyzer_with_budget(
    project: Arc<dyn Project>,
    config: AnalyzerConfig,
    update_strategy: UpdateStrategy,
    observation: Option<&crate::workspace_progress::BuildObservation>,
    budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
) -> Result<WorkspaceAnalyzer, crate::analyzer::store::StoreError> {
    if let Some(observation) = observation {
        return match update_strategy {
            UpdateStrategy::WatchFiles => {
                WorkspaceAnalyzer::build_persisted_with_budget_and_progress(
                    project,
                    config,
                    budget,
                    observation.sink(),
                    observation.cancellation.clone(),
                )
            }
            UpdateStrategy::Manual => {
                WorkspaceAnalyzer::build_persisted_without_automatic_gc_with_budget_and_progress(
                    project,
                    config,
                    budget,
                    observation.sink(),
                    observation.cancellation.clone(),
                )
            }
        };
    }
    match update_strategy {
        UpdateStrategy::WatchFiles => {
            WorkspaceAnalyzer::build_persisted_with_budget(project, config, budget)
        }
        UpdateStrategy::Manual => {
            WorkspaceAnalyzer::build_persisted_without_automatic_gc_with_budget(
                project, config, budget,
            )
        }
    }
}

/// Test-only, with [`SearchToolsService::new_manual_ephemeral`]: the only chain
/// that reaches it is gated the same way.
#[cfg(any(test, feature = "test-support"))]
fn build_ephemeral_workspace(
    root: PathBuf,
    listing: Option<Arc<WorkspaceFileListingCache>>,
    host: &Arc<HostActivationContext>,
) -> Result<(Arc<dyn Project>, HostBoundWorkspace), String> {
    let project = build_project(root, listing)?;
    let workspace =
        WorkspaceAnalyzer::build_ephemeral_footgun(Arc::clone(&project), AnalyzerConfig::default())
            .map_err(|error| format!("Failed to build ephemeral workspace: {error}"))?;
    Ok((project, HostBoundWorkspace::bind(workspace, host)?))
}

/// Share environment loading and failure reporting across the activation stages.
fn activate_session_pack_stage<T>(
    project_root: &Path,
    workspace: &WorkspaceAnalyzer,
    activate: impl FnOnce(
        &Path,
        &WorkspaceAnalyzer,
        Option<ConfiguredSemanticModels>,
    ) -> Result<T, String>,
    failed: impl FnOnce(WorkspacePackActivationState) -> T,
) -> Option<T> {
    match configured_semantic_models()
        .and_then(|configured| activate(project_root, workspace, configured))
    {
        Ok(state) => Some(state),
        Err(error) => {
            eprintln!("bifrost: workspace semantic-pack activation unavailable: {error}");
            Some(failed(WorkspacePackActivationState::unavailable(
                None,
                Vec::new(),
                error,
            )))
        }
    }
}

/// Resolve and activate this workspace's semantic packs, reporting an
/// unavailable activation the way every other caller does: as a stated failure
/// on stderr with no active set, never as a silent one.
fn activate_session_semantic_packs(
    project_root: &Path,
    workspace: &WorkspaceAnalyzer,
) -> Option<Arc<WorkspacePackActivationState>> {
    activate_session_pack_stage(
        project_root,
        workspace,
        activate_configured_semantic_models,
        |state| state,
    )
    .map(Arc::new)
}

/// The installed-pack stage of [`activate_session_semantic_packs`]: the cheap
/// stage of the session's activation, which the query path awaits (issue
/// #3401). An unavailable activation reports the same stated stderr failure
/// and structured failure state as the full stage.
/// Assemble a `WorkspaceSession` from a built project + analyzer: wrap the
/// analyzer in an `Arc`, start the file watcher (per `update_strategy`), and
/// create the session state.
///
/// This eager form runs the semantic-pack activation before returning, so the
/// session it produces has nothing outstanding. It belongs to the constructors
/// that have no readiness barrier to publish early: a one-shot tool call, an
/// embedded host, a reload that must swap in a fully settled session.
fn assemble_session(
    project: Arc<dyn Project>,
    workspace: HostBoundWorkspace,
    update_strategy: UpdateStrategy,
    startup_index_warm: StartupIndexWarm,
    watcher_starter: &WatcherStarter,
) -> Result<WorkspaceSession, String> {
    let workspace = workspace.0;
    let semantic_packs = Arc::new(SemanticPackWarm::settled(activate_session_semantic_packs(
        project.root(),
        &workspace,
    )));
    assemble_session_with_warm(
        project,
        Arc::new(workspace),
        update_strategy,
        startup_index_warm,
        watcher_starter,
        semantic_packs,
    )
}

/// The deferred counterpart of [`assemble_session`]: the semantic-pack
/// activation runs on its own thread (`bifrost-semantic-pack-warm`) and the
/// session is returned while it is still pending.
///
/// A deferred build is what the MCP transport's readiness barrier covers, and
/// that barrier exists so the first tool call pays one-time workspace
/// initialization rather than an unbounded amount of catalog, network, and
/// toolchain work. Activation is warm-up work: the analyzer snapshot answers
/// queries without it, its failure is already a stated session state, and the
/// consumers that need the settled activation (policy evaluation, a pack-scope
/// refresh) wait for it themselves (issue #3372). The warm itself is staged:
/// its cheap installed stage is what the query path awaits, so a resolution
/// answer is deterministic, while the expensive acquisitions it could not
/// settle stay on the warm thread and are named on every answer produced in
/// the meantime (issue #3401).
fn assemble_session_deferred(
    project: Arc<dyn Project>,
    workspace: HostBoundWorkspace,
    update_strategy: UpdateStrategy,
    startup_index_warm: StartupIndexWarm,
    watcher_starter: &WatcherStarter,
) -> Result<WorkspaceSession, String> {
    let workspace = Arc::new(workspace.0);
    let semantic_packs =
        SemanticPackWarm::spawn(project.root().to_path_buf(), Arc::clone(&workspace))?;
    assemble_session_with_warm(
        project,
        workspace,
        update_strategy,
        startup_index_warm,
        watcher_starter,
        semantic_packs,
    )
}

/// [`assemble_session_deferred`] with the warm parked until `hold` releases it.
#[cfg(test)]
fn assemble_session_deferred_held(
    project: Arc<dyn Project>,
    workspace: HostBoundWorkspace,
    update_strategy: UpdateStrategy,
    startup_index_warm: StartupIndexWarm,
    watcher_starter: &WatcherStarter,
    hold: Arc<PackWarmHold>,
) -> Result<WorkspaceSession, String> {
    let workspace = Arc::new(workspace.0);
    let semantic_packs =
        SemanticPackWarm::spawn_held(project.root().to_path_buf(), Arc::clone(&workspace), hold)?;
    assemble_session_with_warm(
        project,
        workspace,
        update_strategy,
        startup_index_warm,
        watcher_starter,
        semantic_packs,
    )
}

fn assemble_session_with_warm(
    project: Arc<dyn Project>,
    workspace: Arc<WorkspaceAnalyzer>,
    update_strategy: UpdateStrategy,
    startup_index_warm: StartupIndexWarm,
    watcher_starter: &WatcherStarter,
    semantic_packs: Arc<SemanticPackWarm>,
) -> Result<WorkspaceSession, String> {
    struct AssemblyWarm(Option<Arc<SemanticPackWarm>>);
    impl Drop for AssemblyWarm {
        fn drop(&mut self) {
            if let Some(warm) = self.0.take() {
                warm.search_warm_cancellation.cancel();
                warm.wait_for_worker();
            }
        }
    }
    let mut assembly_warm = AssemblyWarm(Some(Arc::clone(&semantic_packs)));
    let document_root = Arc::new(
        WorkspaceRoot::open(project.root())
            .map_err(|error| format!("Failed to open workspace document root: {error}"))?,
    );
    let watcher = start_session_watcher(
        Arc::clone(&project),
        &workspace,
        update_strategy,
        watcher_starter,
    )?;
    let snapshot = workspace;
    // Bring the persisted per-file Rust usage facts up to date off the request
    // path (issue #1416). Under the native engine there is no whole-workspace
    // index left to build, so what this buys is repair: a live blob whose
    // canonical facts were never published makes every native Rust graph and
    // reference answer report `unavailable_canonical_facts` until the catch-up
    // persists it, and doing that inside the first query's wall-clock budget is
    // the latency #1416 exists to avoid. A panic here resurfaces on the first
    // query that needs the facts.
    //
    // Opt-out, because the catch-up is a whole-workspace fan-out and a session
    // that will never ask a usage question should not pay for it: a large C++
    // workspace with a vendored Rust tree paid it for work it never queried
    // (d8920a38). `StartupIndexWarm::OnDemand` leaves the repair to the first
    // query that needs it.
    let usage_index_warm = if startup_index_warm == StartupIndexWarm::AtStartup {
        let snapshot = Arc::clone(&snapshot);
        // Background work counts as activity for the idle heap release (#12661): taken before the spawn, held until the thread ends.
        let heap_activity = brokk_bifrost_core::heap_release::IdleHeapRelease::process().warm();
        Some(
            std::thread::Builder::new()
                .name("bifrost-usage-index-warm".to_string())
                .spawn(move || {
                    let _heap_activity = heap_activity;
                    brokk_bifrost_analysis::analyzer::without_project_reads(|| {
                        let _scope =
                            profiling::scope("mcp_cold.query_index_construction.rust_usage");
                        snapshot.warm_rust_usage_facts();
                    })
                })
                .map_err(|error| format!("Failed to spawn usage-index warm thread: {error}"))?,
        )
    } else {
        None
    };
    let session = WorkspaceSession {
        snapshot,
        document_root,
        semantic_packs,
        retired_pack_warms: Vec::new(),
        refresh: PackRefresh::Idle,
        watcher,
        usage_index_warm,
        index_warmer: IndexWarmer::new(),
        lifetime: None,
    };
    drop(assembly_warm.0.take());
    Ok(session)
}

fn start_session_watcher(
    project: Arc<dyn Project>,
    workspace: &WorkspaceAnalyzer,
    update_strategy: UpdateStrategy,
    watcher_starter: &WatcherStarter,
) -> Result<SessionWatcher, String> {
    match update_strategy {
        UpdateStrategy::WatchFiles => {
            let claimed_files = workspace.analyzer().claimed_files();
            let watcher =
                watcher_starter(Arc::clone(&project), &claimed_files).map_err(|error| {
                    format!(
                        "Failed to start project watcher for {}: {error}",
                        project.root().display()
                    )
                })?;
            // Listing-cache fills that precede watcher registration (the
            // deferred index build, `find_filenames` during a pending build)
            // can miss changes the watcher never saw. Drop the cache now that
            // events are being captured: every fill that survives postdates
            // event coverage, so watcher-driven invalidation is complete.
            project.invalidate_cached_file_listing();
            Ok(SessionWatcher::Active(Box::new(watcher)))
        }
        UpdateStrategy::Manual => Ok(SessionWatcher::Disabled),
    }
}

// Resolve an absolute path to the nearest enclosing git root, falling back to
// the canonicalized path itself when the directory is not inside a repository.
// This matches the activation contract used by brokk-core's MCP server.
fn resolve_workspace_root(path: &Path) -> Result<PathBuf, String> {
    let canonical = path
        .canonicalize()
        .map_err(|err| format!("{err} ({})", path.display()))?
        .normalize();
    if !canonical.is_dir() {
        return Err(format!("not a directory: {}", canonical.display()));
    }

    if let Ok(repo) = git2::Repository::discover(&canonical)
        && let Some(workdir) = repo.workdir()
        && let Ok(canon_workdir) = workdir.canonicalize()
    {
        return Ok(canon_workdir.normalize());
    }

    Ok(canonical)
}

fn active_workspace_result(
    result: ActiveWorkspaceResult,
) -> Result<ToolOutput, SearchToolsServiceError> {
    let structured = serde_json::to_value(result).map_err(|err| {
        SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
    })?;
    Ok(ToolOutput::Structured {
        structured,
        rendered_text: None,
    })
}

fn active_workspace_result_for_session(
    root: &Path,
    session: &WorkspaceSession,
    workspace_build: brokk_bifrost_tools::searchtools::WorkspaceBuildStatus,
    retiring_workspaces: Vec<brokk_bifrost_tools::searchtools::RetiringWorkspace>,
) -> Result<ToolOutput, SearchToolsServiceError> {
    active_workspace_result(ActiveWorkspaceResult {
        workspace_path: root.display().to_string(),
        usage_index_ready: session.usage_index_ready(),
        semantic_packs_ready: session.semantic_packs.is_ready()
            && session.refresh == PackRefresh::Idle,
        semantic_model_overlay: if session.refresh != PackRefresh::Idle {
            SemanticModelOverlayStatus::Pending {
                stage: SemanticModelWarmStage::ActivatingInstalledPacks,
                pending_acquisitions: Vec::new(),
                shipped_pack_acquisition: None,
            }
        } else {
            session.semantic_packs.overlay_status()
        },
        session_subset: session_subset(session.snapshot.analyzer()),
        analyzer_ready: true,
        workspace_build,
        retiring_workspaces,
    })
}

#[cfg(test)]
fn test_workspace(file: &str, source: &str) -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::write(root.join(file), source).unwrap();
    (temp, root)
}

#[cfg(test)]
fn unbound_test_service(
    update_strategy: UpdateStrategy,
    watcher_starter: WatcherStarter,
) -> SearchToolsService {
    SearchToolsService {
        retention_budget: brokk_bifrost_core::retention_budget::RetentionBudget::new(
            AnalyzerConfig::default().retention_budget_bytes(),
        ),
        host_activation: HostActivationContext::library_none(),
        phase: Mutex::new(WorkspacePhase::Unbound),
        session: Arc::new(RwLock::new(None)),
        retired_sessions: Mutex::new(Default::default()),
        lifetimes: Arc::new(Default::default()),
        workspace_generation: AtomicU64::new(0),
        flow_state: crate::flow::FlowWorkspaceState::new(),
        query_protocols: RwLock::new(Default::default()),
        query_value_flows: RwLock::new(Default::default()),
        query_taint_results: RwLock::new(Default::default()),
        build_progress: Arc::new(Default::default()),
        update_strategy,
        startup_index_warm: StartupIndexWarm::AtStartup,
        watcher_starter,
        diff_snapshot_object_dir: None,
        diff_scoring: DiffScoringSession::default(),
        workspace_scaled_query_limits: false,
        #[cfg(any(test, feature = "test-support"))]
        semantic_model_runtime_limits: SemanticModelRuntimeLimits::default(),
        snapshot_acquisition_observer: Mutex::new(None),
    }
}

#[cfg(all(test, feature = "test-support"))]
mod retention_census_control_tests {
    use super::*;

    #[test]
    fn retention_census_control_does_not_start_an_unready_workspace() {
        let service = unbound_test_service(UpdateStrategy::Manual, production_watcher_starter());
        let result = service
            .call_tool_value("__bifrost_retention_census", serde_json::json!({}))
            .unwrap();
        assert_eq!(result["status"], "unavailable");
        assert_eq!(result["reason"], "workspace_not_ready");
        assert!(service.session.read().unwrap().is_none());
        assert!(matches!(
            *service.phase.lock().unwrap(),
            WorkspacePhase::Unbound
        ));
        assert!(
            service
                .call_tool_value(
                    "__bifrost_retention_census",
                    serde_json::json!({"fill":true})
                )
                .is_err()
        );
    }

    #[test]
    fn retention_census_control_refuses_pending_changes_and_changed_generation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("lib.rs"), "pub fn answer() {}\n").unwrap();
        let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        let report = service
            .call_tool_value("__bifrost_retention_census", serde_json::json!({}))
            .unwrap();
        assert_eq!(report["status"], "available", "{report}");
        assert!(report["settled_retention_budget"]["owner_id"].is_u64());
        assert!(report["passive_outside_census"]["families"].is_array());
        let generation = service.workspace_generation();
        {
            let guard = service.session.read().unwrap();
            let session = guard.as_ref().unwrap();
            assert_eq!(
                service.retention_census_current_for_test(
                    generation.wrapping_add(1),
                    session,
                    None
                ),
                Err("workspace_generation_changed"),
            );
        }
        let project = Arc::new(FilesystemProject::new(root.clone()).unwrap());
        let watcher = ProjectChangeWatcher::start_polling_for_tests(project).unwrap();
        service.session.write().unwrap().as_mut().unwrap().watcher =
            SessionWatcher::Active(Box::new(watcher));
        std::fs::write(root.join("lib.rs"), "pub fn changed() {}\n").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let pending = {
                let guard = service.session.read().unwrap();
                SearchToolsService::session_watcher_has_pending(guard.as_ref().unwrap())
            };
            if pending {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "poll watcher did not receive edit"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let result = service.retention_census_for_test().unwrap();
        assert_eq!(result["status"], "unavailable");
        assert_eq!(result["reason"], "pending_watcher_changes");
        let guard = service.session.read().unwrap();
        assert!(
            SearchToolsService::session_watcher_has_pending(guard.as_ref().unwrap()),
            "census must not consume or publish watcher changes"
        );
    }
}

/// Keep unknown ownership conservative when comparing live and indexed membership.
fn owned_policy_source_paths(
    index: &dyn brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex,
    root: &Path,
    paths: &[PathBuf],
) -> std::collections::BTreeSet<PathBuf> {
    paths
        .iter()
        .filter(|path| {
            index.owns_source_file(&ProjectFile::new(root.to_path_buf(), (*path).clone()))
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod watcher_startup_tests {
    use super::*;
    use crate::path_normalization::NormalizePath;
    use crate::policy::POLICY_EXIT_UNRELIABLE;
    use brokk_bifrost_test_macros::hardwon;
    use serde_json::json;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    #[hardwon("#12752: ignore edits must reach the analyzer through the real watcher session")]
    fn ignore_membership_watcher_updates_match_fresh_answers() {
        let (_temp, root) = workspace("Keep.java", "class Keep {}\n");
        git2::Repository::init(&root).unwrap();
        for name in ["GitHidden", "ExcludeHidden", "BifrostHidden"] {
            std::fs::write(
                root.join(format!("{name}.java")),
                format!("class {name} {{}}\n"),
            )
            .unwrap();
        }
        let service = SearchToolsService::new_ephemeral_with_strategy(
            root.clone(),
            UpdateStrategy::WatchFiles,
            HostActivationContext::library_none(),
        )
        .unwrap();
        let query = || {
            service
                .call_tool_value(
                    "search_symbols",
                    json!({"patterns": [".*"], "include_tests": true, "limit": 100}),
                )
                .unwrap()
        };
        let initial = query();
        for name in ["GitHidden", "ExcludeHidden", "BifrostHidden"] {
            assert!(initial.to_string().contains(name), "{initial}");
        }
        let check = |input: &str, contents: &str, visible: &str, hidden: &str| {
            std::fs::write(root.join(input), contents).unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                let pending = {
                    let guard = service.session.read().unwrap();
                    matches!(&guard.as_ref().unwrap().watcher, SessionWatcher::Active(watcher) if watcher.has_pending_files(&[ProjectFile::new(&root, input)]) || (input == ".git/info/exclude" && watcher.has_pending_listing_revalidation()))
                };
                if pending {
                    break;
                }
                assert!(Instant::now() < deadline, "watcher did not deliver {input}");
                std::thread::sleep(Duration::from_millis(20));
            }
            let actual = query();
            let fresh = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
            let expected = fresh
                .call_tool_value(
                    "search_symbols",
                    json!({"patterns": [".*"], "include_tests": true, "limit": 100}),
                )
                .unwrap();
            assert_eq!(actual, expected, "after {input}");
            assert!(!actual.to_string().contains(hidden), "{actual}");
            assert!(actual.to_string().contains(visible), "{actual}");
        };
        for (input, hidden) in [
            (".gitignore", "GitHidden"),
            (".git/info/exclude", "ExcludeHidden"),
            (".bifrostignore", "BifrostHidden"),
        ] {
            check(input, &format!("{hidden}.java\n"), "Keep", hidden);
        }
        // In-place rewrites of the now-existing ignore file are content
        // writes: the analyzer, not the watcher listing, revalidates them.
        check(".bifrostignore", "Keep.java\n", "BifrostHidden", "Keep");
        check(
            ".bifrostignore",
            "BifrostHidden.java\n",
            "Keep",
            "BifrostHidden",
        );
    }

    #[test]
    #[hardwon("#13071: retained no-op membership revalidation lost the next save's point lineage")]
    fn index_revalidation_keeps_the_next_edit_point_path() {
        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::full_selection_observation_count_for_test;
        use brokk_bifrost_core::analyzer::project::{
            IgnoreTestEnvironment, age_ignore_test_inputs,
        };
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap().normalize();
        std::fs::write(root.join("Model.java"), "class Model {}\n").unwrap();
        let _env = IgnoreTestEnvironment::new(&temp.path().join("home"));
        let repo = git2::Repository::init(&root).unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(std::path::Path::new("Model.java")).unwrap();
        // An unmaterialized gitlink makes receipt unavailability structural,
        // independently of the host's timestamp granularity or scheduling.
        index
            .add(&git2::IndexEntry {
                ctime: git2::IndexTime::new(0, 0),
                mtime: git2::IndexTime::new(0, 0),
                dev: 0,
                ino: 0,
                mode: 0o160000,
                uid: 0,
                gid: 0,
                file_size: 0,
                id: git2::Oid::from_str("1111111111111111111111111111111111111111").unwrap(),
                flags: 0,
                flags_extended: 0,
                path: b"submodule".to_vec(),
            })
            .unwrap();
        index.write().unwrap();
        let service = SearchToolsService::new_ephemeral_with_strategy(
            root.clone(),
            UpdateStrategy::WatchFiles,
            HostActivationContext::library_none(),
        )
        .unwrap();
        let arguments = json!({"patterns": [".*"], "include_tests": true, "limit": 100});
        service
            .call_tool_value("search_symbols", arguments.clone())
            .unwrap();
        let listing_cache = service.bound_root_and_listing().unwrap().1.unwrap();
        let published = Arc::clone(&service.session.read().unwrap().as_ref().unwrap().snapshot);
        // Registration discards startup storage. Fill the shared listing before
        // measuring the skip for a current structural-Unknown receipt.
        published
            .analyzer()
            .project()
            .all_files_with_omissions()
            .unwrap();
        assert!(
            published
                .analyzer()
                .project()
                .listing_receipt_structurally_unknown()
        );
        let walks = listing_cache.walk_count();
        index
            .remove_path(std::path::Path::new("submodule"))
            .unwrap();
        index.write().unwrap();
        let await_revalidation = || {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let pending = {
                    let guard = service.session.read().unwrap();
                    matches!(&guard.as_ref().unwrap().watcher, SessionWatcher::Active(watcher) if watcher.has_pending_listing_revalidation())
                };
                if pending {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "listing event never reached service"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            std::thread::sleep(Duration::from_millis(200));
        };
        await_revalidation();
        service
            .call_tool_value("search_symbols", arguments.clone())
            .unwrap();
        assert_eq!(
            listing_cache.walk_count(),
            walks,
            "structural Unknown must skip index-only walks"
        );
        assert!(Arc::ptr_eq(
            &published,
            &service.session.read().unwrap().as_ref().unwrap().snapshot
        ));
        age_ignore_test_inputs(&root);

        // The first real edit after Unknown becomes certified compares the
        // complete selection once. Later certified edits use point proofs.
        let before = full_selection_observation_count_for_test(&root);
        std::fs::write(root.join("Model.java"), "class Model { void first() {} }\n").unwrap();
        {
            let mut guard = service.session.write().unwrap();
            SearchToolsService::apply_changed_files(
                guard.as_mut().unwrap(),
                BTreeSet::from([ProjectFile::new(&root, "Model.java")]),
                None,
            )
            .unwrap();
        }
        assert!(
            full_selection_observation_count_for_test(&root) > before,
            "Unknown-to-certified needs one full comparison"
        );
        let actual = service
            .call_tool_value("search_symbols", arguments.clone())
            .unwrap();
        let fresh = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        assert_eq!(
            actual,
            fresh
                .call_tool_value("search_symbols", arguments.clone())
                .unwrap()
        );
        drop(fresh);

        let published = Arc::clone(&service.session.read().unwrap().as_ref().unwrap().snapshot);
        let before = full_selection_observation_count_for_test(&root);
        let walks = listing_cache.walk_count();
        std::fs::write(root.join(".git/info/exclude"), "# unchanged membership\n").unwrap();
        // Age only this receipt window. Rewriting every fixture timestamp here
        // would also schedule source and Git ref events, beyond this delta.
        std::thread::sleep(Duration::from_millis(2100));
        await_revalidation();
        // Isolate the watcher update from settling the asynchronous pack warm
        // started by the preceding source edit, which can publish on its own.
        {
            let mut guard = service.session.write().unwrap();
            SearchToolsService::apply_watcher_delta(guard.as_mut().unwrap(), None).unwrap();
        }
        assert!(
            listing_cache.walk_count() > walks,
            "changed receipt must re-list"
        );
        assert!(Arc::ptr_eq(
            &published,
            &service.session.read().unwrap().as_ref().unwrap().snapshot
        ));
        assert_eq!(full_selection_observation_count_for_test(&root), before);
        std::fs::write(
            root.join("Model.java"),
            "class Model { void second() {} }\n",
        )
        .unwrap();
        {
            let mut guard = service.session.write().unwrap();
            SearchToolsService::apply_changed_files(
                guard.as_mut().unwrap(),
                BTreeSet::from([ProjectFile::new(&root, "Model.java")]),
                None,
            )
            .unwrap();
        }
        assert_eq!(
            full_selection_observation_count_for_test(&root),
            before,
            "certified equal re-list must retain the next edit's point path"
        );
        let actual = service
            .call_tool_value("search_symbols", arguments.clone())
            .unwrap();
        let fresh = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        assert_eq!(
            actual,
            fresh
                .call_tool_value("search_symbols", arguments.clone())
                .unwrap()
        );

        // A transient Unknown must still walk: an immediate forced add could
        // change membership while the ignore input is inside its racy window.
        let published = Arc::clone(&service.session.read().unwrap().as_ref().unwrap().snapshot);
        let walks = listing_cache.walk_count();
        std::fs::write(
            root.join(".git/info/exclude"),
            "# racy unchanged membership\n",
        )
        .unwrap();
        await_revalidation();
        {
            let mut guard = service.session.write().unwrap();
            SearchToolsService::apply_watcher_delta(guard.as_mut().unwrap(), None).unwrap();
        }
        assert!(
            listing_cache.walk_count() > walks,
            "racy receipts must revalidate"
        );
        assert!(Arc::ptr_eq(
            &published,
            &service.session.read().unwrap().as_ref().unwrap().snapshot
        ));
    }

    #[test]
    #[hardwon(
        "#13071: a structural-Unknown receipt dropped info/exclude edits with the index-only skip"
    )]
    fn exclude_edit_revalidates_under_a_structural_unknown_receipt() {
        use brokk_bifrost_core::analyzer::project::IgnoreTestEnvironment;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap().normalize();
        std::fs::write(root.join("Model.java"), "class Model {}\n").unwrap();
        std::fs::write(root.join("Extra.java"), "class Extra {}\n").unwrap();
        let _env = IgnoreTestEnvironment::new(&temp.path().join("home"));
        let repo = git2::Repository::init(&root).unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(std::path::Path::new("Model.java")).unwrap();
        // An unmaterialized gitlink makes the receipt structurally Unknown.
        index
            .add(&git2::IndexEntry {
                ctime: git2::IndexTime::new(0, 0),
                mtime: git2::IndexTime::new(0, 0),
                dev: 0,
                ino: 0,
                mode: 0o160000,
                uid: 0,
                gid: 0,
                file_size: 0,
                id: git2::Oid::from_str("1111111111111111111111111111111111111111").unwrap(),
                flags: 0,
                flags_extended: 0,
                path: b"submodule".to_vec(),
            })
            .unwrap();
        index.write().unwrap();
        let service = SearchToolsService::new_ephemeral_with_strategy(
            root.clone(),
            UpdateStrategy::WatchFiles,
            HostActivationContext::library_none(),
        )
        .unwrap();
        service.ensure_ready().unwrap();
        let extra = ProjectFile::new(&root, "Extra.java");
        let listed = |service: &SearchToolsService| {
            service
                .session
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .snapshot
                .analyzer()
                .project()
                .all_files()
                .unwrap()
                .contains(&extra)
        };
        assert!(listed(&service));
        {
            let guard = service.session.read().unwrap();
            let project = guard.as_ref().unwrap().snapshot.analyzer().project();
            project.all_files_with_omissions().unwrap();
            assert!(project.listing_receipt_structurally_unknown());
        }
        std::fs::write(root.join(".git/info/exclude"), "Extra.java\n").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let pending = {
                let guard = service.session.read().unwrap();
                matches!(&guard.as_ref().unwrap().watcher, SessionWatcher::Active(watcher) if watcher.has_pending_listing_revalidation())
            };
            if pending {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "exclude event never reached service"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(200));
        {
            let mut guard = service.session.write().unwrap();
            SearchToolsService::apply_watcher_delta(guard.as_mut().unwrap(), None).unwrap();
        }
        assert!(
            !listed(&service),
            "an info/exclude edit must update membership even when the receipt cannot certify"
        );
    }

    #[test]
    #[hardwon("#13071: index events must revalidate membership without full refresh or activation")]
    #[hardwon("#14279: a raw symlinked TMPDIR root hid the project's canonical membership")]
    fn index_membership_watcher_service_revalidation() {
        if !brokk_bifrost_core::analyzer::project::rerun_test_with_symlinked_tempdir(
            "searchtools_service::watcher_startup_tests::index_membership_watcher_service_revalidation",
            "BIFROST_ISSUE_14279_SEARCHTOOLS_WATCHER_CHILD",
        ) {
            return;
        }
        use brokk_bifrost_core::analyzer::project::{
            IgnoreTestEnvironment, age_ignore_test_inputs,
        };
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap().normalize();
        std::fs::write(root.join("main.rs"), "fn main() {}\n").unwrap();
        let _env = IgnoreTestEnvironment::new(&temp.path().join("home"));
        let repo = git2::Repository::init(&root).unwrap();
        std::fs::write(root.join(".gitignore"), "ignored.rs\n").unwrap();
        std::fs::write(root.join("ignored.rs"), "pub fn hidden() {}\n").unwrap();
        let git = |args: &[&str]| {
            let output = std::process::Command::new("git")
                .current_dir(&root)
                .args(args)
                .output()
                .unwrap();
            assert!(output.status.success(), "{args:?}: {output:?}");
        };
        git(&["add", "main.rs", ".gitignore"]);
        age_ignore_test_inputs(&root);
        let service = SearchToolsService::new_ephemeral_with_strategy(
            root.clone(),
            UpdateStrategy::WatchFiles,
            HostActivationContext::library_none(),
        )
        .unwrap();
        service.ensure_ready().unwrap();
        let listing_cache = service.bound_root_and_listing().unwrap().1.unwrap();
        // Initialization may create Git-adjacent inputs. Establish a valid
        // quiet receipt before testing whether a stat-only rewrite retains it.
        std::thread::sleep(Duration::from_millis(2100));
        {
            let mut guard = service.session.write().unwrap();
            let session = guard.as_mut().unwrap();
            SearchToolsService::apply_snapshot_update(session, BTreeSet::new(), None).unwrap();
            let SessionWatcher::Active(watcher) = &session.watcher else {
                panic!("expected active watcher");
            };
            watcher.take_changed_files();
        }
        let await_event = || {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let pending = {
                    let guard = service.session.read().unwrap();
                    matches!(&guard.as_ref().unwrap().watcher, SessionWatcher::Active(watcher) if watcher.has_pending_listing_revalidation())
                };
                if pending {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "index event never reached service"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            std::thread::sleep(Duration::from_millis(200));
        };
        // Rewrite only the cached filesystem metadata using real Git.
        std::fs::File::options()
            .write(true)
            .open(root.join("main.rs"))
            .unwrap()
            .set_modified(std::time::SystemTime::now())
            .unwrap();
        git(&["update-index", "--refresh"]);
        await_event();
        {
            let mut guard = service.session.write().unwrap();
            let session = guard.as_mut().unwrap();
            let before = session
                .snapshot
                .analyzer()
                .selected_workspace_snapshots_for_reads();
            assert!(before.is_some());
            let walks = listing_cache.walk_count();
            let source = Arc::clone(&session.snapshot);
            let packs = Arc::clone(&session.semantic_packs);
            let started = Instant::now();
            SearchToolsService::apply_watcher_delta(session, None).unwrap();
            eprintln!(
                "index stat-only watcher service revalidation us={}",
                started.elapsed().as_micros()
            );
            assert_eq!(
                before,
                session
                    .snapshot
                    .analyzer()
                    .selected_workspace_snapshots_for_reads()
            );
            assert_eq!(walks, listing_cache.walk_count());
            assert!(
                Arc::ptr_eq(&source, &session.snapshot),
                "stat refresh updated the analyzer"
            );
            assert!(
                Arc::ptr_eq(&packs, &session.semantic_packs),
                "stat refresh restarted pack activation"
            );
        }
        for (args, listed) in [
            (vec!["add", "-f", "ignored.rs"], true),
            (vec!["rm", "--cached", "ignored.rs"], false),
        ] {
            git(&args);
            await_event();
            let mut guard = service.session.write().unwrap();
            let session = guard.as_mut().unwrap();
            SearchToolsService::apply_watcher_delta(session, None).unwrap();
            assert_eq!(
                session
                    .snapshot
                    .analyzer()
                    .project()
                    .all_files()
                    .unwrap()
                    .contains(&ProjectFile::new(&root, "ignored.rs")),
                listed
            );
            drop(guard);
            let result = service
                .call_tool_value(
                    "search_symbols",
                    json!({"patterns": ["hidden"], "include_tests": true, "limit": 40}),
                )
                .unwrap();
            assert_eq!(result["total_files"], usize::from(listed), "{result}");
        }
        std::thread::sleep(Duration::from_millis(400));
        let guard = service.session.read().unwrap();
        let session = guard.as_ref().unwrap();
        assert!(
            matches!(&session.watcher, SessionWatcher::Active(watcher) if !watcher.has_pending())
        );
        drop(repo);
    }

    const WATCHER_FAILURE: &str = "injected watcher startup failure";

    fn workspace(file: &str, source: &str) -> (tempfile::TempDir, PathBuf) {
        let (temp, root) = super::test_workspace(file, source);
        (temp, root.normalize())
    }

    #[test]
    fn toolchain_wake_coalesces_while_pack_worker_is_running() {
        check_toolchain_wake(Arc::new(PackWarmHold::new()));
    }

    #[test]
    fn toolchain_wake_recovers_after_pack_worker_failure() {
        check_toolchain_wake(Arc::new(PackWarmHold::new_panicking()));
    }

    fn check_toolchain_wake(hold: Arc<PackWarmHold>) {
        let (_temp, root) = workspace("Wake.java", "class Wake {}\n");
        let service = service_with_held_warm(root, Arc::clone(&hold));
        let _release = ReleasePackWarmOnDrop(Arc::clone(&hold));
        service.ensure_ready().unwrap();
        let records = service
            .read_session()
            .unwrap()
            .as_ref()
            .unwrap()
            .snapshot
            .store()
            .unwrap()
            .toolchain_verifications();
        assert!(records.signal_stale());
        let deadline = Instant::now() + PACK_WARM_TEST_HANG_GUARD;
        loop {
            let guard = service.read_session().unwrap();
            if guard.as_ref().unwrap().refresh == PackRefresh::DeferredEcosystems {
                break;
            }
            drop(guard);
            assert!(Instant::now() < deadline, "refresh was not scheduled");
            std::thread::sleep(Duration::from_millis(10));
        }
        // Publication permits a new stale episode. Retain its wake until the
        // current worker exits, without running a concurrent activation.
        records.refresh_finished();
        assert!(records.signal_stale());
        let warm = Arc::clone(
            &service
                .read_session()
                .unwrap()
                .as_ref()
                .unwrap()
                .semantic_packs,
        );
        assert!(records.signal_stale());
        assert!(Arc::ptr_eq(
            &warm,
            &service
                .read_session()
                .unwrap()
                .as_ref()
                .unwrap()
                .semantic_packs
        ));
        hold.release_all();
        loop {
            let guard = service.read_session().unwrap();
            let session = guard.as_ref().unwrap();
            if session.refresh == PackRefresh::Idle
                && !Arc::ptr_eq(&warm, &session.semantic_packs)
                && session.semantic_packs.reap_finished_worker()
            {
                break;
            }
            drop(guard);
            assert!(Instant::now() < deadline, "refresh did not finish");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    #[hardwon("#12999: default ownership hid new files against a complete empty inventory")]
    fn empty_inventory_keeps_new_policy_sources_visible() {
        use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
        use brokk_bifrost_core::analyzer::model::{CodeUnit, Range};
        use brokk_bifrost_core::analyzer::project::Project;
        use brokk_bifrost_core::analyzer::query_batch::QueryBatch;
        use std::collections::BTreeSet;

        struct EmptyIndex;
        impl CodeUnitIndex for EmptyIndex {
            fn project(&self) -> &dyn Project {
                unimplemented!()
            }
            fn languages(&self) -> BTreeSet<Language> {
                BTreeSet::new()
            }
            fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
                Box::new(std::iter::empty())
            }
            fn search_definitions(&self, _: &str, _: bool) -> BTreeSet<CodeUnit> {
                BTreeSet::new()
            }
            fn enclosing_code_unit(&self, _: &ProjectFile, _: &Range) -> Option<CodeUnit> {
                None
            }
            fn enclosing_code_unit_for_lines(
                &self,
                _: &ProjectFile,
                _: usize,
                _: usize,
            ) -> Option<CodeUnit> {
                None
            }
            fn get_skeleton(&self, _: &CodeUnit) -> Option<String> {
                None
            }
            fn get_skeleton_header(&self, _: &CodeUnit) -> Option<String> {
                None
            }
            fn get_sources(&self, _: &CodeUnit, _: bool) -> BTreeSet<String> {
                BTreeSet::new()
            }
            fn indexed_source_files(&self) -> QueryBatch<ProjectFile> {
                QueryBatch::complete(Vec::new(), 0)
            }
        }
        let (_temp, root) = workspace("README.md", "empty resident inventory\n");
        std::fs::create_dir(root.join("src")).unwrap();
        let index = EmptyIndex;
        let inventory = index.indexed_source_files();
        assert!(inventory.complete);
        assert!(inventory.rows.is_empty());
        std::fs::write(root.join("src/new.ts"), "export function added() {}\n").unwrap();
        for source in ["src", "src/*.ts"] {
            let expected =
                crate::scoped_project::resident_source_members(&root, source, &[]).unwrap();
            let live = crate::scoped_project::resolve_sources(&root, &[source.to_owned()]).unwrap();
            let owned = owned_policy_source_paths(&index, &root, &live);
            assert_eq!(owned, BTreeSet::from([PathBuf::from("src/new.ts")]));
            assert_ne!(
                owned, expected,
                "new source must reach the stale-refusal branch"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12999: scoped policy rebuilt live sources outside the resident publication fence"
    )]
    fn scoped_policy_refuses_overlapping_unreported_edit() {
        let (_temp, root) = workspace("selected.ts", "export function target() {}\n");
        std::fs::write(root.join("policy.rqlp"), r#"(policy :schema-version 1 :id "test.fence" :name "Fence" :message "target" :severity warning :analysis (analysis :type match :selector (rql :schema-version 1 (language typescript (function :name "target")))))"#).unwrap();
        let service = Arc::new(SearchToolsService::new_manual_ephemeral(root.clone()).unwrap());
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let policy_service = service.clone();
        let policy = std::thread::spawn(move || {
            crate::scoped_project::CONSTRUCTION_HOOK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    started_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(30)).unwrap();
                }))
            });
            policy_service.call_tool_value("run_policy", json!({"sources": ["selected.ts"], "policy_files": ["policy.rqlp"], "evaluation_date": "2026-11-14"}))
        });
        started_rx.recv_timeout(Duration::from_secs(30)).unwrap();
        // Construction holds precisely the lock the concurrent updater needs.
        assert!(service.session.try_write().is_err());
        std::fs::write(root.join("selected.ts"), "export function changed() {}\n").unwrap();
        let update_service = service.clone();
        let (blocked_tx, blocked_rx) = std::sync::mpsc::channel();
        let update = std::thread::spawn(move || {
            crate::scoped_project::SESSION_LOCK_BLOCKED_HOOK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || blocked_tx.send(()).unwrap()));
            });
            update_service.call_tool_value("update_paths", json!({"paths": ["selected.ts"]}))
        });
        blocked_rx.recv_timeout(Duration::from_secs(30)).unwrap();
        // An independent disk edit is not published to the resident snapshot.
        std::fs::write(
            root.join("selected.ts"),
            "export function unreported() {}\n",
        )
        .unwrap();
        release_tx.send(()).unwrap();
        let error = policy.join().unwrap().unwrap_err();
        assert!(
            matches!(
                error.code,
                SearchToolsServiceErrorCode::StaleWorkspaceGeneration { .. }
            ),
            "{error:?}"
        );
        assert!(!error.retryable_stale_generation);
        update.join().unwrap().unwrap();
    }

    #[test]
    fn semantic_pack_readiness_is_independent_of_usage_warm() {
        let (_temp, root) = workspace("Warm.java", "class Warm {}\n");
        let hold = Arc::new(PackWarmHold::new());
        let service = service_with_held_warm(root, Arc::clone(&hold));
        let _release = ReleasePackWarmOnDrop(Arc::clone(&hold));
        service.ensure_ready().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let result = service
                .call_tool_value("get_active_workspace", json!({}))
                .unwrap();
            assert_eq!(result["semantic_packs_ready"], false, "{result}");
            if result["usage_index_ready"] == true {
                break;
            }
            assert!(Instant::now() < deadline, "usage warm did not settle");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn active_workspace_reports_selected_root() {
        let (_first, first_root) = workspace("First.rs", "pub fn first() {}\n");
        let (_second, second_root) = workspace("Second.rs", "pub fn second() {}\n");
        let service = SearchToolsService::new_manual_ephemeral(first_root).unwrap();
        service
            .call_tool_value("activate_workspace", json!({"workspace_path": second_root}))
            .unwrap();
        let result = service
            .call_tool_value("get_active_workspace", json!({}))
            .unwrap();
        assert_eq!(result["workspace_path"], second_root.display().to_string());
    }

    #[test]
    fn regular_file_cannot_be_a_workspace_root() {
        let (temp, _) = workspace("lib.rs", "pub fn value() {}\n");
        let file = temp.path().join("lib.rs");
        let error = SearchToolsService::new_deferred_manual(file).err().unwrap();
        assert!(error.contains("not a directory"), "{error}");
    }

    #[test]
    fn cyclomatic_complexity_returns_rendered_text_with_structured_result() {
        fn commit(repo: &git2::Repository) {
            let mut index = repo.index().unwrap();
            index.add_path(Path::new("lib.rs")).unwrap();
            index.write().unwrap();
            let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
            let signature = git2::Signature::now("Test", "test@example.com").unwrap();
            let parent = repo.head().ok().and_then(|head| head.peel_to_commit().ok());
            let parents = parent.iter().collect::<Vec<_>>();
            repo.commit(
                Some("HEAD"),
                &signature,
                &signature,
                "fixture",
                &tree,
                &parents,
            )
            .unwrap();
        }

        let (_temp, root) = workspace("lib.rs", "pub fn answer() -> i32 { 1 }\n");
        let repo = git2::Repository::init(&root).unwrap();
        commit(&repo);
        std::fs::write(root.join("lib.rs"), "pub fn answer() -> i32 { 2 }\n").unwrap();
        commit(&repo);
        let service = SearchToolsService::new_manual_ephemeral(root).unwrap();
        let output = service
            .call_tool_output(
                "cyclomatic_complexity",
                json!({"target": "HEAD"}),
                RenderOptions::default(),
            )
            .unwrap();
        let ToolOutput::Structured {
            structured,
            rendered_text,
        } = output
        else {
            panic!("expected structured complexity output");
        };
        assert_eq!(structured["summary"]["edited"], 1, "{structured}");
        assert!(
            rendered_text
                .as_deref()
                .is_some_and(|text| text.contains("answer")),
            "{rendered_text:?}"
        );
    }

    #[test]
    fn rootless_binding_warms_usage_index_without_navigation() {
        let (_temp, root) = workspace(
            "lib.rs",
            "pub fn value() {}\npub fn caller() { value(); }\n",
        );
        let service = SearchToolsService::new_unbound_manual();
        service.bind_client_workspace(root).unwrap();
        service.ensure_ready().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let result = service
                .call_tool_value("get_active_workspace", json!({}))
                .unwrap();
            let facts_warm = {
                let guard = service.session.read().unwrap();
                guard.as_ref().unwrap().snapshot.rust_usage_facts_warm()
            };
            if result["usage_index_ready"] == true && facts_warm {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "startup usage warm did not settle: {result}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13633: a startup-era watcher refresh raced the first search and exposed the pre-registration file"
    )]
    fn git_head_refresh_discovers_file_created_before_watcher_registration() {
        let (_temp, root) = workspace("Base.java", "class Base {}\n");
        let repo = git2::Repository::init(&root).unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let starter: WatcherStarter = Arc::new(move |project, claimed_files| {
            started_tx.send(()).unwrap();
            release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(30))
                .expect("release watcher startup");
            ProjectChangeWatcher::start_polling_with_claimed_files_for_tests(project, claimed_files)
        });
        let service = unbound_watching_service(starter);
        service.bind_client_workspace(root.clone()).unwrap();
        started_rx.recv_timeout(Duration::from_secs(30)).unwrap();
        std::fs::write(root.join("Later.java"), "class Later {}\n").unwrap();
        release_tx.send(()).unwrap();
        service.ensure_ready().unwrap();

        // The measurement below is meaningful only while the session is still
        // the snapshot built before Later.java and the watcher has delivered
        // no file event for it. Startup writes generated analyzer state while
        // the pack warm runs; a polling-watcher scan of that state, or a
        // transient read failure, can queue an unrelated full refresh. Settle
        // the installed pack stage outside the measured query, then drop such
        // a refresh so the HEAD change below is the first workspace refresh
        // the query applies. A file event naming Later.java is still a
        // failure: that file predates watcher registration.
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let installed = {
                let guard = service.session.read().unwrap();
                let session = guard.as_ref().unwrap();
                !matches!(
                    session.semantic_packs.snapshot_phase(),
                    SessionPackActivation::WarmPending
                )
            };
            if installed {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the installed semantic-pack stage did not settle"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let startup_delta = {
            let mut guard = service.session.write().unwrap();
            let session = guard.as_mut().unwrap();
            let packs = Arc::clone(&session.semantic_packs);
            session.settle_pack_stage(&packs);
            let SessionWatcher::Active(watcher) = &session.watcher else {
                panic!("expected active watcher");
            };
            watcher.take_changed_files()
        };
        assert!(
            !startup_delta
                .files
                .contains(&ProjectFile::new(root.clone(), "Later.java")),
            "a file created before watcher registration became a watcher event: {startup_delta:?}"
        );

        let before = service
            .call_tool_value(
                "search_symbols",
                json!({"patterns": ["Later"], "include_tests": true, "limit": 40}),
            )
            .unwrap();
        assert_eq!(before["total_files"], 0, "{before}");

        repo.set_head("refs/heads/refresh").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let pending = {
                let guard = service.session.read().unwrap();
                let session = guard.as_ref().unwrap();
                matches!(&session.watcher, SessionWatcher::Active(watcher) if watcher.has_pending())
            };
            if pending {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "HEAD change did not reach watcher"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let first_delta = {
            let guard = service.session.read().unwrap();
            let session = guard.as_ref().unwrap();
            let SessionWatcher::Active(watcher) = &session.watcher else {
                panic!("expected active watcher");
            };
            watcher.take_changed_files()
        };
        assert!(first_delta.requires_full_refresh);
        assert!(first_delta.files.is_empty(), "{first_delta:?}");

        repo.set_head("refs/heads/refresh-again").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let pending = {
                let guard = service.session.read().unwrap();
                let session = guard.as_ref().unwrap();
                matches!(&session.watcher, SessionWatcher::Active(watcher) if watcher.has_pending())
            };
            if pending {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "second HEAD change did not reach watcher"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let after = service
            .call_tool_value(
                "search_symbols",
                json!({"patterns": ["Later"], "include_tests": true, "limit": 40}),
            )
            .unwrap();
        assert_eq!(after["files"][0]["path"], "Later.java", "{after}");
    }

    #[test]
    fn finished_workspace_build_is_not_pending_before_installation() {
        let (_temp, root) = workspace("lib.rs", "pub fn value() {}\n");
        let service = SearchToolsService::new_unbound_manual();
        service.bind_client_workspace(root).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while service.workspace_build_pending() {
            assert!(Instant::now() < deadline, "workspace build never finished");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(service.initial_workspace_build_uninstalled());
    }

    #[cfg(unix)]
    #[test]
    fn rootless_binding_reuses_canonical_workspace() {
        let (_temp, root) = workspace("lib.rs", "pub fn value() {}\n");
        let link_parent = tempfile::tempdir().unwrap();
        let link = link_parent.path().join("alias");
        std::os::unix::fs::symlink(&root, &link).unwrap();
        let service = SearchToolsService::new_unbound_manual();
        service.bind_client_workspace(root.clone()).unwrap();
        service.ensure_ready().unwrap();
        let generation = service.workspace_generation();
        service.bind_client_workspace(link).unwrap();
        assert_eq!(service.workspace_generation(), generation);
    }

    fn failing_starter(calls: Arc<AtomicUsize>) -> WatcherStarter {
        Arc::new(move |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(WATCHER_FAILURE.to_string())
        })
    }

    fn unbound_watching_service(starter: WatcherStarter) -> SearchToolsService {
        super::unbound_test_service(UpdateStrategy::WatchFiles, starter)
    }

    fn assert_watcher_error(error: &SearchToolsServiceError) {
        assert_eq!(error.code, SearchToolsServiceErrorCode::Internal);
        assert!(error.message.contains("Failed to start project watcher"));
        assert!(error.message.contains(WATCHER_FAILURE));
    }

    fn assert_one_shot_cache_is_shared_and_watcher_free(
        service: &SearchToolsService,
        watcher_starts: &AtomicUsize,
    ) {
        assert_eq!(
            0,
            watcher_starts.load(Ordering::SeqCst),
            "a one-shot process must not install a file watcher"
        );
        let listing = service
            .bound_root_and_listing()
            .unwrap()
            .1
            .expect("a one-shot service shares one listing cache");
        assert_eq!(
            1,
            listing.walk_count(),
            "the workspace must be walked once for the whole process"
        );
    }

    fn assert_watcher_startup_failure_is_retained(
        service: &SearchToolsService,
        watcher_starts: &AtomicUsize,
    ) {
        for _ in 0..2 {
            let error = service.ensure_ready().unwrap_err();
            assert_watcher_error(&error);
            let probe = service
                .call_tool_value("get_active_workspace", json!({}))
                .unwrap();
            assert_eq!(probe["analyzer_ready"], false);
            assert_eq!(probe["workspace_build"]["status"], "failed");
            assert_eq!(probe["workspace_build"]["error"], error.message);
        }
        assert_eq!(watcher_starts.load(Ordering::SeqCst), 1);
    }

    /// A one-shot `--tool` process installs no watcher and walks the workspace
    /// exactly once.
    ///
    /// Nothing consumes a watch event before exit. Starting a watcher would
    /// invalidate the listing built during startup and force the next consumer
    /// to walk the workspace again, without helping a process that exits after
    /// one call.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "ee7c68aa9a94: Commit ee7c68aa9a94 removed the watcher startup and duplicate workspace walk from one-shot tool calls"
    )]
    fn a_one_shot_service_starts_no_watcher_and_walks_the_workspace_once() {
        let (_temp, root) = workspace("OneShot.java", "class OneShot {}\n");
        let calls = Arc::new(AtomicUsize::new(0));
        let starter: WatcherStarter = {
            let calls = Arc::clone(&calls);
            Arc::new(move |project, claimed_files| {
                calls.fetch_add(1, Ordering::SeqCst);
                ProjectChangeWatcher::start_polling_with_claimed_files_for_tests(
                    project,
                    claimed_files,
                )
            })
        };

        let service = SearchToolsService::new_one_shot_with_watcher_starter(
            root,
            starter,
            HostActivationContext::library_none(),
        )
        .unwrap();

        {
            let guard = service.session.read().unwrap();
            let session = guard.as_ref().expect("a one-shot service is built eagerly");
            assert!(
                matches!(session.watcher, SessionWatcher::Disabled),
                "the session must carry no watcher"
            );
            // Stand in for the request path's listing consumers (the scan's
            // sibling-extension probe is the one that paid for the re-walk).
            session
                .snapshot
                .analyzer()
                .project()
                .all_files_shared()
                .expect("workspace listing");
        }

        assert_one_shot_cache_is_shared_and_watcher_free(&service, &calls);
    }

    /// A workspace-independent one-shot tool is lazy, but "lazy" is not "never
    /// built": a worktree endpoint forces the build after all, and every
    /// ignore probe inside it then re-walked the whole tree. On Godot one
    /// claim round's `claim.bifrostignore_probe[124 files]` span cost 9.3
    /// seconds in 129 walks. The walk count is the observable form of that
    /// defect, so it is what this pins.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "a456913fc052: Commit a456913fc052 fixed workspace-independent one-shot requests re-walking the entire tree for every ignore probe"
    )]
    fn a_workspace_independent_one_shot_service_walks_the_workspace_once() {
        let (_temp, root) = workspace("Independent.java", "class Independent {}\n");
        let calls = Arc::new(AtomicUsize::new(0));

        let service = SearchToolsService::new_one_shot_workspace_independent_with_watcher_starter(
            root,
            failing_starter(Arc::clone(&calls)),
            HostActivationContext::library_none(),
        )
        .unwrap();
        assert!(
            service.session.read().unwrap().is_none(),
            "the workspace-independent service must not build a session eagerly"
        );

        // Embedded callers can still wait for installation explicitly.
        service
            .ensure_ready()
            .expect("the lazy workspace should build");
        {
            let guard = service.session.read().unwrap();
            let project = guard
                .as_ref()
                .expect("the forced build installs a session")
                .snapshot
                .analyzer()
                .project();
            for _ in 0..8 {
                project
                    .is_bifrostignored(Path::new("Independent.java"))
                    .expect("ignore observation");
            }
        }

        assert_one_shot_cache_is_shared_and_watcher_free(&service, &calls);
    }

    /// The other side of the distinction above: a long-lived `Manual` service
    /// (the stdio server under `BIFROST_MCP_FILE_WATCHER=off`) has no watcher
    /// to invalidate a listing cache, so it must not carry one -- a stale
    /// listing there is user-visible across requests.
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "a456913fc052: Commit a456913fc052 kept long-lived manual sessions from retaining an uninvalidatable stale listing cache"
    )]
    fn a_long_lived_manual_service_carries_no_listing_cache() {
        let (_temp, root) = workspace("Manual.java", "class Manual {}\n");
        let service = SearchToolsService::new_deferred_manual(root).unwrap();
        assert!(
            service.bound_root_and_listing().unwrap().1.is_none(),
            "a long-lived manual service must keep re-walking; it cannot invalidate a cache"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11534: acknowledging one policy store failure must not hide another"
    )]
    fn query_finish_requires_every_store_error_acknowledged() {
        use crate::analyzer::store::StoreError;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("Model.java"), "class Model {}\n").unwrap();
        let (_project, workspace) =
            build_ephemeral_workspace(root, None, &HostActivationContext::library_none()).unwrap();
        let document_root =
            Arc::new(WorkspaceRoot::open(workspace.analyzer().project().root()).unwrap());
        let workspace = Arc::new(workspace.0);
        for acknowledged in 0..=2 {
            let scope = WorkspaceQueryScope::new(
                Arc::clone(&workspace),
                Arc::clone(&document_root),
                SessionPackActivation::Settled(None),
            );
            scope.context.record_store_error(StoreError::new("first"));
            scope.context.record_store_error(StoreError::new("second"));
            let records = scope.context.recorded_store_errors();
            assert_eq!(records.len(), 2);
            assert_ne!(records[0].id(), records[1].id());
            let ids = records
                .iter()
                .take(acknowledged)
                .map(|r| r.id())
                .collect::<Vec<_>>();
            scope.context.acknowledge_store_errors(&ids);
            let result = scope.finish("ack_test", Ok(42));
            if acknowledged == 2 {
                assert_eq!(result.unwrap(), 42);
            } else {
                let error = result.unwrap_err();
                assert!(!error.is_stale_analyzer_generation());
                assert!(
                    error
                        .message
                        .contains(if acknowledged == 0 { "first" } else { "second" })
                );
            }
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#847: a watcher startup error must be reported instead of opening a watch-mode service"
    )]
    fn eager_watching_service_reports_watcher_startup_failure() {
        let (_temp, root) = workspace("Eager.java", "class Eager {}\n");
        let calls = Arc::new(AtomicUsize::new(0));

        let error = match SearchToolsService::new_with_strategy_and_watcher_starter(
            root,
            UpdateStrategy::WatchFiles,
            failing_starter(Arc::clone(&calls)),
            HostActivationContext::library_none(),
        ) {
            Ok(_) => panic!("watching service unexpectedly ignored watcher failure"),
            Err(error) => error,
        };

        assert!(error.contains("Failed to start project watcher"));
        assert!(error.contains(WATCHER_FAILURE));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#847: lazy startup must retain its watcher failure instead of publishing a partial session"
    )]
    fn lazy_watching_service_retains_watcher_startup_failure() {
        let (_temp, root) = workspace("Lazy.java", "class Lazy {}\n");
        let calls = Arc::new(AtomicUsize::new(0));
        let service = SearchToolsService::new_lazy_with_strategy_and_watcher_starter(
            root,
            UpdateStrategy::WatchFiles,
            failing_starter(Arc::clone(&calls)),
            HostActivationContext::library_none(),
        )
        .unwrap();

        assert_watcher_startup_failure_is_retained(&service, &calls);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#847: concurrent first use must publish one watcher/session outcome"
    )]
    fn concurrent_lazy_first_use_publishes_one_session_outcome() {
        const CALLERS: usize = 8;
        // Under the full library suite, persisted workspace construction can
        // legitimately delay the first watcher-starter callback well beyond
        // the single-test runtime. Keep a bounded hang watchdog here, but do
        // not treat five seconds as a suite-wide performance contract.
        const STARTUP_PUBLISH_TIMEOUT: Duration = Duration::from_secs(30);
        let (_temp, root) = workspace("Concurrent.java", "class Concurrent {}\n");
        let calls = Arc::new(AtomicUsize::new(0));
        let (startup_started_tx, startup_started_rx) = mpsc::channel();
        let (release_startup_tx, release_startup_rx) = mpsc::sync_channel(CALLERS);
        let release_startup_rx = Arc::new(Mutex::new(release_startup_rx));
        let starter: WatcherStarter = {
            let calls = Arc::clone(&calls);
            let release_startup_rx = Arc::clone(&release_startup_rx);
            Arc::new(move |project, claimed_files| {
                calls.fetch_add(1, Ordering::SeqCst);
                startup_started_tx
                    .send(())
                    .expect("test should wait for watcher startup");
                release_startup_rx
                    .lock()
                    .unwrap()
                    .recv()
                    .expect("test should release watcher startup");
                ProjectChangeWatcher::start_polling_with_claimed_files_for_tests(
                    project,
                    claimed_files,
                )
            })
        };
        let service = Arc::new(
            SearchToolsService::new_lazy_with_strategy_and_watcher_starter(
                root,
                UpdateStrategy::WatchFiles,
                starter,
                HostActivationContext::library_none(),
            )
            .unwrap(),
        );
        let barrier = Arc::new(Barrier::new(CALLERS + 1));

        let handles = (0..CALLERS)
            .map(|_| {
                let service = Arc::clone(&service);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    service.call_tool_value("get_active_workspace", json!({}))
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        startup_started_rx
            .recv_timeout(STARTUP_PUBLISH_TIMEOUT)
            .expect("one caller should begin watcher startup");
        for _ in 0..CALLERS {
            release_startup_tx
                .send(())
                .expect("watcher startup should be waiting");
        }
        for handle in handles {
            // A competing poll may observe the publication lock as busy; it
            // must return that observation rather than wait for its owner.
            if let Err(error) = handle.join().unwrap() {
                assert_eq!(error.workspace_incomplete.unwrap().reason, "busy");
            }
        }
        service.ensure_ready().unwrap();
        let installed = service
            .call_tool_value("get_active_workspace", json!({}))
            .unwrap();
        assert_eq!(installed["analyzer_ready"], true);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#847: deferred startup must surface and retain watcher failure"
    )]
    fn deferred_watching_service_retains_watcher_startup_failure() {
        let (_temp, root) = workspace("Deferred.java", "class Deferred {}\n");
        let calls = Arc::new(AtomicUsize::new(0));
        let service = SearchToolsService::new_deferred_with_watcher_starter(
            root,
            failing_starter(Arc::clone(&calls)),
            HostActivationContext::library_none(),
        )
        .unwrap();

        assert_watcher_startup_failure_is_retained(&service, &calls);
    }

    #[test]
    fn profiled_query_charges_deferred_workspace_readiness_to_request_timing() {
        let (_temp, root) = workspace("Timing.java", "class Timing {}\n");
        let (startup_started_tx, startup_started_rx) = mpsc::channel();
        let (release_startup_tx, release_startup_rx) = mpsc::sync_channel(1);
        let release_startup_rx = Arc::new(Mutex::new(release_startup_rx));
        let starter: WatcherStarter = Arc::new(move |project, claimed_files| {
            startup_started_tx
                .send(())
                .expect("test should observe watcher startup");
            release_startup_rx
                .lock()
                .expect("release lock")
                .recv()
                .expect("test should release watcher startup");
            ProjectChangeWatcher::start_polling_with_claimed_files_for_tests(project, claimed_files)
        });
        let service = Arc::new(unbound_watching_service(starter));
        service
            .bind_client_workspace(root)
            .expect("client binding should start a deferred build");
        startup_started_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("deferred build should wait in watcher startup");

        let querying = Arc::clone(&service);
        let query = std::thread::spawn(move || {
            querying.call_tool_value(
                "query_code",
                json!({
                    "schema_version": 1,
                    "match": {"kind": "class", "name": "Timing"},
                    "execution_mode": "profile",
                }),
            )
        });
        // A waiting request holds no lock to observe, so give the query time to
        // start polling the parked build. If it arrives later it still pays the
        // installation, which the nanosecond-resolution readiness timer counts.
        std::thread::sleep(Duration::from_millis(50));
        release_startup_tx
            .send(())
            .expect("test should release the deferred build");

        let profile = query
            .join()
            .expect("query thread should not panic")
            .expect("profiled query should succeed");
        let timings = &profile["request_timings_ns"];
        let workspace_ready = timings["workspace_ready"]
            .as_u64()
            .expect("profile should report workspace readiness");
        let preparation = timings["preparation"]
            .as_u64()
            .expect("profile should report preparation");
        let input_decode = timings["input_decode"]
            .as_u64()
            .expect("profile should report input decoding");
        let query_execution = timings["query_execution"]
            .as_u64()
            .expect("profile should report query execution");
        let rendering_serialization = timings["rendering_serialization"]
            .as_u64()
            .expect("profile should report rendering and serialization");
        let total = timings["total"]
            .as_u64()
            .expect("profile should report total request time");

        assert!(workspace_ready > 0, "deferred readiness must be charged");
        assert!(
            total
                >= workspace_ready
                    .saturating_add(preparation)
                    .saturating_add(input_decode)
                    .saturating_add(query_execution)
                    .saturating_add(rendering_serialization),
            "request total must cover every measured phase: {timings}"
        );
    }

    #[test]
    fn profiled_query_charges_transport_queue_wait_to_request_timing() {
        let (_temp, root) = workspace("Queued.java", "class Queued {}\n");
        let service =
            SearchToolsService::new_manual_ephemeral(root).expect("manual service should start");
        let output = service
            .call_tool_output_with_transport_queue_wait(
                "query_code",
                json!({
                    "schema_version": 1,
                    "match": {"kind": "class", "name": "Queued"},
                    "execution_mode": "profile",
                }),
                RenderOptions::default(),
                None,
                Duration::from_millis(7),
            )
            .expect("profiled query should succeed");
        let structured = output.into_value();
        let timings = &structured["request_timings_ns"];
        assert_eq!(
            timings["transport_queue_wait"].as_u64(),
            Some(7_000_000),
            "profile should retain the host queue wait"
        );
        assert!(
            timings["total"]
                .as_u64()
                .is_some_and(|total| total >= 7_000_000),
            "request total should include the host queue wait: {timings}"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2542: Kotlin cold startup work must remain attributed to MCP transport phases"
    )]
    fn profiled_query_reports_transport_wait_components() {
        let (_temp, root) = workspace("SplitQueued.java", "class SplitQueued {}\n");
        let service =
            SearchToolsService::new_manual_ephemeral(root).expect("manual service should start");
        let output = service
            .call_tool_output_with_transport_timings(
                "query_code",
                json!({
                    "schema_version": 1,
                    "match": {"kind": "class", "name": "SplitQueued"},
                    "execution_mode": "profile",
                }),
                RenderOptions::default(),
                None,
                TransportTimings {
                    transport_queue_wait: Duration::from_millis(11),
                    workspace_readiness_wait: Duration::from_millis(7),
                    analyzer_admission_wait: Duration::from_millis(3),
                },
            )
            .expect("profiled query should succeed");
        let structured = output.into_value();
        let timings = &structured["request_timings_ns"];
        assert_eq!(timings["transport_queue_wait"].as_u64(), Some(11_000_000));
        assert_eq!(
            timings["workspace_readiness_wait"].as_u64(),
            Some(7_000_000)
        );
        assert_eq!(timings["analyzer_admission_wait"].as_u64(), Some(3_000_000));
        assert!(
            timings["total"]
                .as_u64()
                .is_some_and(|total| total >= 11_000_000),
            "request total should include the host queue aggregate: {timings}"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2923: Issue #2923 added and fixed forwarding analyzer build progress through the persisted manual service"
    )]
    fn persisted_manual_service_forwards_analyzer_build_progress() {
        let (_temp, root) = workspace("Progress.js", "export const answer = 42;\n");
        let project: Arc<dyn Project> =
            Arc::new(FilesystemProject::new(root).expect("filesystem project should open"));
        let observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_for_progress = Arc::clone(&observed);

        SearchToolsService::new_manual_persisted_with_progress_for_project(
            project,
            AnalyzerConfig::default(),
            move |_| {
                observed_for_progress.fetch_add(1, Ordering::Relaxed);
            },
        )
        .expect("manual persisted service should start");

        assert!(observed.load(Ordering::Relaxed) > 0);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2923: Issue #2923 fixed the observer not receiving the final canonical policy runs"
    )]
    fn policy_observer_receives_the_final_canonical_runs() {
        let (_temp, root) = workspace("Observed.js", "eval(userInput);\n");
        let service =
            SearchToolsService::new_manual_ephemeral(root.clone()).expect("manual service");
        let catalog = built_in_policy_catalog().expect("built-in policy catalog");
        let selected = catalog
            .select(&BuiltInPolicySelection {
                policy_ids: vec!["bifrost.correctness.dynamic-evaluation".to_owned()],
                ..BuiltInPolicySelection::default()
            })
            .expect("select policy");
        let inputs = selected
            .into_iter()
            .map(PolicyEvaluationInput::selected_builtin)
            .collect::<Vec<_>>();
        let options = PolicyEvaluationOptions::new(
            PolicyEvaluationDate::from_ymd(2026, 9, 3).expect("fixed date"),
        );
        let mut observed = Vec::new();

        let outcome = service
            .evaluate_policy_inputs_with_observer(&root, &inputs, &options, |run| {
                observed.push(run.clone());
            })
            .expect("policy evaluation");

        assert_eq!(observed, outcome.report().runs());
        assert_eq!(observed.len(), 1);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11534: a store failure inside one policy made the real finish discard every sibling's report"
    )]
    fn policy_store_error_real_finish_preserves_siblings() {
        use brokk_bifrost_analysis::test_support::cache_row_count;
        // SAFETY: nextest runs this test in its own process.
        unsafe { std::env::set_var("BIFROST_POLICY_PARALLELISM", "1") };
        let inputs: Vec<_> = ["alpha", "beta", "gamma"]
            .into_iter()
            .map(|name| {
                PolicyEvaluationInput::embedded(
                    brokk_bifrost_policy::PolicySourceIdentity::new(format!("{name}.rqlp")),
                    format!(
                        r#"(policy :schema-version 1 :id "test.{name}" :name "Target"
                    :message "Avoid target" :severity warning :analysis (analysis :type match
                    :selector (rql :schema-version 1
                        (language python (function :name "target")))))"#
                    ),
                )
            })
            .collect();
        let options =
            PolicyEvaluationOptions::new(PolicyEvaluationDate::from_ymd(2026, 9, 3).unwrap());
        // Two identical workspaces, each with its own persisted cache: one
        // runs the batch healthy, the other runs it with the first policy's
        // evaluation recording a store failure.
        let (_healthy_temp, healthy_root) = workspace("target.py", "def target():\n    return 1\n");
        let (_failed_temp, failed_root) = workspace("target.py", "def target():\n    return 1\n");
        let healthy = SearchToolsService::new_manual_persisted(healthy_root.clone())
            .unwrap()
            .evaluate_policy_inputs(&healthy_root, &inputs, &options, &Default::default())
            .unwrap();
        let failed_options = options
            .clone()
            .with_store_error_probe(brokk_bifrost_policy::PolicyId::new("test.alpha").unwrap());
        // `evaluate_policy_inputs` runs the whole batch inside one
        // `WorkspaceQueryScope` and returns through `finish`, so an
        // unattributed store error would turn this `Ok` into `Err`.
        let failed = SearchToolsService::new_manual_persisted(failed_root.clone())
            .unwrap()
            .evaluate_policy_inputs(&failed_root, &inputs, &failed_options, &Default::default())
            .expect("finish must return the batch with the failed policy isolated");

        assert_eq!(failed.exit_status(), 2);
        let report = serde_json::to_value(failed.report()).unwrap();
        let failed_run = report["runs"][0].to_string();
        assert!(failed_run.contains("internal_error"), "{failed_run}");
        assert!(failed_run.contains("test.alpha"), "{failed_run}");
        assert!(failed_run.contains("injected policy read"), "{failed_run}");
        // Healthy siblings are byte-identical to the run without the failure.
        for index in 1..3 {
            assert_eq!(
                serde_json::to_vec(&failed.report().runs()[index]).unwrap(),
                serde_json::to_vec(&healthy.report().runs()[index]).unwrap(),
                "sibling {index} changed"
            );
        }
        // The failed policy's provisional unit is discarded, including the
        // publication its evaluation had already committed; the healthy
        // siblings' units persist; no aggregate evaluation row is admitted
        // for the failed policy.
        assert_eq!(cache_row_count(&healthy_root, "policy_units"), 3);
        assert_eq!(cache_row_count(&failed_root, "policy_units"), 2);
        assert_eq!(
            cache_row_count(&failed_root, "policy_evaluations"),
            cache_row_count(&healthy_root, "policy_evaluations") * 2 / 3
        );
    }

    #[test]
    fn policy_observer_receives_every_selected_run() {
        let (_temp, root) = workspace("Observed.js", "eval(userInput);\n");
        let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        let catalog = built_in_policy_catalog().unwrap();
        let selected = catalog
            .select(&BuiltInPolicySelection {
                policy_ids: vec![
                    "bifrost.correctness.dynamic-evaluation".to_owned(),
                    "bifrost.correctness.repeated-branch-condition".to_owned(),
                ],
                ..BuiltInPolicySelection::default()
            })
            .unwrap();
        let inputs = selected
            .into_iter()
            .map(PolicyEvaluationInput::selected_builtin)
            .collect::<Vec<_>>();
        assert_eq!(inputs.len(), 2);
        let options =
            PolicyEvaluationOptions::new(PolicyEvaluationDate::from_ymd(2026, 9, 3).unwrap());
        let mut observed = Vec::new();
        let outcome = service
            .evaluate_policy_inputs_with_observer(&root, &inputs, &options, |run| {
                observed.push(run.clone());
            })
            .unwrap();
        assert_eq!(outcome.report().runs().len(), 2);
        assert_eq!(observed, outcome.report().runs());
    }

    #[test]
    fn policy_file_count_admits_the_documented_maximum() {
        let (_temp, root) = workspace("Observed.js", "eval(userInput);\n");
        let service = SearchToolsService::new_manual_ephemeral(root).unwrap();
        let maximum = crate::policy::PolicyBatchBudget::default().max_policies();
        let policy_files = (0..maximum)
            .map(|index| format!("policies/missing-{index}.rqlp"))
            .collect::<Vec<_>>();
        let result = service
            .call_tool_value(
                "run_policy",
                json!({"policy_files": policy_files, "evaluation_date": "2026-09-03"}),
            )
            .expect("exactly the documented maximum passes argument validation");
        assert_eq!(result["status"], "unreliable");
        assert_eq!(
            result["report"]["diagnostics"][0]["code"],
            "policy-load-failed"
        );
    }

    /// #2923: naming a pack and one policy id must evaluate that one policy.
    /// The selectors intersect, so the report carries a single run instead of
    /// the whole pack's runs filtered afterwards.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2923: pack and policy-id selectors must intersect instead of running the whole pack"
    )]
    fn issue_2923_a_pack_and_an_id_evaluate_only_that_policy() {
        let (_temp, root) = workspace("Observed.js", "eval(userInput);\n");
        let service = SearchToolsService::new_manual_ephemeral(root).expect("manual service");

        let ToolOutput::Structured { structured, .. } = service
            .call_tool_output(
                "run_policy",
                json!({
                    "policy_packs": ["bifrost.code-smells"],
                    "policy_ids": ["bifrost.correctness.dynamic-evaluation"],
                    "evaluation_date": "2026-09-03",
                    "fail_on": "never"
                }),
                RenderOptions::default(),
            )
            .expect("run_policy should evaluate the narrowed selection")
        else {
            panic!("run_policy must return structured output");
        };
        let evaluated = structured["report"]["runs"]
            .as_array()
            .expect("policy runs")
            .iter()
            .map(|run| run["policy_id"].as_str().expect("policy id"))
            .collect::<Vec<_>>();
        assert_eq!(
            evaluated,
            vec!["bifrost.correctness.dynamic-evaluation"],
            "{structured:#}"
        );

        let error = service
            .call_tool_output(
                "run_policy",
                json!({
                    "policy_packs": ["bifrost.security"],
                    "policy_ids": ["bifrost.correctness.dynamic-evaluation"],
                    "evaluation_date": "2026-09-03",
                    "fail_on": "never"
                }),
                RenderOptions::default(),
            )
            .expect_err("an id outside the named pack selects nothing to run");
        assert_eq!(error.code, SearchToolsServiceErrorCode::InvalidParams);
        assert!(error.message.contains("matches no policy"), "{error:?}");
    }

    #[test]
    fn run_policy_rejects_malformed_cost_hints() {
        let max = crate::policy::PolicyBatchBudget::default().max_policies();
        let too_many = (0..=max)
            .map(|index| (format!("policy-{index}"), json!(1)))
            .collect::<serde_json::Map<_, _>>();
        for hints in [
            json!(null),
            json!([]),
            json!({"": 1}),
            json!({"id": -1}),
            json!({"id": 1.5}),
            json!({"id": "1"}),
            json!({"id": 18446744073709551616.0_f64}),
            Value::Object(too_many),
        ] {
            let error = decode_run_policy_arguments(json!({
                "policy_ids": ["bifrost.correctness.dynamic-evaluation"],
                "evaluation_date": "2026-10-27", "policy_cost_hints": hints
            }))
            .err()
            .expect("malformed hints must be rejected");
            assert_eq!(error.code, SearchToolsServiceErrorCode::InvalidParams);
        }
    }

    #[test]
    fn run_policy_accepts_policy_deadlines_of_at_least_one_millisecond() {
        let request = |deadlines: Value| {
            decode_run_policy_arguments(json!({
                "policy_ids": ["bifrost.correctness.dynamic-evaluation"],
                "evaluation_date": "2026-10-30", "policy_deadlines_ms": deadlines
            }))
        };
        request(json!({"bifrost.correctness.dynamic-evaluation": 1}))
            .expect("a one-millisecond deadline is a valid request");
        for deadlines in [json!({"id": 0}), json!({"": 1}), json!({"id": -1})] {
            let error = request(deadlines)
                .err()
                .expect("malformed deadlines must be rejected");
            assert_eq!(error.code, SearchToolsServiceErrorCode::InvalidParams);
        }
    }

    #[test]
    fn run_policy_uses_the_coordinator_cache_default_and_full_override() {
        let arguments = json!({
            "policy_ids": ["bifrost.correctness.dynamic-evaluation"],
            "evaluation_date": "2026-09-29",
            "fail_on": "warning"
        });
        let default = decode_run_policy_arguments(arguments.clone()).expect("default request");
        assert!(default.options.incremental());

        let mut full = arguments;
        full["incremental"] = json!(false);
        let full = decode_run_policy_arguments(full).expect("full-evaluation request");
        assert!(!full.options.incremental());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1296: a run_policy deadline must return the canonical unreliable report"
    )]
    fn issue_1296_run_policy_snapshot_deadline_returns_canonical_report() {
        let (_temp, root) = workspace("DeferredPolicy.java", "class DeferredPolicy {}\n");
        let (startup_started_tx, startup_started_rx) = mpsc::channel();
        let (release_startup_tx, release_startup_rx) = mpsc::sync_channel(1);
        let release_startup_rx = Arc::new(Mutex::new(release_startup_rx));
        let starter: WatcherStarter = Arc::new(move |project, claimed_files| {
            startup_started_tx
                .send(())
                .expect("test should observe watcher startup");
            release_startup_rx
                .lock()
                .expect("release lock")
                .recv_timeout(Duration::from_secs(30))
                .expect("test should release watcher startup");
            ProjectChangeWatcher::start_polling_with_claimed_files_for_tests(project, claimed_files)
        });
        let service = unbound_watching_service(starter);
        service
            .bind_client_workspace(root)
            .expect("client binding should start a deferred build");
        startup_started_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("deferred build should reach watcher startup");
        let cancellation = CancellationToken::default().with_timeout(Duration::ZERO);

        let result = match service.prepare_run_policy_with_cancellation(
            json!({
                "policy_ids": ["bifrost.correctness.dynamic-evaluation"],
                "evaluation_date": "2026-07-29",
                "fail_on": "warning"
            }),
            Some(&cancellation),
        ) {
            Ok(RunPolicyPreparation::Deadline(result)) => result,
            Ok(RunPolicyPreparation::PreflightFailure(_)) => {
                panic!("expired request unexpectedly failed suppression preflight")
            }
            Ok(RunPolicyPreparation::Ready(_)) => {
                panic!("expired request should not join the deferred build")
            }
            Err(error) => panic!("deadline should return a canonical policy report: {error}"),
        };

        assert_eq!(result.status, "unreliable");
        assert_eq!(result.exit_status, POLICY_EXIT_UNRELIABLE);
        assert_eq!(
            result.report.schema_version(),
            brokk_bifrost_policy::PolicyReportDocument::SCHEMA_VERSION
        );
        assert!(result.report.rules().is_empty());
        assert!(result.report.runs().is_empty());
        assert_eq!(
            result.report.execution().termination(),
            Some(PolicyExecutionTermination::DeadlineExceeded)
        );
        assert_eq!(
            result.report.execution().terminal_stage(),
            Some(PolicyExecutionStage::WorkspaceSnapshot)
        );
        let stages = result
            .report
            .execution()
            .stage_timings()
            .iter()
            .map(|timing| timing.stage())
            .collect::<Vec<_>>();
        for expected in [
            PolicyExecutionStage::PolicySelection,
            PolicyExecutionStage::SuppressionPreflight,
            PolicyExecutionStage::WorkspaceSnapshot,
        ] {
            assert!(
                stages.contains(&expected),
                "missing stage {expected:?}: {stages:?}"
            );
        }
        assert_eq!(
            result.report.execution().pending_policy_ids(),
            &[PolicyId::new("bifrost.correctness.dynamic-evaluation").unwrap()]
        );
        assert_eq!(
            result.report.diagnostics()[0].code(),
            PolicyReportDiagnosticCode::WorkspaceSnapshotDeadlineExceeded
        );
        assert!(
            result
                .report
                .evaluation()
                .suppression_sources()
                .iter()
                .all(|source| source.state() == PolicySuppressionDocumentState::NotFound),
            "suppression preflight completes before the snapshot wait"
        );
        release_startup_tx
            .send(())
            .expect("release deferred watcher startup");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "65092f1ba920: malformed suppressions must fail before deferred readiness work"
    )]
    fn malformed_suppressions_fail_before_deferred_snapshot_readiness() {
        let (_temp, root) = workspace("MalformedPolicy.java", "class MalformedPolicy {}\n");
        let suppression_path = root.join(".bifrost/suppressions.json");
        std::fs::create_dir_all(suppression_path.parent().expect("suppression parent"))
            .expect("create suppression directory");
        std::fs::write(&suppression_path, "{ not json").expect("write malformed suppressions");
        let (startup_started_tx, startup_started_rx) = mpsc::channel();
        let (release_startup_tx, release_startup_rx) = mpsc::sync_channel(1);
        let release_startup_rx = Arc::new(Mutex::new(release_startup_rx));
        let starter: WatcherStarter = Arc::new(move |project, claimed_files| {
            startup_started_tx
                .send(())
                .expect("test should observe watcher startup");
            release_startup_rx
                .lock()
                .expect("release lock")
                .recv_timeout(Duration::from_secs(30))
                .expect("test should release watcher startup");
            ProjectChangeWatcher::start_polling_with_claimed_files_for_tests(project, claimed_files)
        });
        let service = unbound_watching_service(starter);
        service
            .bind_client_workspace(root)
            .expect("client binding should start a deferred build");
        startup_started_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("deferred build should reach watcher startup");

        let result = service
            .prepare_run_policy_with_cancellation(
                json!({
                    "policy_ids": ["bifrost.correctness.dynamic-evaluation"],
                    "evaluation_date": "2026-07-29",
                    "fail_on": "warning"
                }),
                None,
            )
            .expect("malformed suppressions should be a canonical result");
        let RunPolicyPreparation::PreflightFailure(result) = result else {
            panic!("malformed suppressions must fail before snapshot acquisition");
        };
        assert_eq!(result.status, "unreliable");
        assert_eq!(result.exit_status, POLICY_EXIT_UNRELIABLE);
        assert_eq!(
            result.report.schema_version(),
            brokk_bifrost_policy::PolicyReportDocument::SCHEMA_VERSION
        );
        assert!(result.report.rules().is_empty());
        assert!(result.report.runs().is_empty());
        assert_eq!(result.report.diagnostics().len(), 1);
        assert_eq!(
            result.report.diagnostics()[0].code(),
            PolicyReportDiagnosticCode::SuppressionLoadFailed
        );
        assert_eq!(
            result.report.execution().completed_policy_ids(),
            &[] as &[PolicyId]
        );
        assert_eq!(
            result.report.execution().pending_policy_ids(),
            &[] as &[PolicyId]
        );
        let stages = result
            .report
            .execution()
            .stage_timings()
            .iter()
            .map(|timing| timing.stage())
            .collect::<Vec<_>>();
        assert!(stages.contains(&PolicyExecutionStage::PolicySelection));
        assert!(stages.contains(&PolicyExecutionStage::SuppressionPreflight));
        assert!(stages.contains(&PolicyExecutionStage::ReportConstruction));
        assert!(!stages.contains(&PolicyExecutionStage::WorkspaceSnapshot));
        assert!(!stages.contains(&PolicyExecutionStage::PolicyEvaluation));
        assert_eq!(
            result.report.evaluation().suppression_sources()[0].state(),
            PolicySuppressionDocumentState::Invalid
        );
        release_startup_tx
            .send(())
            .expect("release deferred watcher startup");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "65092f1ba920: valid parsed suppressions must be carried into policy execution"
    )]
    fn valid_suppression_preflight_is_carried_into_policy_execution() {
        let (_temp, root) = workspace("Policy.java", "class Policy {}");
        let service = SearchToolsService::new_manual_ephemeral(root.clone())
            .expect("manual service should start");
        let suppression_path = root.join(".bifrost/suppressions.json");
        std::fs::create_dir_all(suppression_path.parent().expect("suppression parent"))
            .expect("create suppression directory");
        std::fs::write(
            &suppression_path,
            r#"{"schema_version":1,"suppressions":[]}"#,
        )
        .expect("write valid suppressions");
        let arguments = json!({
            "policy_ids": ["bifrost.correctness.dynamic-evaluation"],
            "evaluation_date": "2026-07-29",
            "fail_on": "warning"
        });
        let RunPolicyPreflight::Valid(preflight) = service
            .preflight_run_policy(&arguments)
            .expect("suppression preflight should succeed")
        else {
            panic!("valid suppressions must produce a carried preflight");
        };

        // A host-level preflight is intentionally a snapshot of configuration.
        // If execution loaded the file again, this mutation would turn the
        // otherwise valid run into an unreliable suppression-load failure.
        std::fs::write(&suppression_path, "{ malformed").expect("invalidate suppressions");
        let ToolOutput::Structured { structured, .. } = service
            .call_tool_output_with_transport_timings_and_preflight(
                "run_policy",
                arguments,
                RenderOptions::default(),
                None,
                TransportTimings::default(),
                Some(preflight),
            )
            .expect("carried preflight should permit execution")
        else {
            panic!("run_policy must return structured output");
        };
        assert_ne!(structured["status"], "unreliable", "{structured:#}");
        assert_eq!(structured["report"]["diagnostics"], json!([]));
    }

    /// #1199: a request whose budget expires while the deferred initial build
    /// is still running must fail fast with the explicit not-ready retry error,
    /// not block through the build and then emit a zero-result
    /// "cancelled/partial" payload that reads as "no such symbols".
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1199: broad search must return the bounded not-ready error during cold startup"
    )]
    fn issue_1199_search_symbols_snapshot_deadline_returns_not_ready_error() {
        let (_temp, root) = workspace("Deferred.java", "class Deferred {}\n");
        let (startup_started_tx, startup_started_rx) = mpsc::channel();
        let (release_startup_tx, release_startup_rx) = mpsc::sync_channel(1);
        let release_startup_rx = Arc::new(Mutex::new(release_startup_rx));
        let starter: WatcherStarter = Arc::new(move |project, claimed_files| {
            startup_started_tx
                .send(())
                .expect("test should observe watcher startup");
            release_startup_rx
                .lock()
                .expect("release lock")
                .recv_timeout(Duration::from_secs(30))
                .expect("test should release watcher startup");
            ProjectChangeWatcher::start_polling_with_claimed_files_for_tests(project, claimed_files)
        });
        let service = unbound_watching_service(starter);
        service
            .bind_client_workspace(root)
            .expect("client binding should start a deferred build");
        startup_started_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("deferred build should reach watcher startup");
        let cancellation = CancellationToken::default().with_timeout(Duration::ZERO);

        let error = service
            .call_tool_output_with_cancellation(
                "search_symbols",
                json!({
                    "patterns": ["Deferred"],
                    "include_tests": true,
                    "limit": 40
                }),
                RenderOptions::default(),
                Some(&cancellation),
            )
            .expect_err("expired request should not join the deferred build");

        assert_eq!(error.code, SearchToolsServiceErrorCode::DeadlineExceeded);
        assert_eq!(error.message, WORKSPACE_SNAPSHOT_NOT_READY_MESSAGE);
        release_startup_tx
            .send(())
            .expect("release deferred watcher startup");

        // Once the build completes, an unexpired request observes full results.
        let output = service
            .call_tool_output_with_cancellation(
                "search_symbols",
                json!({
                    "patterns": ["Deferred"],
                    "include_tests": true,
                    "limit": 40
                }),
                RenderOptions::default(),
                Some(&CancellationToken::default()),
            )
            .expect("post-build request should succeed")
            .into_value();
        assert_eq!(output["truncated"], false, "{output:#}");
        assert_eq!(output["total_files"], 1, "{output:#}");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1503: concurrent expired cold requests must not duplicate the shared workspace build"
    )]
    fn issue_1503_concurrent_cold_waiters_time_out_without_duplicate_builds() {
        let (_temp, root) = workspace("Cold.java", "class Cold {}\n");
        let starts = Arc::new(AtomicUsize::new(0));
        let (startup_started_tx, startup_started_rx) = mpsc::channel();
        let (release_startup_tx, release_startup_rx) = mpsc::sync_channel(1);
        let release_startup_rx = Arc::new(Mutex::new(release_startup_rx));
        let starter: WatcherStarter = {
            let starts = Arc::clone(&starts);
            Arc::new(move |project, claimed_files| {
                starts.fetch_add(1, Ordering::SeqCst);
                startup_started_tx
                    .send(())
                    .expect("test should observe watcher startup");
                release_startup_rx
                    .lock()
                    .expect("release lock")
                    .recv_timeout(Duration::from_secs(30))
                    .expect("test should release watcher startup");
                ProjectChangeWatcher::start_polling_with_claimed_files_for_tests(
                    project,
                    claimed_files,
                )
            })
        };
        let service = Arc::new(unbound_watching_service(starter));
        service
            .bind_client_workspace(root)
            .expect("client binding should start one deferred build");
        startup_started_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("deferred build should reach watcher startup");

        let waiters = (0..2)
            .map(|_| {
                let service = Arc::clone(&service);
                std::thread::spawn(move || {
                    service.wait_workspace_ready_until(
                        &|| false,
                        Some(Instant::now() + Duration::from_millis(25)),
                    )
                })
            })
            .collect::<Vec<_>>();
        for waiter in waiters {
            let error = waiter
                .join()
                .expect("cold waiter should not panic")
                .expect_err("cold waiter should return a bounded retry result");
            assert_eq!(error.code, SearchToolsServiceErrorCode::DeadlineExceeded);
            assert_eq!(error.message, WORKSPACE_SNAPSHOT_NOT_READY_MESSAGE);
        }
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert!(service.workspace_build_pending());

        release_startup_tx
            .send(())
            .expect("release the single deferred build");
        service
            .wait_workspace_ready(&|| false)
            .expect("the original build should continue after both timeouts");
        let output = service
            .call_tool_value(
                "search_symbols",
                json!({"patterns": ["Cold"], "include_tests": true, "limit": 40}),
            )
            .expect("a later request should publish and query the built snapshot");
        assert_eq!(output["total_files"], 1, "{output:#}");
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13391: failed initial construction must retain its error instead of claiming preparation continues"
    )]
    fn observing_failed_initial_build_retains_the_failure() {
        let (_temp, root) = workspace("Cold.java", "class Cold {}\n");
        let starter: WatcherStarter = Arc::new(|_, _| Err("fixture watcher failure".to_owned()));
        let service = unbound_watching_service(starter);
        service.bind_client_workspace(root).unwrap();
        let failure = service.ensure_ready().unwrap_err();
        assert!(
            failure.message.contains("fixture watcher failure"),
            "{failure:?}"
        );
        for _ in 0..2 {
            assert_eq!(
                service.observe_or_start_workspace().unwrap_err().message,
                failure.message
            );
            let probe = service
                .call_tool_value("get_active_workspace", json!({}))
                .unwrap();
            assert_eq!(probe["analyzer_ready"], false);
            assert_eq!(probe["workspace_build"]["status"], "failed");
            assert_eq!(probe["workspace_build"]["error"], failure.message);
            assert!(!probe.to_string().contains("continues"));
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13391: concurrent cold observations must start exactly one lazy build per binding"
    )]
    fn concurrent_observers_start_one_lazy_build() {
        let (_temp, root) = workspace("Cold.java", "class Cold {}\n");
        let starts = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let starter: WatcherStarter = {
            let starts = Arc::clone(&starts);
            Arc::new(move |project, files| {
                starts.fetch_add(1, Ordering::SeqCst);
                started_tx.send(()).unwrap();
                release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(30))
                    .unwrap();
                ProjectChangeWatcher::start_polling_with_claimed_files_for_tests(project, files)
            })
        };
        let service = Arc::new(unbound_watching_service(starter));
        // Exercise the lazy path rather than a deferred constructor.
        *service.lock_phase() = WorkspacePhase::bound(root, None, WorkspaceBuild::NotStarted);
        let observers = (0..8)
            .map(|_| {
                let service = Arc::clone(&service);
                std::thread::spawn(move || service.observe_or_start_workspace())
            })
            .collect::<Vec<_>>();
        for observer in observers {
            assert!(!observer.join().unwrap().unwrap());
        }
        started_rx.recv_timeout(Duration::from_secs(30)).unwrap();
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert_eq!(
            service
                .workspace_build_progress(service.workspace_generation())
                .unwrap()
                .generation,
            1
        );
        release_tx.send(()).unwrap();
        service.ensure_ready().unwrap();
        assert!(service.observe_or_start_workspace().unwrap());
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13391: explicit reactivation could not retry a failed initial workspace build"
    )]
    fn explicit_activation_retries_a_failed_binding_once() {
        let (_temp, root) = workspace("Retry.java", "class Retry {}\n");
        let starts = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let starter: WatcherStarter = {
            let starts = Arc::clone(&starts);
            Arc::new(move |project, files| {
                if starts.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err("transient watcher failure".to_owned());
                }
                started_tx.send(()).unwrap();
                release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(30))
                    .unwrap();
                ProjectChangeWatcher::start_polling_with_claimed_files_for_tests(project, files)
            })
        };
        let service = unbound_watching_service(starter);
        service.bind_client_workspace(root.clone()).unwrap();
        let failure = service.ensure_ready().unwrap_err();
        let failed_generation = service.workspace_generation();
        let query = json!({"patterns": ["Retry"], "include_tests": true});
        for _ in 0..2 {
            assert_eq!(
                service
                    .call_tool_value("search_symbols", query.clone())
                    .unwrap_err()
                    .message,
                failure.message
            );
            let probe = service
                .call_tool_value("get_active_workspace", json!({}))
                .unwrap();
            assert_eq!(probe["workspace_build"]["status"], "failed");
        }
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        std::fs::write(root.join("Recovered.java"), "class Recovered {}\n").unwrap();
        let activate = json!({"workspace_path": root.display().to_string()});
        let retry = service
            .call_tool_value("activate_workspace", activate.clone())
            .unwrap();
        assert_eq!(retry["analyzer_ready"], false);
        assert_eq!(retry["workspace_build"]["status"], "running");
        assert!(retry["workspace_build"]["error"].is_null());
        assert_eq!(service.workspace_generation(), failed_generation + 1);
        let retry_generation = retry["workspace_build"]["generation"].clone();
        started_rx.recv_timeout(Duration::from_secs(30)).unwrap();
        let cancelled = CancellationToken::default().with_timeout(Duration::ZERO);
        for _ in 0..2 {
            let error = service
                .call_tool_output_with_cancellation(
                    "search_symbols",
                    query.clone(),
                    RenderOptions::default(),
                    Some(&cancelled),
                )
                .unwrap_err();
            assert_eq!(error.code, SearchToolsServiceErrorCode::DeadlineExceeded);
            let probe = service
                .call_tool_value("get_active_workspace", json!({}))
                .unwrap();
            assert_eq!(probe["analyzer_ready"], false);
            assert_eq!(probe["workspace_build"]["status"], "running");
            assert_eq!(probe["workspace_build"]["generation"], retry_generation);
            let same = service
                .call_tool_value("activate_workspace", activate.clone())
                .unwrap();
            assert_eq!(same["analyzer_ready"], false);
        }
        assert_eq!(service.workspace_generation(), failed_generation + 1);
        assert_eq!(starts.load(Ordering::SeqCst), 2);
        release_tx.send(()).unwrap();
        service.ensure_ready().unwrap();
        let ready = service
            .call_tool_value("get_active_workspace", json!({}))
            .unwrap();
        assert_eq!(ready["analyzer_ready"], true);
        assert_eq!(ready["workspace_build"]["status"], "completed");
        assert_eq!(ready["workspace_build"]["generation"], retry_generation);
        let recovered = service
            .call_tool_value(
                "search_symbols",
                json!({"patterns": ["Recovered"], "include_tests": true}),
            )
            .unwrap();
        assert_eq!(recovered["total_files"], 1, "{recovered}");
        let same = service
            .call_tool_value("activate_workspace", activate)
            .unwrap();
        assert_eq!(same["analyzer_ready"], true);
        assert_eq!(service.workspace_generation(), failed_generation + 1);
        assert_eq!(starts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn cancelled_workspace_readiness_wait_stops_without_a_deadline() {
        let (_temp, root) = workspace("Cold.java", "class Cold {}\n");
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let starter: WatcherStarter = Arc::new(move |project, claimed_files| {
            started_tx.send(()).expect("report watcher startup");
            release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(30))
                .expect("release startup");
            ProjectChangeWatcher::start_polling_with_claimed_files_for_tests(project, claimed_files)
        });
        let service = unbound_watching_service(starter);
        service.bind_client_workspace(root).expect("bind workspace");
        started_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("build reached watcher startup");

        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            release_tx.send(()).expect("release build");
        });
        let cancelled = service.wait_workspace_ready(&|| true);
        release.join().expect("release thread");
        assert_eq!(
            cancelled.expect_err("cancelled waiter must stop").code,
            SearchToolsServiceErrorCode::Internal
        );
        service
            .wait_workspace_ready(&|| false)
            .expect("uncancelled waiter continues after build");
    }

    #[test]
    fn watcher_registration_drops_a_listing_filled_before_registration() {
        let (_temp, root) = workspace("Old.java", "class Old {}\n");
        let new_file = root.join("New.java");
        let starter: WatcherStarter = Arc::new(move |project, claimed_files| {
            std::fs::write(&new_file, "class New { String newmarker; }\n")
                .expect("change tree before watcher registration");
            ProjectChangeWatcher::start_polling_with_claimed_files_for_tests(project, claimed_files)
        });
        let service = SearchToolsService::new_lazy_with_strategy_and_watcher_starter(
            root,
            UpdateStrategy::WatchFiles,
            starter,
            HostActivationContext::library_none(),
        )
        .unwrap();
        let listing = service.bound_root_and_listing().unwrap().1.unwrap();
        assert_eq!(listing.files().unwrap().len(), 1);
        let result = service
            .call_tool_value("find_files_containing", json!({"patterns": ["newmarker"]}))
            .expect("file search after watcher registration");
        assert!(result.to_string().contains("New.java"), "{result:#}");
    }

    #[test]
    #[hardwon("#13331: an expired request acquired a pending-overlay scope")]
    fn expired_query_stops_before_pending_pack_stage() {
        let (_temp, root) = workspace("Warm.java", "class Warm {}\n");
        let hold = Arc::new(PackWarmHold::new());
        let service = service_with_held_warm(root, Arc::clone(&hold));
        let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
        service.ensure_ready().expect("publish workspace");
        hold.wait_for_worker_parked();
        let cancellation = CancellationToken::default().with_timeout(Duration::ZERO);
        assert!(cancellation.is_cancelled());
        assert!(cancellation.is_timed_out());
        let release = std::thread::spawn({
            let hold = Arc::clone(&hold);
            move || {
                std::thread::sleep(Duration::from_millis(200));
                hold.release();
            }
        });
        let error = service
            .snapshot_for_query_with_cancellation(Some(&cancellation))
            .err()
            .expect("expired query must not acquire a pending scope");
        release.join().expect("release pack warm");
        assert_eq!(error.code, SearchToolsServiceErrorCode::DeadlineExceeded);
    }

    // The MCP host enters "executing <tool>" before it calls the service, and
    // turns a failed call into an inconclusive isError result whose
    // _meta["io.bifrost/incomplete"].stage is "execution" only when the
    // request token recorded its timeout (rmcp_host.rs execute_tool, #13330).
    // Without that record the same failure becomes a JSON-RPC error. A tool
    // call stopped at the pending installed stage (#13331) must record it.
    #[test]
    fn pending_stage_deadline_reaches_the_host_as_a_recorded_timeout() {
        let (_temp, root) = workspace("Warm.java", "class Warm {}\n");
        let hold = Arc::new(PackWarmHold::new());
        let service = service_with_held_warm(root, Arc::clone(&hold));
        let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
        service.ensure_ready().expect("publish workspace");
        hold.wait_for_worker_parked();
        let reached_wait = Arc::new(AtomicBool::new(false));
        *service.snapshot_acquisition_observer.lock().unwrap() = Some(Arc::new({
            let reached_wait = Arc::clone(&reached_wait);
            move |point| {
                if point == SnapshotAcquisitionPoint::BeforeInstalledWait {
                    reached_wait.store(true, Ordering::SeqCst);
                }
            }
        }));
        // Long enough to reach the held wait after readiness; the deadline
        // then expires inside it.
        let cancellation = CancellationToken::default().with_timeout(Duration::from_secs(2));
        let _execution_phase = cancellation.enter_phase("executing search_symbols");
        let error = service
            .call_tool_output_with_cancellation(
                "search_symbols",
                json!({"patterns": ["Warm"]}),
                RenderOptions::default(),
                Some(&cancellation),
            )
            .expect_err("a call stopped at the pending stage must not answer");
        assert_eq!(
            error.code,
            SearchToolsServiceErrorCode::DeadlineExceeded,
            "{}",
            error.message
        );
        assert!(
            reached_wait.load(Ordering::SeqCst),
            "the call stopped before the installed-stage wait"
        );
        assert!(
            cancellation.is_timed_out(),
            "the host would answer with a JSON-RPC error, not an inconclusive result"
        );
        assert_eq!(
            cancellation.phase().as_deref(),
            Some("executing search_symbols")
        );
    }

    #[test]
    fn refresh_replaces_semantic_pack_activation_after_configuration_changes() {
        let (_temp, root) = workspace("lib.rs", "pub fn item() {}\n");
        let service = SearchToolsService::new_manual_persisted(root.clone()).unwrap();
        let before = service
            .call_tool_value("get_active_workspace", json!({}))
            .unwrap();
        assert_ne!(before["semantic_model_overlay"]["state"], "unavailable");

        std::fs::create_dir_all(root.join(".bifrost")).unwrap();
        std::fs::write(root.join(".bifrost/packs.json"), "not JSON").unwrap();
        service.call_tool_value("refresh", json!({})).unwrap();
        // A refresh starts the replacement activation off the readiness path
        // (#6397), so wait for that warm to settle instead of sampling
        // whichever side of it this status call lands on.
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let after = service
                .call_tool_value("get_active_workspace", json!({}))
                .unwrap();
            if after["semantic_packs_ready"] == true {
                assert_eq!(
                    after["semantic_model_overlay"]["state"], "unavailable",
                    "{after:#}"
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "semantic-pack refresh never settled: {after:#}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1296: registration deadlines must include policy preparation timings"
    )]
    fn issue_1296_registration_deadline_includes_preparation_timings() {
        let (_temp, root) = workspace("Policy.java", "class Policy {}\n");
        let service = SearchToolsService::new_manual_ephemeral(root).expect("manual service");
        // Let snapshot acquisition finish, then expire during registration.
        let cancellation = CancellationToken::timeout_after_checks_for_test(5);

        let output = service
            .call_tool_output_with_cancellation(
                "run_policy",
                json!({
                    "policy_ids": ["bifrost.correctness.dynamic-evaluation"],
                    "evaluation_date": "2026-07-31",
                    "fail_on": "warning"
                }),
                RenderOptions::default(),
                Some(&cancellation),
            )
            .expect("expired evaluation should retain structured output");
        let ToolOutput::Structured { structured, .. } = output else {
            panic!("run_policy must return structured output");
        };

        assert_eq!(structured["status"], "unreliable");
        assert_eq!(
            structured["report"]["schema_version"],
            brokk_bifrost_policy::PolicyReportDocument::SCHEMA_VERSION
        );
        assert_eq!(
            structured["report"]["execution"]["termination"],
            "deadline_exceeded"
        );
        assert_eq!(
            structured["report"]["execution"]["terminal_stage"],
            "policy_registration"
        );
        assert_eq!(
            structured["report"]["execution"]["active_policy_id"],
            Value::Null
        );
        assert_eq!(
            structured["report"]["execution"]["pending_policy_ids"],
            json!(["bifrost.correctness.dynamic-evaluation"])
        );
        let stages = structured["report"]["execution"]["stage_timings"]
            .as_array()
            .expect("stage timings");
        for expected in [
            "policy_selection",
            "suppression_preflight",
            "workspace_snapshot",
            "policy_registration",
        ] {
            assert!(
                stages.iter().any(|timing| timing["stage"] == expected),
                "missing stage {expected}: {stages:?}"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1322: a superseded client build must not publish after workspace rebinding"
    )]
    fn superseded_client_workspace_build_cannot_publish_after_rebinding() {
        let (_first_temp, first_root) = workspace("First.java", "class First {}\n");
        let (_second_temp, second_root) = workspace("Second.java", "class Second {}\n");
        let blocked_root = first_root.clone();
        let (first_started_tx, first_started_rx) = mpsc::channel();
        let (release_first_tx, release_first_rx) = mpsc::sync_channel(1);
        let release_first_rx = Arc::new(Mutex::new(release_first_rx));
        let (first_finished_tx, first_finished_rx) = mpsc::channel();
        let starter: WatcherStarter = Arc::new(move |project, claimed_files| {
            if project.root() == blocked_root {
                first_started_tx
                    .send(())
                    .expect("test should observe the first build");
                // Unbounded on purpose: the release only arrives after the test
                // body binds the second workspace, runs `ensure_ready()` (a
                // Java fixture build), and issues a `list_symbols` query, none
                // of which is wall-clock-bounded. A fixed timeout here raced
                // that work under load. If an assertion panics first,
                // `release_first_tx` is dropped, `recv()` returns `Err`, and
                // this `expect` fails the closure instead of hanging forever.
                release_first_rx
                    .lock()
                    .expect("release lock")
                    .recv()
                    .expect("test should release the first build");
                let watcher = ProjectChangeWatcher::start_polling_with_claimed_files_for_tests(
                    project,
                    claimed_files,
                )?;
                first_finished_tx
                    .send(())
                    .expect("test should observe the first build finishing");
                Ok(watcher)
            } else {
                ProjectChangeWatcher::start_polling_with_claimed_files_for_tests(
                    project,
                    claimed_files,
                )
            }
        });
        let service = unbound_watching_service(starter);

        service
            .bind_client_workspace(first_root)
            .expect("first client binding should start");
        first_started_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("first build should reach watcher startup");
        service
            .bind_client_workspace(second_root.clone())
            .expect("replacement client binding should start");
        service
            .ensure_ready()
            .expect("replacement workspace should become ready");

        assert_eq!(service.active_workspace_root(), Some(second_root.clone()));
        let symbols = service
            .call_tool_value("list_symbols", json!({"file_patterns": ["Second.java"]}))
            .expect("replacement workspace should be queryable");
        assert_eq!(symbols["files"][0]["path"], "Second.java");

        release_first_tx
            .send(())
            .expect("release superseded workspace build");
        first_finished_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("superseded workspace build should finish");
        assert_eq!(service.active_workspace_root(), Some(second_root));
    }

    /// The whole client-workspace lifecycle through the tool surface: bind,
    /// a tool call while the build is parked, a rebind while that build is
    /// still running, a tool call against the replacement, and unbind. The
    /// rebind decision in `WorkspacePhase` is what this pins: the superseded
    /// build never publishes, the readiness probes answer while a build is
    /// parked, and nothing rebuilds silently after unbind.
    #[test]
    fn client_workspace_lifecycle_rebinds_during_a_build_and_unbinds() {
        let (_first_temp, first_root) = workspace("First.java", "class First {}\n");
        let (_second_temp, second_root) = workspace("Second.java", "class Second {}\n");
        let blocked_root = first_root.clone();
        let (first_started_tx, first_started_rx) = mpsc::channel();
        let (release_first_tx, release_first_rx) = mpsc::sync_channel(1);
        let release_first_rx = Arc::new(Mutex::new(release_first_rx));
        let (first_finished_tx, first_finished_rx) = mpsc::channel();
        let starter: WatcherStarter = Arc::new(move |project, claimed_files| {
            let parked = project.root() == blocked_root;
            if parked {
                first_started_tx
                    .send(())
                    .expect("test should observe the first build");
                // Unbounded: if an assertion panics first, the sender drops
                // and this fails instead of hanging.
                release_first_rx
                    .lock()
                    .expect("release lock")
                    .recv()
                    .expect("test should release the first build");
            }
            let watcher = ProjectChangeWatcher::start_polling_with_claimed_files_for_tests(
                project,
                claimed_files,
            );
            if parked {
                first_finished_tx
                    .send(())
                    .expect("test should observe the first build finishing");
            }
            watcher
        });
        let service = unbound_watching_service(starter);
        let list =
            |file: &str| service.call_tool_value("list_symbols", json!({"file_patterns": [file]}));

        service
            .bind_client_workspace(first_root.clone())
            .expect("first client binding should start");
        first_started_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("first build should reach watcher startup");
        // The probes read the phase without waiting behind the parked build.
        assert_eq!(service.active_workspace_root(), Some(first_root));
        assert!(service.workspace_build_pending());
        let expired = CancellationToken::default().with_deadline(Instant::now());
        let error = service
            .call_tool_output_with_cancellation(
                "list_symbols",
                json!({"file_patterns": ["First.java"]}),
                RenderOptions::default(),
                Some(&expired),
            )
            .expect_err("a call whose budget expired must not wait for the parked build");
        assert_eq!(
            (error.code, error.message.as_str()),
            (
                SearchToolsServiceErrorCode::DeadlineExceeded,
                WORKSPACE_SNAPSHOT_NOT_READY_MESSAGE
            )
        );

        service
            .bind_client_workspace(second_root.clone())
            .expect("rebinding while the first build runs should start");
        let symbols = list("Second.java").expect("the replacement workspace answers");
        assert_eq!(symbols["files"][0]["path"], "Second.java");

        release_first_tx
            .send(())
            .expect("release superseded workspace build");
        first_finished_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("superseded workspace build should finish");
        assert_eq!(service.active_workspace_root(), Some(second_root));
        let symbols = list("Second.java").expect("the superseded build must not publish");
        assert_eq!(symbols["files"][0]["path"], "Second.java");

        service
            .unbind_client_workspace()
            .expect("unbinding should succeed");
        assert_eq!(service.active_workspace_root(), None);
        assert!(!service.workspace_build_pending());
        for _ in 0..2 {
            let error = list("Second.java").expect_err("an unbound service must not rebuild");
            assert_eq!(error.message, SearchToolsService::unbound_error().message);
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1322: a failed client build must be retryable after unbinding"
    )]
    fn failed_client_workspace_build_can_be_retried_after_unbinding() {
        let (_temp, root) = workspace("Retry.java", "class Retry {}\n");
        let calls = Arc::new(AtomicUsize::new(0));
        let starter: WatcherStarter = {
            let calls = Arc::clone(&calls);
            Arc::new(move |project, claimed_files| {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(WATCHER_FAILURE.to_string())
                } else {
                    ProjectChangeWatcher::start_polling_with_claimed_files_for_tests(
                        project,
                        claimed_files,
                    )
                }
            })
        };
        let service = unbound_watching_service(starter);

        service
            .bind_client_workspace(root.clone())
            .expect("client binding should start before deferred failure");
        let error = service
            .ensure_ready()
            .expect_err("first deferred build should fail");
        assert_watcher_error(&error);

        service
            .unbind_client_workspace()
            .expect("failed client binding should be revocable");
        service
            .bind_client_workspace(root.clone())
            .expect("client binding should be retryable");
        service
            .ensure_ready()
            .expect("retried client binding should become ready");

        assert_eq!(service.active_workspace_root(), Some(root));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// The deferred-Go regression below resolves the tool profile through live
    /// Go dependency discovery and renames through the resulting live summary,
    /// so it needs the host Go toolchain. The GitHub-hosted macOS runners do
    /// not put `go` on PATH (#4953), so a test that needs an oracle returns
    /// early instead of failing at the spawn.
    fn go_toolchain_available() -> bool {
        std::process::Command::new("go")
            .arg("version")
            .output()
            .is_ok()
    }

    fn go_live_edit_fixture() -> brokk_bifrost_analysis::inline_project::BuiltInlineTestProject {
        brokk_bifrost_analysis::inline_project::InlineTestProject::new()
            .file("go.mod", "module example.test/liveedit\n\ngo 1.22\n")
            .file(
                "caller.go",
                "package liveedit\nfunc Caller() int { return Target() }\n",
            )
            .file(
                "target.go",
                "package liveedit\nfunc Target() int { return 1 }\n",
            )
            .build()
    }

    #[test]
    #[hardwon(
        "#9277: scoped Go activation published root context then rejected its session snapshot"
    )]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn go_manual_scoped_context_uses_only_its_selected_projection() {
        use brokk_bifrost_analysis::analyzer::store::go_package_context::source_inventory_profile;

        if !go_toolchain_available() {
            return;
        }
        let fixture = go_live_edit_fixture();
        let root = SearchToolsService::new_manual_persisted(fixture.root().to_path_buf()).unwrap();
        let inspect = |service: &SearchToolsService| {
            {
                let session = service.read_session().unwrap();
                session.as_ref().unwrap().semantic_packs.wait();
            }
            // Use the same settled query path as real manual service requests,
            // and inspect the selected rows while its projection lease is live.
            let scope = service.snapshot_for_query().unwrap();
            let entry = scope.enter();
            let go = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                brokk_bifrost_go_analysis::analyzer::GoAnalyzer,
            >(entry.analyzer())
            .unwrap();
            let snapshot = go.selected_snapshot_for_test().unwrap();
            let profile = go.context_profile_for_test().unwrap_or_else(|| {
                panic!(
                    "no selected Go profile at {snapshot:?}; active base {:?}",
                    go.native_context_base_profile()
                )
            });
            let store = entry.store().unwrap();
            let context = store
                .selected_go_context(&snapshot, &profile)
                .unwrap()
                .expect("the active profile belongs to the selected projection");
            let conn = store.read_conn().unwrap();
            let head: (i64, i64) = conn
                .query_row(
                    "SELECT generation,revision FROM workspace_heads WHERE workspace_id=?1 AND lang='go'",
                    [snapshot.workspace_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            let publication_interval: (i64, Option<i64>) = conn
                .query_row(
                    "SELECT valid_from,valid_until FROM go_context_publications WHERE context_id=?1",
                    [context.context_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            let (workspace, complete, gaps): (String, bool, String) = conn
                .query_row(
                    "SELECT workspace_id,complete,json(gaps) FROM go_context_publications WHERE context_id=?1",
                    [context.context_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(workspace, snapshot.workspace_id.as_str());
            let mut query = conn
                .prepare("SELECT DISTINCT f.rel_path FROM go_package_files f JOIN go_package_instances p USING(package_id) WHERE p.context_id=?1 ORDER BY f.rel_path")
                .unwrap();
            let members = query
                .query_map([context.context_id], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let mut query = conn
                .prepare("SELECT package_id,complete,provider_kind,provider_provenance,json(gaps) FROM go_package_instances WHERE context_id=?1 ORDER BY tool_import_path")
                .unwrap();
            let packages = query
                .query_map([context.context_id], |row| {
                    let gaps: String = row.get(4)?;
                    Ok(json!({
                        "package_id": row.get::<_, i64>(0)?,
                        "complete": row.get::<_, bool>(1)?,
                        "provider_kind": row.get::<_, String>(2)?,
                        "provider_provenance": row.get::<_, String>(3)?,
                        "gaps": serde_json::from_str::<Value>(&gaps).unwrap(),
                    }))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let mut query = conn
                .prepare("SELECT rel_path FROM workspace_file_versions WHERE workspace_id=?1 AND lang='go' AND generation=?2 AND valid_from<=?3 AND (valid_until IS NULL OR ?3<valid_until) AND input_kind='configuration' ORDER BY rel_path")
                .unwrap();
            let configuration_inputs = query
                .query_map(
                    rusqlite::params![
                        snapshot.workspace_id.as_str(),
                        snapshot.generation.get(),
                        snapshot.revision
                    ],
                    |row| row.get::<_, String>(0),
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            (
                snapshot,
                profile,
                json!({
                    "selection": context.selection_id,
                    "context": context.context_id,
                    "publication_digest": context.publication_digest,
                    "complete": complete,
                    "gaps": serde_json::from_str::<Value>(&gaps).unwrap(),
                    "packages": packages,
                    "members": members,
                    "configuration_inputs": configuration_inputs,
                    "active_base_profile": go.native_context_base_profile(),
                    "workspace_head": head,
                    "publication_interval": publication_interval,
                }),
            )
        };
        let assert_package = |name: &str, context: &Value, complete: bool, provenance: &str| {
            let packages = context["packages"].as_array().unwrap();
            assert_eq!(packages.len(), 1, "{name}: {context}");
            assert!(
                packages[0]["package_id"].as_i64().unwrap() > 0,
                "{name}: {context}"
            );
            assert_eq!(packages[0]["complete"], complete, "{name}: {context}");
            assert_eq!(
                packages[0]["provider_kind"], "workspace",
                "{name}: {context}"
            );
            assert_eq!(
                packages[0]["provider_provenance"], provenance,
                "{name}: {context}"
            );
        };
        let (root_snapshot, root_profile, root_context) = inspect(&root);
        assert_ne!(root_profile, source_inventory_profile());
        assert_eq!(root_context["complete"], true, "{root_context}");
        assert_package("warm root", &root_context, true, "go_tool");
        assert_eq!(
            root_context["workspace_head"],
            json!([root_snapshot.generation.get(), root_snapshot.revision])
        );
        assert_eq!(
            root_context["publication_interval"][0],
            root_snapshot.revision
        );
        assert_eq!(root_context["publication_interval"][1], Value::Null);
        eprintln!("#9277 warm root {root_snapshot:?}: {root_context}");

        let reference = json!({"references": [{"path": "caller.go", "line": 2, "column": 28}]});
        for (name, paths, source_only, has_target) in [
            (
                "source-only-captured-metadata",
                vec!["caller.go"],
                false,
                false,
            ),
            (
                "selected-module",
                vec!["caller.go", "target.go", "go.mod"],
                false,
                true,
            ),
            ("omitted-sibling", vec!["caller.go", "go.mod"], false, false),
        ] {
            let scoped = crate::scoped_project::create_scoped_service(
                fixture.root().to_path_buf(),
                &paths
                    .iter()
                    .map(|path| (*path).to_owned())
                    .collect::<Vec<_>>(),
                None,
            )
            .unwrap();
            let active = scoped
                .call_tool_value("get_active_workspace", json!({}))
                .unwrap();
            assert_eq!(
                active["session_subset"],
                json!({"files": paths.len()}),
                "{name}: {active}"
            );
            let answer = scoped
                .call_tool_value("get_definitions_by_location", reference.clone())
                .unwrap();
            let result = &answer["results"][0];
            let status = result["status"].as_str().expect("definition lookup status");
            assert_ne!(status, "invalid_location", "{name}: {answer}");
            assert_eq!(status == "resolved", has_target, "{name}: {answer}");
            // The public schema omits an empty definitions vector.
            let definitions = result.get("definitions").map_or(&[][..], |value| {
                value.as_array().expect("definition candidates").as_slice()
            });
            assert_eq!(
                definitions
                    .iter()
                    .any(|definition| definition["path"] == "target.go"),
                has_target,
                "{name}: {answer}"
            );
            let (snapshot, profile, context) = inspect(&scoped);
            assert_ne!(snapshot.workspace_id, root_snapshot.workspace_id, "{name}");
            assert_eq!(
                profile == source_inventory_profile(),
                source_only,
                "{name}: {context}"
            );
            assert_eq!(
                context["active_base_profile"], root_context["active_base_profile"],
                "the same base profile must select a distinct session context: {name}: {context}"
            );
            assert_eq!(context["complete"], has_target, "{name}: {context}");
            assert_package(name, &context, has_target, "go_tool");
            // Existing configuration capture retains root Go metadata even
            // when --sources lists only source files. It is captured under
            // this session's identity; it does not admit sibling source.
            assert_eq!(
                context["configuration_inputs"],
                json!(["go.mod"]),
                "{name}: {context}"
            );
            assert_eq!(
                context["members"],
                if has_target {
                    json!(["caller.go", "target.go"])
                } else {
                    json!(["caller.go"])
                },
                "{name}: {context}"
            );
            if !has_target {
                assert!(
                    context["packages"][0]["gaps"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|gap| gap["code"] == "unselected_source_input"),
                    "{name}: {context}"
                );
            }
            assert_eq!(
                inspect(&root),
                (root_snapshot.clone(), root_profile, root_context.clone())
            );
            eprintln!("#9277 {name} {snapshot:?}: {context}");
        }

        // Exercise the actual domains-empty source-inventory path with no
        // module metadata to capture, rather than assuming --sources hides it.
        let unconfigured = brokk_bifrost_analysis::inline_project::InlineTestProject::new()
            .file(
                "caller.go",
                std::fs::read_to_string(fixture.root().join("caller.go")).unwrap(),
            )
            .file(
                "target.go",
                std::fs::read_to_string(fixture.root().join("target.go")).unwrap(),
            )
            .build();
        let scoped = crate::scoped_project::create_scoped_service(
            unconfigured.root().to_path_buf(),
            &["caller.go".to_owned()],
            None,
        )
        .unwrap();
        let (snapshot, profile, context) = inspect(&scoped);
        assert_ne!(
            snapshot.workspace_id,
            brokk_bifrost_analysis::analyzer::store::WorkspaceId::for_root(unconfigured.root())
        );
        assert_eq!(profile, source_inventory_profile(), "{context}");
        assert_eq!(context["complete"], false, "{context}");
        assert!(
            context["gaps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|gap| gap["code"] == "build_selection_unavailable"),
            "{context}"
        );
        // The source-inventory package has a complete admitted source set;
        // the context lacks a selected build configuration.
        assert_package("no-module", &context, true, "source_inventory");
        assert_eq!(context["members"], json!(["caller.go"]), "{context}");
        assert_eq!(context["configuration_inputs"], json!([]), "{context}");
        eprintln!("#9277 no-module source inventory {snapshot:?}: {context}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let changed = go_live_edit_fixture();
            let wrapper_dir = tempfile::tempdir().unwrap();
            let wrapper = wrapper_dir.path().join("go-wrapper");
            let go = std::env::split_paths(&std::env::var_os("PATH").unwrap())
                .map(|path| path.join("go"))
                .find(|path| path.is_file())
                .unwrap();
            let quote =
                |path: &Path| format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"));
            std::fs::write(
                &wrapper,
                format!(
                    "#!/bin/sh\nif [ \"$1\" = list ]; then printf 'module example.test/changed\\n\\ngo 1.22\\n' > {}; fi\nexec {} \"$@\"\n",
                    quote(&changed.root().join("go.mod")),
                    quote(&go),
                ),
            )
            .unwrap();
            std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
            let project: Arc<dyn crate::analyzer::Project> =
                Arc::new(crate::analyzer::FileSetProject::new(
                    changed.root().to_path_buf(),
                    ["caller.go", "target.go"].map(PathBuf::from),
                ));
            let mut config = AnalyzerConfig::default();
            config.go.dependency_discovery.go_executable = Some(wrapper);
            let stale =
                SearchToolsService::new_manual_scoped_persisted_for_project(project, config)
                    .unwrap();
            let answer = stale
                .call_tool_value("get_definitions_by_location", reference.clone())
                .unwrap();
            let result = &answer["results"][0];
            assert_eq!(
                result["status"], "unavailable",
                "stale configuration accepted: {answer}"
            );
            assert!(
                result["diagnostics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|diagnostic| diagnostic["kind"] == "native_context_unavailable"),
                "{answer}"
            );
            assert!(
                std::fs::read_to_string(changed.root().join("go.mod"))
                    .unwrap()
                    .contains("example.test/changed")
            );
            let scope = stale.snapshot_for_query().unwrap();
            let entry = scope.enter();
            let go = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                brokk_bifrost_go_analysis::analyzer::GoAnalyzer,
            >(entry.analyzer())
            .unwrap();
            let selected = go.selected_snapshot_for_test().unwrap();
            // A source-inventory fallback may remain open, but it cannot
            // claim native completeness for the stale configuration.
            let complete: i64 = entry.store().unwrap().read_conn().unwrap().query_row(
                "SELECT count(*) FROM go_context_publications WHERE workspace_id=?1 AND lang='go' AND generation=?2 AND valid_until IS NULL AND complete=1",
                rusqlite::params![selected.workspace_id.as_str(), selected.generation.get()],
                |row| row.get(0),
            ).unwrap();
            assert_eq!(
                complete, 0,
                "stale configuration published a complete Go context: {answer}"
            );
            assert_eq!(
                inspect(&root),
                (root_snapshot.clone(), root_profile, root_context.clone())
            );
            eprintln!("#9277 changed go.mod during go list: {answer}");
        }
        // A public scoped overlay must read the selected bytes. Both files
        // retain their package membership while the declaration and call
        // differ from disk; an omitted declaration cannot leak in from disk.
        let overlay_caller = "package liveedit\nfunc Caller() int { return OverlayTarget() + 7 }\n";
        let overlay_target = "package liveedit\nfunc OverlayTarget() int { return 9 }\n";
        for (name, paths, has_target) in [
            ("overlay-omitted", vec!["caller.go"], false),
            ("overlay-selected", vec!["caller.go", "target.go"], true),
        ] {
            let overlays = paths
                .iter()
                .map(|path| crate::tool_arguments::GitHistoryOverlay {
                    rel_path: PathBuf::from(path),
                    content: if *path == "caller.go" {
                        overlay_caller
                    } else {
                        overlay_target
                    }
                    .to_owned(),
                })
                .collect();
            let scoped = crate::scoped_project::create_cli_tool_service(
                fixture.root().to_path_buf(),
                "get_definitions_by_location",
                &reference,
                &paths
                    .iter()
                    .map(|path| (*path).to_owned())
                    .collect::<Vec<_>>(),
                overlays,
            )
            .unwrap();
            let contents = scoped
                .call_tool_value(
                    "get_file_contents",
                    json!({"file_paths": ["caller.go", "target.go"]}),
                )
                .unwrap();
            assert_eq!(
                contents["files"][0]["content"], overlay_caller,
                "{name}: {contents}"
            );
            assert_eq!(
                contents["files"].as_array().unwrap().len(),
                if has_target { 2 } else { 1 }
            );
            if has_target {
                assert_eq!(
                    contents["files"][1]["content"], overlay_target,
                    "{name}: {contents}"
                );
            }
            let answer = scoped
                .call_tool_value("get_definitions_by_location", reference.clone())
                .unwrap();
            let result = &answer["results"][0];
            if result["status"] == "resolved" {
                assert!(has_target, "omitted source resolved: {name}: {answer}");
                assert_eq!(
                    result["reference"]["target"], "OverlayTarget",
                    "{name}: {answer}"
                );
                let definitions = result["definitions"].as_array().unwrap();
                assert!(
                    definitions.iter().any(|definition| {
                        definition["name"] == "OverlayTarget" && definition["path"] == "target.go"
                    }),
                    "resolved target must come from selected overlay: {name}: {answer}"
                );
                assert!(
                    !definitions
                        .iter()
                        .any(|definition| definition["name"] == "Target"),
                    "disk target leaked: {name}: {answer}"
                );
            } else {
                // #8472: shared definition navigation still reads the disk
                // reference. A safe refusal is allowed until that reader uses
                // selected source; it must not claim a resolved disk target.
                assert!(
                    matches!(
                        result["status"].as_str(),
                        Some("unavailable" | "incomplete")
                    ),
                    "{name}: {answer}"
                );
                assert_eq!(result["complete"], false, "{name}: {answer}");
                assert!(result["incomplete_reason"].is_string(), "{name}: {answer}");
                assert!(
                    result["definitions"].as_array().is_none_or(Vec::is_empty),
                    "{name}: {answer}"
                );
            }
            let (_, _, context) = inspect(&scoped);
            assert_package(name, &context, has_target, "go_tool");
            assert_eq!(
                context["members"],
                if has_target {
                    json!(["caller.go", "target.go"])
                } else {
                    json!(["caller.go"])
                }
            );
            assert_eq!(
                inspect(&root),
                (root_snapshot.clone(), root_profile, root_context.clone())
            );
            eprintln!("#9277 {name}: {context}; {answer}");
        }
    }

    #[test]
    #[hardwon("#6482: a .go edit dropped the selected Go context until go.mod changed")]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn go_live_update_keeps_native_cross_file_definition() {
        if !go_toolchain_available() {
            return;
        }
        let fixture = go_live_edit_fixture();
        let service =
            SearchToolsService::new_manual_persisted(fixture.root().to_path_buf()).unwrap();
        // Real startup discovery must finish before the first native request.
        {
            let guard = service.read_session().unwrap();
            guard.as_ref().unwrap().semantic_packs.wait();
        }
        service.settle_installed_pack_stage(None).unwrap();
        let arguments = json!({
            "references": [{"path": "caller.go", "line": 2, "column": 28}]
        });
        let resolve = || {
            let payload = service
                .call_tool_json("get_definitions_by_location", &arguments.to_string())
                .unwrap();
            let value: Value = serde_json::from_str(&payload).unwrap();
            assert_eq!(value["results"][0]["status"], "resolved", "{value}");
            assert_eq!(
                value["results"][0]["definitions"][0]["path"], "target.go",
                "{value}"
            );
            let snapshot = service.snapshot_for_query().unwrap();
            let snapshot = snapshot.enter();
            let go = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                brokk_bifrost_go_analysis::analyzer::GoAnalyzer,
            >(snapshot.analyzer())
            .unwrap();
            let profile = go
                .context_profile_for_test()
                .expect("Go-tool context profile selected");
            assert_ne!(
                profile,
                brokk_bifrost_analysis::analyzer::store::go_package_context::source_inventory_profile()
            );
            (go.selected_snapshot_for_test().unwrap(), profile)
        };
        let (initial_snapshot, initial_profile) = resolve();
        let initial_scope = service.snapshot_for_query().unwrap();
        let initial_entry = initial_scope.enter();
        let initial_context = initial_entry
            .store()
            .unwrap()
            .selected_go_context(&initial_snapshot, &initial_profile)
            .unwrap()
            .unwrap();
        let initial_digest: Vec<u8> = initial_entry
            .store()
            .unwrap()
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT input_digest FROM go_context_publications WHERE context_id=?1",
                [initial_context.context_id],
                |row| row.get(0),
            )
            .unwrap();
        drop(initial_entry);
        drop(initial_scope);
        let edited = [2, 3, 4].map(|value| {
            fixture
                .file("target.go")
                .write(format!(
                    "package liveedit\nfunc Target() int {{ /* body edit */ return {value} }}\n"
                ))
                .unwrap();
            service
                .call_tool_json("update_paths", &json!({"paths": ["target.go"]}).to_string())
                .unwrap();
            resolve()
        });
        let (latest, profile) = &edited[2];
        let scope = service.snapshot_for_query().unwrap();
        let entry = scope.enter();
        let conn = entry.store().unwrap().read_conn().unwrap();
        let (publications, open, context_id, digest): (i64,i64,i64,Vec<u8>) = conn.query_row(
            "SELECT count(*),sum(p.valid_until IS NULL),max(p.context_id),p.input_digest FROM go_context_selections s JOIN go_context_publications p USING(selection_id) WHERE s.workspace_id=?1 AND s.lang='go' AND s.generation=?2 AND s.profile_digest=?3 AND s.derivation_identity=?4",
            rusqlite::params![latest.workspace_id.as_str(),latest.generation.get(),profile,brokk_bifrost_analysis::analyzer::store::go_package_context::derivation_identity()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).unwrap();
        assert_eq!(
            publications, 1,
            "body edits retain the placement publication"
        );
        assert_eq!(open, 1, "one open publication per domain");
        assert_eq!(context_id, initial_context.context_id);
        assert_ne!(
            digest, initial_digest,
            "body edits update the reconciliation input digest"
        );
    }

    #[test]
    #[hardwon("#6482: a burst of watched Go edits must publish one context at the latest revision")]
    fn go_watched_edit_burst_publishes_one_context() {
        if !go_toolchain_available() {
            return;
        }
        let fixture = go_live_edit_fixture();
        fixture
            .file("spare.go")
            .write("package liveedit\nfunc Spare() int { return 0 }\n")
            .unwrap();
        let starter: WatcherStarter = Arc::new(|project, claimed_files| {
            ProjectChangeWatcher::start_polling_with_claimed_files_for_tests(project, claimed_files)
        });
        let config = AnalyzerConfig::default();
        #[cfg(unix)]
        let (config, invocation_log) = {
            let mut config = config;
            use std::os::unix::fs::PermissionsExt;
            let directory = tempfile::tempdir().unwrap();
            let log = directory.path().join("go-list-log");
            std::fs::write(&log, "").unwrap();
            let wrapper = directory.path().join("go-wrapper");
            let go = std::env::split_paths(&std::env::var_os("PATH").unwrap())
                .map(|path| path.join("go"))
                .find(|path| path.is_file())
                .unwrap();
            let quote =
                |path: &Path| format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"));
            std::fs::write(
                &wrapper,
                format!(
                    "#!/bin/sh\nif [ \"$1\" = list ]; then pwd >> {}; fi\nexec {} \"$@\"\n",
                    quote(&log),
                    quote(&go)
                ),
            )
            .unwrap();
            std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
            config.go.dependency_discovery.go_executable = Some(wrapper);
            (config, (directory, log))
        };
        let (canonical, listing) = canonical_root_and_listing_cache(
            fixture.root().to_path_buf(),
            UpdateStrategy::WatchFiles,
        )
        .unwrap();
        let project = build_project(canonical, listing.clone()).unwrap();
        let workspace = build_persisted_analyzer(
            Arc::clone(&project),
            config,
            UpdateStrategy::WatchFiles,
            None,
            &HostActivationContext::library_none(),
        )
        .unwrap();
        let root = project.root().to_path_buf();
        let session = assemble_session(
            project,
            workspace,
            UpdateStrategy::WatchFiles,
            StartupIndexWarm::OnDemand,
            &starter,
        )
        .unwrap();
        let service = SearchToolsService::with_session_state(
            root.clone(),
            Some(session),
            listing,
            UpdateStrategy::WatchFiles,
            starter,
            HostActivationContext::library_none(),
        );
        {
            let guard = service.read_session().unwrap();
            guard.as_ref().unwrap().semantic_packs.wait();
        }
        service.settle_installed_pack_stage(None).unwrap();
        let arguments = json!({"references": [{"path": "caller.go", "line": 2, "column": 28}]});
        let payload = service
            .call_tool_json("get_definitions_by_location", &arguments.to_string())
            .unwrap();
        let before_answer: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(
            before_answer["results"][0]["status"], "resolved",
            "{before_answer}"
        );
        let (before, profile, previous_context) = {
            let guard = service.read_session().unwrap();
            let snapshot = &guard.as_ref().unwrap().snapshot;
            let go = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                brokk_bifrost_go_analysis::analyzer::GoAnalyzer,
            >(snapshot.analyzer())
            .unwrap();
            let before = go.selected_snapshot_for_test().unwrap();
            let profile = go.context_profile_for_test().unwrap();
            let identity = snapshot
                .store()
                .unwrap()
                .selected_go_context(&before, &profile)
                .unwrap()
                .unwrap();
            (before, profile, identity.context_id)
        };
        #[cfg(unix)]
        std::fs::write(&invocation_log.1, "").unwrap();
        let edits = [
            (
                "target.go",
                "package liveedit\nfunc Target() int { return 2 }\n",
            ),
            (
                "caller.go",
                "package liveedit\nfunc Caller() int { return Target() } // saved\n",
            ),
            (
                "spare.go",
                "package liveedit\nfunc Spare() int { return 3 }\n",
            ),
        ];
        for (path, source) in edits {
            fixture.file(path).write(source).unwrap();
        }
        let changed = edits.map(|(path, _)| fixture.file(path));
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let pending = {
                let guard = service.read_session().unwrap();
                match &guard.as_ref().unwrap().watcher {
                    SessionWatcher::Active(watcher) => watcher.has_pending_files(&changed),
                    SessionWatcher::Disabled => panic!("the burst test needs a real watcher"),
                }
            };
            if pending {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the watcher must deliver all three edits before the request"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // No snapshot/query helper runs between the writes and this one request.
        let payload = service
            .call_tool_json("get_definitions_by_location", &arguments.to_string())
            .unwrap();
        let answer: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(answer["results"][0]["status"], "resolved", "{answer}");
        // The edits make Go stale, so the update invalidated its discovery
        // evidence and a background pack warm republishes it; the request
        // does not wait for that warm. Settle it before reading the evidence
        // and counting go list runs, so both cover the warm's work (#10275).
        {
            let guard = service.read_session().unwrap();
            guard.as_ref().unwrap().semantic_packs.wait();
        }
        service.settle_installed_pack_stage(None).unwrap();
        let guard = service.read_session().unwrap();
        let snapshot = &guard.as_ref().unwrap().snapshot;
        let go = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
            brokk_bifrost_go_analysis::analyzer::GoAnalyzer,
        >(snapshot.analyzer())
        .unwrap();
        let latest = go.selected_snapshot_for_test().unwrap();
        assert!(latest.revision > before.revision);
        let store = snapshot.store().unwrap();
        assert!(
            store
                .selected_go_context(&latest, &profile)
                .unwrap()
                .is_some()
        );
        let current = store
            .selected_go_context(&latest, &profile)
            .unwrap()
            .unwrap();
        assert_eq!(
            current.context_id, previous_context,
            "body burst reuses placement"
        );
        #[cfg(unix)]
        {
            let invocations = std::fs::read_to_string(&invocation_log.1).unwrap();
            let invocations = invocations.lines().collect::<Vec<_>>();
            assert_eq!(
                invocations.len(),
                1,
                "at most one go list for the changed domain: {invocations:?}"
            );
        }
        let warm_evidence = snapshot
            .analyzer()
            .dependency_discovery_evidence(Language::Go)
            .expect("Go evidence on updated snapshot");
        drop(guard);
        let cold = SearchToolsService::new_manual_ephemeral(root).unwrap();
        cold.snapshot_for_query_with_cancellation(None).unwrap();
        let cold_guard = cold.session.read().unwrap();
        let cold_evidence = cold_guard
            .as_ref()
            .unwrap()
            .snapshot
            .analyzer()
            .dependency_discovery_evidence(Language::Go)
            .expect("cold Go evidence");
        assert_eq!(*warm_evidence, *cold_evidence);
        let guard = service.read_session().unwrap();
        let snapshot = &guard.as_ref().unwrap().snapshot;
        for (path, source) in edits {
            assert_eq!(
                snapshot
                    .analyzer()
                    .indexed_source(&fixture.file(path))
                    .unwrap(),
                source
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "03b89afad4b0: deferred Go requests retained the inventory profile after tool activation"
    )]
    fn deferred_go_request_adopts_activated_snapshot_and_live_summary() {
        if !go_toolchain_available() {
            return;
        }
        let (_temp, root) = workspace(
            "a.go",
            "package a\n\ntype Item int\n\nfunc Use(value Item) Item { return value }\n",
        );
        std::fs::write(
            root.join("go.mod"),
            "module example.test/handoff\n\ngo 1.22\n",
        )
        .unwrap();
        let hold = Arc::new(PackWarmHold::new());
        let service = service_with_held_warm(root.clone(), Arc::clone(&hold));
        let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
        service.ensure_ready().unwrap();
        hold.wait_for_worker_parked();
        let original = {
            let guard = service.session.read().unwrap();
            Arc::clone(&guard.as_ref().unwrap().snapshot)
        };
        hold.release();
        let request = service.snapshot_for_query_with_cancellation(None).unwrap();
        assert!(!request.has_source(&original));

        let request = request.enter();
        // The worker published both profiles, but only the tool profile has
        // live summaries. Native rename checks the request's exact profile,
        // so success proves the handed-off request selected that live summary.
        let connection = rusqlite::Connection::open(
            request
                .persisted_store_path()
                .expect("persisted Go snapshot"),
        )
        .unwrap();
        let profiles: i64 = connection
            .query_row(
                "SELECT COUNT(DISTINCT profile_digest) FROM go_context_selections",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(profiles, 2, "inventory and tool profiles were published");
        let target = request
            .analyzer()
            .declarations(&ProjectFile::new(root, "a.go"))
            .into_iter()
            .find(|unit| unit.identifier() == "Item")
            .unwrap();
        let renamed = brokk_bifrost_go_analysis::analyzer::go_native_rename(
            request.analyzer(),
            request.analyzer().project(),
            &target,
            "Renamed",
            &CancellationToken::new(),
        )
        .expect("the request must carry the activated profile with its live summary");
        assert_eq!(renamed.files.len(), 1);
        assert_eq!(renamed.files[0].edits.len(), 3);
    }

    #[test]
    fn installed_warm_does_not_restore_a_superseded_snapshot() {
        let (_temp, root) = workspace("a.go", "package a\ntype Item int\n");
        std::fs::write(
            root.join("go.mod"),
            "module example.test/handoff\n\ngo 1.22\n",
        )
        .unwrap();
        let hold = Arc::new(PackWarmHold::new());
        let service = service_with_held_warm(root.clone(), Arc::clone(&hold));
        let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
        service.ensure_ready().unwrap();
        hold.wait_for_worker_parked();
        hold.release();
        let warm = {
            let guard = service.session.read().unwrap();
            Arc::clone(&guard.as_ref().unwrap().semantic_packs)
        };
        warm.wait_for_installed_stage(None).unwrap();
        {
            let mut guard = service.session.write().unwrap();
            let session = guard.as_mut().unwrap();
            std::fs::write(root.join("a.go"), "package a\ntype Updated int\n").unwrap();
            session.snapshot = Arc::new(
                session
                    .snapshot
                    .update(&BTreeSet::from([ProjectFile::new(root.clone(), "a.go")])),
            );
        }
        let request = service.snapshot_for_query_with_cancellation(None).unwrap();
        // The request may answer under the replacement warm's activated copy
        // of the updated snapshot, but never under the superseded one.
        assert!(request.enter().analyzer().indexed_source_matches(
            &ProjectFile::new(root, "a.go"),
            "package a\ntype Updated int\n"
        ));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6397: an update during a pending pack warm left the new snapshot settled without activation"
    )]
    fn an_update_during_a_pending_warm_activates_the_new_snapshot() {
        let (_temp, root) = workspace("A.java", "class A {}\n");
        std::fs::create_dir_all(root.join(".bifrost")).unwrap();
        std::fs::write(
            root.join(".bifrost/packs.json"),
            r#"{ "schema_version": 1, "ecosystems": ["jvm"] }"#,
        )
        .unwrap();
        let hold = Arc::new(PackWarmHold::new());
        let service = service_with_held_warm(root.clone(), Arc::clone(&hold));
        let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
        service.ensure_ready().unwrap();
        hold.wait_for_worker_parked();
        // While the startup warm is still pending, a C++ file arrives. Under a
        // packs document narrowed to JVM it adds an intrinsic (cpp, language)
        // pair without changing the kept ecosystems.
        {
            let mut guard = service.session.write().unwrap();
            let session = guard.as_mut().unwrap();
            std::fs::write(root.join("b.cpp"), "int f() { return 1; }\n").unwrap();
            session.snapshot = Arc::new(
                session
                    .snapshot
                    .update(&BTreeSet::from([ProjectFile::new(root.clone(), "b.cpp")])),
            );
        }
        let first = {
            let guard = service.session.read().unwrap();
            Arc::clone(&guard.as_ref().unwrap().semantic_packs)
        };
        hold.release();
        // The startup warm finishes for the superseded snapshot. Its worker
        // must exit before settle starts the current snapshot's activation.
        let deadline = Instant::now() + Duration::from_secs(60);
        let replacement = loop {
            service.snapshot_for_query_with_cancellation(None).unwrap();
            let guard = service.session.read().unwrap();
            let current = Arc::clone(&guard.as_ref().unwrap().semantic_packs);
            if !Arc::ptr_eq(&current, &first) {
                break current;
            }
            assert!(Instant::now() < deadline, "replacement warm never started");
            std::thread::sleep(Duration::from_millis(10));
        };
        replacement.wait();
        service.snapshot_for_query_with_cancellation(None).unwrap();
        let guard = service.session.read().unwrap();
        let session = guard.as_ref().unwrap();
        let pinned = session
            .semantic_packs
            .best_known_state()
            .and_then(|state| state.coverage.clone())
            .expect("the current snapshot's activation pins its coverage");
        assert!(
            pinned.coverage.covers_entry("cpp", "language"),
            "{pinned:?}"
        );
        assert!(matches!(
            session.pack_activation(),
            SessionPackActivation::Settled(_)
        ));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1519: a deferred snapshot must resolve before optional query-index warming"
    )]
    fn deferred_build_resolves_before_optional_query_indexes_are_warm() {
        let (_temp, root) = workspace(
            "lib.rs",
            "trait Runnable {}\npub struct Worker;\nimpl Runnable for Worker {}\n",
        );
        let hold = Arc::new(PackWarmHold::new());
        let service = service_with_held_warm(root, Arc::clone(&hold));
        let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));

        // Pack activation can read and warm Rust facts itself. Hold that
        // independent worker so this assertion observes only the deferred
        // snapshot build, whose readiness does not require optional indexes.
        service.wait_workspace_ready(&|| false).unwrap();
        hold.wait_for_worker_parked();
        let guard = service.session.read().unwrap();
        let session = guard.as_ref().expect("readiness installs the analyzer");
        assert!(!session.snapshot.query_indexes_warm());
    }

    #[test]
    fn deferred_build_defers_background_query_index_warm_until_first_tool_call() {
        let (_temp, root) = workspace(
            "Warm.java",
            "class Runnable {}\nclass Worker extends Runnable {}\n",
        );
        let hold = Arc::new(PackWarmHold::new());
        let mut service = service_with_held_warm(root, Arc::clone(&hold));
        let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
        // The held helper avoids an unrelated startup usage warm; retain the
        // long-lived service's first-tool IndexWarmer scheduling contract. The
        // Java fixture keeps query_indexes_warm tied to its lazy external
        // declaration index, rather than the Rust facts that pack activation
        // can warm independently.
        service.startup_index_warm = StartupIndexWarm::AtStartup;

        service.wait_workspace_ready(&|| false).unwrap();
        service.ensure_ready().unwrap();
        hold.wait_for_worker_parked();

        let (snapshot, warmer) = {
            let guard = service.session.read().unwrap();
            let session = guard.as_ref().unwrap();
            (
                Arc::clone(&session.snapshot),
                Arc::clone(&session.index_warmer),
            )
        };
        // Keep semantic-pack activation parked: its independent work must not
        // satisfy the Java query-index sentinel before the first tool call.
        assert!(!snapshot.query_indexes_warm());

        service
            .call_tool_value("get_active_workspace", json!({}))
            .unwrap();
        warmer.wait_until_idle_within(std::time::Duration::from_secs(30));
        assert!(snapshot.query_indexes_warm());
    }

    #[test]
    fn snapshot_reinstall_schedules_a_background_index_warm() {
        let (_temp, root) = workspace(
            "lib.rs",
            "trait Runnable {}\npub struct Worker;\nimpl Runnable for Worker {}\n",
        );
        let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        {
            let guard = service.session.read().unwrap();
            assert!(!guard.as_ref().unwrap().snapshot.query_indexes_warm());
        }

        std::fs::write(
            root.join("lib.rs"),
            "trait Runnable {}\npub struct Worker;\npub struct Spare;\nimpl Runnable for Worker {}\n",
        )
        .unwrap();
        service
            .call_tool_value("update_paths", json!({"paths": ["lib.rs"]}))
            .unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let warm = {
                let guard = service.session.read().unwrap();
                guard.as_ref().unwrap().snapshot.query_indexes_warm()
            };
            if warm {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "background index warm did not complete"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A long-lived server session starts the Rust usage-fact catch-up at
    /// workspace startup, and `get_active_workspace` reports whether a query
    /// would wait for it. The reported field must track the session's own
    /// state rather than a constant, in both states (#1757; re-pointed from
    /// the whole-workspace index build).
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1758: Audit marked this BONE-tricky high: the readiness result can straddle warm completion and must reflect the session state (#1758)"
    )]
    fn workspace_startup_runs_the_usage_index_warm_and_reports_its_readiness() {
        let (_temp, root) = workspace("lib.rs", "pub fn root() {}\npub fn run() { root(); }\n");
        let service = SearchToolsService::new_deferred_manual(root).unwrap();
        service.ensure_ready().unwrap();

        let ready = || {
            let guard = service.session.read().unwrap();
            guard.as_ref().unwrap().usage_index_ready()
        };

        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            // `usage_index_ready` is a `JoinHandle::is_finished` read, so it
            // moves false -> true exactly once. Reading it only after the probe
            // compared two different instants: when the warm finished inside
            // the call, the probe's honest `false` met a later `true`.
            // Bracketing the call pins the probe to the state it could have
            // observed without weakening the claim. On every iteration where
            // the warm does not finish mid-call the two reads agree and the
            // probe must match exactly, so a constant `true` still fails the
            // first iteration and a constant `false` still never leaves the
            // loop. Only the one straddling iteration accepts either answer,
            // which is the only sound treatment of it.
            let before = ready();
            let reported = service
                .call_tool_value("get_active_workspace", json!({}))
                .unwrap();
            let after = ready();
            let reported_ready = &reported["usage_index_ready"];
            assert!(
                *reported_ready == json!(before) || *reported_ready == json!(after),
                "the probe reports the session's own readiness rather than a constant: \
                 reported {reported_ready} with readiness {before} before and {after} after"
            );
            if after {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the startup usage-index warm never finished"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Issue #3372, the #2377 family: the readiness barrier exists so the
    /// first tool call pays the workspace snapshot, not whatever optional work
    /// a background build has taken on. Semantic-pack activation is that kind
    /// of work -- it reads a local toolchain, verifies a release bundle, and
    /// decodes whole packs -- so a deferred build publishes its analyzer and
    /// lets the activation settle on its own thread.
    ///
    /// The build thread here holds the activation open on purpose. Before the
    /// fix the readiness wait covered it and this test fails on its deadline;
    /// after it, the snapshot installs while the warm is still running, the
    /// session says so, and the settled state arrives once the warm finishes.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3372: semantic-pack activation must not delay publishing the ready workspace snapshot"
    )]
    fn workspace_readiness_publishes_before_semantic_pack_activation_settles() {
        let (_temp, root) = workspace("Warm.java", "class Warm {}\n");
        let hold = Arc::new(PackWarmHold::new());
        let service = service_with_held_warm(root, Arc::clone(&hold));
        let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));

        let deadline = Some(Instant::now() + PACK_WARM_TEST_HANG_GUARD);
        service
            .wait_workspace_ready_until(&|| false, deadline)
            .expect("the workspace snapshot must be ready while the pack warm is held");
        service
            .ensure_ready()
            .expect("the published snapshot must install");
        assert!(
            !pack_warm_ready(&service),
            "the session must report the semantic-pack warm it is still running"
        );

        hold.release();
        let deadline = Instant::now() + PACK_WARM_TEST_HANG_GUARD;
        while !pack_warm_ready(&service) {
            assert!(
                Instant::now() < deadline,
                "the released semantic-pack warm never settled"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let guard = service.session.read().unwrap();
        let session = guard.as_ref().unwrap();
        assert!(
            session.semantic_packs.duration().is_some(),
            "a settled warm reports how long it ran, so a profile can name it"
        );
    }

    #[test]
    fn installed_pack_stage_publishes_its_settled_overlay() {
        let (_temp, root) = workspace("Warm.java", "class Warm {}\n");
        let hold = Arc::new(PackWarmHold::new());
        let service = service_with_held_warm(root, Arc::clone(&hold));
        let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
        service.ensure_ready().expect("workspace is ready");
        hold.wait_for_worker_parked();
        hold.release();
        let deadline = Instant::now() + PACK_WARM_TEST_HANG_GUARD;
        while !pack_warm_ready(&service) {
            assert!(
                Instant::now() < deadline,
                "semantic-pack warm never settled"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let active = service
            .call_tool_value("get_active_workspace", json!({}))
            .expect("workspace status");
        assert_eq!(
            active["semantic_model_overlay"]["state"], "no_models",
            "{active}"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "501b6d4e2c67: semantic-pack workers must finish before a closing workspace releases its store"
    )]
    fn closing_workspace_joins_semantic_pack_worker_before_releasing_store() {
        let (_temp, root) = workspace("Warm.java", "class Warm {}\n");
        let hold = Arc::new(PackWarmHold::new());
        let service = Arc::new(service_with_held_warm(root, Arc::clone(&hold)));
        let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
        service.ensure_ready().unwrap();
        let store = {
            let guard = service.session.read().unwrap();
            let session = guard.as_ref().unwrap();
            Arc::downgrade(
                session
                    .snapshot
                    .store()
                    .expect("persisted workspace has a store"),
            )
        };
        hold.wait_for_worker_parked();

        std::thread::scope(|scope| {
            let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
            let (closed_tx, closed_rx) = mpsc::channel();
            let closing_service = Arc::clone(&service);
            let closer = scope.spawn(move || {
                let close_result = closing_service.close();
                (close_result, closed_tx.send(()))
            });
            hold.wait_for_teardown_waiting();
            assert!(
                matches!(
                    closed_rx.recv_timeout(Duration::from_millis(100)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ),
                "close must stay blocked while the semantic-pack worker owns its analyzer clone"
            );

            hold.release_all();
            closed_rx
                .recv_timeout(PACK_WARM_TEST_HANG_GUARD)
                .expect("close completion signal did not arrive");
            let (close_result, signal_result) = closer.join().expect("close thread panicked");
            close_result.expect("close workspace");
            signal_result.expect("close completion receiver remained connected");
        });
        assert!(
            store.upgrade().is_none(),
            "close must return after the worker has released its analyzer store"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13391: optional index warm scheduling blocked a busy readiness probe"
    )]
    fn readiness_probe_returns_busy_with_production_warming_and_a_held_writer() {
        let (_temp, root) = workspace("Probe.java", "class Probe {}\n");
        let mut service = SearchToolsService::new_manual_ephemeral(root).unwrap();
        // Production deferred sessions enable this. The existing capability
        // test's OnDemand service bypassed post-call scheduling entirely.
        service.startup_index_warm = StartupIndexWarm::AtStartup;
        let service = Arc::new(service);
        let writer = service.session.write().unwrap();
        let probing = Arc::clone(&service);
        let (tx, rx) = mpsc::channel();
        let probe = std::thread::spawn(move || {
            let ordinary = probing.call_tool_value("get_active_workspace", json!({}));
            let preflight = probing.call_tool_output_with_transport_timings_and_preflight(
                "get_active_workspace",
                json!({}),
                RenderOptions::default(),
                None,
                TransportTimings::default(),
                None,
            );
            tx.send((ordinary, preflight)).unwrap();
        });
        let result = rx.recv_timeout(Duration::from_secs(30));
        drop(writer);
        probe.join().unwrap();
        let (ordinary, preflight) =
            result.expect("both full service wrappers must answer before the writer releases");
        for error in [ordinary.unwrap_err(), preflight.unwrap_err()] {
            assert_eq!(error.workspace_incomplete.unwrap().reason, "busy");
        }
        service.close().unwrap();
    }

    #[test]
    fn readiness_probe_answers_while_a_reader_and_queued_writer_hold_the_session() {
        let (_temp, root) = workspace("Probe.java", "class Probe {}\n");
        let service = Arc::new(SearchToolsService::new(root).unwrap());
        service.ensure_ready().unwrap();
        let reader = service.session.read().unwrap();
        let (writer_started_tx, writer_started_rx) = mpsc::channel();
        let writing = Arc::clone(&service);
        let writer = std::thread::spawn(move || {
            writer_started_tx.send(()).unwrap();
            drop(writing.session.write().unwrap());
        });
        writer_started_rx.recv().unwrap();
        let probing = Arc::clone(&service);
        let (tx, rx) = mpsc::channel();
        let probe = std::thread::spawn(move || {
            tx.send(probing.call_tool_value("get_active_workspace", json!({})))
                .unwrap()
        });
        let result = rx.recv_timeout(Duration::from_secs(30));
        drop(reader);
        writer.join().unwrap();
        probe.join().unwrap();
        match result.expect("probe must answer before the session reader is released") {
            Ok(value) => assert_eq!(value["analyzer_ready"], true),
            Err(error) => assert_eq!(error.workspace_incomplete.unwrap().reason, "busy"),
        }
        service.close().unwrap();
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13391: failed retirement startup changed the binding and joined old warms during activation"
    )]
    fn retirement_startup_failure_preserves_activation_and_retains_revoked_work() {
        let (_old_temp, old_root) = workspace("Old.java", "class Old {}\n");
        let (_new_temp, new_root) = workspace("New.java", "class New {}\n");
        let hold = Arc::new(PackWarmHold::new());
        let service = Arc::new(service_with_held_warm(old_root.clone(), Arc::clone(&hold)));
        let _release = ReleasePackWarmOnDrop(Arc::clone(&hold));
        service.ensure_ready().unwrap();
        hold.wait_for_worker_parked();
        let generation = service.workspace_generation();
        let store = {
            let guard = service.session.read().unwrap();
            Arc::downgrade(guard.as_ref().unwrap().snapshot.store().unwrap())
        };
        service.retired_sessions.lock().unwrap().fail_next_start = true;
        let (tx, rx) = mpsc::channel();
        let activating = Arc::clone(&service);
        let activator = std::thread::spawn(move || {
            tx.send(activating.call_tool_value(
                "activate_workspace",
                json!({"workspace_path":new_root.display().to_string()}),
            ))
            .unwrap()
        });
        let result = rx.recv_timeout(Duration::from_secs(30));
        if result.is_err() {
            hold.release_all();
        }
        activator.join().unwrap();
        let error = result
            .expect("failed activation must answer before the old warm releases")
            .unwrap_err();
        assert!(
            error
                .message
                .contains("injected retirement worker startup failure"),
            "{error}"
        );
        assert!(error.workspace_incomplete.is_none());
        assert_eq!(service.active_workspace_root(), Some(old_root));
        assert_eq!(service.workspace_generation(), generation);
        assert_eq!(service.lifetimes.count(), 1);
        assert!(
            service
                .workspace_build_progress(generation.wrapping_add(1))
                .is_none()
        );
        assert!(service.session.read().unwrap().as_ref().is_some());
        assert!(
            !service
                .session
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .semantic_packs
                .search_warm_cancellation
                .is_cancelled()
        );
        // Revocation must succeed even if that same OS resource remains absent.
        service.retired_sessions.lock().unwrap().fail_next_start = true;
        let (tx, rx) = mpsc::channel();
        let revoking = Arc::clone(&service);
        let unbinder =
            std::thread::spawn(move || tx.send(revoking.unbind_client_workspace()).unwrap());
        let result = rx.recv_timeout(Duration::from_secs(30));
        if result.is_err() {
            hold.release_all();
        }
        unbinder.join().unwrap();
        result
            .expect("revocation must answer before the old warm releases")
            .unwrap();
        assert!(service.active_workspace_root().is_none());
        assert_eq!(service.lifetimes.count(), 1);
        assert!(store.upgrade().is_some());
        let retirement = service.retired_sessions.lock().unwrap();
        assert!(retirement.worker.is_none());
        assert_eq!(retirement.pending.len(), 1);
        drop(retirement);
        hold.release_all();
        assert_eq!(
            service.close().unwrap_err().message,
            SearchToolsService::unbound_error().message
        );
        assert_eq!(service.lifetimes.count(), 0);
        assert!(store.upgrade().is_none());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13391: workspace activation waited for the superseded session's semantic warm"
    )]
    fn activation_retires_held_warms_without_waiting_and_close_joins_them() {
        let (_old_temp, old_root) = workspace("Old.java", "class Old {}\n");
        let (_new_temp, new_root) = workspace("New.java", "class New {}\n");
        let (_third_temp, third_root) = workspace("Third.java", "class Third {}\n");
        let hold = Arc::new(PackWarmHold::new());
        let service = Arc::new(service_with_held_warm(old_root.clone(), Arc::clone(&hold)));
        let _release = ReleasePackWarmOnDrop(Arc::clone(&hold));
        service.ensure_ready().unwrap();
        hold.wait_for_worker_parked();
        let store = {
            let guard = service.session.read().unwrap();
            Arc::downgrade(guard.as_ref().unwrap().snapshot.store().unwrap())
        };
        let (activated_tx, activated_rx) = mpsc::channel();
        let activating = Arc::clone(&service);
        let expected_root = new_root.display().to_string();
        let activator = std::thread::spawn(move || {
            let result = activating.call_tool_value(
                "activate_workspace",
                json!({"workspace_path": new_root.display().to_string()}),
            );
            activated_tx.send(result).unwrap();
        });
        let activated = activated_rx.recv_timeout(PACK_WARM_TEST_HANG_GUARD);
        if activated.is_err() {
            hold.release_all();
        }
        activator.join().expect("activation thread panicked");
        let activated = activated
            .expect("activation must answer before the old warm is released")
            .unwrap();
        assert_eq!(activated["workspace_path"], expected_root);
        hold.wait_for_teardown_waiting();
        assert!(store.upgrade().is_some());
        service.ensure_ready().unwrap();
        assert_eq!(service.lifetimes.count(), 2);
        let generation = service.workspace_generation();
        let refused = service
            .call_tool_value(
                "activate_workspace",
                json!({"workspace_path": third_root.display().to_string()}),
            )
            .unwrap_err();
        let incomplete = refused.workspace_incomplete.unwrap();
        assert_eq!(incomplete.reason, "workspace_not_ready");
        assert_eq!(incomplete.retiring_workspaces.len(), 1);
        assert_eq!(
            incomplete.retiring_workspaces[0].root,
            old_root.display().to_string()
        );
        assert_eq!(service.workspace_generation(), generation);
        assert_eq!(
            service
                .active_workspace_root()
                .unwrap()
                .display()
                .to_string(),
            expected_root
        );
        let probe = service
            .call_tool_value("get_active_workspace", json!({}))
            .unwrap();
        assert_eq!(probe["retiring_workspaces"].as_array().unwrap().len(), 1);
        // Revocation adds no replacement and is always permitted at capacity.
        service.unbind_client_workspace().unwrap();
        assert!(service.active_workspace_root().is_none());
        assert_eq!(service.lifetimes.count(), 2);
        let (closed_tx, closed_rx) = mpsc::channel();
        let closing = Arc::clone(&service);
        let closer = std::thread::spawn(move || closed_tx.send(closing.close()).unwrap());
        assert!(
            matches!(
                closed_rx.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "close must join the still-held retired warm"
        );
        hold.release_all();
        assert_eq!(
            closed_rx
                .recv_timeout(PACK_WARM_TEST_HANG_GUARD)
                .unwrap()
                .unwrap_err()
                .message,
            SearchToolsService::unbound_error().message
        );
        closer.join().expect("close thread panicked");
        assert!(
            store.upgrade().is_none(),
            "no retired store may outlive close"
        );
        assert_eq!(service.lifetimes.count(), 0);
        service
            .call_tool_value(
                "activate_workspace",
                json!({"workspace_path": third_root.display().to_string()}),
            )
            .unwrap();
        service.ensure_ready().unwrap();
        assert_eq!(service.lifetimes.count(), 1);
        service.close().unwrap();
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3401: a panicked semantic-pack worker must be joined without hiding its panic"
    )]
    fn closing_workspace_joins_panicked_semantic_pack_worker() {
        let (_temp, root) = workspace("Warm.java", "class Warm {}\n");
        let hold = Arc::new(PackWarmHold::new_panicking());
        let service = Arc::new(service_with_held_warm(root, Arc::clone(&hold)));
        let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
        service.ensure_ready().unwrap();
        let store = {
            let guard = service.session.read().unwrap();
            Arc::downgrade(
                guard
                    .as_ref()
                    .unwrap()
                    .snapshot
                    .store()
                    .expect("persisted workspace has a store"),
            )
        };
        hold.wait_for_worker_parked();

        std::thread::scope(|scope| {
            let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
            let closing_service = Arc::clone(&service);
            let closer = scope.spawn(move || closing_service.close());
            hold.wait_for_teardown_waiting();
            hold.release_all();
            closer.join().unwrap().unwrap();
        });
        assert!(
            store.upgrade().is_none(),
            "close must release the store even when the warm worker panics"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13479: a panic in the semantic-pack warm worker left its stage Pending forever"
    )]
    fn panicked_semantic_pack_worker_releases_waiter_and_reports_failure() {
        let (_temp, root) = workspace("Warm.java", "class Warm {}\n");
        let hold = Arc::new(PackWarmHold::new_panicking());
        let service = service_with_held_warm(root, Arc::clone(&hold));
        let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
        service.ensure_ready().unwrap();
        hold.wait_for_worker_parked();
        let warm = Arc::clone(
            &service
                .session
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .semantic_packs,
        );
        let waiting_warm = Arc::clone(&warm);
        let (started_tx, started_rx) = mpsc::channel();
        let (returned_tx, returned_rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            waiting_warm
                .wait_for_installed_stage(None)
                .expect("a Failed stage ends the installed-stage wait");
            returned_tx.send(()).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(30)).unwrap();
        assert!(matches!(
            returned_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        hold.release();
        // This watchdog detects a stuck waiter; it does not settle the stage.
        returned_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("a worker panic must release the installed-stage waiter");
        waiter.join().expect("installed-stage waiter panicked");
        let cause = match &*warm.state.lock().unwrap() {
            PackWarmState::Failed(cause) => cause.clone(),
            _ => panic!("panicked worker must publish Failed"),
        };
        assert!(
            cause.contains("injected semantic-pack warm failure"),
            "{cause}"
        );
        assert!(matches!(
            warm.snapshot_phase(),
            SessionPackActivation::Failed(_)
        ));
        assert!(warm.wait().is_none());
        // The guard publishes Failed and lets the panic keep unwinding, so a
        // join of the worker still receives the panic. Join here, before any
        // tool call: get_active_workspace reaps an exited worker itself.
        // Teardown's own join and report are pinned by
        // closing_workspace_joins_panicked_semantic_pack_worker.
        let worker = warm
            .worker
            .lock()
            .unwrap()
            .take()
            .expect("nothing reaps the warm worker before a tool call");
        let panic = worker
            .join()
            .expect_err("the unwind guard must not swallow the worker's panic");
        let message = brokk_bifrost_core::panic_report::panic_payload_message(panic.as_ref());
        assert!(
            message.contains("injected semantic-pack warm failure"),
            "{message}"
        );
        let active = service
            .call_tool_value("get_active_workspace", json!({}))
            .unwrap();
        assert_eq!(active["semantic_packs_ready"], true, "{active}");
        assert_eq!(
            active["semantic_model_overlay"]["state"], "unavailable",
            "{active}"
        );
        assert_eq!(
            active["semantic_model_overlay"]["reason"], cause,
            "{active}"
        );
        service.close().unwrap();
    }

    /// Issue #3401: a `query_code` that could have used the packs the
    /// expensive stage is still acquiring awaits the installed stage and then
    /// answers with the pending state named in its own diagnostics, never as
    /// a silently pack-blind complete result. Once the warm settles, the
    /// identical query carries no marker.
    ///
    /// The fixture's `node_modules/lodash` is a producible npm dependency the
    /// empty ambient catalog cannot settle from installed packs, so the
    /// warm's installed stage publishes an interim activation with the
    /// acquisition pending. The hold parks the expensive stage there: the
    /// query returning at all proves it did not wait for production.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3372: query_code must mark potentially model-dependent answers while acquisition is pending"
    )]
    fn query_code_marks_pending_pack_acquisition_until_the_warm_settles() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("workspace");
        std::fs::create_dir_all(root.join("node_modules/lodash")).unwrap();
        std::fs::write(
            root.join("app.js"),
            "const _ = require('lodash');\nconsole.log(_.trim(' x '));\n",
        )
        .unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{ "name": "app", "version": "1.0.0", "dependencies": { "lodash": "4.17.21" } }"#,
        )
        .unwrap();
        std::fs::write(
            root.join("package-lock.json"),
            r#"{
              "name": "app",
              "version": "1.0.0",
              "lockfileVersion": 3,
              "packages": {
                "": { "name": "app", "version": "1.0.0", "dependencies": { "lodash": "4.17.21" } },
                "node_modules/lodash": { "version": "4.17.21" }
              }
            }"#,
        )
        .unwrap();
        std::fs::write(
            root.join("node_modules/lodash/package.json"),
            r#"{ "name": "lodash", "version": "4.17.21", "main": "index.js" }"#,
        )
        .unwrap();
        std::fs::write(
            root.join("node_modules/lodash/index.js"),
            "exports.trim = function (value) { return value.trim(); };\n",
        )
        .unwrap();
        std::fs::write(
            root.join("node_modules/lodash/index.d.ts"),
            "export declare function trim(value: string): string;\n",
        )
        .unwrap();
        std::fs::write(
            root.join("flow.py"),
            "def source_one():\n    return 'input'\ndef sink_one(value):\n    pass\ndef run():\n    sink_one(source_one())\n",
        )
        .unwrap();
        let root = root.canonicalize().unwrap().normalize();

        let policy = PolicyEvaluationInput::embedded(
            crate::policy::PolicySourceIdentity::new("test:pending-flow.rqlp"),
            r#"(policy
                  :schema-version 1
                  :id "test.pending.flow"
                  :name "Pending flow"
                  :message "source reaches sink"
                  :severity warning
                  :analysis (analysis
                    :type taint
                    :mode may
                    :call-modeling (call-modeling :unmodeled optimistic)
                    :sources (endpoint-set :entries [
                      (source :id input :display-name "input" :categories [input.user]
                        :selector (rql :schema-version 1
                          (language python (call :callee (name "source_one"))))
                        :bind return-value :labels [untrusted])])
                    :sinks (endpoint-set :entries [
                      (sink :id output :display-name "output" :categories [data.sensitive]
                        :selector (rql :schema-version 1
                          (language python (call :callee (name "sink_one"))))
                        :dangerous-operand (argument :index 0) :accepts [untrusted])]))
                  :classification (classification
                    :fallback (classification-id :taxonomy "Test" :id "PENDING-FLOW")))"#,
        );

        let query = || {
            json!({
                "schema_version": 1,
                "languages": ["javascript"],
                "match": {"kind": "call", "callee": {"name": "trim"}},
            })
        };
        let (hold, expensive_stage) = PackWarmHold::new_holding_expensive_stage();
        let hold = Arc::new(hold);
        let service = service_with_held_warm(root.clone(), Arc::clone(&hold));
        let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));

        hold.release();
        let options =
            PolicyEvaluationOptions::new(PolicyEvaluationDate::from_ymd(2026, 9, 3).unwrap());
        let outcome = service
            .evaluate_policy_inputs(&root, &[policy], &options, &Default::default())
            .unwrap();
        assert_eq!(outcome.taint_findings().len(), 1);
        let flow_plan = Arc::new(
            outcome.taint_analysis_results()[0]
                .plan()
                .value_flow()
                .clone(),
        );
        service
            .register_query_value_flow_plan("test:pending-flow".parse().unwrap(), flow_plan)
            .unwrap();
        let flow_query = || {
            json!({
                "schema_version": 1,
                "match": {"kind": "function", "name": "run"},
                "steps": [
                    {"op": "procedure_of"},
                    {"op": "value_flow", "plan_ref": "test:pending-flow"}
                ]
            })
        };
        // Preparation waits for the installed stage, so when it returns the
        // session has published its interim activation while the expensive
        // stage is still parked. The query returning at all, rather than
        // blocking behind the parked production, is the #3372 half of the
        // contract; the diagnostic it carries is the #3401 half.
        let source_query = json!({
            "schema_version": 1,
            "languages": ["javascript"],
            "where": ["app.js"],
            "match": {"kind": "function", "name": "missing"},
        });
        let prepared_source = service
            .prepare_query_code(source_query, None)
            .expect("prepare source-only query during acquisition");
        let source_output = service
            .execute_prepared_query_code(prepared_source, None)
            .expect("execute source-only query during acquisition");
        let source_result = source_output.into_value();
        assert!(
            source_result["diagnostics"]
                .as_array()
                .is_none_or(|diagnostics| diagnostics.iter().all(|diagnostic| {
                    diagnostic["code"] != "semantic_pack_acquisition_pending"
                })),
            "file-scoped declaration coverage does not depend on pending packs: {source_result:#}"
        );

        let prepared = service
            .prepare_query_code(query(), None)
            .expect("prepare query against the interim activation");
        let output = service
            .execute_prepared_query_code(prepared, None)
            .expect("execute query against the interim activation");
        let structured = output.into_value();
        let diagnostics = structured["diagnostics"]
            .as_array()
            .expect("the interim answer must carry the pending diagnostic");
        assert!(
            diagnostics.iter().any(|diagnostic| {
                diagnostic["code"] == "semantic_pack_acquisition_pending"
                    && diagnostic["impact"] == "incomplete"
            }),
            "the interim answer names its pending acquisition: {structured:#}"
        );

        let pending_flow = service.call_tool_value("query_code", flow_query()).unwrap();
        let pending_rows = pending_flow["results"].as_array().unwrap();
        assert!(!pending_rows.is_empty());
        assert!(
            pending_rows
                .iter()
                .all(|row| { row["result_type"] == "flow_endpoint" && row["status"] == "partial" })
        );
        assert!(
            pending_flow["diagnostics"]
                .as_array()
                .is_some_and(|diagnostics| diagnostics.iter().any(|diagnostic| {
                    diagnostic["code"] == "semantic_pack_acquisition_pending"
                        && diagnostic["impact"] == "incomplete"
                })),
            "flow answer must name the pending dependency: {:?}",
            pending_flow["diagnostics"]
        );

        expensive_stage.release();
        let deadline = Instant::now() + Duration::from_secs(60);
        while !pack_warm_ready(&service) {
            assert!(
                Instant::now() < deadline,
                "the released expensive stage never settled"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let prepared = service
            .prepare_query_code(query(), None)
            .expect("prepare query against the settled activation");
        let output = service
            .execute_prepared_query_code(prepared, None)
            .expect("execute query against the settled activation");
        let structured = output.into_value();
        let still_marked = structured["diagnostics"]
            .as_array()
            .is_some_and(|diagnostics| {
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic["code"] == "semantic_pack_acquisition_pending")
            });
        assert!(
            !still_marked,
            "the settled answer carries no pending marker: {structured:#}"
        );
        let settled_flow = service.call_tool_value("query_code", flow_query()).unwrap();
        let settled_rows = settled_flow["results"].as_array().unwrap();
        assert!(!settled_rows.is_empty());
        assert!(
            settled_rows.iter().all(|row| {
                row["result_type"] == "flow_endpoint" && row["status"] == "complete"
            }),
            "settled flow statuses: {:?}",
            settled_rows
                .iter()
                .map(|row| &row["status"])
                .collect::<Vec<_>>()
        );
        assert!(
            settled_flow["diagnostics"]
                .as_array()
                .is_none_or(|diagnostics| diagnostics
                    .iter()
                    .all(|diagnostic| diagnostic["code"] != "semantic_pack_acquisition_pending"))
        );
    }

    fn service_with_pending_npm_pack() -> (
        tempfile::TempDir,
        Arc<SearchToolsService>,
        Arc<PackWarmHold>,
        Arc<ExpensiveStageHold>,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join("node_modules/lodash")).unwrap();
        std::fs::write(
            root.join("app.js"),
            "const _ = require('lodash');\n_.trim(' x ');\n",
        )
        .unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("package-lock.json"),
            r#"{"name":"app","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.21"}},"node_modules/lodash":{"version":"4.17.21"}}}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("node_modules/lodash/package.json"),
            r#"{"name":"lodash","version":"4.17.21","main":"index.js"}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("node_modules/lodash/index.js"),
            "exports.trim = value => value.trim();\n",
        )
        .unwrap();
        std::fs::write(
            root.join("node_modules/lodash/index.d.ts"),
            "export declare function trim(value: string): string;\n",
        )
        .unwrap();
        let (hold, expensive_stage) = PackWarmHold::new_holding_expensive_stage();
        let hold = Arc::new(hold);
        let service = Arc::new(service_with_held_warm(
            root.canonicalize().unwrap().normalize(),
            Arc::clone(&hold),
        ));
        (temp, service, hold, expensive_stage)
    }

    fn wait_for_pending_npm_pack(service: &SearchToolsService, hold: &PackWarmHold) {
        hold.release();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let active = service
                .call_tool_value("get_active_workspace", json!({}))
                .expect("workspace status");
            if active["semantic_model_overlay"]["stage"] == "acquisition_pending" {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "pack acquisition never became pending: {active}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13182: explain_policy answered during a pending pack acquisition without saying the answer may lack models"
    )]
    fn explain_policy_states_a_pending_pack_acquisition_and_answers_unknown() {
        let (temp, service, hold, expensive_stage) = service_with_pending_npm_pack();
        let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
        std::fs::write(
            temp.path().join("policy.rqlp"),
            r#"(policy
  :id "test.explain.widget"
  :name "Widget render"
  :message "Widget render is reported"
  :severity warning
  :analysis (analysis :type match :selector
    (rql (inside-decl (class :name "Widget") (method :name "render")))))"#,
        )
        .unwrap();
        wait_for_pending_npm_pack(&service, &hold);

        let expected_status = |status: &Value| {
            assert_eq!(status["state"], "pending", "{status}");
            assert_eq!(status["stage"], "acquisition_pending", "{status}");
            let pending = status["pending_acquisitions"].as_array().unwrap();
            assert!(
                !pending.is_empty()
                    && pending.iter().all(|entry| entry["ecosystem"] == "npm"
                        && entry["dependency_id"]
                            .as_str()
                            .is_some_and(|id| id.contains("lodash"))),
                "{status}"
            );
        };
        let explained = service
            .call_tool_value(
                "explain_policy",
                json!({
                    "policy_files": ["policy.rqlp"],
                    "candidate": {"path": "app.js", "byte_start": 0, "byte_end": 1}
                }),
            )
            .expect("explain_policy answers while the acquisition is pending");
        let explanation = &explained["explanation"];
        expected_status(&explanation["semantic_models"]);
        assert_eq!(explanation["outcome"], "unknown", "{explained:#}");
        let obligation = &explanation["root"]["children"][0];
        assert_eq!(obligation["kind"], "coverage_obligation", "{explained:#}");
        assert!(
            obligation["actual"].as_str().is_some_and(|text| text
                .contains("Waiting to acquire npm:")
                && text.contains("lodash")),
            "{explained:#}"
        );

        let ranked = service
            .call_tool_value(
                "explain_policy",
                json!({
                    "policy_files": ["policy.rqlp"],
                    "near_misses": {"enumerate_from_policy_seed": true}
                }),
            )
            .expect("near-miss ranking answers while the acquisition is pending");
        let ranking = &ranked["near_miss_ranking"];
        expected_status(&ranking["semantic_models"]);
        assert!(
            ranking["entries"]
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| entry["outcome"] == "unknown"),
            "{ranked:#}"
        );
        expensive_stage.release();
    }

    #[test]
    fn pending_pack_acquisition_publishes_final_outcome() {
        let (_temp, service, hold, expensive_stage) = service_with_pending_npm_pack();
        let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
        wait_for_pending_npm_pack(&service, &hold);
        expensive_stage.release();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let active = service
                .call_tool_value("get_active_workspace", json!({}))
                .expect("workspace status");
            if active["semantic_packs_ready"] == true {
                assert_ne!(
                    active["semantic_model_overlay"]["state"], "unavailable",
                    "{active}"
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "pack acquisition never settled: {active}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6397: repeated pack refreshes stacked unfinished warm workers"
    )]
    fn pack_refreshes_coalesce_while_a_warm_is_held() {
        let (_temp, root) = workspace("A.java", "class A {}\n");
        let hold = Arc::new(PackWarmHold::new());
        let service = service_with_held_warm(root.clone(), Arc::clone(&hold));
        let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
        service.ensure_ready().unwrap();
        hold.wait_for_worker_parked();
        let first = {
            let mut guard = service.session.write().unwrap();
            let session = guard.as_mut().unwrap();
            let first = Arc::clone(&session.semantic_packs);
            for _ in 0..4 {
                session.refresh_pack_activation();
                assert!(Arc::ptr_eq(&session.semantic_packs, &first));
                assert!(session.retired_pack_warms.is_empty());
                assert!(matches!(
                    session.pack_activation(),
                    SessionPackActivation::WarmPending
                ));
            }
            first
        };
        hold.release();
        first.wait();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            service.snapshot_for_query_with_cancellation(None).unwrap();
            let guard = service.session.read().unwrap();
            let session = guard.as_ref().unwrap();
            if !Arc::ptr_eq(&session.semantic_packs, &first) {
                assert!(session.retired_pack_warms.is_empty());
                break;
            }
            assert!(Instant::now() < deadline, "replacement warm never started");
            drop(guard);
            std::thread::sleep(Duration::from_millis(10));
        }
        let replacement = {
            let guard = service.session.read().unwrap();
            Arc::clone(&guard.as_ref().unwrap().semantic_packs)
        };
        replacement.wait();
        service.snapshot_for_query_with_cancellation(None).unwrap();
        let guard = service.session.read().unwrap();
        let session = guard.as_ref().unwrap();
        assert!(Arc::ptr_eq(&session.semantic_packs, &replacement));
        assert!(matches!(
            session.pack_activation(),
            SessionPackActivation::Settled(_)
        ));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6397: status polling left a coalesced pack refresh pending after its worker exited"
    )]
    fn active_workspace_settles_coalesced_pack_refresh() {
        let (_temp, root) = workspace("A.java", "class A {}\n");
        let hold = Arc::new(PackWarmHold::new());
        let service = service_with_held_warm(root, Arc::clone(&hold));
        let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
        service.ensure_ready().unwrap();
        hold.wait_for_worker_parked();
        let first = {
            let mut guard = service.session.write().unwrap();
            let session = guard.as_mut().unwrap();
            let first = Arc::clone(&session.semantic_packs);
            session.refresh_pack_activation();
            assert_eq!(session.refresh, PackRefresh::DeferredWhole);
            first
        };
        hold.release();
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut seen_replacement: Option<Arc<SemanticPackWarm>> = None;
        let replacement = loop {
            let active = service
                .call_tool_value("get_active_workspace", json!({}))
                .unwrap();
            let guard = service.session.read().unwrap();
            let session = guard.as_ref().unwrap();
            if !Arc::ptr_eq(&session.semantic_packs, &first) {
                if let Some(seen) = &seen_replacement {
                    assert!(Arc::ptr_eq(&session.semantic_packs, seen));
                } else {
                    seen_replacement = Some(Arc::clone(&session.semantic_packs));
                }
            }
            if active["semantic_packs_ready"] == true {
                assert!(!Arc::ptr_eq(&session.semantic_packs, &first));
                assert_eq!(session.refresh, PackRefresh::Idle);
                assert!(matches!(
                    session.pack_activation(),
                    SessionPackActivation::Settled(_)
                ));
                assert!(session.retired_pack_warms.is_empty());
                break Arc::clone(&session.semantic_packs);
            }
            assert!(Instant::now() < deadline, "status never settled: {active}");
            drop(guard);
            std::thread::sleep(Duration::from_millis(10));
        };
        for _ in 0..3 {
            let active = service
                .call_tool_value("get_active_workspace", json!({}))
                .unwrap();
            assert_eq!(active["semantic_packs_ready"], true);
            let guard = service.session.read().unwrap();
            assert!(Arc::ptr_eq(
                &guard.as_ref().unwrap().semantic_packs,
                &replacement
            ));
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon("#9840: an edit during the first warm lost activation")]
    fn edit_during_initial_warm_schedules_whole_activation() {
        let (_temp, root) = workspace("A.java", "class A {}\n");
        let hold = Arc::new(PackWarmHold::new());
        let service = service_with_held_warm(root.clone(), Arc::clone(&hold));
        let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
        service.ensure_ready().unwrap();
        hold.wait_for_worker_parked();
        std::fs::write(root.join("A.java"), "class A { int value; }\n").unwrap();
        service
            .call_tool_value("update_paths", json!({"paths": ["A.java"]}))
            .unwrap();
        {
            let guard = service.session.read().unwrap();
            let session = guard.as_ref().unwrap();
            assert!(session.snapshot.requires_whole_dependency_refresh());
            assert_eq!(session.refresh, PackRefresh::DeferredWhole);
        }
        hold.release();
        let deadline = Instant::now() + PACK_WARM_TEST_HANG_GUARD;
        loop {
            let active = service
                .call_tool_value("get_active_workspace", json!({}))
                .unwrap();
            if active["semantic_packs_ready"] == true {
                let snapshot = service.analyzer_snapshot().unwrap();
                assert!(!snapshot.requires_whole_dependency_refresh());
                assert!(snapshot.carried_activation_request().is_some());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "whole activation never settled: {active}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12441: the watcher's event for an edit refresh had already read restarted pack activation, so query_code answered before the installed stage"
    )]
    fn query_after_refresh_answers_after_the_installed_pack_stage() {
        let (_temp, root) = workspace("app.py", "def run(value):\n    return eval(value)\n");
        let service = SearchToolsService::new(root.clone()).unwrap();
        let query = json!({
            "schema_version": "1",
            "languages": ["python"],
            "match": {"kind": "call", "callee": {"name": "eval"}},
        });
        // Whether acquisition is still running depends on the host's pack
        // cache and download setting; a request that answers before the
        // installed stage published is the defect, whatever the host.
        let answers_after_installed_stage = |service: &SearchToolsService| {
            let prepared = service.prepare_query_code(query.clone(), None).unwrap();
            !matches!(
                prepared.snapshot.pack_activation,
                SessionPackActivation::WarmPending
            )
        };
        assert!(answers_after_installed_stage(&service));

        std::fs::write(
            root.join("app.py"),
            "def run(value):\n    return parse(value)\n",
        )
        .unwrap();
        service.call_tool_value("refresh", json!({})).unwrap();
        // `refresh` read the edit from disk, but the watcher still reports
        // it; the next query drains that delta itself.
        let deadline = Instant::now() + Duration::from_secs(30);
        while !{
            let guard = service.session.read().unwrap();
            SearchToolsService::session_watcher_has_pending(guard.as_ref().unwrap())
        } {
            assert!(
                Instant::now() < deadline,
                "the watcher never reported the edit"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(answers_after_installed_stage(&service));
    }

    fn wait_for_query_delta(service: &SearchToolsService) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let guard = service.session.read().unwrap();
            if SearchToolsService::session_watcher_has_pending(guard.as_ref().unwrap()) {
                return;
            }
            drop(guard);
            assert!(Instant::now() < deadline, "source event was not delivered");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn watching_service_with_held_warm(
        root: PathBuf,
        hold: Arc<PackWarmHold>,
    ) -> SearchToolsService {
        let mut service = service_with_held_warm(root, hold);
        service.ensure_ready().unwrap();
        let mut guard = service.session.write().unwrap();
        let session = guard.as_mut().unwrap();
        session.watcher = SessionWatcher::Active(Box::new(
            ProjectChangeWatcher::start(Arc::new(
                FilesystemProject::new(session.snapshot.analyzer().project().root()).unwrap(),
            ))
            .unwrap(),
        ));
        drop(guard);
        service.update_strategy = UpdateStrategy::WatchFiles;
        service
    }

    #[test]
    #[hardwon("#13331: a late watcher batch answered from an unsettled overlay")]
    fn issue_13331_edit_during_settle_reads_latest_installed_snapshot() {
        let (_temp, root) = workspace("app.py", "def before():\n    pass\n");
        let hold = Arc::new(PackWarmHold::new());
        let service = Arc::new(watching_service_with_held_warm(
            root.clone(),
            Arc::clone(&hold),
        ));
        let _release = ReleasePackWarmOnDrop(Arc::clone(&hold));
        hold.wait_for_worker_parked();
        let (waiting_tx, waiting_rx) = mpsc::channel();
        let once = AtomicBool::new(false);
        *service.snapshot_acquisition_observer.lock().unwrap() = Some(Arc::new(move |point| {
            if point == SnapshotAcquisitionPoint::BeforeInstalledWait
                && !once.swap(true, Ordering::SeqCst)
            {
                waiting_tx.send(()).unwrap();
            }
        }));
        std::fs::write(root.join("app.py"), "def middle():\n    pass\n").unwrap();
        wait_for_query_delta(&service);
        std::thread::scope(|threads| {
            let _release_on_unwind = ReleasePackWarmOnDrop(Arc::clone(&hold));
            let query = threads.spawn(|| {
                service.prepare_query_code(
                    json!({
                        "schema_version": 1, "languages": ["python"],
                        "match": {"kind": "function", "name": "latest"}
                    }),
                    None,
                )
            });
            waiting_rx.recv_timeout(Duration::from_secs(30)).unwrap();
            std::fs::write(root.join("app.py"), "def latest():\n    pass\n").unwrap();
            wait_for_query_delta(&service);
            hold.release();
            let prepared = query.join().unwrap().unwrap();
            assert!(!matches!(
                prepared.snapshot.pack_activation,
                SessionPackActivation::WarmPending
            ));
            assert!(prepared.snapshot.enter().analyzer().indexed_source_matches(
                &ProjectFile::new(root.clone(), "app.py"),
                "def latest():\n    pass\n"
            ));
            let structured = service
                .execute_prepared_query_code(prepared, None)
                .unwrap()
                .into_value();
            assert!(
                !structured["results"].as_array().unwrap().is_empty(),
                "{structured}"
            );
        });
    }

    #[test]
    #[hardwon("#13331: snapshot replacement after settling escaped installed-stage readiness")]
    fn issue_13331_concurrent_replacement_after_settle_is_settled_again() {
        let (_temp, root) = workspace("app.py", "def before():\n    pass\n");
        let service = Arc::new(SearchToolsService::new_manual_ephemeral(root.clone()).unwrap());
        let weak = Arc::downgrade(&service);
        let once = AtomicBool::new(false);
        *service.snapshot_acquisition_observer.lock().unwrap() = Some(Arc::new(move |point| {
            if point == SnapshotAcquisitionPoint::AfterSettle && !once.swap(true, Ordering::SeqCst)
            {
                std::fs::write(root.join("app.py"), "def replacement():\n    pass\n").unwrap();
                weak.upgrade()
                    .unwrap()
                    .call_tool_value("update_paths", json!({"paths": ["app.py"]}))
                    .unwrap();
            }
        }));
        let prepared = service
            .prepare_query_code(
                json!({
                    "schema_version": 1, "languages": ["python"],
                    "match": {"kind": "function", "name": "replacement"}
                }),
                None,
            )
            .unwrap();
        assert!(!matches!(
            prepared.snapshot.pack_activation,
            SessionPackActivation::WarmPending
        ));
        let structured = service
            .execute_prepared_query_code(prepared, None)
            .unwrap()
            .into_value();
        assert!(
            !structured["results"].as_array().unwrap().is_empty(),
            "{structured}"
        );
    }

    #[test]
    #[hardwon(
        "#13331: repeated edits during an installed-stage wait must stop at the request deadline"
    )]
    fn issue_13331_continuous_deltas_stop_at_deadline_without_scope() {
        let (_temp, root) = workspace("app.py", "def initial():\n    pass\n");
        let hold = Arc::new(PackWarmHold::new());
        let service = watching_service_with_held_warm(root.clone(), Arc::clone(&hold));
        let _release = ReleasePackWarmOnDrop(Arc::clone(&hold));
        hold.wait_for_worker_parked();
        let cancellation = CancellationToken::default().with_timeout(Duration::from_millis(200));
        let finished = AtomicBool::new(false);
        std::thread::scope(|threads| {
            let editor = threads.spawn(|| {
                let mut edits = 0;
                while !finished.load(Ordering::Acquire) {
                    std::fs::write(
                        root.join("app.py"),
                        format!("def edited_{edits}():\n    pass\n"),
                    )
                    .unwrap();
                    edits += 1;
                    std::thread::sleep(Duration::from_millis(5));
                }
                edits
            });
            let result = service.snapshot_for_query_with_cancellation(Some(&cancellation));
            finished.store(true, Ordering::Release);
            assert!(editor.join().unwrap() > 1);
            let error = result
                .err()
                .expect("deadline must not return a pending scope");
            assert_eq!(error.code, SearchToolsServiceErrorCode::DeadlineExceeded);
            assert!(cancellation.is_timed_out());
            // The request returned while activation was still parked.
            assert!(!*hold.released.lock().unwrap());
            hold.release();
        });
    }

    #[test]
    #[hardwon(
        "#13331: duplicate watcher events during settling repeated an explicit update_paths update"
    )]
    fn issue_13331_hosted_duplicate_during_settle_keeps_snapshot() {
        let (_temp, root) = workspace("app.py", "def before():\n    pass\n");
        let service = Arc::new(SearchToolsService::new(root.clone()).unwrap());
        std::fs::write(root.join("app.py"), "def latest():\n    pass\n").unwrap();
        service
            .call_tool_value("update_paths", json!({"paths": ["app.py"]}))
            .unwrap();
        service.snapshot_for_query_with_cancellation(None).unwrap();
        let published = {
            let guard = service.session.read().unwrap();
            Arc::clone(&guard.as_ref().unwrap().snapshot)
        };
        let weak = Arc::downgrade(&service);
        let once = AtomicBool::new(false);
        *service.snapshot_acquisition_observer.lock().unwrap() = Some(Arc::new(move |point| {
            if point == SnapshotAcquisitionPoint::AfterSettle && !once.swap(true, Ordering::SeqCst)
            {
                // A new native event, but its content is already indexed by the fence.
                std::fs::write(root.join("app.py"), "def latest():\n    pass\n").unwrap();
                wait_for_query_delta(&weak.upgrade().unwrap());
            }
        }));
        let scope = service.snapshot_for_query_with_cancellation(None).unwrap();
        assert!(
            Arc::ptr_eq(&published, &scope.source_snapshot),
            "duplicate source events performed another update"
        );
        assert!(!matches!(
            scope.pack_activation,
            SessionPackActivation::WarmPending
        ));
    }

    #[test]
    #[hardwon(
        "#13331: a watched checkout returned a pending snapshot instead of the latest settled answer"
    )]
    fn issue_13331_real_linked_worktree_checkout_matches_fresh_query() {
        let (temp, root) = workspace("app.py", "def before():\n    pass\n");
        let repo = git2::Repository::init(&root).unwrap();
        let signature = git2::Signature::now("test", "test@example.com").unwrap();
        let commit = |message: &str, parents: &[&git2::Commit<'_>]| {
            let mut index = repo.index().unwrap();
            index.add_path(Path::new("app.py")).unwrap();
            index.write().unwrap();
            let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
            repo.commit(
                Some("HEAD"),
                &signature,
                &signature,
                message,
                &tree,
                parents,
            )
            .unwrap()
        };
        let old = commit("old tree", &[]);
        std::fs::write(root.join("app.py"), "def latest():\n    pass\n").unwrap();
        commit("new tree", &[&repo.find_commit(old).unwrap()]);
        let linked = temp.path().join("linked");
        repo.worktree("query-linked", &linked, None).unwrap();
        let linked = linked.canonicalize().unwrap();
        let service = SearchToolsService::new(linked.clone()).unwrap();
        let query = json!({"schema_version": 1, "languages": ["python"], "match": {"kind": "function", "name": "before"}});
        let initial = service
            .call_tool_value("query_code", query.clone())
            .unwrap();
        assert!(
            initial["results"].as_array().unwrap().is_empty(),
            "{initial}"
        );
        let output = std::process::Command::new("git")
            .current_dir(&linked)
            .args(["checkout", "--detach", &old.to_string()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        wait_for_query_delta(&service);
        let prepared = service.prepare_query_code(query.clone(), None).unwrap();
        assert!(!matches!(
            prepared.snapshot.pack_activation,
            SessionPackActivation::WarmPending
        ));
        let immediate = service
            .call_tool_value("query_code", query.clone())
            .unwrap();
        assert!(
            !immediate["results"].as_array().unwrap().is_empty(),
            "{immediate}"
        );
        assert_eq!(immediate["truncated"], false, "{immediate}");
        let deadline = Instant::now() + Duration::from_secs(30);
        while !pack_warm_ready(&service) {
            assert!(Instant::now() < deadline, "the pack stage never settled");
            std::thread::sleep(Duration::from_millis(10));
        }
        let answer = service
            .call_tool_value("query_code", query.clone())
            .unwrap();
        let fresh = SearchToolsService::new_manual_ephemeral(linked)
            .unwrap()
            .call_tool_value("query_code", query)
            .unwrap();
        assert!(
            !answer["results"].as_array().unwrap().is_empty(),
            "{answer}"
        );
        assert_eq!(answer["truncated"], false, "{answer}");
        assert!(
            answer["diagnostics"]
                .as_array()
                .is_none_or(|diagnostics| diagnostics.is_empty()),
            "{answer}"
        );
        assert_eq!(answer, fresh);
    }

    #[test]
    #[hardwon("#13331: a deferred installed stage retried an occupied worker slot without waiting")]
    fn issue_13331_deferred_stage_waits_for_worker_slot_with_deadline() {
        let (_temp, service, hold, expensive_stage) = service_with_pending_npm_pack();
        let _release = ReleasePackWarmOnDrop(Arc::clone(&hold));
        wait_for_pending_npm_pack(&service, &hold);
        service.call_tool_value("refresh", json!({})).unwrap();
        let old = {
            let guard = service.session.read().unwrap();
            let session = guard.as_ref().unwrap();
            assert_ne!(session.refresh, PackRefresh::Idle);
            Arc::clone(&session.semantic_packs)
        };
        let token = CancellationToken::default().with_timeout(Duration::from_millis(100));
        let error = service
            .snapshot_for_query_with_cancellation(Some(&token))
            .err()
            .expect("an occupied slot must obey the request deadline");
        assert_eq!(error.code, SearchToolsServiceErrorCode::DeadlineExceeded);
        assert!(!*expensive_stage.released.lock().unwrap());
        {
            let guard = service.session.read().unwrap();
            assert!(Arc::ptr_eq(&old, &guard.as_ref().unwrap().semantic_packs));
        }
        // Explicit cancellation also wakes an unbudgeted library waiter via
        // the bounded cancellation poll, without turning that poll into success.
        let cancellation = CancellationToken::new();
        std::thread::scope(|threads| {
            let cancel = threads.spawn(|| {
                std::thread::sleep(Duration::from_millis(50));
                cancellation.cancel();
            });
            let error = service
                .snapshot_for_query_with_cancellation(Some(&cancellation))
                .err()
                .expect("explicit cancellation must stop slot acquisition");
            cancel.join().unwrap();
            assert_eq!(error.code, SearchToolsServiceErrorCode::Internal);
        });
        expensive_stage.release();
        let scope = service.snapshot_for_query_with_cancellation(None).unwrap();
        assert!(!matches!(
            scope.pack_activation,
            SessionPackActivation::WarmPending
        ));
        let guard = service.session.read().unwrap();
        assert!(!Arc::ptr_eq(&old, &guard.as_ref().unwrap().semantic_packs));
    }

    #[test]
    fn refresh_does_not_wait_for_a_running_pack_warm() {
        let (_temp, service, hold, expensive_stage) = service_with_pending_npm_pack();
        let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
        wait_for_pending_npm_pack(&service, &hold);
        // The startup warm is parked in its expensive stage. A refresh marks
        // it stale and returns without waiting under session.write (#6397).
        let (sender, receiver) = mpsc::channel();
        let refresh_service = Arc::clone(&service);
        let refresh = std::thread::spawn(move || {
            sender
                .send(refresh_service.call_tool_value("refresh", json!({})))
                .unwrap();
        });
        receiver
            .recv_timeout(Duration::from_secs(60))
            .expect("refresh waited for the parked semantic-pack warm")
            .expect("refresh succeeds");
        refresh.join().expect("refresh thread");
        expensive_stage.release();
    }

    /// A service whose deferred build assembles its session with the pack
    /// warm parked on `hold`, so a test decides when each warm stage runs.
    fn service_with_held_warm(root: PathBuf, hold: Arc<PackWarmHold>) -> SearchToolsService {
        let build_root = root.clone();
        let watcher_starter = production_watcher_starter();
        let handle = std::thread::Builder::new()
            .name("bifrost-index-build".to_string())
            .spawn(
                move || -> Result<(u64, PathBuf, WorkspaceSession), String> {
                    let (project, workspace) = build_persisted_workspace(
                        build_root.clone(),
                        None,
                        UpdateStrategy::Manual,
                        &HostActivationContext::library_none(),
                    )?;
                    let session = assemble_session_deferred_held(
                        project,
                        workspace,
                        UpdateStrategy::Manual,
                        StartupIndexWarm::OnDemand,
                        &watcher_starter,
                        hold,
                    )?;
                    Ok((1, build_root, session))
                },
            )
            .unwrap();
        service_with_pending_build(root, handle)
    }

    /// A service whose deferred build is the caller's handle, so a test can
    /// decide what that build is still doing when the readiness barrier runs.
    fn service_with_pending_build(
        root: PathBuf,
        handle: std::thread::JoinHandle<Result<(u64, PathBuf, WorkspaceSession), String>>,
    ) -> SearchToolsService {
        let service = SearchToolsService::with_session_state(
            root,
            None,
            None,
            UpdateStrategy::Manual,
            production_watcher_starter(),
            HostActivationContext::library_none(),
        );
        {
            let mut phase = service.phase.lock().unwrap();
            let bound = phase.bound_mut_for_test();
            bound.lifetime = Some(
                service
                    .lifetimes
                    .reserve(bound.root.clone(), service.workspace_generation())
                    .unwrap(),
            );
            bound.build = WorkspaceBuild::Building(handle);
        }
        service
    }

    fn pack_warm_ready(service: &SearchToolsService) -> bool {
        let guard = service.session.read().unwrap();
        guard.as_ref().unwrap().semantic_packs.is_ready()
    }

    /// The public projection omits repository-root `tests/fixtures/**`, so the
    /// crate keeps the Cargo and npm inputs these warm-start tests need.
    fn warm_dependency_fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/warm-dependency-evidence/cargo-npm")
    }

    fn copy_fixture_tree(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).expect("create fixture dir");
        for entry in std::fs::read_dir(from).expect("read fixture dir") {
            let entry = entry.expect("fixture dir entry");
            let destination = to.join(entry.file_name());
            if entry.file_type().expect("fixture file type").is_dir() {
                copy_fixture_tree(&entry.path(), &destination);
            } else if entry.file_name() != "expected.txt" {
                std::fs::copy(entry.path(), destination).expect("copy fixture file");
            }
        }
    }

    /// Runs `child_body` in a re-executed copy of this test with timing on.
    /// Returns `None` inside that child, and the child's stderr in the parent,
    /// so the parent always reaches its timing assertions: empty timing output
    /// fails them instead of passing silently.
    fn run_warm_timing_child(test_name: &str, child_body: impl FnOnce()) -> Option<String> {
        const CHILD_ENV: &str = "BIFROST_13517_TIMING_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            child_body();
            return None;
        }
        let exe = std::env::current_exe().expect("current test executable");
        let output = std::process::Command::new(exe)
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD_ENV, "1")
            .env("BIFROST_TIMING", "1")
            .env("BIFROST_OPEN_PACKS_DISABLE", "1")
            .env("BIFROST_SEMANTIC_PACK_DOWNLOAD", "off")
            .output()
            .expect("spawn timing child test");
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            output.status.success(),
            "timing child failed ({:?}):\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            stderr
        );
        Some(stderr)
    }

    fn count_timing_begins(stderr: &str, label: &str) -> usize {
        let needle = "[bifrost-timing] ";
        let suffix = format!("BEGIN {label}");
        stderr
            .lines()
            .filter(|line| line.starts_with(needle) && line.trim_end().ends_with(&suffix))
            .count()
    }

    #[test]
    fn warm_configured_stage_reuses_verified_installed_discovery() {
        let Some(stderr) = run_warm_timing_child(
            "searchtools_service::watcher_startup_tests::warm_configured_stage_reuses_verified_installed_discovery",
            || {
                let fixture = warm_dependency_fixture();
                let temp = tempfile::tempdir().expect("tempdir");
                let root = temp.path().join("workspace");
                copy_fixture_tree(&fixture, &root);
                let root = root.canonicalize().expect("canonicalize").normalize();
                let hold = Arc::new(PackWarmHold::new());
                let service = service_with_held_warm(root, Arc::clone(&hold));
                let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
                hold.release();
                service.ensure_ready().expect("workspace ready");
                let deadline = Instant::now() + Duration::from_secs(60);
                while !pack_warm_ready(&service) {
                    assert!(
                        Instant::now() < deadline,
                        "semantic-pack warm never settled"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
            },
        ) else {
            return;
        };
        assert_eq!(
            count_timing_begins(&stderr, "semantic_pack.activate_installed"),
            1,
            "{stderr}"
        );
        assert_eq!(
            count_timing_begins(&stderr, "semantic_pack.activate_configured"),
            1,
            "fixture must leave an acquisition pending so the configured stage runs:\n{stderr}"
        );
        assert_eq!(
            count_timing_begins(&stderr, "semantic_pack.discover[cargo]"),
            1,
            "Cargo discovery must run once across both stages:\n{stderr}"
        );
    }

    #[test]
    fn warm_configured_stage_rediscovers_when_receipt_fails_between_stages() {
        let Some(stderr) = run_warm_timing_child(
            "searchtools_service::watcher_startup_tests::warm_configured_stage_rediscovers_when_receipt_fails_between_stages",
            || {
                let fixture = warm_dependency_fixture();
                let temp = tempfile::tempdir().expect("tempdir");
                let root = temp.path().join("workspace");
                copy_fixture_tree(&fixture, &root);
                let root = root.canonicalize().expect("canonicalize").normalize();
                let (hold, expensive_stage) = PackWarmHold::new_holding_expensive_stage();
                let hold = Arc::new(hold);
                let service = service_with_held_warm(root.clone(), Arc::clone(&hold));
                let _release_hold_on_drop = ReleasePackWarmOnDrop(Arc::clone(&hold));
                hold.release();
                service.ensure_ready().expect("workspace ready");

                let deadline = Instant::now() + Duration::from_secs(60);
                loop {
                    let is_pending = {
                        let guard = service.session.read().unwrap();
                        guard.as_ref().is_some_and(|session| {
                            let state = session.semantic_packs.state.lock().unwrap();
                            matches!(*state, PackWarmState::AcquisitionPending(_))
                        })
                    };
                    if is_pending {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "semantic-pack warm never reached AcquisitionPending"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }

                // Add rust-toolchain.toml between the installed and configured stages
                // so Cargo's handed-over AbsentFile receipt fails verification.
                std::fs::write(
                    root.join("rust-toolchain.toml"),
                    "[toolchain]\nchannel = \"stable\"\n",
                )
                .expect("write rust-toolchain.toml between stages");
                expensive_stage.release();

                let deadline = Instant::now() + Duration::from_secs(60);
                while !pack_warm_ready(&service) {
                    assert!(
                        Instant::now() < deadline,
                        "semantic-pack warm never settled after release"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
            },
        ) else {
            return;
        };
        assert_eq!(
            count_timing_begins(&stderr, "semantic_pack.activate_installed"),
            1,
            "{stderr}"
        );
        assert_eq!(
            count_timing_begins(&stderr, "semantic_pack.activate_configured"),
            1,
            "{stderr}"
        );
        assert_eq!(
            count_timing_begins(&stderr, "semantic_pack.discover[cargo]"),
            2,
            "Cargo must rediscover when rust-toolchain.toml changes between stages:\n{stderr}"
        );
    }

    /// The other half of the trigger: a synchronously constructed service is a
    /// one-shot invocation or an embedded host, which can exit seconds later.
    /// It must not spend startup on Rust usage work it may never query
    /// (#1758, d8920a38), so the build stays lazy and no warm thread is
    /// started at all. Such a session is ready by construction: with nothing
    /// outstanding there is nothing for a caller to wait for.
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1758: Issue #1758 fixed one-shot and embedded services paying startup cost for a usage-index warm they may never query"
    )]
    fn a_one_shot_service_does_not_start_the_usage_index_warm_at_startup() {
        let (_temp, root) = workspace("lib.rs", "pub fn root() {}\npub fn run() { root(); }\n");
        let service = SearchToolsService::new_manual_ephemeral(root).unwrap();

        let guard = service.session.read().unwrap();
        let session = guard.as_ref().unwrap();
        assert!(
            session.usage_index_warm.is_none(),
            "a one-shot service must leave the build to the first query that needs it"
        );
        assert!(
            session.usage_index_ready(),
            "with nothing outstanding there is nothing for a caller to wait for"
        );
    }

    /// A tool call that lands while the startup usage-index warm is still
    /// running returns the same answer it returns once the warm has settled: it
    /// waits on the same memo rather than failing or answering from a partial
    /// index.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1758: Issue #1758 fixed requests racing startup warm so they wait on the same memo and return the settled answer"
    )]
    fn a_request_racing_the_startup_usage_index_warm_returns_the_warm_answer() {
        let (_temp, root) = workspace(
            "lib.rs",
            "pub fn root() {}\npub fn run() { root(); }\npub fn spare() {}\n",
        );
        let service = SearchToolsService::new_deferred_manual(root).unwrap();
        service.ensure_ready().unwrap();

        let racing = service
            .call_tool_value("scan_usages_by_reference", json!({"symbols": ["root"]}))
            .unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !{
            let guard = service.session.read().unwrap();
            guard.as_ref().unwrap().usage_index_ready()
        } {
            assert!(
                std::time::Instant::now() < deadline,
                "the startup usage-index warm never finished"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let warm = service
            .call_tool_value("scan_usages_by_reference", json!({"symbols": ["root"]}))
            .unwrap();

        assert_eq!(racing, warm);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon("#847: a manual service must not start a file watcher")]
    fn manual_service_does_not_invoke_watcher_starter() {
        let (_temp, root) = workspace("Manual.java", "class Manual {}\n");
        let calls = Arc::new(AtomicUsize::new(0));
        let service = SearchToolsService::new_ephemeral_with_strategy_and_watcher_starter(
            root.clone(),
            UpdateStrategy::Manual,
            failing_starter(Arc::clone(&calls)),
            HostActivationContext::library_none(),
        )
        .unwrap();

        let active = service
            .call_tool_value("get_active_workspace", json!({}))
            .unwrap();
        assert_eq!(active["workspace_path"], root.display().to_string());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#847: watcher failure during activation must remain visible on the bound workspace"
    )]
    fn watcher_failure_during_activation_is_retained_on_the_new_binding() {
        let (_old_temp, old_root) = workspace("Old.java", "class Old {}\n");
        let (_new_temp, new_root) = workspace("New.java", "class New {}\n");
        let failed_root = new_root.clone();
        let starter: WatcherStarter = Arc::new(move |project, claimed_files| {
            if project.root() == failed_root {
                Err(WATCHER_FAILURE.to_string())
            } else {
                ProjectChangeWatcher::start_polling_with_claimed_files_for_tests(
                    project,
                    claimed_files,
                )
            }
        });
        let service = SearchToolsService::new_ephemeral_with_strategy_and_watcher_starter(
            old_root.clone(),
            UpdateStrategy::WatchFiles,
            starter,
            HostActivationContext::library_none(),
        )
        .unwrap();

        let activated = service
            .call_tool_value(
                "activate_workspace",
                json!({"workspace_path": new_root.display().to_string()}),
            )
            .unwrap();
        assert_eq!(activated["workspace_path"], new_root.display().to_string());
        let error = service.ensure_ready().unwrap_err();
        assert_watcher_error(&error);
        assert_eq!(service.active_workspace_root(), Some(new_root.clone()));
        let active = service
            .call_tool_value("get_active_workspace", json!({}))
            .unwrap();
        assert_eq!(active["workspace_path"], new_root.display().to_string());
        assert_eq!(active["analyzer_ready"], false);
        assert_eq!(active["workspace_build"]["status"], "failed");
        assert_eq!(active["workspace_build"]["error"], error.message);
        assert!(
            service
                .call_tool_value("list_symbols", json!({"file_patterns": ["Old.java"]}))
                .is_err()
        );
    }

    /// Git bookkeeping is outside the analyzed source set and must not replace
    /// the session snapshot used by subsequent queries.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3755: Issue #3755 fixed Git bookkeeping replacing the source snapshot used by later queries"
    )]
    fn git_bookkeeping_in_a_watched_session_keeps_the_source_snapshot() {
        let (_temp, root) = workspace("Model.java", "class Model { void run() {} }\n");
        let repository = git2::Repository::init(&root).unwrap();
        let mut index = repository.index().unwrap();
        index.add_path(std::path::Path::new("Model.java")).unwrap();
        index.write().unwrap();
        drop(index);
        drop(repository);
        // Written before the watcher exists and staged after it, so the only
        // events in this test are Git's own.
        std::fs::write(root.join("Later.java"), "class Later {}\n").unwrap();

        let service = SearchToolsService::new(root.clone()).unwrap();
        let warm = service.snapshot_for_query().unwrap();
        let published = Arc::clone(&warm.source_snapshot);
        warm.finish("capture_source_snapshot", Ok(())).unwrap();

        for arguments in [
            ["status", "--porcelain"].as_slice(),
            ["add", "-A"].as_slice(),
        ] {
            let output = std::process::Command::new("git")
                .current_dir(&root)
                .args(arguments)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {arguments:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(500));

        let after = service.snapshot_for_query().unwrap();
        assert!(
            Arc::ptr_eq(&published, &after.source_snapshot),
            "Git bookkeeping must not replace the session snapshot"
        );
        after.finish("source_snapshot_pin", Ok(())).unwrap();
    }

    /// A member manifest whose directory holds no source file is outside every
    /// recursive source root. Adding a path dependency there must still reach
    /// the next query through the watcher (#3755).
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3755: nested member manifest edits must invalidate dependency analysis on the next query"
    )]
    fn a_member_manifest_edit_reaches_the_next_query() {
        const APP_MANIFEST: &str =
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        for (path, contents) in [
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"crates/app\", \"crates/dep\"]\nresolver = \"2\"\n",
            ),
            ("crates/app/Cargo.toml", APP_MANIFEST),
            (
                "crates/dep/Cargo.toml",
                "[package]\nname = \"dep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            ),
            (
                "crates/app/src/lib.rs",
                "use dep::target;\npub fn caller() { target(); }\n",
            ),
            ("crates/dep/src/lib.rs", "pub fn target() {}\n"),
        ] {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        }
        let starter: WatcherStarter = Arc::new(|project, claimed_files| {
            ProjectChangeWatcher::start_polling_with_claimed_files_for_tests(project, claimed_files)
        });
        let service = SearchToolsService::new_ephemeral_with_strategy_and_watcher_starter(
            root.clone(),
            UpdateStrategy::WatchFiles,
            starter,
            HostActivationContext::library_none(),
        )
        .unwrap();
        let resolves_the_call = || {
            let graph = service
                .call_tool_value("usage_graph", json!({"include_tests": true, "depth": 1}))
                .unwrap();
            let edges = graph["edges"].as_array().expect("usage graph edges");
            edges.iter().any(|edge| {
                edge["from"]
                    .as_str()
                    .is_some_and(|from| from.ends_with("caller"))
                    && edge["to"].as_str().is_some_and(|to| to.ends_with("target"))
            })
        };
        assert!(
            !resolves_the_call(),
            "without the dependency the cross-crate call is unresolved"
        );

        std::fs::write(
            root.join("crates/app/Cargo.toml"),
            format!("{APP_MANIFEST}[dependencies]\ndep = {{ path = \"../dep\" }}\n"),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !resolves_the_call() {
            assert!(
                Instant::now() < deadline,
                "the query after the manifest edit must resolve the new dependency"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[cfg(test)]
mod analyzer_failure_boundary_tests {
    use super::*;
    use crate::analyzer::store::{StoreError, analyzer_db_path};
    use crate::analyzer::{Language, TestProject};
    use serde_json::json;
    use std::collections::BTreeSet;

    fn multi_language_service() -> (tempfile::TempDir, PathBuf, SearchToolsService) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("Model.java"), "class Model {}\n").unwrap();
        std::fs::write(root.join("helper.py"), "def helper():\n    return 1\n").unwrap();
        git2::Repository::init(&root).unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::with_languages(
            root.clone(),
            BTreeSet::from([Language::Java, Language::Python]),
        ));
        let service = SearchToolsService::new_manual_persisted_for_project(
            project,
            AnalyzerConfig::default(),
        )
        .unwrap();
        (temp, root, service)
    }

    fn make_store_stale(root: &Path, lang: &str) {
        let connection = rusqlite::Connection::open(analyzer_db_path(root)).unwrap();
        assert_eq!(
            connection
                .execute(
                    "UPDATE analysis_epochs SET generation = generation + 1 WHERE lang = ?1",
                    [lang],
                )
                .unwrap(),
            1
        );
    }

    fn make_java_store_stale(root: &Path) {
        make_store_stale(root, "java");
    }

    #[test]
    fn non_stale_internal_failure_does_not_reload_workspace() {
        let (_temp, _root, service) = multi_language_service();
        let generation = service.workspace_generation();
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _guard = service.query_taint_results.write().unwrap();
                    panic!("poison the query registration lock");
                })
                .join()
                .expect_err("lock poisoning thread should panic");
        });

        let error = service
            .call_tool_value(
                "query_code",
                json!({"schema_version": 1, "match": {"kind": "class", "name": "Model"}}),
            )
            .expect_err("poisoned registration lock must fail the query");
        assert_eq!(error.code, SearchToolsServiceErrorCode::Internal);
        assert!(error.message.contains("lock poisoned"), "{error:?}");
        assert_eq!(service.workspace_generation(), generation);
    }

    #[test]
    fn manual_persisted_constructor_retains_workspace_projection_across_restart() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("Model.java"), "class Model {}\n").unwrap();
        git2::Repository::init(&root).unwrap();
        let project = || -> Arc<dyn Project> {
            Arc::new(TestProject::with_languages(
                root.clone(),
                BTreeSet::from([Language::Java]),
            ))
        };
        let first = SearchToolsService::new_manual_persisted_for_project(
            project(),
            AnalyzerConfig::default(),
        )
        .unwrap();
        let first_answer = first
            .call_tool_value("get_symbol_locations", json!({"symbols": ["Model"]}))
            .unwrap();
        assert_eq!(first_answer["locations"][0]["symbol"], "Model");
        drop(first);

        let connection = rusqlite::Connection::open(analyzer_db_path(&root)).unwrap();
        let retained: i64 = connection
            .query_row("SELECT count(*) FROM workspace_file_versions", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(
            retained > 0,
            "a persisted workspace keeps its projection after close"
        );

        let second = SearchToolsService::new_manual_persisted_for_project(
            project(),
            AnalyzerConfig::default(),
        )
        .unwrap();
        let second_answer = second
            .call_tool_value("get_symbol_locations", json!({"symbols": ["Model"]}))
            .unwrap();
        assert_eq!(second_answer["locations"], first_answer["locations"]);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "fecfeafc7647: stale analyzer generations must reload the service snapshot before retry"
    )]
    fn stale_generation_reloads_the_service_snapshot_before_retrying() {
        let (_temp, root, service) = multi_language_service();

        let healthy = service
            .call_tool_value("get_symbol_locations", json!({"symbols": ["Model"]}))
            .unwrap();
        assert_eq!(healthy["locations"][0]["symbol"], "Model");

        make_java_store_stale(&root);

        let recovered = service
            .call_tool_value("get_symbol_locations", json!({"symbols": ["Model"]}))
            .unwrap();
        assert_eq!(recovered["locations"][0]["symbol"], "Model");

        let recovered = service
            .call_tool_value(
                "search_symbols",
                json!({"patterns": ["Model"], "include_tests": true, "limit": 5}),
            )
            .unwrap();
        assert_eq!(recovered["total_files"], 1);
    }

    #[test]
    fn query_code_retries_as_a_query_after_generation_cutover() {
        let (_temp, root, service) = multi_language_service();
        let query = json!({
            "schema_version": 1,
            "languages": ["java"],
            "match": {"kind": "class", "name": "Model"}
        });
        let run_query = |query| {
            service
                .call_tool_output_with_transport_timings_and_preflight(
                    "query_code",
                    query,
                    RenderOptions::default(),
                    None,
                    TransportTimings::default(),
                    None,
                )
                .map(ToolOutput::into_value)
        };
        let baseline = run_query(query.clone()).unwrap();
        assert_eq!(baseline["results"].as_array().unwrap().len(), 1);
        make_java_store_stale(&root);
        let recovered = run_query(query).unwrap();
        assert_eq!(recovered["results"].as_array().unwrap().len(), 1);
        assert_eq!(
            recovered["results"][0]["name"],
            baseline["results"][0]["name"]
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "fecfeafc7647: Rust symbol search must recover after an external generation cutover"
    )]
    fn rust_search_symbols_recovers_after_an_external_generation_cutover() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("Model.rs"), "struct Before {}").unwrap();
        git2::Repository::init(&root).unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::with_languages(
            root.clone(),
            BTreeSet::from([Language::Rust]),
        ));
        let service = SearchToolsService::new_manual_persisted_for_project(
            project,
            AnalyzerConfig::default(),
        )
        .unwrap();

        let initial = service
            .call_tool_output_with_transport_timings_and_preflight(
                "search_symbols",
                json!({"patterns": ["Before"], "include_tests": true, "limit": 5}),
                RenderOptions::default(),
                None,
                TransportTimings::default(),
                None,
            )
            .unwrap()
            .into_value();
        assert_eq!(initial["total_files"], 1);

        // A checkout performed by another process changes the source and
        // advances the shared analyzer generation before this service sees it.
        std::fs::write(root.join("Model.rs"), "struct After {}").unwrap();
        make_store_stale(&root, "rust");

        let recovered = service
            .call_tool_output_with_transport_timings_and_preflight(
                "search_symbols",
                json!({"patterns": ["After"], "include_tests": true, "limit": 5}),
                RenderOptions::default(),
                None,
                TransportTimings::default(),
                None,
            )
            .unwrap()
            .into_value();
        assert_eq!(recovered["total_files"], 1, "{recovered:#}");

        // The rebuilt snapshot is retained, so repeated calls do not replay
        // the stale-generation failure.
        let repeated = service
            .call_tool_output_with_transport_timings_and_preflight(
                "search_symbols",
                json!({"patterns": ["After"], "include_tests": true, "limit": 5}),
                RenderOptions::default(),
                None,
                TransportTimings::default(),
                None,
            )
            .unwrap()
            .into_value();
        assert_eq!(repeated["total_files"], 1, "{repeated:#}");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#7876: an MCP snapshot request lost stale-generation store failures without attribution"
    )]
    fn snapshot_request_entry_records_stale_generation_on_its_own_context() {
        let (_temp, root, service) = multi_language_service();
        let scope = service.snapshot_for_query().unwrap();
        make_java_store_stale(&root);
        let definitions: Vec<_> = scope.enter().analyzer().definitions("Model").collect();
        assert!(definitions.is_empty(), "the stale store read ran");
        let error = scope
            .context
            .store_error()
            .expect("request owns the stale failure");
        assert!(error.is_stale_generation());
        assert!(scope.finish("stale_snapshot", Ok(())).is_err());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#847: concurrent query scopes must not share SQLite failure state"
    )]
    fn overlapping_query_scopes_do_not_share_store_failures() {
        let (_temp, root, service) = multi_language_service();

        let failing_scope = service.snapshot_for_query().unwrap();
        let unaffected_scope = service.snapshot_for_query().unwrap();

        make_java_store_stale(&root);

        let definitions: Vec<_> = failing_scope
            .enter()
            .analyzer()
            .definitions("Model")
            .collect();
        assert!(definitions.is_empty());
        assert!(failing_scope.context.store_error().is_some());
        assert!(
            unaffected_scope.context.store_error().is_none(),
            "a store failure must be attributed only to the request that observed it"
        );

        unaffected_scope
            .finish("unaffected_request", Ok(()))
            .unwrap();
        let error = failing_scope.finish("failing_request", Ok(())).unwrap_err();
        assert_eq!(error.code, SearchToolsServiceErrorCode::Internal);
        assert!(error.message.contains("failing_request"));
        assert!(error.message.contains("stale analyzer generation"));
    }

    /// The trusted budget is reachable only by host configuration, it never
    /// narrows a lane, and it removes the memory-shaped per-dimension estimate.
    ///
    /// That estimate is the whole reason this option exists. With no published
    /// row table, `semantic_budget_limits` holds each retained-row lane to half
    /// of `max_retained_bytes`, split across the row dimensions and priced at
    /// each one's row size. For source mappings that is 33,288 rows regardless
    /// of the repository, which is what stopped both pinned bbolt revisions at
    /// 33,289 attempted mappings. Publishing the audited workspace's own table
    /// is what lifts it, so assert on the table rather than on one number.
    ///
    /// The fixture is Python on purpose: the assertions are about limits, not
    /// about any language, and a Java fixture would make this test pay a
    /// minute of JDK semantic-pack activation for nothing.
    #[test]
    fn workspace_scaled_query_limits_are_host_configuration_and_never_narrow_a_lane() {
        use crate::analyzer::semantic::SemanticBudgetDimension;
        use crate::rql::CodeQuerySemanticRowLimits;

        // The interactive per-dimension source-mapping allowance, measured on
        // the pinned bbolt revisions.
        const INTERACTIVE_SOURCE_MAPPING_ESTIMATE: usize = 33_288;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("model.py"), "class Model:\n    pass\n").unwrap();
        let (_project, workspace) =
            build_ephemeral_workspace(root.clone(), None, &HostActivationContext::library_none())
                .unwrap();
        let document_root =
            Arc::new(WorkspaceRoot::open(workspace.analyzer().project().root()).unwrap());
        let scope = WorkspaceQueryScope::new(
            Arc::new(workspace.0),
            document_root,
            SessionPackActivation::Settled(None),
        );

        let service = SearchToolsService::new_manual_ephemeral(root).unwrap();
        let interactive = service.query_execution_limits(&scope.enter());
        let defaults = crate::rql::CodeQueryExecutionLimits::default();
        assert_eq!(
            interactive.semantic, defaults.semantic,
            "a service nobody configured must keep the interactive defaults"
        );
        assert!(
            interactive.semantic.rows_per_dimension.is_none(),
            "the interactive defaults price no row lane: {:?}",
            interactive.semantic
        );

        let trusted = service
            .with_workspace_scaled_query_limits()
            .query_execution_limits(&scope.enter());
        assert!(
            trusted.semantic.rows_per_dimension.is_some(),
            "a trusted host must get the audited workspace's own row table: {:?}",
            trusted.semantic
        );
        assert!(
            trusted
                .semantic
                .rows(SemanticBudgetDimension::SourceMappings)
                > INTERACTIVE_SOURCE_MAPPING_ESTIMATE,
            "the trusted lane must exceed the estimate that stopped bbolt: {:?}",
            trusted.semantic
        );
        assert!(trusted.max_scanned_files >= defaults.max_scanned_files);
        assert!(trusted.max_scanned_source_bytes >= defaults.max_scanned_source_bytes);
        assert!(trusted.max_fact_nodes >= defaults.max_fact_nodes);
        assert!(
            trusted.semantic.max_materialized_files >= defaults.semantic.max_materialized_files
        );
        assert!(trusted.semantic.max_source_bytes >= defaults.semantic.max_source_bytes);
        assert!(trusted.semantic.max_retained_bytes >= defaults.semantic.max_retained_bytes);
        for dimension in CodeQuerySemanticRowLimits::ROW_DIMENSIONS {
            assert!(
                trusted.semantic.rows(dimension) >= defaults.semantic.rows(dimension),
                "opting in narrowed {dimension:?}"
            );
        }
    }

    #[test]
    fn scaled_query_materializes_every_file_past_the_interactive_cap() {
        const FILES: usize = 257;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        for index in 0..FILES {
            std::fs::write(
                root.join(format!("module_{index}.py")),
                format!("def function_{index}():\n    return {index}\n"),
            )
            .unwrap();
        }
        let query = json!({
            "schema_version": 1,
            "languages": ["python"],
            "match": {"kind": "function"},
            "steps": [{"op": "procedure_of"}, {"op": "cfg_entry"}],
            "limit": FILES + 1
        });
        let interactive = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        let cut = interactive
            .call_tool_value("query_code", query.clone())
            .unwrap();
        assert!(
            cut["diagnostics"]
                .as_array()
                .is_some_and(|diagnostics| diagnostics.iter().any(|diagnostic| {
                    diagnostic["code"] == "semantic_budget_exhausted"
                        && diagnostic["impact"] == "incomplete"
                })),
            "interactive execution must report its semantic file cap: {:?}",
            cut["diagnostics"]
        );
        drop(interactive);

        let scaled = SearchToolsService::new_manual_ephemeral(root)
            .unwrap()
            .with_workspace_scaled_query_limits();
        let answer = scaled.call_tool_value("query_code", query).unwrap();
        assert_eq!(answer["truncated"], false);
        assert!(
            answer["diagnostics"]
                .as_array()
                .is_none_or(|diagnostics| diagnostics
                    .iter()
                    .all(|diagnostic| diagnostic["impact"] != "incomplete")),
            "scaled execution must be complete: {:?}",
            answer["diagnostics"]
        );
        let paths = answer["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["path"].as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>();
        let expected = (0..FILES)
            .map(|index| format!("module_{index}.py"))
            .collect::<BTreeSet<_>>();
        assert_eq!(paths, expected);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#847: a handler error must retain precedence over a recorded store failure"
    )]
    fn query_finish_preserves_handler_error_over_recorded_store_failure() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("Model.java"), "class Model {}\n").unwrap();
        let (_project, workspace) =
            build_ephemeral_workspace(root, None, &HostActivationContext::library_none()).unwrap();
        let document_root =
            Arc::new(WorkspaceRoot::open(workspace.analyzer().project().root()).unwrap());
        let scope = WorkspaceQueryScope::new(
            Arc::new(workspace.0),
            document_root,
            SessionPackActivation::Settled(None),
        );
        scope
            .context
            .record_store_error(StoreError::new("injected store failure"));

        let result: Result<(), SearchToolsServiceError> = Err(
            SearchToolsServiceError::invalid_params("original handler failure"),
        );
        let error = scope.finish("test_operation", result).unwrap_err();
        assert_eq!(error.code, SearchToolsServiceErrorCode::InvalidParams);
        assert_eq!(error.message, "original handler failure");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13844: one missing or newly added path turned a mixed source listing into an internal error"
    )]
    fn function_sources_keeps_existing_files_when_a_requested_path_is_unindexed() {
        for (path, added_source) in [
            ("src/not_found.rs", None),
            ("src/added.rs", Some("pub fn added() {}\n")),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            std::fs::create_dir(root.join("src")).unwrap();
            std::fs::write(
                root.join("Cargo.toml"),
                "[package]\nname = \"source_listing\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .unwrap();
            std::fs::write(
                root.join("src/lib.rs"),
                "pub fn existing() {}\ninclude!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));\n",
            )
            .unwrap();
            let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
            service.ensure_ready().unwrap();
            if let Some(source) = added_source {
                // The diff can name a new file before a fence or watcher update.
                std::fs::write(root.join(path), source).unwrap();
            }
            let result = service
                .call_tool_value(
                    "list_function_sources",
                    json!({"paths": ["src/lib.rs", path], "include_tests": true}),
                )
                .unwrap();
            let records = result["records"].as_array().unwrap();
            assert!(
                records.iter().any(|row| row["name"] == "existing"),
                "{result}"
            );
            assert!(
                records.iter().all(|row| row["rel_path"] == "src/lib.rs"),
                "{result}"
            );
            assert!(
                result["incomplete"]
                    .as_array()
                    .is_some_and(|reasons| reasons.iter().any(|reason| {
                        reason["reason"] == "semantic_evidence_incomplete"
                            && reason["detail"]
                                .as_str()
                                .is_some_and(|detail| detail.contains(path))
                    })),
                "the missing path must retain its own typed reason: {result}"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13977: an added path in a new language disappeared from an empty or mixed source listing"
    )]
    fn function_sources_reports_paths_without_a_selected_language() {
        for initial in [None, Some(("app.py", "def existing():\n    pass\n"))] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            std::fs::write(root.join("README.md"), "A workspace.\n").unwrap();
            let mut paths = vec!["added.rs"];
            if let Some((path, source)) = initial {
                std::fs::write(root.join(path), source).unwrap();
                paths.push(path);
            }
            let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
            service.ensure_ready().unwrap();
            std::fs::write(root.join("added.rs"), "pub fn added() {}\n").unwrap();
            let result = service
                .call_tool_value(
                    "list_function_sources",
                    json!({"paths": paths, "include_tests": true}),
                )
                .unwrap();
            let records = result["records"].as_array().unwrap();
            assert_eq!(records.len(), usize::from(initial.is_some()), "{result}");
            assert!(
                records.iter().all(|row| row["name"] == "existing"),
                "{result}"
            );
            assert!(
                result["incomplete"]
                    .as_array()
                    .is_some_and(|reasons| reasons.iter().any(|reason| {
                        reason["reason"] == "semantic_evidence_incomplete"
                            && reason["detail"]
                                .as_str()
                                .is_some_and(|detail| detail.contains("added.rs"))
                    })),
                "an absent language delegate must not silently drop a requested path: {result}"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13844: a scoped Java function-source listing inherited an unrelated C# conditional-branch gap"
    )]
    fn function_sources_scopes_csharp_branch_gaps_away_from_java_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(
            root.join("Model.java"),
            "class Model { int answer() { return 42; } }\n",
        )
        .unwrap();
        std::fs::write(
            root.join("Conditional.cs"),
            "#if EARLY\nclass Conditional { void Early() {} }\n#else\nclass Conditional { void Late() {} }\n#endif\n",
        )
        .unwrap();
        let service = SearchToolsService::new_manual_ephemeral(root).unwrap();
        let full = service
            .call_tool_value("list_function_sources", json!({"include_tests": true}))
            .unwrap();
        assert!(
            full["incomplete"]
                .as_array()
                .is_some_and(|reasons| reasons.iter().any(|reason| {
                    reason["detail"]
                        .as_str()
                        .is_some_and(|detail| detail.contains("csharp_conditional_branch_unseen"))
                })),
            "the fixture must expose the C# branch gap: {full}"
        );
        let java = service
            .call_tool_value(
                "list_function_sources",
                json!({"paths": ["Model.java"], "include_tests": true}),
            )
            .unwrap();
        assert!(java.get("incomplete").is_none(), "{java}");
        let expected = full["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["rel_path"] == "Model.java")
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(java["records"], json!(expected));
        assert_eq!(java["summary"]["record_count"], 1);
    }
}

#[cfg(test)]
mod source_generation_tests {
    use super::*;
    use serde_json::Value;
    use std::fs;

    #[test]
    fn rename_uses_edited_named_source_before_watcher_delivery() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::write(root.join("app.py"), "def alpha():\n    pass\n\nalpha()\n").unwrap();
        let service = watching_service_without_watcher(root.clone());
        fs::write(root.join("app.py"), "def beta():\n    pass\n\nbeta()\n").unwrap();

        let result = service
            .call_tool_value(
                "rename_symbol",
                serde_json::json!({"path": "app.py", "line": 1, "column": 5, "new_name": "gamma"}),
            )
            .unwrap();
        assert_eq!(result["status"], "ok", "{result}");
        assert_eq!(result["old_name"], "beta", "{result}");
        assert_eq!(result["target"]["symbol"], "app.beta", "{result}");
        let edits = result["edits"][0]["edits"].as_array().unwrap();
        assert!(edits.len() >= 2, "{result}");
        assert!(
            edits.iter().all(|edit| edit["old_text"] == "beta"),
            "{result}"
        );
    }

    const INITIAL_SOURCE: &str = r#"namespace MudBlazor;

public partial class MudDialogContainer
{
    protected string BackgroundClassname => "mud-overlay-dark";
}
"#;

    const UPDATED_SOURCE: &str = r#"namespace MudBlazor;

public partial class MudDialogContainer
{
    protected string BackgroundClassname => "mud-overlay-dark";

    private string GetBackgroundClass()
    {
        return BackgroundClassname;
    }
}
"#;

    const SHIFTED_SOURCE: &str = r#"namespace MudBlazor;

public partial class MudDialogContainer
{
    // This edit shifts the old BackgroundClassname byte range.
    protected string BackgroundClassname => "mud-overlay-light";
}
"#;

    fn write_project() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::write(root.join("MudDialogContainer.cs"), INITIAL_SOURCE).unwrap();
        (temp, root)
    }

    fn write_ambiguous_project() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::write(
            root.join("First.cs"),
            "namespace First; class Container { string Value => \"first\"; }\n",
        )
        .unwrap();
        fs::write(
            root.join("Second.cs"),
            "namespace Second; class Container { string Value => \"second\"; }\n",
        )
        .unwrap();
        (temp, root)
    }

    fn watching_service_without_watcher(root: PathBuf) -> SearchToolsService {
        let (project, workspace) =
            build_ephemeral_workspace(root, None, &HostActivationContext::library_none()).unwrap();
        let service = SearchToolsService {
            retention_budget: brokk_bifrost_core::retention_budget::RetentionBudget::new(
                AnalyzerConfig::default().retention_budget_bytes(),
            ),
            host_activation: HostActivationContext::library_none(),
            phase: Mutex::new(WorkspacePhase::bound(
                project.root().to_path_buf(),
                None,
                WorkspaceBuild::Installed,
            )),
            session: Arc::new(RwLock::new(Some(WorkspaceSession {
                snapshot: Arc::new(workspace.0),
                document_root: Arc::new(WorkspaceRoot::open(project.root()).unwrap()),
                semantic_packs: Arc::new(SemanticPackWarm::settled(None)),
                retired_pack_warms: Vec::new(),
                refresh: PackRefresh::Idle,
                watcher: SessionWatcher::Disabled,
                usage_index_warm: None,
                index_warmer: IndexWarmer::new(),
                lifetime: None,
            }))),
            retired_sessions: Mutex::new(Default::default()),
            lifetimes: Arc::new(Default::default()),
            workspace_generation: AtomicU64::new(1),
            flow_state: crate::flow::FlowWorkspaceState::new(),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            build_progress: Arc::new(Default::default()),
            update_strategy: UpdateStrategy::WatchFiles,
            startup_index_warm: StartupIndexWarm::OnDemand,
            watcher_starter: production_watcher_starter(),
            diff_snapshot_object_dir: None,
            diff_scoring: DiffScoringSession::default(),
            workspace_scaled_query_limits: false,
            #[cfg(any(test, feature = "test-support"))]
            semantic_model_runtime_limits: SemanticModelRuntimeLimits::default(),
            #[cfg(test)]
            snapshot_acquisition_observer: Mutex::new(None),
        };
        {
            let mut session = service.session.write().unwrap();
            let mut phase = service.phase.lock().unwrap();
            let bound = phase.bound_mut_for_test();
            let lifetime = service
                .lifetimes
                .reserve(bound.root.clone(), service.workspace_generation())
                .unwrap();
            session.as_mut().unwrap().lifetime = Some(Arc::clone(&lifetime));
            bound.lifetime = Some(lifetime);
        }
        service
    }

    fn call_sources(service: &SearchToolsService, symbols: &[&str]) -> Value {
        let arguments = serde_json::json!({ "symbols": symbols });
        symbol_sources_json(service, &arguments.to_string())
    }

    fn source_texts(value: &Value) -> Vec<&str> {
        value["sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|source| source["text"].as_str().unwrap())
            .collect()
    }

    /// A location request names its file, so it must observe that file's
    /// current content even when the watcher has not delivered the save yet.
    /// `watching_service_without_watcher` is a watching session whose watcher
    /// never delivers, which makes the race deterministic (gate 13 defect 3).
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "fe0249334d3c: a location request must refresh its requested file before watcher delivery"
    )]
    fn a_location_request_observes_its_own_file_before_the_watcher_delivers() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::write(root.join("app.py"), "def alpha():\n    pass\n").unwrap();
        let service = watching_service_without_watcher(root.clone());
        let edited = "def alpha():\n    pass\n\ndef beta():\n    pass\n\nbeta()\n";
        fs::write(root.join("app.py"), edited).unwrap();

        let arguments = serde_json::json!({
            "references": [{"path": "app.py", "line": 7, "column": 1}]
        });
        let payload = service
            .call_tool_json("get_definitions_by_location", &arguments.to_string())
            .unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], "app.beta", "{value}");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#588: source results must not combine post-edit bytes with a pre-edit symbol index"
    )]
    fn get_symbol_sources_refreshes_combined_stale_member_request() {
        let (_temp, root) = write_project();
        let service = watching_service_without_watcher(root.clone());
        fs::write(root.join("MudDialogContainer.cs"), UPDATED_SOURCE).unwrap();

        let value = call_sources(
            &service,
            &[
                "MudBlazor.MudDialogContainer.BackgroundClassname",
                "MudBlazor.MudDialogContainer.GetBackgroundClass",
            ],
        );

        assert_eq!(0, value["not_found"].as_array().unwrap().len(), "{value}");
        let texts = source_texts(&value);
        assert!(
            texts
                .iter()
                .any(|text| text.contains("protected string BackgroundClassname")),
            "{value}"
        );
        assert!(
            texts
                .iter()
                .any(|text| text.contains("private string GetBackgroundClass()")),
            "{value}"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "95655a5e9778: symbol and usage proofs must recheck source bytes after candidate discovery"
    )]
    fn candidate_files_are_rechecked_after_the_source_changes() {
        let (_temp, root) = write_project();
        let (_project, workspace) =
            build_ephemeral_workspace(root.clone(), None, &HostActivationContext::library_none())
                .unwrap();
        let result = get_symbol_sources(
            workspace.analyzer(),
            SymbolLookupParams {
                symbols: vec!["MudBlazor.MudDialogContainer.BackgroundClassname".to_string()],
            },
        );
        let candidates = symbol_source_candidate_files(workspace.analyzer(), &result);

        fs::write(root.join("MudDialogContainer.cs"), SHIFTED_SOURCE).unwrap();

        let stale = stale_symbol_source_files(workspace.analyzer(), candidates).unwrap();
        assert_eq!(
            BTreeSet::from([ProjectFile::new(
                root,
                PathBuf::from("MudDialogContainer.cs")
            )]),
            stale
        );
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#588: a new member source must be resolved from the indexed owner after edits"
    )]
    fn get_symbol_sources_refreshes_new_member_from_indexed_owner() {
        let (_temp, root) = write_project();
        let service = watching_service_without_watcher(root.clone());
        fs::write(root.join("MudDialogContainer.cs"), UPDATED_SOURCE).unwrap();

        let value = call_sources(
            &service,
            &["MudBlazor.MudDialogContainer.GetBackgroundClass"],
        );

        assert_eq!(0, value["not_found"].as_array().unwrap().len(), "{value}");
        assert!(
            source_texts(&value)
                .iter()
                .any(|text| text.contains("private string GetBackgroundClass()")),
            "{value}"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#588: manual and watched source reads must retain one analyzer generation"
    )]
    fn stale_analyzer_and_manual_service_keep_generation_consistent_source() {
        let (_temp, root) = write_project();
        let (project, workspace) =
            build_ephemeral_workspace(root.clone(), None, &HostActivationContext::library_none())
                .unwrap();
        let manual = SearchToolsService::new_manual_ephemeral_footgun_for_project(
            project,
            AnalyzerConfig::default(),
        )
        .unwrap();
        fs::write(root.join("MudDialogContainer.cs"), SHIFTED_SOURCE).unwrap();

        let direct = get_symbol_sources(
            workspace.analyzer(),
            SymbolLookupParams {
                symbols: vec!["MudBlazor.MudDialogContainer.BackgroundClassname".to_string()],
            },
        );
        assert_eq!(1, direct.sources.len());
        assert_eq!(
            "protected string BackgroundClassname => \"mud-overlay-dark\";",
            direct.sources[0].text
        );

        let manual_value = call_sources(
            &manual,
            &[
                "MudBlazor.MudDialogContainer.BackgroundClassname",
                "MudBlazor.MudDialogContainer.GetBackgroundClass",
            ],
        );
        assert_eq!(1, manual_value["sources"].as_array().unwrap().len());
        assert_eq!(1, manual_value["not_found"].as_array().unwrap().len());
        assert_eq!(
            "protected string BackgroundClassname => \"mud-overlay-dark\";",
            manual_value["sources"][0]["text"]
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#588: transient source read failures must not be converted into deleted-file results"
    )]
    fn transient_source_read_errors_are_not_classified_as_deletion() {
        let (_temp, root) = write_project();
        let file = ProjectFile::new(root, PathBuf::from("MudDialogContainer.cs"));

        let transient = io::Error::new(io::ErrorKind::PermissionDenied, "temporary denial");
        assert!(classify_source_read(&file, Err(transient)).is_err());
        assert!(matches!(
            classify_source_read(&file, Err(io::Error::from(io::ErrorKind::NotFound))).unwrap(),
            ObservedSource::Missing
        ));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#588: a deleted target must refresh to not-found instead of stale source"
    )]
    fn get_symbol_sources_refreshes_deleted_target_to_not_found() {
        let (_temp, root) = write_project();
        let service = watching_service_without_watcher(root.clone());
        fs::remove_file(root.join("MudDialogContainer.cs")).unwrap();

        let value = call_sources(
            &service,
            &["MudBlazor.MudDialogContainer.BackgroundClassname"],
        );

        assert_eq!(0, value["sources"].as_array().unwrap().len(), "{value}");
        assert_eq!(1, value["not_found"].as_array().unwrap().len(), "{value}");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#588: deleting one ambiguous candidate must refresh the remaining target"
    )]
    fn get_symbol_sources_refreshes_stale_ambiguity_after_deletion() {
        let (_temp, root) = write_ambiguous_project();
        let service = watching_service_without_watcher(root.clone());
        let initial = call_sources(&service, &["Container.Value"]);
        assert_eq!(
            1,
            initial["ambiguous"].as_array().unwrap().len(),
            "{initial}"
        );

        fs::remove_file(root.join("First.cs")).unwrap();
        let refreshed = call_sources(&service, &["Container.Value"]);

        assert_eq!(
            0,
            refreshed["ambiguous"].as_array().unwrap().len(),
            "{refreshed}"
        );
        assert_eq!(
            0,
            refreshed["not_found"].as_array().unwrap().len(),
            "{refreshed}"
        );
        assert_eq!(
            1,
            refreshed["sources"].as_array().unwrap().len(),
            "{refreshed}"
        );
        assert!(
            refreshed["sources"][0]["text"]
                .as_str()
                .is_some_and(|text| text.contains("second")),
            "{refreshed}"
        );
    }
}

#[cfg(test)]
mod client_roots_tests {
    use super::*;
    use git2::{Repository, Signature};
    use serde_json::json;

    /// The cache-path checks below assert the default in-root placement,
    /// which `BIFROST_CACHE_ROOT` and `BIFROST_CACHE_DIR` override. Changing
    /// this process's environment would race with every other test in the
    /// binary, so each check reruns itself in a child process without the
    /// overrides (#10540). The child's machine-wide cache (templates and
    /// generated packs) still goes to a private directory, so the check does
    /// not write the user's real cache.
    const DEFAULT_CACHE_CHILD: &str = "BIFROST_TEST_DEFAULT_CACHE_CHILD";

    /// Returns false in the child, which runs the test body. In the parent it
    /// reruns `test` in a child without the cache overrides, asserts that the
    /// child ran and passed exactly one test, and returns true.
    fn ran_in_default_cache_child(test: &str) -> bool {
        if std::env::var_os(DEFAULT_CACHE_CHILD).is_some() {
            return false;
        }
        let machine_cache = tempfile::tempdir().expect("private machine cache");
        let mut child =
            std::process::Command::new(std::env::current_exe().expect("current test executable"));
        child
            // The bare name filters by substring; the assertion below requires
            // that it selects exactly one test.
            .args([test, "--nocapture"])
            .env_remove("BIFROST_CACHE_ROOT")
            .env_remove("BIFROST_CACHE_DIR")
            .env(DEFAULT_CACHE_CHILD, "1");
        isolate_machine_cache(&mut child, machine_cache.path());
        let output = child
            .output()
            .expect("run the default-cache check in a child process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed"),
            "child did not run and pass exactly {test}: stdout={stdout} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        true
    }

    /// Points the platform's per-user cache directory, which
    /// `crate::gitblob::machine_cache_dir` falls back to without
    /// `BIFROST_CACHE_ROOT`, at `dir` for `command`.
    fn isolate_machine_cache(command: &mut std::process::Command, dir: &std::path::Path) {
        command
            .env("XDG_CACHE_HOME", dir)
            .env("LOCALAPPDATA", dir)
            .env("HOME", dir);
    }

    fn commit_all(repo: &Repository) {
        let signature = Signature::now("Bifrost Test", "test@example.com").unwrap();
        crate::test_git_support::commit_all_without_parent(repo, "initial", &signature);
    }

    fn unbound_manual_service() -> SearchToolsService {
        super::unbound_test_service(UpdateStrategy::Manual, production_watcher_starter())
    }

    fn cache_db_for(root: &Path) -> PathBuf {
        root.join(crate::gitblob::PROJECT_DIR_NAME)
            .join(crate::gitblob::CACHE_SUBDIR_NAME)
            .join(crate::cache_db::cache_db_file_name())
    }

    fn committed_workspace(file: &str, source: &str) -> (tempfile::TempDir, PathBuf) {
        let (temp, root) = super::test_workspace(file, source);
        let repo = Repository::init(&root).unwrap();
        commit_all(&repo);
        (temp, root)
    }

    fn make_cache_gc_due(root: &Path) -> PathBuf {
        let store = crate::analyzer::store::AnalyzerStore::open_for_workspace(
            root,
            &brokk_bifrost_core::retention_budget::RetentionBudget::new(1024 * 1024 * 1024),
        )
        .unwrap();
        let db_path = store.db_path().unwrap().to_path_buf();
        drop(store);
        crate::cache_gc::set_accounting_for_test(&db_path, 0, 0).unwrap();
        db_path
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn manual_persisted_sessions_leave_gc_for_explicit_maintenance() {
        let (_source_temp, source_root) = committed_workspace("Source.java", "class Source {}\n");
        let source_db = make_cache_gc_due(&source_root);
        let service = SearchToolsService::new_manual_persisted(source_root.clone()).unwrap();
        assert_eq!(
            crate::cache_gc::gc_accounting_for_test(&source_db).unwrap(),
            (0, 0)
        );

        std::fs::write(
            source_root.join("Source.java"),
            "class Source { int value; }\n",
        )
        .unwrap();
        service.call_tool_value("refresh", json!({})).unwrap();
        assert_eq!(
            crate::cache_gc::gc_accounting_for_test(&source_db).unwrap(),
            (0, 0)
        );

        let (_target_temp, target_root) = committed_workspace("Target.java", "class Target {}\n");
        let target_db = make_cache_gc_due(&target_root);
        service
            .call_tool_value(
                "activate_workspace",
                json!({"workspace_path": target_root.display().to_string()}),
            )
            .unwrap();
        service.close().unwrap();

        assert_eq!(
            crate::cache_gc::gc_accounting_for_test(&source_db).unwrap(),
            (0, 0)
        );
        assert_eq!(
            crate::cache_gc::gc_accounting_for_test(&target_db).unwrap(),
            (0, 0)
        );
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn watched_persisted_sessions_still_run_automatic_gc() {
        let (_temp, root) = committed_workspace("Watched.java", "class Watched {}\n");
        let db_path = make_cache_gc_due(&root);

        let service = SearchToolsService::new(root).unwrap();
        service.close().unwrap();

        let (last_gc_at, blobs_at_last_gc) =
            crate::cache_gc::gc_accounting_for_test(&db_path).unwrap();
        assert!(last_gc_at > 0);
        assert!(blobs_at_last_gc > 0);
    }

    #[test]
    fn explicit_gc_collects_a_manual_cache() {
        let (_temp, root) = committed_workspace("Manual.java", "class Manual {}\n");
        let db_path = make_cache_gc_due(&root);
        let service = SearchToolsService::new_manual_persisted(root).unwrap();

        service.request_cache_gc().unwrap();
        service.close().unwrap();

        let (last_gc_at, blobs_at_last_gc) =
            crate::cache_gc::gc_accounting_for_test(&db_path).unwrap();
        assert!(last_gc_at > 0);
        assert!(blobs_at_last_gc > 0);
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn explicit_gc_rejects_ephemeral_sessions() {
        let (_temp, root) = committed_workspace("Ephemeral.java", "class Ephemeral {}\n");
        let service = SearchToolsService::new_manual_ephemeral(root).unwrap();

        let error = service.request_cache_gc().unwrap_err();

        assert_eq!(error.code, SearchToolsServiceErrorCode::InvalidParams);
        assert!(error.message.contains("persisted workspace"));
    }

    #[test]
    fn manual_ephemeral_service_answers_without_creating_a_persisted_cache() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo = Repository::init(&root).unwrap();
        std::fs::write(root.join("Local.java"), "class Local {}\n").unwrap();
        commit_all(&repo);

        let service = SearchToolsService::new_manual_ephemeral(root.clone()).unwrap();
        let result = service
            .call_tool_value(
                "search_symbols",
                json!({"patterns": ["Local"], "include_tests": true, "limit": 10}),
            )
            .unwrap();

        assert_eq!(result["total_files"], 1, "{result:#}");
        assert!(!cache_db_for(&root).exists());
        assert!(
            !root.join(crate::gitblob::PROJECT_DIR_NAME).exists(),
            "an ephemeral service must not create any generated checkout state"
        );
    }

    #[test]
    fn independent_manual_services_share_process_interner_accounting() {
        use brokk_bifrost_core::analyzer::fq_name::{SegmentKind, segment_interner};
        use brokk_bifrost_core::retention_budget::ProcessRequiredMemory;

        const CHILD: &str = "BIFROST_TWO_SERVICE_INTERNER_ACCOUNTING_CHILD";
        const COMPLETE: &str = "two-service process interner accounting complete";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(
                std::env::current_exe().expect("current test executable"),
            )
            .args([
                "--exact",
                "searchtools_service::client_roots_tests::independent_manual_services_share_process_interner_accounting",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("run isolated two-service interner accounting control");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success(),
                "child status {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
                output.status
            );
            assert!(
                stdout.lines().any(|line| line == COMPLETE),
                "child completion marker missing\nstdout:\n{stdout}\nstderr:\n{stderr}"
            );
            assert!(
                stdout.lines().any(|line| line
                    .starts_with("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;")),
                "child must execute exactly one test\nstdout:\n{stdout}\nstderr:\n{stderr}"
            );
            eprintln!("two-service accounting child stdout:\n{stdout}\nstderr:\n{stderr}");
            return;
        }

        let (_left_temp, left_root) = super::test_workspace("Left.java", "class Left {}\n");
        let (_right_temp, right_root) = super::test_workspace("Right.java", "class Right {}\n");
        let left = SearchToolsService::new_manual_ephemeral_footgun_for_project(
            Arc::new(FilesystemProject::new(left_root).unwrap()),
            AnalyzerConfig {
                retention_budget_bytes: Some(512 * 1024 * 1024),
                ..AnalyzerConfig::default()
            },
        )
        .unwrap();
        let right = SearchToolsService::new_manual_ephemeral_footgun_for_project(
            Arc::new(FilesystemProject::new(right_root).unwrap()),
            AnalyzerConfig {
                retention_budget_bytes: Some(1024 * 1024 * 1024),
                ..AnalyzerConfig::default()
            },
        )
        .unwrap();
        let interner = segment_interner();
        let process = ProcessRequiredMemory::global();
        // Snapshot explicitly settles each real service budget; accounting
        // does not depend on enabling timing or formatting an observer report.
        let left_before = left.retention_budget.snapshot();
        let right_before = right.retention_budget.snapshot();
        let names_before = interner.snapshot();
        let global_before = process.bytes();
        assert_ne!(left_before.owner_id, right_before.owner_id);
        assert_ne!(left_before.capacity_bytes, right_before.capacity_bytes);
        for before in [&left_before, &right_before] {
            assert_eq!(before.process_required_owner_id, process.owner_id());
            assert_eq!(before.process_required_bytes, global_before);
            assert_eq!(
                before.occupied_bytes,
                before.accounted_bytes + global_before
            );
        }

        let names = (0..512)
            .map(|index| {
                let name = format!(
                    "service_process_accounting_{}_{}",
                    std::process::id(),
                    index
                );
                let id = interner.intern(&name, SegmentKind::Type);
                (name, id)
            })
            .collect::<Vec<_>>();
        let global_after = process.bytes();
        let names_after = interner.snapshot();
        let delta = global_after.checked_sub(global_before).unwrap();
        assert!(delta > 0);
        assert_eq!(names_after.entries - names_before.entries, names.len());
        assert_eq!(
            delta,
            u64::try_from(
                names_after.estimated_retained_bytes - names_before.estimated_retained_bytes
            )
            .unwrap(),
            "the process owner charges actual interner growth once"
        );
        let left_after = left.retention_budget.snapshot();
        let right_after = right.retention_budget.snapshot();
        eprintln!(
            "service budgets before: {left_before:?}, {right_before:?}; after: {left_after:?}, {right_after:?}; global delta: {delta}"
        );
        for (before, after) in [(&left_before, &left_after), (&right_before, &right_after)] {
            assert_eq!(after.owner_id, before.owner_id);
            assert_eq!(after.process_required_owner_id, process.owner_id());
            assert_eq!(after.process_required_bytes, global_after);
            assert_eq!(
                after.process_required_bytes - before.process_required_bytes,
                delta
            );
            assert_eq!(
                after.accounted_bytes, before.accounted_bytes,
                "sufficient capacity leaves local retained allocations unchanged"
            );
            assert_eq!(after.occupied_bytes, after.accounted_bytes + global_after);
            assert!(after.occupied_bytes < after.capacity_bytes, "{after:?}");
            let free_before = before.capacity_bytes - before.occupied_bytes;
            let free_after = after.capacity_bytes - after.occupied_bytes;
            assert_eq!(free_before - free_after, delta);
        }
        assert_eq!(process.bytes(), global_after);
        // Existing-name hits and one service's destruction cannot release or
        // duplicate the required process charge or invalidate global IDs.
        for (name, id) in &names {
            assert_eq!(interner.intern(name, SegmentKind::Type), *id);
        }
        assert_eq!(process.bytes(), global_after);
        drop(left);
        assert_eq!(process.bytes(), global_after);
        for (name, id) in &names {
            assert_eq!(interner.resolve(*id), (name.as_str(), SegmentKind::Type));
        }
        let remaining = right.retention_budget.snapshot();
        assert_eq!(remaining.process_required_owner_id, process.owner_id());
        assert_eq!(remaining.process_required_bytes, global_after);
        let result = right
            .call_tool_value(
                "search_symbols",
                json!({
                    "patterns": ["Right"], "include_tests": true, "limit": 10
                }),
            )
            .unwrap();
        assert_eq!(result["total_files"], 1, "{result:#}");
        assert!(process.bytes() >= global_after);
        println!("\n{COMPLETE}");
    }

    /// A client-bound linked worktree resolves its cache the way every other
    /// entry point does: to the primary checkout's database, co-located with
    /// the git object database the analyzer must already read (issue #1544).
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1544: client-bound linked worktrees must share the primary repository cache"
    )]
    fn client_bound_linked_worktree_uses_the_primary_cache() {
        if ran_in_default_cache_child("client_bound_linked_worktree_uses_the_primary_cache") {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let primary_root = temp.path().join("primary");
        std::fs::create_dir(&primary_root).unwrap();
        let repo = Repository::init(&primary_root).unwrap();
        std::fs::write(primary_root.join("Primary.java"), "class Primary {}\n").unwrap();
        commit_all(&repo);

        let linked_root = temp.path().join("linked");
        let worktree = repo.worktree("linked", &linked_root, None).unwrap();
        let linked_repo = Repository::open_from_worktree(&worktree).unwrap();
        assert!(linked_repo.is_worktree());

        let service = unbound_manual_service();
        let canonical_linked = linked_root.canonicalize().unwrap();
        service
            .bind_client_workspace(canonical_linked.clone())
            .unwrap();
        service.ensure_ready().unwrap();

        let canonical_primary = primary_root.canonicalize().unwrap();
        assert!(
            cache_db_for(&canonical_primary).exists(),
            "client-bound linked worktree must write the primary checkout's shared cache"
        );
        assert!(
            !canonical_linked
                .join(crate::gitblob::PROJECT_DIR_NAME)
                .exists(),
            "client-bound linked worktree must not fork a private cache"
        );
    }

    /// A client-bound root that is not inside any repository keeps the local
    /// fallback `gitblob::cache_db_path` already provides: resolution never
    /// escapes such a root.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1544: a non-Git client root must retain its own local cache path"
    )]
    fn client_bound_non_git_root_keeps_a_local_cache_path() {
        if ran_in_default_cache_child("client_bound_non_git_root_keeps_a_local_cache_path") {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("loose");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("Loose.java"), "class Loose {}\n").unwrap();
        let canonical_root = root.canonicalize().unwrap();

        assert_eq!(
            crate::gitblob::cache_db_path(&canonical_root),
            cache_db_for(&canonical_root)
        );

        let service = unbound_manual_service();
        service
            .bind_client_workspace(canonical_root.clone())
            .unwrap();
        service.ensure_ready().unwrap();

        let result = service
            .call_tool_value(
                "search_symbols",
                json!({"patterns": ["Loose"], "include_tests": true, "limit": 10}),
            )
            .unwrap();
        assert_eq!(result["total_files"], 1, "{result:#}");
        assert!(
            cache_db_for(&canonical_root).exists(),
            "a non-git client root must keep its persisted cache inside the bound root"
        );
        assert!(
            !temp.path().join(crate::gitblob::PROJECT_DIR_NAME).exists(),
            "a non-git client root must not write a cache above itself"
        );
    }

    /// Binding a directory nested inside a repository resolves to that
    /// repository's primary cache. The bound root still bounds what the
    /// workspace sees; it does not bound where derived data lives.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1544: nested client roots must map to the repository primary cache"
    )]
    fn nested_client_root_uses_the_repository_primary_cache() {
        if ran_in_default_cache_child("nested_client_root_uses_the_repository_primary_cache") {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let primary_root = temp.path().join("primary");
        std::fs::create_dir(&primary_root).unwrap();
        let repo = Repository::init(&primary_root).unwrap();
        std::fs::create_dir(primary_root.join("nested")).unwrap();
        std::fs::write(primary_root.join("nested/Nested.java"), "class Nested {}\n").unwrap();
        commit_all(&repo);
        let canonical_primary = primary_root.canonicalize().unwrap();
        let nested_root = primary_root.join("nested").canonicalize().unwrap();

        let service = unbound_manual_service();
        service.bind_client_workspace(nested_root.clone()).unwrap();
        service.ensure_ready().unwrap();

        assert!(cache_db_for(&canonical_primary).exists());
        assert!(
            !nested_root.join(crate::gitblob::PROJECT_DIR_NAME).exists(),
            "a nested client root must not fork a private cache"
        );
        let result = service
            .call_tool_value(
                "search_symbols",
                json!({"patterns": ["Nested"], "include_tests": true, "limit": 10}),
            )
            .unwrap();
        assert_eq!(result["total_files"], 1, "{result:#}");
    }

    /// Sharing the primary database must not leak the primary checkout's
    /// content into a linked worktree's results: reconciliation resolves every
    /// answer against the bound worktree's current blob oids.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1544: a shared primary cache must not leak symbols from another workspace"
    )]
    fn shared_primary_cache_does_not_leak_primary_only_symbols() {
        if ran_in_default_cache_child("shared_primary_cache_does_not_leak_primary_only_symbols") {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let primary_root = temp.path().join("primary");
        std::fs::create_dir(&primary_root).unwrap();
        let repo = Repository::init(&primary_root).unwrap();
        std::fs::write(primary_root.join("Shared.java"), "class Shared {}\n").unwrap();
        std::fs::write(
            primary_root.join("Changed.java"),
            "class PrimaryChanged {}\n",
        )
        .unwrap();
        std::fs::write(
            primary_root.join("PrimaryOnly.java"),
            "class PrimaryOnly {}\n",
        )
        .unwrap();
        commit_all(&repo);
        let canonical_primary = primary_root.canonicalize().unwrap();
        let (_primary_project, primary_workspace) = build_persisted_workspace(
            canonical_primary.clone(),
            None,
            UpdateStrategy::Manual,
            &HostActivationContext::library_none(),
        )
        .unwrap();

        let linked_root = temp.path().join("linked");
        let worktree = repo.worktree("linked", &linked_root, None).unwrap();
        let linked_repo = Repository::open_from_worktree(&worktree).unwrap();
        assert!(linked_repo.is_worktree());
        std::fs::write(linked_root.join("Changed.java"), "class LinkedChanged {}\n").unwrap();
        std::fs::remove_file(linked_root.join("PrimaryOnly.java")).unwrap();

        let canonical_linked = linked_root.canonicalize().unwrap();
        let service = unbound_manual_service();
        service
            .bind_client_workspace(canonical_linked.clone())
            .unwrap();
        service.ensure_ready().unwrap();

        assert!(cache_db_for(&canonical_primary).exists());
        assert!(
            !canonical_linked
                .join(crate::gitblob::PROJECT_DIR_NAME)
                .exists()
        );
        for (pattern, expected_files) in [
            ("Shared", 1),
            ("LinkedChanged", 1),
            ("PrimaryChanged", 0),
            ("PrimaryOnly", 0),
        ] {
            let result = service
                .call_tool_value(
                    "search_symbols",
                    json!({"patterns": [pattern], "include_tests": true, "limit": 10}),
                )
                .unwrap();
            assert_eq!(
                result["total_files"], expected_files,
                "pattern={pattern} result={result:#}"
            );
        }
        drop(primary_workspace);
    }
}

#[cfg(test)]
mod search_symbols_cancellation_tests {
    use super::*;
    use serde_json::json;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13331: pre-cancelled queries must stop before acquiring a scope"
    )]
    fn pre_cancelled_queries_stop_before_snapshot_acquisition() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("lib.rs"), "pub fn target() {}\n").unwrap();
        let service = SearchToolsService::new_manual_ephemeral(temp.path().to_path_buf()).unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        for (tool, arguments) in [
            ("search_symbols", json!({"patterns": ["target"]})),
            (
                "most_relevant_files",
                json!({"seed_file_paths": ["lib.rs"], "ranking_mode": "usage_graph", "limit": 10}),
            ),
            ("scan_usages_by_reference", json!({"symbols": ["target"]})),
            (
                "scan_usages_by_location",
                json!({"targets": [{"path": "lib.rs", "line": 1}]}),
            ),
        ] {
            let error = service
                .call_tool_output_with_cancellation(
                    tool,
                    arguments,
                    RenderOptions::default(),
                    Some(&cancellation),
                )
                .expect_err("cancelled acquisition cannot produce a query scope");
            assert_eq!(
                error.code,
                SearchToolsServiceErrorCode::Internal,
                "{tool}: {error:?}"
            );
            assert!(error.message.contains("cancelled"), "{tool}: {error:?}");
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1199: cancellation must reach the cold search_symbols request"
    )]
    fn issue_1199_service_forwards_cancellation_to_search_symbols() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("lib.rs"),
            "pub fn semantic_diagnostics() {}\n",
        )
        .unwrap();
        let service = SearchToolsService::new_manual_ephemeral(temp.path().to_path_buf()).unwrap();
        // Cancel after acquiring the scope, preserving execution's partial result.
        let cancellation = CancellationToken::cancel_after_checks_for_test(5);

        let result = service
            .call_tool_output_with_cancellation(
                "search_symbols",
                json!({
                    "patterns": ["semantic_diagnostics"],
                    "include_tests": true,
                    "limit": 100
                }),
                RenderOptions::default(),
                Some(&cancellation),
            )
            .unwrap()
            .into_value();

        assert_eq!(result["truncated"], true, "{result:#}");
        assert_eq!(result["total_files"], 0, "{result:#}");
        assert_eq!(result["files"], json!([]), "{result:#}");
        assert!(
            result["note"]
                .as_str()
                .is_some_and(|note| note.contains("cancelled") && note.contains("partial")),
            "{result:#}"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1304: cancellation must reach usage-ranked most_relevant_files work"
    )]
    fn issue_1304_service_forwards_cancellation_to_most_relevant_files() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("lib.rs"), "pub fn target() {}\n").unwrap();
        let service = SearchToolsService::new_manual_ephemeral(temp.path().to_path_buf()).unwrap();
        // Cancel after acquiring the scope, preserving execution's partial result.
        let cancellation = CancellationToken::cancel_after_checks_for_test(5);

        let error = service
            .call_tool_output_with_cancellation(
                "most_relevant_files",
                json!({
                    "seed_file_paths": ["lib.rs"],
                    "ranking_mode": "usage_graph",
                    "limit": 10
                }),
                RenderOptions::default(),
                Some(&cancellation),
            )
            .unwrap_err();

        assert_eq!(error.code, SearchToolsServiceErrorCode::Internal);
        assert!(error.message.contains("most_relevant_files was cancelled"));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1304: cancelled shared ranking must publish no incomplete ranked prefix"
    )]
    fn issue_1304_shared_request_cancellation_publishes_no_ranked_prefix() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("A.java"),
            "import local.B; public class A { B value; }\n",
        )
        .unwrap();
        std::fs::create_dir(temp.path().join("local")).unwrap();
        std::fs::write(
            temp.path().join("local/B.java"),
            "package local; public class B {}\n",
        )
        .unwrap();
        let service = SearchToolsService::new_manual_ephemeral(temp.path().to_path_buf()).unwrap();
        let cancellation = CancellationToken::cancel_after_checks_for_test(8);

        let output = service
            .call_tool_output_with_cancellation(
                "most_relevant_files",
                json!({
                    "seed_file_paths": ["A.java"],
                    "ranking_mode": "usage_graph",
                    "limit": 10
                }),
                RenderOptions::default(),
                Some(&cancellation),
            )
            .unwrap();
        let (result, rendered) = match output {
            ToolOutput::Structured {
                structured,
                rendered_text,
            } => (structured, rendered_text.unwrap_or_default()),
            output => panic!("expected structured fallback, got {output:?}"),
        };

        assert_eq!(result["complete"], false, "{result:#}");
        assert_eq!(result["ranking_mode_used"], "history_imports", "{result:#}");
        assert_eq!(result["incomplete_reason"], "cancelled", "{result:#}");
        assert_eq!(result["files"], json!([]), "{result:#}");
        assert!(
            rendered
                .contains("the request was cancelled before a complete result could be published"),
            "{rendered}"
        );
    }

    fn assert_cancelled_scan_result(
        result: &Value,
        expected_input_kind: &str,
        expected_count: usize,
    ) {
        assert_eq!(result["summary"]["partial"], true, "{result:#}");
        assert_eq!(result["summary"]["verified_absent"], 0, "{result:#}");
        assert_eq!(result["summary"]["failure"], expected_count, "{result:#}");
        let entries = result["results"].as_array().expect("scan results array");
        assert_eq!(entries.len(), expected_count, "{result:#}");
        for entry in entries {
            assert_eq!(entry["input_kind"], expected_input_kind);
            assert_eq!(entry["complete"], false, "{result:#}");
            assert_eq!(entry["incomplete_reason"], "cancelled", "{result:#}");
            assert_eq!(entry["reason_kind"], "cancelled", "{result:#}");
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1228: cancellation must reach reference and location usage scans"
    )]
    fn issue_1228_service_forwards_cancellation_to_usage_scans() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("lib.rs"), "pub fn target() {}\n").unwrap();
        let service = SearchToolsService::new_manual_ephemeral(temp.path().to_path_buf()).unwrap();

        for (tool, arguments, input_kind, count) in [
            (
                "scan_usages_by_reference",
                json!({
                    "symbols": ["target", "other"],
                    "include_tests": true
                }),
                "symbol",
                2,
            ),
            (
                "scan_usages_by_location",
                json!({
                    "targets": [{"path": "lib.rs", "line": 1}],
                    "include_tests": true
                }),
                "target",
                1,
            ),
        ] {
            let cancellation = CancellationToken::cancel_after_checks_for_test(5);
            let result = service
                .call_tool_output_with_cancellation(
                    tool,
                    arguments,
                    RenderOptions::default(),
                    Some(&cancellation),
                )
                .unwrap()
                .into_value();
            assert_cancelled_scan_result(&result, input_kind, count);
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1199: unbounded search pattern batches must be rejected before cold work"
    )]
    fn issue_1199_search_symbols_rejects_unbounded_pattern_batches() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("lib.rs"), "pub fn target() {}\n").unwrap();
        let service = SearchToolsService::new_manual_ephemeral(temp.path().to_path_buf()).unwrap();

        let oversized = [
            (
                vec!["target".to_string(); crate::searchtools::SEARCH_SYMBOL_MAX_PATTERNS + 1],
                "at most",
            ),
            (
                vec!["x".repeat(crate::searchtools::SEARCH_SYMBOL_MAX_PATTERN_BYTES + 1)],
                "each search pattern",
            ),
            (
                vec![
                    "x".repeat(
                        crate::searchtools::SEARCH_SYMBOL_MAX_TOTAL_PATTERN_BYTES
                            / crate::searchtools::SEARCH_SYMBOL_MAX_PATTERNS
                            + 1,
                    );
                    crate::searchtools::SEARCH_SYMBOL_MAX_PATTERNS
                ],
                "must total",
            ),
        ];
        for (patterns, expected_message) in oversized {
            let error = service
                .call_tool_output(
                    "search_symbols",
                    json!({ "patterns": patterns }),
                    RenderOptions::default(),
                )
                .expect_err("oversized pattern batches must be rejected before compilation");

            assert_eq!(error.code, SearchToolsServiceErrorCode::InvalidParams);
            assert!(error.message.contains(expected_message), "{error:#?}");
        }
    }
}

#[cfg(test)]
mod query_protocol_tests {
    use super::*;
    use crate::analyzer::semantic::{ProcedureKind, SemanticBudget, SemanticRequest};
    use crate::cancellation::CancellationToken;
    use crate::flow::typestate::{ProtocolSpec, TypestateBindingPlan};
    use crate::rql::{CodeQueryDiagnosticCode, ProtocolRef};
    use serde_json::json;

    const RESOURCE_LIFECYCLE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/typestate/resource-lifecycle.protocol.json"
    ));

    fn protocol_service() -> (tempfile::TempDir, SearchToolsService, ProtocolRef) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("main.ts"),
            "export function lifecycle(): void {}\n",
        )
        .unwrap();
        let service = SearchToolsService::new_manual_ephemeral(temp.path().to_path_buf()).unwrap();
        let workspace = service.analyzer_snapshot().unwrap();
        let file = ProjectFile::new(workspace.analyzer().project().root(), "main.ts");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap()
            .available_value()
            .cloned()
            .expect("TypeScript semantics");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| procedure.kind() == ProcedureKind::Function)
            .expect("lifecycle procedure");
        let root = artifact
            .procedure_handle(procedure.id())
            .expect("scoped lifecycle handle");
        let protocol = Arc::new(
            ProtocolSpec::from_json(RESOURCE_LIFECYCLE)
                .unwrap()
                .compile()
                .unwrap(),
        );
        let bindings = Arc::new(
            TypestateBindingPlan::try_new(&protocol, vec![], vec![], vec![], vec![]).unwrap(),
        );
        let protocol_ref: ProtocolRef = "test:lifecycle".parse().unwrap();
        service
            .register_query_protocol(protocol_ref.clone(), root, Arc::clone(&protocol), bindings)
            .unwrap();
        (temp, service, protocol_ref)
    }

    fn query(protocol_ref: &ProtocolRef) -> Value {
        json!({
            "schema_version": 1,
            "match": {"kind": "function", "name": "lifecycle"},
            "steps": [
                {"op": "procedure_of"},
                {"op": "typestate", "protocol_ref": protocol_ref.to_string()}
            ]
        })
    }

    fn assert_prepared_protocol_snapshot_retained(value: &Value) {
        assert!(
            value.get("diagnostics").is_none_or(|diagnostics| {
                diagnostics
                    .as_array()
                    .expect("query diagnostics are an array")
                    .iter()
                    .all(|diagnostic| {
                        diagnostic["code"] == "step_produced_no_rows"
                            && diagnostic["impact"] == "advisory"
                    })
            }),
            "prepared request should retain its registered protocol without incomplete diagnostics: {value}"
        );
    }

    #[test]
    fn prepared_query_keeps_registration_snapshot_after_alias_removal() {
        let (_temp, service, protocol_ref) = protocol_service();
        let prepared = service
            .prepare_query_code(query(&protocol_ref), None)
            .unwrap();
        assert!(service.unregister_query_protocol(&protocol_ref).unwrap());

        let prepared_value = service
            .execute_prepared_query_code(prepared, None)
            .unwrap()
            .into_value();
        assert_prepared_protocol_snapshot_retained(&prepared_value);

        let current = service.query_code_result(query(&protocol_ref)).unwrap();
        assert_eq!(
            current
                .result()
                .unwrap()
                .diagnostics
                .iter()
                .next()
                .expect("one diagnostic")
                .code(),
            CodeQueryDiagnosticCode::UnresolvedProtocolReference
        );
    }

    #[test]
    fn workspace_generation_advance_clears_live_registrations_but_not_prepared_snapshots() {
        let (_temp, service, protocol_ref) = protocol_service();
        let prepared = service
            .prepare_query_code(query(&protocol_ref), None)
            .unwrap();

        service.advance_workspace_generation();

        let live = service.query_protocol_snapshot().unwrap();
        assert_eq!(live.reference_count(), 0);
        assert_eq!(live.registration_count(), 0);
        assert_eq!(live.retained_artifact_bytes(), 0);

        let prepared_value = service
            .execute_prepared_query_code(prepared, None)
            .unwrap()
            .into_value();
        assert_prepared_protocol_snapshot_retained(&prepared_value);

        let current = service.query_code_result(query(&protocol_ref)).unwrap();
        assert_eq!(
            current
                .result()
                .unwrap()
                .diagnostics
                .iter()
                .next()
                .expect("one diagnostic")
                .code(),
            CodeQueryDiagnosticCode::UnresolvedProtocolReference
        );
    }

    #[test]
    fn repeated_queries_hit_generation_scoped_typestate_results_and_rotation_evicts_them() {
        let (temp, service, protocol_ref) = protocol_service();
        let mut request = query(&protocol_ref);
        request["execution_mode"] = json!("profile");

        let first = service.query_code_result(request.clone()).unwrap();
        let second = service.query_code_result(request).unwrap();
        let first = serde_json::to_value(first).unwrap();
        let second = serde_json::to_value(second).unwrap();
        assert_eq!(first.pointer("/results"), second.pointer("/results"),);
        assert_eq!(
            first.pointer("/diagnostics"),
            second.pointer("/diagnostics"),
        );
        assert_eq!(
            first.pointer("/work/semantic/typestate/summary_misses"),
            Some(&json!(1))
        );
        assert_eq!(
            first.pointer("/work/semantic/typestate/summary_recomputations"),
            Some(&json!(1))
        );
        assert_eq!(
            second.pointer("/work/semantic/typestate/summary_hits"),
            Some(&json!(1))
        );
        assert_eq!(
            second.pointer("/work/semantic/typestate/summary_recomputations"),
            Some(&json!(0))
        );

        std::fs::write(
            temp.path().join("lifecycle.rql"),
            format!(
                "(profile (typestate :protocol-ref \"{protocol_ref}\" (procedure-of (function :name \"lifecycle\"))))"
            ),
        )
        .unwrap();
        let rql = serde_json::to_value(
            service
                .query_code_result(json!({"query_file": "lifecycle.rql"}))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(rql.pointer("/results"), first.pointer("/results"));
        assert_eq!(rql.pointer("/diagnostics"), first.pointer("/diagnostics"));
        assert_eq!(
            rql.pointer("/work/semantic/typestate/summary_hits"),
            Some(&json!(1))
        );

        let prepared = service
            .prepare_query_code(json!({"query_file": "lifecycle.rql"}), None)
            .unwrap();

        // A generation advance no longer rotates the summary repository, so
        // the exact result computed under the previous generation is still a
        // hit. The prepared request retains its protocol registration while a
        // new live request would correctly become unresolved.
        service.advance_workspace_generation();
        let after_advance = serde_json::to_value(
            service
                .execute_prepared_query_code(prepared, None)
                .unwrap()
                .into_value(),
        )
        .unwrap();
        assert_eq!(after_advance.pointer("/results"), first.pointer("/results"));
        assert_eq!(
            after_advance.pointer("/work/semantic/typestate/summary_hits"),
            Some(&json!(1))
        );
        assert_eq!(
            after_advance.pointer("/work/semantic/typestate/summary_recomputations"),
            Some(&json!(0))
        );
    }
}

#[cfg(test)]
mod maintenance_read_tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::{
        AnalyzerQueryScope, ReadLedger, capture_query_reads, read_attribution_fallback_count,
    };
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#7761: refresh workers recorded project inputs into another analyzer's capture")]
    fn refresh_does_not_record_into_active_query_captures() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(
            root.join("Factory.java"),
            "package example; class Before {}\n",
        )
        .unwrap();
        std::fs::write(root.join("helper.js"), "export function helper() {}\n").unwrap();
        std::fs::write(root.join("Second.java"), "class Second {}\n").unwrap();
        let project: Arc<dyn Project> = Arc::new(FilesystemProject::new(root.clone()).unwrap());
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::clone(&project),
            AnalyzerConfig::default(),
        )
        .unwrap();
        assert!(
            !workspace
                .analyzer()
                .get_definitions("example.Before")
                .is_empty()
        );
        let observer = workspace.clone_for_index_warm(Arc::clone(&project));
        let ledger = Arc::new(ReadLedger::new());
        let scope = AnalyzerQueryScope::with_read_ledger(observer.analyzer(), Arc::clone(&ledger));
        let file = ProjectFile::new(root.clone(), "Factory.java");
        assert!(!project.has_overlay(&file));
        let expected = ledger.keys();
        let fallbacks = read_attribution_fallback_count();
        assert!(
            !expected.is_empty(),
            "the shared project's recorder must reach the observer"
        );
        std::fs::write(
            root.join("Factory.java"),
            "package example; class After {}\n",
        )
        .unwrap();
        let changed = BTreeSet::from([file]);
        // The observer stays attached for the complete update. This helper
        // deliberately carries no request frame, as a refresh worker does.
        let (updated, reads) = capture_query_reads(observer.analyzer(), || {
            std::thread::scope(|threads| {
                threads.spawn(|| workspace.update(&changed)).join().unwrap()
            })
        });
        assert!(
            reads.keys().is_empty(),
            "maintenance recorded inputs: {:?}",
            reads.keys()
        );
        assert_eq!(reads.unattributed_reads(), 0);
        assert_eq!(ledger.keys(), expected);
        let (rebuilt, reads) = capture_query_reads(observer.analyzer(), || updated.update_all());
        assert!(
            reads.keys().is_empty(),
            "full refresh recorded inputs: {:?}",
            reads.keys()
        );
        assert_eq!(reads.unattributed_reads(), 0);
        assert_eq!(ledger.keys(), expected);
        // Auto admission is normally requested by a structural query. Mark it
        // here without filling any index, then exercise the actual warmer's
        // provider fan-out and its nested parallel file acquisition.
        use brokk_bifrost_analysis::analyzer::structural::index::{
            QueryStructuralIndexSession, StructuralIndexAcquisition, StructuralIndexLifecycle,
        };
        brokk_bifrost_analysis::analyzer::without_project_reads(|| {
            let session = QueryStructuralIndexSession::default();
            let providers = rebuilt.analyzer().structural_fact_providers();
            assert!(!providers.is_empty());
            for provider in providers {
                let cache = provider.snapshot_structural_index_cache().unwrap().inner();
                let content = provider.structural_content_identity().unwrap();
                session.defer_auto_build(cache, content);
            }
            session.publish_auto_observations();
            assert!(!rebuilt.analyzer().structural_indexes_warm());
        });
        let (_, reads) = capture_query_reads(observer.analyzer(), || {
            // Like refresh above, this independent maintenance worker carries
            // no query frame while the shared observer's capture stays open.
            std::thread::scope(|threads| {
                threads
                    .spawn(|| rebuilt.analyzer().warm_structural_indexes())
                    .join()
                    .unwrap();
            });
        });
        assert!(
            reads.keys().is_empty(),
            "structural warm recorded inputs: {:?}",
            reads.keys()
        );
        assert_eq!(reads.unattributed_reads(), 0);
        assert_eq!(ledger.keys(), expected);
        brokk_bifrost_analysis::analyzer::without_project_reads(|| {
            assert!(rebuilt.analyzer().structural_indexes_warm());
            let mut indexed_files = 0;
            for provider in rebuilt.analyzer().structural_fact_providers() {
                let cache = provider.snapshot_structural_index_cache().unwrap().inner();
                let StructuralIndexAcquisition::Ready {
                    index, lifecycle, ..
                } = cache.acquire(provider, &CancellationToken::default())
                else {
                    panic!("structural warm must publish a complete index");
                };
                assert_eq!(lifecycle, StructuralIndexLifecycle::Hit);
                indexed_files += index.file_count();
            }
            assert!(
                indexed_files >= 3,
                "cold acquisition must index all fixture files"
            );
        });
        assert_eq!(ledger.unattributed_reads(), 0);
        assert_eq!(
            read_attribution_fallback_count(),
            fallbacks,
            "maintenance must not cross an unattributed recorder"
        );
        drop(scope);
        assert!(
            rebuilt
                .analyzer()
                .get_definitions("example.Before")
                .is_empty()
        );
        assert!(
            !rebuilt
                .analyzer()
                .get_definitions("example.After")
                .is_empty()
        );
        let (_, reads) = capture_query_reads(observer.analyzer(), || {
            assert!(!project.has_overlay(changed.first().unwrap()));
        });
        assert!(
            !reads.keys().is_empty(),
            "ordinary query recording must resume after refresh"
        );
    }
}

#[cfg(test)]
mod host_activation_plumbing_tests {
    use super::*;
    use serde_json::json;

    fn project_root() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("A.java"), "class A {}\n").unwrap();
        (temp, root)
    }

    /// The host every analyzer the service currently serves is pinned to.
    fn snapshot_host(service: &SearchToolsService) -> Arc<HostActivationContext> {
        service
            .analyzer_snapshot()
            .unwrap()
            .analyzer()
            .host_activation_context()
            .expect("an analyzer built through the service is bound before activation")
    }

    fn assert_same_host(service: &SearchToolsService, host: &Arc<HostActivationContext>) {
        assert!(Arc::ptr_eq(service.host_activation_context(), host));
        assert!(Arc::ptr_eq(&snapshot_host(service), host));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#14134: source-scoped MCP policy runs dropped their parent host approval"
    )]
    fn source_scoped_policy_keeps_the_parent_host_authority() {
        use brokk_bifrost_analysis::analyzer::semantic_model::VerifiedFirstPartyReleaseInventory;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("app.ts"), "export function target() {}\n").unwrap();
        std::fs::create_dir(root.join("policies")).unwrap();
        std::fs::write(
            root.join("policies/host.rqlp"),
            r#"(policy :schema-version 1
            :id "test.scoped-host" :name "Scoped host" :message "Observed" :severity warning
            :analysis (analysis :type match :selector
              (rql :schema-version 1 (language typescript (function :name "target")))))"#,
        )
        .unwrap();
        let host = HostActivationContext::from_inventory(
            VerifiedFirstPartyReleaseInventory::compiled_default().unwrap(),
            &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
        )
        .unwrap();
        let expected = serde_json::to_value(host.metadata().unwrap()).unwrap();
        let service =
            SearchToolsService::new_manual_persisted_with_host_activation_context(root, host)
                .unwrap();
        for sources in [json!([]), json!(["app.ts"])] {
            let result = service.call_tool_value("run_policy", json!({
                "policy_files": ["policies/host.rqlp"], "sources": sources, "evaluation_date": "2026-09-29"
            })).unwrap();
            assert_eq!(
                result["report"]["packs"]["host_activation"], expected,
                "run_policy must preserve the parent authority before scoped activation: {result}"
            );
            assert_eq!(
                result["report"]["runs"][0]["findings"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
        }
    }

    #[test]
    fn eager_service_binds_the_host_before_activation() {
        let (_temp, root) = project_root();
        let host = HostActivationContext::library_none();
        let service = SearchToolsService::new_manual_ephemeral_with_host_activation_context(
            root,
            Arc::clone(&host),
        )
        .unwrap();
        assert_same_host(&service, &host);
    }

    #[test]
    fn default_constructors_bind_an_explicit_library_none_host() {
        let (_temp, root) = project_root();
        let service = SearchToolsService::new_manual_ephemeral(root).unwrap();
        assert!(Arc::ptr_eq(
            service.host_activation_context(),
            &snapshot_host(&service)
        ));
    }

    #[test]
    fn deferred_session_build_binds_the_same_host() {
        let (_temp, root) = project_root();
        let host = HostActivationContext::library_none();
        let service = SearchToolsService::new_deferred_manual_with_host_activation_context(
            root,
            Arc::clone(&host),
        )
        .unwrap();
        service.ensure_ready().unwrap();
        assert_same_host(&service, &host);
    }

    #[test]
    fn unbound_service_binds_the_host_on_client_workspace_bind() {
        let (_temp, root) = project_root();
        let host = HostActivationContext::library_none();
        let service =
            SearchToolsService::new_unbound_manual_with_host_activation_context(Arc::clone(&host));
        assert!(Arc::ptr_eq(service.host_activation_context(), &host));
        service.bind_client_workspace(root).unwrap();
        service.ensure_ready().unwrap();
        assert_same_host(&service, &host);
    }

    #[test]
    fn activate_workspace_rebuild_keeps_the_same_host() {
        let (_first_temp, first) = project_root();
        let (_second_temp, second) = project_root();
        let host = HostActivationContext::library_none();
        let service = SearchToolsService::new_deferred_manual_with_host_activation_context(
            first,
            Arc::clone(&host),
        )
        .unwrap();
        service.ensure_ready().unwrap();
        service
            .call_tool_value("activate_workspace", json!({"workspace_path": second}))
            .unwrap();
        service.ensure_ready().unwrap();
        assert_same_host(&service, &host);
    }

    #[test]
    fn stale_snapshot_reload_keeps_the_same_host() {
        let (_temp, root) = project_root();
        let host = HostActivationContext::library_none();
        let service = SearchToolsService::new_manual_persisted_with_host_activation_context(
            root,
            Arc::clone(&host),
        )
        .unwrap();
        let before = service.analyzer_snapshot().unwrap();
        service
            .reload_stale_workspace_snapshot(service.workspace_generation())
            .unwrap();
        let after = service.analyzer_snapshot().unwrap();
        assert!(
            !Arc::ptr_eq(&before, &after),
            "the reload rebuilt the analyzer"
        );
        assert_same_host(&service, &host);
    }

    #[test]
    fn project_constructors_bind_the_host() {
        let (_temp, root) = project_root();
        let host = HostActivationContext::library_none();
        let project: Arc<dyn Project> = Arc::new(FilesystemProject::new(root).unwrap());
        let ephemeral =
            SearchToolsService::new_manual_ephemeral_footgun_for_project_with_host_activation_context(
                Arc::clone(&project),
                AnalyzerConfig::default(),
                Arc::clone(&host),
            )
            .unwrap();
        assert_same_host(&ephemeral, &host);
        let scoped =
            SearchToolsService::new_manual_scoped_persisted_for_project_with_host_activation_context(
                Arc::clone(&project),
                AnalyzerConfig::default(),
                Arc::clone(&host),
            )
            .unwrap();
        assert_same_host(&scoped, &host);
        let persisted =
            SearchToolsService::new_manual_persisted_for_project_with_host_activation_context(
                project,
                AnalyzerConfig::default(),
                Arc::clone(&host),
            )
            .unwrap();
        assert_same_host(&persisted, &host);
    }

    #[test]
    fn tool_arguments_cannot_supply_or_replace_the_host() {
        let (_temp, root) = project_root();
        let (_other_temp, other_root) = project_root();
        let host = HostActivationContext::library_none();
        let intruder = HostActivationContext::library_none();
        let service = SearchToolsService::new_deferred_manual_with_host_activation_context(
            root,
            Arc::clone(&host),
        )
        .unwrap();
        service.ensure_ready().unwrap();
        // Hostile argument keys naming a host context are either rejected or
        // ignored; neither outcome may change the bound authority.
        let _ = service.call_tool_value(
            "activate_workspace",
            json!({
                "workspace_path": other_root,
                "host_activation": "library_none",
                "host_activation_context": {"identity": format!("{:?}", intruder.identity())},
            }),
        );
        let _ = service.call_tool_value(
            "get_active_workspace",
            json!({"host_activation": {"inventory": "attacker"}}),
        );
        service.ensure_ready().unwrap();
        assert_same_host(&service, &host);
        assert!(!Arc::ptr_eq(service.host_activation_context(), &intruder));
    }
}
