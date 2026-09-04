#[cfg(test)]
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
    ProjectFile, SubsetCoverage, WorkspaceAnalyzer, WorkspaceFileListingCache,
    analyzer::IndexWarmer,
    analyzer::packs_document::{
        WORKSPACE_PACKS_DOCUMENT_PATH, WorkspaceActivationSources, WorkspacePacksActivation,
        WorkspacePacksConfig, activate_workspace_semantic_sources_in_catalog,
        bootstrap_semantic_model_catalog,
        install_semantic_model_catalog_bootstrap as install_shared_semantic_model_catalog_bootstrap,
        intrinsic_language_evidence, load_workspace_packs_config_at,
        open_ambient_semantic_pack_catalog, workspace_pack_ecosystems,
    },
    analyzer::semantic::WorkspaceRelativePath,
    analyzer::semantic_model::{
        CatalogCoordinate, CatalogOpenMode, CatalogOptions, SemanticModelActivationEvidence,
        SemanticModelActivationRequest, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
        SemanticPackCatalog, WorkspaceSemanticModelOptions, acquire_active_semantic_models,
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
    diff_scoring::{ScoreDiffParams, score_diff_at_root},
    file_tools::{find_files_containing, get_file_contents, search_file_contents},
    path_normalization::NormalizePath,
    policy::{
        BuiltInPolicySelection, ExplainError, ExplanationCandidate, ExplanationLimits,
        ExplanationTarget, NearMissCandidates, POLICY_EXIT_CLEAN, POLICY_EXIT_FINDING,
        POLICY_EXIT_UNRELIABLE, PolicyBaselineOptions, PolicyBaselineSource, PolicyBatchOutcome,
        PolicyEvaluationDate, PolicyEvaluationInput, PolicyEvaluationOptions, PolicyExplanation,
        PolicyFailOn, PolicyFindingId, PolicyHostActivationContext, PolicyId,
        PolicyNearMissRanking, PolicyReportDocument, PolicyRun, PolicyScopeOptions,
        PolicyScopeSource, PolicyStageTiming, PolicySuppressionOptions, PolicySuppressionSource,
        built_in_policy_catalog, explain_policy_inputs, rank_policy_near_misses,
        workspace_snapshot_deadline_outcome_with_preflight,
    },
    profiling,
    searchtools::{
        ActivateWorkspaceParams, ActiveWorkspaceResult, GetActiveWorkspaceParams,
        MostRelevantFilesParams, RefreshParams, SymbolLookupParams, SymbolSourcesResult,
        classify_test_files, get_declarations_by_location_with_cancellation,
        get_definitions_by_location_with_cancellation, get_definitions_by_reference,
        get_summaries_with_cancellation, get_symbol_ancestors,
        get_symbol_locations_with_cancellation, get_symbol_sources_with_source_budget,
        get_type_by_location, list_symbols, most_relevant_files_with_cancellation, refresh_result,
        rename_symbol, scan_usages_by_location_with_cancellation,
        scan_usages_by_reference_with_cancellation, search_symbols_with_cancellation,
        session_subset, symbol_source_candidate_files, usage_graph,
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
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
            artifact_sha256: self.artifact_sha256,
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
    activation: Option<Arc<WorkspacePacksActivation>>,
    ecosystems: Vec<crate::analyzer::DependencyPackEcosystem>,
    failure: Option<String>,
}

fn activate_configured_semantic_models(
    workspace_root: &Path,
    workspace: &WorkspaceAnalyzer,
    configured: Option<ConfiguredSemanticModels>,
) -> Result<WorkspacePackActivationState, String> {
    let _scope = profiling::scope("semantic_pack.activate_configured");
    let packs_config = load_workspace_packs_config_at(workspace_root)
        .map_err(|error| format!("failed to load workspace packs document: {error}"))?
        .map(Arc::new);
    let explicit_legacy = configured.as_ref().is_some_and(|configured| {
        configured.catalog_root.is_some() || !configured.evidence.is_empty()
    });
    if !explicit_legacy {
        // This is the ordinary MCP path. Bootstrap alone is not a legacy
        // override: it contributes reviewed records to the same catalog and
        // one shared transaction as the ambient/default dependency route.
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
                        return Ok(WorkspacePackActivationState {
                            config: packs_config,
                            activation: None,
                            ecosystems,
                            failure: Some(format!(
                                "failed to open workspace semantic-pack catalog: {error}"
                            )),
                        });
                    }
                },
                None => match open_ambient_semantic_pack_catalog(
                    workspace,
                    workspace_root,
                    CatalogOptions::default(),
                ) {
                    Ok(catalog) => catalog,
                    Err(error) => {
                        return Ok(WorkspacePackActivationState {
                            config: packs_config,
                            activation: None,
                            ecosystems,
                            failure: Some(format!(
                                "failed to open generated semantic-pack catalog: {error}"
                            )),
                        });
                    }
                },
            }
        };
        let mut additional_evidence = Vec::new();
        match bootstrap_semantic_model_catalog(&catalog) {
            Ok(true) => additional_evidence.extend(intrinsic_language_evidence(workspace)),
            Ok(false) => {}
            Err(error) => {
                return Ok(WorkspacePackActivationState {
                    config: packs_config,
                    activation: None,
                    ecosystems,
                    failure: Some(format!(
                        "failed to register the MCP semantic-pack catalog bootstrap: {error}"
                    )),
                });
            }
        }
        let activation = match activate_workspace_semantic_sources_in_catalog(
            workspace,
            &AnalyzerConfig::default(),
            &catalog,
            WorkspaceActivationSources {
                catalog_root: workspace_root,
                workspace_model_root: workspace_models.then_some(workspace_root),
                config: packs_config.as_deref(),
                intrinsic_shipped_models: false,
            },
            &additional_evidence,
            &CancellationToken::default(),
        ) {
            Ok(activation) => activation.map(Arc::new),
            Err(error) => {
                return Ok(WorkspacePackActivationState {
                    config: packs_config,
                    activation: None,
                    ecosystems,
                    failure: Some(format!(
                        "workspace semantic-pack activation failed: {error}"
                    )),
                });
            }
        };
        return Ok(WorkspacePackActivationState {
            config: packs_config,
            activation,
            ecosystems,
            failure: None,
        });
    }
    if packs_config.is_some() {
        let ecosystems = workspace_pack_ecosystems(workspace, packs_config.as_deref());
        return Ok(WorkspacePackActivationState {
            config: packs_config,
            activation: None,
            ecosystems,
            failure: Some(
                "workspace packs document cannot be combined with legacy semantic-pack environment configuration"
                    .to_owned(),
            ),
        });
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
    if bootstrap_semantic_model_catalog(&catalog)? {
        {
            let _scope = profiling::scope("semantic_pack.intrinsic_evidence");
            evidence.extend(intrinsic_language_evidence(workspace));
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
        )
        .map_err(|error| error.to_string())?;
        evidence.extend(registration.evidence);
        registration.models
    } else {
        Vec::new()
    };
    evidence.sort();
    evidence.dedup();
    let request = SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION"))
            .expect("crate version must be valid semver"),
        evidence,
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
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
    match outcome {
        SemanticModelRuntimeOutcome::Ready { active, .. } => {
            // Post-activation proof: a registered model that never reaches the
            // active set is invisible, and an invisible model decides answers
            // by its absence. MCP treats every such case, review gate
            // included, as a hard bind error.
            if let Some(inactive) =
                workspace_semantic_models_not_active(&workspace_models, &active).first()
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
            Ok(WorkspacePackActivationState {
                config: None,
                activation: None,
                ecosystems: Vec::new(),
                failure: None,
            })
        }
        SemanticModelRuntimeOutcome::Incomplete { report, .. } => Err(format!(
            "configured semantic-pack activation was incomplete: {report:?}"
        )),
        SemanticModelRuntimeOutcome::Cancelled(report) => Err(format!(
            "configured semantic-pack activation was cancelled: {report:?}"
        )),
        SemanticModelRuntimeOutcome::Unavailable(report) => Err(format!(
            "configured semantic-pack activation was unavailable: {report:?}"
        )),
    }
}

/// Activate shipped and configured semantic models against an already-built
/// workspace. Batch prewarm tools use this to materialize the same structural
/// snapshots that normal MCP startup needs before an evaluation begins.
pub fn prewarm_configured_semantic_models(
    workspace_root: &Path,
    workspace: &WorkspaceAnalyzer,
) -> Result<(), String> {
    let state = activate_configured_semantic_models(
        workspace_root,
        workspace,
        configured_semantic_models()?,
    )?;
    match state.failure {
        Some(failure) => Err(failure),
        None => Ok(()),
    }
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
        assert!(activation.activation.is_some());

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
        assert!(state.activation.is_some());
        assert!(state.failure.is_none());
    }

    #[test]
    fn workspace_setting_requires_an_explicit_supported_value() {
        assert!(!parse_workspace_semantic_models_setting(None).unwrap());
        assert!(parse_workspace_semantic_models_setting(Some(std::ffi::OsStr::new("on"))).unwrap());
        assert!(
            !parse_workspace_semantic_models_setting(Some(std::ffi::OsStr::new("off"))).unwrap()
        );
        let error =
            parse_workspace_semantic_models_setting(Some(std::ffi::OsStr::new("automatic")))
                .unwrap_err();
        assert!(error.contains(WORKSPACE_SEMANTIC_MODELS_ENV));
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
            .semantic_model_overlay()
            .expect("workspace activation publishes an overlay");
        let first_match = first_overlay.symbols_named("workspace.GeneratedJobMaker");
        assert_eq!(
            first_match.disposition,
            SemanticModelOverlayDisposition::Unique
        );
        let first_symbol = first_match.records[0];
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
            .semantic_model_overlay()
            .expect("repeated workspace activation publishes an overlay");
        let second_symbol = second_overlay
            .symbols_named("workspace.GeneratedJobMaker")
            .records[0];
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
    fn invalid_workspace_pack_stops_activation_with_the_source_path() {
        let (root, analyzer) = workspace("{}");
        let state = activate_configured_semantic_models(
            root.path(),
            &analyzer,
            Some(workspace_configuration()),
        )
        .unwrap();
        let error = state.failure.expect("the failed activation is retained");
        assert!(state.activation.is_none());
        assert!(error.contains("workspace semantic-model discovery failed"));
        assert!(error.contains(".bifrost/semantic-models/job-maker.json"));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchToolsServiceErrorCode {
    InvalidParams,
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
    fn oversized_symbol_source_response_is_rejected_before_rendering() {
        let result = SymbolSourcesResult {
            sources: vec![SourceBlock {
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
    fn partial_symbol_source_response_keeps_completed_sources_and_typed_cancellation() {
        let result = SymbolSourcesResult {
            sources: vec![SourceBlock {
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
            }],
            not_found: Vec::new(),
            ambiguous: Vec::new(),
            ambiguous_paths: Vec::new(),
            too_broad: Vec::new(),
            complete: false,
            incomplete: vec![SymbolSourcesIncomplete {
                target: "slow".to_string(),
                reason: SymbolSourcesIncompleteReason::Cancelled,
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
    /// Whether this run may reuse per-unit results an earlier run published
    /// (`.agents/plans/impact-sliced-diff-base.md`). Absent means yes, which
    /// is the same findings for less work; `false` forces the full evaluation
    /// a caller compares against when diagnosing a difference.
    incremental: Option<bool>,
    /// Opt-in wall-clock stage attribution (#2611). When set, the result
    /// carries a `stage_timings` sibling next to the canonical report; the
    /// report itself stays byte-identical either way.
    #[serde(default)]
    include_stage_timings: bool,
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
    /// Present only when the caller passed `include_stage_timings`, so a
    /// result carrying timings is structurally distinguishable from one that
    /// does not. The canonical `report` never changes shape either way.
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
    near_misses: Option<ExplainPolicyNearMisses>,
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

#[derive(Debug, Clone)]
pub struct SearchToolsServiceError {
    pub code: SearchToolsServiceErrorCode,
    pub message: String,
    pub(crate) retryable_stale_generation: bool,
}

impl SearchToolsServiceError {
    fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            code: SearchToolsServiceErrorCode::InvalidParams,
            message: message.into(),
            retryable_stale_generation: false,
        }
    }

    fn unknown_tool(message: impl Into<String>) -> Self {
        Self {
            code: SearchToolsServiceErrorCode::UnknownTool,
            message: message.into(),
            retryable_stale_generation: false,
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: SearchToolsServiceErrorCode::Internal,
            message: message.into(),
            retryable_stale_generation: false,
        }
    }

    fn deadline_exceeded(message: impl Into<String>) -> Self {
        Self {
            code: SearchToolsServiceErrorCode::DeadlineExceeded,
            message: message.into(),
            retryable_stale_generation: false,
        }
    }

    fn stale_analyzer_generation(message: impl Into<String>) -> Self {
        Self {
            code: SearchToolsServiceErrorCode::Internal,
            message: message.into(),
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

#[derive(Debug, Clone, PartialEq)]
pub enum ToolOutput {
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
    pub fn into_value(self) -> Value {
        match self {
            Self::Text(text) => Value::String(text),
            Self::Structured { structured, .. } => structured,
        }
    }

    pub fn into_python_payload(self) -> Value {
        match self {
            Self::Text(text) => Value::String(text),
            Self::Structured {
                structured,
                rendered_text,
            } => serde_json::to_value(PythonToolPayload {
                structured,
                rendered_text,
            })
            .unwrap_or(Value::Null),
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

fn production_watcher_starter() -> WatcherStarter {
    Arc::new(ProjectChangeWatcher::start_with_claimed_files)
}

pub struct SearchToolsService {
    root: RwLock<Option<PathBuf>>,
    session: RwLock<Option<WorkspaceSession>>,
    workspace_generation: AtomicU64,
    flow_state: crate::flow::FlowWorkspaceState,
    query_protocols: RwLock<crate::rql::ProtocolRegistrationSet>,
    query_value_flows: RwLock<crate::rql::ValueFlowPlanRegistrationSet>,
    query_taint_results: RwLock<crate::rql::TaintResultRegistrationSet>,
    /// A deferred workspace build (file discovery + parse) runs on a background
    /// thread and lands here. The result carries the binding generation and root
    /// so a superseded client workspace can never be published later.
    /// `ensure_ready` joins it and installs the resulting session into `session`
    /// on first access. `None` once the session is ready (or for
    /// synchronously-built services).
    pending_build: Mutex<Option<PendingWorkspaceBuild>>,
    /// Records a deferred-build failure (e.g. the workspace walk hit an IO
    /// error) so every access after the first surfaces it instead of hanging.
    build_error: Mutex<Option<String>>,
    /// Watcher-invalidated cache of the active workspace's file listing
    /// (#1401). `Some` exactly when a `WatchFiles` root is bound; the session
    /// project shares the same handle so every `all_files` consumer and the
    /// session-free `find_filenames` fast path answer from one listing.
    /// Deliberately outside the session lock: reads must not wait behind
    /// watcher-delta re-analysis or the initial index build (#1388).
    file_listing: RwLock<Option<Arc<WorkspaceFileListingCache>>>,
    update_strategy: UpdateStrategy,
    startup_index_warm: StartupIndexWarm,
    watcher_starter: WatcherStarter,
    diff_snapshot_object_dir: Option<PathBuf>,
    /// Whether `query_code` may spend the source-volume-scaled budget policy
    /// evaluation uses instead of the interactive defaults. Host configuration
    /// for a trusted whole-workspace caller, never a tool argument: a query
    /// document must not be able to raise its own limits.
    workspace_scaled_query_limits: bool,
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

struct WorkspaceSession {
    snapshot: Arc<WorkspaceAnalyzer>,
    document_root: Arc<WorkspaceRoot>,
    pack_activation: Option<Arc<WorkspacePackActivationState>>,
    watcher: SessionWatcher,
    usage_index_warm: Option<JoinHandle<()>>,
    index_warmer: Arc<IndexWarmer>,
}

enum SessionWatcher {
    Disabled,
    Active(ProjectChangeWatcher),
}

/// Owns one workspace snapshot and its request-scoped analyzer memoization.
///
/// Returning this from `snapshot_for_query` makes the cleanup obligation part
/// of the type, including for direct callers such as the code-query REPL.
struct WorkspaceQueryScope {
    source_snapshot: Arc<WorkspaceAnalyzer>,
    snapshot: Arc<WorkspaceAnalyzer>,
    document_root: Arc<WorkspaceRoot>,
    pack_activation: Option<Arc<WorkspacePackActivationState>>,
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
        return Ok(ExplainPolicyQuestion::Explanation(
            ExplanationTarget::Candidate(explain_policy_candidate(candidate)?),
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

    let selection = BuiltInPolicySelection {
        packs: params.policy_packs.clone(),
        categories: params.policy_categories.clone(),
        policy_ids: params.policy_ids.clone(),
    };
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
        .map(|policy| PolicyEvaluationInput::embedded(policy.source_identity(), policy.source()))
        .collect::<Vec<_>>();
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
    SearchToolsServiceError::invalid_params(format!("explain_policy could not answer: {error}"))
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

    #[test]
    fn explain_policy_answers_why_not_with_a_structured_explanation() {
        let (_temp, service) = service();
        let value = service
            .call_tool_value(
                "explain_policy",
                json!({
                    "policy_files": ["policies/match.rqlp"],
                    "candidate": { "path": "Widget.java", "byte_start": byte_offset("Widget") }
                }),
            )
            .expect("explain_policy should answer");
        let explanation = &value["explanation"];
        assert_eq!(
            explanation["format"],
            brokk_bifrost_policy::POLICY_EXPLANATION_FORMAT,
            "{value:#}"
        );
        assert_eq!(explanation["question"], "why_not", "{value:#}");
        assert_eq!(explanation["policy_id"], "test.explain.mcp.match");
        assert_eq!(explanation["analysis_type"], "match");
        assert_eq!(explanation["subject"]["type"], "candidate");
        assert_eq!(explanation["subject"]["path"], "Widget.java");
        // The result carries no gate: an explanation is a query.
        assert!(value.get("status").is_none(), "{value:#}");
        assert!(value.get("exit_status").is_none(), "{value:#}");
        // The tree is a tree, and its root states an outcome.
        assert!(explanation["node_count"].as_u64().is_some_and(|n| n >= 1));
        assert!(
            ["satisfied", "failed", "unknown"]
                .contains(&explanation["outcome"].as_str().expect("an outcome")),
            "{value:#}"
        );
        assert!(
            explanation["root"]["id"]
                .as_str()
                .is_some_and(|id| id.len() == 32)
        );
    }

    /// The relational adapter reaches the wire: an assertion policy answers
    /// per row binding, and the node vocabulary the slice added is published.
    #[test]
    fn explain_policy_answers_why_not_for_a_relational_policy() {
        let (_temp, service) = service();
        let value = service
            .call_tool_value(
                "explain_policy",
                json!({
                    "policy_files": ["policies/relational.rqlp"],
                    "candidate": {
                        "path": "Widget.java",
                        "byte_start": byte_offset("return 1"),
                        "byte_end": byte_offset("return 1") + 8
                    }
                }),
            )
            .expect("explain_policy should answer for a relational policy");
        let explanation = &value["explanation"];
        assert_eq!(explanation["analysis_type"], "assertion", "{value:#}");
        assert_eq!(explanation["root"]["label"], "relational_candidate");
        let bindings = explanation["root"]["children"]
            .as_array()
            .expect("the root has children")
            .iter()
            .filter(|node| node["kind"] == "relation_binding")
            .count();
        assert_eq!(bindings, 1, "{value:#}");
    }

    #[test]
    fn explain_policy_requires_exactly_one_question() {
        let (_temp, service) = service();
        let neither = service
            .call_tool_value(
                "explain_policy",
                json!({ "policy_files": ["policies/match.rqlp"] }),
            )
            .expect_err("a request with no question has no answer");
        assert_eq!(neither.code, SearchToolsServiceErrorCode::InvalidParams);
        assert!(
            neither
                .message
                .contains("requires finding_id (why), candidate (why-not), or near_misses"),
            "{}",
            neither.message
        );

        for extra in [
            json!({ "candidate": { "path": "Widget.java", "byte_start": 0 } }),
            json!({ "near_misses": { "enumerate_from_policy_seed": true } }),
        ] {
            let mut arguments = json!({
                "policy_files": ["policies/match.rqlp"],
                "finding_id": "0".repeat(64),
            });
            for (key, value) in extra.as_object().expect("an object") {
                arguments[key] = value.clone();
            }
            let both = service
                .call_tool_value("explain_policy", arguments)
                .expect_err("a request with two questions has two answers");
            assert!(both.message.contains("exactly one of"), "{}", both.message);
        }
    }

    #[test]
    fn explain_policy_explains_exactly_one_policy() {
        let (_temp, service) = service();
        let error = service
            .call_tool_value(
                "explain_policy",
                json!({
                    "policy_files": ["policies/match.rqlp", "policies/relational.rqlp"],
                    "candidate": { "path": "Widget.java", "byte_start": 0 }
                }),
            )
            .expect_err("an explanation is about one policy");
        assert_eq!(error.code, SearchToolsServiceErrorCode::InvalidParams);
        assert!(error.message.contains("resolved to 2"), "{}", error.message);
    }

    /// Issue 2500 on the wire: the seed-scoped search returns the sibling
    /// ranking document, ordered by declared-predicate distance.
    #[test]
    fn explain_policy_ranks_near_misses_from_the_policys_own_seed_scope() {
        let (_temp, service) = service();
        let value = service
            .call_tool_value(
                "explain_policy",
                json!({
                    "policy_files": ["policies/match.rqlp"],
                    "near_misses": { "enumerate_from_policy_seed": true }
                }),
            )
            .expect("explain_policy should rank near misses");
        let ranking = &value["near_miss_ranking"];
        assert_eq!(
            ranking["format"],
            brokk_bifrost_policy::POLICY_NEAR_MISS_FORMAT,
            "{value:#}"
        );
        assert_eq!(ranking["question"], "near_miss", "{value:#}");
        assert_eq!(ranking["policy_id"], "test.explain.mcp.match");
        assert_eq!(ranking["analysis_type"], "match");
        assert_eq!(ranking["conjuncts"], json!(["scope", "root.name"]));
        assert_eq!(ranking["enumeration"]["type"], "policy_seed", "{value:#}");
        // An explanation tree is not what a ranking answers with.
        assert!(value.get("explanation").is_none(), "{value:#}");
        assert!(value.get("status").is_none(), "{value:#}");

        let entries = ranking["entries"].as_array().expect("ranked entries");
        assert_eq!(entries.len(), 2, "{value:#}");
        assert_eq!(entries[0]["rank"], 1);
        assert_eq!(entries[0]["outcome"], "satisfied");
        assert_eq!(entries[0]["unsatisfied_conjuncts"], 0);
        assert_eq!(entries[1]["rank"], 2);
        assert_eq!(entries[1]["outcome"], "failed", "{value:#}");
        assert_eq!(entries[1]["unsatisfied_conjuncts"], 1);
        assert_eq!(entries[1]["failing_conjunct"], "root.name", "{value:#}");
        assert_eq!(entries[1]["subject"]["type"], "candidate");
        assert_eq!(entries[1]["subject"]["path"], "Widget.java");
    }

    /// A supplied list is ranked without any search, and the retention bound
    /// reports what it removed.
    #[test]
    fn explain_policy_ranks_a_supplied_candidate_list_under_its_bounds() {
        let (_temp, service) = service();
        let value = service
            .call_tool_value(
                "explain_policy",
                json!({
                    "policy_files": ["policies/match.rqlp"],
                    "near_misses": {
                        "candidates": [
                            { "path": "Widget.java", "byte_start": byte_offset("class Gadget"),
                              "byte_end": byte_offset("class Gadget") + 12 },
                            { "path": "Widget.java", "byte_start": byte_offset("class Widget"),
                              "byte_end": byte_offset("class Widget") + 12 }
                        ],
                        "max_candidates": 1
                    }
                }),
            )
            .expect("explain_policy should rank a supplied list");
        let ranking = &value["near_miss_ranking"];
        assert_eq!(
            ranking["enumeration"],
            json!({ "type": "supplied", "supplied": 2 })
        );
        assert_eq!(ranking["candidates_considered"], 2, "{value:#}");
        let entries = ranking["entries"].as_array().expect("ranked entries");
        assert_eq!(entries.len(), 1, "{value:#}");
        assert_eq!(entries[0]["unsatisfied_conjuncts"], 0, "{value:#}");
        assert_eq!(ranking["truncation"]["candidates_truncated"], true);
        assert_eq!(ranking["truncation"]["omitted_candidates_lower_bound"], 1);
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

    /// A family with no adapter is a stated condition on the wire, and the
    /// message names the families that do have one.
    #[test]
    fn explain_policy_reports_an_unavailable_adapter_with_the_supported_families() {
        let (_temp, service) = service();
        let error = service
            .call_tool_value(
                "explain_policy",
                json!({
                    "policy_files": ["policies/taint.rqlp"],
                    "candidate": { "path": "Widget.java", "byte_start": 0 }
                }),
            )
            .expect_err("taint has no why-not adapter yet");
        assert_eq!(error.code, SearchToolsServiceErrorCode::InvalidParams);
        assert!(
            error
                .message
                .contains("supported analysis types: match, assertion"),
            "{}",
            error.message
        );
    }

    #[test]
    fn explain_policy_rejects_a_malformed_finding_identity_and_a_bad_path() {
        let (_temp, service) = service();
        let bad_id = service
            .call_tool_value(
                "explain_policy",
                json!({
                    "policy_files": ["policies/match.rqlp"],
                    "finding_id": "not-a-digest"
                }),
            )
            .expect_err("a finding identity is a lowercase sha-256");
        assert_eq!(bad_id.code, SearchToolsServiceErrorCode::InvalidParams);

        let escaping = service
            .call_tool_value(
                "explain_policy",
                json!({
                    "policy_files": ["policies/match.rqlp"],
                    "candidate": { "path": "../outside.java", "byte_start": 0 }
                }),
            )
            .expect_err("a candidate stays inside the workspace");
        assert!(
            escaping.message.contains("not inside the workspace"),
            "{}",
            escaping.message
        );

        let reversed = service
            .call_tool_value(
                "explain_policy",
                json!({
                    "policy_files": ["policies/match.rqlp"],
                    "candidate": { "path": "Widget.java", "byte_start": 9, "byte_end": 4 }
                }),
            )
            .expect_err("a candidate range does not end before it starts");
        assert!(
            reversed.message.contains("exceeds end"),
            "{}",
            reversed.message
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
        pack_activation: Option<Arc<WorkspacePackActivationState>>,
    ) -> Self {
        let context = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        Self::with_context(source_snapshot, document_root, pack_activation, context)
    }

    fn with_context(
        source_snapshot: Arc<WorkspaceAnalyzer>,
        document_root: Arc<WorkspaceRoot>,
        pack_activation: Option<Arc<WorkspacePackActivationState>>,
        context: Arc<crate::analyzer::AnalyzerQueryContext>,
    ) -> Self {
        let snapshot = Arc::new(source_snapshot.as_ref().clone());
        snapshot.begin_query(&context);
        Self {
            source_snapshot,
            snapshot,
            document_root,
            pack_activation,
            context,
        }
    }

    fn arc(&self) -> &Arc<WorkspaceAnalyzer> {
        &self.source_snapshot
    }

    fn scope_snapshot(&self, source_snapshot: Arc<WorkspaceAnalyzer>) -> Self {
        Self::with_context(
            source_snapshot,
            Arc::clone(&self.document_root),
            self.pack_activation.clone(),
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
            Ok(value) => match self.context.store_error() {
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

impl Deref for WorkspaceQueryScope {
    type Target = WorkspaceAnalyzer;

    fn deref(&self) -> &Self::Target {
        self.snapshot.as_ref()
    }
}

impl Drop for WorkspaceQueryScope {
    fn drop(&mut self) {
        self.snapshot.end_query(&self.context);
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
    fn pack_activation_scope_changed(&self) -> bool {
        self.pack_activation.as_ref().is_some_and(|state| {
            workspace_pack_ecosystems(&self.snapshot, state.config.as_deref()) != state.ecosystems
        })
    }

    /// Re-run the shared activation transaction after dependency inputs or the
    /// workspace pack document change. Invalidation happens first so a failed
    /// replacement cannot leave proof from an older workspace generation.
    fn refresh_pack_activation(&mut self) {
        self.snapshot
            .invalidate_dependency_pack_state(&crate::analyzer::DependencyPackEcosystem::ALL);
        let root = self.snapshot.analyzer().project().root();
        self.pack_activation = match configured_semantic_models().and_then(|configured| {
            activate_configured_semantic_models(root, self.snapshot.as_ref(), configured)
        }) {
            Ok(state) => Some(Arc::new(state)),
            Err(error) => {
                eprintln!(
                    "bifrost: workspace semantic-pack activation refresh unavailable: {error}"
                );
                None
            }
        };
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

fn changed_files_invalidate_pack_activation(changed_files: &BTreeSet<ProjectFile>) -> bool {
    changed_files.iter().any(|file| {
        let relative = file.rel_path();
        if relative == Path::new(WORKSPACE_PACKS_DOCUMENT_PATH)
            || relative
                .starts_with(crate::analyzer::semantic_model::WORKSPACE_SEMANTIC_MODEL_DIRECTORY)
        {
            return true;
        }
        let Some(file_name) = relative.file_name().and_then(|name| name.to_str()) else {
            return false;
        };
        crate::analyzer::DependencyPackEcosystem::ALL
            .iter()
            .any(|ecosystem| ecosystem.dependency_inputs().contains(&file_name))
    })
}

impl Drop for WorkspaceSession {
    fn drop(&mut self) {
        // The warmer owns the snapshot while its thread runs. Wait for it
        // before the session drops the project and its SQLite connections.
        self.index_warmer.wait_until_idle();
        let Some(handle) = self.usage_index_warm.take() else {
            return;
        };
        if let Err(panic) = handle.join() {
            eprintln!("bifrost usage-index warm thread panicked: {panic:?}");
        }
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

    let selection = BuiltInPolicySelection {
        packs: params.policy_packs,
        categories: params.policy_categories,
        policy_ids: params.policy_ids,
    };
    let selected = built_in_policy_catalog()
        .map_err(|error| {
            SearchToolsServiceError::internal(format!(
                "failed to load built-in policy catalog: {error}"
            ))
        })?
        .select(&selection)
        .map_err(|error| SearchToolsServiceError::invalid_params(error.to_string()))?;
    let selected_policy_ids = selected
        .iter()
        .map(|policy| {
            PolicyId::new(&policy.manifest().id).expect("built-in policy IDs are validated")
        })
        .collect::<Vec<_>>();
    let mut built_in_inputs = selected
        .into_iter()
        .map(|policy| PolicyEvaluationInput::embedded(policy.source_identity(), policy.source()))
        .collect::<Vec<_>>();
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
            .with_policy_timings(params.include_stage_timings);
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
    Ok(DecodedRunPolicy {
        policy_inputs,
        selected_policy_ids,
        options,
        include_stage_timings: params.include_stage_timings,
    })
}

impl SearchToolsService {
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

    pub fn new(root: PathBuf) -> Result<Self, String> {
        Self::new_with_strategy(root, UpdateStrategy::WatchFiles)
    }

    pub fn new_for_python(root: PathBuf) -> Result<Self, String> {
        Self::new_lazy_with_strategy(root, UpdateStrategy::WatchFiles)
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
        Self::new_ephemeral_with_strategy(root, UpdateStrategy::Manual)
    }

    /// Construct with persisted analyzer storage and no watcher. The caller
    /// publishes changes explicitly through `update_paths`.
    pub fn new_manual_persisted(root: PathBuf) -> Result<Self, String> {
        Self::new_with_strategy(root, UpdateStrategy::Manual)
    }

    /// Whether a tool's answer is a pure function of its Git endpoints and
    /// never reads the live workspace analyzer.
    ///
    /// The diff tools are such tools: each builds its own per-endpoint analyzers
    /// over revision images and is dispatched before `snapshot_for_query` is
    /// ever consulted, so booting a persisted whole-repo workspace to serve one
    /// is pure waste. `score_diff` derives from the same endpoint analyzers and
    /// adds one over the whole target revision, so it reads the live workspace
    /// no more than its siblings do.
    ///
    /// Independent means "does not read the live workspace", not "writes
    /// nothing". An immutable endpoint's revision image publishes the blobs it
    /// parses into the repository's shared content-addressed analyzer cache,
    /// which is the point: the next consumer of those blobs, revision or
    /// worktree, reads them instead of parsing them. What the image does not
    /// leave behind is any workspace projection row naming its temporary export
    /// directory; a request-scoped lease removes those when the request ends.
    pub fn tool_is_workspace_independent(name: &str) -> bool {
        matches!(
            name,
            "analyze_diff"
                | "blast_radius"
                | "cyclomatic_complexity"
                | "missing_tests"
                | "score_diff"
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
        Self::new_one_shot_workspace_independent_with_watcher_starter(
            root,
            production_watcher_starter(),
        )
    }

    fn new_one_shot_workspace_independent_with_watcher_starter(
        root: PathBuf,
        watcher_starter: WatcherStarter,
    ) -> Result<Self, String> {
        let canonical = canonical_service_root(root)?;
        let file_listing = Some(Arc::new(WorkspaceFileListingCache::new(canonical.clone())));
        Ok(Self::lazy(
            canonical,
            file_listing,
            UpdateStrategy::Manual,
            watcher_starter,
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
    /// Two callers legitimately want it. One-shot audit drivers (the MCP
    /// property fuzzer) get two things at once: absent an explicit catalog or
    /// cache override, nothing is written into the target checkout, which
    /// matters when the operator does not own it, and
    /// because every file is parsed fresh, session-only evidence such as
    /// tree-sitter ERROR nodes (`IAnalyzer::parse_errors`) is available for the
    /// whole workspace rather than only for the blobs that missed the cache.
    /// Scoped sessions ([`crate::scoped_project`]) want it because their partial
    /// file set must not become the workspace's persisted picture of itself.
    pub fn new_manual_ephemeral_footgun_for_project(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, String> {
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(Arc::clone(&project), config)
            .map_err(|error| format!("Failed to build ephemeral workspace: {error}"))?;
        Self::new_manual_from_workspace(project, workspace)
    }

    /// Persisted-cache sibling of [`Self::new_manual_ephemeral_footgun_for_project`]
    /// for warmed, resumable campaigns. Session-only evidence (tree-sitter
    /// ERROR nodes) is unavailable for files served from the warm cache.
    pub fn new_manual_persisted_for_project(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, String> {
        let workspace =
            WorkspaceAnalyzer::build_persisted_without_automatic_gc(Arc::clone(&project), config)
                .map_err(|error| format!("Failed to build persisted workspace: {error}"))?;
        Self::new_manual_from_workspace(project, workspace)
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
        let workspace = WorkspaceAnalyzer::build_persisted_without_automatic_gc_with_progress(
            Arc::clone(&project),
            config,
            progress,
        )
        .map_err(|error| format!("Failed to build persisted workspace: {error}"))?;
        Self::new_manual_from_workspace(project, workspace)
    }

    fn new_manual_from_workspace(
        project: Arc<dyn Project>,
        workspace: WorkspaceAnalyzer,
    ) -> Result<Self, String> {
        let root = project.root().to_path_buf();
        let watcher_starter = production_watcher_starter();
        let session = assemble_session(
            project,
            workspace,
            UpdateStrategy::Manual,
            StartupIndexWarm::OnDemand,
            &watcher_starter,
        )?;
        Ok(Self {
            root: RwLock::new(Some(root)),
            session: RwLock::new(Some(session)),
            workspace_generation: AtomicU64::new(1),
            flow_state: crate::flow::FlowWorkspaceState::new(),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(None),
            update_strategy: UpdateStrategy::Manual,
            startup_index_warm: StartupIndexWarm::OnDemand,
            watcher_starter,
            diff_snapshot_object_dir: None,
            workspace_scaled_query_limits: false,
        })
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

    /// Evaluate a policy batch against this service's immutable workspace
    /// snapshot. Scoped one-shot CLI runs use this seam so their partial
    /// `FileSetProject` is the only analyzer constructed.
    pub fn evaluate_policy_inputs(
        &self,
        root: &Path,
        policy_inputs: &[PolicyEvaluationInput],
        options: &PolicyEvaluationOptions,
    ) -> Result<PolicyBatchOutcome, String> {
        loop {
            let generation = self.workspace_generation();
            let snapshot = self
                .snapshot_for_query_with_cancellation(None)
                .map_err(|error| error.to_string())?;
            if generation != self.workspace_generation() {
                continue;
            }
            let result = {
                let runtime = CodeIntelligenceRuntime::new(&snapshot, &self.flow_state, None);
                let runtime = match snapshot.pack_activation.as_deref() {
                    Some(state) => {
                        runtime.with_host_activation_context(PolicyHostActivationContext::new(
                            state.config.as_deref(),
                            state.activation.as_deref(),
                            &state.ecosystems,
                            state.failure.as_deref(),
                        ))
                    }
                    None => runtime,
                };
                runtime
                    .evaluate_policy_inputs(root, policy_inputs, options)
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
        let outcome = self.evaluate_policy_inputs(root, policy_inputs, options)?;
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
        let workspace_generation = {
            let session = self.read_session()?;
            session.as_ref().ok_or_else(Self::closed_error)?;
            self.workspace_generation()
        };
        let registration = crate::rql::TaintResultRegistration::new(workspace_generation, results)
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
        let result = self
            .call_tool_output(name, arguments, RenderOptions::default())?
            .into_value();
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
            TransportTimings {
                transport_queue_wait,
                ..TransportTimings::default()
            },
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
        let retry_arguments = arguments.clone();
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
            "update_paths" => return self.handle_update_paths(arguments),
            "activate_workspace" => return self.handle_activate_workspace(arguments),
            "get_active_workspace" => return self.handle_get_active_workspace(arguments),
            _ => {}
        }

        if name == "analyze_diff" {
            let params = serde_json::from_value::<AnalyzeDiffParams>(arguments).map_err(|err| {
                SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
            })?;
            let root = self.service_root()?;
            return Self::structured_only(
                analyze_diff_at_root(
                    &root,
                    params,
                    &DiffAnalysisOptions {
                        snapshot_object_dir: self.diff_snapshot_object_dir.clone(),
                    },
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
            let result = cyclomatic_complexity_at_root(
                &root,
                params,
                &DiffAnalysisOptions {
                    snapshot_object_dir: self.diff_snapshot_object_dir.clone(),
                },
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
            return Self::structured_only(
                score_diff_at_root(
                    &root,
                    params,
                    &DiffAnalysisOptions {
                        snapshot_object_dir: self.diff_snapshot_object_dir.clone(),
                    },
                    // The whole-target-revision reference scan is the long pole
                    // of this tool, so it runs under the caller's token rather
                    // than a fresh one: a client that cancelled the tool call
                    // must be able to stop the scan.
                    cancellation.unwrap_or(&uncancelled),
                )
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

        let arguments =
            self.normalize_arguments_for_current_workspace(name, arguments, cancellation)?;
        if name == "get_symbol_sources" {
            return self.handle_get_symbol_sources(
                strip_legacy_kind_filter(arguments),
                render_options,
                cancellation,
            );
        }
        let snapshot = {
            let _scope = profiling::scope("SearchToolsService::snapshot_for_query");
            // Deadline-aware: a request whose budget expires while the deferred
            // initial build is still running gets an explicit retry error within
            // its budget, instead of blocking through the whole build and then
            // reporting a misleading zero-result "cancelled/partial" payload
            // (#1199).
            self.snapshot_for_query_with_cancellation(cancellation)?
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
                strip_legacy_kind_filter(arguments),
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
                strip_legacy_kind_filter(arguments),
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
            "classify_test_files" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    classify_test_files(workspace.analyzer(), params)
                })
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
                    get_definitions_by_reference(workspace.analyzer(), params)
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
                |workspace, params| usage_graph(workspace.analyzer(), params),
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
            "report_secret_like_code" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    report_secret_like_code(workspace.analyzer(), params)
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
        snapshot.finish(name, result)
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
            let root = snapshot.analyzer().project().root();
            let arguments =
                crate::tool_arguments::normalize_tool_arguments("query_code", arguments, root)
                    .map_err(SearchToolsServiceError::invalid_params)?;
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
            TransportTimings {
                transport_queue_wait,
                ..TransportTimings::default()
            },
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
            let rendering_started = Instant::now();
            let rendered_text = output.render_text();
            let rendering_ns = duration_ns(rendering_started.elapsed());
            let serialization_ns = if matches!(&output, crate::rql::CodeQueryResponse::Profile(_)) {
                let serialization_started = Instant::now();
                serde_json::to_value(&output).map_err(|err| {
                    SearchToolsServiceError::internal(format!(
                        "Failed to serialize tool result: {err}"
                    ))
                })?;
                duration_ns(serialization_started.elapsed())
            } else {
                0
            };
            Self::attach_query_code_request_timing(
                &mut output,
                request_timing,
                execution_timing,
                rendering_ns.saturating_add(serialization_ns),
                transport_timings,
            );
            let structured = serde_json::to_value(&output).map_err(|err| {
                SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
            })?;
            Ok(ToolOutput::Structured {
                structured,
                rendered_text: Some(rendered_text),
            })
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
        let input_decode_started = Instant::now();
        let query = Self::decode_query_code_input(snapshot, arguments)?;
        let input_decode_ns = duration_ns(input_decode_started.elapsed());
        let query_execution_started = Instant::now();
        let response = CodeIntelligenceRuntime::new(snapshot, &self.flow_state, cancellation)
            .execute_query_with_all_analysis_registrations(
                workspace_generation,
                query_protocols,
                query_value_flows,
                query_taint_results,
                &query,
                self.query_execution_limits(snapshot),
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
        snapshot: &WorkspaceQueryScope,
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
        snapshot: &WorkspaceQueryScope,
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
            snapshot.document_root(),
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
        self.root.read().map(|root| root.clone()).unwrap_or(None)
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
    fn new_with_strategy(root: PathBuf, update_strategy: UpdateStrategy) -> Result<Self, String> {
        Self::new_with_strategy_and_watcher_starter(
            root,
            update_strategy,
            production_watcher_starter(),
        )
    }

    /// A one-shot `--tool` process: build the workspace, answer one call, exit.
    ///
    /// No file watcher. Nothing in the process consumes a watch event before it
    /// exits, and installing one is not free: `start_watcher` cost 0.37-0.40 s
    /// of wall clock on the rustc tree, and its deliberate
    /// `invalidate_cached_file_listing` then forced a **second** whole-workspace
    /// walk (0.45 s) inside the tool call's own budget, because the listing the
    /// build had just filled was dropped
    /// (`.agents/docs/gate-cell-overhead-2026-08.md`).
    ///
    /// The listing cache stays, which is the part that is not about watching: a
    /// process that exits cannot observe a change it would need to invalidate
    /// for, so one walk serves every consumer. `Manual` is the honest strategy
    /// here for the same reason the scoped one-shot constructors already use it
    /// -- nothing updates this workspace after construction.
    pub fn new_one_shot(root: PathBuf) -> Result<Self, String> {
        Self::new_one_shot_with_watcher_starter(root, production_watcher_starter())
    }

    fn new_one_shot_with_watcher_starter(
        root: PathBuf,
        watcher_starter: WatcherStarter,
    ) -> Result<Self, String> {
        let canonical = canonical_service_root(root)?;
        let file_listing = Some(Arc::new(WorkspaceFileListingCache::new(canonical.clone())));
        Self::new_synchronous(
            canonical,
            file_listing,
            UpdateStrategy::Manual,
            watcher_starter,
        )
    }

    fn new_with_strategy_and_watcher_starter(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        watcher_starter: WatcherStarter,
    ) -> Result<Self, String> {
        let canonical = canonical_service_root(root)?;
        let file_listing = listing_cache_for(update_strategy, &canonical);
        Self::new_synchronous(canonical, file_listing, update_strategy, watcher_starter)
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
    ) -> Result<Self, String> {
        let (project, workspace) =
            build_persisted_workspace(canonical, file_listing.clone(), update_strategy)?;
        let root = project.root().to_path_buf();
        let session = assemble_session(
            project,
            workspace,
            update_strategy,
            StartupIndexWarm::OnDemand,
            &watcher_starter,
        )?;
        Ok(Self {
            root: RwLock::new(Some(root)),
            session: RwLock::new(Some(session)),
            workspace_generation: AtomicU64::new(1),
            flow_state: crate::flow::FlowWorkspaceState::new(),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(file_listing),
            update_strategy,
            startup_index_warm: StartupIndexWarm::OnDemand,
            watcher_starter,
            diff_snapshot_object_dir: None,
            workspace_scaled_query_limits: false,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    fn new_ephemeral_with_strategy(
        root: PathBuf,
        update_strategy: UpdateStrategy,
    ) -> Result<Self, String> {
        Self::new_ephemeral_with_strategy_and_watcher_starter(
            root,
            update_strategy,
            production_watcher_starter(),
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    fn new_ephemeral_with_strategy_and_watcher_starter(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        watcher_starter: WatcherStarter,
    ) -> Result<Self, String> {
        let canonical = canonical_service_root(root)?;
        let file_listing = listing_cache_for(update_strategy, &canonical);
        let (project, workspace) = build_ephemeral_workspace(canonical, file_listing.clone())?;
        let root = project.root().to_path_buf();
        let session = assemble_session(
            project,
            workspace,
            update_strategy,
            StartupIndexWarm::OnDemand,
            &watcher_starter,
        )?;
        Ok(Self {
            root: RwLock::new(Some(root)),
            session: RwLock::new(Some(session)),
            workspace_generation: AtomicU64::new(1),
            flow_state: crate::flow::FlowWorkspaceState::new(),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(file_listing),
            update_strategy,
            startup_index_warm: StartupIndexWarm::OnDemand,
            watcher_starter,
            diff_snapshot_object_dir: None,
            workspace_scaled_query_limits: false,
        })
    }

    fn new_lazy_with_strategy(
        root: PathBuf,
        update_strategy: UpdateStrategy,
    ) -> Result<Self, String> {
        Self::new_lazy_with_strategy_and_watcher_starter(
            root,
            update_strategy,
            production_watcher_starter(),
        )
    }

    fn new_lazy_with_strategy_and_watcher_starter(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        watcher_starter: WatcherStarter,
    ) -> Result<Self, String> {
        let canonical = canonical_service_root(root)?;
        let file_listing = listing_cache_for(update_strategy, &canonical);
        Ok(Self::lazy(
            canonical,
            file_listing,
            update_strategy,
            watcher_starter,
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
    ) -> Self {
        Self {
            root: RwLock::new(Some(canonical)),
            session: RwLock::new(None),
            workspace_generation: AtomicU64::new(1),
            flow_state: crate::flow::FlowWorkspaceState::new(),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(file_listing),
            update_strategy,
            startup_index_warm: StartupIndexWarm::OnDemand,
            watcher_starter,
            diff_snapshot_object_dir: None,
            workspace_scaled_query_limits: false,
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
        Self::new_deferred_with_watcher_starter(root, production_watcher_starter())
    }

    /// Construct a deferred, persisted service for an immutable workspace.
    /// Queries never poll a file watcher; callers must use `refresh` when they
    /// intentionally change the workspace after construction.
    pub fn new_deferred_manual(root: PathBuf) -> Result<Self, String> {
        Self::new_deferred_with_strategy_and_watcher_starter(
            root,
            UpdateStrategy::Manual,
            production_watcher_starter(),
        )
    }

    /// Construct an MCP service that has not yet been bound to a client-approved
    /// workspace root. Analyzer-backed tools return an actionable error until a
    /// later roots response or negotiated host metadata installs a workspace.
    pub fn new_unbound() -> Self {
        Self::new_unbound_with_strategy(UpdateStrategy::WatchFiles)
    }

    /// Construct an unbound MCP service whose eventual client-selected
    /// workspace is updated only by explicit refresh requests.
    pub fn new_unbound_manual() -> Self {
        Self::new_unbound_with_strategy(UpdateStrategy::Manual)
    }

    fn new_unbound_with_strategy(update_strategy: UpdateStrategy) -> Self {
        Self {
            root: RwLock::new(None),
            session: RwLock::new(None),
            workspace_generation: AtomicU64::new(0),
            flow_state: crate::flow::FlowWorkspaceState::new(),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(None),
            update_strategy,
            startup_index_warm: StartupIndexWarm::AtStartup,
            watcher_starter: production_watcher_starter(),
            diff_snapshot_object_dir: None,
            workspace_scaled_query_limits: false,
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
        let _scope = profiling::scope("mcp_cold.workspace_binding");
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

        if self.active_workspace_root().as_ref() == Some(&canonical) {
            return Ok(canonical);
        }

        let generation = self.workspace_generation().wrapping_add(1);
        let build_root = canonical.clone();
        let update_strategy = self.update_strategy;
        let startup_index_warm = self.startup_index_warm;
        let watcher_starter = Arc::clone(&self.watcher_starter);
        // Created before the deferred build so listing-backed fast paths can
        // fill it while indexing is pending; installed below alongside `root`.
        let file_listing = listing_cache_for(update_strategy, &canonical);
        let build_file_listing = file_listing.clone();
        let handle = std::thread::Builder::new()
            .name("bifrost-index-build".to_string())
            .spawn(
                move || -> Result<(u64, PathBuf, WorkspaceSession), String> {
                    // Cache resolution is the same one every other entry point
                    // uses (`gitblob::cache_db_path`): a linked worktree shares
                    // the primary checkout's oid-keyed database, so a client
                    // bind neither copies nor forks it (issue #1544).
                    let (project, workspace) = build_persisted_workspace(
                        build_root.clone(),
                        build_file_listing,
                        update_strategy,
                    )?;
                    let session = assemble_session(
                        project,
                        workspace,
                        update_strategy,
                        startup_index_warm,
                        &watcher_starter,
                    )?;
                    Ok((generation, build_root, session))
                },
            )
            .map_err(|error| {
                SearchToolsServiceError::internal(format!(
                    "Failed to start client workspace build for {}: {error}",
                    canonical.display()
                ))
            })?;

        let mut pending = self
            .pending_build
            .lock()
            .map_err(|_| SearchToolsServiceError::internal("index build lock poisoned"))?;
        let mut session = self
            .session
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?;
        let mut active_root = self
            .root
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?;
        self.advance_workspace_generation();
        debug_assert_eq!(self.workspace_generation(), generation);
        let old_pending = pending.replace(handle);
        let old_session = session.take();
        *active_root = Some(canonical.clone());
        *self
            .file_listing
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))? =
            file_listing;
        *self
            .build_error
            .lock()
            .map_err(|_| SearchToolsServiceError::internal("index build lock poisoned"))? = None;
        drop(active_root);
        drop(session);
        drop(pending);
        drop(old_pending);
        drop(old_session);
        Ok(canonical)
    }

    /// Remove a workspace previously supplied through MCP roots or negotiated
    /// host metadata, so revoked scope never remains queryable.
    pub fn unbind_client_workspace(&self) -> Result<(), SearchToolsServiceError> {
        let mut pending = self
            .pending_build
            .lock()
            .map_err(|_| SearchToolsServiceError::internal("index build lock poisoned"))?;
        let mut session = self
            .session
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?;
        let mut active_root = self
            .root
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?;
        let was_bound = session.is_some() || active_root.is_some();
        if was_bound {
            self.advance_workspace_generation();
        }
        let old_pending = pending.take();
        let old_session = session.take();
        active_root.take();
        self.file_listing
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?
            .take();
        drop(active_root);
        drop(session);
        drop(pending);
        drop(old_pending);
        drop(old_session);
        Ok(())
    }

    fn new_deferred_with_watcher_starter(
        root: PathBuf,
        watcher_starter: WatcherStarter,
    ) -> Result<Self, String> {
        Self::new_deferred_with_strategy_and_watcher_starter(
            root,
            UpdateStrategy::WatchFiles,
            watcher_starter,
        )
    }

    fn new_deferred_with_strategy_and_watcher_starter(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        watcher_starter: WatcherStarter,
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
        match brokk_bifrost_analysis::relevance::spawn_commit_history_warm(canonical.clone()) {
            // Detached deliberately: nothing in the service ever joins the warm, and the
            // thread reports its own failures.
            Ok(_warm) => {}
            Err(error) => {
                eprintln!("Failed to spawn commit-history warm thread: {error}");
            }
        }
        let handle = std::thread::Builder::new()
            .name("bifrost-index-build".to_string())
            .spawn({
                let canonical = canonical.clone();
                let watcher_starter = Arc::clone(&watcher_starter);
                let file_listing = file_listing.clone();
                move || -> Result<(u64, PathBuf, WorkspaceSession), String> {
                    let _scope = profiling::scope("mcp_cold.analyzer_construction");
                    let project = build_project(canonical.clone(), file_listing)?;
                    let workspace = build_persisted_analyzer(
                        Arc::clone(&project),
                        AnalyzerConfig::default(),
                        update_strategy,
                    )
                    .map_err(|error| format!("Failed to build persisted workspace: {error}"))?;
                    let session = assemble_session(
                        project,
                        workspace,
                        update_strategy,
                        StartupIndexWarm::AtStartup,
                        &watcher_starter,
                    )?;
                    Ok((1, canonical, session))
                }
            })
            .map_err(|err| format!("Failed to spawn index build thread: {err}"))?;
        Ok(Self {
            root: RwLock::new(Some(canonical)),
            session: RwLock::new(None),
            workspace_generation: AtomicU64::new(1),
            flow_state: crate::flow::FlowWorkspaceState::new(),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            pending_build: Mutex::new(Some(handle)),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(file_listing),
            update_strategy,
            startup_index_warm: StartupIndexWarm::AtStartup,
            watcher_starter,
            diff_snapshot_object_dir: None,
            workspace_scaled_query_limits: false,
        })
    }

    /// Block until the deferred initial build (if any) has completed and its
    /// session is installed. A no-op for synchronously-built services and after
    /// the first call. Safe under concurrency: the first caller joins the build
    /// and installs the session while holding `pending_build`; later callers
    /// wait on that mutex and then observe the installed session.
    fn ensure_ready(&self) -> Result<(), SearchToolsServiceError> {
        let mut pending = self
            .pending_build
            .lock()
            .map_err(|_| SearchToolsServiceError::internal("index build lock poisoned"))?;
        if let Some(handle) = pending.take() {
            let built = handle
                .join()
                .map_err(|_| SearchToolsServiceError::internal("index build thread panicked"))?;
            match built {
                Ok((generation, root, session)) => {
                    if generation != self.workspace_generation()
                        || self.active_workspace_root().as_ref() != Some(&root)
                    {
                        return Err(SearchToolsServiceError::internal(
                            "workspace changed while its analyzer snapshot was initializing; retry the request",
                        ));
                    }
                    let mut guard = self.session.write().map_err(|_| {
                        SearchToolsServiceError::internal("SearchToolsService lock poisoned")
                    })?;
                    *guard = Some(session);
                }
                Err(err) => {
                    *self.build_error.lock().map_err(|_| {
                        SearchToolsServiceError::internal("index build lock poisoned")
                    })? = Some(err.clone());
                    return Err(SearchToolsServiceError::internal(err));
                }
            }
        }
        if let Some(err) = self
            .build_error
            .lock()
            .map_err(|_| SearchToolsServiceError::internal("index build lock poisoned"))?
            .clone()
        {
            return Err(SearchToolsServiceError::internal(err));
        }
        if self
            .session
            .read()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?
            .is_none()
        {
            let root = self.service_root()?;
            let file_listing = self
                .file_listing
                .read()
                .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?
                .clone();
            let built = build_persisted_workspace(root, file_listing, self.update_strategy)
                .and_then(|(project, workspace)| {
                    assemble_session(
                        project,
                        workspace,
                        self.update_strategy,
                        self.startup_index_warm,
                        &self.watcher_starter,
                    )
                });
            let session = match built {
                Ok(session) => session,
                Err(err) => {
                    *self.build_error.lock().map_err(|_| {
                        SearchToolsServiceError::internal("index build lock poisoned")
                    })? = Some(err.clone());
                    return Err(SearchToolsServiceError::internal(err));
                }
            };
            let mut guard = self.session.write().map_err(|_| {
                SearchToolsServiceError::internal("SearchToolsService lock poisoned")
            })?;
            if guard.is_none() {
                *guard = Some(session);
            }
        }
        drop(pending);
        Ok(())
    }

    /// Block until any pending background workspace build finishes, honoring
    /// only explicit cancellation -- never a request deadline. MCP hosts call
    /// this before starting a request's budget clock so that one-time session
    /// initialization (the deferred index build after binding a workspace) is
    /// not billed to whichever tool calls happen to arrive first. Issues #1423
    /// and #1419: a cold first batch against a large workspace exhausted every
    /// request budget on index-build wait and returned nothing useful.
    ///
    /// This does not run the build itself; `ensure_ready` still joins the
    /// finished handle and installs the session, which is cheap once the build
    /// thread is done.
    pub fn wait_workspace_ready(
        &self,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), SearchToolsServiceError> {
        self.wait_workspace_ready_until(cancelled, None)
    }

    pub fn workspace_build_pending(&self) -> bool {
        match self.pending_build.try_lock() {
            Ok(pending) => pending.as_ref().is_some_and(|handle| !handle.is_finished()),
            Err(std::sync::TryLockError::WouldBlock) => true,
            Err(std::sync::TryLockError::Poisoned(_)) => true,
        }
    }

    pub fn wait_workspace_ready_until(
        &self,
        cancelled: &dyn Fn() -> bool,
        deadline: Option<Instant>,
    ) -> Result<(), SearchToolsServiceError> {
        let _scope = profiling::scope("mcp_cold.workspace_readiness_wait");
        loop {
            let build_is_pending = match self.pending_build.try_lock() {
                Ok(pending) => pending.as_ref().is_some_and(|handle| !handle.is_finished()),
                Err(std::sync::TryLockError::WouldBlock) => true,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(SearchToolsServiceError::internal(
                        "index build lock poisoned",
                    ));
                }
            };
            if !build_is_pending {
                return Ok(());
            }
            if cancelled() {
                return Err(SearchToolsServiceError::internal(
                    "the tool call was cancelled while waiting for the workspace snapshot",
                ));
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(SearchToolsServiceError::deadline_exceeded(
                    WORKSPACE_SNAPSHOT_NOT_READY_MESSAGE,
                ));
            }
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }

    fn ensure_ready_with_cancellation(
        &self,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), SearchToolsServiceError> {
        let Some(cancellation) = cancellation else {
            return self.ensure_ready();
        };

        loop {
            let build_is_pending = match self.pending_build.try_lock() {
                Ok(pending) => pending.as_ref().is_some_and(|handle| !handle.is_finished()),
                Err(std::sync::TryLockError::WouldBlock) => true,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(SearchToolsServiceError::internal(
                        "index build lock poisoned",
                    ));
                }
            };

            if !build_is_pending {
                return self.ensure_ready();
            }
            if cancellation.is_cancelled() {
                if cancellation.is_timed_out() {
                    return Err(SearchToolsServiceError::deadline_exceeded(
                        WORKSPACE_SNAPSHOT_NOT_READY_MESSAGE,
                    ));
                }
                return Err(SearchToolsServiceError::internal(
                    "workspace snapshot acquisition was cancelled",
                ));
            }
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }

    pub fn close(&self) -> Result<(), SearchToolsServiceError> {
        let mut guard = self.write_session()?;
        let session = guard.take();
        if session.is_some() {
            self.advance_workspace_generation();
        }
        drop(guard);
        drop(session);
        Ok(())
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
        let root = self.service_root()?;
        let file_listing = self
            .file_listing
            .read()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?
            .clone();
        if let Some(file_listing) = &file_listing {
            file_listing.invalidate();
        }
        let mut session_guard = self.write_session()?;
        if self.workspace_generation() != expected_workspace_generation {
            return Ok(());
        }
        session_guard.as_ref().ok_or_else(Self::closed_error)?;
        let (project, workspace) =
            build_persisted_workspace(root, file_listing, self.update_strategy).map_err(
                |error| {
                    SearchToolsServiceError::internal(format!(
                        "Failed to reload workspace after stale analyzer generation: {error}"
                    ))
                },
            )?;
        let new_session = assemble_session(
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
        self.advance_workspace_generation();
        let old_session = session_guard
            .replace(new_session)
            .ok_or_else(Self::closed_error)?;
        drop(session_guard);
        drop(old_session);
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
        let next = session.snapshot.update_all();
        session.snapshot = Arc::new(next);
        session.refresh_pack_activation();
        session.schedule_index_warm();
        Self::structured_only(refresh_result(session.snapshot.analyzer()))
    }

    /// Incrementally re-analyze exactly the given project-relative paths, reusing the
    /// existing analysis for every other file. Unlike `refresh` (which rebuilds the
    /// whole project), this is O(changed files) and is how a caller that knows what
    /// changed (e.g. between two checked-out revisions) drives updates cheaply.
    fn handle_update_paths(&self, arguments: Value) -> Result<ToolOutput, SearchToolsServiceError> {
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
        if !changed.is_empty() {
            let mut refresh_packs = changed_files_invalidate_pack_activation(&changed);
            // The caller is telling us these paths changed on disk; created or
            // deleted files must show up in listing-backed tools, so any
            // cached workspace listing is stale.
            session
                .snapshot
                .analyzer()
                .project()
                .invalidate_cached_file_listing();
            let next = session.snapshot.update(&changed);
            session.snapshot = Arc::new(next);
            refresh_packs |= session.pack_activation_scope_changed();
            if refresh_packs {
                session.refresh_pack_activation();
            }
            session.schedule_index_warm();
        }
        Self::structured_only(refresh_result(session.snapshot.analyzer()))
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

        let mut guard = self.write_session()?;
        let session = guard.as_mut().ok_or_else(Self::closed_error)?;

        if resolved == session.snapshot.analyzer().project().root() {
            let usage_index_ready = session.usage_index_ready();
            let session_subset = session_subset(session.snapshot.analyzer());
            return active_workspace_result(&resolved, usage_index_ready, session_subset);
        }

        // Fully assemble the replacement before mutating either active field so
        // analyzer-store or watcher startup failure leaves the old session usable.
        let new_file_listing = listing_cache_for(self.update_strategy, &resolved);
        let (new_project, new_workspace) = build_persisted_workspace(
            resolved.clone(),
            new_file_listing.clone(),
            self.update_strategy,
        )
        .map_err(|err| {
            SearchToolsServiceError::internal(format!(
                "Failed to activate workspace {}: {err}",
                resolved.display()
            ))
        })?;
        let new_session = assemble_session(
            new_project,
            new_workspace,
            self.update_strategy,
            self.startup_index_warm,
            &self.watcher_starter,
        )
        .map_err(|err| {
            SearchToolsServiceError::internal(format!(
                "Failed to activate workspace {}: {err}",
                resolved.display()
            ))
        })?;
        let mut root = self
            .root
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?;
        self.advance_workspace_generation();
        let old_session = std::mem::replace(session, new_session);
        session.schedule_index_warm();
        let usage_index_ready = session.usage_index_ready();
        let session_subset = session_subset(session.snapshot.analyzer());
        *root = Some(resolved.clone());
        *self
            .file_listing
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))? =
            new_file_listing;
        drop(guard);
        drop(root);
        drop(old_session);

        // The replacement session's background index warm has only just
        // started, so this reports the newly activated workspace's readiness,
        // not the closed one's.
        active_workspace_result(&resolved, usage_index_ready, session_subset)
    }

    fn handle_get_active_workspace(
        &self,
        arguments: Value,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let _params =
            serde_json::from_value::<GetActiveWorkspaceParams>(arguments).map_err(|err| {
                SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
            })?;
        let guard = self.read_session()?;
        let session = guard.as_ref().ok_or_else(Self::closed_error)?;
        active_workspace_result(
            session.snapshot.analyzer().project().root(),
            session.usage_index_ready(),
            session_subset(session.snapshot.analyzer()),
        )
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
    fn snapshot_for_query(&self) -> Result<WorkspaceQueryScope, SearchToolsServiceError> {
        // Manual sessions never mutate the snapshot from this path (no
        // watcher, no implicit updates driven by this call), so a read lock
        // always suffices — never take the write lock at all.
        if self.update_strategy == UpdateStrategy::Manual {
            let guard = self.read_session()?;
            let session = guard.as_ref().ok_or_else(Self::closed_error)?;
            return Ok(WorkspaceQueryScope::new(
                Arc::clone(&session.snapshot),
                Arc::clone(&session.document_root),
                session.pack_activation.clone(),
            ));
        }

        {
            let guard = self.read_session()?;
            let session = guard.as_ref().ok_or_else(Self::closed_error)?;
            if !Self::session_watcher_has_pending(session) {
                return Ok(WorkspaceQueryScope::new(
                    Arc::clone(&session.snapshot),
                    Arc::clone(&session.document_root),
                    session.pack_activation.clone(),
                ));
            }
        }

        // Only reached for `WatchFiles` sessions with a pending delta.
        let mut guard = self.write_session()?;
        let session = guard.as_mut().ok_or_else(Self::closed_error)?;
        Self::apply_watcher_delta(session);
        Ok(WorkspaceQueryScope::new(
            Arc::clone(&session.snapshot),
            Arc::clone(&session.document_root),
            session.pack_activation.clone(),
        ))
    }

    fn snapshot_for_query_with_cancellation(
        &self,
        cancellation: Option<&CancellationToken>,
    ) -> Result<WorkspaceQueryScope, SearchToolsServiceError> {
        self.ensure_ready_with_cancellation(cancellation)?;
        self.snapshot_for_query()
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
            initial_snapshot.analyzer(),
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
                symbol_source_candidate_files(initial_snapshot.analyzer(), &result);

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
                Arc::clone(initial_snapshot.arc())
            } else {
                let mut guard = self.write_session()?;
                let session = guard.as_mut().ok_or_else(Self::closed_error)?;
                Self::apply_watcher_delta(session);
                // Re-validate under the write lock: another thread may have
                // applied a watcher delta between the read-locked peek above
                // and now, which can make a file the peek considered stale
                // fresh again (or vice versa), so recompute against the
                // now-current session snapshot rather than trusting the peek.
                let analyzer = session.snapshot.analyzer();
                let stale_files = stale_symbol_source_files(analyzer, stale_files)?;
                Self::apply_changed_files(session, stale_files);
                Arc::clone(&session.snapshot)
            };

            if !Arc::ptr_eq(initial_snapshot.arc(), &final_snapshot) {
                let final_snapshot = initial_snapshot.scope_snapshot(final_snapshot);
                result = get_symbol_sources_with_source_budget(
                    final_snapshot.analyzer(),
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
        exceeded: brokk_bifrost_analysis::searchtools::SymbolSourcesBudgetExceeded,
    ) -> SearchToolsServiceError {
        SearchToolsServiceError::invalid_params(format!(
            "get_symbol_sources exceeded the {}-byte response budget while resolving source; re-call with fewer or narrower symbols",
            exceeded.max_source_bytes()
        ))
    }

    fn apply_watcher_delta(session: &mut WorkspaceSession) {
        let _scope = profiling::scope("SearchToolsService::apply_watcher_delta");
        let watcher = match &session.watcher {
            SessionWatcher::Disabled => return,
            SessionWatcher::Active(watcher) => watcher,
        };

        let delta = {
            let _scope = profiling::scope("SearchToolsService::take_changed_files");
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
                session.snapshot.update_all()
            });
            session.refresh_pack_activation();
            session.schedule_index_warm();
            return;
        }

        if delta.files.is_empty() {
            return;
        }

        let changed_files: BTreeSet<ProjectFile> = delta.files.into_iter().collect();
        Self::apply_changed_files(session, changed_files);
    }

    fn apply_changed_files(session: &mut WorkspaceSession, changed_files: BTreeSet<ProjectFile>) {
        if changed_files.is_empty() {
            return;
        }
        if profiling::enabled() {
            profiling::note(format!("snapshot_changed_files={}", changed_files.len()));
        }
        let mut refresh_packs = changed_files_invalidate_pack_activation(&changed_files);
        session.snapshot = Arc::new({
            let _scope = profiling::scope("SearchToolsService::snapshot_update");
            session.snapshot.update(&changed_files)
        });
        refresh_packs |= session.pack_activation_scope_changed();
        if refresh_packs {
            session.refresh_pack_activation();
        }
        session.schedule_index_warm();
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
        let params = serde_json::from_value::<P>(arguments).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
        })?;
        let result = handler(workspace, params);
        match serde_json::to_value(result).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })? {
            Value::String(text) => Ok(ToolOutput::Text(text)),
            structured => Ok(ToolOutput::Structured {
                structured,
                rendered_text: None,
            }),
        }
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
        let params = serde_json::from_value::<P>(arguments).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
        })?;
        let result = handler(workspace, params);
        let rendered_text = result.render_text(render_options);
        let structured = serde_json::to_value(result).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })?;
        Ok(ToolOutput::Structured {
            structured,
            rendered_text: Some(rendered_text),
        })
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
        let params = serde_json::from_value::<P>(arguments).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
        })?;
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

    pub(crate) fn preflight_run_policy(
        &self,
        arguments: &Value,
    ) -> Result<RunPolicyPreflight, SearchToolsServiceError> {
        let selection_started = Instant::now();
        let decoded = decode_run_policy_arguments(arguments.clone())?;
        let selection_elapsed = selection_started.elapsed();
        let preflight_started = Instant::now();
        let root = self.service_root()?;
        let preflight = crate::policy::preflight_policy_suppressions(&root, &decoded.options)
            .map_err(|error| {
                SearchToolsServiceError::internal(format!(
                    "run_policy suppression preflight failed: {error}"
                ))
            })?;
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
            policy_inputs,
            selected_policy_ids,
            options,
            include_stage_timings,
        } = decoded;
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
                    let root = self.service_root()?;
                    let preflight = crate::policy::preflight_policy_suppressions(&root, &options)
                        .map_err(|error| {
                        SearchToolsServiceError::internal(format!(
                            "run_policy suppression preflight failed: {error}"
                        ))
                    })?;
                    (
                        preflight,
                        decode_selection_elapsed,
                        preflight_started.elapsed(),
                    )
                }
            };
        if suppression_preflight.is_valid() {
            let preparation = RunPolicySnapshotPreparation {
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
            let root = snapshot.analyzer().project().root().to_path_buf();
            return Ok(RunPolicyPreparation::Ready(Box::new(PreparedRunPolicy {
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
            let root = snapshot.analyzer().project().root().to_path_buf();
            let result = (|| {
                let _scope = profiling::scope("explain_policy.explain_policy_inputs");
                let answer = match &question {
                    ExplainPolicyQuestion::Explanation(target) => {
                        ExplainPolicyToolResult::Explanation {
                            explanation: Box::new(
                                explain_policy_inputs(
                                    &root,
                                    &policy_inputs,
                                    target,
                                    Some(&snapshot),
                                    Some(&self.flow_state),
                                    cancellation,
                                    &ExplanationLimits::default(),
                                )
                                .map_err(explain_error_to_service_error)?,
                            ),
                        }
                    }
                    ExplainPolicyQuestion::NearMiss(candidates, limits) => {
                        ExplainPolicyToolResult::NearMiss {
                            near_miss_ranking: Box::new(
                                rank_policy_near_misses(
                                    &root,
                                    &policy_inputs,
                                    candidates,
                                    Some(&snapshot),
                                    Some(&self.flow_state),
                                    cancellation,
                                    limits,
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
        let result = (|| {
            let _scope = profiling::scope("run_policy.evaluate_policy_inputs");
            let runtime = CodeIntelligenceRuntime::new(&snapshot, &self.flow_state, cancellation);
            let runtime = match snapshot.pack_activation.as_deref() {
                Some(state) => {
                    runtime.with_host_activation_context(PolicyHostActivationContext::new(
                        state.config.as_deref(),
                        state.activation.as_deref(),
                        &state.ecosystems,
                        state.failure.as_deref(),
                    ))
                }
                None => runtime,
            };
            let mut outcome = match suppression_preflight {
                Some(preflight) => runtime.evaluate_policy_inputs_with_suppression_preflight(
                    &root,
                    &policy_inputs,
                    &options,
                    preflight,
                ),
                None => runtime.evaluate_policy_inputs(&root, &policy_inputs, &options),
            }
            .map_err(|error| {
                SearchToolsServiceError::internal(format!("run_policy evaluation failed: {error}"))
            })?;
            outcome.record_preparation_timings(
                selection_elapsed,
                suppression_preflight_elapsed,
                snapshot_elapsed,
            );
            let exit_status = outcome.exit_status();
            let status = match exit_status {
                POLICY_EXIT_CLEAN => "clean",
                POLICY_EXIT_FINDING => "finding",
                POLICY_EXIT_UNRELIABLE => "unreliable",
                _ => {
                    return Err(SearchToolsServiceError::internal(format!(
                        "run_policy returned unknown status {exit_status}"
                    )));
                }
            };
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
        let structured = serde_json::to_value(result).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })?;
        Ok(ToolOutput::Structured {
            structured,
            rendered_text: None,
        })
    }

    fn rendered_structured<R: Serialize + RenderText>(
        result: R,
        render_options: RenderOptions,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let rendered_text = result.render_text(render_options);
        let structured = serde_json::to_value(result).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })?;
        Ok(ToolOutput::Structured {
            structured,
            rendered_text: Some(rendered_text),
        })
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
        let guard = self
            .session
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(session) = guard.as_ref() {
            session.schedule_index_warm();
        }
    }

    fn service_root(&self) -> Result<PathBuf, SearchToolsServiceError> {
        self.root
            .read()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?
            .clone()
            .ok_or_else(Self::unbound_error)
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
        self.session
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))
    }

    fn closed_error() -> SearchToolsServiceError {
        SearchToolsServiceError::internal("SearchToolsService is closed")
    }

    fn unbound_error() -> SearchToolsServiceError {
        SearchToolsServiceError::internal(
            "Bifrost is not bound to a workspace. The MCP client must provide an approved filesystem root via roots/list, or configure Bifrost with --root or BIFROST_WORKSPACE_ROOT.",
        )
    }
}

impl Drop for SearchToolsService {
    fn drop(&mut self) {
        // If a deferred build is still in flight, join it rather than detach it.
        if let Ok(pending) = self.pending_build.get_mut()
            && let Some(handle) = pending.take()
            && let Ok(Ok((_, _, _session))) = handle.join()
        {
            return;
        }
        let Ok(session) = self.session.get_mut() else {
            return;
        };
        session.take();
    }
}

fn strip_legacy_kind_filter(mut arguments: Value) -> Value {
    if let Some(object) = arguments.as_object_mut() {
        object.remove("kind_filter");
    }
    arguments
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

fn build_persisted_workspace(
    root: PathBuf,
    listing: Option<Arc<WorkspaceFileListingCache>>,
    update_strategy: UpdateStrategy,
) -> Result<(Arc<dyn Project>, WorkspaceAnalyzer), String> {
    let _scope = profiling::scope("mcp_cold.analyzer_construction");
    let cache_path = crate::gitblob::cache_db_path(&root);
    crate::cache_db::validate_writable_cache_filesystem(&cache_path)
        .map_err(|error| format!("Failed to initialize persistent cache: {error}"))?;
    let project = build_project(root, listing)?;
    let workspace = build_persisted_analyzer(
        Arc::clone(&project),
        AnalyzerConfig::default(),
        update_strategy,
    )
    .map_err(|error| format!("Failed to build persisted workspace: {error}"))?;
    Ok((project, workspace))
}

fn build_persisted_analyzer(
    project: Arc<dyn Project>,
    config: AnalyzerConfig,
    update_strategy: UpdateStrategy,
) -> Result<WorkspaceAnalyzer, crate::analyzer::store::StoreError> {
    match update_strategy {
        UpdateStrategy::WatchFiles => WorkspaceAnalyzer::build_persisted(project, config),
        UpdateStrategy::Manual => {
            WorkspaceAnalyzer::build_persisted_without_automatic_gc(project, config)
        }
    }
}

/// Test-only, with [`SearchToolsService::new_manual_ephemeral`]: the only chain
/// that reaches it is gated the same way.
#[cfg(any(test, feature = "test-support"))]
fn build_ephemeral_workspace(
    root: PathBuf,
    listing: Option<Arc<WorkspaceFileListingCache>>,
) -> Result<(Arc<dyn Project>, WorkspaceAnalyzer), String> {
    let project = build_project(root, listing)?;
    let workspace =
        WorkspaceAnalyzer::build_ephemeral_footgun(Arc::clone(&project), AnalyzerConfig::default())
            .map_err(|error| format!("Failed to build ephemeral workspace: {error}"))?;
    Ok((project, workspace))
}

/// Assemble a ready `WorkspaceSession` from a built project + analyzer: wrap the
/// analyzer in an `Arc`, start the file watcher (per `update_strategy`), and
/// create the session state. Shared by synchronous and deferred constructors.
fn assemble_session(
    project: Arc<dyn Project>,
    workspace: WorkspaceAnalyzer,
    update_strategy: UpdateStrategy,
    startup_index_warm: StartupIndexWarm,
    watcher_starter: &WatcherStarter,
) -> Result<WorkspaceSession, String> {
    let pack_activation = match activate_configured_semantic_models(
        project.root(),
        &workspace,
        configured_semantic_models()?,
    ) {
        Ok(state) => Some(Arc::new(state)),
        Err(error) => {
            eprintln!("bifrost: workspace semantic-pack activation unavailable: {error}");
            None
        }
    };
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
    let snapshot = Arc::new(workspace);
    // Pre-build the lazy per-language usage indexes off the request path (issue
    // #1416): warmed here in the background, the first `scan_usages` call no
    // longer pays whole-workspace index construction inside its wall-clock
    // budget. The PoolSafeMemo backing the index keeps a failed build
    // unpublished, so any panic here resurfaces on the first query that needs it.
    //
    // Opt-out, because the warm is a whole-workspace fan-out and a session that
    // will never ask a usage question should not pay for it: a large C++
    // workspace with a vendored Rust tree paid the Rust build for work it never
    // queried (d8920a38). `StartupIndexWarm::OnDemand` leaves the build to the
    // first query that needs it, which is the same build under the same memo.
    let usage_index_warm = if startup_index_warm == StartupIndexWarm::AtStartup {
        let snapshot = Arc::clone(&snapshot);
        Some(
            std::thread::Builder::new()
                .name("bifrost-usage-index-warm".to_string())
                .spawn(move || {
                    let _scope = profiling::scope("mcp_cold.query_index_construction.rust_usage");
                    snapshot.warm_usage_analysis();
                })
                .map_err(|error| format!("Failed to spawn usage-index warm thread: {error}"))?,
        )
    } else {
        None
    };
    Ok(WorkspaceSession {
        snapshot,
        document_root,
        pack_activation,
        watcher,
        usage_index_warm,
        index_warmer: IndexWarmer::new(),
    })
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
            Ok(SessionWatcher::Active(watcher))
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
    root: &Path,
    usage_index_ready: bool,
    session_subset: Option<SubsetCoverage>,
) -> Result<ToolOutput, SearchToolsServiceError> {
    let structured = serde_json::to_value(ActiveWorkspaceResult {
        workspace_path: root.display().to_string(),
        usage_index_ready,
        session_subset,
    })
    .map_err(|err| {
        SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
    })?;
    Ok(ToolOutput::Structured {
        structured,
        rendered_text: None,
    })
}

#[cfg(test)]
mod watcher_startup_tests {
    use super::*;
    use crate::path_normalization::NormalizePath;
    use serde_json::json;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    const WATCHER_FAILURE: &str = "injected watcher startup failure";

    fn workspace(file: &str, source: &str) -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join(file), source).unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        (temp, root)
    }

    fn failing_starter(calls: Arc<AtomicUsize>) -> WatcherStarter {
        Arc::new(move |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(WATCHER_FAILURE.to_string())
        })
    }

    fn unbound_watching_service(starter: WatcherStarter) -> SearchToolsService {
        SearchToolsService {
            root: RwLock::new(None),
            session: RwLock::new(None),
            workspace_generation: AtomicU64::new(0),
            flow_state: crate::flow::FlowWorkspaceState::new(),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(None),
            update_strategy: UpdateStrategy::WatchFiles,
            startup_index_warm: StartupIndexWarm::AtStartup,
            watcher_starter: starter,
            diff_snapshot_object_dir: None,
            workspace_scaled_query_limits: false,
        }
    }

    fn assert_watcher_error(error: &SearchToolsServiceError) {
        assert_eq!(error.code, SearchToolsServiceErrorCode::Internal);
        assert!(error.message.contains("Failed to start project watcher"));
        assert!(error.message.contains(WATCHER_FAILURE));
    }

    /// A one-shot `--tool` process installs no watcher and walks the workspace
    /// exactly once.
    ///
    /// Both halves were measured on the rustc tree
    /// (`.agents/docs/gate-cell-overhead-2026-08.md`): `start_watcher` cost
    /// 0.37-0.40 s of wall clock outside the tool's budget, and the
    /// `invalidate_cached_file_listing` it performs to close its own event-
    /// coverage gap threw away the listing the build had just filled, so the
    /// next consumer re-walked the whole tree (0.45 s) *inside* the budget.
    /// Neither buys a process that exits anything: nothing consumes a watch
    /// event before exit.
    #[test]
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

        let service = SearchToolsService::new_one_shot_with_watcher_starter(root, starter).unwrap();

        assert_eq!(
            0,
            calls.load(Ordering::SeqCst),
            "a one-shot process must not install a file watcher"
        );
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

        let listing = service
            .file_listing
            .read()
            .unwrap()
            .clone()
            .expect("a one-shot service shares one listing cache");
        assert_eq!(
            1,
            listing.walk_count(),
            "the workspace must be walked once for the whole process"
        );
    }

    /// A workspace-independent one-shot tool is lazy, but "lazy" is not "never
    /// built": a worktree endpoint forces the build after all, and every
    /// ignore probe inside it then re-walked the whole tree. On Godot one
    /// claim round's `claim.bifrostignore_probe[124 files]` span cost 9.3
    /// seconds in 129 walks. The walk count is the observable form of that
    /// defect, so it is what this pins.
    #[test]
    fn a_workspace_independent_one_shot_service_walks_the_workspace_once() {
        let (_temp, root) = workspace("Independent.java", "class Independent {}\n");
        let calls = Arc::new(AtomicUsize::new(0));

        let service = SearchToolsService::new_one_shot_workspace_independent_with_watcher_starter(
            root,
            failing_starter(Arc::clone(&calls)),
        )
        .unwrap();
        assert!(
            service.session.read().unwrap().is_none(),
            "the workspace-independent service must not build a session eagerly"
        );

        // A worktree endpoint forces the lazy build; `get_active_workspace` is
        // the cheapest thing that does.
        service
            .call_tool_value("get_active_workspace", json!({}))
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
                project.is_bifrostignored(Path::new("Independent.java"));
            }
        }

        assert_eq!(
            0,
            calls.load(Ordering::SeqCst),
            "a one-shot process must not install a file watcher"
        );
        let listing = service
            .file_listing
            .read()
            .unwrap()
            .clone()
            .expect("a one-shot workspace-independent service shares one listing cache");
        assert_eq!(
            1,
            listing.walk_count(),
            "the workspace must be walked once for the whole process"
        );
    }

    /// The other side of the distinction above: a long-lived `Manual` service
    /// (the stdio server under `BIFROST_MCP_FILE_WATCHER=off`) has no watcher
    /// to invalidate a listing cache, so it must not carry one -- a stale
    /// listing there is user-visible across requests.
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn a_long_lived_manual_service_carries_no_listing_cache() {
        let (_temp, root) = workspace("Manual.java", "class Manual {}\n");
        let service = SearchToolsService::new_deferred_manual(root).unwrap();
        assert!(
            service.file_listing.read().unwrap().is_none(),
            "a long-lived manual service must keep re-walking; it cannot invalidate a cache"
        );
    }

    #[test]
    fn eager_watching_service_reports_watcher_startup_failure() {
        let (_temp, root) = workspace("Eager.java", "class Eager {}\n");
        let calls = Arc::new(AtomicUsize::new(0));

        let error = match SearchToolsService::new_with_strategy_and_watcher_starter(
            root,
            UpdateStrategy::WatchFiles,
            failing_starter(Arc::clone(&calls)),
        ) {
            Ok(_) => panic!("watching service unexpectedly ignored watcher failure"),
            Err(error) => error,
        };

        assert!(error.contains("Failed to start project watcher"));
        assert!(error.contains(WATCHER_FAILURE));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn lazy_watching_service_retains_watcher_startup_failure() {
        let (_temp, root) = workspace("Lazy.java", "class Lazy {}\n");
        let calls = Arc::new(AtomicUsize::new(0));
        let service = SearchToolsService::new_lazy_with_strategy_and_watcher_starter(
            root,
            UpdateStrategy::WatchFiles,
            failing_starter(Arc::clone(&calls)),
        )
        .unwrap();

        for _ in 0..2 {
            let error = service
                .call_tool_value("get_active_workspace", json!({}))
                .unwrap_err();
            assert_watcher_error(&error);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
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
            assert!(handle.join().unwrap().is_ok());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn deferred_watching_service_retains_watcher_startup_failure() {
        let (_temp, root) = workspace("Deferred.java", "class Deferred {}\n");
        let calls = Arc::new(AtomicUsize::new(0));
        let service = SearchToolsService::new_deferred_with_watcher_starter(
            root,
            failing_starter(Arc::clone(&calls)),
        )
        .unwrap();

        for _ in 0..2 {
            let error = service
                .call_tool_value("get_active_workspace", json!({}))
                .unwrap_err();
            assert_watcher_error(&error);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
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
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match service.pending_build.try_lock() {
                Ok(pending) => {
                    drop(pending);
                    assert!(
                        Instant::now() < deadline,
                        "query should wait for the deferred workspace build"
                    );
                    std::thread::yield_now();
                }
                Err(std::sync::TryLockError::WouldBlock) => break,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    panic!("pending workspace build lock poisoned")
                }
            }
        }
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
        let ToolOutput::Structured { structured, .. } = output else {
            panic!("query_code should return structured output");
        };
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
        let ToolOutput::Structured { structured, .. } = output else {
            panic!("query_code should return structured output");
        };
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
            .map(|policy| {
                PolicyEvaluationInput::embedded(policy.source_identity(), policy.source())
            })
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
                .recv_timeout(Duration::from_secs(5))
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
        assert_eq!(result.report.schema_version(), 5);
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
                .recv_timeout(Duration::from_secs(5))
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
        assert_eq!(result.report.schema_version(), 5);
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
                .recv_timeout(Duration::from_secs(5))
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
                    .recv_timeout(Duration::from_secs(5))
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
    fn issue_1296_registration_deadline_includes_preparation_timings() {
        let (_temp, root) = workspace("Policy.java", "class Policy {}\n");
        let service = SearchToolsService::new_manual_ephemeral(root).expect("manual service");
        let cancellation = CancellationToken::default().with_timeout(Duration::ZERO);

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
        assert_eq!(structured["report"]["schema_version"], 5);
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
                release_first_rx
                    .lock()
                    .expect("release lock")
                    .recv_timeout(Duration::from_secs(5))
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
            .recv_timeout(Duration::from_secs(5))
            .expect("superseded workspace build should finish");
        assert_eq!(service.active_workspace_root(), Some(second_root));
    }

    #[test]
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

    #[test]
    fn deferred_build_resolves_before_optional_query_indexes_are_warm() {
        let (_temp, root) = workspace(
            "lib.rs",
            "trait Runnable {}\npub struct Worker;\nimpl Runnable for Worker {}\n",
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let service = SearchToolsService::new_deferred_with_strategy_and_watcher_starter(
            root,
            UpdateStrategy::Manual,
            failing_starter(Arc::clone(&calls)),
        )
        .unwrap();

        // A complete base snapshot is ready for ordinary code-intelligence
        // queries before the optional Rust hierarchy and usage accelerators
        // are warm (#1448). Join the finished build directly so the background
        // warmer cannot race this assertion.
        service.wait_workspace_ready(&|| false).unwrap();
        let handle = service
            .pending_build
            .lock()
            .unwrap()
            .take()
            .expect("deferred build should remain pending installation");
        let (_, _, session) = handle.join().unwrap().unwrap();

        assert!(!session.snapshot.query_indexes_warm());
    }

    #[test]
    fn deferred_build_defers_background_query_index_warm_until_first_tool_call() {
        let (_temp, root) = workspace(
            "lib.rs",
            "trait Runnable {}\npub struct Worker;\nimpl Runnable for Worker {}\n",
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let service = SearchToolsService::new_deferred_with_strategy_and_watcher_starter(
            root,
            UpdateStrategy::Manual,
            failing_starter(Arc::clone(&calls)),
        )
        .unwrap();

        service.wait_workspace_ready(&|| false).unwrap();
        service.ensure_ready().unwrap();

        let (snapshot, warmer) = {
            let guard = service.session.read().unwrap();
            let session = guard.as_ref().unwrap();
            (
                Arc::clone(&session.snapshot),
                Arc::clone(&session.index_warmer),
            )
        };
        assert!(!snapshot.query_indexes_warm());

        service
            .call_tool_value("get_active_workspace", json!({}))
            .unwrap();
        warmer.wait_until_idle();
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

    /// The other half of the trigger: a synchronously constructed service is a
    /// one-shot invocation or an embedded host, which can exit seconds later.
    /// It must not spend startup on Rust usage work it may never query
    /// (#1758, d8920a38), so the build stays lazy and no warm thread is
    /// started at all. Such a session is ready by construction: with nothing
    /// outstanding there is nothing for a caller to wait for.
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
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
    fn deferred_manual_service_does_not_invoke_watcher_starter() {
        let (_temp, root) = workspace("DeferredManual.java", "class DeferredManual {}\n");
        let calls = Arc::new(AtomicUsize::new(0));
        let service = SearchToolsService::new_deferred_with_strategy_and_watcher_starter(
            root,
            UpdateStrategy::Manual,
            failing_starter(Arc::clone(&calls)),
        )
        .unwrap();

        service
            .call_tool_value("get_active_workspace", json!({}))
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn manual_service_does_not_invoke_watcher_starter() {
        let (_temp, root) = workspace("Manual.java", "class Manual {}\n");
        let calls = Arc::new(AtomicUsize::new(0));
        let service = SearchToolsService::new_ephemeral_with_strategy_and_watcher_starter(
            root.clone(),
            UpdateStrategy::Manual,
            failing_starter(Arc::clone(&calls)),
        )
        .unwrap();

        let active = service
            .call_tool_value("get_active_workspace", json!({}))
            .unwrap();
        assert_eq!(active["workspace_path"], root.display().to_string());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn watcher_failure_during_activation_preserves_old_workspace() {
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
        )
        .unwrap();

        let error = service
            .call_tool_value(
                "activate_workspace",
                json!({"workspace_path": new_root.display().to_string()}),
            )
            .unwrap_err();
        assert_watcher_error(&error);
        assert_eq!(service.active_workspace_root(), Some(old_root.clone()));

        let active = service
            .call_tool_value("get_active_workspace", json!({}))
            .unwrap();
        assert_eq!(active["workspace_path"], old_root.display().to_string());
        let symbols = service
            .call_tool_value("list_symbols", json!({"file_patterns": ["Old.java"]}))
            .unwrap();
        assert_eq!(symbols["files"][0]["path"], "Old.java");
    }

    /// Git bookkeeping is outside the analyzed source set and must not replace
    /// the session snapshot used by subsequent queries.
    #[test]
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
    fn overlapping_query_scopes_do_not_share_store_failures() {
        let (_temp, root, service) = multi_language_service();

        let failing_scope = service.snapshot_for_query().unwrap();
        let unaffected_scope = service.snapshot_for_query().unwrap();

        make_java_store_stale(&root);

        let definitions: Vec<_> = failing_scope.analyzer().definitions("Model").collect();
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
        let (_project, workspace) = build_ephemeral_workspace(root.clone(), None).unwrap();
        let document_root =
            Arc::new(WorkspaceRoot::open(workspace.analyzer().project().root()).unwrap());
        let scope = WorkspaceQueryScope::new(Arc::new(workspace), document_root, None);

        let service = SearchToolsService::new_manual_ephemeral(root).unwrap();
        let interactive = service.query_execution_limits(&scope);
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
            .query_execution_limits(&scope);
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
        assert!(trusted.semantic.max_traversal_steps >= defaults.semantic.max_traversal_steps);
        for dimension in CodeQuerySemanticRowLimits::ROW_DIMENSIONS {
            assert!(
                trusted.semantic.rows(dimension) >= defaults.semantic.rows(dimension),
                "opting in narrowed {dimension:?}"
            );
        }
    }

    #[test]
    fn query_finish_preserves_handler_error_over_recorded_store_failure() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("Model.java"), "class Model {}\n").unwrap();
        let (_project, workspace) = build_ephemeral_workspace(root, None).unwrap();
        let document_root =
            Arc::new(WorkspaceRoot::open(workspace.analyzer().project().root()).unwrap());
        let scope = WorkspaceQueryScope::new(Arc::new(workspace), document_root, None);
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
}

#[cfg(test)]
mod source_generation_tests {
    use super::*;
    use serde_json::Value;
    use std::fs;

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
        let (project, workspace) = build_ephemeral_workspace(root, None).unwrap();
        SearchToolsService {
            root: RwLock::new(Some(project.root().to_path_buf())),
            session: RwLock::new(Some(WorkspaceSession {
                snapshot: Arc::new(workspace),
                document_root: Arc::new(WorkspaceRoot::open(project.root()).unwrap()),
                pack_activation: None,
                watcher: SessionWatcher::Disabled,
                usage_index_warm: None,
                index_warmer: IndexWarmer::new(),
            })),
            workspace_generation: AtomicU64::new(1),
            flow_state: crate::flow::FlowWorkspaceState::new(),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(None),
            update_strategy: UpdateStrategy::WatchFiles,
            startup_index_warm: StartupIndexWarm::OnDemand,
            watcher_starter: production_watcher_starter(),
            diff_snapshot_object_dir: None,
            workspace_scaled_query_limits: false,
        }
    }

    fn call_sources(service: &SearchToolsService, symbols: &[&str]) -> Value {
        let arguments = serde_json::json!({ "symbols": symbols });
        let payload = service
            .call_tool_json("get_symbol_sources", &arguments.to_string())
            .unwrap();
        serde_json::from_str(&payload).unwrap()
    }

    fn source_texts(value: &Value) -> Vec<&str> {
        value["sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|source| source["text"].as_str().unwrap())
            .collect()
    }

    #[test]
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
    fn candidate_files_are_rechecked_after_the_source_changes() {
        let (_temp, root) = write_project();
        let (_project, workspace) = build_ephemeral_workspace(root.clone(), None).unwrap();
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
    fn stale_analyzer_and_manual_service_keep_generation_consistent_source() {
        let (_temp, root) = write_project();
        let (project, workspace) = build_ephemeral_workspace(root.clone(), None).unwrap();
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
    use git2::{IndexAddOption, Repository, Signature};
    use serde_json::json;

    fn commit_all(repo: &Repository) {
        let mut index = repo.index().unwrap();
        index
            .add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
            .unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let signature = Signature::now("Bifrost Test", "test@example.com").unwrap();
        repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
            .unwrap();
    }

    fn unbound_manual_service() -> SearchToolsService {
        SearchToolsService {
            root: RwLock::new(None),
            session: RwLock::new(None),
            workspace_generation: AtomicU64::new(0),
            flow_state: crate::flow::FlowWorkspaceState::new(),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(None),
            update_strategy: UpdateStrategy::Manual,
            startup_index_warm: StartupIndexWarm::AtStartup,
            watcher_starter: production_watcher_starter(),
            diff_snapshot_object_dir: None,
            workspace_scaled_query_limits: false,
        }
    }

    fn cache_db_for(root: &Path) -> PathBuf {
        root.join(crate::gitblob::PROJECT_DIR_NAME)
            .join(crate::gitblob::CACHE_SUBDIR_NAME)
            .join(crate::cache_db::cache_db_file_name())
    }

    fn committed_workspace(file: &str, source: &str) -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo = Repository::init(&root).unwrap();
        std::fs::write(root.join(file), source).unwrap();
        commit_all(&repo);
        (temp, root)
    }

    fn make_cache_gc_due(root: &Path) -> PathBuf {
        let store = crate::analyzer::store::AnalyzerStore::open_for_workspace(root).unwrap();
        let db_path = store.db_path().unwrap().to_path_buf();
        drop(store);
        crate::cache_gc::set_accounting_for_test(&db_path, 0, 0).unwrap();
        db_path
    }

    fn gc_accounting(db_path: &Path) -> (i64, i64) {
        let connection = rusqlite::Connection::open(db_path).unwrap();
        connection
            .query_row(
                "SELECT last_gc_at, blobs_at_last_gc FROM cache_state WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn manual_persisted_sessions_leave_gc_for_explicit_maintenance() {
        let (_source_temp, source_root) = committed_workspace("Source.java", "class Source {}\n");
        let source_db = make_cache_gc_due(&source_root);
        let service = SearchToolsService::new_manual_persisted(source_root.clone()).unwrap();
        assert_eq!(gc_accounting(&source_db), (0, 0));

        std::fs::write(
            source_root.join("Source.java"),
            "class Source { int value; }\n",
        )
        .unwrap();
        service.call_tool_value("refresh", json!({})).unwrap();
        assert_eq!(gc_accounting(&source_db), (0, 0));

        let (_target_temp, target_root) = committed_workspace("Target.java", "class Target {}\n");
        let target_db = make_cache_gc_due(&target_root);
        service
            .call_tool_value(
                "activate_workspace",
                json!({"workspace_path": target_root.display().to_string()}),
            )
            .unwrap();
        service.close().unwrap();

        assert_eq!(gc_accounting(&source_db), (0, 0));
        assert_eq!(gc_accounting(&target_db), (0, 0));
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn watched_persisted_sessions_still_run_automatic_gc() {
        let (_temp, root) = committed_workspace("Watched.java", "class Watched {}\n");
        let db_path = make_cache_gc_due(&root);

        let service = SearchToolsService::new(root).unwrap();
        service.close().unwrap();

        let (last_gc_at, blobs_at_last_gc) = gc_accounting(&db_path);
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

        let (last_gc_at, blobs_at_last_gc) = gc_accounting(&db_path);
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

    /// A client-bound linked worktree resolves its cache the way every other
    /// entry point does: to the primary checkout's database, co-located with
    /// the git object database the analyzer must already read (issue #1544).
    #[test]
    fn client_bound_linked_worktree_uses_the_primary_cache() {
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
    fn client_bound_non_git_root_keeps_a_local_cache_path() {
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
    fn nested_client_root_uses_the_repository_primary_cache() {
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
    fn shared_primary_cache_does_not_leak_primary_only_symbols() {
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
        let (_primary_project, primary_workspace) =
            build_persisted_workspace(canonical_primary.clone(), None, UpdateStrategy::Manual)
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
    fn issue_1199_service_forwards_cancellation_to_search_symbols() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("lib.rs"),
            "pub fn semantic_diagnostics() {}\n",
        )
        .unwrap();
        let service = SearchToolsService::new_manual_ephemeral(temp.path().to_path_buf()).unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();

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
    fn issue_1304_service_forwards_cancellation_to_most_relevant_files() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("lib.rs"), "pub fn target() {}\n").unwrap();
        let service = SearchToolsService::new_manual_ephemeral(temp.path().to_path_buf()).unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();

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
    fn issue_1304_cancelled_graph_returns_explicit_history_import_fallback() {
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
        let cancellation = CancellationToken::cancel_after_checks_for_test(4);

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
            ToolOutput::Text(text) => panic!("expected structured fallback, got {text}"),
        };

        assert_eq!(result["complete"], false, "{result:#}");
        assert_eq!(result["ranking_mode_used"], "history_imports", "{result:#}");
        assert_eq!(result["incomplete_reason"], "cancelled", "{result:#}");
        assert!(
            rendered.contains("returned deterministic history/import ranking instead"),
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
    fn issue_1228_service_forwards_cancellation_to_scan_usages_by_reference() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("lib.rs"), "pub fn target() {}\n").unwrap();
        let service = SearchToolsService::new_manual_ephemeral(temp.path().to_path_buf()).unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let result = service
            .call_tool_output_with_cancellation(
                "scan_usages_by_reference",
                json!({
                    "symbols": ["target", "other"],
                    "include_tests": true
                }),
                RenderOptions::default(),
                Some(&cancellation),
            )
            .unwrap()
            .into_value();

        assert_cancelled_scan_result(&result, "symbol", 2);
    }

    #[test]
    fn issue_1228_service_forwards_cancellation_to_scan_usages_by_location() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("lib.rs"), "pub fn target() {}\n").unwrap();
        let service = SearchToolsService::new_manual_ephemeral(temp.path().to_path_buf()).unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let result = service
            .call_tool_output_with_cancellation(
                "scan_usages_by_location",
                json!({
                    "targets": [{"path": "lib.rs", "line": 1}],
                    "include_tests": true
                }),
                RenderOptions::default(),
                Some(&cancellation),
            )
            .unwrap()
            .into_value();

        assert_cancelled_scan_result(&result, "target", 1);
    }

    #[test]
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
        assert!(
            prepared_value.get("diagnostics").is_none(),
            "prepared request should retain the registered alias: {prepared_value}"
        );

        let current = service.query_code_result(query(&protocol_ref)).unwrap();
        assert_eq!(
            current.result().unwrap().diagnostics[0].code,
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
        assert!(
            prepared_value.get("diagnostics").is_none(),
            "prepared requests own their generation-consistent registration snapshot"
        );

        let current = service.query_code_result(query(&protocol_ref)).unwrap();
        assert_eq!(
            current.result().unwrap().diagnostics[0].code,
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
