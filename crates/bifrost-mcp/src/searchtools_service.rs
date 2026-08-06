#[cfg(feature = "nlp")]
use crate::nlp::{indexer::SemanticIndexer, query::semantic_search};
#[cfg(test)]
use crate::policy::{
    PolicyExecutionStage, PolicyExecutionTermination, PolicyReportDiagnosticCode,
    PolicySuppressionDocumentState,
};
use crate::{
    AnalyzerConfig, CancellationToken, FilesystemProject, Project, ProjectChangeWatcher,
    ProjectFile, WorkspaceAnalyzer, WorkspaceFileListingCache,
    analyzer::semantic::WorkspaceRelativePath,
    analyzer::semantic_model::{
        CatalogCoordinate, CatalogOpenMode, CatalogOptions, CompilerOptions,
        SemanticModelActivationEvidence, SemanticModelActivationRequest,
        SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome, SemanticPackCatalog,
        SessionPackSource, SessionPackSourceKind, SourceFormat, WorkspaceSemanticModelOptions,
        acquire_active_semantic_models, compile_source, discover_workspace_semantic_models,
    },
    analyzer::{IndexWarmer, Language},
    code_intelligence::CodeIntelligenceRuntime,
    code_quality::{
        analyze_git_hotspots, compute_cognitive_complexity, compute_cyclomatic_complexity,
        report_comment_density_for_code_unit, report_comment_density_for_files,
        report_dead_code_and_unused_abstraction_smells, report_exception_handling_smells,
        report_long_method_and_god_object_smells, report_secret_like_code,
        report_structural_clone_smells, report_test_assertion_smells,
    },
    diff_analysis::{AnalyzeDiffParams, DiffAnalysisOptions, analyze_diff_at_root},
    file_tools::{find_files_containing, get_file_contents, search_file_contents},
    path_normalization::NormalizePath,
    policy::{
        BuiltInPolicySelection, POLICY_EXIT_CLEAN, POLICY_EXIT_FINDING, POLICY_EXIT_UNRELIABLE,
        PolicyEvaluationDate, PolicyEvaluationInput, PolicyEvaluationOptions, PolicyFailOn,
        PolicyId, PolicyReportDocument, PolicyScopeOptions, PolicyScopeSource,
        PolicySuppressionOptions, PolicySuppressionSource, built_in_policy_catalog,
        workspace_snapshot_deadline_outcome,
    },
    profiling,
    searchtools::{
        ActivateWorkspaceParams, ActiveWorkspaceResult, GetActiveWorkspaceParams,
        MostRelevantFilesParams, RefreshParams, SymbolLookupParams, SymbolSourcesResult,
        classify_test_files, get_declarations_by_location_with_cancellation,
        get_definitions_by_location_with_cancellation, get_definitions_by_reference,
        get_summaries_with_cancellation, get_symbol_ancestors,
        get_symbol_locations_with_cancellation, get_symbol_sources, get_type_by_location,
        list_symbols, most_relevant_files_with_cancellation, refresh_result, rename_symbol,
        scan_usages_by_location_with_cancellation, scan_usages_by_reference_with_cancellation,
        search_symbols_with_cancellation, symbol_source_candidate_files, usage_graph,
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
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const SEMANTIC_PACK_CATALOG_ENV: &str = "BIFROST_SEMANTIC_PACK_CATALOG";
const SEMANTIC_PACK_EVIDENCE_ENV: &str = "BIFROST_SEMANTIC_PACK_EVIDENCE";
const WORKSPACE_SEMANTIC_MODELS_ENV: &str = "BIFROST_WORKSPACE_SEMANTIC_MODELS";

/// Facade-owned registration hook for reviewed shipped semantic packs.
pub type SemanticModelCatalogBootstrap = fn(&SemanticPackCatalog) -> Result<(), String>;

static SEMANTIC_MODEL_CATALOG_BOOTSTRAP: OnceLock<SemanticModelCatalogBootstrap> = OnceLock::new();

/// Configure the downstream shipped-pack provider once for this process.
pub fn install_semantic_model_catalog_bootstrap(
    bootstrap: SemanticModelCatalogBootstrap,
) -> Result<(), &'static str> {
    SEMANTIC_MODEL_CATALOG_BOOTSTRAP
        .set(bootstrap)
        .map_err(|_| "semantic-model catalog bootstrap is already configured")
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

fn activate_configured_semantic_models(
    workspace_root: &Path,
    workspace: &WorkspaceAnalyzer,
    configured: Option<ConfiguredSemanticModels>,
) -> Result<(), String> {
    let _scope = profiling::scope("semantic_pack.activate_configured");
    let bootstrap = SEMANTIC_MODEL_CATALOG_BOOTSTRAP.get().copied();
    if configured.is_none() && bootstrap.is_none() {
        return Ok(());
    }
    let configured = configured.unwrap_or(ConfiguredSemanticModels {
        catalog_root: None,
        evidence: Vec::new(),
        workspace_models: false,
    });
    let catalog =
        {
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
                None => SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).map_err(
                    |error| format!("failed to open ephemeral semantic-pack catalog: {error}"),
                )?,
            }
        };
    let mut evidence = configured
        .evidence
        .into_iter()
        .map(ConfiguredSemanticModelEvidence::parse)
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(bootstrap) = bootstrap {
        {
            let _scope = profiling::scope("semantic_pack.bootstrap_catalog");
            bootstrap(&catalog)?;
        }
        {
            let _scope = profiling::scope("semantic_pack.intrinsic_evidence");
            evidence.extend(intrinsic_language_evidence(workspace));
        }
    }
    let workspace_digests = if configured.workspace_models {
        register_workspace_semantic_models(workspace_root, &catalog, &mut evidence)?
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
            for (path, digest) in &workspace_digests {
                if !active
                    .shards()
                    .iter()
                    .any(|shard| shard.manifest.content_sha256 == *digest)
                {
                    return Err(format!(
                        "workspace semantic model {path} did not activate: {:?}",
                        active.activation_report()
                    ));
                }
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
            Ok(())
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
    activate_configured_semantic_models(workspace_root, workspace, configured_semantic_models()?)
}

fn intrinsic_language_evidence(
    workspace: &WorkspaceAnalyzer,
) -> Vec<SemanticModelActivationEvidence> {
    workspace
        .analyzer()
        .languages()
        .into_iter()
        .map(|language| SemanticModelActivationEvidence {
            language: language.config_label().to_owned(),
            ecosystem: intrinsic_ecosystem(language).to_owned(),
            package: None,
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: None,
        })
        .collect()
}

fn intrinsic_ecosystem(language: Language) -> &'static str {
    match language {
        Language::Java | Language::Scala | Language::Kotlin => "maven",
        Language::Rust => "cargo",
        Language::Go => "go",
        Language::Python => "pypi",
        Language::Ruby => "rubygems",
        Language::JavaScript | Language::TypeScript => "npm",
        Language::CSharp => "nuget",
        Language::Cpp | Language::Php | Language::None => "language",
    }
}

fn register_workspace_semantic_models(
    workspace_root: &Path,
    catalog: &SemanticPackCatalog,
    evidence: &mut Vec<SemanticModelActivationEvidence>,
) -> Result<Vec<(String, String)>, String> {
    let report = discover_workspace_semantic_models(
        workspace_root,
        WorkspaceSemanticModelOptions::default(),
    );
    if !report.complete {
        let diagnostics = report
            .diagnostics
            .iter()
            .map(|diagnostic| {
                format!(
                    "{} {}: {}",
                    diagnostic.path, diagnostic.code, diagnostic.message
                )
            })
            .chain(report.files.iter().flat_map(|file| {
                file.diagnostics.iter().map(|diagnostic| {
                    format!(
                        "{} {} {}: {}",
                        file.path, diagnostic.path, diagnostic.code, diagnostic.message
                    )
                })
            }))
            .collect::<Vec<_>>();
        return Err(format!(
            "workspace semantic-model discovery failed: {}",
            diagnostics.join("; ")
        ));
    }
    if !report.enabled {
        return Ok(Vec::new());
    }

    let mut registered = Vec::with_capacity(report.files.len());
    for file in report.files {
        let format = match file.source_format.as_str() {
            "json" => SourceFormat::Json,
            "yaml" => SourceFormat::Yaml,
            value => {
                return Err(format!(
                    "workspace semantic model {} has unsupported source format {value}",
                    file.path
                ));
            }
        };
        let source_path = workspace_root.join(Path::new(&file.path));
        let bytes = std::fs::read(&source_path).map_err(|error| {
            format!(
                "failed to read workspace semantic model {}: {error}",
                file.path
            )
        })?;
        let compiled =
            compile_source(format, &bytes, &CompilerOptions::default()).map_err(|diagnostics| {
                format!(
                    "failed to compile workspace semantic model {}: {diagnostics:?}",
                    file.path
                )
            })?;
        let source_id = format!("workspace:{}#sha256={}", file.path, file.source_sha256);
        let digest = catalog
            .register_session_pack(
                &compiled,
                &SessionPackSource {
                    kind: SessionPackSourceKind::EphemeralWorkspace,
                    source_id,
                },
            )
            .map_err(|error| {
                format!(
                    "failed to register workspace semantic model {}: {error}",
                    file.path
                )
            })?;
        evidence.push(SemanticModelActivationEvidence {
            language: compiled.manifest.language.clone(),
            ecosystem: compiled.manifest.ecosystem.clone(),
            package: None,
            module: None,
            toolchain: None,
            target: None,
            configuration: Some(compiled.manifest.pack_id.clone()),
            artifact_sha256: None,
        });
        registered.push((file.path, digest));
    }
    Ok(registered)
}

#[cfg(test)]
mod workspace_semantic_model_configuration_tests {
    use super::*;
    use crate::analyzer::semantic_model::SemanticModelOverlayDisposition;
    use crate::path_normalization::NormalizePath;

    const WORKSPACE_PACK: &str = r#"{
  "schema_version": 1,
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
        let analyzer = WorkspaceAnalyzer::build_for_service(project, AnalyzerConfig::default());
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
        let error = activate_configured_semantic_models(
            root.path(),
            &analyzer,
            Some(workspace_configuration()),
        )
        .unwrap_err();
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
    use crate::searchtools::{SourceBlock, SymbolSourcesResult};

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
    evaluation_date: PolicyEvaluationDate,
    #[serde(default)]
    fail_on: RunPolicyFailOn,
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
    report: PolicyReportDocument,
}

#[derive(Debug, Clone)]
pub struct SearchToolsServiceError {
    pub code: SearchToolsServiceErrorCode,
    pub message: String,
}

impl SearchToolsServiceError {
    fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            code: SearchToolsServiceErrorCode::InvalidParams,
            message: message.into(),
        }
    }

    fn unknown_tool(message: impl Into<String>) -> Self {
        Self {
            code: SearchToolsServiceErrorCode::UnknownTool,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: SearchToolsServiceErrorCode::Internal,
            message: message.into(),
        }
    }

    fn deadline_exceeded(message: impl Into<String>) -> Self {
        Self {
            code: SearchToolsServiceErrorCode::DeadlineExceeded,
            message: message.into(),
        }
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

type WatcherStarter =
    Arc<dyn Fn(Arc<dyn Project>) -> Result<ProjectChangeWatcher, String> + Send + Sync + 'static>;
type PendingWorkspaceBuild = JoinHandle<Result<(u64, PathBuf, WorkspaceSession), String>>;

fn production_watcher_starter() -> WatcherStarter {
    Arc::new(ProjectChangeWatcher::start)
}

pub struct SearchToolsService {
    root: RwLock<Option<PathBuf>>,
    session: RwLock<Option<WorkspaceSession>>,
    workspace_generation: AtomicU64,
    query_protocols: RwLock<crate::analyzer::structural::ProtocolRegistrationSet>,
    query_value_flows: RwLock<crate::analyzer::structural::ValueFlowPlanRegistrationSet>,
    query_taint_results: RwLock<crate::analyzer::structural::TaintResultRegistrationSet>,
    typestate_summaries:
        RwLock<Arc<crate::analyzer::typestate::ProductionTypestateSummaryRepository>>,
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
    semantic_indexing: bool,
    watcher_starter: WatcherStarter,
    diff_snapshot_object_dir: Option<PathBuf>,
}

struct WorkspaceSession {
    snapshot: Arc<WorkspaceAnalyzer>,
    document_root: Arc<WorkspaceRoot>,
    watcher: SessionWatcher,
    index_warmer: Arc<IndexWarmer>,
    #[cfg(feature = "nlp")]
    semantic: Option<Arc<SemanticIndexer>>,
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
    context: Arc<crate::analyzer::AnalyzerQueryContext>,
}

pub(crate) struct PreparedQueryCode {
    snapshot: WorkspaceQueryScope,
    arguments: Value,
    workspace_generation: u64,
    query_protocols: crate::analyzer::structural::ProtocolRegistrationSet,
    query_value_flows: crate::analyzer::structural::ValueFlowPlanRegistrationSet,
    query_taint_results: crate::analyzer::structural::TaintResultRegistrationSet,
    typestate_summary_lease: crate::analyzer::typestate::ProductionTypestateSummaryLease,
}

impl PreparedQueryCode {
    #[cfg(test)]
    pub(crate) const fn workspace_generation(&self) -> u64 {
        self.workspace_generation
    }
}

pub(crate) struct PreparedRunPolicy {
    snapshot: WorkspaceQueryScope,
    root: PathBuf,
    policy_inputs: Vec<PolicyEvaluationInput>,
    options: PolicyEvaluationOptions,
    selection_elapsed: Duration,
    snapshot_elapsed: Duration,
    #[cfg(test)]
    workspace_generation: u64,
}

pub(crate) enum RunPolicyPreparation {
    Ready(PreparedRunPolicy),
    Deadline(RunPolicyToolResult),
}

impl PreparedRunPolicy {
    #[cfg(test)]
    pub(crate) const fn workspace_generation(&self) -> u64 {
        self.workspace_generation
    }
}

impl WorkspaceQueryScope {
    fn new(source_snapshot: Arc<WorkspaceAnalyzer>, document_root: Arc<WorkspaceRoot>) -> Self {
        let context = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        Self::with_context(source_snapshot, document_root, context)
    }

    fn with_context(
        source_snapshot: Arc<WorkspaceAnalyzer>,
        document_root: Arc<WorkspaceRoot>,
        context: Arc<crate::analyzer::AnalyzerQueryContext>,
    ) -> Self {
        let snapshot = Arc::new(source_snapshot.as_ref().clone());
        snapshot.begin_query(&context);
        Self {
            source_snapshot,
            snapshot,
            document_root,
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
                Some(error) => Err(SearchToolsServiceError::internal(format!(
                    "Analyzer store failure while running `{operation}`: {error}"
                ))),
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
    /// Queue a background warm of the current snapshot's lazy query indexes.
    /// Free when the snapshot is already warm (incremental updates whose
    /// sources were unchanged share the previous generation's indexes).
    fn schedule_index_warm(&self) {
        self.index_warmer.schedule(Arc::clone(&self.snapshot));
    }

    fn close_semantic(&self) {
        #[cfg(feature = "nlp")]
        if let Some(semantic) = &self.semantic {
            semantic.close();
        }
    }
}

/// Semantic indexing is off by default. Set `BIFROST_SEMANTIC_INDEX=auto`
/// (or `on`/`1`/`enabled`) to opt in when semantic_search is needed.
pub(crate) fn semantic_indexing_enabled() -> bool {
    if cfg!(not(feature = "nlp")) {
        return false;
    }
    matches!(
        std::env::var("BIFROST_SEMANTIC_INDEX").as_deref(),
        Ok("auto") | Ok("on") | Ok("1") | Ok("enabled")
    )
}

#[cfg(feature = "nlp")]
fn maybe_start_semantic(
    enabled: bool,
    snapshot: &Arc<WorkspaceAnalyzer>,
) -> Option<Arc<SemanticIndexer>> {
    maybe_start_semantic_checked(enabled, snapshot, semantic_accelerator_ready)
}

/// Ok when the voyage-4-nano embedder can run: a CUDA/Metal accelerator is
/// present, or the operator forced CPU. Mirrors `nlp::semantic_search_available`
/// so the tool is never advertised without also being startable.
#[cfg(feature = "nlp")]
fn semantic_accelerator_ready() -> Result<(), String> {
    if crate::nlp::semantic_search_available() {
        Ok(())
    } else {
        Err(
            "no CUDA or Metal accelerator detected; pass --force-semantic-cpu to run the \
             embedder on CPU"
                .to_string(),
        )
    }
}

#[cfg(feature = "nlp")]
fn maybe_start_semantic_checked(
    enabled: bool,
    snapshot: &Arc<WorkspaceAnalyzer>,
    accelerator_ready: impl FnOnce() -> Result<(), String>,
) -> Option<Arc<SemanticIndexer>> {
    if !enabled {
        return None;
    }
    if let Err(err) = accelerator_ready() {
        eprintln!("bifrost semantic index disabled: {err}");
        return None;
    }
    let root = snapshot.analyzer().project().root().to_path_buf();
    if !crate::nlp::gitcache::is_git_repo(&root) {
        eprintln!("bifrost semantic index disabled: semantic search requires a git repository");
        return None;
    }
    // `SemanticIndexer::start` resolves the same shared cache database as the
    // analyzer store, so semantic rows land beside the analyzer rows for the
    // primary checkout even when the session is bound to a linked worktree.
    Some(SemanticIndexer::start(root, snapshot.clone()))
}

impl SearchToolsService {
    /// Configure trusted Git objects that immutable `analyze_diff` endpoints
    /// may resolve. This is host configuration, never a tool argument.
    #[must_use]
    pub fn with_diff_snapshot_object_dir(mut self, dir: PathBuf) -> Self {
        self.diff_snapshot_object_dir = Some(dir);
        self
    }

    pub fn new(root: PathBuf) -> Result<Self, String> {
        Self::new_with_strategy(
            root,
            UpdateStrategy::WatchFiles,
            semantic_indexing_enabled(),
        )
    }

    pub fn new_for_python(root: PathBuf) -> Result<Self, String> {
        Self::new_lazy_with_strategy(
            root,
            UpdateStrategy::WatchFiles,
            semantic_indexing_enabled(),
        )
    }

    /// Construct without a background semantic indexer regardless of env;
    /// `semantic_search` reports itself unavailable on such a service.
    pub fn new_without_semantic_index(root: PathBuf) -> Result<Self, String> {
        Self::new_with_strategy(root, UpdateStrategy::WatchFiles, false)
    }

    /// Construct with no file watcher and no semantic indexer. This is useful
    /// for immutable, short-lived workspaces such as inline test fixtures.
    pub fn new_manual_without_semantic_index(root: PathBuf) -> Result<Self, String> {
        Self::new_transient_with_strategy(root, UpdateStrategy::Manual, false)
    }

    /// Construct a manual, non-semantic service over an already-selected
    /// project. One-shot CLI subset workspaces use this to avoid whole-root
    /// watchers while still sharing the analyzer blob cache for git roots.
    pub fn new_manual_for_project(project: Arc<dyn Project>) -> Result<Self, String> {
        let root = project.root().to_path_buf();
        let watcher_starter = production_watcher_starter();
        let workspace =
            WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
                .map_err(|error| format!("Failed to build persisted workspace: {error}"))?;
        let session = assemble_session(
            project,
            workspace,
            UpdateStrategy::Manual,
            false,
            &watcher_starter,
        )?;
        Ok(Self {
            root: RwLock::new(Some(root)),
            session: RwLock::new(Some(session)),
            workspace_generation: AtomicU64::new(1),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            typestate_summaries: RwLock::new(Arc::new(
                crate::analyzer::typestate::ProductionTypestateSummaryRepository::new(),
            )),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(None),
            update_strategy: UpdateStrategy::Manual,
            semantic_indexing: false,
            watcher_starter,
            diff_snapshot_object_dir: None,
        })
    }

    /// Construct a manual, non-semantic service over `project` with an
    /// ephemeral (non-persisted) analyzer cache and a caller-supplied analyzer
    /// config. One-shot audit drivers (the MCP property fuzzer) use this:
    /// nothing is written into the target checkout, and because every file is
    /// parsed fresh, session-only evidence such as tree-sitter ERROR nodes
    /// (`IAnalyzer::parse_errors`) is available for the whole workspace.
    pub fn new_manual_ephemeral_for_project(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, String> {
        Self::new_manual_with_cache(project, config, false)
    }

    /// Persisted-cache sibling of [`Self::new_manual_ephemeral_for_project`]
    /// for warmed, resumable campaigns. Session-only evidence (tree-sitter
    /// ERROR nodes) is unavailable for files served from the warm cache.
    pub fn new_manual_persisted_for_project(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, String> {
        Self::new_manual_with_cache(project, config, true)
    }

    fn new_manual_with_cache(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        persisted: bool,
    ) -> Result<Self, String> {
        let root = project.root().to_path_buf();
        let watcher_starter = production_watcher_starter();
        let workspace = if persisted {
            WorkspaceAnalyzer::build_persisted_for_service(Arc::clone(&project), config)
                .map_err(|error| format!("Failed to build persisted workspace: {error}"))?
        } else {
            WorkspaceAnalyzer::build_for_service(Arc::clone(&project), config)
        };
        let session = assemble_session(
            project,
            workspace,
            UpdateStrategy::Manual,
            false,
            &watcher_starter,
        )?;
        Ok(Self {
            root: RwLock::new(Some(root)),
            session: RwLock::new(Some(session)),
            workspace_generation: AtomicU64::new(1),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            typestate_summaries: RwLock::new(Arc::new(
                crate::analyzer::typestate::ProductionTypestateSummaryRepository::new(),
            )),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(None),
            update_strategy: UpdateStrategy::Manual,
            semantic_indexing: false,
            watcher_starter,
            diff_snapshot_object_dir: None,
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

    /// Register one already-compiled protocol and pre-resolved binding plan for
    /// in-process CodeQuery callers. Semantic handles remain host-owned and are
    /// never accepted by an MCP/LSP wire request.
    pub fn register_query_protocol(
        &self,
        protocol_ref: crate::analyzer::structural::ProtocolRef,
        expected_root: crate::analyzer::semantic::ProcedureHandle,
        protocol: Arc<crate::analyzer::typestate::CompiledProtocol>,
        bindings: Arc<crate::analyzer::typestate::TypestateBindingPlan>,
    ) -> Result<crate::analyzer::structural::ProtocolRegistrationOutcome, SearchToolsServiceError>
    {
        let session = self.read_session()?;
        session.as_ref().ok_or_else(Self::closed_error)?;
        let workspace_generation = self.workspace_generation();

        let registration = crate::analyzer::structural::ProtocolRegistration::new(
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
        protocol_ref: &crate::analyzer::structural::ProtocolRef,
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
        plan_ref: crate::analyzer::structural::ValueFlowPlanRef,
        plan: Arc<crate::analyzer::value_flow::ValueFlowPlan>,
    ) -> Result<
        crate::analyzer::structural::ValueFlowPlanRegistrationOutcome,
        SearchToolsServiceError,
    > {
        let workspace_generation = {
            let session = self.read_session()?;
            session.as_ref().ok_or_else(Self::closed_error)?;
            self.workspace_generation()
        };
        let registration =
            crate::analyzer::structural::ValueFlowPlanRegistration::new(workspace_generation, plan);
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
        plan_ref: &crate::analyzer::structural::ValueFlowPlanRef,
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
        taint_ref: crate::analyzer::structural::TaintResultRef,
        results: Vec<Arc<crate::policy::ProductionTaintAnalysisResult>>,
    ) -> Result<crate::analyzer::structural::TaintResultRegistrationOutcome, SearchToolsServiceError>
    {
        let workspace_generation = {
            let session = self.read_session()?;
            session.as_ref().ok_or_else(Self::closed_error)?;
            self.workspace_generation()
        };
        let registration = crate::analyzer::structural::TaintResultRegistration::new(
            workspace_generation,
            results,
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
        taint_ref: &crate::analyzer::structural::TaintResultRef,
    ) -> Result<bool, SearchToolsServiceError> {
        Ok(self
            .query_taint_results
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?
            .unregister(taint_ref))
    }

    /// Construct with no file watcher and no semantic indexer: the caller drives
    /// updates via the incremental `update_paths` tool. For batch consumers that
    /// re-use one session across many revisions of one worktree.
    pub fn new_for_python_manual(root: PathBuf) -> Result<Self, String> {
        Self::new_transient_with_strategy(root, UpdateStrategy::Manual, false)
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

    pub(crate) fn call_tool_output_with_cancellation(
        &self,
        name: &str,
        arguments: Value,
        render_options: RenderOptions,
        cancellation: Option<&CancellationToken>,
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

        if name == "semantic_search" {
            return self.handle_semantic_search(arguments, render_options);
        }
        if name == "semantic_search_status" {
            return self.handle_semantic_search_status(arguments);
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
        if name == "query_code" {
            let prepared = self.prepare_query_code(arguments, cancellation)?;
            return self.execute_prepared_query_code(prepared, cancellation);
        }
        if name == "list_policies" {
            let catalog = built_in_policy_catalog().map_err(|error| {
                SearchToolsServiceError::internal(format!(
                    "failed to load built-in policy catalog: {error}"
                ))
            })?;
            return Self::structured_only(catalog.manifest());
        }
        if name == "run_policy" {
            return match self.prepare_run_policy_with_cancellation(arguments, cancellation)? {
                RunPolicyPreparation::Ready(prepared) => {
                    self.execute_prepared_run_policy(prepared, cancellation)
                }
                RunPolicyPreparation::Deadline(result) => Self::structured_only(result),
            };
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
    ) -> Result<crate::analyzer::structural::CodeQueryResponse, SearchToolsServiceError> {
        let PreparedQueryCode {
            snapshot,
            arguments,
            workspace_generation,
            query_protocols,
            query_value_flows,
            query_taint_results,
            typestate_summary_lease,
        } = self.prepare_query_code(arguments, None)?;
        let result = self.query_code_result_for_snapshot(
            &snapshot,
            arguments,
            None,
            workspace_generation,
            &query_protocols,
            &query_value_flows,
            &query_taint_results,
            typestate_summary_lease,
        );
        snapshot.finish("query_code", result)
    }

    pub(crate) fn prepare_query_code(
        &self,
        arguments: Value,
        cancellation: Option<&CancellationToken>,
    ) -> Result<PreparedQueryCode, SearchToolsServiceError> {
        loop {
            let (generation, typestate_summaries) = {
                let typestate_summaries = self
                    .typestate_summaries
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                (
                    self.workspace_generation(),
                    Arc::clone(&typestate_summaries),
                )
            };
            let snapshot = self.snapshot_for_query_with_cancellation(cancellation)?;
            let query_protocols = self.query_protocol_snapshot()?;
            let query_value_flows = self.query_value_flow_snapshot()?;
            let query_taint_results = self.query_taint_result_snapshot()?;
            if generation != self.workspace_generation() {
                continue;
            }
            let typestate_summary_lease = typestate_summaries
                .lease(generation)
                .map_err(|error| SearchToolsServiceError::internal(error.to_string()))?;
            let root = snapshot.analyzer().project().root();
            let arguments =
                crate::tool_arguments::normalize_tool_arguments("query_code", arguments, root)
                    .map_err(SearchToolsServiceError::invalid_params)?;
            return Ok(PreparedQueryCode {
                snapshot,
                arguments,
                workspace_generation: generation,
                query_protocols,
                query_value_flows,
                query_taint_results,
                typestate_summary_lease,
            });
        }
    }

    pub(crate) fn execute_prepared_query_code(
        &self,
        prepared: PreparedQueryCode,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let PreparedQueryCode {
            snapshot,
            arguments,
            workspace_generation,
            query_protocols,
            query_value_flows,
            query_taint_results,
            typestate_summary_lease,
        } = prepared;
        let result = (|| {
            let output = self.query_code_result_for_snapshot(
                &snapshot,
                arguments,
                cancellation,
                workspace_generation,
                &query_protocols,
                &query_value_flows,
                &query_taint_results,
                typestate_summary_lease,
            )?;
            let rendered_text = output.render_text();
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
        query_protocols: &crate::analyzer::structural::ProtocolRegistrationSet,
        query_value_flows: &crate::analyzer::structural::ValueFlowPlanRegistrationSet,
        query_taint_results: &crate::analyzer::structural::TaintResultRegistrationSet,
        typestate_summary_lease: crate::analyzer::typestate::ProductionTypestateSummaryLease,
    ) -> Result<crate::analyzer::structural::CodeQueryResponse, SearchToolsServiceError> {
        let query = Self::decode_query_code_input(snapshot, arguments)?;
        Ok(CodeIntelligenceRuntime::new(snapshot, cancellation)
            .execute_query_with_all_analysis_registration_lease(
                workspace_generation,
                query_protocols,
                query_value_flows,
                query_taint_results,
                &query,
                crate::analyzer::structural::CodeQueryExecutionLimits::default(),
                typestate_summary_lease,
            ))
    }

    fn decode_query_code_input(
        snapshot: &WorkspaceQueryScope,
        arguments: Value,
    ) -> Result<crate::analyzer::structural::CodeQuery, SearchToolsServiceError> {
        let Some(query_file) = arguments.get("query_file") else {
            return crate::analyzer::structural::CodeQuery::from_json(&arguments)
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
            Some("rql") => crate::analyzer::structural::query::sexp::sexp_to_json(
                contents.source(),
            )
            .map_err(|error| {
                SearchToolsServiceError::invalid_params(format!(
                    "failed to parse RQL query file `{query_file}`: {error}"
                ))
            }),
            Some("json") => serde_json::from_str::<Value>(contents.source()).map_err(|error| {
                SearchToolsServiceError::invalid_params(format!(
                    "failed to parse JSON query file `{query_file}`: {error}"
                ))
            }),
            _ => unreachable!("query file extension was validated before reading"),
        }?;
        let value = crate::tool_arguments::normalize_tool_arguments("query_code", value, root)
            .map_err(SearchToolsServiceError::invalid_params)?;
        crate::analyzer::structural::CodeQuery::from_json(&value).map_err(|error| {
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
    ) -> Result<crate::analyzer::structural::ProtocolRegistrationSet, SearchToolsServiceError> {
        self.query_protocols
            .read()
            .map(|registrations| registrations.clone())
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))
    }

    fn query_value_flow_snapshot(
        &self,
    ) -> Result<crate::analyzer::structural::ValueFlowPlanRegistrationSet, SearchToolsServiceError>
    {
        self.query_value_flows
            .read()
            .map(|registrations| registrations.clone())
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))
    }

    fn query_taint_result_snapshot(
        &self,
    ) -> Result<crate::analyzer::structural::TaintResultRegistrationSet, SearchToolsServiceError>
    {
        self.query_taint_results
            .read()
            .map(|registrations| registrations.clone())
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))
    }

    fn advance_workspace_generation(&self) {
        let mut summaries = self
            .typestate_summaries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        let previous = self.workspace_generation.fetch_add(1, Ordering::AcqRel);
        let generation = previous.wrapping_add(1);
        let successor = summaries.successor_generation(generation);
        *summaries = Arc::new(successor);
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
        semantic_indexing: bool,
    ) -> Result<Self, String> {
        Self::new_with_strategy_and_watcher_starter(
            root,
            update_strategy,
            semantic_indexing,
            production_watcher_starter(),
        )
    }

    fn new_with_strategy_and_watcher_starter(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        semantic_indexing: bool,
        watcher_starter: WatcherStarter,
    ) -> Result<Self, String> {
        let canonical = canonical_service_root(root)?;
        let file_listing = listing_cache_for(update_strategy, &canonical);
        let (project, workspace) = build_persisted_workspace(canonical, file_listing.clone())?;
        let root = project.root().to_path_buf();
        let session = assemble_session(
            project,
            workspace,
            update_strategy,
            semantic_indexing,
            &watcher_starter,
        )?;
        Ok(Self {
            root: RwLock::new(Some(root)),
            session: RwLock::new(Some(session)),
            workspace_generation: AtomicU64::new(1),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            typestate_summaries: RwLock::new(Arc::new(
                crate::analyzer::typestate::ProductionTypestateSummaryRepository::new(),
            )),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(file_listing),
            update_strategy,
            semantic_indexing,
            watcher_starter,
            diff_snapshot_object_dir: None,
        })
    }

    fn new_transient_with_strategy(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        semantic_indexing: bool,
    ) -> Result<Self, String> {
        Self::new_transient_with_strategy_and_watcher_starter(
            root,
            update_strategy,
            semantic_indexing,
            production_watcher_starter(),
        )
    }

    fn new_transient_with_strategy_and_watcher_starter(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        semantic_indexing: bool,
        watcher_starter: WatcherStarter,
    ) -> Result<Self, String> {
        let canonical = canonical_service_root(root)?;
        let file_listing = listing_cache_for(update_strategy, &canonical);
        let (project, workspace) = build_transient_workspace(canonical, file_listing.clone())?;
        let root = project.root().to_path_buf();
        let session = assemble_session(
            project,
            workspace,
            update_strategy,
            semantic_indexing,
            &watcher_starter,
        )?;
        Ok(Self {
            root: RwLock::new(Some(root)),
            session: RwLock::new(Some(session)),
            workspace_generation: AtomicU64::new(1),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            typestate_summaries: RwLock::new(Arc::new(
                crate::analyzer::typestate::ProductionTypestateSummaryRepository::new(),
            )),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(file_listing),
            update_strategy,
            semantic_indexing,
            watcher_starter,
            diff_snapshot_object_dir: None,
        })
    }

    fn new_lazy_with_strategy(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        semantic_indexing: bool,
    ) -> Result<Self, String> {
        Self::new_lazy_with_strategy_and_watcher_starter(
            root,
            update_strategy,
            semantic_indexing,
            production_watcher_starter(),
        )
    }

    fn new_lazy_with_strategy_and_watcher_starter(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        semantic_indexing: bool,
        watcher_starter: WatcherStarter,
    ) -> Result<Self, String> {
        let canonical = canonical_service_root(root)?;
        let file_listing = listing_cache_for(update_strategy, &canonical);
        Ok(Self {
            root: RwLock::new(Some(canonical)),
            session: RwLock::new(None),
            workspace_generation: AtomicU64::new(1),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            typestate_summaries: RwLock::new(Arc::new(
                crate::analyzer::typestate::ProductionTypestateSummaryRepository::new(),
            )),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(file_listing),
            update_strategy,
            semantic_indexing,
            watcher_starter,
            diff_snapshot_object_dir: None,
        })
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
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            typestate_summaries: RwLock::new(Arc::new(
                crate::analyzer::typestate::ProductionTypestateSummaryRepository::new(),
            )),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(None),
            update_strategy,
            semantic_indexing: semantic_indexing_enabled(),
            watcher_starter: production_watcher_starter(),
            diff_snapshot_object_dir: None,
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
        let semantic_indexing = self.semantic_indexing;
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
                    let (project, workspace) =
                        build_persisted_workspace(build_root.clone(), build_file_listing)?;
                    let session = assemble_session(
                        project,
                        workspace,
                        update_strategy,
                        semantic_indexing,
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
        if let Some(old_session) = old_session {
            old_session.close_semantic();
        }
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
        if let Some(old_session) = old_session {
            old_session.close_semantic();
        }
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
        let semantic_indexing = semantic_indexing_enabled();
        let canonical = canonical_service_root(root)?;
        // Created before the deferred build so listing-backed fast paths
        // (`find_filenames`, #1388) can fill it while indexing is pending.
        let file_listing = listing_cache_for(update_strategy, &canonical);
        let handle = std::thread::Builder::new()
            .name("bifrost-index-build".to_string())
            .spawn({
                let canonical = canonical.clone();
                let watcher_starter = Arc::clone(&watcher_starter);
                let file_listing = file_listing.clone();
                move || -> Result<(u64, PathBuf, WorkspaceSession), String> {
                    let _scope = profiling::scope("mcp_cold.analyzer_construction");
                    let project = build_project(canonical.clone(), file_listing)?;
                    let workspace = WorkspaceAnalyzer::build_persisted_for_service(
                        Arc::clone(&project),
                        AnalyzerConfig::default(),
                    )
                    .map_err(|error| format!("Failed to build persisted workspace: {error}"))?;
                    prewarm_configured_semantic_models(project.root(), &workspace)?;
                    let session = assemble_session(
                        project,
                        workspace,
                        update_strategy,
                        semantic_indexing,
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
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            typestate_summaries: RwLock::new(Arc::new(
                crate::analyzer::typestate::ProductionTypestateSummaryRepository::new(),
            )),
            pending_build: Mutex::new(Some(handle)),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(file_listing),
            update_strategy,
            semantic_indexing,
            watcher_starter,
            diff_snapshot_object_dir: None,
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
                    session.schedule_index_warm();
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
            let built =
                build_persisted_workspace(root, file_listing).and_then(|(project, workspace)| {
                    assemble_session(
                        project,
                        workspace,
                        self.update_strategy,
                        self.semantic_indexing,
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
                session.schedule_index_warm();
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
        if let Some(session) = session {
            session.close_semantic();
        }
        Ok(())
    }

    /// Run a forced git-reachability GC on the semantic index and block until it
    /// completes. Off the retrieval path (does not affect `wait_ready`), intended
    /// for occasional maintenance. The session lock is released before blocking.
    pub fn request_semantic_gc(&self) -> Result<(), SearchToolsServiceError> {
        #[cfg(not(feature = "nlp"))]
        {
            Err(SearchToolsServiceError::internal(
                "semantic index requires the nlp feature",
            ))
        }
        #[cfg(feature = "nlp")]
        {
            self.ensure_ready()?;
            let indexer = {
                let guard = self.session.read().map_err(|_| {
                    SearchToolsServiceError::internal("workspace session lock poisoned")
                })?;
                let session = guard.as_ref().ok_or_else(Self::closed_error)?;
                match &session.semantic {
                    Some(indexer) => indexer.clone(),
                    None => {
                        return Err(SearchToolsServiceError::invalid_params(
                            "semantic index is disabled for this session",
                        ));
                    }
                }
            };
            indexer
                .run_gc_blocking()
                .map_err(SearchToolsServiceError::internal)
        }
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
        #[cfg(feature = "nlp")]
        if let Some(semantic) = &session.semantic {
            semantic.request_full_build(session.snapshot.clone());
        }
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
            return active_workspace_result(&resolved);
        }

        // Fully assemble the replacement before mutating either active field so
        // analyzer-store or watcher startup failure leaves the old session usable.
        let new_file_listing = listing_cache_for(self.update_strategy, &resolved);
        let (new_project, new_workspace) =
            build_persisted_workspace(resolved.clone(), new_file_listing.clone()).map_err(
                |err| {
                    SearchToolsServiceError::internal(format!(
                        "Failed to activate workspace {}: {err}",
                        resolved.display()
                    ))
                },
            )?;
        #[cfg(feature = "nlp")]
        let semantic_indexing = session.semantic.is_some();
        #[cfg(not(feature = "nlp"))]
        let semantic_indexing = false;
        let new_session = assemble_session(
            new_project,
            new_workspace,
            self.update_strategy,
            semantic_indexing,
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
        *root = Some(resolved.clone());
        *self
            .file_listing
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))? =
            new_file_listing;
        drop(guard);
        drop(root);
        old_session.close_semantic();

        active_workspace_result(&resolved)
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
        active_workspace_result(session.snapshot.analyzer().project().root())
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
            ));
        }

        {
            let guard = self.read_session()?;
            let session = guard.as_ref().ok_or_else(Self::closed_error)?;
            if !Self::session_watcher_has_pending(session) {
                return Ok(WorkspaceQueryScope::new(
                    Arc::clone(&session.snapshot),
                    Arc::clone(&session.document_root),
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
        let mut result = get_symbol_sources(initial_snapshot.analyzer(), params.clone());
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(SearchToolsServiceError::internal(
                "get_symbol_sources was cancelled or exceeded its request-wide time budget",
            ));
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
                return Err(SearchToolsServiceError::internal(
                    "get_symbol_sources was cancelled or exceeded its request-wide time budget",
                ));
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
                result = get_symbol_sources(final_snapshot.analyzer(), params);
                let output = Self::symbol_sources_output(result, render_options);
                return final_snapshot.finish("get_symbol_sources", output);
            }
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
        let rendered_text = result.render_text(render_options);
        let structured = serde_json::to_value(result).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })?;
        Ok(ToolOutput::Structured {
            structured,
            rendered_text: Some(rendered_text),
        })
    }

    /// Same read-first strategy as `snapshot_for_query`, plus the session's
    /// semantic indexer handle.
    #[cfg(feature = "nlp")]
    fn semantic_snapshot_for_query(
        &self,
    ) -> Result<(WorkspaceQueryScope, Option<Arc<SemanticIndexer>>), SearchToolsServiceError> {
        if self.update_strategy == UpdateStrategy::Manual {
            let guard = self.read_session()?;
            let session = guard.as_ref().ok_or_else(Self::closed_error)?;
            return Ok((
                WorkspaceQueryScope::new(
                    Arc::clone(&session.snapshot),
                    Arc::clone(&session.document_root),
                ),
                session.semantic.clone(),
            ));
        }

        {
            let guard = self.read_session()?;
            let session = guard.as_ref().ok_or_else(Self::closed_error)?;
            if !Self::session_watcher_has_pending(session) {
                return Ok((
                    WorkspaceQueryScope::new(
                        Arc::clone(&session.snapshot),
                        Arc::clone(&session.document_root),
                    ),
                    session.semantic.clone(),
                ));
            }
        }

        // Only reached for `WatchFiles` sessions with a pending delta.
        let mut guard = self.write_session()?;
        let session = guard.as_mut().ok_or_else(Self::closed_error)?;
        Self::apply_watcher_delta(session);
        Ok((
            WorkspaceQueryScope::new(
                Arc::clone(&session.snapshot),
                Arc::clone(&session.document_root),
            ),
            session.semantic.clone(),
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
            #[cfg(feature = "nlp")]
            if let Some(semantic) = &session.semantic {
                semantic.request_full_build(session.snapshot.clone());
            }
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
        session.snapshot = Arc::new({
            let _scope = profiling::scope("SearchToolsService::snapshot_update");
            session.snapshot.update(&changed_files)
        });
        #[cfg(feature = "nlp")]
        if let Some(semantic) = &session.semantic {
            semantic.request_update(session.snapshot.clone(), changed_files);
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
        if arguments
            .get("max_duration_secs")
            .is_some_and(|value| !value.is_u64())
        {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "{tool_name} requires `max_duration_secs` to be a non-negative integer"
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

    #[cfg(feature = "nlp")]
    fn handle_semantic_search(
        &self,
        arguments: Value,
        render_options: RenderOptions,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let (snapshot, semantic) = self.semantic_snapshot_for_query()?;
        let result = match semantic {
            Some(indexer) => Self::decode_render_and_try_run(
                &snapshot,
                arguments,
                render_options,
                move |workspace, params| semantic_search(workspace, &indexer, params),
            ),
            None => Err(SearchToolsServiceError::invalid_params(
                "semantic_search is disabled for this session (set BIFROST_SEMANTIC_INDEX=auto to enable it)",
            )),
        };
        snapshot.finish("semantic_search", result)
    }

    #[cfg(feature = "nlp")]
    fn handle_semantic_search_status(
        &self,
        arguments: Value,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let _params = serde_json::from_value::<RefreshParams>(arguments).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
        })?;
        let (snapshot, semantic) = self.semantic_snapshot_for_query()?;
        let result = match semantic {
            Some(indexer) => Self::structured_only(indexer.status(&snapshot)),
            None => Err(SearchToolsServiceError::invalid_params(
                "semantic_search_status is disabled for this session (set BIFROST_SEMANTIC_INDEX=auto to enable it)",
            )),
        };
        snapshot.finish("semantic_search_status", result)
    }

    #[cfg(not(feature = "nlp"))]
    fn handle_semantic_search(
        &self,
        _arguments: Value,
        _render_options: RenderOptions,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        Err(SearchToolsServiceError::invalid_params(
            "semantic_search is not available in this build (nlp feature disabled)",
        ))
    }

    #[cfg(not(feature = "nlp"))]
    fn handle_semantic_search_status(
        &self,
        _arguments: Value,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        Err(SearchToolsServiceError::invalid_params(
            "semantic_search_status is not available in this build (nlp feature disabled)",
        ))
    }

    pub(crate) fn prepare_run_policy_with_cancellation(
        &self,
        arguments: Value,
        cancellation: Option<&CancellationToken>,
    ) -> Result<RunPolicyPreparation, SearchToolsServiceError> {
        let preparation_started = Instant::now();
        let params = serde_json::from_value::<RunPolicyParams>(arguments).map_err(|error| {
            SearchToolsServiceError::invalid_params(format!(
                "Invalid run_policy arguments: {error}"
            ))
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
                if value.is_empty()
                    || value.len() > crate::mcp_extended::MAX_RUN_POLICY_SELECTOR_BYTES
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
            .map(|policy| {
                PolicyEvaluationInput::embedded(policy.source_identity(), policy.source())
            })
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
        let fail_on = PolicyFailOn::from(params.fail_on);
        let options =
            PolicyEvaluationOptions::with_suppressions(params.evaluation_date, suppressions)
                .with_scope(scope)
                .with_fail_on(fail_on);
        let selection_elapsed = preparation_started.elapsed();
        let snapshot_started = Instant::now();

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
                    let outcome = workspace_snapshot_deadline_outcome(
                        &options,
                        selected_policy_ids,
                        selection_elapsed,
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
                        report: outcome.into_report(),
                    };
                    return Ok(RunPolicyPreparation::Deadline(result));
                }
                Err(error) => return Err(error),
            };
            if workspace_generation != self.workspace_generation() {
                continue;
            }
            let root = snapshot.analyzer().project().root().to_path_buf();
            return Ok(RunPolicyPreparation::Ready(PreparedRunPolicy {
                snapshot,
                root,
                policy_inputs,
                options,
                selection_elapsed,
                snapshot_elapsed: snapshot_started.elapsed(),
                #[cfg(test)]
                workspace_generation,
            }));
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
            snapshot_elapsed,
            ..
        } = prepared;
        let result = (|| {
            let _scope = profiling::scope("run_policy.evaluate_policy_inputs");
            let mut outcome = CodeIntelligenceRuntime::new(&snapshot, cancellation)
                .evaluate_policy_inputs(&root, &policy_inputs, &options)
                .map_err(|error| {
                    SearchToolsServiceError::internal(format!(
                        "run_policy evaluation failed: {error}"
                    ))
                })?;
            outcome.record_preparation_timings(selection_elapsed, snapshot_elapsed);
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

    fn read_session(
        &self,
    ) -> Result<std::sync::RwLockReadGuard<'_, Option<WorkspaceSession>>, SearchToolsServiceError>
    {
        self.ensure_ready()?;
        self.session
            .read()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))
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
        // If a deferred build is still in flight, join it so its session (and
        // any semantic indexer it started) is closed rather than detached.
        if let Ok(pending) = self.pending_build.get_mut()
            && let Some(handle) = pending.take()
            && let Ok(Ok((_, _, session))) = handle.join()
        {
            session.close_semantic();
            return;
        }
        let Ok(session) = self.session.get_mut() else {
            return;
        };
        if let Some(session) = session.take() {
            session.close_semantic();
        }
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
) -> Result<(Arc<dyn Project>, WorkspaceAnalyzer), String> {
    let _scope = profiling::scope("mcp_cold.analyzer_construction");
    let project = build_project(root, listing)?;
    let workspace = WorkspaceAnalyzer::build_persisted_for_service(
        Arc::clone(&project),
        AnalyzerConfig::default(),
    )
    .map_err(|error| format!("Failed to build persisted workspace: {error}"))?;
    prewarm_configured_semantic_models(project.root(), &workspace)?;
    Ok((project, workspace))
}

fn build_transient_workspace(
    root: PathBuf,
    listing: Option<Arc<WorkspaceFileListingCache>>,
) -> Result<(Arc<dyn Project>, WorkspaceAnalyzer), String> {
    let project = build_project(root, listing)?;
    let workspace =
        WorkspaceAnalyzer::build_for_service(Arc::clone(&project), AnalyzerConfig::default());
    prewarm_configured_semantic_models(project.root(), &workspace)?;
    Ok((project, workspace))
}

/// Assemble a ready `WorkspaceSession` from a built project + analyzer: wrap the
/// analyzer in an `Arc`, start the file watcher (per `update_strategy`), and
/// start the semantic indexer when enabled. Shared by the synchronous and
/// deferred constructors so both produce identical sessions.
fn assemble_session(
    project: Arc<dyn Project>,
    workspace: WorkspaceAnalyzer,
    update_strategy: UpdateStrategy,
    semantic_indexing: bool,
    watcher_starter: &WatcherStarter,
) -> Result<WorkspaceSession, String> {
    let document_root = Arc::new(
        WorkspaceRoot::open(project.root())
            .map_err(|error| format!("Failed to open workspace document root: {error}"))?,
    );
    let watcher = start_session_watcher(Arc::clone(&project), update_strategy, watcher_starter)?;
    let snapshot = Arc::new(workspace);
    // Pre-build the lazy Rust usage index off the request path (issue #1416)
    // unless the caller disables it. Large C++ workspaces can contain a large
    // vendored Rust tree. Warming every Rust reference context in those trees
    // competes with ordinary symbol requests and delays their first result.
    if rust_usage_warming_enabled() {
        let snapshot = Arc::clone(&snapshot);
        std::thread::Builder::new()
            .name("bifrost-usage-index-warm".to_string())
            .spawn(move || {
                let _scope = profiling::scope("mcp_cold.query_index_construction.rust_usage");
                snapshot.warm_rust_usage_analysis();
            })
            .map_err(|error| format!("Failed to spawn usage-index warm thread: {error}"))?;
    }
    #[cfg(feature = "nlp")]
    let semantic = maybe_start_semantic(semantic_indexing, &snapshot);
    #[cfg(not(feature = "nlp"))]
    let _ = semantic_indexing;
    Ok(WorkspaceSession {
        snapshot,
        document_root,
        watcher,
        index_warmer: IndexWarmer::new(),
        #[cfg(feature = "nlp")]
        semantic,
    })
}

/// Return whether the session should eagerly build the Rust usage graph.
///
/// The default keeps the interactive behavior for normal sessions. Benchmark
/// and symbol-only callers can set `BIFROST_WARM_USAGE_ANALYSIS=off` when a
/// large workspace contains unrelated Rust sources.
fn rust_usage_warming_enabled() -> bool {
    !matches!(
        std::env::var("BIFROST_WARM_USAGE_ANALYSIS").as_deref(),
        Ok("0") | Ok("off") | Ok("false") | Ok("disabled")
    )
}

fn start_session_watcher(
    project: Arc<dyn Project>,
    update_strategy: UpdateStrategy,
    watcher_starter: &WatcherStarter,
) -> Result<SessionWatcher, String> {
    match update_strategy {
        UpdateStrategy::WatchFiles => {
            let watcher = watcher_starter(Arc::clone(&project)).map_err(|error| {
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

fn active_workspace_result(root: &Path) -> Result<ToolOutput, SearchToolsServiceError> {
    let structured = serde_json::to_value(ActiveWorkspaceResult {
        workspace_path: root.display().to_string(),
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
        Arc::new(move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(WATCHER_FAILURE.to_string())
        })
    }

    fn unbound_watching_service(starter: WatcherStarter) -> SearchToolsService {
        SearchToolsService {
            root: RwLock::new(None),
            session: RwLock::new(None),
            workspace_generation: AtomicU64::new(0),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            typestate_summaries: RwLock::new(Arc::new(
                crate::analyzer::typestate::ProductionTypestateSummaryRepository::new(),
            )),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(None),
            update_strategy: UpdateStrategy::WatchFiles,
            semantic_indexing: false,
            watcher_starter: starter,
            diff_snapshot_object_dir: None,
        }
    }

    fn assert_watcher_error(error: &SearchToolsServiceError) {
        assert_eq!(error.code, SearchToolsServiceErrorCode::Internal);
        assert!(error.message.contains("Failed to start project watcher"));
        assert!(error.message.contains(WATCHER_FAILURE));
    }

    #[test]
    fn eager_watching_service_reports_watcher_startup_failure() {
        let (_temp, root) = workspace("Eager.java", "class Eager {}\n");
        let calls = Arc::new(AtomicUsize::new(0));

        let error = match SearchToolsService::new_with_strategy_and_watcher_starter(
            root,
            UpdateStrategy::WatchFiles,
            false,
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
            false,
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
            Arc::new(move |project| {
                calls.fetch_add(1, Ordering::SeqCst);
                startup_started_tx
                    .send(())
                    .expect("test should wait for watcher startup");
                release_startup_rx
                    .lock()
                    .unwrap()
                    .recv()
                    .expect("test should release watcher startup");
                ProjectChangeWatcher::start_polling_for_tests(project)
            })
        };
        let service = Arc::new(
            SearchToolsService::new_lazy_with_strategy_and_watcher_starter(
                root,
                UpdateStrategy::WatchFiles,
                false,
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
    fn issue_1296_run_policy_snapshot_deadline_returns_canonical_report() {
        let (_temp, root) = workspace("DeferredPolicy.java", "class DeferredPolicy {}\n");
        let (startup_started_tx, startup_started_rx) = mpsc::channel();
        let (release_startup_tx, release_startup_rx) = mpsc::sync_channel(1);
        let release_startup_rx = Arc::new(Mutex::new(release_startup_rx));
        let starter: WatcherStarter = Arc::new(move |project| {
            startup_started_tx
                .send(())
                .expect("test should observe watcher startup");
            release_startup_rx
                .lock()
                .expect("release lock")
                .recv_timeout(Duration::from_secs(5))
                .expect("test should release watcher startup");
            ProjectChangeWatcher::start_polling_for_tests(project)
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
            Ok(RunPolicyPreparation::Ready(_)) => {
                panic!("expired request should not join the deferred build")
            }
            Err(error) => panic!("deadline should return a canonical policy report: {error}"),
        };

        assert_eq!(result.status, "unreliable");
        assert_eq!(result.exit_status, POLICY_EXIT_UNRELIABLE);
        assert_eq!(result.report.schema_version(), 3);
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
        assert_eq!(
            result.report.execution().pending_policy_ids(),
            &[PolicyId::new("bifrost.correctness.dynamic-evaluation").unwrap()]
        );
        assert_eq!(
            result.report.diagnostics()[0].code(),
            PolicyReportDiagnosticCode::WorkspaceSnapshotDeadlineExceeded
        );
        assert_eq!(
            result.report.evaluation().suppression_document_state(),
            PolicySuppressionDocumentState::NotEvaluated
        );
        release_startup_tx
            .send(())
            .expect("release deferred watcher startup");
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
        let starter: WatcherStarter = Arc::new(move |project| {
            startup_started_tx
                .send(())
                .expect("test should observe watcher startup");
            release_startup_rx
                .lock()
                .expect("release lock")
                .recv_timeout(Duration::from_secs(5))
                .expect("test should release watcher startup");
            ProjectChangeWatcher::start_polling_for_tests(project)
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
            Arc::new(move |project| {
                starts.fetch_add(1, Ordering::SeqCst);
                startup_started_tx
                    .send(())
                    .expect("test should observe watcher startup");
                release_startup_rx
                    .lock()
                    .expect("release lock")
                    .recv_timeout(Duration::from_secs(5))
                    .expect("test should release watcher startup");
                ProjectChangeWatcher::start_polling_for_tests(project)
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
        let service =
            SearchToolsService::new_manual_without_semantic_index(root).expect("manual service");
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
        assert_eq!(structured["report"]["schema_version"], 3);
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
        let starter: WatcherStarter = Arc::new(move |project| {
            if project.root() == blocked_root {
                first_started_tx
                    .send(())
                    .expect("test should observe the first build");
                release_first_rx
                    .lock()
                    .expect("release lock")
                    .recv_timeout(Duration::from_secs(5))
                    .expect("test should release the first build");
                let watcher = ProjectChangeWatcher::start_polling_for_tests(project)?;
                first_finished_tx
                    .send(())
                    .expect("test should observe the first build finishing");
                Ok(watcher)
            } else {
                ProjectChangeWatcher::start_polling_for_tests(project)
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
            Arc::new(move |project| {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(WATCHER_FAILURE.to_string())
                } else {
                    ProjectChangeWatcher::start_polling_for_tests(project)
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
    fn deferred_build_install_schedules_background_query_index_warm() {
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
        warmer.wait_until_idle();
        assert!(snapshot.query_indexes_warm());
    }

    #[test]
    fn snapshot_reinstall_schedules_a_background_index_warm() {
        let (_temp, root) = workspace(
            "lib.rs",
            "trait Runnable {}\npub struct Worker;\nimpl Runnable for Worker {}\n",
        );
        let service = SearchToolsService::new_manual_without_semantic_index(root.clone()).unwrap();
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
        let service = SearchToolsService::new_transient_with_strategy_and_watcher_starter(
            root.clone(),
            UpdateStrategy::Manual,
            false,
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
        let starter: WatcherStarter = Arc::new(move |project| {
            if project.root() == failed_root {
                Err(WATCHER_FAILURE.to_string())
            } else {
                ProjectChangeWatcher::start_polling_for_tests(project)
            }
        });
        let service = SearchToolsService::new_transient_with_strategy_and_watcher_starter(
            old_root.clone(),
            UpdateStrategy::WatchFiles,
            false,
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
        let service = SearchToolsService::new_manual_for_project(project).unwrap();
        (temp, root, service)
    }

    fn make_java_store_stale(root: &Path) {
        let connection = rusqlite::Connection::open(analyzer_db_path(root)).unwrap();
        assert_eq!(
            connection
                .execute(
                    "UPDATE analysis_epochs SET generation = generation + 1 WHERE lang = 'java'",
                    [],
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn multi_language_store_failure_replaces_false_empty_tool_success() {
        let (_temp, root, service) = multi_language_service();

        let healthy = service
            .call_tool_value("get_symbol_locations", json!({"symbols": ["Model"]}))
            .unwrap();
        assert_eq!(healthy["locations"][0]["symbol"], "Model");

        make_java_store_stale(&root);

        let error = service
            .call_tool_value("get_symbol_locations", json!({"symbols": ["Model"]}))
            .unwrap_err();
        assert_eq!(error.code, SearchToolsServiceErrorCode::Internal);
        assert!(error.message.contains("get_symbol_locations"));
        assert!(error.message.contains("querying definition candidates"));
        assert!(error.message.contains("stale analyzer generation"));

        let error = service
            .call_tool_value(
                "search_symbols",
                json!({"patterns": ["Model"], "include_tests": true, "limit": 5}),
            )
            .unwrap_err();
        assert_eq!(error.code, SearchToolsServiceErrorCode::Internal);
        assert!(error.message.contains("search_symbols"));
        assert!(error.message.contains("searching symbol candidates"));
        assert!(error.message.contains("stale analyzer generation"));
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

    #[test]
    fn failed_shard_index_build_is_not_published_to_other_requests() {
        let (_temp, root, service) = multi_language_service();
        make_java_store_stale(&root);

        // The workspace definition view is a view over the two delegates' own
        // indexes, so one query attempts two shard builds: Python's succeeds
        // and is published, Java's fails against the stale store.
        let first_scope = service.snapshot_for_query().unwrap();
        first_scope.analyzer().global_usage_definition_index();
        assert!(first_scope.context.store_error().is_some());
        assert_eq!(
            first_scope
                .analyzer()
                .global_usage_definition_index_build_count_for_test(),
            2
        );
        assert!(
            first_scope
                .finish("first_failed_index_build", Ok(()))
                .is_err()
        );

        let retry_scope = service.snapshot_for_query().unwrap();
        retry_scope.analyzer().global_usage_definition_index();
        assert!(
            retry_scope.context.store_error().is_some(),
            "a failed shard build must not be published to later requests"
        );
        assert_eq!(
            retry_scope
                .analyzer()
                .global_usage_definition_index_build_count_for_test(),
            3,
            "the failing Java shard rebuilds while the healthy Python shard stays published"
        );
    }

    #[test]
    fn query_finish_preserves_handler_error_over_recorded_store_failure() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("Model.java"), "class Model {}\n").unwrap();
        let (_project, workspace) = build_transient_workspace(root, None).unwrap();
        let document_root =
            Arc::new(WorkspaceRoot::open(workspace.analyzer().project().root()).unwrap());
        let scope = WorkspaceQueryScope::new(Arc::new(workspace), document_root);
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
        let (project, workspace) = build_transient_workspace(root, None).unwrap();
        SearchToolsService {
            root: RwLock::new(Some(project.root().to_path_buf())),
            session: RwLock::new(Some(WorkspaceSession {
                snapshot: Arc::new(workspace),
                document_root: Arc::new(WorkspaceRoot::open(project.root()).unwrap()),
                watcher: SessionWatcher::Disabled,
                index_warmer: IndexWarmer::new(),
                #[cfg(feature = "nlp")]
                semantic: None,
            })),
            workspace_generation: AtomicU64::new(1),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            typestate_summaries: RwLock::new(Arc::new(
                crate::analyzer::typestate::ProductionTypestateSummaryRepository::new(),
            )),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(None),
            update_strategy: UpdateStrategy::WatchFiles,
            semantic_indexing: false,
            watcher_starter: production_watcher_starter(),
            diff_snapshot_object_dir: None,
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
        let (_project, workspace) = build_transient_workspace(root.clone(), None).unwrap();
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
        let (project, workspace) = build_transient_workspace(root.clone(), None).unwrap();
        let manual = SearchToolsService::new_manual_for_project(project).unwrap();
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
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            typestate_summaries: RwLock::new(Arc::new(
                crate::analyzer::typestate::ProductionTypestateSummaryRepository::new(),
            )),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(None),
            update_strategy: UpdateStrategy::Manual,
            semantic_indexing: false,
            watcher_starter: production_watcher_starter(),
            diff_snapshot_object_dir: None,
        }
    }

    fn cache_db_for(root: &Path) -> PathBuf {
        root.join(crate::gitblob::PROJECT_DIR_NAME)
            .join(crate::gitblob::CACHE_SUBDIR_NAME)
            .join(crate::cache_db::cache_db_file_name())
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
            build_persisted_workspace(canonical_primary.clone(), None).unwrap();

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
        let service =
            SearchToolsService::new_manual_without_semantic_index(temp.path().to_path_buf())
                .unwrap();
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
        let service =
            SearchToolsService::new_manual_without_semantic_index(temp.path().to_path_buf())
                .unwrap();
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
        let service =
            SearchToolsService::new_manual_without_semantic_index(temp.path().to_path_buf())
                .unwrap();
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
        let service =
            SearchToolsService::new_manual_without_semantic_index(temp.path().to_path_buf())
                .unwrap();
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
        let service =
            SearchToolsService::new_manual_without_semantic_index(temp.path().to_path_buf())
                .unwrap();
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
        let service =
            SearchToolsService::new_manual_without_semantic_index(temp.path().to_path_buf())
                .unwrap();

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
    use crate::analyzer::structural::{CodeQueryDiagnosticCode, ProtocolRef};
    use crate::analyzer::typestate::{ProtocolSpec, TypestateBindingPlan};
    use crate::cancellation::CancellationToken;
    use serde_json::json;

    const RESOURCE_LIFECYCLE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/typestate/resource-lifecycle.protocol.json"
    ));

    fn protocol_service() -> (tempfile::TempDir, SearchToolsService, ProtocolRef) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("main.ts"),
            "export function lifecycle(): void {}\n",
        )
        .unwrap();
        let service =
            SearchToolsService::new_manual_without_semantic_index(temp.path().to_path_buf())
                .unwrap();
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
            "schema_version": 4,
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
        let prepared_summaries = prepared.typestate_summary_lease.clone();

        service.advance_workspace_generation();
        let current_summaries = Arc::clone(
            &service
                .typestate_summaries
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        assert_eq!(prepared_summaries.generation(), 1);
        assert_eq!(current_summaries.generation(), Some(2));

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
        assert_eq!(prepared_summaries.generation(), 1);
        assert_eq!(current_summaries.generation(), Some(2));

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

        service.advance_workspace_generation();
        let summaries = Arc::clone(
            &service
                .typestate_summaries
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let counters = summaries.counters();
        assert!(counters.evictions > 0);
    }
}

#[cfg(all(test, feature = "nlp"))]
mod tests {
    use super::*;
    use crate::nlp::engine::FakeHashEmbedder;
    use crate::nlp::indexer::FakeEngineProvider;
    use std::time::Duration;

    #[test]
    fn service_close_closes_semantic_indexer() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Thing.java"),
            "public class Thing { public String value() { return \"value\"; } }\n",
        )
        .unwrap();
        let (_project, workspace) =
            build_persisted_workspace(dir.path().to_path_buf(), None).unwrap();
        let snapshot = Arc::new(workspace);
        let indexer = SemanticIndexer::start_with_provider(
            dir.path().to_path_buf(),
            snapshot.clone(),
            FakeEngineProvider {
                embedder: Arc::new(FakeHashEmbedder::new(16)),
            },
        );
        let service = SearchToolsService {
            root: RwLock::new(Some(dir.path().to_path_buf())),
            session: RwLock::new(Some(WorkspaceSession {
                snapshot,
                document_root: Arc::new(WorkspaceRoot::open(dir.path()).unwrap()),
                watcher: SessionWatcher::Disabled,
                index_warmer: IndexWarmer::new(),
                semantic: Some(indexer.clone()),
            })),
            workspace_generation: AtomicU64::new(1),
            query_protocols: RwLock::new(Default::default()),
            query_value_flows: RwLock::new(Default::default()),
            query_taint_results: RwLock::new(Default::default()),
            typestate_summaries: RwLock::new(Arc::new(
                crate::analyzer::typestate::ProductionTypestateSummaryRepository::new(),
            )),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            file_listing: RwLock::new(None),
            update_strategy: UpdateStrategy::WatchFiles,
            semantic_indexing: true,
            watcher_starter: production_watcher_starter(),
            diff_snapshot_object_dir: None,
        };

        service.close().unwrap();

        let err = indexer
            .wait_ready(Duration::from_secs(30))
            .expect_err("service close should close semantic indexer");
        assert_eq!(err, "semantic index closed");
    }

    #[test]
    fn missing_accelerator_disables_semantic_indexer_startup() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Thing.java"),
            "public class Thing { public String value() { return \"value\"; } }\n",
        )
        .unwrap();
        let (_project, workspace) =
            build_persisted_workspace(dir.path().to_path_buf(), None).unwrap();
        let snapshot = Arc::new(workspace);

        // No CUDA/Metal and no --force-semantic-cpu: the indexer must not start.
        let semantic = maybe_start_semantic_checked(true, &snapshot, || {
            Err("no CUDA or Metal accelerator detected".to_string())
        });

        assert!(semantic.is_none());
    }
}
