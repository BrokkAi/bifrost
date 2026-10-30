//! The shared workspace pack-activation document (`.bifrost/packs.json`).
//!
//! One schema-versioned document names the semantic-pack catalog location and
//! the discovered dependency ecosystems the workspace activates. When the
//! document is absent, the host uses the ambient default of every ecosystem
//! serving a language present in the workspace. A present document with an
//! empty `ecosystems` list explicitly disables that dependency-pack route.
//! The CLI policy runner and the MCP host both read this one
//! document, so every entry point applies the same dependency-pack selection
//! (#1868). A host may separately request the reviewed shipped packs selected
//! by intrinsic language evidence.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use brokk_bifrost_core::analyzer::config::PythonRuntimeEnvironmentConfig;
use brokk_bifrost_js_ts::imports::node_builtin_module;
use semver::Version;
use serde::Deserialize;

use crate::analyzer::semantic_model::{
    CatalogCoordinate, CatalogError, CatalogOpenMode, CatalogOptions, DependencyPackLimits,
    PendingDependencyPackAcquisition, RegisteredWorkspaceSemanticModel,
    SEMANTIC_PACK_CACHE_ROOT_ENV, SemanticModelActivationControl, SemanticModelActivationEvidence,
    SemanticModelActivationRequest, SemanticModelControlAction, SemanticModelControlScope,
    SemanticModelPackSelector, SemanticModelRuntimeLimits, SemanticPackCatalog,
    WORKSPACE_SEMANTIC_MODEL_DIRECTORY, WorkspaceSemanticModelOptions,
    WorkspaceSemanticModelRegistration, WorkspaceSemanticModelRegistrationError,
    open_default_semantic_pack_catalog, register_workspace_semantic_models,
};
use crate::analyzer::{
    AnalyzerConfig, AnalyzerQueryScope, DependencyPackActivationOutcome, DependencyPackEcosystem,
    DependencyPackWorkspaceContext, Language, QueryScope, WorkspaceAnalyzer,
};
use crate::gitblob::{CACHE_DIR_ENV, CACHE_ROOT_ENV};
use crate::workspace_document::{
    WorkspaceDocumentError, WorkspacePathError, WorkspaceRoot, fmt_json_decode_error,
    read_workspace_document, read_workspace_document_without_extension,
    validate_workspace_relative_path,
};

/// Conventional workspace-relative location of the pack-activation document.
pub const WORKSPACE_PACKS_DOCUMENT_PATH: &str = ".bifrost/packs.json";
/// Upper bound for the document itself.
pub const MAX_WORKSPACE_PACKS_DOCUMENT_BYTES: u64 = 256 * 1024;
/// Upper bound for the configured catalog path.
pub const MAX_WORKSPACE_PACKS_CATALOG_PATH_BYTES: usize = 1_024;

const WORKSPACE_PACKS_SCHEMA_VERSION: u32 = 1;
const MAX_JSON_ERROR_BYTES: usize = 512;

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

/// Register reviewed shipped packs when the facade installed a provider.
pub fn bootstrap_semantic_model_catalog(catalog: &SemanticPackCatalog) -> Result<bool, String> {
    let Some(bootstrap) = SEMANTIC_MODEL_CATALOG_BOOTSTRAP.get().copied() else {
        return Ok(false);
    };
    bootstrap(catalog)?;
    Ok(true)
}

/// Intrinsic language evidence selects shipped language/runtime packs without
/// pretending that the workspace declared an external dependency.
pub fn intrinsic_language_evidence(
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

/// SHA-256 of the RFC 8785 canonical JSON of the reviewed Python
/// process-input runtime profile the shipped pack pins.
const REVIEWED_PYTHON_PROCESS_INPUT_PROFILE_DIGEST: &str =
    "b95b6625659ac476f274bdb3a305f20f497727137dc85aa96e50a989d57d8afd";

/// Workspace evidence for the reviewed Python process-input contract.
///
/// The Node runtime-values packs pin one distribution, so a workspace has to
/// name that revision before its evidence exists. The Python contract is
/// different in kind: the standard-library reference specifies `os.environ` as
/// the process environment and `sys.argv` as the launch arguments for every
/// conforming implementation, on every platform, so the reviewed record names
/// no distribution at all. A workspace that contains Python states the profile
/// by containing Python, and the row below carries the profile configuration
/// and nothing else -- no package, no artifact digest -- because the reviewed
/// record makes no claim for either to bind.
pub fn python_process_input_evidence(
    workspace: &WorkspaceAnalyzer,
) -> Vec<SemanticModelActivationEvidence> {
    workspace
        .analyzer()
        .languages()
        .into_iter()
        .filter(|language| *language == Language::Python)
        .map(|language| SemanticModelActivationEvidence {
            language: language.config_label().to_owned(),
            ecosystem: intrinsic_ecosystem(language).to_owned(),
            package: None,
            module: None,
            toolchain: None,
            target: None,
            configuration: Some(REVIEWED_PYTHON_PROCESS_INPUT_PROFILE_DIGEST.to_owned()),
            artifact_sha256: None,
        })
        .collect()
}

/// Conventional workspace documents that pin the Node runtime revision.
const NODE_RUNTIME_DECLARATION_DOCUMENTS: [&str; 2] = [".nvmrc", ".node-version"];
/// Upper bound for one Node runtime declaration document. Real declarations are
/// a line or two; this only stops a hostile file from being read.
const MAX_NODE_RUNTIME_DECLARATION_BYTES: u64 = 1024 * 1024;

/// The one Node revision the shipped runtime-values packs review.
///
/// The reviewed packs embed the distribution-archive digest and the profile
/// configuration for exactly this revision, so a workspace declaration of any
/// other revision names no reviewed artifact and mints no evidence.
const REVIEWED_NODE_RUNTIME_VERSION: &str = "22.11.0";
/// SHA-256 of the reviewed Node distribution archive the shipped packs pin
/// (`node-v22.11.0.tar.gz`, per `semantic-packs/node/runtime-values/README.md`).
const REVIEWED_NODE_RUNTIME_ARTIFACT_DIGEST: &str =
    "24e5130fa7bc1eaab218a0c9cb05e03168fa381bb9e3babddc6a11f655799222";
/// SHA-256 of the RFC 8785 canonical JSON of the reviewed runtime profile the
/// shipped packs pin (Node linux/x64 main-realm CommonJS).
const REVIEWED_NODE_RUNTIME_PROFILE_DIGEST: &str =
    "70db7f8c799decb554bc25e8bf410079c8b377f2852ee2a982d56db40f054056";

/// Workspace evidence for the reviewed Node runtime the shipped runtime-values
/// packs model.
///
/// The shipped packs activate in-process with the exact Node artifact
/// coordinates, digest, and profile configuration their shard selector names
/// (#3329). Nothing on the workspace path minted those coordinates, so a
/// workspace running `bifrost` could enable a pack that decided perfectly
/// against a test fixture and never against the workspace (#3462).
///
/// A workspace that pins [`REVIEWED_NODE_RUNTIME_VERSION`] in its own manifest
/// or Node version document declares exactly that reviewed artifact, so this
/// route mints one evidence row per present JavaScript/TypeScript language. A
/// workspace that declares another revision, or nothing, mints no row and the
/// pack's selector stays unsatisfied with a reason naming what is missing.
/// All exact declarations must agree; conflicts emit a diagnostic and mint no
/// reviewed runtime evidence.
pub fn node_runtime_evidence(
    workspace: &WorkspaceAnalyzer,
) -> Vec<SemanticModelActivationEvidence> {
    let languages: Vec<Language> = workspace
        .analyzer()
        .languages()
        .into_iter()
        .filter(|language| matches!(language, Language::JavaScript | Language::TypeScript))
        .collect();
    if languages.is_empty() {
        return Vec::new();
    }
    if workspace_declared_node_version(workspace.analyzer().project().root()).as_deref()
        != Some(REVIEWED_NODE_RUNTIME_VERSION)
    {
        return Vec::new();
    }
    let artifact = format!("pkg:generic/nodejs.org/node@{REVIEWED_NODE_RUNTIME_VERSION}");
    languages
        .into_iter()
        .map(|language| SemanticModelActivationEvidence {
            language: language.config_label().to_owned(),
            ecosystem: intrinsic_ecosystem(language).to_owned(),
            package: Some(CatalogCoordinate {
                name: artifact.clone(),
                version: None,
            }),
            module: None,
            toolchain: None,
            target: None,
            configuration: Some(REVIEWED_NODE_RUNTIME_PROFILE_DIGEST.to_owned()),
            artifact_sha256: Some(REVIEWED_NODE_RUNTIME_ARTIFACT_DIGEST.to_owned()),
        })
        .collect()
}

/// Files read per bulk import query while collecting Node built-in imports.
const NODE_BUILTIN_IMPORT_SCAN_BATCH: usize = 512;

/// The Node built-in modules the workspace's JavaScript and TypeScript files
/// import, each with its importing language (#3464).
///
/// A built-in such as `fs` is the Node runtime's standard library. No npm
/// dependency declares it, so dependency discovery never names it, and a
/// report would otherwise say nothing about why `readFileSync` resolves to no
/// declaration. The result is bounded by Node's fixed built-in list; files are
/// read in batches and only the module names are kept.
pub fn imported_node_builtin_modules(
    workspace: &WorkspaceAnalyzer,
) -> BTreeSet<(Language, &'static str)> {
    let analyzer = workspace.analyzer();
    let mut modules = BTreeSet::new();
    let Some(provider) = analyzer.import_analysis_provider() else {
        return modules;
    };
    let query_scope = AnalyzerQueryScope::new(analyzer);
    for language in analyzer
        .languages()
        .into_iter()
        .filter(|language| matches!(language, Language::JavaScript | Language::TypeScript))
    {
        for files in analyzer
            .analyzed_files_for_language(language)
            .chunks(NODE_BUILTIN_IMPORT_SCAN_BATCH)
        {
            let imports = provider.import_infos_for_files(files).unwrap_or_else(|| {
                files
                    .iter()
                    .map(|file| {
                        (
                            file.clone(),
                            provider.import_info_of(query_scope.token(), file),
                        )
                    })
                    .collect()
            });
            modules.extend(
                imports
                    .values()
                    .flatten()
                    .filter_map(|import| import.path.as_ref()?.segments.first())
                    .filter_map(|specifier| node_builtin_module(specifier))
                    .map(|module| (language, module)),
            );
        }
    }
    modules
}

/// The exact Node revision the workspace declares, when it declares one.
///
/// `package.json` `engines.node` and `volta.node` are read as JSON fields, and
/// the two conventional version documents as one line of text. Every exact
/// declaration must agree; conflicting revisions name no reviewed runtime.
/// An absent,
/// unreadable, or unparsable declaration names no revision: a workspace still
/// has to say which runtime it runs.
fn workspace_declared_node_version(workspace_root: &Path) -> Option<String> {
    let root = WorkspaceRoot::open(workspace_root).ok()?;
    let versions: BTreeSet<_> = package_manifest_node_versions(&root)
        .into_iter()
        .chain(
            NODE_RUNTIME_DECLARATION_DOCUMENTS
                .iter()
                .filter_map(|document| node_version_document(&root, Path::new(document))),
        )
        .collect();
    if versions.len() > 1 {
        eprintln!(
            "bifrost: conflicting exact Node runtime declarations in {}: {versions:?}; no reviewed runtime evidence",
            workspace_root.display()
        );
        return None;
    }
    versions.into_iter().next()
}

/// `engines.node` and `volta.node` from the workspace's root `package.json`.
fn package_manifest_node_versions(root: &WorkspaceRoot) -> Vec<String> {
    // An absent, unreadable, malformed, or oversized manifest declares no
    // revision, which is the same answer as a manifest without a Node pin: the
    // pack stays incompatible and the report names the evidence that is
    // missing. Only a declaration can change the decision, so a read failure
    // cannot silently activate anything.
    let Ok(document) = read_workspace_document(
        root,
        Path::new("package.json"),
        &["json"],
        MAX_NODE_RUNTIME_DECLARATION_BYTES,
    ) else {
        return Vec::new();
    };
    let Ok(manifest) = serde_json::from_str::<serde_json::Value>(document.source()) else {
        return Vec::new();
    };
    [["engines", "node"], ["volta", "node"]]
        .into_iter()
        .filter_map(|[container, member]| {
            manifest
                .get(container)?
                .get(member)?
                .as_str()
                .and_then(exact_node_version)
        })
        .collect()
}

/// The revision one `.nvmrc` or `.node-version` document names.
fn node_version_document(root: &WorkspaceRoot, relative_path: &Path) -> Option<String> {
    let document = read_workspace_document_without_extension(
        root,
        relative_path,
        MAX_NODE_RUNTIME_DECLARATION_BYTES,
    )
    .ok()?;
    exact_node_version(document.source())
}

/// The revision a declaration names, when it names one exact revision.
///
/// Both `.nvmrc` and `.node-version` conventionally accept one optional leading
/// `v`. A range, a partial version, or any other text names no reviewed
/// artifact.
fn exact_node_version(declaration: &str) -> Option<String> {
    let trimmed = declaration.trim();
    let version = trimmed.strip_prefix('v').unwrap_or(trimmed);
    (!version.is_empty()
        && version
            .chars()
            .all(|character| character.is_ascii_digit() || character == '.'))
    .then(|| version.to_owned())
}

/// The normalized pack-activation configuration for one workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePacksConfig {
    schema_version: u32,
    catalog: Option<PathBuf>,
    ecosystems: Vec<DependencyPackEcosystem>,
    enable: Vec<String>,
    python_runtime_environments: Vec<PythonRuntimeEnvironmentConfig>,
}

impl WorkspacePacksConfig {
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Workspace-relative semantic-pack catalog root, when configured.
    /// When absent, activation uses the default versioned cache catalog for a
    /// persisted analyzer or an explicit cache relocation, and an ephemeral
    /// catalog otherwise.
    pub fn catalog(&self) -> Option<&Path> {
        self.catalog.as_deref()
    }

    /// The configured ecosystems, sorted and free of duplicates. An empty
    /// list explicitly disables ambient dependency-pack activation.
    pub fn ecosystems(&self) -> &[DependencyPackEcosystem] {
        &self.ecosystems
    }

    /// Pack ids the workspace opts into activating. A pack that sets
    /// `safety.review_required = true` stays selected but inactive until its id
    /// is named here (#1937).
    pub fn enable(&self) -> &[String] {
        &self.enable
    }

    pub fn python_runtime_environments(&self) -> &[PythonRuntimeEnvironmentConfig] {
        &self.python_runtime_environments
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePacksDocument {
    schema_version: u64,
    #[serde(default)]
    catalog: Option<String>,
    ecosystems: Vec<String>,
    #[serde(default)]
    enable: Vec<String>,
    #[serde(default)]
    python_runtime_environments: Vec<PythonRuntimeEnvironmentConfig>,
}

/// Parse and validate one pack-activation document from its JSON source.
pub fn parse_workspace_packs_config(
    source: &str,
) -> Result<WorkspacePacksConfig, WorkspacePacksDocumentError> {
    let wire: WirePacksDocument =
        serde_json::from_str(source).map_err(|error| WorkspacePacksDocumentError::JsonDecode {
            message: bounded_error_message(&error),
            line: error.line(),
            column: error.column(),
        })?;
    normalize_packs_document(wire).map_err(WorkspacePacksDocumentError::Validation)
}

fn normalize_packs_document(
    wire: WirePacksDocument,
) -> Result<WorkspacePacksConfig, WorkspacePacksValidationError> {
    if wire.schema_version != u64::from(WORKSPACE_PACKS_SCHEMA_VERSION) {
        return Err(WorkspacePacksValidationError::UnsupportedSchemaVersion {
            observed: wire.schema_version,
        });
    }
    let catalog = match wire.catalog {
        Some(raw) => {
            if raw.len() > MAX_WORKSPACE_PACKS_CATALOG_PATH_BYTES {
                return Err(WorkspacePacksValidationError::CatalogPathTooLong {
                    max_bytes: MAX_WORKSPACE_PACKS_CATALOG_PATH_BYTES,
                });
            }
            let validated = validate_workspace_relative_path(Path::new(&raw)).map_err(|error| {
                WorkspacePacksValidationError::InvalidCatalogPath {
                    reason: match error {
                        WorkspaceDocumentError::InvalidPath { reason, .. } => reason,
                        // validate_workspace_relative_path only reports
                        // InvalidPath; other variants cannot occur here.
                        _ => WorkspacePathError::Empty,
                    },
                }
            })?;
            Some(validated)
        }
        None => None,
    };
    let mut ecosystems = Vec::with_capacity(wire.ecosystems.len());
    for label in &wire.ecosystems {
        let Some(ecosystem) = DependencyPackEcosystem::from_label(label) else {
            return Err(WorkspacePacksValidationError::UnknownEcosystem {
                label: label.clone(),
            });
        };
        if ecosystems.contains(&ecosystem) {
            return Err(WorkspacePacksValidationError::DuplicateEcosystem { ecosystem });
        }
        ecosystems.push(ecosystem);
    }
    ecosystems.sort();
    let mut python_runtime_environments = wire.python_runtime_environments;
    for environment in &mut python_runtime_environments {
        // A component-normalized current directory explicitly covers the workspace.
        if environment
            .source_root
            .components()
            .all(|component| matches!(component, std::path::Component::CurDir))
            && !environment.source_root.as_os_str().is_empty()
        {
            environment.source_root = PathBuf::from(".");
        } else {
            environment.source_root = normalize_python_runtime_path(&environment.source_root)?;
        }
        for artifact in &mut environment.artifacts {
            artifact.archive_path = normalize_python_runtime_path(&artifact.archive_path)?;
            artifact.installed_root = normalize_python_runtime_path(&artifact.installed_root)?;
        }
    }
    Ok(WorkspacePacksConfig {
        schema_version: WORKSPACE_PACKS_SCHEMA_VERSION,
        catalog,
        ecosystems,
        enable: wire.enable,
        python_runtime_environments,
    })
}

fn normalize_python_runtime_path(path: &Path) -> Result<PathBuf, WorkspacePacksValidationError> {
    validate_workspace_relative_path(path).map_err(|error| {
        let WorkspaceDocumentError::InvalidPath { reason, .. } = error else {
            unreachable!("path validation only reports invalid paths");
        };
        WorkspacePacksValidationError::InvalidPythonRuntimePath {
            path: path.to_path_buf(),
            reason,
        }
    })
}

/// Load the conventional document beneath an opened workspace root.
/// An absent document returns `Ok(None)` so hosts can distinguish the ambient
/// default from an explicitly configured document.
pub fn load_workspace_packs_config(
    root: &WorkspaceRoot,
) -> Result<Option<WorkspacePacksConfig>, WorkspacePacksLoadError> {
    let document = match read_workspace_document(
        root,
        Path::new(WORKSPACE_PACKS_DOCUMENT_PATH),
        &["json"],
        MAX_WORKSPACE_PACKS_DOCUMENT_BYTES,
    ) {
        Ok(document) => document,
        Err(error) if error.is_not_found() => return Ok(None),
        Err(error) => return Err(WorkspacePacksLoadError::Workspace(error)),
    };
    parse_workspace_packs_config(document.source())
        .map(Some)
        .map_err(WorkspacePacksLoadError::Document)
}

/// Open `workspace_root` and load the conventional document beneath it.
pub fn load_workspace_packs_config_at(
    workspace_root: &Path,
) -> Result<Option<WorkspacePacksConfig>, WorkspacePacksLoadError> {
    let root = WorkspaceRoot::open(workspace_root).map_err(WorkspacePacksLoadError::Workspace)?;
    load_workspace_packs_config(&root)
}

fn bounded_error_message(error: &serde_json::Error) -> Box<str> {
    let message = error.to_string();
    if message.len() <= MAX_JSON_ERROR_BYTES {
        return message.into_boxed_str();
    }
    let mut end = MAX_JSON_ERROR_BYTES;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message[..end].into()
}

/// The outcome of one workspace activation transaction.
#[derive(Debug)]
pub struct WorkspacePacksActivation {
    /// The document ecosystems that serve a language present in this
    /// workspace, in `DependencyPackEcosystem::ALL` order.
    pub ecosystems: Vec<DependencyPackEcosystem>,
    /// The reviewed workspace-local models this transaction registered, in
    /// discovery order. Empty when the workspace-local route did not run or
    /// `.bifrost/semantic-models/` is absent.
    pub workspace_models: Vec<RegisteredWorkspaceSemanticModel>,
    pub outcome: DependencyPackActivationOutcome,
}

/// Where one activation transaction reads its semantic sources from.
///
/// The two roots are separate on purpose. A diff-base run activates against an
/// exported base tree, so its reviewed models come from that tree, while the
/// catalog stays machine-local infrastructure beneath the head workspace.
#[derive(Debug, Clone, Copy)]
pub struct WorkspaceActivationSources<'a> {
    /// The root a document-configured catalog path resolves beneath.
    pub catalog_root: &'a Path,
    /// The root `.bifrost/semantic-models/` is discovered beneath. `None`
    /// leaves the reviewed workspace-local route out of the transaction.
    pub workspace_model_root: Option<&'a Path>,
    /// The pack-activation document, when the workspace has one.
    pub config: Option<&'a WorkspacePacksConfig>,
    /// Include reviewed shipped packs selected by intrinsic language evidence.
    pub intrinsic_shipped_models: bool,
}

/// Why one activation transaction could not be built.
#[derive(Debug)]
pub enum WorkspaceActivationError {
    Catalog(CatalogError),
    /// The facade's reviewed shipped-pack provider failed registration.
    ShippedModels(String),
    /// The reviewed workspace-local route refused to contribute its models.
    WorkspaceModels(WorkspaceSemanticModelRegistrationError),
}

impl fmt::Display for WorkspaceActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catalog(error) => error.fmt(formatter),
            Self::ShippedModels(error) => error.fmt(formatter),
            Self::WorkspaceModels(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for WorkspaceActivationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Catalog(error) => Some(error),
            Self::ShippedModels(_) => None,
            Self::WorkspaceModels(error) => Some(error),
        }
    }
}

impl From<CatalogError> for WorkspaceActivationError {
    fn from(error: CatalogError) -> Self {
        Self::Catalog(error)
    }
}

/// Activate the document's configured ecosystems on `workspace` (#1868).
///
/// The catalog opens read-write at the document's configured location, so
/// locally generated packs persist across runs; an unconfigured catalog uses
/// the repository-local generated cache. Ecosystems that serve no language
/// present in the workspace are skipped: naming one is configuration, not
/// proof the workspace uses it.
/// Returns `Ok(None)` when no configured ecosystem is relevant.
///
/// This is the document route alone. Use
/// [`activate_workspace_semantic_sources`] to join the reviewed
/// `.bifrost/semantic-models/` route into the same transaction.
pub fn activate_workspace_packs(
    workspace: &WorkspaceAnalyzer,
    analyzer_config: &AnalyzerConfig,
    workspace_root: &Path,
    config: &WorkspacePacksConfig,
    cancellation: &crate::CancellationToken,
) -> Result<Option<WorkspacePacksActivation>, CatalogError> {
    match activate_workspace_semantic_sources(
        workspace,
        analyzer_config,
        WorkspaceActivationSources {
            catalog_root: workspace_root,
            workspace_model_root: None,
            config: Some(config),
            intrinsic_shipped_models: false,
        },
        cancellation,
    ) {
        Ok(activation) => Ok(activation),
        Err(WorkspaceActivationError::Catalog(error)) => Err(error),
        // Unreachable: the shipped-model route is switched off above.
        Err(WorkspaceActivationError::ShippedModels(error)) => Err(CatalogError::Integrity(error)),
        // Unreachable: the reviewed workspace-local route is switched off
        // above, and it is the only producer of this variant.
        Err(WorkspaceActivationError::WorkspaceModels(error)) => {
            Err(CatalogError::Integrity(error.to_string()))
        }
    }
}

/// Activate every semantic source selected for one workspace, as one transaction.
///
/// The dependency, reviewed workspace-local, and reviewed intrinsic routes feed
/// one activation request, because they have to: the resolver publishes exactly
/// one active model set onto an analyzer, so running the routes separately would
/// leave later routes overwriting earlier ones.
///
/// - The pack-activation document names the dependency ecosystems and the
///   catalog, and its `enable` list supplies the review controls. It may also
///   enable a reviewed workspace-local pack by id. An absent document selects
///   every ecosystem serving a language present in the workspace; an empty
///   configured list selects none.
/// - `.bifrost/semantic-models/` supplies the reviewed models the repository
///   checked in beside its policies. Their presence is the opt-in; an absent
///   directory contributes nothing.
///
/// Returns `Ok(None)` when none of the selected routes contributes anything.
pub fn activate_workspace_semantic_sources(
    workspace: &WorkspaceAnalyzer,
    analyzer_config: &AnalyzerConfig,
    sources: WorkspaceActivationSources<'_>,
    cancellation: &crate::CancellationToken,
) -> Result<Option<WorkspacePacksActivation>, WorkspaceActivationError> {
    let ecosystems = workspace_pack_ecosystems(workspace, sources.config);
    let workspace_models_present = sources.workspace_model_root.is_some_and(|root| {
        std::fs::symlink_metadata(root.join(WORKSPACE_SEMANTIC_MODEL_DIRECTORY)).is_ok()
    });
    if ecosystems.is_empty() && !workspace_models_present && !sources.intrinsic_shipped_models {
        return Ok(None);
    }
    let catalog = {
        let _scope = crate::profiling::scope("semantic_pack.open_catalog");
        match sources.config.and_then(WorkspacePacksConfig::catalog) {
            Some(relative) => SemanticPackCatalog::open(
                &sources.catalog_root.join(relative),
                CatalogOpenMode::ReadWrite,
                CatalogOptions::default(),
            )?,
            None => open_ambient_semantic_pack_catalog(
                workspace,
                sources.catalog_root,
                CatalogOptions::default(),
            )?,
        }
    };
    activate_workspace_semantic_sources_in_catalog(
        workspace,
        analyzer_config,
        &catalog,
        sources,
        &[],
        cancellation,
    )
}

/// Open the omitted semantic-pack catalog using the analyzer's actual
/// persistence decision.
///
/// An explicitly ephemeral analyzer must not leave generated state in the
/// checkout merely because semantic-pack bootstrap needs a writable catalog.
/// Explicit cache relocation is still an opt-in to durable reuse, and a
/// persisted analyzer keeps the ordinary versioned catalog beside its store.
pub fn open_ambient_semantic_pack_catalog(
    workspace: &WorkspaceAnalyzer,
    workspace_root: &Path,
    options: CatalogOptions,
) -> Result<SemanticPackCatalog, CatalogError> {
    let persistent_cache_requested = [SEMANTIC_PACK_CACHE_ROOT_ENV, CACHE_DIR_ENV, CACHE_ROOT_ENV]
        .into_iter()
        .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()));
    if workspace.persisted_store_path().is_none() && !persistent_cache_requested {
        SemanticPackCatalog::open_ephemeral(options)
    } else {
        open_default_semantic_pack_catalog(workspace_root, options)
    }
}

// Workspace construction can deliberately disable dependency discovery for a
// lightweight host phase. Activation has its own discovery settings; retain
// those while carrying the source bindings loaded from the workspace document.
fn activation_config_with_source_toolchains<'a>(
    workspace: &WorkspaceAnalyzer,
    activation_config: &'a AnalyzerConfig,
    packs_config: Option<&WorkspacePacksConfig>,
) -> Cow<'a, AnalyzerConfig> {
    let bindings = workspace
        .config()
        .map(|config| {
            config
                .jvm
                .standard_library_discovery
                .source_toolchains
                .as_slice()
        })
        .unwrap_or_default();
    let python_bindings = packs_config
        .map(WorkspacePacksConfig::python_runtime_environments)
        .unwrap_or_default();
    if bindings.iter().all(|binding| {
        activation_config
            .jvm
            .standard_library_discovery
            .source_toolchains
            .contains(binding)
    }) && python_bindings.iter().all(|binding| {
        activation_config
            .python
            .runtime_environments
            .contains(binding)
    }) {
        return Cow::Borrowed(activation_config);
    }
    let mut config = activation_config.clone();
    let merged = &mut config.jvm.standard_library_discovery.source_toolchains;
    for binding in bindings {
        if !merged.contains(binding) {
            merged.push(binding.clone());
        }
    }
    for binding in python_bindings {
        if !config.python.runtime_environments.contains(binding) {
            config.python.runtime_environments.push(binding.clone());
        }
    }
    Cow::Owned(config)
}

/// Activate all semantic sources against a caller-opened catalog.
///
/// Hosts that own a reviewed catalog bootstrap can register it before calling
/// this function and supply bounded intrinsic or host-derived evidence. The
/// catalog, workspace-local models, and dependency ecosystems still publish
/// through one activation request and one analyzer overlay.
pub fn activate_workspace_semantic_sources_in_catalog(
    workspace: &WorkspaceAnalyzer,
    analyzer_config: &AnalyzerConfig,
    catalog: &SemanticPackCatalog,
    sources: WorkspaceActivationSources<'_>,
    additional_evidence: &[SemanticModelActivationEvidence],
    cancellation: &crate::CancellationToken,
) -> Result<Option<WorkspacePacksActivation>, WorkspaceActivationError> {
    let Some(prelude) =
        workspace_activation_prelude(workspace, catalog, &sources, additional_evidence)?
    else {
        return Ok(None);
    };
    let WorkspaceActivationPrelude {
        ecosystems,
        workspace_models,
        evidence,
        controls,
    } = prelude;
    let activation = semantic_model_activation_request(evidence, controls);
    // An empty ecosystem list still resolves: the dependency loop simply has
    // nothing to discover, and the request's workspace evidence is what
    // selects. That keeps one code path for all routes.
    let outcome = workspace.activate_dependency_packs(
        &activation_config_with_source_toolchains(workspace, analyzer_config, sources.config),
        &ecosystems,
        DependencyPackWorkspaceContext {
            catalog,
            persistence: None,
            activation: &activation,
            limits: DependencyPackLimits::default(),
            cancellation,
        },
    );
    Ok(Some(WorkspacePacksActivation {
        ecosystems,
        workspace_models,
        outcome,
    }))
}

/// The outcome of the installed-pack stage of one workspace activation
/// transaction: the published interim activation plus every dependency whose
/// exact acquisition remains for the full stage.
#[derive(Debug)]
pub struct InstalledWorkspacePacksActivation {
    pub activation: WorkspacePacksActivation,
    pub pending: Vec<PendingDependencyPackAcquisition>,
}

/// The installed-pack stage of [`activate_workspace_semantic_sources_in_catalog`]
/// (issue #3401, the #3372 family): the same catalog bootstrap, workspace-local
/// registration, and dependency discovery, but dependency preparation resolves
/// only against packs already installed in the catalog -- nothing is fetched,
/// verified, extracted, read as a dependency artifact, or generated from a
/// local toolchain. Dependencies that stage cannot settle come back in
/// `pending`; running the full transaction afterwards reproduces exactly the
/// activation the un-staged path would have published.
pub fn activate_installed_workspace_semantic_sources_in_catalog(
    workspace: &WorkspaceAnalyzer,
    analyzer_config: &AnalyzerConfig,
    catalog: &SemanticPackCatalog,
    sources: WorkspaceActivationSources<'_>,
    additional_evidence: &[SemanticModelActivationEvidence],
    cancellation: &crate::CancellationToken,
) -> Result<Option<InstalledWorkspacePacksActivation>, WorkspaceActivationError> {
    let Some(prelude) =
        workspace_activation_prelude(workspace, catalog, &sources, additional_evidence)?
    else {
        return Ok(None);
    };
    let WorkspaceActivationPrelude {
        ecosystems,
        workspace_models,
        evidence,
        controls,
    } = prelude;
    let activation = semantic_model_activation_request(evidence, controls);
    let installed = workspace.activate_installed_dependency_packs(
        &activation_config_with_source_toolchains(workspace, analyzer_config, sources.config),
        &ecosystems,
        DependencyPackWorkspaceContext {
            catalog,
            persistence: None,
            activation: &activation,
            limits: DependencyPackLimits::default(),
            cancellation,
        },
    );
    Ok(Some(InstalledWorkspacePacksActivation {
        activation: WorkspacePacksActivation {
            ecosystems,
            workspace_models,
            outcome: installed.outcome,
        },
        pending: installed.pending,
    }))
}

/// The sources every workspace activation transaction assembles the same way:
/// the selected ecosystems, the registered workspace-local models, and the
/// activation request's evidence and controls. `None` is the shared early
/// return of both transaction kinds: no selected route contributes anything.
struct WorkspaceActivationPrelude {
    ecosystems: Vec<DependencyPackEcosystem>,
    workspace_models: Vec<RegisteredWorkspaceSemanticModel>,
    evidence: Vec<SemanticModelActivationEvidence>,
    controls: Vec<SemanticModelActivationControl>,
}

fn semantic_model_activation_request(
    evidence: Vec<SemanticModelActivationEvidence>,
    controls: Vec<SemanticModelActivationControl>,
) -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        approximate_standard_libraries: Vec::new(),
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION"))
            .expect("package version must be semver"),
        evidence,
        controls,
        limits: SemanticModelRuntimeLimits::default(),
    }
}

fn workspace_activation_prelude(
    workspace: &WorkspaceAnalyzer,
    catalog: &SemanticPackCatalog,
    sources: &WorkspaceActivationSources<'_>,
    additional_evidence: &[SemanticModelActivationEvidence],
) -> Result<Option<WorkspaceActivationPrelude>, WorkspaceActivationError> {
    let ecosystems = workspace_pack_ecosystems(workspace, sources.config);
    // Does this workspace opt into the reviewed route at all? Presence of the
    // directory is the whole opt-in, and asking costs one stat. Discovery
    // asks again and properly, rejecting a symlink or a non-directory; an
    // absent directory reaches the same answer either way, so nothing is
    // weakened by asking early. What it buys is not opening a catalog for a
    // workspace that has nothing to put in one.
    let workspace_model_root = sources.workspace_model_root.filter(|root| {
        std::fs::symlink_metadata(root.join(WORKSPACE_SEMANTIC_MODEL_DIRECTORY)).is_ok()
    });
    // Nothing to publish when the caller selected no dependency, workspace,
    // host-evidence, or intrinsic route.
    if ecosystems.is_empty()
        && workspace_model_root.is_none()
        && additional_evidence.is_empty()
        && !sources.intrinsic_shipped_models
    {
        return Ok(None);
    }
    let shipped_models = {
        let _scope = crate::profiling::scope("semantic_pack.bootstrap_shipped_models");
        if sources.intrinsic_shipped_models {
            bootstrap_semantic_model_catalog(catalog)
                .map_err(WorkspaceActivationError::ShippedModels)?
        } else {
            false
        }
    };
    // The reviewed workspace-local models join the same catalog handle and the
    // same evidence, before the dependency route resolves. A discovery,
    // compile, or registration failure aborts the transaction: a checked-in
    // model that quietly fails to load would decide verdicts by its absence
    // (#2493).
    let registration = match workspace_model_root {
        Some(model_root) => register_workspace_semantic_models(
            model_root,
            catalog,
            WorkspaceSemanticModelOptions::default(),
        )
        .map_err(WorkspaceActivationError::WorkspaceModels)?,
        None => WorkspaceSemanticModelRegistration::default(),
    };
    if ecosystems.is_empty()
        && registration.models.is_empty()
        && additional_evidence.is_empty()
        && !shipped_models
    {
        return Ok(None);
    }
    // A pack declaring `safety.review_required` needs an explicit compatible
    // `Enable` control keyed by pack id --
    // matching evidence alone leaves it selected but inactive
    // (`ReviewRequired`). The document's `enable` list is that control,
    // matching the in-process control build in `owasp_benchmark.rs` (#1937).
    // A reviewed workspace-local pack id is nameable there too.
    let controls = sources
        .config
        .map(WorkspacePacksConfig::enable)
        .unwrap_or_default()
        .iter()
        .map(|pack_id| SemanticModelActivationControl {
            scope: SemanticModelControlScope::Workspace,
            action: SemanticModelControlAction::Enable,
            selector: SemanticModelPackSelector {
                pack_id: pack_id.clone(),
                version: None,
                manifest_digest: None,
            },
        })
        .collect();
    let mut evidence = additional_evidence.to_vec();
    evidence.extend(registration.evidence);
    if shipped_models {
        evidence.extend(intrinsic_language_evidence(workspace));
        evidence.extend(node_runtime_evidence(workspace));
        evidence.extend(python_process_input_evidence(workspace));
    }
    Ok(Some(WorkspaceActivationPrelude {
        ecosystems,
        workspace_models: registration.models,
        evidence,
        controls,
    }))
}

/// Resolve the dependency ecosystems one host will attempt for this analyzer.
///
/// Keeping this projection beside the activation transaction lets hosts
/// retain an exact attempted set even when catalog opening or activation fails.
pub fn workspace_pack_ecosystems(
    workspace: &WorkspaceAnalyzer,
    config: Option<&WorkspacePacksConfig>,
) -> Vec<DependencyPackEcosystem> {
    let languages = workspace.analyzer().languages();
    config
        .map(|config| config.ecosystems().to_vec())
        .unwrap_or_else(|| DependencyPackEcosystem::ALL.to_vec())
        .into_iter()
        .filter(|ecosystem| {
            ecosystem
                .languages()
                .iter()
                .any(|language| languages.contains(language))
        })
        .collect()
}

#[derive(Debug)]
pub enum WorkspacePacksLoadError {
    Workspace(WorkspaceDocumentError),
    Document(WorkspacePacksDocumentError),
}

impl fmt::Display for WorkspacePacksLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Workspace(error) => error.fmt(formatter),
            Self::Document(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for WorkspacePacksLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Workspace(error) => Some(error),
            Self::Document(error) => Some(error),
        }
    }
}

#[derive(Debug)]
pub enum WorkspacePacksDocumentError {
    JsonDecode {
        message: Box<str>,
        line: usize,
        column: usize,
    },
    Validation(WorkspacePacksValidationError),
}

impl fmt::Display for WorkspacePacksDocumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JsonDecode {
                message,
                line,
                column,
            } => fmt_json_decode_error(formatter, "packs", message, *line, *column),
            Self::Validation(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for WorkspacePacksDocumentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::JsonDecode { .. } => None,
            Self::Validation(error) => Some(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspacePacksValidationError {
    UnsupportedSchemaVersion {
        observed: u64,
    },
    UnknownEcosystem {
        label: String,
    },
    DuplicateEcosystem {
        ecosystem: DependencyPackEcosystem,
    },
    CatalogPathTooLong {
        max_bytes: usize,
    },
    InvalidCatalogPath {
        reason: WorkspacePathError,
    },
    InvalidPythonRuntimePath {
        path: PathBuf,
        reason: WorkspacePathError,
    },
}

impl fmt::Display for WorkspacePacksValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion { observed } => write!(
                formatter,
                "packs document schema_version {observed} is not supported; expected {WORKSPACE_PACKS_SCHEMA_VERSION}"
            ),
            Self::UnknownEcosystem { label } => {
                let known = DependencyPackEcosystem::ALL
                    .iter()
                    .map(|ecosystem| ecosystem.label())
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(
                    formatter,
                    "packs document names unknown ecosystem {label:?}; known ecosystems: {known}"
                )
            }
            Self::DuplicateEcosystem { ecosystem } => write!(
                formatter,
                "packs document names ecosystem {:?} more than once",
                ecosystem.label()
            ),
            Self::CatalogPathTooLong { max_bytes } => write!(
                formatter,
                "packs document catalog path exceeds {max_bytes} bytes"
            ),
            Self::InvalidPythonRuntimePath { path, reason } => write!(
                formatter,
                "packs document Python runtime path {path:?} is invalid: {reason}"
            ),
            Self::InvalidCatalogPath { reason } => {
                write!(
                    formatter,
                    "packs document catalog path is invalid: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for WorkspacePacksValidationError {}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;
    use std::fs;

    use tempfile::TempDir;

    // The analysis-only test binary deliberately links no language adapters.
    // This fake supplies only the languages/configuration the pack boundary reads.
    #[derive(Clone)]
    pub(crate) struct CatalogWorkspace {
        pub(crate) project: std::sync::Arc<dyn crate::Project>,
        pub(crate) language: Language,
        pub(crate) index:
            Option<std::sync::Arc<dyn crate::analyzer::read_verification::WorkspaceFactIndex>>,
    }
    impl crate::analyzer::CodeUnitIndex for CatalogWorkspace {
        fn project(&self) -> &dyn crate::Project {
            self.project.as_ref()
        }
        fn languages(&self) -> BTreeSet<Language> {
            BTreeSet::from([self.language])
        }
        fn all_declarations(&self) -> Box<dyn Iterator<Item = crate::CodeUnit> + '_> {
            Box::new(std::iter::empty())
        }
        fn search_definitions(&self, _: &str, _: bool) -> BTreeSet<crate::CodeUnit> {
            unimplemented!()
        }
        fn enclosing_code_unit(
            &self,
            _: &crate::ProjectFile,
            _: &crate::Range,
        ) -> Option<crate::CodeUnit> {
            unimplemented!()
        }
        fn enclosing_code_unit_for_lines(
            &self,
            _: &crate::ProjectFile,
            _: usize,
            _: usize,
        ) -> Option<crate::CodeUnit> {
            unimplemented!()
        }
        fn get_skeleton(&self, _: &crate::CodeUnit) -> Option<String> {
            unimplemented!()
        }
        fn get_skeleton_header(&self, _: &crate::CodeUnit) -> Option<String> {
            unimplemented!()
        }
        fn get_sources(&self, _: &crate::CodeUnit, _: bool) -> BTreeSet<String> {
            unimplemented!()
        }
    }
    impl crate::analyzer::IAnalyzer for CatalogWorkspace {
        fn workspace_fact_indexes(
            &self,
        ) -> Vec<&dyn crate::analyzer::read_verification::WorkspaceFactIndex> {
            self.index.iter().map(|index| index.as_ref()).collect()
        }
        fn update(&self, _: &BTreeSet<crate::ProjectFile>) -> Self {
            unimplemented!()
        }
        fn update_all(&self) -> Self {
            unimplemented!()
        }
        fn is_access_expression(&self, _: &crate::ProjectFile, _: usize, _: usize) -> bool {
            unimplemented!()
        }
        fn find_nearest_declaration(
            &self,
            _: &crate::ProjectFile,
            _: usize,
            _: usize,
            _: &str,
        ) -> Option<crate::analyzer::DeclarationInfo> {
            unimplemented!()
        }
    }
    impl crate::analyzer::semantic::ProgramSemanticsProvider for CatalogWorkspace {
        fn current_artifact_source(
            &self,
            _: &crate::ProjectFile,
            _: usize,
        ) -> Result<
            Option<crate::analyzer::semantic::SemanticArtifactSourceSnapshot>,
            crate::analyzer::semantic::SemanticProviderError,
        > {
            unimplemented!()
        }
        fn materialize(
            &self,
            _: &crate::ProjectFile,
            _: &mut crate::analyzer::semantic::SemanticRequest<'_>,
        ) -> Result<
            crate::analyzer::semantic::SemanticOutcome<
                std::sync::Arc<crate::analyzer::semantic::SemanticArtifact>,
            >,
            crate::analyzer::semantic::SemanticProviderError,
        > {
            unimplemented!()
        }
    }
    impl crate::analyzer::multi_analyzer::LanguageAnalyzer for CatalogWorkspace {
        fn analyzer(&self) -> &dyn crate::analyzer::IAnalyzer {
            self
        }
        fn program_semantics_provider(
            &self,
        ) -> &dyn crate::analyzer::semantic::ProgramSemanticsProvider {
            self
        }
        fn clone_with_project(
            &self,
            _: std::sync::Arc<dyn crate::Project>,
        ) -> Box<dyn crate::analyzer::multi_analyzer::LanguageAnalyzer> {
            unimplemented!()
        }
        fn clone_for_index_warm(
            &self,
            _: std::sync::Arc<dyn crate::Project>,
        ) -> Box<dyn crate::analyzer::multi_analyzer::LanguageAnalyzer> {
            unimplemented!()
        }
        fn import_analysis_provider(&self) -> Option<&dyn crate::analyzer::ImportAnalysisProvider> {
            None
        }
        fn type_hierarchy_provider(&self) -> Option<&dyn crate::analyzer::TypeHierarchyProvider> {
            None
        }
        fn type_alias_provider(&self) -> Option<&dyn crate::analyzer::TypeAliasProvider> {
            None
        }
        fn test_detection_provider(&self) -> Option<&dyn crate::analyzer::TestDetectionProvider> {
            None
        }
        fn update(
            &self,
            _: &BTreeSet<crate::ProjectFile>,
        ) -> Box<dyn crate::analyzer::multi_analyzer::LanguageAnalyzer> {
            unimplemented!()
        }
        fn update_all_with_progress(
            &self,
            _: Option<crate::analyzer::BuildProgress>,
        ) -> Box<dyn crate::analyzer::multi_analyzer::LanguageAnalyzer> {
            unimplemented!()
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn clone_box(&self) -> Box<dyn crate::analyzer::multi_analyzer::LanguageAnalyzer> {
            Box::new(self.clone())
        }
    }
    fn workspace_at(root: &Path, config: AnalyzerConfig) -> WorkspaceAnalyzer {
        use crate::analyzer::multi_analyzer::{
            AnalyzerDelegate, MultiAnalyzer, WorkspaceBuildContext,
        };
        let project: std::sync::Arc<dyn crate::Project> = std::sync::Arc::new(
            crate::TestProject::from_root_with_inferred_languages(root).unwrap(),
        );
        let delegates = project
            .analyzer_languages()
            .into_iter()
            .map(|language| {
                (
                    language,
                    AnalyzerDelegate::new(CatalogWorkspace {
                        project: project.clone(),
                        language,
                        index: None,
                    }),
                )
            })
            .collect();
        let store =
            crate::analyzer::tree_sitter_analyzer::ephemeral_store_context(project.as_ref())
                .unwrap();
        let context = std::sync::Arc::new(WorkspaceBuildContext::new(project, config, store, None));
        WorkspaceAnalyzer::Multi(Box::new(MultiAnalyzer::new_for_workspace(
            delegates, context,
        )))
    }

    #[test]
    #[hardwon(
        "97a35feae74c: quicksilver round 12 on brokk-bifrost-analysis: conflicting Node pins claimed a reviewed runtime"
    )]
    fn node_runtime_declarations_must_agree_across_all_documents() {
        for (engines, volta, nvmrc, node_version, expected) in [
            (Some("22.11.0"), Some("20.11.0"), None, None, false),
            (Some("20.11.0"), Some("22.11.0"), None, None, false),
            (Some("22.11.0"), None, Some("20.11.0"), None, false),
            (None, None, Some("22.11.0"), Some("20.11.0"), false),
            (
                Some("22.11.0"),
                Some("v22.11.0"),
                Some("22.11.0"),
                Some("v22.11.0"),
                true,
            ),
            (None, None, None, Some("22.11.0"), true),
        ] {
            let temp = TempDir::new().unwrap();
            fs::write(temp.path().join("app.js"), "const value = 1;").unwrap();
            fs::write(temp.path().join("app.ts"), "const value: number = 1;").unwrap();
            fs::write(
                temp.path().join("package.json"),
                serde_json::json!({
                    "engines": {"node": engines}, "volta": {"node": volta}
                })
                .to_string(),
            )
            .unwrap();
            for (path, version) in [(".nvmrc", nvmrc), (".node-version", node_version)] {
                if let Some(version) = version {
                    fs::write(temp.path().join(path), version).unwrap();
                }
            }
            let workspace = workspace_at(temp.path(), AnalyzerConfig::default());
            let evidence = node_runtime_evidence(&workspace);
            assert_eq!(
                evidence
                    .iter()
                    .map(|row| row.language.as_str())
                    .collect::<BTreeSet<_>>(),
                if expected {
                    BTreeSet::from(["javascript", "typescript"])
                } else {
                    BTreeSet::new()
                },
                "engines={engines:?}, volta={volta:?}, nvmrc={nvmrc:?}, node-version={node_version:?}"
            );
        }
    }

    // Synthetic engine-only catalog fixtures, not product pack content.
    fn bootstrap_intrinsic_fixtures(catalog: &SemanticPackCatalog) -> Result<(), String> {
        use crate::analyzer::semantic_model::dependency::test_support::{
            compiled_pack, install_fixture_pack,
        };
        for (language, ecosystem) in [("rust", "cargo"), ("python", "pypi")] {
            let source = serde_json::json!({
                "schema_version": 2,
                "pack_id": format!("test.intrinsic-{language}"), "version": "1.0.0",
                "producer": {"name": "engine-test", "version": "1.0.0"},
                "language": language, "ecosystem": ecosystem,
                "compatibility": {"bifrost": ">=0.8.0, <1.0.0"},
                "provenance": {"source": "synthetic engine integration fixture"},
                "license": "Apache-2.0", "completeness": "complete",
                "safety": {"generated_code_only": false, "review_required": false},
                "shards": [{"id": "declarations", "activation": [{}], "payload": {
                    "kind": "declaration_facts", "types": [{
                        "id": "test.type", "name": "IntrinsicFixture", "type_kind": "class",
                        "visibility": "public", "type_parameters": [], "hierarchy": [],
                        "aliases": [], "extension_surfaces": [],
                        "locator": {"kind": "artifact", "path": "fixture", "symbol": "IntrinsicFixture"}
                    }], "members": [], "relations": []
                }}]
            });
            install_fixture_pack(catalog, &compiled_pack(&source.to_string()))?;
        }
        Ok(())
    }

    #[test]
    fn intrinsic_catalog_selection_is_multilingual_and_document_route_is_opt_in() {
        use crate::analyzer::semantic_model::{
            SemanticModelActivationStatus, SemanticModelRuntimeOutcome,
        };
        install_semantic_model_catalog_bootstrap(bootstrap_intrinsic_fixtures).unwrap();
        let config =
            parse_workspace_packs_config(r#"{"schema_version":1,"ecosystems":[]}"#).unwrap();
        for files in [
            [("app.rs", "fn main() {}"), ("app.py", "pass")],
            [("app.py", "pass"), ("app.rs", "fn main() {}")],
        ] {
            let temp = TempDir::new().unwrap();
            for (path, source) in files {
                fs::write(temp.path().join(path), source).unwrap();
            }
            let workspace = workspace_at(temp.path(), AnalyzerConfig::default());
            let cancellation = crate::CancellationToken::new();
            assert!(
                activate_workspace_packs(
                    &workspace,
                    &AnalyzerConfig::default(),
                    temp.path(),
                    &config,
                    &cancellation
                )
                .unwrap()
                .is_none()
            );
            let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
            let result = activate_workspace_semantic_sources_in_catalog(
                &workspace,
                &AnalyzerConfig::default(),
                &catalog,
                WorkspaceActivationSources {
                    catalog_root: temp.path(),
                    workspace_model_root: None,
                    config: Some(&config),
                    intrinsic_shipped_models: true,
                },
                &[],
                &cancellation,
            )
            .unwrap()
            .unwrap();
            let Some(SemanticModelRuntimeOutcome::Ready { active, .. }) = result.outcome.runtime
            else {
                panic!("{result:?}");
            };
            let selected = active
                .activation_report()
                .explanations
                .iter()
                .filter(|entry| entry.status == SemanticModelActivationStatus::Active)
                .filter_map(|entry| entry.pack_id.as_deref())
                .collect::<BTreeSet<_>>();
            assert_eq!(
                selected,
                BTreeSet::from(["test.intrinsic-python", "test.intrinsic-rust"])
            );
        }
    }

    #[test]
    fn source_toolchain_activation_preserves_partially_premerged_bindings() {
        use brokk_bifrost_core::analyzer::config::JvmSourceToolchainBinding;
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("App.java"), "class App {}").unwrap();
        let bindings = [
            JvmSourceToolchainBinding::new(PathBuf::from("old"), PathBuf::from("jdk21")),
            JvmSourceToolchainBinding::new(PathBuf::from("new"), PathBuf::from("jdk22")),
        ];
        for bindings in [bindings.to_vec(), bindings.into_iter().rev().collect()] {
            let mut full = AnalyzerConfig::default();
            full.jvm.standard_library_discovery.source_toolchains = bindings;
            let workspace = workspace_at(temp.path(), full.clone());
            let mut partial = full.clone();
            partial
                .jvm
                .standard_library_discovery
                .source_toolchains
                .truncate(1);
            let merged = activation_config_with_source_toolchains(&workspace, &partial, None);
            // Independent source selection is the consumer of the preserved
            // bindings; either source tree must still select its own JDK.
            for (path, expected) in [("old/App.java", "jdk21"), ("new/App.java", "jdk22")] {
                let file = crate::ProjectFile::new(temp.path().to_path_buf(), path);
                assert_eq!(
                    merged
                        .jvm
                        .standard_library_discovery
                        .selected_jdk_home_for_file(&file),
                    Ok(Path::new(expected))
                );
                assert_eq!(
                    merged
                        .jvm
                        .standard_library_discovery
                        .selected_jdk_home_for_file(&file),
                    full.jvm
                        .standard_library_discovery
                        .selected_jdk_home_for_file(&file)
                );
            }
        }
    }

    #[test]
    fn python_runtime_scopes_accept_root_and_reject_portable_path_escapes() {
        let source = |scope: &str| {
            serde_json::json!({
            "schema_version": 1,
            "ecosystems": ["python"],
            "python_runtime_environments": [{
                "source_root": scope,
                "artifacts": [{ "archive_path": "wheels/example.whl", "installed_root": "venv/site-packages" }]
            }]
        }).to_string()
        };
        let config = parse_workspace_packs_config(&source(".")).unwrap();
        assert_eq!(
            config.python_runtime_environments()[0].source_root,
            PathBuf::from(".")
        );
        for scope in [
            "../outside",
            "./../outside",
            "/absolute",
            "C:outside",
            "C:\\outside",
            "\\server\\share",
            "",
        ] {
            let error = parse_workspace_packs_config(&source(scope)).unwrap_err();
            assert!(
                matches!(error, WorkspacePacksDocumentError::Validation(
                WorkspacePacksValidationError::InvalidPythonRuntimePath { ref path, .. }
            ) if path == Path::new(scope)),
                "{error:?}"
            );
        }
        for (scope, expected) in [
            ("src/./application", "src/application"),
            ("./src", "src"),
            ("./src/./application", "src/application"),
        ] {
            let config = parse_workspace_packs_config(&source(scope)).unwrap();
            let canonical = parse_workspace_packs_config(&source(expected)).unwrap();
            assert_eq!(
                config.python_runtime_environments()[0].source_root,
                PathBuf::from(expected)
            );
            assert_eq!(
                config.python_runtime_environments(),
                canonical.python_runtime_environments()
            );
        }
    }

    #[test]
    fn a_valid_document_normalizes_sorted_deduplicated_ecosystems() {
        let config = parse_workspace_packs_config(
            r#"{
                "schema_version": 1,
                "catalog": ".bifrost/packs-catalog",
                "ecosystems": ["python", "jvm"]
            }"#,
        )
        .unwrap();
        assert_eq!(config.schema_version(), 1);
        assert_eq!(config.catalog(), Some(Path::new(".bifrost/packs-catalog")));
        assert_eq!(
            config.ecosystems(),
            [
                DependencyPackEcosystem::Jvm,
                DependencyPackEcosystem::Python
            ]
        );
        assert!(config.enable().is_empty());
    }

    #[test]
    #[hardwon(
        "#1937: authored enable controls were ignored, so review-required packs could not activate"
    )]
    fn a_document_that_names_enable_entries_exposes_them_in_order() {
        let config = parse_workspace_packs_config(
            r#"{
                "schema_version": 1,
                "ecosystems": ["jvm"],
                "enable": ["acme.sanitizers", "acme.frameworks"]
            }"#,
        )
        .unwrap();
        assert_eq!(config.enable(), ["acme.sanitizers", "acme.frameworks"]);
    }

    #[test]
    #[hardwon(
        "#1937: packs documents without enable must allow review-required activation to be opted in"
    )]
    fn a_document_that_omits_enable_still_parses_with_an_empty_list() {
        let config =
            parse_workspace_packs_config(r#"{ "schema_version": 1, "ecosystems": ["jvm"] }"#)
                .unwrap();
        assert!(config.enable().is_empty());
    }

    #[test]
    fn obsolete_review_receipts_require_explicit_configuration_migration() {
        let mut document = serde_json::json!({
            "schema_version": 1,
            "catalog": ".bifrost/packs-catalog",
            "ecosystems": ["jvm"],
            "enable": ["acme.sanitizers"],
            "accept_reviews": [{
                "pack_id": "acme.sanitizers",
                "manifest_digest": "11".repeat(32)
            }]
        });
        let error = parse_workspace_packs_config(&document.to_string()).unwrap_err();
        assert!(
            matches!(&error, WorkspacePacksDocumentError::JsonDecode { message, .. }
                if message.contains("unknown field `accept_reviews`")),
            "an old receipt must not be silently reinterpreted: {error}"
        );

        document.as_object_mut().unwrap().remove("accept_reviews");
        let config = parse_workspace_packs_config(&document.to_string()).unwrap();
        assert_eq!(config.catalog(), Some(Path::new(".bifrost/packs-catalog")));
        assert_eq!(config.ecosystems(), [DependencyPackEcosystem::Jvm]);
        assert_eq!(config.enable(), ["acme.sanitizers"]);
    }
    #[test]
    fn every_ecosystem_label_round_trips_through_the_document() {
        for ecosystem in DependencyPackEcosystem::ALL {
            let source = format!(
                r#"{{ "schema_version": 1, "ecosystems": ["{}"] }}"#,
                ecosystem.label()
            );
            let config = parse_workspace_packs_config(&source).unwrap();
            assert_eq!(config.ecosystems(), [ecosystem]);
            assert_eq!(config.catalog(), None);
        }
    }

    #[test]
    fn malformed_documents_report_typed_errors() {
        for (source, expected_line, expected_column) in [
            ("{ not json", 1, 3),
            ("{\n\"schema_version\":1,\n\"ecosystems\": ?\n}", 3, 15),
        ] {
            let error = parse_workspace_packs_config(source).unwrap_err();
            assert!(
                matches!(error, WorkspacePacksDocumentError::JsonDecode {line, column, ..}
                if (line, column) == (expected_line, expected_column)),
                "{error:?}"
            );
        }
        assert!(matches!(
            parse_workspace_packs_config(r#"{ "schema_version": 2, "ecosystems": ["jvm"] }"#),
            Err(WorkspacePacksDocumentError::Validation(
                WorkspacePacksValidationError::UnsupportedSchemaVersion { observed: 2 }
            ))
        ));
        assert!(matches!(
            parse_workspace_packs_config(r#"{ "schema_version": 1, "ecosystems": [] }"#),
            Ok(config) if config.ecosystems().is_empty()
        ));
        assert!(matches!(
            parse_workspace_packs_config(r#"{ "schema_version": 1, "ecosystems": ["jdk"] }"#),
            Err(WorkspacePacksDocumentError::Validation(
                WorkspacePacksValidationError::UnknownEcosystem { .. }
            ))
        ));
        assert!(matches!(
            parse_workspace_packs_config(
                r#"{ "schema_version": 1, "ecosystems": ["jvm", "jvm"] }"#
            ),
            Err(WorkspacePacksDocumentError::Validation(
                WorkspacePacksValidationError::DuplicateEcosystem {
                    ecosystem: DependencyPackEcosystem::Jvm
                }
            ))
        ));
        assert!(matches!(
            parse_workspace_packs_config(
                r#"{ "schema_version": 1, "ecosystems": ["jvm"], "unknown": true }"#
            ),
            Err(WorkspacePacksDocumentError::JsonDecode { .. })
        ));
        assert!(matches!(
            parse_workspace_packs_config(
                r#"{ "schema_version": 1, "catalog": "../outside", "ecosystems": ["jvm"] }"#
            ),
            Err(WorkspacePacksDocumentError::Validation(
                WorkspacePacksValidationError::InvalidCatalogPath {
                    reason: WorkspacePathError::ParentComponent
                }
            ))
        ));
    }

    #[test]
    fn the_conventional_document_loads_from_the_workspace_root() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join(".bifrost")).unwrap();
        fs::write(
            temp.path().join(WORKSPACE_PACKS_DOCUMENT_PATH),
            r#"{ "schema_version": 1, "ecosystems": ["cargo"] }"#,
        )
        .unwrap();
        let config = load_workspace_packs_config_at(temp.path())
            .unwrap()
            .expect("document present");
        assert_eq!(config.ecosystems(), [DependencyPackEcosystem::Cargo]);
    }
}

#[cfg(test)]
mod bootstrap_capture_tests {
    use super::*;
    use crate::analyzer::{MultiAnalyzer, capture_query_reads};

    #[test]
    fn bootstrap_handle_selection_has_no_workspace_input() {
        let analyzer = MultiAnalyzer::default();
        let before = SEMANTIC_MODEL_CATALOG_BOOTSTRAP
            .get()
            .map(|hook| *hook as usize);
        let (_, reads) = capture_query_reads(&analyzer, || {
            assert_eq!(
                before,
                SEMANTIC_MODEL_CATALOG_BOOTSTRAP
                    .get()
                    .map(|hook| *hook as usize)
            );
        });
        assert!(reads.keys().is_empty());
    }
}
