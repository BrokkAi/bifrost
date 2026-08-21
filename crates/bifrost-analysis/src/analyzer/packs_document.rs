//! The shared workspace pack-activation document (`.bifrost/packs.json`).
//!
//! One schema-versioned document names the semantic-pack catalog location and
//! the discovered dependency ecosystems the workspace opts into activating.
//! The CLI policy runner, the MCP host, and the LSP host all read this one
//! document, so every entry point activates the same packs (#1868).
//! Activation stays opt-in: an absent document activates nothing.

use std::fmt;
use std::path::{Path, PathBuf};

use semver::Version;
use serde::Deserialize;

use crate::analyzer::semantic_model::{
    CatalogError, CatalogOpenMode, CatalogOptions, DependencyPackLimits,
    RegisteredWorkspaceSemanticModel, SemanticModelActivationControl,
    SemanticModelActivationRequest, SemanticModelControlAction, SemanticModelControlScope,
    SemanticModelPackSelector, SemanticModelRuntimeLimits, SemanticPackCatalog,
    WORKSPACE_SEMANTIC_MODEL_DIRECTORY, WorkspaceSemanticModelOptions,
    WorkspaceSemanticModelRegistration, WorkspaceSemanticModelRegistrationError,
    register_workspace_semantic_models,
};
use crate::analyzer::{
    AnalyzerConfig, DependencyPackActivationOutcome, DependencyPackEcosystem,
    DependencyPackWorkspaceContext, WorkspaceAnalyzer,
};
use crate::workspace_document::{
    WorkspaceDocumentError, WorkspacePathError, WorkspaceRoot, read_workspace_document,
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

/// The normalized pack-activation configuration for one workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePacksConfig {
    schema_version: u32,
    catalog: Option<PathBuf>,
    ecosystems: Vec<DependencyPackEcosystem>,
    enable: Vec<String>,
}

impl WorkspacePacksConfig {
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Workspace-relative semantic-pack catalog root, when configured.
    /// Absent means the activation uses an ephemeral catalog.
    pub fn catalog(&self) -> Option<&Path> {
        self.catalog.as_deref()
    }

    /// The opted-in ecosystems, sorted and free of duplicates.
    pub fn ecosystems(&self) -> &[DependencyPackEcosystem] {
        &self.ecosystems
    }

    /// Pack ids the workspace opts into activating. Every shipped pack sets
    /// `safety.review_required = true`, so a pack stays selected but inactive
    /// until its id is named here (#1937).
    pub fn enable(&self) -> &[String] {
        &self.enable
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
    if wire.ecosystems.is_empty() {
        return Err(WorkspacePacksValidationError::EmptyEcosystems);
    }
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
    Ok(WorkspacePacksConfig {
        schema_version: WORKSPACE_PACKS_SCHEMA_VERSION,
        catalog,
        ecosystems,
        enable: wire.enable,
    })
}

/// Load the conventional document beneath an opened workspace root.
/// An absent document is the opt-out and returns `Ok(None)`.
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
        Err(error) if workspace_error_is_not_found(&error) => return Ok(None),
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

fn workspace_error_is_not_found(error: &WorkspaceDocumentError) -> bool {
    matches!(
        error,
        WorkspaceDocumentError::OpenFile { source, .. }
            if source.kind() == std::io::ErrorKind::NotFound
    )
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
}

/// Why one activation transaction could not be built.
#[derive(Debug)]
pub enum WorkspaceActivationError {
    Catalog(CatalogError),
    /// The reviewed workspace-local route refused to contribute its models.
    WorkspaceModels(WorkspaceSemanticModelRegistrationError),
}

impl fmt::Display for WorkspaceActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catalog(error) => error.fmt(formatter),
            Self::WorkspaceModels(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for WorkspaceActivationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Catalog(error) => Some(error),
            Self::WorkspaceModels(error) => Some(error),
        }
    }
}

impl From<CatalogError> for WorkspaceActivationError {
    fn from(error: CatalogError) -> Self {
        Self::Catalog(error)
    }
}

/// Activate the document's opted-in ecosystems on `workspace` (#1868).
///
/// The catalog opens read-write at the document's configured location, so
/// locally generated packs persist across runs; an unconfigured catalog is
/// ephemeral. Ecosystems that serve no language present in the workspace are
/// skipped: naming one is configuration, not proof the workspace uses it.
/// Returns `Ok(None)` when no requested ecosystem is relevant.
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
        },
        cancellation,
    ) {
        Ok(activation) => Ok(activation),
        Err(WorkspaceActivationError::Catalog(error)) => Err(error),
        // Unreachable: the reviewed workspace-local route is switched off
        // above, and it is the only producer of this variant.
        Err(WorkspaceActivationError::WorkspaceModels(error)) => {
            Err(CatalogError::Integrity(error.to_string()))
        }
    }
}

/// Activate every semantic source one workspace opts into, as one transaction.
///
/// Two routes feed one activation request, because they have to: the resolver
/// publishes exactly one active model set onto an analyzer, so running the
/// routes separately would leave the second overwriting the first.
///
/// - The pack-activation document names the dependency ecosystems and the
///   catalog, and its `enable` list supplies the review controls. It may also
///   enable a reviewed workspace-local pack by id.
/// - `.bifrost/semantic-models/` supplies the reviewed models the repository
///   checked in beside its policies. Their presence is the opt-in; an absent
///   directory contributes nothing.
///
/// Returns `Ok(None)` when neither route contributes anything, so a workspace
/// with no configuration keeps paying nothing.
pub fn activate_workspace_semantic_sources(
    workspace: &WorkspaceAnalyzer,
    analyzer_config: &AnalyzerConfig,
    sources: WorkspaceActivationSources<'_>,
    cancellation: &crate::CancellationToken,
) -> Result<Option<WorkspacePacksActivation>, WorkspaceActivationError> {
    let languages = workspace.analyzer().languages();
    let ecosystems: Vec<_> = sources
        .config
        .map(WorkspacePacksConfig::ecosystems)
        .unwrap_or_default()
        .iter()
        .copied()
        .filter(|ecosystem| {
            ecosystem
                .languages()
                .iter()
                .any(|language| languages.contains(language))
        })
        .collect();
    // Does this workspace opt into the reviewed route at all? Presence of the
    // directory is the whole opt-in, and asking costs one stat. Discovery
    // asks again and properly, rejecting a symlink or a non-directory; an
    // absent directory reaches the same answer either way, so nothing is
    // weakened by asking early. What it buys is not opening a catalog for a
    // workspace that has nothing to put in one.
    let workspace_model_root = sources.workspace_model_root.filter(|root| {
        std::fs::symlink_metadata(root.join(WORKSPACE_SEMANTIC_MODEL_DIRECTORY)).is_ok()
    });
    // Nothing to open a catalog for: no relevant ecosystem and no reviewed
    // workspace-local route. This keeps a configured catalog directory from
    // being created by a run that would activate nothing.
    if ecosystems.is_empty() && workspace_model_root.is_none() {
        return Ok(None);
    }
    let catalog = match sources.config.and_then(WorkspacePacksConfig::catalog) {
        Some(relative) => SemanticPackCatalog::open(
            &sources.catalog_root.join(relative),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )?,
        None => SemanticPackCatalog::open_ephemeral(CatalogOptions::default())?,
    };
    // The reviewed workspace-local models join the same catalog handle and the
    // same evidence, before the dependency route resolves. A discovery,
    // compile, or registration failure aborts the transaction: a checked-in
    // model that quietly fails to load would decide verdicts by its absence
    // (#2493).
    let registration = match workspace_model_root {
        Some(model_root) => register_workspace_semantic_models(
            model_root,
            &catalog,
            WorkspaceSemanticModelOptions::default(),
        )
        .map_err(WorkspaceActivationError::WorkspaceModels)?,
        None => WorkspaceSemanticModelRegistration::default(),
    };
    if ecosystems.is_empty() && registration.models.is_empty() {
        return Ok(None);
    }
    // Every shipped pack declares `safety.review_required`, so activation
    // needs an explicit compatible `Enable` control keyed by pack id --
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
    let mut evidence = registration.evidence;
    evidence.sort();
    evidence.dedup();
    let activation = SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION"))
            .expect("package version must be semver"),
        evidence,
        controls,
        limits: SemanticModelRuntimeLimits::default(),
    };
    // An empty ecosystem list still resolves: the dependency loop simply has
    // nothing to discover, and the request's workspace evidence is what
    // selects. That keeps one code path for both routes.
    let outcome = workspace.activate_dependency_packs(
        analyzer_config,
        &ecosystems,
        DependencyPackWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &activation,
            limits: DependencyPackLimits::default(),
            cancellation,
        },
    );
    Ok(Some(WorkspacePacksActivation {
        ecosystems,
        workspace_models: registration.models,
        outcome,
    }))
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
            } => write!(
                formatter,
                "packs document is not valid JSON at line {line} column {column}: {message}"
            ),
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
    UnsupportedSchemaVersion { observed: u64 },
    EmptyEcosystems,
    UnknownEcosystem { label: String },
    DuplicateEcosystem { ecosystem: DependencyPackEcosystem },
    CatalogPathTooLong { max_bytes: usize },
    InvalidCatalogPath { reason: WorkspacePathError },
}

impl fmt::Display for WorkspacePacksValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion { observed } => write!(
                formatter,
                "packs document schema_version {observed} is not supported; expected {WORKSPACE_PACKS_SCHEMA_VERSION}"
            ),
            Self::EmptyEcosystems => {
                formatter.write_str("packs document must name at least one ecosystem")
            }
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
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

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
    fn a_document_that_omits_enable_still_parses_with_an_empty_list() {
        let config =
            parse_workspace_packs_config(r#"{ "schema_version": 1, "ecosystems": ["jvm"] }"#)
                .unwrap();
        assert!(config.enable().is_empty());
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
        assert!(matches!(
            parse_workspace_packs_config("{ not json"),
            Err(WorkspacePacksDocumentError::JsonDecode { .. })
        ));
        assert!(matches!(
            parse_workspace_packs_config(r#"{ "schema_version": 2, "ecosystems": ["jvm"] }"#),
            Err(WorkspacePacksDocumentError::Validation(
                WorkspacePacksValidationError::UnsupportedSchemaVersion { observed: 2 }
            ))
        ));
        assert!(matches!(
            parse_workspace_packs_config(r#"{ "schema_version": 1, "ecosystems": [] }"#),
            Err(WorkspacePacksDocumentError::Validation(
                WorkspacePacksValidationError::EmptyEcosystems
            ))
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
    fn an_absent_document_is_the_opt_out() {
        let temp = TempDir::new().unwrap();
        assert!(
            load_workspace_packs_config_at(temp.path())
                .unwrap()
                .is_none()
        );
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

    #[test]
    fn a_document_that_exceeds_the_byte_cap_is_a_typed_workspace_error() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join(".bifrost")).unwrap();
        let oversized = format!(
            r#"{{ "schema_version": 1, "ecosystems": ["jvm"], "catalog": "{}" }}"#,
            "x".repeat(MAX_WORKSPACE_PACKS_DOCUMENT_BYTES as usize)
        );
        fs::write(temp.path().join(WORKSPACE_PACKS_DOCUMENT_PATH), oversized).unwrap();
        assert!(matches!(
            load_workspace_packs_config_at(temp.path()),
            Err(WorkspacePacksLoadError::Workspace(
                WorkspaceDocumentError::TooLarge { .. }
            ))
        ));
    }
}
