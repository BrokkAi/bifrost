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
    SemanticModelActivationControl, SemanticModelActivationRequest, SemanticModelControlAction,
    SemanticModelControlScope, SemanticModelPackSelector, SemanticModelRuntimeLimits,
    SemanticPackCatalog,
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

/// The outcome of one document-driven activation transaction.
#[derive(Debug)]
pub struct WorkspacePacksActivation {
    /// The document ecosystems that serve a language present in this
    /// workspace, in `DependencyPackEcosystem::ALL` order.
    pub ecosystems: Vec<DependencyPackEcosystem>,
    pub outcome: DependencyPackActivationOutcome,
}

/// Activate the document's opted-in ecosystems on `workspace` (#1868).
///
/// The catalog opens read-write at the document's configured location, so
/// locally generated packs persist across runs; an unconfigured catalog is
/// ephemeral. Ecosystems that serve no language present in the workspace are
/// skipped: naming one is configuration, not proof the workspace uses it.
/// Returns `Ok(None)` when no requested ecosystem is relevant.
pub fn activate_workspace_packs(
    workspace: &WorkspaceAnalyzer,
    analyzer_config: &AnalyzerConfig,
    workspace_root: &Path,
    config: &WorkspacePacksConfig,
    cancellation: &crate::CancellationToken,
) -> Result<Option<WorkspacePacksActivation>, CatalogError> {
    let languages = workspace.analyzer().languages();
    let ecosystems: Vec<_> = config
        .ecosystems()
        .iter()
        .copied()
        .filter(|ecosystem| {
            ecosystem
                .languages()
                .iter()
                .any(|language| languages.contains(language))
        })
        .collect();
    if ecosystems.is_empty() {
        return Ok(None);
    }
    let catalog = match config.catalog() {
        Some(relative) => SemanticPackCatalog::open(
            &workspace_root.join(relative),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )?,
        None => SemanticPackCatalog::open_ephemeral(CatalogOptions::default())?,
    };
    // Every shipped pack declares `safety.review_required`, so activation
    // needs an explicit compatible `Enable` control keyed by pack id --
    // matching evidence alone leaves it selected but inactive
    // (`ReviewRequired`). The document's `enable` list is that control,
    // matching the in-process control build in `owasp_benchmark.rs` (#1937).
    let controls = config
        .enable()
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
    let activation = SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION"))
            .expect("package version must be semver"),
        evidence: Vec::new(),
        controls,
        limits: SemanticModelRuntimeLimits::default(),
    };
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
