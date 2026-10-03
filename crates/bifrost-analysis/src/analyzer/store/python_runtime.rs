//! Durable, snapshot-bound Python runtime provider evidence.
//!
//! The store owns transaction and cancellation boundaries. Semantic readers
//! issue their SQL through `with_python_runtime_acquisition`; result rows live
//! only for that query and no workspace-sized Rust index is retained.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use brokk_bifrost_core::analyzer::config::{
    PYTHON_DECLARED_PROJECT_CONFIG_CANONICALIZATION_URI, PythonDeclaredConfigInput,
    PythonDeclaredConfigInputRole, PythonDeclaredEditableInstallMode, PythonDeclaredEntryMode,
    PythonDeclaredEnvironmentConfig, PythonDeclaredEnvironmentMode, PythonDeclaredFinderMode,
    PythonDeclaredImportPathMode, PythonDeclaredInterpreter, PythonDeclaredIsolationMode,
    PythonDeclaredLaunchSemantics, PythonDeclaredNativeExtensionMode, PythonDeclaredRootRole,
    PythonDeclaredRootSlot, PythonDeclaredSiteStartupMode,
};
use rusqlite::{OptionalExtension, Row, Transaction, TransactionBehavior, params};

use crate::CancellationToken;
use crate::analyzer::semantic_model::csmi::{CsmiArtifactDigest, CsmiDigestAlgorithm};

use super::workspace_inputs::{self, WorkspaceInputKind};
use super::{AnalyzerStore, Result, StoreError, WorkspaceConfigurationInput, WorkspaceSnapshotId};

const MAX_PUBLICATION_ROWS: usize = 250_000;
const MAX_CELL_BYTES: usize = 1 << 20;
const PYTHON_DECLARED_PROJECT_CONFIG_COVERAGE: &str = "resolver-affecting-config";

/// A scalar handle. It is meaningful only together with the exact selected
/// snapshot passed to `with_python_runtime_acquisition`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PythonRuntimeAcquisitionId(i64);

impl PythonRuntimeAcquisitionId {
    pub(crate) fn get(self) -> i64 {
        self.0
    }
}

/// The durable acquisition and the workspace revision produced by its
/// atomic publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PythonRuntimeProviderPublication {
    pub(crate) acquisition_id: PythonRuntimeAcquisitionId,
    pub(crate) snapshot: WorkspaceSnapshotId,
    /// Stable complete provider-input identity. Unlike acquisition_id this
    /// value is safe to include in semantic snapshot/cache identity.
    pub(crate) evidence_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PythonRuntimeStatus {
    ArchiveVerified,
    Incomplete,
    Unresolved,
    Conflicting,
    Cancelled,
    BytesMatched,
    StubOnly,
    MissingInstalled,
    ContentMismatch,
    Unsupported,
}

impl PythonRuntimeStatus {
    fn as_sql(self) -> &'static str {
        match self {
            Self::ArchiveVerified => "archive_verified",
            Self::Incomplete => "incomplete",
            Self::Unresolved => "unresolved",
            Self::Conflicting => "conflicting",
            Self::Cancelled => "cancelled",
            Self::BytesMatched => "bytes_matched",
            Self::StubOnly => "stub_only",
            Self::MissingInstalled => "missing_installed",
            Self::ContentMismatch => "content_mismatch",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PythonRuntimeMemberRole {
    Runtime,
    Stub,
    RuntimeAndStub,
    Other,
}

impl PythonRuntimeMemberRole {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Stub => "stub",
            Self::RuntimeAndStub => "runtime_stub",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PythonRuntimeBindingStatus {
    Unresolved,
    Conflict,
}

impl PythonRuntimeBindingStatus {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Unresolved => "unresolved",
            Self::Conflict => "conflict",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PythonRuntimeFrontierKind {
    ExtraInstalledCandidate,
    SourceShadowCandidate,
    CompetingRuntimeProvider,
    NamespaceContributor,
    PackageInitializerEffects,
    CandidatePathCollision,
    CandidateIdentityUnknown,
    MissingInstalledCandidate,
    SymlinkSkipped,
    PathUnreadable,
    ScanLimit,
    ScanDepthLimit,
    ImportPathOrderUnknown,
    ImportHookSemanticsUnknown,
}

impl PythonRuntimeFrontierKind {
    fn as_sql(self) -> &'static str {
        match self {
            Self::ExtraInstalledCandidate => "extra_installed_candidate",
            Self::SourceShadowCandidate => "source_shadow_candidate",
            Self::CompetingRuntimeProvider => "competing_runtime_provider",
            Self::NamespaceContributor => "namespace_contributor",
            Self::PackageInitializerEffects => "package_initializer_effects",
            Self::CandidatePathCollision => "candidate_path_collision",
            Self::CandidateIdentityUnknown => "candidate_identity_unknown",
            Self::MissingInstalledCandidate => "missing_installed_candidate",
            Self::SymlinkSkipped => "symlink_skipped",
            Self::PathUnreadable => "path_unreadable",
            Self::ScanLimit => "scan_limit",
            Self::ScanDepthLimit => "scan_depth_limit",
            Self::ImportPathOrderUnknown => "import_path_order_unknown",
            Self::ImportHookSemanticsUnknown => "import_hook_semantics_unknown",
        }
    }
}

/// One configured Python source scope. Invalid or unresolved roots remain as
/// rows with a NULL normalized scope path and are returned as frontiers for
/// every provider request; they are never silently dropped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PythonRuntimeEnvironmentInput {
    pub(crate) source_scope: PathBuf,
    pub(crate) status: PythonRuntimeStatus,
    pub(crate) diagnostic: Option<String>,
    pub(crate) artifacts: Vec<PythonRuntimeArtifactInput>,
    pub(crate) frontiers: Vec<PythonRuntimeFrontierInput>,
    pub(crate) declared_environment: Option<PythonDeclaredEnvironmentConfig>,
    pub(crate) project_config: Option<CsmiArtifactDigest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PythonRuntimeArtifactInput {
    /// The exact package URL reported for the archive, when metadata resolved.
    pub(crate) purl: Option<String>,
    pub(crate) raw_version: Option<String>,
    /// SHA-256 of the original archive bytes, distinct from the acquisition
    /// digest that identifies the complete provider input set.
    pub(crate) archive_sha256: Option<String>,
    pub(crate) archive_path: PathBuf,
    pub(crate) installed_root: PathBuf,
    pub(crate) status: PythonRuntimeStatus,
    pub(crate) diagnostic: Option<String>,
    pub(crate) members: Vec<PythonRuntimeMemberInput>,
    pub(crate) providers: Vec<PythonRuntimeProviderInput>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PythonRuntimeMemberInput {
    pub(crate) archive_member_path: PathBuf,
    pub(crate) installed_path: Option<PathBuf>,
    pub(crate) member_sha256: Option<String>,
    pub(crate) installed_sha256: Option<String>,
    pub(crate) installed_bytes_match: Option<bool>,
    pub(crate) role: PythonRuntimeMemberRole,
    pub(crate) status: PythonRuntimeStatus,
    pub(crate) diagnostic: Option<String>,
}

/// An import-name candidate can point to any member in its artifact. Several
/// rows for one name are intentional: ambiguity is evidence, not a reason to
/// pick one provider or prune the others.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PythonRuntimeProviderInput {
    pub(crate) import_name: String,
    pub(crate) member_index: Option<usize>,
    pub(crate) status: PythonRuntimeBindingStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PythonRuntimeFrontierInput {
    pub(crate) kind: PythonRuntimeFrontierKind,
    pub(crate) root: PathBuf,
    pub(crate) path: Option<PathBuf>,
    pub(crate) import_name: Option<String>,
    pub(crate) message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PythonRuntimeScopeRow {
    pub(crate) environment_id: i64,
    pub(crate) source_scope: String,
    pub(crate) scope_path: Option<String>,
    pub(crate) scope_depth: Option<i64>,
    pub(crate) status: String,
    pub(crate) diagnostic: Option<String>,
}

impl PythonRuntimeScopeRow {
    pub(crate) fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            environment_id: row.get(0)?,
            source_scope: row.get(1)?,
            scope_path: row.get(2)?,
            scope_depth: row.get(3)?,
            status: row.get(4)?,
            diagnostic: row.get(5)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PythonRuntimeProviderCandidateRow {
    pub(crate) provider_id: i64,
    pub(crate) environment_id: i64,
    pub(crate) artifact_id: i64,
    pub(crate) member_id: Option<i64>,
    pub(crate) import_name: String,
    pub(crate) binding_status: String,
    pub(crate) purl: Option<String>,
    pub(crate) raw_version: Option<String>,
    pub(crate) archive_sha256: Option<String>,
    pub(crate) archive_path: String,
    pub(crate) installed_root: String,
    pub(crate) artifact_status: String,
    pub(crate) archive_member_path: Option<String>,
    pub(crate) installed_path: Option<String>,
    pub(crate) member_sha256: Option<String>,
    pub(crate) installed_sha256: Option<String>,
    pub(crate) installed_bytes_match: Option<bool>,
    pub(crate) member_role: Option<String>,
    pub(crate) member_status: Option<String>,
}

impl PythonRuntimeProviderCandidateRow {
    pub(crate) fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            provider_id: row.get(0)?,
            environment_id: row.get(1)?,
            artifact_id: row.get(2)?,
            member_id: row.get(3)?,
            import_name: row.get(4)?,
            binding_status: row.get(5)?,
            purl: row.get(6)?,
            raw_version: row.get(7)?,
            archive_sha256: row.get(8)?,
            archive_path: row.get(9)?,
            installed_root: row.get(10)?,
            artifact_status: row.get(11)?,
            archive_member_path: row.get(12)?,
            installed_path: row.get(13)?,
            member_sha256: row.get(14)?,
            installed_sha256: row.get(15)?,
            installed_bytes_match: row.get(16)?,
            member_role: row.get(17)?,
            member_status: row.get(18)?,
        })
    }
}

/// Exact equality query for each `PythonRuntimeScopeAncestor`. Call it for
/// every `Path::ancestors` result; never replace it with string-prefix logic.
pub(crate) const PYTHON_RUNTIME_SCOPE_AT_PATH_SQL: &str =
    "SELECT environment_id, source_scope, scope_path, scope_depth, status, diagnostic
     FROM python_runtime_environments INDEXED BY python_runtime_environments_by_scope
     WHERE acquisition_id = ?1 AND scope_path = ?2";

/// Unknown source roots are global uncertainty for this acquisition and must
/// accompany even a deeper valid scope result.
pub(crate) const PYTHON_RUNTIME_UNRESOLVED_SCOPES_SQL: &str =
    "SELECT environment_id, source_scope, scope_path, scope_depth, status, diagnostic
     FROM python_runtime_environments INDEXED BY python_runtime_environments_by_scope
     WHERE acquisition_id = ?1 AND scope_path IS NULL";

/// Candidate rows are selected by both the acquisition and exact import name.
/// `?2` is one deepest applicable environment row. Tied rows are queried
/// independently so all alternatives survive. `?1` additionally binds the
/// same acquisition ID in the selected snapshot to prevent cross-snapshot
/// reads even when this SQL is called outside the checked callback.
pub(crate) const PYTHON_RUNTIME_IMPORT_CANDIDATES_SQL: &str =
    "SELECT provider.provider_id, provider.environment_id, provider.artifact_id,
            provider.member_id, provider.import_name, provider.binding_status,
            artifact.purl, artifact.raw_version, artifact.archive_sha256,
            artifact.archive_path, artifact.installed_root, artifact.status,
            member.archive_member_path, member.installed_path, member.member_sha256,
            member.installed_sha256, member.installed_bytes_match, member.member_role,
            member.status
     FROM python_runtime_import_providers AS provider
       INDEXED BY python_runtime_import_providers_by_import
     JOIN python_runtime_artifacts AS artifact
       ON artifact.artifact_id = provider.artifact_id
      AND artifact.environment_id = provider.environment_id
     LEFT JOIN python_runtime_artifact_members AS member
       ON member.member_id = provider.member_id
      AND member.artifact_id = provider.artifact_id
     WHERE provider.acquisition_id = ?1
       AND provider.environment_id = ?2
       AND provider.import_name = ?3
       AND EXISTS(
         SELECT 1 FROM python_runtime_acquisitions AS acquisition
         WHERE acquisition.acquisition_id = provider.acquisition_id
           AND acquisition.workspace_id = ?4 AND acquisition.lang = ?5
           AND acquisition.generation = ?6 AND acquisition.revision = ?7
       )";

/// All installed runtime artifacts owned by one explicit environment.
/// `?1` is the environment row and `?2` is the checked acquisition handle.
pub(crate) const PYTHON_RUNTIME_ARTIFACTS_FOR_ENVIRONMENT_SQL: &str =
    "SELECT artifact_id, purl, raw_version, archive_sha256, archive_path,
            installed_root, status
     FROM python_runtime_artifacts INDEXED BY python_runtime_artifacts_by_environment
     WHERE environment_id = ?1 AND acquisition_id = ?2
     ORDER BY artifact_id";

/// Complete inventory for independent archive and installed-byte
/// revalidation. This is intentionally an indexed point/range query per
/// artifact, not an analyzer-resident member index.
pub(crate) const PYTHON_RUNTIME_ARTIFACT_MEMBERS_SQL: &str =
    "SELECT member_id, artifact_id, archive_member_path, installed_path,
            member_sha256, installed_sha256, installed_bytes_match,
            member_role, status, diagnostic
     FROM python_runtime_artifact_members INDEXED BY python_runtime_artifact_members_by_acquisition_artifact
     WHERE acquisition_id = ?1 AND artifact_id = ?2";

pub(crate) const PYTHON_RUNTIME_SCOPE_FRONTIERS_SQL: &str =
    "SELECT frontier_id, kind, root_path, path, import_name, message
     FROM python_runtime_scope_frontiers INDEXED BY python_runtime_frontiers_by_scope
     WHERE acquisition_id = ?1 AND environment_id = ?2 AND import_name = ?3";

pub(crate) const PYTHON_RUNTIME_UNNAMED_SCOPE_FRONTIERS_SQL: &str =
    "SELECT frontier_id, kind, root_path, path, import_name, message
     FROM python_runtime_scope_frontiers INDEXED BY python_runtime_frontiers_by_scope
     WHERE acquisition_id = ?1 AND environment_id = ?2 AND import_name IS NULL";

/// Resolve a declared environment only when both its scope row and acquisition
/// match. The selected declaration ID scopes all three ordered child reads.
pub(crate) const PYTHON_RUNTIME_DECLARED_ENVIRONMENT_SQL: &str =
    "SELECT declared_environment_id, producer_version, resolver_version,
            interpreter_path, interpreter_sha256, interpreter_implementation,
            interpreter_python_version, interpreter_abi, interpreter_platform,
            isolation_mode, site_startup_mode, environment_mode, import_path_mode,
            finder_mode, editable_installs_mode, native_extensions_mode,
            entry_mode, entry_root_slot_id, entry_relative_path,
            working_directory_root_slot_id, working_directory,
            project_config_algorithm, project_config_coverage,
            project_config_canonicalization, project_config_digest
     FROM python_runtime_declared_environments INDEXED BY python_runtime_declared_environments_by_environment
     WHERE acquisition_id = ?1 AND environment_id = ?2";

pub(crate) const PYTHON_RUNTIME_DECLARED_ROOTS_SQL: &str =
    "SELECT ordinal, semantic_id, role, path, artifact_index
     FROM python_runtime_declared_roots
     WHERE declared_environment_id = ?1
     ORDER BY ordinal";

pub(crate) const PYTHON_RUNTIME_DECLARED_INPUTS_SQL: &str =
    "SELECT ordinal, input_id, role, path, sha256
     FROM python_runtime_declared_inputs
     WHERE declared_environment_id = ?1
     ORDER BY ordinal";

pub(crate) const PYTHON_RUNTIME_DECLARED_EXTRAS_SQL: &str = "SELECT ordinal, extra
     FROM python_runtime_declared_extras
     WHERE declared_environment_id = ?1
     ORDER BY ordinal";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PythonRuntimeScopeAncestor {
    pub(crate) path: String,
    pub(crate) depth: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PythonRuntimeFrontierRow {
    pub(crate) frontier_id: i64,
    pub(crate) kind: String,
    pub(crate) root_path: String,
    pub(crate) path: Option<String>,
    pub(crate) import_name: Option<String>,
    pub(crate) message: String,
}

impl PythonRuntimeFrontierRow {
    pub(crate) fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            frontier_id: row.get(0)?,
            kind: row.get(1)?,
            root_path: row.get(2)?,
            path: row.get(3)?,
            import_name: row.get(4)?,
            message: row.get(5)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PythonRuntimeArtifactMemberRow {
    pub(crate) member_id: i64,
    pub(crate) artifact_id: i64,
    pub(crate) archive_member_path: String,
    pub(crate) installed_path: Option<String>,
    pub(crate) member_sha256: Option<String>,
    pub(crate) installed_sha256: Option<String>,
    pub(crate) installed_bytes_match: Option<bool>,
    pub(crate) member_role: String,
    pub(crate) status: String,
    pub(crate) diagnostic: Option<String>,
}

impl PythonRuntimeArtifactMemberRow {
    pub(crate) fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            member_id: row.get(0)?,
            artifact_id: row.get(1)?,
            archive_member_path: row.get(2)?,
            installed_path: row.get(3)?,
            member_sha256: row.get(4)?,
            installed_sha256: row.get(5)?,
            installed_bytes_match: row.get(6)?,
            member_role: row.get(7)?,
            status: row.get(8)?,
            diagnostic: row.get(9)?,
        })
    }
}

struct PythonRuntimeDeclaredEnvironmentRow {
    declared_environment_id: i64,
    producer_version: String,
    resolver_version: String,
    interpreter_path: String,
    interpreter_sha256: String,
    interpreter_implementation: String,
    interpreter_python_version: String,
    interpreter_abi: String,
    interpreter_platform: String,
    isolation_mode: String,
    site_startup_mode: String,
    environment_mode: String,
    import_path_mode: String,
    finder_mode: String,
    editable_installs_mode: String,
    native_extensions_mode: String,
    entry_mode: String,
    entry_root_slot_id: String,
    entry_relative_path: String,
    working_directory_root_slot_id: String,
    working_directory: String,
    project_config_algorithm: String,
    project_config_coverage: String,
    project_config_canonicalization: String,
    project_config_digest: String,
}

impl PythonRuntimeDeclaredEnvironmentRow {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            declared_environment_id: row.get(0)?,
            producer_version: row.get(1)?,
            resolver_version: row.get(2)?,
            interpreter_path: row.get(3)?,
            interpreter_sha256: row.get(4)?,
            interpreter_implementation: row.get(5)?,
            interpreter_python_version: row.get(6)?,
            interpreter_abi: row.get(7)?,
            interpreter_platform: row.get(8)?,
            isolation_mode: row.get(9)?,
            site_startup_mode: row.get(10)?,
            environment_mode: row.get(11)?,
            import_path_mode: row.get(12)?,
            finder_mode: row.get(13)?,
            editable_installs_mode: row.get(14)?,
            native_extensions_mode: row.get(15)?,
            entry_mode: row.get(16)?,
            entry_root_slot_id: row.get(17)?,
            entry_relative_path: row.get(18)?,
            working_directory_root_slot_id: row.get(19)?,
            working_directory: row.get(20)?,
            project_config_algorithm: row.get(21)?,
            project_config_coverage: row.get(22)?,
            project_config_canonicalization: row.get(23)?,
            project_config_digest: row.get(24)?,
        })
    }
}

/// Reconstruct the complete declared import contract for exactly one existing
/// environment/acquisition pair. Child rows are scoped through the returned
/// declaration row and ordered by their persisted ordinals.
pub(crate) fn python_runtime_declared_environment(
    tx: &Transaction<'_>,
    acquisition_id: i64,
    environment_id: i64,
) -> Result<Option<(PythonDeclaredEnvironmentConfig, CsmiArtifactDigest)>> {
    let Some(row) = tx
        .query_row(
            PYTHON_RUNTIME_DECLARED_ENVIRONMENT_SQL,
            params![acquisition_id, environment_id],
            PythonRuntimeDeclaredEnvironmentRow::from_row,
        )
        .optional()?
    else {
        return Ok(None);
    };
    let declared_environment_id = row.declared_environment_id;
    let mut persisted_rows = 1_usize;

    let roots = {
        let mut statement = tx.prepare_cached(PYTHON_RUNTIME_DECLARED_ROOTS_SQL)?;
        let remaining = MAX_PUBLICATION_ROWS - persisted_rows;
        let rows = statement
            .query_map([declared_environment_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            })?
            .take(remaining + 1)
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.len() > remaining {
            return Err(StoreError::resource_bound(format!(
                "Python declared-environment read exceeds {MAX_PUBLICATION_ROWS} rows"
            )));
        }
        persisted_rows += rows.len();
        rows
    };
    let root_slots = roots
        .into_iter()
        .enumerate()
        .map(
            |(position, (ordinal, slot_id, role, path, artifact_index))| {
                Ok(PythonDeclaredRootSlot {
                    ordinal: persisted_ordinal(ordinal, position, "root")?,
                    slot_id,
                    role: parse_declared_root_role(&role)?,
                    path: PathBuf::from(path),
                    artifact_index: artifact_index
                        .map(|value| persisted_u32(value, "root artifact index"))
                        .transpose()?,
                })
            },
        )
        .collect::<Result<Vec<_>>>()?;

    let inputs = {
        let mut statement = tx.prepare_cached(PYTHON_RUNTIME_DECLARED_INPUTS_SQL)?;
        let remaining = MAX_PUBLICATION_ROWS - persisted_rows;
        let rows = statement
            .query_map([declared_environment_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .take(remaining + 1)
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.len() > remaining {
            return Err(StoreError::resource_bound(format!(
                "Python declared-environment read exceeds {MAX_PUBLICATION_ROWS} rows"
            )));
        }
        persisted_rows += rows.len();
        rows
    };
    let config_inputs = inputs
        .into_iter()
        .enumerate()
        .map(|(position, (ordinal, input_id, role, path, sha256))| {
            Ok(PythonDeclaredConfigInput {
                ordinal: persisted_ordinal(ordinal, position, "config input")?,
                input_id,
                role: parse_declared_input_role(&role)?,
                path: PathBuf::from(path),
                sha256,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let extras = {
        let mut statement = tx.prepare_cached(PYTHON_RUNTIME_DECLARED_EXTRAS_SQL)?;
        let remaining = MAX_PUBLICATION_ROWS - persisted_rows;
        let rows = statement
            .query_map([declared_environment_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?
            .take(remaining + 1)
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.len() > remaining {
            return Err(StoreError::resource_bound(format!(
                "Python declared-environment read exceeds {MAX_PUBLICATION_ROWS} rows"
            )));
        }
        rows
    };
    let extras = extras
        .into_iter()
        .enumerate()
        .map(|(position, (ordinal, extra))| {
            persisted_ordinal(ordinal, position, "extra")?;
            Ok(extra)
        })
        .collect::<Result<Vec<_>>>()?;

    let project_config = CsmiArtifactDigest {
        algorithm: parse_declared_digest_algorithm(&row.project_config_algorithm)?,
        coverage: row.project_config_coverage,
        canonicalization: Some(row.project_config_canonicalization),
        value: row.project_config_digest,
    };
    validate_project_config(&project_config)?;

    Ok(Some((
        PythonDeclaredEnvironmentConfig {
            producer_version: row.producer_version,
            resolver_version: row.resolver_version,
            interpreter: PythonDeclaredInterpreter {
                path: PathBuf::from(row.interpreter_path),
                sha256: row.interpreter_sha256,
                implementation: row.interpreter_implementation,
                python_version: row.interpreter_python_version,
                abi: row.interpreter_abi,
                platform: row.interpreter_platform,
            },
            launch: PythonDeclaredLaunchSemantics {
                isolation: parse_declared_isolation_mode(&row.isolation_mode)?,
                site_startup: parse_declared_site_startup_mode(&row.site_startup_mode)?,
                environment: parse_declared_environment_mode(&row.environment_mode)?,
                import_path: parse_declared_import_path_mode(&row.import_path_mode)?,
                finder: parse_declared_finder_mode(&row.finder_mode)?,
                editable_installs: parse_declared_editable_mode(&row.editable_installs_mode)?,
                native_extensions: parse_declared_native_extensions_mode(
                    &row.native_extensions_mode,
                )?,
            },
            entry_point: brokk_bifrost_core::analyzer::config::PythonDeclaredEntryPoint {
                mode: parse_declared_entry_mode(&row.entry_mode)?,
                root_slot_id: row.entry_root_slot_id,
                relative_path: PathBuf::from(row.entry_relative_path),
                working_directory_root_slot_id: row.working_directory_root_slot_id,
                working_directory: PathBuf::from(row.working_directory),
            },
            extras,
            config_inputs,
            root_slots,
        },
        project_config,
    )))
}

/// Component-wise source ancestors, deepest first, including the workspace
/// root as `.`. Paths with absolute roots, parent traversal, or platform
/// prefixes are rejected before they reach SQL.
pub(crate) fn python_runtime_scope_ancestors(
    source_path: &Path,
) -> Result<Vec<PythonRuntimeScopeAncestor>> {
    if source_path.is_absolute() {
        return Err(StoreError::new(
            "Python runtime source path must be workspace-relative",
        ));
    }
    let mut ancestors = Vec::new();
    for ancestor in source_path.ancestors() {
        let (path, depth) = normalized_scope(ancestor).ok_or_else(|| {
            StoreError::new("Python runtime source path must contain normal relative components")
        })?;
        if ancestors
            .last()
            .is_some_and(|previous: &PythonRuntimeScopeAncestor| previous.path == path)
        {
            continue;
        }
        ancestors.push(PythonRuntimeScopeAncestor {
            path,
            depth: i64::try_from(depth).expect("source path depth fits i64"),
        });
    }
    if ancestors.last().is_none_or(|ancestor| ancestor.path != ".") {
        ancestors.push(PythonRuntimeScopeAncestor {
            path: ".".to_owned(),
            depth: 0,
        });
    }
    Ok(ancestors)
}

impl AnalyzerStore {
    /// Publish one immutable acquisition atomically with an optional exact
    /// workspace configuration version. The returned ID is an opaque scalar;
    /// readers must pair it with the exact selected snapshot.
    pub(crate) fn publish_python_runtime_providers(
        &self,
        base_snapshot: &WorkspaceSnapshotId,
        configuration_input: Option<WorkspaceConfigurationInput>,
        evidence_digest: [u8; 32],
        environments: Vec<PythonRuntimeEnvironmentInput>,
        cancellation: &CancellationToken,
    ) -> Result<PythonRuntimeProviderPublication> {
        let row_count = publication_row_count(&environments)?;
        if row_count > MAX_PUBLICATION_ROWS {
            return Err(StoreError::resource_bound(format!(
                "Python runtime provider publication has {row_count} rows, limit is {MAX_PUBLICATION_ROWS}"
            )));
        }
        for environment in &environments {
            validate_declared_environment_pair(environment)?;
        }
        let base_snapshot = base_snapshot.clone();
        let cancellation = cancellation.clone();
        self.conn.execute(move |conn| -> Result<PythonRuntimeProviderPublication> {
            if cancellation.is_cancelled() {
                return Err(StoreError::new("Python runtime provider publication cancelled"));
            }
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if base_snapshot.lang != "python" {
                return Err(StoreError::new(format!(
                    "Python runtime providers require a python workspace snapshot, got {}",
                    base_snapshot.lang
                )));
            }
            super::require_current_generation(&tx, &base_snapshot.lang, base_snapshot.generation)?;
            let revision_exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM workspace_revisions
                 WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3 AND revision = ?4)",
                params![
                    base_snapshot.workspace_id.as_str(),
                    base_snapshot.lang,
                    base_snapshot.generation.0,
                    base_snapshot.revision,
                ],
                |row| row.get(0),
            )?;
            if !revision_exists {
                return Err(StoreError::stale_generation(format!(
                    "Python runtime provider base snapshot {}:{}:{}:{} was reclaimed",
                    base_snapshot.workspace_id.as_str(),
                    base_snapshot.lang,
                    base_snapshot.generation.0,
                    base_snapshot.revision,
                )));
            }
            let head: Option<i64> = tx
                .query_row(
                    "SELECT revision FROM workspace_heads
                     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3",
                    params![
                        base_snapshot.workspace_id.as_str(),
                        base_snapshot.lang,
                        base_snapshot.generation.0,
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            if head != Some(base_snapshot.revision) {
                return Err(StoreError::stale_resolution(format!(
                    "Python runtime provider base revision {} is not the current workspace head {head:?}",
                    base_snapshot.revision
                )));
            }

            let mut snapshot = base_snapshot.clone();
            if let Some(configuration) = configuration_input {
                configuration.retain(&tx)?;
                let old: Option<(i64, String)> = tx
                    .query_row(
                        "SELECT file_version_id, blob_oid FROM workspace_file_versions
                         WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
                           AND input_kind = 'configuration' AND rel_path = ?4
                           AND valid_until IS NULL",
                        params![
                            base_snapshot.workspace_id.as_str(),
                            base_snapshot.lang,
                            base_snapshot.generation.0,
                            configuration.relative_path(),
                        ],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                let new_oid = configuration.content_oid().to_string();
                if old.as_ref().map(|(_, oid)| oid.as_str()) != Some(new_oid.as_str()) {
                    if cancellation.is_cancelled() {
                        return Err(StoreError::new("Python runtime provider publication cancelled"));
                    }
                    let closed = old.map(|(id, _)| id).into_iter().collect::<Vec<_>>();
                    let replacement = configuration.row();
                    let replacements = [(WorkspaceInputKind::Configuration, &replacement)];
                    (snapshot, _) = workspace_inputs::publish_workspace_input_changes(
                        &tx,
                        &base_snapshot.workspace_id,
                        &base_snapshot.lang,
                        base_snapshot.generation,
                        head,
                        &closed,
                        &replacements,
                    )?;
                }
            }

            if cancellation.is_cancelled() {
                return Err(StoreError::new("Python runtime provider publication cancelled"));
            }
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO python_runtime_acquisitions(
                   workspace_id, lang, generation, revision, evidence_digest
                 ) VALUES(?1, ?2, ?3, ?4, ?5)",
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.lang,
                    snapshot.generation.0,
                    snapshot.revision,
                    evidence_digest.as_slice(),
                ],
            )?;
            let acquisition_id = tx.query_row(
                "SELECT acquisition_id FROM python_runtime_acquisitions
                 WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
                   AND revision = ?4 AND evidence_digest = ?5",
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.lang,
                    snapshot.generation.0,
                    snapshot.revision,
                    evidence_digest.as_slice(),
                ],
                |row| row.get::<_, i64>(0),
            )?;
            if inserted == 1 {
                insert_environments(&tx, acquisition_id, &environments, &cancellation)?;
            }
            if cancellation.is_cancelled() {
                return Err(StoreError::new("Python runtime provider publication cancelled"));
            }
            tx.commit()?;
            Ok(PythonRuntimeProviderPublication {
                acquisition_id: PythonRuntimeAcquisitionId(acquisition_id),
                snapshot,
                evidence_digest,
            })
        })
    }

    /// Validate the acquisition against the selected Python snapshot and
    /// current analyzer generation, then lend the read transaction to the
    /// semantic reader for its indexed SQL. The transaction pins both the
    /// generation check and every result row to one SQLite snapshot.
    pub(crate) fn with_python_runtime_acquisition<T>(
        &self,
        acquisition_id: PythonRuntimeAcquisitionId,
        selected_snapshot: &WorkspaceSnapshotId,
        read: impl FnOnce(&Transaction<'_>) -> Result<T>,
    ) -> Result<T> {
        if selected_snapshot.lang != "python" {
            return Err(StoreError::stale_resolution(format!(
                "Python runtime acquisition cannot be read through {} snapshot",
                selected_snapshot.lang
            )));
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        super::require_current_generation(
            &tx,
            &selected_snapshot.lang,
            selected_snapshot.generation,
        )?;
        let snapshot_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM workspace_revisions
             WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3 AND revision = ?4)",
            params![
                selected_snapshot.workspace_id.as_str(),
                selected_snapshot.lang,
                selected_snapshot.generation.0,
                selected_snapshot.revision,
            ],
            |row| row.get(0),
        )?;
        if !snapshot_exists {
            return Err(StoreError::stale_generation(format!(
                "selected Python workspace snapshot revision {} was reclaimed",
                selected_snapshot.revision
            )));
        }
        let acquisition_matches: bool = tx.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM python_runtime_acquisitions AS acquisition
               JOIN workspace_revisions AS revision
                 ON revision.workspace_id = acquisition.workspace_id
                AND revision.lang = acquisition.lang
                AND revision.generation = acquisition.generation
                AND revision.revision = acquisition.revision
               WHERE acquisition.acquisition_id = ?1
                 AND acquisition.workspace_id = ?2 AND acquisition.lang = ?3
                 AND acquisition.generation = ?4 AND acquisition.revision = ?5
             )",
            params![
                acquisition_id.0,
                selected_snapshot.workspace_id.as_str(),
                selected_snapshot.lang,
                selected_snapshot.generation.0,
                selected_snapshot.revision,
            ],
            |row| row.get(0),
        )?;
        if !acquisition_matches {
            return Err(StoreError::stale_resolution(format!(
                "Python runtime acquisition {} does not belong to the selected workspace snapshot",
                acquisition_id.0
            )));
        }
        let value = read(&tx)?;
        tx.commit()?;
        Ok(value)
    }
}

fn publication_row_count(environments: &[PythonRuntimeEnvironmentInput]) -> Result<usize> {
    let mut rows = 1_usize;
    for environment in environments {
        rows = add_publication_rows(rows, 1)?;
        rows = add_publication_rows(rows, environment.frontiers.len())?;
        if let Some(config) = &environment.declared_environment {
            rows = add_publication_rows(rows, 1)?;
            rows = add_publication_rows(rows, config.root_slots.len())?;
            rows = add_publication_rows(rows, config.config_inputs.len())?;
            rows = add_publication_rows(rows, config.extras.len())?;
        }
        for artifact in &environment.artifacts {
            rows = add_publication_rows(rows, 1)?;
            rows = add_publication_rows(rows, artifact.members.len())?;
            rows = add_publication_rows(rows, artifact.providers.len())?;
        }
    }
    Ok(rows)
}

fn add_publication_rows(total: usize, additional: usize) -> Result<usize> {
    total
        .checked_add(additional)
        .ok_or_else(|| StoreError::resource_bound("Python runtime provider row count overflow"))
}

fn insert_environments(
    tx: &Transaction<'_>,
    acquisition_id: i64,
    environments: &[PythonRuntimeEnvironmentInput],
    cancellation: &CancellationToken,
) -> Result<()> {
    for environment in environments {
        if cancellation.is_cancelled() {
            return Err(StoreError::new(
                "Python runtime provider publication cancelled",
            ));
        }
        let original_scope = stored_path(&environment.source_scope)?;
        let scope = normalized_scope(&environment.source_scope);
        let (scope_path, scope_depth, status) = match scope {
            Some((path, depth)) => (
                Some(path),
                Some(i64::try_from(depth).expect("scope depth fits i64")),
                environment.status,
            ),
            None => (None, None, PythonRuntimeStatus::Unresolved),
        };
        check_cell(&original_scope)?;
        check_optional_cell(environment.diagnostic.as_deref())?;
        tx.execute(
            "INSERT INTO python_runtime_environments(
               acquisition_id, source_scope, scope_path, scope_depth, status, diagnostic
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                acquisition_id,
                original_scope,
                scope_path,
                scope_depth,
                status.as_sql(),
                environment.diagnostic,
            ],
        )?;
        let environment_id = tx.last_insert_rowid();
        if let Some(config) = &environment.declared_environment {
            let digest = environment
                .project_config
                .as_ref()
                .expect("paired declared-environment digest was validated before publication");
            insert_declared_environment(
                tx,
                acquisition_id,
                environment_id,
                config,
                digest,
                cancellation,
            )?;
        }
        insert_artifacts(
            tx,
            acquisition_id,
            environment_id,
            environment,
            cancellation,
        )?;
    }
    Ok(())
}

fn insert_declared_environment(
    tx: &Transaction<'_>,
    acquisition_id: i64,
    environment_id: i64,
    config: &PythonDeclaredEnvironmentConfig,
    digest: &CsmiArtifactDigest,
    cancellation: &CancellationToken,
) -> Result<()> {
    if cancellation.is_cancelled() {
        return Err(StoreError::new(
            "Python runtime provider publication cancelled",
        ));
    }
    let interpreter_path = declared_path(&config.interpreter.path)?;
    let entry_relative_path = declared_path(&config.entry_point.relative_path)?;
    let working_directory = declared_path(&config.entry_point.working_directory)?;
    let canonicalization = digest
        .canonicalization
        .as_deref()
        .expect("project-config canonicalization was validated before publication");
    tx.execute(
        "INSERT INTO python_runtime_declared_environments(
           environment_id, acquisition_id, producer_version, resolver_version,
           interpreter_path, interpreter_sha256, interpreter_implementation,
           interpreter_python_version, interpreter_abi, interpreter_platform,
           isolation_mode, site_startup_mode, environment_mode, import_path_mode,
           finder_mode, editable_installs_mode, native_extensions_mode,
           entry_mode, entry_root_slot_id, entry_relative_path,
           working_directory_root_slot_id, working_directory,
           project_config_algorithm, project_config_coverage,
           project_config_canonicalization, project_config_digest
         ) VALUES(
           ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
           ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26
         )",
        params![
            environment_id,
            acquisition_id,
            config.producer_version,
            config.resolver_version,
            interpreter_path,
            config.interpreter.sha256,
            config.interpreter.implementation,
            config.interpreter.python_version,
            config.interpreter.abi,
            config.interpreter.platform,
            declared_isolation_mode_sql(config.launch.isolation),
            declared_site_startup_mode_sql(config.launch.site_startup),
            declared_environment_mode_sql(config.launch.environment),
            declared_import_path_mode_sql(config.launch.import_path),
            declared_finder_mode_sql(config.launch.finder),
            declared_editable_mode_sql(config.launch.editable_installs),
            declared_native_extensions_mode_sql(config.launch.native_extensions),
            declared_entry_mode_sql(config.entry_point.mode),
            config.entry_point.root_slot_id,
            entry_relative_path,
            config.entry_point.working_directory_root_slot_id,
            working_directory,
            declared_digest_algorithm_sql(digest.algorithm),
            digest.coverage,
            canonicalization,
            digest.value,
        ],
    )?;
    let declared_environment_id = tx.last_insert_rowid();

    for slot in &config.root_slots {
        if cancellation.is_cancelled() {
            return Err(StoreError::new(
                "Python runtime provider publication cancelled",
            ));
        }
        let path = declared_path(&slot.path)?;
        tx.execute(
            "INSERT INTO python_runtime_declared_roots(
               declared_environment_id, ordinal, semantic_id, role, path, artifact_index
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                declared_environment_id,
                i64::from(slot.ordinal),
                slot.slot_id,
                declared_root_role_sql(slot.role),
                path,
                slot.artifact_index.map(i64::from),
            ],
        )?;
    }

    for input in &config.config_inputs {
        if cancellation.is_cancelled() {
            return Err(StoreError::new(
                "Python runtime provider publication cancelled",
            ));
        }
        let path = declared_path(&input.path)?;
        tx.execute(
            "INSERT INTO python_runtime_declared_inputs(
               declared_environment_id, ordinal, input_id, role, path, sha256
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                declared_environment_id,
                i64::from(input.ordinal),
                input.input_id,
                declared_input_role_sql(input.role),
                path,
                input.sha256,
            ],
        )?;
    }

    for (ordinal, extra) in config.extras.iter().enumerate() {
        if cancellation.is_cancelled() {
            return Err(StoreError::new(
                "Python runtime provider publication cancelled",
            ));
        }
        tx.execute(
            "INSERT INTO python_runtime_declared_extras(
               declared_environment_id, ordinal, extra
             ) VALUES(?1, ?2, ?3)",
            params![
                declared_environment_id,
                i64::try_from(ordinal).expect("declared extras count is bounded"),
                extra,
            ],
        )?;
    }
    Ok(())
}

fn insert_artifacts(
    tx: &Transaction<'_>,
    acquisition_id: i64,
    environment_id: i64,
    environment: &PythonRuntimeEnvironmentInput,
    cancellation: &CancellationToken,
) -> Result<()> {
    for artifact in &environment.artifacts {
        if cancellation.is_cancelled() {
            return Err(StoreError::new(
                "Python runtime provider publication cancelled",
            ));
        }
        validate_digest(artifact.archive_sha256.as_deref())?;
        for value in [
            artifact.purl.as_deref(),
            artifact.raw_version.as_deref(),
            artifact.archive_sha256.as_deref(),
            artifact.diagnostic.as_deref(),
        ] {
            check_optional_cell(value)?;
        }
        let archive_path = stored_path(&artifact.archive_path)?;
        let installed_root = stored_path(&artifact.installed_root)?;
        check_cell(&archive_path)?;
        check_cell(&installed_root)?;
        tx.execute(
            "INSERT INTO python_runtime_artifacts(
               environment_id, acquisition_id, purl, raw_version, archive_sha256,
               archive_path, installed_root, status, diagnostic
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                environment_id,
                acquisition_id,
                artifact.purl,
                artifact.raw_version,
                artifact.archive_sha256,
                archive_path,
                installed_root,
                artifact.status.as_sql(),
                artifact.diagnostic,
            ],
        )?;
        let artifact_id = tx.last_insert_rowid();
        let mut member_ids = Vec::with_capacity(artifact.members.len());
        for member in &artifact.members {
            if cancellation.is_cancelled() {
                return Err(StoreError::new(
                    "Python runtime provider publication cancelled",
                ));
            }
            let member_sha256 = member.member_sha256.as_deref();
            validate_digest(member_sha256)?;
            validate_digest(member.installed_sha256.as_deref())?;
            check_optional_cell(member.diagnostic.as_deref())?;
            let archive_member_path = stored_normalized_relative_path(&member.archive_member_path)?;
            let installed_path = member
                .installed_path
                .as_deref()
                .map(stored_path)
                .transpose()?;
            check_cell(&archive_member_path)?;
            check_optional_cell(installed_path.as_deref())?;
            tx.execute(
                "INSERT INTO python_runtime_artifact_members(
                   artifact_id, environment_id, acquisition_id, archive_member_path,
                   installed_path, member_sha256, installed_sha256,
                   installed_bytes_match, member_role, status, diagnostic
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    artifact_id,
                    environment_id,
                    acquisition_id,
                    archive_member_path,
                    installed_path,
                    member_sha256,
                    member.installed_sha256,
                    member.installed_bytes_match,
                    member.role.as_sql(),
                    member.status.as_sql(),
                    member.diagnostic,
                ],
            )?;
            member_ids.push(tx.last_insert_rowid());
        }
        for provider in &artifact.providers {
            if cancellation.is_cancelled() {
                return Err(StoreError::new(
                    "Python runtime provider publication cancelled",
                ));
            }
            check_cell(&provider.import_name)?;
            let member_id = provider
                .member_index
                .map(|index| {
                    member_ids.get(index).copied().ok_or_else(|| {
                        StoreError::new(format!(
                            "Python runtime provider member index {index} is outside its artifact inventory"
                        ))
                    })
                })
                .transpose()?;
            tx.execute(
                "INSERT INTO python_runtime_import_providers(
                   acquisition_id, environment_id, artifact_id, member_id,
                   import_name, binding_status
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    acquisition_id,
                    environment_id,
                    artifact_id,
                    member_id,
                    provider.import_name,
                    provider.status.as_sql(),
                ],
            )?;
        }
        for frontier in &environment.frontiers {
            if cancellation.is_cancelled() {
                return Err(StoreError::new(
                    "Python runtime provider publication cancelled",
                ));
            }
            let root_path = stored_path(&frontier.root)?;
            let path = frontier.path.as_deref().map(stored_path).transpose()?;
            check_cell(&root_path)?;
            check_optional_cell(path.as_deref())?;
            check_optional_cell(frontier.import_name.as_deref())?;
            check_cell(&frontier.message)?;
            tx.execute(
                "INSERT INTO python_runtime_scope_frontiers(
                   acquisition_id, environment_id, kind, root_path, path,
                   import_name, message
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    acquisition_id,
                    environment_id,
                    frontier.kind.as_sql(),
                    root_path,
                    path,
                    frontier.import_name,
                    frontier.message,
                ],
            )?;
        }
    }
    Ok(())
}

fn normalized_scope(path: &Path) -> Option<(String, usize)> {
    if path.is_absolute() {
        return None;
    }
    let mut components = Vec::new();
    for component in path.components() {
        let Component::Normal(value) = component else {
            return None;
        };
        let value = value.to_str()?;
        let bytes = value.as_bytes();
        let has_windows_drive_prefix = components.is_empty()
            && bytes.len() >= 2
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':';
        if value.contains('\\') || has_windows_drive_prefix {
            return None;
        }
        components.push(value);
    }
    if components.is_empty() {
        Some((".".to_owned(), 0))
    } else {
        Some((components.join("/"), components.len()))
    }
}

fn stored_path(path: &Path) -> Result<String> {
    let value = if path.as_os_str().is_empty() {
        ".".to_owned()
    } else {
        path.to_string_lossy().into_owned()
    };
    check_cell(&value)?;
    Ok(value)
}

fn stored_normalized_relative_path(path: &Path) -> Result<String> {
    if path.is_absolute() {
        return Err(StoreError::new(
            "Python runtime archive member path must be relative",
        ));
    }
    let mut components = Vec::new();
    for component in path.components() {
        let Component::Normal(value) = component else {
            return Err(StoreError::new(
                "Python runtime archive member path must contain normal components",
            ));
        };
        let value = value.to_str().ok_or_else(|| {
            StoreError::new("Python runtime archive member path is not valid UTF-8")
        })?;
        if value.is_empty() {
            return Err(StoreError::new(
                "Python runtime archive member path has an empty component",
            ));
        }
        components.push(value);
    }
    if components.is_empty() {
        return Err(StoreError::new(
            "Python runtime archive member path cannot be empty",
        ));
    }
    let normalized = components.join("/");
    check_cell(&normalized)?;
    Ok(normalized)
}

fn validate_declared_environment_pair(environment: &PythonRuntimeEnvironmentInput) -> Result<()> {
    match (
        environment.declared_environment.as_ref(),
        environment.project_config.as_ref(),
    ) {
        (None, None) => Ok(()),
        (Some(config), Some(digest)) => validate_declared_environment(config, digest),
        _ => Err(StoreError::new(
            "Python declared environment and project-config digest must be supplied together",
        )),
    }
}

fn validate_declared_environment(
    config: &PythonDeclaredEnvironmentConfig,
    digest: &CsmiArtifactDigest,
) -> Result<()> {
    validate_project_config(digest)?;
    for (field, value) in [
        ("producer version", config.producer_version.as_str()),
        ("resolver version", config.resolver_version.as_str()),
        (
            "interpreter implementation",
            config.interpreter.implementation.as_str(),
        ),
        (
            "interpreter Python version",
            config.interpreter.python_version.as_str(),
        ),
        ("interpreter ABI", config.interpreter.abi.as_str()),
        ("interpreter platform", config.interpreter.platform.as_str()),
        (
            "entry root slot ID",
            config.entry_point.root_slot_id.as_str(),
        ),
        (
            "working-directory root slot ID",
            config.entry_point.working_directory_root_slot_id.as_str(),
        ),
    ] {
        check_nonempty_declared_cell(field, value)?;
    }
    validate_digest(Some(&config.interpreter.sha256))?;
    check_declared_path(&config.interpreter.path, "interpreter path", false)?;
    check_declared_path(
        &config.entry_point.relative_path,
        "entry relative path",
        true,
    )?;
    check_declared_path(
        &config.entry_point.working_directory,
        "working directory",
        true,
    )?;

    let mut root_slot_ids = HashSet::with_capacity(config.root_slots.len());
    for (position, slot) in config.root_slots.iter().enumerate() {
        let expected = u32::try_from(position).expect("declared root count is bounded");
        if slot.ordinal != expected {
            return Err(StoreError::new(format!(
                "Python declared root ordinal {} must match its position {expected}",
                slot.ordinal
            )));
        }
        check_nonempty_declared_cell("root semantic ID", &slot.slot_id)?;
        if !root_slot_ids.insert(slot.slot_id.as_str()) {
            return Err(StoreError::new(format!(
                "duplicate Python declared root semantic ID {:?}",
                slot.slot_id
            )));
        }
        check_declared_path(&slot.path, "root path", false)?;
    }
    for slot_id in [
        config.entry_point.root_slot_id.as_str(),
        config.entry_point.working_directory_root_slot_id.as_str(),
    ] {
        if !root_slot_ids.contains(slot_id) {
            return Err(StoreError::new(format!(
                "Python declared entry point references unknown root slot {slot_id:?}"
            )));
        }
    }

    let mut input_ids = HashSet::with_capacity(config.config_inputs.len());
    for (position, input) in config.config_inputs.iter().enumerate() {
        let expected = u32::try_from(position).expect("declared input count is bounded");
        if input.ordinal != expected {
            return Err(StoreError::new(format!(
                "Python declared config-input ordinal {} must match its position {expected}",
                input.ordinal
            )));
        }
        check_nonempty_declared_cell("config-input ID", &input.input_id)?;
        if !input_ids.insert(input.input_id.as_str()) {
            return Err(StoreError::new(format!(
                "duplicate Python declared config-input ID {:?}",
                input.input_id
            )));
        }
        check_declared_path(&input.path, "config-input path", false)?;
        validate_digest(Some(&input.sha256))?;
    }
    for extra in &config.extras {
        check_nonempty_declared_cell("enabled extra", extra)?;
    }
    Ok(())
}

fn validate_project_config(digest: &CsmiArtifactDigest) -> Result<()> {
    if digest.algorithm != CsmiDigestAlgorithm::Sha256
        || digest.coverage != PYTHON_DECLARED_PROJECT_CONFIG_COVERAGE
        || digest.canonicalization.as_deref()
            != Some(PYTHON_DECLARED_PROJECT_CONFIG_CANONICALIZATION_URI)
    {
        return Err(StoreError::new(
            "Python project-config digest must use sha-256, resolver-affecting-config coverage, and the declared-environment v1 canonicalization URI",
        ));
    }
    check_nonempty_declared_cell("project-config coverage", &digest.coverage)?;
    check_nonempty_declared_cell(
        "project-config canonicalization URI",
        digest
            .canonicalization
            .as_deref()
            .expect("canonical URI checked"),
    )?;
    check_nonempty_declared_cell("project-config digest", &digest.value)?;
    validate_digest(Some(&digest.value))
}

fn check_declared_path(path: &Path, field: &str, allow_empty: bool) -> Result<()> {
    let value = path
        .to_str()
        .ok_or_else(|| StoreError::new(format!("Python declared {field} is not valid UTF-8")))?;
    if !allow_empty && value.is_empty() {
        return Err(StoreError::new(format!("Python declared {field} is empty")));
    }
    check_cell(value)
}

fn declared_path(path: &Path) -> Result<String> {
    let value = path.to_str().ok_or_else(|| {
        StoreError::new("Python declared path is not valid UTF-8 and cannot be reconstructed")
    })?;
    check_cell(value)?;
    Ok(value.to_owned())
}

fn check_nonempty_declared_cell(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(StoreError::new(format!("Python declared {field} is empty")));
    }
    check_cell(value)
}

fn persisted_ordinal(value: i64, position: usize, field: &str) -> Result<u32> {
    let ordinal = persisted_u32(value, &format!("{field} ordinal"))?;
    if usize::try_from(ordinal).ok() != Some(position) {
        return Err(StoreError::new(format!(
            "Python declared {field} ordinals are not contiguous: found {ordinal} at position {position}"
        )));
    }
    Ok(ordinal)
}

fn persisted_u32(value: i64, field: &str) -> Result<u32> {
    u32::try_from(value).map_err(|_| {
        StoreError::new(format!(
            "persisted Python {field} is outside u32 range: {value}"
        ))
    })
}

fn declared_isolation_mode_sql(value: PythonDeclaredIsolationMode) -> &'static str {
    match value {
        PythonDeclaredIsolationMode::Isolated => "isolated",
        PythonDeclaredIsolationMode::EnvironmentSensitive => "environment_sensitive",
    }
}

fn parse_declared_isolation_mode(value: &str) -> Result<PythonDeclaredIsolationMode> {
    match value {
        "isolated" => Ok(PythonDeclaredIsolationMode::Isolated),
        "environment_sensitive" => Ok(PythonDeclaredIsolationMode::EnvironmentSensitive),
        _ => Err(invalid_declared_value("isolation mode", value)),
    }
}

fn declared_site_startup_mode_sql(value: PythonDeclaredSiteStartupMode) -> &'static str {
    match value {
        PythonDeclaredSiteStartupMode::Disabled => "disabled",
        PythonDeclaredSiteStartupMode::Enabled => "enabled",
    }
}

fn parse_declared_site_startup_mode(value: &str) -> Result<PythonDeclaredSiteStartupMode> {
    match value {
        "disabled" => Ok(PythonDeclaredSiteStartupMode::Disabled),
        "enabled" => Ok(PythonDeclaredSiteStartupMode::Enabled),
        _ => Err(invalid_declared_value("site-startup mode", value)),
    }
}

fn declared_environment_mode_sql(value: PythonDeclaredEnvironmentMode) -> &'static str {
    match value {
        PythonDeclaredEnvironmentMode::Cleared => "cleared",
        PythonDeclaredEnvironmentMode::ExplicitInputs => "explicit_inputs",
        PythonDeclaredEnvironmentMode::Ambient => "ambient",
    }
}

fn parse_declared_environment_mode(value: &str) -> Result<PythonDeclaredEnvironmentMode> {
    match value {
        "cleared" => Ok(PythonDeclaredEnvironmentMode::Cleared),
        "explicit_inputs" => Ok(PythonDeclaredEnvironmentMode::ExplicitInputs),
        "ambient" => Ok(PythonDeclaredEnvironmentMode::Ambient),
        _ => Err(invalid_declared_value("environment mode", value)),
    }
}

fn declared_import_path_mode_sql(value: PythonDeclaredImportPathMode) -> &'static str {
    match value {
        PythonDeclaredImportPathMode::DeclaredRootsOnly => "declared_roots_only",
        PythonDeclaredImportPathMode::EnvironmentAugmented => "environment_augmented",
    }
}

fn parse_declared_import_path_mode(value: &str) -> Result<PythonDeclaredImportPathMode> {
    match value {
        "declared_roots_only" => Ok(PythonDeclaredImportPathMode::DeclaredRootsOnly),
        "environment_augmented" => Ok(PythonDeclaredImportPathMode::EnvironmentAugmented),
        _ => Err(invalid_declared_value("import-path mode", value)),
    }
}

fn declared_finder_mode_sql(value: PythonDeclaredFinderMode) -> &'static str {
    match value {
        PythonDeclaredFinderMode::StandardFilesystem => "standard_filesystem",
        PythonDeclaredFinderMode::CustomHooks => "custom_hooks",
    }
}

fn parse_declared_finder_mode(value: &str) -> Result<PythonDeclaredFinderMode> {
    match value {
        "standard_filesystem" => Ok(PythonDeclaredFinderMode::StandardFilesystem),
        "custom_hooks" => Ok(PythonDeclaredFinderMode::CustomHooks),
        _ => Err(invalid_declared_value("finder mode", value)),
    }
}

fn declared_editable_mode_sql(value: PythonDeclaredEditableInstallMode) -> &'static str {
    match value {
        PythonDeclaredEditableInstallMode::Disabled => "disabled",
        PythonDeclaredEditableInstallMode::Enabled => "enabled",
    }
}

fn parse_declared_editable_mode(value: &str) -> Result<PythonDeclaredEditableInstallMode> {
    match value {
        "disabled" => Ok(PythonDeclaredEditableInstallMode::Disabled),
        "enabled" => Ok(PythonDeclaredEditableInstallMode::Enabled),
        _ => Err(invalid_declared_value("editable-installs mode", value)),
    }
}

fn declared_native_extensions_mode_sql(value: PythonDeclaredNativeExtensionMode) -> &'static str {
    match value {
        PythonDeclaredNativeExtensionMode::Disabled => "disabled",
        PythonDeclaredNativeExtensionMode::Enabled => "enabled",
    }
}

fn parse_declared_native_extensions_mode(value: &str) -> Result<PythonDeclaredNativeExtensionMode> {
    match value {
        "disabled" => Ok(PythonDeclaredNativeExtensionMode::Disabled),
        "enabled" => Ok(PythonDeclaredNativeExtensionMode::Enabled),
        _ => Err(invalid_declared_value("native-extensions mode", value)),
    }
}

fn declared_entry_mode_sql(value: PythonDeclaredEntryMode) -> &'static str {
    match value {
        PythonDeclaredEntryMode::Script => "script",
        PythonDeclaredEntryMode::Module => "module",
        PythonDeclaredEntryMode::CommandString => "command_string",
    }
}

fn parse_declared_entry_mode(value: &str) -> Result<PythonDeclaredEntryMode> {
    match value {
        "script" => Ok(PythonDeclaredEntryMode::Script),
        "module" => Ok(PythonDeclaredEntryMode::Module),
        "command_string" => Ok(PythonDeclaredEntryMode::CommandString),
        _ => Err(invalid_declared_value("entry mode", value)),
    }
}

fn declared_root_role_sql(value: PythonDeclaredRootRole) -> &'static str {
    match value {
        PythonDeclaredRootRole::Source => "source",
        PythonDeclaredRootRole::StandardLibrary => "standard_library",
        PythonDeclaredRootRole::InstalledDistribution => "installed_distribution",
    }
}

fn parse_declared_root_role(value: &str) -> Result<PythonDeclaredRootRole> {
    match value {
        "source" => Ok(PythonDeclaredRootRole::Source),
        "standard_library" => Ok(PythonDeclaredRootRole::StandardLibrary),
        "installed_distribution" => Ok(PythonDeclaredRootRole::InstalledDistribution),
        _ => Err(invalid_declared_value("root role", value)),
    }
}

fn declared_input_role_sql(value: PythonDeclaredConfigInputRole) -> &'static str {
    match value {
        PythonDeclaredConfigInputRole::ResolverConfiguration => "resolver_configuration",
        PythonDeclaredConfigInputRole::StartupConfiguration => "startup_configuration",
        PythonDeclaredConfigInputRole::EnvironmentConfiguration => "environment_configuration",
        PythonDeclaredConfigInputRole::ExtrasConfiguration => "extras_configuration",
        PythonDeclaredConfigInputRole::EntryConfiguration => "entry_configuration",
    }
}

fn parse_declared_input_role(value: &str) -> Result<PythonDeclaredConfigInputRole> {
    match value {
        "resolver_configuration" => Ok(PythonDeclaredConfigInputRole::ResolverConfiguration),
        "startup_configuration" => Ok(PythonDeclaredConfigInputRole::StartupConfiguration),
        "environment_configuration" => Ok(PythonDeclaredConfigInputRole::EnvironmentConfiguration),
        "extras_configuration" => Ok(PythonDeclaredConfigInputRole::ExtrasConfiguration),
        "entry_configuration" => Ok(PythonDeclaredConfigInputRole::EntryConfiguration),
        _ => Err(invalid_declared_value("config-input role", value)),
    }
}

fn declared_digest_algorithm_sql(value: CsmiDigestAlgorithm) -> &'static str {
    match value {
        CsmiDigestAlgorithm::Sha256 => "sha-256",
        CsmiDigestAlgorithm::Sha384 => "sha-384",
        CsmiDigestAlgorithm::Sha512 => "sha-512",
    }
}

fn parse_declared_digest_algorithm(value: &str) -> Result<CsmiDigestAlgorithm> {
    match value {
        "sha-256" => Ok(CsmiDigestAlgorithm::Sha256),
        "sha-384" => Ok(CsmiDigestAlgorithm::Sha384),
        "sha-512" => Ok(CsmiDigestAlgorithm::Sha512),
        _ => Err(invalid_declared_value("digest algorithm", value)),
    }
}

fn invalid_declared_value(field: &str, value: &str) -> StoreError {
    StoreError::new(format!(
        "invalid persisted Python declared {field}: {value:?}"
    ))
}

fn validate_digest(digest: Option<&str>) -> Result<()> {
    if let Some(digest) = digest
        && (digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        return Err(StoreError::new(format!(
            "Python runtime SHA-256 must be 64 lowercase hexadecimal characters, got {digest:?}"
        )));
    }
    Ok(())
}

fn check_cell(value: &str) -> Result<()> {
    if value.len() > MAX_CELL_BYTES {
        return Err(StoreError::resource_bound(format!(
            "Python runtime provider cell is {} bytes, limit is {MAX_CELL_BYTES}",
            value.len()
        )));
    }
    Ok(())
}

fn check_optional_cell(value: Option<&str>) -> Result<()> {
    if let Some(value) = value {
        check_cell(value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use rusqlite::{Connection, params};

    use super::*;
    use crate::analyzer::store::WorkspaceId;
    use crate::analyzer::store::planner_statistics::tests::{explain_pin, pinned};

    fn empty_python_snapshot(
        store: &AnalyzerStore,
        workspace_id: &WorkspaceId,
        epoch: &str,
    ) -> WorkspaceSnapshotId {
        let generation = store
            .ensure_language_epoch_value("python", epoch)
            .expect("python generation");
        store
            .sync_workspace_snapshot_for_workspace(
                workspace_id,
                "python",
                generation,
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .expect("empty workspace revision")
    }

    fn declared_environment_fixture() -> (PythonDeclaredEnvironmentConfig, CsmiArtifactDigest) {
        (
            PythonDeclaredEnvironmentConfig {
                producer_version: "descriptor-1".to_owned(),
                resolver_version: "resolver-1".to_owned(),
                interpreter: PythonDeclaredInterpreter {
                    path: PathBuf::from(".venv/bin/python"),
                    sha256: "b".repeat(64),
                    implementation: "cpython".to_owned(),
                    python_version: "3.12.4".to_owned(),
                    abi: "cp312".to_owned(),
                    platform: "linux-x86_64".to_owned(),
                },
                launch: PythonDeclaredLaunchSemantics {
                    isolation: PythonDeclaredIsolationMode::Isolated,
                    site_startup: PythonDeclaredSiteStartupMode::Disabled,
                    environment: PythonDeclaredEnvironmentMode::ExplicitInputs,
                    import_path: PythonDeclaredImportPathMode::DeclaredRootsOnly,
                    finder: PythonDeclaredFinderMode::StandardFilesystem,
                    editable_installs: PythonDeclaredEditableInstallMode::Disabled,
                    native_extensions: PythonDeclaredNativeExtensionMode::Enabled,
                },
                entry_point: brokk_bifrost_core::analyzer::config::PythonDeclaredEntryPoint {
                    mode: PythonDeclaredEntryMode::Module,
                    root_slot_id: "source:app".to_owned(),
                    relative_path: PathBuf::from("pkg/main.py"),
                    working_directory_root_slot_id: "source:app".to_owned(),
                    working_directory: PathBuf::from("."),
                },
                extras: vec!["test".to_owned(), "fast".to_owned()],
                config_inputs: vec![
                    PythonDeclaredConfigInput {
                        ordinal: 0,
                        input_id: "resolver:pyproject".to_owned(),
                        role: PythonDeclaredConfigInputRole::ResolverConfiguration,
                        path: PathBuf::from("pyproject.toml"),
                        sha256: "c".repeat(64),
                    },
                    PythonDeclaredConfigInput {
                        ordinal: 1,
                        input_id: "entry:descriptor".to_owned(),
                        role: PythonDeclaredConfigInputRole::EntryConfiguration,
                        path: PathBuf::from(".bifrost/python-entry.json"),
                        sha256: "d".repeat(64),
                    },
                ],
                root_slots: vec![
                    PythonDeclaredRootSlot {
                        ordinal: 0,
                        slot_id: "source:app".to_owned(),
                        role: PythonDeclaredRootRole::Source,
                        path: PathBuf::from("src"),
                        artifact_index: None,
                    },
                    PythonDeclaredRootSlot {
                        ordinal: 1,
                        slot_id: "site:example".to_owned(),
                        role: PythonDeclaredRootRole::InstalledDistribution,
                        path: PathBuf::from(".venv/site-packages/example"),
                        artifact_index: Some(0),
                    },
                ],
            },
            CsmiArtifactDigest {
                algorithm: CsmiDigestAlgorithm::Sha256,
                coverage: PYTHON_DECLARED_PROJECT_CONFIG_COVERAGE.to_owned(),
                canonicalization: Some(
                    PYTHON_DECLARED_PROJECT_CONFIG_CANONICALIZATION_URI.to_owned(),
                ),
                value: "e".repeat(64),
            },
        )
    }

    #[test]
    fn publication_is_idempotent_snapshot_bound_and_cascades_with_projection_drop() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let workspace_id = WorkspaceId("a".repeat(64));
        let base = empty_python_snapshot(&store, &workspace_id, "python-runtime-publication-v1");
        let digest = [0x5a; 32];
        let config = || {
            WorkspaceConfigurationInput::new(
                ".bifrost/python-runtime-selection.json".to_owned(),
                br#"{"version":1}"#.to_vec().into_boxed_slice(),
            )
        };
        let cancellation = CancellationToken::default();
        let publication = store
            .publish_python_runtime_providers(
                &base,
                Some(config()),
                digest,
                Vec::new(),
                &cancellation,
            )
            .unwrap();
        assert_eq!(publication.snapshot.revision, base.revision + 1);
        assert_eq!(publication.evidence_digest, digest);

        let repeated = store
            .publish_python_runtime_providers(
                &publication.snapshot,
                Some(config()),
                digest,
                Vec::new(),
                &cancellation,
            )
            .unwrap();
        assert_eq!(repeated.snapshot, publication.snapshot);
        assert_eq!(repeated.acquisition_id, publication.acquisition_id);

        let foreign_snapshot = empty_python_snapshot(
            &store,
            &WorkspaceId("b".repeat(64)),
            "python-runtime-publication-v1",
        );
        let wrong_snapshot = store.with_python_runtime_acquisition(
            publication.acquisition_id,
            &foreign_snapshot,
            |_| Ok(()),
        );
        assert!(wrong_snapshot.is_err_and(|error| error.is_stale_resolution()));

        store
            .delete_workspace_projection(&workspace_id)
            .expect("drop workspace projection");
        let dropped_snapshot = store.with_python_runtime_acquisition(
            publication.acquisition_id,
            &publication.snapshot,
            |_| Ok(()),
        );
        assert!(dropped_snapshot.is_err_and(|error| error.is_stale_generation()));
        let conn = store.conn.lock().unwrap();
        let acquisition_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM python_runtime_acquisitions",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            acquisition_count, 0,
            "revision deletion must cascade evidence"
        );
    }

    #[test]
    fn publication_read_rejects_a_changed_analysis_generation() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let workspace_id = WorkspaceId("c".repeat(64));
        let snapshot = empty_python_snapshot(&store, &workspace_id, "python-runtime-epoch-a");
        let publication = store
            .publish_python_runtime_providers(
                &snapshot,
                None,
                [0x33; 32],
                Vec::new(),
                &CancellationToken::default(),
            )
            .unwrap();
        store
            .ensure_language_epoch_value("python", "python-runtime-epoch-b")
            .unwrap();

        let stale = store.with_python_runtime_acquisition(
            publication.acquisition_id,
            &snapshot,
            |_| Ok(()),
        );
        assert!(stale.is_err_and(|error| error.is_stale_generation()));
    }

    #[test]
    fn populated_provider_publication_reads_back_exact_artifact_member_candidate() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let workspace_id = WorkspaceId("f".repeat(64));
        let base_snapshot = empty_python_snapshot(
            &store,
            &workspace_id,
            "python-runtime-provider-roundtrip-v1",
        );
        let archive_sha256 = "c".repeat(64);
        let member_sha256 = "a".repeat(64);
        let (declared_environment, project_config) = declared_environment_fixture();
        let publication = store
            .publish_python_runtime_providers(
                &base_snapshot,
                None,
                [0x66; 32],
                vec![PythonRuntimeEnvironmentInput {
                    source_scope: PathBuf::from("src/pkg"),
                    status: PythonRuntimeStatus::ArchiveVerified,
                    diagnostic: None,
                    artifacts: vec![PythonRuntimeArtifactInput {
                        purl: Some("pkg:pypi/example@1.2".to_owned()),
                        raw_version: Some("1.2".to_owned()),
                        archive_sha256: Some(archive_sha256.clone()),
                        archive_path: PathBuf::from("/archives/example-1.2.whl"),
                        installed_root: PathBuf::from("/venv/site-packages"),
                        status: PythonRuntimeStatus::ArchiveVerified,
                        diagnostic: None,
                        members: vec![PythonRuntimeMemberInput {
                            archive_member_path: PathBuf::from("pkg/mod.py"),
                            installed_path: Some(PathBuf::from("/venv/site-packages/pkg/mod.py")),
                            member_sha256: Some(member_sha256.clone()),
                            installed_sha256: Some(member_sha256.clone()),
                            installed_bytes_match: Some(true),
                            role: PythonRuntimeMemberRole::Runtime,
                            status: PythonRuntimeStatus::BytesMatched,
                            diagnostic: None,
                        }],
                        providers: vec![PythonRuntimeProviderInput {
                            import_name: "pkg.mod".to_owned(),
                            member_index: Some(0),
                            status: PythonRuntimeBindingStatus::Unresolved,
                        }],
                    }],
                    frontiers: Vec::new(),
                    declared_environment: Some(declared_environment.clone()),
                    project_config: Some(project_config.clone()),
                }],
                &CancellationToken::default(),
            )
            .unwrap();
        let acquisition_id = publication.acquisition_id.get();
        let selected_snapshot = publication.snapshot;
        let workspace_key = selected_snapshot.workspace_id.as_str().to_owned();
        let lang = selected_snapshot.lang.clone();
        let generation = selected_snapshot.generation.0;
        let revision = selected_snapshot.revision;

        let (candidate, reconstructed) = store
            .with_python_runtime_acquisition(publication.acquisition_id, &selected_snapshot, |tx| {
                let environment = tx.query_row(
                    PYTHON_RUNTIME_SCOPE_AT_PATH_SQL,
                    params![acquisition_id, "src/pkg"],
                    PythonRuntimeScopeRow::from_row,
                )?;
                let candidate = tx.query_row(
                    PYTHON_RUNTIME_IMPORT_CANDIDATES_SQL,
                    params![
                        acquisition_id,
                        environment.environment_id,
                        "pkg.mod",
                        workspace_key,
                        lang,
                        generation,
                        revision,
                    ],
                    PythonRuntimeProviderCandidateRow::from_row,
                )?;
                let reconstructed = python_runtime_declared_environment(
                    tx,
                    acquisition_id,
                    environment.environment_id,
                )?;
                let cross_acquisition = python_runtime_declared_environment(
                    tx,
                    acquisition_id + 1,
                    environment.environment_id,
                )?;
                assert!(cross_acquisition.is_none());
                Ok((candidate, reconstructed))
            })
            .unwrap();

        assert_eq!(candidate.import_name, "pkg.mod");
        assert_eq!(candidate.purl.as_deref(), Some("pkg:pypi/example@1.2"));
        assert_eq!(candidate.raw_version.as_deref(), Some("1.2"));
        assert_eq!(
            candidate.archive_sha256.as_deref(),
            Some(archive_sha256.as_str())
        );
        assert_eq!(candidate.artifact_status, "archive_verified");
        assert_eq!(candidate.archive_member_path.as_deref(), Some("pkg/mod.py"));
        assert_eq!(
            candidate.installed_path.as_deref(),
            Some("/venv/site-packages/pkg/mod.py")
        );
        assert_eq!(
            candidate.member_sha256.as_deref(),
            Some(member_sha256.as_str())
        );
        assert_eq!(
            candidate.installed_sha256.as_deref(),
            Some(member_sha256.as_str())
        );
        assert_eq!(candidate.installed_bytes_match, Some(true));
        assert_eq!(candidate.member_role.as_deref(), Some("runtime"));
        assert_eq!(candidate.member_status.as_deref(), Some("bytes_matched"));
        assert_eq!(reconstructed, Some((declared_environment, project_config)));
    }

    #[test]
    fn existing_projection_lease_drop_reclaims_provider_acquisition() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(
            AnalyzerStore::open_persistent(&temp.path().join("analyzer-cache.sqlite")).unwrap(),
        );
        let workspace_id = WorkspaceId("d".repeat(64));
        let snapshot =
            empty_python_snapshot(&store, &workspace_id, "python-runtime-projection-lease-v1");
        let (mut declared_environment, project_config) = declared_environment_fixture();
        declared_environment.root_slots.truncate(1);
        let publication = store
            .publish_python_runtime_providers(
                &snapshot,
                None,
                [0x44; 32],
                vec![PythonRuntimeEnvironmentInput {
                    source_scope: PathBuf::from("."),
                    status: PythonRuntimeStatus::Incomplete,
                    diagnostic: None,
                    artifacts: Vec::new(),
                    frontiers: Vec::new(),
                    declared_environment: Some(declared_environment),
                    project_config: Some(project_config),
                }],
                &CancellationToken::default(),
            )
            .unwrap();

        let lease = crate::analyzer::workspace::WorkspaceProjectionLease::new(
            Arc::clone(&store),
            workspace_id,
        );
        drop(lease);
        let reclaimed = store.with_python_runtime_acquisition(
            publication.acquisition_id,
            &snapshot,
            |_| Ok(()),
        );
        assert!(reclaimed.is_err_and(|error| error.is_stale_generation()));
        store
            .read_source_transaction("python", snapshot.generation, |tx| {
                for table in [
                    "python_runtime_declared_environments",
                    "python_runtime_declared_roots",
                    "python_runtime_declared_inputs",
                    "python_runtime_declared_extras",
                ] {
                    let count: i64 = tx
                        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                            row.get(0)
                        })
                        .unwrap();
                    assert_eq!(count, 0, "lease reclamation must cascade to {table}");
                }
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn python_runtime_pinned_queries_use_indexes_on_populated_store_both_states() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        populate_runtime_plan_fixture(&conn);
        let plans = [
            (
                "python_runtime_scope_at_path",
                "python_runtime_environments_by_scope",
            ),
            (
                "python_runtime_unresolved_scopes",
                "python_runtime_environments_by_scope",
            ),
            (
                "python_runtime_import_candidates",
                "python_runtime_import_providers_by_import",
            ),
            (
                "python_runtime_artifacts_for_environment",
                "python_runtime_artifacts_by_environment",
            ),
            (
                "python_runtime_artifact_members",
                "python_runtime_artifact_members_by_acquisition_artifact",
            ),
            (
                "python_runtime_scope_frontiers",
                "python_runtime_frontiers_by_scope",
            ),
            (
                "python_runtime_unnamed_scope_frontiers",
                "python_runtime_frontiers_by_scope",
            ),
            (
                "python_runtime_declared_environment",
                "python_runtime_declared_environments_by_environment",
            ),
            ("python_runtime_declared_roots", "PRIMARY KEY"),
            ("python_runtime_declared_inputs", "PRIMARY KEY"),
            ("python_runtime_declared_extras", "PRIMARY KEY"),
        ];
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            for (name, expected_index) in plans {
                let plan = explain_pin(&conn, &pinned(name));
                assert!(
                    plan.iter().any(|detail| detail.contains(expected_index)),
                    "{name} must seek {expected_index} {state}: {plan:#?}"
                );
                assert!(
                    !plan.iter().any(|detail| detail.contains("AUTOMATIC")),
                    "{name} must not need an automatic index {state}: {plan:#?}"
                );
                if name.starts_with("python_runtime_declared_") {
                    assert!(
                        !plan
                            .iter()
                            .any(|detail| detail.contains("SCAN python_runtime_declared_")),
                        "{name} must not scan declared-environment rows {state}: {plan:#?}"
                    );
                }
            }
        }
    }

    fn populate_runtime_plan_fixture(conn: &Connection) {
        let workspace_id = "a".repeat(64);
        conn.execute(
            "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
             VALUES(?1, 'python', 0, 1)",
            [&workspace_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO python_runtime_acquisitions(
               acquisition_id, workspace_id, lang, generation, revision, evidence_digest
             ) VALUES(1, ?1, 'python', 0, 1, zeroblob(32))",
            [&workspace_id],
        )
        .unwrap();
        for index in 0..48_i64 {
            let source_scope = if index == 6 {
                "src/pkg".to_owned()
            } else {
                format!("src/decoy-{index}")
            };
            conn.execute(
                "INSERT INTO python_runtime_environments(
                   acquisition_id, source_scope, scope_path, scope_depth, status
                 ) VALUES(1, ?1, ?1, 2, 'incomplete')",
                [&source_scope],
            )
            .unwrap();
            let environment_id = conn.last_insert_rowid();
            conn.execute(
                "INSERT INTO python_runtime_artifacts(
                   environment_id, acquisition_id, archive_path, installed_root, status
                 ) VALUES(?1, 1, ?2, '/site-packages', 'incomplete')",
                params![environment_id, format!("/archives/{index}.whl")],
            )
            .unwrap();
            let artifact_id = conn.last_insert_rowid();
            conn.execute(
                "INSERT INTO python_runtime_artifact_members(
                   artifact_id, environment_id, acquisition_id, archive_member_path,
                   member_role, status
                 ) VALUES(?1, ?2, 1, 'pkg/module.py', 'runtime', 'unresolved')",
                params![artifact_id, environment_id],
            )
            .unwrap();
            let member_id = conn.last_insert_rowid();
            conn.execute(
                "INSERT INTO python_runtime_import_providers(
                   acquisition_id, environment_id, artifact_id, member_id,
                   import_name, binding_status
                 ) VALUES(1, ?1, ?2, ?3, 'pkg.module', 'unresolved')",
                params![environment_id, artifact_id, member_id],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO python_runtime_scope_frontiers(
                   acquisition_id, environment_id, kind, root_path, import_name, message
                 ) VALUES(1, ?1, 'scan_limit', '/site-packages', 'pkg.module', 'fixture frontier')",
                [environment_id],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO python_runtime_scope_frontiers(
                   acquisition_id, environment_id, kind, root_path, message
                 ) VALUES(1, ?1, 'import_hook_semantics_unknown', '/site-packages', 'unnamed fixture frontier')",
                [environment_id],
            )
            .unwrap();
        }
        let environment_id: i64 = conn
            .query_row(
                "SELECT environment_id FROM python_runtime_environments
                 WHERE acquisition_id = 1 AND scope_path = 'src/pkg'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            environment_id, 7,
            "pinned query uses this fixture environment"
        );
        conn.execute(
            "INSERT INTO python_runtime_declared_environments(
               environment_id, acquisition_id, producer_version, resolver_version,
               interpreter_path, interpreter_sha256, interpreter_implementation,
               interpreter_python_version, interpreter_abi, interpreter_platform,
               isolation_mode, site_startup_mode, environment_mode, import_path_mode,
               finder_mode, editable_installs_mode, native_extensions_mode,
               entry_mode, entry_root_slot_id, entry_relative_path,
               working_directory_root_slot_id, working_directory,
               project_config_algorithm, project_config_coverage,
               project_config_canonicalization, project_config_digest
             ) VALUES(
               ?1, 1, 'descriptor-1', 'resolver-1', '.venv/bin/python', ?2,
               'cpython', '3.12.4', 'cp312', 'linux-x86_64', 'isolated',
               'disabled', 'explicit_inputs', 'declared_roots_only',
               'standard_filesystem', 'disabled', 'enabled', 'module',
               'source:app', 'pkg/main.py', 'source:app', '.', 'sha-256',
               'resolver-affecting-config',
               'https://bifrost.brokk.ai/csmi/python/project-config/rfc8785-v1', ?3
             )",
            params![environment_id, "b".repeat(64), "e".repeat(64)],
        )
        .unwrap();
        let declared_environment_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO python_runtime_declared_roots(
               declared_environment_id, ordinal, semantic_id, role, path, artifact_index
             ) VALUES(?1, 0, 'source:app', 'source', 'src', NULL)",
            [declared_environment_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO python_runtime_declared_inputs(
               declared_environment_id, ordinal, input_id, role, path, sha256
             ) VALUES(?1, 0, 'resolver:pyproject', 'resolver_configuration',
                     'pyproject.toml', ?2)",
            params![declared_environment_id, "c".repeat(64)],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO python_runtime_declared_extras(
               declared_environment_id, ordinal, extra
             ) VALUES(?1, 0, 'test')",
            [declared_environment_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO python_runtime_environments(
               acquisition_id, source_scope, scope_path, scope_depth, status
             ) VALUES(1, '../unresolved', NULL, NULL, 'unresolved')",
            [],
        )
        .unwrap();
    }

    #[test]
    fn source_scope_ancestors_observe_path_components_and_keep_workspace_root() {
        let paths = python_runtime_scope_ancestors(Path::new("src/pkgish/module.py")).unwrap();
        let spellings = paths
            .into_iter()
            .map(|ancestor| ancestor.path)
            .collect::<Vec<_>>();
        assert_eq!(
            spellings,
            ["src/pkgish/module.py", "src/pkgish", "src", "."]
        );
        assert!(python_runtime_scope_ancestors(Path::new("../src")).is_err());
        assert!(python_runtime_scope_ancestors(Path::new(r"C:\src")).is_err());
        assert!(python_runtime_scope_ancestors(Path::new("C:/src")).is_err());
    }

    #[test]
    fn empty_member_digest_is_rejected_as_malformed_evidence() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let workspace_id = WorkspaceId("e".repeat(64));
        let snapshot = empty_python_snapshot(
            &store,
            &workspace_id,
            "python-runtime-empty-member-digest-v1",
        );
        let cancellation = CancellationToken::default();
        let environment = |member_sha256| PythonRuntimeEnvironmentInput {
            source_scope: PathBuf::from("."),
            status: PythonRuntimeStatus::Incomplete,
            diagnostic: None,
            artifacts: vec![PythonRuntimeArtifactInput {
                purl: None,
                raw_version: None,
                archive_sha256: None,
                archive_path: PathBuf::from("/archives/example.whl"),
                installed_root: PathBuf::from("/site-packages"),
                status: PythonRuntimeStatus::Incomplete,
                diagnostic: None,
                members: vec![PythonRuntimeMemberInput {
                    archive_member_path: PathBuf::from("example.py"),
                    installed_path: None,
                    member_sha256,
                    installed_sha256: None,
                    installed_bytes_match: None,
                    role: PythonRuntimeMemberRole::Runtime,
                    status: PythonRuntimeStatus::Unresolved,
                    diagnostic: None,
                }],
                providers: Vec::new(),
            }],
            frontiers: Vec::new(),
            declared_environment: None,
            project_config: None,
        };

        let rejected = store.publish_python_runtime_providers(
            &snapshot,
            None,
            [0x55; 32],
            vec![environment(Some(String::new()))],
            &cancellation,
        );
        let error = rejected.expect_err("an empty supplied digest must fail publication");
        assert!(
            error
                .to_string()
                .contains("Python runtime SHA-256 must be 64 lowercase hexadecimal characters"),
            "empty supplied digest must fail at the digest validator, got {error:?}"
        );

        let publication = store
            .publish_python_runtime_providers(
                &snapshot,
                None,
                [0x55; 32],
                vec![environment(None)],
                &cancellation,
            )
            .expect("an unresolved member may omit its digest");
        let acquisition_id = publication.acquisition_id.get();
        let member: (Option<String>, String) = store
            .with_python_runtime_acquisition(
                publication.acquisition_id,
                &publication.snapshot,
                |tx| {
                    Ok(tx.query_row(
                        "SELECT member_sha256, status
                         FROM python_runtime_artifact_members
                         WHERE acquisition_id = ?1",
                        [acquisition_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )?)
                },
            )
            .unwrap();
        assert_eq!(member, (None, "unresolved".to_owned()));
    }
}
