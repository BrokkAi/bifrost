//! Bounded validation and portable identity for an explicitly declared Python
//! filesystem-import environment.
//!
//! The resulting evidence describes the declared resolver contract. It does
//! not attest to an arbitrary interpreter that may currently be running.

use crate::CancellationToken;
use crate::analyzer::canonical_hash::{lower_hex_string, sha256_bytes};
use crate::analyzer::semantic_model::csmi::{
    CsmiArtifactDigest, CsmiDigestAlgorithm, canonical_json,
};
use crate::analyzer::semantic_model::{DependencyPackLimits, PythonConditionSnapshot};
use brokk_bifrost_core::analyzer::config::{
    PYTHON_DECLARED_PROJECT_CONFIG_CANONICALIZATION_URI, PythonDeclaredConfigInputRole,
    PythonDeclaredEditableInstallMode, PythonDeclaredEntryMode, PythonDeclaredEntryPoint,
    PythonDeclaredEnvironmentConfig, PythonDeclaredEnvironmentMode, PythonDeclaredFinderMode,
    PythonDeclaredImportPathMode, PythonDeclaredIsolationMode, PythonDeclaredLaunchSemantics,
    PythonDeclaredNativeExtensionMode, PythonDeclaredRootRole, PythonDeclaredSiteStartupMode,
    PythonRuntimeEnvironmentConfig,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

/// Producer version accepted for declared Python environment descriptors.
pub const SUPPORTED_PYTHON_DECLARED_ENVIRONMENT_PRODUCER_VERSION: &str =
    "bifrost-python-environment-producer/v1";
/// Declared filesystem resolver semantics accepted by this implementation.
pub const SUPPORTED_PYTHON_DECLARED_FILESYSTEM_RESOLVER_VERSION: &str =
    "python-filesystem-resolver/v1";

/// Current inventory digest for one root slot, supplied by the caller's
/// bounded Python root scan. Order and semantic identity are checked against
/// the descriptor before these rows participate in projectConfig.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PythonDeclaredRootInventory {
    pub(crate) ordinal: u32,
    pub(crate) slot_id: String,
    pub(crate) role: PythonDeclaredRootRole,
    pub(crate) inventory_sha256: String,
}

/// A verified configuration input used to build the portable digest.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PythonCheckedConfigInput {
    ordinal: u32,
    input_id: String,
    role: PythonDeclaredConfigInputRole,
    sha256: String,
}

/// A verified ordered root used to build the portable digest. Its local path
/// was checked as a host binding and is intentionally omitted here.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PythonCheckedRootSlot {
    ordinal: u32,
    slot_id: String,
    role: PythonDeclaredRootRole,
    artifact_index: Option<u32>,
    inventory_sha256: String,
}

/// Opaque evidence that declared inputs and host bindings passed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckedPythonDeclaredEnvironment {
    project_config: CsmiArtifactDigest,
    condition_snapshot: PythonConditionSnapshot,
    input_bytes_read: u64,
    input_files_read: usize,
}

impl CheckedPythonDeclaredEnvironment {
    pub(crate) fn project_config(&self) -> &CsmiArtifactDigest {
        &self.project_config
    }

    pub(crate) fn condition_snapshot(&self) -> PythonConditionSnapshot {
        self.condition_snapshot.clone()
    }

    /// Bytes rehashed here for the interpreter and configuration inputs.
    /// Root inventory bytes are accounted by the caller.
    pub(crate) fn input_bytes_read(&self) -> u64 {
        self.input_bytes_read
    }

    /// Number of files rehashed here: the interpreter plus config inputs.
    /// Root inventory files are accounted by the caller.
    pub(crate) fn input_files_read(&self) -> usize {
        self.input_files_read
    }
}

#[derive(Debug)]
/// Failure to validate or produce declared Python projectConfig evidence.
pub enum PythonDeclaredEnvironmentError {
    /// No descriptor was supplied for this runtime environment.
    MissingDeclaredEnvironment,
    /// The descriptor names a producer version this implementation cannot validate.
    UnsupportedProducerVersion(String),
    /// The descriptor names filesystem resolver semantics this implementation cannot validate.
    UnsupportedResolverVersion(String),
    /// A launch setting is outside the supported declared filesystem-import subset.
    UnsupportedLaunchSemantics {
        /// The launch setting that is unsupported.
        field: &'static str,
        /// Its declared value.
        mode: String,
    },
    /// Required descriptor evidence is absent, inconsistent, or malformed.
    Incomplete(String),
    /// Validation was interrupted through the supplied cancellation token.
    Cancelled,
    /// A configured relative path is invalid or escapes the workspace.
    PathOutsideWorkspace(PathBuf),
    /// A configured path or one of its components is a symbolic link.
    Symlink(PathBuf),
    /// A configured path does not exist.
    MissingPath(PathBuf),
    /// A configured path does not have the required regular-file or directory kind.
    UnsupportedPathKind {
        /// The path with the unsupported kind.
        path: PathBuf,
        /// The required path kind.
        expected: &'static str,
    },
    /// A declared SHA-256 value is malformed.
    InvalidInputDigest {
        /// The semantic ID of the input with a malformed digest.
        input_id: String,
    },
    /// The bytes at a declared configuration input do not match its digest.
    InputDigestMismatch {
        /// The semantic ID of the input whose content changed.
        input_id: String,
        /// The declared lowercase SHA-256 digest.
        expected: String,
        /// The digest computed from the current bytes.
        actual: String,
    },
    /// A root inventory row has a malformed SHA-256 value.
    InvalidRootInventoryDigest {
        /// The semantic ID of the root with a malformed digest.
        slot_id: String,
    },
    /// Current ordered root inventory rows do not match the descriptor.
    RootInventoryMismatch(String),
    /// A configured bound was exceeded.
    LimitExceeded {
        /// The bounded resource that exceeded its limit.
        resource: &'static str,
        /// The configured upper bound.
        limit: u64,
    },
    /// A filesystem operation failed while inspecting or reading an input.
    Io {
        /// The path involved in the failed operation.
        path: PathBuf,
        /// The underlying operating-system error.
        source: io::Error,
    },
    /// Canonical RFC8785 projectConfig bytes could not be produced.
    Canonicalization(String),
}

impl fmt::Display for PythonDeclaredEnvironmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDeclaredEnvironment => {
                write!(
                    formatter,
                    "runtime environment has no declared Python environment"
                )
            }
            Self::UnsupportedProducerVersion(version) => write!(
                formatter,
                "unsupported declared Python environment producer version: {version}"
            ),
            Self::UnsupportedResolverVersion(version) => write!(
                formatter,
                "unsupported declared Python filesystem resolver version: {version}"
            ),
            Self::UnsupportedLaunchSemantics { field, mode } => write!(
                formatter,
                "unsupported declared Python launch mode for {field}: {mode}"
            ),
            Self::Incomplete(details) => {
                write!(
                    formatter,
                    "declared Python environment is incomplete: {details}"
                )
            }
            Self::Cancelled => {
                write!(
                    formatter,
                    "declared Python environment validation was cancelled"
                )
            }
            Self::PathOutsideWorkspace(path) => write!(
                formatter,
                "workspace-relative path is invalid or escapes the workspace: {}",
                path.display()
            ),
            Self::Symlink(path) => {
                write!(
                    formatter,
                    "configured path contains a symbolic link: {}",
                    path.display()
                )
            }
            Self::MissingPath(path) => {
                write!(formatter, "configured path is missing: {}", path.display())
            }
            Self::UnsupportedPathKind { path, expected } => write!(
                formatter,
                "configured path has an unsupported file kind: {} ({expected})",
                path.display()
            ),
            Self::InvalidInputDigest { input_id } => {
                write!(
                    formatter,
                    "configured input digest is malformed for {input_id}"
                )
            }
            Self::InputDigestMismatch {
                input_id,
                expected,
                actual,
            } => write!(
                formatter,
                "configured input bytes do not match for {input_id}: expected {expected}, got {actual}"
            ),
            Self::InvalidRootInventoryDigest { slot_id } => write!(
                formatter,
                "Python root inventory digest is malformed for slot {slot_id}"
            ),
            Self::RootInventoryMismatch(details) => {
                write!(
                    formatter,
                    "Python root inventory differs from declared slots: {details}"
                )
            }
            Self::LimitExceeded { resource, limit } => write!(
                formatter,
                "Python declared-environment validation exceeded {resource} limit {limit}"
            ),
            Self::Io { path, source } => write!(
                formatter,
                "could not inspect configured path {}: {source}",
                path.display()
            ),
            Self::Canonicalization(details) => {
                write!(
                    formatter,
                    "could not canonicalize Python projectConfig: {details}"
                )
            }
        }
    }
}

impl std::error::Error for PythonDeclaredEnvironmentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Validate the declared filesystem-import environment and finalize its
/// portable projectConfig using the caller's current, bounded root inventory.
/// This function never executes an interpreter or parses dependency files.
pub(crate) fn produce_python_declared_environment(
    workspace_root: &Path,
    runtime: &PythonRuntimeEnvironmentConfig,
    ordered_root_inventory: &[PythonDeclaredRootInventory],
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> Result<CheckedPythonDeclaredEnvironment, PythonDeclaredEnvironmentError> {
    check_cancelled(cancellation)?;
    let declared = runtime
        .declared_environment
        .as_ref()
        .ok_or(PythonDeclaredEnvironmentError::MissingDeclaredEnvironment)?;
    if runtime.artifacts.len() > limits.max_artifacts_per_dependency {
        return Err(PythonDeclaredEnvironmentError::LimitExceeded {
            resource: "installed artifacts",
            limit: limits.max_artifacts_per_dependency as u64,
        });
    }
    validate_scalar_inputs(declared, runtime, limits)?;
    validate_versions(declared)?;
    validate_launch_semantics(&declared.launch)?;

    let workspace_root = fs::canonicalize(workspace_root)
        .map_err(|source| path_io_error(workspace_root.to_path_buf(), source))?;
    if !workspace_root.is_dir() {
        return Err(PythonDeclaredEnvironmentError::UnsupportedPathKind {
            path: workspace_root,
            expected: "workspace directory",
        });
    }

    let runtime_source = normalize_workspace_relative(&runtime.source_root)?;
    let source_slots = declared
        .root_slots
        .iter()
        .filter(|slot| slot.role == PythonDeclaredRootRole::Source)
        .collect::<Vec<_>>();
    if source_slots.len() != 1
        || normalize_workspace_relative(&source_slots[0].path)? != runtime_source
    {
        return Err(PythonDeclaredEnvironmentError::RootInventoryMismatch(
            "exactly one source slot must bind PythonRuntimeEnvironmentConfig.source_root"
                .to_owned(),
        ));
    }

    validate_root_slots(runtime, declared, ordered_root_inventory, limits)?;

    let mut total_bytes = 0_u64;
    let interpreter_path = inspect_workspace_binding(
        &workspace_root,
        &declared.interpreter.path,
        ExpectedPathKind::File,
    )?;
    validate_sha256(&declared.interpreter.sha256, "interpreter".to_owned())?;
    let interpreter_sha256 = hash_file_bounded(
        &workspace_root,
        &interpreter_path,
        "interpreter".to_owned(),
        &declared.interpreter.sha256,
        limits,
        cancellation,
        &mut total_bytes,
    )?;

    let mut checked_inputs = Vec::with_capacity(declared.config_inputs.len());
    for input in &declared.config_inputs {
        check_cancelled(cancellation)?;
        let absolute =
            inspect_workspace_binding(&workspace_root, &input.path, ExpectedPathKind::File)?;
        validate_sha256(&input.sha256, input.input_id.clone())?;
        let sha256 = hash_file_bounded(
            &workspace_root,
            &absolute,
            input.input_id.clone(),
            &input.sha256,
            limits,
            cancellation,
            &mut total_bytes,
        )?;
        checked_inputs.push(PythonCheckedConfigInput {
            ordinal: input.ordinal,
            input_id: input.input_id.clone(),
            role: input.role,
            sha256,
        });
    }
    let input_files_read = declared.config_inputs.len().checked_add(1).ok_or(
        PythonDeclaredEnvironmentError::LimitExceeded {
            resource: "declared input files",
            limit: limits.producer.max_records as u64,
        },
    )?;

    let mut checked_roots = Vec::with_capacity(declared.root_slots.len());
    let mut root_paths = HashMap::<String, PathBuf>::with_capacity(declared.root_slots.len());
    for (slot, inventory) in declared.root_slots.iter().zip(ordered_root_inventory) {
        check_cancelled(cancellation)?;
        let absolute =
            inspect_workspace_binding(&workspace_root, &slot.path, ExpectedPathKind::Directory)?;
        root_paths.insert(slot.slot_id.clone(), absolute);
        checked_roots.push(PythonCheckedRootSlot {
            ordinal: slot.ordinal,
            slot_id: slot.slot_id.clone(),
            role: slot.role,
            artifact_index: slot.artifact_index,
            inventory_sha256: inventory.inventory_sha256.clone(),
        });
    }

    for artifact in &runtime.artifacts {
        inspect_workspace_binding(
            &workspace_root,
            &artifact.archive_path,
            ExpectedPathKind::File,
        )?;
    }

    validate_entry_point(&workspace_root, &declared.entry_point, &root_paths)?;

    let project_config_bytes = canonical_project_config(
        declared,
        &interpreter_sha256,
        &checked_inputs,
        &checked_roots,
    )?;
    let project_config = CsmiArtifactDigest {
        algorithm: CsmiDigestAlgorithm::Sha256,
        coverage: "resolver-affecting-config".to_owned(),
        canonicalization: Some(PYTHON_DECLARED_PROJECT_CONFIG_CANONICALIZATION_URI.to_owned()),
        value: lower_hex_string(&sha256_bytes(&project_config_bytes)),
    };
    let condition_snapshot = PythonConditionSnapshot {
        python_version_raw: Some(declared.interpreter.python_version.clone()),
        implementation: Some(declared.interpreter.implementation.clone()),
        abi_tag: Some(declared.interpreter.abi.clone()),
        platform_tag: Some(declared.interpreter.platform.clone()),
        enabled_extras: Some(declared.extras.iter().cloned().collect::<BTreeSet<_>>()),
        project_config: Some(project_config.clone()),
    };

    Ok(CheckedPythonDeclaredEnvironment {
        project_config,
        condition_snapshot,
        input_bytes_read: total_bytes,
        input_files_read,
    })
}

fn validate_versions(
    declared: &PythonDeclaredEnvironmentConfig,
) -> Result<(), PythonDeclaredEnvironmentError> {
    if declared.producer_version != SUPPORTED_PYTHON_DECLARED_ENVIRONMENT_PRODUCER_VERSION {
        return Err(PythonDeclaredEnvironmentError::UnsupportedProducerVersion(
            declared.producer_version.clone(),
        ));
    }
    if declared.resolver_version != SUPPORTED_PYTHON_DECLARED_FILESYSTEM_RESOLVER_VERSION {
        return Err(PythonDeclaredEnvironmentError::UnsupportedResolverVersion(
            declared.resolver_version.clone(),
        ));
    }
    Ok(())
}

fn validate_launch_semantics(
    launch: &PythonDeclaredLaunchSemantics,
) -> Result<(), PythonDeclaredEnvironmentError> {
    let supported = [
        (
            "isolation",
            matches!(launch.isolation, PythonDeclaredIsolationMode::Isolated),
            format!("{:?}", launch.isolation),
        ),
        (
            "site_startup",
            matches!(launch.site_startup, PythonDeclaredSiteStartupMode::Disabled),
            format!("{:?}", launch.site_startup),
        ),
        (
            "environment",
            matches!(launch.environment, PythonDeclaredEnvironmentMode::Cleared),
            format!("{:?}", launch.environment),
        ),
        (
            "import_path",
            matches!(
                launch.import_path,
                PythonDeclaredImportPathMode::DeclaredRootsOnly
            ),
            format!("{:?}", launch.import_path),
        ),
        (
            "finder",
            matches!(launch.finder, PythonDeclaredFinderMode::StandardFilesystem),
            format!("{:?}", launch.finder),
        ),
        (
            "editable_installs",
            matches!(
                launch.editable_installs,
                PythonDeclaredEditableInstallMode::Disabled
            ),
            format!("{:?}", launch.editable_installs),
        ),
        (
            "native_extensions",
            matches!(
                launch.native_extensions,
                PythonDeclaredNativeExtensionMode::Disabled
            ),
            format!("{:?}", launch.native_extensions),
        ),
    ];
    for (field, is_supported, mode) in supported {
        if !is_supported {
            return Err(PythonDeclaredEnvironmentError::UnsupportedLaunchSemantics { field, mode });
        }
    }
    Ok(())
}

fn validate_scalar_inputs(
    declared: &PythonDeclaredEnvironmentConfig,
    runtime: &PythonRuntimeEnvironmentConfig,
    limits: &DependencyPackLimits,
) -> Result<(), PythonDeclaredEnvironmentError> {
    let row_count = declared
        .config_inputs
        .len()
        .saturating_add(declared.root_slots.len())
        .saturating_add(declared.extras.len());
    if row_count > limits.producer.max_records {
        return Err(PythonDeclaredEnvironmentError::LimitExceeded {
            resource: "declared environment rows",
            limit: limits.producer.max_records as u64,
        });
    }
    if declared.root_slots.len() > limits.max_source_files_per_artifact {
        return Err(PythonDeclaredEnvironmentError::LimitExceeded {
            resource: "declared root slots",
            limit: limits.max_source_files_per_artifact as u64,
        });
    }
    let mut scalar_bytes = 0_u64;
    for value in [
        declared.producer_version.as_str(),
        declared.resolver_version.as_str(),
        declared.interpreter.sha256.as_str(),
        declared.interpreter.implementation.as_str(),
        declared.interpreter.python_version.as_str(),
        declared.interpreter.abi.as_str(),
        declared.interpreter.platform.as_str(),
        declared.entry_point.root_slot_id.as_str(),
        declared.entry_point.working_directory_root_slot_id.as_str(),
    ] {
        scalar_bytes = scalar_bytes.saturating_add(value.len() as u64);
    }
    for path in [
        &declared.interpreter.path,
        &declared.entry_point.relative_path,
        &declared.entry_point.working_directory,
        &runtime.source_root,
    ] {
        scalar_bytes = scalar_bytes.saturating_add(relative_path_scalar_bytes(
            path,
            limits.producer.max_artifact_bytes,
            limits.max_source_path_depth,
        )? as u64);
    }
    for extra in &declared.extras {
        scalar_bytes = scalar_bytes.saturating_add(extra.len() as u64);
    }
    for input in &declared.config_inputs {
        scalar_bytes = scalar_bytes
            .saturating_add(input.input_id.len() as u64)
            .saturating_add(input.sha256.len() as u64)
            .saturating_add(relative_path_scalar_bytes(
                &input.path,
                limits.producer.max_artifact_bytes,
                limits.max_source_path_depth,
            )? as u64);
    }
    for slot in &declared.root_slots {
        scalar_bytes = scalar_bytes
            .saturating_add(slot.slot_id.len() as u64)
            .saturating_add(relative_path_scalar_bytes(
                &slot.path,
                limits.producer.max_artifact_bytes,
                limits.max_source_path_depth,
            )? as u64);
    }
    for artifact in &runtime.artifacts {
        scalar_bytes = scalar_bytes
            .saturating_add(relative_path_scalar_bytes(
                &artifact.archive_path,
                limits.producer.max_artifact_bytes,
                limits.max_source_path_depth,
            )? as u64)
            .saturating_add(relative_path_scalar_bytes(
                &artifact.installed_root,
                limits.producer.max_artifact_bytes,
                limits.max_source_path_depth,
            )? as u64);
    }
    let canonical_upper_bound = scalar_bytes
        .saturating_mul(6)
        .saturating_add((row_count as u64).saturating_mul(256))
        .saturating_add(4_096);
    if canonical_upper_bound > limits.producer.max_artifact_bytes {
        return Err(PythonDeclaredEnvironmentError::LimitExceeded {
            resource: "canonical declared environment bytes",
            limit: limits.producer.max_artifact_bytes,
        });
    }

    for (field, value) in [
        (
            "interpreter implementation",
            declared.interpreter.implementation.as_str(),
        ),
        (
            "Python version",
            declared.interpreter.python_version.as_str(),
        ),
        ("interpreter ABI", declared.interpreter.abi.as_str()),
        (
            "interpreter platform",
            declared.interpreter.platform.as_str(),
        ),
    ] {
        if value.trim().is_empty() {
            return Err(PythonDeclaredEnvironmentError::Incomplete(format!(
                "{field} is empty"
            )));
        }
    }

    let mut extras = HashSet::with_capacity(declared.extras.len());
    for extra in &declared.extras {
        if extra.trim().is_empty() || !extras.insert(extra) {
            return Err(PythonDeclaredEnvironmentError::Incomplete(
                "enabled extras must be nonempty and unique".to_owned(),
            ));
        }
    }

    let mut input_ids = HashSet::with_capacity(declared.config_inputs.len());
    let mut required_roles = [false; 5];
    for (expected_ordinal, input) in declared.config_inputs.iter().enumerate() {
        validate_ordinal(expected_ordinal, input.ordinal, "configuration input")?;
        validate_semantic_id(&input.input_id, "configuration input")?;
        if !input_ids.insert(input.input_id.as_str()) {
            return Err(PythonDeclaredEnvironmentError::Incomplete(format!(
                "duplicate configuration input ID {:?}",
                input.input_id
            )));
        }
        required_roles[match input.role {
            PythonDeclaredConfigInputRole::ResolverConfiguration => 0,
            PythonDeclaredConfigInputRole::StartupConfiguration => 1,
            PythonDeclaredConfigInputRole::EnvironmentConfiguration => 2,
            PythonDeclaredConfigInputRole::ExtrasConfiguration => 3,
            PythonDeclaredConfigInputRole::EntryConfiguration => 4,
        }] = true;
    }
    if required_roles.contains(&false) {
        return Err(PythonDeclaredEnvironmentError::Incomplete(
            "configuration input list must cover resolver, startup, environment, extras, and entry inputs"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_root_slots(
    runtime: &PythonRuntimeEnvironmentConfig,
    declared: &PythonDeclaredEnvironmentConfig,
    inventory: &[PythonDeclaredRootInventory],
    limits: &DependencyPackLimits,
) -> Result<(), PythonDeclaredEnvironmentError> {
    if declared.root_slots.len() != inventory.len() {
        return Err(PythonDeclaredEnvironmentError::RootInventoryMismatch(
            "inventory row count differs from declared root-slot count".to_owned(),
        ));
    }
    if declared.root_slots.len() > limits.max_source_files_per_artifact {
        return Err(PythonDeclaredEnvironmentError::LimitExceeded {
            resource: "declared root slots",
            limit: limits.max_source_files_per_artifact as u64,
        });
    }

    let mut slot_ids = HashSet::with_capacity(declared.root_slots.len());
    let mut slot_paths = HashSet::with_capacity(declared.root_slots.len());
    let mut installed_indices = HashSet::with_capacity(runtime.artifacts.len());
    let mut standard_library_roots = 0_usize;
    for (index, (slot, current)) in declared.root_slots.iter().zip(inventory).enumerate() {
        check_ordinal_limit(index, limits.max_source_files_per_artifact)?;
        validate_ordinal(index, slot.ordinal, "root slot")?;
        validate_ordinal(index, current.ordinal, "root inventory")?;
        validate_semantic_id(&slot.slot_id, "root slot")?;
        if !slot_ids.insert(slot.slot_id.as_str()) {
            return Err(PythonDeclaredEnvironmentError::Incomplete(format!(
                "duplicate root slot ID {:?}",
                slot.slot_id
            )));
        }
        if current.slot_id != slot.slot_id || current.role != slot.role {
            return Err(PythonDeclaredEnvironmentError::RootInventoryMismatch(
                format!("inventory row {index} identity or role differs from its declared slot"),
            ));
        }
        validate_sha256(&current.inventory_sha256, slot.slot_id.clone()).map_err(|error| {
            match error {
                PythonDeclaredEnvironmentError::InvalidInputDigest { .. } => {
                    PythonDeclaredEnvironmentError::InvalidRootInventoryDigest {
                        slot_id: slot.slot_id.clone(),
                    }
                }
                other => other,
            }
        })?;
        let normalized_path = normalize_workspace_relative(&slot.path)?;
        if !slot_paths.insert(normalized_path.clone()) {
            return Err(PythonDeclaredEnvironmentError::Incomplete(format!(
                "duplicate root path {:?}",
                normalized_path
            )));
        }
        match slot.role {
            PythonDeclaredRootRole::Source if slot.artifact_index.is_none() => {}
            PythonDeclaredRootRole::StandardLibrary if slot.artifact_index.is_none() => {
                standard_library_roots += 1;
            }
            PythonDeclaredRootRole::InstalledDistribution => {
                let artifact_index = slot.artifact_index.ok_or_else(|| {
                    PythonDeclaredEnvironmentError::Incomplete(format!(
                        "installed root slot {:?} has no artifact index",
                        slot.slot_id
                    ))
                })? as usize;
                let artifact = runtime.artifacts.get(artifact_index).ok_or_else(|| {
                    PythonDeclaredEnvironmentError::Incomplete(format!(
                        "installed root slot {:?} names undeclared artifact index {artifact_index}",
                        slot.slot_id
                    ))
                })?;
                if normalize_workspace_relative(&artifact.installed_root)? != normalized_path
                    || !installed_indices.insert(artifact_index)
                {
                    return Err(PythonDeclaredEnvironmentError::RootInventoryMismatch(
                        "installed root slots must bind each declared artifact exactly once"
                            .to_owned(),
                    ));
                }
            }
            _ => {
                return Err(PythonDeclaredEnvironmentError::Incomplete(format!(
                    "root slot {:?} has an artifact index incompatible with role {:?}",
                    slot.slot_id, slot.role
                )));
            }
        }
    }

    if standard_library_roots == 0 {
        return Err(PythonDeclaredEnvironmentError::RootInventoryMismatch(
            "declared roots contain no standard-library slot".to_owned(),
        ));
    }
    if installed_indices.len() != runtime.artifacts.len()
        || installed_indices
            .iter()
            .any(|index| *index >= runtime.artifacts.len())
    {
        return Err(PythonDeclaredEnvironmentError::RootInventoryMismatch(
            "declared roots do not include every installed artifact root".to_owned(),
        ));
    }
    Ok(())
}

fn validate_entry_point(
    workspace_root: &Path,
    entry: &PythonDeclaredEntryPoint,
    root_paths: &HashMap<String, PathBuf>,
) -> Result<(), PythonDeclaredEnvironmentError> {
    if entry.mode != PythonDeclaredEntryMode::Script {
        return Err(PythonDeclaredEnvironmentError::UnsupportedLaunchSemantics {
            field: "entry_point.mode",
            mode: format!("{:?}", entry.mode),
        });
    }
    let source_root = root_paths.get(&entry.root_slot_id).ok_or_else(|| {
        PythonDeclaredEnvironmentError::Incomplete(format!(
            "entry point references unknown root slot {:?}",
            entry.root_slot_id
        ))
    })?;
    let entry_relative = normalize_workspace_relative(&entry.relative_path)?;
    if entry_relative == Path::new(".") {
        return Err(PythonDeclaredEnvironmentError::Incomplete(
            "script entry point has an empty relative path".to_owned(),
        ));
    }
    inspect_workspace_binding(
        workspace_root,
        &source_root
            .strip_prefix(workspace_root)
            .map_err(|_| PythonDeclaredEnvironmentError::PathOutsideWorkspace(source_root.clone()))?
            .join(&entry_relative),
        ExpectedPathKind::File,
    )?;

    let working_root = root_paths
        .get(&entry.working_directory_root_slot_id)
        .ok_or_else(|| {
            PythonDeclaredEnvironmentError::Incomplete(format!(
                "working directory references unknown root slot {:?}",
                entry.working_directory_root_slot_id
            ))
        })?;
    let working_relative = normalize_workspace_relative(&entry.working_directory)?;
    inspect_workspace_binding(
        workspace_root,
        &working_root
            .strip_prefix(workspace_root)
            .map_err(|_| {
                PythonDeclaredEnvironmentError::PathOutsideWorkspace(working_root.clone())
            })?
            .join(working_relative),
        ExpectedPathKind::Directory,
    )?;
    Ok(())
}

fn canonical_project_config(
    declared: &PythonDeclaredEnvironmentConfig,
    interpreter_sha256: &str,
    inputs: &[PythonCheckedConfigInput],
    roots: &[PythonCheckedRootSlot],
) -> Result<Vec<u8>, PythonDeclaredEnvironmentError> {
    let portable_inputs = inputs
        .iter()
        .map(|input| PortableConfigInput {
            ordinal: input.ordinal,
            input_id: &input.input_id,
            role: input.role,
            sha256: &input.sha256,
        })
        .collect();
    let portable_roots = roots
        .iter()
        .map(|root| PortableRootSlot {
            ordinal: root.ordinal,
            slot_id: &root.slot_id,
            role: root.role,
            artifact_index: root.artifact_index,
            inventory_sha256: &root.inventory_sha256,
        })
        .collect();
    let portable = PortableProjectConfig {
        schema: "python-project-config/v1",
        producer_version: &declared.producer_version,
        resolver_version: &declared.resolver_version,
        interpreter: PortableInterpreter {
            sha256: interpreter_sha256,
            implementation: &declared.interpreter.implementation,
            python_version: &declared.interpreter.python_version,
            abi: &declared.interpreter.abi,
            platform: &declared.interpreter.platform,
        },
        launch: &declared.launch,
        entry_point: PortableEntryPoint {
            mode: declared.entry_point.mode,
            root_slot_id: &declared.entry_point.root_slot_id,
            relative_path: portable_relative_path(&declared.entry_point.relative_path)?,
            working_directory_root_slot_id: &declared.entry_point.working_directory_root_slot_id,
            working_directory: portable_relative_path(&declared.entry_point.working_directory)?,
        },
        extras: &declared.extras,
        config_inputs: portable_inputs,
        root_slots: portable_roots,
    };
    canonical_json(&portable)
        .map_err(|error| PythonDeclaredEnvironmentError::Canonicalization(error.to_string()))
}

#[derive(Serialize)]
struct PortableProjectConfig<'a> {
    schema: &'static str,
    producer_version: &'a str,
    resolver_version: &'a str,
    interpreter: PortableInterpreter<'a>,
    launch: &'a PythonDeclaredLaunchSemantics,
    entry_point: PortableEntryPoint<'a>,
    extras: &'a [String],
    config_inputs: Vec<PortableConfigInput<'a>>,
    root_slots: Vec<PortableRootSlot<'a>>,
}

#[derive(Serialize)]
struct PortableInterpreter<'a> {
    sha256: &'a str,
    implementation: &'a str,
    python_version: &'a str,
    abi: &'a str,
    platform: &'a str,
}

#[derive(Serialize)]
struct PortableEntryPoint<'a> {
    mode: PythonDeclaredEntryMode,
    root_slot_id: &'a str,
    relative_path: String,
    working_directory_root_slot_id: &'a str,
    working_directory: String,
}

#[derive(Serialize)]
struct PortableConfigInput<'a> {
    ordinal: u32,
    input_id: &'a str,
    role: PythonDeclaredConfigInputRole,
    sha256: &'a str,
}

#[derive(Serialize)]
struct PortableRootSlot<'a> {
    ordinal: u32,
    slot_id: &'a str,
    role: PythonDeclaredRootRole,
    artifact_index: Option<u32>,
    inventory_sha256: &'a str,
}

fn hash_file_bounded(
    workspace_root: &Path,
    absolute_path: &Path,
    input_id: String,
    expected_sha256: &str,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
    total_bytes: &mut u64,
) -> Result<String, PythonDeclaredEnvironmentError> {
    check_cancelled(cancellation)?;
    let relative_path = absolute_path
        .strip_prefix(workspace_root)
        .expect("input path was resolved within the canonical workspace");
    let metadata = fs::symlink_metadata(absolute_path)
        .map_err(|source| path_io_error(absolute_path.to_path_buf(), source))?;
    if metadata.file_type().is_symlink() {
        return Err(PythonDeclaredEnvironmentError::Symlink(
            absolute_path.to_path_buf(),
        ));
    }
    if !metadata.is_file() {
        return Err(PythonDeclaredEnvironmentError::UnsupportedPathKind {
            path: absolute_path.to_path_buf(),
            expected: "regular file",
        });
    }
    if metadata.len() > limits.producer.max_artifact_bytes {
        return Err(PythonDeclaredEnvironmentError::LimitExceeded {
            resource: "single input bytes",
            limit: limits.producer.max_artifact_bytes,
        });
    }
    if (*total_bytes).saturating_add(metadata.len()) > limits.max_total_artifact_bytes {
        return Err(PythonDeclaredEnvironmentError::LimitExceeded {
            resource: "total input bytes",
            limit: limits.max_total_artifact_bytes,
        });
    }

    let mut file = File::open(absolute_path)
        .map_err(|source| path_io_error(absolute_path.to_path_buf(), source))?;
    if !file
        .metadata()
        .map_err(|source| path_io_error(absolute_path.to_path_buf(), source))?
        .is_file()
    {
        return Err(PythonDeclaredEnvironmentError::UnsupportedPathKind {
            path: absolute_path.to_path_buf(),
            expected: "regular file",
        });
    }

    let mut hasher = Sha256::new();
    let mut file_bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        check_cancelled(cancellation)?;
        let read = file
            .read(&mut buffer)
            .map_err(|source| path_io_error(absolute_path.to_path_buf(), source))?;
        if read == 0 {
            break;
        }
        let read = read as u64;
        file_bytes = file_bytes.saturating_add(read);
        *total_bytes = total_bytes.saturating_add(read);
        if file_bytes > limits.producer.max_artifact_bytes {
            return Err(PythonDeclaredEnvironmentError::LimitExceeded {
                resource: "single input bytes",
                limit: limits.producer.max_artifact_bytes,
            });
        }
        if *total_bytes > limits.max_total_artifact_bytes {
            return Err(PythonDeclaredEnvironmentError::LimitExceeded {
                resource: "total input bytes",
                limit: limits.max_total_artifact_bytes,
            });
        }
        hasher.update(&buffer[..read as usize]);
    }
    inspect_workspace_binding(workspace_root, relative_path, ExpectedPathKind::File)?;
    let finalized_digest: [u8; 32] = hasher.finalize().into();
    let actual = lower_hex_string(&finalized_digest);
    if actual != expected_sha256 {
        return Err(PythonDeclaredEnvironmentError::InputDigestMismatch {
            input_id,
            expected: expected_sha256.to_owned(),
            actual,
        });
    }
    Ok(actual)
}

#[derive(Clone, Copy)]
enum ExpectedPathKind {
    File,
    Directory,
}

fn inspect_workspace_binding(
    workspace_root: &Path,
    relative_path: &Path,
    expected: ExpectedPathKind,
) -> Result<PathBuf, PythonDeclaredEnvironmentError> {
    let normalized = normalize_workspace_relative(relative_path)?;
    let mut current = workspace_root.to_path_buf();
    for component in normalized.components() {
        if let Component::Normal(part) = component {
            current.push(part);
            let metadata = fs::symlink_metadata(&current)
                .map_err(|source| path_io_error(current.clone(), source))?;
            if metadata.file_type().is_symlink() {
                return Err(PythonDeclaredEnvironmentError::Symlink(current));
            }
            if current != workspace_root && !current.starts_with(workspace_root) {
                return Err(PythonDeclaredEnvironmentError::PathOutsideWorkspace(
                    relative_path.to_path_buf(),
                ));
            }
            if current != workspace_root
                && current != workspace_root.join(&normalized)
                && !metadata.is_dir()
            {
                return Err(PythonDeclaredEnvironmentError::UnsupportedPathKind {
                    path: current,
                    expected: "directory path component",
                });
            }
        }
    }

    let metadata =
        fs::symlink_metadata(&current).map_err(|source| path_io_error(current.clone(), source))?;
    if metadata.file_type().is_symlink() {
        return Err(PythonDeclaredEnvironmentError::Symlink(current));
    }
    let expected_matches = match expected {
        ExpectedPathKind::File => metadata.is_file(),
        ExpectedPathKind::Directory => metadata.is_dir(),
    };
    if !expected_matches {
        return Err(PythonDeclaredEnvironmentError::UnsupportedPathKind {
            path: current,
            expected: match expected {
                ExpectedPathKind::File => "regular file",
                ExpectedPathKind::Directory => "directory",
            },
        });
    }
    if !current.starts_with(workspace_root) {
        return Err(PythonDeclaredEnvironmentError::PathOutsideWorkspace(
            relative_path.to_path_buf(),
        ));
    }
    Ok(current)
}

fn normalize_workspace_relative(path: &Path) -> Result<PathBuf, PythonDeclaredEnvironmentError> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => {
                let Some(part) = part.to_str() else {
                    return Err(PythonDeclaredEnvironmentError::PathOutsideWorkspace(
                        path.to_path_buf(),
                    ));
                };
                if part.contains('\\') || part.contains(':') {
                    return Err(PythonDeclaredEnvironmentError::PathOutsideWorkspace(
                        path.to_path_buf(),
                    ));
                }
                normalized.push(part);
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(PythonDeclaredEnvironmentError::PathOutsideWorkspace(
                    path.to_path_buf(),
                ));
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        normalized.push(".");
    }
    Ok(normalized)
}

fn relative_path_scalar_bytes(
    path: &Path,
    max_path_bytes: u64,
    max_depth: usize,
) -> Result<usize, PythonDeclaredEnvironmentError> {
    if u64::try_from(path.as_os_str().len()).unwrap_or(u64::MAX) > max_path_bytes {
        return Err(PythonDeclaredEnvironmentError::LimitExceeded {
            resource: "workspace path bytes",
            limit: max_path_bytes,
        });
    }
    let mut bytes = 0_usize;
    let mut depth = 0_usize;
    let mut has_component = false;
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => {
                let Some(part) = part.to_str() else {
                    return Err(PythonDeclaredEnvironmentError::PathOutsideWorkspace(
                        path.to_path_buf(),
                    ));
                };
                if part.contains('\\') || part.contains(':') {
                    return Err(PythonDeclaredEnvironmentError::PathOutsideWorkspace(
                        path.to_path_buf(),
                    ));
                }
                depth += 1;
                if depth > max_depth {
                    return Err(PythonDeclaredEnvironmentError::LimitExceeded {
                        resource: "workspace path depth",
                        limit: max_depth as u64,
                    });
                }
                bytes = bytes.saturating_add(part.len());
                if has_component {
                    bytes = bytes.saturating_add(1);
                }
                has_component = true;
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(PythonDeclaredEnvironmentError::PathOutsideWorkspace(
                    path.to_path_buf(),
                ));
            }
        }
    }
    Ok(if has_component { bytes } else { 1 })
}

fn portable_relative_path(path: &Path) -> Result<String, PythonDeclaredEnvironmentError> {
    let normalized = normalize_workspace_relative(path)?;
    if normalized == Path::new(".") {
        return Ok(".".to_owned());
    }
    let mut components = Vec::new();
    for component in normalized.components() {
        let Component::Normal(part) = component else {
            return Err(PythonDeclaredEnvironmentError::PathOutsideWorkspace(
                path.to_path_buf(),
            ));
        };
        let part = part.to_str().ok_or_else(|| {
            PythonDeclaredEnvironmentError::PathOutsideWorkspace(path.to_path_buf())
        })?;
        components.push(part);
    }
    Ok(components.join("/"))
}

fn validate_semantic_id(
    value: &str,
    kind: &'static str,
) -> Result<(), PythonDeclaredEnvironmentError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(PythonDeclaredEnvironmentError::Incomplete(format!(
            "{kind} ID is empty or not a portable semantic identifier: {value:?}"
        )));
    }
    Ok(())
}

fn validate_ordinal(
    expected: usize,
    actual: u32,
    kind: &'static str,
) -> Result<(), PythonDeclaredEnvironmentError> {
    if u32::try_from(expected).ok() != Some(actual) {
        return Err(PythonDeclaredEnvironmentError::Incomplete(format!(
            "{kind} ordinal {actual} is not contiguous at position {expected}"
        )));
    }
    Ok(())
}

fn check_ordinal_limit(ordinal: usize, limit: usize) -> Result<(), PythonDeclaredEnvironmentError> {
    if ordinal >= limit {
        return Err(PythonDeclaredEnvironmentError::LimitExceeded {
            resource: "declared root slots",
            limit: limit as u64,
        });
    }
    Ok(())
}

fn validate_sha256(value: &str, input_id: String) -> Result<(), PythonDeclaredEnvironmentError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PythonDeclaredEnvironmentError::InvalidInputDigest { input_id });
    }
    Ok(())
}

fn check_cancelled(
    cancellation: Option<&CancellationToken>,
) -> Result<(), PythonDeclaredEnvironmentError> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Err(PythonDeclaredEnvironmentError::Cancelled);
    }
    Ok(())
}

fn path_io_error(path: PathBuf, source: io::Error) -> PythonDeclaredEnvironmentError {
    if source.kind() == io::ErrorKind::NotFound {
        PythonDeclaredEnvironmentError::MissingPath(path)
    } else {
        PythonDeclaredEnvironmentError::Io { path, source }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic_model::DependencyPackLimits;
    use brokk_bifrost_core::analyzer::config::{
        PythonDeclaredConfigInput, PythonDeclaredConfigInputRole,
        PythonDeclaredEditableInstallMode, PythonDeclaredEntryMode, PythonDeclaredEntryPoint,
        PythonDeclaredEnvironmentConfig, PythonDeclaredEnvironmentMode, PythonDeclaredFinderMode,
        PythonDeclaredImportPathMode, PythonDeclaredInterpreter, PythonDeclaredIsolationMode,
        PythonDeclaredLaunchSemantics, PythonDeclaredNativeExtensionMode, PythonDeclaredRootRole,
        PythonDeclaredRootSlot, PythonDeclaredSiteStartupMode, PythonRuntimeArtifactConfig,
    };
    use tempfile::TempDir;

    struct Fixture {
        workspace: TempDir,
        runtime: PythonRuntimeEnvironmentConfig,
        expected_input_bytes: u64,
    }

    fn fixture() -> Fixture {
        let workspace = tempfile::tempdir().expect("temporary workspace");
        for directory in ["bin", "cfg", "src", "stdlib", "site"] {
            fs::create_dir_all(workspace.path().join(directory)).expect("create fixture directory");
        }

        let interpreter_bytes = b"declared-interpreter\n";
        fs::write(workspace.path().join("bin/python"), interpreter_bytes)
            .expect("write interpreter bytes");
        fs::write(workspace.path().join("src/app.py"), b"print('app')\n")
            .expect("write source root");
        fs::write(workspace.path().join("stdlib/os.py"), b"stdlib marker\n")
            .expect("write standard-library root");
        fs::write(workspace.path().join("site/demo.py"), b"installed marker\n")
            .expect("write installed root");
        fs::write(workspace.path().join("demo.whl"), b"wheel bytes\n").expect("write wheel");

        let input_specs = [
            (
                "resolver.json",
                PythonDeclaredConfigInputRole::ResolverConfiguration,
                &b"resolver=v1\n"[..],
            ),
            (
                "startup.json",
                PythonDeclaredConfigInputRole::StartupConfiguration,
                &b"site=disabled\n"[..],
            ),
            (
                "environment.json",
                PythonDeclaredConfigInputRole::EnvironmentConfiguration,
                &b"environment=cleared\n"[..],
            ),
            (
                "extras.json",
                PythonDeclaredConfigInputRole::ExtrasConfiguration,
                &b"extras=fast\n"[..],
            ),
            (
                "entry.json",
                PythonDeclaredConfigInputRole::EntryConfiguration,
                &b"entry=app.py\n"[..],
            ),
        ];
        let mut expected_input_bytes = interpreter_bytes.len() as u64;
        let config_inputs = input_specs
            .into_iter()
            .enumerate()
            .map(|(ordinal, (file_name, role, bytes))| {
                fs::write(workspace.path().join("cfg").join(file_name), bytes)
                    .expect("write declared config input");
                expected_input_bytes += bytes.len() as u64;
                PythonDeclaredConfigInput {
                    ordinal: ordinal as u32,
                    input_id: format!("config-{ordinal}"),
                    role,
                    path: PathBuf::from("cfg").join(file_name),
                    sha256: digest(bytes),
                }
            })
            .collect();

        let runtime = PythonRuntimeEnvironmentConfig {
            source_root: PathBuf::from("src"),
            artifacts: vec![PythonRuntimeArtifactConfig {
                archive_path: PathBuf::from("demo.whl"),
                installed_root: PathBuf::from("site"),
            }],
            declared_environment: Some(PythonDeclaredEnvironmentConfig {
                producer_version: SUPPORTED_PYTHON_DECLARED_ENVIRONMENT_PRODUCER_VERSION.to_owned(),
                resolver_version: SUPPORTED_PYTHON_DECLARED_FILESYSTEM_RESOLVER_VERSION.to_owned(),
                interpreter: PythonDeclaredInterpreter {
                    path: PathBuf::from("bin/python"),
                    sha256: digest(interpreter_bytes),
                    implementation: "cpython".to_owned(),
                    python_version: "3.13.1".to_owned(),
                    abi: "cp313".to_owned(),
                    platform: "linux-x86_64".to_owned(),
                },
                launch: PythonDeclaredLaunchSemantics {
                    isolation: PythonDeclaredIsolationMode::Isolated,
                    site_startup: PythonDeclaredSiteStartupMode::Disabled,
                    environment: PythonDeclaredEnvironmentMode::Cleared,
                    import_path: PythonDeclaredImportPathMode::DeclaredRootsOnly,
                    finder: PythonDeclaredFinderMode::StandardFilesystem,
                    editable_installs: PythonDeclaredEditableInstallMode::Disabled,
                    native_extensions: PythonDeclaredNativeExtensionMode::Disabled,
                },
                entry_point: PythonDeclaredEntryPoint {
                    mode: PythonDeclaredEntryMode::Script,
                    root_slot_id: "source".to_owned(),
                    relative_path: PathBuf::from("app.py"),
                    working_directory_root_slot_id: "source".to_owned(),
                    working_directory: PathBuf::from("."),
                },
                extras: vec!["fast".to_owned()],
                config_inputs,
                root_slots: vec![
                    PythonDeclaredRootSlot {
                        ordinal: 0,
                        slot_id: "source".to_owned(),
                        role: PythonDeclaredRootRole::Source,
                        path: PathBuf::from("src"),
                        artifact_index: None,
                    },
                    PythonDeclaredRootSlot {
                        ordinal: 1,
                        slot_id: "stdlib".to_owned(),
                        role: PythonDeclaredRootRole::StandardLibrary,
                        path: PathBuf::from("stdlib"),
                        artifact_index: None,
                    },
                    PythonDeclaredRootSlot {
                        ordinal: 2,
                        slot_id: "installed-demo".to_owned(),
                        role: PythonDeclaredRootRole::InstalledDistribution,
                        path: PathBuf::from("site"),
                        artifact_index: Some(0),
                    },
                ],
            }),
        };
        Fixture {
            workspace,
            runtime,
            expected_input_bytes,
        }
    }

    fn digest(bytes: &[u8]) -> String {
        lower_hex_string(&sha256_bytes(bytes))
    }

    fn root_inventories(
        workspace: &Path,
        runtime: &PythonRuntimeEnvironmentConfig,
    ) -> Vec<PythonDeclaredRootInventory> {
        runtime
            .declared_environment
            .as_ref()
            .expect("declared environment")
            .root_slots
            .iter()
            .map(|slot| {
                let file_name = match slot.role {
                    PythonDeclaredRootRole::Source => "app.py",
                    PythonDeclaredRootRole::StandardLibrary => "os.py",
                    PythonDeclaredRootRole::InstalledDistribution => "demo.py",
                };
                let path = workspace.join(&slot.path);
                assert!(path.is_dir());
                let contents = fs::read(path.join(file_name)).expect("read root member");
                let file_digest = digest(&contents);
                let mut members = vec![
                    ("directory".to_owned(), String::new(), None),
                    ("file".to_owned(), file_name.to_owned(), Some(file_digest)),
                ];
                members.sort_unstable();
                let canonical = canonical_json(&members).expect("canonical root inventory");
                PythonDeclaredRootInventory {
                    ordinal: slot.ordinal,
                    slot_id: slot.slot_id.clone(),
                    role: slot.role,
                    inventory_sha256: digest(&canonical),
                }
            })
            .collect()
    }

    fn produce(
        fixture: &Fixture,
        runtime: &PythonRuntimeEnvironmentConfig,
        inventories: &[PythonDeclaredRootInventory],
        limits: &DependencyPackLimits,
        cancellation: Option<&CancellationToken>,
    ) -> Result<CheckedPythonDeclaredEnvironment, PythonDeclaredEnvironmentError> {
        produce_python_declared_environment(
            fixture.workspace.path(),
            runtime,
            inventories,
            limits,
            cancellation,
        )
    }

    #[test]
    fn project_config_tracks_root_order_and_exact_content_inputs() {
        let fixture = fixture();
        let baseline_roots = root_inventories(fixture.workspace.path(), &fixture.runtime);
        let baseline = produce(
            &fixture,
            &fixture.runtime,
            &baseline_roots,
            &DependencyPackLimits::default(),
            None,
        )
        .expect("produce declared environment");
        assert_eq!(
            baseline.project_config().coverage,
            "resolver-affecting-config"
        );
        assert_eq!(baseline.input_bytes_read(), fixture.expected_input_bytes);
        assert_eq!(baseline.input_files_read(), 6);
        assert_eq!(
            baseline.condition_snapshot().project_config.as_ref(),
            Some(baseline.project_config())
        );

        let mut changed_metadata_runtime = fixture.runtime.clone();
        changed_metadata_runtime
            .declared_environment
            .as_mut()
            .expect("declared environment")
            .interpreter
            .python_version = "3.13.2".to_owned();
        let changed_metadata = produce(
            &fixture,
            &changed_metadata_runtime,
            &baseline_roots,
            &DependencyPackLimits::default(),
            None,
        )
        .expect("produce after interpreter metadata change");
        assert_ne!(baseline.project_config(), changed_metadata.project_config());

        fs::write(
            fixture.workspace.path().join("site/demo.py"),
            b"changed installed marker\n",
        )
        .expect("mutate installed root");
        let changed_root = root_inventories(fixture.workspace.path(), &fixture.runtime);
        let changed_root = produce(
            &fixture,
            &fixture.runtime,
            &changed_root,
            &DependencyPackLimits::default(),
            None,
        )
        .expect("produce after root mutation");
        assert_ne!(baseline.project_config(), changed_root.project_config());

        fs::write(
            fixture.workspace.path().join("site/demo.py"),
            b"installed marker\n",
        )
        .expect("restore installed root");
        let mut reordered_runtime = fixture.runtime.clone();
        let declared = reordered_runtime
            .declared_environment
            .as_mut()
            .expect("declared environment");
        declared.root_slots.reverse();
        for (ordinal, slot) in declared.root_slots.iter_mut().enumerate() {
            slot.ordinal = ordinal as u32;
        }
        let reordered_roots = root_inventories(fixture.workspace.path(), &reordered_runtime);
        let reordered = produce(
            &fixture,
            &reordered_runtime,
            &reordered_roots,
            &DependencyPackLimits::default(),
            None,
        )
        .expect("produce reordered roots");
        assert_ne!(baseline.project_config(), reordered.project_config());

        let mut changed_input_runtime = fixture.runtime.clone();
        let resolver_bytes = b"resolver=v2\n";
        fs::write(
            fixture.workspace.path().join("cfg/resolver.json"),
            resolver_bytes,
        )
        .expect("mutate resolver input");
        changed_input_runtime
            .declared_environment
            .as_mut()
            .expect("declared environment")
            .config_inputs[0]
            .sha256 = digest(resolver_bytes);
        let changed_input_roots =
            root_inventories(fixture.workspace.path(), &changed_input_runtime);
        let changed_input = produce(
            &fixture,
            &changed_input_runtime,
            &changed_input_roots,
            &DependencyPackLimits::default(),
            None,
        )
        .expect("produce after resolver input mutation");
        assert_ne!(baseline.project_config(), changed_input.project_config());
    }

    #[test]
    fn rejects_mismatched_identity_missing_input_and_unsupported_launch() {
        let fixture = fixture();
        let inventories = root_inventories(fixture.workspace.path(), &fixture.runtime);

        assert!(matches!(
            produce(
                &fixture,
                &fixture.runtime,
                &inventories[..inventories.len() - 1],
                &DependencyPackLimits::default(),
                None,
            ),
            Err(PythonDeclaredEnvironmentError::RootInventoryMismatch(_))
        ));

        let mut escaping_path = fixture.runtime.clone();
        escaping_path
            .declared_environment
            .as_mut()
            .expect("declared environment")
            .interpreter
            .path = PathBuf::from("../outside-python");
        assert!(matches!(
            produce(
                &fixture,
                &escaping_path,
                &inventories,
                &DependencyPackLimits::default(),
                None,
            ),
            Err(PythonDeclaredEnvironmentError::PathOutsideWorkspace(_))
        ));

        let mut wrong_interpreter = fixture.runtime.clone();
        wrong_interpreter
            .declared_environment
            .as_mut()
            .expect("declared environment")
            .interpreter
            .sha256 = digest(b"different interpreter");
        assert!(matches!(
            produce(
                &fixture,
                &wrong_interpreter,
                &inventories,
                &DependencyPackLimits::default(),
                None,
            ),
            Err(PythonDeclaredEnvironmentError::InputDigestMismatch { .. })
        ));

        fs::remove_file(fixture.workspace.path().join("cfg/environment.json"))
            .expect("remove configuration input");
        assert!(matches!(
            produce(
                &fixture,
                &fixture.runtime,
                &inventories,
                &DependencyPackLimits::default(),
                None,
            ),
            Err(PythonDeclaredEnvironmentError::MissingPath(_))
        ));

        let mut unsupported = fixture.runtime.clone();
        unsupported
            .declared_environment
            .as_mut()
            .expect("declared environment")
            .launch
            .site_startup = PythonDeclaredSiteStartupMode::Enabled;
        assert!(matches!(
            produce(
                &fixture,
                &unsupported,
                &inventories,
                &DependencyPackLimits::default(),
                None,
            ),
            Err(PythonDeclaredEnvironmentError::UnsupportedLaunchSemantics { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_configuration_inputs() {
        use std::os::unix::fs::symlink;

        let fixture = fixture();
        let inventories = root_inventories(fixture.workspace.path(), &fixture.runtime);
        let resolver = fixture.workspace.path().join("cfg/resolver.json");
        fs::remove_file(&resolver).expect("remove resolver input");
        symlink("startup.json", &resolver).expect("symlink resolver input");
        assert!(matches!(
            produce(
                &fixture,
                &fixture.runtime,
                &inventories,
                &DependencyPackLimits::default(),
                None,
            ),
            Err(PythonDeclaredEnvironmentError::Symlink(_))
        ));
    }

    #[test]
    fn enforces_shared_input_byte_budget_and_cancellation() {
        let fixture = fixture();
        let inventories = root_inventories(fixture.workspace.path(), &fixture.runtime);
        let limited = DependencyPackLimits {
            max_total_artifact_bytes: fixture.expected_input_bytes - 1,
            ..DependencyPackLimits::default()
        };
        assert!(matches!(
            produce(&fixture, &fixture.runtime, &inventories, &limited, None),
            Err(PythonDeclaredEnvironmentError::LimitExceeded {
                resource: "total input bytes",
                ..
            })
        ));

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(matches!(
            produce(
                &fixture,
                &fixture.runtime,
                &inventories,
                &DependencyPackLimits::default(),
                Some(&cancellation),
            ),
            Err(PythonDeclaredEnvironmentError::Cancelled)
        ));
    }
}
