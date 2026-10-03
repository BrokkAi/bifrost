//! Request-lived installed-provider proof, minted after snapshot and byte checks.

use super::runtime_artifact::{PythonRuntimeArtifactIdentity, verify_python_runtime_artifacts};
use crate::CancellationToken;
use crate::analyzer::semantic_model::{DependencyPackLimits, SemanticModelActivationEvidence};
use crate::analyzer::store::python_runtime::{self as stored, PythonRuntimeProviderPublication};
use crate::analyzer::store::{AnalyzerStore, StoreError, WorkspaceSnapshotId};
use brokk_bifrost_core::analyzer::config::{
    PythonRuntimeArtifactConfig, PythonRuntimeEnvironmentConfig,
};
use brokk_bifrost_core::path_normalization::NormalizePath;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
struct PythonRuntimeArtifactInventory {
    artifact_id: i64,
    purl: Option<String>,
    raw_version: Option<String>,
    archive_sha256: Option<String>,
    archive_path: String,
    installed_root: String,
    status: String,
    members: Vec<stored::PythonRuntimeArtifactMemberRow>,
}

pub(crate) struct PythonRuntimeProviderProof {
    artifact: PythonRuntimeArtifactIdentity,
    evidence: SemanticModelActivationEvidence,
    snapshot: WorkspaceSnapshotId,
    source_path: PathBuf,
    environment_id: i64,
}

impl PythonRuntimeProviderProof {
    pub(crate) fn artifact(&self) -> &PythonRuntimeArtifactIdentity {
        &self.artifact
    }
    pub(crate) fn evidence(&self) -> &SemanticModelActivationEvidence {
        &self.evidence
    }
    pub(crate) fn snapshot(&self) -> &WorkspaceSnapshotId {
        &self.snapshot
    }
    pub(crate) fn source_path(&self) -> &Path {
        &self.source_path
    }
    pub(crate) fn environment_id(&self) -> i64 {
        self.environment_id
    }
}

// Verification publishes canonical absolute artifact paths. The declared
// producer's configuration is workspace-relative; reconstruct that boundary
// without admitting a persisted path outside this workspace.
fn declared_runtime_artifact_config(
    workspace_root: &Path,
    artifact: &PythonRuntimeArtifactInventory,
) -> Result<PythonRuntimeArtifactConfig, StoreError> {
    // Windows canonicalization returns a verbatim `\\?\C:` root while the
    // recorded paths use the ordinary `C:` spelling; compare normalized forms.
    let workspace_root = workspace_root
        .canonicalize()
        .map_err(|error| {
            StoreError::stale_resolution(format!(
                "Python recorded workspace root is unavailable: {error}"
            ))
        })?
        .normalize();
    let relative = |path: &str| {
        PathBuf::from(path)
            .normalize()
            .strip_prefix(&workspace_root)
            .map(Path::to_path_buf)
            .map_err(|error| {
                StoreError::stale_resolution(format!(
                    "Python recorded artifact path is outside workspace {}: {path}: {error}",
                    workspace_root.display()
                ))
            })
    };
    Ok(PythonRuntimeArtifactConfig {
        archive_path: relative(&artifact.archive_path)?,
        installed_root: relative(&artifact.installed_root)?,
    })
}

/// One request's immutable acquisition scope and verification budget. Both
/// declared-environment and provider checks use this same snapshot/root context.
#[derive(Clone, Copy)]
pub(crate) struct PythonRuntimeProviderContext<'a> {
    pub(crate) store: &'a AnalyzerStore,
    pub(crate) publication: &'a PythonRuntimeProviderPublication,
    pub(crate) workspace_root: &'a Path,
    pub(crate) limits: &'a DependencyPackLimits,
    pub(crate) cancellation: &'a CancellationToken,
}

impl PythonRuntimeProviderContext<'_> {
    /// Revalidate the declared environment independently of profile facts. A
    /// changed launch input or root inventory is stale evidence, while a model's
    /// comparable unequal condition is handled separately by the binding evaluator.
    pub(crate) fn checked_environment(
        &self,
        environment_id: i64,
    ) -> Result<super::runtime_environment::CheckedPythonDeclaredEnvironment, StoreError> {
        let Self {
            store,
            publication,
            workspace_root,
            limits,
            cancellation,
        } = *self;
        let (environment, expected) = store.with_python_runtime_acquisition(
        publication.acquisition_id, &publication.snapshot, |tx| {
            let (declared, digest) = stored::python_runtime_declared_environment(tx, publication.acquisition_id.get(), environment_id)?
                .ok_or_else(|| StoreError::stale_resolution("Python selected environment has no checked declared launch evidence"))?;
            let source = tx.query_row(
                "SELECT source_scope FROM python_runtime_environments WHERE environment_id = ?1 AND acquisition_id = ?2",
                rusqlite::params![environment_id, publication.acquisition_id.get()],
                |row| row.get::<_, String>(0),
            )?;
            let artifacts = python_runtime_artifacts_for_environment(tx, publication.acquisition_id, environment_id)?;
            Ok((PythonRuntimeEnvironmentConfig {
                source_root: source.into(),
                artifacts: artifacts.iter().map(|artifact| declared_runtime_artifact_config(workspace_root, artifact))
                    .collect::<Result<Vec<_>, _>>()?,
                declared_environment: Some(declared),
            }, digest))
        },
    )?;
        let (checked, _, _) = super::runtime_artifact::acquire_python_declared_environment(
            workspace_root,
            &environment,
            limits,
            Some(cancellation),
        )
        .map_err(|error| {
            StoreError::stale_resolution(format!(
                "Python declared environment could not be revalidated: {error:?}"
            ))
        })?;
        if checked.project_config() != &expected {
            return Err(StoreError::stale_resolution(format!(
                "Python declared environment changed: recorded={expected:?}, current={:?}",
                checked.project_config()
            )));
        }
        store.with_python_runtime_acquisition(
            publication.acquisition_id,
            &publication.snapshot,
            |_| Ok(()),
        )?;
        Ok(checked)
    }

    /// Revalidate the complete persisted member inventory and the bounded current
    /// provider universe. A byte match alone never discharges import frontiers.
    pub(crate) fn verify_selected_provider(
        &self,
        source_path: &Path,
        import_name: &str,
        binding: &super::runtime_binding::PythonDefiningBinding,
        selected: &SemanticModelActivationEvidence,
    ) -> Result<PythonRuntimeProviderProof, StoreError> {
        let Self {
            store,
            publication,
            workspace_root,
            limits,
            cancellation,
        } = *self;
        let (candidate, artifacts, selected_artifact_index, scopes, frontiers) = store
            .with_python_runtime_acquisition(
                publication.acquisition_id,
                &publication.snapshot,
                |tx| {
                    let lookup = python_runtime_provider_lookup(
                        tx,
                        publication.acquisition_id,
                        &publication.snapshot,
                        source_path,
                        import_name,
                    )?;
                    if lookup.has_scope_ambiguity
                        || !lookup.unresolved_scopes.is_empty()
                        || lookup.candidates.len() != 1
                    {
                        return Err(StoreError::stale_resolution(format!(
                            "Python provider selection is incomplete: {lookup:?}"
                        )));
                    }
                    let candidate = lookup.candidates.into_iter().next().expect("one provider");
                    let mut artifacts = python_runtime_artifacts_for_environment(
                        tx,
                        publication.acquisition_id,
                        candidate.environment_id,
                    )?;
                    for artifact in &mut artifacts {
                        artifact.members = python_runtime_artifact_member_inventory(
                            tx,
                            publication.acquisition_id,
                            artifact.artifact_id,
                        )?;
                    }
                    let selected_artifact_index = artifacts
                        .iter()
                        .position(|artifact| artifact.artifact_id == candidate.artifact_id)
                        .ok_or_else(|| {
                            StoreError::stale_resolution(
                                "Python provider artifact is absent from its environment inventory",
                            )
                        })?;
                    let frontiers = python_runtime_scope_frontiers(
                        tx,
                        publication.acquisition_id,
                        candidate.environment_id,
                        import_name,
                    )?;
                    Ok((
                        candidate,
                        artifacts,
                        selected_artifact_index,
                        lookup.scopes,
                        frontiers,
                    ))
                },
            )?;
        if cancellation.is_cancelled() {
            return Err(StoreError::new("Python provider verification cancelled"));
        }
        if binding.source_path() != source_path
            || binding.snapshot() != &publication.snapshot
            || !binding
                .touched_modules()
                .iter()
                .any(|module| module == import_name)
        {
            return Err(StoreError::stale_resolution(
                "Python provider request is outside the checked defining binding",
            ));
        }
        if candidate.import_name != import_name
        // The scanner records unresolved for a conflict-free path candidate;
        // the exact profile binding above resolves the callable edge.
        || candidate.binding_status != "unresolved"
        || !matches!(candidate.member_role.as_deref(), Some("runtime" | "runtime_stub"))
        || candidate.member_status.as_deref() != Some("bytes_matched")
        || candidate.installed_bytes_match != Some(true)
        || candidate.installed_path.is_none()
        || candidate.member_sha256.is_none()
        || candidate.member_sha256 != candidate.installed_sha256
        {
            return Err(StoreError::stale_resolution(format!(
                "Python provider candidate is not a verified runtime member: {candidate:?}"
            )));
        }
        let candidate_member_id = candidate.member_id.ok_or_else(|| {
            StoreError::stale_resolution("Python provider candidate has no member")
        })?;
        let selected_inventory = &artifacts[selected_artifact_index].members;
        let member = selected_inventory
            .iter()
            .find(|member| member.member_id == candidate_member_id)
            .ok_or_else(|| {
                StoreError::stale_resolution(
                    "Python provider member is absent from its artifact inventory",
                )
            })?;
        if candidate.archive_member_path.as_deref() != Some(member.archive_member_path.as_str())
            || candidate.installed_path != member.installed_path
            || candidate.member_sha256 != member.member_sha256
            || candidate.installed_sha256 != member.installed_sha256
            || candidate.installed_bytes_match != member.installed_bytes_match
            || candidate.member_role.as_deref() != Some(member.member_role.as_str())
            || candidate.member_status.as_deref() != Some(member.status.as_str())
        {
            return Err(StoreError::stale_resolution(
                "Python provider candidate differs from its artifact member row",
            ));
        }
        let purl = candidate
            .purl
            .as_deref()
            .ok_or_else(|| StoreError::stale_resolution("Python provider has no coordinate"))?;
        let digest = candidate
            .archive_sha256
            .as_deref()
            .ok_or_else(|| StoreError::stale_resolution("Python provider has no archive digest"))?;
        let artifact = PythonRuntimeArtifactIdentity::from_validated_profile_selector(purl, digest)
            .ok_or_else(|| {
                StoreError::stale_resolution("Python provider identity is unsupported")
            })?;
        if selected
            .package
            .as_ref()
            .is_none_or(|package| package.name != artifact.purl())
            || selected.artifact_sha256.as_deref() != Some(artifact.archive_sha256())
            || selected.language != "python"
            || selected.ecosystem != "python"
            || selected
                .package
                .as_ref()
                .is_none_or(|package| package.version.is_some())
            || binding.artifact() != &artifact
        {
            return Err(StoreError::stale_resolution(
                "Python selected model artifact differs from installed provider",
            ));
        }
        let scope = scopes
            .iter()
            .find(|scope| scope.environment_id == candidate.environment_id)
            .ok_or_else(|| StoreError::stale_resolution("Python provider scope is absent"))?;
        if scope.status != "archive_verified" || candidate.artifact_status != "archive_verified" {
            return Err(StoreError::stale_resolution(
                "Python provider acquisition is incomplete",
            ));
        }
        let blocking_frontiers = frontiers
            .iter()
            .filter(|frontier| {
                frontier.kind.as_str() != "package_initializer_effects"
                    || !package_initializer_frontier_matches_binding(
                        frontier.import_name.as_deref(),
                        Path::new(&frontier.root_path),
                        frontier.path.as_deref().map(Path::new),
                        import_name,
                        &candidate,
                        &artifacts[selected_artifact_index],
                        binding.touched_modules(),
                    )
            })
            .collect::<Vec<_>>();
        if !blocking_frontiers.is_empty() {
            return Err(StoreError::stale_resolution(format!(
                "Python runtime applicability lacks profile completeness for import frontiers: \
             {blocking_frontiers:?}"
            )));
        }
        let declared_environment = store
            .with_python_runtime_acquisition(
                publication.acquisition_id,
                &publication.snapshot,
                |tx| {
                    stored::python_runtime_declared_environment(
                        tx,
                        publication.acquisition_id.get(),
                        candidate.environment_id,
                    )
                },
            )?
            .ok_or_else(|| {
                StoreError::stale_resolution("Python provider has no declared launch evidence")
            })?;
        let environment = PythonRuntimeEnvironmentConfig {
            declared_environment: Some(declared_environment.0),
            source_root: PathBuf::from(&scope.source_scope),
            artifacts: artifacts
                .iter()
                .map(|artifact| declared_runtime_artifact_config(workspace_root, artifact))
                .collect::<Result<Vec<_>, _>>()?,
        };
        let report = verify_python_runtime_artifacts(
            workspace_root,
            &[environment],
            limits,
            Some(cancellation),
        );
        if report.cancelled
            || !report.complete
            || !report.scope_complete
            || report.suppressed_diagnostics != 0
            || report.suppressed_frontiers != 0
            || report.artifacts.len() != artifacts.len()
        {
            return Err(StoreError::stale_resolution(format!(
                "Python provider inputs changed: {report:?}"
            )));
        }
        let current_environment = report
            .declared_environments
            .first()
            .and_then(Option::as_ref)
            .ok_or_else(|| {
                StoreError::stale_resolution("Python declared provider environment is incomplete")
            })?;
        if current_environment.project_config() != &declared_environment.1 {
            return Err(StoreError::stale_resolution(
                "Python provider projectConfig changed after publication",
            ));
        }
        for (artifact_index, (stored_artifact, current_artifact)) in
            artifacts.iter().zip(&report.artifacts).enumerate()
        {
            let stored_identity = stored_artifact
                .purl
                .as_deref()
                .zip(stored_artifact.archive_sha256.as_deref())
                .and_then(|(purl, digest)| {
                    PythonRuntimeArtifactIdentity::from_validated_profile_selector(purl, digest)
                });
            if stored_artifact.status != "archive_verified"
                || current_artifact.environment_index != 0
                || current_artifact.artifact_index != artifact_index
                || current_artifact.status
                    != super::runtime_artifact::PythonRuntimeArtifactStatus::ArchiveVerified
                || current_artifact.archive_path != Path::new(&stored_artifact.archive_path)
                || current_artifact.installed_root != Path::new(&stored_artifact.installed_root)
                || current_artifact.archive_sha256 != stored_artifact.archive_sha256
                || current_artifact.coordinate != stored_artifact.purl
                || current_artifact.raw_version != stored_artifact.raw_version
                || current_artifact.identity.as_ref() != stored_identity.as_ref()
                || stored_identity.is_none()
                || current_artifact.modules.len() != stored_artifact.members.len()
            {
                return Err(StoreError::stale_resolution(format!(
                    "Python configured artifact changed or is incomplete: stored={stored_artifact:?}, current={current_artifact:?}"
                )));
            }
            let current_modules = current_artifact
                .modules
                .iter()
                .map(|module| (module.archive_member_path.as_path(), module))
                .collect::<HashMap<_, _>>();
            if current_modules.len() != current_artifact.modules.len() {
                return Err(StoreError::stale_resolution(
                    "Python revalidated artifact has duplicate module paths",
                ));
            }
            for member in &stored_artifact.members {
                let current = current_modules
                    .get(Path::new(&member.archive_member_path))
                    .copied()
                    .ok_or_else(|| {
                        StoreError::stale_resolution("Python member inventory changed")
                    })?;
                let current_role_matches = match member.member_role.as_str() {
                    "runtime" => current.runtime && !current.stub,
                    "stub" => !current.runtime && current.stub,
                    "runtime_stub" => current.runtime && current.stub,
                    "other" => !current.runtime && !current.stub,
                    _ => false,
                };
                let current_status_matches = match current.status {
                    super::runtime_artifact::PythonRuntimeModuleStatus::BytesMatched => {
                        member.status == "bytes_matched"
                    }
                    super::runtime_artifact::PythonRuntimeModuleStatus::StubOnly => {
                        member.status == "stub_only"
                    }
                    super::runtime_artifact::PythonRuntimeModuleStatus::MissingInstalled => {
                        member.status == "missing_installed"
                    }
                    super::runtime_artifact::PythonRuntimeModuleStatus::ContentMismatch => {
                        member.status == "content_mismatch"
                    }
                    super::runtime_artifact::PythonRuntimeModuleStatus::Unsupported => {
                        member.status == "unsupported"
                    }
                    super::runtime_artifact::PythonRuntimeModuleStatus::Unresolved => {
                        member.status == "unresolved"
                    }
                };
                if !current_role_matches
                    || !current_status_matches
                    || member.installed_path.as_deref().map(Path::new)
                        != current.installed_path.as_deref()
                    || member.member_sha256 != current.member_sha256
                    || member.installed_sha256 != current.installed_sha256
                    || member.installed_bytes_match != current.installed_bytes_match
                {
                    return Err(StoreError::stale_resolution(format!(
                        "Python configured artifact member changed: stored={member:?}, current={current:?}"
                    )));
                }
            }
        }
        let current = &report.artifacts[selected_artifact_index];
        if current.identity.as_ref() != Some(&artifact) {
            return Err(StoreError::stale_resolution(format!(
                "selected Python provider identity changed after publication: {current:?}"
            )));
        }
        for member in selected_inventory {
            let current = current
                .modules
                .iter()
                .find(|module| module.archive_member_path == Path::new(&member.archive_member_path))
                .ok_or_else(|| StoreError::stale_resolution("Python member inventory changed"))?;
            if member.member_sha256 != current.member_sha256
                || member.installed_sha256 != current.installed_sha256
                || member.installed_bytes_match != current.installed_bytes_match
            {
                return Err(StoreError::stale_resolution(format!(
                    "Python installed member changed: {member:?}"
                )));
            }
            if member.member_id == candidate_member_id
                && (!current.runtime
                    || current.status
                        != super::runtime_artifact::PythonRuntimeModuleStatus::BytesMatched
                    || current.installed_bytes_match != Some(true)
                    || current.member_sha256.is_none()
                    || current.member_sha256 != current.installed_sha256)
            {
                return Err(StoreError::stale_resolution(format!(
                    "Python selected runtime member is not byte verified: {current:?}"
                )));
            }
        }
        let current_blocking_frontiers = report
            .frontiers
            .iter()
            .filter(|frontier| {
                let relevant = frontier.import_name.as_deref() == Some(import_name)
                    || frontier.import_name.is_none();
                relevant
                && (frontier.kind
                    != super::runtime_artifact::PythonRuntimeFrontierKind::PackageInitializerEffects
                    || frontier.environment_index != 0
                    || frontier.artifact_index != Some(selected_artifact_index)
                    || !package_initializer_frontier_matches_binding(
                        frontier.import_name.as_deref(),
                        &frontier.root,
                        frontier.path.as_deref(),
                        import_name,
                        &candidate,
                        &artifacts[selected_artifact_index],
                        binding.touched_modules(),
                    ))
            })
            .collect::<Vec<_>>();
        if !current_blocking_frontiers.is_empty() {
            return Err(StoreError::stale_resolution(format!(
                "Python current provider lacks profile completeness for import frontiers: \
             {current_blocking_frontiers:?}"
            )));
        }
        // Recheck after I/O; reclamation cannot silently convert this to clean-empty.
        store.with_python_runtime_acquisition(
            publication.acquisition_id,
            &publication.snapshot,
            |_| Ok(()),
        )?;
        Ok(PythonRuntimeProviderProof {
            artifact,
            evidence: selected.clone(),
            snapshot: publication.snapshot.clone(),
            source_path: source_path.to_path_buf(),
            environment_id: candidate.environment_id,
        })
    }
}

/// Match only the selection frontier for an initializer on the selected,
/// byte-verified candidate path. The caller supplies touched modules from the
/// opaque defining-binding token after checking its source and snapshot.
fn package_initializer_frontier_matches_binding(
    frontier_import_name: Option<&str>,
    frontier_root: &Path,
    frontier_path: Option<&Path>,
    import_name: &str,
    candidate: &stored::PythonRuntimeProviderCandidateRow,
    artifact: &PythonRuntimeArtifactInventory,
    touched_modules: &[String],
) -> bool {
    if frontier_import_name != Some(import_name)
        || candidate.import_name != import_name
        || candidate.artifact_id != artifact.artifact_id
        || candidate.artifact_status != artifact.status
        || artifact.status != "archive_verified"
        || candidate.purl != artifact.purl
        || candidate.raw_version != artifact.raw_version
        || candidate.archive_sha256 != artifact.archive_sha256
        || candidate.archive_path != artifact.archive_path
        || candidate.installed_root != artifact.installed_root
        || candidate.binding_status != "unresolved"
        || !matches!(
            candidate.member_role.as_deref(),
            Some("runtime" | "runtime_stub")
        )
        || candidate.member_status.as_deref() != Some("bytes_matched")
        || candidate.installed_bytes_match != Some(true)
        || candidate.member_sha256.is_none()
        || candidate.member_sha256 != candidate.installed_sha256
    {
        return false;
    }

    let installed_root = Path::new(&candidate.installed_root);
    if frontier_root != installed_root {
        return false;
    }
    let Some(frontier_path) = frontier_path else {
        return false;
    };
    let Ok(initializer_relative) = frontier_path.strip_prefix(installed_root) else {
        return false;
    };
    if initializer_relative
        .file_name()
        .and_then(|name| name.to_str())
        != Some("__init__.py")
    {
        return false;
    }
    let Some(archive_member_path) = candidate.archive_member_path.as_deref() else {
        return false;
    };
    let Some(installed_path) = candidate.installed_path.as_deref() else {
        return false;
    };
    let archive_member_path = Path::new(archive_member_path);
    let Ok(candidate_relative) = Path::new(installed_path).strip_prefix(installed_root) else {
        return false;
    };
    if candidate_relative != archive_member_path {
        return false;
    }

    let Some(candidate_member_id) = candidate.member_id else {
        return false;
    };
    let mut candidate_members = artifact
        .members
        .iter()
        .filter(|member| member.member_id == candidate_member_id);
    let Some(candidate_member) = candidate_members.next() else {
        return false;
    };
    if candidate_members.next().is_some()
        || candidate_member.artifact_id != artifact.artifact_id
        || Path::new(&candidate_member.archive_member_path) != archive_member_path
        || candidate_member.installed_path.as_deref().map(Path::new)
            != Some(Path::new(installed_path))
        || candidate_member.member_role.as_str()
            != candidate.member_role.as_deref().unwrap_or_default()
        || candidate_member.status != "bytes_matched"
        || candidate_member.status != candidate.member_status.as_deref().unwrap_or_default()
        || candidate_member.installed_bytes_match != Some(true)
        || candidate_member.member_sha256 != candidate.member_sha256
        || candidate_member.installed_sha256 != candidate.installed_sha256
        || candidate_member.member_sha256.is_none()
        || candidate_member.member_sha256 != candidate_member.installed_sha256
    {
        return false;
    }

    let mut parent = candidate_relative.parent();
    let mut initializer_is_candidate_ancestor = false;
    while let Some(directory) = parent.filter(|directory| !directory.as_os_str().is_empty()) {
        if directory.join("__init__.py") == initializer_relative {
            initializer_is_candidate_ancestor = true;
            break;
        }
        parent = directory.parent();
    }
    if !initializer_is_candidate_ancestor {
        return false;
    }

    let mut initializer_members = artifact.members.iter().filter(|member| {
        member.artifact_id == artifact.artifact_id
            && Path::new(&member.archive_member_path) == initializer_relative
    });
    let Some(initializer_member) = initializer_members.next() else {
        return false;
    };
    if initializer_members.next().is_some()
        || !matches!(
            initializer_member.member_role.as_str(),
            "runtime" | "runtime_stub"
        )
        || initializer_member.status != "bytes_matched"
        || initializer_member.installed_path.as_deref().map(Path::new) != Some(frontier_path)
        || initializer_member.installed_bytes_match != Some(true)
        || initializer_member.member_sha256.is_none()
        || initializer_member.member_sha256 != initializer_member.installed_sha256
    {
        return false;
    }

    let Some(initializer_module) =
        super::external::python_module_components_from_relative(initializer_relative)
    else {
        return false;
    };
    let initializer_module = initializer_module.join(".");
    touched_modules
        .iter()
        .any(|module| module == &initializer_module)
}

#[derive(Debug)]
pub(crate) struct PythonRuntimeLookupRows {
    scopes: Vec<stored::PythonRuntimeScopeRow>,
    pub(crate) has_scope_ambiguity: bool,
    pub(crate) unresolved_scopes: Vec<stored::PythonRuntimeScopeRow>,
    pub(crate) candidates: Vec<stored::PythonRuntimeProviderCandidateRow>,
}

pub(crate) fn python_runtime_provider_lookup(
    tx: &rusqlite::Transaction<'_>,
    id: stored::PythonRuntimeAcquisitionId,
    snapshot: &WorkspaceSnapshotId,
    source: &Path,
    import: &str,
) -> Result<PythonRuntimeLookupRows, StoreError> {
    use rusqlite::params;
    let mut scopes = Vec::new();
    for ancestor in stored::python_runtime_scope_ancestors(source)? {
        scopes.extend(
            tx.prepare_cached(stored::PYTHON_RUNTIME_SCOPE_AT_PATH_SQL)?
                .query_map(
                    params![id.get(), ancestor.path],
                    stored::PythonRuntimeScopeRow::from_row,
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        );
    }
    let unresolved_scopes = tx
        .prepare_cached(stored::PYTHON_RUNTIME_UNRESOLVED_SCOPES_SQL)?
        .query_map([id.get()], stored::PythonRuntimeScopeRow::from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let deepest_scope_depth = scopes.iter().filter_map(|scope| scope.scope_depth).max();
    let selected = scopes
        .iter()
        .filter(|scope| scope.scope_depth == deepest_scope_depth)
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();
    for scope in &selected {
        candidates.extend(
            tx.prepare_cached(stored::PYTHON_RUNTIME_IMPORT_CANDIDATES_SQL)?
                .query_map(
                    params![
                        id.get(),
                        scope.environment_id,
                        import,
                        snapshot.workspace_id.as_str(),
                        snapshot.lang,
                        snapshot.generation.get(),
                        snapshot.revision
                    ],
                    stored::PythonRuntimeProviderCandidateRow::from_row,
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        );
    }
    let has_scope_ambiguity = selected.len() > 1;
    Ok(PythonRuntimeLookupRows {
        scopes,
        has_scope_ambiguity,
        unresolved_scopes,
        candidates,
    })
}

fn python_runtime_artifacts_for_environment(
    tx: &rusqlite::Transaction<'_>,
    id: stored::PythonRuntimeAcquisitionId,
    environment: i64,
) -> Result<Vec<PythonRuntimeArtifactInventory>, StoreError> {
    let mut statement = tx.prepare_cached(stored::PYTHON_RUNTIME_ARTIFACTS_FOR_ENVIRONMENT_SQL)?;
    Ok(statement
        .query_map(rusqlite::params![environment, id.get()], |row| {
            Ok(PythonRuntimeArtifactInventory {
                artifact_id: row.get(0)?,
                purl: row.get(1)?,
                raw_version: row.get(2)?,
                archive_sha256: row.get(3)?,
                archive_path: row.get(4)?,
                installed_root: row.get(5)?,
                status: row.get(6)?,
                members: Vec::new(),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

fn python_runtime_artifact_member_inventory(
    tx: &rusqlite::Transaction<'_>,
    id: stored::PythonRuntimeAcquisitionId,
    artifact: i64,
) -> Result<Vec<stored::PythonRuntimeArtifactMemberRow>, StoreError> {
    Ok(tx
        .prepare_cached(stored::PYTHON_RUNTIME_ARTIFACT_MEMBERS_SQL)?
        .query_map(
            rusqlite::params![id.get(), artifact],
            stored::PythonRuntimeArtifactMemberRow::from_row,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

fn python_runtime_scope_frontiers(
    tx: &rusqlite::Transaction<'_>,
    id: stored::PythonRuntimeAcquisitionId,
    environment: i64,
    import: &str,
) -> Result<Vec<stored::PythonRuntimeFrontierRow>, StoreError> {
    let mut rows = tx
        .prepare_cached(stored::PYTHON_RUNTIME_SCOPE_FRONTIERS_SQL)?
        .query_map(
            rusqlite::params![id.get(), environment, import],
            stored::PythonRuntimeFrontierRow::from_row,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.extend(
        tx.prepare_cached(stored::PYTHON_RUNTIME_UNNAMED_SCOPE_FRONTIERS_SQL)?
            .query_map(
                rusqlite::params![id.get(), environment],
                stored::PythonRuntimeFrontierRow::from_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?,
    );
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initializer_frontier_inputs() -> (
        stored::PythonRuntimeProviderCandidateRow,
        PythonRuntimeArtifactInventory,
        PathBuf,
        PathBuf,
    ) {
        let fixture_root = std::env::temp_dir().join("bifrost-python-runtime-provider-test");
        let installed_root = fixture_root.join("site-packages");
        let initializer_path = installed_root.join("bs4/__init__.py");
        let candidate_path = installed_root.join("bs4/element.py");
        let digest = "a".repeat(64);
        let artifact = PythonRuntimeArtifactInventory {
            artifact_id: 17,
            purl: Some("pkg:pypi/beautifulsoup4@4.12.0".to_owned()),
            raw_version: Some("4.12.0".to_owned()),
            archive_sha256: Some("b".repeat(64)),
            archive_path: fixture_root
                .join("beautifulsoup4.whl")
                .to_string_lossy()
                .into_owned(),
            installed_root: installed_root.to_string_lossy().into_owned(),
            status: "archive_verified".to_owned(),
            members: vec![
                stored::PythonRuntimeArtifactMemberRow {
                    member_id: 23,
                    artifact_id: 17,
                    archive_member_path: "bs4/__init__.py".to_owned(),
                    installed_path: Some(initializer_path.to_string_lossy().into_owned()),
                    member_sha256: Some(digest.clone()),
                    installed_sha256: Some(digest.clone()),
                    installed_bytes_match: Some(true),
                    member_role: "runtime".to_owned(),
                    status: "bytes_matched".to_owned(),
                    diagnostic: None,
                },
                stored::PythonRuntimeArtifactMemberRow {
                    member_id: 29,
                    artifact_id: 17,
                    archive_member_path: "bs4/element.py".to_owned(),
                    installed_path: Some(candidate_path.to_string_lossy().into_owned()),
                    member_sha256: Some("c".repeat(64)),
                    installed_sha256: Some("c".repeat(64)),
                    installed_bytes_match: Some(true),
                    member_role: "runtime".to_owned(),
                    status: "bytes_matched".to_owned(),
                    diagnostic: None,
                },
            ],
        };
        let candidate = stored::PythonRuntimeProviderCandidateRow {
            provider_id: 31,
            environment_id: 7,
            artifact_id: 17,
            member_id: Some(29),
            import_name: "bs4.element".to_owned(),
            binding_status: "unresolved".to_owned(),
            purl: artifact.purl.clone(),
            raw_version: artifact.raw_version.clone(),
            archive_sha256: artifact.archive_sha256.clone(),
            archive_path: artifact.archive_path.clone(),
            installed_root: artifact.installed_root.clone(),
            artifact_status: artifact.status.clone(),
            archive_member_path: Some("bs4/element.py".to_owned()),
            installed_path: Some(candidate_path.to_string_lossy().into_owned()),
            member_sha256: Some("c".repeat(64)),
            installed_sha256: Some("c".repeat(64)),
            installed_bytes_match: Some(true),
            member_role: Some("runtime".to_owned()),
            member_status: Some("bytes_matched".to_owned()),
        };
        (candidate, artifact, installed_root, initializer_path)
    }

    #[test]
    fn declared_artifact_paths_roundtrip_and_reject_neighbor_workspaces() {
        let project = crate::inline_project::InlineTestProject::with_language(
            crate::analyzer::Language::Python,
        )
        .file("src/app.py", "pass\n")
        .build();
        let (_, mut artifact, _, _) = initializer_frontier_inputs();
        let archive = PathBuf::from("wheels").join("beautifulsoup4.whl");
        let installed = PathBuf::from("site-packages");
        artifact.archive_path = project
            .root()
            .join(&archive)
            .to_str()
            .expect("UTF-8 fixture path")
            .to_owned();
        artifact.installed_root = project
            .root()
            .join(&installed)
            .to_str()
            .expect("UTF-8 fixture path")
            .to_owned();
        let restored = declared_runtime_artifact_config(project.root(), &artifact)
            .expect("restore configured paths");
        assert_eq!(restored.archive_path, archive);
        assert_eq!(restored.installed_root, installed);
        assert_eq!(
            project.root().join(restored.archive_path),
            Path::new(&artifact.archive_path)
        );
        assert_eq!(
            project.root().join(restored.installed_root),
            Path::new(&artifact.installed_root)
        );
        let neighbor = project.root().with_file_name(format!(
            "{}-neighbor",
            project
                .root()
                .file_name()
                .expect("fixture directory name")
                .to_str()
                .expect("UTF-8 fixture name")
        ));
        for outside in [
            PythonRuntimeArtifactInventory {
                archive_path: neighbor
                    .join("beautifulsoup4.whl")
                    .to_str()
                    .expect("UTF-8 fixture path")
                    .to_owned(),
                ..artifact.clone()
            },
            PythonRuntimeArtifactInventory {
                installed_root: neighbor.to_str().expect("UTF-8 fixture path").to_owned(),
                ..artifact.clone()
            },
        ] {
            let error = declared_runtime_artifact_config(project.root(), &outside)
                .expect_err("neighboring workspace is outside this acquisition");
            assert_eq!(
                error.kind(),
                crate::analyzer::store::StoreErrorKind::StaleResolution
            );
        }
    }

    #[test]
    fn package_initializer_frontier_requires_exact_candidate_scope_and_touched_module() {
        let (candidate, artifact, root, initializer) = initializer_frontier_inputs();
        let touched = vec!["bs4".to_owned(), "bs4.element".to_owned()];
        assert!(package_initializer_frontier_matches_binding(
            Some("bs4.element"),
            &root,
            Some(&initializer),
            "bs4.element",
            &candidate,
            &artifact,
            &touched,
        ));

        assert!(!package_initializer_frontier_matches_binding(
            Some("bs4.common"),
            &root,
            Some(&initializer),
            "bs4.element",
            &candidate,
            &artifact,
            &touched,
        ));
        let other_root = root.with_file_name("different-site-packages");
        assert!(!package_initializer_frontier_matches_binding(
            Some("bs4.element"),
            &other_root,
            Some(&initializer),
            "bs4.element",
            &candidate,
            &artifact,
            &touched,
        ));
        assert!(!package_initializer_frontier_matches_binding(
            Some("bs4.element"),
            &root,
            Some(&root.join("bs4/other/__init__.py")),
            "bs4.element",
            &candidate,
            &artifact,
            &touched,
        ));
        assert!(!package_initializer_frontier_matches_binding(
            Some("bs4.element"),
            &root,
            Some(&initializer),
            "bs4.element",
            &candidate,
            &artifact,
            &["bs4.element".to_owned()],
        ));

        let mut different_artifact = candidate.clone();
        different_artifact.artifact_id += 1;
        assert!(!package_initializer_frontier_matches_binding(
            Some("bs4.element"),
            &root,
            Some(&initializer),
            "bs4.element",
            &different_artifact,
            &artifact,
            &touched,
        ));

        let mut different_digest = candidate.clone();
        different_digest.member_sha256 = Some("d".repeat(64));
        different_digest.installed_sha256 = Some("d".repeat(64));
        assert!(!package_initializer_frontier_matches_binding(
            Some("bs4.element"),
            &root,
            Some(&initializer),
            "bs4.element",
            &different_digest,
            &artifact,
            &touched,
        ));

        let mut initializer_bytes_unmatched = artifact.clone();
        initializer_bytes_unmatched.members[0].installed_bytes_match = Some(false);
        assert!(!package_initializer_frontier_matches_binding(
            Some("bs4.element"),
            &root,
            Some(&initializer),
            "bs4.element",
            &candidate,
            &initializer_bytes_unmatched,
            &touched,
        ));
    }
}
