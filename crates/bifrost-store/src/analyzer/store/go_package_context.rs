//! Revision-selected Go tool output. Canonical discovery is request-owned;
//! reusable package membership and provider relationships live in SQLite.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use git2::{ObjectType, Oid};
use rusqlite::{OptionalExtension, params};

use super::go_unit_summaries::go_unit_key;
use super::{AnalyzerStore, Result, WorkspaceConfigurationInput, WorkspaceSnapshotId};
use crate::CancellationToken;
use crate::analyzer::canonical_hash::CanonicalHasher;
use crate::analyzer::{Language, Project};
use crate::path_normalization::NormalizePath;
use brokk_bifrost_core::analyzer::go_facts::GO_BUILD_SELECTION_FACTS_VERSION;
use brokk_bifrost_go::package_discovery::{GoPackage, GoPackageDiscovery};

/// Version 11 admits source-bearing dependencies as providers while keeping
/// caller ownership with each discovery domain's main modules. Version 13
/// names a member that source admission refused with its recorded reason and
/// folds refused inputs into each domain's input digest. Version 12 labels
/// contexts from builds of this change before its final gap vocabulary, so
/// those contexts are never selected.
/// Version 14 hashes an input by kind, path and content OID only; modified time and length no longer take part, so an unchanged save reuses the context.
/// Version 15 resolves relative source imports outside module mode by importer directory.
#[doc(hidden)]
pub const DERIVATION_VERSION: i64 = 15;

#[derive(Debug, Default)]
#[doc(hidden)]
pub struct GoOverlayPlacement {
    pub changed_membership: bool,
    pub reuse_context: bool,
}

/// Immutable replacement bytes owned by one discovery request, never a workspace cache.
/// Deletions are unsupported: this snapshot supplies bytes, not deletion markers.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct GoOverlaySnapshot {
    pub files: Vec<GoOverlayFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct GoOverlayFile {
    pub path: String,
    pub oid: String,
    pub disk_oid: Option<String>,
    pub bytes: Vec<u8>,
}

impl GoOverlaySnapshot {
    pub fn capture(project: &dyn Project) -> Result<Self> {
        let mut files = Vec::new();
        if let Some(overlays) = project.overlay_content() {
            for (file, _) in overlays.entries() {
                // Go configuration capture currently selects disk bytes, not
                // editor buffers (tree_sitter_analyzer::workspace_configuration_inputs).
                // Unsaved go.mod/go.work edits are unsupported until save.
                if file
                    .rel_path()
                    .extension()
                    .is_none_or(|extension| extension != "go")
                {
                    continue;
                }
                let source = project.read_source_snapshot(file)?;
                let disk = match std::fs::read(file.abs_path()) {
                    Ok(bytes) => Some(Oid::hash_object(ObjectType::Blob, &bytes)?.to_string()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => return Err(error.into()),
                };
                let oid = source.oid().to_string();
                if disk.as_deref() != Some(&oid) {
                    files.push(GoOverlayFile {
                        path: crate::path_utils::rel_path_string(file),
                        oid,
                        disk_oid: disk,
                        bytes: source.source().as_bytes().to_vec(),
                    });
                }
            }
        }
        Ok(Self { files })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[doc(hidden)]
pub struct GoContextIdentity {
    pub selection_id: i64,
    pub revision: i64,
    pub context_id: i64,
    pub publication_digest: [u8; 32],
}

#[derive(Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum GoContextHeadStatus {
    Current,
    Withdrawn,
    Cancelled,
}

#[derive(Debug, Clone)]
#[doc(hidden)]
pub enum GoInputObservationOutcome {
    Ready(GoInputObservation),
    InputsChanged(GoInputChange),
    Cancelled,
}

/// The first disagreement between the disk input domain and the selected
/// revision, reported with a refused publication.
#[derive(Debug, Clone, Eq, PartialEq)]
#[doc(hidden)]
pub enum GoInputChange {
    /// The revision selects or refuses an input the disk listing omits.
    Unlisted { kind: String, path: String },
    /// The revision selects or refuses an input that no longer exists.
    Missing { kind: String, path: String },
    /// The input's bytes no longer hash to the revision's blob.
    ContentChanged { kind: String, path: String },
    /// A listed input that the revision neither selects nor records as refused.
    Unrecorded { kind: String, path: String },
}

/// Fixed-size observation, held only through one discovery invocation.
#[derive(Debug, Clone, Eq, PartialEq)]
#[doc(hidden)]
pub struct GoInputObservation {
    digest: [u8; 32],
}

#[derive(Debug)]
#[doc(hidden)]
pub enum GoContextPublicationOutcome {
    Published(GoContextIdentity),
    InputsChanged,
    Cancelled,
}

pub(crate) const RECHECK_CONTEXT_SQL: &str = "SELECT EXISTS(SELECT 1 FROM go_context_publications p
             WHERE p.selection_id=?1 AND p.context_id=?2 AND p.publication_digest=?3
               AND p.valid_from<=?4 AND (p.valid_until IS NULL OR ?4<p.valid_until)
               AND NOT EXISTS(SELECT 1 FROM go_package_instances package
                 JOIN go_package_files member USING(package_id)
                 WHERE package.context_id=p.context_id AND NOT EXISTS(
                   SELECT 1 FROM workspace_file_versions file
                   WHERE file.workspace_id=p.workspace_id AND file.lang=p.lang AND file.generation=p.generation
                     AND file.input_kind='source' AND file.rel_path=member.rel_path
                     AND file.valid_from<=?4 AND (file.valid_until IS NULL OR ?4<file.valid_until))))";

pub(crate) const OBSERVE_INPUTS_SQL: &str =
    "SELECT input_kind, rel_path, blob_oid FROM workspace_file_versions
             WHERE workspace_id = ?1 AND lang = 'go' AND generation = ?2
               AND valid_from <= ?3 AND (valid_until IS NULL OR ?3 < valid_until)
             ORDER BY input_kind, rel_path";

pub(crate) const REFUSED_INPUT_SQL: &str = "SELECT json(reason) FROM workspace_source_refusals
             WHERE workspace_id = ?1 AND lang = 'go' AND generation = ?2 AND rel_path = ?3
               AND valid_from <= ?4 AND (valid_until IS NULL OR ?4 < valid_until)";

/// Sources the revision records as refused by source admission. They complete
/// the input domain: present on disk, deliberately without a source row.
pub(crate) const REFUSED_INPUTS_SQL: &str =
    "SELECT rel_path, blob_oid, json(reason) FROM workspace_source_refusals
             WHERE workspace_id = ?1 AND lang = 'go' AND generation = ?2
               AND valid_from <= ?3 AND (valid_until IS NULL OR ?3 < valid_until)
             ORDER BY rel_path";

#[doc(hidden)]
pub const PRIOR_HEADS_SQL: &str =
    "SELECT s.profile_digest,s.selection_id,p.context_id,p.publication_digest
     FROM go_context_selections s JOIN go_context_publications p USING(selection_id)
     WHERE s.workspace_id=?1 AND s.lang='go' AND s.generation=?2
       AND p.valid_from<=?3 AND (p.valid_until IS NULL OR ?3<p.valid_until)
       AND s.derivation_version=?4";

pub(crate) const CANONICAL_SOURCE_SQL: &str = "SELECT f.file_version_id,f.blob_oid,m.content_package,manifest.publication_state,manifest.facts_version
                             FROM workspace_file_versions f
                             LEFT JOIN blobs b ON b.blob_oid=f.blob_oid AND b.lang=f.lang AND b.parse_variant=x'' AND b.generation=f.generation
                             LEFT JOIN blob_meta m ON m.blob_id=b.id
                             LEFT JOIN source_fact_manifests manifest ON manifest.blob_id=b.id
                             WHERE f.workspace_id=?1 AND f.lang='go' AND f.generation=?2 AND f.input_kind='source'
                               AND f.rel_path=?3 AND f.valid_from<=?4 AND (f.valid_until IS NULL OR ?4<f.valid_until)";

pub(crate) const SELECT_CONTEXT_SQL: &str =
    "SELECT s.selection_id, p.context_id, p.publication_digest
     FROM go_context_selections s JOIN go_context_publications p USING(selection_id)
     WHERE s.workspace_id=?1 AND s.lang='go' AND s.generation=?2
       AND p.valid_from<=?3 AND (p.valid_until IS NULL OR ?3<p.valid_until)
       AND s.profile_digest=?4 AND s.derivation_version=?5";

#[doc(hidden)]
pub fn base_profile_digest(discovery: &GoPackageDiscovery) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-go-context-base-profile:v1");
    for (key, value) in [
        ("goos", discovery.build_configuration.goos.as_str()),
        ("goarch", discovery.build_configuration.goarch.as_str()),
        ("goversion", discovery.environment.goversion.as_str()),
    ] {
        hash.field(key, value.as_bytes());
    }
    for (key, value) in [
        ("goroot", &discovery.environment.goroot),
        ("gopath", &discovery.environment.gopath),
        ("gomodcache", &discovery.environment.gomodcache),
    ] {
        hash.field(key, value.as_os_str().as_encoded_bytes());
    }
    for pattern in &discovery.workspace_patterns {
        hash.field("pattern", pattern.as_bytes());
    }
    let cgo_identity = u8::from(discovery.build_configuration.cgo_enabled);
    assert_eq!(
        cgo_identity, 0,
        "the selected Go context currently keeps the cgo identity byte disabled"
    );
    hash.field("cgo", &[cgo_identity]);
    hash.field("tests", &[1]);
    for tag in &discovery.build_configuration.tags {
        hash.field("tag", tag.as_bytes());
    }
    hash.finish()
}

#[doc(hidden)]
pub fn profile_digest(discovery: &GoPackageDiscovery) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-go-context-profile:v2");
    hash.field("base", &base_profile_digest(discovery));
    hash.field("directory", discovery.domain.directory.as_bytes());
    hash.field("gowork", discovery.domain.gowork_path.as_bytes());
    for pattern in &discovery.workspace_patterns {
        hash.field("pattern", pattern.as_bytes());
    }
    hash.finish()
}

/// Decode tool path spelling once, then compare and join Path components.
/// Absolute test-variant paths and package-relative paths identify one source.
fn go_tool_source_path(directory: &Path, source: &Path) -> PathBuf {
    let windows = crate::path_utils::is_windows_absolute_path(&directory.to_string_lossy());
    let directory = if windows {
        PathBuf::from(crate::path_utils::normalize_pattern(
            &directory.to_string_lossy(),
        ))
    } else {
        directory.to_path_buf()
    };
    let source = if windows {
        PathBuf::from(crate::path_utils::normalize_pattern(
            &source.to_string_lossy(),
        ))
    } else {
        source.to_path_buf()
    };
    let directory = directory.normalize();
    let source = if source.is_absolute() {
        source.normalize()
    } else {
        source
    };
    let absolute = if let Ok(relative) = source.strip_prefix(&directory) {
        directory.join(relative)
    } else if source.is_absolute()
        || crate::path_utils::is_windows_absolute_path(&source.to_string_lossy())
    {
        source
    } else {
        directory.join(source)
    };
    absolute.normalize()
}

fn go_tool_source_members(package: &GoPackage) -> std::collections::BTreeMap<PathBuf, bool> {
    let mut members = std::collections::BTreeMap::new();
    for (paths, ignored) in [
        (&package.go_files, false),
        (&package.cgo_files, false),
        (&package.ignored_go_files, true),
    ] {
        for path in paths {
            let absolute = go_tool_source_path(&package.dir, path);
            members
                .entry(absolute)
                .and_modify(|excluded| *excluded |= ignored)
                .or_insert(ignored);
        }
    }
    members
}

fn import_mappings<'a>(
    package: &'a GoPackage,
    imports: &'a [String],
) -> std::collections::BTreeMap<&'a str, &'a str> {
    let mut mappings = std::collections::BTreeMap::new();
    for imported in imports {
        if let Some(target) = package.import_map.get(imported) {
            mappings.insert(imported.as_str(), target.as_str());
            continue;
        }
        let mut mapped = false;
        for (spelling, target) in &package.import_map {
            if target == imported {
                mappings.insert(spelling.as_str(), target.as_str());
                mapped = true;
            }
        }
        if !mapped {
            mappings.insert(imported.as_str(), imported.as_str());
        }
    }
    mappings
}

impl AnalyzerStore {
    /// Recheck through a newly checked-out store reader. Authority requires the
    /// publication and every member path's selected version to contain the
    /// request revision; closed intervals remain readable at older revisions.
    #[doc(hidden)]
    pub fn go_context_head_status(
        &self,
        identity: &GoContextIdentity,
        cancellation: &CancellationToken,
    ) -> Result<GoContextHeadStatus> {
        if cancellation.is_cancelled() {
            return Ok(GoContextHeadStatus::Cancelled);
        }
        let conn = self.read_conn()?;
        go_context_status_on(&conn, identity, cancellation)
    }
}

/// A single-connection store's selected operation already owns its writer mutex.
/// No publisher can run until it releases that connection, so recheck on it.
pub(crate) fn go_context_status_on(
    conn: &rusqlite::Connection,
    identity: &GoContextIdentity,
    cancellation: &CancellationToken,
) -> Result<GoContextHeadStatus> {
    let current: bool = conn.query_row(
        RECHECK_CONTEXT_SQL,
        params![
            identity.selection_id,
            identity.context_id,
            identity.publication_digest,
            identity.revision
        ],
        |row| row.get(0),
    )?;
    Ok(if cancellation.is_cancelled() {
        GoContextHeadStatus::Cancelled
    } else if current {
        GoContextHeadStatus::Current
    } else {
        GoContextHeadStatus::Withdrawn
    })
}

impl AnalyzerStore {
    /// Observe the disk input domain against the exact selected revision.
    /// Fresh inventory and content identities detect ordinary concurrent edits;
    /// this is an optimistic check, not an atomic filesystem snapshot.
    #[doc(hidden)]
    pub fn observe_go_context_inputs(
        &self,
        snapshot: &WorkspaceSnapshotId,
        project: &dyn Project,
        cancellation: &CancellationToken,
    ) -> Result<GoInputObservationOutcome> {
        let overlays = GoOverlaySnapshot::capture(project)?;
        self.observe_go_context_inputs_with_overlay(snapshot, project, cancellation, &overlays)
    }

    /// Validate the exact immutable bytes supplied to this request's Go tool.
    #[doc(hidden)]
    pub fn observe_go_context_inputs_with_overlay(
        &self,
        snapshot: &WorkspaceSnapshotId,
        project: &dyn Project,
        cancellation: &CancellationToken,
        overlays: &GoOverlaySnapshot,
    ) -> Result<GoInputObservationOutcome> {
        assert_eq!(snapshot.lang, "go");
        if cancellation.is_cancelled() {
            return Ok(GoInputObservationOutcome::Cancelled);
        }
        // A new or changed buffer must not publish the old discovery snapshot.
        // Saving identical bytes is harmless and intentionally has the same OID.
        let current = GoOverlaySnapshot::capture(project)?;
        for file in current.files.iter().chain(&overlays.files) {
            let selected = crate::analyzer::ProjectFile::new(
                project.root().to_path_buf(),
                PathBuf::from(&file.path),
            );
            let source = match project.read_source_snapshot(&selected) {
                Ok(source) => source,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(GoInputObservationOutcome::InputsChanged(
                        GoInputChange::Missing {
                            kind: "source".into(),
                            path: file.path.clone(),
                        },
                    ));
                }
                Err(error) => return Err(error.into()),
            };
            if source.oid().to_string() != file.oid
                || current
                    .files
                    .iter()
                    .find(|entry| entry.path == file.path)
                    .is_some_and(|entry| entry.oid != file.oid)
            {
                return Ok(GoInputObservationOutcome::InputsChanged(
                    GoInputChange::ContentChanged {
                        kind: "source".into(),
                        path: file.path.clone(),
                    },
                ));
            }
            if current
                .files
                .iter()
                .find(|entry| entry.path == file.path)
                .is_some_and(|entry| {
                    entry.disk_oid != file.disk_oid
                        && entry.disk_oid.as_deref() != Some(file.oid.as_str())
                })
            {
                return Ok(GoInputObservationOutcome::InputsChanged(
                    GoInputChange::ContentChanged {
                        kind: "source".into(),
                        path: file.path.clone(),
                    },
                ));
            }
            if !overlays.files.iter().any(|entry| entry.path == file.path) {
                return Ok(GoInputObservationOutcome::InputsChanged(
                    GoInputChange::ContentChanged {
                        kind: "source".into(),
                        path: file.path.clone(),
                    },
                ));
            }
        }
        project.invalidate_cached_file_listing();
        let files = project.all_files_shared()?;
        let mut configuration = files
            .iter()
            .filter(|file| {
                WorkspaceConfigurationInput::is_native_input(Language::Go, file.rel_path())
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        WorkspaceConfigurationInput::include_native_metadata_paths(
            project,
            &files,
            Language::Go,
            &mut configuration,
        )?;
        let mut inventory = project
            .analyzable_files_from(files.as_ref(), Language::Go)?
            .iter()
            .map(|file| {
                (
                    "source".to_owned(),
                    crate::path_utils::rel_path_string(file),
                )
            })
            .collect::<BTreeSet<_>>();
        inventory.extend(configuration.iter().map(|file| {
            (
                "configuration".to_owned(),
                crate::path_utils::rel_path_string(file),
            )
        }));
        let conn = self.read_conn()?;
        let params = params![
            snapshot.workspace_id.as_str(),
            snapshot.generation.get(),
            snapshot.revision
        ];
        let mut hash = CanonicalHasher::new(b"bifrost-go-observed-inputs:v3");
        let mut selected = conn.prepare_cached(OBSERVE_INPUTS_SQL)?;
        let mut rows = selected.query(params)?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(GoInputObservationOutcome::Cancelled);
            }
            let kind: String = row.get(0)?;
            let path: String = row.get(1)?;
            let oid: String = row.get(2)?;
            if let Some(change) = observe_recorded_input(
                project,
                overlays,
                &mut inventory,
                &mut hash,
                &kind,
                &kind,
                path,
                &oid,
            )? {
                return Ok(GoInputObservationOutcome::InputsChanged(change));
            }
        }
        drop(rows);
        drop(selected);
        // A refused source is listed like any source; the revision records
        // its blob and reason instead of selecting it.
        let mut refused = conn.prepare_cached(REFUSED_INPUTS_SQL)?;
        let mut rows = refused.query(params)?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(GoInputObservationOutcome::Cancelled);
            }
            let path: String = row.get(0)?;
            let oid: String = row.get(1)?;
            let reason: String = row.get(2)?;
            hash.field("refusal", reason.as_bytes());
            if let Some(change) = observe_recorded_input(
                project,
                overlays,
                &mut inventory,
                &mut hash,
                "source",
                "refused",
                path,
                &oid,
            )? {
                return Ok(GoInputObservationOutcome::InputsChanged(change));
            }
        }
        if let Some((kind, path)) = inventory.pop_first() {
            return Ok(GoInputObservationOutcome::InputsChanged(
                GoInputChange::Unrecorded { kind, path },
            ));
        }
        if cancellation.is_cancelled() {
            return Ok(GoInputObservationOutcome::Cancelled);
        }
        Ok(GoInputObservationOutcome::Ready(GoInputObservation {
            digest: hash.finish(),
        }))
    }

    /// Bind/recheck immutable publication identity for one selected profile.
    #[doc(hidden)]
    pub fn selected_go_context(
        &self,
        snapshot: &WorkspaceSnapshotId,
        profile: &[u8; 32],
    ) -> Result<Option<GoContextIdentity>> {
        let selected = self.go_context_for_reconciliation(snapshot, profile)?;
        if let Some(identity) = &selected {
            self.validate_go_context_members(identity)?;
        }
        Ok(selected)
    }

    /// Reconciliation must be able to replace a placement whose member was deleted.
    #[doc(hidden)]
    pub fn go_context_for_reconciliation(
        &self,
        snapshot: &WorkspaceSnapshotId,
        profile: &[u8; 32],
    ) -> Result<Option<GoContextIdentity>> {
        let conn = self.read_conn()?;
        let selected = conn
            .query_row(
                SELECT_CONTEXT_SQL,
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.get(),
                    snapshot.revision,
                    profile,
                    DERIVATION_VERSION
                ],
                |row| {
                    Ok(GoContextIdentity {
                        revision: snapshot.revision,
                        selection_id: row.get(0)?,
                        context_id: row.get(1)?,
                        publication_digest: row
                            .get::<_, Vec<u8>>(2)?
                            .try_into()
                            .expect("schema checks publication digest width"),
                    })
                },
            )
            .optional()?;
        Ok(selected)
    }
}

/// Match one recorded input against the listing and its current bytes, and
/// fold its identity into the observation. `family` is the listing family the
/// recorded `kind` accounts for.
#[allow(clippy::too_many_arguments)]
fn observe_recorded_input(
    project: &dyn Project,
    overlays: &GoOverlaySnapshot,
    inventory: &mut BTreeSet<(String, String)>,
    hash: &mut CanonicalHasher,
    family: &str,
    kind: &str,
    path: String,
    oid: &str,
) -> Result<Option<GoInputChange>> {
    let kind_owned = || kind.to_owned();
    if !inventory.remove(&(family.to_owned(), path.clone())) {
        return Ok(Some(GoInputChange::Unlisted {
            kind: kind_owned(),
            path,
        }));
    }
    let absolute = project.root().join(&path);
    let bytes = match overlays.files.iter().find(|file| file.path == path) {
        Some(file) => std::borrow::Cow::Borrowed(file.bytes.as_slice()),
        None => match std::fs::read(&absolute) {
            Ok(bytes) => std::borrow::Cow::Owned(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Some(GoInputChange::Missing {
                    kind: kind_owned(),
                    path,
                }));
            }
            Err(error) => return Err(error.into()),
        },
    };
    if Oid::hash_object(ObjectType::Blob, &bytes)?.to_string() != oid {
        return Ok(Some(GoInputChange::ContentChanged {
            kind: kind_owned(),
            path,
        }));
    }
    hash.field("kind", kind.as_bytes());
    hash.field("path", path.as_bytes());
    hash.field("oid", oid.as_bytes());
    Ok(None)
}

/// Structured evidence shared by source inventory, publication and Go navigation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GoSourceImportRefusal {
    pub importer: String,
    pub spelling: String,
    pub role: String,
    pub reason: GoSourceImportRefusalReason,
    pub directory: Option<String>,
    pub candidates: Vec<String>,
    pub module_manifest: Option<String>,
    pub declared_names: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoSourceImportRefusalReason {
    RelativeImportInModuleMode,
    RelativeImportOutsideWorkspace,
    SourcePackageDirectoryUnavailable,
    ConflictingSourcePackageNames,
}

struct PackageRows {
    import_path: String,
    name: String,
    for_test: String,
    directory: std::path::PathBuf,
    provider_kind: &'static str,
    provider_provenance: &'static str,
    provider_module_path: Option<String>,
    provider_module_version: Option<String>,
    provider: [u8; 32],
    gaps: Vec<serde_json::Value>,
    complete: bool,
    files: Vec<(String, &'static str)>,
    imports: std::collections::BTreeMap<(&'static str, String), Option<String>>,
    relative_refusals: std::collections::BTreeMap<(&'static str, String), GoSourceImportRefusal>,
}

struct GoSourceInventoryRows {
    packages: Vec<PackageRows>,
    digest: [u8; 32],
    gaps: String,
}

/// The unit key a package row stores, with the source role its summaries name:
/// `go` for a package that is not a test variant, otherwise `xtest` when the
/// variant has external test files and `test` when it does not.
fn go_package_unit_key(
    import_path: &str,
    for_test: &str,
    files: &[(String, &'static str)],
) -> [u8; 32] {
    let role = if for_test.is_empty() {
        "go"
    } else if files.iter().any(|(_, role)| *role == "xtest") {
        "xtest"
    } else {
        "test"
    };
    go_unit_key(import_path, for_test, role)
}

impl AnalyzerStore {
    /// Consume one canonical tool result after matching before/after input
    /// observations. All normalization collections die with this publication.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn publish_go_package_context(
        &self,
        snapshot: WorkspaceSnapshotId,
        root: std::path::PathBuf,
        expected_head: Option<GoContextIdentity>,
        before: &GoInputObservation,
        after: &GoInputObservation,
        mut discovery: GoPackageDiscovery,
        cancellation: &CancellationToken,
    ) -> Result<GoContextPublicationOutcome> {
        use serde_json::json;
        if cancellation.is_cancelled() {
            return Ok(GoContextPublicationOutcome::Cancelled);
        }
        if before != after {
            return Ok(GoContextPublicationOutcome::InputsChanged);
        }
        let profile = profile_digest(&discovery);
        let mut context_gaps = Vec::new();
        let conn = self.read_conn()?;
        let configuration_oid = |path: &Path| -> Result<Option<String>> {
            let Ok(relative) = path.strip_prefix(&root) else {
                return Ok(None);
            };
            let Some(relative) = crate::path_utils::workspace_rel_path(&relative.to_string_lossy())
            else {
                return Ok(None);
            };
            Ok(conn.query_row(
                "SELECT blob_oid FROM workspace_file_versions
                 WHERE workspace_id=?1 AND lang='go' AND generation=?2 AND input_kind='configuration'
                   AND rel_path=?3 AND valid_from<=?4 AND (valid_until IS NULL OR ?4<valid_until)",
                params![snapshot.workspace_id.as_str(), snapshot.generation.get(), crate::path_utils::workspace_relative_slash_path(&relative), snapshot.revision],
                |row| row.get(0),
            ).optional()?)
        };
        if !discovery.environment.gowork.is_empty()
            && discovery.environment.gowork != "off"
            && configuration_oid(Path::new(&discovery.environment.gowork))?.is_none()
        {
            context_gaps.push(
                json!({"code":"uncaptured_go_workspace", "evidence":discovery.environment.gowork}),
            );
        }
        discovery
            .packages
            .sort_by(|left, right| left.import_path.cmp(&right.import_path));
        let conflicts = discovery
            .packages
            .windows(2)
            .filter(|pair| pair[0].import_path == pair[1].import_path)
            .map(|pair| pair[0].import_path.clone())
            .collect::<BTreeSet<_>>();
        // File authority is local to each record. Descriptive test files are
        // known but not admitted unless a selected test variant compiles them.
        let recorded_paths = discovery
            .packages
            .iter()
            .flat_map(|package| {
                package
                    .go_files
                    .iter()
                    .chain(&package.cgo_files)
                    .chain(&package.ignored_go_files)
                    .chain(&package.test_go_files)
                    .chain(&package.x_test_go_files)
                    .map(|path| go_tool_source_path(&package.dir, path))
            })
            .collect::<BTreeSet<_>>();
        let failed_roots = discovery
            .packages
            .iter()
            .filter_map(|package| {
                let error = package.error.as_ref()?;
                let directory = if !package.dir.as_os_str().is_empty() {
                    package.dir.clone()
                } else if discovery.workspace_patterns.contains(&package.import_path) {
                    root.clone()
                } else {
                    return None;
                };
                Some((
                    directory,
                    json!({"code":"build_selection_unavailable", "evidence":{
                        "package":package.import_path,"error":error.err,"position":error.pos,
                        "import_stack":error.import_stack
                    }}),
                ))
            })
            .collect::<Vec<_>>();
        if let Some(error) = &discovery.failure {
            let domain = &discovery.domain;
            let boundaries = {
                let mut statement=conn.prepare_cached("SELECT rel_path FROM workspace_file_versions WHERE workspace_id=?1 AND lang='go' AND generation=?2 AND input_kind='configuration' AND valid_from<=?3 AND (valid_until IS NULL OR ?3<valid_until)")?;
                statement
                    .query_map(
                        params![
                            snapshot.workspace_id.as_str(),
                            snapshot.generation.get(),
                            snapshot.revision
                        ],
                        |row| row.get::<_, String>(0),
                    )?
                    .collect::<std::result::Result<Vec<_>, _>>()?
                    .into_iter()
                    .map(PathBuf::from)
                    .filter(|path| path.file_name().is_some_and(|name| name == "go.mod"))
                    .map(|path| path.parent().expect("module manifest parent").to_path_buf())
                    .collect::<BTreeSet<_>>()
            };
            drop(conn);
            let Some(inventory) =
                self.derive_go_source_context(&snapshot, &root, cancellation, &|path| {
                    path.strip_prefix(&root)
                        .ok()
                        .and_then(Path::parent)
                        .and_then(|directory| {
                            directory
                                .ancestors()
                                .find(|parent| boundaries.contains(*parent))
                        })
                        .is_some_and(|owner| {
                            domain
                                .modules
                                .iter()
                                .any(|(directory, _)| owner == Path::new(directory))
                        })
                })?
            else {
                return Ok(GoContextPublicationOutcome::Cancelled);
            };
            let gaps = serde_json::to_string(
                &json!([{"code":"domain_discovery_failed","evidence":error}]),
            )
            .expect("Go failure is JSON");
            let mut hash = CanonicalHasher::new(b"bifrost-go-domain-failure:v1");
            hash.field("inventory", &inventory.digest);
            hash.field("failure", gaps.as_bytes());
            return self.publish_normalized_go_context(
                snapshot,
                profile,
                base_profile_digest(&discovery),
                discovery.domain.clone(),
                discovery.input_digest.unwrap_or(before.digest),
                expected_head,
                inventory.packages,
                hash.finish(),
                false,
                gaps,
                cancellation,
            );
        }
        let mut normalized = Vec::new();
        let mut publication = CanonicalHasher::new(b"bifrost-go-context-publication:v1");
        publication.field("profile", &profile);

        let base_profile = base_profile_digest(&discovery);
        let domain = discovery.domain.clone();
        let input_digest = discovery.input_digest.unwrap_or(before.digest);
        for package in discovery.packages {
            if cancellation.is_cancelled() {
                return Ok(GoContextPublicationOutcome::Cancelled);
            }
            if package.import_path.is_empty() || conflicts.contains(&package.import_path) {
                context_gaps.push(
                    json!({"code":"conflicting_package_identity", "evidence":package.import_path}),
                );
                continue;
            }
            // A failed pattern is invocation evidence, not a nameless
            // package provider. Inventory supplies the same package rows as
            // the unavailable-tool path for this root.
            if package.error.is_some()
                && package.name.is_empty()
                && discovery.workspace_patterns.contains(&package.import_path)
            {
                continue;
            }
            // Source availability and main-module ownership are separate roles.
            // Resolve admitted inventory once per tool member before classifying the provider.
            let mut selected_members = Vec::new();
            for (absolute, ignored) in go_tool_source_members(&package) {
                let relative = absolute.strip_prefix(&root).ok().and_then(|path| {
                    crate::path_utils::workspace_rel_path(
                        &crate::path_utils::workspace_relative_slash_path(path),
                    )
                });
                let member = if let Some(relative) = &relative {
                    conn.query_row(
                        CANONICAL_SOURCE_SQL,
                        params![
                            snapshot.workspace_id.as_str(),
                            snapshot.generation.get(),
                            crate::path_utils::workspace_relative_slash_path(relative),
                            snapshot.revision
                        ],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, Option<String>>(2)?,
                                row.get::<_, Option<String>>(3)?,
                                row.get::<_, Option<i64>>(4)?,
                            ))
                        },
                    )
                    .optional()?
                } else {
                    None
                };
                selected_members.push((absolute, ignored, relative, member));
            }
            // A main module's packages are workspace source even when no member
            // is admitted; that case keeps its unselected_source_input gaps. A
            // dependency is a workspace provider only when its source is admitted
            // here, as for a local replace.
            let provider_kind = if package.standard {
                "standard"
            } else if package.module.as_ref().is_some_and(|module| !module.main)
                && !selected_members
                    .iter()
                    .any(|(_, _, _, member)| member.is_some())
            {
                "module"
            } else {
                "workspace"
            };
            let source_less_provider = provider_kind != "workspace";
            let provider_module_path = package.module.as_ref().map(|module| module.path.clone());
            let provider_module_version =
                package.module.as_ref().map(|module| module.version.clone());
            let mut gaps = Vec::new();
            let mut dependency_gaps = Vec::new();
            if !source_less_provider && !package.cgo_files.is_empty() {
                gaps.push(
                    json!({"code":"cgo_build_selection_unavailable", "evidence":package.cgo_files}),
                );
            }
            if let Some(error) = &package.error {
                gaps.push(json!({"code":"tool_package_error", "evidence":{"error":error.err,"position":error.pos,"import_stack":error.import_stack}}));
            }
            for error in &package.deps_errors {
                dependency_gaps.push(json!({"code":"tool_dependency_error", "evidence":{"error":error.err,"position":error.pos,"import_stack":error.import_stack}}));
            }
            if package.incomplete {
                let evidence = json!({"code":"tool_incomplete", "evidence":package.import_path});
                // Incomplete propagates up the tool's dependency graph. Only an
                // own Error or an unexplained Incomplete limits this provider.
                if package.error.is_some() || package.deps_errors.is_empty() {
                    gaps.push(evidence);
                } else {
                    dependency_gaps.push(evidence);
                }
            }
            if package.name.is_empty() {
                gaps.push(json!({"code":"missing_package_name", "evidence":package.import_path}));
            }
            let mut provider = CanonicalHasher::new(b"bifrost-go-provider:v1");
            provider.field("directory", package.dir.as_os_str().as_encoded_bytes());
            provider.field("standard", &[u8::from(package.standard)]);
            let mut module = package.module.as_ref();
            while let Some(current) = module {
                provider.field("module", current.path.as_bytes());
                provider.field("version", current.version.as_bytes());
                provider.field("sum", current.sum.as_bytes());
                provider.field("directory", current.dir.as_os_str().as_encoded_bytes());
                provider.field("main", &[u8::from(current.main)]);
                if !source_less_provider && !current.go_mod.as_os_str().is_empty() {
                    match configuration_oid(&current.go_mod)? {
                        Some(_) => {},
                        None => gaps.push(json!({"code":"uncaptured_provider_configuration", "evidence":current.go_mod})),
                    }
                }
                module = current.replace.as_deref();
            }
            let provider = provider.finish();
            let mut members = Vec::new();
            // GoFiles/CgoFiles are the files compiled for this exact tool
            // instance. TestGoFiles/XTestGoFiles alone describe possible tests;
            // they do not select an internal or external test variant. Ignored
            // paths record exclusion evidence without admitting source or imports.
            if source_less_provider {
                selected_members.clear();
            }
            for (absolute, ignored, relative, member) in selected_members {
                let Some((_id, _oid, declared, state, version)) = member else {
                    if ignored {
                        continue;
                    }
                    // A refusal is an explained exclusion: it limits only the
                    // packages that compile the file, and names its reason.
                    let refusal = match &relative {
                        Some(relative) => conn
                            .query_row(
                                REFUSED_INPUT_SQL,
                                params![
                                    snapshot.workspace_id.as_str(),
                                    snapshot.generation.get(),
                                    crate::path_utils::workspace_relative_slash_path(relative),
                                    snapshot.revision
                                ],
                                |row| row.get::<_, String>(0),
                            )
                            .optional()?,
                        None => None,
                    };
                    gaps.push(match refusal {
                        Some(reason) => json!({"code":"source_admission_refused", "evidence":{
                            "path":absolute,
                            "reason":serde_json::from_str::<serde_json::Value>(&reason)
                                .expect("the schema checks refusal reasons are JSON"),
                        }}),
                        None => {
                            json!({"code":"unselected_source_input", "evidence":{"path":absolute}})
                        }
                    });
                    continue;
                };
                if !ignored
                    && (declared.as_deref() != Some(package.name.as_str())
                        || state.as_deref() != Some("complete")
                        || version != Some(super::source_facts::SOURCE_FACTS_VERSION))
                {
                    gaps.push(json!({"code":"package_source_identity_mismatch", "evidence":{"path":absolute,"declared":declared,"tool_name":package.name,"source_state":state,"source_version":version}}));
                    continue;
                }
                let file = crate::analyzer::ProjectFile::new(
                    root.clone(),
                    relative.expect("selected source has a workspace-relative path"),
                );
                let role = if ignored {
                    "ignored"
                } else {
                    brokk_bifrost_go::packages::source_inventory_role(&file, &package.name)
                };
                if role != "go" && role != "ignored" && package.for_test.is_empty() {
                    gaps.push(json!({"code":"test_variant_unselected", "evidence":{"path":absolute,"role":role,"package":package.import_path}}));
                    continue;
                }
                members.push((crate::path_utils::rel_path_string(&file), role));
                publication.field("source-role", role.as_bytes());
                publication.field("source-path", absolute.as_os_str().as_encoded_bytes());
            }
            if members.iter().all(|(_, role)| *role == "ignored") && !source_less_provider {
                gaps.push(json!({"code":"missing_selected_package_source", "evidence":package.import_path}));
            }
            // Keep dependency evidence, but consume its incompleteness only
            // through imports of the failed providers. Unrelated declarations
            // in this package still have complete own-source coverage.
            let complete = gaps.is_empty() && context_gaps.is_empty();
            gaps.extend(dependency_gaps);
            // `go list` reports DepsErrors in a different order on every run, and
            // the gap text is part of the publication and provider digests and of
            // every unit summary derived from it. Canonical order makes an
            // unchanged tree republish to the same digests.
            gaps.sort_by_cached_key(serde_json::Value::to_string);
            let gaps_json = serde_json::to_string(&gaps).expect("Go gap evidence is JSON");
            publication.field("package", package.import_path.as_bytes());
            publication.field("name", package.name.as_bytes());
            publication.field("for-test", package.for_test.as_bytes());
            publication.field("provider-kind", provider_kind.as_bytes());
            publication.field("provider-provenance", b"go_tool");
            if let Some(module_path) = &provider_module_path {
                publication.field("provider-module-path", module_path.as_bytes());
            }
            if let Some(module_version) = &provider_module_version {
                publication.field("provider-module-version", module_version.as_bytes());
            }
            publication.field("provider", &provider);
            publication.field("gaps", gaps_json.as_bytes());
            publication.field("complete", &[u8::from(complete)]);
            let admitted_roles = members
                .iter()
                .map(|(_, role)| *role)
                .filter(|role| *role != "ignored")
                .collect::<BTreeSet<_>>();
            for role in &admitted_roles {
                for import in package.imports.iter().collect::<BTreeSet<_>>() {
                    publication.field("import-role", role.as_bytes());
                    publication.field("import", import.as_bytes());
                }
            }
            for (spelling, target) in &package.import_map {
                publication.field("spelling", spelling.as_bytes());
                publication.field("target", target.as_bytes());
            }
            let imports = admitted_roles
                .into_iter()
                .flat_map(|role| {
                    import_mappings(&package, &package.imports).into_iter().map(
                        move |(spelling, target)| {
                            ((role, spelling.to_owned()), Some(target.to_owned()))
                        },
                    )
                })
                .collect();
            normalized.push(PackageRows {
                import_path: package.import_path,
                name: package.name,
                for_test: package.for_test,
                directory: package.dir,
                provider_kind,
                provider_provenance: "go_tool",
                provider_module_path,
                provider_module_version,
                provider,
                gaps,
                complete,
                files: members,
                imports,
                relative_refusals: Default::default(),
            });
        }
        drop(conn);
        if !failed_roots.is_empty() {
            let Some(inventory) =
                self.derive_go_source_context(&snapshot, &root, cancellation, &|path| {
                    !recorded_paths.contains(path)
                        && failed_roots
                            .iter()
                            .any(|(directory, _)| path.starts_with(directory))
                })?
            else {
                return Ok(GoContextPublicationOutcome::Cancelled);
            };
            publication.field("source-inventory", &inventory.digest);
            context_gaps.extend(
                serde_json::from_str::<Vec<serde_json::Value>>(&inventory.gaps)
                    .expect("Go source inventory gap evidence is JSON"),
            );
            for mut package in inventory.packages {
                let failures = failed_roots
                    .iter()
                    .filter(|(directory, _)| package.directory.starts_with(directory))
                    .map(|(_, gap)| gap.clone())
                    .collect::<Vec<_>>();
                if failures.is_empty() {
                    continue;
                }
                for ((_, spelling), target) in &mut package.imports {
                    if target.is_none()
                        && normalized.iter().any(|tool| tool.import_path == *spelling)
                    {
                        *target = Some(spelling.clone());
                    }
                }
                // A failed tool run has exactly the source-only epistemic
                // state. Keep inventory completeness and package gaps intact;
                // build selection uncertainty belongs to context evidence.
                context_gaps.extend(failures);
                if let Some(tool) = normalized
                    .iter_mut()
                    .find(|tool| tool.import_path == package.import_path)
                {
                    tool.files.extend(package.files);
                    tool.complete &= package.complete;
                    tool.gaps.extend(package.gaps);
                    tool.gaps.sort_by_cached_key(serde_json::Value::to_string);
                    tool.relative_refusals.extend(package.relative_refusals);
                    for (key, target) in package.imports {
                        tool.imports.entry(key).or_insert(target);
                    }
                } else {
                    normalized.push(package);
                }
            }
        }
        context_gaps.sort_by_cached_key(serde_json::Value::to_string);
        context_gaps.dedup();
        // Include final normalized rows, including supplemented inventory, in
        // the reusable publication identity.
        for package in &normalized {
            publication.field("final-package", package.import_path.as_bytes());
            publication.field("final-provider", &package.provider);
            publication.field("final-complete", &[u8::from(package.complete)]);
            for (path, role) in &package.files {
                publication.field("member-path", path.as_bytes());
                publication.field("member-role", role.as_bytes());
            }
            publication.field(
                "final-gaps",
                serde_json::to_string(&package.gaps)
                    .expect("Go gap evidence is JSON")
                    .as_bytes(),
            );
            for ((role, spelling), target) in &package.imports {
                publication.field("final-import-role", role.as_bytes());
                publication.field("final-import", spelling.as_bytes());
                if let Some(target) = target {
                    publication.field("final-target", target.as_bytes());
                }
            }
        }
        let context_complete = {
            let providers = normalized
                .iter()
                .map(|row| (row.import_path.as_str(), row.complete))
                .collect::<crate::hash::HashMap<_, _>>();
            context_gaps.is_empty()
                && normalized.iter().all(|row| {
                    row.complete
                        && row.imports.values().all(|target| {
                            target
                                .as_deref()
                                .and_then(|target| providers.get(target))
                                .copied()
                                == Some(true)
                        })
                })
        };
        let context_gaps = serde_json::to_string(&context_gaps).expect("Go gap evidence is JSON");
        publication.field("context-gaps", context_gaps.as_bytes());
        let digest = publication.finish();
        self.publish_normalized_go_context(
            snapshot,
            profile,
            base_profile,
            domain,
            input_digest,
            expected_head,
            normalized,
            digest,
            context_complete,
            context_gaps,
            cancellation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_normalized_go_context(
        &self,
        snapshot: WorkspaceSnapshotId,
        profile: [u8; 32],
        base_profile: [u8; 32],
        domain: brokk_bifrost_go::package_discovery::GoDiscoveryDomain,
        input_digest: [u8; 32],
        _expected_head: Option<GoContextIdentity>,
        normalized: Vec<PackageRows>,
        digest: [u8; 32],
        context_complete: bool,
        context_gaps: String,
        cancellation: &CancellationToken,
    ) -> Result<GoContextPublicationOutcome> {
        use serde_json::json;
        let cancellation = cancellation.clone();
        self.conn.execute(move |conn| -> Result<_> {
            use super::versioned_relation::{PublicationOutcome, VersionedRelation};
            let relation = VersionedRelation {
                table: "go_context_publications",
                id_column: "context_id",
                key_column: "selection_id",
                output_digest_column: "publication_digest",
            };
            let outcome = relation.publish(
                conn, snapshot.revision, &input_digest, &digest, &cancellation,
                |tx| {
                    super::require_current_generation(tx, "go", snapshot.generation)?;
                    let revision: Option<i64> = tx.query_row(
                        "SELECT revision FROM workspace_heads WHERE workspace_id=?1 AND lang='go' AND generation=?2",
                        params![snapshot.workspace_id.as_str(),snapshot.generation.get()], |row|row.get(0),
                    ).optional()?;
                    if revision != Some(snapshot.revision) { return Ok(None); }
            tx.execute("INSERT OR IGNORE INTO go_context_selections(workspace_id,lang,generation,base_profile_digest,domain_dir,gowork_path,profile_digest,derivation_version) VALUES(?1,'go',?2,?3,?4,?5,?6,?7)",
                params![snapshot.workspace_id.as_str(),snapshot.generation.get(),base_profile,domain.directory,domain.gowork_path,profile,DERIVATION_VERSION])?;
            let selection_id: i64 = tx.query_row("SELECT selection_id FROM go_context_selections WHERE workspace_id=?1 AND lang='go' AND generation=?2 AND base_profile_digest=?3 AND domain_dir=?4 AND gowork_path=?5 AND derivation_version=?6",
                params![snapshot.workspace_id.as_str(),snapshot.generation.get(),base_profile,domain.directory,domain.gowork_path,DERIVATION_VERSION],|row|row.get(0))?;
                    Ok(Some(selection_id))
                },
                |tx, selection_id| {
            tx.execute("INSERT INTO go_context_publications(selection_id,workspace_id,lang,generation,valid_from,input_digest,publication_digest,complete,gaps) VALUES(?1,?2,'go',?3,?4,?5,?6,?7,jsonb(?8))",
                params![selection_id,snapshot.workspace_id.as_str(),snapshot.generation.get(),snapshot.revision,input_digest,digest,context_complete,context_gaps])?;
            let context_id = tx.last_insert_rowid();
                    Ok(context_id)
                },
                |tx, context_id| {
            for (directory, module) in &domain.modules {
                tx.execute("INSERT INTO go_context_domain_modules(context_id,module_dir,module_path) VALUES(?1,?2,?3)",params![context_id,directory,module])?;
            }
                for row in &normalized {
                    if cancellation.is_cancelled() { return Ok(false); }
                    let gaps = serde_json::to_string(&row.gaps).expect("Go package gap evidence is JSON");
                    let unit_key = go_package_unit_key(&row.import_path, &row.for_test, &row.files);
                    tx.execute("INSERT INTO go_package_instances(context_id,tool_import_path,package_name,for_test,provider_directory,provider_digest,complete,gaps,provider_kind,provider_module_path,provider_module_version,provider_provenance,unit_key) VALUES(?1,?2,?3,?4,?5,?6,?7,jsonb(?8),?9,?10,?11,?12,?13)",
                        params![context_id,row.import_path,row.name,row.for_test,row.directory.to_string_lossy(),row.provider,row.complete,gaps,row.provider_kind,row.provider_module_path,row.provider_module_version,row.provider_provenance,unit_key.as_slice()])?;
                    let package_id = tx.last_insert_rowid();
                    for (file,role) in &row.files { tx.execute("INSERT INTO go_package_files(package_id,rel_path,source_role) VALUES(?1,?2,?3)",params![package_id,file,role])?; }
                }
                for row in &normalized {
                    let importer: i64 = tx.query_row("SELECT package_id FROM go_package_instances WHERE context_id=?1 AND tool_import_path=?2",params![context_id,row.import_path],|value|value.get(0))?;
                    for ((role,spelling),target) in &row.imports {
                            if cancellation.is_cancelled() { return Ok(false); }
                            let target: Option<(i64,bool)> = tx.query_row("SELECT package_id,complete FROM go_package_instances WHERE context_id=?1 AND tool_import_path=?2",params![context_id,target],|value|Ok((value.get(0)?,value.get(1)?))).optional()?;
                            let complete = row.complete && target.is_some_and(|(_,complete)|complete);
                            let evidence = row.relative_refusals.get(&(*role, spelling.clone()))
                                .map_or_else(|| json!(spelling), |refusal| json!(refusal));
                            let gaps = if complete { "[]".to_owned() } else { serde_json::to_string(&json!([{"code":"incomplete_import_provider","evidence":evidence}])).expect("Go gap evidence is JSON") };
                            tx.execute("INSERT INTO go_package_imports(context_id,importer_package_id,source_spelling,import_role,target_package_id,complete,gaps) VALUES(?1,?2,?3,?4,?5,?6,jsonb(?7))",params![context_id,importer,spelling,role,target.map(|(id,_)|id),complete,gaps])?;
                    }
                }
                    Ok(true)
                },
            )?;
            Ok(match outcome {
                PublicationOutcome::Published { key, row_id } | PublicationOutcome::Unchanged { key, row_id } => GoContextPublicationOutcome::Published(GoContextIdentity {
                    selection_id: key, context_id: row_id, revision: snapshot.revision, publication_digest: digest,
                }),
                PublicationOutcome::InputsChanged => GoContextPublicationOutcome::InputsChanged,
                PublicationOutcome::Cancelled => GoContextPublicationOutcome::Cancelled,
            })
        })
    }
}

#[doc(hidden)]
pub fn source_inventory_profile() -> [u8; 32] {
    CanonicalHasher::new(b"bifrost-go-source-inventory-profile:v2").finish()
}

pub(crate) const MODULE_MANIFESTS_SQL: &str =
    "SELECT rel_path FROM workspace_file_versions WHERE workspace_id=?1 AND lang='go' AND generation=?2
             AND input_kind='configuration' AND (rel_path='go.mod' OR rel_path GLOB '*/go.mod')
             AND valid_from<=?3 AND (valid_until IS NULL OR ?3<valid_until)";

pub(crate) const SOURCE_INVENTORY_SQL: &str =
    "SELECT f.file_version_id,f.rel_path,f.blob_oid,a.package_name,b.id,m.content_package,
            manifest.publication_state,manifest.facts_version,m.is_complete,
            COALESCE(go_manifest.has_build_constraints,0),
            COALESCE(go_manifest.build_selection_facts_version,0)
     FROM workspace_file_versions f
     LEFT JOIN workspace_file_anchor_rows a ON a.file_version_id=f.file_version_id
       AND a.anchor_kind='own_module' AND a.anchor_pop=0
     LEFT JOIN blobs b ON b.blob_oid=f.blob_oid AND b.lang=f.lang AND b.parse_variant=x'' AND b.generation=f.generation
     LEFT JOIN blob_meta m ON m.blob_id=b.id
     LEFT JOIN source_fact_manifests manifest ON manifest.blob_id=b.id
     LEFT JOIN source_go_manifests go_manifest ON go_manifest.blob_id=b.id
     WHERE f.workspace_id=?1 AND f.lang='go' AND f.generation=?2 AND f.input_kind='source'
       AND f.valid_from<=?3 AND (f.valid_until IS NULL OR ?3<f.valid_until)
     ORDER BY f.rel_path";

impl AnalyzerStore {
    /// Derive partial local evidence only from the selected immutable source
    /// publication. This service never reads live source or invokes the tool.
    #[doc(hidden)]
    pub fn publish_go_source_context(
        &self,
        snapshot: WorkspaceSnapshotId,
        root: &Path,
        cancellation: &CancellationToken,
    ) -> Result<GoContextPublicationOutcome> {
        if cancellation.is_cancelled() {
            return Ok(GoContextPublicationOutcome::Cancelled);
        }
        let profile = source_inventory_profile();
        let expected = self.go_context_for_reconciliation(&snapshot, &profile)?;
        let Some(inventory) =
            self.derive_go_source_context(&snapshot, root, cancellation, &|_| true)?
        else {
            return Ok(GoContextPublicationOutcome::Cancelled);
        };
        self.publish_normalized_go_context(
            snapshot,
            profile,
            profile,
            Default::default(),
            inventory.digest,
            expected,
            inventory.packages,
            inventory.digest,
            false,
            inventory.gaps,
            cancellation,
        )
    }

    fn derive_go_source_context(
        &self,
        snapshot: &WorkspaceSnapshotId,
        root: &Path,
        cancellation: &CancellationToken,
        admits: &impl Fn(&Path) -> bool,
    ) -> Result<Option<GoSourceInventoryRows>> {
        use serde_json::json;
        use std::collections::{BTreeMap, BTreeSet};
        let profile = source_inventory_profile();
        let conn = self.read_conn()?;
        let mut publication = CanonicalHasher::new(b"bifrost-go-source-inventory-publication:v2");
        publication.field("profile", &profile);
        let mut gaps = vec![json!({"code":"build_selection_unavailable","evidence":
            "Source inventory has no selected platform, build tags, cgo admission, tool test variants or external provider authority"})];
        // Both maps are this derivation query's transient result, never analyzer state.
        let mut packages = BTreeMap::<String, PackageRows>::new();
        let mut names = BTreeMap::<String, BTreeSet<String>>::new();
        let mut aliases = BTreeMap::<String, BTreeSet<String>>::new();
        let mut relative_imports = BTreeMap::new();
        // Snapshot module paths are this publication query's transient result.
        // Read them once rather than sorting a correlated subquery per source.
        let module_manifests = conn
            .prepare_cached(MODULE_MANIFESTS_SQL)?
            .query_map(
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.get(),
                    snapshot.revision
                ],
                |row| row.get::<_, String>(0).map(PathBuf::from),
            )?
            .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        let mut query = conn.prepare_cached(SOURCE_INVENTORY_SQL)?;
        let mut files = query.query(params![
            snapshot.workspace_id.as_str(),
            snapshot.generation.get(),
            snapshot.revision
        ])?;
        while let Some(file) = files.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let id: i64 = file.get(0)?;
            let path: String = file.get(1)?;
            if !admits(&root.join(&path)) {
                continue;
            }
            let _oid: String = file.get(2)?;
            let anchor: Option<String> = file.get(3)?;
            let blob: Option<i64> = file.get(4)?;
            let name: Option<String> = file.get(5)?;
            let state: Option<String> = file.get(6)?;
            let version: Option<i64> = file.get(7)?;
            let complete: Option<bool> = file.get(8)?;
            let has_build_constraints: bool = file.get(9)?;
            let build_selection_facts_version: i64 = file.get(10)?;
            let module_manifest = Path::new(&path)
                .parent()
                .expect("source file parent")
                .ancestors()
                .map(|directory| directory.join("go.mod"))
                .find(|manifest| module_manifests.contains(manifest))
                .map(|manifest| crate::path_utils::workspace_relative_slash_path(&manifest));
            let module_mode = module_manifest.is_some();
            publication.field("path", path.as_bytes());

            let (Some(anchor), Some(blob), Some(name)) = (anchor, blob, name) else {
                gaps.push(json!({"code":"missing_source_package_authority","evidence":path}));
                continue;
            };
            if state.as_deref() != Some("complete")
                || version != Some(super::source_facts::SOURCE_FACTS_VERSION)
                || complete != Some(true)
                || name.is_empty()
            {
                gaps.push(json!({"code":"unavailable_source_publication","evidence":path}));
                continue;
            }
            let directory = root.join(Path::new(&path).parent().unwrap_or(Path::new("")));
            let source_file = crate::analyzer::ProjectFile::new(
                root.to_path_buf(),
                std::path::PathBuf::from(&path),
            );
            let role = brokk_bifrost_go::packages::source_inventory_role(&source_file, &name);
            let file_has_build_constraints =
                brokk_bifrost_go::packages::source_file_has_build_constraints(
                    &source_file,
                    has_build_constraints,
                );
            publication.field("package", anchor.as_bytes());
            publication.field("name", name.as_bytes());
            publication.field("role", role.as_bytes());
            publication.field("provider-provenance", b"source_inventory");
            names
                .entry(anchor.clone())
                .or_default()
                .insert(name.clone());
            let package = packages.entry(anchor.clone()).or_insert_with(|| {
                let mut provider = CanonicalHasher::new(b"bifrost-go-source-provider:v2");
                provider.field("package", anchor.as_bytes());
                provider.field("provenance", b"source_inventory");
                PackageRows {
                    import_path: anchor.clone(),
                    name,
                    for_test: String::new(),
                    directory,
                    provider_kind: "workspace",
                    provider_provenance: "source_inventory",
                    provider_module_path: None,
                    provider_module_version: None,
                    provider: provider.finish(),
                    gaps: Vec::new(),
                    complete: true,
                    files: Vec::new(),
                    imports: BTreeMap::new(),
                    relative_refusals: Default::default(),
                }
            });
            if file_has_build_constraints {
                // The selected package profile determines which constrained
                // files participate. Their presence in this source inventory
                // is not itself a missing provider.
                publication.field("build-constrained-file", path.as_bytes());
            }
            if build_selection_facts_version != GO_BUILD_SELECTION_FACTS_VERSION {
                publication.field(
                    "build-selection-facts-version",
                    &build_selection_facts_version.to_le_bytes(),
                );
            }
            package.files.push((path.clone(), role));
            let Some(imports) = super::source_facts::read_source_imports(&conn, blob, &|| {
                !cancellation.is_cancelled()
            })?
            else {
                return Ok(None);
            };
            for import in imports {
                let Some(import_path) = import.path.filter(|path| !path.segments.is_empty()) else {
                    gaps.push(json!({"code":"unavailable_source_import","evidence":{"path":path,"occurrence":import.declaration.index()}}));
                    continue;
                };
                let spelling = import_path.segments.join("/");
                if spelling == "C" {
                    package.complete = false;
                    package.gaps.push(json!({
                        "code":"source_cgo_build_selection_unavailable",
                        "evidence":{"path":path}
                    }));
                    gaps.push(json!({"code":"source_cgo_build_selection_unavailable","evidence":{"path":path}}));
                    publication.field("cgo-file", path.as_bytes());
                    continue;
                }
                publication.field("import-role", role.as_bytes());
                publication.field("import", spelling.as_bytes());
                if matches!(import_path.segments[0].as_str(), "." | "..") {
                    let directory = crate::path_utils::normalize_relative_path_from(
                        Path::new(&path).parent().expect("source file parent"),
                        &import_path.segments.iter().collect::<PathBuf>(),
                    );
                    publication.field("relative-import-module-mode", &[u8::from(module_mode)]);
                    if let Some(directory) = &directory {
                        publication.field(
                            "relative-import-directory",
                            crate::path_utils::workspace_relative_slash_path(directory).as_bytes(),
                        );
                    }
                    if let Some(manifest) = &module_manifest {
                        publication.field("relative-import-module", manifest.as_bytes());
                    }
                    relative_imports.insert(
                        (anchor.clone(), role, spelling.clone()),
                        (path.clone(), directory, module_manifest.clone()),
                    );
                }
                package.imports.insert((role, spelling), None);
            }
            let mut alias_query = conn.prepare_cached("SELECT package_name FROM workspace_file_package_rows WHERE file_version_id=?1 ORDER BY package_name")?;
            let alias_rows = alias_query.query_map([id], |row| row.get::<_, String>(0))?;
            for alias in alias_rows {
                let alias = alias?;
                publication.field("alias", alias.as_bytes());
                aliases.entry(alias).or_default().insert(anchor.clone());
            }
            aliases.entry(anchor.clone()).or_default().insert(anchor);
        }
        drop(files);
        drop(query);
        // A refused source has no row above, so no package learned of it there,
        // and its package clause is unknown. Every package in its directory is
        // partial over it, with the file and reason as package evidence. The
        // gap stays on the packages: a context-level gap would make every
        // request in the workspace incomplete.
        let mut refused = conn.prepare_cached(REFUSED_INPUTS_SQL)?;
        let mut refusals = refused.query(params![
            snapshot.workspace_id.as_str(),
            snapshot.generation.get(),
            snapshot.revision
        ])?;
        while let Some(refusal) = refusals.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let path: String = refusal.get(0)?;
            if !admits(&root.join(&path)) {
                continue;
            }
            let reason: serde_json::Value = serde_json::from_str(&refusal.get::<_, String>(2)?)
                .expect("the schema checks refusal reasons are JSON");
            publication.field("refused-path", path.as_bytes());
            let directory = root.join(Path::new(&path).parent().unwrap_or(Path::new("")));
            for package in packages
                .values_mut()
                .filter(|package| package.directory == directory)
            {
                package.complete = false;
                package
                    .gaps
                    .push(json!({"code":"source_admission_refused","evidence":{
                        "path":path,"reason":reason
                    }}));
            }
        }
        drop(refusals);
        drop(refused);
        let mut directories = BTreeMap::<PathBuf, BTreeSet<String>>::new();
        for package in packages
            .values()
            .filter(|package| package.files.iter().any(|(_, role)| *role != "xtest"))
        {
            directories
                .entry(package.directory.clone())
                .or_default()
                .insert(package.import_path.clone());
        }
        for package in packages.values_mut() {
            let declared = &names[&package.import_path];
            if declared.len() != 1 {
                package.name.clear();
                package.complete = false;
                package.gaps.push(json!({"code":"conflicting_source_package_names","evidence":{"package":package.import_path,"names":declared}}));
                gaps.push(json!({"code":"conflicting_source_package_names","evidence":{"package":package.import_path,"names":declared}}));
            }
            for ((role, spelling), target) in &mut package.imports {
                if let Some((importer, directory, module_manifest)) =
                    relative_imports.get(&(package.import_path.clone(), *role, spelling.clone()))
                {
                    let candidates = directory
                        .as_ref()
                        .and_then(|directory| directories.get(&root.join(directory)));
                    let reason = if module_manifest.is_some() {
                        Some(GoSourceImportRefusalReason::RelativeImportInModuleMode)
                    } else if directory.is_none() {
                        Some(GoSourceImportRefusalReason::RelativeImportOutsideWorkspace)
                    } else if let Some(candidates) = candidates.filter(|rows| rows.len() == 1) {
                        let candidate = candidates.first().expect("one source provider");
                        if names[candidate].len() == 1 {
                            *target = Some(candidate.clone());
                            publication.field("relative-import-target", candidate.as_bytes());
                            None
                        } else {
                            Some(GoSourceImportRefusalReason::ConflictingSourcePackageNames)
                        }
                    } else if candidates.is_some() {
                        Some(GoSourceImportRefusalReason::ConflictingSourcePackageNames)
                    } else {
                        Some(GoSourceImportRefusalReason::SourcePackageDirectoryUnavailable)
                    };
                    if let Some(reason) = reason {
                        let candidates = candidates
                            .into_iter()
                            .flatten()
                            .cloned()
                            .collect::<Vec<_>>();
                        let declared_names = candidates
                            .iter()
                            .flat_map(|candidate| names[candidate].iter().cloned())
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .collect();
                        let refusal = GoSourceImportRefusal {
                            importer: importer.clone(),
                            spelling: spelling.clone(),
                            role: (*role).into(),
                            reason,
                            directory: directory
                                .as_ref()
                                .map(|path| crate::path_utils::workspace_relative_slash_path(path)),
                            candidates,
                            module_manifest: module_manifest.clone(),
                            declared_names,
                        };
                        gaps.push(
                            json!({"code":"source_import_provider_unavailable","evidence":refusal}),
                        );
                        package
                            .relative_refusals
                            .insert((*role, spelling.clone()), refusal);
                    }
                    continue;
                }
                match aliases.get(spelling) {
                    Some(candidates) if candidates.len()==1 => {
                        let candidate = candidates.first().expect("one source provider");
                        if names[candidate].len()==1 { *target=Some(candidate.clone()); }
                    }
                    candidates => gaps.push(json!({"code":"source_import_provider_unavailable","evidence":{"importer":package.import_path,"spelling":spelling,"candidates":candidates}})),
                }
            }
        }
        let gaps = serde_json::to_string(&gaps).expect("Go source gap evidence is JSON");
        publication.field("gaps", gaps.as_bytes());
        for package in packages.values() {
            publication.field("package-complete", &[u8::from(package.complete)]);
            let package_gaps = serde_json::to_string(&package.gaps)
                .expect("Go source package gap evidence is JSON");
            publication.field("package-gaps", package_gaps.as_bytes());
        }
        let digest = publication.finish();
        drop(conn);
        Ok(Some(GoSourceInventoryRows {
            packages: packages.into_values().collect(),
            digest,
            gaps,
        }))
    }
}

impl AnalyzerStore {
    /// Enumerate domains and hash their exact selected input rows in one ordered pass.
    #[doc(hidden)]
    pub fn go_discovery_domain_inputs(
        &self,
        snapshot: &WorkspaceSnapshotId,
        root: &Path,
    ) -> Result<
        Vec<(
            brokk_bifrost_go::package_discovery::GoDiscoveryDomain,
            [u8; 32],
        )>,
    > {
        self.go_discovery_domain_inputs_replacing(snapshot, root, &HashMap::new())
    }

    /// The same manifest digests used by transient placement decide whether
    /// buffers require tool discovery. No second parser or header hash exists.
    #[doc(hidden)]
    pub fn go_overlay_placement(
        &self,
        snapshot: &WorkspaceSnapshotId,
        root: &Path,
        context_id: Option<i64>,
        domain: &brokk_bifrost_go::package_discovery::GoDiscoveryDomain,
        overlays: &GoOverlaySnapshot,
    ) -> Result<GoOverlayPlacement> {
        if overlays.files.is_empty() {
            return Ok(GoOverlayPlacement::default());
        }
        let conn = self.read_conn()?;
        let revision = context_id
            .map(|context_id| {
                conn.query_row(
                    "SELECT valid_from FROM go_context_publications WHERE context_id=?1",
                    [context_id],
                    |row| row.get::<_, i64>(0),
                )
            })
            .transpose()?;
        let boundaries = conn
            .prepare_cached(MODULE_MANIFESTS_SQL)?
            .query_map(
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.get(),
                    snapshot.revision
                ],
                |row| row.get::<_, String>(0),
            )?
            .map(|row| {
                row.map(|path| {
                    PathBuf::from(path)
                        .parent()
                        .expect("module path parent")
                        .to_path_buf()
                })
            })
            .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        // The output can cut off across several saves, updating its input key
        // without moving valid_from. Compare membership against recorded source
        // versions, rather than treating valid_from as the latest input key.
        // This map is the result of this reconciliation query only. It avoids
        // a scan of every header match for each workspace input and dies here.
        let replacements = if let Some(revision) = revision {
            conn.prepare_cached(
            "SELECT current.rel_path, previous.blob_oid FROM workspace_file_versions current
             JOIN workspace_file_versions previous ON previous.workspace_id=current.workspace_id
               AND previous.lang=current.lang AND previous.generation=current.generation
               AND previous.input_kind=current.input_kind AND previous.rel_path=current.rel_path
               AND previous.valid_from<=?4 AND (previous.valid_until IS NULL OR ?4<previous.valid_until)
             JOIN blobs old_blob ON old_blob.blob_oid=previous.blob_oid AND old_blob.lang='go' AND old_blob.parse_variant=x'' AND old_blob.generation=current.generation
             JOIN source_go_manifests old ON old.blob_id=old_blob.id
             JOIN blobs new_blob ON new_blob.blob_oid=current.blob_oid AND new_blob.lang='go' AND new_blob.parse_variant=x'' AND new_blob.generation=current.generation
             JOIN source_go_manifests new ON new.blob_id=new_blob.id AND new.membership_digest=old.membership_digest
             WHERE current.workspace_id=?1 AND current.lang='go' AND current.generation=?2 AND current.input_kind='source'
               AND current.valid_from<=?3 AND (current.valid_until IS NULL OR ?3<current.valid_until)")?
            .query_map(params![snapshot.workspace_id.as_str(),snapshot.generation.get(),snapshot.revision,revision],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?)))?
            .collect::<std::result::Result<HashMap<_,_>,_>>()?
        } else {
            HashMap::new()
        };
        let mut has_overlay = false;
        let mut changed_membership = false;
        for file in &overlays.files {
            let owner = Path::new(&file.path)
                .parent()
                .expect("source path parent")
                .ancestors()
                .find(|directory| boundaries.contains(*directory));
            if owner.is_some_and(|owner| {
                domain
                    .modules
                    .iter()
                    .any(|(directory, _)| Path::new(directory) == owner)
            }) {
                has_overlay = true;
                // An already-published unsaved import must still be supplied
                // on a later forced discovery. Compare the captured overlay
                // with its recorded disk underlay, not with that overlay's own
                // context version. Both digests come from the same source parse
                // authority as transient placement. Missing versions or NULL
                // digests, including new unsaved files, never prove equality.
                let same_disk_header: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM workspace_file_versions recorded
                     JOIN blobs old_blob ON old_blob.blob_oid=recorded.blob_oid AND old_blob.lang=recorded.lang AND old_blob.parse_variant=x'' AND old_blob.generation=recorded.generation
                     JOIN source_go_manifests old ON old.blob_id=old_blob.id
                     JOIN blobs new_blob ON new_blob.blob_oid=?5 AND new_blob.lang=recorded.lang AND new_blob.parse_variant=x'' AND new_blob.generation=recorded.generation
                     JOIN source_go_manifests new ON new.blob_id=new_blob.id AND new.membership_digest=old.membership_digest
                     WHERE recorded.workspace_id=?1 AND recorded.lang='go' AND recorded.generation=?2
                       AND recorded.input_kind='source' AND recorded.rel_path=?3 AND recorded.blob_oid=?4)",
                    params![snapshot.workspace_id.as_str(),snapshot.generation.get(),file.path,file.disk_oid,file.oid],
                    |row|row.get(0),
                )?;
                changed_membership |= !same_disk_header;
            }
        }
        if !has_overlay {
            return Ok(GoOverlayPlacement::default());
        }
        drop(conn);
        let Some(revision) = revision else {
            return Ok(GoOverlayPlacement {
                changed_membership,
                reuse_context: false,
            });
        };
        let mut recorded = snapshot.clone();
        recorded.revision = revision;
        let baseline = self.go_discovery_domain_inputs(&recorded, root)?;
        let current = self.go_discovery_domain_inputs_replacing(snapshot, root, &replacements)?;
        let digest = |inputs: &[(
            brokk_bifrost_go::package_discovery::GoDiscoveryDomain,
            [u8; 32],
        )]| {
            inputs
                .iter()
                .find(|(input, _)| {
                    input.directory == domain.directory && input.gowork_path == domain.gowork_path
                })
                .map(|(_, digest)| *digest)
        };
        Ok(GoOverlayPlacement {
            changed_membership,
            // Reuse compares with the placed context independently of whether
            // the buffer still differs from disk. Body edits after an unsaved
            // import therefore skip discovery too.
            reuse_context: digest(&baseline).is_some() && digest(&baseline) == digest(&current),
        })
    }

    fn go_discovery_domain_inputs_replacing(
        &self,
        snapshot: &WorkspaceSnapshotId,
        root: &Path,
        replacements: &HashMap<String, String>,
    ) -> Result<
        Vec<(
            brokk_bifrost_go::package_discovery::GoDiscoveryDomain,
            [u8; 32],
        )>,
    > {
        let conn = self.read_conn()?;
        let mut query = conn.prepare_cached(
            "SELECT f.rel_path,f.blob_oid,f.input_kind,retained.source_bytes
            FROM workspace_file_versions f LEFT JOIN workspace_input_sources retained
              ON retained.content_oid=f.blob_oid AND f.input_kind='configuration'
            WHERE f.workspace_id=?1 AND f.lang='go' AND f.generation=?2
              AND f.valid_from<=?3 AND (f.valid_until IS NULL OR ?3<f.valid_until)
            ORDER BY f.rel_path,f.input_kind",
        )?;
        let rows = query
            .query_map(
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.get(),
                    snapshot.revision
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                    ))
                },
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let inputs = rows
            .iter()
            .filter(|(_, _, kind, _)| kind == "configuration")
            .map(|(path, _, _, bytes)| {
                let bytes = bytes.as_ref().ok_or_else(|| {
                    super::StoreError::new(format!(
                        "selected Go configuration bytes unavailable: {path}"
                    ))
                })?;
                let source = String::from_utf8(bytes.clone())
                    .map_err(|error| super::StoreError::new(error.to_string()))?;
                Ok((PathBuf::from(path), source))
            })
            .collect::<Result<Vec<_>>>()?;
        let boundaries = inputs
            .iter()
            .filter(|(path, _)| path.file_name().is_some_and(|name| name == "go.mod"))
            .map(|(path, _)| path.parent().expect("module manifest parent"))
            .collect::<BTreeSet<_>>();
        let domains = brokk_bifrost_go::package_discovery::go_discovery_domains(root, &inputs)
            .map_err(super::StoreError::new)?;
        let mut hashes = domains
            .iter()
            .map(|domain| {
                let mut hash = CanonicalHasher::new(b"bifrost-go-domain-inputs:v1");
                for (directory, module) in &domain.modules {
                    hash.field("module-dir", directory.as_bytes());
                    hash.field("module-path", module.as_bytes());
                }
                hash
            })
            .collect::<Vec<_>>();
        // A refused source is a domain input too: `go list` reads its bytes.
        let refused = conn
            .prepare_cached(REFUSED_INPUTS_SQL)?
            .query_map(
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.get(),
                    snapshot.revision
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let selected = rows
            .iter()
            .map(|(path, oid, _, _)| ("path", path, replacements.get(path).unwrap_or(oid)));
        let refused = refused
            .iter()
            .map(|(path, oid)| ("refused-path", path, oid));
        for (field, path, oid) in selected.chain(refused) {
            let path_value = Path::new(path);
            let owner = path_value
                .parent()
                .expect("workspace path parent")
                .ancestors()
                .find(|directory| boundaries.contains(directory));
            for (domain, hash) in domains.iter().zip(&mut hashes) {
                let member = owner.is_some_and(|owner| {
                    domain
                        .modules
                        .iter()
                        .any(|(directory, _)| Path::new(directory) == owner)
                });
                let workfile = !domain.gowork_path.is_empty()
                    && (path == &domain.gowork_path
                        || path_value
                            == Path::new(&domain.gowork_path).with_file_name("go.work.sum"));
                if member || workfile {
                    hash.field(field, path.as_bytes());
                    hash.field("oid", oid.as_bytes());
                }
            }
        }
        Ok(domains
            .into_iter()
            .zip(hashes.into_iter().map(CanonicalHasher::finish))
            .collect())
    }
}

impl AnalyzerStore {
    #[doc(hidden)]
    pub fn validate_go_context_members(&self, identity: &GoContextIdentity) -> Result<()> {
        let conn = self.read_conn()?;
        let mut query = conn.prepare_cached(MISSING_MEMBER_PATHS_SQL)?;
        let missing = query
            .query_map(params![identity.context_id, identity.revision], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if !missing.is_empty() {
            return Err(super::StoreError::new(format!(
                "go_context_member_version_unavailable: context {:?}, paths {missing:?}",
                identity
            )));
        }
        debug_assert!(
            missing.is_empty(),
            "every Go membership path joins a selected file version"
        );
        Ok(())
    }

    #[doc(hidden)]
    pub fn close_absent_go_domains(
        &self,
        snapshot: &WorkspaceSnapshotId,
        base: [u8; 32],
        domains: &[(
            brokk_bifrost_go::package_discovery::GoDiscoveryDomain,
            [u8; 32],
        )],
    ) -> Result<()> {
        let snapshot = snapshot.clone();
        let domains = domains
            .iter()
            .map(|(domain, _)| (&domain.directory, &domain.gowork_path))
            .collect::<Vec<_>>();
        let domains = serde_json::to_string(&domains).expect("Go domains are JSON values");
        self.conn.execute(move |conn| -> Result<()> {
            conn.execute("UPDATE go_context_publications SET valid_until=?3 WHERE valid_until IS NULL
              AND valid_from<=?3 AND selection_id IN(SELECT selection_id FROM go_context_selections s
                WHERE s.workspace_id=?1 AND s.generation=?2 AND s.base_profile_digest=?4
                  AND NOT EXISTS(SELECT 1 FROM json_each(?5) domain
                    WHERE json_extract(domain.value,'$[0]')=s.domain_dir AND json_extract(domain.value,'$[1]')=s.gowork_path))",
                params![snapshot.workspace_id.as_str(),snapshot.generation.get(),snapshot.revision,base,domains])?;
            Ok(())
        })
    }
}

pub(crate) const MISSING_MEMBER_PATHS_SQL: &str="SELECT member.rel_path FROM go_package_instances package
 JOIN go_package_files member USING(package_id)
 JOIN go_context_publications p ON p.context_id=package.context_id
 WHERE package.context_id=?1 AND NOT EXISTS(SELECT 1 FROM workspace_file_versions file
   WHERE file.workspace_id=p.workspace_id AND file.lang=p.lang AND file.generation=p.generation
     AND file.input_kind='source' AND file.rel_path=member.rel_path
     AND file.valid_from<=?2 AND (file.valid_until IS NULL OR ?2<file.valid_until)) ORDER BY member.rel_path";

// Q1/Q4: membership is authority, never an ancestor-directory approximation.
// Provider membership selects every build context holding the source as a target.
// Owner lookup selects only main-module packages to resolve and scan callers once.
macro_rules! participating_context_files_sql {
    () => {
        r#"
FROM go_package_files f
JOIN go_package_instances p ON p.package_id=f.package_id
JOIN go_context_publications c ON c.context_id=p.context_id
JOIN go_context_selections s ON s.selection_id=c.selection_id
WHERE p.provider_kind='workspace' AND f.source_role<>'ignored'
  AND s.workspace_id=?1 AND s.lang='go' AND s.generation=?2
  AND s.base_profile_digest=?4 AND s.derivation_version=?5
  AND c.valid_from<=?3 AND (c.valid_until IS NULL OR ?3<c.valid_until)
"#
    };
}

pub(crate) const CONTEXTS_FOR_FILE_SQL: &str = concat!(
    "SELECT DISTINCT c.selection_id, c.context_id, c.publication_digest, s.profile_digest ",
    participating_context_files_sql!(),
    " AND f.rel_path=?6 ORDER BY c.context_id"
);

pub(crate) const OUTSIDE_SELECTED_BUILD_FILES_SQL: &str = concat!(
    "SELECT source.rel_path FROM workspace_file_versions source
     WHERE source.workspace_id=?1 AND source.lang='go' AND source.generation=?2
       AND source.input_kind='source'
       AND source.valid_from<=?3 AND (source.valid_until IS NULL OR ?3<source.valid_until)
       AND NOT EXISTS (SELECT 1 ",
    participating_context_files_sql!(),
    " AND f.rel_path=source.rel_path) ORDER BY source.rel_path"
);

pub(crate) const OWNER_CONTEXT_FOR_FILE_SQL: &str = r#"
SELECT DISTINCT c.selection_id, c.context_id, c.publication_digest, s.profile_digest
FROM go_package_files f
JOIN go_package_instances p ON p.package_id=f.package_id
JOIN go_context_publications c ON c.context_id=p.context_id
JOIN go_context_selections s ON s.selection_id=c.selection_id
WHERE f.rel_path=?6 AND p.provider_kind='workspace' AND f.source_role<>'ignored'
  AND s.workspace_id=?1 AND s.lang='go' AND s.generation=?2
  AND s.base_profile_digest=?4 AND s.derivation_version=?5
  AND c.valid_from<=?3 AND (c.valid_until IS NULL OR ?3<c.valid_until)
  AND (p.provider_module_path IS NULL OR EXISTS(
    SELECT 1 FROM go_context_domain_modules m
    WHERE m.context_id=c.context_id AND m.module_path=p.provider_module_path))
ORDER BY c.context_id
"#;

pub(crate) const OWNER_CONTEXT_FOR_DEFINITION_FILE_SQL: &str = r#"
SELECT DISTINCT c.selection_id, c.context_id, c.publication_digest, s.profile_digest
FROM go_package_files f
JOIN go_package_instances p ON p.package_id=f.package_id
JOIN go_context_publications c ON c.context_id=p.context_id
JOIN go_context_selections s ON s.selection_id=c.selection_id
WHERE f.rel_path=?6 AND p.provider_kind='workspace'
  AND s.workspace_id=?1 AND s.lang='go' AND s.generation=?2
  AND s.base_profile_digest=?4 AND s.derivation_version=?5
  AND c.valid_from<=?3 AND (c.valid_until IS NULL OR ?3<c.valid_until)
  AND (p.provider_module_path IS NULL OR EXISTS(
    SELECT 1 FROM go_context_domain_modules m
    WHERE m.context_id=c.context_id AND m.module_path=p.provider_module_path))
ORDER BY c.context_id
"#;

pub(crate) fn go_contexts_for_file_on(
    conn: &rusqlite::Connection,
    snapshot: &WorkspaceSnapshotId,
    base: &[u8; 32],
    path: &str,
) -> Result<Vec<(GoContextIdentity, [u8; 32])>> {
    contexts_for_file_statement_on(conn, snapshot, base, path, CONTEXTS_FOR_FILE_SQL)
}

pub(crate) fn go_owner_context_for_file_on(
    conn: &rusqlite::Connection,
    snapshot: &WorkspaceSnapshotId,
    base: &[u8; 32],
    path: &str,
) -> Result<Vec<(GoContextIdentity, [u8; 32])>> {
    contexts_for_file_statement_on(conn, snapshot, base, path, OWNER_CONTEXT_FOR_FILE_SQL)
}

pub(crate) fn go_owner_context_for_definition_file_on(
    conn: &rusqlite::Connection,
    snapshot: &WorkspaceSnapshotId,
    base: &[u8; 32],
    path: &str,
) -> Result<Vec<(GoContextIdentity, [u8; 32])>> {
    contexts_for_file_statement_on(
        conn,
        snapshot,
        base,
        path,
        OWNER_CONTEXT_FOR_DEFINITION_FILE_SQL,
    )
}

fn contexts_for_file_statement_on(
    conn: &rusqlite::Connection,
    snapshot: &WorkspaceSnapshotId,
    base: &[u8; 32],
    path: &str,
    sql: &str,
) -> Result<Vec<(GoContextIdentity, [u8; 32])>> {
    let mut statement = conn.prepare_cached(sql)?;
    let rows = statement.query_map(
        params![
            snapshot.workspace_id.as_str(),
            snapshot.generation.get(),
            snapshot.revision,
            base,
            DERIVATION_VERSION,
            path
        ],
        |row| context_for_file_row(row, snapshot),
    )?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Decode the same publication evidence for direct and selected-operation readers.
pub(crate) fn context_for_file_row(
    row: &rusqlite::Row<'_>,
    snapshot: &WorkspaceSnapshotId,
) -> rusqlite::Result<(GoContextIdentity, [u8; 32])> {
    Ok((
        GoContextIdentity {
            revision: snapshot.revision,
            selection_id: row.get(0)?,
            context_id: row.get(1)?,
            publication_digest: row
                .get::<_, Vec<u8>>(2)?
                .try_into()
                .expect("schema checks digest width"),
        },
        row.get::<_, Vec<u8>>(3)?
            .try_into()
            .expect("schema checks profile width"),
    ))
}

impl AnalyzerStore {
    /// All source files with no non-ignored membership in any selected context.
    #[doc(hidden)]
    pub fn go_files_outside_selected_build(
        &self,
        snapshot: &WorkspaceSnapshotId,
        base: &[u8; 32],
    ) -> Result<Vec<String>> {
        let conn = self.read_conn()?;
        let mut statement = conn.prepare_cached(OUTSIDE_SELECTED_BUILD_FILES_SQL)?;
        let rows = statement.query_map(
            params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.get(),
                snapshot.revision,
                base,
                DERIVATION_VERSION
            ],
            |row| row.get(0),
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    #[doc(hidden)]
    pub fn go_contexts_for_file(
        &self,
        snapshot: &WorkspaceSnapshotId,
        base: &[u8; 32],
        path: &str,
    ) -> Result<Vec<(GoContextIdentity, [u8; 32])>> {
        let contexts = {
            let conn = self.read_conn()?;
            go_contexts_for_file_on(&conn, snapshot, base, path)?
        };
        for (context, _) in &contexts {
            self.validate_go_context_members(context)?;
        }
        Ok(contexts)
    }
    #[doc(hidden)]
    pub fn go_owner_context_for_file(
        &self,
        snapshot: &WorkspaceSnapshotId,
        base: &[u8; 32],
        path: &str,
    ) -> Result<Vec<(GoContextIdentity, [u8; 32])>> {
        let contexts = {
            let conn = self.read_conn()?;
            go_owner_context_for_file_on(&conn, snapshot, base, path)?
        };
        for (context, _) in &contexts {
            self.validate_go_context_members(context)?;
        }
        Ok(contexts)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn go_domain_intervals_cut_off_and_revalidate_superseded_or_missing_paths() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("go", "domain-interval-fixture")
            .unwrap();
        let snapshot = WorkspaceSnapshotId {
            workspace_id: super::super::WorkspaceId::for_root(
                &std::env::temp_dir().join("go-interval-fixture"),
            ),
            lang: "go".into(),
            generation,
            revision: 1,
        };
        let seed = snapshot.clone();
        store.conn.execute(move |conn| {
            conn.execute("INSERT INTO workspace_revisions VALUES(?1,'go',?2,1)",params![seed.workspace_id.as_str(),seed.generation.get()]).unwrap();
            conn.execute("INSERT INTO workspace_heads VALUES(?1,'go',?2,1)",params![seed.workspace_id.as_str(),seed.generation.get()]).unwrap();
            conn.execute("INSERT INTO workspace_file_versions(workspace_id,lang,generation,rel_path,blob_oid,projection_digest,valid_from) VALUES(?1,'go',?2,'member.go',?3,?4,1)",params![seed.workspace_id.as_str(),seed.generation.get(),"a".repeat(40),"b".repeat(64)]).unwrap();
        });
        let domain = brokk_bifrost_go::package_discovery::GoDiscoveryDomain {
            directory: String::new(),
            gowork_path: String::new(),
            modules: vec![(String::new(), "example.test/root".into())],
        };
        let rows = || {
            vec![PackageRows {
                import_path: "example.test/root".into(),
                name: "root".into(),
                for_test: String::new(),
                directory: std::env::temp_dir(),
                provider_kind: "workspace",
                provider_provenance: "go_tool",
                provider_module_path: Some("example.test/root".into()),
                provider_module_version: None,
                provider: [0; 32],
                gaps: Vec::new(),
                complete: true,
                files: vec![("member.go".into(), "go")],
                imports: Default::default(),
                relative_refusals: Default::default(),
            }]
        };
        let publish =
            |snapshot: WorkspaceSnapshotId, expected: Option<GoContextIdentity>, input, output| {
                let GoContextPublicationOutcome::Published(identity) = store
                    .publish_normalized_go_context(
                        snapshot,
                        [1; 32],
                        [2; 32],
                        domain.clone(),
                        input,
                        expected,
                        rows(),
                        output,
                        true,
                        "[]".into(),
                        &CancellationToken::new(),
                    )
                    .unwrap()
                else {
                    panic!("domain must publish")
                };
                identity
            };
        let first = publish(snapshot.clone(), None, [3; 32], [4; 32]);
        let writes = store.conn.execute(|conn| conn.total_changes());
        assert_eq!(
            publish(snapshot.clone(), Some(first.clone()), [3; 32], [4; 32]),
            first
        );
        assert_eq!(
            store.conn.execute(|conn| conn.total_changes()),
            writes,
            "unchanged root activation writes no publication rows"
        );
        let next = snapshot.clone();
        store.conn.execute(move |conn| {
            conn.execute("INSERT INTO workspace_revisions VALUES(?1,'go',?2,2)",params![next.workspace_id.as_str(),next.generation.get()]).unwrap();
            conn.execute("UPDATE workspace_heads SET revision=2 WHERE workspace_id=?1",[next.workspace_id.as_str()]).unwrap();
            conn.execute("UPDATE workspace_file_versions SET valid_until=2 WHERE workspace_id=?1 AND valid_until IS NULL",[next.workspace_id.as_str()]).unwrap();
            conn.execute("INSERT INTO workspace_file_versions(workspace_id,lang,generation,rel_path,blob_oid,projection_digest,valid_from) VALUES(?1,'go',?2,'member.go',?3,?4,2)",params![next.workspace_id.as_str(),next.generation.get(),"c".repeat(40),"d".repeat(64)]).unwrap();
        });
        let mut next = snapshot.clone();
        next.revision = 2;
        let mut observed = first.clone();
        observed.revision = 2;
        let cutoff = publish(next.clone(), Some(observed.clone()), [5; 32], [4; 32]);
        assert_eq!(
            cutoff.context_id, first.context_id,
            "body-only change keeps placement"
        );
        assert!(
            store
                .selected_go_context(&next, &[1; 32])
                .unwrap()
                .is_some()
        );
        let second = publish(next.clone(), Some(cutoff.clone()), [5; 32], [6; 32]);
        assert_eq!(
            store
                .go_context_head_status(&cutoff, &CancellationToken::new())
                .unwrap(),
            GoContextHeadStatus::Withdrawn
        );
        assert_eq!(
            store
                .go_context_head_status(&first, &CancellationToken::new())
                .unwrap(),
            GoContextHeadStatus::Current,
            "older snapshot retains its interval"
        );
        let third = publish(next.clone(), Some(second.clone()), [5; 32], [7; 32]);
        assert_eq!(
            store
                .go_context_head_status(&second, &CancellationToken::new())
                .unwrap(),
            GoContextHeadStatus::Withdrawn,
            "in-flight request bound before same-revision replacement must report stale"
        );
        assert_eq!(
            store.selected_go_context(&next, &[1; 32]).unwrap().unwrap(),
            third
        );
        let conn = store.read_conn().unwrap();
        let retained: i64 = conn
            .query_row(
                "SELECT count(*) FROM go_package_instances WHERE context_id=?1",
                [second.context_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            retained, 1,
            "superseded packages are retained rather than yielding a valid empty answer"
        );
        let open:i64=conn.query_row("SELECT count(*) FROM go_context_publications WHERE selection_id=?1 AND valid_until IS NULL",[third.selection_id],|row|row.get(0)).unwrap();
        assert_eq!(open, 1);
        drop(conn);
        let removed = next.clone();
        store.conn.execute(move |conn| {
            conn.execute("INSERT INTO workspace_revisions VALUES(?1,'go',?2,3)",params![removed.workspace_id.as_str(),removed.generation.get()]).unwrap();
            conn.execute("UPDATE workspace_heads SET revision=3 WHERE workspace_id=?1",[removed.workspace_id.as_str()]).unwrap();
            conn.execute("UPDATE workspace_file_versions SET valid_until=3 WHERE workspace_id=?1 AND valid_until IS NULL",[removed.workspace_id.as_str()]).unwrap();
        });
        let mut removed = next;
        removed.revision = 3;
        let error = store
            .selected_go_context(&removed, &[1; 32])
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("go_context_member_version_unavailable") && error.contains("member.go"),
            "{error}"
        );
        assert!(
            store
                .go_context_for_reconciliation(&removed, &[1; 32])
                .unwrap()
                .is_some(),
            "writer must repair a missing membership path"
        );
        assert!(
            store
                .selected_go_context(&snapshot, &[1; 32])
                .unwrap()
                .is_some(),
            "older request remains honest and readable"
        );
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5766: Windows Go-tool paths lost ignored membership evidence"
    )]
    fn windows_tool_paths_preserve_selected_and_ignored_memberships() {
        let package = serde_json::from_str(
            r#"{
            "ImportPath":"example.test/pkg", "Name":"pkg", "Dir":"C:\\workspace\\pkg",
            "GoFiles":["plain.go", "C:/workspace/pkg/plain.go", "ignored.go"],
            "CgoFiles":["C:\\workspace\\pkg\\cgo.go"],
            "IgnoredGoFiles":["C:\\workspace\\pkg\\ignored.go"]
        }"#,
        )
        .unwrap();
        let directory = go_tool_source_path(Path::new(r"C:\workspace\pkg"), Path::new(""));
        #[cfg(windows)]
        assert_eq!(
            go_tool_source_path(
                Path::new(r"\\?\C:\workspace\pkg"),
                Path::new(r"C:\workspace\pkg\plain.go")
            ),
            directory.join("plain.go"),
        );
        let rows = go_tool_source_members(&package)
            .into_iter()
            .map(|(path, ignored)| {
                let relative = path.strip_prefix(&directory).unwrap();
                (
                    crate::path_utils::workspace_relative_slash_path(relative),
                    if ignored { "ignored" } else { "go" },
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            rows,
            [
                ("cgo.go".to_owned(), "go"),
                ("ignored.go".to_owned(), "ignored"),
                ("plain.go".to_owned(), "go")
            ]
        );
    }
}
