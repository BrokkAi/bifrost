//! Revision publication shared by source projections and retained configuration.

use git2::Oid;
use rusqlite::{OptionalExtension, Transaction, params};

use crate::analyzer::semantic::source_admission::SourceAdmissionRefusal;
use crate::hash::{HashMap, HashSet};

use super::{GenerationId, Result, StoreError, WorkspaceId, WorkspaceSnapshotId};

/// Exact input bytes retained independently of source extraction or Cargo parsing.
#[derive(Clone)]
#[doc(hidden)]
pub struct WorkspaceConfigurationInput {
    #[doc(hidden)]
    pub relative_path: String,
    content_oid: Oid,
    #[doc(hidden)]
    pub source_bytes: Box<[u8]>,
}

impl WorkspaceConfigurationInput {
    /// Workspace-contained inputs shared by capture and selected-context guards.
    #[doc(hidden)]
    pub fn is_native_input(language: crate::analyzer::Language, path: &std::path::Path) -> bool {
        crate::analyzer::store::store_language_support_for_hook(
            language,
            "is_configuration_input_path",
        )
        .is_some_and(|support| support.is_configuration_input_path(path))
    }

    #[doc(hidden)]
    pub fn include_native_metadata_paths(
        project: &dyn crate::analyzer::Project,
        files: &std::collections::BTreeSet<crate::analyzer::ProjectFile>,
        language: crate::analyzer::Language,
        inputs: &mut std::collections::BTreeSet<crate::analyzer::ProjectFile>,
    ) -> std::io::Result<()> {
        use crate::analyzer::{Language, ProjectFile};
        use std::collections::BTreeSet;
        let root = project.root();
        // Metadata can be readable by path even when ignore rules omit it
        // from enumeration. Membership still belongs to the selected Project.
        if let Some(support) = crate::analyzer::store::store_language_support_for_hook(
            language,
            "include_native_metadata_paths",
        ) {
            support.include_native_metadata_paths(project, files, inputs)?;
        }
        if super::resolution_operation::nominal_rules::jvm_package_rules().admits(language) {
            // The toolchain selector is read explicitly even when .bifrost is
            // excluded from the project's ordinary source listing.
            let toolchains = ProjectFile::new(
                root,
                std::path::PathBuf::from(".bifrost/jvm-toolchains.json"),
            );
            if toolchains.abs_path().try_exists()? {
                inputs.insert(toolchains);
            }
        }
        if language == Language::Rust {
            let directories = metadata_ancestor_directories(inputs.iter().filter(|file| {
                file.rel_path()
                    .file_name()
                    .is_some_and(|name| name == "Cargo.toml")
            }));
            for directory in directories {
                for name in ["Cargo.lock", ".cargo/config.toml", ".cargo/config"] {
                    let file = ProjectFile::new(root, directory.join(name));
                    if file.abs_path().try_exists()? {
                        inputs.insert(file);
                    }
                }
            }
        }
        if matches!(language, Language::JavaScript | Language::TypeScript) {
            let directories = metadata_ancestor_directories(inputs.iter().filter(|file| {
                file.rel_path()
                    .file_name()
                    .is_some_and(|name| name == "package.json")
            }));
            for directory in directories {
                for name in [
                    "package.json",
                    "package-lock.json",
                    "npm-shrinkwrap.json",
                    "pnpm-lock.yaml",
                    "yarn.lock",
                ] {
                    let file = ProjectFile::new(root, directory.join(name));
                    if file.abs_path().try_exists()? {
                        inputs.insert(file);
                    }
                }
            }
        }
        if language == Language::CSharp {
            // MSBuild imports the nearest Directory.Build.props/.targets and
            // Directory.Packages.props above a project whether or not ignore
            // rules list them, and each can change the project's items. Probe
            // them by path so membership records their bytes, or absence.
            let directories = metadata_ancestor_directories(inputs.iter().filter(|file| {
                file.rel_path()
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("csproj"))
            }));
            for directory in directories {
                for name in [
                    "Directory.Build.props",
                    "Directory.Build.targets",
                    "Directory.Packages.props",
                ] {
                    let file = ProjectFile::new(root, directory.join(name));
                    if file.abs_path().try_exists()? {
                        inputs.insert(file);
                    }
                }
            }
        }
        if language == Language::Go {
            // Go reads metadata beside its module/workspace manifests even
            // when ignore rules omit checksums or vendor metadata from listing.
            let mut roots = BTreeSet::from([std::path::PathBuf::new()]);
            for file in inputs.iter() {
                if matches!(
                    file.rel_path().file_name().and_then(|name| name.to_str()),
                    Some("go.mod" | "go.work")
                ) {
                    roots.insert(
                        file.rel_path()
                            .parent()
                            .expect("relative input parent")
                            .to_path_buf(),
                    );
                }
            }
            for relative_root in roots {
                for name in [
                    "go.mod",
                    "go.sum",
                    "go.work",
                    "go.work.sum",
                    "vendor/modules.txt",
                ] {
                    let file = ProjectFile::new(root, relative_root.join(name));
                    if file.abs_path().try_exists()? {
                        inputs.insert(file);
                    }
                }
            }
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn new(relative_path: String, source_bytes: Box<[u8]>) -> Self {
        assert!(!relative_path.is_empty());
        assert!(
            std::path::Path::new(&relative_path)
                .components()
                .all(|component| { matches!(component, std::path::Component::Normal(_)) }),
            "configuration path must be workspace relative"
        );
        Self {
            content_oid: Oid::hash_object(git2::ObjectType::Blob, &source_bytes)
                .expect("hashing configuration input"),
            relative_path,
            source_bytes,
        }
    }

    #[doc(hidden)]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }
    #[doc(hidden)]
    pub fn content_oid(&self) -> Oid {
        self.content_oid
    }
    #[doc(hidden)]
    pub fn source_bytes(&self) -> &[u8] {
        &self.source_bytes
    }

    pub(super) fn row(&self) -> WorkspaceInputRow<'_> {
        WorkspaceInputRow {
            relative_path: &self.relative_path,
            content_oid: self.content_oid(),
            projection_digest: None,
        }
    }

    pub(super) fn retain(&self, tx: &Transaction<'_>) -> Result<()> {
        tx.execute(
            "INSERT OR IGNORE INTO workspace_input_sources(content_oid, source_bytes)
             VALUES(?1, ?2)",
            params![self.content_oid.to_string(), &self.source_bytes],
        )?;
        let equal: bool = tx.query_row(
            "SELECT source_bytes = ?2 FROM workspace_input_sources WHERE content_oid = ?1",
            params![self.content_oid.to_string(), &self.source_bytes],
            |row| row.get(0),
        )?;
        if !equal {
            return Err(StoreError::new(format!(
                "retained configuration bytes conflict for {} at {:?}",
                self.content_oid, self.relative_path,
            )));
        }
        Ok(())
    }
}

/// Ancestors of selected inputs, including the workspace root.
#[doc(hidden)]
pub fn metadata_ancestor_directories<'a>(
    files: impl Iterator<Item = &'a crate::analyzer::ProjectFile>,
) -> std::collections::BTreeSet<std::path::PathBuf> {
    std::iter::once(std::path::PathBuf::new())
        .chain(files.flat_map(|file| {
            file.rel_path()
                .parent()
                .into_iter()
                .flat_map(std::path::Path::ancestors)
                .map(std::path::Path::to_path_buf)
        }))
        .collect()
}

/// Digest of one revision's complete configuration partition. Inputs must be
/// ordered by relative path, the order SQL `ORDER BY rel_path` also yields.
#[doc(hidden)]
pub fn configuration_digest<'a>(
    inputs: impl IntoIterator<Item = (&'a str, Oid)>,
) -> crate::analyzer::semantic::ids::StableDigest {
    let mut digest = crate::analyzer::canonical_hash::CanonicalHasher::new(
        b"bifrost-workspace-configuration:v1",
    );
    let mut previous: Option<&str> = None;
    for (relative_path, content_oid) in inputs {
        debug_assert!(
            previous.is_none_or(|previous| previous < relative_path),
            "configuration inputs ordered by unique path: {previous:?} then {relative_path:?}"
        );
        previous = Some(relative_path);
        digest.field(relative_path, content_oid.as_bytes());
    }
    crate::analyzer::semantic::ids::StableDigest::from_array(digest.finish())
}

pub(super) const SELECTED_CONFIGURATION_BYTES_SQL: &str = "SELECT retained.source_bytes
     FROM workspace_file_versions AS versions
     JOIN workspace_input_sources AS retained ON retained.content_oid = versions.blob_oid
     WHERE versions.workspace_id = ?1 AND versions.lang = ?2
       AND versions.generation = ?3 AND versions.rel_path = ?4
       AND versions.input_kind = 'configuration'
       AND versions.valid_from <= ?5
       AND (versions.valid_until IS NULL OR ?5 < versions.valid_until)";

#[derive(Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum NativeConfigurationOverlayAuthority {
    Current,
    Mismatch(String),
    Cancelled,
}

impl super::AnalyzerStore {
    /// The canonical OwnModule identity already published with this file version.
    pub fn selected_module_name(
        &self,
        snapshot: &WorkspaceSnapshotId,
        relative_path: &str,
    ) -> Result<Option<String>> {
        self.read_conn()?
            .query_row(
                "SELECT anchors.package_name FROM workspace_file_versions versions
             JOIN workspace_file_anchor_rows anchors USING(file_version_id)
             WHERE versions.workspace_id=?1 AND versions.lang=?2
               AND versions.generation=?3 AND versions.rel_path=?4
               AND versions.input_kind='source'
               AND versions.valid_from<=?5
               AND (versions.valid_until IS NULL OR ?5<versions.valid_until)
               AND anchors.anchor_kind='own_module' AND anchors.anchor_pop=0",
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.lang,
                    snapshot.generation.get(),
                    relative_path,
                    snapshot.revision
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Exact configuration bytes, including absence, selected by this revision.
    #[doc(hidden)]
    pub fn selected_configuration_source(
        &self,
        snapshot: &WorkspaceSnapshotId,
        relative_path: &str,
    ) -> Result<Option<Vec<u8>>> {
        self.read_conn()?
            .query_row(
                SELECTED_CONFIGURATION_BYTES_SQL,
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.lang,
                    snapshot.generation.get(),
                    relative_path,
                    snapshot.revision
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Return the first native configuration overlay that cannot use the disk
    /// context selected by this exact workspace revision. Bytes live in SQL;
    /// this check retains only one input for the duration of the request.
    #[doc(hidden)]
    pub fn native_configuration_overlay_mismatch(
        &self,
        project: &dyn crate::analyzer::Project,
        snapshots: &super::WorkspaceSnapshots,
        storage_language: &str,
        language: crate::analyzer::Language,
        cancellation: &crate::CancellationToken,
    ) -> Result<NativeConfigurationOverlayAuthority> {
        if cancellation.is_cancelled() {
            return Ok(NativeConfigurationOverlayAuthority::Cancelled);
        }
        let Some(overlays) = project.overlay_content() else {
            return Ok(NativeConfigurationOverlayAuthority::Current);
        };
        let conn = self.read_conn()?;
        for (file, digest) in overlays.entries() {
            if cancellation.is_cancelled() {
                return Ok(NativeConfigurationOverlayAuthority::Cancelled);
            }
            if !WorkspaceConfigurationInput::is_native_input(language, file.rel_path()) {
                continue;
            }
            let path = crate::path_utils::rel_path_string(file);
            let Some(snapshot) = snapshots.get(storage_language) else {
                return Ok(NativeConfigurationOverlayAuthority::Mismatch(path));
            };
            let bytes: Option<Vec<u8>> = conn
                .query_row(
                    SELECTED_CONFIGURATION_BYTES_SQL,
                    params![
                        snapshot.workspace_id.as_str(),
                        storage_language,
                        snapshot.generation.get(),
                        path,
                        snapshot.revision
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            if cancellation.is_cancelled() {
                return Ok(NativeConfigurationOverlayAuthority::Cancelled);
            }
            if !bytes.is_some_and(|bytes| {
                crate::analyzer::canonical_hash::sha256_bytes(&bytes) == *digest
            }) {
                return Ok(NativeConfigurationOverlayAuthority::Mismatch(path));
            }
        }
        if cancellation.is_cancelled() {
            return Ok(NativeConfigurationOverlayAuthority::Cancelled);
        }
        Ok(NativeConfigurationOverlayAuthority::Current)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum WorkspaceInputKind {
    Source,
    Configuration,
}

impl WorkspaceInputKind {
    fn label(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Configuration => "configuration",
        }
    }
}

pub(super) struct WorkspaceInputRow<'a> {
    pub relative_path: &'a str,
    pub content_oid: Oid,
    pub projection_digest: Option<&'a str>,
}

/// A live source that source admission refused. It has no source row; this
/// row completes the revision's input domain with the refusal evidence, so a
/// reader can tell an explained exclusion from a missing or changed input.
#[derive(Clone, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct WorkspaceSourceRefusalRow {
    #[doc(hidden)]
    pub rel_path: String,
    #[doc(hidden)]
    pub blob_oid: Oid,
    #[doc(hidden)]
    pub reason: SourceAdmissionRefusal,
}

impl WorkspaceSourceRefusalRow {
    /// The `workspace_source_refusals.reason` object.
    fn reason_json(&self) -> serde_json::Value {
        use crate::analyzer::semantic::source_admission::AdmissionDimension;
        use serde_json::json;
        match &self.reason {
            SourceAdmissionRefusal::Binary => json!({"code": "binary"}),
            SourceAdmissionRefusal::ProofRejected => json!({"code": "proof_rejected"}),
            SourceAdmissionRefusal::StructuralLine { limit, observed } => {
                json!({"code": "structural_line", "limit": limit, "observed": observed})
            }
            SourceAdmissionRefusal::Budget {
                dimension,
                limit,
                observed,
            } => {
                let dimension = match dimension {
                    AdmissionDimension::SourceBytes => "source_bytes",
                    AdmissionDimension::Nodes => "nodes",
                    AdmissionDimension::Depth => "depth",
                    AdmissionDimension::SpanBytes => "span_bytes",
                    AdmissionDimension::ExcludedNodes => "excluded_nodes",
                };
                json!({"code": "budget", "dimension": dimension, "limit": limit, "observed": observed})
            }
        }
    }
}

/// Refusal rows one publication closes and opens, applied at the revision
/// that also carries its file-version changes.
#[derive(Default)]
pub(super) struct WorkspaceRefusalChanges<'a> {
    closed_paths: Vec<String>,
    opened: Vec<&'a WorkspaceSourceRefusalRow>,
}

impl<'a> WorkspaceRefusalChanges<'a> {
    fn is_empty(&self) -> bool {
        self.closed_paths.is_empty() && self.opened.is_empty()
    }

    /// Replace every open refusal row of one storage language that the
    /// publisher owns; rows at `foreign_paths` belong to another publisher.
    pub(super) fn replacing(
        tx: &Transaction<'_>,
        workspace_id: &WorkspaceId,
        lang: &str,
        generation: GenerationId,
        rows: &'a [WorkspaceSourceRefusalRow],
        foreign_paths: &HashSet<String>,
    ) -> Result<Self> {
        let mut incoming = HashMap::default();
        for row in rows {
            assert!(
                incoming.insert(row.rel_path.as_str(), row).is_none(),
                "unique refused paths"
            );
            assert!(
                !foreign_paths.contains(&row.rel_path),
                "a publisher does not refuse a path it names as foreign: {}",
                row.rel_path
            );
        }
        let mut changes = Self::default();
        let mut statement = tx.prepare_cached(
            "SELECT rel_path, blob_oid, json(reason) FROM workspace_source_refusals
             WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3 AND valid_until IS NULL",
        )?;
        let mut open = statement.query(params![workspace_id.as_str(), lang, generation.0])?;
        while let Some(row) = open.next()? {
            let path: String = row.get(0)?;
            if foreign_paths.contains(&path) {
                continue;
            }
            let (oid, reason): (String, String) = (row.get(1)?, row.get(2)?);
            let unchanged = incoming
                .get(path.as_str())
                .is_some_and(|new| refusal_matches(new, &oid, &reason));
            if unchanged {
                incoming.remove(path.as_str());
            } else {
                changes.closed_paths.push(path);
            }
        }
        changes.opened.extend(incoming.into_values());
        Ok(changes)
    }

    /// Replace the refusal row, if any, of one path in one storage language.
    pub(super) fn replacing_path(
        tx: &Transaction<'_>,
        workspace_id: &WorkspaceId,
        lang: &str,
        generation: GenerationId,
        rel_path: &str,
        refusal: Option<&'a WorkspaceSourceRefusalRow>,
    ) -> Result<Self> {
        if let Some(refusal) = refusal {
            assert_eq!(
                refusal.rel_path, rel_path,
                "a path replacement refuses that path"
            );
        }
        let open = tx
            .query_row(
                "SELECT blob_oid, json(reason) FROM workspace_source_refusals
                 WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
                   AND rel_path = ?4 AND valid_until IS NULL",
                params![workspace_id.as_str(), lang, generation.0, rel_path],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let unchanged = match (&open, refusal) {
            (None, None) => true,
            (Some((oid, reason)), Some(new)) => refusal_matches(new, oid, reason),
            _ => false,
        };
        let mut changes = Self::default();
        if !unchanged {
            if open.is_some() {
                changes.closed_paths.push(rel_path.to_owned());
            }
            changes.opened.extend(refusal);
        }
        Ok(changes)
    }
}

/// Admission is a function of the bytes and the process's admission policy,
/// which not every language folds into its epoch, so the reason is compared
/// as well as the blob.
fn refusal_matches(new: &WorkspaceSourceRefusalRow, oid: &str, reason: &str) -> bool {
    oid == new.blob_oid.to_string()
        && serde_json::from_str::<serde_json::Value>(reason)
            .expect("the schema checks refusal reasons are JSON")
            == new.reason_json()
}

/// A complete replacement of the rows one publisher owns in one input family;
/// omitted families remain selected.
///
/// Two publishers can share one family of one storage language: the
/// analyzer's ordinary workspace sync owns the files whose own storage
/// language this is, and a content-reading publisher (C++ publishes the C
/// reading of headers under `cpp:c`) owns the other files it mounts there.
/// Each names the paths the other owns in `foreign_paths`, and their open
/// rows are left as they are. Without that, each publisher closed the
/// other's rows and every warm start advanced the revision twice (#3763).
pub(super) struct WorkspaceInputPartition<'a> {
    pub kind: WorkspaceInputKind,
    pub rows: &'a [WorkspaceInputRow<'a>],
    pub foreign_paths: &'a HashSet<String>,
}

pub(super) type PublishedWorkspaceInputChanges = (
    WorkspaceSnapshotId,
    HashMap<(WorkspaceInputKind, String), i64>,
);

/// Publish all supplied input families at one revision and return new row IDs.
/// The caller inserts source projection children before committing the same
/// transaction. Configuration-only changes never replace source rows.
pub(super) fn replace_workspace_input_partitions(
    tx: &Transaction<'_>,
    workspace_id: &WorkspaceId,
    lang: &str,
    generation: GenerationId,
    partitions: &[WorkspaceInputPartition<'_>],
    refusals: &WorkspaceRefusalChanges<'_>,
) -> Result<PublishedWorkspaceInputChanges> {
    super::require_current_generation(tx, lang, generation)?;
    let head = tx
        .query_row(
            "SELECT revision FROM workspace_heads
             WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3",
            params![workspace_id.as_str(), lang, generation.0],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let mut closed_ids = Vec::new();
    let mut replacements = Vec::new();
    let mut kinds = crate::hash::HashSet::default();
    for partition in partitions {
        assert!(
            kinds.insert(partition.kind),
            "one replacement per input family"
        );
        let mut incoming = HashMap::default();
        for row in partition.rows {
            assert_eq!(
                row.projection_digest.is_some(),
                partition.kind == WorkspaceInputKind::Source,
                "only source inputs own projection digests"
            );
            assert!(
                incoming.insert(row.relative_path, row).is_none(),
                "unique input paths"
            );
            assert!(
                !partition.foreign_paths.contains(row.relative_path),
                "a publisher does not supply a row it names as foreign: {}",
                row.relative_path
            );
        }
        let mut statement = tx.prepare_cached(
            "SELECT file_version_id, rel_path, blob_oid, projection_digest
             FROM workspace_file_versions
             WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
               AND input_kind = ?4 AND valid_until IS NULL",
        )?;
        let rows = statement.query_map(
            params![
                workspace_id.as_str(),
                lang,
                generation.0,
                partition.kind.label()
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )?;
        for row in rows {
            let (id, path, oid, digest) = row?;
            if partition.foreign_paths.contains(&path) {
                continue;
            }
            let old_oid = Oid::from_str(&oid)?;
            let unchanged = incoming.get(path.as_str()).is_some_and(|new| {
                new.content_oid == old_oid && new.projection_digest == digest.as_deref()
            });
            if unchanged {
                incoming.remove(path.as_str());
            } else {
                closed_ids.push(id);
            }
        }
        replacements.extend(incoming.into_values().map(|row| (partition.kind, row)));
    }
    publish_workspace_input_changes(
        tx,
        workspace_id,
        lang,
        generation,
        head,
        &closed_ids,
        &replacements,
        refusals,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn publish_workspace_input_changes(
    tx: &Transaction<'_>,
    workspace_id: &WorkspaceId,
    lang: &str,
    generation: GenerationId,
    head: Option<i64>,
    closed_ids: &[i64],
    replacements: &[(WorkspaceInputKind, &WorkspaceInputRow<'_>)],
    refusals: &WorkspaceRefusalChanges<'_>,
) -> Result<PublishedWorkspaceInputChanges> {
    let mut inserted = HashMap::default();
    let revision = match head {
        Some(revision)
            if closed_ids.is_empty() && replacements.is_empty() && refusals.is_empty() =>
        {
            revision
        }
        _ => {
            let revision = head
                .unwrap_or(0)
                .checked_add(1)
                .expect("workspace revision fits i64");
            tx.execute(
                "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
             VALUES(?1, ?2, ?3, ?4)",
                params![workspace_id.as_str(), lang, generation.0, revision],
            )?;
            {
                let mut close = tx.prepare_cached(
                    "UPDATE workspace_file_versions SET valid_until = ?2
                 WHERE file_version_id = ?1 AND valid_until IS NULL",
                )?;
                for id in closed_ids {
                    assert_eq!(
                        close.execute(params![id, revision])?,
                        1,
                        "one open input version"
                    );
                }
            }
            {
                let mut insert = tx.prepare_cached(
                    "INSERT INTO workspace_file_versions(
                   workspace_id, lang, generation, input_kind, rel_path, blob_oid,
                   projection_digest, valid_from
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                )?;
                for (kind, row) in replacements {
                    insert.execute(params![
                        workspace_id.as_str(),
                        lang,
                        generation.0,
                        kind.label(),
                        row.relative_path,
                        row.content_oid.to_string(),
                        row.projection_digest,
                        revision,
                    ])?;
                    inserted.insert(
                        (*kind, row.relative_path.to_owned()),
                        tx.last_insert_rowid(),
                    );
                }
            }
            {
                let mut close = tx.prepare_cached(
                    "UPDATE workspace_source_refusals SET valid_until = ?5
                     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
                       AND rel_path = ?4 AND valid_until IS NULL",
                )?;
                for path in &refusals.closed_paths {
                    assert_eq!(
                        close.execute(params![
                            workspace_id.as_str(),
                            lang,
                            generation.0,
                            path,
                            revision
                        ])?,
                        1,
                        "one open refusal for {path}"
                    );
                }
                let mut insert = tx.prepare_cached(
                    "INSERT INTO workspace_source_refusals(
                       workspace_id, lang, generation, rel_path, blob_oid, reason, valid_from
                     ) VALUES(?1, ?2, ?3, ?4, ?5, jsonb(?6), ?7)",
                )?;
                for row in &refusals.opened {
                    insert.execute(params![
                        workspace_id.as_str(),
                        lang,
                        generation.0,
                        row.rel_path,
                        row.blob_oid.to_string(),
                        row.reason_json().to_string(),
                        revision,
                    ])?;
                }
            }
            tx.execute(
                "INSERT INTO workspace_heads(workspace_id, lang, generation, revision)
             VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(workspace_id, lang, generation)
             DO UPDATE SET revision = excluded.revision",
                params![workspace_id.as_str(), lang, generation.0, revision],
            )?;
            revision
        }
    };
    let snapshot = WorkspaceSnapshotId {
        workspace_id: workspace_id.clone(),
        lang: lang.to_owned(),
        generation,
        revision,
    };
    super::dependency_file_evidence::publish(tx, &snapshot)?;
    super::csharp_compilation::publish(tx, &snapshot)?;
    Ok((snapshot, inserted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::store::AnalyzerStore;

    #[test]
    fn selected_configuration_bytes_use_indexed_revision_path_lookup() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("java", "configuration-pin")
            .unwrap();
        let workspace = WorkspaceId("a".repeat(64));
        let inputs = (0..96)
            .map(|index| {
                WorkspaceConfigurationInput::new(
                    if index == 0 {
                        "gradle.properties".into()
                    } else {
                        format!("module{index}/gradle.properties")
                    },
                    format!("value={index}\n").into_bytes().into_boxed_slice(),
                )
            })
            .collect::<Vec<_>>();
        store
            .sync_workspace_inputs_for_workspace(
                &workspace,
                "java",
                generation,
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &inputs,
                &[],
                &[],
            )
            .unwrap();
        let conn = store.conn.lock().unwrap();
        let mut query =
            super::super::planner_statistics::pinned_plans::pinned("selected_configuration_bytes");
        query.params[2] = rusqlite::types::Value::Integer(generation.get());
        for state in brokk_bifrost_core::cache_gc::PlannerStatisticsState::BOTH {
            state.install(&conn);
            let plan = super::super::planner_statistics::pinned_plans::explain_pin(&conn, &query);
            assert!(
                plan.iter().any(
                    |line| line.contains("idx_workspace_file_versions_snapshot_kind")
                        || line.contains("idx_workspace_file_versions_snapshot_path")
                ),
                "{state:?}: {plan:?}"
            );
            assert!(
                !plan.iter().any(|line| line.contains("SCAN versions")
                    || line.contains("SCAN retained")
                    || line.contains("AUTOMATIC")
                    || line.contains("TEMP B-TREE")),
                "{state:?}: {plan:?}"
            );
        }
    }
}
