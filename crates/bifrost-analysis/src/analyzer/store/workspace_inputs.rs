//! Revision publication shared by source projections and retained configuration.

use git2::Oid;
use rusqlite::{OptionalExtension, Transaction, params};

use crate::hash::{HashMap, HashSet};

use super::{GenerationId, Result, StoreError, WorkspaceId, WorkspaceSnapshotId};

/// Exact input bytes retained independently of source extraction or Cargo parsing.
#[derive(Clone)]
pub(crate) struct WorkspaceConfigurationInput {
    relative_path: String,
    content_oid: Oid,
    source_bytes: Box<[u8]>,
}

impl WorkspaceConfigurationInput {
    /// Workspace-contained inputs shared by capture and selected-context guards.
    pub(crate) fn is_native_input(
        language: crate::analyzer::Language,
        path: &std::path::Path,
    ) -> bool {
        crate::analyzer::languages::language_support(language)
            .is_some_and(|support| support.is_configuration_input_path(path))
    }

    pub(crate) fn include_native_metadata_paths(
        root: &std::path::Path,
        language: crate::analyzer::Language,
        inputs: &mut std::collections::BTreeSet<crate::analyzer::ProjectFile>,
    ) -> std::io::Result<()> {
        use crate::analyzer::{Language, ProjectFile};
        use std::collections::BTreeSet;
        if matches!(
            language,
            Language::Java | Language::Kotlin | Language::Scala
        ) {
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

    pub(crate) fn new(relative_path: String, source_bytes: Box<[u8]>) -> Self {
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

    pub(crate) fn relative_path(&self) -> &str {
        &self.relative_path
    }
    pub(crate) fn content_oid(&self) -> Oid {
        self.content_oid
    }
    pub(crate) fn source_bytes(&self) -> &[u8] {
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

/// Digest of one revision's complete configuration partition. Inputs must be
/// ordered by relative path, the order SQL `ORDER BY rel_path` also yields.
pub(crate) fn configuration_digest<'a>(
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
pub(crate) enum NativeConfigurationOverlayAuthority {
    Current,
    Mismatch(String),
    Cancelled,
}

impl super::AnalyzerStore {
    /// Return the first native configuration overlay that cannot use the disk
    /// context selected by this exact workspace revision. Bytes live in SQL;
    /// this check retains only one input for the duration of the request.
    pub(crate) fn native_configuration_overlay_mismatch(
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
    )
}

pub(super) fn publish_workspace_input_changes(
    tx: &Transaction<'_>,
    workspace_id: &WorkspaceId,
    lang: &str,
    generation: GenerationId,
    head: Option<i64>,
    closed_ids: &[i64],
    replacements: &[(WorkspaceInputKind, &WorkspaceInputRow<'_>)],
) -> Result<PublishedWorkspaceInputChanges> {
    let mut inserted = HashMap::default();
    let revision = match head {
        Some(revision) if closed_ids.is_empty() && replacements.is_empty() => revision,
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
    Ok((
        WorkspaceSnapshotId {
            workspace_id: workspace_id.clone(),
            lang: lang.to_owned(),
            generation,
            revision,
        },
        inserted,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::store::{AnalyzerStore, WorkspaceFileRow};

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

    #[test]
    fn configuration_and_source_publish_atomically_without_replacing_unchanged_source() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("rust", "shared-input-test")
            .unwrap();
        let workspace = WorkspaceId("a".repeat(64));
        let other_workspace = WorkspaceId("b".repeat(64));
        let source = WorkspaceFileRow {
            rel_path: "src/lib.rs".into(),
            blob_oid: Oid::hash_object(git2::ObjectType::Blob, b"pub fn run() {}").unwrap(),
        };
        let a = WorkspaceConfigurationInput::new(
            "Cargo.toml".into(),
            b"[package]\r\nname = \"a\"\r\n".as_slice().into(),
        );
        let b = WorkspaceConfigurationInput::new(
            "Cargo.toml".into(),
            b"[package]\nname = \"b\"\n".as_slice().into(),
        );
        let publish = |workspace: &WorkspaceId, configuration: &WorkspaceConfigurationInput| {
            store
                .sync_workspace_inputs_for_workspace(
                    workspace,
                    "rust",
                    generation,
                    std::slice::from_ref(&source),
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    std::slice::from_ref(configuration),
                    &[],
                )
                .unwrap()
        };
        let first = publish(&workspace, &a);
        let source_versions = || {
            let conn = store.conn.lock().expect("store mutex");
            conn.prepare(
                "SELECT file_version_id, blob_oid, projection_digest, valid_from, valid_until
                 FROM workspace_file_versions
                 WHERE workspace_id = ?1 AND lang = 'rust' AND generation = ?2
                   AND input_kind = 'source' AND rel_path = 'src/lib.rs'
                 ORDER BY file_version_id",
            )
            .unwrap()
            .query_map(params![workspace.as_str(), generation.0], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            })
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
        };
        let initial_source = source_versions();
        assert_eq!(initial_source.len(), 1);
        assert_eq!(initial_source[0].1, source.blob_oid.to_string());
        assert_eq!(initial_source[0].3, first.revision);
        assert_eq!(initial_source[0].4, None);
        assert_eq!(
            first.revision, 1,
            "source and configuration share initial revision"
        );
        assert_eq!(publish(&workspace, &a), first);
        assert_eq!(source_versions(), initial_source);
        let second = publish(&workspace, &b);
        assert_eq!(second.revision, 2);
        assert_eq!(source_versions(), initial_source);
        let third = publish(&workspace, &a);
        assert_eq!(third.revision, 3);
        assert_eq!(source_versions(), initial_source);
        let independent = publish(&other_workspace, &b);
        assert_eq!(independent.revision, 1);
        let fourth = store
            .replace_path_symbol_unit(
                &workspace,
                &HashMap::from_iter([("rust".to_owned(), third.clone())]),
                &["rust".to_owned()],
                &HashMap::from_iter([("rust".to_owned(), generation)]),
                "src/other.rs",
                Some(("rust", source.blob_oid)),
                None,
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap()
            .remove("rust")
            .unwrap();
        assert_eq!(fourth.revision, 4);
        assert_eq!(source_versions(), initial_source);
        let conn = store.conn.lock().expect("store mutex");
        for (snapshot, configuration) in [
            (&first, &a),
            (&second, &b),
            (&third, &a),
            (&independent, &b),
            (&fourth, &a),
        ] {
            store
                .select_writer_workspace_snapshots(
                    &conn,
                    &HashMap::from_iter([("rust".to_owned(), snapshot.clone())]),
                )
                .unwrap();
            let paths = conn
                .prepare("SELECT rel_path FROM workspace_files ORDER BY rel_path")
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            let expected = if snapshot == &fourth {
                vec!["src/lib.rs", "src/other.rs"]
            } else {
                vec!["src/lib.rs"]
            };
            assert_eq!(paths, expected, "configuration is not a source mount");
            let bytes: Vec<u8> = conn.query_row(
                "SELECT retained.source_bytes FROM workspace_file_versions AS versions
                 JOIN workspace_input_sources AS retained ON retained.content_oid = versions.blob_oid
                 WHERE versions.workspace_id = ?1 AND versions.input_kind = 'configuration'
                   AND versions.valid_from <= ?2
                   AND (versions.valid_until IS NULL OR ?2 < versions.valid_until)",
                params![snapshot.workspace_id.as_str(), snapshot.revision], |row| row.get(0),
            ).unwrap();
            assert_eq!(bytes, configuration.source_bytes());
        }
    }
}
