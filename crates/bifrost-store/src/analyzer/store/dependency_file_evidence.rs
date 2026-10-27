//! Bounded static evidence derived once per selected configuration content.
//! Only SQL rows survive publication; a read never discovers dependency files.
use super::{AnalyzerStore, Result, WorkspaceSnapshotId, WorkspaceSnapshots};
use crate::analyzer::canonical_hash::{CanonicalHasher, lower_hex_string};
use crate::analyzer::semantic_model::{
    DependencyCondition, DependencyEvidence, DependencyEvidenceGap, DependencyEvidenceGapKind,
    DependencyEvidenceKind, DependencyFileEvidence, DependencyFileEvidenceLimits,
};
use crate::analyzer::topology::DependencyScope;
use crate::analyzer::{Project, ProjectFile, ProjectSourceSnapshot};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use std::path::PathBuf;
use std::sync::Arc;

const PRODUCER: &[u8] = b"bifrost.static-dependency-evidence.v3";
pub(super) const READ_ROWS_SQL: &str = "SELECT ecosystem,package,kind,version_requirement,exact_version,source,locator,declared_by,scope,conditions,build_file,source_digest,start_byte,end_byte,complete FROM dependency_file_evidence WHERE set_id = ?1 ORDER BY id";

fn supports_language(language: &str) -> bool {
    matches!(language, "rust" | "javascript" | "typescript:ts")
}

fn prepare_selected(
    language: &str,
    root: &std::path::Path,
    selected: &[(ProjectFile, ProjectSourceSnapshot)],
    limits: &DependencyFileEvidenceLimits,
) -> DependencyFileEvidence {
    let language = match language {
        "rust" => crate::analyzer::Language::Rust,
        "javascript" => crate::analyzer::Language::JavaScript,
        "typescript:ts" => crate::analyzer::Language::TypeScript,
        _ => unreachable!("unsupported dependency evidence language: {language}"),
    };
    crate::analyzer::store::store_language_support_for_hook(
        language,
        "selected_dependency_file_evidence",
    )
    .expect("selected dependency evidence language has a support")
    .selected_dependency_file_evidence(root, selected, limits)
}

#[doc(hidden)]
pub fn publish(tx: &Transaction<'_>, snapshot: &WorkspaceSnapshotId) -> Result<()> {
    if !supports_language(&snapshot.lang) {
        return Ok(());
    }
    let limits = DependencyFileEvidenceLimits::default();
    let mut hash = CanonicalHasher::new(PRODUCER);
    // The indexed, ordered metadata cursor has constant memory even when the
    // workspace exceeds the acquisition cap. Include omitted identities in the
    // digest so a relevant edit cannot reuse a stale limit result.
    let mut metadata = tx.prepare_cached("SELECT rel_path,blob_oid FROM workspace_file_versions WHERE workspace_id=?1 AND lang=?2 AND generation=?3 AND input_kind='configuration' AND valid_from<=?4 AND (valid_until IS NULL OR valid_until>?4) ORDER BY rel_path")?;
    let mut cursor = metadata.query(params![
        snapshot.workspace_id.as_str(),
        snapshot.lang,
        snapshot.generation.0,
        snapshot.revision
    ])?;
    while let Some(row) = cursor.next()? {
        hash.field("path", row.get::<_, String>(0)?.as_bytes());
        hash.field("oid", row.get::<_, String>(1)?.as_bytes());
    }
    let digest = lower_hex_string(&hash.finish());
    let existing = tx.query_row("SELECT set_id FROM dependency_evidence_sets WHERE workspace_id=?1 AND lang=?2 AND generation=?3 AND input_digest=?4", params![snapshot.workspace_id.as_str(),snapshot.lang,snapshot.generation.0,digest], |r| r.get::<_,i64>(0)).optional()?;
    let set_id = if let Some(id) = existing {
        id
    } else {
        // This is only a lexical anchor for the existing selected-file reader.
        // All paths, source identities and ownership are workspace relative;
        // no file under this synthetic absolute root is opened.
        let root = std::env::temp_dir().join("bifrost-selected-dependency-inputs");
        let (selected, gaps) =
            selected_inputs(tx, snapshot, &root, &limits, std::iter::empty(), |_, _| {
                unreachable!("disk publication has no overlay inputs")
            })?;
        let mut evidence = prepare_selected(&snapshot.lang, &root, &selected, &limits);
        evidence.gaps.extend(gaps);
        insert_set(tx, snapshot, &digest, &evidence, &selected)?
    };
    tx.execute("INSERT INTO dependency_evidence_selections VALUES(?1,?2,?3,?4,?5) ON CONFLICT(workspace_id,lang,generation,revision) DO UPDATE SET set_id=excluded.set_id", params![snapshot.workspace_id.as_str(),snapshot.lang,snapshot.generation.0,snapshot.revision,set_id])?;
    Ok(())
}

type SelectedInputs = (
    Vec<(ProjectFile, ProjectSourceSnapshot)>,
    Vec<DependencyEvidenceGap>,
);

fn selected_inputs<'a>(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    root: &std::path::Path,
    limits: &DependencyFileEvidenceLimits,
    overlays: impl Iterator<Item = (&'a ProjectFile, &'a [u8; 32])>,
    mut read_overlay: impl FnMut(&ProjectFile, usize) -> Result<Option<ProjectSourceSnapshot>>,
) -> Result<SelectedInputs> {
    let mut selected = Vec::new();
    let mut gaps = Vec::new();
    let mut bytes = 0_usize;
    let mut statement = conn.prepare_cached("SELECT versions.rel_path, length(retained.source_bytes), substr(retained.source_bytes,1,?5) FROM workspace_file_versions AS versions JOIN workspace_input_sources AS retained ON retained.content_oid=versions.blob_oid WHERE versions.workspace_id=?1 AND versions.lang=?2 AND versions.generation=?3 AND versions.input_kind='configuration' AND versions.valid_from<=?4 AND (versions.valid_until IS NULL OR versions.valid_until>?4) ORDER BY versions.rel_path LIMIT ?6")?;
    let mut rows = statement.query(params![
        snapshot.workspace_id.as_str(),
        snapshot.lang,
        snapshot.generation.0,
        snapshot.revision,
        limits.max_file_bytes,
        limits.max_files.saturating_add(1)
    ])?;
    // Merge the ordered overlay identities into the SQL cursor before applying
    // limits. Replaced disk bytes must neither exhaust the budget nor prevent
    // later inputs from being considered. Only capped sources survive this call.
    let mut overlays = overlays.peekable();
    let mut disk = rows.next()?;
    while disk.is_some() || overlays.peek().is_some() {
        let disk_path = disk.map(|row| row.get::<_, String>(0)).transpose()?;
        let overlay_path = overlays
            .peek()
            .map(|(file, _)| brokk_bifrost_core::path_utils::rel_path_string(file));
        let take_overlay = overlay_path
            .as_ref()
            .is_some_and(|path| disk_path.as_ref().is_none_or(|disk| path <= disk));
        let advance_disk = !take_overlay || disk_path == overlay_path;
        let path = PathBuf::from(if take_overlay {
            overlay_path.unwrap()
        } else {
            disk_path.unwrap()
        });
        if selected.len() >= limits.max_files {
            gaps.push(DependencyEvidenceGap {
                kind: DependencyEvidenceGapKind::Limit,
                build_file: path,
                byte_range: 0..0,
                message: "dependency input file cap exceeded".into(),
            });
            break;
        }
        let mut overlay_source = None;
        let mut overlay_digest = None;
        let length = if take_overlay {
            let (file, digest) = overlays.next().expect("selected overlay input");
            overlay_digest = Some(digest);
            let Some(source) = read_overlay(
                file,
                limits
                    .max_file_bytes
                    .min(limits.max_total_bytes.saturating_sub(bytes)),
            )?
            else {
                gaps.push(DependencyEvidenceGap {
                    kind: DependencyEvidenceGapKind::Limit,
                    build_file: path,
                    byte_range: 0..0,
                    message: "dependency overlay byte cap exceeded".into(),
                });
                break;
            };
            let length = source.source().len();
            overlay_source = Some(source);
            length
        } else {
            disk.expect("selected disk input").get::<_, usize>(1)?
        };
        let gap = if length > limits.max_file_bytes {
            Some("dependency input file byte cap exceeded")
        } else if bytes.saturating_add(length) > limits.max_total_bytes {
            Some("dependency input total byte cap exceeded")
        } else {
            None
        };
        if let Some(message) = gap {
            gaps.push(DependencyEvidenceGap {
                kind: DependencyEvidenceGapKind::Limit,
                build_file: path,
                byte_range: 0..0,
                message: message.into(),
            });
            break;
        }
        bytes += length;
        let source = if let Some(source) = overlay_source {
            Ok(source)
        } else {
            ProjectSourceSnapshot::disk_bytes(
                disk.expect("selected disk input").get::<_, Vec<u8>>(2)?,
            )
        };
        match source {
            Ok(source)
                if overlay_digest.is_some_and(|digest| {
                    &crate::analyzer::canonical_hash::sha256_bytes(source.source().as_bytes())
                        != digest
                }) =>
            {
                gaps.push(DependencyEvidenceGap {
                    kind: DependencyEvidenceGapKind::Conflict,
                    build_file: path,
                    byte_range: 0..0,
                    message: "dependency overlay changed during admission".into(),
                })
            }
            Ok(source) => selected.push((ProjectFile::new(root, path), source)),
            Err(error) => gaps.push(DependencyEvidenceGap {
                kind: DependencyEvidenceGapKind::Malformed,
                build_file: path,
                byte_range: 0..0,
                message: format!("dependency input decoding failed: {error}"),
            }),
        }
        if advance_disk {
            disk = rows.next()?;
        }
    }
    Ok((selected, gaps))
}

fn insert_set(
    tx: &Transaction<'_>,
    snapshot: &WorkspaceSnapshotId,
    digest: &str,
    evidence: &DependencyFileEvidence,
    selected: &[(ProjectFile, ProjectSourceSnapshot)],
) -> Result<i64> {
    tx.execute("INSERT INTO dependency_evidence_sets(workspace_id,lang,generation,input_digest) VALUES(?1,?2,?3,?4)", params![snapshot.workspace_id.as_str(),snapshot.lang,snapshot.generation.0,digest])?;
    let id = tx.last_insert_rowid();
    let mut insert = tx.prepare_cached("INSERT INTO dependency_file_evidence VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)")?;
    for row in &evidence.rows {
        let conditions = serde_json::to_string(
            &row.conditions
                .iter()
                .map(|c| (&c.kind, &c.value))
                .collect::<Vec<_>>(),
        )
        .expect("string pairs serialize");
        insert.execute(params![
            id,
            row.id(),
            row.ecosystem,
            row.package,
            row.kind.label(),
            row.version_requirement,
            row.exact_version,
            row.source,
            row.locator,
            row.declared_by,
            row.scope.label(),
            conditions,
            row.build_file.to_string_lossy(),
            row.source_digest,
            row.byte_range.start,
            row.byte_range.end,
            row.complete
        ])?;
    }
    let mut insert_location =
        tx.prepare_cached("INSERT INTO dependency_file_locations VALUES(?1,?2,?3,?4,?5,?6,?7)")?;
    // This bounded map exists only during publication, not across queries.
    let sources = selected
        .iter()
        .map(|(file, source)| {
            (
                file.rel_path(),
                (
                    source,
                    brokk_bifrost_core::text_utils::compute_line_starts(source.source()),
                ),
            )
        })
        .collect::<std::collections::HashMap<_, _>>();
    for row in &evidence.rows {
        let (source, starts) = sources
            .get(row.build_file.as_path())
            .ok_or_else(|| super::StoreError::new("dependency evidence has no selected source"))?;
        if source.oid().to_string() != row.source_digest {
            return Err(super::StoreError::new(
                "dependency evidence source identity mismatch",
            ));
        }
        let slice = source.source().get(row.byte_range.clone()).ok_or_else(|| {
            super::StoreError::new("dependency evidence span is outside selected source")
        })?;
        let (sl, sc) = brokk_bifrost_core::text_utils::line_column_for_offset(
            source.source(),
            starts,
            row.byte_range.start,
        );
        let (el, ec) = brokk_bifrost_core::text_utils::line_column_for_offset(
            source.source(),
            starts,
            row.byte_range.end,
        );
        let hash = crate::analyzer::canonical_hash::sha256_bytes(slice.as_bytes());
        insert_location.execute(params![id, row.id(), sl, sc, el, ec, hash.as_slice()])?;
    }
    let mut insert_gap =
        tx.prepare_cached("INSERT INTO dependency_file_gaps VALUES(?1,?2,?3,?4,?5,?6,?7)")?;
    for (index, gap) in evidence.gaps.iter().enumerate() {
        insert_gap.execute(params![
            id,
            index,
            gap_label(gap.kind),
            gap.build_file.to_string_lossy(),
            gap.byte_range.start,
            gap.byte_range.end,
            gap.message
        ])?;
    }
    Ok(id)
}

fn read_set(conn: &Connection, set: i64) -> Result<DependencyFileEvidence> {
    let mut result = DependencyFileEvidence::default();
    let mut statement = conn.prepare_cached(READ_ROWS_SQL)?;
    let rows = statement.query_map([set], |r| {
        let conditions: String = r.get(9)?;
        let conditions: Vec<(String, String)> = serde_json::from_str(&conditions).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, Box::new(e))
        })?;
        Ok(DependencyEvidence {
            ecosystem: r.get(0)?,
            package: r.get(1)?,
            kind: evidence_kind(&r.get::<_, String>(2)?)?,
            version_requirement: r.get(3)?,
            exact_version: r.get(4)?,
            source: r.get(5)?,
            locator: r.get(6)?,
            declared_by: r.get(7)?,
            scope: scope(&r.get::<_, String>(8)?)?,
            conditions: conditions
                .into_iter()
                .map(|(kind, value)| DependencyCondition { kind, value })
                .collect(),
            build_file: PathBuf::from(r.get::<_, String>(10)?),
            source_digest: r.get(11)?,
            byte_range: r.get(12)?..r.get(13)?,
            complete: r.get(14)?,
        })
    })?;
    result
        .rows
        .extend(rows.collect::<std::result::Result<Vec<_>, _>>()?);
    let mut statement = conn.prepare_cached("SELECT kind,build_file,start_byte,end_byte,message FROM dependency_file_gaps WHERE set_id=?1 ORDER BY ordinal")?;
    result.gaps.extend(
        statement
            .query_map([set], |r| {
                Ok(DependencyEvidenceGap {
                    kind: gap_kind(&r.get::<_, String>(0)?)?,
                    build_file: PathBuf::from(r.get::<_, String>(1)?),
                    byte_range: r.get(2)?..r.get(3)?,
                    message: r.get(4)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?,
    );
    Ok(result)
}

/// An overlay analysis owns only a scalar SQL publication lease. Its facts do
/// not replace the disk-native configuration authority or another request.
#[doc(hidden)]
pub struct ScopedDependencyEvidence {
    store: Arc<AnalyzerStore>,
    set_id: i64,
}
impl ScopedDependencyEvidence {
    #[doc(hidden)]
    pub fn locations(
        &self,
    ) -> Result<
        Vec<(
            String,
            crate::analyzer::semantic_model::DependencyEvidenceLocation,
        )>,
    > {
        let conn = self.store.read_conn()?;
        read_locations(&conn, self.set_id)
    }
    #[doc(hidden)]
    pub fn read(&self) -> Result<DependencyFileEvidence> {
        let conn = self.store.read_conn()?;
        read_set(&conn, self.set_id)
    }
}
impl Drop for ScopedDependencyEvidence {
    fn drop(&mut self) {
        let id = self.set_id;
        if let Err(error) = self.store.conn.execute(move |conn| -> Result<()> {
            conn.execute("DELETE FROM dependency_evidence_sets WHERE set_id=?1", [id])?;
            Ok(())
        }) {
            eprintln!("reclaiming scoped dependency evidence {id} failed: {error}");
        }
    }
}

/// Called during analyzer admission/update, never during seed execution.
#[doc(hidden)]
pub fn publish_overlay(
    store: &Arc<AnalyzerStore>,
    snapshots: &WorkspaceSnapshots,
    project: &dyn Project,
    language: crate::analyzer::Language,
) -> Result<Option<Arc<ScopedDependencyEvidence>>> {
    let Some(overlay) = project.overlay_content() else {
        return Ok(None);
    };
    let entries = overlay.entries();
    if !entries.iter().any(|(file, _)| {
        super::WorkspaceConfigurationInput::is_native_input(language, file.rel_path())
    }) {
        return Ok(None);
    }
    let key = match language {
        crate::analyzer::Language::Rust => "rust",
        crate::analyzer::Language::JavaScript => "javascript",
        crate::analyzer::Language::TypeScript => "typescript:ts",
        _ => return Ok(None),
    };
    let snapshot = snapshots.get(key).ok_or_else(|| {
        super::StoreError::new("dependency overlay has no selected input revision")
    })?;
    let limits = DependencyFileEvidenceLimits::default();
    let (selected, gaps) = {
        let conn = store.read_conn_for_workspace(snapshots)?;
        selected_inputs(
            &conn,
            snapshot,
            project.root(),
            &limits,
            entries
                .iter()
                .filter(|(file, _)| {
                    super::WorkspaceConfigurationInput::is_native_input(language, file.rel_path())
                })
                .map(|(file, digest)| (file, digest)),
            |file, limit| {
                project
                    .read_source_snapshot_limited(file, limit)
                    .map_err(|error| {
                        super::StoreError::new(format!(
                            "reading selected dependency overlay {file}: {error}"
                        ))
                    })
            },
        )?
    };
    let mut evidence = prepare_selected(&snapshot.lang, project.root(), &selected, &limits);
    evidence.gaps.extend(gaps);
    // A private set has one Arc lease. UUID ownership prevents a drop from
    // deleting an identical publication still owned by another analyzer.
    let digest = format!("overlay:{}", uuid::Uuid::new_v4());
    let snapshot = snapshot.clone();
    let set_id = store.conn.execute(move |conn| -> Result<i64> {
        let tx = conn.transaction()?;
        let id = insert_set(&tx, &snapshot, &digest, &evidence, &selected)?;
        tx.commit()?;
        Ok(id)
    })?;
    Ok(Some(Arc::new(ScopedDependencyEvidence {
        store: Arc::clone(store),
        set_id,
    })))
}

fn read_locations(
    conn: &Connection,
    set: i64,
) -> Result<
    Vec<(
        String,
        crate::analyzer::semantic_model::DependencyEvidenceLocation,
    )>,
> {
    let mut statement = conn.prepare_cached("SELECT id,start_line,start_column,end_line,end_column,slice_sha256 FROM dependency_file_locations WHERE set_id=?1 ORDER BY id")?;
    Ok(statement
        .query_map([set], |r| {
            Ok((
                r.get(0)?,
                crate::analyzer::semantic_model::DependencyEvidenceLocation {
                    start_line: r.get(1)?,
                    start_column: r.get(2)?,
                    end_line: r.get(3)?,
                    end_column: r.get(4)?,
                    slice_sha256: r.get(5)?,
                },
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?)
}
impl AnalyzerStore {
    #[doc(hidden)]
    pub fn dependency_file_locations(
        &self,
        snapshots: &WorkspaceSnapshots,
    ) -> Result<
        Vec<(
            String,
            crate::analyzer::semantic_model::DependencyEvidenceLocation,
        )>,
    > {
        let conn = self.read_conn_for_workspace(snapshots)?;
        let mut result = Vec::new();
        for snapshot in snapshots.values().filter(|s| supports_language(&s.lang)) {
            let set = conn.query_row("SELECT set_id FROM dependency_evidence_selections WHERE workspace_id=?1 AND lang=?2 AND generation=?3 AND revision=?4", params![snapshot.workspace_id.as_str(),snapshot.lang,snapshot.generation.0,snapshot.revision], |r|r.get::<_,i64>(0)).optional()?;
            if let Some(set) = set {
                result.extend(read_locations(&conn, set)?);
            }
        }
        Ok(result)
    }
    #[doc(hidden)]
    pub fn dependency_file_evidence(
        &self,
        snapshots: &WorkspaceSnapshots,
    ) -> Result<DependencyFileEvidence> {
        let conn = self.read_conn_for_workspace(snapshots)?;
        let mut result = DependencyFileEvidence::default();
        for snapshot in snapshots.values().filter(|s| supports_language(&s.lang)) {
            let set = conn.query_row("SELECT set_id FROM dependency_evidence_selections WHERE workspace_id=?1 AND lang=?2 AND generation=?3 AND revision=?4", params![snapshot.workspace_id.as_str(),snapshot.lang,snapshot.generation.0,snapshot.revision], |r|r.get::<_,i64>(0)).optional()?;
            let Some(set) = set else {
                result.gaps.push(DependencyEvidenceGap {
                    kind: DependencyEvidenceGapKind::Missing,
                    build_file: PathBuf::new(),
                    byte_range: 0..0,
                    message: "selected revision has no static dependency publication".into(),
                });
                continue;
            };
            let evidence = read_set(&conn, set)?;
            result.rows.extend(evidence.rows);
            result.gaps.extend(evidence.gaps);
        }
        Ok(result)
    }
}
fn invalid(label: &str) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(format!("invalid persisted dependency label {label}"))
}
fn evidence_kind(label: &str) -> rusqlite::Result<DependencyEvidenceKind> {
    DependencyEvidenceKind::from_label(label).ok_or_else(|| invalid(label))
}
fn scope(label: &str) -> rusqlite::Result<DependencyScope> {
    Ok(match label {
        "compile" => DependencyScope::Compile,
        "runtime" => DependencyScope::Runtime,
        "test" => DependencyScope::Test,
        "provided" => DependencyScope::Provided,
        "optional" => DependencyScope::Optional,
        "feature_gated" => DependencyScope::FeatureGated,
        "unknown" => DependencyScope::Unknown,
        _ => return Err(invalid(label)),
    })
}
fn gap_label(kind: DependencyEvidenceGapKind) -> &'static str {
    match kind {
        DependencyEvidenceGapKind::Malformed => "malformed",
        DependencyEvidenceGapKind::Unsupported => "unsupported",
        DependencyEvidenceGapKind::Unresolved => "unresolved",
        DependencyEvidenceGapKind::Conflict => "conflict",
        DependencyEvidenceGapKind::UnsafePath => "unsafe_path",
        DependencyEvidenceGapKind::Cycle => "cycle",
        DependencyEvidenceGapKind::Missing => "missing",
        DependencyEvidenceGapKind::Limit => "limit",
        DependencyEvidenceGapKind::Cancelled => "cancelled",
    }
}
fn gap_kind(label: &str) -> rusqlite::Result<DependencyEvidenceGapKind> {
    Ok(match label {
        "malformed" => DependencyEvidenceGapKind::Malformed,
        "unsupported" => DependencyEvidenceGapKind::Unsupported,
        "unresolved" => DependencyEvidenceGapKind::Unresolved,
        "conflict" => DependencyEvidenceGapKind::Conflict,
        "unsafe_path" => DependencyEvidenceGapKind::UnsafePath,
        "cycle" => DependencyEvidenceGapKind::Cycle,
        "missing" => DependencyEvidenceGapKind::Missing,
        "limit" => DependencyEvidenceGapKind::Limit,
        "cancelled" => DependencyEvidenceGapKind::Cancelled,
        _ => return Err(invalid(label)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::store::{StoreLanguageSupport, WorkspaceConfigurationInput, WorkspaceId};
    use crate::analyzer::{FilesystemProject, Language, OverlayProject};
    use brokk_bifrost_test_macros::hardwon;

    const OVERLAY: &str = "[package]\nname='demo'\nversion='0.1.0'\n";

    struct OverlayEvidenceSupport(std::sync::atomic::AtomicUsize);
    impl StoreLanguageSupport for OverlayEvidenceSupport {
        fn is_configuration_input_path(&self, path: &std::path::Path) -> bool {
            path == std::path::Path::new("Cargo.toml")
        }

        fn selected_dependency_file_evidence(
            &self,
            _root: &std::path::Path,
            selected: &[(ProjectFile, ProjectSourceSnapshot)],
            _limits: &DependencyFileEvidenceLimits,
        ) -> DependencyFileEvidence {
            // This test concerns store acquisition, not language parsing. Prove
            // that the real publisher admitted the replacement buffer.
            if let Some((file, source)) = selected.first() {
                assert!(selected.len() <= 2);
                assert_eq!(file.rel_path(), std::path::Path::new("Cargo.toml"));
                assert_eq!(source.source(), OVERLAY);
                assert!(matches!(
                    source.origin(),
                    crate::analyzer::ProjectSourceOrigin::Overlay(_)
                ));
                if let Some((file, source)) = selected.get(1) {
                    assert_eq!(file.rel_path(), std::path::Path::new("member/Cargo.toml"));
                    assert_eq!(source.source(), OVERLAY);
                    assert_eq!(source.origin(), crate::analyzer::ProjectSourceOrigin::Disk);
                }
                self.0
                    .fetch_add(selected.len(), std::sync::atomic::Ordering::Relaxed);
            }
            DependencyFileEvidence::default()
        }
    }

    #[test]
    #[hardwon("4fe7c7de1924: a small overlay retains the replaced disk file's byte-cap gap")]
    fn small_overlay_clears_replaced_disk_acquisition_limit_gap() {
        static SUPPORT: OverlayEvidenceSupport =
            OverlayEvidenceSupport(std::sync::atomic::AtomicUsize::new(0));
        let _support =
            super::super::language_support::neutral_fixture::dependency_overlay_fixture(&SUPPORT);
        let mut admitted = 0;
        // The second case pins the suffix the old disk acquisition abandoned:
        // a replacement must reconsider that retained source, not just its gap.
        for paths in [vec!["Cargo.toml"], vec!["Cargo.toml", "member/Cargo.toml"]] {
            let root = tempfile::tempdir().unwrap();
            let disk = vec![b' '; DependencyFileEvidenceLimits::default().max_file_bytes + 1];
            std::fs::write(root.path().join("Cargo.toml"), &disk).unwrap();
            let store = Arc::new(AnalyzerStore::open_ephemeral().unwrap());
            let generation = store
                .ensure_language_epoch_value("rust", "overlay-acquisition-gap-test")
                .unwrap();
            let snapshot = store
                .sync_workspace_inputs_for_workspace(
                    &WorkspaceId("a".repeat(64)),
                    "rust",
                    generation,
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &paths
                        .iter()
                        .map(|path| {
                            WorkspaceConfigurationInput::new(
                                (*path).into(),
                                if *path == "Cargo.toml" {
                                    disk.clone().into_boxed_slice()
                                } else {
                                    OVERLAY.as_bytes().into()
                                },
                            )
                        })
                        .collect::<Vec<_>>(),
                    &[],
                    &[],
                )
                .unwrap();
            let snapshots = WorkspaceSnapshots::from_iter([("rust".into(), snapshot)]);
            let before = store.dependency_file_evidence(&snapshots).unwrap();
            assert_eq!(before.gaps.len(), 1);
            assert_eq!(before.gaps[0].kind, DependencyEvidenceGapKind::Limit);
            assert_eq!(
                before.gaps[0].message,
                "dependency input file byte cap exceeded"
            );
            let project =
                OverlayProject::new(Arc::new(FilesystemProject::new(root.path()).unwrap()));
            // Key the overlay by the project's canonical root, as an editor
            // resolving through the project would. The raw temp path can be a
            // Windows 8.3 short name that never prefixes the canonical root.
            assert!(project.set(project.root().join("Cargo.toml"), OVERLAY.into()));
            let publication = publish_overlay(&store, &snapshots, &project, Language::Rust)
                .unwrap()
                .expect("configuration overlay must publish evidence");
            let after = publication.read().unwrap();
            admitted += paths.len();
            assert_eq!(
                SUPPORT.0.load(std::sync::atomic::Ordering::Relaxed),
                admitted
            );
            assert_eq!(
                after.gaps,
                Vec::new(),
                "replacement overlay must clear the disk acquisition gap"
            );
        }
    }
}
