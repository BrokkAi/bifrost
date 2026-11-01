//! Incremental selected compilation membership and global directive inventories.
use super::*;
use crate::analyzer::Language;
use crate::analyzer::store::{BlobKey, row_batch};

pub(in crate::analyzer::store) const CERTIFICATE_COUNTS_SQL: &str =
    "SELECT publications_expected,publications_installed FROM csharp_compilation_using_coverage
            WHERE workspace_id=?1 AND compilation_id=?2 AND valid_from=?3";
pub(in crate::analyzer::store) const UPDATE_INSTALLED_SQL: &str =
    "UPDATE csharp_compilation_using_coverage SET publications_installed=?4,reasons=jsonb(?5)
            WHERE workspace_id=?1 AND compilation_id=?2 AND valid_from=?3";
pub(in crate::analyzer::store) const MARK_SQL: &str =
    "INSERT OR IGNORE INTO csharp_using_publications VALUES(?1,?2)";
pub(in crate::analyzer::store) const UNMARK_SQL: &str =
    "DELETE FROM csharp_using_publications WHERE blob_id=?1 RETURNING blob_id";
pub(in crate::analyzer::store) const RETIRE_MARK_SQL: &str = "DELETE FROM csharp_using_publications WHERE blob_id=?1 AND producer_epoch<>?2 RETURNING producer_epoch";

pub(in crate::analyzer::store) const FILES_SQL: &str = "SELECT file_version_id,rel_path,blob_oid
 FROM workspace_file_versions WHERE workspace_id=?1 AND lang='csharp' AND generation=?2
 AND input_kind='source' AND valid_from<=?3 AND (valid_until IS NULL OR valid_until>?3)";
pub(in crate::analyzer::store) const PUBLICATION_SQL: &str = "SELECT b.id FROM blobs b
 JOIN resolution_fragment_interiors h ON h.blob_id=b.id
 JOIN blob_meta meta ON meta.blob_id=b.id AND meta.lang=b.lang AND meta.is_complete=1
 WHERE b.blob_oid=?1 AND b.lang='csharp' AND b.generation=?2 AND b.parse_variant=?4
 AND h.publication_state='complete' AND h.producer_epoch=?3
 AND EXISTS(SELECT 1 FROM source_fact_readiness s WHERE s.blob_id=b.id AND s.available=1)";
pub(in crate::analyzer::store) const COUNTS_SQL: &str = "SELECT count(*),coalesce(sum(EXISTS(
 SELECT 1 FROM blobs b JOIN resolution_fragment_interiors h ON h.blob_id=b.id
 JOIN blob_meta meta ON meta.blob_id=b.id AND meta.lang=b.lang AND meta.is_complete=1
 WHERE b.blob_oid=f.blob_oid AND b.lang='csharp' AND b.generation=m.generation
 AND b.parse_variant=COALESCE(decisions.decision_digest,x'') AND b.id<>?6 AND h.publication_state='complete' AND h.producer_epoch=?5
 AND EXISTS(SELECT 1 FROM source_fact_readiness s WHERE s.blob_id=b.id AND s.available=1))),0)
 FROM csharp_compilation_members m INDEXED BY idx_csharp_members_snapshot
 JOIN workspace_file_versions f ON f.file_version_id=m.file_version_id
 LEFT JOIN csharp_file_version_decisions decisions ON decisions.file_version_id=f.file_version_id
 WHERE m.workspace_id=?1 AND m.lang='csharp' AND m.generation=?2 AND m.compilation_id=?3
 AND m.valid_from<=?4 AND (m.valid_until IS NULL OR m.valid_until>?4)";
pub(in crate::analyzer::store) const PUBLICATION_MEMBERS_SQL: &str = "SELECT m.workspace_id,m.generation,m.compilation_id,m.rel_path,m.valid_from,m.valid_until
 FROM (SELECT DISTINCT workspace_id,generation FROM csharp_compilation_sets) owners
 CROSS JOIN blobs b ON b.id=?1 AND b.lang='csharp' AND b.generation=owners.generation
 CROSS JOIN workspace_file_versions f INDEXED BY idx_workspace_file_versions_snapshot_blob
 ON f.workspace_id=owners.workspace_id AND f.lang='csharp' AND f.generation=owners.generation AND f.blob_oid=b.blob_oid
 LEFT JOIN csharp_file_version_decisions decisions ON decisions.file_version_id=f.file_version_id
 JOIN csharp_compilation_members m INDEXED BY idx_csharp_members_file ON m.file_version_id=f.file_version_id
 WHERE b.parse_variant=COALESCE(decisions.decision_digest,x'')";

pub(in crate::analyzer::store) fn affected_certificates_sql() -> &'static str {
    static SQL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SQL.get_or_init(||format!("SELECT v.workspace_id,v.generation,v.compilation_id,v.valid_from,v.membership_complete,v.metadata_complete,count(*)
        FROM ({PUBLICATION_MEMBERS_SQL}) publication
        JOIN csharp_compilation_using_coverage v INDEXED BY idx_csharp_coverage_compilation
        ON v.compilation_id=publication.compilation_id AND v.workspace_id=publication.workspace_id
        AND v.generation=publication.generation
        AND publication.valid_from < coalesce(v.valid_until,9223372036854775807)
        AND v.valid_from < coalesce(publication.valid_until,9223372036854775807)
        GROUP BY v.workspace_id,v.compilation_id,v.valid_from"))
}

fn epoch() -> &'static str {
    crate::analyzer::store::resolution::resolution_bundle_epoch(Language::CSharp)
}

fn coverage_reasons(membership: bool, metadata: bool, expected: i64, installed: i64) -> String {
    let mut reasons = Vec::new();
    if !membership {
        reasons.push(serde_json::json!({"kind":"membership"}));
    }
    if !metadata {
        reasons.push(serde_json::json!({"kind":"metadata"}));
    }
    if installed != expected {
        reasons.push(serde_json::json!({"kind":"publications"}));
    }
    serde_json::to_string(&reasons).expect("coverage diagnostics serialize")
}

fn refresh(tx: &Transaction<'_>, snapshot: &WorkspaceSnapshotId, compilation: i64) -> Result<()> {
    let (expected, installed): (i64, i64) = tx.query_row(
        COUNTS_SQL,
        params![
            snapshot.workspace_id.as_str(),
            snapshot.generation.0,
            compilation,
            snapshot.revision,
            epoch(),
            0
        ],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let (membership, metadata): (bool, bool) = tx.query_row(
        "SELECT coverage.membership_complete AND NOT c.inventory_open AND NOT EXISTS (
         SELECT 1 FROM json_each(s.gaps) g WHERE json_extract(g.value,'$[0]') IN (SELECT value FROM json_each(?2))),c.global_usings_complete FROM csharp_compilations c
         JOIN csharp_compilation_membership_coverage coverage USING(compilation_id) JOIN csharp_compilation_sets s ON s.set_id=c.set_id WHERE c.compilation_id=?1",
        params![compilation, serde_json::to_string(&super::MEMBERSHIP_CAP_CODES).expect("codes serialize")],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let reasons = coverage_reasons(membership, metadata, expected, installed);
    let same: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM csharp_compilation_using_coverage
        WHERE workspace_id=?1 AND generation=?2 AND compilation_id=?3 AND valid_until IS NULL
        AND membership_complete=?4 AND metadata_complete=?5 AND publications_expected=?6
        AND publications_installed=?7 AND json(reasons)=?8 AND valid_from=?9)",
        params![
            snapshot.workspace_id.as_str(),
            snapshot.generation.0,
            compilation,
            membership,
            metadata,
            expected,
            installed,
            reasons,
            snapshot.revision
        ],
        |r| r.get(0),
    )?;
    if same {
        return Ok(());
    }
    tx.execute(
        "UPDATE csharp_compilation_using_coverage SET valid_until=?4
        WHERE workspace_id=?1 AND generation=?2 AND compilation_id=?3
        AND valid_until IS NULL AND valid_from<?4",
        params![
            snapshot.workspace_id.as_str(),
            snapshot.generation.0,
            compilation,
            snapshot.revision
        ],
    )?;
    tx.execute("INSERT INTO csharp_compilation_using_coverage
        (workspace_id,lang,generation,compilation_id,valid_from,membership_complete,
         publications_expected,publications_installed,metadata_complete,reasons)
        VALUES(?1,'csharp',?2,?3,?4,?5,?6,?7,?8,jsonb(?9))
        ON CONFLICT(workspace_id,compilation_id,valid_from) DO UPDATE SET
        membership_complete=excluded.membership_complete,publications_expected=excluded.publications_expected,
        publications_installed=excluded.publications_installed,metadata_complete=excluded.metadata_complete,
        reasons=excluded.reasons",
        params![snapshot.workspace_id.as_str(),snapshot.generation.0,compilation,snapshot.revision,
            membership,expected,installed,metadata,reasons])?;
    Ok(())
}

fn install_path(
    tx: &Transaction<'_>,
    snapshot: &WorkspaceSnapshotId,
    view: &CSharpCompilationView<'_>,
    path: &str,
) -> Result<Vec<i64>> {
    let mut affected = tx
        .prepare_cached(
            "SELECT compilation_id FROM csharp_compilation_members
        WHERE workspace_id=?1 AND rel_path=?2 AND generation=?3 AND valid_until IS NULL",
        )?
        .query_map(
            params![snapshot.workspace_id.as_str(), path, snapshot.generation.0],
            |r| r.get::<_, i64>(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    // A retry at the same revision replaces its own rows; older intervals close.
    for table in ["csharp_compilation_members", "csharp_global_using_extent"] {
        tx.execute(
            &format!(
                "DELETE FROM {table} WHERE workspace_id=?1 AND rel_path=?2
            AND generation=?3 AND valid_from=?4"
            ),
            params![
                snapshot.workspace_id.as_str(),
                path,
                snapshot.generation.0,
                snapshot.revision
            ],
        )?;
        tx.execute(
            &format!(
                "UPDATE {table} SET valid_until=?4 WHERE workspace_id=?1 AND rel_path=?2
            AND generation=?3 AND valid_until IS NULL AND valid_from<?4"
            ),
            params![
                snapshot.workspace_id.as_str(),
                path,
                snapshot.generation.0,
                snapshot.revision
            ],
        )?;
    }
    let file: Option<(i64,String,super::super::ParseVariant)> = tx.query_row("SELECT file_version_id,blob_oid,COALESCE((SELECT decision_digest FROM csharp_file_version_decisions decisions WHERE decisions.file_version_id=workspace_file_versions.file_version_id),x'') FROM workspace_file_versions
        WHERE workspace_id=?1 AND lang='csharp' AND generation=?2 AND rel_path=?3 AND input_kind='source'
        AND valid_from<=?4 AND (valid_until IS NULL OR valid_until>?4)",
        params![snapshot.workspace_id.as_str(),snapshot.generation.0,path,snapshot.revision],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    if let Some((file, oid, variant)) = file {
        let members = match view.evaluate_membership(path)? {
            super::SelectedCSharpMembership::Proven(membership) => membership.proven,
            super::SelectedCSharpMembership::Unproven { .. } => Vec::new(),
            #[cfg(any(test, feature = "test-support"))]
            super::SelectedCSharpMembership::NotSelected => Vec::new(),
        };
        let rows = members
            .iter()
            .map(|&compilation| {
                (
                    snapshot.workspace_id.as_str(),
                    "csharp",
                    snapshot.generation.0,
                    compilation,
                    path,
                    file,
                    snapshot.revision,
                )
            })
            .collect::<Vec<_>>();
        assert!(row_batch::insert_typed_rows(tx, "INSERT INTO csharp_compilation_members
            (workspace_id,lang,generation,compilation_id,rel_path,file_version_id,valid_from) VALUES",
            "(?,?,?,?,?,?,?)", &rows, &crate::CancellationToken::new())?);
        if let Some(blob) = tx
            .query_row(
                PUBLICATION_SQL,
                params![oid, snapshot.generation.0, epoch(), variant],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
        {
            tx.execute(MARK_SQL, params![blob, epoch()])?;
            for &compilation in &members {
                install_imports(tx, snapshot, compilation, path, blob, None)?;
            }
        }
        affected.extend(members);
    }
    affected.sort_unstable();
    affected.dedup();
    Ok(affected)
}

fn install_imports(
    tx: &Transaction<'_>,
    snapshot: &WorkspaceSnapshotId,
    compilation: i64,
    path: &str,
    blob: i64,
    until: Option<i64>,
) -> Result<()> {
    tx.execute("INSERT OR IGNORE INTO csharp_global_using_extent
        (workspace_id,lang,generation,compilation_id,rel_path,blob_id,import_site,valid_from,valid_until)
        SELECT ?1,'csharp',?2,?3,?4,?5,import_site,?6,?7 FROM resolution_compilation_imports WHERE blob_id=?5",
        params![snapshot.workspace_id.as_str(),snapshot.generation.0,compilation,path,blob,snapshot.revision,until])?;
    Ok(())
}

fn close_inventory(tx: &Transaction<'_>, snapshot: &WorkspaceSnapshotId) -> Result<()> {
    for table in [
        "csharp_compilation_members",
        "csharp_global_using_extent",
        "csharp_compilation_using_coverage",
    ] {
        tx.execute(
            &format!(
                "DELETE FROM {table} WHERE workspace_id=?1 AND generation=?2 AND valid_from=?3"
            ),
            params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.0,
                snapshot.revision
            ],
        )?;
        tx.execute(
            &format!(
                "UPDATE {table} SET valid_until=?3 WHERE workspace_id=?1 AND generation=?2
                AND valid_until IS NULL AND valid_from<?3"
            ),
            params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.0,
                snapshot.revision
            ],
        )?;
    }
    Ok(())
}

/// Called after set activation even when derivation reused the current version.
pub(in crate::analyzer::store) fn publish(
    tx: &Transaction<'_>,
    snapshot: &WorkspaceSnapshotId,
    head: Option<i64>,
    changed: &[i64],
) -> Result<()> {
    if snapshot.lang != STORAGE_LANGUAGE {
        return Ok(());
    }
    let Some(view) = CSharpCompilationView::selected(tx, snapshot)? else {
        close_inventory(tx, snapshot)?;
        return Ok(());
    };
    let previous = head.map(|revision| WorkspaceSnapshotId {
        revision,
        ..snapshot.clone()
    });
    let old_set = previous
        .as_ref()
        .map(|s| selected_set(tx, s))
        .transpose()?
        .flatten()
        .map(|v| v.id);
    let covered: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM csharp_compilation_using_coverage v
        JOIN csharp_compilations c ON c.compilation_id=v.compilation_id WHERE c.set_id=?1
        AND v.workspace_id=?2 AND v.valid_from<=?3 AND (v.valid_until IS NULL OR v.valid_until>?3))",
        params![view.set_id,snapshot.workspace_id.as_str(),snapshot.revision], |r|r.get(0))?;
    if old_set != Some(view.set_id) || !covered {
        close_inventory(tx, snapshot)?;
        let mut statement = tx.prepare_cached(FILES_SQL)?;
        let mut files = statement.query(params![
            snapshot.workspace_id.as_str(),
            snapshot.generation.0,
            snapshot.revision
        ])?;
        while let Some(file) = files.next()? {
            install_path(tx, snapshot, &view, &file.get::<_, String>(1)?)?;
        }
        // Include empty compilations and unknown memberships, without inferring absence.
        let mut statement =
            tx.prepare_cached("SELECT compilation_id FROM csharp_compilations WHERE set_id=?1")?;
        let mut compilations = statement.query([view.set_id])?;
        while let Some(row) = compilations.next()? {
            refresh(tx, snapshot, row.get(0)?)?;
        }
    } else {
        for &file in changed {
            let path = tx
                .query_row(
                    "SELECT rel_path FROM workspace_file_versions
                WHERE file_version_id=?1 AND input_kind='source'",
                    [file],
                    |r| r.get::<_, String>(0),
                )
                .optional()?;
            if let Some(path) = path {
                for compilation in install_path(tx, snapshot, &view, &path)? {
                    refresh(tx, snapshot, compilation)?;
                }
            }
        }
    }

    Ok(())
}

// A publication can be shared by retained revisions and several workspaces.
// Restore its existing member intervals, without re-deriving membership.
pub(in crate::analyzer::store) fn content_available(
    tx: &Transaction<'_>,
    language: &str,
    blob: i64,
) -> Result<()> {
    if language != STORAGE_LANGUAGE {
        return Ok(());
    }
    let identity = tx
        .query_row(
            "SELECT blob_oid,generation,parse_variant FROM blobs
        WHERE id=?1 AND lang='csharp'",
            [blob],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, super::super::ParseVariant>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((oid, generation, variant)) = identity else {
        return Ok(());
    };
    if tx
        .query_row(
            PUBLICATION_SQL,
            params![oid, generation, epoch(), variant],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        != Some(blob)
    {
        return Ok(());
    }
    let previous: Option<String> = tx
        .query_row(RETIRE_MARK_SQL, params![blob, epoch()], |r| r.get(0))
        .optional()?;
    if previous.is_some() {
        adjust_certificates(tx, blob, -1)?;
    }
    if tx.execute(MARK_SQL, params![blob, epoch()])? == 0 {
        return Ok(());
    }
    adjust_certificates(tx, blob, 1)?;
    let members = tx
        .prepare_cached(PUBLICATION_MEMBERS_SQL)?
        .query_map([blob], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Option<i64>>(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if members.is_empty() {
        return Ok(());
    }
    for (workspace, generation, compilation, path, revision, until) in members {
        install_imports(
            tx,
            &WorkspaceSnapshotId {
                workspace_id: crate::analyzer::store::WorkspaceId(workspace),
                lang: STORAGE_LANGUAGE.into(),
                generation: crate::analyzer::store::GenerationId(generation),
                revision,
            },
            compilation,
            &path,
            blob,
            until,
        )?;
    }

    Ok(())
}

struct Certificate {
    workspace: String,
    compilation: i64,
    revision: i64,
    membership: bool,
    metadata: bool,
    multiplicity: i64,
}

fn adjust_certificates(tx: &Transaction<'_>, blob: i64, direction: i64) -> Result<()> {
    for c in certificates(tx, blob)? {
        let (expected, installed): (i64, i64) = tx.query_row(
            CERTIFICATE_COUNTS_SQL,
            params![c.workspace, c.compilation, c.revision],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let installed = installed + direction * c.multiplicity;
        let reasons = coverage_reasons(c.membership, c.metadata, expected, installed);
        tx.execute(
            UPDATE_INSTALLED_SQL,
            params![c.workspace, c.compilation, c.revision, installed, reasons],
        )?;
    }
    Ok(())
}

fn certificates(tx: &Transaction<'_>, blob: i64) -> Result<Vec<Certificate>> {
    Ok(tx
        .prepare_cached(affected_certificates_sql())?
        .query_map([blob], |r| {
            Ok(Certificate {
                workspace: r.get(0)?,
                compilation: r.get(2)?,
                revision: r.get(3)?,
                membership: r.get(4)?,
                metadata: r.get(5)?,
                multiplicity: r.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Content parents cannot disappear while extent history references them.
pub(in crate::analyzer::store) fn before_blob_delete(
    tx: &Transaction<'_>,
    key: &BlobKey,
) -> Result<()> {
    if key.lang != STORAGE_LANGUAGE {
        return Ok(());
    }
    let blob = tx
        .query_row(
            "SELECT id FROM blobs WHERE blob_oid=?1 AND lang='csharp' AND parse_variant=?2",
            params![key.oid.to_string(), key.variant],
            |r| r.get::<_, i64>(0),
        )
        .optional()?;
    let Some(blob) = blob else {
        return Ok(());
    };
    let removed: Option<i64> = tx.query_row(UNMARK_SQL, [blob], |r| r.get(0)).optional()?;
    if removed.is_some() {
        adjust_certificates(tx, blob, -1)?;
    }
    tx.execute(
        "DELETE FROM csharp_global_using_extent WHERE blob_id=?1",
        [blob],
    )?;
    Ok(())
}

// Masks drive path seeks even before statistics exist; never range over all members.
pub(in crate::analyzer::store) const OVERLAY_AFFECTED_SQL: &str =
    "SELECT compilation_id FROM csharp_compilations WHERE set_id=?1 AND ?2
 UNION SELECT m.compilation_id FROM temp.selected_resolution_overlay_masks mask
 CROSS JOIN csharp_compilation_members m INDEXED BY idx_csharp_members_path
 ON m.workspace_id=?3 AND m.rel_path=mask.persisted_relative_path AND m.generation=?4
 AND m.valid_from<=?5 AND (m.valid_until IS NULL OR m.valid_until>?5)
 WHERE mask.storage_language='csharp'
 UNION SELECT compilation_id FROM temp.selected_csharp_overlay_members";

pub(in crate::analyzer::store) const OVERLAY_COUNTS_SQL: &str =
    "SELECT count(*),coalesce(sum(blob_id IS NOT NULL),0)
 FROM temp.selected_csharp_compilation_members WHERE compilation_id=?1";

// Only overlay deltas are staged. Base rows stay in SQLite and are anti-masked
// through indexed paths. Context deletion cascades even on a retained reader.
pub(in crate::analyzer::store) const OVERLAY_SCHEMA: &str = "
CREATE TEMP TABLE IF NOT EXISTS selected_csharp_extent_state(
 singleton INTEGER PRIMARY KEY REFERENCES selected_resolution_context(singleton) ON DELETE CASCADE,
 configuration_open INTEGER NOT NULL) STRICT;
CREATE TEMP TABLE IF NOT EXISTS selected_csharp_overlay_members(
 singleton INTEGER NOT NULL DEFAULT 0 REFERENCES selected_resolution_context(singleton) ON DELETE CASCADE,
 compilation_id INTEGER NOT NULL,rel_path TEXT NOT NULL,blob_id INTEGER,
 PRIMARY KEY(compilation_id,rel_path)) WITHOUT ROWID,STRICT;
CREATE TEMP TABLE IF NOT EXISTS selected_csharp_overlay_extent(
 singleton INTEGER NOT NULL DEFAULT 0 REFERENCES selected_resolution_context(singleton) ON DELETE CASCADE,
 compilation_id INTEGER NOT NULL,rel_path TEXT NOT NULL,blob_id INTEGER NOT NULL,import_site INTEGER NOT NULL,
 PRIMARY KEY(compilation_id,rel_path,import_site)) WITHOUT ROWID,STRICT;
CREATE TEMP TABLE IF NOT EXISTS selected_csharp_overlay_coverage(
 singleton INTEGER NOT NULL DEFAULT 0 REFERENCES selected_resolution_context(singleton) ON DELETE CASCADE,
 compilation_id INTEGER PRIMARY KEY,membership_complete INTEGER NOT NULL,publications_expected INTEGER NOT NULL,
 publications_installed INTEGER NOT NULL,metadata_complete INTEGER NOT NULL,reasons BLOB NOT NULL) STRICT;
CREATE TEMP VIEW IF NOT EXISTS selected_csharp_compilation_members AS
 SELECT m.compilation_id,m.rel_path,m.file_version_id,
 CASE WHEN h.blob_id IS NOT NULL AND meta.is_complete=1
 AND EXISTS(SELECT 1 FROM main.source_fact_readiness s WHERE s.blob_id=b.id AND s.available=1)
 THEN b.id END blob_id
 FROM main.csharp_compilation_members m
 JOIN temp.selected_workspace_revisions v ON v.workspace_id=m.workspace_id AND v.lang=m.lang AND v.generation=m.generation
 JOIN main.csharp_compilations c ON c.compilation_id=m.compilation_id
 JOIN main.csharp_compilation_selections cs ON cs.workspace_id=v.workspace_id AND cs.lang=v.lang
 AND cs.generation=v.generation AND cs.revision=v.revision AND cs.set_id=c.set_id
 JOIN main.workspace_file_versions f ON f.file_version_id=m.file_version_id
 LEFT JOIN main.csharp_file_version_decisions decisions ON decisions.file_version_id=f.file_version_id
 LEFT JOIN main.blobs b ON b.blob_oid=f.blob_oid AND b.lang='csharp' AND b.generation=m.generation AND b.parse_variant=COALESCE(decisions.decision_digest,x'')
 LEFT JOIN main.resolution_fragment_interiors h ON h.blob_id=b.id AND h.publication_state='complete'
 AND h.producer_epoch=(SELECT expected_producer_epoch FROM temp.selected_resolution_languages WHERE storage_language='csharp')
 LEFT JOIN main.blob_meta meta ON meta.blob_id=b.id AND meta.lang=b.lang
 WHERE m.valid_from<=v.revision AND (m.valid_until IS NULL OR m.valid_until>v.revision)
 AND (SELECT configuration_open FROM temp.selected_csharp_extent_state)=0
 AND NOT EXISTS(SELECT 1 FROM temp.selected_resolution_overlay_masks mask WHERE mask.storage_language='csharp' AND mask.persisted_relative_path=m.rel_path)
 UNION ALL SELECT compilation_id,rel_path,NULL,blob_id FROM temp.selected_csharp_overlay_members;
CREATE TEMP VIEW IF NOT EXISTS selected_csharp_global_using_extent AS
 SELECT e.compilation_id,e.rel_path,e.blob_id,e.import_site FROM main.csharp_global_using_extent e
 JOIN temp.selected_workspace_revisions v ON v.workspace_id=e.workspace_id AND v.lang=e.lang AND v.generation=e.generation
 JOIN main.csharp_compilations c ON c.compilation_id=e.compilation_id
 JOIN main.csharp_compilation_selections cs ON cs.workspace_id=v.workspace_id AND cs.lang=v.lang
 AND cs.generation=v.generation AND cs.revision=v.revision AND cs.set_id=c.set_id
 WHERE e.valid_from<=v.revision AND (e.valid_until IS NULL OR e.valid_until>v.revision)
 AND (SELECT configuration_open FROM temp.selected_csharp_extent_state)=0
 AND NOT EXISTS(SELECT 1 FROM temp.selected_resolution_overlay_masks mask WHERE mask.storage_language='csharp' AND mask.persisted_relative_path=e.rel_path)
 UNION ALL SELECT compilation_id,rel_path,blob_id,import_site FROM temp.selected_csharp_overlay_extent;
CREATE TEMP VIEW IF NOT EXISTS selected_csharp_compilation_using_coverage AS
 SELECT c.compilation_id,c.membership_complete,c.publications_expected,c.publications_installed,c.metadata_complete,c.reasons
 FROM main.csharp_compilation_using_coverage c JOIN temp.selected_workspace_revisions v
 ON v.workspace_id=c.workspace_id AND v.lang=c.lang AND v.generation=c.generation
 JOIN main.csharp_compilations compilation ON compilation.compilation_id=c.compilation_id
 JOIN main.csharp_compilation_selections cs ON cs.workspace_id=v.workspace_id AND cs.lang=v.lang
 AND cs.generation=v.generation AND cs.revision=v.revision AND cs.set_id=compilation.set_id
 WHERE c.valid_from<=v.revision AND (c.valid_until IS NULL OR c.valid_until>v.revision)
 AND NOT EXISTS(SELECT 1 FROM temp.selected_csharp_overlay_coverage overlay WHERE overlay.compilation_id=c.compilation_id)
 UNION ALL SELECT compilation_id,membership_complete,publications_expected,publications_installed,metadata_complete,reasons
 FROM temp.selected_csharp_overlay_coverage;
";

pub(in crate::analyzer::store) fn stage(
    tx: &Transaction<'_>,
    cancellation: &crate::CancellationToken,
) -> Result<bool> {
    tx.execute_batch(OVERLAY_SCHEMA)?;
    // A retained selection can rebuild its inventory on the same connection.
    tx.execute_batch(
        "DELETE FROM temp.selected_csharp_extent_state;
        DELETE FROM temp.selected_csharp_overlay_members;
        DELETE FROM temp.selected_csharp_overlay_extent;
        DELETE FROM temp.selected_csharp_overlay_coverage;",
    )?;
    let snapshot = tx
        .query_row(
            "SELECT workspace_id,generation,revision FROM temp.selected_workspace_revisions
        WHERE lang='csharp'",
            [],
            |r| {
                Ok(WorkspaceSnapshotId {
                    workspace_id: crate::analyzer::store::WorkspaceId(r.get(0)?),
                    lang: "csharp".into(),
                    generation: crate::analyzer::store::GenerationId(r.get(1)?),
                    revision: r.get(2)?,
                })
            },
        )
        .optional()?;
    let Some(snapshot) = snapshot else {
        return Ok(true);
    };
    let open: bool = tx.query_row(
        SELECTED_CONFIGURATION_MASK_SQL,
        params![
            snapshot.workspace_id.as_str(),
            snapshot.generation.0,
            snapshot.revision
        ],
        |r| r.get(0),
    )?;
    tx.execute(
        "INSERT INTO temp.selected_csharp_extent_state VALUES(0,?1)",
        [open],
    )?;
    let Some(view) = CSharpCompilationView::selected(tx, &snapshot)? else {
        return Ok(true);
    };
    if !open {
        let mut statement = tx.prepare_cached(
            "SELECT persisted_relative_path,blob_id FROM temp.selected_resolution_mounts
            WHERE storage_language='csharp' AND file_version_id IS NULL",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            let path: String = row.get(0)?;
            let blob: i64 = row.get(1)?;
            let members = match view.evaluate_membership(&path)? {
                super::SelectedCSharpMembership::Proven(membership) => membership.proven,
                super::SelectedCSharpMembership::Unproven { .. } => Vec::new(),
                #[cfg(any(test, feature = "test-support"))]
                super::SelectedCSharpMembership::NotSelected => Vec::new(),
            };
            for compilation in members {
                tx.execute("INSERT INTO temp.selected_csharp_overlay_members(compilation_id,rel_path,blob_id) VALUES(?1,?2,?3)",params![compilation,path,blob])?;
                tx.execute("INSERT INTO temp.selected_csharp_overlay_extent(compilation_id,rel_path,blob_id,import_site)
                    SELECT ?1,?2,?3,import_site FROM resolution_compilation_imports WHERE blob_id=?3",params![compilation,path,blob])?;
            }
        }
    }
    if !open {
        let mut missing = tx.prepare_cached(
            "SELECT persisted_relative_path FROM temp.selected_resolution_overlay_masks
            WHERE storage_language='csharp' AND expected_transient_replacement_count=1",
        )?;
        let mut rows = missing.query([])?;
        while let Some(row) = rows.next()? {
            let path: String = row.get(0)?;
            let members = match view.evaluate_membership(&path)? {
                super::SelectedCSharpMembership::Proven(membership) => membership.proven,
                super::SelectedCSharpMembership::Unproven { .. } => Vec::new(),
                #[cfg(any(test, feature = "test-support"))]
                super::SelectedCSharpMembership::NotSelected => Vec::new(),
            };
            for compilation in members {
                tx.execute("INSERT OR IGNORE INTO temp.selected_csharp_overlay_members(compilation_id,rel_path,blob_id)
                    VALUES(?1,?2,NULL)",params![compilation,path])?;
            }
        }
    }
    let mut affected = tx.prepare_cached(OVERLAY_AFFECTED_SQL)?;
    let mut rows = affected.query(params![
        view.set_id,
        open,
        snapshot.workspace_id.as_str(),
        snapshot.generation.0,
        snapshot.revision
    ])?;
    while let Some(row) = rows.next()? {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let compilation: i64 = row.get(0)?;
        let (expected, installed): (i64, i64) =
            tx.query_row(OVERLAY_COUNTS_SQL, [compilation], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
        let metadata: bool = tx.query_row(
            "SELECT global_usings_complete FROM csharp_compilations WHERE compilation_id=?1",
            [compilation],
            |r| r.get(0),
        )?;
        let membership: bool = tx.query_row("SELECT membership_complete AND NOT inventory_open FROM csharp_compilation_membership_coverage JOIN csharp_compilations USING(compilation_id) WHERE compilation_id=?1", [compilation], |r|r.get(0))?;
        let membership = membership && !open && !view.membership_capped;
        let reasons = coverage_reasons(membership, !open && metadata, expected, installed);
        tx.execute("INSERT INTO temp.selected_csharp_overlay_coverage
            (compilation_id,membership_complete,publications_expected,publications_installed,metadata_complete,reasons)
            VALUES(?1,?2,?3,?4,?5,jsonb(?6))",params![compilation,membership,expected,installed,metadata && !open,
                reasons])?;
    }
    Ok(!cancellation.is_cancelled())
}
