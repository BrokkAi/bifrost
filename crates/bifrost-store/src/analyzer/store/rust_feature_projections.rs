//! Independent discovery outputs. No feature graph or config parser is retained here.
use std::path::Path;

use brokk_bifrost_core::analyzer::canonical_hash::{CanonicalHasher, lower_hex_string};
use brokk_bifrost_rust::cargo_config::is_cargo_configuration_path;
use brokk_bifrost_rust::selected_context::RustFeatureActivation;
use rusqlite::{Connection, OptionalExtension, params};

use super::{Result, WorkspaceSnapshotId};

pub(super) fn input_digest(conn: &Connection, snapshot: &WorkspaceSnapshotId) -> Result<[u8; 32]> {
    let mut hash = CanonicalHasher::new(b"rust-feature-discovery-inputs:v1");
    hash.field("derivation", &super::rust_crates::derivation_identity());
    // External config edits can change these inputs at the same source revision.
    // Publication withdraws the reconciliation certificate before refreshing it;
    // warm reuse reads only the recorded identity, never the external files.
    if let Some(digest) = super::rust_acquired_cargo_config::selected_digest(
        conn,
        snapshot,
        &super::dependency_file_evidence::NonQueryEvidenceReadRecorder,
    )? {
        hash.field("acquired-cargo-config", &digest);
    } else {
        hash.field("acquired-cargo-config-missing", b"");
    }
    let mut statement = conn.prepare_cached(
        "SELECT rel_path, blob_oid, file_present FROM workspace_file_versions
         WHERE workspace_id=?1 AND lang='rust' AND generation=?2
           AND valid_from<=?3 AND (valid_until IS NULL OR ?3<valid_until)
         ORDER BY rel_path",
    )?;
    let mut rows = statement.query(params![
        snapshot.workspace_id.as_str(),
        snapshot.generation.get(),
        snapshot.revision
    ])?;
    while let Some(row) = rows.next()? {
        let path: String = row.get(0)?;
        let file = Path::new(&path);
        // Source membership affects automatic targets and glob admission, not source bytes.
        hash.field("path", path.as_bytes());
        hash.field(
            "present",
            &[u8::from(row.get::<_, Option<bool>>(2)?.unwrap_or(true))],
        );
        if file.file_name().is_some_and(|name| name == "Cargo.toml")
            || is_cargo_configuration_path(file)
        {
            hash.field("configuration", row.get::<_, String>(1)?.as_bytes());
        }
    }
    Ok(hash.finish())
}

/// Discovery publishes this certificate with its reconciliation marker in one transaction.
/// Matching the immutable selected revision certifies the input identity without
/// rehashing the workspace on a warm summary retry.
pub(super) fn current_input_digest(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
) -> Result<Option<[u8; 32]>> {
    let digest: Option<Vec<u8>> = conn
        .prepare_cached(
            "SELECT discovery.input_digest FROM rust_feature_discoveries AS discovery
         JOIN rust_crate_reconciliations AS publication USING(workspace_id,generation)
         WHERE discovery.workspace_id=?1 AND discovery.generation=?2
           AND discovery.publication_revision=?3 AND publication.revision=?3
           AND publication.derivation_identity=?4",
        )?
        .query_row(
            params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.get(),
                snapshot.revision,
                super::rust_crates::derivation_identity().as_slice()
            ],
            |row| row.get(0),
        )
        .optional()?;
    Ok(digest.map(|digest| {
        digest
            .try_into()
            .expect("discovery input digests have 32 bytes")
    }))
}

pub(super) fn prepare(conn: &Connection) -> Result<()> {
    conn.execute_batch("CREATE TEMP TABLE IF NOT EXISTS rust_discovery_features(
        unit_key BLOB PRIMARY KEY, projection_digest BLOB NOT NULL, complete INTEGER NOT NULL,
        reason TEXT, manifest_path TEXT NOT NULL, configuration_directory TEXT NOT NULL) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS rust_discovery_feature_packages(
        unit_key BLOB NOT NULL, manifest_path TEXT NOT NULL, features TEXT NOT NULL, complete INTEGER NOT NULL,
        PRIMARY KEY(unit_key,manifest_path)) WITHOUT ROWID;")?;
    Ok(())
}

/// One unit's feature projection, as the reconcile pass computed it.
pub(super) struct StagedFeatureRow<'a> {
    pub key: &'a [u8; 32],
    pub manifest_path: &'a Path,
    pub configuration_directory: &'a Path,
    pub features_complete: bool,
    pub packages: &'a [RustFeatureActivation],
}

/// Stage any number of units with two statements, whatever their count. Every
/// projection is still computed here; only the statement shape is set-based.
pub(super) fn stage(conn: &Connection, rows: &[StagedFeatureRow<'_>]) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut units = Vec::with_capacity(rows.len());
    let mut packages = Vec::new();
    for row in rows {
        let mut hash = CanonicalHasher::new(b"rust-feature-projection:v1");
        let complete = row.features_complete && row.packages.iter().all(|package| package.complete);
        hash.field("complete", &[u8::from(complete)]);
        let key = lower_hex_string(row.key);
        for package in row.packages {
            let manifest = super::rust_crates::stable_path(&package.manifest_path);
            hash.field("manifest", manifest.as_bytes());
            hash.field("complete", &[u8::from(package.complete)]);
            for feature in &package.features {
                hash.field("feature", feature.as_bytes());
            }
            packages.push(serde_json::json!([
                key,
                manifest,
                serde_json::to_string(&package.features).expect("feature strings serialize"),
                u8::from(package.complete)
            ]));
        }
        let reason = (!complete).then_some("activation_not_established");
        if let Some(reason) = reason {
            hash.field("reason", reason.as_bytes());
        }
        units.push(serde_json::json!([
            key,
            lower_hex_string(&hash.finish()),
            u8::from(complete),
            reason,
            super::rust_crates::stable_path(row.manifest_path),
            super::rust_crates::stable_path(row.configuration_directory)
        ]));
    }
    conn.prepare_cached(
        "INSERT INTO temp.rust_discovery_features
         SELECT unhex(value->>0), unhex(value->>1), value->>2, value->>3, value->>4, value->>5
         FROM json_each(?1)",
    )?
    .execute([serde_json::to_string(&units).expect("feature rows serialize")])?;
    if !packages.is_empty() {
        conn.prepare_cached(
            "INSERT INTO temp.rust_discovery_feature_packages
             SELECT unhex(value->>0), value->>1, value->>2, value->>3 FROM json_each(?1)",
        )?
        .execute([serde_json::to_string(&packages).expect("feature package rows serialize")])?;
    }
    Ok(())
}

// The staged rows live in the in-memory schedule connection, so publication reads
// them back as two JSON arrays and hands them to the write connection as
// parameters. `staged_units` and `staged_packages` below turn those arrays back
// into rows, identically in the compare and in the rewrite; the plan registry
// reads these statements as literals, so the text is repeated instead of composed.
const STAGED_UNITS_JSON_SQL: &str = "SELECT json_group_array(json_array(hex(unit_key),hex(projection_digest),complete,reason,manifest_path,configuration_directory)) FROM temp.rust_discovery_features";
const STAGED_PACKAGES_JSON_SQL: &str = "SELECT json_group_array(json_array(hex(unit_key),manifest_path,features,complete)) FROM temp.rust_discovery_feature_packages";

/// The persisted rows under `digest` equal the staged rows. Run inside the publication
/// transaction, so no other writer can change the persisted rows between this compare
/// and the write that follows it.
///
/// The compared columns are the FULL row of each table, not a digest and not a subset:
/// every column of `rust_feature_projections` other than the three that the WHERE
/// clause fixes (workspace_id, generation, input_digest), and likewise every column of
/// `rust_feature_projection_packages` (`features` through `json()` on both sides, so
/// SQLite's own writer renders both). Both directions are compared, so a row present
/// on one side only is a difference. EXCEPT has set semantics, which is exact here
/// because neither side can hold a duplicate row: the staged TEMP tables have
/// PRIMARY KEY(unit_key) and PRIMARY KEY(unit_key,manifest_path), and the persisted
/// tables have the same keys extended by the three fixed columns. Under fixed
/// (workspace, generation, input_digest) a row is therefore identified by its key, and
/// set equality is multiset equality. A false mismatch only costs a rewrite; a missed
/// difference would certify a wrong projection, so nothing is left out.
pub(super) const UNCHANGED_SQL: &str = "WITH staged_units AS (
  SELECT unhex(value->>0) AS unit_key, unhex(value->>1) AS projection_digest, value->>2 AS complete,
         value->>3 AS reason, value->>4 AS manifest_path, value->>5 AS configuration_directory
  FROM json_each(?4)),
 staged_packages AS (
  SELECT unhex(value->>0) AS unit_key, value->>1 AS manifest_path, json(jsonb(value->>2)) AS features,
         value->>3 AS complete
  FROM json_each(?5))
SELECT EXISTS(SELECT 1 FROM rust_feature_discoveries WHERE workspace_id=?1 AND generation=?2 AND input_digest=?3)
  AND NOT EXISTS(SELECT unit_key,projection_digest,complete,reason,manifest_path,configuration_directory FROM staged_units
    EXCEPT SELECT unit_key,projection_digest,complete,reason,manifest_path,configuration_directory FROM rust_feature_projections WHERE workspace_id=?1 AND generation=?2 AND input_digest=?3)
  AND NOT EXISTS(SELECT unit_key,projection_digest,complete,reason,manifest_path,configuration_directory FROM rust_feature_projections WHERE workspace_id=?1 AND generation=?2 AND input_digest=?3
    EXCEPT SELECT unit_key,projection_digest,complete,reason,manifest_path,configuration_directory FROM staged_units)
  AND NOT EXISTS(SELECT unit_key,manifest_path,features,complete FROM staged_packages
    EXCEPT SELECT unit_key,manifest_path,json(features),complete FROM rust_feature_projection_packages WHERE workspace_id=?1 AND generation=?2 AND input_digest=?3)
  AND NOT EXISTS(SELECT unit_key,manifest_path,json(features),complete FROM rust_feature_projection_packages WHERE workspace_id=?1 AND generation=?2 AND input_digest=?3
    EXCEPT SELECT unit_key,manifest_path,features,complete FROM staged_packages)";

const REWRITE_PROJECTIONS_SQL: &str = "INSERT INTO rust_feature_projections
 SELECT ?1,?2,?3,unhex(value->>0),unhex(value->>1),value->>2,value->>3,value->>4,value->>5
 FROM json_each(?4)";
const REWRITE_PACKAGES_SQL: &str = "INSERT INTO rust_feature_projection_packages
 SELECT ?1,?2,?3,unhex(value->>0),value->>1,jsonb(value->>2),value->>3
 FROM json_each(?4)";

/// Publish the staged projections. `conn` must be inside the publication transaction
/// (`rust_crates.rs`, the `execute_selection_publication` closure of
/// `reconcile_rust_crates`): the compare and the write below are in that one
/// transaction, and it is the only decision point. The staging stays in the schedule
/// connection's TEMP tables, outside it, because only this pass reads them.
pub(super) fn publish(
    conn: &Connection,
    schedule: &Connection,
    snapshot: &WorkspaceSnapshotId,
    digest: &[u8; 32],
) -> Result<()> {
    let units: String = schedule
        .prepare_cached(STAGED_UNITS_JSON_SQL)?
        .query_row([], |row| row.get(0))?;
    let packages: String = schedule
        .prepare_cached(STAGED_PACKAGES_JSON_SQL)?
        .query_row([], |row| row.get(0))?;
    let workspace = snapshot.workspace_id.as_str();
    let generation = snapshot.generation.get();
    let unchanged: bool = conn.prepare_cached(UNCHANGED_SQL)?.query_row(
        params![workspace, generation, digest.as_slice(), units, packages],
        |row| row.get(0),
    )?;
    if unchanged {
        // Every unit was recomputed this pass and equals its persisted row, so the
        // certificate stays exact; only the revision it certifies moves.
        let moved = conn
            .prepare_cached(
                "UPDATE rust_feature_discoveries SET publication_revision=?4
                 WHERE workspace_id=?1 AND generation=?2 AND input_digest=?3",
            )?
            .execute(params![
                workspace,
                generation,
                digest.as_slice(),
                snapshot.revision
            ])?;
        assert_eq!(moved, 1, "an unchanged certificate has exactly one row");
        return Ok(());
    }
    // Children first, so the foreign-key cascade has nothing left to visit.
    for table in [
        "rust_feature_projection_packages",
        "rust_feature_projections",
        "rust_feature_discoveries",
    ] {
        conn.prepare_cached(&format!(
            "DELETE FROM {table} WHERE workspace_id=?1 AND generation=?2"
        ))?
        .execute(params![workspace, generation])?;
    }
    conn.prepare_cached("INSERT INTO rust_feature_discoveries VALUES(?1,?2,?3,?4)")?
        .execute(params![
            workspace,
            generation,
            digest.as_slice(),
            snapshot.revision
        ])?;
    conn.prepare_cached(REWRITE_PROJECTIONS_SQL)?
        .execute(params![workspace, generation, digest.as_slice(), units])?;
    conn.prepare_cached(REWRITE_PACKAGES_SQL)?.execute(params![
        workspace,
        generation,
        digest.as_slice(),
        packages
    ])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

    use super::super::AnalyzerStore;
    use super::super::planner_statistics::pinned_plans::pinned_queries;

    /// The compare runs under the publication write lock, so its persisted side
    /// has to be a key-prefix seek on both tables and in both directions.
    #[test]
    fn unchanged_compare_seeks_persisted_rows_by_key_prefix() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        store
            .select_writer_workspace_snapshots(&conn, &Default::default())
            .unwrap();
        let query = pinned_queries()
            .into_iter()
            .find(|query| query.name == "rust_feature_projection_unchanged")
            .unwrap();
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let plan = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {}", query.sql))
                .unwrap()
                .query_map(rusqlite::params_from_iter(query.params.iter()), |row| {
                    row.get::<_, String>(3)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            for table in [
                "rust_feature_projections",
                "rust_feature_projection_packages",
            ] {
                let searches = plan
                    .iter()
                    .filter(|step| {
                        step.starts_with(&format!("SEARCH {table} USING PRIMARY KEY"))
                            && step.contains("workspace_id=? AND generation=? AND input_digest=?")
                    })
                    .count();
                assert_eq!(searches, 2, "{state:?}: {table} seeks: {plan:?}");
                assert!(
                    !plan
                        .iter()
                        .any(|step| step.starts_with(&format!("SCAN {table}"))),
                    "{state:?}: {table} is scanned: {plan:?}"
                );
            }
        }
    }
}
