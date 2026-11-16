//! Independent discovery outputs. No feature graph or config parser is retained here.
use std::path::Path;

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
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
    if let Some(digest) = super::rust_acquired_cargo_config::selected_digest(conn, snapshot)? {
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

pub(super) fn stage(
    conn: &Connection,
    key: &[u8; 32],
    manifest_path: &Path,
    configuration_directory: &Path,
    features_complete: bool,
    packages: &[RustFeatureActivation],
) -> Result<()> {
    let mut hash = CanonicalHasher::new(b"rust-feature-projection:v1");
    let complete = features_complete && packages.iter().all(|package| package.complete);
    hash.field("complete", &[u8::from(complete)]);
    for package in packages {
        let manifest = super::rust_crates::stable_path(&package.manifest_path);
        hash.field("manifest", manifest.as_bytes());
        hash.field("complete", &[u8::from(package.complete)]);
        for feature in &package.features {
            hash.field("feature", feature.as_bytes());
        }
        conn.prepare_cached(
            "INSERT INTO temp.rust_discovery_feature_packages VALUES(?1,?2,?3,?4)",
        )?
        .execute(params![
            key.as_slice(),
            manifest,
            serde_json::to_string(&package.features).expect("feature strings serialize"),
            package.complete
        ])?;
    }
    let reason = (!complete).then_some("activation_not_established");
    if let Some(reason) = reason {
        hash.field("reason", reason.as_bytes());
    }
    conn.prepare_cached("INSERT INTO temp.rust_discovery_features VALUES(?1,?2,?3,?4,?5,?6)")?
        .execute(params![
            key.as_slice(),
            hash.finish().as_slice(),
            complete,
            reason,
            super::rust_crates::stable_path(manifest_path),
            super::rust_crates::stable_path(configuration_directory)
        ])?;
    Ok(())
}

pub(super) fn publish(
    conn: &Connection,
    schedule: &Connection,
    snapshot: &WorkspaceSnapshotId,
    digest: &[u8; 32],
) -> Result<()> {
    conn.prepare_cached(
        "DELETE FROM rust_feature_discoveries WHERE workspace_id=?1 AND generation=?2",
    )?
    .execute(params![
        snapshot.workspace_id.as_str(),
        snapshot.generation.get()
    ])?;
    conn.prepare_cached("INSERT INTO rust_feature_discoveries VALUES(?1,?2,?3,?4)")?
        .execute(params![
            snapshot.workspace_id.as_str(),
            snapshot.generation.get(),
            digest.as_slice(),
            snapshot.revision
        ])?;
    let mut statement = schedule.prepare_cached("SELECT unit_key,projection_digest,complete,reason,manifest_path,configuration_directory FROM temp.rust_discovery_features")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        conn.prepare_cached(
            "INSERT INTO rust_feature_projections VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        )?
        .execute(params![
            snapshot.workspace_id.as_str(),
            snapshot.generation.get(),
            digest.as_slice(),
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, bool>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?
        ])?;
    }
    let mut statement = schedule.prepare_cached(
        "SELECT unit_key,manifest_path,features,complete FROM temp.rust_discovery_feature_packages",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        conn.prepare_cached(
            "INSERT INTO rust_feature_projection_packages VALUES(?1,?2,?3,?4,?5,jsonb(?6),?7)",
        )?
        .execute(params![
            snapshot.workspace_id.as_str(),
            snapshot.generation.get(),
            digest.as_slice(),
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, bool>(3)?
        ])?;
    }
    Ok(())
}
