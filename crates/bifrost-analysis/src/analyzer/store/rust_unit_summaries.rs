//! Rust crate definition for the shared per-unit resolution summary.
//!
//! The topology tables remain Rust-owned. Their crate key is also the shared
//! summary unit key, which makes rust_crate_versions the crosswalk from a
//! summary version to its topology row.
use std::collections::{BTreeMap, HashMap, HashSet};
#[cfg(test)]
use std::fmt::Debug;

use rusqlite::{Connection, OptionalExtension, params};

use super::unit_summaries::{
    ConsumedDependency, UnitDependency, UnitExport, UnitGap, UnitImport, UnitInputs, UnitMember,
    UnitOutputs, UnitRead, UnitSummaryLanguage,
};
use super::{Result, StoreError, WorkspaceSnapshotId};
use crate::analyzer::canonical_hash::CanonicalHasher;
use crate::analyzer::store::resolution_prepare::resolution_rows::{language_code, namespace_code};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

/// Bump when the Rust summary's normalized rows or read set changes.
pub(crate) const RUST_UNIT_SUMMARY_DERIVATION_VERSION: i64 = 1;

const STAGE_SCHEMA_SQL: &str = "CREATE TEMP TABLE IF NOT EXISTS rust_unit_summary_units(
    unit_id INTEGER PRIMARY KEY,
    topology_id INTEGER NOT NULL UNIQUE,
    crate_key BLOB NOT NULL UNIQUE,
    label TEXT NOT NULL
  ) STRICT;
  DELETE FROM temp.rust_unit_summary_units;";

const STAGE_UNITS_SQL: &str = "INSERT INTO temp.rust_unit_summary_units(topology_id, crate_key, label)
    SELECT versions.topology_id, versions.crate_key, topologies.crate_name || ' [' || topologies.target_kind || ']'
    FROM main.rust_crate_versions AS versions
    JOIN main.rust_crate_topologies AS topologies ON topologies.topology_id = versions.topology_id
    WHERE versions.workspace_id = ?1 AND versions.lang = 'rust' AND versions.generation = ?2
      AND versions.valid_from <= ?3 AND (versions.valid_until IS NULL OR ?3 < versions.valid_until)
      AND topologies.publication_state = 'complete'
    ORDER BY versions.crate_key";

const STAGE_DEPENDENCY_EDGES_SQL: &str = "INSERT OR IGNORE INTO temp.unit_summary_edges(unit_id, dependency_unit_id)
    SELECT owner.unit_id, child.unit_id
    FROM temp.rust_unit_summary_units AS owner
    JOIN main.rust_crate_dependencies AS dependencies ON dependencies.topology_id = owner.topology_id
      AND dependencies.boundary = 'workspace'
    JOIN temp.rust_unit_summary_units AS child ON child.crate_key = dependencies.dependency_crate_key";

const UNIT_SQL: &str = "SELECT units.topology_id, topologies.crate_key, units.label
    FROM temp.rust_unit_summary_units AS units
    JOIN main.rust_crate_topologies AS topologies ON topologies.topology_id = units.topology_id
    WHERE units.unit_id = ?1";

const MEMBERS_SQL: &str =
    "SELECT DISTINCT sources.blob_id, blobs.blob_oid, sources.rel_path, sources.source_kind
    FROM main.rust_crate_container_sources AS sources
    JOIN main.blobs AS blobs ON blobs.id = sources.blob_id
    WHERE sources.topology_id = ?1
    ORDER BY sources.rel_path, sources.source_kind, sources.blob_id";

const CONFIGURATION_READS_SQL: &str = "SELECT versions.rel_path, versions.blob_oid
    FROM main.workspace_file_versions AS versions
    WHERE versions.workspace_id = ?1 AND versions.lang = 'rust' AND versions.generation = ?2
      AND versions.input_kind = 'configuration' AND versions.valid_from <= ?3
      AND (versions.valid_until IS NULL OR ?3 < versions.valid_until)
    ORDER BY versions.rel_path";

const DEPENDENCIES_SQL: &str = "SELECT dependencies.extern_name, dependencies.boundary,
       dependencies.dependency_crate_key, dependencies.dependency_kind,
       child.unit_id, COALESCE(target.crate_name, dependencies.extern_name)
    FROM main.rust_crate_dependencies AS dependencies
    LEFT JOIN temp.rust_unit_summary_units AS child
      ON child.crate_key = dependencies.dependency_crate_key
    LEFT JOIN main.rust_crate_topologies AS target ON target.topology_id = child.topology_id
    WHERE dependencies.topology_id = ?1
    ORDER BY dependencies.extern_name";

const IMPORTS_SQL: &str =
    "SELECT sources.blob_id, imports.import_id, imports.alias, imports.identifier,
       sources.rel_path, segment.ordinal, segment.segment
    FROM (SELECT topology_id, blob_id, MIN(rel_path) AS rel_path
          FROM main.rust_crate_container_sources WHERE topology_id = ?1
          GROUP BY topology_id, blob_id) AS sources
    JOIN main.source_imports AS imports ON imports.blob_id = sources.blob_id
    LEFT JOIN main.source_import_segments AS segment
      ON segment.blob_id = imports.blob_id AND segment.import_id = imports.import_id
    ORDER BY sources.rel_path, sources.blob_id, imports.import_id, segment.ordinal";

const IMPORT_TARGET_KEYS_SQL: &str = "SELECT DISTINCT imports.target_crate_key
    FROM main.source_rust_import_targets AS targets
    JOIN main.rust_crate_imports AS imports
      ON imports.topology_id = ?1 AND imports.module_path = targets.module_path
     AND imports.blob_id = targets.blob_id AND imports.import_ordinal = targets.ordinal
    WHERE targets.blob_id = ?2 AND targets.source_import_id = ?3
    UNION
    SELECT DISTINCT imports.target_crate_key
    FROM main.source_rust_import_targets AS targets
    JOIN main.rust_crate_glob_imports AS imports
      ON imports.topology_id = ?1 AND imports.module_path = targets.module_path
     AND imports.blob_id = targets.blob_id AND imports.import_ordinal = targets.ordinal
    WHERE targets.blob_id = ?2 AND targets.source_import_id = ?3";

const EXPORTS_SQL: &str = "SELECT exports.module_path, exports.namespace, exports.name,
       exports.origin, exports.declaration_blob_id, exports.declaration_site,
       semantic.semantic_key
    FROM main.rust_crate_exports AS exports
    LEFT JOIN main.resolution_semantic_sites AS semantic
      ON semantic.blob_id = exports.declaration_blob_id
     AND semantic.source_site = exports.declaration_site
     AND semantic.semantic_role = 'definition'
    WHERE exports.topology_id = ?1 AND exports.visibility = 'public'
    ORDER BY exports.module_path, exports.namespace, exports.name";

const NAMED_REEXPORT_TARGETS_SQL: &str =
    "SELECT DISTINCT target_crate_key, target_module_path, target_name
    FROM main.rust_crate_imports
    WHERE topology_id = ?1 AND module_path = ?2 AND namespace = ?3 AND bound_name = ?4";

const ROUTED_REEXPORT_TARGETS_SQL: &str =
    "SELECT DISTINCT target_crate_key, target_module_path, target_name
    FROM main.rust_crate_reexport_routes
    WHERE topology_id = ?1 AND module_path = ?2 AND bound_name = ?3 AND visibility = 'public'";

const GLOB_REEXPORT_TARGETS_SQL: &str =
    "SELECT DISTINCT routes.target_crate_key, routes.target_module_path
    FROM main.rust_crate_glob_reexport_routes AS routes
    JOIN main.rust_crate_versions AS versions
      ON versions.workspace_id = ?5 AND versions.lang = 'rust' AND versions.generation = ?6
     AND versions.crate_key = routes.target_crate_key
     AND versions.valid_from <= ?7 AND (versions.valid_until IS NULL OR ?7 < versions.valid_until)
    JOIN main.rust_crate_exports AS target
      ON target.topology_id = versions.topology_id
     AND target.module_path = routes.target_module_path
     AND target.namespace = ?3 AND target.name = ?4
     AND (target.visibility = 'public' OR routes.target_crate_key = ?8)
    WHERE routes.topology_id = ?1 AND routes.module_path = ?2 AND routes.visibility = 'public'";

const TARGET_IDENTITY_SQL: &str = "SELECT identities.id, identities.identity_digest
    FROM main.rust_crate_versions AS versions
    JOIN main.rust_crate_exports AS exports ON exports.topology_id = versions.topology_id
    JOIN main.resolution_identities AS identities
      ON identities.semantic_language = ?8 AND identities.namespace = ?9 AND identities.spelling = ?7
    WHERE versions.workspace_id = ?1 AND versions.lang = 'rust' AND versions.generation = ?2
      AND versions.crate_key = ?3 AND versions.valid_from <= ?4
      AND (versions.valid_until IS NULL OR ?4 < versions.valid_until)
      AND exports.module_path = ?5 AND exports.namespace = ?6 AND exports.name = ?7
      AND (?10 OR exports.visibility = 'public')
    LIMIT 1";

const LOCAL_IMPORT_SQL: &str = "SELECT EXISTS(
    SELECT 1 FROM main.source_rust_import_targets AS targets
    JOIN main.rust_crate_imports AS imports
      ON imports.topology_id = ?1 AND imports.module_path = targets.module_path
     AND imports.blob_id = targets.blob_id AND imports.import_ordinal = targets.ordinal
    WHERE targets.blob_id = ?2 AND targets.source_import_id = ?3 AND imports.target_crate_key = ?4
    UNION
    SELECT 1 FROM main.source_rust_import_targets AS targets
    JOIN main.rust_crate_glob_imports AS imports
      ON imports.topology_id = ?1 AND imports.module_path = targets.module_path
     AND imports.blob_id = targets.blob_id AND imports.import_ordinal = targets.ordinal
    WHERE targets.blob_id = ?2 AND targets.source_import_id = ?3 AND imports.target_crate_key = ?4
  )";

const GAPS_SQL: &str = "SELECT gap_kind, subject, json(detail)
    FROM main.rust_crate_gaps WHERE topology_id = ?1 ORDER BY gap_kind, subject";

pub(crate) struct RustUnitSummaries;

/// The dependency ordinal, identity id and identity digest of a re-export target.
type ReexportTarget = (Option<usize>, i64, [u8; 32]);

#[cfg(test)]
pub(super) fn assert_differential(conn: &Connection, snapshot: &WorkspaceSnapshotId) {
    let topology_count: usize = conn
        .query_row(
            "SELECT count(*) FROM main.rust_crate_versions AS versions
             JOIN main.rust_crate_topologies AS topology USING(topology_id)
             WHERE versions.workspace_id = ?1 AND versions.lang = 'rust'
               AND versions.generation = ?2 AND versions.valid_from <= ?3
               AND (versions.valid_until IS NULL OR ?3 < versions.valid_until)
               AND topology.publication_state = 'complete'",
            rusqlite::params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.get(),
                snapshot.revision
            ],
            |row| row.get(0),
        )
        .expect("count selected Rust topology versions");
    let crosswalk = {
        let mut statement = conn
            .prepare(
                "SELECT topology.topology_id, topology.crate_key, topology.crate_name,
                        summary.summary_id
                 FROM main.rust_crate_versions AS versions
                 JOIN main.rust_crate_topologies AS topology
                   ON topology.topology_id = versions.topology_id
                 JOIN main.resolution_unit_summary_versions AS summary
                   ON summary.workspace_id = versions.workspace_id
                  AND summary.lang = versions.lang AND summary.generation = versions.generation
                  AND summary.unit_key = versions.crate_key
                 JOIN main.resolution_unit_summaries AS headers
                   ON headers.summary_id = summary.summary_id
                 WHERE versions.workspace_id = ?1 AND versions.lang = 'rust'
                   AND versions.generation = ?2
                   AND versions.valid_from <= ?3
                   AND (versions.valid_until IS NULL OR ?3 < versions.valid_until)
                   AND summary.valid_from <= ?3
                   AND (summary.valid_until IS NULL OR ?3 < summary.valid_until)
                   AND headers.lang = 'rust' AND headers.unit_kind = 'rust_crate'
                   AND headers.publication_state = 'complete'
                 ORDER BY topology.crate_key",
            )
            .expect("prepare Rust summary crosswalk");
        statement
            .query_map(
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.get(),
                    snapshot.revision
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .expect("read Rust summary crosswalk")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect Rust summary crosswalk")
    };
    assert_eq!(
        topology_count,
        crosswalk.len(),
        "Rust topology-to-summary crosswalk missing rows at workspace {} generation {} revision {}",
        snapshot.workspace_id.as_str(),
        snapshot.generation.get(),
        snapshot.revision
    );

    for (topology_id, crate_key, crate_name, summary_id) in crosswalk {
        let expected_members = {
            let mut statement = conn
                .prepare(
                    "SELECT DISTINCT blob_id, rel_path, source_kind
                     FROM main.rust_crate_container_sources
                     WHERE topology_id = ?1",
                )
                .expect("prepare Rust topology members");
            statement
                .query_map([topology_id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .expect("read Rust topology members")
                .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()
                .expect("collect Rust topology members")
        };
        let actual_members = {
            let mut statement = conn
                .prepare(
                    "SELECT blob_id, rel_path, source_role
                     FROM main.resolution_unit_summary_members
                     WHERE summary_id = ?1",
                )
                .expect("prepare Rust summary members");
            statement
                .query_map([summary_id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .expect("read Rust summary members")
                .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()
                .expect("collect Rust summary members")
        };
        assert_set_equal(
            &format!("{crate_name} members"),
            &expected_members,
            &actual_members,
        );

        let expected_exports = {
            let mut statement = conn
                .prepare(
                    "SELECT namespace, name FROM main.rust_crate_exports
                     WHERE topology_id = ?1 AND visibility = 'public'",
                )
                .expect("prepare Rust topology exports");
            let names = statement
                .query_map([topology_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .expect("read Rust topology exports")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("collect Rust topology exports");
            names
                .into_iter()
                .map(|(namespace, name)| {
                    let (identity_id, _) = identity_for_name(conn, &namespace, &name)
                        .expect("lookup Rust export identity")
                        .unwrap_or_else(|| {
                            panic!(
                                "{crate_name} export {namespace}:{name} lacks its shared identity"
                            )
                        });
                    (identity_id, namespace)
                })
                .collect::<std::collections::BTreeSet<_>>()
        };
        let actual_exports = {
            let mut statement = conn
                .prepare(
                    "SELECT identity_id, namespace
                     FROM main.resolution_unit_summary_exports
                     WHERE summary_id = ?1 AND visibility = 'exported'",
                )
                .expect("prepare Rust summary exports");
            statement
                .query_map([summary_id], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .expect("read Rust summary exports")
                .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()
                .expect("collect Rust summary exports")
        };
        let missing_exports = expected_exports
            .difference(&actual_exports)
            .map(|(identity_id, namespace)| {
                let spelling: String = conn
                    .query_row(
                        "SELECT spelling FROM main.resolution_identities WHERE id = ?1",
                        [identity_id],
                        |row| row.get(0),
                    )
                    .expect("lookup missing Rust export spelling");
                let topology_rows = {
                    let mut statement = conn
                        .prepare(
                            "SELECT module_path, origin, declaration_blob_id, declaration_site
                             FROM main.rust_crate_exports
                             WHERE topology_id = ?1 AND namespace = ?2 AND name = ?3
                               AND visibility = 'public'
                             ORDER BY module_path, origin",
                        )
                        .expect("prepare missing Rust export detail");
                    statement
                        .query_map(params![topology_id, namespace, spelling], |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, i64>(2)?,
                                row.get::<_, i64>(3)?,
                            ))
                        })
                        .expect("read missing Rust export detail")
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .expect("collect missing Rust export detail")
                };
                ((*identity_id, namespace.clone(), spelling), topology_rows)
            })
            .collect::<Vec<_>>();
        assert_set_equal(
            &format!("{crate_name} exports missing-details={missing_exports:?}"),
            &expected_exports,
            &actual_exports,
        );

        let expected_dependencies = {
            let mut statement = conn
                .prepare(
                    "SELECT extern_name, boundary, dependency_crate_key
                     FROM main.rust_crate_dependencies WHERE topology_id = ?1",
                )
                .expect("prepare Rust topology dependencies");
            statement
                .query_map([topology_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                })
                .expect("read Rust topology dependencies")
                .map(|row| {
                    let (extern_name, boundary, dependency_key) =
                        row.expect("decode Rust topology dependency");
                    let key = match (boundary.as_str(), dependency_key) {
                        ("workspace", Some(key)) => {
                            digest_from_row(key).expect("Rust workspace dependency key is 32 bytes")
                        }
                        ("external", None) => external_unit_key(&extern_name),
                        ("std", None) => standard_unit_key(&extern_name),
                        other => {
                            panic!("{crate_name} has invalid dependency boundary/key {other:?}")
                        }
                    };
                    let boundary = if boundary == "std" {
                        "standard".to_owned()
                    } else {
                        boundary
                    };
                    (boundary, key)
                })
                .collect::<std::collections::BTreeSet<_>>()
        };
        let actual_dependencies = {
            let mut statement = conn
                .prepare(
                    "SELECT boundary, dependency_unit_key
                     FROM main.resolution_unit_summary_dependencies
                     WHERE summary_id = ?1 AND boundary IN ('workspace', 'external', 'standard')",
                )
                .expect("prepare Rust summary dependencies");
            statement
                .query_map([summary_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .expect("read Rust summary dependencies")
                .map(|row| {
                    let (boundary, key) = row.expect("decode Rust summary dependency");
                    (
                        boundary,
                        digest_from_row(key).expect("Rust summary dependency key is 32 bytes"),
                    )
                })
                .collect::<std::collections::BTreeSet<_>>()
        };
        assert_eq!(crate_key.len(), 32, "{crate_name} crate key width");
        assert_set_equal(
            &format!("{crate_name} dependencies"),
            &expected_dependencies,
            &actual_dependencies,
        );
    }
}

#[cfg(test)]
fn assert_set_equal<T: Ord + Debug>(
    label: &str,
    expected: &std::collections::BTreeSet<T>,
    actual: &std::collections::BTreeSet<T>,
) {
    let expected_only = expected.difference(actual).collect::<Vec<_>>();
    let actual_only = actual.difference(expected).collect::<Vec<_>>();
    assert!(
        expected_only.is_empty() && actual_only.is_empty(),
        "Rust summary differential failed for {label}: topology-only={expected_only:?}, summary-only={actual_only:?}"
    );
}

impl UnitSummaryLanguage for RustUnitSummaries {
    fn lang(&self) -> &'static str {
        "rust"
    }

    fn unit_kind(&self) -> &'static str {
        "rust_crate"
    }

    fn derivation_version(&self) -> i64 {
        RUST_UNIT_SUMMARY_DERIVATION_VERSION
    }

    fn stage(&self, conn: &Connection, snapshot: &WorkspaceSnapshotId) -> Result<()> {
        conn.execute_batch(STAGE_SCHEMA_SQL)?;
        conn.execute(
            STAGE_UNITS_SQL,
            params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.get(),
                snapshot.revision
            ],
        )?;
        conn.execute(
            "INSERT INTO temp.unit_summary_work(unit_id)
             SELECT unit_id FROM temp.rust_unit_summary_units",
            [],
        )?;
        conn.execute(STAGE_DEPENDENCY_EDGES_SQL, [])?;
        Ok(())
    }

    fn clear_stage(&self, conn: &Connection) -> Result<()> {
        conn.execute("DELETE FROM temp.rust_unit_summary_units", [])?;
        Ok(())
    }

    fn inputs(
        &self,
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        unit_id: i64,
    ) -> Result<UnitInputs> {
        let (topology_id, unit_key, label): (i64, Vec<u8>, String) = conn
            .prepare_cached(UNIT_SQL)?
            .query_row([unit_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        let unit_key = digest_from_row(unit_key)?;
        let mut members = Vec::new();
        {
            let mut statement = conn.prepare_cached(MEMBERS_SQL)?;
            let mut rows = statement.query([topology_id])?;
            while let Some(row) = rows.next()? {
                members.push(UnitMember {
                    blob_id: row.get(0)?,
                    blob_oid: row.get(1)?,
                    rel_path: row.get(2)?,
                    source_role: row.get(3)?,
                });
            }
        }

        let producer_epoch: String = conn.query_row(
            "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang = 'rust'",
            [],
            |row| row.get(0),
        )?;
        let reads = read_rows(conn, snapshot, &producer_epoch)?;

        let mut dependencies = Vec::new();
        let mut dependency_keys = HashSet::new();
        {
            let mut statement = conn.prepare_cached(DEPENDENCIES_SQL)?;
            let mut rows = statement.query([topology_id])?;
            while let Some(row) = rows.next()? {
                let extern_name: String = row.get(0)?;
                let boundary: String = row.get(1)?;
                let crate_key: Option<Vec<u8>> = row.get(2)?;
                let dependency_kind: String = row.get(3)?;
                let dependency_unit_id: Option<i64> = row.get(4)?;
                let dependency_label: String = row.get(5)?;
                let (key, unit_id, boundary, provenance, external_digest) = match (
                    boundary.as_str(),
                    crate_key,
                ) {
                    ("workspace", Some(key)) => (
                        digest_from_row(key)?,
                        dependency_unit_id,
                        "workspace",
                        None,
                        None,
                    ),
                    ("external", None) => {
                        let key = external_unit_key(&extern_name);
                        let provenance = format!("cargo-external:{extern_name}:{dependency_kind}");
                        let digest = external_dependency_digest(
                            &extern_name,
                            &dependency_kind,
                            &producer_epoch,
                            &reads,
                        );
                        (key, None, "external", Some(provenance), Some(digest))
                    }
                    ("std", None) => {
                        let key = standard_unit_key(&extern_name);
                        let provenance = format!("rust-standard:{extern_name}:{dependency_kind}");
                        let digest = standard_dependency_digest(&extern_name, &producer_epoch);
                        (key, None, "standard", Some(provenance), Some(digest))
                    }
                    other => {
                        return Err(StoreError::corrupt(format!(
                            "{label}: invalid Rust dependency row {other:?} for {extern_name:?}/{dependency_kind:?}"
                        )));
                    }
                };
                if dependency_keys.insert(key) {
                    dependencies.push(UnitDependency {
                        unit_key: key,
                        unit_id,
                        label: format!("Rust dependency {dependency_label}"),
                        boundary,
                        provenance,
                        external_digest,
                    });
                }
            }
        }
        Ok(UnitInputs {
            unit_id,
            unit_key,
            label,
            members,
            reads,
            dependencies,
        })
    }

    fn derive(
        &self,
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        unit: &UnitInputs,
        dependencies: &[ConsumedDependency],
        _producer_epoch: &str,
    ) -> Result<UnitOutputs> {
        let (topology_id, inventory_complete): (i64, bool) = conn
            .prepare_cached(
                "SELECT units.topology_id, topologies.inventory_complete
                 FROM temp.rust_unit_summary_units AS units
                 JOIN main.rust_crate_topologies AS topologies USING(topology_id)
                 WHERE units.unit_id = ?1",
            )?
            .query_row([unit.unit_id], |row| Ok((row.get(0)?, row.get(1)?)))?;

        let mut gaps = BTreeMap::<(&'static str, String), String>::new();
        {
            let mut statement = conn.prepare_cached(GAPS_SQL)?;
            let mut rows = statement.query([topology_id])?;
            while let Some(row) = rows.next()? {
                let kind: String = row.get(0)?;
                let subject: String = row.get(1)?;
                let detail: String = row.get(2)?;
                gaps.insert((rust_gap_kind(&kind)?, subject), detail);
            }
        }
        for dependency in dependencies
            .iter()
            .filter(|dependency| !dependency.available)
        {
            gaps.insert(
                ("unit_summary_unavailable", dependency.label.clone()),
                "{}".to_owned(),
            );
        }

        let dependency_ordinals: HashMap<[u8; 32], usize> = dependencies
            .iter()
            .map(|dependency| (dependency.unit_key, dependency.ordinal))
            .collect();
        let dependency_keys_by_extern = {
            let mut statement = conn.prepare_cached(
                "SELECT extern_name, boundary, dependency_crate_key
                 FROM main.rust_crate_dependencies WHERE topology_id = ?1 ORDER BY extern_name",
            )?;
            let mut rows = statement.query([topology_id])?;
            let mut mapping = HashMap::new();
            while let Some(row) = rows.next()? {
                let extern_name: String = row.get(0)?;
                let boundary: String = row.get(1)?;
                let dependency_key: Option<Vec<u8>> = row.get(2)?;
                let key = match (boundary.as_str(), dependency_key) {
                    ("workspace", Some(key)) => digest_from_row(key)?,
                    ("external", None) => external_unit_key(&extern_name),
                    ("std", None) => standard_unit_key(&extern_name),
                    other => {
                        return Err(StoreError::corrupt(format!(
                            "{}: invalid dependency binding for {extern_name:?}: {other:?}",
                            unit.label
                        )));
                    }
                };
                mapping.insert(extern_name, key);
            }
            mapping
        };

        let mut exports = Vec::new();
        // Identity, namespace, declaration blob and declaration site.
        type ExportKey = (i64, String, i64, i64);
        // Identity digest, origin, alias dependency ordinal, alias digest and
        // declaration key.
        type ExportSignature = ([u8; 32], &'static str, Option<usize>, Option<[u8; 32]>, i64);
        let mut export_keys: HashMap<ExportKey, (ExportSignature, usize)> = HashMap::new();
        {
            let mut statement = conn.prepare_cached(EXPORTS_SQL)?;
            let mut rows = statement.query([topology_id])?;
            while let Some(row) = rows.next()? {
                let module_path: String = row.get(0)?;
                let namespace: String = row.get(1)?;
                let name: String = row.get(2)?;
                let rust_origin: String = row.get(3)?;
                let declaration_blob_id: i64 = row.get(4)?;
                let declaration_site: i64 = row.get(5)?;
                let declaration_key: Option<i64> = row.get(6)?;
                let Some(declaration_key) = declaration_key else {
                    return Err(StoreError::corrupt(format!(
                        "{}: public export {module_path}::{name} lacks a definition semantic site at blob {declaration_blob_id} site {declaration_site}",
                        unit.label
                    )));
                };
                let (identity_id, identity_digest) = identity_for_name(conn, &namespace, &name)?
                    .ok_or_else(|| {
                        StoreError::corrupt(format!(
                            "{}: public export {module_path}::{name} has no Rust name identity",
                            unit.label
                        ))
                    })?;
                let (origin, alias_dependency_ordinal, alias_identity_id, alias_identity_digest) =
                    if rust_origin == "declaration" {
                        ("declaration", None, None, None)
                    } else {
                        let target = self.reexport_target(
                            conn,
                            snapshot,
                            unit,
                            topology_id,
                            &module_path,
                            &namespace,
                            &name,
                            &rust_origin,
                            &dependency_ordinals,
                        )?;
                        let Some((dependency_ordinal, identity_id, identity_digest)) = target
                        else {
                            gaps.insert(
                                (
                                    "unresolved_reexport",
                                    format!("{module_path}::{namespace}:{name}"),
                                ),
                                "{\"reason\":\"reexport_target_unavailable\"}".to_owned(),
                            );
                            continue;
                        };
                        (
                            "reexport",
                            dependency_ordinal,
                            Some(identity_id),
                            Some(identity_digest),
                        )
                    };
                let (origin, alias_dependency_ordinal, alias_identity_id, alias_identity_digest) =
                    if origin == "reexport"
                        && alias_dependency_ordinal.is_none()
                        && alias_identity_id == Some(identity_id)
                    {
                        // `pub use` can expose a declaration under its existing
                        // identity inside this crate. The shared key is declaration
                        // based, so retain the direct declaration instead of a
                        // self-alias that carries no additional lookup information.
                        ("declaration", None, None, None)
                    } else {
                        (
                            origin,
                            alias_dependency_ordinal,
                            alias_identity_id,
                            alias_identity_digest,
                        )
                    };
                let export_key = (
                    identity_id,
                    namespace.clone(),
                    declaration_blob_id,
                    declaration_site,
                );
                let export_signature = (
                    identity_digest,
                    origin,
                    alias_dependency_ordinal,
                    alias_identity_digest,
                    declaration_key,
                );
                let export = UnitExport {
                    identity_id,
                    identity_digest,
                    namespace: namespace.clone(),
                    visibility: "exported",
                    origin,
                    alias_dependency_ordinal,
                    alias_identity_id,
                    alias_identity_digest,
                    declaration_blob_id,
                    declaration_site,
                    declaration_key,
                };
                if let Some((previous, index)) = export_keys.get(&export_key).copied() {
                    if previous == export_signature {
                        continue;
                    }
                    if previous.1 == "declaration" && origin == "reexport" {
                        exports[index] = export;
                        export_keys.insert(export_key, (export_signature, index));
                    } else if previous.1 == "reexport" && origin == "declaration" {
                        continue;
                    } else {
                        return Err(StoreError::corrupt(format!(
                            "{}: Rust export {module_path}::{namespace}:{name} collides at declaration blob {declaration_blob_id} site {declaration_site} with different identity or re-export target: previous={previous:?}, current={export_signature:?}",
                            unit.label
                        )));
                    }
                } else {
                    let index = exports.len();
                    exports.push(export);
                    export_keys.insert(export_key, (export_signature, index));
                }
            }
        }

        let imports = self.imports(
            conn,
            topology_id,
            unit,
            &dependency_ordinals,
            &dependency_keys_by_extern,
        )?;
        for import in imports.iter().filter(|import| import.state == "unresolved") {
            gaps.entry(("unresolved_import", import.spelling.clone()))
                .or_insert_with(|| "{}".to_owned());
        }

        let gaps = gaps
            .into_iter()
            .map(|((kind, subject), detail)| UnitGap {
                kind,
                subject,
                detail,
            })
            .collect::<Vec<_>>();
        let complete = inventory_complete
            && !gaps.iter().any(|gap| {
                matches!(
                    gap.kind,
                    "unit_summary_unavailable"
                        | "unresolved_import"
                        | "unresolved_reexport"
                        | "open_export_inventory"
                        | "unresolved_visibility"
                )
            });
        Ok(UnitOutputs {
            exports,
            imports,
            gaps,
            complete,
        })
    }
}

impl RustUnitSummaries {
    fn imports(
        &self,
        conn: &Connection,
        topology_id: i64,
        unit: &UnitInputs,
        dependency_ordinals: &HashMap<[u8; 32], usize>,
        dependency_keys_by_extern: &HashMap<String, [u8; 32]>,
    ) -> Result<Vec<UnitImport>> {
        struct Pending {
            blob_id: i64,
            import_id: i64,
            alias: Option<String>,
            identifier: Option<String>,
            rel_path: String,
            segments: Vec<String>,
        }
        let mut imports = Vec::new();
        let mut statement = conn.prepare_cached(IMPORTS_SQL)?;
        let mut rows = statement.query([topology_id])?;
        let mut current: Option<Pending> = None;
        let mut finish = |pending: Option<Pending>| -> Result<()> {
            let Some(pending) = pending else {
                return Ok(());
            };
            let mut segments = pending.segments;
            if segments.is_empty()
                && let Some(identifier) = pending.identifier.as_deref()
            {
                segments.push(identifier.to_owned());
            }
            if segments.is_empty() {
                return Err(StoreError::corrupt(format!(
                    "{}: Rust import {} at {} has no structured source path",
                    unit.label, pending.import_id, pending.rel_path
                )));
            }
            let spelling = segments.join("::");
            let root = segments[0].as_str();
            let is_local = matches!(root, "crate" | "self" | "super")
                || conn.query_row(
                    LOCAL_IMPORT_SQL,
                    params![
                        topology_id,
                        pending.blob_id,
                        pending.import_id,
                        unit.unit_key.as_slice()
                    ],
                    |row| row.get::<_, bool>(0),
                )?;
            if is_local {
                return Ok(());
            }
            let direct_key = dependency_keys_by_extern.get(root).copied();
            let target_key =
                import_target_key(conn, topology_id, pending.blob_id, pending.import_id)?;
            let dependency_key = direct_key.or(target_key);
            let dependency_ordinal =
                dependency_key.and_then(|key| dependency_ordinals.get(&key).copied());
            let blank = pending.alias.as_deref() == Some("_");
            let state = if blank {
                "blank"
            } else if dependency_ordinal.is_some() {
                "resolved"
            } else {
                "unresolved"
            };
            imports.push(UnitImport {
                blob_id: pending.blob_id,
                import_id: pending.import_id,
                // Rust has no Go-style package definition key. The source import
                // declaration id is its blob-local binding key.
                kind: if blank { "blank" } else { "named" },
                definition_key: Some(pending.import_id),
                spelling,
                dependency_ordinal,
                state,
            });
            Ok(())
        };
        while let Some(row) = rows.next()? {
            let key = (row.get::<_, i64>(0)?, row.get::<_, i64>(1)?);
            if current
                .as_ref()
                .is_none_or(|pending| (pending.blob_id, pending.import_id) != key)
            {
                finish(current.take())?;
                current = Some(Pending {
                    blob_id: key.0,
                    import_id: key.1,
                    alias: row.get(2)?,
                    identifier: row.get(3)?,
                    rel_path: row.get(4)?,
                    segments: Vec::new(),
                });
            }
            if let Some(segment) = row.get::<_, Option<String>>(6)? {
                current
                    .as_mut()
                    .expect("the current import owns its source path segment")
                    .segments
                    .push(segment);
            }
        }
        finish(current.take())?;
        Ok(imports)
    }

    #[allow(clippy::too_many_arguments)]
    fn reexport_target(
        &self,
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        unit: &UnitInputs,
        topology_id: i64,
        module_path: &str,
        namespace: &str,
        name: &str,
        rust_origin: &str,
        dependency_ordinals: &HashMap<[u8; 32], usize>,
    ) -> Result<Option<ReexportTarget>> {
        let candidates = if rust_origin == "glob_reexport" {
            let mut statement = conn.prepare_cached(GLOB_REEXPORT_TARGETS_SQL)?;
            statement
                .query_map(
                    params![
                        topology_id,
                        module_path,
                        namespace,
                        name,
                        snapshot.workspace_id.as_str(),
                        snapshot.generation.get(),
                        snapshot.revision,
                        unit.unit_key.as_slice()
                    ],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, String>(1)?,
                            name.to_owned(),
                        ))
                    },
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            let mut statement = conn.prepare_cached(NAMED_REEXPORT_TARGETS_SQL)?;
            let mut targets = statement
                .query_map(params![topology_id, module_path, namespace, name], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if targets.is_empty() {
                let mut statement = conn.prepare_cached(ROUTED_REEXPORT_TARGETS_SQL)?;
                targets = statement
                    .query_map(params![topology_id, module_path, name], |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
            }
            targets
        };
        let mut resolved = HashSet::new();
        for (key, target_module, target_name) in candidates {
            let key = digest_from_row(key)?;
            let same_unit = key == unit.unit_key;
            let Some((identity_id, identity_digest)) = target_identity(
                conn,
                snapshot,
                &key,
                &target_module,
                namespace,
                &target_name,
                same_unit,
            )?
            else {
                continue;
            };
            let dependency_ordinal = if same_unit {
                None
            } else {
                dependency_ordinals.get(&key).copied()
            };
            let dependency_ordinal = if same_unit {
                None
            } else if let Some(ordinal) = dependency_ordinal {
                Some(ordinal)
            } else {
                continue;
            };
            resolved.insert((dependency_ordinal, identity_id, identity_digest));
        }
        if resolved.len() == 1 {
            Ok(resolved.into_iter().next())
        } else {
            Ok(None)
        }
    }
}

fn read_rows(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    producer_epoch: &str,
) -> Result<Vec<UnitRead>> {
    let mut reads = Vec::new();
    let mut statement = conn.prepare_cached(CONFIGURATION_READS_SQL)?;
    let mut rows = statement.query(params![
        snapshot.workspace_id.as_str(),
        snapshot.generation.get(),
        snapshot.revision
    ])?;
    while let Some(row) = rows.next()? {
        let path: String = row.get(0)?;
        let oid: String = row.get(1)?;
        reads.push(UnitRead {
            kind: "configuration",
            key_digest: read_key("rust-configuration", Some(path.as_str())),
            digest: value_digest("rust-configuration-oid", oid.as_bytes()),
        });
    }
    reads.push(UnitRead {
        kind: "epoch",
        key_digest: read_key("rust-producer-epoch", None),
        digest: value_digest("rust-producer-epoch", producer_epoch.as_bytes()),
    });
    reads.push(UnitRead {
        kind: "derivation",
        key_digest: read_key("rust-unit-summary-derivation", None),
        digest: value_digest(
            "rust-unit-summary-derivation",
            &RUST_UNIT_SUMMARY_DERIVATION_VERSION.to_be_bytes(),
        ),
    });
    Ok(reads)
}

fn identity_for_name(
    conn: &Connection,
    namespace: &str,
    name: &str,
) -> Result<Option<(i64, [u8; 32])>> {
    let namespace = rust_namespace_code(namespace)?;
    let row = conn
        .prepare_cached(
            "SELECT id, identity_digest FROM main.resolution_identities
             WHERE semantic_language = ?1 AND namespace = ?2 AND spelling = ?3",
        )?
        .query_row(
            params![
                language_code(crate::analyzer::Language::Rust),
                namespace,
                name
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    row.map(|(id, digest)| Ok((id, digest_from_row(digest)?)))
        .transpose()
}

fn target_identity(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    crate_key: &[u8; 32],
    module_path: &str,
    namespace: &str,
    name: &str,
    same_unit: bool,
) -> Result<Option<(i64, [u8; 32])>> {
    let namespace_code = rust_namespace_code(namespace)?;
    let row = conn
        .prepare_cached(TARGET_IDENTITY_SQL)?
        .query_row(
            params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.get(),
                crate_key.as_slice(),
                snapshot.revision,
                module_path,
                namespace,
                name,
                language_code(crate::analyzer::Language::Rust),
                namespace_code,
                same_unit
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    row.map(|(id, digest)| Ok((id, digest_from_row(digest)?)))
        .transpose()
}

fn import_target_key(
    conn: &Connection,
    topology_id: i64,
    blob_id: i64,
    import_id: i64,
) -> Result<Option<[u8; 32]>> {
    let mut statement = conn.prepare_cached(IMPORT_TARGET_KEYS_SQL)?;
    let keys = statement
        .query_map(params![topology_id, blob_id, import_id], |row| {
            row.get::<_, Vec<u8>>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if keys.len() > 1 {
        return Ok(None);
    }
    keys.into_iter().next().map(digest_from_row).transpose()
}

fn rust_namespace_code(namespace: &str) -> Result<i64> {
    let namespace = match namespace {
        "type" => ResolutionNamespace::Type,
        "value" => ResolutionNamespace::Value,
        "macro" => ResolutionNamespace::Macro,
        other => {
            return Err(StoreError::corrupt(format!(
                "Rust crate export has unsupported namespace {other:?}"
            )));
        }
    };
    Ok(namespace_code(namespace))
}

fn rust_gap_kind(kind: &str) -> Result<&'static str> {
    match kind {
        "external_dependency" => Ok("external_dependency"),
        "unsupported_manifest" => Ok("unsupported_manifest"),
        "inactive_placement" => Ok("inactive_placement"),
        "unknown_activation" => Ok("unknown_activation"),
        "unplaced_module" => Ok("unplaced_module"),
        "duplicate_placement" => Ok("duplicate_placement"),
        "unresolved_import" => Ok("unresolved_import"),
        "unresolved_reexport" => Ok("unresolved_reexport"),
        "open_export_inventory" => Ok("open_export_inventory"),
        "unresolved_visibility" => Ok("unresolved_visibility"),
        "unresolved_trait_impl" => Ok("unresolved_trait_impl"),
        other => Err(StoreError::corrupt(format!(
            "Rust crate topology has unknown gap kind {other:?}"
        ))),
    }
}

fn read_key(name: &str, key: Option<&str>) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-unit-summary-read-key:v1");
    hash.field("name", name.as_bytes());
    if let Some(key) = key {
        hash.field("key", key.as_bytes());
    }
    hash.finish()
}

fn value_digest(kind: &str, value: &[u8]) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-rust-unit-summary-input:v1");
    hash.field("kind", kind.as_bytes());
    hash.field("value", value);
    hash.finish()
}

fn external_unit_key(extern_name: &str) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-rust-external-unit:v1");
    hash.field("extern-name", extern_name.as_bytes());
    hash.finish()
}

fn standard_unit_key(name: &str) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-rust-standard-unit:v1");
    hash.field("crate-name", name.as_bytes());
    hash.finish()
}

fn external_dependency_digest(
    extern_name: &str,
    dependency_kind: &str,
    producer_epoch: &str,
    reads: &[UnitRead],
) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-rust-external-dependency:v1");
    hash.field("extern-name", extern_name.as_bytes());
    hash.field("dependency-kind", dependency_kind.as_bytes());
    hash.field("producer-epoch", producer_epoch.as_bytes());
    let mut configuration: Vec<_> = reads
        .iter()
        .filter(|read| read.kind == "configuration")
        .collect();
    configuration.sort_by_key(|read| read.key_digest);
    for read in configuration {
        hash.field("configuration-key", &read.key_digest);
        hash.field("configuration-oid", &read.digest);
    }
    hash.finish()
}

fn standard_dependency_digest(name: &str, producer_epoch: &str) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-rust-standard-dependency:v1");
    hash.field("crate-name", name.as_bytes());
    hash.field("producer-epoch", producer_epoch.as_bytes());
    hash.finish()
}

fn digest_from_row(bytes: Vec<u8>) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| StoreError::corrupt(format!("digest is {} bytes", bytes.len())))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::AnalyzerConfig;
    use crate::analyzer::WorkspaceAnalyzer;
    use crate::inline_project::InlineTestProject;

    fn live_summaries(workspace: &WorkspaceAnalyzer) -> BTreeMap<String, (i64, Vec<u8>)> {
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        let mut statement = conn
            .prepare(
                "SELECT topology.crate_name, summaries.summary_id, summaries.output_digest
                 FROM rust_crate_versions AS topology_versions
                 JOIN rust_crate_topologies AS topology USING(topology_id)
                 JOIN resolution_unit_summary_versions AS summary_versions
                   ON summary_versions.workspace_id = topology_versions.workspace_id
                  AND summary_versions.lang = topology_versions.lang
                  AND summary_versions.generation = topology_versions.generation
                  AND summary_versions.unit_key = topology_versions.crate_key
                  AND summary_versions.valid_until IS NULL
                 JOIN resolution_unit_summaries AS summaries
                   ON summaries.summary_id = summary_versions.summary_id
                 WHERE topology_versions.lang = 'rust'
                   AND topology_versions.valid_until IS NULL
                   AND topology.target_kind = 'lib'
                   AND summaries.publication_state = 'complete'
                 ORDER BY topology.crate_name",
            )
            .unwrap();
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .unwrap()
            .map(|row| {
                let (name, summary_id, output_digest) = row.unwrap();
                (name, (summary_id, output_digest))
            })
            .collect()
    }

    fn changed_summaries(
        before: &BTreeMap<String, (i64, Vec<u8>)>,
        after: &BTreeMap<String, (i64, Vec<u8>)>,
    ) -> BTreeSet<String> {
        assert_eq!(
            before.keys().collect::<Vec<_>>(),
            after.keys().collect::<Vec<_>>()
        );
        before
            .iter()
            .filter(|(name, (summary_id, _))| after[*name].0 != *summary_id)
            .map(|(name, _)| name.clone())
            .collect()
    }

    #[test]
    fn body_edit_stops_at_rust_output_digest_and_public_item_reaches_direct_dependents() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers = [\"base\", \"alpha\", \"beta\", \"leaf\"]\nresolver = \"2\"\n",
            )
            .file(
                "base/Cargo.toml",
                "[package]\nname = \"base_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("base/src/lib.rs", "pub fn first() -> u32 { 1 }\n")
            .file(
                "alpha/Cargo.toml",
                "[package]\nname = \"alpha_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nbase_unit = { path = \"../base\" }\n",
            )
            .file(
                "alpha/src/lib.rs",
                "pub fn alpha() -> u32 { base_unit::first() }\n",
            )
            .file(
                "beta/Cargo.toml",
                "[package]\nname = \"beta_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nbase_unit = { path = \"../base\" }\n",
            )
            .file(
                "beta/src/lib.rs",
                "pub fn beta() -> u32 { base_unit::first() }\n",
            )
            .file(
                "leaf/Cargo.toml",
                "[package]\nname = \"leaf_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nalpha_unit = { path = \"../alpha\" }\n",
            )
            .file(
                "leaf/src/lib.rs",
                "pub fn leaf() -> u32 { alpha_unit::alpha() }\n",
            )
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let initial = live_summaries(&workspace);
        assert_eq!(initial.len(), 4, "live Rust summaries: {initial:?}");

        let base_path = fixture.root().join("base/src/lib.rs");
        let body_edit = "pub fn first() -> u32 { 2 }\n";
        std::fs::write(&base_path, body_edit).unwrap();
        let body_update = workspace.update(&BTreeSet::from([fixture.file("base/src/lib.rs")]));
        let after_body = live_summaries(&body_update);
        assert_eq!(
            changed_summaries(&initial, &after_body),
            BTreeSet::from(["base_unit".to_owned()]),
            "body-only edit should derive just its Rust crate"
        );
        assert_eq!(
            initial["base_unit"].1, after_body["base_unit"].1,
            "body-only edit must preserve the crate output digest"
        );

        let public_item_edit = format!("{body_edit}pub fn second() -> u32 {{ 2 }}\n");
        std::fs::write(&base_path, public_item_edit).unwrap();
        let public_update = body_update.update(&BTreeSet::from([fixture.file("base/src/lib.rs")]));
        let after_public_item = live_summaries(&public_update);
        assert_eq!(
            changed_summaries(&after_body, &after_public_item),
            BTreeSet::from([
                "alpha_unit".to_owned(),
                "base_unit".to_owned(),
                "beta_unit".to_owned(),
            ]),
            "an exported item should derive its crate and direct dependents only"
        );
        assert_eq!(
            after_body["alpha_unit"].1, after_public_item["alpha_unit"].1,
            "an importing crate keeps its output digest"
        );
        assert_eq!(
            after_body["beta_unit"].1, after_public_item["beta_unit"].1,
            "an importing crate keeps its output digest"
        );
    }

    #[test]
    #[ignore = "operator measurement: needs BIFROST_RUST_UNIT_SUMMARY_CORPUS, a writable Rust repository copy"]
    fn measure_rust_unit_summary_reconcile_on_a_corpus() {
        use std::sync::Arc;
        use std::time::Instant;

        use crate::analyzer::{Language, ProjectFile, TestProject};

        let root = std::path::PathBuf::from(
            std::env::var("BIFROST_RUST_UNIT_SUMMARY_CORPUS")
                .expect("BIFROST_RUST_UNIT_SUMMARY_CORPUS names a writable Rust repository copy"),
        )
        .canonicalize()
        .unwrap();
        let project: Arc<dyn crate::analyzer::Project> =
            Arc::new(TestProject::new(root.clone(), Language::Rust));
        let started = Instant::now();
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("build the real Rust workspace");
        eprintln!("MEASURE Rust fresh build {:?}", started.elapsed());

        let report_rows = |label: &str, workspace: &WorkspaceAnalyzer| {
            let store = workspace.store().unwrap();
            let conn = store.read_conn().unwrap();
            let mut statement = conn
                .prepare(
                    "SELECT topology.crate_name, summaries.summary_id,
                       2
                       + (SELECT count(*) FROM resolution_unit_summary_members AS members
                          WHERE members.summary_id = summaries.summary_id)
                       + (SELECT count(*) FROM resolution_unit_summary_dependencies AS dependencies
                          WHERE dependencies.summary_id = summaries.summary_id)
                       + (SELECT count(*) FROM resolution_unit_summary_reads AS reads
                          WHERE reads.summary_id = summaries.summary_id)
                       + (SELECT count(*) FROM resolution_unit_summary_exports AS exports
                          WHERE exports.summary_id = summaries.summary_id)
                       + (SELECT count(*) FROM resolution_unit_summary_imports AS imports
                          WHERE imports.summary_id = summaries.summary_id)
                       + (SELECT count(*) FROM resolution_unit_summary_gaps AS gaps
                          WHERE gaps.summary_id = summaries.summary_id)
                     FROM rust_crate_versions AS topology_versions
                     JOIN rust_crate_topologies AS topology USING(topology_id)
                     JOIN resolution_unit_summary_versions AS summary_versions
                       ON summary_versions.workspace_id = topology_versions.workspace_id
                      AND summary_versions.lang = topology_versions.lang
                      AND summary_versions.generation = topology_versions.generation
                      AND summary_versions.unit_key = topology_versions.crate_key
                      AND summary_versions.valid_until IS NULL
                     JOIN resolution_unit_summaries AS summaries
                       ON summaries.summary_id = summary_versions.summary_id
                     WHERE topology_versions.lang = 'rust'
                       AND topology_versions.valid_until IS NULL
                       AND topology.publication_state = 'complete'
                     ORDER BY topology.crate_name, topology.target_kind",
                )
                .unwrap();
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            eprintln!("MEASURE {label} summary rows per crate: {rows:?}");
            rows
        };

        let fresh = report_rows("fresh", &workspace);
        assert!(
            !fresh.is_empty(),
            "the Rust workspace published no summaries"
        );
        let store = workspace.store().unwrap();
        let member = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT rel_path FROM resolution_unit_summary_members
                 ORDER BY rel_path LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        let path = root.join(&member);
        let mut source = std::fs::read_to_string(&path).unwrap();
        source.push_str("\n// Rust unit summary measurement edit\n");
        std::fs::write(&path, source).unwrap();
        let started = Instant::now();
        let updated = workspace.update(&BTreeSet::from([ProjectFile::new(
            root.clone(),
            std::path::PathBuf::from(&member),
        )]));
        eprintln!(
            "MEASURE Rust one-file edit/update {:?} ({member})",
            started.elapsed()
        );
        let after = report_rows("one-file-edit", &updated);
        let fresh_summary_ids = fresh
            .iter()
            .map(|(_, summary_id, _)| *summary_id)
            .collect::<BTreeSet<_>>();
        let derived = after
            .iter()
            .filter(|(_, summary_id, _)| !fresh_summary_ids.contains(summary_id))
            .map(|(crate_name, summary_id, rows)| (crate_name.clone(), *summary_id, *rows))
            .collect::<Vec<_>>();
        eprintln!("MEASURE Rust one-file edit derived crate summaries: {derived:?}");
        assert_eq!(
            derived.len(),
            1,
            "a body-only edit should derive its crate summary and no dependents"
        );
    }
}
