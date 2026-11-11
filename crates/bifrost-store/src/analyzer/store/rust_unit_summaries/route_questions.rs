use super::{RUST_UNIT_SUMMARY_DERIVATION_VERSION, check_rust_summary_selection};
use crate::analyzer::store::{self, AnalyzerStore, Result, StoreError, WorkspaceSnapshotId};
use rusqlite::{Connection, OptionalExtension, params};

/// Content identity of the selected live Rust unit and its route-bearing version.
/// A version that exists but is not publishable is unknown, not absent.
pub fn rust_unit_inputs(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    unit: &[u8; 32],
) -> Result<Option<([u8; 32], bool)>> {
    check(c, s)?;
    let row = c
        .query_row(
            r#"SELECT x.summary_digest,t.topology_digest,m.rel_path,m.blob_oid,
                x.complete,x.publication_state,x.derivation_version,e.lang,
                rv.manifest_file_version_id,x.unit_kind,t.publication_state,t.broad_complete,
                t.producer_epoch=(SELECT epoch FROM main.analysis_epochs WHERE lang='rust')
         FROM temp.selected_workspace_revisions selected
         JOIN main.resolution_unit_summary_versions v
           ON v.workspace_id=selected.workspace_id AND v.lang=selected.lang
          AND v.generation=selected.generation AND v.unit_key=?2
          AND v.valid_from<=selected.revision
          AND (v.valid_until IS NULL OR selected.revision<v.valid_until)
         JOIN main.resolution_unit_summaries x ON x.summary_id=v.summary_id
         LEFT JOIN main.resolution_producer_epochs e
           ON e.lang=v.lang AND e.producer_epoch=x.producer_epoch
         LEFT JOIN main.rust_resolution_unit_summary_versions rv
           ON rv.workspace_id=v.workspace_id AND rv.lang=v.lang
          AND rv.generation=v.generation AND rv.unit_key=v.unit_key
          AND rv.valid_from=v.valid_from AND rv.summary_id=v.summary_id
         LEFT JOIN main.rust_crate_topologies t ON t.topology_id=rv.topology_id
         LEFT JOIN main.workspace_file_versions m ON m.file_version_id=rv.manifest_file_version_id
           AND m.workspace_id=v.workspace_id AND m.lang=v.lang AND m.generation=v.generation
           AND m.valid_from<=selected.revision
           AND (m.valid_until IS NULL OR selected.revision<m.valid_until)
         WHERE selected.lang='rust' AND selected.workspace_id=?1"#,
            params![s.workspace_id.as_str(), unit.as_slice()],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Option<Vec<u8>>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, bool>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, Option<String>>(7)?,
                    r.get::<_, Option<i64>>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, Option<String>>(10)?,
                    r.get::<_, Option<bool>>(11)?,
                    r.get::<_, Option<bool>>(12)?,
                ))
            },
        )
        .optional()?;
    let Some((
        summary,
        topology,
        path,
        oid,
        complete,
        state,
        version,
        epoch,
        manifest_id,
        kind,
        topology_state,
        inventory_complete,
        topology_current,
    )) = row
    else {
        return Ok(None);
    };
    if state != "complete"
        || kind != "rust_crate"
        || version != RUST_UNIT_SUMMARY_DERIVATION_VERSION
        || epoch.is_none()
        || topology.is_none()
        || topology_state.as_deref() != Some("complete")
        || inventory_complete.is_none()
        || topology_current != Some(true)
        || (manifest_id.is_some() != path.is_some())
        || (manifest_id.is_some() != oid.is_some())
    {
        return Err(StoreError::corrupt(format!(
            "Rust unit {unit:?} has an unpublished or stale selected summary"
        )));
    }
    let mut hash = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
        b"derivation:rust_unit_inputs:v1",
    );
    hash.field("summary", &summary);
    hash.field("complete", &[u8::from(complete)]);
    hash.field("topology", topology.as_ref().unwrap());
    hash.field(
        "inventory-complete",
        &[u8::from(inventory_complete.unwrap())],
    );
    match (path, oid) {
        (Some(path), Some(oid)) => {
            hash.field("manifest-present", &[1]);
            hash.field("manifest-path", path.as_bytes());
            hash.field("manifest-oid", oid.as_bytes());
        }
        (None, None) => hash.field("manifest-present", &[0]),
        _ => unreachable!("manifest presence checked above"),
    }
    let package_rows = AnalyzerStore::rust_summary_package_rows_for_unit(c, s, unit)?;
    let cargo_rows = AnalyzerStore::rust_summary_cargo_route_rows_for_unit(c, s, unit)?;
    if package_rows.is_empty() || cargo_rows.is_empty() {
        return Err(StoreError::corrupt(format!(
            "Rust unit {unit:?} has filtered or incomplete selected route rows"
        )));
    }
    let mut package_content = package_rows
        .iter()
        .map(|r| {
            serde_json::to_vec(&(
                &r.rel_path,
                &r.package_components,
                &r.crate_name,
                &r.target_kind,
                &r.blob_oid,
                r.is_root_member,
            ))
            .expect("package row fields serialize")
        })
        .collect::<Vec<_>>();
    package_content.sort_unstable();
    hash.sequence("package-rows", &package_content, |h, row| h.value(row));
    let mut cargo_content = cargo_rows
        .iter()
        .map(|r| {
            serde_json::to_vec(&(
                r.unit_key,
                &r.manifest_rel_path,
                &r.target_kind,
                &r.crate_name,
                &r.edition,
                r.development_capable,
                &r.root_rel_path,
                &r.root_package_components,
                &r.dependency_extern_name,
                &r.dependency_kind,
                &r.dependency_boundary,
                &r.dependency_unit_key,
                &r.dependency_target_kind,
                &r.dependency_root_rel_path,
                &r.dependency_root_package_components,
                &r.dependency_manifest_rel_path,
            ))
            .expect("Cargo route row fields serialize")
        })
        .collect::<Vec<_>>();
    cargo_content.sort_unstable();
    hash.sequence("cargo-rows", &cargo_content, |h, row| h.value(row));
    let placements = rust_broad_placement_rows(c, s, unit)?;
    let mut placement_content = placements
        .iter()
        .map(|r| serde_json::to_vec(r).expect("placement serializes"))
        .collect::<Vec<_>>();
    placement_content.sort_unstable();
    hash.sequence("broad-placements", &placement_content, |h, row| {
        h.value(row)
    });
    // Module facts are selected using this content key, never a reusable blob row id.
    hash.field("module-generation", &s.generation.0.to_be_bytes());
    hash.field("module-parse-variant", b"");
    Ok(Some((hash.finish(), inventory_complete.unwrap())))
}

const LIVE: &str = r#"WITH live AS (
 SELECT v.workspace_id,v.generation,v.summary_id,v.unit_key,rv.topology_id
 FROM temp.selected_workspace_revisions s
 JOIN main.resolution_unit_summary_versions v ON v.workspace_id=s.workspace_id AND v.lang=s.lang AND v.generation=s.generation
 JOIN main.resolution_unit_summaries x ON x.summary_id=v.summary_id
 JOIN main.resolution_producer_epochs e ON e.lang=v.lang AND e.producer_epoch=x.producer_epoch
 JOIN main.rust_resolution_unit_summary_versions rv ON rv.workspace_id=v.workspace_id AND rv.lang=v.lang AND rv.generation=v.generation AND rv.unit_key=v.unit_key AND rv.valid_from=v.valid_from AND rv.summary_id=v.summary_id
 WHERE s.lang='rust' AND v.valid_from<=s.revision AND (v.valid_until IS NULL OR s.revision<v.valid_until)
 AND x.lang='rust' AND x.unit_kind='rust_crate' AND x.publication_state='complete' AND x.derivation_version=?1
) "#;
fn check(c: &Connection, s: &WorkspaceSnapshotId) -> Result<()> {
    store::require_current_generation(c, "rust", s.generation)?;
    check_rust_summary_selection(c, s)
}
fn key(v: Vec<u8>) -> Result<[u8; 32]> {
    v.try_into()
        .map_err(|v: Vec<u8>| StoreError::corrupt(format!("unit key has {} bytes", v.len())))
}

#[derive(Clone, Copy)]
enum RouteQuestion {
    Dependents,
    FileUnits,
    BroadFileUnits,
    PackageUnits,
    CrateNameUnits,
}

fn route_sql(question: RouteQuestion) -> String {
    match question {
        RouteQuestion::Dependents => format!(
            "{LIVE} SELECT live.unit_key,n.role FROM main.resolution_unit_summary_dependencies d INDEXED BY resolution_unit_summary_dependencies_unit JOIN live ON live.summary_id=d.summary_id JOIN main.resolution_unit_summary_dependency_names n ON n.summary_id=d.summary_id AND n.dependency_ordinal=d.dependency_ordinal WHERE d.dependency_unit_key=?2 AND d.boundary='workspace' ORDER BY live.unit_key,n.role"
        ),
        RouteQuestion::FileUnits => format!(
            "{LIVE} SELECT DISTINCT live.unit_key FROM main.resolution_unit_summary_members m INDEXED BY resolution_unit_summary_members_path JOIN live ON live.summary_id=m.summary_id JOIN temp.selected_workspace_file_versions f ON f.workspace_id=live.workspace_id AND f.lang='rust' AND f.generation=live.generation AND f.rel_path=m.rel_path JOIN main.blobs b ON b.id=m.blob_id AND b.blob_oid=f.blob_oid AND b.lang=f.lang AND b.generation=f.generation WHERE m.rel_path=?2 ORDER BY live.unit_key"
        ),
        // Detached summaries describe source ownership for other consumers;
        // they are not Cargo roots in the whole route index.
        RouteQuestion::BroadFileUnits => format!(
            "{LIVE} SELECT DISTINCT live.unit_key FROM live JOIN temp.selected_workspace_revisions sel ON sel.workspace_id=live.workspace_id AND sel.lang='rust' AND sel.generation=live.generation JOIN main.rust_crate_versions cv ON cv.workspace_id=live.workspace_id AND cv.lang='rust' AND cv.generation=live.generation AND cv.crate_key=live.unit_key AND cv.topology_id=live.topology_id AND cv.valid_from<=sel.revision AND (cv.valid_until IS NULL OR sel.revision<cv.valid_until) JOIN main.rust_crate_topologies t ON t.topology_id=cv.topology_id AND t.publication_state='complete' AND t.producer_epoch=(SELECT epoch FROM main.analysis_epochs WHERE lang='rust') AND t.target_kind<>'detached' JOIN main.rust_crate_broad_placements p ON p.topology_id=t.topology_id WHERE p.rel_path=?2 ORDER BY live.unit_key"
        ),
        RouteQuestion::PackageUnits => format!(
            "{LIVE} SELECT live.unit_key,n.member_ordinal FROM main.rust_resolution_unit_summary_file_naming n INDEXED BY rust_resolution_unit_summary_file_naming_package JOIN live ON live.summary_id=n.summary_id JOIN main.resolution_unit_summary_members m ON m.summary_id=n.summary_id AND m.member_ordinal=n.member_ordinal JOIN temp.selected_workspace_file_versions f ON f.workspace_id=live.workspace_id AND f.lang='rust' AND f.generation=live.generation AND f.rel_path=m.rel_path JOIN main.blobs b ON b.id=m.blob_id AND b.blob_oid=f.blob_oid AND b.lang=f.lang AND b.generation=f.generation WHERE n.package_path=?2 ORDER BY live.unit_key,n.member_ordinal"
        ),
        RouteQuestion::CrateNameUnits => format!(
            r#"{}, candidate AS (
 SELECT live.unit_key,t.target_kind,root.rel_path FROM main.rust_resolution_unit_summary_contexts t INDEXED BY rust_resolution_unit_summary_contexts_name_kind
 CROSS JOIN live ON live.summary_id=t.summary_id JOIN main.resolution_unit_summary_placements p ON p.summary_id=live.summary_id AND p.container_path=''
 JOIN main.resolution_unit_summary_members root ON root.summary_id=p.summary_id AND root.member_ordinal=p.member_ordinal
 JOIN temp.selected_workspace_file_versions f ON f.workspace_id=live.workspace_id AND f.lang='rust' AND f.generation=live.generation AND f.rel_path=root.rel_path
 JOIN main.blobs b ON b.id=root.blob_id AND b.blob_oid=f.blob_oid AND b.lang=f.lang AND b.generation=f.generation
 WHERE t.crate_name=?2 AND t.target_kind IN ('lib','bin')
 UNION
 SELECT child.unit_key,t.target_kind,root.rel_path FROM main.resolution_unit_summary_dependency_names n INDEXED BY resolution_unit_summary_dependency_names_name
 CROSS JOIN main.resolution_unit_summary_dependencies d ON d.summary_id=n.summary_id AND d.dependency_ordinal=n.dependency_ordinal AND d.boundary='workspace'
 CROSS JOIN live parent ON parent.summary_id=n.summary_id CROSS JOIN live child ON child.workspace_id=parent.workspace_id AND child.generation=parent.generation AND child.unit_key=d.dependency_unit_key
 JOIN main.rust_resolution_unit_summary_contexts t ON t.summary_id=child.summary_id
 JOIN main.resolution_unit_summary_placements p ON p.summary_id=child.summary_id AND p.container_path=''
 JOIN main.resolution_unit_summary_members root ON root.summary_id=p.summary_id AND root.member_ordinal=p.member_ordinal
 JOIN temp.selected_workspace_file_versions f ON f.workspace_id=child.workspace_id AND f.lang='rust' AND f.generation=child.generation AND f.rel_path=root.rel_path
 JOIN main.blobs b ON b.id=root.blob_id AND b.blob_oid=f.blob_oid AND b.lang=f.lang AND b.generation=f.generation
 WHERE n.name=?2 AND t.target_kind IN ('lib','bin')
) SELECT unit_key,target_kind,rel_path FROM (
  SELECT unit_key,target_kind,rel_path,
         ROW_NUMBER() OVER (PARTITION BY rel_path,target_kind ORDER BY unit_key) AS rn
  FROM candidate
) WHERE rn=1 ORDER BY rel_path,unit_key,target_kind"#,
            live_not_materialized()
        ),
    }
}

// The crate-name question seeks its candidates by name and then validates each
// one against `live`. It references `live` more than once, so SQLite would
// materialize it, which builds a row for every live unit in the workspace.
// NOT MATERIALIZED keeps `live` a keyed lookup after the candidate seek.
fn live_not_materialized() -> String {
    let live = LIVE.replacen("live AS (", "live AS NOT MATERIALIZED (", 1);
    assert_ne!(live, LIVE, "LIVE no longer starts its CTE with `live AS (`");
    live
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn rust_crate_name_units_sql() -> String {
    route_sql(RouteQuestion::CrateNameUnits)
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn explain_rust_route_questions(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    target: &[u8; 32],
    path: &str,
    name: &str,
    package: &str,
) -> Result<Vec<(String, Vec<String>)>> {
    check(c, s)?;
    let mut plans = Vec::new();
    for (kind, label, value) in [
        (
            RouteQuestion::Dependents,
            "dependents",
            rusqlite::types::Value::Blob(target.to_vec()),
        ),
        (
            RouteQuestion::FileUnits,
            "file_units",
            rusqlite::types::Value::Text(path.to_string()),
        ),
        (
            RouteQuestion::CrateNameUnits,
            "crate_name_units",
            rusqlite::types::Value::Text(name.to_string()),
        ),
        (
            RouteQuestion::PackageUnits,
            "package_units",
            rusqlite::types::Value::Text(package.to_string()),
        ),
    ] {
        let query = format!("EXPLAIN QUERY PLAN {}", route_sql(kind));
        let details = c
            .prepare(&query)?
            .query_map(params![RUST_UNIT_SUMMARY_DERIVATION_VERSION, value], |r| {
                r.get::<_, String>(3)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        plans.push((label.to_string(), details));
    }
    Ok(plans)
}

/// Selected Rust crate membership. A published summary with incomplete
/// topology gives a partial answer; missing publication leaves it unavailable.
pub enum RustSelectedUnitsPublication {
    Published { partial: Vec<[u8; 32]> },
    Unpublished(Vec<[u8; 32]>),
}

pub fn rust_selected_units_known(
    c: &Connection,
    s: &WorkspaceSnapshotId,
) -> Result<RustSelectedUnitsPublication> {
    check(c, s)?;
    let rows = c
        .prepare_cached(
            r#"SELECT cv.crate_key,
 (SELECT t.broad_complete FROM main.rust_crate_topologies t
  WHERE t.topology_id=cv.topology_id AND t.publication_state='complete'
    AND t.producer_epoch=(SELECT epoch FROM main.analysis_epochs WHERE lang='rust')),
 EXISTS(
  SELECT 1 FROM main.resolution_unit_summary_versions v
  JOIN main.resolution_unit_summaries x ON x.summary_id=v.summary_id
  JOIN main.resolution_producer_epochs e ON e.lang=v.lang AND e.producer_epoch=x.producer_epoch
  JOIN main.rust_resolution_unit_summary_versions rv ON rv.workspace_id=v.workspace_id
   AND rv.lang=v.lang AND rv.generation=v.generation AND rv.unit_key=v.unit_key
   AND rv.valid_from=v.valid_from AND rv.summary_id=v.summary_id
   AND rv.topology_id=cv.topology_id
  WHERE v.workspace_id=cv.workspace_id AND v.lang=cv.lang AND v.generation=cv.generation
   AND v.unit_key=cv.crate_key AND v.valid_from<=sel.revision
   AND (v.valid_until IS NULL OR sel.revision<v.valid_until)
   AND x.lang='rust' AND x.unit_kind='rust_crate' AND x.publication_state='complete'
   AND x.derivation_version=?2)
 FROM temp.selected_workspace_revisions sel
 JOIN main.rust_crate_versions cv ON cv.workspace_id=sel.workspace_id AND cv.lang=sel.lang
  AND cv.generation=sel.generation AND cv.valid_from<=sel.revision
  AND (cv.valid_until IS NULL OR sel.revision<cv.valid_until)
 WHERE sel.lang='rust' AND sel.workspace_id=?1"#,
        )?
        .query_map(
            params![
                s.workspace_id.as_str(),
                RUST_UNIT_SUMMARY_DERIVATION_VERSION
            ],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Option<bool>>(1)?,
                    r.get::<_, bool>(2)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut partial = Vec::new();
    let mut unpublished = Vec::new();
    for (unit, inventory, published) in rows {
        let unit = key(unit)?;
        if !published || inventory.is_none() {
            unpublished.push(unit);
        } else if inventory == Some(false) {
            partial.push(unit);
        }
    }
    unpublished.sort_unstable();
    if !unpublished.is_empty() {
        return Ok(RustSelectedUnitsPublication::Unpublished(unpublished));
    }
    partial.sort_unstable();
    Ok(RustSelectedUnitsPublication::Published { partial })
}

pub fn rust_unit_dependents(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    target: &[u8; 32],
) -> Result<Vec<([u8; 32], String)>> {
    check(c, s)?;
    let sql = route_sql(RouteQuestion::Dependents);
    let rows = c
        .prepare_cached(&sql)?
        .query_map(
            params![RUST_UNIT_SUMMARY_DERIVATION_VERSION, target.as_slice()],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?)),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter().map(|(k, v)| Ok((key(k)?, v))).collect()
}

pub fn rust_file_units(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    path: &str,
) -> Result<Vec<[u8; 32]>> {
    check(c, s)?;
    let sql = route_sql(RouteQuestion::FileUnits);
    let rows = c
        .prepare_cached(&sql)?
        .query_map(params![RUST_UNIT_SUMMARY_DERIVATION_VERSION, path], |r| {
            r.get::<_, Vec<u8>>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter().map(key).collect()
}

pub fn rust_broad_file_units(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    path: &str,
) -> Result<Vec<[u8; 32]>> {
    check(c, s)?;
    let rows = c
        .prepare_cached(&route_sql(RouteQuestion::BroadFileUnits))?
        .query_map(params![RUST_UNIT_SUMMARY_DERIVATION_VERSION, path,], |r| {
            r.get::<_, Vec<u8>>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter().map(key).collect()
}

/// Every placement for the selected current topology, including inactive routes.
/// The returned tuple binds route, mount site, activation, and source content.
#[allow(clippy::type_complexity)]
pub fn rust_broad_placement_rows(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    unit: &[u8; 32],
) -> Result<
    Vec<(
        String,
        String,
        String,
        Option<i64>,
        Option<i64>,
        Option<String>,
        i64,
        Option<String>,
    )>,
> {
    check(c, s)?;
    let sql = format!(
        "{LIVE} SELECT p.rel_path,p.module_path,p.placement,p.mount_blob_id,p.mount_start_byte,mount.blob_oid,p.activation,f.blob_oid FROM live JOIN temp.selected_workspace_revisions sel ON sel.workspace_id=live.workspace_id AND sel.lang='rust' AND sel.generation=live.generation JOIN main.rust_crate_versions cv ON cv.workspace_id=live.workspace_id AND cv.lang='rust' AND cv.generation=live.generation AND cv.crate_key=live.unit_key AND cv.topology_id=live.topology_id AND cv.valid_from<=sel.revision AND (cv.valid_until IS NULL OR sel.revision<cv.valid_until) JOIN main.rust_crate_topologies t ON t.topology_id=cv.topology_id AND t.publication_state='complete' AND t.producer_epoch=(SELECT epoch FROM main.analysis_epochs WHERE lang='rust') JOIN main.rust_crate_broad_placements p ON p.topology_id=t.topology_id LEFT JOIN main.blobs mount ON mount.id=p.mount_blob_id LEFT JOIN temp.selected_workspace_file_versions f ON f.workspace_id=live.workspace_id AND f.lang='rust' AND f.generation=live.generation AND f.rel_path=p.rel_path WHERE live.unit_key=?2 ORDER BY p.rel_path,p.module_path,p.placement,p.mount_blob_id,p.mount_start_byte,p.activation"
    );
    let rows = c
        .prepare_cached(&sql)?
        .query_map(
            params![RUST_UNIT_SUMMARY_DERIVATION_VERSION, unit.as_slice(),],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.is_empty() {
        return Err(StoreError::corrupt(format!(
            "selected Rust unit {unit:?} has no current broad placements"
        )));
    }
    Ok(rows)
}

pub fn rust_package_units(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    package: &str,
) -> Result<Vec<([u8; 32], u32)>> {
    check(c, s)?;
    let sql = route_sql(RouteQuestion::PackageUnits);
    let rows = c
        .prepare_cached(&sql)?
        .query_map(
            params![RUST_UNIT_SUMMARY_DERIVATION_VERSION, package],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, u32>(1)?)),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter().map(|(k, v)| Ok((key(k)?, v))).collect()
}

/// One selected unit's package rows and whether its member listing is
/// complete, read from the unit's summary rows alone: no module facts and no
/// route rows. `None` when the unit is not live at the selection.
pub fn rust_unit_package_rows(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    unit: &[u8; 32],
) -> Result<Option<(Vec<super::RustSummaryPackageRow>, bool)>> {
    check(c, s)?;
    let sql = format!(
        "{LIVE} SELECT t.broad_complete FROM live LEFT JOIN main.rust_crate_topologies t ON t.topology_id=live.topology_id AND t.publication_state='complete' AND t.producer_epoch=(SELECT epoch FROM main.analysis_epochs WHERE lang='rust') WHERE live.unit_key=?2"
    );
    let complete = c
        .prepare_cached(&sql)?
        .query_row(
            params![RUST_UNIT_SUMMARY_DERIVATION_VERSION, unit.as_slice()],
            |r| r.get::<_, Option<bool>>(0),
        )
        .optional()?;
    let Some(complete) = complete else {
        return Ok(None);
    };
    let complete = complete.ok_or_else(|| {
        StoreError::corrupt(format!(
            "Rust unit {unit:?} has no current published inventory completeness"
        ))
    })?;
    let rows = AnalyzerStore::rust_summary_package_rows_for_unit(c, s, unit)?;
    Ok(Some((rows, complete)))
}

/// The lib and bin crate roots under a crate name: one row per root path and
/// target kind, so a library and a binary that share a name and a root file
/// both stay visible and the caller selects the kinds it needs.
pub fn rust_crate_name_units(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    name: &str,
) -> Result<Vec<([u8; 32], String, String)>> {
    check(c, s)?;
    let sql = route_sql(RouteQuestion::CrateNameUnits);
    let rows = c
        .prepare_cached(&sql)?
        .query_map(params![RUST_UNIT_SUMMARY_DERIVATION_VERSION, name], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter()
        .map(|(k, t, p)| Ok((key(k)?, t, p)))
        .collect()
}
