use super::{check_rust_summary_selection, rust_unit_summary_derivation_identity};
use crate::analyzer::store::resolution_operation::rust_crate_access::RustBlobActivity;
use crate::analyzer::store::{self, AnalyzerStore, Result, StoreError, WorkspaceSnapshotId};
use rusqlite::{Connection, OptionalExtension, params};

/// Exact selected overlay-added edge membership check for a target file.
pub const RUST_ADDED_EDGE_TARGET_SQL: &str =
    "SELECT EXISTS(SELECT 1 FROM temp.selected_rust_added_edges WHERE target_path=?1)";

/// Whether the selected overlay mounts `path` through an added module or include edge.
pub fn rust_added_edge_targets_path(c: &Connection, path: &str) -> Result<bool> {
    Ok(c.query_row(RUST_ADDED_EDGE_TARGET_SQL, [path], |row| row.get(0))?)
}

// A transcript of the actual hashing calls is available only to engine tests.
#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static INPUT_TRACE: std::cell::RefCell<Vec<(String, Vec<u8>)>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(any(test, feature = "test-support"))]
pub fn take_rust_unit_inputs_trace() -> Vec<(String, Vec<u8>)> {
    INPUT_TRACE.with(|trace| std::mem::take(&mut *trace.borrow_mut()))
}

struct InputHasher(brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher);
impl InputHasher {
    fn field(&mut self, name: &str, value: &[u8]) {
        #[cfg(any(test, feature = "test-support"))]
        INPUT_TRACE.with(|trace| trace.borrow_mut().push((name.to_owned(), value.to_vec())));
        self.0.field(name, value);
    }
    fn sequence(&mut self, name: &str, values: &[Vec<u8>]) {
        #[cfg(any(test, feature = "test-support"))]
        INPUT_TRACE.with(|trace| {
            let mut trace = trace.borrow_mut();
            trace.push((format!("{name}.len"), values.len().to_string().into_bytes()));
            for value in values {
                trace.push((name.to_owned(), value.clone()));
            }
        });
        self.0.sequence(name, values, |hash, row| hash.value(row));
    }
}

/// Content identity of the selected live Rust unit and its route-bearing version.
/// A version that exists but is not publishable is unknown, not absent.
pub fn rust_unit_inputs(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    unit: &[u8; 32],
) -> Result<Option<([u8; 32], bool)>> {
    use super::RustUnitAvailability;
    match super::rust_unit_availability(c, s, unit)? {
        Some(RustUnitAvailability::Published { .. }) => published_unit_inputs(c, s, unit),
        Some(RustUnitAvailability::IntentionallyUnavailable { evidence, .. }) => {
            Ok(Some((evidence, false)))
        }
        // A stale unit (after a derivation change, before reconcile rewrites it)
        // has no content identity to report, and it may be an unavailable target
        // with no summary row at all, so this point read fails. Stale is the
        // normal upgrade window, not a store fault. Only the membership
        // questions report a stale unit as partial.
        Some(RustUnitAvailability::Stale) => Err(StoreError::new(format!(
            "stale selected Rust unit {unit:02x?}: derivation or reconcile pending"
        ))),
        Some(RustUnitAvailability::Unpublished) => Err(StoreError::corrupt(format!(
            "unpublished selected Rust unit {unit:02x?}"
        ))),
        None => Ok(None),
    }
}

pub(super) fn published_unit_inputs(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    unit: &[u8; 32],
) -> Result<Option<([u8; 32], bool)>> {
    check(c, s)?;
    let row = c
        .query_row(
            r#"SELECT x.summary_digest,x.summary_digest,m.rel_path,m.blob_oid,
                x.complete,x.publication_state,x.derivation_identity,e.lang,
                cv.manifest_file_version_id,x.unit_kind,t.publication_state,ctx.broad_complete,
                (t.producer_epoch=(SELECT epoch FROM main.analysis_epochs WHERE lang='rust') AND cv.topology_id IS NOT NULL)
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
         LEFT JOIN main.rust_crate_versions cv
           ON cv.workspace_id=v.workspace_id AND cv.lang=v.lang
          AND cv.generation=v.generation AND cv.crate_key=v.unit_key
          AND cv.topology_id=rv.topology_id AND cv.valid_from<=selected.revision
          AND (cv.valid_until IS NULL OR selected.revision<cv.valid_until)
         LEFT JOIN main.rust_resolution_unit_summary_contexts ctx ON ctx.summary_id=x.summary_id
         LEFT JOIN main.rust_crate_topologies t ON t.topology_id=rv.topology_id
         LEFT JOIN main.workspace_file_versions m ON m.file_version_id=cv.manifest_file_version_id
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
                    r.get::<_, [u8; 32]>(6)?,
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
        consumed_summary,
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
        || version != rust_unit_summary_derivation_identity()
        || epoch.is_none()
        || consumed_summary.is_none()
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
    #[cfg(any(test, feature = "test-support"))]
    INPUT_TRACE.with(|trace| trace.borrow_mut().clear());
    let mut hash = InputHasher(
        brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
            b"derivation:rust_unit_inputs:v3",
        ),
    );
    hash.field("summary", &summary);
    hash.field("complete", &[u8::from(complete)]);
    hash.field("consumed-summary", consumed_summary.as_ref().unwrap());
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
    // The route derivations read the selected content, so the token must see
    // the selected blob of each member (an overlay moves it) and whether the
    // selection still places the member.
    let package_rows = AnalyzerStore::rust_selected_package_rows_for_unit(c, s, unit)?;
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
                r.unplaced_by_selection,
            ))
            .expect("package row fields serialize")
        })
        .collect::<Vec<_>>();
    package_content.sort_unstable();
    hash.sequence("package-rows", &package_content);
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
    hash.sequence("cargo-rows", &cargo_content);
    let placements = rust_broad_placement_rows(c, s, unit)?;
    let mut placement_content = placements
        .iter()
        .map(|r| serde_json::to_vec(r).expect("placement serializes"))
        .collect::<Vec<_>>();
    placement_content.sort_unstable();
    hash.sequence("broad-placements", &placement_content);
    // Route composition also reads activity derived from the placement gaps.
    // Broad placement rows alone do not cover those answers: changing a gap's
    // path can change activity while the unit remains broadly incomplete.
    // Hash the decoded answers, not the gap JSON or its storage order.
    let activity_code = |activity| match activity {
        RustBlobActivity::Active => 1u8,
        RustBlobActivity::Inactive => 0,
        RustBlobActivity::Unknown => 2,
    };
    let mut file_activity = rust_unit_file_activity(c, s, unit)?
        .into_iter()
        .map(|(path, activity)| {
            let mut row = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
                b"rust-unit-input-file-activity:v1",
            );
            row.field("path", path.as_bytes());
            row.field("activity", &[activity_code(activity)]);
            row.finish().to_vec()
        })
        .collect::<Vec<_>>();
    file_activity.sort_unstable();
    hash.sequence("file-activity", &file_activity);
    let mut placement_activity = rust_unit_placement_activity(c, s, unit)?
        .into_iter()
        .map(|(path, module_path, activity)| {
            let mut row = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
                b"rust-unit-input-placement-activity:v1",
            );
            row.field("path", path.as_bytes());
            row.field("module", module_path.as_bytes());
            row.field("activity", &[activity_code(activity)]);
            row.finish().to_vec()
        })
        .collect::<Vec<_>>();
    placement_activity.sort_unstable();
    hash.sequence("placement-activity", &placement_activity);
    // Module facts are selected using this content key, never a reusable blob row id.
    hash.field("module-generation", &s.generation.0.to_be_bytes());
    hash.field("module-parse-variant", b"");
    Ok(Some((hash.0.finish(), inventory_complete.unwrap())))
}

const LIVE: &str = r#"WITH live AS (
 SELECT v.workspace_id,v.generation,v.summary_id,v.unit_key,rv.topology_id
 FROM temp.selected_workspace_revisions s
 JOIN main.resolution_unit_summary_versions v ON v.workspace_id=s.workspace_id AND v.lang=s.lang AND v.generation=s.generation
 JOIN main.resolution_unit_summaries x ON x.summary_id=v.summary_id
 JOIN main.resolution_producer_epochs e ON e.lang=v.lang AND e.producer_epoch=x.producer_epoch
 JOIN main.rust_resolution_unit_summary_versions rv ON rv.workspace_id=v.workspace_id AND rv.lang=v.lang AND rv.generation=v.generation AND rv.unit_key=v.unit_key AND rv.valid_from=v.valid_from AND rv.summary_id=v.summary_id
 WHERE s.lang='rust' AND v.valid_from<=s.revision AND (v.valid_until IS NULL OR s.revision<v.valid_until)
 AND x.lang='rust' AND x.unit_kind='rust_crate' AND x.publication_state='complete' AND x.derivation_identity=?1
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
            "{LIVE} SELECT DISTINCT live.unit_key,m.rel_path FROM main.resolution_unit_summary_members m INDEXED BY resolution_unit_summary_members_path JOIN live ON live.summary_id=m.summary_id JOIN temp.selected_workspace_file_versions f ON f.workspace_id=live.workspace_id AND f.lang='rust' AND f.generation=live.generation AND f.rel_path=m.rel_path CROSS JOIN temp.selected_unit_member_blobs attachment ON attachment.summary_id=m.summary_id AND attachment.member_ordinal=m.member_ordinal JOIN main.blobs b ON b.id=attachment.blob_id AND b.blob_oid=f.blob_oid AND b.lang=f.lang AND b.generation=f.generation WHERE m.rel_path IN (SELECT value FROM json_each(?2)) ORDER BY live.unit_key,m.rel_path"
        ),
        // Detached summaries describe source ownership for other consumers;
        // they are not Cargo roots in the whole route index.
        RouteQuestion::BroadFileUnits => format!(
            "{}, broad_paths AS NOT MATERIALIZED (SELECT m.summary_id,m.rel_path FROM main.resolution_unit_summary_members m INDEXED BY resolution_unit_summary_members_path CROSS JOIN main.resolution_unit_summary_placements p ON p.summary_id=m.summary_id AND p.member_ordinal=m.member_ordinal WHERE m.rel_path=?2 UNION ALL SELECT i.summary_id,i.rel_path FROM main.resolution_unit_summary_input_files i INDEXED BY resolution_unit_summary_input_files_path CROSS JOIN main.rust_resolution_unit_summary_inactive_placements p ON p.summary_id=i.summary_id AND p.input_file_ordinal=i.input_ordinal WHERE i.rel_path=?2) SELECT DISTINCT live.unit_key FROM broad_paths p CROSS JOIN live ON live.summary_id=p.summary_id JOIN temp.selected_workspace_revisions sel ON sel.workspace_id=live.workspace_id AND sel.lang='rust' AND sel.generation=live.generation JOIN main.rust_crate_versions cv ON cv.workspace_id=live.workspace_id AND cv.lang='rust' AND cv.generation=live.generation AND cv.crate_key=live.unit_key AND cv.topology_id=live.topology_id AND cv.valid_from<=sel.revision AND (cv.valid_until IS NULL OR sel.revision<cv.valid_until) JOIN main.rust_crate_topologies t ON t.topology_id=cv.topology_id AND t.publication_state='complete' AND t.producer_epoch=(SELECT epoch FROM main.analysis_epochs WHERE lang='rust') JOIN main.rust_resolution_unit_summary_contexts ctx ON ctx.summary_id=live.summary_id WHERE p.rel_path=?2 AND ctx.target_kind<>'detached' ORDER BY live.unit_key",
            live_not_materialized()
        ),
        RouteQuestion::PackageUnits => format!(
            "{LIVE} SELECT live.unit_key,n.member_ordinal FROM main.rust_resolution_unit_summary_file_naming n INDEXED BY rust_resolution_unit_summary_file_naming_package JOIN live ON live.summary_id=n.summary_id JOIN main.resolution_unit_summary_members m ON m.summary_id=n.summary_id AND m.member_ordinal=n.member_ordinal JOIN temp.selected_workspace_file_versions f ON f.workspace_id=live.workspace_id AND f.lang='rust' AND f.generation=live.generation AND f.rel_path=m.rel_path CROSS JOIN temp.selected_unit_member_blobs attachment ON attachment.summary_id=m.summary_id AND attachment.member_ordinal=m.member_ordinal JOIN main.blobs b ON b.id=attachment.blob_id AND b.blob_oid=f.blob_oid AND b.lang=f.lang AND b.generation=f.generation WHERE n.package_path=?2 ORDER BY live.unit_key,n.member_ordinal"
        ),
        RouteQuestion::CrateNameUnits => format!(
            r#"{}, candidate AS (
 SELECT live.unit_key,t.target_kind,root.rel_path FROM main.rust_resolution_unit_summary_contexts t INDEXED BY rust_resolution_unit_summary_contexts_name_kind
 CROSS JOIN live ON live.summary_id=t.summary_id JOIN main.resolution_unit_summary_placements p ON p.summary_id=live.summary_id AND p.container_path=''
 JOIN main.resolution_unit_summary_members root ON root.summary_id=p.summary_id AND root.member_ordinal=p.member_ordinal
 JOIN temp.selected_workspace_file_versions f ON f.workspace_id=live.workspace_id AND f.lang='rust' AND f.generation=live.generation AND f.rel_path=root.rel_path
 CROSS JOIN temp.selected_unit_member_blobs attachment ON attachment.summary_id=root.summary_id AND attachment.member_ordinal=root.member_ordinal JOIN main.blobs b ON b.id=attachment.blob_id AND b.blob_oid=f.blob_oid AND b.lang=f.lang AND b.generation=f.generation
 WHERE t.crate_name=?2 AND t.target_kind IN ('lib','bin')
 UNION
 SELECT child.unit_key,t.target_kind,root.rel_path FROM main.resolution_unit_summary_dependency_names n INDEXED BY resolution_unit_summary_dependency_names_name
 CROSS JOIN main.resolution_unit_summary_dependencies d ON d.summary_id=n.summary_id AND d.dependency_ordinal=n.dependency_ordinal AND d.boundary='workspace'
 CROSS JOIN live parent ON parent.summary_id=n.summary_id CROSS JOIN live child ON child.workspace_id=parent.workspace_id AND child.generation=parent.generation AND child.unit_key=d.dependency_unit_key
 JOIN main.rust_resolution_unit_summary_contexts t ON t.summary_id=child.summary_id
 JOIN main.resolution_unit_summary_placements p ON p.summary_id=child.summary_id AND p.container_path=''
 JOIN main.resolution_unit_summary_members root ON root.summary_id=p.summary_id AND root.member_ordinal=p.member_ordinal
 JOIN temp.selected_workspace_file_versions f ON f.workspace_id=child.workspace_id AND f.lang='rust' AND f.generation=child.generation AND f.rel_path=root.rel_path
 CROSS JOIN temp.selected_unit_member_blobs attachment ON attachment.summary_id=root.summary_id AND attachment.member_ordinal=root.member_ordinal JOIN main.blobs b ON b.id=attachment.blob_id AND b.blob_oid=f.blob_oid AND b.lang=f.lang AND b.generation=f.generation
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
pub fn rust_broad_file_units_sql() -> String {
    route_sql(RouteQuestion::BroadFileUnits)
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
            rusqlite::types::Value::Text(serde_json::to_string(&[path]).expect("paths serialize")),
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
            .query_map(
                params![rust_unit_summary_derivation_identity(), value],
                |r| r.get::<_, String>(3),
            )?
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
    let mut partial = Vec::new();
    let mut unpublished = Vec::new();
    for (unit, state) in super::availability::rust_published_units_availability(c, s)? {
        match state {
            super::RustUnitAvailability::Published { complete, .. } => {
                if !complete {
                    partial.push(unit)
                }
            }
            // A stale row is not current, so membership is unknown exactly as for
            // an unpublished one; the upgrade window before reconcile is normal.
            super::RustUnitAvailability::Unpublished | super::RustUnitAvailability::Stale => {
                unpublished.push(unit)
            }
            super::RustUnitAvailability::IntentionallyUnavailable { .. } => {
                unreachable!("ordinary publication query only")
            }
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
            params![rust_unit_summary_derivation_identity(), target.as_slice()],
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
    Ok(rust_files_units(c, s, &[path.to_owned()])?
        .into_iter()
        .map(|(unit, _)| unit)
        .collect())
}

/// The same selected membership seek for a set of paths, retaining the path
/// so availability can distinguish healthy owners from unowned package files.
pub(super) fn rust_files_units(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    paths: &[String],
) -> Result<Vec<([u8; 32], String)>> {
    check(c, s)?;
    let sql = route_sql(RouteQuestion::FileUnits);
    let paths = serde_json::to_string(paths).expect("paths serialize");
    let rows = c
        .prepare_cached(&sql)?
        .query_map(
            params![rust_unit_summary_derivation_identity(), paths],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?)),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter()
        .map(|(k, path)| Ok((key(k)?, path)))
        .collect()
}

/// Whether the selection holds Rust state the persisted units never saw: an
/// overlay's content mount, or a mask over (or removal of) a revision file.
/// A path that no persisted unit holds may then belong to a unit through a
/// declaration the persisted units do not carry.
pub fn rust_selection_has_overlay(c: &Connection) -> Result<bool> {
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM temp.selected_resolution_overlay_masks WHERE storage_language='rust') OR EXISTS(SELECT 1 FROM temp.selected_resolution_mounts WHERE storage_language='rust' AND file_version_id IS NULL)",
        [],
        |row| row.get::<_, bool>(0),
    )?)
}

/// The Rust paths the selection overlays: an overlay's content mount, or a mask
/// over (or removal of) a revision file. The same rows `rust_selection_has_overlay`
/// tests for existence.
pub fn rust_selection_overlay_paths(c: &Connection) -> Result<Vec<String>> {
    let mut statement = c.prepare_cached(
        "SELECT persisted_relative_path FROM temp.selected_resolution_overlay_masks WHERE storage_language='rust'
         UNION SELECT persisted_relative_path FROM temp.selected_resolution_mounts WHERE storage_language='rust' AND file_version_id IS NULL
         ORDER BY 1",
    )?;
    Ok(statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Whether changing any of `paths` can change what the units holding `file`
/// export to a local glob, so that an answer read from the persisted summaries
/// cannot stand for the selected content.
///
/// The closure is the workspace-dependency closure of those units, which the
/// glob's module walk and the units' recorded inputs stay inside. A path is
/// read when a closure summary lists it as a member or an input file. A path
/// no selected summary lists (a new file, or one outside every crate) reads
/// nothing, unless a closure unit holds a module the summaries could not place
/// or an unknown cfg activation: the new file could be that module. No unit
/// holding `file` means no closure, which is refused.
pub fn rust_local_glob_closure_reads_paths(
    c: &Connection,
    file: &str,
    paths: &[String],
) -> Result<bool> {
    let paths = serde_json::to_string(paths).expect("paths are strings");
    Ok(c.prepare_cached(
        "WITH roots(unit_key) AS (
           SELECT unit.unit_key FROM selected_rust_unit_summaries unit
           JOIN main.resolution_unit_summary_members m ON m.summary_id=unit.summary_id
           WHERE m.rel_path=?1),
         closure(summary_id) AS (
           SELECT summary_id FROM temp.selected_rust_unit_closure
           WHERE root_unit_key IN (SELECT unit_key FROM roots)),
         changed(path) AS (SELECT value FROM json_each(?2)),
         listed(path,in_closure) AS (
           SELECT m.rel_path, m.summary_id IN (SELECT summary_id FROM closure)
           FROM changed JOIN main.resolution_unit_summary_members m ON m.rel_path=changed.path
           JOIN selected_rust_unit_summaries unit ON unit.summary_id=m.summary_id
           UNION ALL
           SELECT i.rel_path, i.summary_id IN (SELECT summary_id FROM closure)
           FROM changed JOIN main.resolution_unit_summary_input_files i ON i.rel_path=changed.path
           JOIN selected_rust_unit_summaries unit ON unit.summary_id=i.summary_id)
         SELECT NOT EXISTS(SELECT 1 FROM roots)
            OR EXISTS(SELECT 1 FROM listed WHERE in_closure)
            OR (EXISTS(SELECT 1 FROM changed WHERE path NOT IN (SELECT path FROM listed))
                AND EXISTS(SELECT 1 FROM closure
                  JOIN main.rust_resolution_unit_summary_gaps gap ON gap.summary_id=closure.summary_id
                  WHERE gap.gap_kind IN ('unknown_activation','unplaced_module','duplicate_placement')))",
    )?
    .query_row(params![file, paths], |row| row.get::<_, bool>(0))?)
}

pub fn rust_broad_file_units(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    path: &str,
) -> Result<Vec<[u8; 32]>> {
    check(c, s)?;
    let rows = c
        .prepare_cached(&route_sql(RouteQuestion::BroadFileUnits))?
        .query_map(
            params![rust_unit_summary_derivation_identity(), path,],
            |r| r.get::<_, Vec<u8>>(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter().map(key).collect()
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn rust_broad_placement_rows_sql() -> String {
    broad_placement_rows_sql()
}

/// Joins `live` to the selected revision and to the published, current-epoch
/// topology of its crate version. A unit read through them is the selected live
/// unit; a summary of an unpublished or old-epoch topology is not read.
const CURRENT_TOPOLOGY_JOINS: &str = " JOIN temp.selected_workspace_revisions sel ON sel.workspace_id=live.workspace_id AND sel.lang='rust' AND sel.generation=live.generation JOIN main.rust_crate_versions cv ON cv.workspace_id=live.workspace_id AND cv.lang='rust' AND cv.generation=live.generation AND cv.crate_key=live.unit_key AND cv.topology_id=live.topology_id AND cv.valid_from<=sel.revision AND (cv.valid_until IS NULL OR sel.revision<cv.valid_until) JOIN main.rust_crate_topologies t ON t.topology_id=cv.topology_id AND t.publication_state='complete' AND t.producer_epoch=(SELECT epoch FROM main.analysis_epochs WHERE lang='rust')";

fn broad_placement_rows_sql() -> String {
    let live = live_not_materialized();
    format!(
        "{live}, broad AS (SELECT m.summary_id,m.rel_path,CASE p.container_path WHEN '' THEN 'crate' ELSE p.container_path END AS module_path,m.source_role AS placement,1 AS activation FROM main.resolution_unit_summary_placements p INDEXED BY resolution_unit_summary_placements_member CROSS JOIN main.resolution_unit_summary_members m ON m.summary_id=p.summary_id AND m.member_ordinal=p.member_ordinal WHERE p.summary_id IN (SELECT summary_id FROM live WHERE unit_key=?2) UNION SELECT i.summary_id,i.rel_path,p.module_path,p.placement,p.activation FROM main.rust_resolution_unit_summary_inactive_placements p CROSS JOIN main.resolution_unit_summary_input_files i ON i.summary_id=p.summary_id AND i.input_ordinal=p.input_file_ordinal WHERE p.summary_id IN (SELECT summary_id FROM live WHERE unit_key=?2)) SELECT p.rel_path,p.module_path,p.placement,p.activation,f.blob_oid FROM live{CURRENT_TOPOLOGY_JOINS} JOIN broad p ON p.summary_id=live.summary_id LEFT JOIN temp.selected_resolution_mounts f ON f.storage_language='rust' AND f.persisted_relative_path=p.rel_path WHERE live.unit_key=?2 ORDER BY p.rel_path,p.module_path,p.placement,p.activation"
    )
}

/// Every placement for the selected current topology, including inactive routes.
/// The returned tuple binds route, activation, and source content.
/// The source content is the selected mount's blob (an overlay's content, never
/// the revision's blob for a masked path), sought by the mounts' unique
/// (storage_language, persisted_relative_path) key; `None` when the selection
/// mounts no content at the path. The placements come from the unit summary's
/// placement tables, which carry no mount site, so none is returned.
#[allow(clippy::type_complexity)]
pub fn rust_broad_placement_rows(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    unit: &[u8; 32],
) -> Result<Vec<(String, String, String, i64, Option<String>)>> {
    check(c, s)?;
    let sql = broad_placement_rows_sql();
    let rows = c
        .prepare_cached(&sql)?
        .query_map(
            params![rust_unit_summary_derivation_identity(), unit.as_slice(),],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.is_empty() {
        return Err(StoreError::corrupt(format!(
            "selected Rust unit {unit:?} has no current broad placements"
        )));
    }
    Ok(rows)
}

/// The activity of every file of one selected live unit with a stored
/// placement, by the single definition in `rust_file_activity.sql` (#11639).
/// Paths are workspace-relative. A path the unit stores no placement of is
/// absent, and a unit that is not live yields no rows.
pub fn rust_unit_file_activity(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    unit: &[u8; 32],
) -> Result<Vec<(String, RustBlobActivity)>> {
    check(c, s)?;
    let live = live_not_materialized();
    let sql = format!(
        "{live}, probe(summary_id, rel_path) AS (
 SELECT live.summary_id, member.rel_path FROM live{CURRENT_TOPOLOGY_JOINS}
 JOIN main.resolution_unit_summary_members member ON member.summary_id=live.summary_id
 WHERE live.unit_key=?2
 UNION
 SELECT live.summary_id, input.rel_path FROM live{CURRENT_TOPOLOGY_JOINS}
 JOIN main.rust_resolution_unit_summary_inactive_placements inactive ON inactive.summary_id=live.summary_id
 JOIN main.resolution_unit_summary_input_files input
  ON input.summary_id=inactive.summary_id AND input.input_ordinal=inactive.input_file_ordinal
 WHERE live.unit_key=?2
 UNION
 SELECT live.summary_id, json_extract(gap.detail, '$.path') FROM live{CURRENT_TOPOLOGY_JOINS}
 JOIN main.rust_resolution_unit_summary_gaps gap
  ON gap.summary_id=live.summary_id
 AND gap.gap_kind IN ('unknown_activation','unplaced_module','duplicate_placement')
 WHERE live.unit_key=?2 AND json_extract(gap.detail, '$.path') IS NOT NULL
), {} SELECT rel_path, activation FROM file_activity ORDER BY rel_path",
        include_str!("../resolution_operation/rust_file_activity.sql")
    );
    c.prepare_cached(&sql)?
        .query_map(
            params![rust_unit_summary_derivation_identity(), unit.as_slice()],
            |r| Ok((r.get(0)?, RustBlobActivity::from_activation(r.get(1)?))),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

/// The activity of every stored placement of one selected live unit, by the
/// placement grain of the single definition in `rust_file_activity.sql`
/// (#11639): one verdict per (workspace-relative path, module path), where the
/// module path is `crate` for the root. The route index matches each `mod`
/// declaration to the placement it creates by the declared module name.
pub fn rust_unit_placement_activity(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    unit: &[u8; 32],
) -> Result<Vec<(String, String, RustBlobActivity)>> {
    check(c, s)?;
    let live = live_not_materialized();
    let sql = format!(
        "{live}, placement_probe(summary_id, rel_path, module_path) AS (
 SELECT live.summary_id, member.rel_path,
        CASE placement.container_path WHEN '' THEN 'crate' ELSE placement.container_path END
 FROM live{CURRENT_TOPOLOGY_JOINS}
 JOIN main.resolution_unit_summary_placements placement ON placement.summary_id=live.summary_id
 JOIN main.resolution_unit_summary_members member
  ON member.summary_id=placement.summary_id AND member.member_ordinal=placement.member_ordinal
 WHERE live.unit_key=?2
 UNION
 SELECT live.summary_id, input.rel_path, inactive.module_path
 FROM live{CURRENT_TOPOLOGY_JOINS}
 JOIN main.rust_resolution_unit_summary_inactive_placements inactive ON inactive.summary_id=live.summary_id
 JOIN main.resolution_unit_summary_input_files input
  ON input.summary_id=inactive.summary_id AND input.input_ordinal=inactive.input_file_ordinal
 WHERE live.unit_key=?2
), {} SELECT rel_path, module_path, activation FROM placement_activity ORDER BY rel_path, module_path",
        include_str!("../resolution_operation/rust_file_activity.sql")
    );
    c.prepare_cached(&sql)?
        .query_map(
            params![rust_unit_summary_derivation_identity(), unit.as_slice()],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    RustBlobActivity::from_activation(r.get(2)?),
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
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
            params![rust_unit_summary_derivation_identity(), package],
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
    match super::rust_unit_availability(c, s, unit)? {
        Some(super::RustUnitAvailability::IntentionallyUnavailable { .. }) => {
            return Ok(Some((Vec::new(), false)));
        }
        // A stale unit may be an unavailable target with no summary row, which
        // the query below would answer as not live, so this point read fails.
        // Stale is the normal upgrade window, not a store fault.
        Some(super::RustUnitAvailability::Stale) => {
            return Err(StoreError::new(format!(
                "stale selected Rust unit {unit:02x?}: derivation or reconcile pending"
            )));
        }
        Some(state) => state.require_published_or_stale(unit)?,
        None => return Ok(None),
    }
    let sql = format!(
        // The topology join is the reconcile-currency guard, kept until #11173 M4:
        // a summary whose topology is unpublished or from an old producer epoch
        // yields NULL completeness, which fails closed below.
        "{LIVE} SELECT CASE WHEN t.topology_id IS NOT NULL THEN ctx.broad_complete END FROM live JOIN main.rust_resolution_unit_summary_contexts ctx ON ctx.summary_id=live.summary_id LEFT JOIN main.rust_crate_topologies t ON t.topology_id=live.topology_id AND t.publication_state='complete' AND t.producer_epoch=(SELECT epoch FROM main.analysis_epochs WHERE lang='rust') WHERE live.unit_key=?2"
    );
    let complete = c
        .prepare_cached(&sql)?
        .query_row(
            params![rust_unit_summary_derivation_identity(), unit.as_slice()],
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
    let rows = AnalyzerStore::rust_selected_package_rows_for_unit(c, s, unit)?;
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
        .query_map(
            params![rust_unit_summary_derivation_identity(), name],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter()
        .map(|(k, t, p)| Ok((key(k)?, t, p)))
        .collect()
}
