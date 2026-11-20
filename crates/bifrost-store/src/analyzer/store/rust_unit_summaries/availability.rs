//! The route layer's single interpretation of selected unit availability.
use super::*;
use brokk_bifrost_rust::selected_context::RustTargetRootUnavailableReason;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct RustUnavailableUnitCause {
    pub manifest: PathBuf,
    pub target_name: String,
    pub declared_root: PathBuf,
    pub reason: RustTargetRootUnavailableReason,
}

#[derive(Debug, Clone)]
pub enum RustUnitAvailability {
    Published {
        input: [u8; 32],
        complete: bool,
    },
    IntentionallyUnavailable {
        cause: RustUnavailableUnitCause,
        evidence: [u8; 32],
    },
    Unpublished,
    Stale,
}

impl RustUnitAvailability {
    /// Fails for a unit with a retained version but no summary row: a store
    /// fault no binary upgrade produces. A [`Self::Stale`] row is the normal
    /// window between a derivation change and reconcile; callers count it as
    /// incomplete or partial and this check lets it pass.
    pub fn require_published_or_stale(&self, unit: &[u8; 32]) -> Result<()> {
        match self {
            Self::Unpublished => Err(StoreError::corrupt(format!(
                "unpublished selected Rust unit {unit:02x?}"
            ))),
            _ => Ok(()),
        }
    }
}

// The selected crate interval owns the manifest binding. A reused summary
// retains its original publication inputs across meaning-preserving edits.
const NORMAL_AVAILABILITY: &str = "SELECT cv.crate_key,t.publication_state,t.producer_epoch=(SELECT epoch FROM analysis_epochs WHERE lang='rust'),v.summary_id,x.publication_state,x.derivation_identity,EXISTS(SELECT 1 FROM resolution_producer_epochs e WHERE e.lang='rust' AND e.producer_epoch=x.producer_epoch),ctx.broad_complete,x.summary_digest,rv.topology_id=cv.topology_id,
    (cv.manifest_file_version_id IS NULL OR EXISTS(SELECT 1 FROM workspace_file_versions f WHERE f.file_version_id=cv.manifest_file_version_id AND f.workspace_id=cv.workspace_id AND f.generation=cv.generation AND f.valid_from<=?3 AND (f.valid_until IS NULL OR ?3<f.valid_until)))
    FROM rust_crate_versions cv LEFT JOIN rust_crate_topologies t ON t.topology_id=cv.topology_id
    LEFT JOIN resolution_unit_summary_versions v ON v.workspace_id=cv.workspace_id AND v.lang='rust' AND v.generation=cv.generation AND v.unit_key=cv.crate_key AND v.valid_from<=?3 AND (v.valid_until IS NULL OR ?3<v.valid_until)
    LEFT JOIN resolution_unit_summaries x ON x.summary_id=v.summary_id AND x.lang='rust' AND x.unit_kind='rust_crate'
    LEFT JOIN rust_resolution_unit_summary_versions rv ON rv.workspace_id=v.workspace_id AND rv.generation=v.generation AND rv.unit_key=v.unit_key AND rv.valid_from=v.valid_from AND rv.summary_id=v.summary_id
    LEFT JOIN rust_resolution_unit_summary_contexts ctx ON ctx.summary_id=v.summary_id
    WHERE cv.workspace_id=?1 AND cv.generation=?2 AND cv.lang='rust' AND cv.valid_from<=?3 AND (cv.valid_until IS NULL OR ?3<cv.valid_until)";

fn normal_availability(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<([u8; 32], RustUnitAvailability)> {
    let key = row.get(0)?;
    let topology_state: Option<String> = row.get(1)?;
    let topology_current: Option<bool> = row.get(2)?;
    let summary: Option<i64> = row.get(3)?;
    let state: Option<String> = row.get(4)?;
    let producer: Option<[u8; 32]> = row.get(5)?;
    let epoch_current: bool = row.get(6)?;
    let inventory: Option<bool> = row.get(7)?;
    let digest: Option<[u8; 32]> = row.get(8)?;
    let crosswalk: Option<bool> = row.get(9)?;
    let manifest_current: bool = row.get(10)?;
    let Some(inventory) = inventory else {
        return Ok((key, RustUnitAvailability::Unpublished));
    };
    let availability = if summary.is_none()
        || topology_state.as_deref() != Some("complete")
        || state.as_deref() != Some("complete")
        || crosswalk != Some(true)
    {
        RustUnitAvailability::Unpublished
    } else if topology_current != Some(true)
        || producer != Some(rust_unit_summary_derivation_identity())
        || !epoch_current
        || !manifest_current
    {
        RustUnitAvailability::Stale
    } else {
        RustUnitAvailability::Published {
            input: digest.expect("published summary digest"),
            complete: inventory,
        }
    };
    Ok((key, availability))
}

pub(super) fn rust_published_units_availability(
    c: &Connection,
    s: &WorkspaceSnapshotId,
) -> Result<Vec<([u8; 32], RustUnitAvailability)>> {
    c.prepare_cached(NORMAL_AVAILABILITY)?
        .query_map(
            params![s.workspace_id.as_str(), s.generation.0, s.revision],
            normal_availability,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

/// None means no selected unit, never an intentionally unavailable target.
pub fn rust_unit_availability(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    unit: &[u8; 32],
) -> Result<Option<RustUnitAvailability>> {
    check_rust_summary_selection(c, s)?;
    super::super::require_current_generation(c, "rust", s.generation)?;
    selected_unit_availability(c, s, unit)
}

/// [`rust_unit_availability`] for a caller that already checked the selection
/// and generation once for several units.
fn selected_unit_availability(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    unit: &[u8; 32],
) -> Result<Option<RustUnitAvailability>> {
    let normal = c
        .prepare_cached(&format!("{NORMAL_AVAILABILITY} AND cv.crate_key=?4"))?
        .query_row(
            params![
                s.workspace_id.as_str(),
                s.generation.0,
                s.revision,
                unit.as_slice()
            ],
            normal_availability,
        )
        .optional()?
        .map(|(_, state)| state);
    // A unit is either a published topology or an unavailable target, never
    // both (the reconcile publishes them from one partition of the targets),
    // so a topology answers without reading the carrier.
    if let Some(state) = normal {
        return Ok(Some(state));
    }
    let unavailable = c.query_row(
        "SELECT p.manifest_path,u.target_name,u.declared_root,u.reason,p.output_digest,p.derivation_identity,
         EXISTS(SELECT 1 FROM workspace_file_versions f WHERE f.file_version_id=p.manifest_file_version_id AND f.workspace_id=p.workspace_id AND f.generation=p.generation AND f.rel_path=p.manifest_path AND f.valid_from<=?4 AND (f.valid_until IS NULL OR ?4<f.valid_until))
         FROM rust_package_route_versions p JOIN rust_package_unavailable_targets u USING(route_set_id)
         WHERE p.workspace_id=?1 AND p.generation=?2 AND u.unit_key=?3 AND p.valid_from<=?4 AND (p.valid_until IS NULL OR ?4<p.valid_until)",
        params![s.workspace_id.as_str(),s.generation.0,unit.as_slice(),s.revision],
        |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,[u8;32]>(4)?,r.get::<_,[u8;32]>(5)?,r.get::<_,bool>(6)?)),
    ).optional()?;
    let Some((manifest, target_name, root, reason, evidence, producer, manifest_current)) =
        unavailable
    else {
        return Ok(None);
    };
    let reconciled:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM rust_crate_reconciliations WHERE workspace_id=?1 AND generation=?2 AND revision>=?3 AND derivation_identity=?4)",params![s.workspace_id.as_str(),s.generation.0,s.revision,super::super::rust_crates::derivation_identity()],|row|row.get(0))?;
    if producer != super::super::rust_crates::derivation_identity()
        || !manifest_current
        || !reconciled
    {
        return Ok(Some(RustUnitAvailability::Stale));
    }
    let reason = match reason.as_str() {
        "outside_workspace" => RustTargetRootUnavailableReason::OutsideWorkspace,
        "outside_package_unsupported" => RustTargetRootUnavailableReason::OutsidePackageUnsupported,
        _ => {
            return Err(StoreError::corrupt(format!(
                "unknown Rust target root reason {reason:?}"
            )));
        }
    };
    Ok(Some(RustUnitAvailability::IntentionallyUnavailable {
        cause: RustUnavailableUnitCause {
            manifest: manifest.into(),
            target_name,
            declared_root: root.into(),
            reason,
        },
        evidence,
    }))
}

/// Exact claims and unavailable targets in their selected dependency closure,
/// or the nearest package's gap when the file has no healthy owner.
/// This is local coverage, not the exhaustive owners-of-file union.
pub fn rust_file_unit_availability(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    path: &str,
) -> Result<Vec<([u8; 32], RustUnitAvailability)>> {
    selected_files_unit_availability(c, s, &[path.to_owned()])
}

/// Share claims, nearest-package admission, and dependency-closure coverage
/// between point file questions and all files selected by a package name.
fn selected_files_unit_availability(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    paths: &[String],
) -> Result<Vec<([u8; 32], RustUnitAvailability)>> {
    let memberships = super::route_questions::rust_files_units(c, s, paths)?;
    let healthy: BTreeSet<_> = memberships.iter().map(|(unit, _)| *unit).collect();
    let owned: BTreeSet<_> = memberships.iter().map(|(_, path)| path.as_str()).collect();
    let mut keys = healthy.clone();
    // A file with a healthy selected owner does not borrow its nearest
    // package's unrelated gap. Explicit claims and dependencies still apply.
    let requested: Vec<_> = paths
        .iter()
        .map(|path| {
            let manifests: Vec<_> = if owned.contains(path.as_str()) {
                Vec::new()
            } else {
                Path::new(path)
                    .parent()
                    .into_iter()
                    .flat_map(Path::ancestors)
                    .map(|directory| {
                        super::super::rust_crates::stable_path(&directory.join("Cargo.toml"))
                    })
                    .collect()
            };
            (path, manifests)
        })
        .collect();
    let encoded = serde_json::to_string(&requested).expect("requested paths serialize");
    let mut rows = c.prepare_cached("WITH RECURSIVE files(rel_path,manifest_path) AS (
        SELECT requested.value->>0,(
            SELECT p.manifest_path FROM rust_package_route_versions p
            WHERE p.workspace_id=?1 AND p.generation=?2 AND p.valid_from<=?3 AND (p.valid_until IS NULL OR ?3<p.valid_until)
            AND p.manifest_path IN (SELECT value FROM json_each(requested.value->1))
            ORDER BY length(p.manifest_path) DESC LIMIT 1
        ) FROM json_each(?4) requested
    ), reached(unit_key) AS (
        SELECT v.unit_key FROM resolution_unit_summary_versions v
        JOIN resolution_unit_summary_members m ON m.summary_id=v.summary_id
        WHERE v.workspace_id=?1 AND v.lang='rust' AND v.generation=?2 AND v.valid_from<=?3 AND (v.valid_until IS NULL OR ?3<v.valid_until) AND m.rel_path IN (SELECT rel_path FROM files)
        UNION
        SELECT d.dependency_unit_key FROM reached r
        JOIN resolution_unit_summary_versions v ON v.unit_key=r.unit_key AND v.workspace_id=?1 AND v.lang='rust' AND v.generation=?2 AND v.valid_from<=?3 AND (v.valid_until IS NULL OR ?3<v.valid_until)
        JOIN resolution_unit_summary_dependencies d ON d.summary_id=v.summary_id AND d.boundary='workspace'
        WHERE d.dependency_unit_key IS NOT NULL
    )
    SELECT claim.unit_key FROM rust_package_target_claims claim JOIN rust_package_route_versions p USING(route_set_id) WHERE claim.rel_path IN (SELECT rel_path FROM files) AND p.workspace_id=?1 AND p.generation=?2 AND p.valid_from<=?3 AND (p.valid_until IS NULL OR ?3<p.valid_until)
    UNION SELECT u.unit_key FROM rust_package_route_versions p JOIN rust_package_unavailable_targets u USING(route_set_id) WHERE p.workspace_id=?1 AND p.generation=?2 AND p.valid_from<=?3 AND (p.valid_until IS NULL OR ?3<p.valid_until) AND p.manifest_path IN (SELECT manifest_path FROM files)
    UNION SELECT u.unit_key FROM reached r
        JOIN rust_package_unavailable_targets u ON u.unit_key=r.unit_key
        JOIN rust_package_route_versions p USING(route_set_id)
        WHERE p.workspace_id=?1 AND p.generation=?2 AND p.valid_from<=?3 AND (p.valid_until IS NULL OR ?3<p.valid_until)")?;
    for key in rows.query_map(
        params![s.workspace_id.as_str(), s.generation.0, s.revision, encoded],
        |r| r.get::<_, [u8; 32]>(0),
    )? {
        keys.insert(key?);
    }
    let mut states = Vec::new();
    for unit in keys {
        let state = selected_unit_availability(c, s, &unit)?.ok_or_else(|| {
            StoreError::stale_generation(format!(
                "selected target claim {unit:02x?} has no current unit"
            ))
        })?;
        state.require_published_or_stale(&unit)?;
        // A healthy claim is discovery evidence, not proof of compilation at
        // the selected mount. Classify it before discarding it: a stale summary
        // (the window between a binary upgrade and reconcile) is reported to the
        // caller, which counts it as incomplete, and never turns its owner into
        // complete emptiness.
        if healthy.contains(&unit) || !matches!(state, RustUnitAvailability::Published { .. }) {
            states.push((unit, state));
        }
    }
    Ok(states)
}

/// Name-scoped coverage for package/root naming questions. The dotted name is
/// an analyzer value, not source syntax; matching it never parses source text.
pub fn rust_name_unit_availability(
    c: &Connection,
    s: &WorkspaceSnapshotId,
    name: &str,
) -> Result<Vec<([u8; 32], RustUnitAvailability)>> {
    check_rust_summary_selection(c, s)?;
    super::super::require_current_generation(c, "rust", s.generation)?;
    let mut rows=c.prepare_cached("SELECT u.unit_key FROM rust_package_route_versions p JOIN rust_package_unavailable_targets u USING(route_set_id) WHERE p.workspace_id=?1 AND p.generation=?2 AND p.valid_from<=?3 AND (p.valid_until IS NULL OR ?3<p.valid_until) AND (u.target_name=?4 OR substr(?4,1,length(u.target_name)+1)=u.target_name||'.' OR EXISTS(
        SELECT 1 FROM resolution_unit_summary_dependency_names n
        JOIN resolution_unit_summary_dependencies d ON d.summary_id=n.summary_id AND d.dependency_ordinal=n.dependency_ordinal AND d.boundary='workspace'
        JOIN resolution_unit_summary_versions parent ON parent.summary_id=n.summary_id AND parent.workspace_id=p.workspace_id AND parent.lang='rust' AND parent.generation=p.generation AND parent.valid_from<=?3 AND (parent.valid_until IS NULL OR ?3<parent.valid_until)
        WHERE d.dependency_unit_key=u.unit_key AND (n.name=?4 OR substr(?4,1,length(n.name)+1)=n.name||'.')
    )) ORDER BY u.unit_key")?;
    let keys = rows
        .query_map(
            params![s.workspace_id.as_str(), s.generation.0, s.revision, name],
            |r| r.get::<_, [u8; 32]>(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut states = keys
        .into_iter()
        .map(|unit| {
            let state = selected_unit_availability(c, s, &unit)?
                .expect("selected unavailable target has a state");
            state.require_published_or_stale(&unit)?;
            Ok((unit, state))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>>>()?;

    // These are selected naming rows, not names inferred from source paths or
    // target spelling. Seek each ancestor package through the naming index.
    let components: Vec<_> = brokk_bifrost_core::analyzer::fq_name::joined_segments(name, ".")
        .map(str::to_owned)
        .collect();
    let mut package =
        brokk_bifrost_core::analyzer::fq_name::FqName::from_package_components(&components);
    let mut names = Vec::new();
    loop {
        names.push(package.display(brokk_bifrost_core::analyzer::fq_name::segment_interner()));
        let Some(parent) = package.parent().filter(|parent| !parent.is_empty()) else {
            break;
        };
        package = parent;
    }
    let names = serde_json::to_string(&names).expect("package names serialize");
    let paths = c.prepare_cached("SELECT DISTINCT f.rel_path FROM workspace_file_package_rows n INDEXED BY idx_workspace_file_package_rows_name
        CROSS JOIN workspace_file_versions f ON f.file_version_id=n.file_version_id
        WHERE n.package_name IN (SELECT value FROM json_each(?4))
        AND f.workspace_id=?1 AND f.lang='rust' AND f.generation=?2 AND f.input_kind='source'
        AND f.valid_from<=?3 AND (f.valid_until IS NULL OR ?3<f.valid_until)
        AND EXISTS(SELECT 1 FROM rust_package_route_versions p JOIN rust_package_unavailable_targets u USING(route_set_id)
            WHERE p.workspace_id=?1 AND p.generation=?2 AND p.valid_from<=?3 AND (p.valid_until IS NULL OR ?3<p.valid_until))
        ORDER BY f.rel_path")?
        .query_map(params![s.workspace_id.as_str(),s.generation.0,s.revision,names], |r| r.get::<_,String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !paths.is_empty() {
        states.extend(selected_files_unit_availability(c, s, &paths)?);
    }
    Ok(states.into_iter().collect())
}
