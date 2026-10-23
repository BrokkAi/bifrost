//! Query-lived point contexts compiled from persisted crate rows.
use super::rust_crate_rows::{RustCrateDeclaration, RustCrateExport};
use super::*;
use crate::analyzer::resolution::SharedNameInterner;
use crate::analyzer::resolution::mounted_site_semantic;
use rusqlite::params;
use rusqlite::params_from_iter;
use rusqlite::types::Value;

/// Production point-target query used by cross-crate planner regressions.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub const POINT_TARGETS_SQL_FOR_TEST: &str = include_str!("rust_crate_point_targets.sql");

pub(super) const GENERATED_ITEM_SURFACE_REASON: &str = "GeneratedItemSurface";
pub(super) const UNLOWERED_EXPORT_REASON: &str = "UnloweredExportedDeclaration";

pub(in crate::analyzer::store) const SELECTED_MODULE_PLACEMENTS_SCHEMA_SQL: &str = concat!(
    include_str!("selected_container_placements.sql"),
    include_str!("rust_selected_module_placements.sql")
);
#[doc(hidden)]
pub const SELECTED_MODULE_PLACEMENTS_FILL_SQL: &str =
    include_str!("rust_selected_module_placements_fill.sql");

pub(super) const NAMING: &str = include_str!("rust_crate_point_naming.sql");
/// One file's selected blob and its selected mount ordinal, both keyed on the
/// same workspace-relative path, in one statement. Either can be absent: a
/// content mount has no file version and an unselected file has no mount.
pub(super) const FILE_BLOB_AND_MOUNT: &str = "SELECT (SELECT blobs.id FROM selected_workspace_file_versions AS files CROSS JOIN blobs ON blobs.lang=files.lang AND blobs.blob_oid=files.blob_oid WHERE files.lang='rust' AND files.rel_path=?1), mount.mount_ordinal, mount.semantic_language FROM (SELECT 1) AS requested LEFT JOIN temp.selected_resolution_mounts AS mount ON mount.storage_language='rust' AND mount.persisted_relative_path=?1";
pub(super) const FILE_BLOB: &str = "SELECT blobs.id FROM selected_workspace_file_versions AS files CROSS JOIN blobs ON blobs.lang=files.lang AND blobs.blob_oid=files.blob_oid WHERE files.lang='rust' AND files.rel_path=?1";
pub(super) const MACRO_IMPORT_TARGET_RANGE: &str = "SELECT
 json_extract(spans, '$[' || ?2 || '][0]'),
 json_extract(spans, '$[' || ?2 || '][1]')
 FROM source_occurrence_arenas WHERE blob_id = ?1";
#[doc(hidden)]
pub const SELECT_IMPORTED_MACRO_DEFINITION: &str = r#"
WITH RECURSIVE selected_members(
 workspace_id, generation, summary_id, member_ordinal, blob_id
) AS MATERIALIZED (
 SELECT owner.workspace_id, owner.generation, owner.summary_id,
        member.member_ordinal, member.blob_id
 FROM selected_workspace_file_versions AS files
 CROSS JOIN main.blobs AS blob
  ON blob.lang=files.lang AND blob.blob_oid=files.blob_oid
 AND blob.generation=files.generation
 CROSS JOIN main.resolution_unit_summary_members AS member
  INDEXED BY resolution_unit_summary_members_blob
  ON member.blob_id=blob.id AND member.rel_path=files.rel_path
 CROSS JOIN selected_rust_unit_summaries AS owner
  ON owner.summary_id=member.summary_id
 WHERE files.lang='rust' AND files.rel_path=?1
), imported_routes(
 workspace_id, generation, target_unit_key, target_module_path, target_name,
 local_extent, is_glob
) AS (
 SELECT DISTINCT owner_member.workspace_id, owner_member.generation, route.target_unit_key,
        route.target_module_path, route.target_name,
        COALESCE(source.local_end-source.local_start, 9223372036854775807), 0
 FROM selected_members AS owner_member
 CROSS JOIN source_rust_import_targets AS source
  ON source.blob_id=owner_member.blob_id AND source.is_glob=0
 AND source.bound_name=?3
 CROSS JOIN main.rust_resolution_unit_summary_import_routes AS route
  INDEXED BY rust_resolution_unit_summary_import_routes_site
  ON route.summary_id=owner_member.summary_id
 AND route.member_ordinal=owner_member.member_ordinal
 AND route.import_id=source.source_import_id
 AND route.route_ordinal=source.ordinal
 AND route.binder_scope=source.native_scope
 AND route.namespace='macro' AND route.bound_name=?3
 WHERE source.owner_start<=?2 AND ?2<source.owner_end
  AND (source.local_start IS NULL
       OR (source.local_start<=?2 AND ?2<source.local_end))
 UNION ALL
 SELECT DISTINCT owner_member.workspace_id, owner_member.generation, route.target_unit_key,
        route.target_module_path, ?3,
        COALESCE(source.local_end-source.local_start, 9223372036854775807), 1
 FROM selected_members AS owner_member
 CROSS JOIN source_rust_import_targets AS source
  ON source.blob_id=owner_member.blob_id AND source.is_glob=1
 CROSS JOIN main.rust_resolution_unit_summary_glob_imports AS route
  ON route.summary_id=owner_member.summary_id
 AND route.member_ordinal=owner_member.member_ordinal
 AND route.source_import_id=source.source_import_id
 AND route.route_ordinal=source.ordinal
 AND route.binder_scope=source.native_scope
 WHERE source.owner_start<=?2 AND ?2<source.owner_end
  AND (source.local_start IS NULL
       OR (source.local_start<=?2 AND ?2<source.local_end))
), targets(
 workspace_id, generation, unit_key, module_path, name, local_extent, is_glob
) AS (
 SELECT workspace_id, generation, target_unit_key, target_module_path, target_name,
        local_extent, is_glob
 FROM imported_routes
 UNION
 SELECT targets.workspace_id, targets.generation, export.target_unit_key,
        export.target_module_path, export.target_name,
        targets.local_extent, targets.is_glob
 FROM targets
 CROSS JOIN selected_rust_unit_summaries AS owner
  ON owner.workspace_id=targets.workspace_id
 AND owner.generation=targets.generation AND owner.unit_key=targets.unit_key
 CROSS JOIN main.rust_resolution_unit_summary_exports AS export
  ON export.summary_id=owner.summary_id AND export.module_path=targets.module_path
 AND export.namespace='macro' AND export.name=targets.name
 WHERE export.origin<>'declaration'
), candidates(rel_path, declaration_id, local_extent, is_glob) AS (
 SELECT DISTINCT member.rel_path, bridge.declaration_id,
        targets.local_extent, targets.is_glob
 FROM targets
 CROSS JOIN selected_rust_unit_summaries AS owner
  ON owner.workspace_id=targets.workspace_id
 AND owner.generation=targets.generation AND owner.unit_key=targets.unit_key
 CROSS JOIN main.rust_resolution_unit_summary_exports AS export
  ON export.summary_id=owner.summary_id AND export.module_path=targets.module_path
 AND export.namespace='macro' AND export.name=targets.name
 AND export.origin='declaration'
 CROSS JOIN main.resolution_unit_summary_members AS member
  ON member.summary_id=export.summary_id
 AND member.member_ordinal=export.declaration_member_ordinal
 CROSS JOIN source_native_declaration_bridges AS bridge
  ON bridge.blob_id=member.blob_id AND bridge.source_site=export.declaration_site
)
SELECT rel_path, declaration_id, local_extent, is_glob
FROM candidates ORDER BY local_extent, is_glob, rel_path, declaration_id
"#;
pub(super) const BOUNDARY_IMPORT_NAMES: &str = r#"
SELECT DISTINCT json((SELECT json_group_array(segment) FROM (
  SELECT segment FROM source_rust_import_module_segments
  WHERE blob_id=import.blob_id AND import_ordinal=import.ordinal ORDER BY ordinal
))), import.imported_name
FROM temp.selected_resolution_mounts AS mount
CROSS JOIN resolution_paths AS binding
  ON binding.blob_id=mount.blob_id AND binding.end_node=-1
 AND binding.start_node<>-1 AND binding.end_open_tail=1
 AND json_extract(binding.end_fixed_key,'$[#-2][0]')=?2
CROSS JOIN resolution_identities AS identity
  ON identity.id=binding.root_terminal
CROSS JOIN resolution_node_catalog AS scope
  ON scope.blob_id=binding.blob_id AND scope.local_key=binding.start_node
CROSS JOIN source_rust_import_targets AS import
  ON import.blob_id=scope.blob_id AND import.native_scope=scope.source_scope
 AND import.bound_name=identity.spelling AND import.is_glob=0
CROSS JOIN main.resolution_unit_summary_members AS member
  INDEXED BY resolution_unit_summary_members_blob
  ON member.blob_id=mount.blob_id AND member.rel_path=mount.persisted_relative_path
CROSS JOIN selected_rust_unit_summary_route_owners AS owner
  ON owner.summary_id=member.summary_id AND owner.workspace_id=mount.workspace_id
 AND owner.generation=mount.generation
JOIN main.rust_unit_summary_placements AS placement
  ON placement.summary_id=member.summary_id
 AND placement.member_ordinal=member.member_ordinal
CROSS JOIN main.rust_resolution_unit_summary_gaps AS gap
  ON gap.summary_id=member.summary_id AND gap.gap_kind='external_dependency'
 AND gap.subject=placement.module_path || '::' || import.bound_name
CROSS JOIN json_each(gap.detail, '$.evidence') AS evidence
  ON evidence.value ->> 'import_ordinal'=import.ordinal
WHERE mount.mount_ordinal=?1 AND import.imported_name IS NOT NULL
"#;
pub(super) const CFG: &str = "SELECT json(contexts.cfg_atoms), contexts.target_kind
 FROM selected_rust_unit_summaries AS units
 CROSS JOIN main.rust_resolution_unit_summary_contexts AS contexts
  ON contexts.summary_id=units.summary_id
 WHERE units.unit_key=?1";
pub(super) const CRATE: &str =
    "SELECT topology_id, summary_id FROM selected_rust_unit_summaries WHERE unit_key = ?1";
pub(super) const CRATE_KEYS: &str =
    "SELECT unit_key FROM selected_rust_unit_summaries ORDER BY unit_key";
pub(super) const CRATE_MEMBER_FILES: &str = "SELECT members.rel_path
 FROM selected_rust_unit_summaries AS units
 CROSS JOIN main.resolution_unit_summary_members AS members
  ON members.summary_id=units.summary_id
 WHERE units.unit_key=?1 ORDER BY members.member_ordinal";
/// The crates whose forward scope can bind into crate `?1`: every crate with
/// `?1` in its dependency closure, `?1` itself included, and every detached
/// crate, whose scope is never narrowed. The closure seek is keyed by the
/// root and the target's summary, so it costs one index probe per selected
/// crate.
pub(super) const CRATES_REACHING: &str = "SELECT root.unit_key
 FROM selected_rust_unit_summaries AS target
 CROSS JOIN selected_rust_unit_summaries AS root
 CROSS JOIN selected_rust_unit_closure AS closure
  ON closure.root_unit_key=root.unit_key AND closure.summary_id=target.summary_id
 WHERE target.unit_key=?1
UNION
SELECT units.unit_key
 FROM selected_rust_unit_summaries AS units
 CROSS JOIN main.rust_resolution_unit_summary_contexts AS contexts
  ON contexts.summary_id=units.summary_id
 WHERE contexts.target_kind='detached'";
pub(super) const FILE_CRATES: &str = "SELECT units.unit_key
 FROM main.resolution_unit_summary_members AS members
  INDEXED BY resolution_unit_summary_members_blob
 CROSS JOIN selected_rust_unit_summaries AS units
  ON units.summary_id=members.summary_id
 WHERE members.blob_id=?1 AND members.rel_path=?2";
/// Enumerate a crate and its workspace dependency crates from live summaries.
/// Rust placements supply the module path/scope route; the shared member row
/// supplies the selected source file. `topology_id` is only the Rust-owned
/// crosswalk retained by the point-context API.
pub(super) const MODULES: &str =
    "SELECT units.topology_id, placement.module_path, members.blob_id, members.rel_path,
 scopes.resolution_scope, contexts.edition,
 mount.mount_ordinal, mount.blob_id,
 (contexts.target_kind='detached' AND EXISTS(
   SELECT 1 FROM selected_rust_unit_summaries AS cargo
   JOIN main.rust_resolution_unit_summary_contexts AS cargo_context
     ON cargo_context.summary_id=cargo.summary_id
   WHERE cargo.workspace_id=graph.workspace_id
     AND cargo.generation=graph.generation AND cargo_context.target_kind<>'detached')),
 mount.semantic_language
FROM selected_rust_unit_summaries AS root
CROSS JOIN selected_rust_unit_closure AS graph ON graph.root_unit_key=root.unit_key
CROSS JOIN selected_rust_unit_summaries AS units ON units.summary_id=graph.summary_id
CROSS JOIN main.rust_resolution_unit_summary_contexts AS contexts
  ON contexts.summary_id=graph.summary_id
CROSS JOIN main.rust_unit_summary_placements AS placement
  ON placement.summary_id=graph.summary_id AND placement.scope_ordinal IS NOT NULL
CROSS JOIN selected_rust_unit_members AS members
  ON members.summary_id=placement.summary_id
 AND members.member_ordinal=placement.member_ordinal
CROSS JOIN source_rust_module_scopes AS scopes
  ON scopes.blob_id=members.blob_id AND scopes.ordinal=placement.scope_ordinal
LEFT JOIN temp.selected_resolution_mounts AS mount
  ON mount.storage_language='rust' AND mount.persisted_relative_path=members.rel_path
WHERE root.summary_id=?1 AND scopes.resolution_scope IS NOT NULL";
pub(super) const MODULE_PLACEMENTS: &str = "SELECT topology_id, container_path, placement_blob
     FROM selected_rust_container_placements
     WHERE placement_blob=?1 AND container_path=?2";
// Unchanged imports retain their exact indexed binder lookup. When the
// inventory proved a name-only change, the selected blob owns both names;
// the persisted row supplies only the already-proved module/crate route.
pub(super) const NAMED: &str =
    "SELECT route.target_unit_key, route.target_module_path, route.target_name
 FROM selected_rust_unit_summaries AS unit
 CROSS JOIN main.resolution_unit_summary_members AS member
  ON member.summary_id=unit.summary_id AND member.blob_id=?3
 CROSS JOIN main.rust_resolution_unit_summary_import_routes AS route
  ON route.summary_id=unit.summary_id AND route.member_ordinal=member.member_ordinal
 WHERE ?7=?3 AND unit.topology_id=?1 AND route.module_path=?2
  AND route.binder_scope=?4 AND route.bound_name=?5 AND route.namespace=?6
 UNION ALL
 SELECT route.target_unit_key, route.target_module_path, selected.imported_name
 FROM selected_rust_unit_summaries AS unit
 CROSS JOIN main.resolution_unit_summary_members AS member
  ON member.summary_id=unit.summary_id AND member.blob_id=?3
 CROSS JOIN main.rust_resolution_unit_summary_import_routes AS route
  ON route.summary_id=unit.summary_id AND route.member_ordinal=member.member_ordinal
 CROSS JOIN source_rust_import_targets AS selected
  ON selected.blob_id=?7 AND selected.ordinal=route.route_ordinal
 WHERE ?7<>?3 AND unit.topology_id=?1 AND route.module_path=?2
  AND route.binder_scope=?4 AND route.namespace=?6 AND selected.bound_name=?5";
// The name a single-segment `use` spells at its root. `use serde as s;` and
// `use serde::{self as s};` state no module segment, so the import's target
// name is the root itself and an alias renames only the binding. The import
// fact carries both, which is what makes the root recoverable when the route
// is empty.
pub(super) const IMPORT_ROOT_NAME: &str = "SELECT source.imported_name
 FROM source_rust_import_targets AS source
 WHERE source.blob_id=?1 AND source.native_scope=?2 AND source.bound_name=?3
  AND source.is_glob=0 AND source.imported_name IS NOT NULL
  AND NOT EXISTS(SELECT 1 FROM source_rust_import_module_segments AS segment
                 WHERE segment.blob_id=source.blob_id
                   AND segment.import_ordinal=source.ordinal)";
pub(super) const GLOBS: &str = "SELECT route.target_unit_key, route.target_module_path,
 json((SELECT json_group_array(segment) FROM (
  SELECT segment FROM source_rust_import_module_segments
  WHERE blob_id=member.blob_id AND import_ordinal=route.route_ordinal ORDER BY ordinal)))
 FROM selected_rust_unit_summaries AS unit
 CROSS JOIN main.resolution_unit_summary_members AS member
  ON member.summary_id=unit.summary_id AND member.blob_id=?3
 CROSS JOIN main.rust_resolution_unit_summary_glob_imports AS route
  ON route.summary_id=unit.summary_id AND route.member_ordinal=member.member_ordinal
 WHERE unit.topology_id=?1 AND route.module_path=?2 AND route.binder_scope=?4";
pub(super) const SCOPES: &str = include_str!("rust_crate_point_scopes.sql");
/// The validity rule of one target unit, for the key `keys.unit_key`, at the
/// requester `owner`'s revision. It restates `selected_rust_unit_summaries`
/// (revisioned_workspace_views.sql) for one key, so a point query can seek each
/// target by primary key. The view is DDL and keeps its own copy: change the two
/// together. Both composed queries (`DEPENDENCY`, `REFERENCE_NAMES_WORKSPACE_CRATE`)
/// use this block, and each binds `target` and `target_context` from it.
///
/// `derivation_version_param` is the caller's placeholder for
/// [`RUST_UNIT_SUMMARY_DERIVATION_VERSION`], bound at the call site so the
/// reader tracks a version bump instead of repeating the literal.
pub(super) fn target_unit_joins(derivation_version_param: &str) -> String {
    format!(
        "CROSS JOIN main.resolution_unit_summary_versions AS target_version
 ON target_version.workspace_id=owner.workspace_id AND target_version.lang=owner.lang
AND target_version.generation=owner.generation AND target_version.unit_key=keys.unit_key
AND target_version.valid_from<=owner.revision
AND (target_version.valid_until IS NULL OR owner.revision<target_version.valid_until)
CROSS JOIN main.resolution_unit_summaries AS target_summary
 ON target_summary.summary_id=target_version.summary_id
AND target_summary.lang='rust' AND target_summary.unit_kind='rust_crate'
AND target_summary.publication_state='complete' AND target_summary.derivation_version={derivation_version_param}
CROSS JOIN main.resolution_producer_epochs AS epoch
 ON epoch.lang=target_version.lang AND epoch.producer_epoch=target_summary.producer_epoch
CROSS JOIN main.rust_resolution_unit_summary_contexts AS target_context
 ON target_context.summary_id=target_summary.summary_id
CROSS JOIN main.rust_resolution_unit_summary_versions AS target
 ON target.workspace_id=target_version.workspace_id AND target.lang=target_version.lang
AND target.generation=target_version.generation AND target.unit_key=target_version.unit_key
AND target.valid_from=target_version.valid_from AND target.summary_id=target_version.summary_id"
    )
}

/// The point dependency query: the owner's dependency keys under an extern name,
/// then each target's topology. The owner and key CTEs live in
/// rust_crate_point_dependency.sql.
#[doc(hidden)]
pub static DEPENDENCY: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        "{}SELECT target.topology_id\nFROM owner\nCROSS JOIN dependency_keys AS keys\n{}",
        include_str!("rust_crate_point_dependency.sql"),
        target_unit_joins("?3")
    )
});
pub(super) const PARENT: &str = "SELECT CASE container.parent_container_path WHEN '' THEN 'crate' ELSE container.parent_container_path END
 FROM selected_rust_unit_summaries AS unit
 CROSS JOIN main.resolution_unit_summary_containers AS container
  ON container.summary_id=unit.summary_id AND container.container_path=?2
 AND container.container_path<>''
 CROSS JOIN main.rust_resolution_unit_summary_container_attributes AS attributes
  ON attributes.summary_id=container.summary_id AND attributes.container_path=container.container_path
 AND attributes.kind='module'
 CROSS JOIN main.resolution_unit_summary_placements AS placement
  ON placement.summary_id=container.summary_id AND placement.container_path=container.container_path
 WHERE unit.topology_id=?1
 LIMIT 1";

/// Structured macro gates for a selected module import whose target module
/// has an unknown activation. The importer and target route come from the
/// persisted Cargo rows; the gate is tied to its source macro invocation.
/// This keeps a route behind an unexpanded item macro an explicit boundary
/// without treating the macro's tokens as expanded module declarations.
pub(super) fn macro_gated_import_route_details(
    conn: &rusqlite::Connection,
    module: &Module,
    name: &str,
    binder_scope: u32,
) -> Result<Vec<String>> {
    conn.prepare_cached(MACRO_GATED_IMPORT_ROUTE)?
        .query_map(
            params![
                module.topology,
                module.path,
                module.blob,
                binder_scope,
                name,
                module.selected_blob
            ],
            |row| row.get::<_, String>(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

pub(super) fn macro_gated_unmounted_file_details(
    conn: &rusqlite::Connection,
    relative_path: &str,
) -> Result<Vec<String>> {
    conn.prepare_cached(MACRO_GATED_UNMOUNTED_FILE)?
        .query_map([relative_path], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

pub(super) fn inactive_cfg_unmounted_file_details(
    conn: &rusqlite::Connection,
    relative_path: &str,
) -> Result<Vec<String>> {
    conn.prepare_cached(INACTIVE_CFG_UNMOUNTED_FILE)?
        .query_map([relative_path], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

pub(super) fn macro_gated_route_boundary(
    identities: &SelectedContextIdentities,
    details: &[String],
) -> ResolutionCompletion {
    ResolutionCompletion::incomplete(details.iter().map(|detail| {
        let mut digest = CanonicalHasher::new(b"bifrost-rust-unsupported-macro-route:v1");
        digest.field("evidence", detail.as_bytes());
        ResolutionIncompleteReason::UnsupportedSemantic(identities.named_semantic(
            digest.finish(),
            "UnsupportedMacroGeneratedModule",
            detail,
        ))
    }))
}

/// The topology of a route target's unit, or `None` when this selection holds
/// no summary for that unit. The caller decides what the absence means.
pub(super) fn selected_crate_topology(
    conn: &rusqlite::Connection,
    unit_key: &[u8],
) -> Result<Option<i64>> {
    conn.prepare_cached(CRATE)?
        .query_row([unit_key], |row| row.get(0))
        .optional()
        .map_err(Into::into)
}

/// A route target whose unit has no selected summary. A replaced blob
/// withdraws every summary that lists it until a reconcile derives the unit
/// again (`WITHDRAW_VERSIONS_OF_REPLACED_BLOB_SQL`), so this selection cannot
/// answer through that target. The route is an open boundary, not an absent
/// name, so it stays incomplete.
pub(super) fn unselected_target_boundary(
    identities: &SelectedContextIdentities,
    unit_key: &[u8],
) -> ResolutionCompletion {
    let mut digest = CanonicalHasher::new(b"bifrost-rust-unselected-route-target:v1");
    digest.field("unit_key", unit_key);
    ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
        identities.named_semantic(
            digest.finish(),
            "UnselectedRustRouteTarget",
            &format!("{unit_key:?}"),
        ),
    )])
}

pub(super) fn inactive_cfg_route_boundary(
    identities: &SelectedContextIdentities,
    details: &[String],
) -> ResolutionCompletion {
    ResolutionCompletion::incomplete(details.iter().map(|detail| {
        let mut digest = CanonicalHasher::new(b"bifrost-rust-inactive-cfg-route:v1");
        digest.field("evidence", detail.as_bytes());
        ResolutionIncompleteReason::UnsupportedSemantic(identities.named_semantic(
            digest.finish(),
            "InactiveCfgPlacement",
            detail,
        ))
    }))
}

pub(super) fn generated_item_surface_boundary(
    conn: &rusqlite::Connection,
    identities: &SelectedContextIdentities,
    targets: &[SemanticId],
) -> Result<ResolutionCompletion> {
    let origin = crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(
        crate::analyzer::resolution::LoweringGapOrigin::Extracted(
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::GeneratedItemSurface,
        ),
    );
    let mut details = Vec::new();
    for semantic in targets {
        let (Some(ordinal), Some(key)) = (semantic.ordinal(), semantic.local_key()) else {
            continue;
        };
        if conn
            .prepare_cached(REASON_GAP_ORIGIN)?
            .query_row(rusqlite::params![ordinal, key], |row| row.get::<_, i64>(0))
            .optional()?
            != Some(origin)
        {
            continue;
        }
        details.push(
            serde_json::json!({
                "evidence": [{
                    "reason": "GeneratedItemSurface",
                    "semantic": semantic.to_string(),
                }]
            })
            .to_string(),
        );
    }
    details.sort_unstable();
    details.dedup();
    if details.is_empty() {
        return Ok(ResolutionCompletion::Complete);
    }
    Ok(ResolutionCompletion::incomplete(details.iter().map(
        |detail| {
            let mut digest = CanonicalHasher::new(b"bifrost-rust-generated-item-surface:v1");
            digest.field("evidence", detail.as_bytes());
            ResolutionIncompleteReason::UnsupportedSemantic(identities.named_semantic(
                digest.finish(),
                GENERATED_ITEM_SURFACE_REASON,
                detail,
            ))
        },
    )))
}

/// The source declaration whose persisted attribute facts leave its generated
/// surface open. This covers a same-file qualified prefix whose route has no
/// semantic target to pass to `generated_item_surface_boundary`.
pub(super) fn generated_surface_prefix_boundary(
    conn: &rusqlite::Connection,
    identities: &SelectedContextIdentities,
    modules: &[Module],
    prefix_mount: Option<u32>,
    spelling: Option<&str>,
    route: &[ResolutionLookupSemanticRecipe],
) -> Result<ResolutionCompletion> {
    let Some(spelling) = spelling else {
        return Ok(ResolutionCompletion::Complete);
    };
    let mut detail = if let Some(prefix_mount) = prefix_mount {
        conn.prepare_cached(GENERATED_SURFACE_PREFIX)?
            .query_row(rusqlite::params![prefix_mount, spelling], |row| {
                row.get::<_, String>(0)
            })
            .optional()?
    } else {
        None
    };
    if detail.is_none()
        && let Some(prefix_mount) = prefix_mount
    {
        detail = conn
            .prepare_cached(GENERATED_SURFACE_MODULE_PREFIX)?
            .query_row(rusqlite::params![prefix_mount, spelling], |row| {
                row.get::<_, String>(0)
            })
            .optional()?;
    }
    if detail.is_none()
        && let Some(prefix_mount) = prefix_mount
    {
        detail = conn
            .prepare_cached(GENERATED_SURFACE_MODULE_DECLARATION_PREFIX)?
            .query_row(rusqlite::params![prefix_mount, spelling], |row| {
                row.get::<_, String>(0)
            })
            .optional()?;
    }
    if detail.is_none() {
        for name in std::iter::once(spelling).chain(route.iter().map(|segment| segment.spelling()))
        {
            if is_module_anchor(name) {
                continue;
            }
            if let Some(prefix_mount) = prefix_mount {
                detail = conn
                    .prepare_cached(GENERATED_SURFACE_MODULE_PREFIX)?
                    .query_row(rusqlite::params![prefix_mount, name], |row| {
                        row.get::<_, String>(0)
                    })
                    .optional()?;
            }
            if detail.is_none()
                && let Some(prefix_mount) = prefix_mount
            {
                detail = conn
                    .prepare_cached(GENERATED_SURFACE_MODULE_DECLARATION_PREFIX)?
                    .query_row(rusqlite::params![prefix_mount, name], |row| {
                        row.get::<_, String>(0)
                    })
                    .optional()?;
            }
            if detail.is_none() {
                for module in modules {
                    detail = conn
                        .prepare_cached(GENERATED_SURFACE_SOURCE_MODULE_PREFIX)?
                        .query_row(
                            rusqlite::params![module.blob, name, module.rel_path],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()?;
                    if detail.is_some() {
                        break;
                    }
                }
            }
            if detail.is_some() {
                break;
            }
        }
    }
    let Some(detail) = detail else {
        return Ok(ResolutionCompletion::Complete);
    };
    let mut digest = CanonicalHasher::new(b"bifrost-rust-generated-item-surface:v1");
    digest.field("evidence", detail.as_bytes());
    Ok(ResolutionCompletion::incomplete([
        ResolutionIncompleteReason::UnsupportedSemantic(identities.named_semantic(
            digest.finish(),
            GENERATED_ITEM_SURFACE_REASON,
            &detail,
        )),
    ]))
}
/// The selected import targets for a module prefix. The selected blob supplies
/// the bound name; the persisted import row supplies its already-proved route.
pub(super) const IMPORT_MODULE_PREFIX_STARTS: &str = concat!(
    "WITH binding(target_crate_key, target_module_path, target_name) AS (",
    " SELECT imports.target_crate_key, imports.target_module_path, imports.target_name",
    " FROM rust_crate_imports AS imports",
    " WHERE ?7=?3 AND imports.topology_id=?1 AND imports.module_path=?2 AND imports.blob_id=?3",
    " AND imports.binder_scope=?4 AND imports.bound_name=?5 AND imports.namespace=?6",
    " UNION ALL",
    " SELECT imports.target_crate_key, imports.target_module_path, selected.imported_name",
    " FROM rust_crate_imports AS imports",
    " CROSS JOIN source_rust_import_targets AS selected",
    " ON selected.blob_id=?7 AND selected.ordinal=imports.import_ordinal",
    " WHERE ?7<>?3 AND imports.topology_id=?1 AND imports.module_path=?2 AND imports.blob_id=?3",
    " AND imports.binder_scope=?4 AND imports.namespace=?6 AND selected.bound_name=?5",
    ")",
    " SELECT DISTINCT target.topology_id, binding.target_module_path, binding.target_name",
    " FROM binding",
    " CROSS JOIN selected_rust_crates AS target ON target.crate_key=binding.target_crate_key"
);

const MACRO_GATED_IMPORT_ROUTE: &str =
    "WITH binding(target_crate_key, target_module_path, target_name) AS (
 SELECT imports.target_crate_key, imports.target_module_path, imports.target_name
 FROM rust_crate_imports AS imports
 WHERE imports.topology_id=?1 AND imports.module_path=?2 AND imports.blob_id=?3
  AND imports.binder_scope=?4 AND imports.bound_name=?5 AND imports.namespace='type'
 UNION
 SELECT imports.target_crate_key, imports.target_module_path, selected.imported_name
 FROM rust_crate_imports AS imports
 CROSS JOIN source_rust_import_targets AS selected
  ON selected.blob_id=?6 AND selected.ordinal=imports.import_ordinal
 WHERE imports.topology_id=?1 AND imports.module_path=?2 AND imports.blob_id=?3
  AND imports.binder_scope=?4 AND imports.namespace='type' AND selected.bound_name=?5
)
SELECT DISTINCT json_object('evidence', json_array(json_object(
 'reason', 'UnsupportedMacroGeneratedModule',
 'member_blob', route.blob_id,
 'invocation_occurrence', gate.invocation_occurrence_id,
 'macro', invocation.macro_name,
 'replay_covered', json('false'),
 'route_subject', gap.subject)))
FROM binding
CROSS JOIN selected_rust_crates AS target ON target.crate_key=binding.target_crate_key
CROSS JOIN rust_crate_gaps AS gap ON gap.topology_id=target.topology_id
 AND gap.gap_kind='unknown_activation'
 AND gap.subject=binding.target_module_path || '::' || binding.target_name
CROSS JOIN source_rust_module_routes AS route
 ON route.blob_id=json_extract(gap.detail, '$.member_blob')
 AND route.declaration_id=json_extract(gap.detail, '$.declaration_id')
CROSS JOIN source_rust_module_route_gates AS gate
 ON gate.blob_id=route.blob_id AND gate.route_ordinal=route.ordinal
CROSS JOIN source_rust_macro_invocations AS invocation
 ON invocation.blob_id=gate.blob_id AND invocation.occurrence_id=gate.invocation_occurrence_id";

const MACRO_GATED_UNMOUNTED_FILE: &str = "WITH RECURSIVE ancestors(path) AS (
 SELECT ?1
 UNION ALL SELECT cr_parent(path) FROM ancestors WHERE path NOT IN ('', '.')
)
SELECT DISTINCT json_object('evidence', json_array(json_object(
 'reason', 'UnsupportedMacroGeneratedModule',
 'member_blob', route.blob_id,
 'invocation_occurrence', gate.invocation_occurrence_id,
 'macro', invocation.macro_name,
 'replay_covered', json('false'),
 'route_subject', gap.subject)))
FROM ancestors
CROSS JOIN rust_crate_container_sources AS parent
CROSS JOIN selected_rust_crates AS selected ON selected.topology_id=parent.topology_id
CROSS JOIN source_rust_module_routes AS route ON route.blob_id=parent.blob_id
CROSS JOIN source_rust_module_declarations AS declaration
 ON declaration.blob_id=route.blob_id AND declaration.declaration_id=route.declaration_id
CROSS JOIN rust_crate_gaps AS gap ON gap.topology_id=parent.topology_id
 AND gap.gap_kind='unknown_activation'
 AND gap.subject=parent.container_path || '::' || declaration.module_name
CROSS JOIN source_rust_module_route_gates AS gate
 ON gate.blob_id=route.blob_id AND gate.route_ordinal=route.ordinal
CROSS JOIN source_rust_macro_invocations AS invocation
 ON invocation.blob_id=gate.blob_id AND invocation.occurrence_id=gate.invocation_occurrence_id
WHERE ancestors.path=cr_join(cr_parent(parent.rel_path), declaration.module_name)";

const INACTIVE_CFG_UNMOUNTED_FILE: &str =
    "SELECT DISTINCT json_object('evidence', json_array(json_object(
 'reason', 'InactiveCfgPlacement',
 'rel_path', json_extract(gap.detail, '$.path'),
 'route_subject', gap.subject,
 'activation', json_extract(gap.detail, '$.activation'))))
FROM rust_crate_gaps AS gap
CROSS JOIN selected_rust_crates AS selected ON selected.topology_id=gap.topology_id
WHERE gap.gap_kind='inactive_placement'
 AND json_extract(gap.detail, '$.path')=?1
 AND json_extract(gap.detail, '$.activation')=0
ORDER BY gap.subject";
/// Source gap conditions: derive-helper names of module-level declarations and
/// directly proven inactive macro inputs. A NULL helper is an inactive-input proof.
/// The derive-helper attribute names of the module-level declarations a
/// lookup reached, with the open binder gap the producer left on each
/// declaration site (origin ?1) and every placement of the declaration.
///
/// `?2` is a JSON array of `[mount_ordinal, reason]` pairs naming what the
/// lookup reached: a `null` reason names every candidate declaration of the
/// mount's blob, a number names the one declaration whose gap carries that
/// reason. A blob holds few derive-helper declarations and the partial index
/// reads only them, so both forms cost one seek per reached mount.
pub(super) const DERIVE_HELPER_CONDITIONS: &str = "SELECT mount.mount_ordinal, gap.reason,
 helper.value, placement.topology_id, placement.container_path
 FROM json_each(?2) AS reached
 CROSS JOIN temp.selected_resolution_mounts AS mount
  ON mount.mount_ordinal=reached.value->>0
 CROSS JOIN source_rust_declaration_properties AS property
  INDEXED BY source_rust_declaration_properties_derive_helpers
  ON property.blob_id=mount.blob_id AND property.derive_helper_attributes IS NOT NULL
 CROSS JOIN json_each(property.derive_helper_attributes) AS helper
 CROSS JOIN source_native_declaration_bridges AS bridge
  ON bridge.blob_id=property.blob_id AND bridge.declaration_id=property.declaration_id
 CROSS JOIN resolution_gap_reasons AS gap
  ON gap.blob_id=bridge.blob_id AND gap.site=bridge.source_site AND gap.origin=?1
  AND (reached.value->>1 IS NULL OR gap.reason=reached.value->>1)
 CROSS JOIN resolution_rust_declaration_authorities AS authority
  ON authority.blob_id=bridge.blob_id AND authority.semantic_key=bridge.source_site
 CROSS JOIN selected_rust_container_placements AS placement
  ON placement.mount_ordinal=mount.mount_ordinal
  AND placement.module_declaration IS authority.module_declaration
 WHERE mount.storage_language='rust' AND property.nearest_declaration_boundary=0
 UNION ALL
 -- A macro input in a proven-inactive source placement cannot add names or
 -- members. A NULL helper denotes this direct cfg proof, not a helper lookup.
 SELECT mount.mount_ordinal, gap.reason, NULL, 0, ''
 FROM json_each(?2) AS reached
 CROSS JOIN temp.selected_resolution_mounts AS mount
  ON mount.mount_ordinal=reached.value->>0
 CROSS JOIN main.source_rust_macro_inputs AS input
  INDEXED BY source_rust_macro_inputs_conditional_frontier
  ON input.blob_id=mount.blob_id AND input.cfg_condition<>'always'
  AND input.native_gap_site IS NOT NULL
 CROSS JOIN main.resolution_gap_reasons AS gap
  INDEXED BY resolution_gap_reasons_site
  ON gap.blob_id=input.blob_id AND gap.site=input.native_gap_site
  AND (reached.value->>1 IS NULL OR gap.reason=reached.value->>1)
 WHERE mount.storage_language='rust'
  AND EXISTS (
   SELECT 1 FROM main.resolution_unit_summary_members AS member
    INDEXED BY resolution_unit_summary_members_blob
   CROSS JOIN selected_rust_unit_summaries AS selected
    ON selected.summary_id=member.summary_id
   WHERE member.blob_id=input.blob_id)
  AND NOT EXISTS (
   SELECT 1 FROM main.resolution_unit_summary_members AS member
    INDEXED BY resolution_unit_summary_members_blob
   CROSS JOIN selected_rust_unit_summaries AS selected
    ON selected.summary_id=member.summary_id
   LEFT JOIN main.rust_resolution_unit_summary_contexts AS context
    ON context.summary_id=selected.summary_id
   WHERE member.blob_id=input.blob_id
    AND CASE WHEN context.summary_id IS NULL THEN -1
             ELSE cr_cfg(input.cfg_condition,json(context.cfg_atoms)) END<>0)
 ORDER BY 1, 2, 3, 4, 5";
pub(super) const EXTERNAL_BINDING: &str = concat!(
    include_str!("rust_crate_point_targets.sql"),
    include_str!("rust_crate_point_external.sql")
);
/// Whether a route step spells one of Rust's module anchors.
///
/// `crate`, `self` and `super` are keywords, so no declaration can carry one
/// of these spellings and a demand that does is always an anchor occurrence.
pub(super) fn is_module_anchor(spelling: &str) -> bool {
    matches!(spelling, "crate" | "self" | "super")
}

pub(super) const CONTAINER_DECLARATION: &str = "SELECT CASE parent.container_path WHEN '' THEN 'crate' ELSE parent.container_path END, declaration.module_name
 FROM selected_rust_unit_summaries AS unit
 CROSS JOIN main.resolution_unit_summary_placements AS child
  ON child.summary_id=unit.summary_id AND child.container_path=CASE ?2 WHEN 'crate' THEN '' ELSE ?2 END
 CROSS JOIN main.resolution_unit_summary_containers AS container
  ON container.summary_id=child.summary_id AND container.container_path=child.container_path
 CROSS JOIN main.resolution_unit_summary_placements AS parent
  ON parent.summary_id=child.summary_id AND parent.container_path=container.parent_container_path
 CROSS JOIN main.resolution_unit_summary_members AS member
  ON member.summary_id=parent.summary_id AND member.member_ordinal=parent.member_ordinal
 CROSS JOIN source_rust_module_inventory AS declaration
  ON declaration.blob_id=member.blob_id
 AND declaration.parent_scope_ordinal=parent.scope_ordinal
 WHERE unit.topology_id=?1
  AND CASE parent.container_path WHEN '' THEN 'crate' ELSE parent.container_path END || '::' || declaration.module_name=?2";
pub(super) const DEFINITION_MODULE: &str = "SELECT selected.topology_id, modules.module_path
 FROM source_native_declaration_bridges AS bridge
 CROSS JOIN source_declaration_units AS mapping
  ON mapping.blob_id=bridge.blob_id AND mapping.declaration_id=bridge.declaration_id
 CROSS JOIN code_units AS unit ON unit.blob_id=mapping.blob_id AND unit.unit_key=mapping.unit_key
 CROSS JOIN selected_rust_unit_summaries AS selected ON selected.topology_id=?3
 CROSS JOIN main.rust_unit_summary_containers AS modules
  ON modules.summary_id=selected.summary_id
 AND modules.module_path=?4 || '::' || unit.identifier
 WHERE bridge.blob_id=?1 AND bridge.source_site=?2";
/// The module a `mod` item names when the crate declared the item for a
/// cross-file passthrough invocation: `DEFINITION_MODULE` for a
/// `rust_crate_macro_items` row. `?1`/`?2` are the item's blob and declaration
/// replay's declaration, `?3`/`?4` the module that holds it, `?5` its name.
pub(super) const MACRO_ITEM_MODULE: &str = "SELECT unit.topology_id, modules.module_path
 FROM selected_rust_unit_summaries AS unit
 CROSS JOIN main.resolution_unit_summary_members AS member
  ON member.summary_id=unit.summary_id AND member.blob_id=?1
 CROSS JOIN main.rust_resolution_unit_summary_generated_names AS item
  ON item.summary_id=unit.summary_id AND item.member_ordinal=member.member_ordinal
 CROSS JOIN main.rust_unit_summary_containers AS modules
  ON modules.summary_id=unit.summary_id
 AND modules.module_path=item.module_path || '::' || item.name
 WHERE unit.topology_id=?3 AND item.module_path=?4 AND item.namespace='type' AND item.name=?5
  AND item.declaration_id=?2 AND item.module_item=1";
/// The byte range of the name declaration replay recorded for one of its
/// declarations, in the host file's coordinates, and whether it declares a
/// module: `?1` is the blob, `?2` the declaration. A crate-declared macro
/// item's capsule definition is staged at exactly this range, except a
/// module's: a capsule mints no declaration for a `mod` in a token tree,
/// because the module route facts own it (`lower_macro_fragment`), so a module
/// item has no definition to stage.
pub(super) const MACRO_ITEM_NAME_RANGE: &str = "SELECT declaration.name_start_byte,
  declaration.name_end_byte, properties.declaration_kind IN (4, 5)
 FROM source_declarations AS declaration
 CROSS JOIN source_rust_declaration_properties AS properties
  ON properties.blob_id=declaration.blob_id AND properties.declaration_id=declaration.declaration_id
 WHERE declaration.blob_id=?1 AND declaration.declaration_id=?2";
/// The container of the module an item macro declares, as a crate row, in
/// module `?2` of topology `?1` under the name `?3` (`rust_crate_macro_items`,
/// `module_item`). A bare path prefix is looked up in its own module, and such
/// a module has no lexical binder there, so a prefix that names one starts its
/// route here.
pub(super) const NAMED_MACRO_MODULE: &str = "SELECT unit.topology_id, modules.module_path
 FROM selected_rust_unit_summaries AS unit
 CROSS JOIN main.rust_resolution_unit_summary_generated_names AS item
  ON item.summary_id=unit.summary_id
 CROSS JOIN main.rust_unit_summary_containers AS modules
  ON modules.summary_id=unit.summary_id
 AND modules.module_path=item.module_path || '::' || item.name
 WHERE unit.topology_id=?1 AND item.module_path=?2
  AND item.namespace='type' AND item.name=?3 AND item.module_item=1";
/// Whether any selected crate declared an item for a cross-file passthrough
/// invocation. A request with none has no host to stage.
pub(super) const MACRO_ITEMS_PRESENT: &str = "SELECT 1
 FROM selected_rust_unit_summaries AS unit
 CROSS JOIN main.rust_resolution_unit_summary_generated_names AS item
  ON item.summary_id=unit.summary_id
 LIMIT 1";
/// The files whose capsules define the crate-declared items
/// (`rust_crate_macro_items`) that the selected file `?1` spells: a name one of
/// its references looks up, or one of its routes (a `use` or a qualified
/// path) ends with. A request stages these before it resolves references in
/// `?1`, so the export lookup can reach the item's definition; a renamed
/// import in the file still spells the item's own name in its route.
pub(super) const MACRO_ITEM_HOSTS: &str = "WITH mount AS (
  SELECT blob_id FROM temp.selected_resolution_mounts
  WHERE storage_language='rust' AND persisted_relative_path=?1
), names(name) AS (
  SELECT identity.spelling FROM mount
  CROSS JOIN resolution_reference_lookup_identities AS reference ON reference.blob_id=mount.blob_id
  CROSS JOIN resolution_identities AS identity ON identity.id=reference.identity_id
  WHERE identity.spelling IS NOT NULL
  UNION
  SELECT segment.terminal_spelling FROM mount
  CROSS JOIN resolution_root_route_segments AS segment ON segment.blob_id=mount.blob_id
  WHERE segment.terminal_spelling IS NOT NULL
)
SELECT DISTINCT member.rel_path
 FROM names
 CROSS JOIN main.rust_resolution_unit_summary_generated_names AS item
  INDEXED BY rust_resolution_unit_summary_generated_names_name
  ON item.name=names.name
 CROSS JOIN selected_rust_unit_summaries AS unit ON unit.summary_id=item.summary_id
 CROSS JOIN main.resolution_unit_summary_members AS member
  ON member.summary_id=item.summary_id AND member.member_ordinal=item.member_ordinal";
// Point readers consume the published own-binding authority, with request-time projections.
#[doc(hidden)]
pub const PUBLISHED_EXPORT: &str = concat!(
    include_str!("rust_crate_published_bindings.sql"),
    include_str!("rust_crate_published_macro_prelude.sql"),
    include_str!("rust_crate_published_targets.sql"),
    include_str!("rust_crate_point_export.sql"),
    " ORDER BY 1,2,3,4,5,6"
);
pub(super) const PUBLISHED_ROOT_REEXPORT: &str = concat!(
    include_str!("rust_crate_published_bindings.sql"),
    include_str!("rust_crate_published_macro_prelude.sql"),
    include_str!("rust_crate_published_targets.sql"),
    "SELECT DISTINCT topology_id FROM targets WHERE module_path='crate' AND name='self' ORDER BY 1"
);
pub(super) const PUBLISHED_MODULE_PREFIX_ROUTE: &str = concat!(
    include_str!("rust_crate_published_bindings.sql"),
    include_str!("rust_crate_published_macro_prelude.sql"),
    include_str!("rust_crate_published_targets.sql"),
    "SELECT DISTINCT targets.topology_id,",
    " CASE WHEN targets.name='self' THEN targets.module_path",
    " ELSE targets.module_path || '::' || targets.name END AS container_path",
    " FROM targets",
    " CROSS JOIN rust_crate_containers AS container ON container.topology_id=targets.topology_id",
    " AND container.kind='module'",
    " AND container.container_path=CASE WHEN targets.name='self' THEN targets.module_path",
    " ELSE targets.module_path || '::' || targets.name END ORDER BY 1,2"
);
#[doc(hidden)]
pub const PUBLISHED_OPEN_INVENTORY: &str = concat!(
    include_str!("rust_crate_published_bindings.sql"),
    include_str!("rust_crate_published_macro_prelude.sql"),
    include_str!("rust_crate_published_targets.sql"),
    include_str!("rust_crate_published_inventory.sql")
);
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub const PUBLISHED_MACRO_PRELUDE: &str = concat!(
    include_str!("rust_crate_published_bindings.sql"),
    include_str!("rust_crate_published_macro_prelude.sql"),
    "SELECT owner_id FROM macro_prelude_owners ORDER BY owner_id"
);
pub(super) const PUBLISHED_BINDING_EXACT: &str = concat!(
    include_str!("rust_crate_published_bindings.sql"),
    include_str!("rust_crate_published_exact.sql")
);
/// A listed certificate, its completeness, and the accessible endpoints. An
/// endpoint keeps a NULL topology when its target unit is not selected.
pub(super) type PublishedBindingExact = (bool, Vec<(Option<i64>, String, String)>);

pub(super) fn published_binding_exact(
    conn: &rusqlite::Connection,
    topology: i64,
    path: &str,
    namespace: &str,
    name: &str,
    requester_topology: i64,
    requester_path: &str,
) -> Result<Option<PublishedBindingExact>> {
    let mut answer: Option<PublishedBindingExact> = None;
    for row in conn.prepare_cached(PUBLISHED_BINDING_EXACT)?.query_map(
        params![
            topology,
            path,
            namespace,
            name,
            requester_topology,
            requester_path
        ],
        |row| {
            Ok((
                row.get::<_, bool>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        },
    )? {
        let (complete, topology, path, name) = row?;
        let (certificate_complete, endpoints) =
            answer.get_or_insert_with(|| (complete, Vec::new()));
        debug_assert_eq!(*certificate_complete, complete);
        if let Some(path) = path {
            endpoints.push((topology, path, name.expect("an endpoint has a target name")));
        }
    }
    Ok(answer)
}

/// Module and crate-root continuations admitted for one binding and requester.
pub(super) fn published_module_starts(
    conn: &rusqlite::Connection,
    topology: i64,
    path: &str,
    name: &str,
    requester_topology: i64,
    requester_path: &str,
) -> Result<Vec<(i64, String)>> {
    Ok(conn
        .prepare_cached(PUBLISHED_MODULE_PREFIX_ROUTE)?
        .query_map(
            params![
                topology,
                path,
                "type",
                name,
                requester_topology,
                requester_path
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}
pub(super) const BINDING_TARGET_TOPOLOGY: &str = "SELECT topology_id
 FROM selected_rust_unit_summaries WHERE unit_key=unhex(?1)";
pub(super) const BINDING_INVENTORY: &str = "SELECT json_object('evidence',json_group_array(json(evidence.value)))
 FROM selected_rust_unit_summaries unit CROSS JOIN main.rust_resolution_unit_summary_gaps gap
 ON gap.summary_id=unit.summary_id AND gap.gap_kind='open_export_inventory' AND gap.subject=?2 || '::' || ?4
 CROSS JOIN json_each(gap.detail,'$.evidence') evidence
 WHERE unit.topology_id=?1 AND json_extract(evidence.value,'$.member_blob')=?5
 AND json_extract(evidence.value,'$.binder_scope')=?6
 AND json_extract(evidence.value,'$.reason') IN ('InconsistentPrecedence','CyclicExpansion','OpenBoundary','UnsupportedImportTarget','UnsupportedGlobConflictVisibility')
 AND (?3='' OR json_extract(evidence.value,'$.namespace') IS NULL OR json_extract(evidence.value,'$.namespace')=?3)
 GROUP BY gap.summary_id,gap.subject
 UNION ALL
 SELECT json(gap.detail) FROM selected_rust_unit_summaries unit
 CROSS JOIN main.rust_resolution_unit_summary_gaps gap ON gap.summary_id=unit.summary_id
 AND gap.subject=?2 AND gap.gap_kind IN ('open_export_inventory','unknown_activation','unresolved_visibility')
 WHERE unit.topology_id=?1 AND EXISTS(
 SELECT 1 FROM main.rust_resolution_unit_summary_gaps scoped
 CROSS JOIN json_each(scoped.detail,'$.evidence') evidence
 WHERE scoped.summary_id=unit.summary_id AND scoped.gap_kind='open_export_inventory' AND scoped.subject=?2 || '::' || ?4
 AND json_extract(evidence.value,'$.member_blob')=?5 AND json_extract(evidence.value,'$.binder_scope')=?6
 AND (?3='' OR json_extract(evidence.value,'$.namespace')=?3) AND json_extract(evidence.value,'$.reason')='OpenBoundary'
 AND json_extract(evidence.value,'$.boundary')='workspace_local')";
pub(super) const UNKNOWN_IMPORT_INVENTORY: &str = "SELECT json_object('evidence',json_group_array(json(evidence.value)))
 FROM selected_rust_unit_summaries AS unit
 CROSS JOIN main.rust_resolution_unit_summary_gaps AS gap
  ON gap.summary_id=unit.summary_id AND gap.gap_kind IN ('unknown_activation','open_export_inventory')
 CROSS JOIN json_each(gap.detail,'$.evidence') AS evidence
 WHERE unit.topology_id=?1 AND gap.subject IN (?2, ?2 || '::' || ?3)
 AND (gap.gap_kind='unknown_activation' AND json_extract(evidence.value,'$.import_ordinal') IS NOT NULL
 AND ((?5=0 AND ?6=0) OR (json_extract(evidence.value,'$.member_blob')=?5 AND json_extract(evidence.value,'$.binder_scope')=?6))
 OR (json_extract(evidence.value,'$.member_blob')=?5
 AND json_extract(evidence.value,'$.binder_scope')=?6
 AND json_extract(evidence.value,'$.reason') IN ('InconsistentPrecedence','CyclicExpansion','OpenBoundary','UnsupportedImportTarget','UnsupportedGlobConflictVisibility')
 AND (json_extract(evidence.value,'$.namespace') IS NULL OR json_extract(evidence.value,'$.namespace')=?4)))
 GROUP BY gap.summary_id,gap.gap_kind,gap.subject";
#[doc(hidden)]
pub const UNINDEXED_SCOPE: &str = concat!(
    include_str!("rust_crate_point_targets.sql"),
    include_str!("rust_crate_point_unindexed_scope.sql"),
);
pub(super) const OPEN_ROUTE: &str = "SELECT json(gap.detail)
 FROM selected_rust_unit_summaries AS unit
 CROSS JOIN main.rust_resolution_unit_summary_gaps AS gap
  ON gap.summary_id=unit.summary_id
 WHERE unit.topology_id=?1
  AND gap.gap_kind IN ('unknown_activation','unplaced_module','duplicate_placement')
  AND gap.subject=?2 || '::' || ?3";
pub(super) const GAP_DETAILS: &str = include_str!("rust_crate_point_gap_details.sql");
pub(super) const IMPORT_INVENTORY: &str = "SELECT json_array(imports.native_scope, imports.bound_name, imports.imported_name, imports.is_glob, imports.leading_absolute, imports.is_extern_crate, imports.is_macro_use, imports.visibility, imports.cfg_condition, imports.owner_module, imports.local_start IS NOT NULL, json((SELECT json_group_array(segment) FROM (SELECT segment FROM source_rust_import_module_segments WHERE blob_id=imports.blob_id AND import_ordinal=imports.ordinal ORDER BY ordinal)))) FROM source_rust_import_targets AS imports WHERE imports.blob_id=?1 ORDER BY imports.ordinal";
pub(super) const OVERLAY_IMPORT_TARGETS: &str = r#"SELECT DISTINCT target.topology_id, route.target_module_path, route.namespace,
 owner.topology_id, route.module_path
 FROM main.resolution_unit_summary_members AS member
  INDEXED BY resolution_unit_summary_members_blob
 CROSS JOIN selected_rust_unit_summaries AS owner ON owner.summary_id=member.summary_id
 CROSS JOIN source_rust_import_targets AS source
  ON source.blob_id=member.blob_id AND source.ordinal=?2
 CROSS JOIN main.rust_resolution_unit_summary_import_routes AS route
  ON route.summary_id=owner.summary_id
 AND route.member_ordinal=member.member_ordinal
 AND route.import_id=source.source_import_id
 AND route.route_ordinal=source.ordinal
 CROSS JOIN selected_rust_unit_summaries AS target
  ON target.unit_key=route.target_unit_key
 WHERE member.blob_id=?1"#;
pub(in crate::analyzer::store) const MACRO_HOST_FILES: &str = r#"SELECT DISTINCT host_member.rel_path
 FROM temp.selected_resolution_mounts AS included_mount
 CROSS JOIN main.resolution_unit_summary_members AS included_member
  INDEXED BY resolution_unit_summary_members_blob
  ON included_member.blob_id=included_mount.blob_id
 AND included_member.rel_path=included_mount.persisted_relative_path
 CROSS JOIN selected_rust_unit_summaries AS unit
  ON unit.summary_id=included_member.summary_id
 CROSS JOIN main.rust_unit_summary_placements AS included
  ON included.summary_id=unit.summary_id
 AND included.member_ordinal=included_member.member_ordinal
 AND included.source_kind='include'
 CROSS JOIN main.rust_unit_summary_placements AS host
  ON host.summary_id=included.summary_id AND host.module_path=included.module_path
 CROSS JOIN main.resolution_unit_summary_members AS host_member
  ON host_member.summary_id=host.summary_id AND host_member.member_ordinal=host.member_ordinal
 CROSS JOIN rust_include_edges AS edge ON edge.blob_id=host_member.blob_id
  AND included_member.rel_path LIKE '%' || edge.file_name
 WHERE included_mount.storage_language='rust'
  AND included_mount.persisted_relative_path=?1"#;
/// Every file above the files in the JSON array `?1` in the textual-macro
/// climb, with the byte at which each one brings the file below it in:
/// `(child, parent, position)`.
///
/// The summary-owned placements keep each edge within one live crate version.
/// The selected mount and member blob index seek each requested path; parent
/// placements are then reached by the child's indexed module path. Source
/// module routes and include edges continue to supply the structured source
/// coordinates used by the walk.
#[doc(hidden)]
pub const MACRO_WALK_ANCESTRY: &str = r#"WITH RECURSIVE climb(summary_id, child, parent, position) AS (
 SELECT NULL, NULL, requested.value, NULL FROM json_each(?1) AS requested
 UNION
 SELECT unit.summary_id, climb.parent, parent_member.rel_path, route.declaration_start
 FROM climb
 CROSS JOIN temp.selected_resolution_mounts AS child_mount
  ON child_mount.storage_language='rust'
 AND child_mount.persisted_relative_path=climb.parent
 CROSS JOIN main.resolution_unit_summary_members AS child_member
  INDEXED BY resolution_unit_summary_members_blob
  ON child_member.blob_id=child_mount.blob_id
 AND child_member.rel_path=child_mount.persisted_relative_path
 CROSS JOIN selected_rust_unit_summaries AS unit
  ON unit.summary_id=child_member.summary_id
 AND (climb.summary_id IS NULL OR climb.summary_id=unit.summary_id)
 CROSS JOIN main.rust_unit_summary_placements AS child
  ON child.summary_id=unit.summary_id
 AND child.member_ordinal=child_member.member_ordinal
 AND child.source_kind='declared'
 CROSS JOIN main.resolution_unit_summary_placements AS parent
  ON parent.summary_id=child.summary_id
 AND parent.container_path=CASE child.parent_module_path WHEN 'crate' THEN '' ELSE child.parent_module_path END
 CROSS JOIN main.rust_resolution_unit_summary_placement_attributes AS parent_attributes
  ON parent_attributes.summary_id=parent.summary_id AND parent_attributes.container_path=parent.container_path
 AND parent_attributes.member_ordinal=parent.member_ordinal
 AND parent_attributes.source_kind='declared'
 CROSS JOIN main.resolution_unit_summary_members AS parent_member
  ON parent_member.summary_id=parent.summary_id
 AND parent_member.member_ordinal=parent.member_ordinal
 CROSS JOIN rust_module_routes AS route
  ON route.blob_id=parent_member.blob_id
 AND child.module_path=CASE parent.container_path WHEN '' THEN 'crate' ELSE parent.container_path END || '::' || route.module_name
 UNION
 SELECT unit.summary_id, climb.parent, host_member.rel_path, edge.include_start
 FROM climb
 CROSS JOIN temp.selected_resolution_mounts AS included_mount
  ON included_mount.storage_language='rust'
 AND included_mount.persisted_relative_path=climb.parent
 CROSS JOIN main.resolution_unit_summary_members AS included_member
  INDEXED BY resolution_unit_summary_members_blob
  ON included_member.blob_id=included_mount.blob_id
 AND included_member.rel_path=included_mount.persisted_relative_path
 CROSS JOIN selected_rust_unit_summaries AS unit
  ON unit.summary_id=included_member.summary_id
 AND (climb.summary_id IS NULL OR climb.summary_id=unit.summary_id)
 CROSS JOIN main.rust_unit_summary_placements AS included
  ON included.summary_id=unit.summary_id
 AND included.member_ordinal=included_member.member_ordinal
 AND included.source_kind='include'
 CROSS JOIN main.rust_unit_summary_placements AS host
  ON host.summary_id=included.summary_id AND host.module_path=included.module_path
 CROSS JOIN main.resolution_unit_summary_members AS host_member
  ON host_member.summary_id=host.summary_id AND host_member.member_ordinal=host.member_ordinal
 CROSS JOIN rust_include_edges AS edge ON edge.blob_id=host_member.blob_id
  AND included_member.rel_path LIKE '%' || edge.file_name
) SELECT child, parent, position FROM climb WHERE child IS NOT NULL"#;
/// The files of the child module `?2` that `?1` declares.
/// A `#[macro_use] mod x;` makes `x`'s macros visible after the declaration,
/// so the walk descends into the child it names.
pub(in crate::analyzer::store) const MACRO_WALK_CHILD_MODULE_FILES: &str = r#"SELECT DISTINCT child_member.rel_path
 FROM selected_rust_unit_members AS parent_member
 CROSS JOIN main.rust_unit_summary_placements AS parent
  ON parent.summary_id=parent_member.summary_id
 AND parent.member_ordinal=parent_member.member_ordinal
 AND parent.source_kind='declared'
 CROSS JOIN main.rust_unit_summary_placements AS child
  ON child.summary_id=parent.summary_id
 AND child.module_path=parent.module_path || '::' || ?2
 AND child.source_kind='declared'
 CROSS JOIN main.resolution_unit_summary_members AS child_member
  ON child_member.summary_id=child.summary_id AND child_member.member_ordinal=child.member_ordinal
 WHERE parent_member.rel_path=?1"#;
/// The file `?1` includes under the file name `?2`.
/// Read by the same walk and by the overlay's include-splice component walk.
pub(in crate::analyzer::store) const MACRO_INCLUDED_FILE: &str = r#"SELECT DISTINCT included_member.rel_path
 FROM temp.selected_resolution_mounts AS host_mount
 CROSS JOIN main.resolution_unit_summary_members AS host_member
  INDEXED BY resolution_unit_summary_members_blob
  ON host_member.blob_id=host_mount.blob_id
 AND host_member.rel_path=host_mount.persisted_relative_path
 CROSS JOIN selected_rust_unit_summaries AS unit
  ON unit.summary_id=host_member.summary_id
 CROSS JOIN main.rust_unit_summary_placements AS host
  ON host.summary_id=unit.summary_id AND host.member_ordinal=host_member.member_ordinal
 CROSS JOIN main.rust_unit_summary_placements AS included
  ON included.summary_id=host.summary_id AND included.module_path=host.module_path
 AND included.source_kind='include'
 CROSS JOIN main.resolution_unit_summary_members AS included_member
  ON included_member.summary_id=included.summary_id
 AND included_member.member_ordinal=included.member_ordinal
 WHERE host_mount.storage_language='rust'
  AND host_mount.persisted_relative_path=?1
  AND included_member.rel_path LIKE '%' || ?2"#;
/// Every byte at which `?1` includes a file the selection carries.
#[doc(hidden)]
pub const MACRO_INCLUDE_STARTS: &str = r#"SELECT DISTINCT edge.include_start, included_member.rel_path, included_member.blob_id
 FROM temp.selected_resolution_mounts AS host_mount
 CROSS JOIN main.resolution_unit_summary_members AS host_member
  INDEXED BY resolution_unit_summary_members_blob
  ON host_member.blob_id=host_mount.blob_id
 AND host_member.rel_path=host_mount.persisted_relative_path
 CROSS JOIN selected_rust_unit_summaries AS unit
  ON unit.summary_id=host_member.summary_id
 CROSS JOIN main.rust_unit_summary_placements AS host
  ON host.summary_id=unit.summary_id AND host.member_ordinal=host_member.member_ordinal
 CROSS JOIN rust_include_edges AS edge ON edge.blob_id=host_member.blob_id
 CROSS JOIN main.rust_unit_summary_placements AS included
  ON included.summary_id=host.summary_id AND included.module_path=host.module_path
 AND included.source_kind='include'
 CROSS JOIN main.resolution_unit_summary_members AS included_member
  ON included_member.summary_id=included.summary_id
 AND included_member.member_ordinal=included.member_ordinal
 AND included_member.rel_path LIKE '%' || edge.file_name
 WHERE host_mount.storage_language='rust'
  AND host_mount.persisted_relative_path=?1"#;
pub(super) const GAPS: &str = "SELECT gap.gap_kind, gap.subject, json(gap.detail)
 FROM selected_rust_unit_summaries AS unit
 CROSS JOIN main.rust_resolution_unit_summary_gaps AS gap
  ON gap.summary_id=unit.summary_id
 WHERE unit.topology_id=?1";
/// How many of the requested crate keys are a synthetic `detached` topology.
///
/// A file Cargo never described still gets a crate row, a topology of its own
/// holding only that file, so its dependency closure is that file. That is not
/// a scope, it is the absence of one, and narrowing to it would hide every
/// answer the lexical route finds in a workspace with no manifest. A request
/// that names such a crate binds into the whole selection, as it did before
/// this scope existed.
#[doc(hidden)]
pub const DETACHED_SCOPE_CRATES: &str = "SELECT COUNT(*) FROM selected_rust_unit_summaries AS unit
 CROSS JOIN main.rust_resolution_unit_summary_contexts AS context
  ON context.summary_id=unit.summary_id
 WHERE context.target_kind='detached' AND unit.unit_key IN ";
/// The mounts of the crates in the transitive dependency closure of the
/// requested crate keys.
///
/// The closure is per selected unit, never per package: a crate key names one
/// Cargo target, the summary dependency rows carry that target's own
/// `dependency_kind` rows (`cargo_route_available_to_target` decides them at
/// derivation), so a test target reaches its dev-dependencies and the library
/// target of the same package does not. `UNION`, not `UNION ALL`, terminates
/// the walk on the dev-dependency cycle Cargo allows, where A dev-depends on B
/// and B depends on A.
///
/// The statement drives from the live summary closure to its member files to the
/// selection's `UNIQUE(storage_language, persisted_relative_path)` index, so
/// it costs one primary-key range per summary and one index seek per member
/// file rather than a pass over the selection or Rust topology sources.
#[doc(hidden)]
pub const CLOSURE_SCOPE_MOUNTS_HEAD: &str =
    "INSERT OR IGNORE INTO temp.selected_resolution_scope_mounts(mount_ordinal)
 SELECT DISTINCT mount.mount_ordinal
 FROM selected_rust_unit_closure AS closure
 CROSS JOIN selected_rust_unit_members AS member ON member.summary_id=closure.summary_id
 CROSS JOIN temp.selected_resolution_mounts AS mount
  ON mount.storage_language='rust' AND mount.persisted_relative_path=member.rel_path
 WHERE closure.root_unit_key IN ";
#[doc(hidden)]
pub const CLOSURE_SCOPE_MOUNTS_TAIL: &str = "";
#[cfg(any(test, feature = "test-support"))]
static CLOSURE_SCOPE_MOUNTS_PIN: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!("{CLOSURE_SCOPE_MOUNTS_HEAD}(?1){CLOSURE_SCOPE_MOUNTS_TAIL}")
});

/// The mounts no crate row can place, which a crate closure cannot narrow:
/// another language's files, and a content mount carrying an editor buffer
/// whose path the crate derivation has never seen.
const UNPLACEABLE_SCOPE_MOUNTS: &str =
    "INSERT OR IGNORE INTO temp.selected_resolution_scope_mounts(mount_ordinal)
 SELECT mount_ordinal FROM temp.selected_resolution_mounts
 WHERE storage_language <> 'rust' OR file_version_id IS NULL";

/// One narrowed request scope, restored when it is dropped.
///
/// `narrow_forward_scope_to_crates` returns it and
/// `with_rust_forward_crate_scope` holds it across the request, so the restore
/// is a `Drop` and happens on an unwind as well as on a return. That matters
/// because the selection's temp tables are materialized once and reused by
/// every later request on the same inventory: a scope relation that still said
/// one crate's closure after a panic would answer every later reverse request
/// wrongly, missing usages in the crates that depend on the definition's.
/// `Drop` cannot return the error, so the reset asserts; a store that cannot
/// restore its own scope has no correct answer left to give.
///
/// The guard borrows the inventory and owns nothing, so holding it across the
/// request costs nothing.
pub(super) struct ForwardCrateScope<'inventory, 'store> {
    inventory: &'inventory SelectedResolutionMountInventory<'store>,
}

impl Drop for ForwardCrateScope<'_, '_> {
    fn drop(&mut self) {
        self.inventory
            .reset_scope_mounts()
            .expect("a forward request restores the whole selection as its scope");
    }
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static CONTEXT_BRIDGE_PEAK: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Start counting the bridges the contexts built on this thread carry.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn reset_rust_context_bridge_peak_for_test() {
    CONTEXT_BRIDGE_PEAK.with(|peak| peak.set(0));
}

/// The largest root-bridge count any one crate context built on this thread
/// has carried since the last reset.
///
/// A graph build's context retention is this number: the context is what the
/// build holds while it resolves, and its bridges are what it is made of.
/// Merging every crate's bridges into one context made this the workspace's
/// bridge inventory; walking one crate at a time makes it the largest single
/// crate's.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn rust_context_bridge_peak_for_test() -> usize {
    CONTEXT_BRIDGE_PEAK.with(std::cell::Cell::get)
}

#[doc(hidden)]
pub struct Module {
    pub(super) topology: i64,
    pub(super) path: String,
    pub(super) blob: i64,
    /// The file this module's container source places, as the crate rows
    /// spell it.
    pub(super) rel_path: String,
    pub(super) selected_blob: i64,
    pub(super) fragment: BindingFragmentId,
    pub(super) scope: ResolutionScopeId,
    pub(super) edition: String,
    /// This module's file is in the workspace and in no Cargo target of it.
    ///
    /// The derivation gives such a file its own synthetic `detached` topology
    /// whose `crate` root holds only that file, so the file still has a crate
    /// row and still answers `crate::`-rooted routes -- from a crate Cargo
    /// never described. The second half of the test is deliberate: when the
    /// workspace declares no Cargo target at all, one detached topology per
    /// file is the model, not a gap, and the lexical route carries that
    /// workspace. It is a file left out of a build that exists that nothing
    /// can answer for.
    pub(super) unmounted: bool,
    /// The module topology is a requested root or a selected Cargo dependency
    /// of one of those roots.
    pub(super) requested: bool,
    pub(super) overlay_completion: ResolutionCompletion,
}

impl Module {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        topology: i64,
        path: String,
        blob: i64,
        rel_path: String,
        selected_blob: i64,
        fragment: BindingFragmentId,
        scope: ResolutionScopeId,
        edition: String,
        unmounted: bool,
        requested: bool,
        overlay_completion: ResolutionCompletion,
    ) -> Self {
        Self {
            topology,
            path,
            blob,
            rel_path,
            selected_blob,
            fragment,
            scope,
            edition,
            unmounted,
            requested,
            overlay_completion,
        }
    }
}

impl SelectedResolutionOperation<'_, '_> {
    /// Resolve the lookup recipes for one page of root-half semantics, taking
    /// a transient overlay's own recipe first. Returns false on cancellation.
    /// Append the bridges to one crate-declared macro item
    /// (`rust_crate_macro_items`) and return what the request could not
    /// bridge, or `None` when cancelled.
    ///
    /// The item's only definition is the invoking file's request-scoped
    /// capsule, staged where declaration replay recorded the item's name
    /// (`MACRO_ITEM_NAME_RANGE`). The capsule's paths from the module root to
    /// that definition are its export halves, found the way the point route
    /// finds a persisted export's: by the reverse candidate paths that end at
    /// the definition. A request that did not stage the invoking file finds no
    /// definition and returns `unstaged_macro_item`'s incompleteness, because
    /// the item's module inventory is closed and an empty answer would read as
    /// an absence.
    #[allow(clippy::too_many_arguments)]
    fn append_macro_item_bridges(
        &self,
        reader: &SelectedResolutionLexicalSource<'_, '_>,
        out: &mut Vec<SelectedRootBridgeDescriptor>,
        mount: SelectedResolutionMountOrdinal,
        blob: i64,
        declaration: i64,
        source: BindingFragmentId,
        token: SemanticId,
        anchor: ResolutionRootImportAnchor,
        anchor_semantic: SemanticId,
        prefix: Option<SemanticId>,
        route: &[ResolutionLookupSemanticRecipe],
        demand: &ResolutionLookupSemanticRecipe,
        continuation: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<ResolutionCompletion>> {
        use crate::analyzer::resolution::{
            BatchCandidateRequest, BatchResolutionFragmentSource, EndpointSignature, StackPattern,
            classify_selected_root_path_half,
        };
        let (start, end, module) = self
            .ready
            .inventory
            .connection()
            .prepare_cached(MACRO_ITEM_NAME_RANGE)?
            .query_row(params![blob, declaration], |row| {
                Ok((
                    row.get::<_, usize>(0)?,
                    row.get::<_, usize>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            })?;
        let Some(staged) = reader.stage_definitions_at_range(mount, start, end, cancellation)?
        else {
            return Ok(None);
        };
        if staged.is_empty() {
            return Ok(Some(unstaged_macro_item(
                &self.ready.context_identities,
                blob,
                declaration,
                module,
            )));
        }
        let mut halves = Vec::new();
        let mut completions = Vec::new();
        for (_, node) in staged {
            let endpoint =
                EndpointSignature::new(node, StackPattern::closed([]), StackPattern::closed([]));
            reader.visit_reverse_candidate_match_pages(
                &[BatchCandidateRequest::new(0, endpoint)],
                cancellation,
                &mut |page| {
                    let ids = page.iter().map(|row| row.candidate()).collect::<Vec<_>>();
                    for (id, path) in reader.hydrate_candidate_paths(&ids, cancellation)? {
                        let Some(half) =
                            classify_selected_root_path_half(reader, id, &path, cancellation)?
                        else {
                            continue;
                        };
                        let SelectedRootPathHalf::Export {
                            incomplete_reasons, ..
                        } = &half
                        else {
                            continue;
                        };
                        completions.push(if incomplete_reasons.is_empty() {
                            ResolutionCompletion::Complete
                        } else {
                            ResolutionCompletion::incomplete(incomplete_reasons.iter().copied())
                        });
                        completions.push(path.completion().clone());
                        halves.push(half);
                    }
                    Ok(!cancellation.is_cancelled())
                },
            )?;
        }
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(closed) = reader.close_completions(&completions, cancellation)? else {
            return Ok(None);
        };
        let mut closed = closed.into_iter();
        let mut requests = Vec::with_capacity(halves.len());
        for half in &mut halves {
            let SelectedRootPathHalf::Export {
                identity,
                demand,
                incomplete_reasons,
                ..
            } = half
            else {
                unreachable!("the macro item read collects export halves");
            };
            let export = closed.next().expect("export completion");
            let path = closed.next().expect("path completion");
            *incomplete_reasons = match export.combine(&path) {
                ResolutionCompletion::Complete => Box::new([]),
                ResolutionCompletion::Incomplete(reasons) => reasons.iter().copied().collect(),
            };
            requests.push(SelectedLookupRecipeRequest {
                fragment: identity.fragment(),
                semantic: *demand,
            });
        }
        assert!(closed.next().is_none());
        let mut recipes = HashMap::default();
        if !self.fill_root_lookup_recipes(reader, requests, &mut recipes, cancellation)? {
            return Ok(None);
        }
        append_half_bridges(
            out,
            &self.ready.shared_names(),
            halves.iter(),
            &recipes,
            source,
            token,
            anchor,
            anchor_semantic,
            prefix,
            route,
            demand,
            continuation,
        );
        Ok(Some(ResolutionCompletion::Complete))
    }

    fn fill_root_lookup_recipes(
        &self,
        source: &SelectedResolutionLexicalSource<'_, '_>,
        mut requests: Vec<SelectedLookupRecipeRequest>,
        recipes: &mut HashMap<(BindingFragmentId, SemanticId), ResolutionLookupSemanticRecipe>,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        let mut seen = HashSet::default();
        requests.retain(|request| seen.insert((request.fragment, request.semantic)));
        requests.retain(|request| {
            let key = (request.fragment, request.semantic);
            if recipes.contains_key(&key) {
                return false;
            }
            true
        });
        for page in requests.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            let SelectedLookupRecipeReadOutcome::Ready(rows) =
                source.lookup_semantic_recipes(page, cancellation, None)?
            else {
                return Ok(false);
            };
            for (request, recipe) in page.iter().zip(rows) {
                if let Some(recipe) = recipe {
                    recipes.insert((request.fragment, request.semantic), recipe);
                }
            }
        }
        Ok(true)
    }

    #[doc(hidden)]
    pub fn rust_crate_keys_for_file(
        &self,
        caller: &Path,
        cancellation: &CancellationToken,
    ) -> Result<Vec<[u8; 32]>> {
        Ok(self.rust_file_crates_and_mount(caller, cancellation)?.0)
    }

    /// The crates that compile `caller`, and the mount the selection holds for
    /// it.
    ///
    /// Both questions are keyed on the same path and the selection indexes it,
    /// so `FILE_BLOB_AND_MOUNT` answers them in one statement and the caller
    /// that wants the mount does not pay a second read for it.
    // Keep the joined crate keys and optional selected mount in one query result.
    #[allow(clippy::type_complexity)]
    fn rust_file_crates_and_mount(
        &self,
        caller: &Path,
        cancellation: &CancellationToken,
    ) -> Result<(
        Vec<[u8; 32]>,
        Option<(SelectedResolutionMountOrdinal, Language)>,
    )> {
        if cancellation.is_cancelled() {
            return Ok((Vec::new(), None));
        }
        let path = crate::path_utils::normalize_pattern(&caller.to_string_lossy());
        let (blob, ordinal, semantic): (Option<i64>, Option<u32>, Option<String>) = self
            .ready
            .inventory
            .connection()
            .prepare_cached(FILE_BLOB_AND_MOUNT)?
            .query_row([&path], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        let mount = selected_mount_columns(ordinal, semantic)?;
        let Some(blob) = blob else {
            return Ok((Vec::new(), mount));
        };
        let mut statement = self
            .ready
            .inventory
            .connection()
            .prepare_cached(FILE_CRATES)?;
        let keys = statement
            .query_map(params![blob, path], |row| row.get::<_, Vec<u8>>(0))?
            .map(|row| Ok(row?.try_into().expect("crate-key schema constraint")))
            .collect::<Result<Vec<_>>>()?;
        Ok((keys, mount))
    }

    /// One file's Rust context, with the crates that compile it.
    ///
    /// The caller needs both: the context answers the file's references, and
    /// the crate keys are what it installs the forward scope from before the
    /// blueprint is built. They come out of the same `FILE_CRATES` read this
    /// build already makes, so the caller does not pay a second pair of
    /// statements to learn its own crates.
    #[doc(hidden)]
    pub fn rust_context_for_file(
        &self,
        caller: &Path,
        cancellation: &CancellationToken,
    ) -> Result<SelectedRustFileContextOutcome> {
        self.rust_context_for_files(std::iter::once(caller), cancellation)
    }

    /// Run one forward Rust request with the mounts it may bind into narrowed
    /// to the dependency closure of the crates it is made on behalf of.
    ///
    /// A reference written in crate A resolves to a declaration in A or in A's
    /// transitive dependency closure; nothing in a crate that depends on A, and
    /// nothing in a crate unrelated to A, can answer it. Coherence keeps a
    /// trait implementation in the trait's crate or the implementing type's
    /// crate, and both are in closure for a receiver typed in A, so a
    /// type-qualified member read stays inside it too.
    ///
    /// The scope belongs to the request, not to each statement: every
    /// membership read that turns a name into a set of blobs joins
    /// `temp.selected_resolution_scope_mounts`, so narrowing that one relation
    /// narrows all of them at once and no read can name a mount outside it.
    /// Lane ER measured what this removes: staging `tract-data`, a crate with
    /// no workspace dependency at all, batch 0 made 1,836 interior productions
    /// of which 1,758 (95.8 percent, 36.1 of 38.2 weighed GiB) were blobs in
    /// crates that depend on `tract-data`.
    ///
    /// Nothing is narrowed when the request names no crate, or when it names a
    /// `detached` one. The reverse routes never call this, so a usage in a
    /// dependent crate is still found: the scope they read is the whole
    /// selection, which is what the table holds until this narrows it.
    ///
    /// The restore is a guard's `Drop`, so it also happens on an unwind. This
    /// project asserts instead of branching, so a panic inside `run` is a
    /// designed outcome, and the selection's temp tables are materialized once
    /// and reused by every later request on the same inventory: a narrowed
    /// scope that survived a panic would make the next reverse request miss
    /// usages in crates that depend on the definition's, which is a wrong
    /// answer rather than a slow one.
    #[doc(hidden)]
    pub fn with_rust_forward_crate_scope<T>(
        &self,
        crate_keys: &[[u8; 32]],
        cancellation: &CancellationToken,
        run: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let _scope = self
            .ready
            .narrow_forward_scope_to_crates(crate_keys, cancellation)?;
        run()
    }
}

impl<'store> ReadySelectedResolution<'store, '_> {
    /// Install one crate stage's memos on this request; see
    /// [`SelectedResolutionOperation::crate_stage_memos`]. The guard must drop
    /// before [`Self::finish`], whose revalidation of the whole selection is
    /// what lets the stage trust a publication it has already checked.
    pub(super) fn crate_stage_memos(&self) -> Result<super::rust_crate_rows::CrateStageMemos<'_>> {
        super::rust_crate_rows::CrateStageMemos::install(
            &self.inventory,
            &self.crate_rows,
            self.inventory.crate_access_memo(),
            self.inventory.authority_validations(),
        )
    }

    /// Replace the request scope with the closure of `crate_keys`, or leave it
    /// alone and answer `None` when these crates do not bound anything.
    ///
    /// The guard is handed to the caller rather than wrapped around a closure
    /// because the two point routes install it where the graph stage does:
    /// after the context has been validated and before the blueprint is
    /// collected, at which point the operation has already been destructured
    /// into its mounts and this retained half.
    pub(super) fn narrow_forward_scope_to_crates(
        &self,
        crate_keys: &[[u8; 32]],
        cancellation: &CancellationToken,
    ) -> Result<Option<ForwardCrateScope<'_, 'store>>> {
        if crate_keys.is_empty() || cancellation.is_cancelled() {
            return Ok(None);
        }
        let keys = crate_keys
            .iter()
            .map(|key| Value::Blob(key.to_vec()))
            .collect::<Vec<_>>();
        let placeholders = format!(
            "({})",
            (1..=crate_keys.len())
                .map(|index| format!("?{index}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let detached: i64 = self.inventory.connection().query_row(
            &format!("{DETACHED_SCOPE_CRATES}{placeholders}"),
            params_from_iter(keys.iter()),
            |row| row.get(0),
        )?;
        if detached > 0 {
            return Ok(None);
        }
        // The scope rows belong to this request, which writes them and puts
        // them back, so they are accounted to it. An unaccounted temp write
        // reads as somebody else's, and the selection is discarded with its
        // retained operation when the inventory drops.
        self.inventory.with_owned_temp_write(|conn| {
            conn.execute("DELETE FROM temp.selected_resolution_scope_mounts", [])?;
            conn.execute(
                &format!("{CLOSURE_SCOPE_MOUNTS_HEAD}{placeholders}{CLOSURE_SCOPE_MOUNTS_TAIL}"),
                params_from_iter(keys.iter()),
            )?;
            conn.execute(UNPLACEABLE_SCOPE_MOUNTS, [])?;
            Ok(())
        })?;
        self.inventory.note_scope_narrowed(crate_keys);
        Ok(Some(ForwardCrateScope {
            inventory: &self.inventory,
        }))
    }
}

impl SelectedResolutionOperation<'_, '_> {
    /// The distinct crates that compile `files`, in crate-key order.
    ///
    /// This is the order a graph build walks its scopes in, and the vector is
    /// one entry per crate the request touches, not one per file.
    #[doc(hidden)]
    pub fn rust_crate_keys_for_files<'path>(
        &self,
        files: impl IntoIterator<Item = &'path Path>,
        cancellation: &CancellationToken,
    ) -> Result<Vec<[u8; 32]>> {
        let mut keys = BTreeSet::new();
        for file in files {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            keys.extend(self.rust_crate_keys_for_file(file, cancellation)?);
        }
        Ok(keys.into_iter().collect())
    }

    /// The `callers` whose graph stage can bind a reference into a crate that
    /// compiles one of `targets`, in `callers` order.
    ///
    /// A graph stage binds only inside its crate's dependency closure: that is
    /// the scope [`Self::with_rust_forward_crate_scope`] installs. A caller
    /// none of whose crates has a target's crate in its closure therefore
    /// stages no edge into a target, whatever its references spell. A caller
    /// no selected crate compiles is staged unnarrowed, as is one in a
    /// detached crate, so both are kept; a target no selected crate compiles
    /// bounds nothing, so it keeps every caller.
    #[doc(hidden)]
    pub fn rust_callers_reaching(
        &self,
        callers: &[ProjectFile],
        targets: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> Result<Vec<ProjectFile>> {
        let mut target_keys = BTreeSet::new();
        for target in targets {
            let keys = self.rust_crate_keys_for_file(target.rel_path(), cancellation)?;
            if keys.is_empty() {
                return Ok(callers.to_vec());
            }
            target_keys.extend(keys);
        }
        let mut reaching = HashSet::default();
        let mut statement = self
            .ready
            .inventory
            .connection()
            .prepare_cached(CRATES_REACHING)?;
        for key in target_keys {
            for row in statement.query_map([key.as_slice()], |row| row.get::<_, Vec<u8>>(0))? {
                let key: [u8; 32] = row?.try_into().expect("crate-key schema constraint");
                reaching.insert(key);
            }
        }
        let mut kept = Vec::new();
        for caller in callers {
            let keys = self.rust_crate_keys_for_file(caller.rel_path(), cancellation)?;
            if keys.is_empty() || keys.iter().any(|key| reaching.contains(key)) {
                kept.push(caller.clone());
            }
        }
        Ok(kept)
    }

    fn rust_context_for_files<'path>(
        &self,
        callers: impl IntoIterator<Item = &'path Path>,
        cancellation: &CancellationToken,
    ) -> Result<SelectedRustFileContextOutcome> {
        let mut keys = BTreeSet::new();
        let mut sources = Vec::new();
        let mounts = self.mount_table();
        for caller in callers {
            let (crates, persisted) = self.rust_file_crates_and_mount(caller, cancellation)?;
            keys.extend(crates);
            let path = selected_path_key(caller);
            sources.extend(mounts.mount_for_joined_path(persisted, "rust", &path));
        }
        let crate_keys = keys.into_iter().collect::<Vec<_>>();
        Ok(
            match self.rust_context_for_crate_keys(crate_keys.clone(), &sources, cancellation)? {
                SelectedRustContextOutcome::Ready(context) => {
                    SelectedRustFileContextOutcome::Ready {
                        context: Box::new(context),
                        crate_keys,
                    }
                }
                SelectedRustContextOutcome::Cancelled => SelectedRustFileContextOutcome::Cancelled,
            },
        )
    }

    /// One context over every selected crate, sized by the whole workspace's
    /// bridge inventory.
    ///
    /// No production route builds this. A root-less `usage_graph` used to,
    /// and that is the retention RV-2 recorded: the set it produced was the
    /// workspace's, and the graph build held it from the first unit to the
    /// last. The graph route now walks one crate at a time through
    /// [`Self::rust_crate_keys_for_files`] and
    /// [`Self::rust_context_for_crate_files`], so the only callers left are
    /// fixtures with a handful of files that want the whole selection in one
    /// context.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn rust_context_for_all_crates(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<SelectedRustContextOutcome> {
        if cancellation.is_cancelled() {
            return Ok(SelectedRustContextOutcome::Cancelled);
        }
        let keys = self.rust_selected_crate_keys(cancellation)?;
        let sources = self.mounts()?;
        self.rust_context_for_crate_keys(keys, sources, cancellation)
    }

    /// Every selected crate key, in crate-key order.
    #[cfg(any(test, feature = "test-support"))]
    fn rust_selected_crate_keys(&self, cancellation: &CancellationToken) -> Result<Vec<[u8; 32]>> {
        if cancellation.is_cancelled() {
            return Ok(Vec::new());
        }
        let mut statement = self
            .ready
            .inventory
            .connection()
            .prepare_cached(CRATE_KEYS)?;
        statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .map(|row| Ok(row?.try_into().expect("crate-key schema constraint")))
            .collect()
    }

    /// The workspace-relative paths of the files `crate_key` compiles.
    ///
    /// A file compiled into more than one Cargo target appears under each of
    /// its crates, which is what lets a graph build resolve it once per crate
    /// and let the edge rows deduplicate by endpoint.
    #[doc(hidden)]
    pub fn rust_crate_member_paths(
        &self,
        crate_key: [u8; 32],
        cancellation: &CancellationToken,
    ) -> Result<Vec<String>> {
        if cancellation.is_cancelled() {
            return Ok(Vec::new());
        }
        let connection = self.ready.inventory.connection();
        let mut statement = connection.prepare_cached(CRATE_MEMBER_FILES)?;
        let rows = statement
            .query_map([crate_key.as_slice()], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()?;
        Ok(rows.into_iter().collect())
    }

    /// The context that answers the references of `files` under `keys`.
    ///
    /// `keys` is the crate a graph build is currently walking, or empty for
    /// the requested files no selected crate compiles: those own no crate
    /// module, so no crate context can compile a bridge out of them, and an
    /// empty crate set reads their access exactly as the whole-workspace set
    /// did.
    #[doc(hidden)]
    pub fn rust_context_for_crate_files(
        &self,
        keys: Vec<[u8; 32]>,
        files: &HashSet<ProjectFile>,
        cancellation: &CancellationToken,
    ) -> Result<SelectedRustContextOutcome> {
        // A graph build calls this once per crate with that crate's share of
        // the requested files. Seeking each requested file is one probe per
        // file; filtering the selection was one pass over every selected file
        // per crate, and allocated a ProjectFile for each.
        let mounts = self.mount_table();
        let mut sources = Vec::with_capacity(files.len());
        for file in files {
            sources.extend(mounts.mount_for_path("rust", &selected_path_key(file.rel_path()))?);
        }
        self.rust_context_for_crate_keys(keys, &sources, cancellation)
    }

    /// `sources` names the files this context answers references for. Their
    /// root halves are the only ones that can compile a bridge out, so they
    /// are the only import and reference halves read.
    fn rust_context_for_crate_keys(
        &self,
        keys: Vec<[u8; 32]>,
        sources: &[SelectedResolutionOperationMount],
        cancellation: &CancellationToken,
    ) -> Result<SelectedRustContextOutcome> {
        let mut bridges = Vec::new();
        let mut completion = ResolutionCompletion::Complete;
        // One table for every crate's context and for the merged one. A
        // bridge's path and tail are numbers this table minted, and
        // `compile_bridge` mints them again from the same digests, so a
        // per-crate table would renumber the bridges this loop merges. The
        // request owns it, which is also what makes a reason minted while a
        // crate's rows are read agree with the context built from them.
        let identities = self.ready.context_identities.clone();
        for key in &keys {
            let SelectedRustContextOutcome::Ready(context) =
                self.rust_crate_context(identities.clone(), *key, sources, cancellation)?
            else {
                return Ok(SelectedRustContextOutcome::Cancelled);
            };
            let SelectedResolutionContextValidationOutcome::Ready(context) = context
                .validate_exact_mounts(
                    self.mount_table().mount_count(),
                    &selected_mount_lookup(self.mount_table()),
                    cancellation,
                )?
            else {
                return Ok(SelectedRustContextOutcome::Cancelled);
            };
            let (additional, evidence, access, _owned, _identities, packages, imports) =
                context.into_parts();
            assert!(
                packages.is_empty() && imports.is_empty(),
                "Rust crate context does not produce package bridges"
            );
            drop(access);
            bridges.extend(additional);
            // Every `UnsupportedSemantic` this crate context carries is already
            // attached to the bridge or dead-end descriptor that owns it: the
            // route that could not answer pushed the same reason into that
            // descriptor's evidence (`rust_crate_rows::crate_route`, the
            // dead-end arms below), and `bridges` above carries those
            // descriptors out of this loop unchanged. Combining the reason a
            // second time across every selected crate broadcast one crate's
            // demand failure into unrelated routes, which is what commit
            // `ae3d6ac3c` removed. The filter is that discharge and not a
            // deletion of route-level doubt; a reason kind with no descriptor
            // to carry it -- an `OpenBoundary`, or the unmounted-file reason --
            // is kept, because nothing else records it.
            let evidence = match evidence {
                ResolutionCompletion::Complete => ResolutionCompletion::Complete,
                ResolutionCompletion::Incomplete(reasons) => reasons
                    .without_reasons(
                        reasons
                            .iter()
                            .filter(|reason| {
                                matches!(reason, ResolutionIncompleteReason::UnsupportedSemantic(_))
                            })
                            .copied(),
                    )
                    .map_or(
                        ResolutionCompletion::Complete,
                        ResolutionCompletion::Incomplete,
                    ),
            };
            completion = completion.combine(&evidence);
        }
        #[cfg(any(test, feature = "test-support"))]
        CONTEXT_BRIDGE_PEAK.with(|peak| peak.set(peak.get().max(bridges.len())));
        let context = self.crate_context_from_bridges(identities, bridges, &completion)?;
        Ok(SelectedRustContextOutcome::Ready(
            context.with_declaration_access_source(self.crate_set_access_policy(keys)?),
        ))
    }

    pub(crate) fn rust_crate_context(
        &self,
        identities: SelectedContextIdentities,
        crate_key: [u8; 32],
        sources: &[SelectedResolutionOperationMount],
        cancellation: &CancellationToken,
    ) -> Result<SelectedRustContextOutcome> {
        if cancellation.is_cancelled() {
            return Ok(SelectedRustContextOutcome::Cancelled);
        }
        let conn = self.ready.inventory.connection();
        let mounts = self.mount_table();
        // Every scope-head comparison below asks the blob that owns the node,
        // because a node id is that blob's catalog position now.
        let persisted = self.ready.lexical_source();
        let (topology, summary_id): (i64, i64) = conn
            .prepare_cached(CRATE)?
            .query_row([crate_key.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut modules = Vec::new();
        let mut module_mounts = Vec::new();
        let mut statement = conn.prepare_cached(MODULES)?;
        // The module rows carry their own mount: the selection indexes the
        // path they name, so SQLite joins it here instead of Rust asking one
        // question per module, once per crate.
        let rows = statement.query_map([summary_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, u32>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<u32>>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, bool>(8)?,
                row.get::<_, Option<String>>(9)?,
            ))
        })?;
        for row in rows {
            if cancellation.is_cancelled() {
                return Ok(SelectedRustContextOutcome::Cancelled);
            }
            let (
                topology,
                path,
                blob,
                rel_path,
                scope,
                edition,
                ordinal,
                selected_blob,
                unmounted,
                semantic,
            ) = row?;
            if let Some(mount) = mounts.mount_for_joined_path(
                selected_mount_columns(ordinal, semantic)?,
                "rust",
                &rel_path,
            ) {
                let fragment = mount.fragment();
                module_mounts.push(mount);
                modules.push(Module {
                    topology,
                    path,
                    blob,
                    rel_path: rel_path.clone(),
                    selected_blob: selected_blob.expect("selected module has a published blob"),
                    fragment,
                    scope: ResolutionScopeId::new(scope),
                    edition,
                    unmounted,
                    requested: true,
                    overlay_completion: (super::rust_crate_rows::RustCrateRows {
                        ready: &self.ready,
                    })
                    .crate_overlay_import_completion(
                        blob,
                        &rel_path,
                        selected_blob,
                        cancellation,
                    )?,
                });
            }
        }
        drop(statement);
        // Only a module this crate or one of its dependencies mounts can own
        // an export a bridge lands on, and only a requested source file can
        // own an import or reference a bridge leaves from. Nothing else in the
        // workspace's root inventory is probed.
        let scope = super::RustRootHalfScope::new(sources.iter(), module_mounts.iter());
        let Some((halves, source_completion)) =
            self.rust_root_halves(&scope, cancellation, None)?
        else {
            return Ok(SelectedRustContextOutcome::Cancelled);
        };
        let source = self.ready.lexical_source();
        let Some(authorities) =
            self.rust_declaration_authorities_for_exports(&source, &halves, cancellation, None)?
        else {
            return Ok(SelectedRustContextOutcome::Cancelled);
        };
        // An export endpoint is addressed by its declaring mount and site. The
        // linear scan this replaces charged every target the whole half
        // inventory, which is where `usage_graph` spent 21 minutes.
        let mut exports_by_site: BTreeMap<(BindingFragmentId, ResolutionSiteId), Vec<usize>> =
            BTreeMap::new();
        for (index, half) in halves.iter().enumerate() {
            if let SelectedRootPathHalf::Export {
                identity,
                definition,
                ..
            } = half
                && let Some(authority) = authorities.get(definition)
            {
                exports_by_site
                    .entry((identity.fragment(), authority.source_site))
                    .or_default()
                    .push(index);
            }
        }
        let mut requests = Vec::new();
        for half in &halves {
            match half {
                SelectedRootPathHalf::Import {
                    identity,
                    route,
                    demand,
                    ..
                }
                | SelectedRootPathHalf::Reference {
                    identity,
                    route,
                    demand,
                    ..
                } => {
                    for semantic in route.iter().chain(std::iter::once(demand)) {
                        requests.push(SelectedLookupRecipeRequest {
                            fragment: identity.fragment(),
                            semantic: *semantic,
                        });
                    }
                }
                SelectedRootPathHalf::Export {
                    identity, demand, ..
                } => requests.push(SelectedLookupRecipeRequest {
                    fragment: identity.fragment(),
                    semantic: *demand,
                }),
            }
        }
        let mut recipes = HashMap::default();
        if !self.fill_root_lookup_recipes(&source, requests, &mut recipes, cancellation)? {
            return Ok(SelectedRustContextOutcome::Cancelled);
        }
        let Some(scope_ordinals) = persisted.node_scope_ordinals(
            halves
                .iter()
                .filter_map(|half| match half {
                    SelectedRootPathHalf::Import {
                        source_scope_head, ..
                    }
                    | SelectedRootPathHalf::Reference {
                        source_scope_head, ..
                    } => Some(*source_scope_head),
                    SelectedRootPathHalf::Export { .. } => None,
                })
                .chain(halves.iter().filter_map(|half| match half {
                    SelectedRootPathHalf::Reference {
                        lexical_scope_head: Some(scope_head),
                        ..
                    } => Some(*scope_head),
                    _ => None,
                })),
            cancellation,
        )?
        else {
            return Ok(SelectedRustContextOutcome::Cancelled);
        };
        let mut descriptors = Vec::new();
        for half in &halves {
            if cancellation.is_cancelled() {
                return Ok(SelectedRustContextOutcome::Cancelled);
            }
            let (identity, scope, token, demand, route, anchor, anchor_semantic, is_import) =
                match half {
                    SelectedRootPathHalf::Import {
                        identity,
                        source_scope_head,
                        token,
                        demand,
                        route,
                        anchor,
                        anchor_semantic,
                        ..
                    } => (
                        *identity,
                        *source_scope_head,
                        *token,
                        *demand,
                        route,
                        *anchor,
                        *anchor_semantic,
                        true,
                    ),
                    SelectedRootPathHalf::Reference {
                        identity,
                        source_scope_head,
                        token,
                        demand,
                        route,
                        anchor,
                        anchor_semantic,
                        prefix_reference: None,
                        ..
                    } => (
                        *identity,
                        *source_scope_head,
                        *token,
                        *demand,
                        route,
                        *anchor,
                        *anchor_semantic,
                        false,
                    ),
                    _ => continue,
                };
            let Some(demand) = recipes.get(&(identity.fragment(), demand)).cloned() else {
                continue;
            };
            let route = route
                .iter()
                .map(|semantic| {
                    recipes
                        .get(&(identity.fragment(), *semantic))
                        .cloned()
                        .expect("source route recipe")
                })
                .collect::<Vec<_>>();
            // One source half is one site, and the dead end it answers with
            // is identified by that site's tokens, route and demand. The
            // module placement that failed to answer is not part of that
            // identity, so a file this crate's dependency closure compiles
            // more than once -- a module of this crate and of a crate it
            // depends on -- used to publish one dead-end derivation per
            // placement for a single candidate path. The placements disagree
            // by construction, because only one of them has the dependency
            // that binds the route head, so the two derivations carried
            // different completions and the selected context rejected them.
            // The half's evidence is combined across its placements and
            // answered once, which is what the point route already does in
            // `rust_demand/rows.rs`.
            let mut half_completion = ResolutionCompletion::Complete;
            let mut route_reached_a_target = false;
            let mut answered_placements = 0_usize;
            let half_before = descriptors.len();
            for module in modules
                .iter()
                .filter(|module| module.fragment == identity.fragment())
            {
                if !is_import
                    && !persisted.node_is_scope_head_in(
                        &scope_ordinals,
                        scope,
                        module.fragment,
                        module.scope,
                    )
                {
                    continue;
                }
                let mut targets = Vec::new();
                let mut route_completion = module.overlay_completion.clone();
                if is_import {
                    let mut matched_scope = false;
                    for raw in (super::rust_crate_rows::RustCrateRows { ready: &self.ready })
                        .module_import_scopes(module.blob, module.scope.get())?
                    {
                        if cancellation.is_cancelled() {
                            return Ok(SelectedRustContextOutcome::Cancelled);
                        }
                        if !persisted.node_is_scope_head_in(
                            &scope_ordinals,
                            scope,
                            module.fragment,
                            ResolutionScopeId::new(raw),
                        ) {
                            continue;
                        }
                        matched_scope = true;
                        let mut named = conn.prepare_cached(NAMED)?;
                        for row in named.query_map(
                            params![
                                module.topology,
                                module.path,
                                module.blob,
                                raw,
                                demand.spelling(),
                                namespace(demand.namespace()),
                                if module.overlay_completion == ResolutionCompletion::Complete {
                                    module.selected_blob
                                } else {
                                    module.blob
                                }
                            ],
                            |row| {
                                Ok((
                                    row.get::<_, Vec<u8>>(0)?,
                                    row.get::<_, String>(1)?,
                                    row.get::<_, String>(2)?,
                                ))
                            },
                        )? {
                            let (key, path, name) = row?;
                            match selected_crate_topology(conn, &key)? {
                                Some(id) => targets.push((id, path, name)),
                                None => {
                                    route_completion =
                                        route_completion.combine(&unselected_target_boundary(
                                            &self.ready.context_identities,
                                            &key,
                                        ));
                                }
                            }
                        }
                        let mut globs = conn.prepare_cached(GLOBS)?;
                        for row in globs.query_map(
                            params![module.topology, module.path, module.blob, raw],
                            |row| {
                                Ok((
                                    row.get::<_, Vec<u8>>(0)?,
                                    row.get::<_, String>(1)?,
                                    row.get::<_, String>(2)?,
                                ))
                            },
                        )? {
                            let (key, path, segments) = row?;
                            let segments: Vec<String> = serde_json::from_str(&segments)
                                .map_err(|error| StoreError::corrupt(error.to_string()))?;
                            if !segments
                                .iter()
                                .map(String::as_str)
                                .eq(route.iter().map(|recipe| recipe.spelling()))
                            {
                                continue;
                            }
                            match selected_crate_topology(conn, &key)? {
                                Some(id) => {
                                    targets.push((id, path, demand.spelling().to_owned()));
                                }
                                None => {
                                    route_completion =
                                        route_completion.combine(&unselected_target_boundary(
                                            &self.ready.context_identities,
                                            &key,
                                        ));
                                }
                            }
                        }
                    }
                    if !matched_scope && module.overlay_completion == ResolutionCompletion::Complete
                    {
                        continue;
                    }
                } else if persisted.node_is_scope_head_in(
                    &scope_ordinals,
                    scope,
                    module.fragment,
                    module.scope,
                ) {
                    for (id, path) in (super::rust_crate_rows::RustCrateRows { ready: &self.ready })
                        .crate_route(
                            module,
                            module.topology,
                            module.path.clone(),
                            &route,
                            anchor,
                            &mut route_completion,
                            cancellation,
                        )?
                    {
                        targets.push((id, path, demand.spelling().to_owned()));
                    }
                }
                let mut binding_targets = None;
                // The import's own binding evidence. Every target the import
                // reaches depends on it, so each bridge carries it, as each
                // point-route candidate depends on its placement's completion
                // (`demand_closure.rs`). Reading evidence only at the target
                // let a canonical terminal behind a sibling glob with an open
                // macro inventory look complete (#6102).
                let mut import_completion = ResolutionCompletion::Complete;
                if is_import
                    && let Some((fragment, owner_scope)) =
                        scope_ordinals.get(&scope).copied().flatten()
                    && fragment == module.fragment
                {
                    let rows = super::rust_crate_rows::RustCrateRows { ready: &self.ready };
                    let inventory = if owner_scope == module.scope {
                        rows.crate_import_inventory(module, &demand)?
                    } else {
                        rows.crate_owner_import_inventory(
                            module,
                            &demand,
                            module.selected_blob,
                            owner_scope.get(),
                        )?
                    };
                    route_completion = route_completion.combine(&inventory.completion);
                    import_completion = inventory.completion;
                    binding_targets = inventory.targets;
                }
                // The import's published routes already name its canonical
                // targets. Walking the spelled route as well reached the same
                // export a second time, through a different module, with that
                // module's evidence. The point route walks only an import its
                // routes did not answer (`rust_demand/rows.rs`, `module_starts`).
                if is_import
                    && targets.is_empty()
                    && matches!(module.overlay_completion, ResolutionCompletion::Complete)
                    && persisted.node_is_scope_head_in(
                        &scope_ordinals,
                        scope,
                        module.fragment,
                        module.scope,
                    )
                {
                    for (id, path) in (super::rust_crate_rows::RustCrateRows { ready: &self.ready })
                        .crate_route(
                            module,
                            module.topology,
                            module.path.clone(),
                            &route,
                            anchor,
                            &mut route_completion,
                            cancellation,
                        )?
                    {
                        targets.push((id, path, demand.spelling().to_owned()));
                    }
                }
                if let Some(canonical) = binding_targets {
                    targets = canonical;
                }
                // An anchor names the module its own route step reached, so
                // its target is that module's declaration rather than an
                // export inside it.
                if is_module_anchor(demand.spelling()) {
                    targets = (super::rust_crate_rows::RustCrateRows { ready: &self.ready })
                        .anchor_declaration_targets(targets)?;
                }
                route_reached_a_target |= !targets.is_empty();
                let before = descriptors.len();
                for (target_topology, path, name) in targets {
                    let rows = super::rust_crate_rows::RustCrateRows { ready: &self.ready };
                    let binding_inventory = rows.crate_binding_inventory(
                        module,
                        target_topology,
                        &path,
                        namespace(demand.namespace()),
                        &name,
                    )?;
                    let binding_completion = module
                        .overlay_completion
                        .combine(&import_completion)
                        .combine(&binding_inventory.completion);
                    let exports = rows.crate_exports_from_inventory(
                        module,
                        target_topology,
                        &path,
                        namespace(demand.namespace()),
                        &name,
                        &binding_inventory,
                    )?;
                    // The point route's rule (`rust_demand/rows.rs`): behind
                    // an open inventory, a name the walk finds as an import
                    // that leaves the workspace is the boundary, and the open
                    // inventory does not reopen a found name.
                    let mut inventory = rows.crate_inventory_completion(
                        module,
                        target_topology,
                        &path,
                        namespace(demand.namespace()),
                        &name,
                    )?;
                    if exports.is_empty() {
                        let bindings = rows.crate_external_bindings(
                            module,
                            target_topology,
                            &path,
                            demand.namespace(),
                            &name,
                        )?;
                        if !bindings.is_empty() {
                            inventory = ResolutionCompletion::incomplete(bindings.into_iter().map(|semantic|
                                ResolutionIncompleteReason::OpenBoundary {
                                    semantic,
                                    status: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                                }
                            ));
                        }
                    }
                    route_completion = route_completion.combine(&inventory);
                    for RustCrateExport {
                        blob,
                        declaration,
                        topology: export_topology,
                        module_path: export_module_path,
                        mount,
                    } in exports
                    {
                        let site = match declaration {
                            RustCrateDeclaration::Site(site) => site,
                            RustCrateDeclaration::MacroItem(declaration) => {
                                let Some(unstaged) = self.append_macro_item_bridges(
                                    &source,
                                    &mut descriptors,
                                    mount,
                                    blob,
                                    declaration,
                                    identity.fragment(),
                                    token,
                                    anchor,
                                    anchor_semantic,
                                    None,
                                    &route,
                                    &demand,
                                    &binding_completion,
                                    cancellation,
                                )?
                                else {
                                    return Ok(SelectedRustContextOutcome::Cancelled);
                                };
                                route_completion = route_completion.combine(&unstaged);
                                continue;
                            }
                        };
                        if !append_export_bridges(
                            &mut descriptors,
                            &self.ready.shared_names(),
                            &modules,
                            &halves,
                            &exports_by_site,
                            &recipes,
                            identity.fragment(),
                            token,
                            anchor,
                            anchor_semantic,
                            None,
                            &route,
                            &demand,
                            mounts.mount_by_ordinal(mount)?.fragment(),
                            site,
                            export_topology,
                            &export_module_path,
                            &binding_completion,
                        ) {
                            route_completion =
                                route_completion.combine(&unlowered_export_declaration(
                                    &self.ready.context_identities,
                                    mounts.mount_by_ordinal(mount)?.persisted_relative_path(),
                                    site,
                                ));
                        }
                    }
                }
                answered_placements += 1;
                if descriptors.len() == before {
                    half_completion = half_completion.combine(&route_completion);
                }
            }
            // A half whose file this crate's closure places nowhere was never
            // asked, and an unasked question has no answer to publish. The
            // per-placement arm this replaces could not reach that state.
            if answered_placements > 0 && descriptors.len() == half_before {
                // A path whose first segment names no module this workspace
                // compiles has left the workspace, and that is a boundary, not
                // a decided negative. The reason answers a question about the
                // route head and the workspace, not about one module
                // placement: a file compiled into this crate and into a crate
                // it depends on asks it once per placement, and only the
                // placement whose topology declares the dependency can bind
                // the root. Claiming the boundary per placement said a
                // workspace crate left the workspace. The question is the
                // half's, so the answer is too. The point route's copy of this
                // guard says the same thing (`rust_demand/rows.rs`), and the
                // two must not drift, because this route's completions reach
                // `forward_completeness` and so the dead-code and scan
                // surfaces, not only navigation.
                if !route_reached_a_target
                    && route
                        .first()
                        .is_some_and(|segment| !is_module_anchor(segment.spelling()))
                {
                    half_completion =
                        half_completion.combine(&ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::OpenBoundary {
                                semantic: token,
                                status: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                            },
                        ]));
                }
                if !matches!(half_completion, ResolutionCompletion::Complete) {
                    descriptors.push(deadend(
                        identity.fragment(),
                        token,
                        anchor,
                        anchor_semantic,
                        None,
                        &route,
                        &demand,
                        half_completion,
                    ));
                }
            }
        }
        let mut completion = source_completion;
        let mut owned_reasons = Vec::new();
        for row in conn.prepare_cached(GAPS)?.query_map([topology], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })? {
            let (kind, subject, detail) = row?;
            if matches!(
                kind.as_str(),
                "inactive_placement"
                    | "unplaced_module"
                    | "external_dependency"
                    | "unresolved_import"
                    | "unresolved_reexport"
                    | "unresolved_visibility"
            ) {
                continue;
            }
            if kind == "open_export_inventory" {
                let parsed: serde_json::Value =
                    serde_json::from_str(&detail).expect("crate gap evidence is JSON");
                if parsed["evidence"].as_array().is_some_and(|items| {
                    items.iter().all(|item| {
                        matches!(
                            item["reason"].as_str(),
                            Some(
                                "InconsistentPrecedence"
                                    | "CyclicExpansion"
                                    | "OpenBoundary"
                                    | "UnsupportedImportTarget"
                                    | "UnsupportedGlobConflictVisibility"
                            )
                        )
                    })
                }) {
                    // Binding-relation reasons belong to the requested owner,
                    // namespace and name; inventory lookup attaches them there.
                    continue;
                }
            }
            // A reason the context invents for itself: it belongs to no
            // file, so the context's own table numbers it and two
            // compilations of one gap agree.
            let mut digest = CanonicalHasher::new(b"bifrost-rust-crate-gap-reason:v1");
            digest.field("crate", &crate_key);
            digest.field("kind", kind.as_bytes());
            digest.field("subject", subject.as_bytes());
            digest.field("detail", detail.as_bytes());
            let reason = identities.semantic(digest.finish());
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(reason),
            ]));
            owned_reasons.push(reason);
        }
        let mut context = self.crate_context_from_bridges(identities, descriptors, &completion)?;
        for reason in owned_reasons {
            context = context.with_context_owned_inventory_reason(reason);
        }
        context =
            context.with_declaration_access_source(self.crate_access_policy(vec![crate_key])?);
        let Some(prefixes) =
            self.resolve_rust_prefixes_preliminary(context.clone(), &halves, cancellation)?
        else {
            return Ok(SelectedRustContextOutcome::Cancelled);
        };
        let mut prefix_names = HashMap::default();
        let absent_prefixes = prefixes
            .iter()
            .filter_map(|(reference, resolution)| {
                resolution.targets.is_empty().then_some(*reference)
            })
            .collect::<Vec<_>>();
        for page in absent_prefixes.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            prefix_names.extend(
                self.ready
                    .rust_prefix_spellings(&source, page, cancellation)?,
            );
        }
        let mut additions = Vec::new();
        for half in &halves {
            let SelectedRootPathHalf::Reference {
                identity,
                source_scope_head,
                lexical_scope_head,
                prefix_reference: Some(prefix),
                token,
                demand,
                route,
                anchor,
                anchor_semantic,
                ..
            } = half
            else {
                continue;
            };
            let Some((_, resolved)) = prefixes.iter().find(|(reference, _)| reference == prefix)
            else {
                continue;
            };
            let Some(demand) = recipes.get(&(identity.fragment(), *demand)).cloned() else {
                continue;
            };
            let route = route
                .iter()
                .map(|semantic| {
                    recipes
                        .get(&(identity.fragment(), *semantic))
                        .cloned()
                        .expect("prefix route recipe")
                })
                .collect::<Vec<_>>();
            let prefix_import_scope = lexical_scope_head
                .map(|scope_head| {
                    let Some((fragment, scope)) = scope_ordinals
                        .get(&scope_head)
                        .expect("prefix lexical scope was batched")
                        .as_ref()
                    else {
                        panic!("prefix lexical scope must have source scope authority")
                    };
                    assert_eq!(*fragment, identity.fragment());
                    scope.get()
                })
                .unwrap_or_else(|| {
                    let Some((fragment, source_scope)) = scope_ordinals
                        .get(source_scope_head)
                        .expect("reference source scope was batched")
                        .as_ref()
                    else {
                        panic!("reference source scope must have source scope authority")
                    };
                    assert_eq!(*fragment, identity.fragment());
                    source_scope.get()
                });
            let before = additions.len();
            // A crate-declared macro item this request did not stage: the
            // name exists and binds nothing here, which the dead end names.
            let mut unstaged_items = ResolutionCompletion::Complete;
            let mut module_targets = BTreeSet::new();
            let mut known_targets = BTreeSet::new();
            let mut known_prefix = false;
            // The filter asks the blob that owns the node, which is a read,
            // so it is taken before the loop rather than inside a closure that
            // cannot carry the error.
            let mut scoped_modules = Vec::new();
            for module in modules
                .iter()
                .filter(|module| module.fragment == identity.fragment())
            {
                if persisted.node_is_scope_head_in(
                    &scope_ordinals,
                    *source_scope_head,
                    module.fragment,
                    module.scope,
                ) {
                    scoped_modules.push(module);
                }
            }
            let prefix_kind = route_prefix_kind(
                &self.ready,
                prefix_names.get(prefix).map(String::as_str),
                &resolved.targets,
                &resolved.completion,
            )?;
            for module in scoped_modules {
                if resolved.targets.is_empty()
                    || *anchor == ResolutionRootImportAnchor::Absolute
                    || !prefix_kind.is_type()
                {
                    let mut continuation = resolved.completion.combine(&module.overlay_completion);
                    let mut starts = Vec::new();
                    if *anchor == ResolutionRootImportAnchor::Absolute {
                        starts.push((module.topology, module.path.clone()));
                    } else if let Some(name) = prefix_names.get(prefix) {
                        // The native half consumes its positioned prefix before
                        // exposing the remaining route. A prefix that is not a
                        // type can name a module through a dependency or a
                        // named import, so consult its selected route here.
                        for row in conn.prepare_cached(DEPENDENCY.as_str())?.query_map(
                            params![module.topology,name,super::super::rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION],
                            |row| row.get::<_,i64>(0),
                        )? { starts.push((row?,"crate".to_owned())); }
                        starts.extend(published_module_starts(
                            conn,
                            module.topology,
                            &module.path,
                            name,
                            module.topology,
                            &module.path,
                        )?);
                        let mut import_scopes = vec![prefix_import_scope, module.scope.get()];
                        import_scopes.sort_unstable();
                        import_scopes.dedup();
                        for import_scope in import_scopes {
                            let bindings = conn
                                .prepare_cached(IMPORT_MODULE_PREFIX_STARTS)?
                                .query_map(
                                    params![
                                        module.topology,
                                        module.path,
                                        module.blob,
                                        import_scope,
                                        name,
                                        "type",
                                        module.selected_blob
                                    ],
                                    |row| {
                                        Ok((
                                            row.get::<_, i64>(0)?,
                                            row.get::<_, String>(1)?,
                                            row.get::<_, String>(2)?,
                                        ))
                                    },
                                )?
                                .collect::<rusqlite::Result<Vec<_>>>()?;
                            for (topology, path, target_name) in bindings {
                                starts.extend(published_module_starts(
                                    conn,
                                    topology,
                                    &path,
                                    &target_name,
                                    module.topology,
                                    &module.path,
                                )?);
                            }
                        }
                        // A module an item macro declares in this module has no
                        // lexical binder; the crate row places it. The point
                        // route's copy is in `rust_demand/rows.rs`.
                        for row in conn
                            .prepare_cached(NAMED_MACRO_MODULE)?
                            .query_map(params![module.topology, module.path, name], |row| {
                                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                            })?
                        {
                            starts.push(row?);
                        }
                        if starts.is_empty() {
                            let mut details = macro_gated_import_route_details(
                                conn,
                                module,
                                name,
                                prefix_import_scope,
                            )?;
                            if details.is_empty() && module.unmounted {
                                details.extend(macro_gated_unmounted_file_details(
                                    conn,
                                    &module.rel_path,
                                )?);
                            }
                            if !details.is_empty() {
                                known_prefix = true;
                                continuation = continuation.combine(&macro_gated_route_boundary(
                                    &self.ready.context_identities,
                                    &details,
                                ));
                            } else if module.unmounted {
                                let details =
                                    inactive_cfg_unmounted_file_details(conn, &module.rel_path)?;
                                if !details.is_empty() {
                                    known_prefix = true;
                                    continuation =
                                        continuation.combine(&inactive_cfg_route_boundary(
                                            &self.ready.context_identities,
                                            &details,
                                        ));
                                }
                            }
                        }
                    }
                    known_prefix |= !starts.is_empty();
                    let mut targets = Vec::new();
                    for (id, path) in starts {
                        targets.extend(
                            (super::rust_crate_rows::RustCrateRows { ready: &self.ready })
                                .crate_route(
                                    module,
                                    id,
                                    path,
                                    &route,
                                    *anchor,
                                    &mut continuation,
                                    cancellation,
                                )?,
                        );
                    }
                    for (id, path) in targets {
                        for RustCrateExport {
                            blob,
                            declaration,
                            topology: export_topology,
                            module_path: export_module_path,
                            mount,
                        } in (super::rust_crate_rows::RustCrateRows { ready: &self.ready })
                            .crate_exports(
                                module,
                                id,
                                &path,
                                namespace(demand.namespace()),
                                demand.spelling(),
                            )?
                        {
                            let site = match declaration {
                                RustCrateDeclaration::Site(site) => site,
                                RustCrateDeclaration::MacroItem(declaration) => {
                                    let Some(unstaged) = self.append_macro_item_bridges(
                                        &source,
                                        &mut additions,
                                        mount,
                                        blob,
                                        declaration,
                                        identity.fragment(),
                                        *token,
                                        *anchor,
                                        *anchor_semantic,
                                        Some(*prefix),
                                        &route,
                                        &demand,
                                        &continuation,
                                        cancellation,
                                    )?
                                    else {
                                        return Ok(SelectedRustContextOutcome::Cancelled);
                                    };
                                    unstaged_items = unstaged_items.combine(&unstaged);
                                    continue;
                                }
                            };
                            if !append_export_bridges(
                                &mut additions,
                                &self.ready.shared_names(),
                                &modules,
                                &halves,
                                &exports_by_site,
                                &recipes,
                                identity.fragment(),
                                *token,
                                *anchor,
                                *anchor_semantic,
                                Some(*prefix),
                                &route,
                                &demand,
                                mounts.mount_by_ordinal(mount)?.fragment(),
                                site,
                                export_topology,
                                &export_module_path,
                                &continuation,
                            ) {
                                unstaged_items =
                                    unstaged_items.combine(&unlowered_export_declaration(
                                        &self.ready.context_identities,
                                        mounts.mount_by_ordinal(mount)?.persisted_relative_path(),
                                        site,
                                    ));
                            }
                        }
                    }
                }
                if *anchor == ResolutionRootImportAnchor::Absolute {
                    continue;
                }
                // An export site is reached once per exported name: several
                // names can share one declaration, and each owns its bridge.
                for (&(target_fragment, source_site), exported) in &exports_by_site {
                    let definition = mounted_site_semantic(target_fragment, source_site);
                    if !resolved.targets.contains(&definition) {
                        continue;
                    }
                    known_targets.insert(definition);
                    // The impl-to-trait join, once per subject declaration.
                    // It depends on neither the exported name nor the module
                    // the declaration is placed in, and a file that declares
                    // inline modules contributes one `Module` per module over
                    // one blob, so both loops below would ask it the same
                    // question several times. The point route's copy is in
                    // `rust_demand/rows.rs`; both ask the same shared read, on
                    // the same condition, and the two must not drift.
                    if route.is_empty() {
                        let mut asked = BTreeSet::new();
                        for target_module in modules
                            .iter()
                            .filter(|module| module.fragment == target_fragment)
                        {
                            if !asked.insert(target_module.blob) {
                                continue;
                            }
                            additions.extend(
                                (super::rust_crate_rows::RustCrateRows { ready: &self.ready })
                                    .crate_trait_member_bridges(
                                        &mounts,
                                        module,
                                        identity.fragment(),
                                        *token,
                                        *anchor,
                                        *anchor_semantic,
                                        *prefix,
                                        &demand,
                                        target_module.blob,
                                        source_site.get(),
                                        &target_module.rel_path,
                                        &resolved.completion.combine(&module.overlay_completion),
                                        cancellation,
                                    )?,
                            );
                        }
                    }
                    for _ in exported {
                        for target_module in modules
                            .iter()
                            .filter(|module| module.fragment == target_fragment)
                        {
                            let mut statement = conn.prepare_cached(DEFINITION_MODULE)?;
                            for row in statement.query_map(
                                params![
                                    target_module.selected_blob,
                                    source_site.get(),
                                    target_module.topology,
                                    target_module.path
                                ],
                                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                            )? {
                                let (id, path) = row?;
                                module_targets.insert(definition);
                                let mut continuation =
                                    resolved.completion.combine(&module.overlay_completion);
                                for (id, path) in
                                    (super::rust_crate_rows::RustCrateRows { ready: &self.ready })
                                        .crate_route(
                                        module,
                                        id,
                                        path,
                                        &route[route.len().min(1)..],
                                        ResolutionRootImportAnchor::Lexical,
                                        &mut continuation,
                                        cancellation,
                                    )?
                                {
                                    for RustCrateExport {
                                        blob,
                                        declaration,
                                        topology: export_topology,
                                        module_path: export_module_path,
                                        mount,
                                    } in (super::rust_crate_rows::RustCrateRows {
                                        ready: &self.ready,
                                    })
                                    .crate_exports(
                                        module,
                                        id,
                                        &path,
                                        namespace(demand.namespace()),
                                        demand.spelling(),
                                    )? {
                                        let site = match declaration {
                                            RustCrateDeclaration::Site(site) => site,
                                            RustCrateDeclaration::MacroItem(declaration) => {
                                                let Some(unstaged) = self
                                                    .append_macro_item_bridges(
                                                        &source,
                                                        &mut additions,
                                                        mount,
                                                        blob,
                                                        declaration,
                                                        identity.fragment(),
                                                        *token,
                                                        *anchor,
                                                        *anchor_semantic,
                                                        Some(*prefix),
                                                        &route,
                                                        &demand,
                                                        &continuation,
                                                        cancellation,
                                                    )?
                                                else {
                                                    return Ok(
                                                        SelectedRustContextOutcome::Cancelled,
                                                    );
                                                };
                                                unstaged_items = unstaged_items.combine(&unstaged);
                                                continue;
                                            }
                                        };
                                        if !append_export_bridges(
                                            &mut additions,
                                            &self.ready.shared_names(),
                                            &modules,
                                            &halves,
                                            &exports_by_site,
                                            &recipes,
                                            identity.fragment(),
                                            *token,
                                            *anchor,
                                            *anchor_semantic,
                                            Some(*prefix),
                                            &route,
                                            &demand,
                                            mounts.mount_by_ordinal(mount)?.fragment(),
                                            site,
                                            export_topology,
                                            &export_module_path,
                                            &continuation,
                                        ) {
                                            unstaged_items = unstaged_items.combine(
                                                &unlowered_export_declaration(
                                                    &self.ready.context_identities,
                                                    mounts
                                                        .mount_by_ordinal(mount)?
                                                        .persisted_relative_path(),
                                                    site,
                                                ),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            let unknown = resolved.targets.is_empty()
                || resolved
                    .targets
                    .iter()
                    .any(|target| !known_targets.contains(target));
            let mixed = !module_targets.is_empty()
                && resolved
                    .targets
                    .iter()
                    .any(|target| !module_targets.contains(target));
            let unstaged_only =
                additions.len() == before && unstaged_items != ResolutionCompletion::Complete;
            // A type prefix is handled by the typed member route, not by a
            // crate module walk. `Self` and type parameters retain their
            // existing selected-member behavior. A known nominal type is
            // likewise a usable route prefix when unrelated lexical gaps keep
            // its full binding answer open; retain those reasons below.
            let type_member = additions.len() == before
                && unknown
                && !mixed
                && !unstaged_only
                && route.is_empty()
                && prefix_kind == RoutePrefixKind::MemberType;
            if type_member && resolved.completion != ResolutionCompletion::Complete {
                additions.push(deadend(
                    identity.fragment(),
                    *token,
                    *anchor,
                    *anchor_semantic,
                    Some(*prefix),
                    &route,
                    &demand,
                    resolved.completion.combine(&unstaged_items),
                ));
            }
            // The bare two-segment shape of the same question the route-head
            // guard above answers: `ext_crate::Widget` carries its root as the
            // prefix reference, whose lexical lookup and whose Cargo dependency
            // lookup both came back empty. That is a boundary, and a boundary
            // is the whole answer, so the coarse reasons below are discharged
            // where it is claimed rather than left to defeat the all-boundary
            // predicate in `rust/native_points.rs`.
            let bound_in_the_crate = additions.len() == before
                && !known_prefix
                && unstaged_items == ResolutionCompletion::Complete
                && prefix_bound_in_the_crate(&self.ready, *prefix, resolved, cancellation)?;
            let external_prefix = additions.len() == before
                && !known_prefix
                && !bound_in_the_crate
                && !type_member
                && prefix_kind == RoutePrefixKind::Other
                && prefix_left_the_indexed_workspace(&self.ready, resolved);
            // A known block-local type has a selected declaration but no
            // crate module projection for the remaining path.
            if ((additions.len() == before && (!module_targets.is_empty() || unknown))
                || mixed
                || unstaged_only
                || prefix_kind == RoutePrefixKind::BlockLocalType)
                && !type_member
            {
                let mut completion = resolved.completion.combine(&unstaged_items);
                if external_prefix {
                    completion = completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::OpenBoundary {
                            semantic: *token,
                            status:
                                crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                        },
                    ]));
                } else {
                    let dead_end = if unknown {
                        RouteDeadEnd::UnplacedRoutePrefix
                    } else if mixed {
                        RouteDeadEnd::MixedRoutePrefix
                    } else {
                        RouteDeadEnd::UnexportedRouteSegment
                    };
                    let rel_path = self
                        .mount_table()
                        .mount_for_fragment(identity.fragment())?
                        .map(|mount| mount.persisted_relative_path().to_owned());
                    let prefix_spelling = self
                        .ready
                        .rust_prefix_spellings(
                            &self.ready.lexical_source(),
                            &[*prefix],
                            cancellation,
                        )?
                        .remove(prefix);
                    let prefix_class = if dead_end == RouteDeadEnd::UnplacedRoutePrefix {
                        Some(classify_route_prefix(
                            &self.ready,
                            rel_path.as_deref(),
                            prefix_spelling.as_deref(),
                            resolved,
                            prefix.ordinal(),
                            route.is_empty(),
                            cancellation,
                        )?)
                    } else {
                        None
                    };
                    if prefix_class != Some(RoutePrefixClass::OpenInventory) {
                        completion = completion.combine(&route_dead_end(
                            &self.ready.context_identities,
                            dead_end,
                            rel_path.as_deref(),
                            prefix_spelling.as_deref(),
                            prefix_class,
                            &route,
                            &demand,
                        ));
                    }
                }
                additions.push(deadend(
                    identity.fragment(),
                    *token,
                    *anchor,
                    *anchor_semantic,
                    Some(*prefix),
                    &route,
                    &demand,
                    completion,
                ));
            }
        }
        let selected_mount_of = selected_mount_lookup(self.mount_table());
        let Some(extended) =
            context.extend_root_bridges(additions, cancellation, None, &selected_mount_of)?
        else {
            return Ok(SelectedRustContextOutcome::Cancelled);
        };
        context = extended;
        Ok(SelectedRustContextOutcome::Ready(context))
    }

    fn overlay_base_blobs(&self) -> Result<Vec<(BindingFragmentId, i64)>> {
        let mut base_blobs = Vec::new();
        let mounts = self.mount_table();
        let mut content_mounts = Vec::with_capacity(self.ready.content_mounts.len());
        for request in &self.ready.content_mounts {
            content_mounts.push(
                mounts
                    .mount_for_path(
                        request.storage_language(),
                        request.persisted_relative_path(),
                    )?
                    .expect("selected content request has an operation mount"),
            );
        }
        for mount in &content_mounts {
            let blob: Option<i64> = self
                .ready
                .inventory
                .connection()
                .prepare_cached(FILE_BLOB)?
                .query_row([mount.persisted_relative_path()], |row| row.get(0))
                .optional()?;
            if let Some(blob) = blob {
                base_blobs.push((mount.fragment(), blob));
            }
        }
        Ok(base_blobs)
    }

    pub(super) fn crate_access_policy(
        &self,
        crate_keys: Vec<[u8; 32]>,
    ) -> Result<std::sync::Arc<super::rust_crate_access::RustCrateAccessPolicy>> {
        Ok(std::sync::Arc::new(
            super::rust_crate_access::RustCrateAccessPolicy {
                identity: self.ready.context_identities.semantic(crate_access_digest(
                    b"rust-point-crate-access:v1",
                    &crate_keys,
                )),
                crate_keys,
                base_blobs: self.overlay_base_blobs()?,
            },
        ))
    }

    pub(super) fn crate_set_access_policy(
        &self,
        crate_keys: Vec<[u8; 32]>,
    ) -> Result<std::sync::Arc<super::rust_crate_access::RustCrateSetAccessPolicy>> {
        Ok(std::sync::Arc::new(
            super::rust_crate_access::RustCrateSetAccessPolicy {
                identity: self.ready.context_identities.semantic(crate_access_digest(
                    b"rust-crate-set-access:v1",
                    &crate_keys,
                )),
                crate_keys,
                base_blobs: self.overlay_base_blobs()?,
            },
        ))
    }

    fn crate_context_from_bridges(
        &self,
        identities: SelectedContextIdentities,
        bridges: Vec<SelectedRootBridgeDescriptor>,
        completion: &ResolutionCompletion,
    ) -> Result<SelectedResolutionContextSet> {
        let mut by_fragment: HashMap<_, Vec<_>> = HashMap::default();
        for bridge in bridges {
            by_fragment
                .entry(bridge.source_fragment())
                .or_default()
                .push(bridge);
        }
        // Only a mount that owns a bridge earns an entry here. The completion
        // is evidence about the read rather than about one mount, and the
        // context set combines it into one operand, so it rides on a single
        // entry: the first mount that owns a bridge when there is one and the
        // first selected mount otherwise, which then exists only to carry it.
        // A crate with neither a bridge nor anything incomplete contributes no
        // context set at all, whatever the mount count.
        // The bridges name their own mounts, so the entries come from draining
        // them rather than from walking the selection once per crate context.
        // Sorting by ordinal restores the order the walk produced, which is
        // what the context set is read in.
        let mounts = self.mount_table();
        let mut owners = by_fragment
            .into_iter()
            .map(|(fragment, bridges)| -> Result<_> {
                let mount = mounts
                    .mount_for_fragment(fragment)?
                    .expect("a selected root bridge leaves from a selected mount");
                Ok((mount, bridges))
            })
            .collect::<Result<Vec<_>>>()?;
        owners.sort_unstable_by_key(|(mount, _)| mount.ordinal());
        let evidence = if matches!(completion, ResolutionCompletion::Complete) {
            None
        } else if let Some((mount, _)) = owners.first() {
            Some(mount.clone())
        } else if mounts.mount_count() != 0 {
            Some(mounts.mount_by_ordinal(SelectedResolutionMountOrdinal::new(0))?)
        } else {
            None
        };
        let mut sparse = Vec::with_capacity(owners.len() + 1);
        for (mount, bridges) in owners {
            let carries_evidence = evidence
                .as_ref()
                .is_some_and(|carrier| carrier.ordinal() == mount.ordinal());
            sparse.push(SelectedResolutionMountContext::new(
                mount.ordinal(),
                mount.fragment(),
                mount.semantic_language(),
                bridges,
                if carries_evidence {
                    completion.clone()
                } else {
                    ResolutionCompletion::Complete
                },
            )?);
        }
        if sparse.is_empty()
            && let Some(mount) = evidence
        {
            sparse.push(SelectedResolutionMountContext::new(
                mount.ordinal(),
                mount.fragment(),
                mount.semantic_language(),
                Vec::new(),
                completion.clone(),
            )?);
        }
        SelectedResolutionContextSet::new(
            identities,
            sparse,
            mounts.mount_count(),
            &selected_mount_lookup(mounts),
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn deadend(
    fragment: BindingFragmentId,
    token: SemanticId,
    anchor: ResolutionRootImportAnchor,
    anchor_semantic: SemanticId,
    prefix: Option<SemanticId>,
    route: &[ResolutionLookupSemanticRecipe],
    demand: &ResolutionLookupSemanticRecipe,
    completion: ResolutionCompletion,
) -> SelectedRootBridgeDescriptor {
    super::demand_closure::deadend_bridge(
        fragment,
        Language::Rust,
        token,
        anchor,
        anchor_semantic,
        prefix,
        route,
        demand,
        completion,
    )
}

pub(super) fn inventory_reason(identities: &SelectedContextIdentities, detail: &str) -> SemanticId {
    let mut digest = CanonicalHasher::new(b"bifrost-rust-unsupported-macro-module:v1");
    // Filtered inventory queries can render the same evidence with different
    // object-key order. Its identity must also match the unfiltered diagnostic
    // inventory, or the reader loses the invocation's named reason (#5780).
    let mut value: serde_json::Value =
        serde_json::from_str(detail).expect("persisted inventory evidence is JSON");
    value.sort_all_objects();
    let canonical = serde_json::to_string(&value).expect("inventory JSON is serializable");
    digest.field("detail", canonical.as_bytes());
    if value["evidence"].as_array().is_some_and(|items| {
        !items.is_empty()
            && items
                .iter()
                .all(|item| item["reason"].as_str() == Some("UnsupportedMacroGeneratedModule"))
    }) {
        identities.named_semantic(
            digest.finish(),
            "UnsupportedMacroGeneratedModule",
            &canonical,
        )
    } else if value["evidence"].as_array().is_some_and(|items| {
        !items.is_empty()
            && items
                .iter()
                .all(|item| item["reason"].as_str() == Some("UnsupportedGlobConflictVisibility"))
    }) {
        identities.named_semantic(
            digest.finish(),
            "UnsupportedGlobConflictVisibility",
            "a glob conflict group with mixed member visibility, whose export depends on rustc's import resolution order",
        )
    } else {
        identities.semantic(digest.finish())
    }
}

/// The incompleteness of a crate-declared macro item (`rust_crate_macro_items`)
/// with no capsule definition in this request: the item exists, and this
/// request cannot bind it. `module` says why: a module item has no capsule
/// definition at all (see `MACRO_ITEM_NAME_RANGE`); any other item's invoking
/// file was not staged.
pub(super) fn unstaged_macro_item(
    identities: &SelectedContextIdentities,
    blob: i64,
    declaration: i64,
    module: bool,
) -> ResolutionCompletion {
    ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
        inventory_reason(
            identities,
            &serde_json::json!({
                "evidence": [{
                    "member_blob": blob,
                    "declaration": declaration,
                    "reason": if module { "MacroModuleItem" } else { "UnstagedMacroItem" },
                }]
            })
            .to_string(),
        ),
    )])
}

/// The incompleteness of a root half whose file is placed only in crates the
/// request is not made on behalf of (`topologies`): the half's root anchor
/// names one of those crates, and the request compiles no route for them.
pub(super) fn placed_outside_request_crates(
    identities: &SelectedContextIdentities,
    rel_path: &str,
    topologies: impl Iterator<Item = i64>,
) -> ResolutionCompletion {
    ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
        inventory_reason(
            identities,
            &serde_json::json!({
                "evidence": [{
                    "rel_path": rel_path,
                    "topologies": topologies.collect::<Vec<_>>(),
                    "reason": "PlacedOutsideRequestCrates",
                }]
            })
            .to_string(),
        ),
    )])
}

/// Why a qualified path's route stopped at its prefix. Each is a named
/// incompleteness reason: the answer publishes the name and its evidence, so a
/// reader can tell these apart from every other `UnsupportedSemantic`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RouteDeadEnd {
    /// The prefix resolved, but to nothing the selected crates place: no
    /// module and no declaration of theirs, and it did not leave the workspace
    /// for an unindexed dependency. The route has nowhere to continue.
    UnplacedRoutePrefix,
    /// The prefix resolved both to a module and to a declaration that is not
    /// a module, so the route cannot say which one it continues through.
    MixedRoutePrefix,
    /// The prefix is a module the crates place, and it exports nothing under
    /// the demanded name in the demanded namespace that this request can bind.
    UnexportedRouteSegment,
}

impl RouteDeadEnd {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::UnplacedRoutePrefix => "UnplacedRoutePrefix",
            Self::MixedRoutePrefix => "MixedRoutePrefix",
            Self::UnexportedRouteSegment => "UnexportedRouteSegment",
        }
    }
}

/// What an unplaced route prefix is, for the reply: each class routes to
/// different work. Decided from what the rows hold, never from the source text:
/// the prefix's own binding (its targets and the boundary or prelude gap its
/// completion carries), the declaration kind of its targets, the language's
/// fixed primitive type names and standard crate names, and the `Self`
/// keyword segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RoutePrefixClass {
    /// A crate outside the workspace the index does not hold (`smallvec`,
    /// `clap`): an external boundary.
    ExternalCrate,
    /// A crate of this workspace (`tract_core`) that the route still could not
    /// place: an engine gap, since the index holds the crate.
    WorkspaceCrate,
    /// The standard library (`std`, `core`, `alloc`, and items bound from
    /// them, such as `Box` or an imported `Arc`), which the index does not hold.
    Std,
    /// A primitive type (`i64::MIN`, `f32::from_bits`).
    Primitive,
    /// A generic type parameter (`T::one`): resolvable through its bounds.
    GenericParameter,
    /// `Self` inside a trait or an impl: resolvable through the owner.
    SelfQualifier,
    /// Bound through a glob or re-export whose target module's inventory is
    /// open (an undecided item macro), so the name may be generated there.
    OpenInventory,
    Other,
}

impl RoutePrefixClass {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::ExternalCrate => "external_crate",
            Self::WorkspaceCrate => "workspace_crate",
            Self::Std => "std",
            Self::Primitive => "primitive",
            Self::GenericParameter => "generic_parameter",
            Self::SelfQualifier => "self_qualifier",
            Self::OpenInventory => "open_inventory",
            Self::Other => "other",
        }
    }
}

/// The crates of the Rust standard distribution, as a route head names them.
const STANDARD_CRATES: [&str; 3] = ["std", "core", "alloc"];
/// Rust's primitive type names. A prefix spelled so and bound to nothing
/// names the primitive; a declaration of the same name would bind it.
const PRIMITIVE_TYPES: [&str; 19] = [
    "bool", "char", "str", "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64",
    "u128", "usize", "f16", "f32", "f64", "f128",
];
/// The Rust 2021 standard prelude's names that can head a type path. A prefix
/// spelled so and bound to nothing is the prelude item.
const STD_PRELUDE: [&str; 37] = [
    "Box",
    "Vec",
    "String",
    "Option",
    "Result",
    "Some",
    "None",
    "Ok",
    "Err",
    "Default",
    "Clone",
    "Copy",
    "Send",
    "Sync",
    "Sized",
    "Unpin",
    "Drop",
    "Fn",
    "FnMut",
    "FnOnce",
    "Iterator",
    "IntoIterator",
    "DoubleEndedIterator",
    "ExactSizeIterator",
    "Extend",
    "FromIterator",
    "ToOwned",
    "ToString",
    "AsRef",
    "AsMut",
    "Into",
    "From",
    "TryFrom",
    "TryInto",
    "PartialEq",
    "Eq",
    "PartialOrd",
];
/// How the selected crates declare a crate name: `workspace`, `external` or
/// `std` (`rust_crate_dependencies.boundary`).
const DEPENDENCY_BOUNDARY: &str = "SELECT dependency.boundary
 FROM selected_rust_unit_summaries AS unit
 CROSS JOIN main.rust_unit_summary_dependency_names AS name
  ON name.summary_id=unit.summary_id AND name.extern_name=?1
 CROSS JOIN main.resolution_unit_summary_dependencies AS dependency
  ON dependency.summary_id=name.summary_id
 AND dependency.dependency_ordinal=name.dependency_ordinal
 ORDER BY dependency.boundary LIMIT 1";
/// The root segment of each non-glob import in the prefix's file that binds
/// the prefix's name.
const IMPORT_ROOTS: &str = "SELECT segment.segment FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN source_rust_import_targets AS import ON import.blob_id=mount.blob_id
 CROSS JOIN source_rust_import_module_segments AS segment
  ON segment.blob_id=import.blob_id AND segment.import_ordinal=import.ordinal AND segment.ordinal=0
 WHERE mount.mount_ordinal=?1 AND import.bound_name=?2 AND import.is_glob=0";
/// Whether a selected declaration with this route prefix has a structured
/// attribute-generated surface fact. The prefix name comes from its parsed
/// route; the boundary decision comes from the persisted declaration property.
const GENERATED_SURFACE_PREFIX: &str = "SELECT json_object('evidence', json_array(json_object(
 'reason', 'GeneratedItemSurface',
 'member_blob', declaration.blob_id,
 'declaration_id', declaration.declaration_id,
 'rel_path', mount.persisted_relative_path)))
FROM temp.selected_resolution_mounts AS mount
CROSS JOIN source_rust_declaration_properties AS properties
 ON properties.blob_id=mount.blob_id AND properties.generated_surface=1
CROSS JOIN source_declarations AS declaration
 ON declaration.blob_id=properties.blob_id AND declaration.declaration_id=properties.declaration_id
CROSS JOIN source_declaration_units AS mapping
 ON mapping.blob_id=declaration.blob_id AND mapping.declaration_id=declaration.declaration_id
CROSS JOIN code_units AS unit
 ON unit.blob_id=mapping.blob_id AND unit.unit_key=mapping.unit_key
WHERE mount.mount_ordinal=?1 AND unit.identifier=?2
 AND properties.nearest_declaration_boundary=0
LIMIT 1";
/// Whether the route enters an attribute-generated inline module in this
/// source file, such as the declaration carried by `#[cxx::bridge]`.
const GENERATED_SURFACE_MODULE_PREFIX: &str =
    "SELECT json_object('evidence', json_array(json_object(
 'reason', 'GeneratedItemSurface',
 'member_blob', scope.blob_id,
 'declaration_id', scope.declaration_id,
 'rel_path', mount.persisted_relative_path,
 'module', scope.module_name)))
FROM temp.selected_resolution_mounts AS mount
CROSS JOIN source_rust_module_scopes AS scope
 ON scope.blob_id=mount.blob_id AND scope.module_name=?2
CROSS JOIN source_rust_declaration_properties AS properties
 ON properties.blob_id=scope.blob_id AND properties.declaration_id=scope.declaration_id
WHERE mount.mount_ordinal=?1 AND scope.declaration_id IS NOT NULL
 AND properties.generated_surface=1
LIMIT 1";
/// Whether a selected module declaration has a generated attribute boundary,
/// including when its module scope was withheld by that attribute.
const GENERATED_SURFACE_MODULE_DECLARATION_PREFIX: &str =
    "SELECT json_object('evidence', json_array(json_object(
 'reason', 'GeneratedItemSurface',
 'member_blob', declaration.blob_id,
 'declaration_id', declaration.declaration_id,
 'rel_path', mount.persisted_relative_path,
 'module', declaration.module_name)))
FROM temp.selected_resolution_mounts AS mount
CROSS JOIN source_rust_module_declarations AS declaration
 ON declaration.blob_id=mount.blob_id AND declaration.module_name=?2
CROSS JOIN source_rust_declaration_properties AS properties
 ON properties.blob_id=declaration.blob_id AND properties.declaration_id=declaration.declaration_id
WHERE mount.mount_ordinal=?1 AND properties.generated_surface=1
LIMIT 1";
/// Whether an unmounted source file declares a module scope with a persisted
/// attribute-generated surface, such as a `#[cxx::bridge]` module.
const GENERATED_SURFACE_SOURCE_MODULE_PREFIX: &str =
    "SELECT json_object('evidence', json_array(json_object(
 'reason', 'GeneratedItemSurface',
 'member_blob', scope.blob_id,
 'declaration_id', scope.declaration_id,
 'rel_path', ?3,
 'module', scope.module_name)))
FROM source_rust_module_scopes AS scope
CROSS JOIN source_rust_declaration_properties AS properties
 ON properties.blob_id=scope.blob_id AND properties.declaration_id=scope.declaration_id
WHERE scope.blob_id=?1 AND scope.module_name=?2 AND scope.declaration_id IS NOT NULL
 AND properties.generated_surface=1 AND properties.nearest_declaration_boundary=0
LIMIT 1";
/// Whether a mounted target is a generic type parameter's declaration.
const GENERIC_TYPE_PARAMETER_TARGET: &str = "SELECT EXISTS(SELECT 1
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_semantic_sites AS semantic
  ON semantic.blob_id=mount.blob_id AND semantic.semantic_key=?2 AND semantic.semantic_role='definition'
 CROSS JOIN source_native_declaration_bridges AS bridge
  ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site
 CROSS JOIN source_declarations AS declaration
  ON declaration.blob_id=bridge.blob_id AND declaration.declaration_id=bridge.declaration_id
 CROSS JOIN source_rust_item_generic_parameters AS parameter
  ON parameter.blob_id=declaration.blob_id
  AND parameter.name_occurrence_id=declaration.name_occurrence_id
  AND parameter.syntax_kind='type_parameter'
 WHERE mount.mount_ordinal=?1)";
/// Whether a mounted target is a non-module, non-block-local type declaration.
/// Module paths continue through crate rows; block-local declarations have no
/// placed module continuation and keep the route dead-end classification.
const NOMINAL_TYPE_TARGET: &str = "SELECT EXISTS(SELECT 1
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_semantic_sites AS semantic
  ON semantic.blob_id=mount.blob_id AND semantic.semantic_key=?2 AND semantic.semantic_role='definition'
 CROSS JOIN source_native_declaration_bridges AS bridge
  ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site
 CROSS JOIN source_rust_declaration_properties AS properties
  ON properties.blob_id=bridge.blob_id AND properties.declaration_id=bridge.declaration_id
 WHERE mount.mount_ordinal=?1 AND properties.nearest_declaration_boundary=0
  AND properties.declaration_kind IN (0,1,2,3,13,14))";
/// Whether a target is a block-local type declaration whose binder is known
/// even though its missing parser-unit projection left a gap on the item.
const BLOCK_LOCAL_TYPE_TARGET: &str = "SELECT EXISTS(SELECT 1
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_semantic_sites AS semantic
  ON semantic.blob_id=mount.blob_id AND semantic.semantic_key=?2 AND semantic.semantic_role='definition'
 CROSS JOIN source_native_declaration_bridges AS bridge
  ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site
 CROSS JOIN source_rust_declaration_properties AS properties
  ON properties.blob_id=bridge.blob_id AND properties.declaration_id=bridge.declaration_id
 WHERE mount.mount_ordinal=?1 AND properties.nearest_declaration_boundary=1
  AND properties.declaration_kind IN (0,1,2,3,13))";
/// Whether one incomplete prefix reason is exactly the parser-unit gap on one
/// of the block-local type declarations selected by that prefix.
const BLOCK_LOCAL_TYPE_GAP_FOR_TARGET: &str = "SELECT EXISTS(SELECT 1
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_gap_reasons AS gap
  ON gap.blob_id=mount.blob_id AND gap.reason=?2 AND gap.origin=?4
 CROSS JOIN resolution_semantic_sites AS semantic
  ON semantic.blob_id=gap.blob_id AND semantic.source_site=gap.site
  AND semantic.semantic_key=?3 AND semantic.semantic_role='definition'
 CROSS JOIN source_native_declaration_bridges AS bridge
  ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site
 CROSS JOIN source_rust_declaration_properties AS properties
  ON properties.blob_id=bridge.blob_id AND properties.declaration_id=bridge.declaration_id
 WHERE mount.mount_ordinal=?1 AND properties.nearest_declaration_boundary=1
  AND properties.declaration_kind IN (0,1,2,3,13))";
/// The gap-kind origin of a mounted reason, when the reason is a gap's.
pub(super) const REASON_GAP_ORIGIN: &str = "SELECT reason.origin
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_gap_reasons AS reason ON reason.blob_id=mount.blob_id AND reason.reason=?2
 WHERE mount.mount_ordinal=?1";

/// Whether every target of a resolved route prefix is a generic type
/// parameter's declaration, as `T` is in `T::one`. Such a prefix is a type
/// whose members come from the parameter's bounds, which the typed member
/// route reads; it is never a module the crate route continues through. No
/// targets is not a parameter.
pub(super) fn prefix_names_type_parameters(
    ready: &ReadySelectedResolution<'_, '_>,
    targets: &[SemanticId],
) -> Result<bool> {
    if targets.is_empty() {
        return Ok(false);
    }
    let conn = ready.inventory.connection();
    for target in targets {
        let (Some(ordinal), Some(key)) = (target.ordinal(), target.local_key()) else {
            return Ok(false);
        };
        let parameter: bool = conn
            .prepare_cached(GENERIC_TYPE_PARAMETER_TARGET)?
            .query_row(params![ordinal, key], |row| row.get(0))?;
        if !parameter {
            return Ok(false);
        }
    }
    Ok(true)
}

fn prefix_names_nominal_types(
    ready: &ReadySelectedResolution<'_, '_>,
    targets: &[SemanticId],
) -> Result<bool> {
    if targets.is_empty() {
        return Ok(false);
    }
    let conn = ready.inventory.connection();
    for target in targets {
        let (Some(ordinal), Some(key)) = (target.ordinal(), target.local_key()) else {
            return Ok(false);
        };
        let nominal_type: bool = conn
            .prepare_cached(NOMINAL_TYPE_TARGET)?
            .query_row(params![ordinal, key], |row| row.get(0))?;
        if !nominal_type {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether this incomplete prefix answer contains only known gaps on the exact
/// block-local type declarations it selected. Scope/binder and visibility
/// gaps do not undo the declaration's name or Type namespace.
pub(super) fn block_local_type_prefix_binding_is_decided(
    ready: &ReadySelectedResolution<'_, '_>,
    targets: &[SemanticId],
    completion: &ResolutionCompletion,
) -> Result<bool> {
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return Ok(false);
    };
    if targets.is_empty() || reasons.is_empty() {
        return Ok(false);
    }
    let conn = ready.inventory.connection();
    for target in targets {
        let (Some(ordinal), Some(key)) = (target.ordinal(), target.local_key()) else {
            return Ok(false);
        };
        let local_type: bool = conn
            .prepare_cached(BLOCK_LOCAL_TYPE_TARGET)?
            .query_row(params![ordinal, key], |row| row.get(0))?;
        if !local_type {
            return Ok(false);
        }
    }
    let origins = [
        crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(
            crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::
                    UnsupportedScopeOrBinder,
            ),
        ),
        crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(
            crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::
                    UnsupportedVisibility,
            ),
        ),
    ];
    for reason in reasons.iter() {
        let ResolutionIncompleteReason::UnsupportedSemantic(reason) = reason else {
            return Ok(false);
        };
        let (Some(reason_ordinal), Some(reason_key)) = (reason.ordinal(), reason.local_key())
        else {
            return Ok(false);
        };
        let mut matched = false;
        for target in targets {
            if target.ordinal() != Some(reason_ordinal) {
                continue;
            }
            let target_key = target
                .local_key()
                .expect("fragment-local type target has a local key");
            for &origin in &origins {
                let exact_gap: bool = conn
                    .prepare_cached(BLOCK_LOCAL_TYPE_GAP_FOR_TARGET)?
                    .query_row(
                        params![reason_ordinal, reason_key, target_key, origin],
                        |row| row.get(0),
                    )?;
                matched |= exact_gap;
            }
        }
        if !matched {
            return Ok(false);
        }
    }
    Ok(true)
}

/// How a route prefix participates in continuation. A block-local type
/// shadows a module route, but its missing parser-unit projection cannot
/// answer a member lookup; that path remains an explicit unplaced-route gap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RoutePrefixKind {
    MemberType,
    BlockLocalType,
    Other,
}

impl RoutePrefixKind {
    pub(super) const fn is_type(self) -> bool {
        matches!(self, Self::MemberType | Self::BlockLocalType)
    }
}

/// Classify a positioned Rust path prefix using its selected binding and the
/// exact incomplete reasons attached to that binding.
pub(super) fn route_prefix_kind(
    ready: &ReadySelectedResolution<'_, '_>,
    spelling: Option<&str>,
    targets: &[SemanticId],
    completion: &ResolutionCompletion,
) -> Result<RoutePrefixKind> {
    if spelling == Some("Self") || prefix_names_type_parameters(ready, targets)? {
        return Ok(RoutePrefixKind::MemberType);
    }
    if block_local_type_prefix_binding_is_decided(ready, targets, completion)? {
        return Ok(RoutePrefixKind::BlockLocalType);
    }
    if prefix_names_nominal_types(ready, targets)? {
        return Ok(RoutePrefixKind::MemberType);
    }
    Ok(RoutePrefixKind::Other)
}

/// Whether a route prefix has left the indexed workspace.
///
/// Either the prefix named no target at all, or every target it named is an
/// entry of the language's fixed universe table. A universe entry is a
/// language builtin - a primitive type name such as `i64` - that no selected
/// source scope declares and no workspace catalog holds, and whose associated
/// items live in the unindexed std. `i64::MIN` is therefore beyond a boundary,
/// exactly as a `std::` or external-crate root is, and never a dead end inside
/// the workspace. A source declaration that shadows the primitive is an
/// ordinary selected target, so its route keeps its dead end.
pub(super) fn prefix_left_the_indexed_workspace(
    ready: &ReadySelectedResolution<'_, '_>,
    resolved: &super::rust_prefix::RustQualifiedPrefixResolution,
) -> bool {
    // A prefix proved bound to nothing left the workspace through an import
    // the index does not hold; a prefix bound only to fixed universe entries
    // names a language builtin, whose members are as unindexed as that import.
    super::rust_prefix::rust_prefix_left_the_workspace(resolved)
        || prefix_targets_are_universe_entries(ready, &resolved.targets)
}

/// Whether every target this prefix resolved to is an entry of the language's
/// fixed universe table rather than a declaration this request indexes. The
/// identity carries the digest it was interned under, so a source declaration
/// cannot match one.
fn prefix_targets_are_universe_entries(
    ready: &ReadySelectedResolution<'_, '_>,
    targets: &[SemanticId],
) -> bool {
    if targets.is_empty() {
        return false;
    }
    let names = ready.shared_names();
    targets.iter().all(|target| {
        target
            .shared_name_id()
            .and_then(|name| names.digest_for_id(name))
            .is_some_and(|digest| {
                crate::analyzer::resolution::universe_is_entry_digest(Language::Rust, digest)
            })
    })
}

/// Classify the prefix a route stopped at. `spelling` is the prefix path's
/// root segment; `head` says the prefix is that root alone. A root proved
/// bound to nothing is an extern-prelude crate name only when it is the head.
/// `rel_path` is the reference's file, whose open inventories
/// (`GAP_DETAILS`) name the reasons an open glob target gives.
#[allow(clippy::too_many_arguments)]
pub(super) fn classify_route_prefix(
    ready: &ReadySelectedResolution<'_, '_>,
    rel_path: Option<&str>,
    spelling: Option<&str>,
    resolved: &super::rust_prefix::RustQualifiedPrefixResolution,
    prefix_mount: Option<u32>,
    head: bool,
    cancellation: &CancellationToken,
) -> Result<RoutePrefixClass> {
    let conn = ready.inventory.connection();
    if spelling == Some("Self") {
        return Ok(RoutePrefixClass::SelfQualifier);
    }
    let has_targets = !resolved.targets.is_empty();
    if has_targets && prefix_names_type_parameters(ready, &resolved.targets)? {
        return Ok(RoutePrefixClass::GenericParameter);
    }
    // A primitive type name binds nothing, or binds the primitive the
    // universe table supplies when no source scope declares one. Both name the
    // same unindexed type, and a shadowing declaration does not reach here.
    if spelling.is_some_and(|spelling| PRIMITIVE_TYPES.contains(&spelling))
        && (!has_targets || prefix_targets_are_universe_entries(ready, &resolved.targets))
    {
        return Ok(RoutePrefixClass::Primitive);
    }
    let standard = |spelling: &str| STANDARD_CRATES.contains(&spelling);
    let crate_class = |name: &str| -> Result<Option<RoutePrefixClass>> {
        if standard(name) {
            return Ok(Some(RoutePrefixClass::Std));
        }
        let boundary: Option<String> = conn
            .prepare_cached(DEPENDENCY_BOUNDARY)?
            .query_row([name], |row| row.get(0))
            .optional()?;
        Ok(boundary.map(|boundary| match boundary.as_str() {
            "workspace" => RoutePrefixClass::WorkspaceCrate,
            "std" => RoutePrefixClass::Std,
            _ => RoutePrefixClass::ExternalCrate,
        }))
    };
    if !has_targets && let Some(spelling) = spelling {
        if let Some(class) = crate_class(spelling)? {
            return Ok(class);
        }
        if STD_PRELUDE.contains(&spelling) {
            return Ok(RoutePrefixClass::Std);
        }
        if let Some(ordinal) = prefix_mount {
            let roots = conn
                .prepare_cached(IMPORT_ROOTS)?
                .query_map(params![ordinal, spelling], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for root in &roots {
                if is_module_anchor(root) {
                    return Ok(RoutePrefixClass::WorkspaceCrate);
                }
                if let Some(class) = crate_class(root)? {
                    return Ok(class);
                }
            }
        }
    }
    let mut boundary_roots = Vec::new();
    let mut prelude_gap = false;
    let mut unsupported = Vec::new();
    if let ResolutionCompletion::Incomplete(reasons) = &resolved.completion {
        for reason in reasons.iter() {
            match reason {
                ResolutionIncompleteReason::OpenBoundary {
                    semantic,
                    status: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                } if !has_targets => boundary_roots.push(*semantic),
                ResolutionIncompleteReason::UnsupportedSemantic(semantic) => {
                    unsupported.push(*semantic);
                    if let (Some(ordinal), Some(key)) = (semantic.ordinal(), semantic.local_key())
                        && let Some(origin) = conn
                            .prepare_cached(REASON_GAP_ORIGIN)?
                            .query_row(params![ordinal, key], |row| row.get::<_, i64>(0))
                            .optional()?
                    {
                        prelude_gap |= crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_from_code(origin)
                            == crate::analyzer::resolution::LoweringGapOrigin::ExternalPreludeBoundary;
                    }
                }
                _ => {}
            }
        }
    }
    if !boundary_roots.is_empty() {
        // The import that bound the prefix left the workspace; its root crate
        // says which world it went to.
        let roots =
            ready.rust_prefix_spellings(&ready.lexical_source(), &boundary_roots, cancellation)?;
        return Ok(if roots.values().any(|root| standard(root)) {
            RoutePrefixClass::Std
        } else {
            RoutePrefixClass::ExternalCrate
        });
    }
    if unsupported.iter().any(|semantic| {
        ready
            .context_identities
            .named_reason(*semantic)
            .is_some_and(|(kind, _)| kind == "UnsupportedMacroGeneratedModule")
    }) {
        return Ok(RoutePrefixClass::OpenInventory);
    }
    if !unsupported.is_empty()
        && let Some(rel_path) = rel_path
    {
        for detail in conn
            .prepare_cached(GAP_DETAILS)?
            .query_map([rel_path], |row| row.get::<_, String>(0))?
        {
            if unsupported.contains(&inventory_reason(&ready.context_identities, &detail?)) {
                return Ok(RoutePrefixClass::OpenInventory);
            }
        }
    }
    if has_targets {
        return Ok(RoutePrefixClass::Other);
    }
    if !matches!(resolved.completion, ResolutionCompletion::Incomplete(_)) {
        // Bound to nothing and proved so: the head is an extern-prelude name.
        return Ok(match spelling {
            Some(spelling) if head && standard(spelling) => RoutePrefixClass::Std,
            Some(_) if head => RoutePrefixClass::ExternalCrate,
            _ => RoutePrefixClass::Other,
        });
    }
    Ok(if prelude_gap {
        RoutePrefixClass::Std
    } else {
        RoutePrefixClass::Other
    })
}

/// The incompleteness of a route that stopped at its prefix, as one named
/// reason. The evidence names the file, the route and the demand, so two
/// sites of one file that ask the same question share the reason.
/// Whether the prefix's file has a non-glob import that binds the prefix's
/// spelling through a path rooted at `crate`, `self` or `super`. Such a path
/// names a module of this crate, so a prefix it binds cannot have left the
/// workspace: a route that found nothing is the dead end, not an unindexed
/// boundary (`use crate::missing::Local; Local::new()`).
const ANCHORED_IMPORT_BINDS: &str = "SELECT EXISTS(SELECT 1
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN source_rust_import_targets AS import
  ON import.blob_id=mount.blob_id AND import.bound_name=?2 AND import.is_glob=0
 CROSS JOIN source_rust_import_module_segments AS segment
  ON segment.blob_id=import.blob_id AND segment.import_ordinal=import.ordinal AND segment.ordinal=0
  AND segment.segment IN ('crate','self','super')
 WHERE mount.mount_ordinal=?1)";

/// A route prefix that resolved to nothing, completely, through an import
/// anchored in this crate (`ANCHORED_IMPORT_BINDS`). The route stayed in the
/// workspace. It is not answered as a proved absence: measured on the census,
/// such walks still miss real declarations (items a macro declares in another
/// crate, re-export chains across crates), so the answer is the dead end.
pub(super) fn prefix_bound_in_the_crate(
    ready: &ReadySelectedResolution<'_, '_>,
    prefix: SemanticId,
    resolved: &super::rust_prefix::RustQualifiedPrefixResolution,
    cancellation: &CancellationToken,
) -> Result<bool> {
    if !resolved.targets.is_empty() || resolved.completion != ResolutionCompletion::Complete {
        return Ok(false);
    }
    let Some(ordinal) = prefix.ordinal() else {
        return Ok(false);
    };
    let Some(spelling) = ready
        .rust_prefix_spellings(&ready.lexical_source(), &[prefix], cancellation)?
        .remove(&prefix)
    else {
        return Ok(false);
    };
    Ok(ready
        .inventory
        .connection()
        .prepare_cached(ANCHORED_IMPORT_BINDS)?
        .query_row(params![ordinal, spelling], |row| row.get(0))?)
}

/// A crate export row names a declaration whose file's lowering produced no
/// definition for it: the producer withheld the item (an attribute it treats
/// as possibly item-transforming, for one). The row proves the name is
/// declared, so the walk is not a proved absence; this names why it is open.
pub(super) fn unlowered_export_declaration(
    identities: &SelectedContextIdentities,
    rel_path: &str,
    site: u32,
) -> ResolutionCompletion {
    let evidence = serde_json::json!({
        "evidence": [{
            "reason": "UnloweredExportedDeclaration",
            "rel_path": rel_path,
            "declaration_site": site,
        }]
    })
    .to_string();
    let mut digest = CanonicalHasher::new(b"bifrost-rust-unlowered-export:v1");
    digest.field("evidence", evidence.as_bytes());
    ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
        identities.named_semantic(digest.finish(), UNLOWERED_EXPORT_REASON, &evidence),
    )])
}

pub(super) fn route_dead_end(
    identities: &SelectedContextIdentities,
    dead_end: RouteDeadEnd,
    rel_path: Option<&str>,
    prefix: Option<&str>,
    prefix_class: Option<RoutePrefixClass>,
    route: &[ResolutionLookupSemanticRecipe],
    demand: &ResolutionLookupSemanticRecipe,
) -> ResolutionCompletion {
    let evidence = serde_json::json!({
        "evidence": [{
            "reason": dead_end.name(),
            "rel_path": rel_path,
            "prefix": prefix,
            "prefix_class": prefix_class.map(RoutePrefixClass::label),
            "route": route.iter().map(ResolutionLookupSemanticRecipe::spelling).collect::<Vec<_>>(),
            "demand": demand.spelling(),
            "namespace": namespace(demand.namespace()),
        }]
    })
    .to_string();
    let mut digest = CanonicalHasher::new(b"bifrost-rust-route-dead-end:v1");
    digest.field("evidence", evidence.as_bytes());
    ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
        identities.named_semantic(digest.finish(), dead_end.name(), &evidence),
    )])
}

/// A crate's edition and implicit prelude kind, from its topology row.
pub(super) const TOPOLOGY_PRELUDE: &str = "SELECT contexts.edition, contexts.prelude
 FROM selected_rust_unit_summaries AS unit
 CROSS JOIN main.rust_resolution_unit_summary_contexts AS contexts
  ON contexts.summary_id=unit.summary_id
 WHERE unit.topology_id = ?1";

/// The open boundary for an unqualified name that falls through every scope
/// of a crate whose implicit prelude supplies it: a semantic naming the
/// prelude crate (std or core), the edition's prelude module and the name.
/// `None` when the crate has no prelude (`#![no_core]`) or its prelude does
/// not inject the name in that namespace.
pub(super) fn prelude_boundary(
    conn: &rusqlite::Connection,
    identities: &SelectedContextIdentities,
    topology: i64,
    demand: &ResolutionLookupSemanticRecipe,
) -> Result<Option<SemanticId>> {
    use brokk_bifrost_rust::prelude::{
        RustEdition, RustPreludeCrate, RustPreludeNamespace, rust_prelude_name,
    };
    let namespace = match demand.namespace() {
        ResolutionNamespace::Type => RustPreludeNamespace::Type,
        ResolutionNamespace::Value | ResolutionNamespace::Callable => RustPreludeNamespace::Value,
        _ => return Ok(None),
    };
    let (edition, prelude): (String, String) = conn
        .prepare_cached(TOPOLOGY_PRELUDE)?
        .query_row([topology], |row| Ok((row.get(0)?, row.get(1)?)))?;
    let edition = RustEdition::from_crate_row(&edition).expect("schema checks the edition");
    let prelude = match prelude.as_str() {
        "std" => RustPreludeCrate::Std,
        "core" => RustPreludeCrate::Core,
        "none" => return Ok(None),
        other => unreachable!("schema checks the prelude: {other}"),
    };
    let Some(entry) = rust_prelude_name(demand.spelling(), namespace, edition, prelude) else {
        return Ok(None);
    };
    let evidence = serde_json::json!({
        "crate": prelude.name(),
        "prelude": edition.prelude_module(),
        "name": entry.name,
        "namespace": self::namespace(demand.namespace()),
    })
    .to_string();
    let mut digest = CanonicalHasher::new(b"bifrost-rust-prelude-boundary:v1");
    digest.field("evidence", evidence.as_bytes());
    Ok(Some(identities.named_semantic(
        digest.finish(),
        "rust_prelude_item",
        &evidence,
    )))
}

pub(super) fn namespace(namespace: ResolutionNamespace) -> &'static str {
    match namespace {
        ResolutionNamespace::Type => "type",
        ResolutionNamespace::Macro => "macro",
        _ => "value",
    }
}

#[allow(clippy::too_many_arguments)]
fn append_export_bridges(
    out: &mut Vec<SelectedRootBridgeDescriptor>,
    names: &dyn crate::analyzer::resolution::SharedNameInterner,
    modules: &[Module],
    halves: &[SelectedRootPathHalf],
    exports_by_site: &BTreeMap<(BindingFragmentId, ResolutionSiteId), Vec<usize>>,
    recipes: &HashMap<(BindingFragmentId, SemanticId), ResolutionLookupSemanticRecipe>,
    source: BindingFragmentId,
    token: SemanticId,
    anchor: ResolutionRootImportAnchor,
    anchor_semantic: SemanticId,
    prefix: Option<SemanticId>,
    route: &[ResolutionLookupSemanticRecipe],
    demand: &ResolutionLookupSemanticRecipe,
    target_fragment: BindingFragmentId,
    site: u32,
    topology: i64,
    export_module_path: &str,
    continuation: &ResolutionCompletion,
) -> bool {
    // Blobs are content addressed, so two byte-identical files at different
    // module paths share one blob id. The export row's own container path is
    // what names the mount that declares it.
    let declaring = modules.iter().filter(|module| {
        module.fragment == target_fragment
            && module.topology == topology
            && (module.path == export_module_path
                || demand.namespace() == ResolutionNamespace::Macro)
    });
    // Whether the declaring file lowered this declaration at all: a lowered
    // declaration has export halves at its site, whatever their demand.
    let lowered = declaring.clone().any(|module| {
        exports_by_site.contains_key(&(module.fragment, ResolutionSiteId::new(site)))
    });
    append_half_bridges(
        out,
        names,
        declaring
            .flat_map(|module| exports_by_site.get(&(module.fragment, ResolutionSiteId::new(site))))
            .flatten()
            .map(|index| &halves[*index]),
        recipes,
        source,
        token,
        anchor,
        anchor_semantic,
        prefix,
        route,
        demand,
        continuation,
    );
    lowered
}

/// One bridge per export half whose demand spells the route's demand in its
/// namespace, from the source token to the half's export token.
#[allow(clippy::too_many_arguments)]
fn append_half_bridges<'a>(
    out: &mut Vec<SelectedRootBridgeDescriptor>,
    names: &dyn crate::analyzer::resolution::SharedNameInterner,
    halves: impl Iterator<Item = &'a SelectedRootPathHalf>,
    recipes: &HashMap<(BindingFragmentId, SemanticId), ResolutionLookupSemanticRecipe>,
    source: BindingFragmentId,
    token: SemanticId,
    anchor: ResolutionRootImportAnchor,
    anchor_semantic: SemanticId,
    prefix: Option<SemanticId>,
    route: &[ResolutionLookupSemanticRecipe],
    demand: &ResolutionLookupSemanticRecipe,
    continuation: &ResolutionCompletion,
) {
    for half in halves {
        let SelectedRootPathHalf::Export {
            identity,
            token: export,
            demand: target_demand,
            incomplete_reasons,
            ..
        } = half
        else {
            continue;
        };
        let Some(target_demand) = recipes.get(&(identity.fragment(), *target_demand)) else {
            continue;
        };
        if target_demand.namespace() != demand.namespace() {
            continue;
        }
        let completion = if incomplete_reasons.is_empty() {
            ResolutionCompletion::Complete
        } else {
            ResolutionCompletion::incomplete(incomplete_reasons.iter().copied())
        };
        let completion = completion.combine(continuation);
        let bridge = if let Some(prefix) = prefix {
            SelectedRootBridgeDescriptor::from_selected_path_tokens_with_prefix(
                source,
                Language::Rust,
                token,
                anchor,
                anchor_semantic,
                identity.fragment(),
                Language::Rust,
                *export,
                prefix,
                route.to_vec(),
                demand.clone(),
                target_demand.clone(),
                completion,
            )
        } else {
            SelectedRootBridgeDescriptor::from_selected_path_tokens(
                source,
                Language::Rust,
                token,
                anchor,
                anchor_semantic,
                identity.fragment(),
                Language::Rust,
                *export,
                route.to_vec(),
                demand.clone(),
                target_demand.clone(),
                completion,
            )
        };
        out.push(bridge.with_selected_export(names, half));
    }
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn sql_pins() -> Vec<(&'static str, &'static str, usize)> {
    vec![
        (
            "rust_unit_summary_package_members",
            super::super::rust_unit_summaries::PACKAGE_ROWS_SQL,
            1,
        ),
        (
            "rust_unit_summary_cargo_routes",
            super::super::rust_unit_summaries::CARGO_ROUTE_ROWS_SQL,
            1,
        ),
        (
            "rust_unit_summary_development_capability",
            super::super::rust_unit_summaries::DEVELOPMENT_CAPABILITY_SQL,
            4,
        ),
        ("rust_point_naming", NAMING, 1),
        ("rust_point_file_blob", FILE_BLOB, 1),
        ("rust_point_macro_hosts", MACRO_HOST_FILES, 1),
        (
            "rust_point_access_placements",
            super::rust_crate_access::PLACEMENTS,
            3,
        ),
        (
            "rust_point_access_reference_placements",
            super::rust_crate_access::REFERENCE_PLACEMENTS,
            3,
        ),
        (
            "rust_point_access_memberships",
            super::rust_crate_access::MEMBERSHIPS,
            2,
        ),
        (
            "rust_point_access_visibility",
            super::rust_crate_access::VISIBILITY,
            6,
        ),
        ("rust_point_crate", CRATE, 1),
        ("rust_point_topology_prelude", TOPOLOGY_PRELUDE, 1),
        ("rust_graph_crate_keys", CRATE_KEYS, 0),
        ("rust_graph_crate_member_files", CRATE_MEMBER_FILES, 1),
        ("rust_point_cfg", CFG, 1),
        (
            "rust_point_macro_import_target_range",
            MACRO_IMPORT_TARGET_RANGE,
            2,
        ),
        (
            "rust_point_imported_macro_definition",
            SELECT_IMPORTED_MACRO_DEFINITION,
            3,
        ),
        ("rust_point_boundary_import_names", BOUNDARY_IMPORT_NAMES, 2),
        ("rust_point_file_crates", FILE_CRATES, 2),
        ("rust_graph_crates_reaching", CRATES_REACHING, 1),
        ("rust_point_modules", MODULES, 1),
        (
            "rust_scope_closure_mounts",
            CLOSURE_SCOPE_MOUNTS_PIN.as_str(),
            1,
        ),
        ("rust_point_module_placements", MODULE_PLACEMENTS, 2),
        ("rust_point_named", NAMED, 7),
        ("rust_point_import_root_name", IMPORT_ROOT_NAME, 3),
        (
            "rust_point_overlay_import_targets",
            OVERLAY_IMPORT_TARGETS,
            2,
        ),
        ("rust_point_globs", GLOBS, 4),
        ("rust_point_scopes", SCOPES, 2),
        ("rust_point_dependency", DEPENDENCY.as_str(), 3),
        ("rust_point_dependency_boundary", DEPENDENCY_BOUNDARY, 1),
        ("rust_point_parent", PARENT, 2),
        ("rust_point_container_declaration", CONTAINER_DECLARATION, 2),
        ("rust_published_export", PUBLISHED_EXPORT, 6),
        ("rust_published_macro_prelude", PUBLISHED_MACRO_PRELUDE, 6),
        ("rust_point_anchored_import_binds", ANCHORED_IMPORT_BINDS, 2),
        ("rust_published_root_reexport", PUBLISHED_ROOT_REEXPORT, 6),
        (
            "rust_published_module_prefix",
            PUBLISHED_MODULE_PREFIX_ROUTE,
            6,
        ),
        (
            "rust_point_module_import_prefix_starts",
            IMPORT_MODULE_PREFIX_STARTS,
            7,
        ),
        (
            "rust_point_macro_gated_import_route",
            MACRO_GATED_IMPORT_ROUTE,
            6,
        ),
        (
            "rust_point_macro_gated_unmounted_file",
            MACRO_GATED_UNMOUNTED_FILE,
            1,
        ),
        (
            "rust_point_generated_surface_prefix",
            GENERATED_SURFACE_PREFIX,
            2,
        ),
        (
            "rust_point_generated_surface_module_prefix",
            GENERATED_SURFACE_MODULE_PREFIX,
            2,
        ),
        (
            "rust_point_generated_surface_module_declaration_prefix",
            GENERATED_SURFACE_MODULE_DECLARATION_PREFIX,
            2,
        ),
        (
            "rust_point_generated_surface_source_module_prefix",
            GENERATED_SURFACE_SOURCE_MODULE_PREFIX,
            3,
        ),
        (
            "rust_point_derive_helper_conditions",
            DERIVE_HELPER_CONDITIONS,
            2,
        ),
        ("rust_point_unindexed_scope", UNINDEXED_SCOPE, 6),
        ("rust_point_external_binding", EXTERNAL_BINDING, 7),
        ("rust_point_definition_module", DEFINITION_MODULE, 4),
        ("rust_point_macro_item_module", MACRO_ITEM_MODULE, 5),
        ("rust_point_named_macro_module", NAMED_MACRO_MODULE, 3),
        ("rust_point_macro_item_hosts", MACRO_ITEM_HOSTS, 1),
        ("rust_point_macro_item_name", MACRO_ITEM_NAME_RANGE, 2),
        ("rust_point_macro_items_present", MACRO_ITEMS_PRESENT, 0),
        ("rust_point_nominal_type_target", NOMINAL_TYPE_TARGET, 2),
        (
            "rust_point_block_local_type_target",
            BLOCK_LOCAL_TYPE_TARGET,
            2,
        ),
        (
            "rust_point_block_local_type_gap_for_target",
            BLOCK_LOCAL_TYPE_GAP_FOR_TARGET,
            4,
        ),
        ("rust_point_gaps", GAPS, 1),
        (
            "rust_point_trait_visible_at",
            super::rust_crate_rows::TRAIT_VISIBLE_AT,
            8,
        ),
        (
            "rust_point_trait_impls_visible_at",
            super::rust_crate_rows::TRAIT_IMPLS_VISIBLE_AT,
            8,
        ),
        (
            "rust_point_trait_impl_member_at",
            super::rust_crate_rows::TRAIT_IMPL_MEMBER_AT,
            9,
        ),
        (
            "rust_point_reference_module_placements",
            super::rust_crate_rows::REFERENCE_MODULE_PLACEMENTS,
            2,
        ),
        (
            "rust_point_owner_declaration",
            super::rust_crate_rows::OWNER_DECLARATION,
            2,
        ),
        (
            "rust_point_external_type_identity",
            super::rust_crate_rows::EXTERNAL_TYPE_IDENTITY,
            3,
        ),
        (
            "rust_point_impl_item_traits",
            super::rust_crate_rows::IMPL_ITEM_TRAITS,
            3,
        ),
        (
            "rust_point_store_trait_impl_rows",
            super::super::RUST_TRAIT_IMPL_ROWS_SQL.as_str(),
            4,
        ),
        (
            "rust_point_store_traits_of_impl",
            super::super::RUST_TRAITS_OF_IMPL_SQL.as_str(),
            4,
        ),
        (
            "rust_point_store_trait_impl_spellings",
            super::super::RUST_TRAIT_IMPL_SPELLINGS_SQL.as_str(),
            4,
        ),
        (
            "rust_point_store_traits_implemented_by",
            super::super::RUST_TRAITS_IMPLEMENTED_BY_SQL.as_str(),
            4,
        ),
        (
            "rust_point_store_types_implementing",
            super::super::RUST_TYPES_IMPLEMENTING_SQL.as_str(),
            4,
        ),
        (
            "rust_point_reference_names_macro_module",
            super::rust_crate_rows::REFERENCE_NAMES_MACRO_MODULE,
            3,
        ),
        (
            "rust_point_reference_names_workspace_crate",
            super::rust_crate_rows::REFERENCE_NAMES_WORKSPACE_CRATE.as_str(),
            4,
        ),
        ("rust_point_import_inventory", IMPORT_INVENTORY, 1),
        ("rust_point_gap_details", GAP_DETAILS, 1),
        ("rust_published_open_inventory", PUBLISHED_OPEN_INVENTORY, 6),
        ("rust_published_binding_exact", PUBLISHED_BINDING_EXACT, 6),
        (
            "rust_point_binding_target_topology",
            BINDING_TARGET_TOPOLOGY,
            1,
        ),
        ("rust_point_binding_inventory", BINDING_INVENTORY, 6),
        (
            "rust_point_unknown_import_inventory",
            UNKNOWN_IMPORT_INVENTORY,
            6,
        ),
        ("rust_point_open_route", OPEN_ROUTE, 3),
    ]
}

/// One Rust file's package naming: the module components its definitions'
/// packages are built from.
///
/// The naming is a property of the file alone, and a caller that hydrates a
/// mount's definition units hydrates many rows of one file. Reading it once per
/// row through `Connection::query_row`, which prepares the statement on every
/// call, ran `rust_crate_point_naming.sql` 42,457 times over the 200 tract
/// usages points (77 percent of their statements, none of them reusing a
/// prepared statement), mostly asking one target file's naming again for each
/// of its definitions. Callers now read it once per mount, through the
/// reader's statement cache, and keep it for that one hydration.
pub(super) struct RustFileNaming {
    package: Box<[String]>,
    root: Box<[String]>,
}

impl RustFileNaming {
    pub(super) fn read(
        ready: &ReadySelectedResolution<'_, '_>,
        file: &ProjectFile,
    ) -> Result<Option<Self>> {
        let path = crate::path_utils::rel_path_string(file);
        let naming: Option<(String, String)> = ready
            .inventory
            .connection()
            .prepare_cached(NAMING)?
            .query_row([&path], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        let Some((package, root)) = naming else {
            return Ok(None);
        };
        let components = |json: &str| {
            serde_json::from_str::<Box<[String]>>(json)
                .map_err(|error| StoreError::corrupt(error.to_string()))
        };
        Ok(Some(Self {
            package: components(&package)?,
            root: components(&root)?,
        }))
    }

    pub(super) fn package_prefix(
        &self,
        anchor: brokk_bifrost_core::analyzer::PackageAnchor,
    ) -> brokk_bifrost_core::analyzer::fq_name::FqName {
        use brokk_bifrost_core::analyzer::{
            PackageAnchor,
            fq_name::{FqName, SegmentKind, segment_interner},
        };
        let (components, pop) = match anchor {
            PackageAnchor::OwnModule { pop } => (&self.package, usize::from(pop)),
            PackageAnchor::CrateRoot => (&self.root, 0),
        };
        let keep = components.len().saturating_sub(pop);
        let mut fq = FqName::new();
        for name in components.iter().take(keep) {
            fq.push(segment_interner().intern(name, SegmentKind::Package));
        }
        fq
    }
}

/// One access policy's own content key: its domain and its crate keys.
fn crate_access_digest(domain: &[u8], crate_keys: &[[u8; 32]]) -> [u8; 32] {
    let mut digest = CanonicalHasher::new(domain);
    digest.field("crate_keys", crate_keys.as_flattened());
    digest.finish()
}

impl SelectedResolutionOperation<'_, '_> {
    /// Install the combined Rust memo and read snapshot used by scoped point
    /// paths. Native graph units use `RustGraphStageTables` with the generic
    /// graph guard instead, so context and batch reads share those same Rust
    /// rows inside the language-neutral authority and transaction boundary.
    #[doc(hidden)]
    pub fn crate_stage_memos(&self) -> Result<super::rust_crate_rows::CrateStageMemos<'_>> {
        self.ready.crate_stage_memos()
    }
    #[doc(hidden)]
    pub fn rust_graph_stage_tables(&self) -> super::rust_crate_rows::RustGraphStageTables<'_> {
        super::rust_crate_rows::RustGraphStageTables::install(
            &self.ready.crate_rows,
            self.ready.inventory.crate_access_memo(),
        )
    }
}
