//! Query-lived point contexts compiled from persisted crate rows.
use super::rust_crate_rows::{RustCrateDeclaration, RustCrateExport};
use super::*;
use crate::analyzer::resolution::mounted_site_semantic;
use rusqlite::params;
use rusqlite::params_from_iter;
use rusqlite::types::Value;

pub(super) const GENERATED_ITEM_SURFACE_REASON: &str = "GeneratedItemSurface";
pub(super) const UNLOWERED_EXPORT_REASON: &str = "UnloweredExportedDeclaration";

pub(in crate::analyzer::store) const SELECTED_MODULE_PLACEMENTS_SCHEMA_SQL: &str =
    include_str!("rust_selected_module_placements.sql");
pub(in crate::analyzer::store) const SELECTED_MODULE_PLACEMENTS_FILL_SQL: &str =
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
pub(super) const SELECT_IMPORTED_MACRO_DEFINITION: &str = r#"
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
JOIN main.rust_resolution_unit_summary_placements AS placement
  INDEXED BY rust_resolution_unit_summary_placements_member
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
CROSS JOIN main.rust_resolution_unit_summary_placements AS placement
  INDEXED BY rust_resolution_unit_summary_placements_member
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
     FROM selected_rust_module_placements
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
pub(super) const TARGET_UNIT_JOINS: &str =
    "CROSS JOIN main.resolution_unit_summary_versions AS target_version
 ON target_version.workspace_id=owner.workspace_id AND target_version.lang=owner.lang
AND target_version.generation=owner.generation AND target_version.unit_key=keys.unit_key
AND target_version.valid_from<=owner.revision
AND (target_version.valid_until IS NULL OR owner.revision<target_version.valid_until)
CROSS JOIN main.resolution_unit_summaries AS target_summary
 ON target_summary.summary_id=target_version.summary_id
AND target_summary.lang='rust' AND target_summary.unit_kind='rust_crate'
AND target_summary.publication_state='complete' AND target_summary.derivation_version=7
CROSS JOIN main.resolution_producer_epochs AS epoch
 ON epoch.lang=target_version.lang AND epoch.producer_epoch=target_summary.producer_epoch
CROSS JOIN main.rust_resolution_unit_summary_contexts AS target_context
 ON target_context.summary_id=target_summary.summary_id
CROSS JOIN main.rust_resolution_unit_summary_versions AS target
 ON target.workspace_id=target_version.workspace_id AND target.lang=target_version.lang
AND target.generation=target_version.generation AND target.unit_key=target_version.unit_key
AND target.valid_from=target_version.valid_from AND target.summary_id=target_version.summary_id";

/// The point dependency query: the owner's dependency keys under an extern name,
/// then each target's topology. The owner and key CTEs live in
/// rust_crate_point_dependency.sql.
pub(super) static DEPENDENCY: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        "{}SELECT target.topology_id\nFROM owner\nCROSS JOIN dependency_keys AS keys\n{TARGET_UNIT_JOINS}",
        include_str!("rust_crate_point_dependency.sql")
    )
});
/// A crate-root name reached through the same visible named and glob routes
/// as ordinary exports. Crate roots have no item declaration to return from
/// EXPORT, but their terminal `crate::self` route is a module continuation.
pub(super) const ROOT_REEXPORT: &str = concat!(
    include_str!("rust_crate_point_targets.sql"),
    "SELECT DISTINCT topology_id FROM targets WHERE module_path='crate' AND name='self'"
);
/// The module containers reached by the same point-route walk used for an
/// imported name, including named re-exports through the requesting crate.
const MODULE_PREFIX_ROUTE: &str = concat!(
    include_str!("rust_crate_point_targets.sql"),
    "SELECT DISTINCT targets.topology_id,",
    " CASE WHEN targets.name='self' THEN targets.module_path",
    " ELSE targets.module_path || '::' || targets.name END AS container_path",
    " FROM targets",
    " CROSS JOIN rust_crate_containers AS container ON container.topology_id=targets.topology_id",
    " AND container.kind='module'",
    " AND container.container_path=CASE WHEN targets.name='self' THEN targets.module_path",
    " ELSE targets.module_path || '::' || targets.name END"
);
/// The module starts available for a type-namespace prefix: a dependency's
/// extern name, a crate-root reexport, or a named import that resolves to a
/// module container. Callers first check that a local type does not shadow it. The point route
/// (`rust_demand/rows.rs`) and the graph route below both start a prefix's
/// module walk here, so the two cannot drift.
pub(super) fn route_prefix_module_starts(
    conn: &rusqlite::Connection,
    module: &Module,
    name: &str,
    binder_scope: u32,
) -> Result<Vec<(i64, String)>> {
    let mut starts = Vec::new();
    for row in conn
        .prepare_cached(DEPENDENCY.as_str())?
        .query_map(params![module.topology, name], |row| row.get::<_, i64>(0))?
    {
        starts.push((row?, "crate".to_owned()));
    }
    for row in conn.prepare_cached(ROOT_REEXPORT)?.query_map(
        params![
            module.topology,
            module.path,
            "type",
            name,
            module.topology,
            module.path
        ],
        |row| row.get::<_, i64>(0),
    )? {
        starts.push((row?, "crate".to_owned()));
    }
    for row in conn.prepare_cached(MODULE_PREFIX_ROUTE)?.query_map(
        params![
            module.topology,
            module.path,
            "type",
            name,
            module.topology,
            module.path
        ],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
    )? {
        starts.push(row?);
    }
    let mut import_scopes = vec![binder_scope, module.scope.get()];
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
        for (topology, target_module_path, target_name) in bindings {
            for row in conn.prepare_cached(IMPORT_MODULE_PREFIX_ROUTE)?.query_map(
                params![
                    topology,
                    target_module_path,
                    "type",
                    target_name,
                    module.topology,
                    module.path
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )? {
                starts.push(row?);
            }
        }
    }
    starts.sort_unstable();
    starts.dedup();
    Ok(starts)
}
pub(super) const PARENT: &str = "SELECT placement.parent_module_path
 FROM selected_rust_unit_summaries AS unit
 CROSS JOIN main.rust_resolution_unit_summary_containers AS container
  ON container.summary_id=unit.summary_id AND container.module_path=?2
 AND container.kind='module' AND container.module_path<>'crate'
 CROSS JOIN main.rust_resolution_unit_summary_placements AS placement
  ON placement.summary_id=container.summary_id AND placement.module_path=container.module_path
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
const IMPORT_MODULE_PREFIX_STARTS: &str = concat!(
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

/// Module containers reached by following a selected import target through
/// the same re-export route used for point lookups.
const IMPORT_MODULE_PREFIX_ROUTE: &str = concat!(
    include_str!("rust_crate_point_targets.sql"),
    "SELECT DISTINCT targets.topology_id,",
    " CASE WHEN targets.name='self' THEN targets.module_path",
    " ELSE targets.module_path || '::' || targets.name END AS container_path",
    " FROM targets",
    " CROSS JOIN rust_crate_containers AS container ON container.topology_id=targets.topology_id",
    " AND container.kind='module'",
    " AND container.container_path=CASE WHEN targets.name='self' THEN targets.module_path",
    " ELSE targets.module_path || '::' || targets.name END"
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
pub(super) const EXPORT: &str = concat!(
    include_str!("rust_crate_point_targets.sql"),
    include_str!("rust_crate_point_export.sql")
);
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
 CROSS JOIN selected_rust_module_placements AS placement
  ON placement.mount_ordinal=mount.mount_ordinal
  AND placement.module_declaration IS authority.module_declaration
 WHERE mount.storage_language='rust' AND property.nearest_declaration_boundary=0
 ORDER BY mount.mount_ordinal, gap.reason, helper.value, placement.topology_id, placement.container_path";
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

pub(super) const CONTAINER_DECLARATION: &str = "SELECT parent.module_path, declaration.module_name
 FROM selected_rust_unit_summaries AS unit
 CROSS JOIN main.rust_resolution_unit_summary_placements AS child
  ON child.summary_id=unit.summary_id AND child.module_path=?2
 CROSS JOIN main.rust_resolution_unit_summary_placements AS parent
  ON parent.summary_id=child.summary_id AND parent.module_path=child.parent_module_path
 CROSS JOIN main.resolution_unit_summary_members AS member
  ON member.summary_id=parent.summary_id AND member.member_ordinal=parent.member_ordinal
 CROSS JOIN source_rust_module_inventory AS declaration
  ON declaration.blob_id=member.blob_id
 AND declaration.parent_scope_ordinal=parent.scope_ordinal
 WHERE unit.topology_id=?1
  AND parent.module_path || '::' || declaration.module_name=?2";
pub(super) const DEFINITION_MODULE: &str = "SELECT selected.topology_id, modules.module_path
 FROM source_native_declaration_bridges AS bridge
 CROSS JOIN source_declaration_units AS mapping
  ON mapping.blob_id=bridge.blob_id AND mapping.declaration_id=bridge.declaration_id
 CROSS JOIN code_units AS unit ON unit.blob_id=mapping.blob_id AND unit.unit_key=mapping.unit_key
 CROSS JOIN selected_rust_unit_summaries AS selected ON selected.topology_id=?3
 CROSS JOIN main.rust_resolution_unit_summary_containers AS modules
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
 CROSS JOIN main.rust_resolution_unit_summary_containers AS modules
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
 CROSS JOIN main.rust_resolution_unit_summary_containers AS modules
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
pub(super) const OPEN_INVENTORY: &str = concat!(
    include_str!("rust_crate_point_targets.sql"),
    include_str!("rust_crate_point_inventory.sql"),
);
pub(super) const UNINDEXED_SCOPE: &str = concat!(
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
 CROSS JOIN main.rust_resolution_unit_summary_placements AS included
  INDEXED BY rust_resolution_unit_summary_placements_member
  ON included.summary_id=unit.summary_id
 AND included.member_ordinal=included_member.member_ordinal
 AND included.source_kind='include'
 CROSS JOIN main.rust_resolution_unit_summary_placements AS host
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
pub(in crate::analyzer::store) const MACRO_WALK_ANCESTRY: &str = r#"WITH RECURSIVE climb(summary_id, child, parent, position) AS (
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
 CROSS JOIN main.rust_resolution_unit_summary_placements AS child
  INDEXED BY rust_resolution_unit_summary_placements_member
  ON child.summary_id=unit.summary_id
 AND child.member_ordinal=child_member.member_ordinal
 AND child.source_kind='declared'
 CROSS JOIN main.rust_resolution_unit_summary_placements AS parent
  ON parent.summary_id=child.summary_id
 AND parent.module_path=child.parent_module_path
 AND parent.source_kind='declared'
 CROSS JOIN main.resolution_unit_summary_members AS parent_member
  ON parent_member.summary_id=parent.summary_id
 AND parent_member.member_ordinal=parent.member_ordinal
 CROSS JOIN rust_module_routes AS route
  ON route.blob_id=parent_member.blob_id
 AND child.module_path=parent.module_path || '::' || route.module_name
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
 CROSS JOIN main.rust_resolution_unit_summary_placements AS included
  ON included.summary_id=unit.summary_id
 AND included.member_ordinal=included_member.member_ordinal
 AND included.source_kind='include'
 CROSS JOIN main.rust_resolution_unit_summary_placements AS host
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
 CROSS JOIN main.rust_resolution_unit_summary_placements AS parent
  INDEXED BY rust_resolution_unit_summary_placements_member
  ON parent.summary_id=parent_member.summary_id
 AND parent.member_ordinal=parent_member.member_ordinal
 AND parent.source_kind='declared'
 CROSS JOIN main.rust_resolution_unit_summary_placements AS child
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
 CROSS JOIN main.rust_resolution_unit_summary_placements AS host
  INDEXED BY rust_resolution_unit_summary_placements_member
  ON host.summary_id=unit.summary_id AND host.member_ordinal=host_member.member_ordinal
 CROSS JOIN main.rust_resolution_unit_summary_placements AS included
  ON included.summary_id=host.summary_id AND included.module_path=host.module_path
 AND included.source_kind='include'
 CROSS JOIN main.resolution_unit_summary_members AS included_member
  ON included_member.summary_id=included.summary_id
 AND included_member.member_ordinal=included.member_ordinal
 WHERE host_mount.storage_language='rust'
  AND host_mount.persisted_relative_path=?1
  AND included_member.rel_path LIKE '%' || ?2"#;
/// Every byte at which `?1` includes a file the selection carries.
pub(in crate::analyzer::store) const MACRO_INCLUDE_STARTS: &str = r#"SELECT DISTINCT edge.include_start, included_member.rel_path, included_member.blob_id
 FROM temp.selected_resolution_mounts AS host_mount
 CROSS JOIN main.resolution_unit_summary_members AS host_member
  INDEXED BY resolution_unit_summary_members_blob
  ON host_member.blob_id=host_mount.blob_id
 AND host_member.rel_path=host_mount.persisted_relative_path
 CROSS JOIN selected_rust_unit_summaries AS unit
  ON unit.summary_id=host_member.summary_id
 CROSS JOIN main.rust_resolution_unit_summary_placements AS host
  INDEXED BY rust_resolution_unit_summary_placements_member
  ON host.summary_id=unit.summary_id AND host.member_ordinal=host_member.member_ordinal
 CROSS JOIN rust_include_edges AS edge ON edge.blob_id=host_member.blob_id
 CROSS JOIN main.rust_resolution_unit_summary_placements AS included
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
const DETACHED_SCOPE_CRATES: &str = "SELECT COUNT(*) FROM selected_rust_unit_summaries AS unit
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
const CLOSURE_SCOPE_MOUNTS_HEAD: &str =
    "INSERT OR IGNORE INTO temp.selected_resolution_scope_mounts(mount_ordinal)
 SELECT DISTINCT mount.mount_ordinal
 FROM selected_rust_unit_closure AS closure
 CROSS JOIN selected_rust_unit_members AS member ON member.summary_id=closure.summary_id
 CROSS JOIN temp.selected_resolution_mounts AS mount
  ON mount.storage_language='rust' AND mount.persisted_relative_path=member.rel_path
 WHERE closure.root_unit_key IN ";
const CLOSURE_SCOPE_MOUNTS_TAIL: &str = "";
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

#[cfg(test)]
thread_local! {
    static CONTEXT_BRIDGE_PEAK: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Start counting the bridges the contexts built on this thread carry.
#[cfg(test)]
pub(crate) fn reset_rust_context_bridge_peak_for_test() {
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
#[cfg(test)]
pub(crate) fn rust_context_bridge_peak_for_test() -> usize {
    CONTEXT_BRIDGE_PEAK.with(std::cell::Cell::get)
}

pub(super) struct Module {
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

    pub(crate) fn rust_crate_keys_for_file(
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
    pub(crate) fn rust_context_for_file(
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
    pub(crate) fn with_rust_forward_crate_scope<T>(
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
    pub(crate) fn rust_crate_keys_for_files<'path>(
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
    #[cfg(test)]
    pub(crate) fn rust_context_for_all_crates(
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
    #[cfg(test)]
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
    pub(crate) fn rust_crate_member_paths(
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
    pub(crate) fn rust_context_for_crate_files(
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
        #[cfg(test)]
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
                    let exports = rows.crate_exports(
                        module,
                        target_topology,
                        &path,
                        namespace(demand.namespace()),
                        &name,
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
                                    &module.overlay_completion,
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
                            &module.overlay_completion,
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
                        starts.extend(route_prefix_module_starts(
                            conn,
                            module,
                            name,
                            prefix_import_scope,
                        )?);
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
                && super::rust_prefix::rust_prefix_left_the_workspace(resolved);
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
    if let Some(prefix) = prefix {
        SelectedRootBridgeDescriptor::from_selected_path_tokens_with_prefix(
            fragment,
            Language::Rust,
            token,
            anchor,
            anchor_semantic,
            fragment,
            Language::Rust,
            token,
            prefix,
            route.to_vec(),
            demand.clone(),
            demand.clone(),
            completion,
        )
    } else {
        SelectedRootBridgeDescriptor::from_selected_path_tokens(
            fragment,
            Language::Rust,
            token,
            anchor,
            anchor_semantic,
            fragment,
            Language::Rust,
            token,
            route.to_vec(),
            demand.clone(),
            demand.clone(),
            completion,
        )
    }
}

pub(super) fn inventory_reason(identities: &SelectedContextIdentities, detail: &str) -> SemanticId {
    let mut digest = CanonicalHasher::new(b"bifrost-rust-unsupported-macro-module:v1");
    digest.field("detail", detail.as_bytes());
    identities.semantic(digest.finish())
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
 CROSS JOIN main.rust_resolution_unit_summary_dependency_names AS name
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
    if !has_targets && spelling.is_some_and(|spelling| PRIMITIVE_TYPES.contains(&spelling)) {
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
            0,
        ),
        (
            "rust_unit_summary_cargo_routes",
            super::super::rust_unit_summaries::CARGO_ROUTE_ROWS_SQL,
            0,
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
        ("rust_point_dependency", DEPENDENCY.as_str(), 2),
        ("rust_point_dependency_boundary", DEPENDENCY_BOUNDARY, 1),
        ("rust_point_parent", PARENT, 2),
        ("rust_point_container_declaration", CONTAINER_DECLARATION, 2),
        ("rust_point_export", EXPORT, 6),
        ("rust_point_anchored_import_binds", ANCHORED_IMPORT_BINDS, 2),
        ("rust_point_root_reexport", ROOT_REEXPORT, 6),
        ("rust_point_module_prefix_route", MODULE_PREFIX_ROUTE, 6),
        (
            "rust_point_module_import_prefix_starts",
            IMPORT_MODULE_PREFIX_STARTS,
            7,
        ),
        (
            "rust_point_module_import_prefix_route",
            IMPORT_MODULE_PREFIX_ROUTE,
            6,
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
            7,
        ),
        (
            "rust_point_trait_impls_visible_at",
            super::rust_crate_rows::TRAIT_IMPLS_VISIBLE_AT,
            7,
        ),
        (
            "rust_point_trait_impl_member_at",
            super::rust_crate_rows::TRAIT_IMPL_MEMBER_AT,
            8,
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
            2,
        ),
        (
            "rust_point_store_trait_impl_rows",
            super::super::RUST_TRAIT_IMPL_ROWS_SQL.as_str(),
            3,
        ),
        (
            "rust_point_store_traits_of_impl",
            super::super::RUST_TRAITS_OF_IMPL_SQL.as_str(),
            3,
        ),
        (
            "rust_point_store_trait_impl_spellings",
            super::super::RUST_TRAIT_IMPL_SPELLINGS_SQL.as_str(),
            3,
        ),
        (
            "rust_point_store_traits_implemented_by",
            super::super::RUST_TRAITS_IMPLEMENTED_BY_SQL.as_str(),
            3,
        ),
        (
            "rust_point_store_types_implementing",
            super::super::RUST_TYPES_IMPLEMENTING_SQL.as_str(),
            3,
        ),
        (
            "rust_point_reference_names_macro_module",
            super::rust_crate_rows::REFERENCE_NAMES_MACRO_MODULE,
            3,
        ),
        (
            "rust_point_reference_names_workspace_crate",
            super::rust_crate_rows::REFERENCE_NAMES_WORKSPACE_CRATE.as_str(),
            3,
        ),
        ("rust_point_import_inventory", IMPORT_INVENTORY, 1),
        ("rust_point_gap_details", GAP_DETAILS, 1),
        ("rust_point_open_inventory", OPEN_INVENTORY, 6),
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

#[cfg(test)]
mod tests {
    use super::{
        CLOSURE_SCOPE_MOUNTS_HEAD, CLOSURE_SCOPE_MOUNTS_TAIL, DETACHED_SCOPE_CRATES,
        SELECT_IMPORTED_MACRO_DEFINITION,
    };
    use crate::AnalyzerConfig;
    use crate::analyzer::store::planner_statistics::pinned_plans::{
        explain_pin, pinned, pinned_queries,
    };
    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use brokk_bifrost_test_macros::hardwon;
    use rusqlite::types::Value;

    /// External globs can bind any namespace, while a root macro-use import
    /// contributes to every macro lookup from its crate. Keep these checks in
    /// helper proof and keep ordinary point lookup inventory closed.
    #[test]
    #[hardwon("#4458: unindexed external imports left derive-helper proof falsely closed")]
    fn unindexed_helper_scope_does_not_open_point_inventory() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2024'\n[dependencies]\nunindexed='1'\n",
            )
            .file(
                "src/lib.rs",
                "#[macro_use] extern crate unindexed; pub mod inner { use unindexed::prelude::*; }",
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().expect("the fixture builds a store");
        let conn = store.conn.lock().expect("the fixture store lock");
        crate::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
        crate::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(&conn);
        crate::analyzer::store::rust_crates::register_point_export_functions(&conn).unwrap();
        conn.execute(
            "INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'",
            [],
        )
        .unwrap();
        crate::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        let (topology, blob): (i64, i64) = conn
            .query_row(
                "SELECT topology_id,blob_id FROM selected_rust_crate_containers WHERE container_path='crate' AND rel_path='src/lib.rs'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        conn.execute(
            "INSERT INTO selected_resolution_mounts(mount_ordinal,blob_id,storage_language,semantic_language,persisted_relative_path) VALUES(0,?1,'rust','rust','src/lib.rs')",
            [blob],
        )
        .unwrap();
        conn.execute_batch(crate::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL).unwrap();

        for (module, namespace, name, expected) in [
            (
                "crate::inner",
                "macro",
                "missing_macro",
                "UnindexedExternalGlobImport",
            ),
            (
                "crate",
                "macro",
                "missing_macro",
                "UnindexedExternalMacroUseImport",
            ),
        ] {
            let helper_scope_open = conn
                .prepare(super::UNINDEXED_SCOPE)
                .unwrap()
                .exists(rusqlite::params![
                    topology, module, namespace, name, topology, module
                ])
                .unwrap();
            assert!(helper_scope_open, "{module} {namespace} {name}: {expected}");
            if expected == "UnindexedExternalGlobImport" {
                let point_inventory = conn
                    .prepare(super::OPEN_INVENTORY)
                    .unwrap()
                    .query_map(
                        rusqlite::params![topology, module, namespace, name, topology, module],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert!(
                    point_inventory.is_empty(),
                    "an external glob stays an external boundary for ordinary name lookups: {point_inventory:?}"
                );
            }
        }
    }

    fn assert_rust_workspace_graph_builds(project: &BuiltInlineTestProject, failure: &str) {
        use crate::analyzer::rust::build_rust_native_workspace_graph_for_files;
        use crate::analyzer::{IAnalyzer, Language, RustAnalyzer};

        let analyzer = RustAnalyzer::from_project(project.project().clone());
        let files = analyzer
            .source_file_inventory()
            .rows
            .into_iter()
            .filter(|file| crate::analyzer::common::language_for_file(file) == Language::Rust)
            .collect::<Vec<_>>();
        if let Err(error) = build_rust_native_workspace_graph_for_files(
            &analyzer,
            &files,
            8,
            &crate::CancellationToken::new(),
        ) {
            panic!("{failure}: {error}");
        }
    }

    #[test]
    fn imported_macro_definition_matches_the_topology_reader() {
        let source = "use provider::chosen as renamed;\nuse provider::*;\nfn named() { renamed!(); }\nfn glob() { chosen!(); }\n";
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nprovider={path='provider'}\n",
            )
            .file("src/lib.rs", source)
            .file(
                "provider/Cargo.toml",
                "[package]\nname='provider'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file(
                "provider/src/lib.rs",
                "#[macro_export]\nmacro_rules! chosen { () => {} }\n",
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        crate::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
        crate::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(&conn);
        conn.execute(
            "INSERT INTO selected_workspace_revisions
             SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'",
            [],
        )
        .unwrap();
        crate::analyzer::store::fill_selected_rust_units(&conn).unwrap();

        const LEGACY: &str = r#"WITH candidates(rel_path, declaration_id, local_extent, is_glob) AS (
            SELECT DISTINCT target_source.rel_path, bridge.declaration_id,
                   COALESCE(source.local_end-source.local_start, 9223372036854775807), 0
            FROM rust_crate_container_sources AS owner
            CROSS JOIN selected_rust_crates AS selected
              ON selected.topology_id=owner.topology_id
            CROSS JOIN rust_crate_imports AS import
              ON import.topology_id=owner.topology_id
             AND import.module_path=owner.container_path
             AND import.blob_id=owner.blob_id
            CROSS JOIN source_rust_import_targets AS source
              ON source.blob_id=import.blob_id
             AND source.ordinal=import.import_ordinal
             AND source.native_scope=import.binder_scope
            CROSS JOIN selected_rust_crates AS target
              ON target.crate_key=import.target_crate_key
            CROSS JOIN rust_crate_exports AS export
              ON export.topology_id=target.topology_id
             AND export.module_path=import.target_module_path
             AND export.namespace='macro'
             AND export.name=import.target_name
            CROSS JOIN source_native_declaration_bridges AS bridge
              ON bridge.blob_id=export.declaration_blob_id
             AND bridge.source_site=export.declaration_site
            CROSS JOIN rust_crate_container_sources AS target_source
              ON target_source.topology_id=export.topology_id
             AND target_source.blob_id=export.declaration_blob_id
            WHERE owner.rel_path=?1 AND import.namespace='macro'
              AND import.bound_name=?3
              AND source.owner_start<=?2 AND ?2<source.owner_end
              AND (source.local_start IS NULL
                   OR (source.local_start<=?2 AND ?2<source.local_end))
            UNION ALL
            SELECT DISTINCT target_source.rel_path, bridge.declaration_id,
                   COALESCE(source.local_end-source.local_start, 9223372036854775807), 1
            FROM rust_crate_container_sources AS owner
            CROSS JOIN selected_rust_crates AS selected
              ON selected.topology_id=owner.topology_id
            CROSS JOIN rust_crate_glob_imports AS import
              ON import.topology_id=owner.topology_id
             AND import.module_path=owner.container_path
             AND import.blob_id=owner.blob_id
            CROSS JOIN source_rust_import_targets AS source
              ON source.blob_id=import.blob_id
             AND source.ordinal=import.import_ordinal
             AND source.native_scope=import.binder_scope
            CROSS JOIN selected_rust_crates AS target
              ON target.crate_key=import.target_crate_key
            CROSS JOIN rust_crate_exports AS export
              ON export.topology_id=target.topology_id
             AND export.module_path=import.target_module_path
             AND export.namespace='macro' AND export.name=?3
            CROSS JOIN source_native_declaration_bridges AS bridge
              ON bridge.blob_id=export.declaration_blob_id
             AND bridge.source_site=export.declaration_site
            CROSS JOIN rust_crate_container_sources AS target_source
              ON target_source.topology_id=export.topology_id
             AND target_source.blob_id=export.declaration_blob_id
            WHERE owner.rel_path=?1
              AND source.owner_start<=?2 AND ?2<source.owner_end
              AND (source.local_start IS NULL
                   OR (source.local_start<=?2 AND ?2<source.local_end))
        )
        SELECT rel_path, declaration_id, local_extent, is_glob
        FROM candidates ORDER BY local_extent, is_glob, rel_path, declaration_id"#;

        for (name, is_glob) in [("renamed", false), ("chosen", true)] {
            let position = source.find(&format!("{name}!")).expect("macro invocation") as i64;
            let params = rusqlite::params!["src/lib.rs", position, name];
            let legacy = conn
                .prepare(LEGACY)
                .unwrap()
                .query_map(params, |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, bool>(3)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let summary = conn
                .prepare(SELECT_IMPORTED_MACRO_DEFINITION)
                .unwrap()
                .query_map(params, |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, bool>(3)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(summary, legacy, "macro={name:?}");
            assert!(
                summary.iter().any(|row| row.3 == is_glob),
                "macro={name:?} expected glob={is_glob}; rows={summary:?}"
            );
        }
    }

    /// The three answers a file no Cargo target mounts must give, and the one
    /// workspace shape that is not that case.
    ///
    /// `extra/orphan.rs` is in the workspace and in no Cargo target of it, so
    /// the derivation gives it its own `detached` topology whose `crate` root
    /// holds only that file. `crate::helpers::helper()` out of it used to walk
    /// that synthetic root, find nothing, and answer a decided negative, while
    /// the whole-workspace projection called itself complete and the dead-code
    /// report published "dead, 0 usages" for every declaration in the file.
    #[test]
    #[hardwon("fef6e65216dc: a detached file under no Cargo target is incomplete, not absent")]
    fn a_file_under_no_cargo_target_answers_incomplete_and_stops_the_projection() {
        use crate::analyzer::rust::{
            RustNativeWorkspaceGraphOutcome, build_rust_native_workspace_graph_for_files,
        };
        use crate::analyzer::usages::get_definition::{
            DefinitionLookupRequest, DefinitionLookupStatus,
            trace::resolve_definition_batch_with_trace,
        };
        use crate::analyzer::{IAnalyzer, Language, RustAnalyzer};

        const ORPHAN: &str = "fn caller_one() { crate::helpers::helper(); }";
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", "pub mod helpers;")
            .file("src/helpers.rs", "pub fn helper() {}")
            .file("extra/orphan.rs", ORPHAN)
            .build();
        let analyzer = RustAnalyzer::from_project(project.project().clone());

        let file = project.file("extra/orphan.rs");
        let start = ORPHAN.find("helper()").expect("call site");
        let outcome = resolve_definition_batch_with_trace(
            &analyzer,
            vec![DefinitionLookupRequest {
                file: file.clone(),
                line: None,
                column: None,
                start_byte: Some(start),
                end_byte: Some(start + "helper".len()),
            }],
            file,
            std::sync::Arc::<str>::from(ORPHAN),
            &crate::CancellationToken::new(),
        );
        let answer = &outcome[0].0;
        assert_eq!(
            answer.status,
            DefinitionLookupStatus::Incomplete,
            "a crate-rooted route out of an unmounted file is not a proved absence: {answer:?}"
        );
        assert!(
            answer
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("unmounted_file(")),
            "the incompleteness must name the file it is about: {answer:?}"
        );

        let files = analyzer
            .source_file_inventory()
            .rows
            .into_iter()
            .filter(|file| crate::analyzer::common::language_for_file(file) == Language::Rust)
            .collect::<Vec<_>>();
        let projection = build_rust_native_workspace_graph_for_files(
            &analyzer,
            &files,
            8,
            &crate::CancellationToken::new(),
        )
        .expect("projection");
        assert!(
            matches!(projection, RustNativeWorkspaceGraphOutcome::Incomplete(_)),
            "a whole-workspace projection that admits an unmounted file cannot be complete"
        );

        // The same workspace with the file taken out: the incompleteness above
        // is the orphan's and not this fixture's.
        let mounted = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", "pub mod helpers;")
            .file("src/helpers.rs", "pub fn helper() {}")
            .build();
        let mounted_analyzer = RustAnalyzer::from_project(mounted.project().clone());
        let mounted_files = mounted_analyzer
            .source_file_inventory()
            .rows
            .into_iter()
            .filter(|file| crate::analyzer::common::language_for_file(file) == Language::Rust)
            .collect::<Vec<_>>();
        assert!(
            matches!(
                build_rust_native_workspace_graph_for_files(
                    &mounted_analyzer,
                    &mounted_files,
                    8,
                    &crate::CancellationToken::new(),
                )
                .expect("projection"),
                RustNativeWorkspaceGraphOutcome::Complete(_)
            ),
            "the crate this workspace does declare still projects completely"
        );
    }

    /// The dead-code half of the case above. The projection is incomplete
    /// with `UnmountedFile`, but the bucket abstains per candidate spelled by
    /// an unresolved reference (lane UP, 2026-09-17), and the unresolved
    /// reference here is `helper`, not `caller_one`, so the orphan's own
    /// declaration is still reported dead. What closes it is the file itself
    /// on the projection's input-failure channel from a crate-rows read
    /// (plan open item: the declaration-only half of DC-A).
    #[test]
    #[ignore = "finds real bug: an unmounted file's own declarations are reported dead; the bucket abstains per unresolved name, not per unmounted file"]
    fn an_unmounted_files_own_declarations_are_not_reported_dead() {
        use crate::analyzer::RustAnalyzer;

        const ORPHAN: &str = "fn caller_one() { crate::helpers::helper(); }";
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", "pub mod helpers;")
            .file("src/helpers.rs", "pub fn helper() {}")
            .file("extra/orphan.rs", ORPHAN)
            .build();
        let analyzer = RustAnalyzer::from_project(project.project().clone());
        let report = crate::code_quality::report_dead_code_and_unused_abstraction_smells(
            &analyzer,
            crate::code_quality::ReportDeadCodeAndUnusedAbstractionSmellsParams {
                file_paths: vec!["extra/orphan.rs".to_owned()],
                ..Default::default()
            },
        )
        .report;
        assert!(
            report.contains("Skipped symbols"),
            "the dead-code bucket must abstain on an unmounted file's candidates: {report}"
        );
    }

    /// One import site answers once, however many times the crate being
    /// walked compiles the file it is written in.
    ///
    /// `src/shared.rs` is a module of `app/lib` and of `app/bin`, and a bin
    /// target depends on its own package's lib, so the bin crate's context
    /// reads two module rows for that one file. The two answer
    /// `use app::Thing;` differently by construction: from the bin's topology
    /// `app` names the lib, whose export inventory the unexpanded
    /// `generate!()` leaves open, and from the lib's own topology `app` names
    /// nothing at all, because a crate is not its own dependency. Each row
    /// used to push its own dead-end descriptor for the one candidate path
    /// that import site spells, so the selected context received two
    /// derivations of one path whose completions disagreed and rejected the
    /// publication. That is the store error Bifrost's own whole-workspace
    /// `usage_graph` raised.
    #[test]
    #[hardwon("77aab427cd16: one source import must not derive a duplicate dead end")]
    fn one_import_site_derives_one_dead_end_when_its_file_is_compiled_twice() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", "generate!();\npub mod shared;\n")
            .file(
                "src/main.rs",
                "mod shared;\nfn main() { shared::use_it(); }\n",
            )
            .file(
                "src/shared.rs",
                "use app::Thing;\npub fn use_it() { let _ = Thing; }\n",
            )
            .build();
        assert_rust_workspace_graph_builds(&project, "one import site must derive one dead end");
    }

    /// The same answer when the two placements are in one crate.
    ///
    /// Owner decision of 2026-09-22 keyed `duplicate_placement` on the module
    /// path, so a file reached from two `mod` declarations is now two modules
    /// of one topology instead of a gap, which is the shape Bifrost's own
    /// `test-support/inline_project.rs` has in several libraries. `MODULES` is
    /// keyed on the blob and the file, not on the topology, so those two
    /// placements arrive at the crate context exactly as two topologies do;
    /// this pins that they combine into one dead end rather than two. The bin
    /// target makes the completions disagree, which is what turns a duplicate
    /// publication into the store error: from the bin `app` names the lib with
    /// an open inventory, and from the lib `app` names nothing.
    #[test]
    #[hardwon("80645bcc16c2: module placement identity must not duplicate a file import")]
    fn two_placements_of_one_file_in_one_crate_derive_one_dead_end() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", "generate!();\npub mod alpha;\npub mod beta;\n")
            .file(
                "src/main.rs",
                "mod alpha;\nmod beta;\nfn main() { alpha::shared::use_it(); beta::shared::use_it(); }\n",
            )
            .file(
                "src/alpha.rs",
                "#[path = \"../test-support/shared.rs\"]\npub mod shared;\n",
            )
            .file(
                "src/beta.rs",
                "#[path = \"../test-support/shared.rs\"]\npub mod shared;\n",
            )
            .file(
                "test-support/shared.rs",
                "use app::Thing;\npub fn use_it() { let _ = Thing; }\n",
            )
            .build();
        assert_rust_workspace_graph_builds(
            &project,
            "two placements in one crate must derive one dead end",
        );
    }

    /// The scope of the reason above, which a reader must not widen by
    /// accident. A workspace that declares no Cargo target at all publishes one
    /// `detached` topology per Rust file by design; that is the model, not a
    /// gap, and the lexical route is what carries such a workspace. Making
    /// every file in it "unmounted" would turn the whole non-Cargo Rust surface
    /// into an abstention.
    #[test]
    #[hardwon("fef6e65216dc: Cargo-free workspaces remain answerable")]
    fn a_workspace_with_no_cargo_target_at_all_is_not_an_unmounted_file() {
        use crate::analyzer::RustAnalyzer;
        use crate::analyzer::usages::get_definition::{
            DefinitionLookupRequest, DefinitionLookupStatus,
            trace::resolve_definition_batch_with_trace,
        };

        const CALLER: &str = "fn caller_one() { crate::helpers::helper(); }";
        let project = InlineTestProject::new()
            .file("helpers.rs", "pub fn helper() {}")
            .file("callers.rs", CALLER)
            .build();
        let analyzer = RustAnalyzer::from_project(project.project().clone());
        let file = project.file("callers.rs");
        let start = CALLER.find("helper()").expect("call site");
        let outcome = resolve_definition_batch_with_trace(
            &analyzer,
            vec![DefinitionLookupRequest {
                file: file.clone(),
                line: None,
                column: None,
                start_byte: Some(start),
                end_byte: Some(start + "helper".len()),
            }],
            file,
            std::sync::Arc::<str>::from(CALLER),
            &crate::CancellationToken::new(),
        );
        let answer = &outcome[0].0;
        assert!(
            !answer
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("unmounted_file(")),
            "no Cargo target exists to leave this file out of: {answer:?}"
        );
        assert_ne!(
            answer.status,
            DefinitionLookupStatus::Incomplete,
            "{answer:?}"
        );
    }

    /// Resolve the member of a Rust type-qualified path or of a method call on
    /// a receiver, at the analyzer boundary, and say which definitions it
    /// named. The member is the path's last segment after `::` or `.`.
    #[cfg(test)]
    fn qualified_member_definitions(
        files: &[(&str, &str)],
        caret_file: &str,
        path: &str,
    ) -> (
        crate::analyzer::usages::get_definition::DefinitionLookupStatus,
        Vec<String>,
    ) {
        let outcome = qualified_member_outcome(files, caret_file, path);
        let names = outcome
            .definitions
            .iter()
            .map(|unit| unit.short_name().to_owned())
            .collect();
        (outcome.status, names)
    }

    /// The whole definition outcome [`qualified_member_definitions`] reads.
    #[cfg(test)]
    fn qualified_member_outcome(
        files: &[(&str, &str)],
        caret_file: &str,
        path: &str,
    ) -> crate::analyzer::usages::get_definition::DefinitionLookupOutcome {
        use crate::analyzer::usages::get_definition::{
            DefinitionLookupRequest, resolve_definition_batch_with_source,
        };
        let mut project = InlineTestProject::new();
        for (name, contents) in files {
            project = project.file(*name, *contents);
        }
        let project = project.build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let source = files
            .iter()
            .find(|(name, _)| *name == caret_file)
            .map(|(_, contents)| *contents)
            .expect("caret file");
        let member = path
            .rsplit(['.', ':'])
            .next()
            .expect("a qualified path has a member");
        let at = source.find(path).expect("the fixture spells the path")
            + path.rfind(member).expect("member position");
        let file = project.file(caret_file);
        resolve_definition_batch_with_source(
            workspace.analyzer(),
            vec![DefinitionLookupRequest {
                file: file.clone(),
                line: None,
                column: None,
                start_byte: Some(at),
                end_byte: Some(at + member.len()),
            }],
            file,
            std::sync::Arc::<str>::from(source),
        )
        .into_iter()
        .next()
        .expect("one request has one outcome")
    }

    /// The join's read is bounded by the subject, not by the crate's impls.
    ///
    /// The plan pin above proves the statement seeks
    /// `rust_crate_trait_impls_subject` on both subject columns. This proves
    /// what that buys: growing the crate from two trait implementations to
    /// forty-one leaves the request reading the same one row, and leaves the
    /// answer unchanged. One statement per qualifier value, and its rows are
    /// the subject's traits.
    #[test]
    fn the_trait_impl_join_reads_one_subject_however_many_impls_the_crate_holds() {
        use crate::analyzer::usages::get_definition::DefinitionLookupStatus;

        let mut rows = Vec::new();
        for unrelated in [1usize, 40] {
            let mut source = String::from(
                "struct Foo;\ntrait Trait {\n    fn frobnicate();\n}\nimpl Trait for Foo {}\n",
            );
            for ordinal in 0..unrelated {
                source.push_str(&format!(
                    "struct Other{ordinal};\nimpl Trait for Other{ordinal} {{}}\n"
                ));
            }
            source.push_str("\nfn bar() {\n    Foo::frobnicate();\n}\n");
            let project = InlineTestProject::new().file("t.rs", &source).build();
            let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().expect("the fixture builds a store");
            let conn = store.conn.lock().expect("the fixture store lock");
            crate::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
            crate::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(&conn);
            conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
            crate::analyzer::store::fill_selected_rust_units(&conn).unwrap();
            let (blob, site): (i64, i64) = conn
                .query_row(
                    "SELECT declaration_blob_id,declaration_site FROM rust_crate_exports WHERE namespace='type' AND name='Foo' AND origin='declaration'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("the subject has an export row");
            let topology: i64 = conn
                .query_row("SELECT topology_id FROM selected_rust_crates", [], |row| {
                    row.get(0)
                })
                .expect("one crate");
            let impls: i64 = conn
                .query_row("SELECT count(*) FROM rust_crate_trait_impls", [], |row| {
                    row.get(0)
                })
                .unwrap();
            conn.execute("INSERT INTO selected_resolution_mounts(mount_ordinal,blob_id,storage_language,semantic_language,persisted_relative_path) SELECT 0,?1,'rust','rust','t.rs'", [blob]).unwrap();
            conn.execute_batch(crate::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL).unwrap();
            let read: i64 = conn
                .query_row(
                    &format!(
                        "SELECT count(*) FROM ({})",
                        super::super::rust_crate_rows::TRAIT_IMPLS_VISIBLE_AT
                    ),
                    rusqlite::params![blob, site, topology, "crate", "t.rs", 0, 0],
                    |row| row.get(0),
                )
                .expect("the join reads its subject");
            drop(conn);
            let answer = super::tests::qualified_member_definitions(
                &[("t.rs", source.as_str())],
                "t.rs",
                "Foo::frobnicate",
            );
            rows.push((unrelated, impls, read, answer));
        }
        eprintln!("trait-impl join reads (unrelated impls, table rows, rows read): {rows:?}");
        assert_eq!(
            (rows[0].1, rows[1].1),
            (2, 41),
            "the fixture must really grow the crate's impls: {rows:?}"
        );
        assert_eq!(
            rows[0].2, rows[1].2,
            "the join must read one subject's traits whatever else the crate implements: {rows:?}"
        );
        assert_eq!(rows[0].2, 1, "the subject implements one trait: {rows:?}");
        for (unrelated, _, _, answer) in &rows {
            assert_eq!(
                answer,
                &(
                    DefinitionLookupStatus::Resolved,
                    vec!["Trait.frobnicate".to_owned()]
                ),
                "the answer must not move with {unrelated} unrelated impls"
            );
        }
    }

    /// A method nothing indexed supplies is an open boundary, never a proved
    /// absence, in both call forms.
    ///
    /// A blanket `impl<T: Bound> Runner for T {}` leaves no crate row at all:
    /// `spelled_impl_header_path` has no nominal path for a type-parameter
    /// subject, so the lowering writes no `resolution_trait_implementations`
    /// row, and derivation writes neither a `rust_crate_trait_impls` row nor a
    /// `rust_crate_unresolved_trait_impls` row for it. A derive, a `Deref`
    /// target and a default method of a trait from an unindexed crate are the
    /// same shape. The producer declares the member surface open for every
    /// qualified reference, and the answer is the boundary that declaration
    /// permits, as for `Host::ITEM`.
    #[test]
    fn a_method_the_indexed_rows_cannot_supply_is_an_open_boundary() {
        use crate::analyzer::usages::get_definition::DefinitionLookupStatus;

        let fixtures = [
            (
                "blanket receiver",
                "trait Bound {}\ntrait Runner {\n    fn run(&self) {}\n}\nimpl<T: Bound> Runner for T {}\nstruct Service;\nimpl Bound for Service {}\n\nfn caller(service: Service) {\n    service.run();\n}\n",
                "service.run",
            ),
            (
                "blanket where-clause",
                "trait Bound {}\ntrait Runner {\n    fn run(&self) {}\n}\nimpl<T> Runner for T where T: Bound {}\nstruct Service;\nimpl Bound for Service {}\n\nfn caller(service: Service) {\n    service.run();\n}\n",
                "service.run",
            ),
            (
                "blanket type-qualified",
                "trait Bound {}\ntrait Runner {\n    fn run(&self) {}\n}\nimpl<T: Bound> Runner for T {}\nstruct Service;\nimpl Bound for Service {}\n\nfn caller(service: Service) {\n    Service::run(&service);\n}\n",
                "Service::run",
            ),
            (
                "derive",
                "#[derive(Clone)]\nstruct Service;\n\nfn caller(service: Service) {\n    service.clone();\n}\n",
                "service.clone",
            ),
            (
                "deref target",
                "struct Inner;\nimpl Inner {\n    fn run(&self) {}\n}\nstruct Service {\n    inner: Inner,\n}\nimpl std::ops::Deref for Service {\n    type Target = Inner;\n    fn deref(&self) -> &Inner {\n        &self.inner\n    }\n}\n\nfn caller(service: Service) {\n    service.run();\n}\n",
                "service.run",
            ),
            (
                "unindexed trait default",
                "use std::fmt::Write;\nstruct Service;\nimpl Write for Service {\n    fn write_str(&mut self, _: &str) -> std::fmt::Result {\n        Ok(())\n    }\n}\n\nfn caller(mut service: Service) {\n    service.write_char('a');\n}\n",
                "service.write_char",
            ),
        ];
        for (label, source, path) in fixtures {
            let outcome = qualified_member_outcome(&[("t.rs", source)], "t.rs", path);
            assert_eq!(
                (outcome.status, outcome.definitions.len()),
                (DefinitionLookupStatus::UnresolvableImportBoundary, 0),
                "{label}: {outcome:?}"
            );
        }
    }

    /// The reverse half: the impl item and the other trait's default each see
    /// the tied call as a usage they cannot prove.
    #[test]
    fn an_impl_item_tie_is_an_unproven_usage_of_each_candidate() {
        const TIED: &str = "struct Service;\ntrait One {\n    fn run(&self);\n}\ntrait Two {\n    fn run(&self) {}\n}\nimpl One for Service {\n    fn run(&self) {}\n}\nimpl Two for Service {}\n\nfn caller(service: Service) {\n    service.run();\n}\n";
        for (line, symbol) in [(9, "Service.run"), (6, "Two.run")] {
            assert_one_unproven_usage(&scan_usages_at(TIED, line), symbol, 14);
        }
    }

    /// Scan the usages of the declaration at one line of a one-file fixture.
    #[cfg(test)]
    fn scan_usages_at(source: &str, line: usize) -> crate::searchtools::ScanUsagesResult {
        use crate::searchtools::{
            ScanUsagesByLocationParams, ScanUsagesTarget, scan_usages_by_location,
        };
        let project = InlineTestProject::new().file("t.rs", source).build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        scan_usages_by_location(
            workspace.analyzer(),
            ScanUsagesByLocationParams {
                targets: vec![ScanUsagesTarget {
                    path: "t.rs".to_owned(),
                    line,
                    column: None,
                    symbol: None,
                }],
                include_tests: true,
                paths: None,
                include_same_owner: true,
            },
        )
    }

    /// The call as an unproven usage of `symbol`: not a proven usage, and not
    /// a verified absence.
    #[cfg(test)]
    fn assert_one_unproven_usage(
        result: &crate::searchtools::ScanUsagesResult,
        symbol: &str,
        call_line: usize,
    ) {
        assert_eq!(result.results.len(), 1, "{symbol}: {result:#?}");
        let entry = &result.results[0];
        assert_eq!(entry.symbol.as_deref(), Some(symbol), "{result:#?}");
        assert_eq!(
            (
                entry.status,
                entry.total_hits,
                entry.unproven_hits,
                entry
                    .unproven_files
                    .iter()
                    .flat_map(|file| file.hits.iter().map(|hit| hit.line))
                    .collect::<Vec<_>>(),
            ),
            (
                crate::searchtools::ScanUsagesStatus::UnverifiedAbsent,
                Some(0),
                Some(1),
                vec![call_line],
            ),
            "{symbol}: the call is an unproven usage: {entry:#?}"
        );
    }

    /// The reverse half of the E0034 test above: each of the two tied trait
    /// methods sees the call as a usage it cannot prove, never as a proven
    /// one, because the call binds neither.
    #[test]
    fn a_tied_method_call_is_an_unproven_usage_of_each_trait_method() {
        const TIED: &str = "struct Service;\ntrait One {\n    fn run(&self) {}\n}\ntrait Two {\n    fn run(&self) {}\n}\nimpl One for Service {}\nimpl Two for Service {}\n\nfn caller(service: Service) {\n    service.run();\n}\n";
        for (line, symbol) in [(3, "One.run"), (6, "Two.run")] {
            assert_one_unproven_usage(&scan_usages_at(TIED, line), symbol, 12);
        }
    }

    /// The reverse half of the open-boundary test: a trait default's usages are
    /// not a verified absence while a blanket impl may lend the default to the
    /// receiver of a call that names it.
    #[test]
    fn a_blanket_impl_call_is_an_unproven_usage_of_the_trait_default() {
        const BLANKET: &str = "trait Bound {}\ntrait Runner {\n    fn run(&self) {}\n}\nimpl<T: Bound> Runner for T {}\nstruct Service;\nimpl Bound for Service {}\n\nfn caller(service: Service) {\n    service.run();\n}\n";
        assert_one_unproven_usage(&scan_usages_at(BLANKET, 3), "Runner.run", 10);
    }

    /// The receiver form of the test above: a trait default method's usages
    /// reach a method call on a value whose type implements the trait with an
    /// empty impl body. The forward answer is the typed member route's, and a
    /// reverse scan confirms each candidate with that same forward answer.
    #[test]
    fn a_trait_default_methods_usages_reach_the_receiver_call_site() {
        use crate::searchtools::{
            ScanUsagesByLocationParams, ScanUsagesTarget, scan_usages_by_location,
        };
        const ONE: &str = "struct Foo;\ntrait Trait {\n    fn frobnicate(&self) {}\n}\nimpl Trait for Foo {}\n\nfn bar(foo: Foo) {\n    foo.frobnicate();\n}\n";
        let project = InlineTestProject::new().file("t.rs", ONE).build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let result = scan_usages_by_location(
            workspace.analyzer(),
            ScanUsagesByLocationParams {
                targets: vec![ScanUsagesTarget {
                    path: "t.rs".to_owned(),
                    line: 3,
                    column: None,
                    symbol: None,
                }],
                include_tests: true,
                paths: None,
                include_same_owner: true,
            },
        );
        assert_eq!(result.summary.found, 1, "{result:#?}");
        let entry = &result.results[0];
        assert_eq!(entry.symbol.as_deref(), Some("Trait.frobnicate"));
        assert!(entry.complete, "{entry:#?}");
        assert_eq!(entry.total_hits, Some(1), "{entry:#?}");
        let hits = &entry.files[0].hits;
        assert_eq!(
            (entry.files[0].path.as_str(), hits[0].line),
            ("t.rs", 8),
            "the trait default's one usage is the receiver call: {entry:#?}"
        );
    }

    #[test]
    fn rust_supertrait_callable_reverse_reaches_trait_body_self() {
        let source = "trait Base {\n    fn base();\n}\ntrait Mid: Base {}\ntrait Sub: Mid {\n    fn caller() { Self::base(); }\n}\n";
        let result = scan_usages_at(source, 2);
        assert_eq!(result.summary.found, 1, "{result:#?}");
        let entry = &result.results[0];
        assert_eq!(entry.symbol.as_deref(), Some("Base.base"));
        assert_eq!(entry.total_hits, Some(1), "{entry:#?}");
        let lines = entry
            .files
            .iter()
            .flat_map(|file| file.hits.iter().map(|hit| hit.line))
            .collect::<Vec<_>>();
        assert_eq!(lines, [6], "{entry:#?}");
    }

    #[test]
    fn rust_supertrait_callable_reverse_reaches_generic_receiver() {
        let source = "trait Base {\n    fn base(&self);\n}\ntrait Mid: Base {}\ntrait Sub: Mid {}\nfn caller<T: Sub>(value: T) {\n    value.base();\n}\n";
        let result = scan_usages_at(source, 2);
        assert_eq!(result.summary.found, 1, "{result:#?}");
        let entry = &result.results[0];
        assert_eq!(entry.symbol.as_deref(), Some("Base.base"));
        assert_eq!(entry.total_hits, Some(1), "{entry:#?}");
        let lines = entry
            .files
            .iter()
            .flat_map(|file| file.hits.iter().map(|hit| hit.line))
            .collect::<Vec<_>>();
        assert_eq!(lines, [7], "{entry:#?}");
    }

    #[test]
    #[hardwon("#2767: an extern alias in an included member keeps its crate-root route")]
    fn crate_point_root_extern_alias_is_visible_in_include_member() {
        let project = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname='demo'\nversion='0.1.0'\nedition='2024'\n[dependencies]\ndep={path='dep'}\n")
            .file("src/lib.rs", "extern crate dep as tk; mod host { include!(\"generated.rs\"); }")
            .file("src/generated.rs", "fn generated() { tk::target(); }")
            .file("dep/Cargo.toml", "[package]\nname='dep'\nversion='0.1.0'\nedition='2024'\n")
            .file("dep/src/lib.rs", "pub fn target() {}")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
        crate::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        let topology: i64 = conn
            .query_row(
                "SELECT topology_id FROM selected_rust_crates WHERE crate_name='demo'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let aliases = conn.prepare("SELECT imported_name,bound_name,native_scope,is_extern_crate FROM source_rust_import_targets").unwrap().query_map([], |row| Ok((row.get::<_,Option<String>>(0)?,row.get::<_,Option<String>>(1)?,row.get::<_,Option<i64>>(2)?,row.get::<_,bool>(3)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        let targets = conn
            .prepare(super::DEPENDENCY.as_str())
            .unwrap()
            .query_map(rusqlite::params![topology, "tk"], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            targets.len(),
            1,
            "root extern alias must reach its dependency: {aliases:?}"
        );
        drop(conn);
        use crate::analyzer::usages::get_definition::{
            DefinitionLookupRequest, DefinitionLookupStatus,
            trace::resolve_definition_batch_with_trace,
        };
        let file = project.file("src/generated.rs");
        let source = "fn generated() { tk::target(); }";
        let start = source.find("target").unwrap();
        let request = DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(start),
            end_byte: Some(start + "target".len()),
        };
        let result = resolve_definition_batch_with_trace(
            analyzer.analyzer(),
            vec![request],
            file,
            std::sync::Arc::<str>::from(source),
            &crate::CancellationToken::new(),
        );
        assert_eq!(
            result[0].0.status,
            DefinitionLookupStatus::Resolved,
            "{:?}",
            result[0].0
        );
    }

    /// The textual-macro climb reads a file's whole ancestry in one
    /// statement: the file that declares each module on the way to the crate
    /// root, with the byte of its `mod` item, and the host of an included
    /// file, with the byte of its `include!`. It used to ask one file at a
    /// time, twice (declarers and include hosts), and found each declaring
    /// container by scanning every container of the crate for the one whose
    /// path spelled the child's with one more segment; the recursion now seeks
    /// the declaring container's source rows on the child's recorded parent.
    /// Pinned on a populated store under both statistics states, with the
    /// answer each file gives.
    #[test]
    #[hardwon("53b66d27a224: macro ancestry reads were repeated for each reference")]
    fn macro_walk_ancestry_reads_every_parent_in_one_statement() {
        let lib = "macro_rules! shout { () => {} }\npub mod inner;\n";
        let inner = "pub mod deep;\npub mod host { include!(\"table.rs\"); }\n";
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='climb'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", lib)
            .file("src/inner.rs", inner)
            .file("src/inner/deep.rs", "pub fn g() {}\n")
            .file("src/table.rs", "pub fn t() {}\n")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        crate::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
        crate::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(&conn);
        conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
        crate::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        // The walk reads the selected mounts; stage each summary member's file as
        // one mount, the way a selected operation does.
        conn.execute("INSERT INTO selected_resolution_mounts(mount_ordinal,blob_id,storage_language,persisted_relative_path) SELECT row_number() OVER(),blob_id,'rust',rel_path FROM (SELECT DISTINCT member.blob_id,member.rel_path FROM selected_rust_unit_summaries AS units CROSS JOIN main.resolution_unit_summary_members AS member ON member.summary_id=units.summary_id)", []).unwrap();
        conn.execute_batch(crate::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL).unwrap();
        let parents: Vec<(String, String, Option<String>)> = conn
            .prepare("SELECT placement.module_path, member.rel_path, placement.parent_module_path
             FROM selected_rust_unit_summaries AS units
             CROSS JOIN main.rust_resolution_unit_summary_placements AS placement
              ON placement.summary_id=units.summary_id
             CROSS JOIN main.resolution_unit_summary_members AS member
              ON member.summary_id=placement.summary_id AND member.member_ordinal=placement.member_ordinal
             ORDER BY placement.module_path, member.rel_path")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let row = |container: &str, file: &str, parent: Option<&str>| {
            (
                container.to_owned(),
                file.to_owned(),
                parent.map(str::to_owned),
            )
        };
        assert_eq!(
            parents,
            [
                row("crate", "src/lib.rs", None),
                row("crate::inner", "src/inner.rs", Some("crate")),
                row(
                    "crate::inner::deep",
                    "src/inner/deep.rs",
                    Some("crate::inner")
                ),
                row("crate::inner::host", "src/inner.rs", Some("crate::inner")),
                row("crate::inner::host", "src/table.rs", Some("crate::inner")),
            ]
        );
        let declared = |source: &str, item: &str| source.find(item).unwrap() as i64;
        let edge = |child: &str, parent: &str, position: i64| {
            (child.to_owned(), parent.to_owned(), position)
        };
        let lib_inner = edge("src/inner.rs", "src/lib.rs", declared(lib, "pub mod inner"));
        let text = |value: &str| Value::Text(value.to_owned());
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            for (file, expected) in [
                ("src/lib.rs", vec![]),
                ("src/inner.rs", vec![lib_inner.clone()]),
                (
                    "src/inner/deep.rs",
                    vec![
                        lib_inner.clone(),
                        edge("src/inner/deep.rs", "src/inner.rs", 0),
                    ],
                ),
                (
                    "src/table.rs",
                    vec![
                        lib_inner.clone(),
                        edge("src/table.rs", "src/inner.rs", declared(inner, "include!")),
                    ],
                ),
            ] {
                let requested = serde_json::json!([file]).to_string();
                let mut answer = conn
                    .prepare_cached(super::MACRO_WALK_ANCESTRY)
                    .unwrap()
                    .query_map([&requested], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                answer.sort();
                assert_eq!(answer, expected, "{state:?} {file}");
                // Two files at once answer the union of their ancestries.
                let pair = serde_json::json!([file, "src/table.rs"]).to_string();
                let both = conn
                    .prepare_cached(super::MACRO_WALK_ANCESTRY)
                    .unwrap()
                    .query_map([&pair], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()
                    .unwrap();
                let union = expected
                    .iter()
                    .cloned()
                    .chain([
                        lib_inner.clone(),
                        edge("src/table.rs", "src/inner.rs", declared(inner, "include!")),
                    ])
                    .collect::<std::collections::BTreeSet<_>>();
                assert_eq!(both, union, "{state:?} {file} with src/table.rs");
                let mut pin = pinned_queries()
                    .into_iter()
                    .find(|pin| pin.name == "rust_macro_walk_ancestry")
                    .expect("the climb is a registered pin");
                pin.params = vec![text(&requested)];
                let plan = explain_pin(&conn, &pin);
                assert!(
                    // The summary walk seeks the declaring container by its summary
                    // and module path (the legacy reader sought topology and container).
                    plan.iter().any(|step| step.contains(
                        "SEARCH parent USING PRIMARY KEY (summary_id=? AND module_path=?)"
                    )),
                    "{state:?} {file}: the declaring container is not sought: {plan:?}"
                );
                // The recursion scans only its requested files and its own
                // queue.
                assert!(
                    !plan.iter().any(|step| (step.contains("SCAN")
                        && !step.starts_with("SCAN requested")
                        && step != "SCAN climb")
                        || step.contains("AUTOMATIC")),
                    "{state:?} {file}: {plan:?}"
                );
            }
        }
    }

    #[test]
    fn point_target_walk_closes_long_cycles_without_revisiting_each_depth() {
        // Each module re-exports the next. All 70 are reachable, including
        // those beyond the former depth cap; the last closes the cycle.
        let source = (0..70)
            .map(|index| {
                format!(
                    "pub mod m{index} {{ pub use crate::m{}::*; }}\n",
                    (index + 1) % 70
                )
            })
            .collect::<String>();
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='cycle'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", &source)
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        crate::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
        crate::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(&conn);
        conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
        crate::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        let topology: i64 = conn
            .query_row(
                "SELECT topology_id FROM selected_rust_crates WHERE crate_name='cycle'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let sql = concat!(
            include_str!("rust_crate_point_targets.sql"),
            " SELECT module_path FROM targets"
        );
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let modules = conn
                .prepare(sql)
                .unwrap()
                .query_map(
                    rusqlite::params![
                        topology,
                        "crate::m0",
                        "type",
                        "Absent",
                        topology,
                        "crate::m0"
                    ],
                    |row| row.get::<_, String>(0),
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let distinct = modules
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            let expected = (0..70)
                .map(|index| format!("crate::m{index}"))
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                distinct, expected,
                "{state:?}: every reachable module contributes inventory"
            );
            assert!(
                modules.len() <= 71,
                "{state:?}: cycle repeats targets: {modules:?}"
            );
        }
    }

    #[test]
    fn rust_crate_point_queries_have_populated_plan_pins() {
        let project = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname='point'\nversion='0.1.0'\nedition='2021'\n")
            .file("src/lib.rs", "mod inner; use inner::Thing as Alias; use inner::*; pub fn make() -> Alias { Alias }")
            .file("src/inner.rs", "pub struct Thing; pub struct Other;")
            .file("src/edited.rs", "mod inner; use inner::Other as Renamed; use inner::*; pub fn make() -> Renamed { Renamed }")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        crate::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
        crate::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(&conn);
        crate::analyzer::store::rust_crates::register_point_export_functions(&conn).unwrap();
        conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
        crate::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        let (topology, key, blob): (i64, Vec<u8>, i64) = conn.query_row("SELECT topology_id,crate_key,blob_id FROM selected_rust_crate_containers WHERE container_path='crate' AND rel_path='src/lib.rs'", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap();
        let summary_id: i64 = conn
            .query_row(
                "SELECT summary_id FROM selected_rust_unit_summaries WHERE unit_key=?1",
                [&key],
                |row| row.get(0),
            )
            .unwrap();
        conn.execute("INSERT INTO selected_resolution_mounts(mount_ordinal,blob_id,storage_language,semantic_language,persisted_relative_path) VALUES(0,?1,'rust','rust','src/lib.rs')", [blob]).unwrap();
        conn.execute_batch(crate::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL).unwrap();
        let (target_blob, target_site): (i64, i64) = conn.query_row(
            "SELECT declaration_blob_id,declaration_site FROM rust_crate_exports WHERE topology_id=?1 AND module_path='crate::inner' AND namespace='type' AND name='Thing' AND origin='declaration'",
            [topology], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
        let target_blob_oid: String = conn
            .query_row(
                "SELECT blob_oid FROM blobs WHERE id=?1",
                [target_blob],
                |row| row.get(0),
            )
            .unwrap();
        let edited_blob: i64 = conn
            .query_row(
                "SELECT blobs.id FROM selected_workspace_file_versions AS files
             JOIN blobs ON blobs.lang=files.lang AND blobs.blob_oid=files.blob_oid
             WHERE files.lang='rust' AND files.rel_path='src/edited.rs'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let blob_oid: String = conn
            .query_row("SELECT blob_oid FROM blobs WHERE id=?1", [blob], |row| {
                row.get(0)
            })
            .unwrap();
        let int = Value::Integer;
        let text = |value: &str| Value::Text(value.to_owned());
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let scope_pins = [
                crate::analyzer::store::planner_statistics::pinned_plans::PinnedQuery {
                    name: "rust_scope_detached_summary".to_owned(),
                    sql: format!("{DETACHED_SCOPE_CRATES}(?1)"),
                    params: vec![Value::Blob(key.clone())],
                },
                crate::analyzer::store::planner_statistics::pinned_plans::PinnedQuery {
                    name: "rust_scope_dependency_closure".to_owned(),
                    sql: format!("{CLOSURE_SCOPE_MOUNTS_HEAD}(?1){CLOSURE_SCOPE_MOUNTS_TAIL}"),
                    params: vec![Value::Blob(key.clone())],
                },
            ];
            for pin in &scope_pins {
                let plan = explain_pin(&conn, pin);
                eprintln!("{state:?} {}: {plan:?}", pin.name);
                assert!(
                    plan.iter().all(|step| !step.contains("AUTOMATIC")),
                    "{state:?} {} uses an automatic index: {plan:?}",
                    pin.name
                );
                assert!(
                    plan.iter().any(|step| {
                        step.contains("SEARCH")
                            && step.contains(if pin.name == "rust_scope_dependency_closure" {
                                "selected_rust_unit_closure_summary"
                            } else {
                                "selected_rust_unit_summaries_key"
                            })
                    }),
                    "{state:?} {} must use selected shared unit versions: {plan:?}",
                    pin.name
                );
                assert!(
                    plan.iter().all(|step| {
                        !step.contains("rust_crate_dependencies")
                            && !step.contains("rust_crate_container_sources")
                    }),
                    "{state:?} {} must read summary dependencies and members: {plan:?}",
                    pin.name
                );
                if pin.name == "rust_scope_dependency_closure" {
                    assert!(
                        plan.iter().any(|step| {
                            step.contains("SEARCH closure USING")
                                && step.contains("selected_rust_unit_closure_summary")
                                && step.contains("root_unit_key=?")
                        }),
                        "{state:?} closure mounts must seek the materialized root rows: {plan:?}"
                    );
                    assert!(
                        plan.iter().any(|step| {
                            step.contains("SEARCH members USING PRIMARY KEY (summary_id=?)")
                        }),
                        "{state:?} closure mounts must seek selected summary members: {plan:?}"
                    );
                }
            }
            for mut pin in pinned_queries()
                .into_iter()
                .filter(|pin| pin.name.starts_with("rust_point_"))
            {
                pin.params = match pin.name.as_str() {
                    "rust_point_macro_import_target_range" => vec![int(blob), int(0)],
                    "rust_point_boundary_import_names" => vec![int(0), int(0)],
                    "rust_point_imported_macro_definition" => {
                        vec![text("src/lib.rs"), int(0), text("Macro")]
                    }
                    "rust_point_demand_modules" => {
                        vec![int(blob), text("src/lib.rs"), text(&format!("[{topology}]"))]
                    }
                    "rust_point_demand_export_node" => vec![int(blob), int(0)],
                    "rust_point_demand_reverse_export_names" => {
                        vec![int(target_blob), int(target_site), text("type"), int(0)]
                    }
                    "rust_point_demand_overlay_exports" => {
                        vec![int(topology), text("crate"), text("type")]
                    }
                    "rust_point_demand_prefix_modules" => vec![int(0), int(0), int(topology)],
                    "rust_point_unresolved_trait_impl_files" => vec![text("Unbound")],
                    "rust_point_item_macro_decisions" => {
                        vec![text(&blob_oid), text("src/lib.rs")]
                    }
                    "rust_point_summary_importing_files" => {
                        vec![text(&target_blob_oid), text("src/inner.rs")]
                    }
                    "rust_point_selected_macro_item_unit" => vec![
                        int(0),
                        Value::Null,
                        Value::Null,
                        int(crate::analyzer::store::resolution_prepare::resolution_rows::semantic_role_code(
                            crate::analyzer::resolution::LoweredSemanticRole::Definition,
                        )),
                    ],
                    "rust_point_prefix_spellings" => vec![text("[[0,0]]")],
                    "rust_point_naming" => vec![text("src/lib.rs")],
                    "rust_point_workspace_access_roots" => vec![int(blob)],
                    "rust_point_overlay_import_targets" => vec![int(blob), int(0)],
                    "rust_point_file_blob"
                    | "rust_point_gap_details"
                    | "rust_point_macro_hosts"
                    | "rust_point_macro_gated_unmounted_file" => {
                        vec![text("src/lib.rs")]
                    }
                    "rust_point_access_placements"
                    | "rust_point_access_reference_placements" => {
                        vec![Value::Blob(key.clone()), int(blob), Value::Null]
                    }
                    "rust_point_access_memberships" => {
                        vec![Value::Blob(key.clone()), int(blob)]
                    }
                    "rust_point_access_visibility" => vec![
                        int(topology),
                        text("crate"),
                        int(topology),
                        text("crate"),
                        text("private"),
                        Value::Null,
                    ],
                    "rust_point_crate" | "rust_point_cfg" => vec![Value::Blob(key.clone())],
                    "rust_point_module_placements" => vec![int(blob), text("crate")],
                    "rust_point_file_crates" => vec![int(blob), text("src/lib.rs")],
                    "rust_point_scopes" => vec![int(blob), int(0)],
                    "rust_point_import_inventory" => vec![int(blob)],
                    "rust_point_modules" => vec![int(summary_id)],
                    "rust_point_gaps" => vec![int(topology)],
                    "rust_point_named" => vec![
                        int(topology),
                        text("crate"),
                        int(blob),
                        int(0),
                        text("Alias"),
                        text("type"),
                        int(blob),
                    ],
                    "rust_point_globs" => vec![int(topology), text("crate"), int(blob), int(0)],
                    "rust_point_topology_prelude" => vec![int(topology)],
                    "rust_point_dependency" => vec![int(topology), text("point")],
                    "rust_point_dependency_boundary" => vec![text("point")],
                    "rust_point_import_root_name" => vec![int(blob), int(0), text("Thing")],
                    "rust_point_open_inventory" => {
                        vec![int(topology), text("crate"), text("type"), text("Thing"), int(topology), text("crate")]
                    }
                    "rust_point_unindexed_scope" => {
                        vec![int(topology), text("crate::inner"), text("macro"), text("helper"), int(topology), text("crate")]
                    }
                    "rust_point_open_route" => vec![int(topology), text("crate"), text("inner")],
                    "rust_point_module_prefix_route"
                    | "rust_point_module_import_prefix_route" => vec![
                        int(topology),
                        text("crate"),
                        text("type"),
                        text("Thing"),
                        int(topology),
                        text("crate"),
                    ],
                    "rust_point_parent" => vec![int(topology), text("crate::inner")],
                    "rust_point_container_declaration" => {
                        vec![int(topology), text("crate::inner")]
                    }
                    "rust_point_anchored_import_binds" => vec![int(0), text("Alias")],
                    "rust_point_root_reexport" => vec![int(topology), text("crate"), text("type"), text("Alias"), int(topology), text("crate")],
                    "rust_point_module_import_prefix_starts" => vec![int(topology), text("crate"), int(blob), int(0), text("alias"), text("type"), int(blob)],
                    "rust_point_macro_gated_import_route" => vec![
                        int(topology),
                        text("crate"),
                        int(blob),
                        int(0),
                        text("Alias"),
                        int(blob),
                    ],
                    "rust_point_generated_surface_prefix"
                    | "rust_point_generated_surface_module_prefix"
                    | "rust_point_generated_surface_module_declaration_prefix" => {
                        vec![int(0), text("Thing")]
                    }
                    "rust_point_generated_surface_source_module_prefix" => {
                        vec![int(blob), text("Thing"), text("src/lib.rs")]
                    }
                    "rust_point_derive_helper_conditions" => vec![int(3), text("[[0,null]]")],
                    "rust_point_external_binding" => vec![
                        int(topology), text("crate::inner"), text("type"), text("Thing"), int(topology), text("crate"),
                        int(crate::analyzer::store::resolution_prepare::resolution_rows::namespace_code(brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Type)),
                    ],
                    "rust_point_export" => vec![
                        int(topology),
                        text("crate::inner"),
                        text("type"),
                        text("Thing"),
                        int(topology),
                        text("crate"),
                    ],
                    "rust_point_definition_module" => {
                        vec![int(blob), int(0), int(topology), text("crate")]
                    }
                    "rust_point_macro_item_module" => {
                        vec![
                            int(blob),
                            int(0),
                            int(topology),
                            text("crate"),
                            text("inner"),
                        ]
                    }
                    "rust_point_macro_item_hosts" => vec![text("src/lib.rs")],
                    "rust_point_named_macro_module" => {
                        vec![int(topology), text("crate"), text("inner")]
                    }
                    "rust_point_macro_item_name" => vec![int(blob), int(0)],
                    "rust_point_macro_items_present" => Vec::new(),
                    "rust_point_nominal_type_target" | "rust_point_block_local_type_target" => {
                        vec![int(0), int(0)]
                    }
                    "rust_point_block_local_type_gap_for_target" => vec![
                        int(0),
                        int(0),
                        int(0),
                        int(crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(
                            crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                                brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedScopeOrBinder,
                            ),
                        )),
                    ],
                    "rust_point_trait_visible_at" | "rust_point_trait_impls_visible_at" => vec![
                        int(target_blob),
                        int(target_site),
                        int(topology),
                        text("crate"),
                        text("src/inner.rs"),
                        int(0),
                        int(0),
                    ],
                    "rust_point_trait_impl_member_at" => vec![
                        int(0),
                        int(0),
                        int(target_blob),
                        int(target_site),
                        text("src/inner.rs"),
                        int(target_blob),
                        int(target_site),
                        text("src/inner.rs"),
                    ],
                    "rust_point_store_trait_impl_rows"
                    | "rust_point_store_trait_impl_spellings"
                    | "rust_point_store_traits_implemented_by"
                    | "rust_point_store_types_implementing"
                    | "rust_point_store_traits_of_impl" => {
                        vec![text(&blob_oid), int(0), text("src/lib.rs")]
                    }
                    "rust_point_reference_module_placements"
                    | "rust_point_owner_declaration"
                    | "rust_point_impl_item_traits" => vec![int(0), int(0)],
                    "rust_point_external_type_identity" => {
                        let namespace = crate::analyzer::store::resolution_prepare::resolution_rows::namespace_code(brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Type);
                        let token: i64 = conn.query_row(
                            "SELECT json_extract(binding.end_fixed_key,'$[#-2][0]') FROM resolution_paths binding JOIN resolution_identities identity ON identity.id=binding.root_terminal WHERE binding.blob_id=?1 AND binding.start_node<>-1 AND binding.end_node=-1 AND binding.end_open_tail=1 AND identity.namespace=?2 LIMIT 1",
                            rusqlite::params![blob, namespace], |row| row.get(0)).unwrap();
                        vec![int(0), int(token), int(namespace)]
                    }
                    "rust_point_reference_names_macro_module"
                    | "rust_point_reference_names_workspace_crate" => {
                        vec![int(0), int(0), text("inner")]
                    }
                    name if name.starts_with("rust_point_targets_") => {
                        let mut params = pin.params.clone();
                        params[0] = int(topology);
                        params[4] = int(topology);
                        params
                    }
                    name => panic!("populate the new point query's parameters: {name}"),
                };
                let mut parameter_sets = vec![pin.params.clone()];
                if pin.name == "rust_point_named" {
                    let mut selected = pin.params.clone();
                    selected[4] = text("Renamed");
                    selected[6] = int(edited_blob);
                    parameter_sets.push(selected);
                }
                for parameters in parameter_sets {
                    pin.params = parameters;
                    if pin.name == "rust_point_named" {
                        let names = conn
                            .prepare_cached(&pin.sql)
                            .unwrap()
                            .query_map(rusqlite::params_from_iter(pin.params.iter()), |row| {
                                row.get::<_, String>(2)
                            })
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap();
                        let expected = if pin.params[6] == int(blob) {
                            "Thing"
                        } else {
                            "Other"
                        };
                        assert_eq!(names, [expected], "{state:?} {:?}", pin.params);
                    }
                    let plan = explain_pin(&conn, &pin);
                    eprintln!("{state:?} {}: {plan:?}", pin.name);
                    if matches!(
                        pin.name.as_str(),
                        "rust_point_export"
                            | "rust_point_root_reexport"
                            | "rust_point_external_binding"
                            | "rust_point_open_inventory"
                    ) {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("SEARCH route USING PRIMARY KEY (summary_id=? AND module_path=? AND bound_name=?)")
                            }),
                            "{state:?}: {} must seek named Rust re-export routes: {plan:?}",
                            pin.name
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("rust_resolution_unit_summary_import_routes_binder")
                            }),
                            "{state:?}: {} must seek Rust import binders by member/scope/name: {plan:?}",
                            pin.name
                        );
                        assert!(
                            plan.iter().all(|step| !step.contains("AUTOMATIC")),
                            "{state:?}: {} must not build automatic route indexes: {plan:?}",
                            pin.name
                        );
                    }
                    if pin.name == "rust_point_root_reexport" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("rust_resolution_unit_summary_root_routes_owner")
                            }),
                            "{state:?}: root import targets must seek the Rust-owned route rows: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_summary_importing_files" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains(
                                    "rust_resolution_unit_summary_import_routes_target_identity",
                                )
                            }),
                            "{state:?} reverse named imports must use the target identity index: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| !step.contains("AUTOMATIC")),
                            "{state:?} reverse importer lookup must not build automatic indexes: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| !step.contains("SCAN versions")),
                            "{state:?} reverse importer lookup must seek the live target summary instead of scanning versions: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_imported_macro_definition" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("resolution_unit_summary_members_blob (blob_id=?)")
                            }),
                            "{state:?} imported macro lookup must seek selected members from the path-selected blob: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("rust_resolution_unit_summary_import_routes_site")
                            }),
                            "{state:?} imported macro lookup must seek named route sites: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("SEARCH export USING PRIMARY KEY (summary_id=? AND module_path=? AND namespace=? AND name=?)")
                            }),
                            "{state:?} imported macro lookup must seek target exports by unit/module/name: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("SEARCH route USING PRIMARY KEY (summary_id=? AND member_ordinal=? AND source_import_id=? AND route_ordinal=?)")
                            }),
                            "{state:?} imported macro glob lookup must seek its Rust summary route: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_imports")
                                    && !step.contains("rust_crate_glob_imports")
                                    && !step.contains("rust_crate_exports")
                                    && !step.contains("rust_crate_container_sources")
                                    && !step.contains("AUTOMATIC")
                            }),
                            "{state:?} imported macro lookup must use only live summary rows: {plan:?}"
                        );
                    }
                    if matches!(
                        pin.name.as_str(),
                        "rust_point_access_placements"
                            | "rust_point_access_reference_placements"
                            | "rust_point_module_placements"
                    ) {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains(
                                    "selected_rust_module_placements_blob (placement_blob=?",
                                )
                            }),
                            "{state:?} placement lookup must seek the materialized blob index: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_boundary_import_names" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("rust_resolution_unit_summary_placements_member")
                            }),
                            "{state:?} boundary import names must seek member placements: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("SEARCH gap USING PRIMARY KEY (summary_id=? AND gap_kind=? AND subject=?)")
                            }),
                            "{state:?} boundary import names must seek a summary gap by exact subject: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_gaps")
                                    && !step.contains("rust_crate_container_sources")
                                    && !step.contains("AUTOMATIC")
                            }),
                            "{state:?} boundary import names must use selected summary rows: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_demand_reverse_export_names" {
                        for index in [
                            "rust_resolution_unit_summary_reexport_routes_target_identity",
                            "rust_resolution_unit_summary_glob_reexport_routes_target_identity",
                            "rust_resolution_unit_summary_import_routes_target_identity",
                        ] {
                            assert!(
                                plan.iter().any(|step| step.contains(index)),
                                "{state:?}: reverse demand closure must seek {index}: {plan:?}"
                            );
                        }
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_reexport_routes")
                                    && !step.contains("rust_crate_glob_reexport_routes")
                                    && !step.contains("rust_crate_imports")
                            }),
                            "{state:?}: reverse demand closure must use summary route rows: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_demand_prefix_modules" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("resolution_unit_summary_dependencies")
                            }),
                            "{state:?}: prefix reachability must traverse shared summary dependencies: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains(
                                    "SEARCH modules USING PRIMARY KEY (summary_id=? AND module_path=?) LEFT-JOIN",
                                )
                            }),
                            "{state:?}: prefix module lookup must seek Rust summary containers: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_dependencies")
                                    && !step.contains("rust_crate_containers")
                            }),
                            "{state:?}: prefix module lookup must use live summary rows: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_item_macro_decisions" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("resolution_unit_summary_members_blob")
                            }),
                            "{state:?}: item macro placements must seek members by blob: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("SEARCH decided USING PRIMARY KEY (summary_id=? AND member_ordinal=? AND invocation_occurrence_id=?)")
                            }),
                            "{state:?}: macro decisions must seek the selected member invocation: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_decided_item_macros")
                                    && !step.contains("rust_crate_topologies")
                            }),
                            "{state:?}: item macro decisions must use live summary rows: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_unresolved_trait_impl_files" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains(
                                    "rust_resolution_unit_summary_trait_endpoints_unresolved",
                                )
                            }),
                            "{state:?}: unresolved trait candidates must seek by role and spelling: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("resolution_unit_summary_versions_summary")
                            }),
                            "{state:?}: unresolved trait candidates must validate the shared live version: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_unresolved_trait_impls")
                                    && !step.contains("AUTOMATIC")
                            }),
                            "{state:?}: unresolved trait candidates use published summary rows without automatic indexes: {plan:?}"
                        );
                    }
                    if matches!(
                        pin.name.as_str(),
                        "rust_point_trait_visible_at" | "rust_point_trait_impls_visible_at"
                    ) {
                        for index in [
                            "rust_resolution_unit_summary_exports_declaration",
                            "rust_resolution_unit_summary_exports_alias_target",
                            "rust_resolution_unit_summary_import_routes_target_identity",
                            "rust_resolution_unit_summary_glob_imports_target_identity",
                        ] {
                            assert!(
                                plan.iter().any(|step| step.contains(index)),
                                "{state:?}: {} must seek {index}: {plan:?}",
                                pin.name
                            );
                        }
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_trait_impls")
                                    && !step.contains("rust_crate_exports")
                                    && !step.contains("rust_crate_imports")
                                    && !step.contains("rust_crate_glob_imports")
                                    && !step.contains("rust_crate_versions")
                                    && !step.contains("AUTOMATIC")
                            }),
                            "{state:?}: {} must use only live summary rows: {plan:?}",
                            pin.name
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("SEARCH rust_versions USING PRIMARY KEY")
                            }),
                            "{state:?}: {} must seek topology ids from the Rust summary crosswalk: {plan:?}",
                            pin.name
                        );
                    }
                    if matches!(
                        pin.name.as_str(),
                        "rust_point_trait_impl_member_at" | "rust_point_impl_item_traits"
                    ) {
                        let endpoint_index = if pin.name == "rust_point_trait_impl_member_at" {
                            "rust_resolution_unit_summary_trait_endpoints_target"
                        } else {
                            "rust_resolution_unit_summary_trait_endpoints_impl"
                        };
                        assert!(
                            plan.iter().any(|step| step.contains(endpoint_index)),
                            "{state:?}: {} must seek endpoints through {endpoint_index}: {plan:?}",
                            pin.name
                        );
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_trait_impls")
                                    && !step.contains("rust_crate_versions")
                                    && !step.contains("AUTOMATIC")
                            }),
                            "{state:?}: {} must use live summary endpoints: {plan:?}",
                            pin.name
                        );
                    }
                    if pin.name.starts_with("rust_point_store_trait_")
                        || pin.name.starts_with("rust_point_store_types_implementing")
                    {
                        let endpoint_index = if pin.name == "rust_point_store_traits_of_impl" {
                            "rust_resolution_unit_summary_trait_endpoints_impl"
                        } else {
                            "rust_resolution_unit_summary_trait_endpoints_target"
                        };
                        assert!(
                            plan.iter().any(|step| step.contains(endpoint_index)),
                            "{state:?}: {} must seek through {endpoint_index}: {plan:?}",
                            pin.name
                        );
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_trait_impls")
                                    && !step.contains("AUTOMATIC")
                            }),
                            "{state:?}: {} must use live Rust summary endpoints without automatic indexes: {plan:?}",
                            pin.name
                        );
                    }
                    if pin.name == "rust_point_selected_macro_item_unit" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains(
                                    "rust_resolution_unit_summary_generated_names_declaration",
                                )
                            }),
                            "{state:?}: selected macro items must seek by declaration: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("resolution_unit_summary_members_blob")
                            }),
                            "{state:?}: selected macro items must seek their live member by blob: {plan:?}"
                        );
                        assert!(
                            plan.iter()
                                .all(|step| !step.contains("rust_crate_macro_items")),
                            "{state:?}: selected macro items must use Rust summary names: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_demand_modules" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("resolution_unit_summary_members_blob")
                            }),
                            "{state:?}: module enumeration must seek selected summary members by blob: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("rust_resolution_unit_summary_placements_member")
                            }),
                            "{state:?}: module enumeration must seek placements by member: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_container_sources")
                                    && !step.contains("AUTOMATIC")
                            }),
                            "{state:?}: module enumeration must use live summary placements: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_owner_declaration" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("resolution_unit_summary_members_blob")
                            }),
                            "{state:?}: declaration membership must seek selected summary members by blob: {plan:?}"
                        );
                        assert!(
                            plan.iter()
                                .all(|step| !step.contains("rust_crate_container_sources")),
                            "{state:?}: declaration membership must use live summary rows: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_dependency_boundary"
                        || pin.name == "rust_point_dependency"
                    {
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_dependencies")
                                    && !step.contains("rust_crate_topologies")
                            }),
                            "{state:?}: dependency names and boundaries must use live summary rows: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("SEARCH name USING")
                                    && (step.contains("rust_resolution_unit_summary_dependency_names_owner_extern")
                                        || step.contains("PRIMARY KEY (summary_id=? AND extern_name=?)"))
                            }),
                            "{state:?}: dependency lookup must seek the Rust extern-name crosswalk: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_topology_prelude" {
                        assert!(
                            plan.iter()
                                .all(|step| !step.contains("rust_crate_topologies")),
                            "{state:?}: edition and prelude must come from selected Rust summary contexts: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_reference_names_workspace_crate" {
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_dependencies")
                                    && !step.contains("rust_crate_imports")
                                    && !step.contains("rust_crate_container_sources")
                                    && !step.contains("rust_crate_topologies")
                                    && !step.contains("rust_crate_versions")
                                    && !step.contains("SCAN versions")
                                    && !step.contains("AUTOMATIC")
                            }),
                            "{state:?}: workspace crate names must use live summary dependencies and routes: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("rust_resolution_unit_summary_versions_topology")
                            }),
                            "{state:?}: requester crate selection must seek the live summary topology crosswalk: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("rust_resolution_unit_summary_import_routes_binder")
                            }),
                            "{state:?}: workspace crate aliases must seek summary import routes: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_reference_names_macro_module" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("rust_resolution_unit_summary_generated_names_module")
                            }),
                            "{state:?}: macro module names must seek the selected summary's generated-name rows: {plan:?}"
                        );
                        assert!(
                            plan.iter()
                                .all(|step| !step.contains("rust_crate_macro_items")),
                            "{state:?}: macro module names must use live Rust summary rows: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_export" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("SEARCH exports USING PRIMARY KEY (summary_id=? AND module_path=? AND namespace=? AND name=?)")
                            }),
                            "{state:?}: exports must seek a selected unit/module/name: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("rust_resolution_unit_summary_generated_names_name")
                            }),
                            "{state:?}: generated names must use their name index: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_overlay_import_targets" {
                        assert!(
                            plan.iter()
                                .any(|step| step.contains("resolution_unit_summary_members_blob")),
                            "{state:?}: overlay import source must seek shared membership by blob: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| step.contains(
                                "SEARCH route USING PRIMARY KEY (summary_id=? AND member_ordinal=? AND import_id=? AND route_ordinal=?)"
                            )),
                            "{state:?}: overlay import routes must seek by summary/member/import/route: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| !step.contains("AUTOMATIC")),
                            "{state:?}: overlay import route lookup must not build an automatic index: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_parent" {
                        assert!(
                            plan.iter().any(|step| step.contains(
                                "SEARCH placement USING PRIMARY KEY (summary_id=? AND module_path=?)"
                            )),
                            "{state:?}: parent module placement must use its summary/path key: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_container_declaration" {
                        assert!(
                            plan.iter().any(|step| step.contains(
                                "SEARCH child USING PRIMARY KEY (summary_id=? AND module_path=?)"
                            )) && plan.iter().any(|step| step.contains(
                                "SEARCH parent USING PRIMARY KEY (summary_id=? AND module_path=?)"
                            )),
                            "{state:?}: module declaration placements must use their summary/path keys: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_dependency" {
                        assert!(
                            plan.iter().any(|step| step
                                .contains("rust_resolution_unit_summary_versions_topology")),
                            "{state:?}: owner must use the live summary topology crosswalk index: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| step.contains(
                                "rust_resolution_unit_summary_dependency_names_owner_extern"
                            )),
                            "{state:?}: dependency extern names must use their summary index: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_versions")
                                    && !step.contains("SCAN versions")
                                    && !step.contains("SCAN shared_version")
                                    && !step.contains("AUTOMATIC")
                            }),
                            "{state:?}: dependency targets must come from selected live summaries without scans or automatic indexes: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_macro_import_target_range" {
                        assert!(
                            plan.iter().any(|step| step.contains(
                                "SEARCH source_occurrence_arenas USING PRIMARY KEY (blob_id=?)"
                            )),
                            "{state:?}: {plan:?}"
                        );
                        assert!(
                            !plan
                                .iter()
                                .any(|step| step.contains("SCAN") || step.contains("json_each")),
                            "{state:?}: {plan:?}"
                        );
                    }
                    assert!(
                        !plan.iter().any(|step| step.contains("SCAN exports")),
                        "{state:?} {} scans exports: {plan:?}",
                        pin.name
                    );
                    assert!(
                        !plan.iter().any(|step| step.contains("AUTOMATIC")),
                        "{state:?} {} uses an automatic index: {plan:?}",
                        pin.name
                    );
                    assert!(
                        plan.iter().any(|step| step.contains("SEARCH")),
                        "{state:?} {} has no indexed lookup: {plan:?}",
                        pin.name
                    );
                    if pin.name == "rust_graph_crate_member_files" {
                        assert!(
                            plan.iter()
                                .any(|step| step.contains("selected_rust_unit_summaries_key")),
                            "{state:?} {} must seek the active unit version: {plan:?}",
                            pin.name
                        );
                        assert!(
                            plan.iter()
                                .any(|step| step.contains("resolution_unit_summary_members")),
                            "{state:?} {} must seek shared summary members: {plan:?}",
                            pin.name
                        );
                    }
                    if pin.name == "rust_point_file_crates" {
                        assert!(
                            plan.iter()
                                .any(|step| step.contains("resolution_unit_summary_members_blob")),
                            "{state:?} {} must seek members by blob: {plan:?}",
                            pin.name
                        );
                    }
                    // The derive-helper read is driven by the mounts a lookup
                    // reached: the mount is sought by ordinal and the
                    // candidate declarations come from the partial index, so
                    // the only scans are the two `json_each` tables and the
                    // placement view's own scope-alignment recursion.
                    if pin.name == "rust_point_derive_helper_conditions" {
                        assert!(
                            plan.iter().any(|step| step
                                .contains("source_rust_declaration_properties_derive_helpers")),
                            "{state:?} derive-helper read skips its partial index: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| !step.starts_with("SCAN ")
                                || step.contains("reached")
                                || step.contains("helper")
                                || step == "SCAN CONSTANT ROW"
                                || step == "SCAN aligned"),
                            "{state:?} derive-helper read scans a table: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_named" {
                        assert!(
                            !plan.iter().any(|step| step.contains("SCAN imports")),
                            "{state:?} {:?} scans import inventory: {plan:?}",
                            pin.params
                        );
                    }
                    // The implemented-trait read keys every table by the one
                    // mount and semantic it asks about. The only scans allowed
                    // are the placement view's own scope-alignment recursion.
                    if matches!(
                        pin.name.as_str(),
                        "rust_point_reference_module_placements"
                            | "rust_point_owner_declaration"
                            | "rust_point_impl_item_traits"
                            | "rust_point_trait_impl_member_at"
                            | "rust_point_external_type_identity"
                    ) {
                        assert!(
                            !plan.iter().any(|step| step.starts_with("SCAN ")
                                && step != "SCAN CONSTANT ROW"
                                && step != "SCAN aligned"),
                            "{state:?} {} scans a table: {plan:?}",
                            pin.name
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn rust_unit_membership_and_graph_queries_have_indexed_plans() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='pin'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", "pub fn item() {}\n")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        crate::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
        crate::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(&conn);
        crate::analyzer::store::rust_crates::register_point_export_functions(&conn).unwrap();
        conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
        crate::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        let (key, blob): (Vec<u8>, i64) = conn.query_row(
            "SELECT crate_key,blob_id FROM selected_rust_crate_containers WHERE rel_path='src/lib.rs' LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        let summary_id: i64 = conn
            .query_row(
                "SELECT summary_id FROM selected_rust_unit_summaries WHERE unit_key=?1",
                [&key],
                |row| row.get(0),
            )
            .unwrap();
        conn.execute("INSERT INTO selected_resolution_mounts(mount_ordinal,blob_id,storage_language,semantic_language,persisted_relative_path) VALUES(0,?1,'rust','rust','src/lib.rs')", [blob]).unwrap();
        conn.execute_batch(crate::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL).unwrap();
        let member_files = pinned("rust_graph_crate_member_files");
        let graph_keys = pinned("rust_graph_crate_keys");
        let file_crates = pinned("rust_point_file_crates");
        let mut cfg = pinned("rust_point_cfg");
        let mut modules = pinned("rust_point_modules");
        let mut module_placements = pinned("rust_point_module_placements");
        let graph_definitions = pinned("rust_graph_definitions");
        let mut member_files = member_files;
        member_files.params = vec![rusqlite::types::Value::Blob(key.clone())];
        let mut file_crates = file_crates;
        file_crates.params = vec![
            rusqlite::types::Value::Integer(blob),
            rusqlite::types::Value::Text("src/lib.rs".to_owned()),
        ];
        cfg.params = vec![rusqlite::types::Value::Blob(key.clone())];
        modules.params = vec![rusqlite::types::Value::Integer(summary_id)];
        module_placements.params = vec![
            rusqlite::types::Value::Integer(blob),
            rusqlite::types::Value::Text("crate".to_owned()),
        ];
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            for pin in [
                &graph_keys,
                &member_files,
                &file_crates,
                &cfg,
                &modules,
                &module_placements,
                &graph_definitions,
            ] {
                let plan = explain_pin(&conn, pin);
                eprintln!("{state:?} {}: {plan:?}", pin.name);
                assert!(
                    !plan.iter().any(|step| step.contains("AUTOMATIC")),
                    "{state:?} {} uses an automatic index: {plan:?}",
                    pin.name
                );
                assert!(
                    pin.name == "rust_graph_crate_keys"
                        || plan.iter().any(|step| step.contains("SEARCH")),
                    "{state:?} {} has no indexed seek: {plan:?}",
                    pin.name
                );
            }
            let member_plan = explain_pin(&conn, &member_files);
            let keys_plan = explain_pin(&conn, &graph_keys);
            assert!(
                keys_plan
                    .iter()
                    .any(|step| step.contains("SCAN selected_rust_unit_summaries USING COVERING INDEX selected_rust_unit_summaries_key")),
                "{state:?} crate key enumeration must walk the selected unit key index: {keys_plan:?}"
            );
            assert!(
                member_plan.iter().any(|step| {
                    step.contains("SEARCH units USING INDEX selected_rust_unit_summaries_key")
                        && step.contains("unit_key=?")
                }),
                "{state:?} member enumeration must seek the active unit version: {member_plan:?}"
            );
            assert!(
                member_plan.iter().any(|step| {
                    step.contains("SEARCH members USING PRIMARY KEY (summary_id=?)")
                }),
                "{state:?} member enumeration must seek shared members: {member_plan:?}"
            );
            let file_plan = explain_pin(&conn, &file_crates);
            assert!(
                file_plan
                    .iter()
                    .any(|step| step.contains("resolution_unit_summary_members_blob")),
                "{state:?} file-to-crate lookup must seek members by blob: {file_plan:?}"
            );
            let cfg_plan = explain_pin(&conn, &cfg);
            assert!(
                cfg_plan.iter().any(|step| {
                    step.contains("SEARCH units USING INDEX selected_rust_unit_summaries_key")
                        && step.contains("unit_key=?")
                }),
                "{state:?} Rust cfg lookup must seek the selected unit version: {cfg_plan:?}"
            );
            assert!(
                cfg_plan
                    .iter()
                    .any(|step| { step.contains("SEARCH contexts USING INTEGER PRIMARY KEY") }),
                "{state:?} Rust cfg lookup must seek the summary context: {cfg_plan:?}"
            );
            let graph_plan = explain_pin(&conn, &graph_definitions);
            assert!(
                graph_plan.iter().any(|step| step == "SCAN units"),
                "{state:?} graph definition enumeration must enumerate only materialized selected units: {graph_plan:?}"
            );
            assert!(
                graph_plan.iter().any(|step| {
                    step.contains("SEARCH members USING PRIMARY KEY (summary_id=?)")
                }),
                "{state:?} graph definition enumeration must seek summary members: {graph_plan:?}"
            );
            let modules_plan = explain_pin(&conn, &modules);
            assert!(
                modules_plan.iter().any(|step| {
                    step.contains("SEARCH root USING INDEX selected_rust_unit_summaries_summary")
                        && step.contains("summary_id=?")
                }),
                "{state:?} module enumeration must seek its live summary: {modules_plan:?}"
            );
            assert!(
                modules_plan.iter().any(|step| {
                    step.contains("SEARCH graph USING INDEX selected_rust_unit_closure_summary")
                }),
                "{state:?} module dependency closure must seek materialized root rows: {modules_plan:?}"
            );
            assert!(
                modules_plan.iter().any(|step| {
                    step.contains(
                        "SEARCH placement USING INDEX rust_resolution_unit_summary_placements_member (summary_id=?)",
                    )
                }),
                "{state:?} module enumeration must seek Rust placements by the selected closure summary: {modules_plan:?}"
            );
            let module_placements_plan = explain_pin(&conn, &module_placements);
            assert!(
                module_placements_plan
                    .iter()
                    .any(|step| step
                        .contains("selected_rust_module_placements_blob (placement_blob=?)")),
                "{state:?} module placement lookup must seek the materialized blob index: {module_placements_plan:?}"
            );
        }
    }

    /// An override never ties with the method it overrides. Here the trait's
    /// own module holds an item macro the producer cannot expand, so the
    /// impl's trait path names `Op` through a lookup that is not proven
    /// exhaustive and the impl's trait frontier is incomplete. The frontier
    /// still names `Op`, so the trait-item replay skips `Op` and answers the
    /// override alone. Found by the point-answer census (2026-09-24): counting
    /// such an item as one of an unnameable trait made the replay find `Op`
    /// again and report a false E0034 tie. rustc calls the override.
    #[test]
    #[hardwon("2150d85feb2f: an impl override was counted twice as an E0034 tie")]
    fn an_override_does_not_tie_with_the_method_it_overrides() {
        let source = "unexpanded_item_macro!();\ntrait Op {\n    fn name(&self) -> u8 {\n        0\n    }\n}\nstruct Service;\nimpl Op for Service {\n    fn name(&self) -> u8 {\n        1\n    }\n}\n\nfn caller(service: Service) {\n    service.name();\n}\n";
        let outcome = qualified_member_outcome(&[("t.rs", source)], "t.rs", "service.name");
        let names = outcome
            .definitions
            .iter()
            .map(|unit| unit.short_name().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["Service.name".to_owned()], "{outcome:?}");
        assert!(
            outcome
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.kind != "unordered_candidates"),
            "{outcome:?}"
        );
    }

    /// A two-crate workspace in the shape the point-answer census found the
    /// cross-crate tie on: `core-crate` declares `CodeUnitIndex`, `analysis`
    /// implements it for `JavaAnalyzer` in `analyzer/java/mod.rs` and names it
    /// through `analyzer_mod`'s re-export, and `java_prelude` precedes the
    /// impl. `analysis` calls the method from the impl's file, from another
    /// file of its library, and from an integration test.
    fn cross_crate_override_files(analysis_mod: &str, java_prelude: &str) -> Vec<(String, String)> {
        [
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"core\", \"analysis\"]\nresolver = \"2\"\n".to_owned(),
            ),
            (
                "core/Cargo.toml",
                "[package]\nname = \"core-crate\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
                    .to_owned(),
            ),
            ("core/src/lib.rs", "pub mod analyzer;\n".to_owned()),
            ("core/src/analyzer/mod.rs", "pub mod code_unit_index;\n".to_owned()),
            (
                "core/src/analyzer/code_unit_index.rs",
                "pub trait CodeUnitIndex {\n    fn get_definitions(&self) -> u8 {\n        0\n    }\n}\n"
                    .to_owned(),
            ),
            (
                "analysis/Cargo.toml",
                "[package]\nname = \"analysis\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ncore-crate = { path = \"../core\" }\n"
                    .to_owned(),
            ),
            ("analysis/src/lib.rs", "pub mod analyzer;\nmod caller;\n".to_owned()),
            (
                "analysis/src/caller.rs",
                "use crate::analyzer::java::JavaAnalyzer;\nuse crate::analyzer::CodeUnitIndex;\n\nfn same_crate(same: JavaAnalyzer) {\n    same.get_definitions();\n}\n"
                    .to_owned(),
            ),
            ("analysis/src/analyzer/mod.rs", analysis_mod.to_owned()),
            ("analysis/src/analyzer/java/tests.rs", "fn t() {}\n".to_owned()),
            (
                "analysis/src/analyzer/java/mod.rs",
                format!(
                    "pub struct JavaAnalyzer;\n{java_prelude}\nimpl CodeUnitIndex for JavaAnalyzer {{\n    fn get_definitions(&self) -> u8 {{\n        1\n    }}\n}}\n\nfn same_file(analyzer: JavaAnalyzer) {{\n    analyzer.get_definitions();\n}}\n"
                ),
            ),
            (
                "analysis/tests/t.rs",
                "use analysis::analyzer::java::JavaAnalyzer;\nuse analysis::analyzer::CodeUnitIndex;\n\nfn integration(ext: JavaAnalyzer) {\n    ext.get_definitions();\n}\n"
                    .to_owned(),
            ),
        ]
        .into_iter()
        .map(|(name, contents)| (name.to_owned(), contents))
        .collect()
    }

    const MODULE_IMPORT_REEXPORT: &str = "pub mod java;\nuse core_crate::analyzer::{code_unit_index};\npub use code_unit_index::CodeUnitIndex;\n";

    /// The override answers alone, with no tie reason, from every caller.
    fn assert_override_alone(analysis_mod: &str, java_prelude: &str, callers: &[(&str, &str)]) {
        let files = cross_crate_override_files(analysis_mod, java_prelude);
        let files = files
            .iter()
            .map(|(name, contents)| (name.as_str(), contents.as_str()))
            .collect::<Vec<_>>();
        for (caller, path) in callers {
            let outcome = qualified_member_outcome(&files, caller, path);
            let names = outcome
                .definitions
                .iter()
                .map(|unit| unit.short_name().to_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                names,
                vec!["JavaAnalyzer.get_definitions".to_owned()],
                "{caller}: {outcome:?}"
            );
            assert!(
                outcome.diagnostics.iter().all(|diagnostic| {
                    diagnostic.kind != "unordered_candidates"
                        && !diagnostic.message.contains("inconsistent_precedence")
                }),
                "{caller}: {outcome:?}"
            );
        }
    }

    const ALL_CALLERS: [(&str, &str); 3] = [
        (
            "analysis/src/analyzer/java/mod.rs",
            "analyzer.get_definitions",
        ),
        ("analysis/src/caller.rs", "same.get_definitions"),
        ("analysis/tests/t.rs", "ext.get_definitions"),
    ];

    /// An impl item's trait is the one crate derivation bound in the impl's
    /// own crate. Asked from an integration test, the impl header's lexical
    /// lookup runs in the test's crate, whose request compiles no route for
    /// the library's `crate::`; the crate rows still name `CodeUnitIndex`, so
    /// the override answers alone from the impl's file, from its crate, and
    /// from the test. Found by the point-answer census (2026-09-24): 1,522
    /// Bifrost sites, all calls from another crate, tied the override with
    /// the declaration it overrides.
    #[test]
    #[hardwon("2cb71a73a409: a module re-export must not create a false override tie")]
    fn a_cross_crate_override_does_not_tie_through_a_module_import_reexport() {
        assert_override_alone(
            MODULE_IMPORT_REEXPORT,
            "use crate::analyzer::CodeUnitIndex;",
            &ALL_CALLERS,
        );
    }

    #[test]
    #[hardwon("2cb71a73a409: a direct re-export must preserve the impl trait owner")]
    fn a_cross_crate_override_does_not_tie_through_a_direct_reexport() {
        assert_override_alone(
            "pub mod java;\npub use core_crate::analyzer::code_unit_index::CodeUnitIndex;\n",
            "use crate::analyzer::CodeUnitIndex;",
            &ALL_CALLERS,
        );
    }

    /// A `#[cfg(test)] mod` beside the impl leaves a placement gap in the
    /// file; it does not make the override tie.
    #[test]
    #[hardwon("2cb71a73a409: cfg test modules must not change cross-crate override identity")]
    fn a_cross_crate_override_does_not_tie_beside_a_cfg_test_module() {
        assert_override_alone(
            MODULE_IMPORT_REEXPORT,
            "#[cfg(test)]\nmod tests;\nuse crate::analyzer::CodeUnitIndex;",
            &ALL_CALLERS,
        );
    }

    /// A qualified item macro beside the impl could add an inherent
    /// `get_definitions`, so the answer is not proven, but the override still
    /// does not tie with the declaration it overrides.
    #[test]
    #[hardwon("2cb71a73a409: a qualified item macro must not create a false trait candidate")]
    fn a_cross_crate_override_does_not_tie_beside_a_qualified_item_macro() {
        assert_override_alone(
            "pub mod java;\nmacro_rules! fwd { ($t:ty) => { impl $t { pub fn extra(&self) {} } }; }\npub(crate) use fwd;\nuse core_crate::analyzer::{code_unit_index};\npub use code_unit_index::CodeUnitIndex;\n",
            "crate::analyzer::fwd!(JavaAnalyzer);\nuse crate::analyzer::CodeUnitIndex;",
            &ALL_CALLERS,
        );
    }

    /// A lookup a request demands in a file of a crate it is not made on
    /// behalf of, through that file's own `crate::` route, answers incomplete.
    /// Here an integration test calls `make().spin()`, and `make`'s return
    /// type is spelled `crate::widget::Widget` in the library; the test's
    /// request compiles no route for the library's `crate::`. The lookup used
    /// to claim a complete absence, so the call answered `NoDefinition`.
    #[test]
    #[hardwon("2cb71a73a409: an unbridged dependency root cannot prove absence")]
    fn a_lookup_through_another_crates_root_is_incomplete_not_absent() {
        let files: Vec<(&str, &str)> = vec![
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"analysis\"]\nresolver = \"2\"\n",
            ),
            (
                "analysis/Cargo.toml",
                "[package]\nname = \"analysis\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            ),
            (
                "analysis/src/lib.rs",
                "pub mod widget;\npub fn make() -> crate::widget::Widget {\n    crate::widget::Widget\n}\n",
            ),
            (
                "analysis/src/widget.rs",
                "pub struct Widget;\nimpl Widget {\n    pub fn spin(&self) {}\n}\n",
            ),
            (
                "analysis/tests/t.rs",
                "fn caller() {\n    analysis::make().spin();\n}\n",
            ),
        ];
        let outcome = qualified_member_outcome(&files, "analysis/tests/t.rs", "make().spin");
        assert_eq!(
            outcome.status,
            crate::analyzer::usages::get_definition::DefinitionLookupStatus::Incomplete,
            "{outcome:?}"
        );
    }

    const TDIM_FROM_IMPLS: &str = "pub struct Symbol;\npub struct TDim;\nimpl From<Symbol> for TDim {\n    fn from(s: Symbol) -> TDim {\n        TDim\n    }\n}\nimpl<'a> From<&'a Symbol> for TDim {\n    fn from(s: &'a Symbol) -> TDim {\n        TDim\n    }\n}\nmacro_rules! from_i {\n    ($i: ty) => {\n        impl From<$i> for TDim {\n            fn from(v: $i) -> TDim {\n                TDim\n            }\n        }\n    };\n}\nfrom_i!(i32);\nfrom_i!(i64);\n";

    /// Several impls of one trait the rows cannot name (`From`, from std) for
    /// one self type are not an E0034 tie: they may be impls of one generic
    /// trait, and rustc picks between them by the argument's type. When the
    /// arguments cannot decide it, the answer keeps the candidates and says
    /// it is not decided. Found by the point-answer census (2026-09-24): 81
    /// tract `TDim::from` sites answered a tie between `impl From<Symbol> for
    /// TDim` and `impl From<&Symbol> for TDim`, beside `from_i!`'s impls.
    #[test]
    #[hardwon("140ac61e6887: impls of one unnameable trait were reported as an E0034 tie")]
    fn impls_of_one_unnameable_trait_are_undecided_not_a_tie() {
        for call in [
            "fn caller() {\n    let d = TDim::from(12);\n}\n",
            "fn caller(s: Symbol) {\n    let d = TDim::from(s);\n}\n",
        ] {
            let source = format!("{TDIM_FROM_IMPLS}{call}");
            let outcome = qualified_member_outcome(&[("t.rs", &source)], "t.rs", "TDim::from");
            let mut signatures = outcome
                .definitions
                .iter()
                .map(|unit| unit.signature().unwrap_or_default().to_owned())
                .collect::<Vec<_>>();
            signatures.sort();
            assert_eq!(
                signatures,
                vec![
                    "impl From<&'a Symbol> for TDim::fn from(s: &'a Symbol) -> TDim { ... }"
                        .to_owned(),
                    "impl From<Symbol> for TDim::fn from(s: Symbol) -> TDim { ... }".to_owned(),
                ],
                "{call}: {outcome:?}"
            );
            assert_eq!(
                outcome.status,
                crate::analyzer::usages::get_definition::DefinitionLookupStatus::Incomplete,
                "{call}: {outcome:?}"
            );
            assert!(
                outcome.diagnostics.iter().all(|diagnostic| {
                    diagnostic.kind != "unordered_candidates"
                        && !diagnostic.message.contains("inconsistent_precedence")
                }),
                "{call}: {outcome:?}"
            );
        }
    }

    /// The argument decides among impls of one unnameable trait when the
    /// coercion filter proves every other impl's parameter cannot take it:
    /// a `u8` value binds no `&str` parameter.
    #[test]
    #[hardwon("140ac61e6887: argument evidence must narrow impls of one unnameable trait")]
    fn the_argument_decides_among_impls_of_one_unnameable_trait() {
        let source = "pub struct W;\nimpl From<u8> for W {\n    fn from(v: u8) -> W {\n        W\n    }\n}\nimpl<'a> From<&'a str> for W {\n    fn from(v: &'a str) -> W {\n        W\n    }\n}\n\nfn caller(x: u8) {\n    let w = W::from(x);\n}\n";
        let outcome = qualified_member_outcome(&[("t.rs", source)], "t.rs", "W::from");
        let signatures = outcome
            .definitions
            .iter()
            .map(|unit| unit.signature().unwrap_or_default().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            signatures,
            vec!["impl From<u8> for W::fn from(v: u8) -> W { ... }".to_owned()],
            "{outcome:?}"
        );
        assert_eq!(
            outcome.status,
            crate::analyzer::usages::get_definition::DefinitionLookupStatus::Resolved,
            "{outcome:?}"
        );
    }

    /// Two traits that both declare `import_statements`, each implemented for
    /// `JavascriptAnalyzer` in another crate, and an integration test that
    /// calls the method with `imports` in scope. `core-crate` declares
    /// `IAnalyzer` in `iface` and `JsTsSource` in `source`.
    fn trait_scope_outcome(imports: &str) -> Vec<String> {
        let test = format!(
            "{imports}\nuse analysis::JavascriptAnalyzer;\n\nfn caller(analyzer: JavascriptAnalyzer) {{\n    analyzer.import_statements();\n}}\n"
        );
        let files = [
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"core\", \"analysis\"]\nresolver = \"2\"\n",
            ),
            (
                "core/Cargo.toml",
                "[package]\nname = \"core-crate\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            ),
            ("core/src/lib.rs", "pub mod iface;\npub mod source;\n"),
            (
                "core/src/iface.rs",
                "pub trait IAnalyzer {\n    fn import_statements(&self) -> u8;\n}\n",
            ),
            (
                "core/src/source.rs",
                "pub trait JsTsSource {\n    fn import_statements(&self) -> u8;\n}\n",
            ),
            (
                "analysis/Cargo.toml",
                "[package]\nname = \"analysis\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ncore-crate = { path = \"../core\" }\n",
            ),
            (
                "analysis/src/lib.rs",
                "use core_crate::iface::IAnalyzer;\nuse core_crate::source::JsTsSource;\n\npub struct JavascriptAnalyzer;\n\nimpl JsTsSource for JavascriptAnalyzer {\n    fn import_statements(&self) -> u8 {\n        1\n    }\n}\n\nimpl IAnalyzer for JavascriptAnalyzer {\n    fn import_statements(&self) -> u8 {\n        2\n    }\n}\n",
            ),
            ("analysis/tests/t.rs", test.as_str()),
        ];
        let outcome =
            qualified_member_outcome(&files, "analysis/tests/t.rs", "analyzer.import_statements");
        let mut signatures = outcome
            .definitions
            .iter()
            .map(|unit| unit.signature().unwrap_or_default().to_owned())
            .collect::<Vec<_>>();
        signatures.sort();
        let tie = outcome.diagnostics.iter().any(|diagnostic| {
            diagnostic.kind == "unordered_candidates"
                || diagnostic.message.contains("inconsistent_precedence")
        });
        signatures.push(format!("tie={tie}"));
        signatures
    }

    const IANALYZER_ITEM: &str =
        "impl IAnalyzer for JavascriptAnalyzer::fn import_statements(&self) -> u8 { ... }";
    const JSTS_ITEM: &str =
        "impl JsTsSource for JavascriptAnalyzer::fn import_statements(&self) -> u8 { ... }";

    /// rustc considers a trait's method for a method call only when the trait
    /// is in scope where the call is written. With `IAnalyzer` imported and
    /// `JsTsSource` not, the call is `IAnalyzer`'s. Found by the point-answer
    /// census (2026-09-24): Bifrost's JavaScript and TypeScript import tests
    /// answered a tie between the two.
    #[test]
    #[hardwon("6b483a993525: an out of scope trait method was admitted as a candidate")]
    fn a_trait_method_out_of_scope_at_the_call_is_not_a_candidate() {
        assert_eq!(
            trait_scope_outcome("use core_crate::iface::IAnalyzer;"),
            vec![IANALYZER_ITEM.to_owned(), "tie=false".to_owned()]
        );
    }

    /// With both traits in scope the call is rustc's E0034, and stays a tie.
    #[test]
    #[hardwon("6b483a993525: scope filtering must preserve the real E0034 tie")]
    fn two_trait_methods_in_scope_at_the_call_stay_a_tie() {
        assert_eq!(
            trait_scope_outcome(
                "use core_crate::iface::IAnalyzer;\nuse core_crate::source::JsTsSource;"
            ),
            vec![
                IANALYZER_ITEM.to_owned(),
                JSTS_ITEM.to_owned(),
                "tie=true".to_owned()
            ]
        );
    }

    /// A glob import brings a trait into scope as a named import does.
    #[test]
    #[hardwon("6b483a993525: a trait introduced by a glob import was omitted")]
    fn a_trait_in_scope_through_a_glob_import_is_a_candidate() {
        assert_eq!(
            trait_scope_outcome("use core_crate::iface::*;"),
            vec![IANALYZER_ITEM.to_owned(), "tie=false".to_owned()]
        );
    }

    /// A test module two packages' integration tests splice in with
    /// `include!`, each host naming the dependency's items through a glob
    /// import (tract's `api/tests/mobilenet/mod.rs`). The spliced file's
    /// lookups are lowered in the host's stage, so the context anchors they
    /// select decode to that staged catalog. The anchor check accepted only
    /// a persisted catalog and failed every point request in the file with a
    /// store error (678 tract sites in the point-answer census, 2026-09-24).
    #[test]
    #[hardwon("b29b68d51e93: included source used the wrong staged catalog at its host")]
    fn an_include_spliced_module_resolves_through_its_hosts_glob_imports() {
        for both_hosts in [false, true] {
            let mut files = vec![
                (
                    "Cargo.toml",
                    "[workspace]\nmembers = [\"api/rs\", \"api/proxy\"]\nresolver = \"2\"\n",
                ),
                (
                    "api/rs/Cargo.toml",
                    "[package]\nname = \"tract\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                ),
                (
                    "api/rs/src/lib.rs",
                    "pub struct Thing;\nimpl Thing {\n    pub fn make() -> Thing {\n        Thing\n    }\n}\n",
                ),
                (
                    "api/proxy/Cargo.toml",
                    "[package]\nname = \"tract-proxy\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ntract = { path = \"../rs\" }\n",
                ),
                ("api/proxy/src/lib.rs", "pub use tract::Thing;\n"),
                (
                    "api/tests/mobilenet/mod.rs",
                    "fn build() -> Thing {\n    Thing::make()\n}\n",
                ),
                (
                    "api/rs/tests/mobilenet.rs",
                    "use tract::*;\n\ninclude!(\"../../tests/mobilenet/mod.rs\");\n",
                ),
            ];
            if both_hosts {
                files.push((
                    "api/proxy/tests/mobilenet.rs",
                    "use tract_proxy::*;\n\ninclude!(\"../../tests/mobilenet/mod.rs\");\n",
                ));
            }
            let outcome =
                qualified_member_outcome(&files, "api/tests/mobilenet/mod.rs", "Thing::make");
            let names = outcome
                .definitions
                .iter()
                .map(|unit| unit.short_name().to_owned())
                .collect::<Vec<_>>();
            assert_eq!(names, vec!["Thing.make".to_owned()], "{outcome:?}");
            assert_eq!(
                outcome.status,
                crate::analyzer::usages::get_definition::DefinitionLookupStatus::Resolved,
                "{outcome:?}"
            );
        }
    }

    /// A trait whose body writes `Self::` gets a `Self` lower bound through a
    /// reference the producer writes to the trait's own name. That reference
    /// is the producer's device, not something a user wrote, so it publishes
    /// no range: no reference row spans the trait (the point-answer census
    /// found 31 such rows answering `invalid_location`), and the `Self::`
    /// path still resolves through the bound.
    #[test]
    #[hardwon("f2faba63346c: a synthetic Self lower bound published a fake source span")]
    fn a_traits_self_lower_bound_publishes_no_reference_row() {
        let source = "pub trait Model {\n    type Fact;\n    fn fact(&self) -> Self::Fact;\n}\n";
        let outcome = qualified_member_outcome(&[("t.rs", source)], "t.rs", "Self::Fact");
        let names = outcome
            .definitions
            .iter()
            .map(|unit| unit.short_name().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["Model.Fact".to_owned()], "{outcome:?}");

        let project = InlineTestProject::new().file("t.rs", source).build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let spans = conn
            .prepare(
                "SELECT count(*) FROM resolution_sites WHERE role=0 AND start_byte=0 AND end_byte=?1",
            )
            .unwrap()
            .query_row([source.trim_end().len()], |row| row.get::<_, i64>(0))
            .unwrap();
        assert_eq!(spans, 0, "a reference row spans the trait declaration");
    }

    const RECEIVER_SHAPES: &str = "pub struct T;\nimpl T {\n    pub fn b(&self) -> u8 {\n        1\n    }\n}\npub struct S {\n    pub ts: Vec<T>,\n}\nimpl S {\n    pub fn maybe(&self) -> Result<T, ()> {\n        Ok(T)\n    }\n    pub fn opt(&self) -> Option<T> {\n        None\n    }\n}\n";

    /// `value?.member()` takes the member on the operand's value with one
    /// `Result` or `Option` layer removed, as a `?` let initializer does. The
    /// receiver slot had no producer, and the answer was incomplete with
    /// `missing-slot-producer` (the point-answer census, 2026-09-24).
    #[test]
    #[hardwon("365b87dd9c25: try receiver slots lost their operand producer")]
    fn a_try_receiver_reaches_the_unwrapped_values_member() {
        for body in [
            "fn f(s: S) -> Result<(), ()> { s.maybe()?.b(); Ok(()) }",
            "fn f(s: S) -> Option<()> { s.opt()?.b(); None }",
        ] {
            let source = format!("{RECEIVER_SHAPES}{body}\n");
            let outcome = qualified_member_outcome(&[("t.rs", &source)], "t.rs", "?.b");
            let names = outcome
                .definitions
                .iter()
                .map(|unit| unit.short_name().to_owned())
                .collect::<Vec<_>>();
            assert_eq!(names, vec!["T.b".to_owned()], "{body}: {outcome:?}");
            assert_eq!(
                outcome.status,
                crate::analyzer::usages::get_definition::DefinitionLookupStatus::Resolved,
                "{body}: {outcome:?}"
            );
        }
    }

    /// An index receiver has no value type the producer models, so the
    /// member answers incomplete, and the reason is the receiver slot's own
    /// unsupported-expression gap, a fragment-local reason, not the
    /// operation's `missing-slot-producer` service reason.
    #[test]
    #[hardwon("365b87dd9c25: an index receiver reported the wrong incomplete reason")]
    fn an_index_receivers_member_names_its_unsupported_receiver() {
        let source = format!("{RECEIVER_SHAPES}fn f(s: S) {{ s.ts[0].b(); }}\n");
        let outcome = qualified_member_outcome(&[("t.rs", &source)], "t.rs", "].b");
        assert!(outcome.definitions.is_empty(), "{outcome:?}");
        assert_eq!(
            outcome.status,
            crate::analyzer::usages::get_definition::DefinitionLookupStatus::Incomplete,
            "{outcome:?}"
        );
        assert!(
            outcome
                .diagnostics
                .iter()
                .all(|diagnostic| !diagnostic.message.contains("SemanticId#op:")),
            "the reason is the slot's own gap: {outcome:?}"
        );
    }

    /// A method on the result of `into()` over an `impl Into<PathBuf>` value
    /// is not a decided absence: `NormalizePath::normalize` is implemented
    /// for `PathBuf` and rustc calls it. `Into` is a prelude name, so the
    /// bound, the value's type and the conversion's result are open, not
    /// empty. Found by the missing-slot-producer re-sweep (2026-09-25): 46
    /// sites such as Bifrost's `root.into().canonicalize()?.normalize()`
    /// answered `NoDefinition`.
    #[test]
    fn a_member_on_an_into_conversion_is_not_a_decided_absence() {
        let lib = "use std::path::PathBuf;\npub trait NormalizePath {\n    fn normalize(self) -> PathBuf;\n}\nimpl NormalizePath for PathBuf {\n    fn normalize(self) -> PathBuf {\n        self\n    }\n}\npub fn f(p: impl Into<PathBuf>) {\n    let c = p.into();\n    c.normalize();\n}\n";
        let outcome = prelude_outcome("2021", lib, "c.normalize");
        assert_ne!(
            outcome.status,
            crate::analyzer::usages::get_definition::DefinitionLookupStatus::NoDefinition,
            "{outcome:?}"
        );
    }

    /// Opaque external type identities travel through normal type transfers.
    /// They can name a candidate but never prove external member completeness.
    #[test]
    #[hardwon("0f37730c3963: external import identity was lost through receiver type flow")]
    fn a_workspace_impl_for_an_external_type_supplies_the_receivers_member() {
        use crate::analyzer::usages::get_definition::DefinitionLookupStatus;
        let head = "use std::path::PathBuf;\npub trait NormalizePath {\n    fn normalize(&self) -> u8;\n}\nimpl NormalizePath for PathBuf {\n    fn normalize(&self) -> u8 { 7 }\n}\n";
        for (body, expected) in [
            ("pub fn f(c: PathBuf) { c.normalize(); }", 1),
            (
                "pub fn f(p: impl Into<PathBuf>) { let c: PathBuf = p.into(); c.normalize(); }",
                1,
            ),
            ("pub fn f(c: &PathBuf) { c.normalize(); }", 1),
            ("pub fn f(c: Box<PathBuf>) { c.normalize(); }", 1),
            ("pub fn f(c: Option<PathBuf>) { c.normalize(); }", 0),
            ("pub fn f(c: *const PathBuf) { c.normalize(); }", 0),
            (
                "pub fn f(value: Option<PathBuf>) { let c = value.unwrap(); c.normalize(); }",
                1,
            ),
        ] {
            let outcome = prelude_outcome("2021", &format!("{head}{body}\n"), "c.normalize");
            let names = outcome
                .definitions
                .iter()
                .map(|unit| unit.fq_name())
                .collect::<Vec<_>>();
            assert_ne!(
                outcome.status,
                DefinitionLookupStatus::Resolved,
                "{body}: {outcome:?}"
            );
            assert_eq!(names.len(), expected, "{body}: {outcome:?}");
            if expected != 0 {
                assert_eq!(
                    outcome.status,
                    DefinitionLookupStatus::Incomplete,
                    "{outcome:?}"
                );
                assert!(names[0].ends_with("PathBuf.normalize"), "{body}: {names:?}");
            }
        }
    }

    #[test]
    #[hardwon("0f37730c3963: external aliases and same-spelled local types shared an identity")]
    fn external_subject_identity_keeps_aliases_and_unrelated_bindings_distinct() {
        use crate::analyzer::usages::get_definition::DefinitionLookupStatus;
        for (source, expected) in [
            (
                "use std::path::PathBuf as Buffer; trait N { fn normalize(&self); } impl N for Buffer { fn normalize(&self) {} } fn f(c: Buffer) { c.normalize(); }",
                1,
            ),
            (
                "mod left { use std::path::PathBuf; pub trait N { fn normalize(&self); } impl N for PathBuf { fn normalize(&self) {} } } mod right { use std::ffi::PathBuf; use crate::left::N; fn f(c: PathBuf) { c.normalize(); } }",
                0,
            ),
            (
                "use std::path::PathBuf; mod hidden { use super::PathBuf; pub trait N { fn normalize(&self); } impl N for PathBuf { fn normalize(&self) {} } } fn f(c: PathBuf) { c.normalize(); }",
                0,
            ),
            (
                "use std::path::PathBuf; mod visible { use super::PathBuf; pub trait N { fn normalize(&self); } impl N for PathBuf { fn normalize(&self) {} } } use visible::N; fn f(c: PathBuf) { c.normalize(); }",
                1,
            ),
        ] {
            let outcome = prelude_outcome("2021", source, "c.normalize");
            assert_ne!(
                outcome.status,
                DefinitionLookupStatus::Resolved,
                "{source}: {outcome:?}"
            );
            assert_eq!(outcome.definitions.len(), expected, "{source}: {outcome:?}");
        }
    }

    /// The status and boundary names a point answer gives `path` in a crate
    /// of `edition` whose root file is `lib`.
    fn prelude_outcome(
        edition: &str,
        lib: &str,
        path: &str,
    ) -> crate::analyzer::usages::get_definition::DefinitionLookupOutcome {
        let manifest =
            format!("[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"{edition}\"\n");
        qualified_member_outcome(
            &[("Cargo.toml", manifest.as_str()), ("src/lib.rs", lib)],
            "src/lib.rs",
            path,
        )
    }

    /// An unqualified type or value name that no scope binds falls through to
    /// the crate's implicit std prelude, which Bifrost does not index: an open
    /// boundary, never a proved absence, in type, bound and value positions
    /// alike, and members of a value typed through it are not decided absent.
    #[test]
    #[hardwon("f5fb9c487416: prelude names were incorrectly treated as proved absences")]
    fn a_prelude_name_is_an_unindexed_import_boundary() {
        use crate::analyzer::usages::get_definition::DefinitionLookupStatus::UnresolvableImportBoundary;
        for (lib, path) in [
            ("pub fn f(v: Vec<u8>) {}\n", "Vec"),
            ("pub fn f(p: impl Clone) {}\n", "Clone"),
            ("pub fn f() { let x = Some(1); }\n", "Some"),
            ("pub fn f() { let v = Vec::<u8>::new(); }\n", "Vec"),
            ("pub fn f(p: impl Clone) { p.clone(); }\n", "p.clone"),
            ("pub fn f<P: Clone>(p: P) { p.clone(); }\n", "p.clone"),
            (
                "pub fn f<P>(p: P) where P: Clone { p.clone(); }\n",
                "p.clone",
            ),
        ] {
            let outcome = prelude_outcome("2021", lib, path);
            assert_eq!(
                outcome.status, UnresolvableImportBoundary,
                "{lib}: {outcome:?}"
            );
        }
    }

    /// A lexical binding of a prelude name wins over the prelude, as in rustc.
    /// A struct's private constructor is such a binding in its own module.
    #[test]
    #[hardwon("f5fb9c487416: a local item must shadow its implicit prelude spelling")]
    fn a_local_item_shadows_the_prelude() {
        for (lib, name) in [
            ("pub type A = Vec;\npub struct Vec;\n", "Vec"),
            (
                "pub fn f() { let _ = Some(1); }\nstruct Some(u8);\n",
                "Some",
            ),
            ("pub fn f() { let _ = None; }\nstruct None;\n", "None"),
        ] {
            let outcome = prelude_outcome("2021", lib, name);
            let names = outcome
                .definitions
                .iter()
                .map(|unit| unit.short_name().to_owned())
                .collect::<Vec<_>>();
            assert_eq!(names, vec![name.to_owned()], "{lib}: {outcome:?}");
            assert_eq!(
                outcome.status,
                crate::analyzer::usages::get_definition::DefinitionLookupStatus::Resolved,
                "{lib}: {outcome:?}"
            );
        }
    }

    /// A struct pattern reads the fields its path names: for `E::V { .. }`
    /// that is the variant's own member scope, not the enum's, exactly as a
    /// struct literal writes them. Explicit and shorthand fields alike.
    #[test]
    #[hardwon("#3746: a variant pattern field resolved against the enum scope")]
    fn a_variant_struct_pattern_field_resolves_on_the_variant() {
        for body in [
            "pub fn f(e: E) { let E::V { ty: x } = e; let _ = x; }\n",
            "pub fn f(e: E) { match e { E::V { ty } => { let _ = ty; } } }\n",
        ] {
            let lib = format!("{body}pub enum E {{ V {{ ty: u8 }} }}\n");
            let outcome = prelude_outcome("2021", &lib, "ty");
            let names = outcome
                .definitions
                .iter()
                .map(|unit| unit.fq_name())
                .collect::<Vec<_>>();
            assert_eq!(names, vec!["demo.E.V.ty".to_owned()], "{body}: {outcome:?}");
            assert_eq!(
                outcome.status,
                crate::analyzer::usages::get_definition::DefinitionLookupStatus::Resolved,
                "{body}: {outcome:?}"
            );
        }
    }

    /// The crate's edition and prelude kind decide the name set: `TryFrom`
    /// joined the prelude in 2021, `#![no_std]` selects core's prelude, which
    /// has `Option` but not `String`, and `#![no_core]` has no prelude.
    #[test]
    #[hardwon("f5fb9c487416: edition and no_std prelude names were classified incorrectly")]
    fn the_crates_edition_and_prelude_kind_select_the_prelude_names() {
        use crate::analyzer::usages::get_definition::DefinitionLookupStatus::{
            NoDefinition, UnresolvableImportBoundary,
        };
        for (edition, lib, path, expected) in [
            (
                "2018",
                "pub fn f(v: impl TryFrom<u8>) {}\n",
                "TryFrom",
                NoDefinition,
            ),
            (
                "2021",
                "pub fn f(v: impl TryFrom<u8>) {}\n",
                "TryFrom",
                UnresolvableImportBoundary,
            ),
            (
                "2021",
                "#![no_std]\npub fn f(v: Option<u8>) {}\n",
                "Option",
                UnresolvableImportBoundary,
            ),
            (
                "2021",
                "#![no_std]\npub fn f(v: String) {}\n",
                "String",
                NoDefinition,
            ),
            (
                "2021",
                "#![no_core]\npub fn f(v: Option<u8>) {}\n",
                "Option",
                NoDefinition,
            ),
        ] {
            let outcome = prelude_outcome(edition, lib, path);
            assert_eq!(outcome.status, expected, "{edition} {lib}: {outcome:?}");
        }
    }

    const UNNAMEABLE_TRAIT_TIE: &str = "use std::fmt::Display;\nstruct Service;\ntrait Two {\n    fn fmt(&self) {}\n}\nimpl Display for Service {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        Ok(())\n    }\n}\nimpl Two for Service {}\n\nfn caller(service: Service, f: &mut std::fmt::Formatter<'_>) {\n    service.fmt(f);\n}\n";

    /// An impl item of a trait the rows cannot name (here `std::fmt::Display`)
    /// is one trait candidate among the receiver's others. An in-scope trait
    /// whose default supplies the same method makes the call E0034, and the
    /// answer keeps both candidates with the cause named. With no such trait,
    /// the item answers alone and complete: the rows enumerated every trait the
    /// call site can name, and none supplies the method.
    #[test]
    #[hardwon("21a0f8b34f4a: an unnameable trait item was lost from a real candidate tie")]
    fn an_impl_item_of_an_unnameable_trait_meets_the_nameable_traits() {
        use crate::analyzer::usages::get_definition::DefinitionLookupStatus;

        let alone = "use std::fmt::Display;\nstruct Service;\nimpl Display for Service {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        Ok(())\n    }\n}\n\nfn caller(service: Service, f: &mut std::fmt::Formatter<'_>) {\n    service.fmt(f);\n}\n";
        let unrelated = "use std::fmt::Display;\nstruct Service;\ntrait Two {\n    fn other(&self) {}\n}\nimpl Display for Service {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        Ok(())\n    }\n}\nimpl Two for Service {}\n\nfn caller(service: Service, f: &mut std::fmt::Formatter<'_>) {\n    service.fmt(f);\n}\n";
        for (label, source) in [("alone", alone), ("unrelated trait", unrelated)] {
            assert_eq!(
                qualified_member_definitions(&[("t.rs", source)], "t.rs", "service.fmt"),
                (
                    DefinitionLookupStatus::Resolved,
                    vec!["Service.fmt".to_owned()]
                ),
                "{label}"
            );
        }

        let outcome =
            qualified_member_outcome(&[("t.rs", UNNAMEABLE_TRAIT_TIE)], "t.rs", "service.fmt");
        let names = outcome
            .definitions
            .iter()
            .map(|unit| unit.short_name().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            (outcome.status, names),
            (
                DefinitionLookupStatus::Ambiguous,
                vec!["Service.fmt".to_owned(), "Two.fmt".to_owned()]
            ),
            "{outcome:?}"
        );
        assert!(
            outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "unordered_candidates"),
            "the ambiguity names its cause: {outcome:?}"
        );
    }

    /// The reverse half: the unnameable trait's impl item and the nameable
    /// trait's default each see the tied call as a usage they cannot prove.
    #[test]
    #[hardwon(
        "21a0f8b34f4a: both candidates in an unnameable-trait tie need unproven reverse edges"
    )]
    fn an_unnameable_trait_items_tie_is_an_unproven_usage_of_each_candidate() {
        for (line, symbol) in [(7, "Service.fmt"), (4, "Two.fmt")] {
            assert_one_unproven_usage(&scan_usages_at(UNNAMEABLE_TRAIT_TIE, line), symbol, 14);
        }
    }
}
