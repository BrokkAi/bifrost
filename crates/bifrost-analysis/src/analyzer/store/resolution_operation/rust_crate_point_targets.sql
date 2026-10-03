-- Every (topology, module path, name) a lookup of name ?4 in module ?2 of
-- topology ?1 reaches, as seen from module ?6 of topology ?5: re-export
-- routes, glob re-exports, the named imports and glob imports that bind in
-- the requesting module and its ancestors, and the crate-wide macro scope.
-- The export lookup (`rust_crate_point_export.sql`) and the external binding
-- lookup (`rust_crate_point_external.sql`) and inventory completeness lookup
-- (`rust_crate_point_inventory.sql`) continue from this walk; ?3 is
-- the namespace.
-- Retain only whether a route has been followed: private named imports and
-- macro-root lookup distinguish the seed from subsequent targets. Including
-- path depth in UNION identity revisits cycles at every depth and duplicates
-- inventory evidence. This finite fixed point also reaches chains beyond 64
-- hops without silently losing their terminal declarations or open inventory.
WITH RECURSIVE targets(topology_id, module_path, name, followed) AS (
 SELECT ?1, ?2, ?4, 0
 UNION
 SELECT dependency.topology_id, route.target_module_path, route.target_name, 1
 FROM targets
 CROSS JOIN rust_crate_reexport_routes AS route ON route.topology_id=targets.topology_id AND route.module_path=targets.module_path AND route.bound_name=targets.name
 CROSS JOIN selected_rust_crates AS dependency ON dependency.crate_key=route.target_crate_key
 WHERE (route.visibility='public' OR (targets.topology_id=?5 AND (route.visibility='crate' OR (route.visibility='private' AND (?6=route.module_path OR substr(?6,1,length(route.module_path)+2)=route.module_path || '::')) OR (route.visibility='restricted' AND (?6=route.restricted_module_path OR substr(?6,1,length(route.restricted_module_path)+2)=route.restricted_module_path || '::')))))
 UNION
 SELECT dependency.topology_id, route.target_module_path, targets.name, 1
 FROM targets
 CROSS JOIN rust_crate_glob_reexport_routes AS route ON route.topology_id=targets.topology_id AND route.module_path=targets.module_path
 CROSS JOIN selected_rust_crates AS dependency ON dependency.crate_key=route.target_crate_key
 WHERE (route.visibility='public' OR (targets.topology_id=?5 AND (route.visibility='crate' OR (route.visibility='private' AND (?6=route.module_path OR substr(?6,1,length(route.module_path)+2)=route.module_path || '::')) OR (route.visibility='restricted' AND (?6=route.restricted_module_path OR substr(?6,1,length(route.restricted_module_path)+2)=route.restricted_module_path || '::')))))
  -- Re-exported globs have the same precedence as private glob imports:
  -- a declaration or spelled module-level import in this module wins.
  -- Test the module traversed here, not the requesting descendant; otherwise
  -- `use super::execution::...` can pick up the requester's child module
  -- through its parent's `pub use search::*`.
  AND NOT EXISTS(SELECT 1 FROM rust_crate_exports AS declared
                 WHERE declared.topology_id=targets.topology_id
                   AND declared.module_path=targets.module_path
                   AND declared.namespace=?3 AND declared.name=targets.name
                   AND declared.origin IN ('declaration','reexport'))
  AND NOT EXISTS(
       SELECT 1 FROM rust_crate_container_sources AS source
       CROSS JOIN source_rust_module_scopes AS scope
         ON scope.blob_id=source.blob_id AND scope.ordinal=source.scope_ordinal
       CROSS JOIN rust_crate_imports AS spelled
         ON spelled.topology_id=source.topology_id
         AND spelled.module_path=source.container_path
         AND spelled.blob_id=source.blob_id
         AND spelled.binder_scope=scope.resolution_scope
         AND spelled.namespace=?3 AND spelled.bound_name=targets.name
       WHERE source.topology_id=targets.topology_id
         AND source.container_path=targets.module_path)
 UNION
 SELECT dependency.topology_id, route.target_module_path, route.target_name, 1
 FROM targets
 CROSS JOIN rust_crate_container_sources AS source ON source.topology_id=targets.topology_id AND source.container_path=targets.module_path
 CROSS JOIN source_rust_module_scopes AS scope ON scope.blob_id=source.blob_id AND scope.ordinal=source.scope_ordinal
 CROSS JOIN rust_crate_imports AS route ON route.topology_id=source.topology_id AND route.module_path=source.container_path
  AND route.blob_id=source.blob_id AND route.binder_scope=scope.resolution_scope AND route.namespace=?3 AND route.bound_name=targets.name
 CROSS JOIN selected_rust_crates AS dependency ON dependency.crate_key=route.target_crate_key
 -- A row that binds a crate's root (`use dep as alias;`, target `crate`/`self`,
 -- `rust_crate_import_bindings.sql`) ends the walk with no export row to
 -- check visibility against, so the requester must see the import itself: a
 -- public one travels as a re-export route instead.
 WHERE (targets.followed=1 AND route.target_name<>'self')
    OR (targets.topology_id=?5 AND (?6=targets.module_path OR substr(?6,1,length(targets.module_path)+2)=targets.module_path || '::'))
 UNION
 -- A private import of an unlowered declaration has no resolved import row.
 -- Its source-backed terminal route still identifies the inventory to inspect.
 -- Follow that route rather than treating every unresolved import as open:
 -- a missing name in a closed target module remains a proved absence.
 SELECT dependency.topology_id, route.target_module_path, route.target_name, 1
 FROM targets
 CROSS JOIN rust_crate_gaps AS gap ON gap.topology_id=targets.topology_id
  AND gap.gap_kind='unresolved_import' AND gap.subject=targets.module_path || '::' || targets.name
 CROSS JOIN rust_crate_container_sources AS source ON source.topology_id=targets.topology_id AND source.container_path=targets.module_path
 CROSS JOIN source_rust_module_scopes AS scope ON scope.blob_id=source.blob_id AND scope.ordinal=source.scope_ordinal
 CROSS JOIN source_rust_import_targets AS imported ON imported.blob_id=source.blob_id
  AND imported.native_scope=scope.resolution_scope AND imported.bound_name=targets.name AND imported.is_glob=0
 CROSS JOIN rust_crate_root_references AS route ON route.topology_id=targets.topology_id
  AND route.module_path=targets.module_path AND route.blob_id=source.blob_id
 CROSS JOIN resolution_semantic_sites AS bridge ON bridge.blob_id=route.blob_id AND bridge.source_site=route.reference_source_site
 CROSS JOIN resolution_rust_reference_contexts AS reference ON reference.blob_id=bridge.blob_id
  AND reference.semantic_key=bridge.semantic_key AND reference.source_occurrence=imported.target_occurrence_id
 CROSS JOIN selected_rust_crates AS dependency ON dependency.crate_key=route.target_crate_key
 WHERE (targets.followed=1 OR (targets.topology_id=?5 AND (?6=targets.module_path OR substr(?6,1,length(targets.module_path)+2)=targets.module_path || '::')))
 UNION
 -- A module's own glob imports bind names in that module and in the modules
 -- it declares, whether or not the glob re-exports them.
 -- `rust_crate_glob_reexport_routes` carries only the non-private globs, so a
 -- private `use crate::*;` was invisible here and a name it binds looked like
 -- a route that left the workspace. The binding is private to the module that
 -- writes it, and a private binding is in scope in that module's descendants:
 -- `use crate::ops::*;` in `crate::mapping` is what `use super::*;` in
 -- `crate::mapping::test` re-exposes, and no export row records it. The
 -- named-import arm above already states that rule with the same predicate.
 -- The requesting module `?6` decides it, so a module the walk merely stepped
 -- into still contributes nothing.
 SELECT dependency.topology_id, glob.target_module_path, targets.name, 1
 FROM targets
 CROSS JOIN rust_crate_container_sources AS source ON source.topology_id=targets.topology_id AND source.container_path=targets.module_path
 CROSS JOIN source_rust_module_scopes AS scope ON scope.blob_id=source.blob_id AND scope.ordinal=source.scope_ordinal
 CROSS JOIN rust_crate_glob_imports AS glob ON glob.topology_id=source.topology_id AND glob.module_path=source.container_path
  AND glob.blob_id=source.blob_id AND glob.binder_scope=scope.resolution_scope
 CROSS JOIN selected_rust_crates AS dependency ON dependency.crate_key=glob.target_crate_key
 WHERE targets.topology_id=?5
  AND (?6=targets.module_path OR substr(?6,1,length(targets.module_path)+2)=targets.module_path || '::')
  -- A glob import is the weakest binder Rust has. An item the globbing
  -- module declares, and a name it imports by spelling, both shadow it, in
  -- that module -- not in the module asking. The shadow belongs to
  -- `targets.module_path`, the module that wrote the glob;
  -- `rust_crate_export_fixpoint.sql` states the same rule for the rows it
  -- derives, with the same `is_glob = 0` test.
  --
  -- The spelled half reuses `scope`, which is this module's own scope and is
  -- already what restricts the glob itself. That is what carries the binder
  -- scope: a `use` written inside a function has its own binder scope, shadows
  -- only within it, and does not match here. `data/src/dim/tree.rs` holds a
  -- function-local `use super::super::sym::SymbolValues;` while the module
  -- globs `sym::*`, and both the glob route and the local binding are right.
  AND NOT EXISTS(SELECT 1 FROM rust_crate_exports AS declared
                 WHERE declared.topology_id=targets.topology_id
                   AND declared.module_path=targets.module_path
                   AND declared.namespace=?3 AND declared.name=targets.name
                   AND declared.origin IN ('declaration','reexport'))
  AND NOT EXISTS(SELECT 1 FROM rust_crate_imports AS spelled
                 WHERE spelled.topology_id=source.topology_id
                   AND spelled.module_path=source.container_path
                   AND spelled.blob_id=source.blob_id
                   AND spelled.binder_scope=scope.resolution_scope
                   AND spelled.namespace=?3 AND spelled.bound_name=targets.name)
 UNION
 -- `#[macro_use] extern crate rocket;` is written at the crate root and binds
 -- the macros it imports for every module of the crate. That scope is the
 -- crate, not a lexical module: a `routes![..]` written in one file names a
 -- macro another file imported, and no module walk connects the two. A macro
 -- lookup that started in a module of the requesting crate therefore continues
 -- at that crate's root, which is where the import row is. Only the macro
 -- namespace continues: `#[macro_use]` imports macros, so a value or type name
 -- gets no crate-wide scope from it.
 SELECT targets.topology_id, 'crate', targets.name, 1
 FROM targets
 WHERE ?3='macro' AND targets.followed=0 AND targets.topology_id=?5
   AND targets.module_path<>'crate'
)
