-- Reprove every container against the edited mount before admitting it.
--
-- Two checks gate a persisted placement. The local alignment below proves the
-- placement's module scope still exists in the selected mount of its own file.
-- The edge check proves the declaration that mounts a file as a module still
-- exists in the selected declaring file. A persisted placement records only the
-- state of the declaring file at the persisted revision, so an overlay (or a
-- removal) of a declaring file D can hide a module it used to declare while the
-- declared file keeps its own bytes and its own local alignment.
--
-- `changed` is the overlay mask set whose selected blob differs from the
-- persisted blob of the same path (a removal has no selected blob), so the
-- work follows the changed declaring files and never scans the workspace.
-- For each changed D, `old_edge` lists the persisted declared child edges: the
-- child containers whose parent container is placed in D and which are mounted
-- by `mod x;` or `#[path]`. `edge` lists the same parent and child module
-- paths from D's structured module routes, on the persisted blob (side 0) and
-- on the selected blob (side 1); both are built from the module paths of the
-- containers that place D, so no surface or dense ordinal is compared. An old
-- edge survives when the selected blob still declares the same module name
-- with the same `#[path]` attribute, its `cfg` is active under the summary's
-- cfg atoms (the target environment), no item macro gates it, and every
-- enclosing inline module is a plain active inline module. Included files are
-- the same comparison on D's include edges: a persisted include placement of a
-- file D included survives only while D's selected blob still includes that
-- path from an active scope of the same module (`inc_edge`, `dead_include`).
-- The persisted walk collapses several include routes to one file in one module
-- into a single placement, so that placement dies only when every host's edge
-- is dead: a changed host is judged by its selected blob, and an unchanged
-- co-host placed in the same container by its own blob (`cohost_roots`).
-- An inline module with `#[path]` stays in the scope chain, and its attribute is
-- part of the edge key, because it moves where its `mod child;` children resolve.
-- A persisted placement whose own module scope has no counterpart in the
-- selected blob of its file (the alignment below) is dead too; for an included
-- file's own root placement that kills the file (kind 1), not its host's container.
--
-- `dead` is the one worklist. A dead edge or failed alignment kills a whole
-- container and, through the container tree, every descendant container; a
-- dead included file kills its own placement and the child containers and
-- included files it declared. The result is recorded once in
-- temp.selected_rust_unplaced_placements: the selected placements omit them,
-- and the temp.rust_unit_summary_placements view (which every
-- persisted-placement reader goes through) and FILE_CRATES exclude them, so
-- no reader certifies a module the selected root no longer mounts. New
-- placements come only from the selected-source path, never from this relation.
--
-- Each unplaced placement also records its module path and file, which
-- temp.selected_rust_unplaced_gaps projects as `unplaced_module` gap rows keyed
-- like the persisted gaps (the module path is the subject).
-- A reader that turns a persisted gap into incompleteness unions that view, so it
-- reports a module this selection unplaced, instead of reading its absence as a
-- module without source files.
-- Statements 0-2 fill the placements of the CHANGED mounts only: a mount whose
-- selected blob differs from the persisted blob of its path (an overlay
-- replacement; a removal has no mount). A mount whose blob equals the persisted
-- one has exactly its persisted placements plus the sibling scopes the walk
-- persisted as inactive placements, so the selected_rust_container_placements
-- view serves it from the persisted tables by a keyed seek, minus the unplaced
-- set below. Driving the fill from the overlay masks makes its cost follow the
-- changed files, never the workspace.
--
-- The mirror direction is `temp.selected_rust_added_edges` (the last statement):
-- a module or include edge that a changed declaring file's selected blob holds
-- and the persisted topology lacks. Nothing places the module or file it names,
-- so a reader that treats "no placement" as "not part of the crate" would answer
-- Complete. A `mod x;` row names each file it can mount in `target_path`, by the
-- module walk's own rule (`cr_module_candidates`), so a reader that asks whether a
-- path is the target of an added edge also covers a new `x.rs`. Activation is three-valued (the rule is above the final SELECT): an
-- edge that is active or unknown in the selection is added unless the persisted
-- topology holds its counterpart. A selected active `mod x;` is added unless the persisted blob held
-- the same edge (same parent and child module path, same `#[path]` value, same
-- inline `#[path]` chain: the same target file, since the declaring file and its
-- own placement did not move) and a persisted declared placement exists at the
-- child module path. A selected active `include!` is added unless a persisted
-- include placement of that file exists in that module. A persisted edge that
-- was inactive (a removed `#[cfg(any())]`) does not count as a counterpart. The
-- gap view projects each row as an `unplaced_module` gap on the child module and
-- an `open_export_inventory` gap on the parent (or host) module. The work follows
-- the changed declaring files, as the unplacing worklist does, and reads only
-- their selected and persisted blobs and the persisted placements.
DELETE FROM temp.selected_rust_transient_placement_attributes;
DELETE FROM temp.selected_resolution_transient_placements;
INSERT INTO temp.selected_resolution_transient_placements
SELECT mount.mount_ordinal, members.summary_id, placement.container_path,
       members.member_ordinal, scope.ordinal
FROM selected_resolution_overlay_masks AS mask
CROSS JOIN selected_resolution_mounts AS mount
 ON mount.storage_language=mask.storage_language
AND mount.persisted_relative_path=mask.persisted_relative_path
CROSS JOIN source_rust_module_scopes AS scope ON scope.blob_id=mount.blob_id
CROSS JOIN selected_workspace_file_versions AS file
 ON file.lang=mount.storage_language AND file.rel_path=mount.persisted_relative_path
CROSS JOIN blobs AS base ON base.lang=file.lang AND base.blob_oid=file.blob_oid
 AND base.parse_variant=x''
CROSS JOIN main.resolution_unit_summary_members AS members
 INDEXED BY resolution_unit_summary_members_path
 ON members.rel_path=mount.persisted_relative_path
CROSS JOIN selected_rust_unit_summaries AS owner ON owner.summary_id=members.summary_id
CROSS JOIN main.resolution_unit_summary_placements AS placement
 INDEXED BY resolution_unit_summary_placements_surface_lookup
 ON placement.summary_id=members.summary_id
AND placement.member_ordinal=members.member_ordinal
WHERE mask.storage_language='rust' AND base.id<>mount.blob_id
 AND placement.scope_surface_ordinal IS NOT NULL
 AND EXISTS(SELECT 1 FROM temp.selected_unit_member_blobs AS attachment
            WHERE attachment.summary_id=members.summary_id
              AND attachment.member_ordinal=members.member_ordinal
              AND attachment.blob_id=base.id)
 AND EXISTS (
 WITH RECURSIVE aligned(old_scope,new_scope) AS (
  SELECT (SELECT scope_id.dense_id FROM temp.surface_dense AS scope_id
          WHERE scope_id.blob_id=base.id AND scope_id.id_space=7
            AND scope_id.surface_ordinal=placement.scope_surface_ordinal),scope.ordinal
  UNION ALL
  SELECT old.parent_ordinal,new.parent_ordinal FROM aligned
  CROSS JOIN source_rust_module_scopes AS old ON old.blob_id=base.id AND old.ordinal=aligned.old_scope
  CROSS JOIN source_rust_module_scopes AS new ON new.blob_id=mount.blob_id AND new.ordinal=aligned.new_scope
  WHERE old.module_name=new.module_name AND old.parent_ordinal IS NOT NULL AND new.parent_ordinal IS NOT NULL
 ) SELECT 1 FROM aligned WHERE old_scope=0 AND new_scope=0
 );

DELETE FROM temp.selected_rust_unplaced_placements;
INSERT INTO temp.selected_rust_unplaced_placements
WITH RECURSIVE
changed(rel_path, base_blob, new_blob) AS MATERIALIZED (
 SELECT mask.persisted_relative_path, base.id, mount.blob_id
 FROM selected_resolution_overlay_masks AS mask
 CROSS JOIN selected_workspace_file_versions AS file
  ON file.lang=mask.storage_language AND file.rel_path=mask.persisted_relative_path
 CROSS JOIN blobs AS base ON base.lang=file.lang AND base.blob_oid=file.blob_oid
  AND base.parse_variant=x''
 LEFT JOIN selected_resolution_mounts AS mount
  ON mount.storage_language=mask.storage_language
 AND mount.persisted_relative_path=mask.persisted_relative_path
 WHERE mask.storage_language='rust' AND base.id IS NOT mount.blob_id
), roots(summary_id, rel_path, root_module, atoms) AS MATERIALIZED (
 SELECT DISTINCT member.summary_id, changed.rel_path, attribute.module_path, json(context.cfg_atoms)
 FROM changed
 CROSS JOIN main.resolution_unit_summary_members AS member
  INDEXED BY resolution_unit_summary_members_path ON member.rel_path=changed.rel_path
 CROSS JOIN selected_rust_unit_summaries AS owner ON owner.summary_id=member.summary_id
 CROSS JOIN temp.selected_unit_member_blobs AS attachment
  ON attachment.summary_id=member.summary_id AND attachment.member_ordinal=member.member_ordinal
 AND attachment.blob_id=changed.base_blob
 CROSS JOIN main.rust_resolution_unit_summary_placement_attributes AS attribute
  ON attribute.summary_id=member.summary_id AND attribute.member_ordinal=member.member_ordinal
 AND attribute.placement NOT IN ('inline','enum_declaration')
 CROSS JOIN main.rust_resolution_unit_summary_contexts AS context ON context.summary_id=member.summary_id
), include_candidate(summary_id, container_path, member_ordinal, module_path, host_path, target_path) AS MATERIALIZED (
 -- Persisted include placements that a changed host D hosted: the placed file
 -- is the path D's persisted blob includes, in D's module or one below it.
 SELECT DISTINCT included_attribute.summary_id, included_attribute.container_path,
        included_attribute.member_ordinal, included_attribute.module_path,
        roots.rel_path, included_member.rel_path
 FROM roots
 CROSS JOIN changed ON changed.rel_path=roots.rel_path
 CROSS JOIN rust_include_edges AS include ON include.blob_id=changed.base_blob
 CROSS JOIN main.resolution_unit_summary_members AS included_member
  INDEXED BY resolution_unit_summary_members_path
  ON included_member.rel_path=cr_join(cr_parent(roots.rel_path), include.relative_path)
 AND included_member.summary_id=roots.summary_id
 CROSS JOIN main.rust_resolution_unit_summary_placement_attributes AS included_attribute
  ON included_attribute.summary_id=included_member.summary_id
 AND included_attribute.member_ordinal=included_member.member_ordinal
 AND included_attribute.source_kind='include'
 AND (included_attribute.module_path=roots.root_module
      OR included_attribute.module_path>roots.root_module||'::'
         AND included_attribute.module_path<roots.root_module||';')
), cohost_roots(summary_id, rel_path, base_blob, root_module, atoms) AS MATERIALIZED (
 -- The persisted walk collapses include routes into one placement per
 -- container, so a placement can have several declaring edges. The other files
 -- placed in the container of an include placement that a changed host hosted
 -- are its candidate co-hosts; an unchanged one is judged by its own blob, which
 -- is both its persisted and its selected blob.
 SELECT DISTINCT candidate.summary_id, other.rel_path, other.blob_id, attribute.module_path,
        json(context.cfg_atoms)
 FROM include_candidate AS candidate
 CROSS JOIN main.rust_resolution_unit_summary_placement_attributes AS co
  ON co.summary_id=candidate.summary_id AND co.container_path=candidate.container_path
 AND co.member_ordinal<>candidate.member_ordinal
 CROSS JOIN main.resolution_unit_summary_members AS other
  ON other.summary_id=co.summary_id AND other.member_ordinal=co.member_ordinal
 CROSS JOIN main.rust_resolution_unit_summary_placement_attributes AS attribute
  ON attribute.summary_id=other.summary_id AND attribute.member_ordinal=other.member_ordinal
 AND attribute.placement NOT IN ('inline','enum_declaration')
 CROSS JOIN main.rust_resolution_unit_summary_contexts AS context ON context.summary_id=other.summary_id
 WHERE other.rel_path NOT IN (SELECT rel_path FROM changed)
), sides(rel_path, side, blob_id) AS (
 SELECT rel_path, 0, base_blob FROM changed
 UNION ALL
 SELECT rel_path, 1, new_blob FROM changed WHERE new_blob IS NOT NULL
 UNION
 SELECT rel_path, 1, base_blob FROM cohost_roots
), scope_chain(rel_path, side, blob_id, ordinal, chain, cfgs, paths) AS (
 SELECT rel_path, side, blob_id, 0, '', '[]', '[]' FROM sides
 UNION ALL
 SELECT parent.rel_path, parent.side, parent.blob_id, scope.ordinal,
        CASE parent.chain WHEN '' THEN declaration.module_name
             ELSE parent.chain || '::' || declaration.module_name END,
        json_insert(parent.cfgs, '$[#]', property.cfg_condition),
        -- An inline #[path] moves the directory its `mod child;` children
        -- resolve against, so it is part of the edge key like the child's own.
        json_insert(parent.paths, '$[#]', declaration.path_attribute)
 FROM scope_chain AS parent
 CROSS JOIN source_rust_module_scopes AS scope
  ON scope.blob_id=parent.blob_id AND scope.parent_ordinal=parent.ordinal
 CROSS JOIN source_rust_module_declarations AS declaration
  ON declaration.blob_id=scope.blob_id AND declaration.declaration_id=scope.declaration_id
 CROSS JOIN source_rust_declaration_properties AS property
  ON property.blob_id=declaration.blob_id AND property.declaration_id=declaration.declaration_id
 CROSS JOIN source_declarations AS site
  ON site.blob_id=declaration.blob_id AND site.declaration_id=declaration.declaration_id
 WHERE declaration.body_occurrence_id IS NOT NULL
   AND NOT EXISTS(SELECT 1 FROM source_rust_item_macro_expansions AS invocation
                  WHERE invocation.blob_id=declaration.blob_id
                    AND invocation.invocation_start_byte<=site.start_byte
                    AND site.end_byte<=invocation.invocation_end_byte)
), edge(summary_id, side, parent_module, child_module, path_attribute, inline_paths, active) AS MATERIALIZED (
 SELECT roots.summary_id, scope.side,
        roots.root_module || CASE scope.chain WHEN '' THEN '' ELSE '::' || scope.chain END,
        roots.root_module || CASE scope.chain WHEN '' THEN '' ELSE '::' || scope.chain END
          || '::' || declaration.module_name,
        declaration.path_attribute, scope.paths,
        cr_cfg(property.cfg_condition, roots.atoms)=1
        AND NOT EXISTS(SELECT 1 FROM json_each(scope.cfgs) AS enclosing
                       WHERE cr_cfg(enclosing.value, roots.atoms)<>1)
        AND NOT EXISTS(SELECT 1 FROM source_rust_module_route_gates AS gate
                       WHERE gate.blob_id=route.blob_id AND gate.route_ordinal=route.ordinal)
 FROM roots
 CROSS JOIN scope_chain AS scope ON scope.rel_path=roots.rel_path
 CROSS JOIN source_rust_module_routes AS route
  ON route.blob_id=scope.blob_id AND route.scope_ordinal=scope.ordinal
 CROSS JOIN source_rust_module_declarations AS declaration
  ON declaration.blob_id=route.blob_id AND declaration.declaration_id=route.declaration_id
 AND declaration.body_occurrence_id IS NULL
 CROSS JOIN source_rust_declaration_properties AS property
  ON property.blob_id=declaration.blob_id AND property.declaration_id=declaration.declaration_id
), old_edge(summary_id, container_path, parent_module, child_module, declared_by_path) AS MATERIALIZED (
 SELECT member.summary_id, child.container_path, parent_attribute.module_path,
        child_attribute.module_path, child_attribute.placement='path_attribute'
 FROM changed
 CROSS JOIN main.resolution_unit_summary_members AS member
  INDEXED BY resolution_unit_summary_members_path ON member.rel_path=changed.rel_path
 CROSS JOIN selected_rust_unit_summaries AS owner ON owner.summary_id=member.summary_id
 CROSS JOIN temp.selected_unit_member_blobs AS attachment
  ON attachment.summary_id=member.summary_id AND attachment.member_ordinal=member.member_ordinal
 AND attachment.blob_id=changed.base_blob
 CROSS JOIN main.rust_resolution_unit_summary_placement_attributes AS parent_attribute
  ON parent_attribute.summary_id=member.summary_id
 AND parent_attribute.member_ordinal=member.member_ordinal
 AND parent_attribute.placement<>'enum_declaration'
 CROSS JOIN main.resolution_unit_summary_containers AS child
  ON child.summary_id=member.summary_id AND child.parent_container_path=parent_attribute.container_path
 CROSS JOIN main.rust_resolution_unit_summary_placement_attributes AS child_attribute
  ON child_attribute.summary_id=child.summary_id AND child_attribute.container_path=child.container_path
 AND child_attribute.placement IN ('mod_declaration','path_attribute')
 AND child_attribute.source_kind='declared'
 -- A module another file of the same container declares (the host of an
 -- include, or an included file) is judged by that file, not by D: a dead
 -- include reaches it through `dead`, and when that file is itself changed it is
 -- the D of its own edges. Only an ACTIVE declaration in that file mounts the
 -- module, by the same test `edge.active` applies at a file's top scope: its
 -- cfg is true for the unit and no macro gates its route. A cfg-false or
 -- undecided sibling `mod child;` proves nothing, so D's edge is still judged.
 WHERE NOT EXISTS(
  SELECT 1 FROM main.rust_resolution_unit_summary_placement_attributes AS sibling_attribute
  CROSS JOIN main.resolution_unit_summary_members AS sibling
   ON sibling.summary_id=sibling_attribute.summary_id
  AND sibling.member_ordinal=sibling_attribute.member_ordinal
  CROSS JOIN source_rust_module_routes AS sibling_route
   ON sibling_route.blob_id=sibling.blob_id AND sibling_route.scope_ordinal=0
  CROSS JOIN source_rust_module_declarations AS sibling_declaration
   ON sibling_declaration.blob_id=sibling_route.blob_id
  AND sibling_declaration.declaration_id=sibling_route.declaration_id
  CROSS JOIN source_rust_declaration_properties AS sibling_property
   ON sibling_property.blob_id=sibling_declaration.blob_id
  AND sibling_property.declaration_id=sibling_declaration.declaration_id
  CROSS JOIN main.rust_resolution_unit_summary_contexts AS sibling_context
   ON sibling_context.summary_id=sibling_attribute.summary_id
  WHERE sibling_attribute.summary_id=member.summary_id
    AND sibling_attribute.container_path=parent_attribute.container_path
    AND sibling_attribute.member_ordinal<>member.member_ordinal
    AND child_attribute.module_path=parent_attribute.module_path||'::'||sibling_declaration.module_name
    AND cr_cfg(sibling_property.cfg_condition, json(sibling_context.cfg_atoms))=1
    AND NOT EXISTS(SELECT 1 FROM source_rust_module_route_gates AS sibling_gate
                   WHERE sibling_gate.blob_id=sibling_route.blob_id
                     AND sibling_gate.route_ordinal=sibling_route.ordinal))
), host_roots(summary_id, rel_path, root_module, atoms) AS MATERIALIZED (
 SELECT summary_id, rel_path, root_module, atoms FROM roots
 UNION
 SELECT summary_id, rel_path, root_module, atoms FROM cohost_roots
), inc_edge(summary_id, side, rel_path, parent_module, target_path, active) AS MATERIALIZED (
 SELECT roots.summary_id, scope.side, roots.rel_path,
        roots.root_module || CASE scope.chain WHEN '' THEN '' ELSE '::' || scope.chain END,
        cr_join(cr_parent(roots.rel_path), include.relative_path),
        NOT EXISTS(SELECT 1 FROM json_each(scope.cfgs) AS enclosing
                   WHERE cr_cfg(enclosing.value, roots.atoms)<>1)
 FROM host_roots AS roots
 CROSS JOIN scope_chain AS scope ON scope.rel_path=roots.rel_path
 CROSS JOIN rust_include_edges AS include ON include.blob_id=scope.blob_id
 LEFT JOIN source_rust_module_scopes AS inline_scope
  ON inline_scope.blob_id=scope.blob_id AND inline_scope.ordinal=scope.ordinal
 LEFT JOIN source_rust_module_declarations AS inline_declaration
  ON inline_declaration.blob_id=inline_scope.blob_id
 AND inline_declaration.declaration_id=inline_scope.declaration_id
 -- The innermost scope holding the include, as the module walk chooses it.
 WHERE (scope.ordinal=0
        OR include.include_start BETWEEN inline_declaration.body_start_byte AND inline_declaration.body_end_byte-1)
   AND NOT EXISTS(
    SELECT 1 FROM source_rust_module_scopes AS inner_scope
    CROSS JOIN source_rust_module_declarations AS inner_declaration
     ON inner_declaration.blob_id=inner_scope.blob_id
    AND inner_declaration.declaration_id=inner_scope.declaration_id
    WHERE inner_scope.blob_id=scope.blob_id AND inner_scope.parent_ordinal=scope.ordinal
      AND include.include_start BETWEEN inner_declaration.body_start_byte AND inner_declaration.body_end_byte-1)
), dead_include(summary_id, container_path, member_ordinal) AS MATERIALIZED (
 -- Dead only when no host keeps an active include of the placed file in the
 -- module that holds it: a changed host is judged by its selected blob and an
 -- unchanged co-host by its own blob.
 SELECT candidate.summary_id, candidate.container_path, candidate.member_ordinal
 FROM include_candidate AS candidate
 WHERE NOT EXISTS(
  SELECT 1 FROM inc_edge AS selected
  WHERE selected.summary_id=candidate.summary_id AND selected.side=1 AND selected.active
    AND selected.parent_module=candidate.module_path
    AND selected.target_path=candidate.target_path)
), alive_include(summary_id, container_path, member_ordinal) AS (
 -- Include placements the selection still reaches, positively: a selected
 -- active include edge (host plus target, in the module that holds the
 -- placement) from a file placed in the same container otherwise than by an
 -- include (the container's own files), or from an include placement that is
 -- itself alive. An edge from a host that only the include walk reaches counts
 -- only while that host is alive, so removing the one edge that reached a host
 -- does not keep the files that host alone included, and a file another live
 -- host still includes survives the removal of one host. A dead container
 -- needs no entry: the container arm of `dead` kills every placement in it.
 SELECT included.summary_id, included.container_path, included.member_ordinal
 FROM inc_edge AS selected
 CROSS JOIN main.resolution_unit_summary_members AS host_member
  INDEXED BY resolution_unit_summary_members_path
  ON host_member.rel_path=selected.rel_path AND host_member.summary_id=selected.summary_id
 CROSS JOIN main.rust_resolution_unit_summary_placement_attributes AS host
  ON host.summary_id=host_member.summary_id AND host.member_ordinal=host_member.member_ordinal
 AND host.placement NOT IN ('inline','enum_declaration') AND host.source_kind<>'include'
 CROSS JOIN main.resolution_unit_summary_members AS target
  INDEXED BY resolution_unit_summary_members_path
  ON target.rel_path=selected.target_path AND target.summary_id=selected.summary_id
 CROSS JOIN main.rust_resolution_unit_summary_placement_attributes AS included
  ON included.summary_id=target.summary_id AND included.member_ordinal=target.member_ordinal
 AND included.source_kind='include' AND included.container_path=host.container_path
 AND included.module_path=selected.parent_module
 WHERE selected.side=1 AND selected.active
 UNION
 SELECT included.summary_id, included.container_path, included.member_ordinal
 FROM alive_include AS alive
 CROSS JOIN main.resolution_unit_summary_members AS host_member
  ON host_member.summary_id=alive.summary_id AND host_member.member_ordinal=alive.member_ordinal
 CROSS JOIN inc_edge AS selected
  ON selected.summary_id=alive.summary_id AND selected.rel_path=host_member.rel_path
 AND selected.side=1 AND selected.active
 CROSS JOIN main.resolution_unit_summary_members AS target
  INDEXED BY resolution_unit_summary_members_path
  ON target.rel_path=selected.target_path AND target.summary_id=selected.summary_id
 CROSS JOIN main.rust_resolution_unit_summary_placement_attributes AS included
  ON included.summary_id=target.summary_id AND included.member_ordinal=target.member_ordinal
 AND included.source_kind='include' AND included.container_path=alive.container_path
 AND included.module_path=selected.parent_module
), failed_alignment(summary_id, container_path, member_ordinal, included_file) AS MATERIALIZED (
 -- A persisted placement of a changed file whose module scope has no
 -- counterpart in the selected blob of that file (the aligned candidates);
 -- every placement of a removed file qualifies, as it has no selected blob.
 -- `included_file` marks the placement of an included file's own root scope:
 -- it sits in its host's container, so only that file dies, not the container.
 SELECT DISTINCT placement.summary_id, placement.container_path, placement.member_ordinal,
        attribute.source_kind='include' AND root_scope.dense_id=0
 FROM changed
 CROSS JOIN main.resolution_unit_summary_members AS members
  INDEXED BY resolution_unit_summary_members_path ON members.rel_path=changed.rel_path
 CROSS JOIN selected_rust_unit_summaries AS owner ON owner.summary_id=members.summary_id
 CROSS JOIN temp.selected_unit_member_blobs AS attachment
  ON attachment.summary_id=members.summary_id AND attachment.member_ordinal=members.member_ordinal
 AND attachment.blob_id=changed.base_blob
 CROSS JOIN main.resolution_unit_summary_placements AS placement
  INDEXED BY resolution_unit_summary_placements_surface_lookup
  ON placement.summary_id=members.summary_id AND placement.member_ordinal=members.member_ordinal
 CROSS JOIN main.rust_resolution_unit_summary_placement_attributes AS attribute
  ON attribute.summary_id=placement.summary_id AND attribute.container_path=placement.container_path
 AND attribute.member_ordinal=placement.member_ordinal
 CROSS JOIN temp.surface_dense AS root_scope
  ON root_scope.blob_id=changed.base_blob AND root_scope.id_space=7
 AND root_scope.surface_ordinal=placement.scope_surface_ordinal
 WHERE placement.scope_surface_ordinal IS NOT NULL
   AND NOT EXISTS(SELECT 1 FROM temp.selected_resolution_transient_placements AS kept
                  WHERE kept.summary_id=placement.summary_id
                    AND kept.container_path=placement.container_path
                    AND kept.member_ordinal=placement.member_ordinal)
), dead(kind, summary_id, container_path, member_ordinal) AS (
 -- kind 0: a whole container (every placement in it, then its child containers);
 -- kind 1: one included file placed in a live container, then whatever that
 -- file declares or includes.
 SELECT 0, summary_id, container_path, -1 FROM old_edge AS old
 WHERE NOT EXISTS(
  SELECT 1 FROM edge AS persisted
  CROSS JOIN edge AS selected
   ON selected.summary_id=persisted.summary_id AND selected.side=1
  AND selected.parent_module=persisted.parent_module AND selected.child_module=persisted.child_module
  AND selected.path_attribute IS persisted.path_attribute
  AND selected.inline_paths=persisted.inline_paths AND selected.active
  WHERE persisted.summary_id=old.summary_id AND persisted.side=0
    AND persisted.parent_module=old.parent_module AND persisted.child_module=old.child_module
    AND (persisted.path_attribute IS NOT NULL)=old.declared_by_path)
 UNION
 SELECT 0, summary_id, container_path, -1 FROM failed_alignment WHERE NOT included_file
 UNION
 SELECT 1, summary_id, container_path, member_ordinal FROM failed_alignment WHERE included_file
 UNION
 SELECT 1, summary_id, container_path, member_ordinal FROM dead_include
 UNION
 SELECT 0, child.summary_id, child.container_path, -1
 FROM dead
 CROSS JOIN main.resolution_unit_summary_containers AS child
  ON child.summary_id=dead.summary_id AND child.parent_container_path=dead.container_path
 WHERE dead.kind=0
 UNION
 SELECT 0, child.summary_id, child.container_path, -1
 FROM dead
 CROSS JOIN main.resolution_unit_summary_members AS member
  ON member.summary_id=dead.summary_id AND member.member_ordinal=dead.member_ordinal
 CROSS JOIN source_rust_module_routes AS route
  ON route.blob_id=member.blob_id AND route.scope_ordinal=0
 CROSS JOIN source_rust_module_declarations AS declaration
  ON declaration.blob_id=route.blob_id AND declaration.declaration_id=route.declaration_id
 CROSS JOIN main.resolution_unit_summary_containers AS child
  ON child.summary_id=dead.summary_id
 AND child.container_path=CASE dead.container_path WHEN '' THEN 'crate' ELSE dead.container_path END
                          || '::' || declaration.module_name
 WHERE dead.kind=1
 UNION
 SELECT 0, child.summary_id, child.container_path, -1
 FROM dead
 CROSS JOIN main.resolution_unit_summary_members AS member
  ON member.summary_id=dead.summary_id AND member.member_ordinal=dead.member_ordinal
 CROSS JOIN source_rust_module_scopes AS scope
  ON scope.blob_id=member.blob_id AND scope.parent_ordinal=0
 CROSS JOIN source_rust_module_declarations AS declaration
  ON declaration.blob_id=scope.blob_id AND declaration.declaration_id=scope.declaration_id
 CROSS JOIN main.resolution_unit_summary_containers AS child
  ON child.summary_id=dead.summary_id
 AND child.container_path=CASE dead.container_path WHEN '' THEN 'crate' ELSE dead.container_path END
                          || '::' || declaration.module_name
 WHERE dead.kind=1
 UNION
 SELECT 1, included.summary_id, included.container_path, included.member_ordinal
 FROM dead
 CROSS JOIN main.resolution_unit_summary_members AS member
  ON member.summary_id=dead.summary_id AND member.member_ordinal=dead.member_ordinal
 CROSS JOIN rust_include_edges AS include ON include.blob_id=member.blob_id
 CROSS JOIN main.resolution_unit_summary_members AS included_member
  INDEXED BY resolution_unit_summary_members_path
  ON included_member.rel_path=cr_join(cr_parent(member.rel_path), include.relative_path)
 AND included_member.summary_id=dead.summary_id
 CROSS JOIN main.rust_resolution_unit_summary_placement_attributes AS included
  ON included.summary_id=included_member.summary_id
 AND included.member_ordinal=included_member.member_ordinal
 AND included.source_kind='include'
 AND included.container_path=dead.container_path
 -- A dead host kills only what no live host still includes (the edge that
 -- reached the file is the host's, not the file's).
 WHERE dead.kind=1
   AND NOT EXISTS(SELECT 1 FROM alive_include AS alive
                  WHERE alive.summary_id=included.summary_id
                    AND alive.container_path=included.container_path
                    AND alive.member_ordinal=included.member_ordinal)
)
SELECT unplaced.summary_id, unplaced.container_path, unplaced.member_ordinal,
       attribute.module_path, member.rel_path
FROM (
 SELECT summary_id, container_path, member_ordinal
 FROM dead WHERE kind=1
 UNION
 SELECT placement.summary_id, placement.container_path, placement.member_ordinal
 FROM dead
 CROSS JOIN main.resolution_unit_summary_placements AS placement
  ON placement.summary_id=dead.summary_id AND placement.container_path=dead.container_path
 WHERE dead.kind=0
) AS unplaced
CROSS JOIN main.resolution_unit_summary_members AS member
 ON member.summary_id=unplaced.summary_id AND member.member_ordinal=unplaced.member_ordinal
LEFT JOIN main.rust_resolution_unit_summary_placement_attributes AS attribute
 ON attribute.summary_id=unplaced.summary_id AND attribute.container_path=unplaced.container_path
AND attribute.member_ordinal=unplaced.member_ordinal;

-- The aligned placements above are only the candidates: one exclusion serves
-- the selected placements and every reader of the persisted view.
-- Driven by the unplaced rows, so the cost follows them and not the table.
DELETE FROM temp.selected_resolution_transient_placements
WHERE (mount_ordinal, summary_id, container_path, member_ordinal, scope_ordinal) IN (
 SELECT kept.mount_ordinal, kept.summary_id, kept.container_path, kept.member_ordinal, kept.scope_ordinal
 FROM temp.selected_rust_unplaced_placements AS unplaced
 CROSS JOIN temp.selected_resolution_transient_placements AS kept
  ON kept.summary_id=unplaced.summary_id AND kept.container_path=unplaced.container_path
 AND kept.member_ordinal=unplaced.member_ordinal);

INSERT INTO temp.selected_rust_transient_placement_attributes
 SELECT p.mount_ordinal, p.summary_id, p.container_path, p.member_ordinal, p.scope_ordinal, scope.declaration_id
 FROM selected_resolution_transient_placements AS p
 JOIN selected_resolution_mounts AS mount ON mount.mount_ordinal=p.mount_ordinal
 JOIN source_rust_module_scopes AS scope
   ON scope.blob_id=mount.blob_id AND scope.ordinal=p.scope_ordinal;

DELETE FROM temp.selected_rust_added_edges;
INSERT INTO temp.selected_rust_added_edges
WITH RECURSIVE
changed(rel_path, base_blob, new_blob) AS MATERIALIZED (
 SELECT mask.persisted_relative_path, base.id, mount.blob_id
 FROM selected_resolution_overlay_masks AS mask
 CROSS JOIN selected_workspace_file_versions AS file
  ON file.lang=mask.storage_language AND file.rel_path=mask.persisted_relative_path
 CROSS JOIN blobs AS base ON base.lang=file.lang AND base.blob_oid=file.blob_oid
  AND base.parse_variant=x''
 LEFT JOIN selected_resolution_mounts AS mount
  ON mount.storage_language=mask.storage_language
 AND mount.persisted_relative_path=mask.persisted_relative_path
 WHERE mask.storage_language='rust' AND base.id IS NOT mount.blob_id
), roots(summary_id, rel_path, root_module, atoms) AS MATERIALIZED (
 SELECT DISTINCT member.summary_id, changed.rel_path, attribute.module_path, json(context.cfg_atoms)
 FROM changed
 CROSS JOIN main.resolution_unit_summary_members AS member
  INDEXED BY resolution_unit_summary_members_path ON member.rel_path=changed.rel_path
 CROSS JOIN selected_rust_unit_summaries AS owner ON owner.summary_id=member.summary_id
 CROSS JOIN temp.selected_unit_member_blobs AS attachment
  ON attachment.summary_id=member.summary_id AND attachment.member_ordinal=member.member_ordinal
 AND attachment.blob_id=changed.base_blob
 CROSS JOIN main.rust_resolution_unit_summary_placement_attributes AS attribute
  ON attribute.summary_id=member.summary_id AND attribute.member_ordinal=member.member_ordinal
 -- A file included inside an inline module sits in that inline container, so
 -- its include placement is a root even though the container is inline.
 AND (attribute.placement NOT IN ('inline','enum_declaration')
      OR attribute.placement='inline' AND attribute.source_kind='include')
 CROSS JOIN main.rust_resolution_unit_summary_contexts AS context ON context.summary_id=member.summary_id
), ancestors(summary_id, module_path) AS (
 -- The modules a root sits in and the modules above them, by point seeks up the
 -- container tree, so the work follows the changed files and their depth.
 SELECT DISTINCT summary_id, root_module FROM roots
 UNION
 SELECT child.summary_id, CASE child.parent_container_path WHEN '' THEN 'crate' ELSE child.parent_container_path END
 FROM ancestors AS up
 CROSS JOIN main.resolution_unit_summary_containers AS child
  ON child.summary_id=up.summary_id
 AND child.container_path=CASE up.module_path WHEN 'crate' THEN '' ELSE up.module_path END
 WHERE child.parent_container_path IS NOT NULL
), container_dirs(summary_id, module_path, module_dir, path_dir) AS (
 -- The directories the module walk carries for a module (`module_dir` for the
 -- children of an ordinary `mod x;`, `path_dir` for a `#[path]` value). A module
 -- opened by a file has them from that file: the walk derives them from the file
 -- it mounted, and `cr_module_file_dir` inverts that step. An inline module has
 -- no opening file and takes the walk's inline step (`cr_module_candidate` with
 -- an empty suffix) from its parent's directories and its own declaration in the
 -- persisted blob of the file that declares it. An included file belongs to its
 -- host's module, so it is judged by that module's directories.
 SELECT opening.summary_id, opening.module_path,
        cr_module_file_dir(opening.placement, opener.rel_path), cr_parent(opener.rel_path)
 FROM ancestors
 CROSS JOIN main.rust_resolution_unit_summary_placement_attributes AS opening
  ON opening.summary_id=ancestors.summary_id AND opening.module_path=ancestors.module_path
 AND opening.source_kind='declared' AND opening.placement NOT IN ('inline','enum_declaration')
 CROSS JOIN main.resolution_unit_summary_members AS opener
  ON opener.summary_id=opening.summary_id AND opener.member_ordinal=opening.member_ordinal
 UNION
 SELECT parent.summary_id, inline.module_path,
        cr_module_candidate(parent.module_dir, parent.path_dir, declaration.module_name, declaration.path_attribute, ''),
        cr_module_candidate(parent.module_dir, parent.path_dir, declaration.module_name, declaration.path_attribute, '')
 FROM container_dirs AS parent
 CROSS JOIN ancestors AS below ON below.summary_id=parent.summary_id
 CROSS JOIN main.resolution_unit_summary_containers AS child
  ON child.summary_id=below.summary_id
 AND child.container_path=CASE below.module_path WHEN 'crate' THEN '' ELSE below.module_path END
 AND CASE child.parent_container_path WHEN '' THEN 'crate' ELSE child.parent_container_path END=parent.module_path
 CROSS JOIN main.rust_resolution_unit_summary_placement_attributes AS inline
  ON inline.summary_id=child.summary_id AND inline.container_path=child.container_path
 AND inline.placement='inline' AND inline.source_kind='declared'
 CROSS JOIN main.resolution_unit_summary_members AS declaring
  ON declaring.summary_id=inline.summary_id AND declaring.member_ordinal=inline.member_ordinal
 -- The declaration is the one the placement's own scope stands for (the same
 -- scope identity the alignment above uses), not any declaration of that name:
 -- one file can declare same-named inline modules under different parents.
 CROSS JOIN main.resolution_unit_summary_placements AS placed
  ON placed.summary_id=inline.summary_id AND placed.container_path=inline.container_path
 AND placed.member_ordinal=inline.member_ordinal
 CROSS JOIN temp.surface_dense AS scope_id
  ON scope_id.blob_id=declaring.blob_id AND scope_id.id_space=7
 AND scope_id.surface_ordinal=placed.scope_surface_ordinal
 CROSS JOIN source_rust_module_scopes AS inline_scope
  ON inline_scope.blob_id=declaring.blob_id AND inline_scope.ordinal=scope_id.dense_id
 CROSS JOIN source_rust_module_declarations AS declaration
  ON declaration.blob_id=inline_scope.blob_id AND declaration.declaration_id=inline_scope.declaration_id
), module_dirs(summary_id, rel_path, root_module, module_dir, path_dir) AS MATERIALIZED (
 -- Unknown directories (a module whose opener the persisted rows do not hold)
 -- leave NULLs, never a missing row: the edge and its gaps are still emitted,
 -- with a NULL target.
 SELECT DISTINCT roots.summary_id, roots.rel_path, roots.root_module, dirs.module_dir, dirs.path_dir
 FROM roots
 LEFT JOIN container_dirs AS dirs
  ON dirs.summary_id=roots.summary_id AND dirs.module_path=roots.root_module
), sides(rel_path, side, blob_id) AS (
 SELECT rel_path, 0, base_blob FROM changed
 UNION ALL
 SELECT rel_path, 1, new_blob FROM changed WHERE new_blob IS NOT NULL
), scope_chain(rel_path, side, blob_id, ordinal, chain, cfgs, paths, parent_chain,
               summary_id, root_module, module_dir, path_dir) AS (
 SELECT sides.rel_path, side, blob_id, 0, '', '[]', '[]', '',
        dirs.summary_id, dirs.root_module, dirs.module_dir, dirs.path_dir
 FROM sides
 CROSS JOIN module_dirs AS dirs ON dirs.rel_path=sides.rel_path
 UNION ALL
 SELECT parent.rel_path, parent.side, parent.blob_id, scope.ordinal,
        CASE parent.chain WHEN '' THEN declaration.module_name
             ELSE parent.chain || '::' || declaration.module_name END,
        json_insert(parent.cfgs, '$[#]', property.cfg_condition),
        json_insert(parent.paths, '$[#]', declaration.path_attribute), parent.chain,
        parent.summary_id, parent.root_module,
        cr_module_candidate(parent.module_dir, parent.path_dir, declaration.module_name, declaration.path_attribute, ''),
        cr_module_candidate(parent.module_dir, parent.path_dir, declaration.module_name, declaration.path_attribute, '')
 FROM scope_chain AS parent
 CROSS JOIN source_rust_module_scopes AS scope
  ON scope.blob_id=parent.blob_id AND scope.parent_ordinal=parent.ordinal
 CROSS JOIN source_rust_module_declarations AS declaration
  ON declaration.blob_id=scope.blob_id AND declaration.declaration_id=scope.declaration_id
 CROSS JOIN source_rust_declaration_properties AS property
  ON property.blob_id=declaration.blob_id AND property.declaration_id=declaration.declaration_id
 CROSS JOIN source_declarations AS site
  ON site.blob_id=declaration.blob_id AND site.declaration_id=declaration.declaration_id
 WHERE declaration.body_occurrence_id IS NOT NULL
   AND NOT EXISTS(SELECT 1 FROM source_rust_item_macro_expansions AS invocation
                  WHERE invocation.blob_id=declaration.blob_id
                    AND invocation.invocation_start_byte<=site.start_byte
                    AND site.end_byte<=invocation.invocation_end_byte)
), edge_raw(summary_id, side, rel_path, parent_module, child_module, path_attribute, inline_paths, activation, gated, macro_use, candidates) AS MATERIALIZED (
 -- `activation` is three-valued like cr_cfg: 0 when the declaration's own cfg
 -- or an enclosing inline module's cfg is provably false, 1 when every one is
 -- provably true, -1 otherwise. An item macro that gates the route can only
 -- make it unknown or false, so `edge` below lowers a gated 1 to -1.
 SELECT roots.summary_id, scope.side, roots.rel_path,
        roots.root_module || CASE scope.chain WHEN '' THEN '' ELSE '::' || scope.chain END,
        roots.root_module || CASE scope.chain WHEN '' THEN '' ELSE '::' || scope.chain END
          || '::' || declaration.module_name,
        declaration.path_attribute, scope.paths,
        (SELECT CASE WHEN COALESCE(SUM(a=0),0)>0 THEN 0
                     WHEN COALESCE(SUM(a=1),0)=COUNT(*) THEN 1 ELSE -1 END
         FROM (SELECT cr_cfg(each.value, roots.atoms) AS a
               FROM json_each(json_insert(scope.cfgs, '$[#]', property.cfg_condition)) AS each)),
        EXISTS(SELECT 1 FROM source_rust_module_route_gates AS gate
               WHERE gate.blob_id=route.blob_id AND gate.route_ordinal=route.ordinal),
        declaration.macro_use,
        -- The files the declaration can mount, by the walk's own rule.
        cr_module_candidates(scope.module_dir, scope.path_dir, declaration.module_name, declaration.path_attribute)
 FROM roots
 CROSS JOIN scope_chain AS scope ON scope.rel_path=roots.rel_path
 AND scope.summary_id=roots.summary_id AND scope.root_module=roots.root_module
 CROSS JOIN source_rust_module_routes AS route
  ON route.blob_id=scope.blob_id AND route.scope_ordinal=scope.ordinal
 CROSS JOIN source_rust_module_declarations AS declaration
  ON declaration.blob_id=route.blob_id AND declaration.declaration_id=route.declaration_id
 AND declaration.body_occurrence_id IS NULL
 CROSS JOIN source_rust_declaration_properties AS property
  ON property.blob_id=declaration.blob_id AND property.declaration_id=declaration.declaration_id
), edge(summary_id, side, rel_path, parent_module, child_module, path_attribute, inline_paths, activation, macro_use, gated, candidates) AS (
 SELECT summary_id, side, rel_path, parent_module, child_module, path_attribute, inline_paths,
        CASE WHEN activation=1 AND gated THEN -1 ELSE activation END, macro_use, gated, candidates
 FROM edge_raw
), inc_edge(summary_id, side, rel_path, parent_module, target_path, activation) AS MATERIALIZED (
 SELECT roots.summary_id, scope.side, roots.rel_path,
        roots.root_module || CASE scope.chain WHEN '' THEN '' ELSE '::' || scope.chain END,
        cr_join(cr_parent(roots.rel_path), include.relative_path),
        (SELECT CASE WHEN COALESCE(SUM(a=0),0)>0 THEN 0
                     WHEN COALESCE(SUM(a=1),0)=COUNT(*) THEN 1 ELSE -1 END
         FROM (SELECT cr_cfg(each.value, roots.atoms) AS a FROM json_each(scope.cfgs) AS each))
 FROM roots
 CROSS JOIN scope_chain AS scope ON scope.rel_path=roots.rel_path
 AND scope.summary_id=roots.summary_id AND scope.root_module=roots.root_module
 CROSS JOIN rust_include_edges AS include ON include.blob_id=scope.blob_id
 LEFT JOIN source_rust_module_scopes AS inline_scope
  ON inline_scope.blob_id=scope.blob_id AND inline_scope.ordinal=scope.ordinal
 LEFT JOIN source_rust_module_declarations AS inline_declaration
  ON inline_declaration.blob_id=inline_scope.blob_id
 AND inline_declaration.declaration_id=inline_scope.declaration_id
 -- The innermost scope holding the include, as the module walk chooses it.
 WHERE (scope.ordinal=0
        OR include.include_start BETWEEN inline_declaration.body_start_byte AND inline_declaration.body_end_byte-1)
   AND NOT EXISTS(
    SELECT 1 FROM source_rust_module_scopes AS inner_scope
    CROSS JOIN source_rust_module_declarations AS inner_declaration
     ON inner_declaration.blob_id=inner_scope.blob_id
    AND inner_declaration.declaration_id=inner_scope.declaration_id
    WHERE inner_scope.blob_id=scope.blob_id AND inner_scope.parent_ordinal=scope.ordinal
      AND include.include_start BETWEEN inner_declaration.body_start_byte AND inner_declaration.body_end_byte-1)
)
-- An edge is added when it is not provably inactive in the selection (`activation`
-- 1 or -1) and has no counterpart in the persisted topology. The counterpart must
-- agree in kind: a persisted edge of the same key that was active and is placed
-- vouches for a selected active edge, and a persisted edge that was unknown
-- vouches for a selected unknown one (the persisted topology holds its
-- `unknown_activation` gap). Every other pairing is an addition: an unknown
-- selected edge has no placement and no gap of its own when the persisted blob
-- lacked it or held it inactive, and a selected edge that turned unknown or
-- active against the other state is not what the persisted rows describe.
SELECT DISTINCT selected.summary_id, selected.parent_module, selected.child_module, candidate.value, selected.rel_path, selected.macro_use
FROM edge AS selected
LEFT JOIN json_each(selected.candidates) AS candidate ON 1
WHERE selected.side=1 AND selected.activation<>0 AND NOT selected.gated
  AND NOT EXISTS(
   SELECT 1 FROM edge AS persisted
   WHERE persisted.summary_id=selected.summary_id AND persisted.side=0
     AND persisted.rel_path=selected.rel_path
     AND persisted.parent_module=selected.parent_module
     AND persisted.child_module=selected.child_module
     AND persisted.path_attribute IS selected.path_attribute
     AND persisted.inline_paths=selected.inline_paths
     AND ((selected.activation=-1 AND persisted.activation=-1)
          OR (selected.activation=1 AND persisted.activation=1
              AND EXISTS(
               SELECT 1 FROM main.rust_resolution_unit_summary_placement_attributes AS placed
               WHERE placed.summary_id=selected.summary_id
                 AND placed.container_path=selected.child_module
                 AND placed.source_kind='declared'
                 AND placed.placement=CASE WHEN selected.path_attribute IS NULL
                                           THEN 'mod_declaration' ELSE 'path_attribute' END))))
UNION
-- An inline `mod x { .. }` the selected blob holds and the persisted blob did not
-- (same chain of inline modules, same `#[path]` chain) has no persisted
-- placement either: its scope has no aligned counterpart to place. The same
-- three-valued rule applies to the chain's cfgs.
SELECT roots.summary_id,
       roots.root_module || CASE selected.parent_chain WHEN '' THEN '' ELSE '::' || selected.parent_chain END,
       roots.root_module || '::' || selected.chain, NULL, roots.rel_path, 0
FROM roots
CROSS JOIN scope_chain AS selected ON selected.rel_path=roots.rel_path AND selected.side=1
 AND selected.summary_id=roots.summary_id AND selected.root_module=roots.root_module
WHERE selected.chain<>''
  AND (SELECT CASE WHEN COALESCE(SUM(a=0),0)>0 THEN 0
                   WHEN COALESCE(SUM(a=1),0)=COUNT(*) THEN 1 ELSE -1 END
       FROM (SELECT cr_cfg(each.value, roots.atoms) AS a FROM json_each(selected.cfgs) AS each))<>0
  AND NOT EXISTS(
   SELECT 1 FROM scope_chain AS persisted
   WHERE persisted.rel_path=selected.rel_path AND persisted.side=0
     AND persisted.summary_id=selected.summary_id AND persisted.root_module=selected.root_module
     AND persisted.chain=selected.chain AND persisted.paths=selected.paths
     AND (SELECT CASE WHEN COALESCE(SUM(a=0),0)>0 THEN 0
                      WHEN COALESCE(SUM(a=1),0)=COUNT(*) THEN 1 ELSE -1 END
          FROM (SELECT cr_cfg(each.value, roots.atoms) AS a FROM json_each(persisted.cfgs) AS each))
         =(SELECT CASE WHEN COALESCE(SUM(a=0),0)>0 THEN 0
                       WHEN COALESCE(SUM(a=1),0)=COUNT(*) THEN 1 ELSE -1 END
           FROM (SELECT cr_cfg(each.value, roots.atoms) AS a FROM json_each(selected.cfgs) AS each)))
UNION
-- An include is added the same way: a selected edge that is not provably inactive
-- and no persisted placement (active) or persisted unknown edge (unknown) of
-- that file in that module.
SELECT selected.summary_id, selected.parent_module, NULL, selected.target_path, selected.rel_path, 1
FROM inc_edge AS selected
WHERE selected.side=1 AND selected.activation<>0
  AND NOT EXISTS(
   SELECT 1 FROM main.resolution_unit_summary_members AS target
    INDEXED BY resolution_unit_summary_members_path
   CROSS JOIN main.rust_resolution_unit_summary_placement_attributes AS placed
    ON placed.summary_id=target.summary_id AND placed.member_ordinal=target.member_ordinal
   AND placed.source_kind='include' AND placed.module_path=selected.parent_module
   WHERE selected.activation=1
     AND target.rel_path=selected.target_path AND target.summary_id=selected.summary_id)
  AND NOT EXISTS(
   SELECT 1 FROM inc_edge AS persisted
   WHERE selected.activation=-1 AND persisted.summary_id=selected.summary_id
     AND persisted.side=0 AND persisted.activation=-1
     AND persisted.rel_path=selected.rel_path
     AND persisted.parent_module=selected.parent_module
     AND persisted.target_path=selected.target_path);


-- The gap rows of the unplaced placements and the added edges, in the persisted
-- gap shape (the module path is the subject); see
-- temp.selected_rust_unplaced_gaps.
DELETE FROM temp.selected_rust_overlay_gaps;
INSERT INTO temp.selected_rust_overlay_gaps
SELECT summary_id, 'unplaced_module', module_path,
       jsonb_object('path', rel_path, 'activation', 1,
                    'evidence', jsonb_array(jsonb_object(
                     'reason', 'OverlayUnplacedModule', 'rel_path', rel_path)))
FROM temp.selected_rust_unplaced_placements
WHERE module_path IS NOT NULL
UNION ALL
SELECT DISTINCT summary_id, 'unplaced_module', child_module,
       jsonb_object('path', rel_path, 'activation', 1,
                    'evidence', jsonb_array(jsonb_object(
                     'reason', 'OverlayAddedModule', 'rel_path', rel_path)))
FROM temp.selected_rust_added_edges
WHERE child_module IS NOT NULL
UNION ALL
SELECT DISTINCT summary_id, 'open_export_inventory', parent_module,
       jsonb_object('path', rel_path, 'activation', 1,
                    'evidence', jsonb_array(jsonb_object(
                     'reason', 'OverlayAddedModule', 'rel_path', rel_path)))
FROM temp.selected_rust_added_edges;
