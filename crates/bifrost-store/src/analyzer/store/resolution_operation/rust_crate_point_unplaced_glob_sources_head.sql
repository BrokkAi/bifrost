-- The `unplaced_module` gap rows of every module that the module at ?1
-- (topology) and ?2 (module path) reaches through glob imports, itself
-- included. A name absent from a glob source's persisted export set is a
-- proven absence only while the selected root still places that source. When
-- the selection unplaced it (`rust_selected_module_placements_fill.sql`), its
-- current content is unknown, so the lookup owes the same incomplete answer a
-- found name already gets (`RustCrateExport::unplaced`).
--
-- Rust's binding precedence bounds the walk by the requested name ?4 in
-- namespace ?3 ('' asks every namespace). An explicit binding of the name in a
-- placed module (a declaration or a named import, never a glob alternative)
-- shadows whatever its glob imports could supply, so the walk neither reports
-- nor follows past that module. The persisted bindings describe the persisted
-- files, so they stop the walk only while the selection changes none of the
-- files placed at that module: an unplaced module, or one with an overlaid
-- (replaced or removed) placed file, never stops it. An overlay that adds an
-- explicit declaration just keeps the walk going, which fails closed.
--
-- A lookup with a block or function binder scope never stops on an explicit
-- binding: a block-scoped `use` shadows the enclosing module's items, so the
-- unplaced glob source may be what supplies the name. The stop applies to a
-- module-scope lookup only. This file and the `_tail` file are the two halves
-- of the arm; each caller splices between them the predicate that says its
-- lookup is scoped (`rust_crate_context.rs`).
--
-- Both persisted binding certificates close over the persisted export sets of
-- glob sources; this arm is their selection-time correction. The guard makes
-- the walk empty on every connection without an overlay that unplaced a module,
-- and the walk follows the glob chain of one module, never the workspace.
-- Spliced as one arm of a UNION ALL of gap-detail rows.
SELECT DISTINCT json(reached.detail) FROM (
 WITH RECURSIVE walk(summary_id, unit_key, module_path) AS (
  SELECT unit.summary_id, unit.unit_key, ?2
  FROM selected_rust_unit_summaries AS unit
  WHERE unit.topology_id=?1
    AND EXISTS(SELECT 1 FROM temp.selected_rust_unplaced_gaps)
  UNION
  SELECT target.summary_id, target.unit_key, glob.target_module_path
  FROM walk
  CROSS JOIN main.rust_resolution_unit_summary_glob_imports AS glob
   ON glob.summary_id=walk.summary_id AND glob.module_path=walk.module_path
  CROSS JOIN selected_rust_unit_summaries AS target
   ON target.unit_key=glob.target_unit_key
  WHERE EXISTS(SELECT 1 FROM temp.selected_rust_unplaced_gaps AS unplaced
               WHERE unplaced.summary_id=walk.summary_id AND unplaced.subject=walk.module_path)
     OR EXISTS(SELECT 1 FROM temp.rust_unit_summary_placements AS placed
               CROSS JOIN main.resolution_unit_summary_members AS member
                ON member.summary_id=placed.summary_id AND member.member_ordinal=placed.member_ordinal
               WHERE placed.summary_id=walk.summary_id AND placed.module_path=walk.module_path
                 AND (EXISTS(SELECT 1 FROM temp.selected_resolution_overlay_masks AS mask
                             WHERE mask.storage_language='rust'
                               AND mask.persisted_relative_path=member.rel_path)
                   OR EXISTS(SELECT 1 FROM temp.selected_resolution_content_mounts AS mount
                             WHERE mount.storage_language='rust'
                               AND mount.persisted_relative_path=member.rel_path)))
     OR 