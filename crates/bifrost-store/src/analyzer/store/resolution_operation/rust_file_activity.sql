-- The one definition of whether a Rust file, or one placement of it, is
-- compiled (#11639). It has two grains and one rule. A reader appends this text
-- after a CTE it defines itself, and reads the CTE of the grain it asks about:
--   `probe(summary_id, rel_path)`                       -> `file_activity`
--   `placement_probe(summary_id, rel_path, module_path)` -> `placement_activity`
-- Only the CTE a reader reads needs its probe; SQLite never resolves an unused CTE.
--
-- activation, per unit summary and file (or file and module path), from the
-- stored rows of that summary:
--   1   some placement of the file is active and not on or under the subject
--       of an `unknown_activation` gap (a module another file may also place,
--       or one whose cfg is undecided);
--   0   the file has no active placement, every inactive placement row of it
--       has activation 0, and no gap of the summary names it as undecided,
--       unplaced or duplicated: no configuration compiles it, so it is inactive
--       through every route (`#[cfg(any())] mod caller;` and every module it
--       declares);
--   -1  any other mix, and a file only such a gap names: nothing is proved.
-- No row is produced for a pair the summary stores no placement or gap of.
--
-- At placement grain the same rule reads the rows at one module path. A module
-- path with both an active and an inactive row is -1: two declarations create
-- that placement and the rows do not say which is which, so neither the active
-- nor the inactive verdict is attributable to a declaration.
--
-- The rows are the persisted ones. A selection that overlays a file of the unit
-- can make an inactive row stale (the overlay may re-activate the module). The
-- reverse-reference gate (BLOB_PLACEMENT_ACTIVITY) therefore downgrades 0 to -1
-- for such a unit. The route index stays on persisted rows: for a file placed
-- only inactively it already fails closed (the file is routed incompletely,
-- `file_is_test_only` is an error and `package_contains` is incomplete).
--
-- Active placements are `resolution_unit_summary_placements`. Inactive ones
-- are `rust_resolution_unit_summary_inactive_placements`, which holds a row for
-- every module the walk reached through a non-active route, including the
-- descendants of an inactive or undecided module and every duplicate
-- placement. The `inactive_placement` gaps hold only the first inactive route
-- of each chain, so they cannot say that such a descendant is inactive. A gap
-- names its file in `$.path` and its module path in `subject`.
file_activity(summary_id, rel_path, activation) AS MATERIALIZED (
 SELECT summary_id, rel_path, activation FROM (
  SELECT probe.summary_id, probe.rel_path,
   CASE
    WHEN EXISTS (
     SELECT 1 FROM main.resolution_unit_summary_members AS member
     CROSS JOIN main.resolution_unit_summary_placements AS placement
      ON placement.summary_id=member.summary_id AND placement.member_ordinal=member.member_ordinal
     WHERE member.summary_id=probe.summary_id AND member.rel_path=probe.rel_path
      AND NOT EXISTS (
       SELECT 1 FROM main.rust_resolution_unit_summary_gaps AS gap
       WHERE gap.summary_id=placement.summary_id AND gap.gap_kind='unknown_activation'
        AND (gap.subject=placement.container_path
         OR substr(placement.container_path,1,length(gap.subject)+2)=gap.subject || '::')
      )
    ) THEN 1
    WHEN NOT EXISTS (
     SELECT 1 FROM main.resolution_unit_summary_members AS member
     CROSS JOIN main.resolution_unit_summary_placements AS placement
      ON placement.summary_id=member.summary_id AND placement.member_ordinal=member.member_ordinal
     WHERE member.summary_id=probe.summary_id AND member.rel_path=probe.rel_path
    ) AND EXISTS (
     SELECT 1 FROM main.resolution_unit_summary_input_files AS input
     CROSS JOIN main.rust_resolution_unit_summary_inactive_placements AS inactive
      ON inactive.summary_id=input.summary_id AND inactive.input_file_ordinal=input.input_ordinal
     WHERE input.summary_id=probe.summary_id AND input.rel_path=probe.rel_path
    ) AND NOT EXISTS (
     SELECT 1 FROM main.resolution_unit_summary_input_files AS input
     CROSS JOIN main.rust_resolution_unit_summary_inactive_placements AS inactive
      ON inactive.summary_id=input.summary_id AND inactive.input_file_ordinal=input.input_ordinal
     WHERE input.summary_id=probe.summary_id AND input.rel_path=probe.rel_path
      AND inactive.activation<>0
    ) AND NOT EXISTS (
     SELECT 1 FROM main.rust_resolution_unit_summary_gaps AS gap
     WHERE gap.summary_id=probe.summary_id
      AND gap.gap_kind IN ('unknown_activation','unplaced_module','duplicate_placement')
      AND json_extract(gap.detail, '$.path')=probe.rel_path
    ) THEN 0
    WHEN EXISTS (
     SELECT 1 FROM main.resolution_unit_summary_members AS member
     CROSS JOIN main.resolution_unit_summary_placements AS placement
      ON placement.summary_id=member.summary_id AND placement.member_ordinal=member.member_ordinal
     WHERE member.summary_id=probe.summary_id AND member.rel_path=probe.rel_path
    ) OR EXISTS (
     SELECT 1 FROM main.resolution_unit_summary_input_files AS input
     CROSS JOIN main.rust_resolution_unit_summary_inactive_placements AS inactive
      ON inactive.summary_id=input.summary_id AND inactive.input_file_ordinal=input.input_ordinal
     WHERE input.summary_id=probe.summary_id AND input.rel_path=probe.rel_path
    ) OR EXISTS (
     SELECT 1 FROM main.rust_resolution_unit_summary_gaps AS gap
     WHERE gap.summary_id=probe.summary_id
      AND gap.gap_kind IN ('unknown_activation','unplaced_module','duplicate_placement')
      AND json_extract(gap.detail, '$.path')=probe.rel_path
    ) THEN -1
   END AS activation
  FROM probe
 ) WHERE activation IS NOT NULL
),
placement_activity(summary_id, rel_path, module_path, activation) AS MATERIALIZED (
 SELECT summary_id, rel_path, module_path, activation FROM (
  SELECT probe.summary_id, probe.rel_path, probe.module_path,
   CASE
    WHEN EXISTS (
     SELECT 1 FROM main.resolution_unit_summary_members AS member
     CROSS JOIN main.resolution_unit_summary_placements AS placement
      ON placement.summary_id=member.summary_id AND placement.member_ordinal=member.member_ordinal
     WHERE member.summary_id=probe.summary_id AND member.rel_path=probe.rel_path
      AND CASE placement.container_path WHEN '' THEN 'crate' ELSE placement.container_path END=probe.module_path
      AND NOT EXISTS (
       SELECT 1 FROM main.rust_resolution_unit_summary_gaps AS gap
       WHERE gap.summary_id=placement.summary_id AND gap.gap_kind='unknown_activation'
        AND (gap.subject=probe.module_path
         OR substr(probe.module_path,1,length(gap.subject)+2)=gap.subject || '::')
      )
    ) AND NOT EXISTS (
     SELECT 1 FROM main.resolution_unit_summary_input_files AS input
     CROSS JOIN main.rust_resolution_unit_summary_inactive_placements AS inactive
      ON inactive.summary_id=input.summary_id AND inactive.input_file_ordinal=input.input_ordinal
     WHERE input.summary_id=probe.summary_id AND input.rel_path=probe.rel_path
      AND inactive.module_path=probe.module_path
    ) THEN 1
    WHEN NOT EXISTS (
     SELECT 1 FROM main.resolution_unit_summary_members AS member
     CROSS JOIN main.resolution_unit_summary_placements AS placement
      ON placement.summary_id=member.summary_id AND placement.member_ordinal=member.member_ordinal
     WHERE member.summary_id=probe.summary_id AND member.rel_path=probe.rel_path
      AND CASE placement.container_path WHEN '' THEN 'crate' ELSE placement.container_path END=probe.module_path
    ) AND EXISTS (
     SELECT 1 FROM main.resolution_unit_summary_input_files AS input
     CROSS JOIN main.rust_resolution_unit_summary_inactive_placements AS inactive
      ON inactive.summary_id=input.summary_id AND inactive.input_file_ordinal=input.input_ordinal
     WHERE input.summary_id=probe.summary_id AND input.rel_path=probe.rel_path
      AND inactive.module_path=probe.module_path
    ) AND NOT EXISTS (
     SELECT 1 FROM main.resolution_unit_summary_input_files AS input
     CROSS JOIN main.rust_resolution_unit_summary_inactive_placements AS inactive
      ON inactive.summary_id=input.summary_id AND inactive.input_file_ordinal=input.input_ordinal
     WHERE input.summary_id=probe.summary_id AND input.rel_path=probe.rel_path
      AND inactive.module_path=probe.module_path AND inactive.activation<>0
    ) AND NOT EXISTS (
     SELECT 1 FROM main.rust_resolution_unit_summary_gaps AS gap
     WHERE gap.summary_id=probe.summary_id
      AND gap.gap_kind IN ('unknown_activation','unplaced_module','duplicate_placement')
      AND gap.subject=probe.module_path
      AND json_extract(gap.detail, '$.path')=probe.rel_path
    ) THEN 0
    ELSE -1
   END AS activation
  FROM placement_probe AS probe
 )
)
