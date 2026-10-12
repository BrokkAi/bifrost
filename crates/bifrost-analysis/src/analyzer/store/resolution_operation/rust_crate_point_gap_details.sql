WITH RECURSIVE graph(workspace_id, generation, unit_key, summary_id) AS (
 SELECT unit.workspace_id, unit.generation, unit.unit_key, unit.summary_id
 FROM selected_rust_unit_summaries AS unit
 CROSS JOIN main.rust_resolution_unit_summary_file_naming AS naming
  ON naming.summary_id=unit.summary_id
 CROSS JOIN main.resolution_unit_summary_members AS member
  ON member.summary_id=naming.summary_id AND member.member_ordinal=naming.member_ordinal
 WHERE member.rel_path=?1
 UNION
 SELECT child.workspace_id, child.generation, child.unit_key, child.summary_id
 FROM graph
 CROSS JOIN main.resolution_unit_summary_dependencies AS dependency
  ON dependency.summary_id=graph.summary_id AND dependency.boundary='workspace'
 CROSS JOIN selected_rust_unit_summaries AS child
  ON child.workspace_id=graph.workspace_id AND child.generation=graph.generation
 AND child.unit_key=dependency.dependency_unit_key
)
SELECT json(gap.detail)
FROM graph
CROSS JOIN main.rust_resolution_unit_summary_gaps AS gap
 ON gap.summary_id=graph.summary_id
WHERE gap.gap_kind='open_export_inventory'
