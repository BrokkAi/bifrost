WITH RECURSIVE graph(topology_id) AS (
 SELECT selected.topology_id FROM rust_crate_file_naming AS naming
 CROSS JOIN selected_rust_crates AS selected USING(topology_id)
 WHERE naming.rel_path=?1
 UNION
 SELECT target.topology_id FROM graph
 CROSS JOIN rust_crate_dependencies AS dependency USING(topology_id)
 CROSS JOIN selected_rust_crates AS target ON target.crate_key=dependency.dependency_crate_key
)
SELECT json(gap.detail) FROM graph CROSS JOIN rust_crate_gaps AS gap USING(topology_id)
WHERE gap.gap_kind='open_export_inventory'
