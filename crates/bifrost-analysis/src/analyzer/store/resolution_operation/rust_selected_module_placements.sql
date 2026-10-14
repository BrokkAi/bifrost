-- Selection-local alignment of module scopes and crate placements. Build once
-- after the selection inputs are complete; clear with those inputs on check-in.
CREATE TEMP TABLE IF NOT EXISTS selected_rust_module_placements(
 mount_ordinal INTEGER NOT NULL,
 blob_id INTEGER NOT NULL,
 scope_ordinal INTEGER NOT NULL,
 module_declaration INTEGER,
 topology_id INTEGER NOT NULL,
 unit_key BLOB NOT NULL,
 summary_id INTEGER NOT NULL,
 member_ordinal INTEGER NOT NULL,
 container_path TEXT NOT NULL,
 placement_blob INTEGER NOT NULL
) STRICT;
-- PLACEMENTS and REFERENCE_PLACEMENTS seek a blob/declaration and read only
-- topology and path. MODULE_PLACEMENTS uses the same blob prefix.
CREATE INDEX IF NOT EXISTS temp.selected_rust_module_placements_blob
 ON selected_rust_module_placements(placement_blob, module_declaration, topology_id, container_path);
-- Forward/reverse scope readers seek one mount and its local module ordinal.
CREATE INDEX IF NOT EXISTS temp.selected_rust_module_placements_mount
 ON selected_rust_module_placements(mount_ordinal, scope_ordinal);
-- Reverse candidate discovery enumerates the hosts of one target topology.
CREATE INDEX IF NOT EXISTS temp.selected_rust_module_placements_topology
 ON selected_rust_module_placements(topology_id, container_path);
