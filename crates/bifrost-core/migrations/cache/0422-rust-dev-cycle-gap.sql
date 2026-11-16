-- #12358: retain the scoped cause of an omitted Cargo dev-cycle edge.
-- BREAKING: old decoders reject this kind. user_version and crate derivation
-- identity fence retained products. No incoming foreign keys name this table.
CREATE TABLE rust_crate_gaps_0422(
  topology_id     INTEGER NOT NULL,
  gap_kind        TEXT NOT NULL CHECK(gap_kind IN
    ('external_dependency', 'unsupported_manifest', 'inactive_placement', 'unknown_activation',
     'unplaced_module', 'duplicate_placement', 'unresolved_import', 'unresolved_reexport',
     'open_export_inventory', 'unresolved_visibility', 'unresolved_trait_impl', 'dev_dependency_cycle_edge_dropped')),
  subject         TEXT NOT NULL,                               -- module path, extern name, or rel_path the gap is about
  detail          BLOB NOT NULL CHECK(json_valid(detail, 8) AND json_type(detail) = 'object'),
  PRIMARY KEY(topology_id, gap_kind, subject),
  FOREIGN KEY(topology_id) REFERENCES rust_crate_topologies(topology_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
INSERT INTO rust_crate_gaps_0422 SELECT * FROM rust_crate_gaps;
DROP TABLE rust_crate_gaps;
ALTER TABLE rust_crate_gaps_0422 RENAME TO rust_crate_gaps;
