CREATE TABLE rust_crate_public_module_reachability (
  topology_id INTEGER NOT NULL REFERENCES rust_crate_topologies(topology_id) ON DELETE CASCADE,
  target_crate_key BLOB NOT NULL
    CHECK(typeof(target_crate_key) = 'blob' AND length(target_crate_key) = 32),
  target_module_path TEXT NOT NULL,
  PRIMARY KEY(topology_id, target_crate_key, target_module_path)
) WITHOUT ROWID, STRICT;
