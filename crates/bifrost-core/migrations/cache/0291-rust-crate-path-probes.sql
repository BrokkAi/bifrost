-- Compatible: adds only a table; existing topology rows are unchanged.
-- Reverse path lookup and listing-prefix checks seek probe_key.
CREATE TABLE rust_crate_path_probes(
  topology_id INTEGER NOT NULL REFERENCES rust_crate_topologies(topology_id) ON DELETE CASCADE,
  probe_key TEXT NOT NULL,
  PRIMARY KEY(probe_key, topology_id)
) WITHOUT ROWID, STRICT;

CREATE INDEX rust_crate_path_probes_topology ON rust_crate_path_probes(topology_id);
