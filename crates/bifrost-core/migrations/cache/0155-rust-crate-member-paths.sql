-- Separate a crate member's semantic identity from the source paths that
-- realize it. Identical source blobs can be included from several paths in
-- the same module, while root references still target one member identity.
CREATE TABLE rust_crate_container_members(
  topology_id INTEGER NOT NULL,
  container_path TEXT NOT NULL,
  blob_id INTEGER NOT NULL,
  PRIMARY KEY(topology_id, container_path, blob_id),
  FOREIGN KEY(topology_id, container_path)
    REFERENCES rust_crate_containers(topology_id, container_path) ON DELETE CASCADE,
  FOREIGN KEY(blob_id) REFERENCES blobs(id)
) WITHOUT ROWID, STRICT;

INSERT INTO rust_crate_container_members(topology_id, container_path, blob_id)
SELECT DISTINCT topology_id, container_path, blob_id
FROM rust_crate_container_sources;

CREATE TABLE rust_crate_container_sources_replacement(
  topology_id INTEGER NOT NULL,
  container_path TEXT NOT NULL,
  blob_id INTEGER NOT NULL,
  scope_ordinal INTEGER CHECK(scope_ordinal >= 0),
  rel_path TEXT NOT NULL CHECK(length(rel_path) > 0),
  source_kind TEXT NOT NULL CHECK(source_kind IN ('declared', 'include')),
  enum_scope_node_key INTEGER CHECK(enum_scope_node_key >= 0),
  parent_container_path TEXT,
  CHECK((scope_ordinal IS NULL) <> (enum_scope_node_key IS NULL)),
  CHECK((container_path = 'crate') = (parent_container_path IS NULL)),
  PRIMARY KEY(topology_id, container_path, blob_id, rel_path),
  FOREIGN KEY(topology_id, container_path, blob_id)
    REFERENCES rust_crate_container_members(topology_id, container_path, blob_id)
    ON DELETE CASCADE,
  FOREIGN KEY(topology_id, container_path)
    REFERENCES rust_crate_containers(topology_id, container_path) ON DELETE CASCADE,
  FOREIGN KEY(blob_id) REFERENCES blobs(id)
) WITHOUT ROWID, STRICT;

INSERT INTO rust_crate_container_sources_replacement(
  topology_id, container_path, blob_id, scope_ordinal, rel_path, source_kind,
  enum_scope_node_key, parent_container_path
)
SELECT topology_id, container_path, blob_id, scope_ordinal, rel_path, source_kind,
       enum_scope_node_key, parent_container_path
FROM rust_crate_container_sources;

CREATE TABLE rust_crate_root_references_replacement(
  topology_id INTEGER NOT NULL,
  module_path TEXT NOT NULL,
  blob_id INTEGER NOT NULL,
  path_key INTEGER NOT NULL,
  reference_source_site INTEGER NOT NULL
    CHECK(reference_source_site BETWEEN 0 AND 4294967295),
  target_crate_key BLOB NOT NULL
    CHECK(typeof(target_crate_key) = 'blob' AND length(target_crate_key)=32),
  target_module_path TEXT NOT NULL,
  target_name TEXT NOT NULL,
  PRIMARY KEY(topology_id, module_path, blob_id, path_key),
  FOREIGN KEY(topology_id, module_path, blob_id)
    REFERENCES rust_crate_container_members(topology_id, container_path, blob_id)
    ON DELETE CASCADE,
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO rust_crate_root_references_replacement(
  topology_id, module_path, blob_id, path_key, reference_source_site,
  target_crate_key, target_module_path, target_name
)
SELECT topology_id, module_path, blob_id, path_key, reference_source_site,
       target_crate_key, target_module_path, target_name
FROM rust_crate_root_references;

DROP TABLE rust_crate_root_references;
DROP TABLE rust_crate_container_sources;
ALTER TABLE rust_crate_container_sources_replacement
  RENAME TO rust_crate_container_sources;
ALTER TABLE rust_crate_root_references_replacement
  RENAME TO rust_crate_root_references;

CREATE INDEX rust_crate_containers_blob
  ON rust_crate_container_sources(blob_id, topology_id, container_path);
CREATE INDEX rust_crate_containers_path
  ON rust_crate_container_sources(topology_id, rel_path);
CREATE INDEX rust_crate_containers_rel_path
  ON rust_crate_container_sources(rel_path, source_kind);
CREATE INDEX rust_crate_root_references_target
  ON rust_crate_root_references(
    target_crate_key, target_module_path, target_name,
    topology_id, module_path, blob_id, path_key, reference_source_site
  );
