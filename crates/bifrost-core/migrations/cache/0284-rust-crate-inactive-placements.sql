ALTER TABLE rust_crate_topologies ADD COLUMN broad_complete INTEGER NOT NULL DEFAULT 0 CHECK(broad_complete IN (0,1));

-- One positive source-listing proof per published workspace revision. A
-- derivation version mismatch is absence of proof, never a cached negative.
CREATE TABLE rust_source_listing_certificates (
  workspace_id TEXT NOT NULL,
  lang TEXT NOT NULL CHECK(lang = 'rust'),
  generation INTEGER NOT NULL,
  revision INTEGER NOT NULL,
  derivation_version INTEGER NOT NULL,
  complete INTEGER NOT NULL CHECK(complete IN (0,1)),
  PRIMARY KEY(workspace_id,lang,generation,revision),
  FOREIGN KEY(workspace_id,lang,generation,revision)
    REFERENCES workspace_revisions(workspace_id,lang,generation,revision) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE rust_source_listing_failures (
  workspace_id TEXT NOT NULL,
  lang TEXT NOT NULL CHECK(lang = 'rust'),
  generation INTEGER NOT NULL,
  revision INTEGER NOT NULL,
  rel_path TEXT NOT NULL,
  reason TEXT NOT NULL,
  PRIMARY KEY(workspace_id,lang,generation,revision,rel_path),
  FOREIGN KEY(workspace_id,lang,generation,revision)
    REFERENCES rust_source_listing_certificates(workspace_id,lang,generation,revision) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- Two rows equal on every key column are one placement. Their activation
-- folds to -1 if either is unknown, otherwise 0; the writer enforces this.
-- -1 encodes the absent mount site (SQLite NULLs do not conflict in a key).
CREATE TABLE rust_crate_inactive_placements (
  topology_id INTEGER NOT NULL REFERENCES rust_crate_topologies(topology_id) ON DELETE CASCADE,
  module_path TEXT NOT NULL,
  rel_path TEXT NOT NULL,
  placement TEXT NOT NULL,
  mount_blob_id INTEGER NOT NULL,
  mount_start_byte INTEGER NOT NULL,
  scope_ordinal INTEGER NOT NULL,
  blob_id INTEGER REFERENCES blobs(id),
  activation INTEGER NOT NULL CHECK(activation IN (-1,0)),
  PRIMARY KEY(topology_id,module_path,rel_path,placement,mount_blob_id,mount_start_byte,scope_ordinal)
) WITHOUT ROWID, STRICT;
CREATE INDEX rust_crate_inactive_placements_path ON rust_crate_inactive_placements(rel_path,topology_id);
CREATE VIEW rust_crate_broad_placements AS
 SELECT topology_id,container_path AS module_path,rel_path,1 AS activation,
        source_kind AS placement,NULL AS mount_blob_id,NULL AS mount_start_byte
 FROM rust_crate_container_sources
 UNION ALL
 SELECT topology_id,module_path,rel_path,activation,placement,
        NULLIF(mount_blob_id,-1),NULLIF(mount_start_byte,-1)
 FROM rust_crate_inactive_placements;
