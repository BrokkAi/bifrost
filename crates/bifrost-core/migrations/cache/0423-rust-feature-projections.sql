-- Compatible: additive discovery outputs; older readers ignore these tables.
-- A missing projection forces rediscovery rather than accepting an old summary.
CREATE TABLE rust_feature_discoveries(
 workspace_id TEXT NOT NULL, generation INTEGER NOT NULL,
 input_digest BLOB NOT NULL CHECK(length(input_digest)=32),
 publication_revision INTEGER NOT NULL CHECK(publication_revision>0),
 PRIMARY KEY(workspace_id,generation,input_digest),
 FOREIGN KEY(workspace_id,generation) REFERENCES rust_crate_reconciliations(workspace_id,generation) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE rust_feature_projections(
 workspace_id TEXT NOT NULL, generation INTEGER NOT NULL,
 input_digest BLOB NOT NULL CHECK(length(input_digest)=32),
 unit_key BLOB NOT NULL CHECK(length(unit_key)=32),
 projection_digest BLOB NOT NULL CHECK(length(projection_digest)=32),
 complete INTEGER NOT NULL CHECK(complete IN (0,1)),
 reason TEXT CHECK(reason IS NULL OR reason='activation_not_established'),
 manifest_path TEXT NOT NULL, configuration_directory TEXT NOT NULL,
 CHECK((complete=1 AND reason IS NULL) OR (complete=0 AND reason IS NOT NULL)),
 PRIMARY KEY(workspace_id,generation,input_digest,unit_key),
 FOREIGN KEY(workspace_id,generation,input_digest) REFERENCES rust_feature_discoveries(workspace_id,generation,input_digest) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE rust_feature_projection_packages(
 workspace_id TEXT NOT NULL, generation INTEGER NOT NULL,
 input_digest BLOB NOT NULL, unit_key BLOB NOT NULL, manifest_path TEXT NOT NULL,
 features BLOB NOT NULL CHECK(json_valid(features,8)),
 complete INTEGER NOT NULL CHECK(complete IN (0,1)),
 PRIMARY KEY(workspace_id,generation,input_digest,unit_key,manifest_path),
 FOREIGN KEY(workspace_id,generation,input_digest,unit_key) REFERENCES rust_feature_projections(workspace_id,generation,input_digest,unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
