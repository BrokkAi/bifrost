-- Migration 0517: persist Rust package target routes and typed unavailable targets.
-- BREAKING: a binary that predates these tables would reconcile Rust crates without maintaining them, leaving stale open intervals or claims that a newer reader trusts.
-- Mixed-version writers are excluded by the version-suffixed store file and the user_version check.

CREATE TABLE rust_package_route_versions(
  route_set_id INTEGER PRIMARY KEY,
  workspace_id TEXT NOT NULL CHECK(length(workspace_id)=64),
  generation INTEGER NOT NULL CHECK(generation>=0),
  manifest_path TEXT NOT NULL,
  manifest_file_version_id INTEGER NOT NULL REFERENCES workspace_file_versions(file_version_id),
  valid_from INTEGER NOT NULL CHECK(valid_from>0),
  valid_until INTEGER CHECK(valid_until IS NULL OR valid_until>valid_from),
  derivation_identity BLOB NOT NULL CHECK(typeof(derivation_identity)='blob' AND length(derivation_identity)=32),
  input_digest BLOB NOT NULL CHECK(typeof(input_digest)='blob' AND length(input_digest)=32),
  output_digest BLOB NOT NULL CHECK(typeof(output_digest)='blob' AND length(output_digest)=32),
  UNIQUE(workspace_id,generation,manifest_path,valid_from)
) STRICT;

CREATE TABLE rust_package_unavailable_targets(
  route_set_id INTEGER NOT NULL REFERENCES rust_package_route_versions(route_set_id) ON DELETE CASCADE,
  unit_key BLOB NOT NULL CHECK(typeof(unit_key)='blob' AND length(unit_key)=32),
  target_kind TEXT NOT NULL,
  target_name TEXT NOT NULL,
  declared_root TEXT NOT NULL,
  normalized_workspace_root TEXT,
  configuration_digest BLOB NOT NULL CHECK(typeof(configuration_digest)='blob' AND length(configuration_digest)=32),
  reason TEXT NOT NULL CHECK(reason IN ('outside_workspace','outside_package_unsupported')),
  PRIMARY KEY(route_set_id,unit_key)
) WITHOUT ROWID, STRICT;

CREATE TABLE rust_package_target_claims(
  route_set_id INTEGER NOT NULL REFERENCES rust_package_route_versions(route_set_id) ON DELETE CASCADE,
  unit_key BLOB NOT NULL CHECK(typeof(unit_key)='blob' AND length(unit_key)=32),
  rel_path TEXT NOT NULL,
  PRIMARY KEY(route_set_id,unit_key,rel_path)
) WITHOUT ROWID, STRICT;

CREATE INDEX rust_package_routes_selected ON rust_package_route_versions(workspace_id,generation,valid_from,valid_until);
CREATE INDEX rust_package_claims_path ON rust_package_target_claims(rel_path,route_set_id,unit_key);
CREATE INDEX rust_package_routes_manifest_version ON rust_package_route_versions(manifest_file_version_id);
