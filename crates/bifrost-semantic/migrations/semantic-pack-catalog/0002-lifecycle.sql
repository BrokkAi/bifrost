CREATE INDEX catalog_packs_gc
  ON catalog_packs(state, last_used_at, installed_at, manifest_digest);

CREATE TABLE catalog_pins(
  manifest_digest TEXT NOT NULL REFERENCES catalog_packs(manifest_digest) ON DELETE CASCADE,
  pin_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(manifest_digest, pin_id)
) STRICT;

CREATE TABLE catalog_activations(
  scope_id TEXT NOT NULL,
  active_set_digest TEXT NOT NULL
    CHECK(length(active_set_digest) = 64 AND active_set_digest NOT GLOB '*[^0-9a-f]*'),
  manifest_digest TEXT NOT NULL REFERENCES catalog_packs(manifest_digest) ON DELETE CASCADE,
  source_kind TEXT NOT NULL CHECK(source_kind IN (
    'installed', 'generated', 'pre_shipped', 'workspace_produced'
  )),
  source_id TEXT NOT NULL,
  activated_at INTEGER NOT NULL,
  PRIMARY KEY(scope_id, manifest_digest)
) STRICT;

CREATE INDEX catalog_activations_manifest
  ON catalog_activations(manifest_digest, scope_id);
CREATE INDEX catalog_activations_source
  ON catalog_activations(source_kind, source_id, manifest_digest);

CREATE TABLE catalog_leases(
  lease_id TEXT PRIMARY KEY,
  manifest_digest TEXT NOT NULL REFERENCES catalog_packs(manifest_digest) ON DELETE CASCADE,
  owner TEXT NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;

CREATE INDEX catalog_leases_manifest_expiry
  ON catalog_leases(manifest_digest, expires_at);
CREATE INDEX catalog_leases_expiry
  ON catalog_leases(expires_at, manifest_digest);

CREATE TABLE catalog_install_object_reservations(
  installation_id TEXT NOT NULL,
  stored_digest TEXT NOT NULL
    CHECK(length(stored_digest) = 64 AND stored_digest NOT GLOB '*[^0-9a-f]*'),
  expires_at INTEGER NOT NULL,
  PRIMARY KEY(installation_id, stored_digest)
) STRICT;

CREATE INDEX catalog_install_object_reservations_digest
  ON catalog_install_object_reservations(stored_digest, expires_at);
