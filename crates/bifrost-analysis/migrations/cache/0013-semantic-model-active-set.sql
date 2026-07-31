CREATE TABLE semantic_pack_active_state(
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  active_set_digest TEXT NOT NULL
    CHECK(length(active_set_digest) = 64 AND active_set_digest NOT GLOB '*[^0-9a-f]*'),
  updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE semantic_pack_active_members(
  ordinal INTEGER PRIMARY KEY CHECK(ordinal >= 0),
  manifest_digest TEXT NOT NULL UNIQUE
    CHECK(length(manifest_digest) = 64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'),
  source_kind TEXT NOT NULL CHECK(source_kind IN (
    'installed',
    'generated',
    'pre_shipped',
    'workspace_produced',
    'embedded',
    'ephemeral_workspace'
  )),
  source_id TEXT NOT NULL CHECK(length(source_id) > 0),
  workspace_produced INTEGER NOT NULL CHECK(workspace_produced IN (0, 1))
) STRICT;

CREATE INDEX semantic_pack_active_members_source
  ON semantic_pack_active_members(source_kind, source_id, manifest_digest);
