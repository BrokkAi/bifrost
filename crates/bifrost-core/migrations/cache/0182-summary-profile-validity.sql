-- #5147: validity belongs to a context profile as well as a unit and revision.
-- Rust and other single-profile languages use the zero digest. The schema
-- enforces that singleton so their existing readers cannot select another
-- profile. Go writers always supply their selected context profile.
--
-- Old Go intervals cannot establish profile isolation, and migration SQL has
-- no canonical hashing helper to identify the profile read in the ledger.
-- Invalidate these derived intervals; normal Go context reconciliation rebinds
-- the content-addressed summaries. Preserve all other intervals and Rust's
-- referencing rows. Headers and source facts remain reusable.
CREATE TEMP TABLE saved_unit_summary_versions AS
  SELECT * FROM resolution_unit_summary_versions WHERE lang <> 'go';
CREATE TEMP TABLE saved_rust_unit_summary_versions AS
  SELECT * FROM rust_resolution_unit_summary_versions;
DROP TABLE rust_resolution_unit_summary_versions;
DROP TABLE resolution_unit_summary_versions;

CREATE TABLE resolution_unit_summary_versions (
  workspace_id  TEXT NOT NULL CHECK(length(workspace_id) = 64),
  lang          TEXT NOT NULL CHECK(length(lang) > 0),
  generation    INTEGER NOT NULL CHECK(generation >= 0),
  unit_key      BLOB NOT NULL CHECK(typeof(unit_key) = 'blob' AND length(unit_key) = 32),
  profile_digest BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
    CHECK(typeof(profile_digest) = 'blob' AND length(profile_digest) = 32)
    CHECK(lang = 'go' OR profile_digest = zeroblob(32)),
  valid_from    INTEGER NOT NULL CHECK(valid_from > 0),
  valid_until   INTEGER CHECK(valid_until IS NULL OR valid_until > valid_from),
  summary_id    INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id),
  PRIMARY KEY(workspace_id, lang, generation, unit_key, profile_digest, valid_from)
) WITHOUT ROWID, STRICT;
-- Reconcile closes every open row a pass did not rebind; unbound-header cleanup
-- seeks the summary side.
CREATE INDEX resolution_unit_summary_versions_open
  ON resolution_unit_summary_versions(workspace_id, lang, generation, profile_digest, unit_key)
  WHERE valid_until IS NULL;
CREATE INDEX resolution_unit_summary_versions_summary
  ON resolution_unit_summary_versions(summary_id);

CREATE TABLE rust_resolution_unit_summary_versions (
  workspace_id TEXT NOT NULL,
  lang TEXT NOT NULL CHECK(lang = 'rust'),
  generation INTEGER NOT NULL CHECK(generation >= 0),
  unit_key BLOB NOT NULL CHECK(typeof(unit_key) = 'blob' AND length(unit_key) = 32),
  profile_digest BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
    CHECK(typeof(profile_digest) = 'blob' AND profile_digest = zeroblob(32)),
  valid_from INTEGER NOT NULL CHECK(valid_from > 0),
  summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  manifest_file_version_id INTEGER REFERENCES workspace_file_versions(file_version_id),
  topology_id INTEGER NOT NULL REFERENCES rust_crate_topologies(topology_id),
  PRIMARY KEY(workspace_id, lang, generation, unit_key, valid_from),
  FOREIGN KEY(workspace_id, lang, generation, unit_key, profile_digest, valid_from)
    REFERENCES resolution_unit_summary_versions(workspace_id, lang, generation, unit_key, profile_digest, valid_from)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX rust_resolution_unit_summary_versions_manifest
  ON rust_resolution_unit_summary_versions(
    workspace_id, generation, manifest_file_version_id, unit_key, summary_id)
  WHERE manifest_file_version_id IS NOT NULL;
CREATE INDEX rust_resolution_unit_summary_versions_topology
  ON rust_resolution_unit_summary_versions(
    topology_id, workspace_id, generation, unit_key, valid_from, summary_id);

INSERT INTO resolution_unit_summary_versions(
  workspace_id, lang, generation, unit_key, valid_from, valid_until, summary_id)
SELECT workspace_id, lang, generation, unit_key, valid_from, valid_until, summary_id
FROM saved_unit_summary_versions;
INSERT INTO rust_resolution_unit_summary_versions(
  workspace_id, lang, generation, unit_key, valid_from, summary_id,
  manifest_file_version_id, topology_id)
SELECT workspace_id, lang, generation, unit_key, valid_from, summary_id,
       manifest_file_version_id, topology_id
FROM saved_rust_unit_summary_versions;
DROP TABLE temp.saved_unit_summary_versions;
DROP TABLE temp.saved_rust_unit_summary_versions;
