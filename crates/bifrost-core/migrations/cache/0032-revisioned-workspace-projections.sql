-- Revisioned workspace projections.
--
-- Blob-derived facts are shared by every linked worktree, but workspace paths,
-- package mounts, anchors, and path symbols belong to one bound root and one
-- immutable analyzer revision. Version 29 stored only one mutable projection
-- per language, so its rows cannot be attributed to a worktree during upgrade.
-- Drop only that derived projection and retain all content-addressed facts.

DROP VIEW live_callable_facts;
DROP VIEW live_package_types;
DROP VIEW live_anchored_definition_identifiers;
DROP VIEW live_stable_definition_identifiers;
DROP VIEW live_definition_identifiers;
DROP VIEW live_visible_members;
DROP VIEW live_structural_members;
DROP VIEW live_definition_normalized_names;
DROP VIEW live_definition_exact_names;
DROP VIEW live_anchored_definition_normalized_names;
DROP VIEW live_stable_definition_normalized_names;
DROP VIEW live_anchored_definition_parent_names;
DROP VIEW live_stable_definition_parent_names;
DROP VIEW workspace_path_symbol_normalized_names;
DROP VIEW workspace_path_symbol_exact_names;
DROP VIEW workspace_path_symbols;
DROP VIEW live_workspace_package_descendants;
DROP VIEW live_workspace_package_edges;
DROP VIEW live_workspace_package_files;
DROP VIEW live_workspace_packages;
DROP VIEW live_workspace_files;

DROP TABLE workspace_file_anchors;
DROP TABLE workspace_package_edges;
DROP TABLE workspace_package_files;
DROP TABLE workspace_packages;
DROP TABLE workspace_files;
DROP TABLE workspace_snapshots;
DROP TABLE path_symbol_units;

CREATE TABLE workspace_revisions(
  workspace_id  TEXT    NOT NULL
    CHECK(length(workspace_id) = 64 AND workspace_id NOT GLOB '*[^0-9a-f]*'),
  lang          TEXT    NOT NULL,
  generation    INTEGER NOT NULL CHECK(generation >= 0),
  revision      INTEGER NOT NULL CHECK(revision > 0),
  PRIMARY KEY(workspace_id, lang, generation, revision)
) WITHOUT ROWID, STRICT;

CREATE TABLE workspace_heads(
  workspace_id  TEXT    NOT NULL,
  lang          TEXT    NOT NULL,
  generation    INTEGER NOT NULL,
  revision      INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, lang, generation),
  FOREIGN KEY(workspace_id, lang, generation, revision)
    REFERENCES workspace_revisions(workspace_id, lang, generation, revision)
) WITHOUT ROWID, STRICT;

CREATE TABLE workspace_file_versions(
  file_version_id   INTEGER PRIMARY KEY,
  workspace_id      TEXT    NOT NULL,
  lang              TEXT    NOT NULL,
  generation        INTEGER NOT NULL,
  rel_path          TEXT    NOT NULL CHECK(length(rel_path) > 0),
  blob_oid          TEXT    NOT NULL
    CHECK(length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*'),
  projection_digest TEXT    NOT NULL
    CHECK(length(projection_digest) = 64 AND projection_digest NOT GLOB '*[^0-9a-f]*'),
  valid_from         INTEGER NOT NULL CHECK(valid_from > 0),
  valid_until        INTEGER CHECK(valid_until IS NULL OR valid_until > valid_from),
  UNIQUE(workspace_id, lang, generation, rel_path, valid_from),
  UNIQUE(file_version_id, lang),
  FOREIGN KEY(workspace_id, lang, generation, valid_from)
    REFERENCES workspace_revisions(workspace_id, lang, generation, revision)
      ON DELETE CASCADE
) STRICT;

CREATE UNIQUE INDEX idx_workspace_file_versions_open_path
  ON workspace_file_versions(workspace_id, lang, generation, rel_path)
  WHERE valid_until IS NULL;
CREATE INDEX idx_workspace_file_versions_snapshot_path
  ON workspace_file_versions(
    workspace_id, lang, generation, rel_path, valid_from, valid_until, file_version_id
  );
CREATE INDEX idx_workspace_file_versions_snapshot_blob
  ON workspace_file_versions(
    workspace_id, lang, generation, blob_oid, valid_from, valid_until, file_version_id
  );

CREATE TABLE workspace_file_package_rows(
  file_version_id  INTEGER NOT NULL,
  package_name     TEXT    NOT NULL,
  PRIMARY KEY(file_version_id, package_name),
  FOREIGN KEY(file_version_id) REFERENCES workspace_file_versions(file_version_id)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX idx_workspace_file_package_rows_name
  ON workspace_file_package_rows(package_name, file_version_id);

CREATE TABLE workspace_file_package_edge_rows(
  file_version_id      INTEGER NOT NULL,
  parent_package_name  TEXT    NOT NULL,
  child_package_name   TEXT    NOT NULL,
  PRIMARY KEY(file_version_id, parent_package_name, child_package_name),
  CHECK(parent_package_name <> child_package_name),
  FOREIGN KEY(file_version_id) REFERENCES workspace_file_versions(file_version_id)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX idx_workspace_file_package_edge_rows_parent
  ON workspace_file_package_edge_rows(parent_package_name, child_package_name, file_version_id);
CREATE INDEX idx_workspace_file_package_edge_rows_child
  ON workspace_file_package_edge_rows(child_package_name, parent_package_name, file_version_id);

CREATE TABLE workspace_file_anchor_rows(
  file_version_id  INTEGER NOT NULL,
  anchor_kind      TEXT    NOT NULL CHECK(anchor_kind IN ('own_module', 'crate_root')),
  anchor_pop       INTEGER NOT NULL CHECK(anchor_pop BETWEEN 0 AND 255),
  package_name     TEXT    NOT NULL,
  PRIMARY KEY(file_version_id, anchor_kind, anchor_pop),
  CHECK(anchor_kind <> 'crate_root' OR anchor_pop = 0),
  FOREIGN KEY(file_version_id) REFERENCES workspace_file_versions(file_version_id)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX idx_workspace_file_anchor_rows_package
  ON workspace_file_anchor_rows(package_name, anchor_kind, anchor_pop, file_version_id);

CREATE TABLE workspace_file_path_symbol_rows(
  file_version_id  INTEGER NOT NULL,
  kind             INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 5),
  package_name     TEXT    NOT NULL,
  short_name       TEXT    NOT NULL,
  exact_fqn        TEXT    NOT NULL,
  normalized_fqn   TEXT    NOT NULL,
  PRIMARY KEY(file_version_id, kind, exact_fqn),
  FOREIGN KEY(file_version_id) REFERENCES workspace_file_versions(file_version_id)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX idx_workspace_file_path_symbol_rows_exact
  ON workspace_file_path_symbol_rows(exact_fqn, file_version_id);
CREATE INDEX idx_workspace_file_path_symbol_rows_normalized
  ON workspace_file_path_symbol_rows(normalized_fqn, file_version_id);
