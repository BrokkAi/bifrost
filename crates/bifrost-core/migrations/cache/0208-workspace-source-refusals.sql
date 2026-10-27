-- Sources that source admission refused at a workspace revision. A refused
-- path has no source row in workspace_file_versions; this row completes the
-- revision's input domain, so a reader can tell an explained exclusion from
-- a missing or changed input. `reason` is one object read whole:
-- {"code":"binary"|"proof_rejected"|"structural_line"|"budget",
--  "dimension"?, "limit"?, "observed"?}.
CREATE TABLE workspace_source_refusals(
  workspace_id TEXT    NOT NULL,
  lang         TEXT    NOT NULL,
  generation   INTEGER NOT NULL,
  rel_path     TEXT    NOT NULL CHECK(length(rel_path) > 0),
  blob_oid     TEXT    NOT NULL
    CHECK(length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*'),
  reason       BLOB    NOT NULL CHECK(json_valid(reason, 8) AND json_type(reason) = 'object'),
  valid_from   INTEGER NOT NULL CHECK(valid_from > 0),
  valid_until  INTEGER CHECK(valid_until IS NULL OR valid_until > valid_from),
  PRIMARY KEY(workspace_id, lang, generation, rel_path, valid_from),
  FOREIGN KEY(workspace_id, lang, generation, valid_from)
    REFERENCES workspace_revisions(workspace_id, lang, generation, revision)
      ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- Publication replaces the open rows of one storage language.
CREATE UNIQUE INDEX idx_workspace_source_refusals_open_path
  ON workspace_source_refusals(workspace_id, lang, generation, rel_path)
  WHERE valid_until IS NULL;
