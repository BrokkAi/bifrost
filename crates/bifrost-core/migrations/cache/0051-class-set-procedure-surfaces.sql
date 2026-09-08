-- Class-set summaries can cut a procedure body only when the structural call
-- surface that produced the row is available and replay-valid. Version 50 did
-- not retain that surface, so discard its derived rows before making the root
-- certificate mandatory.

DELETE FROM class_set_summaries;

CREATE TABLE class_set_procedure_surfaces(
  surface_id                 INTEGER PRIMARY KEY,
  surface_digest             BLOB    NOT NULL CHECK(length(surface_digest) = 32),
  procedure_lineage          BLOB    NOT NULL CHECK(length(procedure_lineage) = 32),
  owner_rel_path             TEXT    NOT NULL CHECK(length(owner_rel_path) > 0),
  owner_blob_id              INTEGER NOT NULL,
  lang                       TEXT    NOT NULL,
  artifact_public_identity   BLOB    NOT NULL CHECK(length(artifact_public_identity) = 32),
  artifact_content_identity  BLOB    NOT NULL CHECK(length(artifact_content_identity) = 32),
  schema_version             INTEGER NOT NULL CHECK(schema_version > 0),
  local_structure_digest     BLOB    NOT NULL CHECK(length(local_structure_digest) = 32),
  behavior_read_digest       BLOB    NOT NULL CHECK(length(behavior_read_digest) = 32),
  carrier_semantics_digest   BLOB    NOT NULL CHECK(length(carrier_semantics_digest) = 32),
  direct_calls_digest        BLOB    NOT NULL CHECK(length(direct_calls_digest) = 32),
  call_count                 INTEGER NOT NULL CHECK(call_count >= 0 AND call_count <= 100000),
  binding_count              INTEGER NOT NULL CHECK(binding_count >= 0 AND binding_count <= 1000000),
  entered_count              INTEGER NOT NULL CHECK(entered_count >= 0 AND entered_count <= 1000000),
  lexical_child_count        INTEGER NOT NULL CHECK(lexical_child_count >= 0 AND lexical_child_count <= 100000),
  read_count                 INTEGER NOT NULL CHECK(read_count >= 0 AND read_count <= 100000),
  completion                 TEXT    NOT NULL CHECK(completion = 'complete'),
  published_at               INTEGER NOT NULL CHECK(published_at >= 0),
  UNIQUE(surface_digest),
  CHECK(entered_count <= binding_count),
  FOREIGN KEY(owner_blob_id, lang) REFERENCES blobs(id, lang) ON DELETE CASCADE
) STRICT;

CREATE INDEX class_set_procedure_surfaces_exact_family
  ON class_set_procedure_surfaces(
    procedure_lineage, owner_rel_path, lang, schema_version,
    local_structure_digest, behavior_read_digest, surface_digest
  );
CREATE INDEX class_set_procedure_surfaces_owner_blob
  ON class_set_procedure_surfaces(owner_blob_id, lang);

CREATE TABLE class_set_procedure_surface_calls(
  surface_id                         INTEGER NOT NULL,
  call_ordinal                       INTEGER NOT NULL CHECK(call_ordinal >= 0),
  has_uncovered_boundary             INTEGER NOT NULL CHECK(has_uncovered_boundary IN (0, 1)),
  truncated                          INTEGER NOT NULL CHECK(truncated = 0),
  complete_receiver_hint_refinable   INTEGER NOT NULL CHECK(complete_receiver_hint_refinable IN (0, 1)),
  dispatch_kind                      TEXT NOT NULL CHECK(dispatch_kind IN ('resolved', 'unavailable')),
  dispatch_status                    TEXT NOT NULL CHECK(dispatch_status IN (
    'complete', 'ambiguous', 'unknown', 'unsupported', 'unproven'
  )),
  dispatch_capability                TEXT,
  dispatch_coverage                  TEXT CHECK(dispatch_coverage IN ('exhaustive', 'open')),
  binding_count                      INTEGER NOT NULL CHECK(binding_count >= 0),
  entered_count                      INTEGER NOT NULL CHECK(entered_count >= 0),
  PRIMARY KEY(surface_id, call_ordinal),
  FOREIGN KEY(surface_id) REFERENCES class_set_procedure_surfaces(surface_id) ON DELETE CASCADE,
  CHECK((dispatch_status = 'unsupported') = (dispatch_capability IS NOT NULL)),
  CHECK((dispatch_kind = 'resolved') = (dispatch_coverage IS NOT NULL)),
  CHECK(entered_count <= binding_count),
  CHECK(dispatch_kind = 'resolved' OR (binding_count = 0 AND entered_count = 0))
) WITHOUT ROWID, STRICT;

CREATE TABLE class_set_procedure_surface_bindings(
  surface_id          INTEGER NOT NULL,
  call_ordinal        INTEGER NOT NULL CHECK(call_ordinal >= 0),
  binding_ordinal     INTEGER NOT NULL CHECK(binding_ordinal >= 0),
  binding_status      TEXT NOT NULL CHECK(binding_status IN (
    'complete', 'ambiguous', 'unknown', 'unsupported', 'unproven'
  )),
  binding_capability  TEXT,
  PRIMARY KEY(surface_id, call_ordinal, binding_ordinal),
  FOREIGN KEY(surface_id, call_ordinal)
    REFERENCES class_set_procedure_surface_calls(surface_id, call_ordinal) ON DELETE CASCADE,
  CHECK((binding_status = 'unsupported') = (binding_capability IS NOT NULL))
) WITHOUT ROWID, STRICT;

CREATE TABLE class_set_procedure_surface_entered(
  surface_id                       INTEGER NOT NULL,
  call_ordinal                     INTEGER NOT NULL CHECK(call_ordinal >= 0),
  entered_ordinal                  INTEGER NOT NULL CHECK(entered_ordinal >= 0),
  target_procedure_lineage         BLOB NOT NULL CHECK(length(target_procedure_lineage) = 32),
  target_rel_path                  TEXT NOT NULL CHECK(length(target_rel_path) > 0),
  target_lang                      TEXT NOT NULL,
  target_artifact_public_identity  BLOB NOT NULL CHECK(length(target_artifact_public_identity) = 32),
  target_artifact_content_identity BLOB NOT NULL CHECK(length(target_artifact_content_identity) = 32),
  target_local_structure_digest     BLOB NOT NULL CHECK(length(target_local_structure_digest) = 32),
  PRIMARY KEY(surface_id, call_ordinal, entered_ordinal),
  FOREIGN KEY(surface_id, call_ordinal)
    REFERENCES class_set_procedure_surface_calls(surface_id, call_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE class_set_procedure_surface_lexical_children(
  surface_id                       INTEGER NOT NULL,
  child_ordinal                    INTEGER NOT NULL CHECK(child_ordinal >= 0),
  child_procedure_lineage          BLOB NOT NULL CHECK(length(child_procedure_lineage) = 32),
  child_rel_path                   TEXT NOT NULL CHECK(length(child_rel_path) > 0),
  child_lang                       TEXT NOT NULL,
  child_artifact_public_identity   BLOB NOT NULL CHECK(length(child_artifact_public_identity) = 32),
  child_artifact_content_identity  BLOB NOT NULL CHECK(length(child_artifact_content_identity) = 32),
  child_local_structure_digest     BLOB NOT NULL CHECK(length(child_local_structure_digest) = 32),
  PRIMARY KEY(surface_id, child_ordinal),
  UNIQUE(surface_id, child_procedure_lineage, child_rel_path, child_lang,
         child_local_structure_digest),
  FOREIGN KEY(surface_id) REFERENCES class_set_procedure_surfaces(surface_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE class_set_procedure_surface_reads(
  surface_id    INTEGER NOT NULL,
  read_ordinal  INTEGER NOT NULL CHECK(read_ordinal >= 0),
  key_digest    BLOB    NOT NULL CHECK(length(key_digest) = 32),
  kind          TEXT    NOT NULL CHECK(kind = 'lookup'),
  family        TEXT    NOT NULL CHECK(family = 'procedure_dispatch'),
  languages     TEXT,
  rel_path      TEXT    NOT NULL,
  name          TEXT,
  index_key     BLOB,
  blob_oid      TEXT,
  subject       BLOB    NOT NULL CHECK(length(subject) = 32),
  start_byte    INTEGER NOT NULL CHECK(start_byte >= 0),
  end_byte      INTEGER NOT NULL CHECK(end_byte >= start_byte),
  digest        BLOB    NOT NULL CHECK(length(digest) = 32),
  PRIMARY KEY(surface_id, read_ordinal),
  UNIQUE(surface_id, key_digest),
  FOREIGN KEY(surface_id) REFERENCES class_set_procedure_surfaces(surface_id) ON DELETE CASCADE,
  CHECK(languages IS NULL AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL)
) WITHOUT ROWID, STRICT;

ALTER TABLE class_set_summaries
  ADD COLUMN root_surface_digest BLOB
    REFERENCES class_set_procedure_surfaces(surface_digest) ON DELETE CASCADE
    CHECK(length(root_surface_digest) = 32);

ALTER TABLE class_set_summaries
  ADD COLUMN direct_calls_digest BLOB CHECK(length(direct_calls_digest) = 32);

CREATE INDEX class_set_summaries_root_surface
  ON class_set_summaries(root_surface_digest);
CREATE INDEX class_set_summaries_exact_family
  ON class_set_summaries(
    procedure_lineage, owner_rel_path, lang, schema_version, semantics_digest,
    context_digest, behavior_read_digest, carrier_digest, field_slots_digest,
    root_surface_digest, lookup_digest
  );

CREATE TRIGGER class_set_summaries_require_root_surface_insert
BEFORE INSERT ON class_set_summaries
WHEN NEW.root_surface_digest IS NULL OR NEW.direct_calls_digest IS NULL
BEGIN
  SELECT RAISE(ABORT, 'class-set summary structural surface contract is required');
END;

CREATE TRIGGER class_set_summaries_require_root_surface_update
BEFORE UPDATE OF root_surface_digest, direct_calls_digest ON class_set_summaries
WHEN NEW.root_surface_digest IS NULL OR NEW.direct_calls_digest IS NULL
BEGIN
  SELECT RAISE(ABORT, 'class-set summary structural surface contract is required');
END;
