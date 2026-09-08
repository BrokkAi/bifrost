-- Complete finding-free class-set projections for one exact RQL root.
--
-- A generation names the complete environment and limit contract under which
-- roots are evaluated. It is incrementally populated: its presence never
-- claims that every root in the workspace has been analyzed. Result rows are
-- final stable RQL values, not materialization-scoped dataflow handles.

CREATE TABLE class_set_root_result_generations (
  generation_id              INTEGER PRIMARY KEY,
  lang                       TEXT    NOT NULL,
  workspace_content_digest   BLOB    NOT NULL CHECK(length(workspace_content_digest) = 32),
  provider_behavior_digest   BLOB    NOT NULL CHECK(length(provider_behavior_digest) = 32),
  active_pack_digest         BLOB    NOT NULL CHECK(length(active_pack_digest) = 32),
  field_slots_digest         BLOB    NOT NULL CHECK(length(field_slots_digest) = 32),
  root_result_semantics_digest BLOB  NOT NULL CHECK(length(root_result_semantics_digest) = 32),
  representation_version     INTEGER NOT NULL CHECK(representation_version > 0),
  published_at               INTEGER NOT NULL CHECK(published_at >= 0),
  UNIQUE(lang, workspace_content_digest, provider_behavior_digest,
         active_pack_digest, field_slots_digest, root_result_semantics_digest,
         representation_version),
  UNIQUE(generation_id, lang)
) STRICT;

CREATE INDEX class_set_root_result_generations_recent
  ON class_set_root_result_generations(lang, published_at DESC, generation_id DESC);

CREATE TABLE class_set_finding_free_root_results (
  result_id                  INTEGER PRIMARY KEY,
  generation_id              INTEGER NOT NULL,
  root_public_digest         BLOB    NOT NULL CHECK(length(root_public_digest) = 32),
  owner_rel_path             TEXT    NOT NULL CHECK(length(owner_rel_path) > 0),
  owner_blob_id              INTEGER NOT NULL,
  lang                       TEXT    NOT NULL,
  completion                 TEXT    NOT NULL CHECK(completion = 'complete'),
  finding_count              INTEGER NOT NULL CHECK(finding_count = 0),
  row_count                  INTEGER NOT NULL CHECK(row_count >= 0),
  payload_text_bytes         INTEGER NOT NULL CHECK(payload_text_bytes >= 0),
  content_digest             BLOB    NOT NULL CHECK(length(content_digest) = 32),
  published_at               INTEGER NOT NULL CHECK(published_at >= 0),
  UNIQUE(generation_id, root_public_digest),
  FOREIGN KEY(generation_id, lang)
    REFERENCES class_set_root_result_generations(generation_id, lang) ON DELETE CASCADE,
  FOREIGN KEY(owner_blob_id, lang) REFERENCES blobs(id, lang) ON DELETE CASCADE
) STRICT;

CREATE INDEX class_set_finding_free_root_results_owner_blob
  ON class_set_finding_free_root_results(owner_blob_id, lang);

CREATE TABLE class_set_finding_free_root_rows (
  result_id                  INTEGER NOT NULL,
  row_ordinal                INTEGER NOT NULL CHECK(row_ordinal >= 0),
  rel_path                   TEXT    NOT NULL CHECK(length(rel_path) > 0),
  start_byte                 INTEGER NOT NULL CHECK(start_byte >= 0),
  start_line                 INTEGER NOT NULL CHECK(start_line >= 0),
  start_byte_column          INTEGER NOT NULL CHECK(start_byte_column >= 0),
  end_byte                   INTEGER NOT NULL CHECK(end_byte >= start_byte),
  end_line                   INTEGER NOT NULL CHECK(end_line >= start_line),
  end_byte_column            INTEGER NOT NULL CHECK(end_byte_column >= 0),
  member                     TEXT    NOT NULL CHECK(length(member) > 0),
  atom_kind                  TEXT    NOT NULL CHECK(atom_kind IN ('workspace', 'external', 'unknown')),
  class_name                 TEXT,
  unknown_reason             TEXT,
  class_set_status           TEXT    NOT NULL CHECK(class_set_status IN (
                                  'known', 'partial', 'no_information', 'inconclusive')),
  PRIMARY KEY(result_id, row_ordinal),
  FOREIGN KEY(result_id)
    REFERENCES class_set_finding_free_root_results(result_id) ON DELETE CASCADE,
  CHECK(end_byte > start_byte
        OR (end_line = start_line AND end_byte_column = start_byte_column)),
  CHECK(end_line <> start_line
        OR end_byte - start_byte = end_byte_column - start_byte_column),
  CHECK(
    (atom_kind IN ('workspace', 'external')
      AND class_name IS NOT NULL AND length(class_name) > 0
      AND unknown_reason IS NULL)
    OR
    (atom_kind = 'unknown' AND class_name IS NULL
      AND unknown_reason IN (
        'root_parameter', 'self_receiver', 'variadic_parameter',
        'unresolved_call', 'truncated', 'unmodeled_load', 'await', 'capture',
        'ambiguous_callee', 'external_not_modeled', 'unresolved_base',
        'dynamic_attributes', 'pack_incomplete', 'uncertain_flow',
        'field_slot_incomplete', 'solver_budget', 'semantic_budget',
        'incomplete_root'))
  )
) WITHOUT ROWID, STRICT;
