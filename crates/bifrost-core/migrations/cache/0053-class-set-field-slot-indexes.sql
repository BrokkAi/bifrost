-- Exact-workspace, complete class-set field-slot indexes.
--
-- The index is a workspace-wide derived value, so its key names the exact
-- language content, provider behavior, active model set, and representation.
-- Payload rows retain stable declaration identities and source coordinates;
-- no artifact-local dense ID crosses the persistence boundary.

CREATE TABLE class_set_field_slot_indexes (
  index_id                    INTEGER PRIMARY KEY,
  lang                        TEXT    NOT NULL,
  workspace_content_digest    BLOB    NOT NULL CHECK(length(workspace_content_digest) = 32),
  provider_behavior_digest    BLOB    NOT NULL CHECK(length(provider_behavior_digest) = 32),
  active_pack_digest          BLOB    NOT NULL CHECK(length(active_pack_digest) = 32),
  adapter_semantics_digest    BLOB    NOT NULL CHECK(length(adapter_semantics_digest) = 32),
  representation_version      INTEGER NOT NULL CHECK(representation_version > 0),
  content_digest              BLOB    NOT NULL CHECK(length(content_digest) = 32),
  slot_count                  INTEGER NOT NULL CHECK(slot_count >= 0),
  atom_count                  INTEGER NOT NULL CHECK(atom_count >= 0),
  artifact_count              INTEGER NOT NULL CHECK(artifact_count >= 0),
  payload_text_bytes          INTEGER NOT NULL CHECK(payload_text_bytes >= 0),
  completion                  TEXT    NOT NULL CHECK(completion = 'complete'),
  published_at                INTEGER NOT NULL,
  UNIQUE(lang, workspace_content_digest, provider_behavior_digest,
         active_pack_digest, adapter_semantics_digest, representation_version)
) STRICT;

CREATE INDEX class_set_field_slot_indexes_recent
  ON class_set_field_slot_indexes(lang, published_at DESC, index_id DESC);

CREATE TABLE class_set_field_slot_artifacts (
  index_id                    INTEGER NOT NULL REFERENCES class_set_field_slot_indexes(index_id) ON DELETE CASCADE,
  artifact_ordinal            INTEGER NOT NULL CHECK(artifact_ordinal >= 0),
  artifact_rel_path           TEXT    NOT NULL,
  artifact_public_digest      BLOB    NOT NULL CHECK(length(artifact_public_digest) = 32),
  source_bytes                INTEGER NOT NULL CHECK(source_bytes >= 0),
  procedures                  INTEGER NOT NULL CHECK(procedures >= 0),
  blocks                      INTEGER NOT NULL CHECK(blocks >= 0),
  program_points              INTEGER NOT NULL CHECK(program_points >= 0),
  values_count                INTEGER NOT NULL CHECK(values_count >= 0),
  allocations                 INTEGER NOT NULL CHECK(allocations >= 0),
  call_sites                  INTEGER NOT NULL CHECK(call_sites >= 0),
  memory_locations            INTEGER NOT NULL CHECK(memory_locations >= 0),
  captures                    INTEGER NOT NULL CHECK(captures >= 0),
  source_mappings             INTEGER NOT NULL CHECK(source_mappings >= 0),
  evidence                    INTEGER NOT NULL CHECK(evidence >= 0),
  gaps                        INTEGER NOT NULL CHECK(gaps >= 0),
  events                      INTEGER NOT NULL CHECK(events >= 0),
  control_edges               INTEGER NOT NULL CHECK(control_edges >= 0),
  nested_entries              INTEGER NOT NULL CHECK(nested_entries >= 0),
  owned_text_bytes            INTEGER NOT NULL CHECK(owned_text_bytes >= 0),
  PRIMARY KEY(index_id, artifact_ordinal)
) STRICT;

CREATE TABLE class_set_field_slots (
  index_id                    INTEGER NOT NULL REFERENCES class_set_field_slot_indexes(index_id) ON DELETE CASCADE,
  slot_ordinal                INTEGER NOT NULL CHECK(slot_ordinal >= 0),
  owner_kind                  TEXT    NOT NULL CHECK(owner_kind IN ('workspace', 'external')),
  owner_declaration_id        TEXT,
  owner_fq_name               TEXT    NOT NULL,
  owner_rel_path              TEXT,
  owner_symbol_id             TEXT,
  member                      TEXT    NOT NULL,
  PRIMARY KEY(index_id, slot_ordinal),
  CHECK(
    (owner_kind = 'workspace' AND owner_declaration_id IS NOT NULL
                              AND owner_rel_path IS NOT NULL
                              AND owner_symbol_id IS NULL)
    OR
    (owner_kind = 'external' AND owner_declaration_id IS NULL
                             AND owner_rel_path IS NULL
                             AND owner_symbol_id IS NOT NULL)
  )
) STRICT;

CREATE TABLE class_set_field_slot_atoms (
  index_id                    INTEGER NOT NULL,
  slot_ordinal                INTEGER NOT NULL,
  atom_ordinal                INTEGER NOT NULL CHECK(atom_ordinal >= 0),
  atom_kind                   TEXT    NOT NULL CHECK(atom_kind IN ('workspace', 'external', 'unknown')),
  class_declaration_id        TEXT,
  class_fq_name               TEXT,
  class_rel_path              TEXT,
  class_symbol_id             TEXT,
  unknown_reason              TEXT,
  source_rel_path             TEXT    NOT NULL,
  source_start_byte           INTEGER NOT NULL CHECK(source_start_byte >= 0),
  source_start_line           INTEGER NOT NULL CHECK(source_start_line >= 0),
  source_start_byte_column    INTEGER NOT NULL CHECK(source_start_byte_column >= 0),
  source_end_byte             INTEGER NOT NULL CHECK(source_end_byte >= source_start_byte),
  source_end_line             INTEGER NOT NULL CHECK(source_end_line >= source_start_line),
  source_end_byte_column      INTEGER NOT NULL CHECK(source_end_byte_column >= 0),
  source_kind                 TEXT    NOT NULL CHECK(source_kind IN (
                                  'constructor_call', 'literal', 'container_literal',
                                  'declared_parameter', 'root_receiver', 'unknown')),
  PRIMARY KEY(index_id, slot_ordinal, atom_ordinal),
  FOREIGN KEY(index_id, slot_ordinal)
    REFERENCES class_set_field_slots(index_id, slot_ordinal) ON DELETE CASCADE,
  CHECK(
    (atom_kind = 'workspace' AND class_declaration_id IS NOT NULL
                              AND class_fq_name IS NOT NULL
                              AND class_rel_path IS NOT NULL
                              AND class_symbol_id IS NULL
                              AND unknown_reason IS NULL)
    OR
    (atom_kind = 'external' AND class_declaration_id IS NULL
                             AND class_fq_name IS NOT NULL
                             AND class_rel_path IS NULL
                             AND class_symbol_id IS NOT NULL
                             AND unknown_reason IS NULL)
    OR
    (atom_kind = 'unknown' AND class_declaration_id IS NULL
                            AND class_fq_name IS NULL
                            AND class_rel_path IS NULL
                            AND class_symbol_id IS NULL
                            AND unknown_reason IS NOT NULL)
  )
) STRICT;
