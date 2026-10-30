CREATE TABLE class_set_field_slot_atoms_new (
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
                                  'constructor_call', 'exact_call_result', 'exact_access_result',
                                  'literal', 'container_literal',
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

INSERT INTO class_set_field_slot_atoms_new SELECT * FROM class_set_field_slot_atoms;
DROP TABLE class_set_field_slot_atoms;
ALTER TABLE class_set_field_slot_atoms_new RENAME TO class_set_field_slot_atoms;
