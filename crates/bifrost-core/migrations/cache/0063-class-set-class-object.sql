-- Admit the typed class-object remainder. A value that is a class object has
-- the member surface of its metaclass plus the class's own class-level
-- attributes, which the class-set domain does not model, so a member it does
-- not name is not proven absent. SQLite cannot alter a CHECK constraint in
-- place, so rebuild only the constrained leaf row table and preserve every
-- schema-62 row, including the guard class that migration 0061 added and the
-- class-creation remainder that migration 0062 added.

CREATE TABLE class_set_finding_free_root_rows_v63 (
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
  guard_class                TEXT,
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
      AND unknown_reason IS NULL AND guard_class IS NULL)
    OR
    (atom_kind = 'unknown' AND class_name IS NULL AND guard_class IS NULL
      AND unknown_reason IS NOT NULL AND unknown_reason IN (
        'root_parameter', 'self_receiver', 'variadic_parameter',
        'unresolved_call', 'truncated', 'unmodeled_load', 'await', 'capture',
        'ambiguous_callee', 'external_not_modeled', 'unresolved_base',
        'dynamic_attributes', 'pack_incomplete', 'uncertain_flow',
        'field_slot_incomplete', 'solver_budget', 'semantic_budget',
        'incomplete_root', 'open_type_bound', 'scalar_receiver',
        'class_creation', 'class_object'))
    OR
    (atom_kind = 'unknown' AND class_name IS NULL
      AND unknown_reason IS NOT NULL AND unknown_reason = 'unmodeled_guard'
      AND guard_class IS NOT NULL AND length(guard_class) > 0)
  )
) WITHOUT ROWID, STRICT;

INSERT INTO class_set_finding_free_root_rows_v63(
  result_id, row_ordinal, rel_path,
  start_byte, start_line, start_byte_column,
  end_byte, end_line, end_byte_column,
  member, atom_kind, class_name, unknown_reason, class_set_status, guard_class)
SELECT result_id, row_ordinal, rel_path,
       start_byte, start_line, start_byte_column,
       end_byte, end_line, end_byte_column,
       member, atom_kind, class_name, unknown_reason, class_set_status, guard_class
FROM class_set_finding_free_root_rows;

DROP TABLE class_set_finding_free_root_rows;
ALTER TABLE class_set_finding_free_root_rows_v63
  RENAME TO class_set_finding_free_root_rows;
