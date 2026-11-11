-- #9546: one affirmative member-type claim per certified Java, Kotlin or Scala
-- source type owner. 'complete' says every type the owner declares as a member
-- is published as a member-owner row for that owner; 'open' names the first
-- reason the producer cannot say so. A type-body owner with no row is Unknown.
-- Other languages retain zero counts and their preexisting canonical digests.
ALTER TABLE resolution_fragment_interiors
  ADD COLUMN expected_member_type_coverage_count INTEGER NOT NULL DEFAULT 0
  CHECK(expected_member_type_coverage_count >= 0 AND
        (semantic_language IN ('java', 'kotlin', 'scala') OR expected_member_type_coverage_count = 0));

CREATE TABLE resolution_member_type_coverage (
  blob_id INTEGER NOT NULL,
  definition_semantic_key INTEGER NOT NULL CHECK(definition_semantic_key >= 0),
  scope_head_node_key INTEGER NOT NULL CHECK(scope_head_node_key >= 0),
  coverage TEXT NOT NULL CHECK(coverage IN ('complete', 'open')),
  open_reason TEXT CHECK(open_reason IS NULL OR open_reason IN (
    'malformed', 'unnamed_type_declaration', 'member_row_missing', 'unrecognized_form',
    'nested_type_alias_without_member_row', 'enum_entry_body_declaration', 'export_clause'
  )),
  CHECK((open_reason IS NOT NULL) = (coverage = 'open')),
  PRIMARY KEY(blob_id, definition_semantic_key),
  FOREIGN KEY(blob_id, definition_semantic_key, scope_head_node_key)
    REFERENCES resolution_member_scope_properties(blob_id, definition_semantic_key, scope_head_node_key)
    ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;
