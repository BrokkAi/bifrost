-- Preserve all owned scope heads while distinguishing member scopes from executable scopes.
CREATE TABLE resolution_member_scope_properties_rebuilt (
  blob_id INTEGER NOT NULL,
  definition_semantic_key INTEGER NOT NULL CHECK(definition_semantic_key >= 0),
  scope_head_node_key INTEGER NOT NULL CHECK(scope_head_node_key >= 0),
  scope_kind TEXT NOT NULL CHECK(scope_kind IN ('type_body', 'executable')),
  PRIMARY KEY(blob_id, definition_semantic_key, scope_head_node_key),
  UNIQUE(blob_id, scope_head_node_key),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
INSERT INTO resolution_member_scope_properties_rebuilt
SELECT blob_id,definition_semantic_key,scope_head_node_key,'type_body'
FROM resolution_member_scope_properties;
DROP TABLE resolution_member_scope_properties;
ALTER TABLE resolution_member_scope_properties_rebuilt
RENAME TO resolution_member_scope_properties;
CREATE UNIQUE INDEX resolution_member_scope_properties_type_owner
ON resolution_member_scope_properties(blob_id,definition_semantic_key)
WHERE scope_kind='type_body';
