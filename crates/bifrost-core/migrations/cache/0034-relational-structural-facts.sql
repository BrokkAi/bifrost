-- Relational structural facts.
--
-- The old table stored one bincode payload per file. Persist the same
-- normalized arena as ordinary rows so SQLite can inspect and, in future
-- migrations, index the facts without understanding a Rust serialization.

DROP TABLE structural_facts_snapshots;

CREATE TABLE structural_fact_manifests(
  blob_id               INTEGER NOT NULL,
  facts_version         INTEGER NOT NULL CHECK(facts_version > 0),
  source_bytes          INTEGER NOT NULL CHECK(source_bytes >= 0),
  node_count            INTEGER NOT NULL CHECK(node_count >= 0),
  role_count            INTEGER NOT NULL CHECK(role_count >= 0),
  occurrence_role_count INTEGER NOT NULL CHECK(occurrence_role_count >= 0),
  PRIMARY KEY(blob_id),
  FOREIGN KEY(blob_id)
    REFERENCES blob_meta(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE structural_fact_nodes(
  blob_id                 INTEGER NOT NULL,
  node_id                 INTEGER NOT NULL CHECK(node_id >= 0),
  kind                    TEXT    NOT NULL CHECK(kind IN (
    'declaration', 'callable', 'function', 'method', 'constructor', 'lambda',
    'class', 'import', 'parameter', 'call', 'assignment', 'field_access',
    'identifier', 'literal', 'string_literal', 'numeric_literal',
    'boolean_literal', 'null_literal', 'collection_literal', 'jsx_element',
    'jsx_attribute', 'jsx_spread_attribute', 'object_property',
    'computed_property', 'spread_element', 'return', 'throw', 'catch', 'if',
    'loop', 'for_loop', 'while_loop', 'decorator', 'block'
  )),
  boolean_value           INTEGER CHECK(boolean_value IN (0, 1)),
  construct               TEXT,
  start_byte              INTEGER NOT NULL CHECK(start_byte >= 0),
  end_byte                INTEGER NOT NULL CHECK(end_byte >= start_byte),
  parent_node_id          INTEGER CHECK(parent_node_id >= 0 AND parent_node_id < node_id),
  name_start_byte         INTEGER CHECK(name_start_byte >= start_byte),
  name_end_byte           INTEGER CHECK(name_end_byte <= end_byte),
  subtree_end             INTEGER NOT NULL CHECK(subtree_end > node_id),
  call_kind               TEXT CHECK(call_kind IN (
    'function', 'method', 'constructor', 'extractor', 'infix', 'operator',
    'method_value'
  )),
  call_coverage           TEXT CHECK(call_coverage IN (
    'exact', 'partial', 'unknown_macro_derived', 'unknown_dynamic'
  )),
  continues_callee_groups INTEGER CHECK(continues_callee_groups IN (0, 1)),
  PRIMARY KEY(blob_id, node_id),
  FOREIGN KEY(blob_id)
    REFERENCES structural_fact_manifests(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, parent_node_id)
    REFERENCES structural_fact_nodes(blob_id, node_id),
  CHECK((name_start_byte IS NULL) = (name_end_byte IS NULL)),
  CHECK(boolean_value IS NULL OR kind = 'boolean_literal'),
  CHECK(
    (call_coverage IS NULL AND call_kind IS NULL AND continues_callee_groups IS NULL)
    OR (call_coverage IS NOT NULL AND continues_callee_groups IS NOT NULL)
  )
) WITHOUT ROWID, STRICT;

CREATE TABLE structural_fact_roles(
  blob_id            INTEGER NOT NULL,
  source_node_id     INTEGER NOT NULL CHECK(source_node_id >= 0),
  ordinal            INTEGER NOT NULL CHECK(ordinal >= 0),
  role               TEXT    NOT NULL CHECK(role IN (
    'callee', 'receiver', 'args', 'kwargs', 'left', 'right', 'module',
    'decorators', 'object', 'field', 'iterable', 'elements', 'tag',
    'attributes', 'children', 'value', 'key'
  )),
  spread             INTEGER NOT NULL CHECK(spread IN (0, 1)),
  keyword_start_byte INTEGER CHECK(keyword_start_byte >= 0),
  keyword_end_byte   INTEGER CHECK(keyword_end_byte >= keyword_start_byte),
  target_node_id     INTEGER CHECK(target_node_id >= 0),
  target_start_byte  INTEGER NOT NULL CHECK(target_start_byte >= 0),
  target_end_byte    INTEGER NOT NULL CHECK(target_end_byte >= target_start_byte),
  name_start_byte    INTEGER CHECK(name_start_byte >= 0),
  name_end_byte      INTEGER CHECK(name_end_byte >= name_start_byte),
  PRIMARY KEY(blob_id, source_node_id, ordinal),
  FOREIGN KEY(blob_id, source_node_id)
    REFERENCES structural_fact_nodes(blob_id, node_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, target_node_id)
    REFERENCES structural_fact_nodes(blob_id, node_id),
  CHECK((keyword_start_byte IS NULL) = (keyword_end_byte IS NULL)),
  CHECK((name_start_byte IS NULL) = (name_end_byte IS NULL))
) WITHOUT ROWID, STRICT;

CREATE TABLE structural_fact_occurrence_roles(
  blob_id INTEGER NOT NULL,
  node_id INTEGER NOT NULL CHECK(node_id >= 0),
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  role    TEXT    NOT NULL CHECK(role IN (
    'declaration_name', 'binder', 'label_or_key', 'type_operand',
    'path_segment', 'import_alias', 'import_target', 'receiver_position',
    'member_position', 'pattern_position', 'generated_source',
    'value_reference'
  )),
  PRIMARY KEY(blob_id, node_id, ordinal),
  FOREIGN KEY(blob_id, node_id)
    REFERENCES structural_fact_nodes(blob_id, node_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
