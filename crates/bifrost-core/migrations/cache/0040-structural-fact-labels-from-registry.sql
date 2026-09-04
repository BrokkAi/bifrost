-- Structural fact labels come from the Rust registry, not from the schema.
--
-- Migration 0034 enumerated `structural_fact_nodes.kind` and
-- `structural_fact_roles.role` in CHECK constraints copied from
-- `NormalizedKind::LABELS` and the `Role` labels in
-- `crates/bifrost-core/src/analyzer/structural/kinds.rs`. The copies lagged
-- the registry: `module`, `concurrent_spawn`, and `operator` joined the
-- registry and never the schema, so the insert for every file whose facts
-- carried one of them failed the CHECK, the file never got a manifest row,
-- and it was re-extracted from source on every warm run (#2922: 586 of 2033
-- Rust files in this repository, every one with a `mod` declaration).
--
-- Hydration already rejects an unknown label structurally:
-- `FileFacts::from_persisted_rows` resolves each label through `from_label`
-- and fails the hydration when the registry does not know it. The schema
-- enumeration therefore protected nothing; it was a second copy of the
-- registry that could drift. The two columns keep NOT NULL and lose the
-- enumeration. Every other CHECK is kept verbatim, and the insert site
-- asserts in debug builds that each label round-trips through the registry.
--
-- SQLite cannot alter a CHECK, so the tables are recreated. The chain runs
-- with `PRAGMA foreign_keys` ON, under which `DROP TABLE` performs an
-- implicit `DELETE FROM` that fires cascades: dropping the old nodes table
-- first would delete every role and occurrence-role row through their
-- foreign keys. So each `_new` table is created and filled before any old
-- table is dropped, the `_new` children name the `_new` nodes table, the old
-- tables are dropped children-before-parents, and `ALTER TABLE x_new RENAME
-- TO x` rewrites `REFERENCES x_new` in every other table (the same three
-- rules migration 0033 follows). `structural_fact_occurrence_roles` keeps
-- its definition; it is recreated only because its foreign key names the
-- nodes table and it would otherwise be emptied by the old table's drop.
--
-- Every existing row is valid under the wider schema and is carried across.
-- Nothing is re-extracted; the files the CHECK rejected simply persist on
-- their next extraction.

CREATE TABLE structural_fact_nodes_new(
  blob_id                 INTEGER NOT NULL,
  node_id                 INTEGER NOT NULL CHECK(node_id >= 0),
  kind                    TEXT    NOT NULL,
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
    REFERENCES structural_fact_nodes_new(blob_id, node_id),
  CHECK((name_start_byte IS NULL) = (name_end_byte IS NULL)),
  CHECK(boolean_value IS NULL OR kind = 'boolean_literal'),
  CHECK(
    (call_coverage IS NULL AND call_kind IS NULL AND continues_callee_groups IS NULL)
    OR (call_coverage IS NOT NULL AND continues_callee_groups IS NOT NULL)
  )
) WITHOUT ROWID, STRICT;

INSERT INTO structural_fact_nodes_new(
  blob_id, node_id, kind, boolean_value, construct, start_byte, end_byte,
  parent_node_id, name_start_byte, name_end_byte, subtree_end, call_kind,
  call_coverage, continues_callee_groups
)
SELECT blob_id, node_id, kind, boolean_value, construct, start_byte, end_byte,
       parent_node_id, name_start_byte, name_end_byte, subtree_end, call_kind,
       call_coverage, continues_callee_groups
FROM structural_fact_nodes
ORDER BY blob_id, node_id;

CREATE TABLE structural_fact_roles_new(
  blob_id            INTEGER NOT NULL,
  source_node_id     INTEGER NOT NULL CHECK(source_node_id >= 0),
  ordinal            INTEGER NOT NULL CHECK(ordinal >= 0),
  role               TEXT    NOT NULL,
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
    REFERENCES structural_fact_nodes_new(blob_id, node_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, target_node_id)
    REFERENCES structural_fact_nodes_new(blob_id, node_id),
  CHECK((keyword_start_byte IS NULL) = (keyword_end_byte IS NULL)),
  CHECK((name_start_byte IS NULL) = (name_end_byte IS NULL))
) WITHOUT ROWID, STRICT;

INSERT INTO structural_fact_roles_new(
  blob_id, source_node_id, ordinal, role, spread, keyword_start_byte,
  keyword_end_byte, target_node_id, target_start_byte, target_end_byte,
  name_start_byte, name_end_byte
)
SELECT blob_id, source_node_id, ordinal, role, spread, keyword_start_byte,
       keyword_end_byte, target_node_id, target_start_byte, target_end_byte,
       name_start_byte, name_end_byte
FROM structural_fact_roles
ORDER BY blob_id, source_node_id, ordinal;

CREATE TABLE structural_fact_occurrence_roles_new(
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
    REFERENCES structural_fact_nodes_new(blob_id, node_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO structural_fact_occurrence_roles_new(blob_id, node_id, ordinal, role)
SELECT blob_id, node_id, ordinal, role
FROM structural_fact_occurrence_roles
ORDER BY blob_id, node_id, ordinal;

DROP TABLE structural_fact_occurrence_roles;
DROP TABLE structural_fact_roles;
DROP TABLE structural_fact_nodes;

ALTER TABLE structural_fact_nodes_new RENAME TO structural_fact_nodes;
ALTER TABLE structural_fact_roles_new RENAME TO structural_fact_roles;
ALTER TABLE structural_fact_occurrence_roles_new RENAME TO structural_fact_occurrence_roles;
