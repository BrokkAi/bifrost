-- Certified list-role coverage is stored beside the per-blob structural rows.
-- No populated table could apply the original non-constant ADD COLUMN default:
-- those upgrades failed and discarded the store. Empty-table upgrades could
-- succeed; like fresh stores, they already have the current schema text and
-- never replay 0273. Rebuild here without changing that existing schema.
-- migrate() in cache_db.rs:2530+ disables foreign keys before the migration
-- transaction, checks them before commit, and restores enforcement afterwards.
-- There are no inbound foreign keys, explicit indexes or dependent triggers;
-- CREATE restores the primary key and outbound cascading foreign key below.
-- Create under the final unquoted name: ALTER TABLE RENAME adds quotes to the
-- stored SQL, and cache schema validation removes whitespace only.
CREATE TEMP TABLE structural_facts_0273_backup AS
SELECT blob_id, nodes, roles, occurrence_roles FROM source_structural_facts;
DROP VIEW structural_source_facts;
DROP TABLE source_structural_facts;
CREATE TABLE source_structural_facts(
  blob_id          INTEGER NOT NULL,
  -- One element per node; the node id is the array index:
  -- [kind_code, boolean_value (0/1/null), construct (text/null), start_byte,
  --  end_byte, name_start_byte/null, name_end_byte/null, parent_node_id/null,
  --  subtree_end, call_kind_code/null, call_coverage_code/null,
  --  continues_callee_groups (0/1/null)]
  nodes            BLOB NOT NULL CHECK(json_valid(nodes, 8) AND json_type(nodes) = 'array'),
  -- Ordered by (source_node_id, ordinal); the ordinal is the rank within one
  -- source node: [source_node_id, role_code, spread (0/1), target_node_id/null,
  --  start_byte, end_byte, name_start_byte/null, name_end_byte/null,
  --  keyword_start_byte/null, keyword_end_byte/null]
  roles            BLOB NOT NULL CHECK(json_valid(roles, 8) AND json_type(roles) = 'array'),
  -- Ordered by (node_id, ordinal); the ordinal is the rank within one node:
  -- [node_id, role_code]
  occurrence_roles BLOB NOT NULL
    CHECK(json_valid(occurrence_roles, 8) AND json_type(occurrence_roles) = 'array'), role_coverage BLOB NOT NULL DEFAULT (jsonb('[]'))
  CHECK(json_valid(role_coverage, 8) AND json_type(role_coverage) = 'array'),
  PRIMARY KEY(blob_id),
  FOREIGN KEY(blob_id)
    REFERENCES source_fact_manifests(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
-- SQLite's JSONB empty array is X'0B', byte-identical to jsonb('[]').
INSERT INTO source_structural_facts(blob_id, nodes, roles, occurrence_roles, role_coverage)
SELECT blob_id, nodes, roles, occurrence_roles, X'0B'
FROM structural_facts_0273_backup;
DROP TABLE structural_facts_0273_backup;
CREATE VIEW structural_source_facts AS
SELECT facts.blob_id,
       json(facts.nodes) AS nodes,
       json(facts.roles) AS roles,
       json(facts.occurrence_roles) AS occurrence_roles,
       json(facts.role_coverage) AS role_coverage
FROM source_structural_facts AS facts
JOIN source_fact_manifests AS source
  ON source.blob_id = facts.blob_id
 AND source.publication_state = 'complete';
