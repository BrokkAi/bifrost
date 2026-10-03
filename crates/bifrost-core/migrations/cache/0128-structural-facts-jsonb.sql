-- Store each blob's structural facts as three JSONB positional arrays.
--
-- source_structural_nodes, source_structural_roles and
-- source_structural_occurrence_roles held about five rows per resolution site
-- (issue #3737). Their only reader takes a whole blob in node order, and no
-- statement joins or filters on the rows, so one JSONB array per family per
-- blob replaces them. The structural integrity checks the seal trigger ran on
-- the rows (node_count agreement, subtree_end bounds, parent ordering, name
-- range containment) are Rust assertions (StructuralFactRows::new and
-- ParsedSourceFacts::assert_storable). Migration 0127 already dropped that
-- seal trigger, so nothing here references the old tables except the copy
-- and the drops.

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
    CHECK(json_valid(occurrence_roles, 8) AND json_type(occurrence_roles) = 'array'),
  PRIMARY KEY(blob_id),
  FOREIGN KEY(blob_id)
    REFERENCES source_fact_manifests(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO source_structural_facts(blob_id, nodes, roles, occurrence_roles)
SELECT manifest.blob_id,
  jsonb((SELECT COALESCE(json_group_array(json_array(
            kind_code, boolean_value, construct, start_byte, end_byte,
            name_start_byte, name_end_byte, parent_node_id, subtree_end,
            call_kind_code, call_coverage_code, continues_callee_groups)), '[]')
         FROM (SELECT * FROM source_structural_nodes
               WHERE blob_id = manifest.blob_id ORDER BY node_id))),
  jsonb((SELECT COALESCE(json_group_array(json_array(
            source_node_id, role_code, spread, target_node_id, start_byte, end_byte,
            name_start_byte, name_end_byte, keyword_start_byte, keyword_end_byte)), '[]')
         FROM (SELECT * FROM source_structural_roles
               WHERE blob_id = manifest.blob_id ORDER BY source_node_id, ordinal))),
  jsonb((SELECT COALESCE(json_group_array(json_array(node_id, role_code)), '[]')
         FROM (SELECT * FROM source_structural_occurrence_roles
               WHERE blob_id = manifest.blob_id ORDER BY node_id, ordinal)))
FROM source_fact_manifests AS manifest;

DROP VIEW structural_source_nodes;
DROP VIEW structural_source_roles;
DROP VIEW structural_source_occurrence_roles;
DROP TABLE source_structural_nodes;
DROP TABLE source_structural_roles;
DROP TABLE source_structural_occurrence_roles;

CREATE VIEW structural_source_facts AS
SELECT
  facts.blob_id,
  json(facts.nodes) AS nodes,
  json(facts.roles) AS roles,
  json(facts.occurrence_roles) AS occurrence_roles
FROM source_structural_facts AS facts
JOIN source_fact_manifests AS source
  ON source.blob_id = facts.blob_id
 AND source.publication_state = 'complete';
