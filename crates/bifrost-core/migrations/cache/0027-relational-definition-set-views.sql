-- Set-oriented definition lookup views.
--
-- The general mounted-name views combine stable, anchored, and path-derived
-- identities with UNION ALL. That is the right reusable shape for point
-- queries, but SQLite materializes the compound view when a request relation
-- joins it. Keep the two content-backed access paths separate so a batch's
-- request rows can drive the same selective indexes as prepared point queries.

CREATE VIEW live_stable_definition_parent_names AS
SELECT units.lang, files.generation, files.rel_path, units.blob_oid,
       units.unit_key, units.kind, units.short_name, units.identifier,
       'content' AS source_kind, '' AS prefix, units.exact_fqn_tail AS tail,
       units.normalized_fqn_tail AS normalized_tail,
       units.exact_parent_fqn_tail AS exact_parent_tail,
       units.normalized_parent_fqn_tail AS normalized_parent_tail,
       units.package_fqn_tail AS package_tail,
       units.simple_type_name, units.signature
FROM code_units AS units INDEXED BY idx_code_units_stable_parent_identifier
JOIN live_parsed_blobs AS live
  ON live.blob_oid = units.blob_oid AND live.lang = units.lang
JOIN live_workspace_files AS files
  ON files.lang = units.lang AND files.blob_oid = units.blob_oid
WHERE units.fq_anchor_kind IS NULL
  AND units.exact_parent_fqn_tail IS NOT NULL
  AND (units.in_declarations = 1 OR units.in_definition_lookup = 1);

CREATE VIEW live_anchored_definition_parent_names AS
SELECT units.lang, files.generation, files.rel_path, units.blob_oid,
       units.unit_key, units.kind, units.short_name, units.identifier,
       'anchored' AS source_kind, anchors.package_name AS prefix,
       units.exact_fqn_tail AS tail,
       units.normalized_fqn_tail AS normalized_tail,
       units.exact_parent_fqn_tail AS exact_parent_tail,
       units.normalized_parent_fqn_tail AS normalized_parent_tail,
       units.package_fqn_tail AS package_tail,
       units.simple_type_name, units.signature
FROM code_units AS units INDEXED BY idx_code_units_anchored_parent_identifier
JOIN live_parsed_blobs AS live
  ON live.blob_oid = units.blob_oid AND live.lang = units.lang
JOIN live_workspace_files AS files
  ON files.lang = units.lang AND files.blob_oid = units.blob_oid
JOIN workspace_file_anchors AS anchors
  ON anchors.lang = files.lang
 AND anchors.generation = files.generation
 AND anchors.file_id = files.file_id
 AND anchors.anchor_kind = units.fq_anchor_kind
 AND anchors.anchor_pop = units.fq_anchor_pop
WHERE units.fq_anchor_kind IS NOT NULL
  AND units.exact_parent_fqn_tail IS NOT NULL
  AND (units.in_declarations = 1 OR units.in_definition_lookup = 1);

CREATE VIEW live_stable_definition_normalized_names AS
SELECT units.lang, files.generation, files.rel_path, units.blob_oid,
       units.unit_key, units.kind, units.short_name, units.identifier,
       'content' AS source_kind, '' AS prefix,
       units.normalized_fqn_tail AS tail,
       units.normalized_fqn_tail AS normalized_tail,
       units.exact_parent_fqn_tail AS exact_parent_tail,
       units.normalized_parent_fqn_tail AS normalized_parent_tail,
       units.package_fqn_tail AS package_tail,
       units.simple_type_name, units.signature
FROM code_units AS units INDEXED BY idx_code_units_stable_normalized_tail
JOIN live_parsed_blobs AS live
  ON live.blob_oid = units.blob_oid AND live.lang = units.lang
JOIN live_workspace_files AS files
  ON files.lang = units.lang AND files.blob_oid = units.blob_oid
WHERE units.fq_anchor_kind IS NULL
  AND units.normalized_fqn_tail IS NOT NULL
  AND (units.in_declarations = 1 OR units.in_definition_lookup = 1);

CREATE VIEW live_anchored_definition_normalized_names AS
SELECT units.lang, files.generation, files.rel_path, units.blob_oid,
       units.unit_key, units.kind, units.short_name, units.identifier,
       'anchored' AS source_kind, anchors.package_name AS prefix,
       units.normalized_fqn_tail AS tail,
       units.normalized_fqn_tail AS normalized_tail,
       units.exact_parent_fqn_tail AS exact_parent_tail,
       units.normalized_parent_fqn_tail AS normalized_parent_tail,
       units.package_fqn_tail AS package_tail,
       units.simple_type_name, units.signature
FROM code_units AS units INDEXED BY idx_code_units_anchored_normalized_tail
JOIN live_parsed_blobs AS live
  ON live.blob_oid = units.blob_oid AND live.lang = units.lang
JOIN live_workspace_files AS files
  ON files.lang = units.lang AND files.blob_oid = units.blob_oid
JOIN workspace_file_anchors AS anchors
  ON anchors.lang = files.lang
 AND anchors.generation = files.generation
 AND anchors.file_id = files.file_id
 AND anchors.anchor_kind = units.fq_anchor_kind
 AND anchors.anchor_pop = units.fq_anchor_pop
WHERE units.fq_anchor_kind IS NOT NULL
  AND units.normalized_fqn_tail IS NOT NULL
  AND (units.in_declarations = 1 OR units.in_definition_lookup = 1);
