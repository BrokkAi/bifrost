-- Lean content-only views for the Identifier/IdentifierPrefix definition-
-- lookup shapes (issue #2588 residual cost).
--
-- `live_definition_identifiers` (0026) selects from the wide three-arm
-- `live_definition_exact_names` compound view (0026). Unlike the
-- parent-tail/normalized-tail shapes migration 0027 split, both of
-- `live_definition_identifiers`'s content arms already seek
-- `idx_code_units_lang_identifier_lookup` (0018) directly: that index is
-- keyed on `(lang, identifier)` with no `fq_anchor_kind` prefix, so it is
-- not anchor-partitioned the way `idx_code_units_anchored_parent_identifier`
-- is, and neither arm needs a correlated `workspace_file_anchors` scan to
-- reach it. But SQLite still fully materializes the wide compound view as a
-- co-routine before joining it against `code_units` in the caller's query,
-- and it still unconditionally computes the view's third, path-derived arm
-- -- including, for JavaScript/TypeScript, a correlated `import_statements`
-- existence check per candidate row -- even though every caller of this
-- shape filters `source_kind <> 'path'` and so discards 100% of that arm's
-- rows. `AnalyzerDefinitionLookup` (see
-- `crates/bifrost-analysis/src/analyzer/analyzer_definition_lookup.rs`)
-- issues `Identifier`/`IdentifierPrefix` requests on nearly every
-- exact-name and normalized-name lookup (consulting the identifier view for
-- source-spelling and mounted-name compatibility), so this cost is paid at
-- the same call volume as the shapes 0027 already addressed, not just on
-- literal identifier searches.
--
-- Keep the stable and anchored arms' join structure identical to
-- `live_definition_exact_names`'s corresponding arms, including the
-- anchored arm's join to `workspace_file_anchors` (which enforces the same
-- anchor-liveness membership the wide view enforces) and the
-- `exact_fqn_tail IS NOT NULL` filter the wide view's non-path arms both
-- carry, so each new view's row set is exactly the wide view's matching arm
-- minus the path-derived arm neither `Identifier` nor `IdentifierPrefix`
-- ever wanted in the first place. `live_definition_identifiers` remains
-- unchanged and in place for its other caller (the blob-local lookup pinned
-- by `relational_definition_views_enforce_identity_constraints_and_index_name_lookups`
-- in `crates/bifrost-core/src/cache_db.rs`).
CREATE VIEW live_stable_definition_identifiers AS
SELECT units.lang, files.generation, files.rel_path, units.blob_oid,
       units.unit_key, units.kind, units.identifier,
       'content' AS source_kind
FROM code_units AS units INDEXED BY idx_code_units_lang_identifier_lookup
JOIN live_parsed_blobs AS live
  ON live.blob_oid = units.blob_oid AND live.lang = units.lang
JOIN live_workspace_files AS files
  ON files.lang = units.lang AND files.blob_oid = units.blob_oid
WHERE units.fq_anchor_kind IS NULL
  AND units.exact_fqn_tail IS NOT NULL
  AND (units.in_declarations = 1 OR units.in_definition_lookup = 1);

CREATE VIEW live_anchored_definition_identifiers AS
SELECT units.lang, files.generation, files.rel_path, units.blob_oid,
       units.unit_key, units.kind, units.identifier,
       'anchored' AS source_kind
FROM code_units AS units INDEXED BY idx_code_units_lang_identifier_lookup
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
  AND units.exact_fqn_tail IS NOT NULL
  AND (units.in_declarations = 1 OR units.in_definition_lookup = 1);
