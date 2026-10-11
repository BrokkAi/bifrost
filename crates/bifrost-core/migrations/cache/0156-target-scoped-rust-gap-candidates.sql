ALTER TABLE resolution_fragment_interiors
  ADD COLUMN expected_rust_reverse_gap_candidate_count INTEGER NOT NULL DEFAULT 0
    CHECK(expected_rust_reverse_gap_candidate_count >= 0);

-- The reverse-gap candidate reader needs structured identifiers from a local
-- macro_rules transcriber after source facts have been hydrated from SQLite.
ALTER TABLE source_rust_macro_arms
  ADD COLUMN transcriber_identifiers TEXT
    CHECK(transcriber_identifiers IS NULL OR
      (json_valid(transcriber_identifiers)
        AND json_type(transcriber_identifiers) = 'array'));

DROP TRIGGER source_rust_item_manifests_validate_accounting;
CREATE TRIGGER source_rust_item_manifests_validate_accounting
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND EXISTS (
   SELECT 1 FROM source_rust_item_manifests AS item
   WHERE item.blob_id = NEW.blob_id
     AND (item.logical_rows <> 1
           + (SELECT COUNT(*) FROM source_rust_item_syntax WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_item_contexts WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_impl_items WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_trait_items WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_alias_items WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_callable_items WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_value_items WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_item_generic_parameters WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_item_body_children WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_callable_parameters WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_item_macro_expansions WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_item_import_contexts WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_types WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_type_children WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_type_wrappers WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_type_segments WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_type_generic_lists WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_type_generic_arguments WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_macro_definitions WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_macro_arms WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_macro_pattern_nodes WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_macro_ident_roles WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_macro_inputs WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_macro_input_tokens WHERE blob_id = NEW.blob_id)
       OR item.payload_bytes <> COALESCE((SELECT SUM(COALESCE(length(CAST(syntax_kind AS BLOB)), 0) + COALESCE(length(CAST(name AS BLOB)), 0)) FROM source_rust_item_generic_parameters WHERE blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(COALESCE(length(CAST(syntax_kind AS BLOB)), 0)) FROM source_rust_item_body_children WHERE blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(COALESCE(length(CAST(syntax_kind AS BLOB)), 0) + COALESCE(length(CAST(label AS BLOB)), 0)) FROM source_rust_callable_parameters WHERE blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(COALESCE(length(CAST(unsupported_syntax_kind AS BLOB)), 0)) FROM source_rust_types WHERE blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(COALESCE(length(CAST(name AS BLOB)), 0)) FROM source_rust_type_segments WHERE blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(COALESCE(length(CAST(literal_kind AS BLOB)), 0)
                              + COALESCE(length(CAST(literal_text AS BLOB)), 0)
                              + COALESCE(length(CAST(binding_name AS BLOB)), 0)
                              + COALESCE(length(CAST(separator AS BLOB)), 0))
                      FROM source_rust_macro_pattern_nodes WHERE blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(length(CAST(name AS BLOB)))
                       FROM source_rust_macro_ident_roles WHERE blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(length(CAST(transcriber_identifiers AS BLOB)))
                       FROM source_rust_macro_arms WHERE blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(length(CAST(source AS BLOB))) FROM source_rust_macro_inputs WHERE blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(length(CAST(syntax_kind AS BLOB))) FROM source_rust_macro_input_tokens WHERE blob_id = NEW.blob_id), 0))
 )
BEGIN SELECT RAISE(ABORT, 'canonical Rust item accounting is inconsistent'); END;

CREATE TABLE resolution_rust_reverse_gap_candidates(
  blob_id        INTEGER NOT NULL,
  site           INTEGER NOT NULL CHECK(site BETWEEN 0 AND 4294967295),
  candidate_name TEXT NOT NULL CHECK(length(candidate_name) > 0),
  namespace      TEXT NOT NULL CHECK(namespace IN (
    '*', 'type', 'value', 'callable', 'constructor', 'macro', 'constant',
    'type_or_value', 'package'
  )),
  PRIMARY KEY(blob_id, site, candidate_name, namespace),
  FOREIGN KEY(blob_id)
    REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_rust_reverse_gap_candidates_name
  ON resolution_rust_reverse_gap_candidates(candidate_name, namespace, blob_id, site);

CREATE INDEX resolution_identities_spelling
  ON resolution_identities(spelling)
  WHERE spelling IS NOT NULL;

CREATE INDEX resolution_rust_reverse_gap_candidates_site
  ON resolution_rust_reverse_gap_candidates(blob_id, site);

CREATE INDEX source_rust_type_segments_name
  ON source_rust_type_segments(name, blob_id, type_occurrence_id, ordinal);

CREATE INDEX resolution_gaps_reason_covers
  ON resolution_gaps(blob_id, reason, covers);

CREATE INDEX rust_crate_dependencies_target_workspace
  ON rust_crate_dependencies(dependency_crate_key, boundary, topology_id)
  WHERE boundary = 'workspace';

CREATE INDEX resolution_root_route_segments_reference
  ON resolution_root_route_segments(blob_id, reference_source_site, position, path_key)
  WHERE reference_source_site IS NOT NULL;

CREATE INDEX idx_source_imports_identifier
  ON source_imports(identifier, blob_id, import_id)
  WHERE identifier IS NOT NULL;

CREATE INDEX idx_rust_import_targets_source_import
  ON rust_import_targets(blob_id, source_import_id, bound_name)
  WHERE source_import_id IS NOT NULL;

CREATE INDEX idx_rust_import_targets_imported_name
  ON rust_import_targets(imported_name, blob_id, bound_name)
  WHERE source_import_id IS NULL AND imported_name IS NOT NULL;

CREATE INDEX idx_rust_import_targets_unresolved_source_alias
  ON rust_import_targets(blob_id, source_import_id, bound_name)
  WHERE source_import_id IS NOT NULL AND bound_name IS NOT NULL;

CREATE INDEX idx_rust_import_targets_unresolved_legacy_alias
  ON rust_import_targets(blob_id, bound_name)
  WHERE source_import_id IS NULL AND imported_name IS NULL AND bound_name IS NOT NULL;

CREATE TRIGGER resolution_fragment_interiors_validate_rust_reverse_gap_candidates
BEFORE UPDATE OF publication_state ON resolution_fragment_interiors
WHEN OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND (
   (SELECT COUNT(*) FROM resolution_rust_reverse_gap_candidates
    WHERE blob_id = NEW.blob_id) <> NEW.expected_rust_reverse_gap_candidate_count
   OR EXISTS (
     SELECT 1 FROM resolution_rust_reverse_gap_candidates AS candidate
     WHERE candidate.blob_id = NEW.blob_id
       AND NOT EXISTS (
         SELECT 1 FROM resolution_gap_reasons AS reason
         WHERE reason.blob_id = candidate.blob_id AND reason.site = candidate.site
       )
   )
 )
BEGIN
  SELECT RAISE(ABORT, 'Rust reverse-gap candidate rows are inconsistent');
END;
