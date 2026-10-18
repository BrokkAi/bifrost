-- Explicit lexical access regions supplement, but never replace, modifiers.
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_declaration_access_boundary_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_declaration_access_boundary_count >= 0);
CREATE TABLE source_declaration_access_boundaries (
  blob_id INTEGER NOT NULL,
  declaration_id INTEGER NOT NULL CHECK(declaration_id >= 0),
  boundary_kind INTEGER NOT NULL CHECK(boundary_kind IN (0, 1)),
  package_region TEXT,
  template_declaration_id INTEGER CHECK(template_declaration_id >= 0),
  CHECK((boundary_kind = 0 AND package_region IS NOT NULL AND length(package_region) > 0 AND template_declaration_id IS NULL)
     OR (boundary_kind = 1 AND package_region IS NULL AND template_declaration_id IS NOT NULL)),
  PRIMARY KEY(blob_id, declaration_id),
  FOREIGN KEY(blob_id, declaration_id) REFERENCES source_declarations(blob_id, declaration_id)
    ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, template_declaration_id) REFERENCES source_declarations(blob_id, declaration_id)
    DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;
-- Lexical scope occurrences join directly to their canonical declarations.
CREATE INDEX source_declarations_occurrence
ON source_declarations(blob_id, occurrence_id, declaration_id);

CREATE INDEX source_declaration_access_boundaries_template
ON source_declaration_access_boundaries(blob_id, template_declaration_id);

CREATE VIEW resolution_declaration_access_boundaries AS
SELECT site.blob_id, site.semantic_key AS definition_semantic_key,
       boundary.boundary_kind, boundary.package_region,
       template.semantic_key AS template_semantic_key
FROM source_declaration_access_boundaries AS boundary
JOIN source_scala_declaration_manifests AS seal ON seal.blob_id = boundary.blob_id
JOIN source_native_declaration_bridges AS bridge
  ON bridge.blob_id = boundary.blob_id AND bridge.declaration_id = boundary.declaration_id
JOIN resolution_semantic_sites AS site
  ON site.blob_id = bridge.blob_id AND site.source_site = bridge.source_site
 AND site.semantic_role = 'definition'
-- A canonical template owns a type-body scope. Export projections of the
-- same source declaration do not. This also covers unitless local templates.
LEFT JOIN source_native_declaration_bridges AS owner
  ON owner.blob_id = boundary.blob_id
 AND owner.declaration_id = boundary.template_declaration_id
 AND EXISTS (
   SELECT 1 FROM resolution_semantic_sites AS definition
   JOIN resolution_member_scope_properties AS scope
     ON scope.blob_id = definition.blob_id
    AND scope.definition_semantic_key = definition.semantic_key
    AND scope.scope_kind = 'type_body'
   WHERE definition.blob_id = owner.blob_id
     AND definition.source_site = owner.source_site AND definition.semantic_role = 'definition'
 )
LEFT JOIN resolution_semantic_sites AS template
  ON template.blob_id = owner.blob_id AND template.source_site = owner.source_site
 AND template.semantic_role = 'definition';

CREATE TRIGGER resolution_declaration_access_boundaries_validate
INSTEAD OF INSERT ON resolution_declaration_access_boundaries
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM resolution_declaration_access_boundaries AS boundary
    WHERE boundary.blob_id = NEW.blob_id
      AND boundary.definition_semantic_key = NEW.definition_semantic_key
      AND boundary.boundary_kind = NEW.boundary_kind
      AND boundary.package_region IS NEW.package_region
      AND boundary.template_semantic_key IS NEW.template_semantic_key
  ) THEN RAISE(ABORT, 'native access boundary must agree with canonical source authority') END;
END;

DROP VIEW source_scala_declaration_costs;
CREATE VIEW source_scala_declaration_costs AS
SELECT blob.id AS blob_id,
       1
       + (SELECT COUNT(*) FROM source_declaration_access_boundaries WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_scala_declarations WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_scala_declaration_lexical_prefixes WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_scala_declaration_lexical_scopes WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_scala_declaration_path_segments WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_scala_generic_owners WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_scala_generic_parameters WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_scala_generic_supertypes WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_scala_type_expressions WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_scala_type_expression_segments WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_scala_type_expression_arguments WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_scala_callables WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_scala_callable_lists WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_scala_callable_parameters WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_scala_callable_parameter_path_segments WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_scala_callable_path_segments WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_scala_callable_function_paths WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_scala_callable_function_path_cells WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_scala_callable_function_path_segments WHERE blob_id = blob.id)
         AS logical_rows,
       COALESCE((SELECT SUM(length(CAST(package_region AS BLOB))) FROM source_declaration_access_boundaries WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(prefix AS BLOB)))
                 FROM source_scala_declaration_lexical_prefixes WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(segment AS BLOB)))
                   FROM source_scala_declaration_path_segments WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(name AS BLOB)))
                   FROM source_scala_generic_parameters WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(segment AS BLOB)))
                   FROM source_scala_type_expression_segments WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(segment AS BLOB)))
                   FROM source_scala_callable_parameter_path_segments WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(segment AS BLOB)))
                   FROM source_scala_callable_path_segments WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(segment AS BLOB)))
                   FROM source_scala_callable_function_path_segments WHERE blob_id = blob.id), 0)
         AS payload_bytes
FROM blobs AS blob;

CREATE TRIGGER source_declaration_access_boundaries_no_delete_after_seal
BEFORE DELETE ON source_declaration_access_boundaries
WHEN EXISTS (SELECT 1 FROM source_scala_declaration_manifests WHERE blob_id = OLD.blob_id) AND EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
BEGIN SELECT RAISE(ABORT, 'sealed Scala source facts are immutable'); END;

CREATE TRIGGER source_declaration_access_boundaries_no_insert_after_seal
BEFORE INSERT ON source_declaration_access_boundaries
WHEN EXISTS (SELECT 1 FROM source_scala_declaration_manifests WHERE blob_id = NEW.blob_id) AND EXISTS (SELECT 1 FROM blobs WHERE id = NEW.blob_id)
BEGIN SELECT RAISE(ABORT, 'sealed Scala source facts are immutable'); END;

CREATE TRIGGER source_declaration_access_boundaries_no_update_after_seal
BEFORE UPDATE ON source_declaration_access_boundaries
WHEN EXISTS (SELECT 1 FROM source_scala_declaration_manifests WHERE blob_id IN (OLD.blob_id, NEW.blob_id)) AND EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id OR id = NEW.blob_id)
BEGIN SELECT RAISE(ABORT, 'sealed Scala source facts are immutable'); END;
