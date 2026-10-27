-- Access visibility never belongs to a parameter or local-variable binding.
-- Keep item definitions, including modules, functions and impl methods, intact.
DROP VIEW resolution_declaration_visibility_properties;

CREATE VIEW resolution_declaration_visibility_properties AS
SELECT legacy.blob_id, legacy.definition_semantic_key, legacy.visibility
FROM legacy_resolution_declaration_visibility_properties AS legacy
LEFT JOIN blob_meta AS meta ON meta.blob_id = legacy.blob_id
WHERE (meta.blob_id IS NULL OR meta.declaration_visibility_version IS NULL)
  AND NOT EXISTS (
    SELECT 1 FROM source_declaration_visibility_manifests AS marker
    WHERE marker.blob_id = legacy.blob_id
  )
UNION ALL
SELECT site.blob_id, site.semantic_key, visibility.visibility
FROM resolution_semantic_sites AS site
JOIN source_native_declaration_bridges AS native
  ON native.blob_id = site.blob_id AND native.source_site = site.source_site
JOIN source_declaration_visibilities AS visibility
  ON visibility.blob_id = native.blob_id
 AND visibility.declaration_id = native.declaration_id
JOIN blob_meta AS meta ON meta.blob_id = site.blob_id
JOIN source_declaration_visibility_readiness AS readiness
  ON readiness.blob_id = site.blob_id AND readiness.available = 1
WHERE meta.declaration_visibility_version IS NOT NULL
  AND site.semantic_role = 'definition'
  AND NOT EXISTS (
    SELECT 1 FROM source_declarations AS declaration
    WHERE declaration.blob_id = native.blob_id
      AND declaration.declaration_id = native.declaration_id
      AND declaration.lexical_kind IN (
        'parameter', 'receiver_parameter', 'catch_parameter', 'lambda_parameter',
        'local_variable', 'enhanced_for_variable', 'pattern_variable', 'resource_variable'
      )
  );

CREATE TRIGGER resolution_declaration_visibility_properties_insert_canonical
INSTEAD OF INSERT ON resolution_declaration_visibility_properties
WHEN EXISTS (
  SELECT 1 FROM blob_meta
  WHERE blob_id = NEW.blob_id AND declaration_visibility_version IS NOT NULL
)
BEGIN
  SELECT CASE WHEN EXISTS (
    SELECT 1 FROM resolution_fragment_interiors
    WHERE blob_id = NEW.blob_id AND publication_state = 'complete'
  ) THEN RAISE(ABORT, 'sealed resolution interior is immutable') END;
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM resolution_semantic_sites AS site
    JOIN source_native_declaration_bridges AS native
      ON native.blob_id = site.blob_id AND native.source_site = site.source_site
    JOIN source_declaration_visibilities AS visibility
      ON visibility.blob_id = native.blob_id
     AND visibility.declaration_id = native.declaration_id
    JOIN source_declaration_visibility_readiness AS readiness
      ON readiness.blob_id = site.blob_id AND readiness.available = 1
    WHERE site.blob_id = NEW.blob_id
      AND site.semantic_role = 'definition'
      AND site.semantic_key = NEW.definition_semantic_key
      AND visibility.visibility = NEW.visibility
  ) THEN RAISE(ABORT, 'native visibility disagrees with canonical source visibility') END;
END;

CREATE TRIGGER resolution_declaration_visibility_properties_insert_legacy
INSTEAD OF INSERT ON resolution_declaration_visibility_properties
WHEN NOT EXISTS (
  SELECT 1 FROM blob_meta
  WHERE blob_id = NEW.blob_id AND declaration_visibility_version IS NOT NULL
)
 AND NOT EXISTS (
   SELECT 1 FROM source_declaration_visibility_manifests
   WHERE blob_id = NEW.blob_id
 )
BEGIN
  INSERT INTO legacy_resolution_declaration_visibility_properties(
    blob_id, definition_semantic_key, visibility
  ) VALUES(NEW.blob_id, NEW.definition_semantic_key, NEW.visibility);
END;
