-- Compatible vocabulary expansion. Existing rows retain their meanings.
-- Rows written under an older C# bundle never contain the new values:
-- resolution-bundle-csharp-v62 separates their source facts from older bundles.
DROP TRIGGER resolution_declaration_visibility_properties_insert_canonical;
DROP TRIGGER source_declaration_visibilities_no_delete_after_seal;
DROP TRIGGER source_declaration_visibilities_no_insert_after_seal;
DROP TRIGGER source_declaration_visibilities_no_update_after_seal;
DROP TRIGGER source_declaration_visibilities_require_expected;
DROP TRIGGER source_declaration_visibility_manifests_validate_contents;
DROP VIEW resolution_declaration_visibility_properties;
DROP VIEW unit_signature_metadata_values;
CREATE TABLE source_declaration_visibilities_new(
  blob_id        INTEGER NOT NULL,
  declaration_id INTEGER NOT NULL CHECK(declaration_id >= 0),
  visibility     TEXT NOT NULL CHECK(visibility IN (
    'public', 'protected', 'internal', 'package_private', 'private',
    'crate_or_module', 'unknown', 'protected_internal', 'private_protected'
  )),
  PRIMARY KEY(blob_id, declaration_id),
  FOREIGN KEY(blob_id)
    REFERENCES source_fact_manifests(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, declaration_id)
    REFERENCES source_declarations(blob_id, declaration_id)
    ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;
INSERT INTO source_declaration_visibilities_new SELECT * FROM source_declaration_visibilities;
DROP TABLE source_declaration_visibilities;
ALTER TABLE source_declaration_visibilities_new RENAME TO source_declaration_visibilities;

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

CREATE VIEW unit_signature_metadata_values AS
SELECT metadata.blob_id, metadata.lang, metadata.unit_key, metadata.ordinal,
       metadata.label,
       CASE WHEN metadata.parameter_count IS NULL THEN metadata.parameters
            ELSE (SELECT json_group_array(json_object(
                    'label', parameter.label, 'name', parameter.name,
                    'start_byte', parameter.start_byte, 'end_byte', parameter.end_byte)
                    ORDER BY parameter.ordinal)
                  FROM unit_signature_parameters AS parameter
                  WHERE parameter.blob_id = metadata.blob_id
                    AND parameter.unit_key = metadata.unit_key
                    AND parameter.metadata_ordinal = metadata.ordinal)
       END AS parameters,
       metadata.return_type_text,
       metadata.return_type_identity, metadata.underlying_type_identity,
       metadata.declaration_only, metadata.callable_arity_required,
       metadata.callable_arity_total, metadata.callable_arity_repeated,
       metadata.type_parameters, metadata.bare_return_type_parameter,
       metadata.callable_linkage, metadata.dispatch_extensibility,
       metadata.extension_receiver_type, metadata.extension_receiver_type_identity,
       metadata.extension_receiver_is_unconstrained, metadata.field_is_static,
       metadata.field_is_final, metadata.field_has_initializer,
       metadata.cpp_field_linkage, metadata.companion_object,
       metadata.callable_is_static, metadata.callable_is_constructor,
       CASE
         WHEN meta.declaration_visibility_version IS NOT NULL
          AND units.synthetic = 0
          THEN CASE
            WHEN readiness.available = 1
             AND (SELECT COUNT(*)
                  FROM source_declaration_metadata_bridges AS bridge
                  WHERE bridge.blob_id = metadata.blob_id
                    AND bridge.unit_key = metadata.unit_key
                    AND bridge.metadata_ordinal = metadata.ordinal) > 0
             AND (SELECT COUNT(visibility.declaration_id)
                  FROM source_declaration_metadata_bridges AS bridge
                  JOIN source_declaration_visibilities AS visibility
                    ON visibility.blob_id = bridge.blob_id
                   AND visibility.declaration_id = bridge.declaration_id
                  WHERE bridge.blob_id = metadata.blob_id
                    AND bridge.unit_key = metadata.unit_key
                    AND bridge.metadata_ordinal = metadata.ordinal)
                 = (SELECT COUNT(*)
                    FROM source_declaration_metadata_bridges AS bridge
                    WHERE bridge.blob_id = metadata.blob_id
                      AND bridge.unit_key = metadata.unit_key
                      AND bridge.metadata_ordinal = metadata.ordinal)
             AND (SELECT COUNT(DISTINCT visibility.visibility)
                  FROM source_declaration_metadata_bridges AS bridge
                  JOIN source_declaration_visibilities AS visibility
                    ON visibility.blob_id = bridge.blob_id
                   AND visibility.declaration_id = bridge.declaration_id
                  WHERE bridge.blob_id = metadata.blob_id
                    AND bridge.unit_key = metadata.unit_key
                    AND bridge.metadata_ordinal = metadata.ordinal) = 1
            THEN (SELECT MIN(visibility.visibility)
                  FROM source_declaration_metadata_bridges AS bridge
                  JOIN source_declaration_visibilities AS visibility
                    ON visibility.blob_id = bridge.blob_id
                   AND visibility.declaration_id = bridge.declaration_id
                  WHERE bridge.blob_id = metadata.blob_id
                    AND bridge.unit_key = metadata.unit_key
                    AND bridge.metadata_ordinal = metadata.ordinal)
            ELSE NULL
          END
         ELSE metadata.callable_declared_visibility
       END AS callable_declared_visibility,
       metadata.callable_modifiers_recorded, metadata.callable_parameter_types,
       metadata.callable_is_native,
       CASE WHEN metadata.class_like_kind IS NULL THEN metadata.class_like_is_interface
            ELSE metadata.class_like_kind = 'interface' END AS class_like_is_interface,
       metadata.class_like_is_static,
       metadata.type_parameters_recorded, metadata.result_type_identities,
       metadata.parameter_type_identities, metadata.callable_override_modifier,
       metadata.overload_discriminator,
       metadata.java_constructor_shape, metadata.java_constructor_arity_required,
       metadata.java_constructor_arity_total, metadata.java_constructor_arity_repeated,
       metadata.class_like_kind,
       CASE
         WHEN metadata.parameter_count IS NOT NULL
          AND metadata.parameter_count <> (SELECT COUNT(*) FROM unit_signature_parameters AS parameter
                 WHERE parameter.blob_id = metadata.blob_id
                   AND parameter.unit_key = metadata.unit_key
                   AND parameter.metadata_ordinal = metadata.ordinal) THEN 0
         WHEN readiness.available = 0 THEN 0
         WHEN meta.metadata_bridges_required = 1
          AND (units.synthetic = 0 OR EXISTS (
            SELECT 1 FROM source_declaration_units AS source_unit
            WHERE source_unit.blob_id = metadata.blob_id AND source_unit.unit_key = metadata.unit_key
          ))
          AND NOT EXISTS (
            SELECT 1 FROM source_declaration_metadata_bridges AS bridge
            WHERE bridge.blob_id = metadata.blob_id AND bridge.unit_key = metadata.unit_key
              AND bridge.metadata_ordinal = metadata.ordinal
          ) THEN 0
         WHEN meta.java_type_constructor_version IS NOT NULL
          AND units.kind = 0 AND units.synthetic = 0
          AND metadata.java_constructor_shape IS NULL THEN 0
         WHEN meta.declaration_visibility_version IS NULL OR units.synthetic = 1 THEN 1
         WHEN (SELECT COUNT(*)
               FROM source_declaration_metadata_bridges AS bridge
               WHERE bridge.blob_id = metadata.blob_id
                 AND bridge.unit_key = metadata.unit_key
                 AND bridge.metadata_ordinal = metadata.ordinal) > 0
          AND (SELECT COUNT(visibility.declaration_id)
               FROM source_declaration_metadata_bridges AS bridge
               JOIN source_declaration_visibilities AS visibility
                 ON visibility.blob_id = bridge.blob_id
                AND visibility.declaration_id = bridge.declaration_id
               WHERE bridge.blob_id = metadata.blob_id
                 AND bridge.unit_key = metadata.unit_key
                 AND bridge.metadata_ordinal = metadata.ordinal)
              = (SELECT COUNT(*)
                 FROM source_declaration_metadata_bridges AS bridge
                 WHERE bridge.blob_id = metadata.blob_id
                   AND bridge.unit_key = metadata.unit_key
                   AND bridge.metadata_ordinal = metadata.ordinal)
          AND (SELECT COUNT(DISTINCT visibility.visibility)
               FROM source_declaration_metadata_bridges AS bridge
               JOIN source_declaration_visibilities AS visibility
                 ON visibility.blob_id = bridge.blob_id
                AND visibility.declaration_id = bridge.declaration_id
               WHERE bridge.blob_id = metadata.blob_id
                 AND bridge.unit_key = metadata.unit_key
                 AND bridge.metadata_ordinal = metadata.ordinal) = 1
         THEN 1
         ELSE 0
       END AS metadata_available
FROM unit_signature_metadata AS metadata
JOIN blob_meta AS meta ON meta.blob_id = metadata.blob_id
JOIN code_units AS units
  ON units.blob_id = metadata.blob_id AND units.unit_key = metadata.unit_key
JOIN source_declaration_visibility_readiness AS readiness
  ON readiness.blob_id = metadata.blob_id;

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

CREATE TRIGGER source_declaration_visibilities_no_delete_after_seal
BEFORE DELETE ON source_declaration_visibilities
WHEN EXISTS (SELECT 1 FROM source_declaration_visibility_manifests
             WHERE blob_id = OLD.blob_id)
 AND EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
BEGIN SELECT RAISE(ABORT, 'sealed source declaration visibility is immutable'); END;

CREATE TRIGGER source_declaration_visibilities_no_insert_after_seal
BEFORE INSERT ON source_declaration_visibilities
WHEN EXISTS (SELECT 1 FROM source_declaration_visibility_manifests
             WHERE blob_id = NEW.blob_id)
 AND EXISTS (SELECT 1 FROM blobs WHERE id = NEW.blob_id)
BEGIN SELECT RAISE(ABORT, 'sealed source declaration visibility is immutable'); END;

CREATE TRIGGER source_declaration_visibilities_no_update_after_seal
BEFORE UPDATE ON source_declaration_visibilities
WHEN EXISTS (SELECT 1 FROM source_declaration_visibility_manifests
             WHERE blob_id IN (OLD.blob_id, NEW.blob_id))
 AND EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id OR id = NEW.blob_id)
BEGIN SELECT RAISE(ABORT, 'sealed source declaration visibility is immutable'); END;

CREATE TRIGGER source_declaration_visibilities_require_expected
BEFORE INSERT ON source_declaration_visibilities
WHEN NOT EXISTS (
  SELECT 1 FROM blob_meta
  WHERE blob_id = NEW.blob_id AND declaration_visibility_version IS NOT NULL
)
BEGIN
  SELECT RAISE(ABORT, 'source declaration visibility row has no blob requirement');
END;

CREATE TRIGGER source_declaration_visibility_manifests_validate_contents
BEFORE INSERT ON source_declaration_visibility_manifests
BEGIN
  SELECT CASE WHEN EXISTS (
    SELECT 1 FROM source_declaration_visibility_manifests
    WHERE blob_id = NEW.blob_id
  ) THEN RAISE(ABORT, 'source declaration visibility marker is immutable') END;
  SELECT CASE WHEN NEW.visibility_count <> (
    SELECT COUNT(*) FROM source_declaration_visibilities
    WHERE blob_id = NEW.blob_id
  ) THEN RAISE(ABORT, 'source declaration visibility count is inconsistent') END;
  SELECT CASE WHEN NEW.native_bridge_count <> (
    SELECT COUNT(*) FROM source_native_declaration_bridges
    WHERE blob_id = NEW.blob_id
  ) THEN RAISE(ABORT, 'source native declaration bridge count is inconsistent') END;
  SELECT CASE WHEN NEW.metadata_bridge_count <> (
    SELECT COUNT(*) FROM source_declaration_metadata_bridges
    WHERE blob_id = NEW.blob_id
  ) THEN RAISE(ABORT, 'source declaration metadata bridge count is inconsistent') END;
  SELECT CASE WHEN EXISTS (
    SELECT 1
    FROM unit_signature_metadata AS metadata
    JOIN code_units AS unit
      ON unit.blob_id = metadata.blob_id
     AND unit.unit_key = metadata.unit_key
    WHERE metadata.blob_id = NEW.blob_id
      AND unit.synthetic = 0
      AND NOT EXISTS (
        SELECT 1
        FROM source_declaration_metadata_bridges AS bridge
        WHERE bridge.blob_id = metadata.blob_id
          AND bridge.unit_key = metadata.unit_key
          AND bridge.metadata_ordinal = metadata.ordinal
      )
  ) THEN RAISE(ABORT, 'source declaration metadata bridge coverage is incomplete') END;
  SELECT CASE WHEN EXISTS (
    SELECT 1
    FROM source_declaration_metadata_bridges AS bridge
    JOIN code_units AS unit
      ON unit.blob_id = bridge.blob_id AND unit.unit_key = bridge.unit_key
    LEFT JOIN source_declaration_visibilities AS visibility
      ON visibility.blob_id = bridge.blob_id
     AND visibility.declaration_id = bridge.declaration_id
    WHERE bridge.blob_id = NEW.blob_id
      AND unit.synthetic = 0
      AND visibility.declaration_id IS NULL
  ) THEN RAISE(ABORT, 'source declaration metadata visibility is missing') END;
  SELECT CASE WHEN EXISTS (
    SELECT 1
    FROM source_declaration_metadata_bridges AS bridge
    JOIN code_units AS unit
      ON unit.blob_id = bridge.blob_id AND unit.unit_key = bridge.unit_key
    JOIN source_declaration_visibilities AS visibility
      ON visibility.blob_id = bridge.blob_id
     AND visibility.declaration_id = bridge.declaration_id
    WHERE bridge.blob_id = NEW.blob_id
      AND unit.synthetic = 0
    GROUP BY bridge.blob_id, bridge.unit_key, bridge.metadata_ordinal
    HAVING COUNT(DISTINCT visibility.visibility) <> 1
  ) THEN RAISE(ABORT, 'source declaration metadata visibility conflicts') END;
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
