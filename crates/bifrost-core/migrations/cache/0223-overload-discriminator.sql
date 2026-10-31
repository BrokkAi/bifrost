-- Canonical declaration-time overload identity, independent of source trivia.
ALTER TABLE unit_signature_metadata ADD COLUMN overload_discriminator BLOB
  CHECK(length(overload_discriminator) = 32);

DROP VIEW unit_signature_metadata_values;
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
