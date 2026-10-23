-- All same-CodeUnit cfg alternatives contribute possible target arities.
-- A complete signature and the authored parameter-list marker establish an
-- empty list. Absent parameter rows alone never establish arity zero.
SELECT CASE WHEN callable.parameters_occurrence_id IS NOT NULL
                 AND signature.body IS NOT NULL
                 AND json_extract(signature.body,'$[2]') IS NULL
                 AND NOT EXISTS (
                   SELECT 1 FROM json_each(signature.body,'$[1]') AS repeated
                   WHERE repeated.value->>2<>0
                 )
                 AND (SELECT COUNT(*) FROM source_rust_callable_parameters AS parameter
                      WHERE parameter.blob_id=alternative.blob_id
                        AND parameter.declaration_id=alternative.declaration_id)
                     = json_array_length(signature.body,'$[1]') + EXISTS (
                       SELECT 1 FROM source_rust_callable_parameters AS receiver
                       WHERE receiver.blob_id=alternative.blob_id
                         AND receiver.declaration_id=alternative.declaration_id
                         AND (receiver.syntax_kind='self_parameter' OR receiver.label='self')
                     )
            THEN json_array_length(signature.body,'$[1]') END AS ordinary_arity,
       EXISTS (
         SELECT 1 FROM source_rust_callable_parameters AS receiver
         WHERE receiver.blob_id=alternative.blob_id
           AND receiver.declaration_id=alternative.declaration_id
           AND (receiver.syntax_kind='self_parameter' OR receiver.label='self')
       ) AS has_receiver
FROM temp.selected_resolution_mounts AS mount
CROSS JOIN resolution_semantic_sites AS target
  ON target.blob_id=mount.blob_id AND target.semantic_key=?2
 AND target.semantic_role='definition'
CROSS JOIN source_native_declaration_bridges AS bridge
  ON bridge.blob_id=target.blob_id AND bridge.source_site=target.source_site
CROSS JOIN source_declaration_units AS unit
  ON unit.blob_id=bridge.blob_id AND unit.declaration_id=bridge.declaration_id
CROSS JOIN source_declaration_units AS alternative
  INDEXED BY source_declaration_units_unit
  ON alternative.blob_id=unit.blob_id AND alternative.unit_key=unit.unit_key
LEFT JOIN source_native_declaration_bridges AS alternative_bridge
  ON alternative_bridge.blob_id=alternative.blob_id
 AND alternative_bridge.declaration_id=alternative.declaration_id
LEFT JOIN resolution_semantic_sites AS alternative_site
  ON alternative_site.blob_id=alternative_bridge.blob_id
 AND alternative_site.source_site=alternative_bridge.source_site
 AND alternative_site.semantic_role='definition'
LEFT JOIN resolution_callable_signatures AS signature
  ON signature.blob_id=alternative_site.blob_id
 AND signature.definition=alternative_site.semantic_key
LEFT JOIN source_rust_callable_items AS callable
  ON callable.blob_id=alternative.blob_id
 AND callable.declaration_id=alternative.declaration_id
WHERE mount.mount_ordinal=?1
