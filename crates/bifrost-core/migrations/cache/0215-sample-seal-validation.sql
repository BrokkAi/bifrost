-- Sample expensive per-blob consistency checks in production (#6390).
-- State-order and immutability guards remain unconditional. A writer missing
-- bifrost_seal_validates fails loudly rather than silently bypassing validation.

DROP TRIGGER resolution_catalog_authority_seal;
CREATE TRIGGER resolution_catalog_authority_seal
BEFORE UPDATE OF publication_state ON resolution_fragment_interiors
WHEN bifrost_seal_validates(NEW.blob_id) AND NEW.publication_state='complete' AND (
  NEW.expected_rust_reference_context_count <> (SELECT COUNT(*) FROM resolution_rust_reference_contexts WHERE blob_id=NEW.blob_id)
  OR NEW.expected_rust_declaration_authority_count <> (SELECT COUNT(*) FROM resolution_rust_declaration_authorities WHERE blob_id=NEW.blob_id)
  OR
  NEW.expected_semantic_catalog_count <> (SELECT COUNT(*) FROM resolution_semantic_catalog WHERE blob_id=NEW.blob_id)
  OR NEW.expected_node_catalog_count <> (SELECT COUNT(*) FROM resolution_node_catalog WHERE blob_id=NEW.blob_id)
  OR NEW.expected_contract_reference_count <> (SELECT COUNT(*) FROM resolution_contract_references WHERE blob_id=NEW.blob_id)
)
BEGIN SELECT RAISE(ABORT, 'resolution catalog authority is incomplete'); END;

DROP TRIGGER resolution_fragment_interiors_validate_callable_parameter_owners;
CREATE TRIGGER resolution_fragment_interiors_validate_callable_parameter_owners
BEFORE UPDATE OF publication_state ON resolution_fragment_interiors
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND (
   (SELECT count(*) FROM resolution_callable_parameter_owners WHERE blob_id=NEW.blob_id)
     <> NEW.expected_callable_parameter_owner_count
   OR NEW.expected_callable_parameter_owner_count <>
     (SELECT coalesce(sum(json_array_length(body, '$[1]')), 0)
      FROM resolution_callable_signatures WHERE blob_id=NEW.blob_id)
   OR EXISTS (
     SELECT 1 FROM resolution_callable_signatures AS signature,
       json_each(signature.body, '$[1]') AS parameter
     WHERE signature.blob_id=NEW.blob_id
       AND NOT EXISTS (
         SELECT 1 FROM resolution_callable_parameter_owners AS owner
         WHERE owner.blob_id=signature.blob_id
           AND owner.parameter_definition=json_extract(parameter.value, '$[0]')
           AND owner.signature_definition=signature.definition
       )
   )
 )
BEGIN
  SELECT RAISE(ABORT, 'resolution callable parameter ownership is inconsistent');
END;

DROP TRIGGER resolution_fragment_interiors_validate_common_resolution_families;
CREATE TRIGGER resolution_fragment_interiors_validate_common_resolution_families
BEFORE UPDATE OF publication_state ON resolution_fragment_interiors
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND (
   EXISTS (
     SELECT 1
     FROM resolution_additional_definition_namespaces AS extra
     WHERE extra.blob_id = NEW.blob_id
       AND NOT EXISTS (
         SELECT 1 FROM resolution_semantic_sites AS definition
         WHERE definition.blob_id = extra.blob_id
           AND definition.semantic_key = extra.definition_semantic_key
           AND definition.semantic_role = 'definition'
       )
   )
   OR EXISTS (
     SELECT 1
     FROM resolution_definition_unit_crosswalks AS crosswalk
     WHERE crosswalk.blob_id = NEW.blob_id
       AND (
         NOT EXISTS (
           SELECT 1 FROM resolution_semantic_sites AS definition
           WHERE definition.blob_id = crosswalk.blob_id
             AND definition.semantic_key = crosswalk.definition_semantic_key
             AND definition.semantic_role = 'definition'
         )
         OR NOT EXISTS (
           SELECT 1 FROM code_units AS unit
           WHERE unit.blob_id = crosswalk.blob_id
             AND unit.lang = NEW.lang
             AND unit.unit_key = crosswalk.unit_key
         )
       )
   )
 )
BEGIN
  SELECT RAISE(ABORT, 'resolution common family is inconsistent');
END;

DROP TRIGGER resolution_fragment_interiors_validate_node_payloads;
CREATE TRIGGER resolution_fragment_interiors_validate_node_payloads
BEFORE UPDATE OF publication_state ON resolution_fragment_interiors
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state='building' AND NEW.publication_state='complete'
 AND EXISTS (
   SELECT 1 FROM resolution_node_catalog AS node WHERE node.blob_id=NEW.blob_id
     AND (
       (node.semantic_local_key IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM resolution_semantic_catalog AS semantic
         WHERE semantic.blob_id=node.blob_id AND semantic.local_key=node.semantic_local_key
           AND semantic.shared_identity IS NULL
       ))
       OR (node.semantic_shared_identity IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM resolution_semantic_catalog AS semantic
         WHERE semantic.blob_id=node.blob_id AND semantic.shared_identity=node.semantic_shared_identity
       ))
       OR (node.target_local_key IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM resolution_node_catalog AS target
         WHERE target.blob_id=node.blob_id AND target.local_key=node.target_local_key
       ))
       OR (node.kind IN (8,9) AND NOT EXISTS (
         SELECT 1 FROM resolution_sites AS site
         JOIN resolution_semantic_catalog AS semantic
           ON semantic.blob_id=site.blob_id AND semantic.local_key=site.site
         WHERE site.blob_id=node.blob_id AND site.site=node.local_key
           AND site.role=CASE node.kind WHEN 8 THEN 0 ELSE 1 END
           AND ((node.semantic_local_key=semantic.local_key AND semantic.shared_identity IS NULL)
             OR node.semantic_shared_identity=semantic.shared_identity)
       ))
     )
 )
BEGIN
  SELECT RAISE(ABORT, 'resolution node payload is inconsistent');
END;

DROP TRIGGER resolution_fragment_interiors_validate_root_prefix_keys;
CREATE TRIGGER resolution_fragment_interiors_validate_root_prefix_keys
BEFORE UPDATE OF publication_state ON resolution_fragment_interiors
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND EXISTS (
   SELECT 1 FROM resolution_paths AS path INDEXED BY resolution_paths_reverse_root_prefix
   WHERE path.blob_id = NEW.blob_id AND path.end_node = -1
     AND (EXISTS (
       SELECT 1 FROM json_each(path.end_fixed_key) AS cell
       WHERE CASE WHEN cell.type <> 'array' THEN 1
         WHEN json_array_length(cell.value) <> 3 THEN 1
         ELSE (
           ((json_type(cell.value, '$[0]') = 'integer'
             AND cell.value ->> 0 >= 0 AND json_type(cell.value, '$[1]') = 'null')
            OR (json_type(cell.value, '$[0]') = 'null'
             AND json_type(cell.value, '$[1]') = 'integer' AND cell.value ->> 1 > 0)) IS NOT TRUE
           OR (json_type(cell.value, '$[2]') = 'integer' AND cell.value ->> 2 IN (0, 1)) IS NOT TRUE
         ) END
     ) OR path.end_fixed_key <> (
       SELECT json_group_array(json(canonical_cell)) FROM (
         SELECT json_array(
           CASE WHEN signed >= 0 THEN signed ELSE NULL END,
           CASE WHEN signed < 0 THEN -signed ELSE NULL END,
           scoped) AS canonical_cell
         FROM (
           SELECT symbol.key AS ordinal,
             CASE WHEN symbol.type = 'integer' THEN symbol.value
               WHEN symbol.type = 'array' THEN
                 CASE WHEN json_type(symbol.value, '$[0]') = 'integer'
                   THEN symbol.value ->> 0 ELSE NULL END
               ELSE NULL END AS signed,
             symbol.type = 'array' AS scoped
           FROM json_each(path.body, '$[4]') AS symbol
         ) ORDER BY ordinal
       )
     ))
 )
BEGIN
  SELECT RAISE(ABORT, 'resolution root prefix key is inconsistent');
END;

DROP TRIGGER resolution_fragment_interiors_validate_rust_reverse_gap_candidates;
CREATE TRIGGER resolution_fragment_interiors_validate_rust_reverse_gap_candidates
BEFORE UPDATE OF publication_state ON resolution_fragment_interiors
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
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

DROP TRIGGER resolution_fragment_interiors_validate_shared_language_facts;
CREATE TRIGGER resolution_fragment_interiors_validate_shared_language_facts
BEFORE UPDATE OF publication_state ON resolution_fragment_interiors
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND (
   EXISTS (
     SELECT 1 FROM resolution_jvm_aliases AS alias
     JOIN resolution_sites AS declaration
       ON declaration.blob_id = alias.blob_id
      AND declaration.site = alias.declaration_site
     WHERE alias.blob_id = NEW.blob_id AND declaration.role <> 1
   )
   OR EXISTS (
     SELECT 1 FROM resolution_jvm_aliases AS alias
     LEFT JOIN resolution_jvm_alias_owner_segments AS segment
       ON segment.blob_id = alias.blob_id AND segment.alias = alias.alias
     WHERE alias.blob_id = NEW.blob_id
     GROUP BY alias.alias
     HAVING count(segment.ordinal) = 0
        OR min(segment.ordinal) <> 0
        OR max(segment.ordinal) <> count(segment.ordinal) - 1
   )
   OR EXISTS (
     SELECT 1 FROM resolution_callable_parameter_semantics AS parameter
     JOIN resolution_sites AS callable
       ON callable.blob_id = parameter.blob_id AND callable.site = parameter.callable_site
     JOIN resolution_sites AS declaration
       ON declaration.blob_id = parameter.blob_id AND declaration.site = parameter.parameter_site
     WHERE parameter.blob_id = NEW.blob_id
       AND (callable.role <> 1 OR declaration.role <> 1)
   )
   OR EXISTS (
     SELECT 1 FROM resolution_call_argument_lists AS list
     WHERE list.blob_id = NEW.blob_id
     GROUP BY list.call_site
     HAVING min(list.list_ordinal) <> 0
        OR max(list.list_ordinal) <> count(*) - 1
   )
   OR EXISTS (
     SELECT 1 FROM resolution_callable_parameter_lists AS list
     WHERE list.blob_id = NEW.blob_id
     GROUP BY list.callable_site
     HAVING min(list.list_ordinal) <> 0
        OR max(list.list_ordinal) <> count(*) - 1
   )
   OR EXISTS (
     SELECT 1 FROM resolution_package_route_segments AS segment
     JOIN resolution_package_routes AS route
       ON route.blob_id = segment.blob_id
      AND route.package_scope_node_key = segment.package_scope_node_key
     WHERE segment.blob_id = NEW.blob_id
     GROUP BY segment.package_scope_node_key
     HAVING route.declaration_site IS NULL
        OR min(segment.ordinal) <> 0
        OR max(segment.ordinal) <> count(*) - 1
   )
   OR EXISTS (
     SELECT 1 FROM resolution_package_routes AS route
     JOIN resolution_sites AS declaration
       ON declaration.blob_id = route.blob_id
      AND declaration.site = route.declaration_site
     WHERE route.blob_id = NEW.blob_id AND declaration.role <> 1
   )
   OR EXISTS (
     SELECT 1 FROM resolution_package_object_exports AS export
     JOIN resolution_sites AS package_object
       ON package_object.blob_id = export.blob_id
      AND package_object.site = export.package_object_site
     JOIN resolution_sites AS member
       ON member.blob_id = export.blob_id
      AND member.site = export.member_site
     WHERE export.blob_id = NEW.blob_id
       AND (package_object.role <> 1 OR member.role <> 1)
   )
   OR EXISTS (
     SELECT 1 FROM resolution_extension_receivers AS receiver
     JOIN resolution_sites AS callable
       ON callable.blob_id = receiver.blob_id AND callable.site = receiver.callable_site
     WHERE receiver.blob_id = NEW.blob_id AND callable.role <> 1
   )
   OR EXISTS (
     SELECT 1 FROM resolution_singleton_relations AS relation
     JOIN resolution_sites AS declaration
       ON declaration.blob_id = relation.blob_id AND declaration.site = relation.declaration_site
     WHERE relation.blob_id = NEW.blob_id AND declaration.role <> 1
   )
 )
BEGIN
  SELECT RAISE(ABORT, 'resolution shared language fact rows are inconsistent');
END;

DROP TRIGGER resolution_fragment_interiors_validate_source_native_declaration_bridges;
CREATE TRIGGER resolution_fragment_interiors_validate_source_native_declaration_bridges
BEFORE UPDATE OF publication_state ON resolution_fragment_interiors
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND EXISTS (
   SELECT 1
   FROM source_native_declaration_bridges AS bridge
   LEFT JOIN resolution_semantic_sites AS site
     ON site.blob_id = bridge.blob_id AND site.source_site = bridge.source_site
   WHERE bridge.blob_id = NEW.blob_id
     AND (site.source_site IS NULL OR site.semantic_role <> 'definition')
 )
BEGIN
  SELECT RAISE(ABORT, 'source native declaration bridge does not name a definition site');
END;

DROP TRIGGER source_fact_manifests_require_java_type_constructor_shapes;
CREATE TRIGGER source_fact_manifests_require_java_type_constructor_shapes
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND NEW.publication_state = 'complete'
 AND EXISTS (SELECT 1 FROM blob_meta
             WHERE blob_id = NEW.blob_id AND java_type_constructor_version IS NOT NULL)
BEGIN
  SELECT CASE WHEN EXISTS (
    SELECT 1 FROM code_units AS units
    WHERE units.blob_id = NEW.blob_id AND units.kind = 0 AND units.synthetic = 0
      AND (
        NOT EXISTS (SELECT 1 FROM unit_signature_metadata AS metadata
                    WHERE metadata.blob_id = units.blob_id
                      AND metadata.unit_key = units.unit_key)
        OR EXISTS (SELECT 1 FROM unit_signature_metadata AS metadata
                   WHERE metadata.blob_id = units.blob_id
                     AND metadata.unit_key = units.unit_key
                     AND metadata.java_constructor_shape IS NULL)
      )
  ) THEN RAISE(ABORT, 'canonical Java type constructor shape is unavailable') END;
END;

DROP TRIGGER source_fact_manifests_require_metadata_coverage;
CREATE TRIGGER source_fact_manifests_require_metadata_coverage
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND NEW.publication_state = 'complete'
 AND EXISTS (SELECT 1 FROM blob_meta WHERE blob_id = NEW.blob_id AND metadata_bridges_required = 1)
BEGIN
  SELECT CASE WHEN NEW.metadata_bridge_count IS NULL
    THEN RAISE(ABORT, 'source metadata bridge requirement is missing') END;
  SELECT CASE WHEN EXISTS (
    SELECT 1 FROM unit_signature_metadata AS metadata
    JOIN code_units AS units ON units.blob_id = metadata.blob_id AND units.unit_key = metadata.unit_key
    WHERE metadata.blob_id = NEW.blob_id
      AND (units.synthetic = 0 OR EXISTS (
        SELECT 1 FROM source_declaration_units AS source_unit
        WHERE source_unit.blob_id = metadata.blob_id AND source_unit.unit_key = metadata.unit_key
      ))
      AND NOT EXISTS (
        SELECT 1 FROM source_declaration_metadata_bridges AS bridge
        WHERE bridge.blob_id = metadata.blob_id AND bridge.unit_key = metadata.unit_key
          AND bridge.metadata_ordinal = metadata.ordinal
      )
  ) THEN RAISE(ABORT, 'source metadata bridge coverage is incomplete') END;
END;

DROP TRIGGER source_fact_manifests_require_native_bridges;
CREATE TRIGGER source_fact_manifests_require_native_bridges
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND NEW.publication_state = 'complete'
 AND NEW.native_bridge_count IS NULL
 AND EXISTS (SELECT 1 FROM blob_meta WHERE blob_id = NEW.blob_id AND native_bridges_required = 1)
BEGIN SELECT RAISE(ABORT, 'source native declaration bridge requirement is missing'); END;

DROP TRIGGER source_fact_manifests_require_signature_parameters;
CREATE TRIGGER source_fact_manifests_require_signature_parameters
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND NEW.publication_state = 'complete'
BEGIN
  SELECT CASE WHEN EXISTS (SELECT 1 FROM unit_signature_metadata AS metadata
    WHERE metadata.blob_id = NEW.blob_id AND metadata.parameter_count IS NOT NULL
      AND metadata.parameter_count <> (SELECT COUNT(*) FROM unit_signature_parameters AS parameter
        WHERE parameter.blob_id = metadata.blob_id AND parameter.unit_key = metadata.unit_key
          AND parameter.metadata_ordinal = metadata.ordinal))
    THEN RAISE(ABORT, 'canonical signature parameter publication is incomplete') END;
END;

DROP TRIGGER source_fact_manifests_validate_import_occurrences;
CREATE TRIGGER source_fact_manifests_validate_import_occurrences
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND (
  SELECT (
  EXISTS (SELECT 1 FROM import_statements AS import
          WHERE import.blob_id = NEW.blob_id
            AND import.source_import_id IS NULL
            AND (import.declaration_occurrence_id IS NULL
                 OR (import.declaration_occurrence_id < 0 OR import.declaration_occurrence_id >= NEW.occurrence_count)
                 OR (import.binder_occurrence_id IS NOT NULL AND (import.binder_occurrence_id < 0 OR import.binder_occurrence_id >= NEW.occurrence_count))))
 OR EXISTS (SELECT 1
             FROM import_statements AS import
             WHERE import.blob_id = NEW.blob_id AND import.source_import_id IS NULL
               AND (import.occurrence_binder_start_byte < import.occurrence_declaration_start_byte
                    OR import.occurrence_binder_end_byte > import.occurrence_declaration_end_byte))
 OR EXISTS (SELECT 1 FROM import_statements AS import
             WHERE import.blob_id = NEW.blob_id
             GROUP BY import.blob_id
             HAVING MIN(import.ordinal) <> 0 OR MAX(import.ordinal) <> COUNT(*) - 1)
 )
)
BEGIN SELECT RAISE(ABORT, 'canonical generic import occurrences are inconsistent'); END;

DROP TRIGGER source_fact_manifests_validate_import_path_availability;
CREATE TRIGGER source_fact_manifests_validate_import_path_availability
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND (
   EXISTS (
     SELECT 1
     FROM source_imports AS import
     WHERE import.blob_id = NEW.blob_id
       AND import.has_structured_path = 0
       AND import.path_kind IS NOT NULL
   )
   OR EXISTS (
     SELECT 1
     FROM source_import_segments AS segment
     JOIN source_imports AS import
       ON import.blob_id = segment.blob_id
      AND import.import_id = segment.import_id
     WHERE segment.blob_id = NEW.blob_id
       AND import.has_structured_path = 0
   )
   OR EXISTS (
     SELECT 1
     FROM source_import_scopes AS scope
     JOIN source_imports AS import
       ON import.blob_id = scope.blob_id
      AND import.import_id = scope.import_id
     WHERE scope.blob_id = NEW.blob_id
       AND import.has_structured_path = 0
   )
   OR EXISTS (
     SELECT 1
     FROM source_import_prefixes AS prefix
     JOIN source_imports AS import
       ON import.blob_id = prefix.blob_id
      AND import.import_id = prefix.import_id
     WHERE prefix.blob_id = NEW.blob_id
       AND import.has_structured_path = 0
   )
 )
BEGIN SELECT RAISE(ABORT, 'canonical import path availability is inconsistent'); END;

DROP TRIGGER source_fact_manifests_validate_metadata_bridges;
CREATE TRIGGER source_fact_manifests_validate_metadata_bridges
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND NEW.publication_state = 'complete'
 AND NEW.metadata_bridge_count IS NOT NULL
 AND NEW.metadata_bridge_count <> (
   SELECT COUNT(*) FROM source_declaration_metadata_bridges WHERE blob_id = NEW.blob_id
 )
BEGIN SELECT RAISE(ABORT, 'source metadata bridge count is inconsistent'); END;

DROP TRIGGER source_fact_manifests_validate_native_bridges;
CREATE TRIGGER source_fact_manifests_validate_native_bridges
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND NEW.publication_state = 'complete'
 AND NEW.native_bridge_count IS NOT NULL
 AND NEW.native_bridge_count <> (
   SELECT COUNT(*) FROM source_native_declaration_bridges WHERE blob_id = NEW.blob_id
 )
BEGIN SELECT RAISE(ABORT, 'source native declaration bridge count is inconsistent'); END;

DROP TRIGGER source_fact_manifests_validate_rust_annotations;
CREATE TRIGGER source_fact_manifests_validate_rust_annotations
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND EXISTS (SELECT 1 FROM source_rust_item_manifests WHERE blob_id = NEW.blob_id)
BEGIN
  SELECT CASE WHEN
    EXISTS (
      SELECT 1 FROM source_rust_value_items AS item
      JOIN source_declarations AS declaration
        ON declaration.blob_id = item.blob_id
       AND declaration.declaration_id = item.declaration_id
      LEFT JOIN source_rust_item_syntax AS syntax
        ON syntax.blob_id = item.blob_id
       AND syntax.occurrence_id = declaration.occurrence_id
      LEFT JOIN source_rust_declaration_properties AS property
        ON property.blob_id = item.blob_id
       AND property.declaration_id = item.declaration_id
      WHERE item.blob_id = NEW.blob_id
        AND (syntax.occurrence_id IS NULL
             OR (property.declaration_id IS NOT NULL
                 AND property.declaration_kind NOT IN (8, 9, 10, 11)))
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_value_items AS item
      JOIN source_declarations AS declaration
        ON declaration.blob_id = item.blob_id
       AND declaration.declaration_id = item.declaration_id
      JOIN source_rust_item_contexts AS context
        ON context.blob_id = item.blob_id
       AND context.occurrence_id = item.context_occurrence_id
      WHERE item.blob_id = NEW.blob_id
        AND (declaration.start_byte < context.start_byte
             OR declaration.end_byte > context.end_byte)
    )
    OR EXISTS (
      SELECT 1 FROM (
        SELECT blob_id, declaration_id, return_type_occurrence_id AS type_id
        FROM source_rust_callable_items WHERE blob_id = NEW.blob_id
        UNION ALL
        SELECT blob_id, declaration_id, declared_type_occurrence_id AS type_id
        FROM source_rust_value_items WHERE blob_id = NEW.blob_id
      ) AS item
      JOIN source_declarations AS declaration
        ON declaration.blob_id = item.blob_id
       AND declaration.declaration_id = item.declaration_id
      JOIN source_rust_types AS annotation
        ON annotation.blob_id = item.blob_id
       AND annotation.occurrence_id = item.type_id
      WHERE annotation.start_byte < declaration.start_byte
         OR annotation.end_byte > declaration.end_byte
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_type_generic_arguments AS argument
      LEFT JOIN source_rust_types AS type
        ON type.blob_id = argument.blob_id
       AND type.occurrence_id = argument.occurrence_id
      WHERE argument.blob_id = NEW.blob_id AND type.occurrence_id IS NULL
    )
  THEN RAISE(ABORT, 'canonical Rust declaration annotations are inconsistent') END;
END;

DROP TRIGGER source_fact_manifests_validate_rust_classification;
CREATE TRIGGER source_fact_manifests_validate_rust_classification
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND (
   EXISTS (
     SELECT 1 FROM source_rust_declaration_properties
     WHERE blob_id = NEW.blob_id
       AND (declaration_kind IS NULL OR macro_exported IS NULL OR trait_impl_member IS NULL
            OR (macro_exported = 1 AND declaration_kind <> 12)
            OR (constructor_non_exhaustive IS NOT NULL AND declaration_kind <> 0))
   )
   OR EXISTS (
     SELECT 1 FROM source_rust_item_macros AS macro
     LEFT JOIN source_rust_declaration_properties AS property
       ON property.blob_id = macro.blob_id
      AND property.declaration_id = macro.declaration_id
     WHERE macro.blob_id = NEW.blob_id
       AND (property.declaration_kind IS NULL OR property.declaration_kind <> 12)
   )
 )
BEGIN SELECT RAISE(ABORT, 'canonical Rust declaration classification is inconsistent'); END;

DROP TRIGGER source_fact_manifests_validate_rust_declaration_boundaries;
CREATE TRIGGER source_fact_manifests_validate_rust_declaration_boundaries
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND EXISTS (
   SELECT 1 FROM source_rust_declaration_properties
   WHERE blob_id = NEW.blob_id
     AND (has_impl_or_trait_ancestor IS NULL OR nearest_declaration_boundary IS NULL
          OR ((nearest_declaration_boundary IN (2, 3) OR trait_impl_member = 1)
              AND has_impl_or_trait_ancestor <> 1))
 )
BEGIN SELECT RAISE(ABORT, 'canonical Rust declaration boundaries are inconsistent'); END;

DROP TRIGGER source_fact_manifests_validate_rust_declaration_properties;
CREATE TRIGGER source_fact_manifests_validate_rust_declaration_properties
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND (
  EXISTS (
    SELECT 1 FROM source_rust_declaration_properties AS property
    LEFT JOIN source_declarations AS declaration
      ON declaration.blob_id = property.blob_id
     AND declaration.declaration_id = property.declaration_id
    WHERE property.blob_id = NEW.blob_id
      AND declaration.name_occurrence_id IS NULL
  )
  OR EXISTS (
    SELECT 1 FROM source_rust_constructor_fields AS field
    LEFT JOIN source_rust_declaration_properties AS property
      ON property.blob_id = field.blob_id
     AND property.declaration_id = field.declaration_id
    WHERE field.blob_id = NEW.blob_id
      AND property.constructor_non_exhaustive IS NULL
  )
  OR EXISTS (
    SELECT 1 FROM source_rust_constructor_fields
    WHERE blob_id = NEW.blob_id
    GROUP BY declaration_id
    HAVING MIN(ordinal) <> 0 OR MAX(ordinal) <> COUNT(*) - 1
  )
  OR (
    EXISTS (SELECT 1 FROM blobs WHERE id = NEW.blob_id AND lang = 'rust')
    AND EXISTS (
      SELECT 1 FROM source_declaration_units AS link
      WHERE link.blob_id = NEW.blob_id
        AND NOT EXISTS (
          SELECT 1 FROM source_rust_declaration_properties AS property
          WHERE property.blob_id = link.blob_id
            AND property.declaration_id = link.declaration_id
        )
    )
  )
 )
BEGIN SELECT RAISE(ABORT, 'canonical Rust declaration properties are inconsistent'); END;

DROP TRIGGER source_fact_manifests_validate_rust_import_contexts;
CREATE TRIGGER source_fact_manifests_validate_rust_import_contexts
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND (
  SELECT (
  EXISTS (
   SELECT 1
   FROM source_rust_import_contexts AS context
   LEFT JOIN source_imports AS source
     ON source.blob_id = context.blob_id
    AND source.declaration_occurrence_id = context.declaration_occurrence_id
   WHERE context.blob_id = NEW.blob_id
     AND (source.import_id IS NULL
          OR source.declaration_occurrence_id <> context.declaration_occurrence_id)
  )
  OR EXISTS (
   SELECT 1
   FROM source_rust_import_contexts AS context
   WHERE context.blob_id = NEW.blob_id
     AND (context.declaration_start_byte < context.owner_scope_start_byte
          OR context.declaration_end_byte > context.owner_scope_end_byte)
  )
  OR EXISTS (
   SELECT 1
   FROM source_rust_import_contexts AS context
   WHERE context.blob_id = NEW.blob_id
     AND (context.declaration_start_byte < context.local_scope_start_byte
          OR context.declaration_end_byte > context.local_scope_end_byte)
  )
  OR EXISTS (
   SELECT 1
   FROM source_rust_import_contexts AS context
   WHERE context.blob_id = NEW.blob_id
     AND NOT (
       (context.local_scope_start_byte <= context.owner_scope_start_byte
        AND context.local_scope_end_byte >= context.owner_scope_end_byte)
       OR (context.owner_scope_start_byte <= context.local_scope_start_byte
           AND context.owner_scope_end_byte >= context.local_scope_end_byte)
     )
  )
  OR EXISTS (
   SELECT 1
   FROM rust_import_targets AS target
   LEFT JOIN source_imports AS source
     ON source.blob_id = target.blob_id
    AND source.import_id = target.source_import_id
   LEFT JOIN source_rust_import_contexts AS context
     ON context.blob_id = target.blob_id
    AND context.declaration_occurrence_id = target.source_context_occurrence_id
   WHERE target.blob_id = NEW.blob_id
     AND target.source_context_occurrence_id IS NOT NULL
     AND (source.import_id IS NULL OR context.declaration_occurrence_id IS NULL
          OR source.declaration_occurrence_id <> context.declaration_occurrence_id)
  )
 )
)
BEGIN SELECT RAISE(ABORT, 'Rust import contexts are inconsistent'); END;

DROP TRIGGER source_fact_manifests_validate_rust_import_module_segments;
CREATE TRIGGER source_fact_manifests_validate_rust_import_module_segments
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND EXISTS (
   SELECT 1 FROM rust_import_targets AS import
   WHERE import.blob_id = NEW.blob_id AND import.source_import_id IS NULL
 )
BEGIN SELECT RAISE(ABORT, 'canonical Rust import target is missing its source import'); END;

DROP TRIGGER source_fact_manifests_validate_rust_import_targets;
CREATE TRIGGER source_fact_manifests_validate_rust_import_targets
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND (
  SELECT EXISTS (
  SELECT 1 FROM rust_import_targets AS import
  WHERE import.blob_id = NEW.blob_id AND import.source_import_id IS NULL
    AND (import.declaration_occurrence_id IS NULL
         OR (import.target_occurrence_id IS NOT NULL AND
             (import.target_start_byte < import.declaration_start_byte OR import.target_end_byte > import.declaration_end_byte))
         OR (import.alias_occurrence_id IS NOT NULL AND
             (import.alias_start_byte < import.declaration_start_byte OR import.alias_end_byte > import.declaration_end_byte)))
 )
)
BEGIN SELECT RAISE(ABORT, 'canonical Rust import target occurrences are inconsistent'); END;

DROP TRIGGER source_fact_manifests_validate_rust_item_macro_links;
CREATE TRIGGER source_fact_manifests_validate_rust_item_macro_links
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND EXISTS (SELECT 1 FROM source_rust_item_manifests
             WHERE blob_id = NEW.blob_id AND macro_contexts_version = 1)
BEGIN
  SELECT CASE WHEN EXISTS (
    SELECT 1
    FROM source_rust_item_macros AS macro
    LEFT JOIN source_declarations AS declaration
      ON declaration.blob_id = macro.blob_id
     AND declaration.declaration_id = macro.declaration_id
    LEFT JOIN source_rust_macro_definitions AS definition
      ON definition.blob_id = macro.blob_id
     AND definition.declaration_id = macro.declaration_id
    LEFT JOIN source_rust_item_contexts AS context
      ON context.blob_id = definition.blob_id
     AND context.occurrence_id = definition.context_occurrence_id
    WHERE macro.blob_id = NEW.blob_id
      AND (macro.declaration_id IS NULL
           OR declaration.occurrence_id IS NULL
           OR definition.declaration_id IS NULL
           OR definition.context_occurrence_id IS NULL
           OR context.occurrence_id IS NULL)
  ) THEN RAISE(ABORT, 'canonical Rust macro route links are inconsistent') END;
END;

DROP TRIGGER source_fact_manifests_validate_rust_item_shapes;
CREATE TRIGGER source_fact_manifests_validate_rust_item_shapes
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND EXISTS (SELECT 1 FROM source_rust_item_manifests WHERE blob_id = NEW.blob_id)
BEGIN
  SELECT CASE WHEN (
    (SELECT COUNT(*) FROM source_rust_item_contexts WHERE blob_id = NEW.blob_id)
      <> COALESCE((SELECT MAX(ordinal) + 1 FROM source_rust_item_contexts
                   WHERE blob_id = NEW.blob_id), 0)
    OR (SELECT COUNT(*) FROM source_rust_item_contexts
        WHERE blob_id = NEW.blob_id AND parent_occurrence_id IS NULL) <> 1
    OR NOT EXISTS (
      SELECT 1 FROM source_rust_item_contexts AS root
      JOIN source_rust_module_manifests AS module
        ON module.blob_id = root.blob_id
       AND module.root_occurrence_id = root.occurrence_id
      WHERE root.blob_id = NEW.blob_id
        AND root.ordinal = 0
        AND root.parent_occurrence_id IS NULL
        AND root.owner_declaration_id IS NULL
        AND root.context_kind = 0
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_item_contexts AS child
      JOIN source_rust_item_contexts AS parent
        ON parent.blob_id = child.blob_id
       AND parent.occurrence_id = child.parent_occurrence_id
      WHERE child.blob_id = NEW.blob_id
        AND parent.ordinal >= child.ordinal
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_item_contexts AS child
      LEFT JOIN source_rust_item_contexts AS parent_occurrence
        ON parent_occurrence.blob_id = child.blob_id
       AND parent_occurrence.occurrence_id = child.parent_occurrence_id
      WHERE child.blob_id = NEW.blob_id
        AND child.parent_occurrence_id IS NOT NULL
        AND (parent_occurrence.occurrence_id IS NULL
             OR child.start_byte < parent_occurrence.start_byte
             OR child.end_byte > parent_occurrence.end_byte)
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_item_contexts AS root
      WHERE root.blob_id = NEW.blob_id
        AND root.context_kind = 0
        AND ((root.ordinal = 0 AND root.provenance <> 0)
             OR (root.ordinal <> 0
                 AND (root.parent_occurrence_id IS NULL
                      OR root.provenance <> 2)))
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_item_contexts AS context
      LEFT JOIN source_declarations AS declaration
        ON declaration.blob_id = context.blob_id
       AND declaration.declaration_id = context.owner_declaration_id
      WHERE context.blob_id = NEW.blob_id
        AND context.owner_declaration_id IS NOT NULL
        AND (declaration.occurrence_id IS NULL
             OR declaration.occurrence_id <> context.occurrence_id)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_item_contexts AS root
      WHERE root.blob_id = NEW.blob_id
        AND root.context_kind = 0
        AND root.parent_occurrence_id IS NOT NULL
        AND NOT EXISTS (
          SELECT 1 FROM source_rust_item_macro_expansions AS macro
          WHERE macro.blob_id = root.blob_id
            AND macro.expansion_kind = 0
            AND macro.root_occurrence_id = root.occurrence_id
            AND macro.context_occurrence_id = root.parent_occurrence_id
        )
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_item_macro_expansions AS macro
      LEFT JOIN source_rust_item_contexts AS root
        ON root.blob_id = macro.blob_id
       AND root.occurrence_id = macro.root_occurrence_id
      WHERE macro.blob_id = NEW.blob_id
        AND macro.expansion_kind = 0
        AND (root.context_kind IS NULL
             OR root.context_kind <> 0
             OR root.parent_occurrence_id IS NOT macro.context_occurrence_id)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_item_macro_expansions AS macro
      JOIN source_rust_item_contexts AS root
        ON root.blob_id = macro.blob_id
       AND root.occurrence_id = macro.root_occurrence_id
      WHERE macro.blob_id = NEW.blob_id
        AND macro.expansion_kind = 0
        AND (root.start_byte < macro.invocation_start_byte
             OR root.end_byte > macro.invocation_end_byte)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_impl_items AS item
      LEFT JOIN source_declarations AS declaration
        ON declaration.blob_id = item.blob_id
       AND declaration.declaration_id = item.declaration_id
      LEFT JOIN source_rust_item_syntax AS syntax
        ON syntax.blob_id = item.blob_id
       AND syntax.occurrence_id = declaration.occurrence_id
      WHERE item.blob_id = NEW.blob_id AND syntax.occurrence_id IS NULL
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_trait_items AS item
      LEFT JOIN source_declarations AS declaration
        ON declaration.blob_id = item.blob_id
       AND declaration.declaration_id = item.declaration_id
      LEFT JOIN source_rust_item_syntax AS syntax
        ON syntax.blob_id = item.blob_id
       AND syntax.occurrence_id = declaration.occurrence_id
      WHERE item.blob_id = NEW.blob_id AND syntax.occurrence_id IS NULL
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_alias_items AS item
      LEFT JOIN source_declarations AS declaration
        ON declaration.blob_id = item.blob_id
       AND declaration.declaration_id = item.declaration_id
      LEFT JOIN source_rust_item_syntax AS syntax
        ON syntax.blob_id = item.blob_id
       AND syntax.occurrence_id = declaration.occurrence_id
      WHERE item.blob_id = NEW.blob_id AND syntax.occurrence_id IS NULL
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_callable_items AS item
      LEFT JOIN source_declarations AS declaration
        ON declaration.blob_id = item.blob_id
       AND declaration.declaration_id = item.declaration_id
      LEFT JOIN source_rust_item_syntax AS syntax
        ON syntax.blob_id = item.blob_id
       AND syntax.occurrence_id = declaration.occurrence_id
      WHERE item.blob_id = NEW.blob_id AND syntax.occurrence_id IS NULL
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_impl_items AS item
      JOIN source_declarations AS declaration
        ON declaration.blob_id = item.blob_id
       AND declaration.declaration_id = item.declaration_id
      LEFT JOIN source_rust_item_contexts AS own_context
        ON own_context.blob_id = item.blob_id
       AND own_context.occurrence_id = declaration.occurrence_id
      WHERE item.blob_id = NEW.blob_id
        AND (own_context.context_kind IS NULL
             OR own_context.context_kind <> 3
             OR own_context.owner_declaration_id IS NOT item.declaration_id
             OR own_context.parent_occurrence_id IS NOT item.context_occurrence_id)
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_trait_items AS item
      JOIN source_declarations AS declaration
        ON declaration.blob_id = item.blob_id
       AND declaration.declaration_id = item.declaration_id
      LEFT JOIN source_rust_item_contexts AS own_context
        ON own_context.blob_id = item.blob_id
       AND own_context.occurrence_id = declaration.occurrence_id
      WHERE item.blob_id = NEW.blob_id
        AND (own_context.context_kind IS NULL
             OR own_context.context_kind <> 2
             OR own_context.owner_declaration_id IS NOT item.declaration_id
             OR own_context.parent_occurrence_id IS NOT item.context_occurrence_id)
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_callable_items AS item
      JOIN source_declarations AS declaration
        ON declaration.blob_id = item.blob_id
       AND declaration.declaration_id = item.declaration_id
      LEFT JOIN source_rust_item_contexts AS own_context
        ON own_context.blob_id = item.blob_id
       AND own_context.occurrence_id = declaration.occurrence_id
      WHERE item.blob_id = NEW.blob_id
        AND (own_context.context_kind IS NULL
             OR own_context.context_kind <> 4
             OR own_context.owner_declaration_id IS NOT item.declaration_id
             OR own_context.parent_occurrence_id IS NOT item.context_occurrence_id)
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_alias_items AS item
      JOIN source_rust_declaration_properties AS property
        ON property.blob_id = item.blob_id
       AND property.declaration_id = item.declaration_id
      WHERE item.blob_id = NEW.blob_id
        AND property.declaration_kind NOT IN (13, 14)
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_trait_items AS item
      JOIN source_rust_declaration_properties AS property
        ON property.blob_id = item.blob_id
       AND property.declaration_id = item.declaration_id
      WHERE item.blob_id = NEW.blob_id
        AND property.declaration_kind <> 3
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_callable_items AS item
      JOIN source_rust_declaration_properties AS property
        ON property.blob_id = item.blob_id
       AND property.declaration_id = item.declaration_id
      WHERE item.blob_id = NEW.blob_id
        AND property.declaration_kind NOT IN (6, 7)
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_impl_items AS item
      JOIN source_declarations AS declaration
        ON declaration.blob_id = item.blob_id
       AND declaration.declaration_id = item.declaration_id
      LEFT JOIN source_rust_item_contexts AS context_occurrence
        ON context_occurrence.blob_id = item.blob_id
       AND context_occurrence.occurrence_id = item.context_occurrence_id
      WHERE item.blob_id = NEW.blob_id
        AND (context_occurrence.occurrence_id IS NULL
             OR declaration.start_byte < context_occurrence.start_byte
             OR declaration.end_byte > context_occurrence.end_byte)
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_trait_items AS item
      JOIN source_declarations AS declaration
        ON declaration.blob_id = item.blob_id
       AND declaration.declaration_id = item.declaration_id
      LEFT JOIN source_rust_item_contexts AS context_occurrence
        ON context_occurrence.blob_id = item.blob_id
       AND context_occurrence.occurrence_id = item.context_occurrence_id
      WHERE item.blob_id = NEW.blob_id
        AND (context_occurrence.occurrence_id IS NULL
             OR declaration.start_byte < context_occurrence.start_byte
             OR declaration.end_byte > context_occurrence.end_byte)
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_alias_items AS item
      JOIN source_declarations AS declaration
        ON declaration.blob_id = item.blob_id
       AND declaration.declaration_id = item.declaration_id
      LEFT JOIN source_rust_item_contexts AS context_occurrence
        ON context_occurrence.blob_id = item.blob_id
       AND context_occurrence.occurrence_id = item.context_occurrence_id
      WHERE item.blob_id = NEW.blob_id
        AND (context_occurrence.occurrence_id IS NULL
             OR declaration.start_byte < context_occurrence.start_byte
             OR declaration.end_byte > context_occurrence.end_byte)
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_callable_items AS item
      JOIN source_declarations AS declaration
        ON declaration.blob_id = item.blob_id
       AND declaration.declaration_id = item.declaration_id
      LEFT JOIN source_rust_item_contexts AS context_occurrence
        ON context_occurrence.blob_id = item.blob_id
       AND context_occurrence.occurrence_id = item.context_occurrence_id
      WHERE item.blob_id = NEW.blob_id
        AND (context_occurrence.occurrence_id IS NULL
             OR declaration.start_byte < context_occurrence.start_byte
             OR declaration.end_byte > context_occurrence.end_byte)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_item_body_children AS child
      LEFT JOIN source_rust_item_syntax AS syntax
        ON syntax.blob_id = child.blob_id
       AND syntax.occurrence_id = child.occurrence_id
      WHERE child.blob_id = NEW.blob_id AND syntax.occurrence_id IS NULL
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_impl_items AS item
      JOIN source_declarations AS declaration
        ON declaration.blob_id = item.blob_id
       AND declaration.declaration_id = item.declaration_id
      LEFT JOIN source_rust_types AS trait_occurrence
        ON trait_occurrence.blob_id = item.blob_id
       AND trait_occurrence.occurrence_id = item.trait_type_occurrence_id
      LEFT JOIN source_rust_types AS target_occurrence
        ON target_occurrence.blob_id = item.blob_id
       AND target_occurrence.occurrence_id = item.target_type_occurrence_id
      WHERE item.blob_id = NEW.blob_id
        AND ((item.trait_type_occurrence_id IS NOT NULL
                 AND (trait_occurrence.occurrence_id IS NULL
                      OR trait_occurrence.start_byte < declaration.start_byte
                      OR trait_occurrence.end_byte > declaration.end_byte))
             OR (item.negation_occurrence_id IS NOT NULL
                 AND (item.negation_start_byte < declaration.start_byte
                      OR item.negation_end_byte > declaration.end_byte))
             OR (item.target_type_occurrence_id IS NOT NULL
                 AND (target_occurrence.occurrence_id IS NULL
                      OR target_occurrence.start_byte < declaration.start_byte
                      OR target_occurrence.end_byte > declaration.end_byte))
             OR (item.body_occurrence_id IS NOT NULL
                 AND (item.body_start_byte < declaration.start_byte
                      OR item.body_end_byte > declaration.end_byte)))
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_trait_items AS item
      JOIN source_declarations AS declaration
        ON declaration.blob_id = item.blob_id
       AND declaration.declaration_id = item.declaration_id
      WHERE item.blob_id = NEW.blob_id
        AND ((item.body_occurrence_id IS NOT NULL
                 AND (item.body_start_byte < declaration.start_byte
                      OR item.body_end_byte > declaration.end_byte)))
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_alias_items AS item
      JOIN source_declarations AS declaration
        ON declaration.blob_id = item.blob_id
       AND declaration.declaration_id = item.declaration_id
      LEFT JOIN source_rust_types AS target_occurrence
        ON target_occurrence.blob_id = item.blob_id
       AND target_occurrence.occurrence_id = item.target_type_occurrence_id
      WHERE item.blob_id = NEW.blob_id
        AND ((item.target_type_occurrence_id IS NOT NULL
                 AND (target_occurrence.occurrence_id IS NULL
                      OR target_occurrence.start_byte < declaration.start_byte
                      OR target_occurrence.end_byte > declaration.end_byte)))
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_callable_items AS item
      JOIN source_declarations AS declaration
        ON declaration.blob_id = item.blob_id
       AND declaration.declaration_id = item.declaration_id
      WHERE item.blob_id = NEW.blob_id
        AND ((item.parameters_occurrence_id IS NOT NULL
                 AND (item.parameters_start_byte < declaration.start_byte
                      OR item.parameters_end_byte > declaration.end_byte)))
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_item_body_children AS child
      LEFT JOIN source_rust_impl_items AS impl
        ON impl.blob_id = child.blob_id
       AND impl.declaration_id = child.owner_declaration_id
      LEFT JOIN source_rust_trait_items AS trait
        ON trait.blob_id = child.blob_id
       AND trait.declaration_id = child.owner_declaration_id
      WHERE child.blob_id = NEW.blob_id
        AND ((impl.body_occurrence_id IS NOT NULL
              AND (child.start_byte < impl.body_start_byte
                   OR child.end_byte > impl.body_end_byte))
             OR (trait.body_occurrence_id IS NOT NULL
                 AND (child.start_byte < trait.body_start_byte
                      OR child.end_byte > trait.body_end_byte)))
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_item_generic_parameters AS parameter
      LEFT JOIN source_rust_item_contexts AS owner
        ON owner.blob_id = parameter.blob_id
       AND owner.owner_declaration_id = parameter.declaration_id
       AND owner.context_kind IN (2, 3, 4, 7)
      WHERE parameter.blob_id = NEW.blob_id
        AND owner.occurrence_id IS NULL
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_item_body_children AS child
      LEFT JOIN source_rust_impl_items AS impl
        ON impl.blob_id = child.blob_id
       AND impl.declaration_id = child.owner_declaration_id
      LEFT JOIN source_rust_trait_items AS trait
        ON trait.blob_id = child.blob_id
       AND trait.declaration_id = child.owner_declaration_id
      WHERE child.blob_id = NEW.blob_id
        AND impl.declaration_id IS NULL AND trait.declaration_id IS NULL
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_item_body_children AS child
      LEFT JOIN source_rust_impl_items AS impl
        ON impl.blob_id = child.blob_id
       AND impl.declaration_id = child.owner_declaration_id
      LEFT JOIN source_rust_trait_items AS trait
        ON trait.blob_id = child.blob_id
       AND trait.declaration_id = child.owner_declaration_id
      WHERE child.blob_id = NEW.blob_id
        AND ((impl.declaration_id IS NOT NULL AND impl.body_occurrence_id IS NULL)
             OR (trait.declaration_id IS NOT NULL AND trait.body_occurrence_id IS NULL))
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_callable_parameters AS parameter
      LEFT JOIN source_rust_callable_items AS callable
        ON callable.blob_id = parameter.blob_id
       AND callable.declaration_id = parameter.declaration_id
      WHERE parameter.blob_id = NEW.blob_id AND callable.declaration_id IS NULL
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_callable_parameters AS parameter
      JOIN source_rust_callable_items AS callable
        ON callable.blob_id = parameter.blob_id
       AND callable.declaration_id = parameter.declaration_id
      WHERE parameter.blob_id = NEW.blob_id
        AND callable.parameters_occurrence_id IS NULL
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_item_generic_parameters
      WHERE blob_id = NEW.blob_id
      GROUP BY blob_id, declaration_id
      HAVING MIN(ordinal) <> 0 OR MAX(ordinal) + 1 <> COUNT(*)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_item_body_children
      WHERE blob_id = NEW.blob_id
      GROUP BY blob_id, owner_declaration_id
      HAVING MIN(ordinal) <> 0 OR MAX(ordinal) + 1 <> COUNT(*)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_callable_parameters
      WHERE blob_id = NEW.blob_id
      GROUP BY blob_id, declaration_id
      HAVING MIN(ordinal) <> 0 OR MAX(ordinal) + 1 <> COUNT(*)
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_item_body_children AS child
      LEFT JOIN source_declarations AS declaration
        ON declaration.blob_id = child.blob_id
       AND declaration.declaration_id = child.declaration_id
      WHERE child.blob_id = NEW.blob_id
        AND child.declaration_id IS NOT NULL
        AND (declaration.occurrence_id IS NULL
             OR declaration.occurrence_id <> child.occurrence_id)
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_item_generic_parameters AS parameter
      JOIN source_declarations AS declaration
        ON declaration.blob_id = parameter.blob_id
       AND declaration.declaration_id = parameter.declaration_id
      WHERE parameter.blob_id = NEW.blob_id
        AND (parameter.start_byte < declaration.start_byte
             OR parameter.end_byte > declaration.end_byte
             OR (parameter.name_occurrence_id IS NOT NULL
                 AND (parameter.name_start_byte < parameter.start_byte
                      OR parameter.name_end_byte > parameter.end_byte)))
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_callable_parameters AS parameter
      JOIN source_rust_callable_items AS callable
        ON callable.blob_id = parameter.blob_id
       AND callable.declaration_id = parameter.declaration_id
      WHERE parameter.blob_id = NEW.blob_id
        AND (callable.parameters_occurrence_id IS NULL
             OR parameter.start_byte < callable.parameters_start_byte
             OR parameter.end_byte > callable.parameters_end_byte
             OR (parameter.label_occurrence_id IS NOT NULL
                 AND (parameter.label_start_byte < parameter.start_byte
                      OR parameter.label_end_byte > parameter.end_byte)))
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_type_segments AS segment
      JOIN source_rust_types AS type
        ON type.blob_id = segment.blob_id
       AND type.occurrence_id = segment.type_occurrence_id
      WHERE segment.blob_id = NEW.blob_id
        AND (type.path_kind <> 0
             OR segment.start_byte < type.start_byte
             OR segment.end_byte > type.end_byte
             OR segment.provenance IS NOT type.provenance)
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_type_segments AS first
      JOIN source_rust_type_segments AS next
        ON next.blob_id = first.blob_id
       AND next.type_occurrence_id = first.type_occurrence_id
       AND next.ordinal = first.ordinal + 1
      WHERE first.blob_id = NEW.blob_id
        AND (next.start_byte < first.end_byte
             OR next.start_byte < first.start_byte)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_types AS type
      WHERE type.blob_id = NEW.blob_id
        AND type.path_kind = 1
        AND (type.unsupported_start_byte < type.start_byte
             OR type.unsupported_end_byte > type.end_byte
             OR type.unsupported_provenance IS NOT type.provenance)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_type_generic_lists AS list
      JOIN source_rust_types AS type
        ON type.blob_id = list.blob_id
       AND type.occurrence_id = list.type_occurrence_id
      JOIN source_rust_type_segments AS segment
        ON segment.blob_id = list.blob_id
       AND segment.type_occurrence_id = list.type_occurrence_id
       AND segment.ordinal = list.segment_ordinal
      WHERE list.blob_id = NEW.blob_id
        AND (type.path_kind <> 0
             OR list.start_byte < type.start_byte
             OR list.end_byte > type.end_byte
             OR list.occurrence_id = segment.occurrence_id
             OR list.provenance IS NOT type.provenance
             OR list.provenance IS NOT segment.provenance)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_type_generic_arguments AS argument
      JOIN source_rust_type_generic_lists AS list
        ON list.blob_id = argument.blob_id
       AND list.type_occurrence_id = argument.type_occurrence_id
       AND list.segment_ordinal = argument.segment_ordinal
      JOIN source_rust_types AS type
        ON type.blob_id = argument.blob_id
       AND type.occurrence_id = argument.type_occurrence_id
      JOIN source_rust_types AS argument_occurrence
        ON argument_occurrence.blob_id = argument.blob_id
       AND argument_occurrence.occurrence_id = argument.occurrence_id
      WHERE argument.blob_id = NEW.blob_id
        AND (argument_occurrence.start_byte < list.start_byte
             OR argument_occurrence.end_byte > list.end_byte
             OR argument_occurrence.provenance IS NOT list.provenance
             OR argument_occurrence.provenance IS NOT type.provenance)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_type_generic_arguments
      WHERE blob_id = NEW.blob_id
      GROUP BY blob_id, type_occurrence_id, segment_ordinal
      HAVING MIN(ordinal) <> 0 OR MAX(ordinal) + 1 <> COUNT(*)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_type_wrappers AS wrapper
      JOIN source_rust_types AS type
        ON type.blob_id = wrapper.blob_id
       AND type.occurrence_id = wrapper.type_occurrence_id
      LEFT JOIN source_rust_type_wrappers AS previous
        ON previous.blob_id = wrapper.blob_id
       AND previous.type_occurrence_id = wrapper.type_occurrence_id
       AND previous.ordinal = wrapper.ordinal - 1
      WHERE wrapper.blob_id = NEW.blob_id
        AND (wrapper.ordinal = 0 AND wrapper.occurrence_id <> wrapper.type_occurrence_id
             OR wrapper.start_byte < type.start_byte
             OR wrapper.end_byte > type.end_byte
             OR wrapper.provenance IS NOT type.provenance
             OR (wrapper.ordinal > 0 AND (
                   previous.ordinal IS NULL
                   OR previous.occurrence_id IS NULL
                   OR wrapper.start_byte < previous.start_byte
                   OR wrapper.end_byte > previous.end_byte
                   OR previous.provenance IS NOT type.provenance)))
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_type_wrappers
      WHERE blob_id = NEW.blob_id
      GROUP BY blob_id, type_occurrence_id
      HAVING MIN(ordinal) <> 0 OR MAX(ordinal) + 1 <> COUNT(*)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_type_segments
      WHERE blob_id = NEW.blob_id
      GROUP BY blob_id, type_occurrence_id
      HAVING MIN(ordinal) <> 0 OR MAX(ordinal) + 1 <> COUNT(*)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_type_generic_lists AS list
      JOIN source_rust_type_segments AS segment
        ON segment.blob_id = list.blob_id
       AND segment.type_occurrence_id = list.type_occurrence_id
       AND segment.ordinal = list.segment_ordinal
      WHERE list.blob_id = NEW.blob_id
        AND (list.start_byte < segment.end_byte
             OR list.end_byte <= segment.end_byte)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_types AS type
      WHERE type.blob_id = NEW.blob_id
        AND ((type.path_kind = 0 AND NOT EXISTS (
                SELECT 1 FROM source_rust_type_segments AS segment
                WHERE segment.blob_id = type.blob_id
                  AND segment.type_occurrence_id = type.occurrence_id
              ))
             OR (type.path_kind = 1 AND EXISTS (
                SELECT 1 FROM source_rust_type_segments AS segment
                WHERE segment.blob_id = type.blob_id
                  AND segment.type_occurrence_id = type.occurrence_id
              )))
    )
  ) THEN RAISE(ABORT, 'canonical Rust item or type facts are inconsistent') END;
END;

DROP TRIGGER source_fact_manifests_validate_rust_macro_contexts;
CREATE TRIGGER source_fact_manifests_validate_rust_macro_contexts
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND EXISTS (SELECT 1 FROM source_rust_item_manifests
             WHERE blob_id = NEW.blob_id AND macro_contexts_version = 1)
BEGIN
  SELECT CASE WHEN EXISTS (
    SELECT 1
    FROM source_rust_macro_definitions AS definition
    JOIN source_declarations AS declaration
      ON declaration.blob_id = definition.blob_id
     AND declaration.declaration_id = definition.declaration_id
    LEFT JOIN source_rust_item_contexts AS context
      ON context.blob_id = definition.blob_id
     AND context.occurrence_id = definition.context_occurrence_id
    WHERE definition.blob_id = NEW.blob_id
      AND (context.occurrence_id IS NULL
           OR context.occurrence_id = declaration.occurrence_id
           OR context.provenance IS NOT declaration.provenance
           OR context.start_byte > declaration.start_byte
           OR context.end_byte < declaration.end_byte)
  ) THEN RAISE(ABORT, 'canonical Rust macro definition contexts are inconsistent') END;
END;

DROP TRIGGER source_fact_manifests_validate_rust_macro_definitions;
CREATE TRIGGER source_fact_manifests_validate_rust_macro_definitions
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND EXISTS (SELECT 1 FROM source_rust_item_manifests
             WHERE blob_id = NEW.blob_id AND macro_facts_version = 1)
BEGIN
  SELECT CASE WHEN
    (SELECT COUNT(*) FROM source_rust_macro_definitions WHERE blob_id = NEW.blob_id)
       <> COALESCE((SELECT MAX(ordinal) + 1 FROM source_rust_macro_definitions WHERE blob_id = NEW.blob_id), 0)
    OR EXISTS (
      SELECT 1 FROM source_rust_macro_definitions AS definition
      WHERE definition.blob_id = NEW.blob_id
        AND (SELECT COUNT(*) FROM source_rust_macro_arms AS arm
             WHERE arm.blob_id = definition.blob_id
               AND arm.declaration_id = definition.declaration_id)
            <> COALESCE((SELECT MAX(arm.ordinal) + 1
                         FROM source_rust_macro_arms AS arm
                         WHERE arm.blob_id = definition.blob_id
                           AND arm.declaration_id = definition.declaration_id), 0)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_macro_arms AS arm
      WHERE arm.blob_id = NEW.blob_id
        AND (SELECT COUNT(*) FROM source_rust_macro_pattern_nodes AS node
             WHERE node.blob_id = arm.blob_id
               AND node.declaration_id = arm.declaration_id
               AND node.arm_ordinal = arm.ordinal)
            <> COALESCE((SELECT MAX(node.ordinal) + 1
                         FROM source_rust_macro_pattern_nodes AS node
                         WHERE node.blob_id = arm.blob_id
                           AND node.declaration_id = arm.declaration_id
                           AND node.arm_ordinal = arm.ordinal), 0)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_macro_arms AS arm
      WHERE arm.blob_id = NEW.blob_id
        AND (SELECT COUNT(*) FROM source_rust_macro_ident_roles AS role
             WHERE role.blob_id = arm.blob_id
               AND role.declaration_id = arm.declaration_id
               AND role.arm_ordinal = arm.ordinal)
            <> COALESCE((SELECT MAX(role.ordinal) + 1
                         FROM source_rust_macro_ident_roles AS role
                         WHERE role.blob_id = arm.blob_id
                           AND role.declaration_id = arm.declaration_id
                           AND role.arm_ordinal = arm.ordinal), 0)
    )
    OR EXISTS (
      SELECT 1
      FROM source_rust_macro_arms AS arm
      JOIN source_rust_macro_definitions AS definition
        ON definition.blob_id = arm.blob_id
       AND definition.declaration_id = arm.declaration_id
      JOIN source_declarations AS definition_occurrence
        ON definition_occurrence.blob_id = definition.blob_id
       AND definition_occurrence.declaration_id = definition.declaration_id
      WHERE arm.blob_id = NEW.blob_id
        AND (arm.start_byte < definition_occurrence.start_byte
             OR arm.end_byte > definition_occurrence.end_byte
             OR arm.provenance <> definition_occurrence.provenance)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_macro_pattern_nodes AS node
      JOIN source_rust_macro_arms AS arm
        ON arm.blob_id = node.blob_id
       AND arm.declaration_id = node.declaration_id
       AND arm.ordinal = node.arm_ordinal
      WHERE node.blob_id = NEW.blob_id
        AND (node.start_byte < arm.start_byte
             OR node.end_byte > arm.end_byte
             OR node.provenance <> arm.provenance)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_macro_arms AS arm
      JOIN source_rust_macro_definitions AS definition
        ON definition.blob_id = arm.blob_id
       AND definition.declaration_id = arm.declaration_id
      JOIN source_declarations AS declaration
        ON declaration.blob_id = definition.blob_id
       AND declaration.declaration_id = definition.declaration_id
      WHERE arm.blob_id = NEW.blob_id
        AND arm.occurrence_id = declaration.occurrence_id
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_macro_pattern_nodes AS node
      JOIN source_rust_macro_arms AS arm
        ON arm.blob_id = node.blob_id
       AND arm.declaration_id = node.declaration_id
       AND arm.ordinal = node.arm_ordinal
      WHERE node.blob_id = NEW.blob_id
        AND node.occurrence_id = arm.occurrence_id
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_macro_pattern_nodes AS node
      JOIN source_rust_macro_definitions AS definition
        ON definition.blob_id = node.blob_id
       AND definition.declaration_id = node.declaration_id
      JOIN source_declarations AS declaration
        ON declaration.blob_id = definition.blob_id
       AND declaration.declaration_id = definition.declaration_id
      WHERE node.blob_id = NEW.blob_id
        AND node.occurrence_id = declaration.occurrence_id
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_macro_arms AS arm
      JOIN source_rust_macro_pattern_nodes AS root
        ON root.blob_id = arm.blob_id
       AND root.declaration_id = arm.declaration_id
       AND root.arm_ordinal = arm.ordinal
       AND root.occurrence_id = arm.pattern_occurrence_id
      WHERE arm.blob_id = NEW.blob_id
        AND (root.node_kind <> 2 OR root.ordinal <> 0
             OR root.parent_occurrence_id IS NOT NULL
             OR (SELECT COUNT(*) FROM source_rust_macro_pattern_nodes AS candidate
                 WHERE candidate.blob_id = arm.blob_id
                   AND candidate.declaration_id = arm.declaration_id
                   AND candidate.arm_ordinal = arm.ordinal
                   AND candidate.parent_occurrence_id IS NULL) <> 1)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_macro_arms AS arm
      WHERE arm.blob_id = NEW.blob_id
        AND ((arm.pattern_occurrence_id IS NULL AND EXISTS (
                SELECT 1 FROM source_rust_macro_pattern_nodes AS node
                WHERE node.blob_id = arm.blob_id
                  AND node.declaration_id = arm.declaration_id
                  AND node.arm_ordinal = arm.ordinal
              ))
             OR (arm.pattern_occurrence_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM source_rust_macro_pattern_nodes AS node
                WHERE node.blob_id = arm.blob_id
                  AND node.declaration_id = arm.declaration_id
                  AND node.arm_ordinal = arm.ordinal
                  AND node.occurrence_id = arm.pattern_occurrence_id
              )))
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_macro_pattern_nodes AS node
      JOIN source_rust_macro_pattern_nodes AS parent
        ON parent.blob_id = node.blob_id
       AND parent.declaration_id = node.declaration_id
       AND parent.arm_ordinal = node.arm_ordinal
       AND parent.occurrence_id = node.parent_occurrence_id
      WHERE node.blob_id = NEW.blob_id
        AND parent.ordinal >= node.ordinal
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_macro_pattern_nodes AS node
      JOIN source_rust_macro_pattern_nodes AS parent
        ON parent.blob_id = node.blob_id
       AND parent.declaration_id = node.declaration_id
       AND parent.arm_ordinal = node.arm_ordinal
       AND parent.occurrence_id = node.parent_occurrence_id
      WHERE node.blob_id = NEW.blob_id
        AND parent.node_kind NOT IN (2, 3)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_macro_pattern_nodes AS node
      WHERE node.blob_id = NEW.blob_id
        AND node.node_kind = 2
        AND node.parent_occurrence_id IS NOT NULL
        AND node.delimiter IS NULL
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_macro_pattern_nodes AS node
      JOIN source_rust_macro_pattern_nodes AS parent
        ON parent.blob_id = node.blob_id
       AND parent.declaration_id = node.declaration_id
       AND parent.arm_ordinal = node.arm_ordinal
       AND parent.occurrence_id = node.parent_occurrence_id
      WHERE node.blob_id = NEW.blob_id
        AND (node.start_byte < parent.start_byte
             OR node.end_byte > parent.end_byte
             OR node.provenance <> parent.provenance)
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_macro_arms AS arm
      JOIN source_rust_macro_pattern_nodes AS root
        ON root.blob_id = arm.blob_id
       AND root.declaration_id = arm.declaration_id
       AND root.arm_ordinal = arm.ordinal
       AND root.occurrence_id = arm.pattern_occurrence_id
      WHERE arm.blob_id = NEW.blob_id
        AND root.parent_occurrence_id IS NOT NULL
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_macro_pattern_nodes AS node
      WHERE node.blob_id = NEW.blob_id
        AND node.parent_occurrence_id IS NOT NULL
        AND node.parent_occurrence_id = node.occurrence_id
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_macro_ident_roles AS role
      WHERE role.blob_id = NEW.blob_id
        AND NOT EXISTS (
          SELECT 1 FROM source_rust_macro_pattern_nodes AS node
          WHERE node.blob_id = role.blob_id
            AND node.declaration_id = role.declaration_id
            AND node.arm_ordinal = role.arm_ordinal
            AND node.node_kind = 1
            AND node.fragment_kind = 0
            AND node.binding_name = role.name
        )
    )
    OR EXISTS (
      SELECT 1 FROM source_rust_macro_pattern_nodes AS node
      JOIN source_rust_macro_arms AS arm
        ON arm.blob_id = node.blob_id
       AND arm.declaration_id = node.declaration_id
       AND arm.ordinal = node.arm_ordinal
      WHERE node.blob_id = NEW.blob_id
        AND node.node_kind = 1
        AND node.fragment_kind = 0
        AND NOT EXISTS (
          SELECT 1 FROM source_rust_macro_ident_roles AS role
          WHERE role.blob_id = node.blob_id
            AND role.declaration_id = node.declaration_id
            AND role.arm_ordinal = node.arm_ordinal
            AND role.name = node.binding_name
        )
    )
  THEN RAISE(ABORT, 'canonical Rust macro definitions are inconsistent') END;
END;

DROP TRIGGER source_fact_manifests_validate_rust_macro_position;
CREATE TRIGGER source_fact_manifests_validate_rust_macro_position
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND EXISTS (
   SELECT 1 FROM source_rust_item_macro_expansions
   WHERE blob_id = NEW.blob_id
     AND (source_position IS NULL OR (source_position = 0 AND expansion_kind = 4))
 )
BEGIN SELECT RAISE(ABORT, 'canonical Rust macro position is incomplete'); END;

DROP TRIGGER source_fact_manifests_validate_rust_module_placement;
CREATE TRIGGER source_fact_manifests_validate_rust_module_placement
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND EXISTS (SELECT 1 FROM source_rust_module_manifests WHERE blob_id = NEW.blob_id)
BEGIN
  SELECT CASE WHEN EXISTS (
    SELECT 1 FROM source_rust_macro_invocations AS invocation
    JOIN source_rust_module_manifests AS manifest ON manifest.blob_id = invocation.blob_id
    WHERE invocation.blob_id = NEW.blob_id
      AND (invocation.provenance NOT IN (0, 2)
           OR invocation.start_byte < manifest.root_start_byte OR invocation.end_byte > manifest.root_end_byte)
  ) OR EXISTS (
    WITH placements AS (
      SELECT parent_ordinal AS parent, declaration_id
      FROM source_rust_module_scopes WHERE blob_id = NEW.blob_id AND ordinal > 0
      UNION ALL
      SELECT scope_ordinal, declaration_id
      FROM source_rust_module_routes WHERE blob_id = NEW.blob_id
      UNION ALL
      SELECT parent_scope_ordinal, declaration_id
      FROM source_rust_module_inventory WHERE blob_id = NEW.blob_id AND ordinal > 0
    )
    SELECT 1 FROM placements AS placement
    JOIN source_declarations AS declaration
      ON declaration.blob_id = NEW.blob_id AND declaration.declaration_id = placement.declaration_id
    JOIN source_rust_module_scopes AS parent
      ON parent.blob_id = NEW.blob_id AND parent.ordinal = placement.parent
    LEFT JOIN source_rust_module_declarations AS parent_declaration
      ON parent_declaration.blob_id = parent.blob_id AND parent_declaration.declaration_id = parent.declaration_id
    JOIN source_rust_module_manifests AS manifest ON manifest.blob_id = NEW.blob_id

    WHERE declaration.start_byte < (CASE WHEN parent.ordinal = 0 THEN manifest.root_start_byte ELSE parent_declaration.body_start_byte END) OR declaration.end_byte > (CASE WHEN parent.ordinal = 0 THEN manifest.root_end_byte ELSE parent_declaration.body_end_byte END)
  ) OR EXISTS (
    SELECT 1 FROM source_rust_module_route_gates AS gate
    JOIN source_rust_macro_invocations AS invocation
      ON invocation.blob_id = gate.blob_id AND invocation.occurrence_id = gate.invocation_occurrence_id
    JOIN source_rust_module_routes AS route
      ON route.blob_id = gate.blob_id AND route.ordinal = gate.route_ordinal
    JOIN source_declarations AS declaration
      ON declaration.blob_id = route.blob_id AND declaration.declaration_id = route.declaration_id
    LEFT JOIN source_rust_module_route_gates AS previous
      ON previous.blob_id = gate.blob_id AND previous.route_ordinal = gate.route_ordinal
     AND previous.gate_ordinal = gate.gate_ordinal - 1
    LEFT JOIN source_rust_macro_invocations AS outer_invocation
      ON outer_invocation.blob_id = previous.blob_id AND outer_invocation.occurrence_id = previous.invocation_occurrence_id
    WHERE gate.blob_id = NEW.blob_id
      AND (declaration.start_byte < invocation.start_byte OR declaration.end_byte > invocation.end_byte
           OR invocation.start_byte < outer_invocation.start_byte OR invocation.end_byte > outer_invocation.end_byte)
  ) THEN RAISE(ABORT, 'canonical Rust module placement is inconsistent') END;
END;

DROP TRIGGER source_fact_manifests_validate_rust_modules;
CREATE TRIGGER source_fact_manifests_validate_rust_modules
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND EXISTS (SELECT 1 FROM source_rust_module_manifests
             WHERE blob_id = NEW.blob_id)
BEGIN
  SELECT CASE WHEN (
   NOT EXISTS (SELECT 1 FROM source_fact_manifests
              WHERE blob_id = NEW.blob_id)
   OR NOT EXISTS (SELECT 1 FROM blobs
                  WHERE id = NEW.blob_id AND lang = 'rust')
   OR NOT EXISTS (SELECT 1 FROM source_rust_module_manifests AS root
                  WHERE root.blob_id = NEW.blob_id AND root.root_provenance = 0)
   OR EXISTS (SELECT 1 FROM source_rust_module_manifests AS root
              JOIN source_fact_manifests AS source ON source.blob_id=root.blob_id
              WHERE root.blob_id=NEW.blob_id AND root.root_end_byte>source.source_bytes)
   OR NOT EXISTS (SELECT 1 FROM source_rust_module_scopes
                  WHERE blob_id = NEW.blob_id AND ordinal = 0
                    AND parent_ordinal IS NULL AND declaration_id IS NULL
                    AND module_name = '' AND imports_macros = 1)
   OR NOT EXISTS (SELECT 1 FROM source_rust_module_inventory
                  WHERE blob_id = NEW.blob_id AND ordinal = 0
                    AND parent_scope_ordinal = 0 AND declaration_id IS NULL
                    AND module_name = '')
   OR EXISTS (SELECT 1 FROM source_rust_declaration_properties AS property
              WHERE property.blob_id = NEW.blob_id
                AND property.declaration_kind IN (4, 5)
                AND NOT EXISTS (
                  SELECT 1 FROM source_rust_module_declarations AS declaration
                  WHERE declaration.blob_id = property.blob_id
                    AND declaration.declaration_id = property.declaration_id
                ))
   OR (SELECT COUNT(*) FROM source_rust_module_scopes WHERE blob_id = NEW.blob_id)
      <> COALESCE((SELECT MAX(ordinal) + 1 FROM source_rust_module_scopes
                   WHERE blob_id = NEW.blob_id), 0)
   OR (SELECT COUNT(*) FROM source_rust_module_inventory WHERE blob_id = NEW.blob_id)
      <> COALESCE((SELECT MAX(ordinal) + 1 FROM source_rust_module_inventory
                   WHERE blob_id = NEW.blob_id), 0)
   OR (SELECT COUNT(*) FROM source_rust_module_routes WHERE blob_id = NEW.blob_id)
      <> COALESCE((SELECT MAX(ordinal) + 1 FROM source_rust_module_routes
                   WHERE blob_id = NEW.blob_id), 0)
   OR EXISTS (SELECT 1 FROM source_rust_module_scopes AS scope
              WHERE scope.blob_id = NEW.blob_id
                AND scope.ordinal > 0
                AND (scope.parent_ordinal IS NULL
                     OR scope.parent_ordinal >= scope.ordinal
                     OR scope.declaration_id IS NULL
                     OR scope.module_name = ''))
   OR EXISTS (SELECT 1 FROM source_rust_module_inventory AS item
              WHERE item.blob_id = NEW.blob_id
                AND item.ordinal > 0
                AND (item.declaration_id IS NULL OR item.module_name = ''))
   OR EXISTS (SELECT 1 FROM source_rust_module_declarations AS declaration
              LEFT JOIN source_declarations AS source
                ON source.blob_id = declaration.blob_id
               AND source.declaration_id = declaration.declaration_id
              LEFT JOIN source_rust_declaration_properties AS property
                ON property.blob_id = declaration.blob_id
               AND property.declaration_id = declaration.declaration_id
              WHERE declaration.blob_id = NEW.blob_id
                AND (source.name_occurrence_id IS NULL
                     OR property.declaration_kind IS NULL
                     OR property.declaration_kind NOT IN (4, 5)
                     OR (property.declaration_kind = 4 AND declaration.body_occurrence_id IS NULL)
                     OR (property.declaration_kind = 5 AND declaration.body_occurrence_id IS NOT NULL)
                     OR source.start_byte < (SELECT root_start_byte FROM source_rust_module_manifests WHERE blob_id = NEW.blob_id)
                     OR source.end_byte > (SELECT root_end_byte FROM source_rust_module_manifests WHERE blob_id = NEW.blob_id)
                     OR (declaration.body_start_byte < source.start_byte
                         OR declaration.body_end_byte > source.end_byte
                         OR declaration.body_provenance <> source.provenance)
                     OR (declaration.body_start_byte < (SELECT root_start_byte FROM source_rust_module_manifests WHERE blob_id = NEW.blob_id)
                         OR declaration.body_end_byte > (SELECT root_end_byte FROM source_rust_module_manifests WHERE blob_id = NEW.blob_id))))
   OR EXISTS (SELECT 1 FROM source_rust_module_scopes AS scope
              JOIN source_rust_module_scopes AS parent
                ON parent.blob_id = scope.blob_id
               AND parent.ordinal = scope.parent_ordinal
              JOIN source_rust_module_declarations AS declaration
                ON declaration.blob_id = scope.blob_id
               AND declaration.declaration_id = scope.declaration_id
              JOIN source_rust_declaration_properties AS property
                ON property.blob_id = declaration.blob_id
               AND property.declaration_id = declaration.declaration_id
              WHERE scope.blob_id = NEW.blob_id
                AND scope.ordinal > 0
                AND (property.declaration_kind IS NULL
                     OR property.declaration_kind <> 4
                     OR scope.module_name <> CASE WHEN parent.module_name = ''
                          THEN declaration.module_name
                          ELSE parent.module_name || '.' || declaration.module_name END
                     OR scope.imports_macros <> (parent.imports_macros AND declaration.macro_use)))
   OR EXISTS (SELECT 1 FROM source_rust_module_inventory AS item
              JOIN source_rust_module_scopes AS parent
                ON parent.blob_id = item.blob_id
               AND parent.ordinal = item.parent_scope_ordinal
              JOIN source_rust_module_declarations AS declaration
                ON declaration.blob_id = item.blob_id
               AND declaration.declaration_id = item.declaration_id
              JOIN source_rust_declaration_properties AS property
                ON property.blob_id = declaration.blob_id
               AND property.declaration_id = declaration.declaration_id
              WHERE item.blob_id = NEW.blob_id
                AND item.ordinal > 0
                AND (property.declaration_kind IS NULL
                     OR item.module_name <> CASE WHEN parent.module_name = ''
                          THEN declaration.module_name
                          ELSE parent.module_name || '.' || declaration.module_name END
                     OR property.declaration_kind NOT IN (4, 5)))
   OR EXISTS (SELECT 1 FROM source_rust_module_routes AS route
              JOIN source_rust_module_scopes AS scope
                ON scope.blob_id = route.blob_id
               AND scope.ordinal = route.scope_ordinal
              JOIN source_rust_module_declarations AS declaration
                ON declaration.blob_id = route.blob_id
               AND declaration.declaration_id = route.declaration_id
              JOIN source_rust_declaration_properties AS property
                ON property.blob_id = declaration.blob_id
               AND property.declaration_id = declaration.declaration_id
              WHERE route.blob_id = NEW.blob_id
                AND (property.declaration_kind IS NULL
                     OR property.declaration_kind <> 5
                     OR declaration.body_occurrence_id IS NOT NULL
                     OR route.imports_macros <> (scope.imports_macros AND declaration.macro_use)))
   OR EXISTS (SELECT 1 FROM source_rust_module_route_gates AS gate
              WHERE gate.blob_id = NEW.blob_id
              GROUP BY gate.blob_id, gate.route_ordinal
              HAVING MIN(gate.gate_ordinal) <> 0
                  OR MAX(gate.gate_ordinal) <> COUNT(*) - 1)
   OR EXISTS (SELECT 1
              FROM source_rust_module_routes AS route
              JOIN source_rust_module_scopes AS scope
                ON scope.blob_id = route.blob_id
               AND scope.ordinal = route.scope_ordinal
              JOIN source_rust_module_declarations AS scope_declaration
                ON scope_declaration.blob_id = scope.blob_id
               AND scope_declaration.declaration_id = scope.declaration_id
              JOIN source_declarations AS route_source
                ON route_source.blob_id = route.blob_id
               AND route_source.declaration_id = route.declaration_id
              JOIN source_rust_module_manifests AS manifest
                ON manifest.blob_id = route.blob_id
              WHERE route.blob_id = NEW.blob_id
                AND (route_source.start_byte < COALESCE(scope_declaration.body_start_byte, manifest.root_start_byte)
                     OR route_source.end_byte > COALESCE(scope_declaration.body_end_byte, manifest.root_end_byte)))
   OR EXISTS (SELECT 1
              FROM source_rust_module_routes AS route
              JOIN source_declarations AS route_source
                ON route_source.blob_id = route.blob_id
               AND route_source.declaration_id = route.declaration_id
              JOIN source_rust_module_route_gates AS gate
                ON gate.blob_id = route.blob_id
               AND gate.route_ordinal = route.ordinal
              JOIN source_rust_macro_invocations AS invocation
                ON invocation.blob_id = gate.blob_id
               AND invocation.occurrence_id = gate.invocation_occurrence_id
              JOIN source_rust_module_manifests AS manifest
                ON manifest.blob_id = route.blob_id
              WHERE route.blob_id = NEW.blob_id
                AND (invocation.start_byte < manifest.root_start_byte
                     OR invocation.end_byte > manifest.root_end_byte
                     OR invocation.start_byte > route_source.start_byte
                     OR invocation.end_byte < route_source.end_byte))
   OR EXISTS (SELECT 1
              FROM source_rust_module_route_gates AS outer_gate
              JOIN source_rust_module_route_gates AS inner_gate
                ON inner_gate.blob_id = outer_gate.blob_id
               AND inner_gate.route_ordinal = outer_gate.route_ordinal
               AND inner_gate.gate_ordinal = outer_gate.gate_ordinal + 1
              JOIN source_rust_macro_invocations AS outer_invocation
                ON outer_invocation.blob_id = outer_gate.blob_id
               AND outer_invocation.occurrence_id = outer_gate.invocation_occurrence_id
              JOIN source_rust_macro_invocations AS inner_invocation
                ON inner_invocation.blob_id = inner_gate.blob_id
               AND inner_invocation.occurrence_id = inner_gate.invocation_occurrence_id
              WHERE outer_gate.blob_id = NEW.blob_id
                AND (inner_invocation.start_byte < outer_invocation.start_byte
                     OR inner_invocation.end_byte > outer_invocation.end_byte))
 ) THEN RAISE(ABORT, 'canonical Rust module facts are inconsistent') END;
END;

DROP TRIGGER source_fact_manifests_validate_rust_type_contexts;
CREATE TRIGGER source_fact_manifests_validate_rust_type_contexts
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND EXISTS (
   SELECT 1 FROM source_rust_item_contexts AS context
   JOIN source_rust_declaration_properties AS property
     ON property.blob_id = context.blob_id
    AND property.declaration_id = context.owner_declaration_id
   WHERE context.blob_id = NEW.blob_id AND context.context_kind = 7
     AND property.declaration_kind NOT IN (0, 1, 2, 13, 14)
 )
BEGIN SELECT RAISE(ABORT, 'canonical Rust type context has an invalid owner'); END;

DROP TRIGGER source_fact_manifests_validate_rust_type_forms;
CREATE TRIGGER source_fact_manifests_validate_rust_type_forms
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
BEGIN
  SELECT CASE WHEN EXISTS (
    SELECT 1 FROM source_rust_types AS type
    JOIN source_rust_item_manifests AS item ON item.blob_id = type.blob_id
    WHERE type.blob_id = NEW.blob_id AND type.path_kind BETWEEN 2 AND 5
      AND (item.type_forms_version IS NOT 1
        OR (SELECT COUNT(*) FROM source_rust_type_children AS child
            WHERE child.blob_id = type.blob_id AND child.type_occurrence_id = type.occurrence_id) = 0
        OR (type.path_kind IN (2, 3, 5)
            AND (SELECT COUNT(*) FROM source_rust_type_children AS child
                 WHERE child.blob_id = type.blob_id AND child.type_occurrence_id = type.occurrence_id) <> 1)
        OR (SELECT COUNT(*) FROM source_rust_type_children AS child
            WHERE child.blob_id = type.blob_id AND child.type_occurrence_id = type.occurrence_id)
           <> (SELECT MAX(ordinal) + 1 FROM source_rust_type_children AS child
               WHERE child.blob_id = type.blob_id AND child.type_occurrence_id = type.occurrence_id))
  ) OR EXISTS (
    SELECT 1 FROM source_rust_types AS type
    WHERE type.blob_id = NEW.blob_id AND type.path_kind BETWEEN 2 AND 5
      AND (type.compound_start_byte < type.start_byte OR type.compound_end_byte > type.end_byte
        OR type.compound_provenance IS NOT type.provenance
        OR (type.type_parameters_occurrence_id IS NOT NULL
            AND (type.type_parameters_start_byte < type.compound_start_byte OR type.type_parameters_end_byte > type.compound_end_byte
              OR type.type_parameters_provenance IS NOT type.compound_provenance))
        OR EXISTS (
          SELECT 1 FROM source_rust_type_wrappers AS wrapper
          WHERE wrapper.blob_id = type.blob_id AND wrapper.type_occurrence_id = type.occurrence_id
            AND (type.compound_start_byte < wrapper.start_byte OR type.compound_end_byte > wrapper.end_byte)))
  ) OR EXISTS (
    SELECT 1 FROM source_rust_type_children AS child
    JOIN source_rust_types AS type
      ON type.blob_id = child.blob_id AND type.occurrence_id = child.type_occurrence_id
    CROSS JOIN source_rust_types AS occurrence
      ON occurrence.blob_id = child.blob_id AND occurrence.occurrence_id = child.occurrence_id
    WHERE child.blob_id = NEW.blob_id
      AND (type.path_kind NOT BETWEEN 2 AND 5
        OR occurrence.start_byte < type.compound_start_byte OR occurrence.end_byte > type.compound_end_byte
        OR occurrence.end_byte - occurrence.start_byte >= type.compound_end_byte - type.compound_start_byte
        OR occurrence.provenance IS NOT type.compound_provenance)
  ) OR EXISTS (
    SELECT 1 FROM source_rust_type_children AS child
    JOIN source_rust_type_children AS next
      ON next.blob_id = child.blob_id AND next.type_occurrence_id = child.type_occurrence_id
     AND next.ordinal = child.ordinal + 1
    CROSS JOIN source_rust_types AS first
      ON first.blob_id = child.blob_id AND first.occurrence_id = child.occurrence_id
    CROSS JOIN source_rust_types AS second
      ON second.blob_id = next.blob_id AND second.occurrence_id = next.occurrence_id
    WHERE child.blob_id = NEW.blob_id AND second.start_byte < first.end_byte
  ) THEN RAISE(ABORT, 'canonical Rust compound type shape is inconsistent') END;
END;

DROP TRIGGER source_fact_manifests_validate_shared_imports;
CREATE TRIGGER source_fact_manifests_validate_shared_imports
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND (
  EXISTS (SELECT 1 FROM import_statements AS import
             WHERE import.blob_id = NEW.blob_id AND import.source_import_id IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM source_imports AS source
                               WHERE source.blob_id = import.blob_id AND source.import_id = import.source_import_id))
  OR EXISTS (SELECT 1 FROM rust_import_targets AS target
             WHERE target.blob_id = NEW.blob_id AND target.source_import_id IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM source_imports AS source
                               WHERE source.blob_id = target.blob_id AND source.import_id = target.source_import_id))
  OR EXISTS (SELECT 1 FROM rust_exports AS export
             WHERE export.blob_id = NEW.blob_id AND export.source_import_id IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM source_imports AS source
                               WHERE source.blob_id = export.blob_id AND source.import_id = export.source_import_id))
  OR EXISTS (SELECT 1 FROM import_statements AS import
             WHERE import.blob_id = NEW.blob_id AND import.source_import_id IS NOT NULL
               AND (import.statement IS NOT NULL OR import.is_wildcard IS NOT NULL
                    OR import.is_global IS NOT NULL OR import.identifier IS NOT NULL
                    OR import.alias IS NOT NULL OR import.path_kind IS NOT NULL
                    OR import.declaration_occurrence_id IS NOT NULL
                    OR import.binder_occurrence_id IS NOT NULL
 ))
  OR EXISTS (SELECT 1 FROM rust_import_targets AS target
             WHERE target.blob_id = NEW.blob_id AND target.source_import_id IS NOT NULL
               AND (target.imported_name IS NOT NULL OR target.is_glob IS NOT NULL
                    OR target.leading_absolute IS NOT NULL OR target.is_extern_crate IS NOT NULL OR target.is_macro_use IS NOT NULL
                    OR target.declaration_occurrence_id IS NOT NULL
                    OR target.target_occurrence_id IS NOT NULL OR target.alias_occurrence_id IS NOT NULL
 ))
  OR EXISTS (SELECT 1 FROM rust_import_targets AS target
             JOIN source_imports AS source
               ON source.blob_id = target.blob_id
              AND source.import_id = target.source_import_id
             WHERE target.blob_id = NEW.blob_id
               AND ((source.is_wildcard = 1 AND
                     (source.identifier IS NOT NULL OR source.alias IS NOT NULL
                      OR source.target_occurrence_id IS NOT NULL OR source.alias_occurrence_id IS NOT NULL))
                    OR (source.is_wildcard = 0 AND
                        (source.target_occurrence_id IS NULL OR source.identifier IS NULL
                         OR source.identifier IS NOT (SELECT segment FROM source_import_segments
                                                      WHERE blob_id = source.blob_id AND import_id = source.import_id
                                                      ORDER BY ordinal DESC LIMIT 1)))
                    OR (source.alias IS NULL) <> (source.alias_occurrence_id IS NULL)))
  OR EXISTS (SELECT 1 FROM rust_import_targets AS target
             JOIN source_imports AS source
               ON source.blob_id = target.blob_id
              AND source.import_id = target.source_import_id
             WHERE target.blob_id = NEW.blob_id
               AND ((target.module_path IS NOT COALESCE((SELECT group_concat(segment, '::' ORDER BY ordinal)
                                                         FROM source_import_segments
                                                         WHERE blob_id = source.blob_id AND import_id = source.import_id
                                                           AND (source.is_wildcard = 1 OR ordinal <
                                                                (SELECT MAX(ordinal) FROM source_import_segments
                                                                 WHERE blob_id = source.blob_id AND import_id = source.import_id))), '')
                    AND NOT (source.is_wildcard = 0
                             AND target.module_path IS (SELECT group_concat(segment, '::' ORDER BY ordinal)
                                                        FROM source_import_segments
                                                        WHERE blob_id = source.blob_id
                                                          AND import_id = source.import_id)))
                    OR target.bound_name IS NOT CASE WHEN source.alias = '_' THEN NULL ELSE COALESCE(source.alias, source.identifier) END))
  OR EXISTS (SELECT 1 FROM rust_exports AS export
             JOIN source_imports AS source
               ON source.blob_id = export.blob_id
              AND source.import_id = export.source_import_id
             WHERE export.blob_id = NEW.blob_id
               AND export.exported_name IS NOT CASE WHEN source.is_wildcard = 1 THEN NULL
                                                     ELSE CASE WHEN source.alias = '_' THEN NULL ELSE COALESCE(source.alias, source.identifier) END END)
 )
BEGIN SELECT RAISE(ABORT, 'shared canonical import projections are inconsistent'); END;

DROP TRIGGER source_rust_item_manifests_validate_accounting;
CREATE TRIGGER source_rust_item_manifests_validate_accounting
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
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

DROP TRIGGER source_rust_macro_inputs_validate_seal;
CREATE TRIGGER source_rust_macro_inputs_validate_seal
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND (EXISTS (
   SELECT 1 FROM source_rust_macro_inputs AS input
   WHERE input.blob_id = NEW.blob_id AND NOT EXISTS (
     SELECT 1 FROM source_rust_macro_input_tokens AS root
     WHERE root.blob_id = input.blob_id
       AND root.invocation_occurrence_id = input.invocation_occurrence_id
       AND root.ordinal = 0 AND root.parent_ordinal IS NULL
       AND root.syntax_kind = 'token_tree'
       AND root.start_byte = input.start_byte
       AND root.end_byte = input.start_byte + length(CAST(input.source AS BLOB))))
 OR EXISTS (
   SELECT 1 FROM source_rust_macro_input_tokens AS token
   LEFT JOIN source_rust_macro_input_tokens AS parent
     ON parent.blob_id = token.blob_id
    AND parent.invocation_occurrence_id = token.invocation_occurrence_id
    AND parent.ordinal = token.parent_ordinal
   WHERE token.blob_id = NEW.blob_id AND token.ordinal > 0
     AND (parent.ordinal IS NULL OR token.start_byte < parent.start_byte
       OR token.end_byte > parent.end_byte))
 OR EXISTS (
   SELECT 1 FROM source_rust_macro_input_tokens
   WHERE blob_id = NEW.blob_id GROUP BY invocation_occurrence_id
   HAVING MIN(ordinal) <> 0 OR MAX(ordinal) + 1 <> COUNT(*)))
BEGIN SELECT RAISE(ABORT, 'canonical Rust macro input tree is inconsistent'); END;
