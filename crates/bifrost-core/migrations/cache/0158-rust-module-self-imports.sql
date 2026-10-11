DROP VIEW source_rust_exports;
DROP VIEW source_rust_import_module_segments;
DROP VIEW source_rust_import_targets;

CREATE VIEW source_rust_import_module_self AS
SELECT target.blob_id, target.lang, target.ordinal AS import_ordinal,
       target.source_import_id
FROM rust_import_targets AS target
JOIN source_imports AS source
  ON source.blob_id = target.blob_id AND source.import_id = target.source_import_id
WHERE target.source_import_id IS NOT NULL
  AND source.is_wildcard = 0
  AND target.module_path = (
      SELECT group_concat(segment.segment, '::' ORDER BY segment.ordinal)
      FROM source_import_segments AS segment
      WHERE segment.blob_id = source.blob_id AND segment.import_id = source.import_id);

CREATE VIEW source_rust_exports AS
SELECT export.blob_id, export.lang, export.ordinal, export.exported_name,
       CASE WHEN export.source_import_id IS NULL THEN export.source_path ELSE
         COALESCE((SELECT group_concat(segment.segment, '::' ORDER BY segment.ordinal)
                   FROM source_import_segments AS segment
                   WHERE segment.blob_id = source.blob_id
                     AND segment.import_id = source.import_id
                     AND (source.is_wildcard = 1 OR (
                          source.is_wildcard = 0 AND EXISTS (
                            SELECT 1 FROM rust_import_targets AS self_target
                            WHERE self_target.blob_id = source.blob_id
                              AND self_target.source_import_id = source.import_id
                              AND self_target.module_path = (
                                SELECT group_concat(full_segment.segment, '::' ORDER BY full_segment.ordinal)
                                FROM source_import_segments AS full_segment
                                WHERE full_segment.blob_id = source.blob_id
                                  AND full_segment.import_id = source.import_id))) OR segment.ordinal <
                          (SELECT MAX(last_segment.ordinal) FROM source_import_segments AS last_segment
                           WHERE last_segment.blob_id = source.blob_id
                             AND last_segment.import_id = source.import_id))), '') END
         AS source_path,
       CASE WHEN export.source_import_id IS NULL THEN export.imported_name
            WHEN source.is_wildcard = 0 AND EXISTS (
              SELECT 1 FROM rust_import_targets AS self_target
              WHERE self_target.blob_id = source.blob_id
                AND self_target.source_import_id = source.import_id
                AND self_target.module_path = (
                  SELECT group_concat(segment.segment, '::' ORDER BY segment.ordinal)
                  FROM source_import_segments AS segment
                  WHERE segment.blob_id = source.blob_id
                    AND segment.import_id = source.import_id)) THEN 'self'
            ELSE source.identifier END AS imported_name,
       CASE WHEN export.source_import_id IS NULL THEN export.is_glob
            ELSE source.is_wildcard END AS is_glob,
       export.source_import_id AS source_import_id
FROM rust_exports AS export
LEFT JOIN source_imports AS source
  ON source.blob_id = export.blob_id AND source.import_id = export.source_import_id;

CREATE VIEW source_rust_import_module_segments AS
SELECT target.blob_id, target.lang, target.ordinal AS import_ordinal,
       segment.ordinal AS ordinal, segment.segment
FROM rust_import_targets AS target
JOIN source_imports AS source
  ON source.blob_id = target.blob_id AND source.import_id = target.source_import_id
JOIN source_import_segments AS segment
  ON segment.blob_id = source.blob_id AND segment.import_id = source.import_id
WHERE target.source_import_id IS NOT NULL
  AND (source.is_wildcard = 1 OR (
       source.is_wildcard = 0 AND target.module_path = (
         SELECT group_concat(full_segment.segment, '::' ORDER BY full_segment.ordinal)
         FROM source_import_segments AS full_segment
         WHERE full_segment.blob_id = source.blob_id
           AND full_segment.import_id = source.import_id)) OR segment.ordinal <
       (SELECT MAX(last_segment.ordinal) FROM source_import_segments AS last_segment
        WHERE last_segment.blob_id = source.blob_id AND last_segment.import_id = source.import_id));

CREATE VIEW source_rust_import_targets AS
SELECT target.blob_id, target.lang, target.ordinal, target.module_path, target.bound_name,
       CASE WHEN target.source_import_id IS NULL THEN target.imported_name
            WHEN source.is_wildcard = 0 AND target.module_path = (
              SELECT group_concat(segment.segment, '::' ORDER BY segment.ordinal)
              FROM source_import_segments AS segment
              WHERE segment.blob_id = source.blob_id
                AND segment.import_id = source.import_id) THEN 'self'
            ELSE source.identifier END AS imported_name,
       CASE WHEN target.source_import_id IS NULL THEN target.is_glob
            ELSE source.is_wildcard END AS is_glob,
       CASE WHEN target.source_context_occurrence_id IS NULL THEN target.visibility
            ELSE context.visibility END AS visibility,
       CASE WHEN target.source_context_occurrence_id IS NULL THEN target.owner_module
            WHEN context.declaration_occurrence_id IS NULL THEN NULL
            ELSE context.owner_module END AS owner_module,
       CASE WHEN target.source_context_occurrence_id IS NULL THEN target.owner_start
            WHEN context.declaration_occurrence_id IS NULL THEN NULL
            WHEN context.owner_scope_occurrence_id IS NULL THEN 0
            ELSE context.owner_scope_start_byte END AS owner_start,
       CASE WHEN target.source_context_occurrence_id IS NULL THEN target.owner_end
            WHEN context.declaration_occurrence_id IS NULL THEN NULL
            WHEN context.owner_scope_occurrence_id IS NULL THEN manifest.source_bytes
            ELSE context.owner_scope_end_byte END AS owner_end,
       CASE WHEN target.source_context_occurrence_id IS NULL THEN target.local_start
            WHEN context.declaration_occurrence_id IS NULL OR context.local_scope_occurrence_id IS NULL THEN NULL
            ELSE context.local_scope_start_byte END AS local_start,
       CASE WHEN target.source_context_occurrence_id IS NULL THEN target.local_end
            WHEN context.declaration_occurrence_id IS NULL OR context.local_scope_occurrence_id IS NULL THEN NULL
            ELSE context.local_scope_end_byte END AS local_end,
       CASE WHEN target.source_context_occurrence_id IS NULL THEN target.cfg_condition
            ELSE context.cfg_condition END AS cfg_condition,
       CASE WHEN target.source_import_id IS NULL THEN target.is_extern_crate
            ELSE CASE WHEN source.path_kind = 'extern_crate' THEN 1 ELSE 0 END END
         AS is_extern_crate,
       CASE WHEN target.source_import_id IS NULL THEN target.is_macro_use
            ELSE source.is_macro_use END AS is_macro_use,
       CASE WHEN target.source_import_id IS NULL THEN target.leading_absolute
            ELSE source.is_global END AS leading_absolute,
       CASE WHEN target.source_import_id IS NULL THEN target.declaration_occurrence_id ELSE source.declaration_occurrence_id END
         AS declaration_occurrence_id,
       CASE WHEN target.source_import_id IS NULL THEN target.target_occurrence_id ELSE source.target_occurrence_id END
         AS target_occurrence_id,
       CASE WHEN target.source_import_id IS NULL THEN target.alias_occurrence_id ELSE source.alias_occurrence_id END
         AS alias_occurrence_id,
       target.source_import_id AS source_import_id,
       context.native_scope AS native_scope
FROM rust_import_targets AS target
LEFT JOIN source_imports AS source
  ON source.blob_id = target.blob_id AND source.import_id = target.source_import_id
LEFT JOIN source_rust_import_contexts AS context
  ON context.blob_id = target.blob_id
 AND context.declaration_occurrence_id = target.source_context_occurrence_id
LEFT JOIN source_fact_manifests AS manifest
  ON manifest.blob_id = target.blob_id;

DROP TRIGGER source_fact_manifests_validate_shared_imports;

CREATE TRIGGER source_fact_manifests_validate_shared_imports
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
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
