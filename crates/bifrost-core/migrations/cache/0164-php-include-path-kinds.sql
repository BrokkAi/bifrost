DROP TRIGGER source_fact_manifests_validate_import_path_availability;
DROP TRIGGER source_fact_manifests_validate_rust_import_contexts;
DROP TRIGGER source_fact_manifests_validate_shared_imports;
DROP TRIGGER source_php_manifests_validate;
DROP TRIGGER source_ruby_manifests_validate;
DROP VIEW source_import_statements;
DROP VIEW source_rust_exports;
DROP VIEW source_rust_import_module_segments;
DROP VIEW source_rust_import_module_self;
DROP VIEW source_rust_import_targets;

CREATE TABLE source_imports_0164(
  blob_id                   INTEGER NOT NULL,
  import_id                 INTEGER NOT NULL CHECK(import_id >= 0),
  statement                 TEXT NOT NULL,
  is_wildcard               INTEGER NOT NULL CHECK(is_wildcard IN (0, 1)),
  is_global                 INTEGER NOT NULL CHECK(is_global IN (0, 1)),
  is_macro_use              INTEGER NOT NULL DEFAULT 0 CHECK(is_macro_use IN (0, 1)),
  identifier                TEXT,
  alias                     TEXT,
  path_kind                 TEXT CHECK(path_kind IN (
    'namespace', 'import_from', 'static_member', 'extern_crate',
    'file_include', 'dynamic_include'
  )),
  declaration_occurrence_id INTEGER NOT NULL CHECK(declaration_occurrence_id >= 0),
  target_occurrence_id      INTEGER CHECK(target_occurrence_id IS NULL OR target_occurrence_id >= 0),
  alias_occurrence_id       INTEGER CHECK(alias_occurrence_id IS NULL OR alias_occurrence_id >= 0),
  has_structured_path       INTEGER NOT NULL DEFAULT 1 CHECK(has_structured_path IN (0, 1)),
  declaration_start_byte    INTEGER NOT NULL CHECK(declaration_start_byte >= 0),
  declaration_end_byte      INTEGER NOT NULL CHECK(declaration_end_byte >= declaration_start_byte),
  target_start_byte         INTEGER CHECK(target_start_byte >= 0),
  target_end_byte           INTEGER CHECK(target_end_byte >= target_start_byte),
  alias_start_byte          INTEGER CHECK(alias_start_byte >= 0),
  alias_end_byte            INTEGER CHECK(alias_end_byte >= alias_start_byte),
  PRIMARY KEY(blob_id, import_id),
  CHECK((target_occurrence_id IS NULL) = (target_start_byte IS NULL)),
  CHECK((alias_occurrence_id IS NULL) = (alias_start_byte IS NULL)),
  CHECK((target_occurrence_id IS NULL) = (target_end_byte IS NULL)),
  CHECK((alias_occurrence_id IS NULL) = (alias_end_byte IS NULL)),
  FOREIGN KEY(blob_id) REFERENCES source_fact_manifests(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO source_imports_0164(
  blob_id, import_id, statement, is_wildcard, is_global, is_macro_use,
  identifier, alias, path_kind, declaration_occurrence_id,
  target_occurrence_id, alias_occurrence_id, has_structured_path,
  declaration_start_byte, declaration_end_byte, target_start_byte,
  target_end_byte, alias_start_byte, alias_end_byte
)
SELECT
  blob_id, import_id, statement, is_wildcard, is_global, is_macro_use,
  identifier, alias, path_kind, declaration_occurrence_id,
  target_occurrence_id, alias_occurrence_id, has_structured_path,
  declaration_start_byte, declaration_end_byte, target_start_byte,
  target_end_byte, alias_start_byte, alias_end_byte
FROM source_imports;

DROP TABLE source_imports;
ALTER TABLE source_imports_0164 RENAME TO source_imports;

CREATE INDEX idx_source_imports_declaration
  ON source_imports(blob_id, declaration_occurrence_id);

CREATE INDEX idx_source_imports_identifier
  ON source_imports(identifier, blob_id, import_id)
  WHERE identifier IS NOT NULL;

CREATE INDEX idx_source_imports_dynamic_include_blob
  ON source_imports(blob_id, import_id)
  WHERE path_kind = 'dynamic_include';

CREATE TRIGGER source_imports_no_delete_after_seal
BEFORE DELETE ON source_imports
WHEN EXISTS (SELECT 1 FROM source_fact_manifests
             WHERE blob_id = OLD.blob_id AND publication_state = 'complete')
BEGIN SELECT RAISE(ABORT, 'sealed source facts are immutable'); END;

CREATE TRIGGER source_imports_no_insert_after_seal
BEFORE INSERT ON source_imports
WHEN EXISTS (SELECT 1 FROM source_fact_manifests
             WHERE blob_id = NEW.blob_id AND publication_state = 'complete')
BEGIN SELECT RAISE(ABORT, 'sealed source facts are immutable'); END;

CREATE TRIGGER source_imports_no_update_after_seal
BEFORE UPDATE ON source_imports
WHEN EXISTS (SELECT 1 FROM source_fact_manifests
             WHERE blob_id IN (OLD.blob_id, NEW.blob_id)
               AND publication_state = 'complete')
BEGIN SELECT RAISE(ABORT, 'sealed source facts are immutable'); END;

CREATE VIEW source_import_statements AS
SELECT import.blob_id, import.lang, import.ordinal,
       CASE WHEN import.source_import_id IS NULL THEN import.statement
            ELSE (SELECT source.statement FROM source_imports AS source
                  WHERE source.blob_id = import.blob_id AND source.import_id = import.source_import_id) END AS statement,
       CASE WHEN import.source_import_id IS NULL THEN import.is_wildcard
            ELSE (SELECT source.is_wildcard FROM source_imports AS source
                  WHERE source.blob_id = import.blob_id AND source.import_id = import.source_import_id) END AS is_wildcard,
       CASE WHEN import.source_import_id IS NULL THEN import.is_global
            ELSE (SELECT source.is_global FROM source_imports AS source
                  WHERE source.blob_id = import.blob_id AND source.import_id = import.source_import_id) END AS is_global,
       CASE WHEN import.source_import_id IS NULL THEN import.identifier
            ELSE (SELECT source.identifier FROM source_imports AS source
                  WHERE source.blob_id = import.blob_id AND source.import_id = import.source_import_id) END AS identifier,
       CASE WHEN import.source_import_id IS NULL THEN import.alias
            ELSE (SELECT source.alias FROM source_imports AS source
                  WHERE source.blob_id = import.blob_id AND source.import_id = import.source_import_id) END AS alias,
       CASE WHEN import.source_import_id IS NULL THEN import.path_kind
            ELSE (SELECT source.path_kind FROM source_imports AS source
                  WHERE source.blob_id = import.blob_id AND source.import_id = import.source_import_id) END AS path_kind,
       CASE WHEN import.source_import_id IS NOT NULL THEN
              (SELECT source.declaration_start_byte FROM source_imports AS source
               WHERE source.blob_id = import.blob_id AND source.import_id = import.source_import_id)
            ELSE import.declaration_start_byte END AS declaration_start_byte,
       CASE WHEN import.source_import_id IS NOT NULL THEN
              (SELECT COALESCE(source.alias_start_byte, source.target_start_byte) FROM source_imports AS source
               WHERE source.blob_id = import.blob_id AND source.import_id = import.source_import_id)
            ELSE import.binder_start END AS binder_start,
       CASE WHEN import.source_import_id IS NOT NULL THEN
              (SELECT COALESCE(source.alias_end_byte, source.target_end_byte) FROM source_imports AS source
               WHERE source.blob_id = import.blob_id AND source.import_id = import.source_import_id)
            ELSE import.binder_end END AS binder_end,
       CASE WHEN import.source_import_id IS NULL THEN import.declaration_occurrence_id
            ELSE (SELECT source.declaration_occurrence_id FROM source_imports AS source
                  WHERE source.blob_id = import.blob_id AND source.import_id = import.source_import_id) END AS declaration_occurrence_id,
       CASE WHEN import.source_import_id IS NULL THEN import.binder_occurrence_id
            ELSE (SELECT COALESCE(source.alias_occurrence_id, source.target_occurrence_id) FROM source_imports AS source
                  WHERE source.blob_id = import.blob_id AND source.import_id = import.source_import_id) END AS binder_occurrence_id,
       CASE WHEN import.source_import_id IS NULL THEN
              CASE WHEN import.declaration_start_byte IS NOT NULL
                         OR import.declaration_occurrence_id IS NOT NULL
                   THEN 1 ELSE 0 END
            ELSE (SELECT source.has_structured_path FROM source_imports AS source
                  WHERE source.blob_id = import.blob_id AND source.import_id = import.source_import_id) END
         AS has_structured_path
FROM import_statements AS import;

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

CREATE TRIGGER source_fact_manifests_validate_import_path_availability
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
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

CREATE TRIGGER source_fact_manifests_validate_rust_import_contexts
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
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

CREATE TRIGGER source_php_manifests_validate
BEFORE INSERT ON source_php_manifests
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM blob_meta AS meta
    WHERE meta.blob_id = NEW.blob_id AND meta.php_source_version = NEW.facts_version
  ) THEN RAISE(ABORT, 'PHP source publication requires a matching PHP blob requirement') END;
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM source_php_fact_costs WHERE blob_id = NEW.blob_id
      AND logical_rows = NEW.logical_rows AND payload_bytes = NEW.payload_bytes
  ) THEN RAISE(ABORT, 'PHP source publication accounting is inconsistent') END;
  SELECT CASE WHEN (
    (SELECT COUNT(*) FROM source_php_contexts WHERE blob_id = NEW.blob_id)
      <> COALESCE((SELECT MAX(context_id) + 1 FROM source_php_contexts WHERE blob_id = NEW.blob_id), 0)
    OR (SELECT COUNT(*) FROM source_php_aliases WHERE blob_id = NEW.blob_id)
      <> COALESCE((SELECT MAX(alias_id) + 1 FROM source_php_aliases WHERE blob_id = NEW.blob_id), 0)
    OR (SELECT COUNT(*) FROM source_php_writes WHERE blob_id = NEW.blob_id)
      <> COALESCE((SELECT MAX(ordinal) + 1 FROM source_php_writes WHERE blob_id = NEW.blob_id), 0)
    OR EXISTS (SELECT 1 FROM source_php_aliases AS alias
               JOIN source_imports AS imported
                 ON imported.blob_id = alias.blob_id AND imported.import_id = alias.source_import_id
               WHERE alias.blob_id = NEW.blob_id
                 AND (COALESCE(length(COALESCE(imported.alias, imported.identifier)), 0) = 0
                   OR NOT EXISTS (SELECT 1 FROM source_import_segments AS segment
                                  WHERE segment.blob_id = imported.blob_id AND segment.import_id = imported.import_id)))
    OR EXISTS (SELECT 1 FROM source_php_context_aliases WHERE blob_id = NEW.blob_id
               GROUP BY context_id HAVING MIN(ordinal) <> 0 OR MAX(ordinal) <> COUNT(*) - 1)
    OR EXISTS (SELECT 1 FROM source_php_context_aliases WHERE blob_id = NEW.blob_id
               GROUP BY context_id, alias_id HAVING COUNT(*) > 1)
    OR EXISTS (SELECT 1
               FROM source_php_context_aliases AS previous
               JOIN source_php_context_aliases AS following
                 ON following.blob_id = previous.blob_id
                AND following.context_id = previous.context_id
                AND following.ordinal = previous.ordinal + 1
               WHERE previous.blob_id = NEW.blob_id
                 AND following.alias_id <= previous.alias_id)
    OR EXISTS (SELECT 1 FROM source_php_nominal_arms WHERE blob_id = NEW.blob_id
               GROUP BY declaration_id HAVING MIN(ordinal) <> 0 OR MAX(ordinal) <> COUNT(*) - 1)
    OR EXISTS (SELECT 1 FROM source_php_nominal_arms WHERE blob_id = NEW.blob_id
               GROUP BY declaration_id, arm HAVING COUNT(*) > 1)
    OR EXISTS (SELECT 1 FROM source_php_supertypes WHERE blob_id = NEW.blob_id
               GROUP BY declaration_id HAVING MIN(ordinal) <> 0 OR MAX(ordinal) <> COUNT(*) - 1)
    OR EXISTS (SELECT 1 FROM source_php_write_nominal_arms WHERE blob_id = NEW.blob_id
               GROUP BY write_ordinal HAVING MIN(ordinal) <> 0 OR MAX(ordinal) <> COUNT(*) - 1)
    OR EXISTS (SELECT 1 FROM source_php_write_nominal_arms WHERE blob_id = NEW.blob_id
               GROUP BY write_ordinal, arm HAVING COUNT(*) > 1)
    OR EXISTS (SELECT 1 FROM source_php_declarations AS declaration
               WHERE declaration.blob_id = NEW.blob_id
                 AND declaration.class_parent_ordinal IS NOT NULL
                 AND declaration.kind <> 0)
    OR EXISTS (SELECT 1 FROM source_php_declarations AS declaration
               WHERE declaration.blob_id = NEW.blob_id
                 AND declaration.declared_type_kind <> 0
                 AND declaration.declared_type_occurrence_id IS NULL)
    OR EXISTS (SELECT 1 FROM source_php_declarations AS declaration
               WHERE declaration.blob_id = NEW.blob_id
                 AND ((declaration.declared_type_kind = 1) <> EXISTS (
                    SELECT 1 FROM source_php_nominal_arms AS arm
                    WHERE arm.blob_id = declaration.blob_id AND arm.declaration_id = declaration.declaration_id)))
    OR EXISTS (SELECT 1 FROM source_php_writes AS write
               WHERE write.blob_id = NEW.blob_id
                 AND ((write.value_type_kind = 1) <> EXISTS (
                    SELECT 1 FROM source_php_write_nominal_arms AS arm
                    WHERE arm.blob_id = write.blob_id AND arm.write_ordinal = write.ordinal)))
    OR EXISTS (SELECT 1 FROM source_php_writes AS write
               JOIN source_php_declarations AS declaration
                 ON declaration.blob_id = write.blob_id
                AND declaration.declaration_id = write.class_declaration_id
               WHERE write.blob_id = NEW.blob_id AND declaration.kind <> 0)
  ) THEN RAISE(ABORT, 'PHP source publication has invalid dense rows or type shape') END;
END;

CREATE TRIGGER source_ruby_manifests_validate
BEFORE INSERT ON source_ruby_manifests
BEGIN
  SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM blob_meta AS meta WHERE meta.blob_id = NEW.blob_id
    AND meta.lang = 'ruby' AND meta.ruby_source_version = NEW.facts_version)
    THEN RAISE(ABORT, 'Ruby source publication requires matching blob requirement') END;
  SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM source_ruby_costs WHERE blob_id = NEW.blob_id
    AND logical_rows = NEW.logical_rows AND payload_bytes = NEW.payload_bytes)
    THEN RAISE(ABORT, 'Ruby source publication accounting is inconsistent') END;
  SELECT CASE WHEN EXISTS (SELECT 1 FROM source_ruby_loads AS load WHERE load.blob_id = NEW.blob_id
      AND load.has_constant <> EXISTS (SELECT 1 FROM source_ruby_load_constants AS part
        WHERE part.blob_id = load.blob_id AND part.import_id = load.import_id))
    OR EXISTS (SELECT 1 FROM source_ruby_load_constants WHERE blob_id = NEW.blob_id GROUP BY import_id
      HAVING MIN(ordinal) <> 0 OR MAX(ordinal) <> COUNT(*) - 1)
    OR (SELECT COUNT(*) FROM source_ruby_loads WHERE blob_id = NEW.blob_id)
       <> (SELECT COUNT(*) FROM source_imports WHERE blob_id = NEW.blob_id)
    THEN RAISE(ABORT, 'Ruby load source facts are inconsistent') END;
END;
