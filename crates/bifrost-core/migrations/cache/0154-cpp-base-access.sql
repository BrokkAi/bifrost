-- Widen the C++ source requirement to admit facts version 2. The original
-- CHECK rejected the bumped requirement; INSERT OR IGNORE then left an
-- incomplete blob_meta row behind, making optional-fact triggers report the
-- misleading "requires a complete blob" error during publication.
PRAGMA foreign_keys = OFF;
PRAGMA legacy_alter_table = ON;
ALTER TABLE blob_meta RENAME TO blob_meta_0154_old;
CREATE TABLE blob_meta(
  blob_id                    INTEGER NOT NULL,
  lang                       TEXT    NOT NULL,
  contains_tests             INTEGER NOT NULL CHECK(contains_tests IN (0, 1)),
  content_package            TEXT    NOT NULL,
  stored_unit_count          INTEGER NOT NULL CHECK(stored_unit_count >= 0),
  range_count                INTEGER NOT NULL CHECK(range_count >= 0),
  signature_count            INTEGER NOT NULL CHECK(signature_count >= 0),
  signature_metadata_count   INTEGER NOT NULL CHECK(signature_metadata_count >= 0),
  supertype_count            INTEGER NOT NULL CHECK(supertype_count >= 0),
  child_count                INTEGER NOT NULL CHECK(child_count >= 0),
  import_statement_count     INTEGER NOT NULL CHECK(import_statement_count >= 0),
  type_identifier_count      INTEGER NOT NULL CHECK(type_identifier_count >= 0),
  is_complete                INTEGER NOT NULL CHECK(is_complete IN (0, 1)),
  declaration_visibility_version INTEGER
  CHECK(declaration_visibility_version IS NULL OR declaration_visibility_version = 1),
  java_type_constructor_version INTEGER
  CHECK(java_type_constructor_version IS NULL
    OR (java_type_constructor_version = 1 AND declaration_visibility_version IS NOT NULL)),
  go_source_version INTEGER CHECK(go_source_version IS NULL OR go_source_version = 1),
  java_source_version INTEGER CHECK(java_source_version IS NULL OR java_source_version = 1),
  ruby_source_version INTEGER CHECK(ruby_source_version IS NULL OR ruby_source_version = 1),
  php_source_version INTEGER CHECK(php_source_version IS NULL OR php_source_version = 1),
  scala_source_version INTEGER CHECK(scala_source_version IS NULL OR scala_source_version = 1),
  js_ts_source_version INTEGER CHECK(js_ts_source_version IS NULL OR js_ts_source_version = 1),
  cpp_source_version INTEGER CHECK(cpp_source_version IS NULL OR cpp_source_version IN (1, 2)),
  source_facts_version INTEGER CHECK(source_facts_version > 0),
  metadata_bridges_required INTEGER NOT NULL DEFAULT 0
  CHECK(metadata_bridges_required IN (0, 1)),
  python_source_version INTEGER CHECK(python_source_version IS NULL OR python_source_version = 1),
  native_bridges_required INTEGER NOT NULL DEFAULT 0
  CHECK(native_bridges_required IN (0, 1)),
  parse_completeness TEXT NOT NULL DEFAULT 'complete'
  CHECK(parse_completeness IN ('complete', 'partial')),
  PRIMARY KEY(blob_id),
  FOREIGN KEY(blob_id, lang)
    REFERENCES "blobs"(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
INSERT INTO blob_meta(
  blob_id, lang, contains_tests, content_package, stored_unit_count,
  range_count, signature_count, signature_metadata_count, supertype_count,
  child_count, import_statement_count, type_identifier_count, is_complete,
  declaration_visibility_version, java_type_constructor_version,
  go_source_version, java_source_version, ruby_source_version,
  php_source_version, scala_source_version, js_ts_source_version,
  cpp_source_version, source_facts_version, metadata_bridges_required,
  python_source_version, native_bridges_required, parse_completeness
)
SELECT
  blob_id, lang, contains_tests, content_package, stored_unit_count,
  range_count, signature_count, signature_metadata_count, supertype_count,
  child_count, import_statement_count, type_identifier_count, is_complete,
  declaration_visibility_version, java_type_constructor_version,
  go_source_version, java_source_version, ruby_source_version,
  php_source_version, scala_source_version, js_ts_source_version,
  cpp_source_version, source_facts_version, metadata_bridges_required,
  python_source_version, native_bridges_required, parse_completeness
FROM blob_meta_0154_old;
DROP TABLE blob_meta_0154_old;
PRAGMA legacy_alter_table = OFF;
PRAGMA foreign_keys = ON;

-- Recreate the triggers that were attached to blob_meta and therefore were
-- removed with the old table. Other schema objects retain their blob_meta
-- references because legacy_alter_table kept those definitions unchanged.
CREATE TRIGGER blob_meta_cpp_source_requirement_is_immutable
BEFORE UPDATE OF cpp_source_version ON blob_meta
WHEN EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
 AND (OLD.is_complete = 1 OR EXISTS (SELECT 1 FROM source_fact_manifests
                                   WHERE blob_id = OLD.blob_id AND publication_state = 'complete'))
BEGIN SELECT RAISE(ABORT, 'sealed C++ source requirement is immutable'); END;

CREATE TRIGGER blob_meta_signature_metadata_pairs_no_update_after_seal
BEFORE UPDATE OF signature_metadata_count ON blob_meta
WHEN EXISTS (
  SELECT 1 FROM blob_optional_fact_manifest
  WHERE blob_id = OLD.blob_id AND fact_kind = 6
)
AND EXISTS (
  SELECT 1 FROM blobs WHERE id = OLD.blob_id
)
BEGIN
  SELECT RAISE(ABORT, 'sealed signature metadata pair manifest is immutable');
END;
CREATE TRIGGER common_source_requirements_are_immutable
BEFORE UPDATE OF source_facts_version, metadata_bridges_required, native_bridges_required ON blob_meta
WHEN OLD.is_complete = 1
BEGIN SELECT RAISE(ABORT, 'sealed common source requirements are immutable'); END;

CREATE TRIGGER cpp_source_requirement_no_update_after_seal
BEFORE UPDATE OF cpp_source_version ON blob_meta
WHEN EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
 AND (OLD.is_complete = 1 OR EXISTS (SELECT 1 FROM source_fact_manifests
                                   WHERE blob_id = OLD.blob_id AND publication_state = 'complete'))
BEGIN SELECT RAISE(ABORT, 'sealed C++ source requirement is immutable'); END;

CREATE TRIGGER go_source_requirement_no_update_after_seal
BEFORE UPDATE OF go_source_version ON blob_meta
WHEN EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
 AND (OLD.is_complete = 1 OR EXISTS (SELECT 1 FROM source_fact_manifests
                                   WHERE blob_id = OLD.blob_id AND publication_state = 'complete'))
BEGIN SELECT RAISE(ABORT, 'sealed Go source requirement is immutable'); END;

CREATE TRIGGER java_source_requirement_no_update_after_seal
BEFORE UPDATE OF java_source_version ON blob_meta
WHEN EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
 AND (OLD.is_complete = 1 OR EXISTS (SELECT 1 FROM source_fact_manifests
                                   WHERE blob_id = OLD.blob_id AND publication_state = 'complete'))
BEGIN SELECT RAISE(ABORT, 'sealed Java source requirement is immutable'); END;

CREATE TRIGGER java_type_constructor_requirement_no_update_after_seal
BEFORE UPDATE OF java_type_constructor_version ON blob_meta
WHEN EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
 AND (
   OLD.is_complete = 1
   OR EXISTS (SELECT 1 FROM source_declaration_visibility_manifests
              WHERE blob_id = OLD.blob_id)
 )
BEGIN
  SELECT RAISE(ABORT, 'sealed Java constructor shape requirement is immutable');
END;

CREATE TRIGGER js_ts_source_requirement_no_update_after_seal
BEFORE UPDATE OF js_ts_source_version ON blob_meta
WHEN EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
 AND (OLD.is_complete = 1 OR EXISTS (SELECT 1 FROM source_fact_manifests
                                   WHERE blob_id = OLD.blob_id AND publication_state = 'complete'))
BEGIN SELECT RAISE(ABORT, 'sealed JS/TS source requirement is immutable'); END;

CREATE TRIGGER php_source_requirement_no_update_after_seal
BEFORE UPDATE OF php_source_version ON blob_meta
WHEN EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
 AND (OLD.is_complete = 1 OR EXISTS (SELECT 1 FROM source_fact_manifests
                                   WHERE blob_id = OLD.blob_id AND publication_state = 'complete'))
BEGIN SELECT RAISE(ABORT, 'sealed PHP source requirement is immutable'); END;

CREATE TRIGGER python_source_requirement_no_update_after_seal
BEFORE UPDATE OF python_source_version ON blob_meta
WHEN EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
 AND (OLD.is_complete = 1 OR EXISTS (SELECT 1 FROM source_fact_manifests
                                   WHERE blob_id = OLD.blob_id AND publication_state = 'complete'))
BEGIN SELECT RAISE(ABORT, 'sealed Python source requirement is immutable'); END;

CREATE TRIGGER ruby_source_requirement_no_update_after_seal
BEFORE UPDATE OF ruby_source_version ON blob_meta
WHEN EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
 AND (OLD.is_complete = 1 OR EXISTS (SELECT 1 FROM source_fact_manifests WHERE blob_id = OLD.blob_id))
 AND NEW.ruby_source_version IS NOT OLD.ruby_source_version
BEGIN SELECT RAISE(ABORT, 'sealed Ruby source requirement is immutable'); END;

CREATE TRIGGER scala_source_requirement_no_update_after_seal
BEFORE UPDATE OF scala_source_version ON blob_meta
WHEN EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
 AND (OLD.is_complete = 1 OR EXISTS (SELECT 1 FROM source_fact_manifests
                                   WHERE blob_id = OLD.blob_id AND publication_state = 'complete'))
BEGIN SELECT RAISE(ABORT, 'sealed Scala source requirement is immutable'); END;

CREATE TRIGGER source_declaration_visibility_requirement_no_update_after_seal
BEFORE UPDATE OF declaration_visibility_version ON blob_meta
WHEN EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
 AND (
   OLD.is_complete = 1
   OR EXISTS (SELECT 1 FROM source_declaration_visibility_manifests
              WHERE blob_id = OLD.blob_id)
 )
BEGIN
  SELECT RAISE(ABORT, 'sealed source declaration visibility requirement is immutable');
END;

-- Preserve the access specifier on C++ base rows (#4343). The C++ source
-- facts version invalidates older rows that were written without this value.
ALTER TABLE source_cpp_bases ADD COLUMN access TEXT NOT NULL DEFAULT 'unknown'
  CHECK(access IN ('public', 'protected', 'private', 'unknown'));

-- Widen the C++ publication marker to the same facts-version range. Its
-- original CHECK also predates the persisted access field and would reject
-- every version-2 source publication.
PRAGMA foreign_keys = OFF;
PRAGMA legacy_alter_table = ON;
ALTER TABLE source_cpp_manifests RENAME TO source_cpp_manifests_0154_old;
CREATE TABLE source_cpp_manifests(
  blob_id INTEGER PRIMARY KEY REFERENCES blobs(id) ON DELETE CASCADE,
  facts_version INTEGER NOT NULL CHECK(facts_version IN (1, 2)),
  logical_rows INTEGER NOT NULL CHECK(logical_rows >= 1),
  payload_bytes INTEGER NOT NULL CHECK(payload_bytes >= 0)
) STRICT;
INSERT INTO source_cpp_manifests(blob_id, facts_version, logical_rows, payload_bytes)
SELECT blob_id, facts_version, logical_rows, payload_bytes
FROM source_cpp_manifests_0154_old;
DROP TABLE source_cpp_manifests_0154_old;
PRAGMA legacy_alter_table = OFF;
PRAGMA foreign_keys = ON;

-- Recreate the validation triggers removed with source_cpp_manifests.
CREATE TRIGGER source_cpp_manifests_no_delete_after_seal
BEFORE DELETE ON source_cpp_manifests
WHEN EXISTS (SELECT 1 FROM source_cpp_manifests WHERE blob_id = OLD.blob_id)
 AND EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
BEGIN SELECT RAISE(ABORT, 'sealed C++ source facts are immutable'); END;

CREATE TRIGGER source_cpp_manifests_no_insert_after_seal
BEFORE INSERT ON source_cpp_manifests
WHEN EXISTS (SELECT 1 FROM source_cpp_manifests WHERE blob_id = NEW.blob_id)
BEGIN SELECT RAISE(ABORT, 'sealed C++ source facts are immutable'); END;

CREATE TRIGGER source_cpp_manifests_no_update_after_seal
BEFORE UPDATE ON source_cpp_manifests
WHEN EXISTS (SELECT 1 FROM source_cpp_manifests WHERE blob_id IN (OLD.blob_id, NEW.blob_id))
BEGIN SELECT RAISE(ABORT, 'sealed C++ source facts are immutable'); END;

CREATE TRIGGER source_cpp_manifests_validate
BEFORE INSERT ON source_cpp_manifests
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM blob_meta AS meta
    WHERE meta.blob_id = NEW.blob_id AND meta.cpp_source_version = NEW.facts_version
  ) THEN RAISE(ABORT, 'C++ source publication requires a matching C++ blob requirement') END;
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM source_cpp_fact_costs WHERE blob_id = NEW.blob_id
      AND logical_rows = NEW.logical_rows AND payload_bytes = NEW.payload_bytes
  ) THEN RAISE(ABORT, 'C++ source publication accounting is inconsistent') END;
  SELECT CASE WHEN (
    (SELECT COUNT(*) FROM source_cpp_includes WHERE blob_id = NEW.blob_id)
      <> COALESCE((SELECT MAX(ordinal) + 1 FROM source_cpp_includes WHERE blob_id = NEW.blob_id), 0)
    OR (SELECT COUNT(*) FROM source_cpp_using_namespaces WHERE blob_id = NEW.blob_id)
      <> COALESCE((SELECT MAX(ordinal) + 1 FROM source_cpp_using_namespaces WHERE blob_id = NEW.blob_id), 0)
    OR (SELECT COUNT(*) FROM source_cpp_template_expressions WHERE blob_id = NEW.blob_id)
      <> COALESCE((SELECT MAX(expression_id) + 1 FROM source_cpp_template_expressions WHERE blob_id = NEW.blob_id), 0)
    OR (SELECT COUNT(*) FROM source_cpp_template_terms WHERE blob_id = NEW.blob_id)
      <> COALESCE((SELECT MAX(term_id) + 1 FROM source_cpp_template_terms WHERE blob_id = NEW.blob_id), 0)
    OR EXISTS (SELECT 1 FROM source_cpp_declaration_paths WHERE blob_id = NEW.blob_id
               GROUP BY declaration_id, path_kind HAVING MIN(ordinal) <> 0 OR MAX(ordinal) <> COUNT(*) - 1)
    OR EXISTS (SELECT 1 FROM source_cpp_callable_shapes WHERE blob_id = NEW.blob_id
               GROUP BY declaration_id HAVING MIN(ordinal) <> 0 OR MAX(ordinal) <> COUNT(*) - 1)
    OR EXISTS (SELECT 1 FROM source_cpp_comparable_nodes WHERE blob_id = NEW.blob_id
               GROUP BY parameter_id HAVING MIN(node_id) <> 0 OR MAX(node_id) <> COUNT(*) - 1)
    OR EXISTS (SELECT 1 FROM source_cpp_comparable_node_names WHERE blob_id = NEW.blob_id
               GROUP BY parameter_id, node_id, axis HAVING MIN(ordinal) <> 0 OR MAX(ordinal) <> COUNT(*) - 1)
    OR EXISTS (SELECT 1 FROM source_cpp_comparable_node_arguments WHERE blob_id = NEW.blob_id
               GROUP BY parameter_id, node_id HAVING MIN(ordinal) <> 0 OR MAX(ordinal) <> COUNT(*) - 1)
    OR EXISTS (SELECT 1 FROM source_cpp_alias_components WHERE blob_id = NEW.blob_id
               GROUP BY declaration_id HAVING MIN(ordinal) <> 0 OR MAX(ordinal) <> COUNT(*) - 1)
    OR EXISTS (SELECT 1 FROM source_cpp_member_usings WHERE blob_id = NEW.blob_id
               GROUP BY declaration_id HAVING MIN(ordinal) <> 0 OR MAX(ordinal) <> COUNT(*) - 1)
    OR EXISTS (SELECT 1 FROM source_cpp_member_using_scopes WHERE blob_id = NEW.blob_id
               GROUP BY declaration_id, using_ordinal HAVING MIN(ordinal) <> 0 OR MAX(ordinal) <> COUNT(*) - 1)
    OR EXISTS (SELECT 1 FROM source_cpp_bases WHERE blob_id = NEW.blob_id
               GROUP BY declaration_id HAVING MIN(ordinal) <> 0 OR MAX(ordinal) <> COUNT(*) - 1)
    OR EXISTS (SELECT 1 FROM source_cpp_base_components WHERE blob_id = NEW.blob_id
               GROUP BY declaration_id, base_ordinal HAVING MIN(ordinal) <> 0 OR MAX(ordinal) <> COUNT(*) - 1)
    OR EXISTS (SELECT 1 FROM source_cpp_template_expressions WHERE blob_id = NEW.blob_id
               GROUP BY declaration_id, owner_kind HAVING MIN(argument_ordinal) <> 0 OR MAX(argument_ordinal) <> COUNT(*) - 1)
    OR EXISTS (SELECT 1 FROM source_cpp_template_terms AS term
               WHERE term.blob_id = NEW.blob_id AND term.parent_term_id IS NOT NULL
                 AND NOT EXISTS (SELECT 1 FROM source_cpp_template_terms AS parent
                                 WHERE parent.blob_id = term.blob_id AND parent.term_id = term.parent_term_id
                                   AND parent.expression_id = term.expression_id))
    OR EXISTS (SELECT 1 FROM source_cpp_template_terms AS term
               WHERE term.blob_id = NEW.blob_id AND term.kind <> 2
                 AND EXISTS (SELECT 1 FROM source_cpp_template_terms AS child
                             WHERE child.blob_id = term.blob_id AND child.parent_term_id = term.term_id))
    OR EXISTS (SELECT 1 FROM source_cpp_template_expressions AS expression
               WHERE expression.blob_id = NEW.blob_id
                 AND (SELECT COUNT(*) FROM source_cpp_template_terms AS term
                      WHERE term.blob_id = expression.blob_id AND term.expression_id = expression.expression_id
                        AND term.parent_term_id IS NULL) <> 1)
    OR EXISTS (SELECT 1 FROM source_cpp_template_expressions AS expression
               JOIN source_cpp_declarations AS declaration
                 ON declaration.blob_id = expression.blob_id AND declaration.declaration_id = expression.declaration_id
               WHERE expression.blob_id = NEW.blob_id
                 AND ((expression.owner_kind = 0 AND declaration.field_arguments_present = 0)
                      OR (expression.owner_kind = 1 AND declaration.alias_arguments_present = 0)))
    OR EXISTS (SELECT 1 FROM source_cpp_declarations AS declaration
               WHERE declaration.blob_id = NEW.blob_id
                 AND declaration.callable_shapes_present = 0 AND EXISTS
                         (SELECT 1 FROM source_cpp_callable_shapes AS shape
                          WHERE shape.blob_id = declaration.blob_id
                            AND shape.declaration_id = declaration.declaration_id))
    OR EXISTS (SELECT 1 FROM source_cpp_callable_shapes AS shape
               WHERE shape.blob_id = NEW.blob_id
                 AND ((shape.kind = 0 AND shape.parameter_id IS NULL)
                      OR (shape.kind <> 0 AND shape.parameter_id IS NOT NULL)))
  ) THEN RAISE(ABORT, 'C++ source publication has invalid ordered syntax') END;
END;
