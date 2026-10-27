-- C++ namespace aliases (`namespace name = target;`) become typed source facts
-- of the file that writes them (#6902 item 12). The shared namespace-binding
-- resolver reads every alias of a visible file whole, so the reader's question
-- is "which aliases does this blob define"; the blob and the alias ordinal key
-- both tables. A row keeps the definition's occurrence (source order), its name,
-- the structured target path, the enclosing named namespaces, the enclosing
-- block of a block-scope alias, and the guards the definition stands under.
--
-- `guards` is a positional JSON array `[roots, nodes]`, one value per row that
-- the resolver decodes whole: `roots` lists node indexes, and each node is
-- `[kind, payload]` with the `source_cpp_guard_nodes.kind` codes; the payload is
-- the guard text, the constant, or the child node indexes. NULL means the guard
-- environment could not be represented, which the resolver keeps unresolved.
-- `target_present = 0` records an alias whose target has no structured path.
CREATE TABLE source_cpp_namespace_aliases(
  blob_id INTEGER NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  occurrence_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  target_present INTEGER NOT NULL CHECK(target_present IN (0, 1)),
  target_global INTEGER NOT NULL CHECK(target_global IN (0, 1)),
  block_occurrence_id INTEGER,
  guards TEXT CHECK(guards IS NULL OR (json_valid(guards) AND json_type(guards) = 'array')),
  PRIMARY KEY(blob_id, ordinal),
  FOREIGN KEY(blob_id) REFERENCES blobs(id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

-- path_kind 0 is the target path, 1 the enclosing namespaces; outermost first.
CREATE TABLE source_cpp_namespace_alias_paths(
  blob_id INTEGER NOT NULL,
  alias_ordinal INTEGER NOT NULL,
  path_kind INTEGER NOT NULL CHECK(path_kind IN (0, 1)),
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  component TEXT NOT NULL,
  PRIMARY KEY(blob_id, alias_ordinal, path_kind, ordinal),
  FOREIGN KEY(blob_id, alias_ordinal)
    REFERENCES source_cpp_namespace_aliases(blob_id, ordinal) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TRIGGER source_cpp_namespace_aliases_no_delete_after_seal
BEFORE DELETE ON source_cpp_namespace_aliases
WHEN EXISTS (SELECT 1 FROM source_cpp_manifests WHERE blob_id = OLD.blob_id)
 AND EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
BEGIN SELECT RAISE(ABORT, 'sealed C++ source facts are immutable'); END;

CREATE TRIGGER source_cpp_namespace_aliases_no_insert_after_seal
BEFORE INSERT ON source_cpp_namespace_aliases
WHEN EXISTS (SELECT 1 FROM source_cpp_manifests WHERE blob_id = NEW.blob_id)
BEGIN SELECT RAISE(ABORT, 'sealed C++ source facts are immutable'); END;

CREATE TRIGGER source_cpp_namespace_aliases_no_update_after_seal
BEFORE UPDATE ON source_cpp_namespace_aliases
WHEN EXISTS (SELECT 1 FROM source_cpp_manifests WHERE blob_id IN (OLD.blob_id, NEW.blob_id))
BEGIN SELECT RAISE(ABORT, 'sealed C++ source facts are immutable'); END;

CREATE TRIGGER source_cpp_namespace_alias_paths_no_delete_after_seal
BEFORE DELETE ON source_cpp_namespace_alias_paths
WHEN EXISTS (SELECT 1 FROM source_cpp_manifests WHERE blob_id = OLD.blob_id)
 AND EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
BEGIN SELECT RAISE(ABORT, 'sealed C++ source facts are immutable'); END;

CREATE TRIGGER source_cpp_namespace_alias_paths_no_insert_after_seal
BEFORE INSERT ON source_cpp_namespace_alias_paths
WHEN EXISTS (SELECT 1 FROM source_cpp_manifests WHERE blob_id = NEW.blob_id)
BEGIN SELECT RAISE(ABORT, 'sealed C++ source facts are immutable'); END;

CREATE TRIGGER source_cpp_namespace_alias_paths_no_update_after_seal
BEFORE UPDATE ON source_cpp_namespace_alias_paths
WHEN EXISTS (SELECT 1 FROM source_cpp_manifests WHERE blob_id IN (OLD.blob_id, NEW.blob_id))
BEGIN SELECT RAISE(ABORT, 'sealed C++ source facts are immutable'); END;

DROP VIEW source_cpp_fact_costs;
CREATE VIEW source_cpp_fact_costs AS
SELECT blob.id AS blob_id,
       1
       + (SELECT COUNT(*) FROM source_cpp_declaration_contexts WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_flattened_namespaces WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_guard_sets WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_guard_nodes WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_guard_edges WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_guard_roots WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_includes WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_using_namespaces WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_namespace_aliases WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_namespace_alias_paths WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_declarations WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_callable_shapes WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_comparable_parameters WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_comparable_nodes WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_comparable_node_names WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_comparable_node_arguments WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_declaration_paths WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_alias_components WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_member_usings WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_member_using_scopes WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_bases WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_base_components WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_template_expressions WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_cpp_template_terms WHERE blob_id = blob.id) AS logical_rows,
       COALESCE((SELECT SUM(length(CAST(path AS BLOB))) FROM source_cpp_includes WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(namespace AS BLOB))) FROM source_cpp_using_namespaces WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(name AS BLOB)) + COALESCE(length(CAST(guards AS BLOB)), 0))
                   FROM source_cpp_namespace_aliases WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(component AS BLOB))) FROM source_cpp_namespace_alias_paths WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(COALESCE(length(CAST(field_type_text AS BLOB)), 0)
                          + COALESCE(length(CAST(alias_target_text AS BLOB)), 0)
                          + length(CAST(trailing_qualifiers AS BLOB))
                          + COALESCE(length(CAST(callable_identity_suffix AS BLOB)), 0))
                   FROM source_cpp_declarations WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(component AS BLOB))) FROM source_cpp_declaration_paths WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(component AS BLOB))) FROM source_cpp_alias_components WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(member AS BLOB))) FROM source_cpp_member_usings WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(component AS BLOB))) FROM source_cpp_member_using_scopes WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(component AS BLOB))) FROM source_cpp_base_components WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(name AS BLOB))) FROM source_cpp_comparable_node_names WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(text AS BLOB))) FROM source_cpp_template_expressions WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(COALESCE(length(CAST(text AS BLOB)), 0)
                          + COALESCE(length(CAST(atom_kind AS BLOB)), 0))
                   FROM source_cpp_template_terms WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(COALESCE(length(CAST(file_alias_name AS BLOB)), 0)
           + COALESCE(length(CAST(file_alias_target AS BLOB)), 0)
           + COALESCE(length(CAST(file_alias_namespace AS BLOB)), 0))
           FROM source_cpp_declaration_contexts WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(component AS BLOB))) FROM source_cpp_flattened_namespaces WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(text AS BLOB))) FROM source_cpp_guard_nodes WHERE blob_id = blob.id), 0) AS payload_bytes
FROM blobs AS blob;

DROP TRIGGER source_cpp_manifests_validate;
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
    OR (SELECT COUNT(*) FROM source_cpp_namespace_aliases WHERE blob_id = NEW.blob_id)
      <> COALESCE((SELECT MAX(ordinal) + 1 FROM source_cpp_namespace_aliases WHERE blob_id = NEW.blob_id), 0)
    OR EXISTS (SELECT 1 FROM source_cpp_namespace_alias_paths WHERE blob_id = NEW.blob_id
               GROUP BY alias_ordinal, path_kind HAVING MIN(ordinal) <> 0 OR MAX(ordinal) <> COUNT(*) - 1)
    OR EXISTS (SELECT 1 FROM source_cpp_namespace_aliases AS alias
               WHERE alias.blob_id = NEW.blob_id
                 AND alias.target_present <> EXISTS
                         (SELECT 1 FROM source_cpp_namespace_alias_paths AS path
                          WHERE path.blob_id = alias.blob_id AND path.alias_ordinal = alias.ordinal
                            AND path.path_kind = 0))
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
