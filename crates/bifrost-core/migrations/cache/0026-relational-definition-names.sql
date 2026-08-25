-- Relational definition identities and one atomic workspace snapshot.
--
-- Version 25 was used by a rejected local experiment and is intentionally not
-- reused. Existing version-24 content rows cannot be decoded into segment rows
-- by SQL, so the added projections are nullable for migration compatibility.
-- The analyzer epoch changes with this migration; only republished rows with a
-- complete relational identity enter the views below.

ALTER TABLE code_units ADD COLUMN fq_anchor_kind TEXT
  CHECK(fq_anchor_kind IS NULL OR fq_anchor_kind IN ('own_module', 'crate_root'));
ALTER TABLE code_units ADD COLUMN fq_anchor_pop INTEGER
  CHECK(CASE fq_anchor_kind
    WHEN 'own_module' THEN fq_anchor_pop IS NOT NULL AND fq_anchor_pop BETWEEN 0 AND 255
    WHEN 'crate_root' THEN fq_anchor_pop = 0
    ELSE fq_anchor_kind IS NULL AND fq_anchor_pop IS NULL
  END);
ALTER TABLE code_units ADD COLUMN fq_package_tail_segments INTEGER
  CHECK(fq_package_tail_segments IS NULL OR fq_package_tail_segments >= 0);
ALTER TABLE code_units ADD COLUMN exact_fqn_tail TEXT;
ALTER TABLE code_units ADD COLUMN normalized_fqn_tail TEXT
  CHECK(normalized_fqn_tail IS NULL
        OR (exact_fqn_tail IS NOT NULL AND normalized_fqn_tail <> exact_fqn_tail));
ALTER TABLE code_units ADD COLUMN exact_parent_fqn_tail TEXT;
ALTER TABLE code_units ADD COLUMN normalized_parent_fqn_tail TEXT
  CHECK(normalized_parent_fqn_tail IS NULL
        OR (exact_parent_fqn_tail IS NOT NULL
            AND normalized_parent_fqn_tail <> exact_parent_fqn_tail));
ALTER TABLE code_units ADD COLUMN package_fqn_tail TEXT;

-- The authoritative persisted FqName. `seg_ordinal` is relative to the
-- content-derived tail: a workspace anchor supplies any omitted prefix.
CREATE TABLE code_unit_fq_segments(
  blob_oid     TEXT    NOT NULL,
  lang         TEXT    NOT NULL,
  unit_key     INTEGER NOT NULL,
  seg_ordinal  INTEGER NOT NULL CHECK(seg_ordinal >= 0),
  seg_kind     TEXT    NOT NULL CHECK(seg_kind IN (
    'path', 'package', 'type', 'companion', 'nested', 'member', 'unknown'
  )),
  segment      TEXT    NOT NULL CHECK(length(segment) > 0),
  PRIMARY KEY(blob_oid, lang, unit_key, seg_ordinal),
  FOREIGN KEY(blob_oid, lang, unit_key)
    REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- Extra containment that is semantically visible but is not the structured
-- FqName parent. It shares the unit's anchor; only the content tail differs.
CREATE TABLE unit_visibility_containers(
  blob_oid                  TEXT    NOT NULL,
  lang                      TEXT    NOT NULL,
  unit_key                  INTEGER NOT NULL,
  container_ordinal         INTEGER NOT NULL CHECK(container_ordinal >= 0),
  exact_container_tail      TEXT    NOT NULL,
  normalized_container_tail TEXT
    CHECK(normalized_container_tail IS NULL
          OR normalized_container_tail <> exact_container_tail),
  PRIMARY KEY(blob_oid, lang, unit_key, container_ordinal),
  FOREIGN KEY(blob_oid, lang, unit_key)
    REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- A snapshot is replaced as one transaction. Child tables include generation
-- in their keys so a reader can validate exactly the generation it captured.
CREATE TABLE workspace_snapshots(
  lang         TEXT    NOT NULL,
  generation   INTEGER NOT NULL CHECK(generation >= 0),
  fingerprint  TEXT    NOT NULL
    CHECK(length(fingerprint) = 64 AND fingerprint NOT GLOB '*[^0-9a-f]*'),
  PRIMARY KEY(lang, generation)
) WITHOUT ROWID, STRICT;

CREATE TABLE workspace_files(
  file_id      INTEGER PRIMARY KEY,
  lang        TEXT    NOT NULL,
  generation  INTEGER NOT NULL,
  rel_path    TEXT    NOT NULL CHECK(length(rel_path) > 0),
  blob_oid    TEXT    NOT NULL
    CHECK(length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*'),
  UNIQUE(lang, generation, rel_path),
  UNIQUE(lang, generation, file_id),
  FOREIGN KEY(lang, generation)
    REFERENCES workspace_snapshots(lang, generation) ON DELETE CASCADE
) STRICT;

CREATE TABLE workspace_packages(
  lang          TEXT    NOT NULL,
  generation    INTEGER NOT NULL,
  package_name  TEXT    NOT NULL,
  PRIMARY KEY(lang, generation, package_name),
  FOREIGN KEY(lang, generation)
    REFERENCES workspace_snapshots(lang, generation) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE workspace_package_files(
  lang          TEXT    NOT NULL,
  generation    INTEGER NOT NULL,
  package_name  TEXT    NOT NULL,
  file_id       INTEGER NOT NULL,
  PRIMARY KEY(lang, generation, package_name, file_id),
  FOREIGN KEY(lang, generation, package_name)
    REFERENCES workspace_packages(lang, generation, package_name) ON DELETE CASCADE,
  FOREIGN KEY(lang, generation, file_id)
    REFERENCES workspace_files(lang, generation, file_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE workspace_package_edges(
  lang                 TEXT    NOT NULL,
  generation           INTEGER NOT NULL,
  parent_package_name  TEXT    NOT NULL,
  child_package_name   TEXT    NOT NULL,
  PRIMARY KEY(lang, generation, parent_package_name, child_package_name),
  CHECK(parent_package_name <> child_package_name),
  FOREIGN KEY(lang, generation, parent_package_name)
    REFERENCES workspace_packages(lang, generation, package_name) ON DELETE CASCADE,
  FOREIGN KEY(lang, generation, child_package_name)
    REFERENCES workspace_packages(lang, generation, package_name) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE workspace_file_anchors(
  lang          TEXT    NOT NULL,
  generation    INTEGER NOT NULL,
  file_id       INTEGER NOT NULL,
  anchor_kind   TEXT    NOT NULL CHECK(anchor_kind IN ('own_module', 'crate_root')),
  anchor_pop    INTEGER NOT NULL CHECK(anchor_pop BETWEEN 0 AND 255),
  package_name  TEXT    NOT NULL,
  PRIMARY KEY(lang, generation, file_id, anchor_kind, anchor_pop),
  CHECK(anchor_kind <> 'crate_root' OR anchor_pop = 0),
  FOREIGN KEY(lang, generation, file_id)
    REFERENCES workspace_files(lang, generation, file_id) ON DELETE CASCADE,
  FOREIGN KEY(lang, generation, package_name)
    REFERENCES workspace_packages(lang, generation, package_name) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- Changed normalized tails and structured owner/name lookups use separate
-- stable and anchored partial indexes, avoiding broad OR predicates.
CREATE INDEX idx_code_units_stable_normalized_tail
  ON code_units(lang, normalized_fqn_tail)
  WHERE fq_anchor_kind IS NULL
    AND normalized_fqn_tail IS NOT NULL
    AND (in_declarations = 1 OR in_definition_lookup = 1);
CREATE INDEX idx_code_units_anchored_normalized_tail
  ON code_units(lang, fq_anchor_kind, fq_anchor_pop, normalized_fqn_tail)
  WHERE fq_anchor_kind IS NOT NULL
    AND normalized_fqn_tail IS NOT NULL
    AND (in_declarations = 1 OR in_definition_lookup = 1);
CREATE INDEX idx_code_units_stable_parent_identifier
  ON code_units(lang, exact_parent_fqn_tail, identifier)
  WHERE fq_anchor_kind IS NULL
    AND exact_parent_fqn_tail IS NOT NULL
    AND (in_declarations = 1 OR in_definition_lookup = 1);
CREATE INDEX idx_code_units_anchored_parent_identifier
  ON code_units(lang, fq_anchor_kind, fq_anchor_pop, exact_parent_fqn_tail, identifier)
  WHERE fq_anchor_kind IS NOT NULL
    AND exact_parent_fqn_tail IS NOT NULL
    AND (in_declarations = 1 OR in_definition_lookup = 1);
CREATE INDEX idx_code_units_stable_package_type
  ON code_units(lang, package_fqn_tail, simple_type_name)
  WHERE fq_anchor_kind IS NULL AND in_declarations = 1 AND kind = 0;
CREATE INDEX idx_code_units_anchored_package_type
  ON code_units(lang, fq_anchor_kind, fq_anchor_pop, package_fqn_tail, simple_type_name)
  WHERE fq_anchor_kind IS NOT NULL AND in_declarations = 1 AND kind = 0;
CREATE INDEX idx_workspace_files_blob
  ON workspace_files(lang, generation, blob_oid, file_id);
CREATE INDEX idx_workspace_package_files_file
  ON workspace_package_files(lang, generation, file_id, package_name);
CREATE INDEX idx_workspace_package_edges_child
  ON workspace_package_edges(lang, generation, child_package_name, parent_package_name);
CREATE INDEX idx_workspace_file_anchors_lookup
  ON workspace_file_anchors(
    lang, generation, anchor_kind, anchor_pop, package_name, file_id
  );

-- The live workspace join discovers generation after constraining the name.
-- Put the selective name before generation so a cold connection does not scan
-- every path symbol for the language while establishing that join.
DROP INDEX idx_path_symbol_units_lang_generation_exact_fqn;
CREATE INDEX idx_path_symbol_units_lang_generation_exact_fqn
  ON path_symbol_units(lang, exact_fqn, generation);
DROP INDEX idx_path_symbol_units_lang_generation_normalized_fqn;
CREATE INDEX idx_path_symbol_units_lang_generation_normalized_fqn
  ON path_symbol_units(lang, normalized_fqn, generation);

DROP TABLE path_symbol_snapshots;

CREATE VIEW live_workspace_files AS
SELECT files.file_id, files.lang, files.generation, files.rel_path, files.blob_oid
FROM workspace_files AS files
JOIN workspace_snapshots AS snapshots
  ON snapshots.lang = files.lang
 AND snapshots.generation = files.generation
LEFT JOIN analysis_epochs AS epochs
  ON epochs.lang = files.lang
JOIN live_parsed_blobs AS live
  ON live.lang = files.lang
 AND live.blob_oid = files.blob_oid
WHERE files.generation = COALESCE(epochs.generation, 0);

CREATE VIEW live_workspace_packages AS
SELECT packages.lang, packages.generation, packages.package_name
FROM workspace_packages AS packages
JOIN workspace_snapshots AS snapshots
  ON snapshots.lang = packages.lang
 AND snapshots.generation = packages.generation
LEFT JOIN analysis_epochs AS epochs
  ON epochs.lang = packages.lang
WHERE packages.generation = COALESCE(epochs.generation, 0);

CREATE VIEW live_workspace_package_files AS
SELECT members.lang, members.generation, members.package_name,
       files.rel_path, files.blob_oid
FROM workspace_package_files AS members
JOIN live_workspace_packages AS packages
  ON packages.lang = members.lang
 AND packages.generation = members.generation
 AND packages.package_name = members.package_name
JOIN live_workspace_files AS files
  ON files.lang = members.lang
 AND files.generation = members.generation
 AND files.file_id = members.file_id;

CREATE VIEW live_workspace_package_edges AS
SELECT edges.lang, edges.generation,
       edges.parent_package_name, edges.child_package_name
FROM workspace_package_edges AS edges
JOIN live_workspace_packages AS parents
  ON parents.lang = edges.lang
 AND parents.generation = edges.generation
 AND parents.package_name = edges.parent_package_name
JOIN live_workspace_packages AS children
  ON children.lang = edges.lang
 AND children.generation = edges.generation
 AND children.package_name = edges.child_package_name;

CREATE VIEW live_workspace_package_descendants AS
WITH RECURSIVE descendants(
  lang, generation, ancestor_package_name, descendant_package_name
) AS (
  SELECT lang, generation, parent_package_name, child_package_name
  FROM live_workspace_package_edges
  UNION
  SELECT descendants.lang,
         descendants.generation,
         descendants.ancestor_package_name,
         edges.child_package_name
  FROM descendants
  JOIN live_workspace_package_edges AS edges
    ON edges.lang = descendants.lang
   AND edges.generation = descendants.generation
   AND edges.parent_package_name = descendants.descendant_package_name
)
SELECT lang, generation, ancestor_package_name, descendant_package_name
FROM descendants;

CREATE VIEW workspace_path_symbols AS
SELECT symbols.lang, symbols.generation, symbols.rel_path, symbols.blob_oid,
       symbols.kind, symbols.package_name, symbols.short_name,
       symbols.exact_fqn, symbols.normalized_fqn
FROM path_symbol_units AS symbols
JOIN live_workspace_files AS files
  ON files.lang = symbols.lang
 AND files.generation = symbols.generation
 AND files.rel_path = symbols.rel_path
 AND files.blob_oid = symbols.blob_oid
WHERE symbols.lang NOT IN ('javascript', 'typescript:ts', 'typescript:tsx')
UNION ALL
SELECT symbols.lang, symbols.generation, symbols.rel_path, symbols.blob_oid,
       symbols.kind, symbols.package_name, symbols.short_name,
       symbols.exact_fqn, symbols.normalized_fqn
FROM path_symbol_units AS symbols
JOIN live_workspace_files AS files
  ON files.lang = symbols.lang
 AND files.generation = symbols.generation
 AND files.rel_path = symbols.rel_path
 AND files.blob_oid = symbols.blob_oid
WHERE symbols.lang IN ('javascript', 'typescript:ts', 'typescript:tsx')
  AND EXISTS(
     SELECT 1 FROM import_statements AS imports
     WHERE imports.blob_oid = symbols.blob_oid
       AND imports.lang = symbols.lang
  );

-- Point-name variants pin the corresponding name-first index. The generic
-- workspace view above remains available for enumeration; forcing one name
-- index there would make the other query shape and enumeration worse.
CREATE VIEW workspace_path_symbol_exact_names AS
SELECT symbols.lang, symbols.generation, symbols.rel_path, symbols.blob_oid,
       symbols.kind, symbols.package_name, symbols.short_name,
       symbols.exact_fqn, symbols.normalized_fqn
FROM path_symbol_units AS symbols
     INDEXED BY idx_path_symbol_units_lang_generation_exact_fqn
JOIN live_workspace_files AS files
  ON files.lang = symbols.lang
 AND files.generation = symbols.generation
 AND files.rel_path = symbols.rel_path
 AND files.blob_oid = symbols.blob_oid
WHERE symbols.lang NOT IN ('javascript', 'typescript:ts', 'typescript:tsx')
UNION ALL
SELECT symbols.lang, symbols.generation, symbols.rel_path, symbols.blob_oid,
       symbols.kind, symbols.package_name, symbols.short_name,
       symbols.exact_fqn, symbols.normalized_fqn
FROM path_symbol_units AS symbols
     INDEXED BY idx_path_symbol_units_lang_generation_exact_fqn
JOIN live_workspace_files AS files
  ON files.lang = symbols.lang
 AND files.generation = symbols.generation
 AND files.rel_path = symbols.rel_path
 AND files.blob_oid = symbols.blob_oid
WHERE symbols.lang IN ('javascript', 'typescript:ts', 'typescript:tsx')
  AND EXISTS(
     SELECT 1 FROM import_statements AS imports
     WHERE imports.blob_oid = symbols.blob_oid
       AND imports.lang = symbols.lang
  );

CREATE VIEW workspace_path_symbol_normalized_names AS
SELECT symbols.lang, symbols.generation, symbols.rel_path, symbols.blob_oid,
       symbols.kind, symbols.package_name, symbols.short_name,
       symbols.exact_fqn, symbols.normalized_fqn
FROM path_symbol_units AS symbols
     INDEXED BY idx_path_symbol_units_lang_generation_normalized_fqn
JOIN live_workspace_files AS files
  ON files.lang = symbols.lang
 AND files.generation = symbols.generation
 AND files.rel_path = symbols.rel_path
 AND files.blob_oid = symbols.blob_oid
WHERE symbols.lang NOT IN ('javascript', 'typescript:ts', 'typescript:tsx')
UNION ALL
SELECT symbols.lang, symbols.generation, symbols.rel_path, symbols.blob_oid,
       symbols.kind, symbols.package_name, symbols.short_name,
       symbols.exact_fqn, symbols.normalized_fqn
FROM path_symbol_units AS symbols
     INDEXED BY idx_path_symbol_units_lang_generation_normalized_fqn
JOIN live_workspace_files AS files
  ON files.lang = symbols.lang
 AND files.generation = symbols.generation
 AND files.rel_path = symbols.rel_path
 AND files.blob_oid = symbols.blob_oid
WHERE symbols.lang IN ('javascript', 'typescript:ts', 'typescript:tsx')
  AND EXISTS(
     SELECT 1 FROM import_statements AS imports
     WHERE imports.blob_oid = symbols.blob_oid
       AND imports.lang = symbols.lang
  );

-- A row is a mounted definition identity. `prefix` is empty for a stable
-- content name and contains the resolved workspace anchor otherwise. `tail`
-- is always content-derived.
CREATE VIEW live_definition_exact_names AS
SELECT units.lang, files.generation, files.rel_path, units.blob_oid,
       units.unit_key, units.kind, units.short_name, units.identifier,
       'content' AS source_kind, '' AS prefix, units.exact_fqn_tail AS tail,
       units.normalized_fqn_tail AS normalized_tail,
       units.exact_parent_fqn_tail AS exact_parent_tail,
       units.normalized_parent_fqn_tail AS normalized_parent_tail,
       units.package_fqn_tail AS package_tail,
       units.simple_type_name, units.signature
FROM live_definition_units AS units
JOIN live_workspace_files AS files
  ON files.lang = units.lang AND files.blob_oid = units.blob_oid
WHERE units.fq_anchor_kind IS NULL AND units.exact_fqn_tail IS NOT NULL
UNION ALL
SELECT units.lang, files.generation, files.rel_path, units.blob_oid,
       units.unit_key, units.kind, units.short_name, units.identifier,
       'anchored' AS source_kind, anchors.package_name AS prefix,
       units.exact_fqn_tail AS tail,
       units.normalized_fqn_tail AS normalized_tail,
       units.exact_parent_fqn_tail AS exact_parent_tail,
       units.normalized_parent_fqn_tail AS normalized_parent_tail,
       units.package_fqn_tail AS package_tail,
       units.simple_type_name, units.signature
FROM live_definition_units AS units
JOIN live_workspace_files AS files
  ON files.lang = units.lang AND files.blob_oid = units.blob_oid
JOIN workspace_file_anchors AS anchors
  ON anchors.lang = files.lang
 AND anchors.generation = files.generation
 AND anchors.file_id = files.file_id
 AND anchors.anchor_kind = units.fq_anchor_kind
 AND anchors.anchor_pop = units.fq_anchor_pop
WHERE units.fq_anchor_kind IS NOT NULL AND units.exact_fqn_tail IS NOT NULL
UNION ALL
SELECT symbols.lang, symbols.generation, symbols.rel_path, symbols.blob_oid,
       NULL AS unit_key, symbols.kind, symbols.short_name, symbols.short_name,
       'path' AS source_kind, '' AS prefix, symbols.exact_fqn AS tail,
       CASE WHEN symbols.normalized_fqn <> symbols.exact_fqn
            THEN symbols.normalized_fqn END AS normalized_tail,
       symbols.package_name AS exact_parent_tail,
       NULL AS normalized_parent_tail, symbols.package_name AS package_tail,
       symbols.short_name AS simple_type_name, NULL AS signature
FROM workspace_path_symbol_exact_names AS symbols;

CREATE VIEW live_definition_normalized_names AS
SELECT lang, generation, rel_path, blob_oid, unit_key, kind, short_name,
       identifier, source_kind, prefix, normalized_tail AS tail,
       exact_parent_tail, normalized_parent_tail, package_tail,
       simple_type_name, signature
FROM live_definition_exact_names
WHERE source_kind <> 'path' AND normalized_tail IS NOT NULL
UNION ALL
SELECT lang, generation, rel_path, blob_oid, unit_key, kind, short_name,
       identifier, source_kind, prefix, tail,
       exact_parent_tail, normalized_parent_tail, package_tail,
       simple_type_name, signature
FROM live_definition_exact_names
WHERE source_kind <> 'path' AND normalized_tail IS NULL
UNION ALL
SELECT symbols.lang, symbols.generation, symbols.rel_path, symbols.blob_oid,
       NULL AS unit_key, symbols.kind, symbols.short_name, symbols.short_name,
       'path' AS source_kind, '' AS prefix, symbols.normalized_fqn AS tail,
       symbols.package_name AS exact_parent_tail,
       NULL AS normalized_parent_tail, symbols.package_name AS package_tail,
       symbols.short_name AS simple_type_name, NULL AS signature
FROM workspace_path_symbol_normalized_names AS symbols;

CREATE VIEW live_structural_members AS
SELECT *
FROM live_definition_exact_names
WHERE exact_parent_tail IS NOT NULL;

CREATE VIEW live_visible_members AS
SELECT members.*
FROM live_structural_members AS members
UNION ALL
SELECT names.lang, names.generation, names.rel_path, names.blob_oid,
       names.unit_key, names.kind, names.short_name, names.identifier,
       names.source_kind, names.prefix, names.tail, names.normalized_tail,
       containers.exact_container_tail AS exact_parent_tail,
       containers.normalized_container_tail AS normalized_parent_tail,
       names.package_tail, names.simple_type_name, names.signature
FROM live_definition_exact_names AS names
JOIN unit_visibility_containers AS containers
  ON containers.blob_oid = names.blob_oid
 AND containers.lang = names.lang
 AND containers.unit_key = names.unit_key;

CREATE VIEW live_definition_identifiers AS
SELECT lang, generation, rel_path, blob_oid, unit_key, kind, identifier,
       source_kind, prefix, tail, normalized_tail
FROM live_definition_exact_names;

CREATE VIEW live_package_types AS
SELECT units.lang, files.generation, files.rel_path, units.blob_oid,
       units.unit_key, units.identifier, 'content' AS source_kind,
       '' AS prefix, units.package_fqn_tail AS package_tail,
       units.simple_type_name, units.exact_fqn_tail AS tail,
       units.normalized_fqn_tail AS normalized_tail
FROM code_units AS units INDEXED BY idx_code_units_stable_package_type
JOIN live_workspace_files AS files
  ON files.lang = units.lang AND files.blob_oid = units.blob_oid
WHERE units.fq_anchor_kind IS NULL
  AND units.exact_fqn_tail IS NOT NULL
  AND units.in_declarations = 1 AND units.kind = 0
  AND units.simple_type_name IS NOT NULL
UNION ALL
SELECT units.lang, files.generation, files.rel_path, units.blob_oid,
       units.unit_key, units.identifier, 'anchored' AS source_kind,
       anchors.package_name AS prefix,
       units.package_fqn_tail AS package_tail, units.simple_type_name,
       units.exact_fqn_tail AS tail, units.normalized_fqn_tail AS normalized_tail
FROM code_units AS units INDEXED BY idx_code_units_anchored_package_type
JOIN live_workspace_files AS files
  ON files.lang = units.lang AND files.blob_oid = units.blob_oid
JOIN workspace_file_anchors AS anchors
  ON anchors.lang = files.lang
 AND anchors.generation = files.generation
 AND anchors.file_id = files.file_id
 AND anchors.anchor_kind = units.fq_anchor_kind
 AND anchors.anchor_pop = units.fq_anchor_pop
WHERE units.fq_anchor_kind IS NOT NULL
  AND units.exact_fqn_tail IS NOT NULL
  AND units.in_declarations = 1 AND units.kind = 0
  AND units.simple_type_name IS NOT NULL
UNION ALL
SELECT symbols.lang, symbols.generation, symbols.rel_path, symbols.blob_oid,
       NULL AS unit_key, symbols.short_name AS identifier,
       'path' AS source_kind, '' AS prefix,
       symbols.package_name AS package_tail,
       symbols.short_name AS simple_type_name,
       symbols.exact_fqn AS tail,
       CASE WHEN symbols.normalized_fqn <> symbols.exact_fqn
            THEN symbols.normalized_fqn END AS normalized_tail
FROM workspace_path_symbol_exact_names AS symbols
WHERE symbols.kind = 0;

CREATE VIEW live_callable_facts AS
SELECT names.lang, names.generation, names.rel_path, names.blob_oid,
       names.unit_key, names.prefix, names.tail, names.normalized_tail,
       names.identifier, names.exact_parent_tail,
       signatures.ordinal, signatures.text,
       metadata.label, metadata.parameters,
       metadata.return_type_text, metadata.return_type_identity,
       metadata.underlying_type_identity, metadata.declaration_only,
       metadata.callable_arity_required, metadata.callable_arity_total,
       metadata.callable_arity_repeated, metadata.type_parameters,
       metadata.bare_return_type_parameter, metadata.callable_linkage,
       metadata.dispatch_extensibility, metadata.extension_receiver_type,
       metadata.extension_receiver_type_identity,
       metadata.extension_receiver_is_unconstrained,
       metadata.field_is_static, metadata.field_is_final,
       metadata.field_has_initializer, metadata.cpp_field_linkage,
       metadata.companion_object, metadata.callable_is_static,
       metadata.callable_is_constructor, metadata.callable_declared_visibility,
       metadata.callable_modifiers_recorded,
       metadata.callable_parameter_types, metadata.callable_is_native,
       metadata.class_like_is_interface, metadata.class_like_is_static
FROM live_definition_exact_names AS names
JOIN unit_signatures AS signatures
  ON signatures.blob_oid = names.blob_oid
 AND signatures.lang = names.lang
 AND signatures.unit_key = names.unit_key
LEFT JOIN unit_signature_metadata AS metadata
  ON metadata.blob_oid = signatures.blob_oid
 AND metadata.lang = signatures.lang
 AND metadata.unit_key = signatures.unit_key
 AND metadata.ordinal = signatures.ordinal;
