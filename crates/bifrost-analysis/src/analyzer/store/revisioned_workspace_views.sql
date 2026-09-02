-- The workspace projections, as TEMP views over the content-addressed tables.
--
-- Fact rows are keyed by an interned integer `blob_id` that only `blobs` can
-- mint (`.agents/plans/store-blob-id-interning.md`). `workspace_file_versions`
-- still stores the forty-character blob OID, because its rows outlive any one
-- publication and a republished blob gets a new id. `live_workspace_files`
-- therefore carries BOTH: the hex it read from the projection and the id its
-- `live_parsed_blobs` join already resolved. Every view below that reaches a
-- fact table joins on the id, and every view that seeks a workspace row joins
-- on the hex, so no view here pays for a join it did not pay for before.
CREATE TEMP TABLE IF NOT EXISTS selected_workspace_revisions(
  workspace_id TEXT NOT NULL,
  lang TEXT NOT NULL PRIMARY KEY,
  generation INTEGER NOT NULL,
  revision INTEGER NOT NULL
) WITHOUT ROWID, STRICT;

CREATE TEMP VIEW IF NOT EXISTS workspace_snapshots AS
SELECT lang, generation, printf('%s:%d', workspace_id, revision) AS fingerprint
FROM selected_workspace_revisions;

CREATE TEMP VIEW IF NOT EXISTS workspace_files AS
SELECT versions.file_version_id AS file_id, versions.lang, versions.generation,
       versions.rel_path, versions.blob_oid
FROM main.workspace_file_versions AS versions
JOIN selected_workspace_revisions AS selected
  ON selected.workspace_id = versions.workspace_id
 AND selected.lang = versions.lang
 AND selected.generation = versions.generation
WHERE versions.valid_from <= selected.revision
  AND (versions.valid_until IS NULL OR selected.revision < versions.valid_until);

CREATE TEMP VIEW IF NOT EXISTS workspace_package_files AS
SELECT files.lang, files.generation, rows.package_name,
       files.file_id
FROM main.workspace_file_package_rows AS rows
     INDEXED BY idx_workspace_file_package_rows_name
JOIN workspace_files AS files ON files.file_id = rows.file_version_id;

CREATE TEMP VIEW IF NOT EXISTS workspace_package_edges AS
SELECT DISTINCT files.lang, files.generation,
       rows.parent_package_name, rows.child_package_name
FROM main.workspace_file_package_edge_rows AS rows
JOIN workspace_files AS files ON files.file_id = rows.file_version_id;

CREATE TEMP VIEW IF NOT EXISTS workspace_packages AS
SELECT lang, generation, package_name FROM workspace_package_files
UNION
SELECT lang, generation, parent_package_name FROM workspace_package_edges
UNION
SELECT lang, generation, child_package_name FROM workspace_package_edges;

CREATE TEMP VIEW IF NOT EXISTS workspace_file_anchors AS
SELECT files.lang, files.generation, files.file_id,
       rows.anchor_kind, rows.anchor_pop, rows.package_name
FROM main.workspace_file_anchor_rows AS rows
     INDEXED BY idx_workspace_file_anchor_rows_package
JOIN workspace_files AS files ON files.file_id = rows.file_version_id;

CREATE TEMP VIEW IF NOT EXISTS path_symbol_units AS
SELECT files.lang, files.rel_path, files.blob_oid, files.file_id,
       rows.kind, rows.package_name, rows.short_name,
       rows.exact_fqn, rows.normalized_fqn, files.generation
FROM main.workspace_file_path_symbol_rows AS rows
JOIN workspace_files AS files ON files.file_id = rows.file_version_id;

CREATE TEMP VIEW IF NOT EXISTS live_workspace_files AS
SELECT files.file_id, files.lang, files.generation, files.rel_path,
       files.blob_oid, live.blob_id
FROM workspace_files AS files
LEFT JOIN main.analysis_epochs AS epochs ON epochs.lang = files.lang
JOIN main.live_parsed_blobs AS live
  ON live.lang = files.lang AND live.blob_oid = files.blob_oid
WHERE files.generation = COALESCE(epochs.generation, 0);

CREATE TEMP VIEW IF NOT EXISTS live_workspace_packages AS
SELECT packages.lang, packages.generation, packages.package_name
FROM workspace_packages AS packages
LEFT JOIN main.analysis_epochs AS epochs ON epochs.lang = packages.lang
WHERE packages.generation = COALESCE(epochs.generation, 0);

CREATE TEMP VIEW IF NOT EXISTS live_workspace_package_files AS
SELECT members.lang, members.generation, members.package_name,
       files.rel_path, files.blob_oid
FROM workspace_package_files AS members
JOIN live_workspace_files AS files
  ON files.lang = members.lang
 AND files.generation = members.generation
 AND files.file_id = members.file_id;

CREATE TEMP VIEW IF NOT EXISTS live_workspace_package_edges AS
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

CREATE TEMP VIEW IF NOT EXISTS live_workspace_package_descendants AS
WITH RECURSIVE descendants(
  lang, generation, ancestor_package_name, descendant_package_name
) AS (
  SELECT lang, generation, parent_package_name, child_package_name
  FROM live_workspace_package_edges
  UNION
  SELECT descendants.lang, descendants.generation,
         descendants.ancestor_package_name, edges.child_package_name
  FROM descendants
  JOIN live_workspace_package_edges AS edges
    ON edges.lang = descendants.lang
   AND edges.generation = descendants.generation
   AND edges.parent_package_name = descendants.descendant_package_name
)
SELECT lang, generation, ancestor_package_name, descendant_package_name
FROM descendants;

CREATE TEMP VIEW IF NOT EXISTS workspace_path_symbols AS
SELECT symbols.lang, symbols.generation, symbols.rel_path, symbols.blob_oid,
       files.blob_id,
       symbols.kind, symbols.package_name, symbols.short_name,
       symbols.exact_fqn, symbols.normalized_fqn
FROM path_symbol_units AS symbols
JOIN live_workspace_files AS files
  ON files.lang = symbols.lang
 AND files.generation = symbols.generation
 AND files.rel_path = symbols.rel_path
 AND files.blob_oid = symbols.blob_oid
WHERE symbols.lang NOT IN ('javascript', 'typescript:ts', 'typescript:tsx')
   OR EXISTS(
     SELECT 1 FROM main.import_statements AS imports
     WHERE imports.blob_id = files.blob_id
   );

CREATE TEMP VIEW IF NOT EXISTS workspace_path_symbol_exact_names AS
SELECT * FROM workspace_path_symbols;

CREATE TEMP VIEW IF NOT EXISTS workspace_path_symbol_normalized_names AS
SELECT * FROM workspace_path_symbols;

CREATE TEMP VIEW IF NOT EXISTS live_definition_exact_names AS
SELECT units.lang, files.generation, files.rel_path, files.blob_oid,
       units.blob_id,
       units.unit_key, units.kind, units.short_name, units.identifier,
       'content' AS source_kind, '' AS prefix, units.exact_fqn_tail AS tail,
       units.normalized_fqn_tail AS normalized_tail,
       units.exact_parent_fqn_tail AS exact_parent_tail,
       units.normalized_parent_fqn_tail AS normalized_parent_tail,
       units.package_fqn_tail AS package_tail,
       units.simple_type_name, units.signature
FROM main.live_definition_units AS units
JOIN live_workspace_files AS files
  ON files.blob_id = units.blob_id
WHERE units.fq_anchor_kind IS NULL AND units.exact_fqn_tail IS NOT NULL
UNION ALL
SELECT units.lang, files.generation, files.rel_path, files.blob_oid,
       units.blob_id,
       units.unit_key, units.kind, units.short_name, units.identifier,
       'anchored' AS source_kind, anchors.package_name AS prefix,
       units.exact_fqn_tail AS tail, units.normalized_fqn_tail AS normalized_tail,
       units.exact_parent_fqn_tail AS exact_parent_tail,
       units.normalized_parent_fqn_tail AS normalized_parent_tail,
       units.package_fqn_tail AS package_tail,
       units.simple_type_name, units.signature
FROM main.live_definition_units AS units
JOIN live_workspace_files AS files
  ON files.blob_id = units.blob_id
JOIN workspace_file_anchors AS anchors
  ON anchors.lang = files.lang
 AND anchors.generation = files.generation
 AND anchors.file_id = files.file_id
 AND anchors.anchor_kind = units.fq_anchor_kind
 AND anchors.anchor_pop = units.fq_anchor_pop
WHERE units.fq_anchor_kind IS NOT NULL AND units.exact_fqn_tail IS NOT NULL
UNION ALL
SELECT symbols.lang, symbols.generation, symbols.rel_path, symbols.blob_oid,
       symbols.blob_id,
       NULL AS unit_key, symbols.kind, symbols.short_name, symbols.short_name,
       'path' AS source_kind, '' AS prefix, symbols.exact_fqn AS tail,
       CASE WHEN symbols.normalized_fqn <> symbols.exact_fqn
            THEN symbols.normalized_fqn END AS normalized_tail,
       symbols.package_name AS exact_parent_tail,
       NULL AS normalized_parent_tail, symbols.package_name AS package_tail,
       symbols.short_name AS simple_type_name, NULL AS signature
FROM workspace_path_symbol_exact_names AS symbols;

CREATE TEMP VIEW IF NOT EXISTS live_definition_normalized_names AS
SELECT lang, generation, rel_path, blob_oid, blob_id, unit_key, kind, short_name,
       identifier, source_kind, prefix, normalized_tail AS tail,
       exact_parent_tail, normalized_parent_tail, package_tail,
       simple_type_name, signature
FROM live_definition_exact_names
WHERE source_kind <> 'path' AND normalized_tail IS NOT NULL
UNION ALL
SELECT lang, generation, rel_path, blob_oid, blob_id, unit_key, kind, short_name,
       identifier, source_kind, prefix, tail,
       exact_parent_tail, normalized_parent_tail, package_tail,
       simple_type_name, signature
FROM live_definition_exact_names
WHERE source_kind <> 'path' AND normalized_tail IS NULL
UNION ALL
SELECT symbols.lang, symbols.generation, symbols.rel_path, symbols.blob_oid,
       symbols.blob_id,
       NULL AS unit_key, symbols.kind, symbols.short_name, symbols.short_name,
       'path' AS source_kind, '' AS prefix, symbols.normalized_fqn AS tail,
       symbols.package_name AS exact_parent_tail,
       NULL AS normalized_parent_tail, symbols.package_name AS package_tail,
       symbols.short_name AS simple_type_name, NULL AS signature
FROM workspace_path_symbol_normalized_names AS symbols;

CREATE TEMP VIEW IF NOT EXISTS live_structural_members AS
SELECT * FROM live_definition_exact_names WHERE exact_parent_tail IS NOT NULL;

CREATE TEMP VIEW IF NOT EXISTS live_visible_members AS
SELECT * FROM live_structural_members
UNION ALL
SELECT names.lang, names.generation, names.rel_path, names.blob_oid,
       names.blob_id,
       names.unit_key, names.kind, names.short_name, names.identifier,
       names.source_kind, names.prefix, names.tail, names.normalized_tail,
       containers.exact_container_tail AS exact_parent_tail,
       containers.normalized_container_tail AS normalized_parent_tail,
       names.package_tail, names.simple_type_name, names.signature
FROM live_definition_exact_names AS names
JOIN main.unit_visibility_containers AS containers
  ON containers.blob_id = names.blob_id
 AND containers.unit_key = names.unit_key;

CREATE TEMP VIEW IF NOT EXISTS live_definition_identifiers AS
SELECT lang, generation, rel_path, blob_oid, blob_id, unit_key, kind, identifier,
       source_kind, prefix, tail, normalized_tail
FROM live_definition_exact_names;

CREATE TEMP VIEW IF NOT EXISTS live_package_types AS
SELECT units.lang, files.generation, files.rel_path, files.blob_oid,
       units.blob_id,
       units.unit_key, units.identifier, 'content' AS source_kind,
       '' AS prefix, units.package_fqn_tail AS package_tail,
       units.simple_type_name, units.exact_fqn_tail AS tail,
       units.normalized_fqn_tail AS normalized_tail
FROM main.code_units AS units INDEXED BY idx_code_units_stable_package_type
JOIN live_workspace_files AS files
  ON files.blob_id = units.blob_id
WHERE units.fq_anchor_kind IS NULL
  AND units.exact_fqn_tail IS NOT NULL
  AND units.in_declarations = 1 AND units.kind = 0
  AND units.simple_type_name IS NOT NULL
UNION ALL
SELECT units.lang, files.generation, files.rel_path, files.blob_oid,
       units.blob_id,
       units.unit_key, units.identifier, 'anchored' AS source_kind,
       anchors.package_name AS prefix,
       units.package_fqn_tail AS package_tail, units.simple_type_name,
       units.exact_fqn_tail AS tail, units.normalized_fqn_tail AS normalized_tail
FROM main.code_units AS units INDEXED BY idx_code_units_anchored_package_type
JOIN live_workspace_files AS files
  ON files.blob_id = units.blob_id
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
       symbols.blob_id,
       NULL AS unit_key, symbols.short_name AS identifier,
       'path' AS source_kind, '' AS prefix,
       symbols.package_name AS package_tail,
       symbols.short_name AS simple_type_name,
       symbols.exact_fqn AS tail,
       CASE WHEN symbols.normalized_fqn <> symbols.exact_fqn
            THEN symbols.normalized_fqn END AS normalized_tail
FROM workspace_path_symbol_exact_names AS symbols
WHERE symbols.kind = 0;

CREATE TEMP VIEW IF NOT EXISTS live_callable_facts AS
SELECT names.lang, names.generation, names.rel_path, names.blob_oid,
       names.blob_id,
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
       metadata.class_like_is_interface, metadata.class_like_is_static,
       metadata.type_parameters_recorded
FROM live_definition_exact_names AS names
JOIN main.unit_signatures AS signatures
  ON signatures.blob_id = names.blob_id
 AND signatures.unit_key = names.unit_key
LEFT JOIN main.unit_signature_metadata AS metadata
  ON metadata.blob_id = signatures.blob_id
 AND metadata.unit_key = signatures.unit_key
 AND metadata.ordinal = signatures.ordinal;

CREATE TEMP VIEW IF NOT EXISTS live_stable_definition_parent_names AS
SELECT units.lang, files.generation, files.rel_path, live.blob_oid,
       units.blob_id,
       units.unit_key, units.kind, units.short_name, units.identifier,
       'content' AS source_kind, '' AS prefix, units.exact_fqn_tail AS tail,
       units.normalized_fqn_tail AS normalized_tail,
       units.exact_parent_fqn_tail AS exact_parent_tail,
       units.normalized_parent_fqn_tail AS normalized_parent_tail,
       units.package_fqn_tail AS package_tail,
       units.simple_type_name, units.signature
FROM main.code_units AS units INDEXED BY idx_code_units_stable_parent_identifier
CROSS JOIN main.live_parsed_blobs AS live
  ON live.blob_id = units.blob_id
CROSS JOIN selected_workspace_revisions AS selected
  ON selected.lang = units.lang
CROSS JOIN main.workspace_file_versions AS files
     INDEXED BY idx_workspace_file_versions_snapshot_blob
  ON files.workspace_id = selected.workspace_id
 AND files.lang = selected.lang
 AND files.generation = selected.generation
 AND files.blob_oid = live.blob_oid
WHERE units.fq_anchor_kind IS NULL
  AND units.exact_parent_fqn_tail IS NOT NULL
  AND (units.in_declarations = 1 OR units.in_definition_lookup = 1)
  AND files.valid_from <= selected.revision
  AND (files.valid_until IS NULL OR selected.revision < files.valid_until);

CREATE TEMP VIEW IF NOT EXISTS live_anchored_definition_parent_names AS
SELECT units.lang, files.generation, files.rel_path, files.blob_oid,
       units.blob_id,
       units.unit_key, units.kind, units.short_name, units.identifier,
       'anchored' AS source_kind, anchors.package_name AS prefix,
       units.exact_fqn_tail AS tail, units.normalized_fqn_tail AS normalized_tail,
       units.exact_parent_fqn_tail AS exact_parent_tail,
       units.normalized_parent_fqn_tail AS normalized_parent_tail,
       units.package_fqn_tail AS package_tail,
       units.simple_type_name, units.signature
FROM main.workspace_file_anchor_rows AS anchors
     INDEXED BY idx_workspace_file_anchor_rows_package
CROSS JOIN main.workspace_file_versions AS files
  ON files.file_version_id = anchors.file_version_id
CROSS JOIN selected_workspace_revisions AS selected
  ON selected.workspace_id = files.workspace_id
 AND selected.lang = files.lang
 AND selected.generation = files.generation
CROSS JOIN main.live_parsed_blobs AS live
  ON live.blob_oid = files.blob_oid AND live.lang = files.lang
CROSS JOIN main.code_units AS units INDEXED BY idx_code_units_anchored_parent_identifier
  ON units.blob_id = live.blob_id
 AND units.fq_anchor_kind = anchors.anchor_kind
 AND units.fq_anchor_pop = anchors.anchor_pop
WHERE units.fq_anchor_kind IS NOT NULL
  AND units.exact_parent_fqn_tail IS NOT NULL
  AND (units.in_declarations = 1 OR units.in_definition_lookup = 1)
  AND files.valid_from <= selected.revision
  AND (files.valid_until IS NULL OR selected.revision < files.valid_until);

CREATE TEMP VIEW IF NOT EXISTS live_stable_definition_normalized_names AS
SELECT units.lang, files.generation, files.rel_path, live.blob_oid,
       units.blob_id,
       units.unit_key, units.kind, units.short_name, units.identifier,
       'content' AS source_kind, '' AS prefix,
       units.normalized_fqn_tail AS tail,
       units.normalized_fqn_tail AS normalized_tail,
       units.exact_parent_fqn_tail AS exact_parent_tail,
       units.normalized_parent_fqn_tail AS normalized_parent_tail,
       units.package_fqn_tail AS package_tail,
       units.simple_type_name, units.signature
FROM main.code_units AS units INDEXED BY idx_code_units_stable_normalized_tail
CROSS JOIN main.live_parsed_blobs AS live
  ON live.blob_id = units.blob_id
CROSS JOIN selected_workspace_revisions AS selected
  ON selected.lang = units.lang
CROSS JOIN main.workspace_file_versions AS files
     INDEXED BY idx_workspace_file_versions_snapshot_blob
  ON files.workspace_id = selected.workspace_id
 AND files.lang = selected.lang
 AND files.generation = selected.generation
 AND files.blob_oid = live.blob_oid
WHERE units.fq_anchor_kind IS NULL
  AND units.normalized_fqn_tail IS NOT NULL
  AND (units.in_declarations = 1 OR units.in_definition_lookup = 1)
  AND files.valid_from <= selected.revision
  AND (files.valid_until IS NULL OR selected.revision < files.valid_until);

CREATE TEMP VIEW IF NOT EXISTS live_anchored_definition_normalized_names AS
SELECT units.lang, files.generation, files.rel_path, files.blob_oid,
       units.blob_id,
       units.unit_key, units.kind, units.short_name, units.identifier,
       'anchored' AS source_kind, anchors.package_name AS prefix,
       units.normalized_fqn_tail AS tail,
       units.normalized_fqn_tail AS normalized_tail,
       units.exact_parent_fqn_tail AS exact_parent_tail,
       units.normalized_parent_fqn_tail AS normalized_parent_tail,
       units.package_fqn_tail AS package_tail,
       units.simple_type_name, units.signature
FROM main.workspace_file_anchor_rows AS anchors
     INDEXED BY idx_workspace_file_anchor_rows_package
CROSS JOIN main.workspace_file_versions AS files
  ON files.file_version_id = anchors.file_version_id
CROSS JOIN selected_workspace_revisions AS selected
  ON selected.workspace_id = files.workspace_id
 AND selected.lang = files.lang
 AND selected.generation = files.generation
CROSS JOIN main.live_parsed_blobs AS live
  ON live.blob_oid = files.blob_oid AND live.lang = files.lang
CROSS JOIN main.code_units AS units INDEXED BY idx_code_units_anchored_normalized_tail
  ON units.blob_id = live.blob_id
 AND units.fq_anchor_kind = anchors.anchor_kind
 AND units.fq_anchor_pop = anchors.anchor_pop
WHERE units.fq_anchor_kind IS NOT NULL
  AND units.normalized_fqn_tail IS NOT NULL
  AND (units.in_declarations = 1 OR units.in_definition_lookup = 1)
  AND files.valid_from <= selected.revision
  AND (files.valid_until IS NULL OR selected.revision < files.valid_until);

CREATE TEMP VIEW IF NOT EXISTS live_stable_definition_identifiers AS
SELECT units.lang, files.generation, files.rel_path, live.blob_oid,
       units.blob_id,
       units.unit_key, units.kind, units.identifier,
       'content' AS source_kind, '' AS prefix,
       units.exact_fqn_tail AS tail,
       units.normalized_fqn_tail AS normalized_tail
FROM main.code_units AS units INDEXED BY idx_code_units_lang_identifier_lookup
CROSS JOIN main.live_parsed_blobs AS live
  ON live.blob_id = units.blob_id
CROSS JOIN selected_workspace_revisions AS selected
  ON selected.lang = units.lang
CROSS JOIN main.workspace_file_versions AS files
     INDEXED BY idx_workspace_file_versions_snapshot_blob
  ON files.workspace_id = selected.workspace_id
 AND files.lang = selected.lang
 AND files.generation = selected.generation
 AND files.blob_oid = live.blob_oid
WHERE units.fq_anchor_kind IS NULL
  AND units.exact_fqn_tail IS NOT NULL
  AND (units.in_declarations = 1 OR units.in_definition_lookup = 1)
  AND files.valid_from <= selected.revision
  AND (files.valid_until IS NULL OR selected.revision < files.valid_until);

CREATE TEMP VIEW IF NOT EXISTS live_anchored_definition_identifiers AS
SELECT units.lang, files.generation, files.rel_path, live.blob_oid,
       units.blob_id,
       units.unit_key, units.kind, units.identifier,
       'anchored' AS source_kind, anchors.package_name AS prefix,
       units.exact_fqn_tail AS tail,
       units.normalized_fqn_tail AS normalized_tail
FROM main.code_units AS units INDEXED BY idx_code_units_lang_identifier_lookup
CROSS JOIN main.live_parsed_blobs AS live
  ON live.blob_id = units.blob_id
CROSS JOIN selected_workspace_revisions AS selected
  ON selected.lang = units.lang
CROSS JOIN main.workspace_file_versions AS files
     INDEXED BY idx_workspace_file_versions_snapshot_blob
  ON files.workspace_id = selected.workspace_id
 AND files.lang = selected.lang
 AND files.generation = selected.generation
 AND files.blob_oid = live.blob_oid
CROSS JOIN main.workspace_file_anchor_rows AS anchors
  ON anchors.file_version_id = files.file_version_id
 AND anchors.anchor_kind = units.fq_anchor_kind
 AND anchors.anchor_pop = units.fq_anchor_pop
WHERE units.fq_anchor_kind IS NOT NULL
  AND units.exact_fqn_tail IS NOT NULL
  AND (units.in_declarations = 1 OR units.in_definition_lookup = 1)
  AND files.valid_from <= selected.revision
  AND (files.valid_until IS NULL OR selected.revision < files.valid_until);

-- The mounted-declaration shape (issue #2794), split from the wide
-- `live_definition_exact_names` compound view for the same reason migration
-- `0031-relational-definition-identifier-views.sql` split the identifier
-- shapes: its one caller,
-- `AnalyzerStore::mounted_declaration_rows_for_langs`, wants nothing the wide
-- view's three arms compute.
--
-- That caller enumerates every declaration in the workspace together with the
-- workspace path each blob reading was mounted under, and it reads exactly two
-- things from the name side: the `rel_path` of the mounting, and the join key
-- back to `code_units`. It then discards the entire path-derived arm with
-- `source_kind <> 'path'`, ignores every fully-qualified-name column the wide
-- view assembles, and does not distinguish the stable arm from the anchored
-- one -- `hydrate_unit_fq` rebuilds the name from the adapter, the content
-- qualifier, and the file. Reading that through the compound view cost 89.4
-- minutes on dotnet/runtime (4.2 s in the graph-only record): SQLite
-- materialized all three arms as a co-routine, built an AUTOMATIC PARTIAL
-- COVERING INDEX over the result, and scanned all 802,432 `code_units` rows to
-- probe it.
--
-- So walk the workspace instead. `live_workspace_files` is one row per mounted
-- reading and already carries the path, and every unit of a reading is one
-- primary-key range of `code_units` under its `blob_id`. The `CROSS JOIN` pins
-- that direction, which is the whole point: the work becomes proportional to
-- the workspace's files rather than to a materialized copy of every name in
-- it.
--
-- The row set is the wide view's two content arms, restricted to declarations:
-- `live_workspace_files` enforces the same blob liveness and epoch generation
-- (through `live_parsed_blobs`), `exact_fqn_tail IS NOT NULL` is the filter
-- both non-path arms carry, and the `EXISTS` reproduces the anchored arm's
-- membership -- an anchored unit is mounted by a reading only if that reading
-- published the matching anchor. `workspace_file_anchor_rows` is keyed on
-- `(file_version_id, anchor_kind, anchor_pop)`, so the check is a primary-key
-- probe and, unlike the wide view's join, it cannot multiply a unit by its
-- anchors: the caller sorts and dedups in Rust, and now has less to dedup.
CREATE TEMP VIEW IF NOT EXISTS live_mounted_declarations AS
SELECT files.lang, files.rel_path, files.blob_oid, files.blob_id,
       units.unit_key, units.kind, units.short_name, units.content_qualifier,
       units.signature, units.synthetic, units.is_type_alias,
       units.top_level_ordinal, units.in_declarations,
       units.in_definition_lookup, units.fq_anchor_kind, units.fq_anchor_pop,
       units.fq_package_tail_segments, units.fq_segment_count,
       units.exact_fqn_tail, units.fq_segment_bytes, units.normalized_fqn_tail
FROM live_workspace_files AS files
CROSS JOIN main.code_units AS units
  ON units.blob_id = files.blob_id
WHERE units.in_declarations = 1
  AND units.exact_fqn_tail IS NOT NULL
  AND (units.fq_anchor_kind IS NULL
       OR EXISTS(
         SELECT 1 FROM main.workspace_file_anchor_rows AS anchors
         WHERE anchors.file_version_id = files.file_id
           AND anchors.anchor_kind = units.fq_anchor_kind
           AND anchors.anchor_pop = units.fq_anchor_pop
       ));
