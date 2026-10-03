-- A module declaration resolves against one of two bases, and the walk carries
-- both because Rust does.
--
-- `module_dir` is the logical module directory: `<dir>/foo` for `foo.rs` and
-- for `foo/mod.rs` alike, which is where an ordinary `mod bar;` looks.
-- `path_dir` is the directory of the source file that holds the declaration,
-- which is what a `#[path = "..."]` attribute written at a file's top level is
-- relative to. The two agree for a crate root and for a `mod.rs`, and differ
-- for every other file, which is why carrying only `module_dir` placed
-- `#[path]` declarations in `lib.rs` and lost the identical declaration in an
-- ordinary module file. Inside an inline `mod` block both bases advance by the
-- block's name, so the inline arm sets them together.
--
-- `?3` carries this crate's item-position macro decisions as a JSON array of
-- `[blob_id, invocation_occurrence_id, decoration_cfg, no_route]`. A `mod
-- child;` written inside an invocation is a module route with one gate per
-- enclosing invocation. When every gate is decided, the route's activation is
-- its own `cfg` combined with each gate's decoration, the `cfg` the
-- invocation's rules add to the item (`cfg_unix! { pub mod x; }` mounts `x`
-- only where `unix` holds). A no-route decision carries the encoded empty
-- `any()` predicate and closes the route. An undecided gate keeps the `-1`
-- unknown activation that publishes `UnsupportedMacroGeneratedModule`. The caller derives the array
-- from `rust_crate_item_macro_decisions.sql` and re-runs this walk until its
-- module placements and macro decisions reach a fixed point.
--
-- `parent_path` is the module that declares this one: NULL for the crate root,
-- the enclosing module for an inline or file module, and the host module's own
-- parent for an included file, which belongs to its host's module.
WITH RECURSIVE modules(module_path, blob_id, scope_ordinal, rel_path,
                       placement, module_dir, path_dir, activation, depth,
                       mount_blob_id, mount_start_byte, parent_path) AS (
  SELECT 'crate', blobs.id, 0, files.rel_path, 'root', cr_parent(files.rel_path),
         cr_parent(files.rel_path), 1, 0, NULL, NULL, NULL
  FROM selected_workspace_file_versions AS files
  LEFT JOIN blobs ON blobs.blob_oid = files.blob_oid AND blobs.lang = files.lang
            AND blobs.generation = files.generation
  WHERE files.rel_path = ?1 AND files.lang = 'rust'
  UNION ALL
  -- An inline module written inside item-macro invocations
  -- (`plain! { pub mod m { .. } }`) exists only if every enclosing invocation
  -- expands, so it takes the same gates a `mod child;` route does: each
  -- enclosing invocation must be decided, and its decoration combines with
  -- the module's own `cfg`. The enclosing invocations are the item-macro
  -- expansions of the same blob whose range holds the module's declaration.
  SELECT parent.module_path || '::' || declarations.module_name, parent.blob_id,
         scopes.ordinal, parent.rel_path, 'inline',
         cr_join(parent.module_dir, declarations.module_name),
         cr_join(parent.module_dir, declarations.module_name),
         CASE WHEN cr_cfg(properties.cfg_condition, ?2) <> 1
              THEN cr_cfg(properties.cfg_condition, ?2)
              WHEN EXISTS(SELECT 1 FROM source_rust_item_macro_expansions AS invocation
                          CROSS JOIN source_declarations AS placed
                            ON placed.blob_id = declarations.blob_id
                           AND placed.declaration_id = declarations.declaration_id
                          WHERE invocation.blob_id = declarations.blob_id
                            AND invocation.invocation_start_byte <= placed.start_byte
                            AND placed.end_byte <= invocation.invocation_end_byte
                            AND NOT EXISTS(SELECT 1 FROM json_each(?3) AS admitted
                                           WHERE admitted.value ->> 0 = invocation.blob_id
                                             AND admitted.value ->> 1 = invocation.invocation_occurrence_id))
              THEN -1
              ELSE COALESCE((SELECT CASE WHEN SUM(cr_cfg(admitted.value ->> 2, ?2) = 0) > 0 THEN 0
                                         ELSE MIN(cr_cfg(admitted.value ->> 2, ?2)) END
                             FROM source_rust_item_macro_expansions AS invocation
                             CROSS JOIN source_declarations AS placed
                               ON placed.blob_id = declarations.blob_id
                              AND placed.declaration_id = declarations.declaration_id
                             CROSS JOIN json_each(?3) AS admitted
                               ON admitted.value ->> 0 = invocation.blob_id
                              AND admitted.value ->> 1 = invocation.invocation_occurrence_id
                             WHERE invocation.blob_id = declarations.blob_id
                               AND invocation.invocation_start_byte <= placed.start_byte
                               AND placed.end_byte <= invocation.invocation_end_byte), 1)
         END,
         parent.depth + 1,
         NULL, NULL, parent.module_path
  FROM modules AS parent
  CROSS JOIN source_rust_module_scopes AS scopes
    ON scopes.blob_id = parent.blob_id AND scopes.parent_ordinal = parent.scope_ordinal
  CROSS JOIN source_rust_module_declarations AS declarations
    ON declarations.blob_id = scopes.blob_id AND declarations.declaration_id = scopes.declaration_id
   AND declarations.body_occurrence_id IS NOT NULL
  CROSS JOIN source_rust_declaration_properties AS properties
    ON properties.blob_id = declarations.blob_id AND properties.declaration_id = declarations.declaration_id
  WHERE parent.activation = 1 AND parent.depth < 256
  UNION ALL
  SELECT parent.module_path || '::' || declarations.module_name, blobs.id,
         0, files.rel_path,
         CASE WHEN declarations.path_attribute IS NULL THEN 'mod_declaration' ELSE 'path_attribute' END,
         CASE WHEN declarations.path_attribute IS NULL
              THEN cr_join(parent.module_dir, declarations.module_name)
              ELSE cr_parent(files.rel_path) END,
         cr_parent(files.rel_path),
         CASE WHEN cr_cfg(properties.cfg_condition, ?2) <> 1 THEN cr_cfg(properties.cfg_condition, ?2)
              WHEN NOT EXISTS(SELECT 1 FROM source_rust_module_route_gates AS gates
                          WHERE gates.blob_id = routes.blob_id AND gates.route_ordinal = routes.ordinal)
              THEN 1
              WHEN NOT EXISTS(SELECT 1 FROM source_rust_module_route_gates AS gates
                          WHERE gates.blob_id = routes.blob_id AND gates.route_ordinal = routes.ordinal
                            AND NOT EXISTS(SELECT 1 FROM json_each(?3) AS admitted
                                           WHERE admitted.value ->> 0 = gates.blob_id
                                             AND admitted.value ->> 1 = gates.invocation_occurrence_id))
              THEN (SELECT CASE WHEN SUM(cr_cfg(admitted.value ->> 2, ?2) = 0) > 0 THEN 0
                                ELSE MIN(cr_cfg(admitted.value ->> 2, ?2)) END
                    FROM source_rust_module_route_gates AS gates
                    CROSS JOIN json_each(?3) AS admitted
                      ON admitted.value ->> 0 = gates.blob_id
                     AND admitted.value ->> 1 = gates.invocation_occurrence_id
                    WHERE gates.blob_id = routes.blob_id AND gates.route_ordinal = routes.ordinal)
              ELSE -1 END,
         parent.depth + 1,
         parent.blob_id, route_declaration.start_byte, parent.module_path
  FROM modules AS parent
  CROSS JOIN source_rust_module_routes AS routes
    ON routes.blob_id = parent.blob_id AND routes.scope_ordinal = parent.scope_ordinal
  CROSS JOIN source_rust_module_declarations AS declarations
    ON declarations.blob_id = routes.blob_id AND declarations.declaration_id = routes.declaration_id
   AND declarations.body_occurrence_id IS NULL
  CROSS JOIN source_rust_declaration_properties AS properties
    ON properties.blob_id = declarations.blob_id AND properties.declaration_id = declarations.declaration_id
  CROSS JOIN source_declarations AS route_declaration
    ON route_declaration.blob_id = routes.blob_id
   AND route_declaration.declaration_id = routes.declaration_id
  LEFT JOIN workspace_file_versions AS files ON files.file_version_id IN (
    SELECT selected.file_version_id FROM selected_workspace_file_versions AS selected
    WHERE selected.lang = 'rust' AND selected.rel_path IN (
      cr_join(CASE WHEN declarations.path_attribute IS NULL THEN parent.module_dir ELSE parent.path_dir END,
              COALESCE(declarations.path_attribute, declarations.module_name || '.rs')),
      cr_join(CASE WHEN declarations.path_attribute IS NULL THEN parent.module_dir ELSE parent.path_dir END,
              COALESCE(declarations.path_attribute, declarations.module_name || '/mod.rs'))))
  LEFT JOIN blobs ON blobs.blob_oid = files.blob_oid AND blobs.lang = files.lang
                 AND blobs.generation = files.generation
  WHERE parent.activation = 1 AND parent.blob_id IS NOT NULL AND parent.depth < 256
  UNION ALL
  SELECT parent.module_path, blobs.id, 0, files.rel_path, 'include',
         parent.module_dir, parent.path_dir, 1, parent.depth + 1,
         NULL, NULL, parent.parent_path
  FROM modules AS parent
  CROSS JOIN rust_include_edges AS edge ON edge.blob_id = parent.blob_id
  LEFT JOIN source_rust_module_scopes AS scope
    ON scope.blob_id = parent.blob_id AND scope.ordinal = parent.scope_ordinal
  LEFT JOIN source_rust_module_declarations AS declaration
    ON declaration.blob_id = scope.blob_id AND declaration.declaration_id = scope.declaration_id
  LEFT JOIN workspace_file_versions AS files ON files.file_version_id IN (
    SELECT selected.file_version_id FROM selected_workspace_file_versions AS selected
    WHERE selected.lang = 'rust' AND selected.rel_path = cr_join(cr_parent(parent.rel_path), edge.relative_path))
  LEFT JOIN blobs ON blobs.blob_oid = files.blob_oid AND blobs.lang = files.lang
                 AND blobs.generation = files.generation
  WHERE parent.activation = 1 AND parent.depth < 256
    AND (parent.scope_ordinal = 0
         OR edge.include_start BETWEEN declaration.body_start_byte AND declaration.body_end_byte - 1)
    AND NOT EXISTS(
      SELECT 1 FROM source_rust_module_scopes AS inner_scope
      JOIN source_rust_module_declarations AS inner_declaration
        ON inner_declaration.blob_id = inner_scope.blob_id AND inner_declaration.declaration_id = inner_scope.declaration_id
      WHERE inner_scope.blob_id = parent.blob_id AND inner_scope.parent_ordinal = parent.scope_ordinal
        AND edge.include_start BETWEEN inner_declaration.body_start_byte AND inner_declaration.body_end_byte - 1)

)
-- One file reached from two module files is two modules, not an ambiguity.
-- rustc compiles the file once per placement, and the two results are distinct
-- modules with distinct paths, distinct items and distinct type identities, so
-- the walk publishes a row for each. The ambiguity the crate rows cannot hold
-- is two files under one module path (`foo.rs` and `foo/mod.rs` both present),
-- which the caller detects by counting placements per module path; this walk
-- does not label it, because a module path can also repeat through an
-- `include!`, which is the same module.
SELECT module_path, blob_id, scope_ordinal, rel_path, placement,
       mount_blob_id, mount_start_byte,
       CASE WHEN activation <> 1 THEN activation
            WHEN depth = 256 THEN -1
            ELSE activation END,
       parent_path
FROM modules ORDER BY module_path, rel_path
