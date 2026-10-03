-- A named import binds the export its route ends on. The route already names
-- the crate and the container the path reaches, in this crate or in a
-- dependency it re-exported through, and `cr_exports` holds both crates' rows
-- under their crate key, so one statement binds both. The namespace triple is
-- the seek key, not a filter: it completes the export primary key.
--
-- An item the crate declared for a decided item-macro invocation is an export
-- with no persisted site, so it is in `cr_macro_items` for this crate and in
-- `rust_crate_macro_items` for a dependency, not in `cr_exports`. The import
-- binds it all the same: its module's export inventory is closed on the
-- strength of those rows, so an import the rows can bind must not read as
-- unresolved.
INSERT INTO cr_imports
SELECT source.module_path, exports.namespace, source.bound_name, source.blob_id,
       source.import_ordinal, source.binder_scope,
       route.target_crate_key, route.target_module_path, source.imported_name
FROM cr_source_imports AS source
CROSS JOIN cr_routes AS route ON route.blob_id=source.blob_id AND route.import_ordinal=source.import_ordinal AND route.module_path=source.module_path
CROSS JOIN (VALUES('type'), ('value'), ('macro')) AS namespaces
CROSS JOIN cr_exports AS exports ON exports.crate_key = route.target_crate_key
  AND exports.module_path = route.target_module_path
  AND exports.namespace = namespaces.column1 AND exports.name = source.imported_name
WHERE source.is_glob = 0 AND source.bound_name IS NOT NULL
UNION
SELECT source.module_path, item.namespace, source.bound_name, source.blob_id,
       source.import_ordinal, source.binder_scope,
       route.target_crate_key, route.target_module_path, source.imported_name
FROM cr_source_imports AS source
CROSS JOIN cr_routes AS route ON route.blob_id=source.blob_id AND route.import_ordinal=source.import_ordinal AND route.module_path=source.module_path
CROSS JOIN cr_macro_items AS item ON item.module_path = route.target_module_path
  AND item.name = source.imported_name
WHERE source.is_glob = 0 AND source.bound_name IS NOT NULL
  AND route.target_crate_key = (SELECT crate_key FROM cr_identity)
UNION
SELECT source.module_path, item.namespace, source.bound_name, source.blob_id,
       source.import_ordinal, source.binder_scope,
       route.target_crate_key, route.target_module_path, source.imported_name
FROM cr_source_imports AS source
CROSS JOIN cr_routes AS route ON route.blob_id=source.blob_id AND route.import_ordinal=source.import_ordinal AND route.module_path=source.module_path
CROSS JOIN cr_foreign AS dependency ON dependency.crate_key = route.target_crate_key
CROSS JOIN rust_crate_macro_items AS item ON item.topology_id = dependency.topology_id
  AND item.module_path = route.target_module_path AND item.name = source.imported_name
  AND item.visibility = 'public'
WHERE source.is_glob = 0 AND source.bound_name IS NOT NULL
UNION
-- A `use` with no module segment whose name is a workspace dependency binds
-- that dependency's root module under its own name or an alias:
-- `use dep as alias;`, `use dep::{self as alias};`, `extern crate dep as alias;`.
-- A crate root has no export row to bind, so the row names it the way
-- `LOCAL_REEXPORT_STEPS_SQL` does, as the dependency's `crate` module with the
-- name `self`. The point route's root re-export walk
-- (`rust_crate_context::ROOT_REEXPORT`) follows it to the crate.
SELECT source.module_path, 'type', source.bound_name, source.blob_id,
       source.import_ordinal, source.binder_scope,
       root.dependency_crate_key, 'crate', 'self'
FROM cr_source_imports AS source
CROSS JOIN cr_dependencies AS root ON root.extern_name = source.imported_name
  AND root.dependency_crate_key IS NOT NULL
WHERE source.head_segment IS NULL AND source.is_glob = 0 AND source.bound_name IS NOT NULL;
